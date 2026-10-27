"""Adversarial and boundary regression tests for security audit of TraceGraph."""

import json

import httpx
import pytest

from tracegraph.collectors.dns import LiveDNSCollector
from tracegraph.collectors.rdap import RDAPCollector
from tracegraph.core.enums import CollectionStatus, EntityType
from tracegraph.core.exceptions import CollectorValidationError
from tracegraph.core.scope import ScopeValidator, is_public_ip


class TestIPValidationEdgeCases:
    """Security audit: IP address validation and SSRF boundary testing."""

    def test_ipv4_mapped_ipv6_private_and_loopback_rejected(self):
        """IPv4-mapped IPv6 addresses representing private/loopback must be rejected."""
        disallowed = [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:172.16.5.1",
            "::ffff:169.254.169.254",
            "::ffff:198.51.100.1",
            "::ffff:0.0.0.0",
            "::ffff:255.255.255.255",
        ]
        for ip in disallowed:
            assert is_public_ip(ip) is False, f"Expected {ip} to be rejected as non-public"

    def test_disallowed_ipv6_ranges_rejected(self):
        """Special-use and reserved IPv6 ranges must be rejected."""
        disallowed_v6 = [
            "::",  # Unspecified
            "::1",  # Loopback
            "100::1",  # Discard-only (RFC 6666)
            "2001:db8::1",  # Documentation (RFC 3849)
            "fc00::1",  # Unique Local (RFC 4193)
            "fd00::1234",  # Unique Local
            "fe80::1",  # Link-Local (RFC 4291)
            "ff02::1",  # Multicast
        ]
        for ip in disallowed_v6:
            assert is_public_ip(ip) is False, f"Expected {ip} to be rejected as non-public"

    def test_malformed_and_ambiguous_ip_inputs_rejected(self):
        """Malformed or integer-encoded IP inputs must be rejected by is_public_ip."""
        malformed = [
            "",
            "   ",
            "not-an-ip",
            "2130706433",  # Integer encoding of 127.0.0.1
            "0x7f000001",  # Hex encoding
            "999.999.999.999",
            "1.2.3.4.5",
            "127.0.0.1/32",  # CIDR passed as IP
            "http://127.0.0.1",
            "::ffff:999.999.999.999",
        ]
        for val in malformed:
            assert is_public_ip(val) is False, f"Expected '{val}' to be rejected"


class TestRDAPSSRFAndRedirectSecurity:
    """Security audit: RDAP redirect and SSRF mitigation tests."""

    def test_rdap_rejects_ipv4_mapped_private_ip_before_network(self):
        """Collector validation must reject IPv4-mapped private IPs before HTTP call."""
        collector = RDAPCollector(rate_limit_delay=0.0)
        with pytest.raises(CollectorValidationError, match="private, loopback, or reserved"):
            collector.collect("::ffff:127.0.0.1", EntityType.IPV6)

    def test_rdap_redirect_to_loopback_rejected(self):
        """Redirect to 127.0.0.1 must be blocked as prohibited destination."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://127.0.0.1:8443/admin"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        err = (result.error_message or "").lower()
        assert "prohibited" in err or "rejected" in err

    def test_rdap_redirect_to_cloud_metadata_rejected(self):
        """Redirect to 169.254.169.254 must be blocked."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://169.254.169.254/latest/meta-data/"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        err = (result.error_message or "").lower()
        assert "prohibited" in err or "rejected" in err

    def test_rdap_redirect_to_private_lan_rejected(self):
        """Redirect to private RFC 1918 addresses must be blocked."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://192.168.1.1/secret.json"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED

    def test_rdap_redirect_to_localhost_hostname_rejected(self):
        """Redirect to 'localhost' must be blocked."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://localhost:8443/internal"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED

    def test_rdap_untrusted_redirect_host_blocked(self):
        """Redirect to arbitrary third-party domain outside RIR allowlist must be blocked."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://attacker-controlled-site.org/rdap"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        err = (result.error_message or "").lower()
        assert "untrusted" in err or "not in authorized" in err

    def test_rdap_redirect_loop_detected(self):
        """Circular redirect loop (A -> B -> A) must be detected and aborted."""
        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "endpoint-a" in url_str:
                return httpx.Response(
                    status_code=302,
                    headers={"Location": "https://rdap.arin.net/registry/ip/endpoint-b"},
                )
            if "endpoint-b" in url_str:
                return httpx.Response(
                    status_code=302,
                    headers={"Location": "https://rdap.arin.net/registry/ip/endpoint-a"},
                )
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://rdap.arin.net/registry/ip/endpoint-a"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        assert "loop" in result.error_message.lower() or "redirect" in result.error_message.lower()

    def test_rdap_relative_redirect_handled_safely(self):
        """Relative redirect Location headers must be safely joined with parent URL."""
        sample_rdap = {
            "handle": "NET-RELATIVE",
            "startAddress": "93.184.215.0",
            "endAddress": "93.184.215.255",
            "ipVersion": "v4",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str.endswith("/rel-dest"):
                return httpx.Response(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    content=json.dumps(sample_rdap).encode("utf-8"),
                )
            return httpx.Response(
                status_code=302,
                headers={"Location": "/registry/ip/rel-dest"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.SUCCESS
        assert result.data["handle"] == "NET-RELATIVE"


class TestRDAPResponseStreamingLimits:
    """Security audit: Response size limits enforced while streaming."""

    def test_oversized_stream_without_content_length_aborted(self):
        """Stream exceeding 512 KB without Content-Length header must be terminated."""
        def handler(request: httpx.Request) -> httpx.Response:
            # Generate 600 KB payload in chunks without Content-Length
            chunk = b"A" * 65536  # 64 KB
            def stream_gen():
                for _ in range(10):  # 10 * 64 KB = 640 KB
                    yield chunk
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "application/json"},
                content=stream_gen(),
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        assert "exceed" in result.error_message.lower()


class TestScopeValidatorBoundaries:
    """Security audit: Scope boundary enforcement and exception handling."""

    def test_scope_cidr_cross_version_does_not_crash(self):
        """Matching IPv4 CIDR against IPv6 scope network must return False without TypeError."""
        validator = ScopeValidator("2001:db8::/32")
        # IPv4 CIDR should not raise TypeError
        assert validator.is_in_scope("192.168.1.0/24", EntityType.CIDR) is False

        validator_v4 = ScopeValidator("192.168.0.0/16")
        # IPv6 CIDR should not raise TypeError
        assert validator_v4.is_in_scope("2001:db8::/32", EntityType.CIDR) is False

    def test_domain_lookalike_and_suffix_boundaries(self):
        """Scope validator must reject domain lookalikes and suffix collisions."""
        validator = ScopeValidator("example.com")

        # Allowed
        assert validator.is_in_scope("example.com", EntityType.DOMAIN) is True
        assert validator.is_in_scope("sub.example.com", EntityType.DOMAIN) is True
        assert validator.is_in_scope("a.b.c.example.com", EntityType.DOMAIN) is True

        # Forbidden lookalikes
        assert validator.is_in_scope("notexample.com", EntityType.DOMAIN) is False
        assert validator.is_in_scope("attacker-example.com", EntityType.DOMAIN) is False
        assert validator.is_in_scope("example.com.attacker.com", EntityType.DOMAIN) is False
        assert validator.is_in_scope("myexample.com", EntityType.DOMAIN) is False

    def test_wildcard_domain_boundary(self):
        """Wildcard scope *.example.com must not match attacker-example.com."""
        validator = ScopeValidator("*.example.com")

        assert validator.is_in_scope("example.com", EntityType.DOMAIN) is True
        assert validator.is_in_scope("sub.example.com", EntityType.DOMAIN) is True
        assert validator.is_in_scope("badexample.com", EntityType.DOMAIN) is False
        assert validator.is_in_scope("attacker-example.com", EntityType.DOMAIN) is False


class TestLiveDNSSecurity:
    """Security audit: Live DNS target validation and boundaries."""

    def test_live_dns_rejects_localhost_and_internal_domains(self):
        """Live DNS must reject localhost and RFC 6761/6762 special-use internal domains."""
        collector = LiveDNSCollector()

        disallowed_domains = [
            "localhost",
            "app.localhost",
            "router.local",
            "internal.lan",
            "myhost.internal",
            "gateway.home.arpa",
        ]
        for domain in disallowed_domains:
            with pytest.raises(
                CollectorValidationError, match="special-use, loopback, or internal"
            ):
                collector.collect(domain, EntityType.DOMAIN)


class TestDatabaseConsistencyOnFailure:
    """Security audit: Database state after collection failure."""

    def test_failed_collection_creates_no_relationships(self, tmp_path):
        """Failed or timed out collection runs must never create relationships."""
        from typer.testing import CliRunner

        from tracegraph.cli.main import app
        from tracegraph.storage.database import create_session_factory, create_storage_engine
        from tracegraph.storage.repository import EvidenceRepository
        from tracegraph.storage.workspace import get_workspace_status, resolve_workspace_path

        runner = CliRunner()
        ws_dir = tmp_path / "ws_sec_db"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        runner.invoke(
            app,
            ["investigate", "new", "Sec Failure Test", "--scope", "*", "--workspace", str(ws_dir)],
        )

        # Run collection against failure.test which fails deterministically
        res = runner.invoke(
            app,
            [
                "collect",
                "failure.test",
                "--collector",
                "mock_dns",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res.exit_code == 1

        # Check repository state directly
        resolved = resolve_workspace_path(ws_dir)
        engine = create_storage_engine(resolved / "tracegraph.db")
        session_factory = create_session_factory(engine)
        repo = EvidenceRepository(session_factory)

        invs = repo.list_investigations()
        assert len(invs) >= 1
        obs = repo.list_observations_for_investigation(invs[0].id)
        assert len(obs) == 1
        assert obs[0].status == CollectionStatus.FAILED

        # Invariant: ZERO relationships must be created for failed collection
        ws_status = get_workspace_status(resolved)
        assert ws_status.relationship_count == 0

