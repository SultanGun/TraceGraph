"""Unit tests for the bounded RDAP collector."""

import json
from unittest.mock import MagicMock

import httpx
import pytest

from tracegraph.collectors.rdap import RDAPCollector
from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import CollectorValidationError


class TestRDAPCollector:
    """Test suite for RDAPCollector."""

    def test_rdap_input_validation_rejects_private_and_reserved_ips(self):
        collector = RDAPCollector(rate_limit_delay=0.0)

        private_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.5.10",
            "169.254.10.20",
            "::1",
            "fc00::1",
            "fe80::1",
        ]
        for ip in private_ips:
            with pytest.raises(CollectorValidationError, match="private, loopback, or reserved"):
                collector.collect(ip, EntityType.IPV4 if ":" not in ip else EntityType.IPV6)

    def test_rdap_success_with_cidr_and_pii_sanitization(self):
        sample_rdap = {
            "handle": "NET-93-184-215-0-1",
            "name": "EDGECAST-NETBLK-3",
            "startAddress": "93.184.215.0",
            "endAddress": "93.184.215.255",
            "ipVersion": "v4",
            "type": "ASSIGNMENT",
            "country": "US",
            "cidr0_cidrs": [{"v4prefix": "93.184.215.0", "length": 24}],
            "events": [
                {"eventAction": "registration", "eventDate": "2013-05-28T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2020-01-15T12:00:00Z"},
            ],
            "entities": [
                {
                    "handle": "ORG-VERIZON",
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "John Doe PII Contact"],
                            ["email", {}, "text", "john.doe@example.com"],
                            ["tel", {}, "text", "+1-555-0199"],
                        ],
                    ],
                }
            ],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            assert "93.184.215.14" in str(request.url)
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "application/rdap+json"},
                content=json.dumps(sample_rdap).encode("utf-8"),
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)

        assert result.status == CollectionStatus.SUCCESS
        assert result.collector_name == "rdap"
        assert result.collector_version == "0.2.0"
        assert result.error_message is None

        # Verify PII was stripped
        data = result.data
        assert data["handle"] == "NET-93-184-215-0-1"
        assert data["name"] == "EDGECAST-NETBLK-3"
        assert "vcardArray" not in data
        assert len(data["entities"]) == 1
        assert data["entities"][0] == {"handle": "ORG-VERIZON", "roles": ["registrant"]}
        # Confirm no raw emails or phone numbers leaked
        dumped = json.dumps(data)
        assert "john.doe@example.com" not in dumped
        assert "+1-555-0199" not in dumped

        # Verify discovered entities
        discovered_cidrs = [
            e for e in result.discovered_entities if e.entity_type == EntityType.CIDR
        ]
        assert len(discovered_cidrs) == 1
        assert discovered_cidrs[0].raw_value == "93.184.215.0/24"

        # Verify discovered relationships
        assert len(result.discovered_relationships) == 1
        rel = result.discovered_relationships[0]
        assert rel.relationship_type == RelationshipType.BELONGS_TO
        assert rel.source.raw_value == "93.184.215.14"
        assert rel.target.raw_value == "93.184.215.0/24"

    def test_rdap_address_range_fallback_when_no_cidr0(self):
        sample_rdap = {
            "handle": "NET-RANGE",
            "startAddress": "93.184.216.0",
            "endAddress": "93.184.216.255",
            "ipVersion": "v4",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "application/json"},
                content=json.dumps(sample_rdap).encode("utf-8"),
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.216.5", EntityType.IPV4)
        assert result.status == CollectionStatus.SUCCESS
        cidrs = [
            e.raw_value for e in result.discovered_entities if e.entity_type == EntityType.CIDR
        ]
        assert "93.184.216.0/24" in cidrs

    def test_rdap_not_found_empty(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=404, content=b"Not Found")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.EMPTY
        assert result.data["status_code"] == 404
        assert result.discovered_entities == []

    def test_rdap_rate_limit_429(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=429, content=b"Too Many Requests")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        assert "429" in result.error_message

    def test_rdap_server_error_500(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=500, content=b"Internal Server Error")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        assert "500" in result.error_message

    def test_rdap_timeout(self):
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = httpx.ReadTimeout("Read operation timed out")

        collector = RDAPCollector(http_client=mock_client, rate_limit_delay=0.0)
        result = collector.collect("93.184.215.14", EntityType.IPV4)

        assert result.status == CollectionStatus.TIMEOUT
        assert "timed out" in result.error_message.lower()

    def test_rdap_malformed_json(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=200, content=b"THIS IS NOT VALID JSON")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        assert "Malformed JSON" in result.error_message

    def test_rdap_redirect_following(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "arin.net" in str(request.url):
                return httpx.Response(
                    status_code=302,
                    headers={"Location": "https://rdap.ripe.net/ip/93.184.215.14"},
                )
            if "ripe.net" in str(request.url):
                return httpx.Response(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    content=json.dumps({
                        "handle": "RIPE-NET-1",
                        "startAddress": "93.184.215.0",
                        "endAddress": "93.184.215.255",
                    }).encode("utf-8"),
                )
            return httpx.Response(status_code=400)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.SUCCESS
        assert result.data["handle"] == "RIPE-NET-1"
        assert "ripe.net" in result.source_reference

    def test_rdap_insecure_redirect_rejected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": "http://insecure-rdap.example.com/ip/93.184.215.14"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        assert "Insecure redirect rejected" in result.error_message

    def test_rdap_oversized_response_rejected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            # Report content length > 512 KB
            return httpx.Response(
                status_code=200,
                headers={"Content-Length": "600000"},
                content=b"A" * 600000,
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        collector = RDAPCollector(http_client=client, rate_limit_delay=0.0)

        result = collector.collect("93.184.215.14", EntityType.IPV4)
        assert result.status == CollectionStatus.FAILED
        assert "exceeds limit" in result.error_message
