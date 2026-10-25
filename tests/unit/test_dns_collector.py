"""Unit tests for LiveDNSCollector with deterministic resolver mocks."""

from unittest.mock import MagicMock

import dns.exception
import dns.resolver
import pytest

from tracegraph.collectors.dns import LiveDNSCollector
from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import (
    CollectorValidationError,
)


class FakeRdataA:
    address = "93.184.215.14"


class FakeRdataAAAA:
    address = "2606:2800:220:1:248:1893:25c8:1946"


class FakeRdataNS:
    target = "a.iana-servers.net."


class FakeRdataMX:
    preference = 10
    exchange = "mail.example.com."


class TestLiveDNSCollector:
    def test_dns_success(self):
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        def resolve_side_effect(target, qtype, lifetime=None):
            if qtype == "A":
                return [FakeRdataA()]
            if qtype == "AAAA":
                return [FakeRdataAAAA()]
            if qtype == "NS":
                return [FakeRdataNS()]
            if qtype == "MX":
                return [FakeRdataMX()]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect

        collector = LiveDNSCollector(resolver=mock_resolver, nameservers=["1.1.1.1"])
        result = collector.collect("example.com", EntityType.DOMAIN)

        assert result.status == CollectionStatus.SUCCESS
        assert result.collector_name == "live_dns"
        assert result.collector_version == "0.2.0"
        assert "dns://[1.1.1.1]/example.com" in result.source_reference
        assert "93.184.215.14" in result.data["records"]["A"]
        assert "2606:2800:220:1:248:1893:25c8:1946" in result.data["records"]["AAAA"]
        assert "a.iana-servers.net" in result.data["records"]["NS"]

        # Check discovered entities
        discovered_values = {e.raw_value for e in result.discovered_entities}
        assert "93.184.215.14" in discovered_values
        assert "2606:2800:220:1:248:1893:25c8:1946" in discovered_values
        assert "a.iana-servers.net" in discovered_values
        assert "mail.example.com" in discovered_values

        # Check discovered relationships
        rel_types = {r.relationship_type for r in result.discovered_relationships}
        assert RelationshipType.RESOLVES_TO in rel_types
        assert RelationshipType.SERVED_BY in rel_types
        assert RelationshipType.MAIL_EXCHANGER_FOR in rel_types

    def test_dns_empty_nxdomain(self):
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        collector = LiveDNSCollector(resolver=mock_resolver)
        result = collector.collect("nonexistent-domain.test", EntityType.DOMAIN)

        assert result.status == CollectionStatus.EMPTY
        assert result.is_empty is True
        assert len(result.discovered_entities) == 0
        assert len(result.discovered_relationships) == 0

    def test_dns_empty_no_answer(self):
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        collector = LiveDNSCollector(resolver=mock_resolver)
        result = collector.collect("empty-answers.test", EntityType.DOMAIN)

        assert result.status == CollectionStatus.EMPTY
        assert result.is_empty is True
        assert len(result.discovered_entities) == 0

    def test_dns_timeout(self):
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)
        mock_resolver.resolve.side_effect = dns.exception.Timeout("Query timed out")

        collector = LiveDNSCollector(resolver=mock_resolver)
        result = collector.collect("timeout.test", EntityType.DOMAIN)

        assert result.status == CollectionStatus.TIMEOUT
        assert result.is_failure is True
        assert "timed out" in (result.error_message or "").lower()

    def test_dns_failure(self):
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()

        collector = LiveDNSCollector(resolver=mock_resolver)
        result = collector.collect("failure.test", EntityType.DOMAIN)

        assert result.status == CollectionStatus.FAILED
        assert result.is_failure is True
        err = (result.error_message or "").lower()
        assert "servfail" in err or "failed" in err

    def test_dns_input_validation(self):
        collector = LiveDNSCollector()
        with pytest.raises(CollectorValidationError):
            collector.collect("192.168.1.1", EntityType.IPV4)

        with pytest.raises(CollectorValidationError):
            collector.collect("invalid..domain", EntityType.DOMAIN)
