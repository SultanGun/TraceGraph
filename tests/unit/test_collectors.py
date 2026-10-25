"""Unit tests for OSINT collector interfaces and MockDNSCollector."""

import pytest

from tracegraph.collectors.base import DiscoveredEntity, DiscoveredRelationship
from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import CollectorValidationError


class TestMockDNSCollector:
    def test_collector_metadata(self, mock_dns):
        assert mock_dns.name == "mock_dns"
        assert mock_dns.version == "0.1.0"
        assert EntityType.DOMAIN in mock_dns.supported_entity_types

    def test_input_validation_unsupported_type(self, mock_dns):
        with pytest.raises(CollectorValidationError):
            mock_dns.collect("192.168.1.1", EntityType.IPV4)

    def test_input_validation_invalid_domain(self, mock_dns):
        with pytest.raises(CollectorValidationError):
            mock_dns.collect("invalid..domain", EntityType.DOMAIN)

    def test_deterministic_success_collection(self, mock_dns):
        result = mock_dns.collect("example.com", EntityType.DOMAIN)

        assert result.status == CollectionStatus.SUCCESS
        assert result.is_successful is True
        assert result.collector_name == "mock_dns"
        assert result.source_reference == "synthetic://mock-dns/example.com"
        assert "93.184.215.14" in result.data["records"]["A"]
        assert len(result.discovered_entities) >= 3
        assert len(result.discovered_relationships) >= 3
        assert result.duration_seconds >= 0.0

    def test_deterministic_empty_collection(self, mock_dns):
        result = mock_dns.collect("empty.test", EntityType.DOMAIN)

        assert result.status == CollectionStatus.EMPTY
        assert result.is_empty is True
        assert result.data["records"] == {}
        assert len(result.discovered_entities) == 0

    def test_unregistered_domain_returns_empty(self, mock_dns):
        result = mock_dns.collect("unknown-unregistered.local", EntityType.DOMAIN)

        assert result.status == CollectionStatus.EMPTY
        assert result.is_empty is True
        assert len(result.discovered_entities) == 0

    def test_deterministic_timeout_handling(self, mock_dns):
        result = mock_dns.collect("timeout.test", EntityType.DOMAIN)

        assert result.status == CollectionStatus.TIMEOUT
        assert result.is_failure is True
        assert "exceeded configured timeout" in (result.error_message or "")

    def test_deterministic_failure_handling(self, mock_dns):
        result = mock_dns.collect("failure.test", EntityType.DOMAIN)

        assert result.status == CollectionStatus.FAILED
        assert result.is_failure is True
        assert "SERVFAIL" in (result.error_message or "")

    def test_custom_fixture_registration(self, mock_dns):
        custom_domain = "custom-target.dev"
        mock_dns.register_fixture(
            domain=custom_domain,
            status=CollectionStatus.SUCCESS,
            records={"A": ["10.0.0.1"]},
            entities=[DiscoveredEntity(EntityType.IPV4, "10.0.0.1")],
            relationships=[
                DiscoveredRelationship(
                    source=DiscoveredEntity(EntityType.DOMAIN, custom_domain),
                    relationship_type=RelationshipType.RESOLVES_TO,
                    target=DiscoveredEntity(EntityType.IPV4, "10.0.0.1"),
                )
            ],
        )

        res = mock_dns.collect(custom_domain, EntityType.DOMAIN)
        assert res.status == CollectionStatus.SUCCESS
        assert res.data["records"]["A"] == ["10.0.0.1"]
        assert len(res.discovered_entities) == 1
        assert res.discovered_entities[0].raw_value == "10.0.0.1"
