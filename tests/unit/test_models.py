"""Unit tests for Pydantic evidence data models."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.evidence.models import (
    EntityModel,
    EvidenceLinkModel,
    InvestigationModel,
    ObservationModel,
    RelationshipModel,
)


class TestInvestigationModel:
    def test_valid_investigation(self):
        inv = InvestigationModel(name="Operation Aurora", description="Defensive scope")
        assert inv.id is not None
        assert inv.name == "Operation Aurora"
        assert inv.description == "Defensive scope"
        assert inv.created_at.tzinfo == UTC
        assert isinstance(inv.config_metadata, dict)

    def test_empty_name_fails(self):
        with pytest.raises(ValidationError):
            InvestigationModel(name="")

    def test_timezone_conversion(self):
        naive = datetime(2026, 1, 1, 12, 0, 0)
        inv = InvestigationModel(name="Test", created_at=naive)
        assert inv.created_at.tzinfo == UTC


class TestEntityModel:
    def test_valid_domain_normalization(self):
        ent = EntityModel(entity_type=EntityType.DOMAIN, raw_value="  Example.COM. ")
        assert ent.normalized_value == "example.com"
        assert ent.entity_type == EntityType.DOMAIN

    def test_valid_ipv4_normalization(self):
        ent = EntityModel(entity_type=EntityType.IPV4, raw_value="  192.168.1.1  ")
        assert ent.normalized_value == "192.168.1.1"

    def test_invalid_ipv4_fails(self):
        with pytest.raises(Exception):
            EntityModel(entity_type=EntityType.IPV4, raw_value="999.999.999.999")

    def test_valid_asn_normalization(self):
        ent = EntityModel(entity_type=EntityType.ASN, raw_value="as15169")
        assert ent.normalized_value == "AS15169"


class TestObservationModel:
    def test_valid_observation_provenance(self):
        now = datetime.now(UTC)
        obs = ObservationModel(
            entity_id="test-ent-id",
            collector_name="mock_dns",
            collector_version="0.1.0",
            source_reference="synthetic://mock-dns/example.com",
            observed_at=now - timedelta(minutes=5),
            data={"ip": "93.184.215.14"},
            status=CollectionStatus.SUCCESS,
        )
        assert obs.entity_id == "test-ent-id"
        assert obs.collector_name == "mock_dns"
        assert obs.observed_at.tzinfo == UTC
        assert obs.ingested_at.tzinfo == UTC
        assert obs.observed_at < obs.ingested_at
        assert obs.status == CollectionStatus.SUCCESS

    def test_missing_entity_id_fails(self):
        with pytest.raises(ValidationError):
            ObservationModel(
                entity_id="",
                collector_name="mock_dns",
                collector_version="0.1.0",
                source_reference="synthetic://ref",
                observed_at=datetime.now(UTC),
            )


class TestRelationshipModel:
    def test_unsupported_relationship_is_unverified(self):
        rel = RelationshipModel(
            source_entity_id="ent-1",
            target_entity_id="ent-2",
            relationship_type=RelationshipType.RESOLVES_TO,
            supporting_observation_ids=[],
        )
        assert not rel.is_verified

    def test_supported_relationship_is_verified(self):
        rel = RelationshipModel(
            source_entity_id="ent-1",
            target_entity_id="ent-2",
            relationship_type=RelationshipType.RESOLVES_TO,
            supporting_observation_ids=["obs-uuid-1"],
        )
        assert rel.is_verified

    def test_identical_source_and_target_fails(self):
        with pytest.raises(ValidationError):
            RelationshipModel(
                source_entity_id="ent-1",
                target_entity_id="ent-1",
                relationship_type=RelationshipType.RESOLVES_TO,
            )


class TestEvidenceLinkModel:
    def test_valid_link(self):
        link = EvidenceLinkModel(
            relationship_id="rel-1",
            observation_id="obs-1",
            notes="Authoritative A record match",
        )
        assert link.relationship_id == "rel-1"
        assert link.observation_id == "obs-1"
        assert link.created_at.tzinfo == UTC
