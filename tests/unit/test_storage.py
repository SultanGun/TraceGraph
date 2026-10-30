"""Unit tests for SQLite storage, foreign key constraints, and repository operations."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import (
    AmbiguousInvestigationError,
    DatabaseIntegrityError,
    NotFoundError,
)
from tracegraph.storage.database import check_connection, session_scope
from tracegraph.storage.schema import EntityRecord, InvestigationRecord


class TestStorageEngine:
    def test_database_connectivity_and_foreign_keys(self, test_db_engine):
        assert check_connection(test_db_engine) is True
        with test_db_engine.connect() as conn:
            fk_status = conn.execute(text("PRAGMA foreign_keys;")).scalar()
            assert fk_status == 1


class TestEvidenceRepository:
    def test_investigation_lifecycle(self, evidence_repo):
        inv = evidence_repo.create_investigation(
            name="Alpha Scope",
            description="Testing investigation",
            config_metadata={"target": "example.com"},
        )
        assert inv.id is not None
        assert inv.name == "Alpha Scope"

        fetched = evidence_repo.get_investigation(inv.id)
        assert fetched.id == inv.id
        assert fetched.name == "Alpha Scope"
        assert fetched.config_metadata == {"target": "example.com"}

    def test_investigation_id_prefix_resolution(self, evidence_repo, test_session_factory):
        """Investigation retrieval resolves unique prefixes of at least 8 characters."""
        inv = evidence_repo.create_investigation(
            name="Prefix Resolution Test Investigation",
            description="Testing prefix resolution",
        )

        # 1. Full UUID lookup works
        full_res = evidence_repo.get_investigation(inv.id)
        assert full_res.id == inv.id
        assert full_res.name == "Prefix Resolution Test Investigation"

        # 2. 8-character unique prefix works
        prefix_8 = inv.id[:8]
        p8_res = evidence_repo.get_investigation(prefix_8)
        assert p8_res.id == inv.id
        assert p8_res.name == "Prefix Resolution Test Investigation"

        # 3. 12-character unique prefix works
        prefix_12 = inv.id[:12]
        p12_res = evidence_repo.get_investigation(prefix_12)
        assert p12_res.id == inv.id

        # 4. Prefix shorter than 8 characters is rejected with NotFoundError
        with pytest.raises(NotFoundError):
            evidence_repo.get_investigation(inv.id[:7])

        # 5. Non-existent prefix raises NotFoundError
        with pytest.raises(NotFoundError):
            evidence_repo.get_investigation("ffffffff-ffff")

        # 6. Ambiguous prefix matching multiple investigations raises AmbiguousInvestigationError
        col1_id = "aaaa1111-0000-4000-8000-000000000001"
        col2_id = "aaaa1111-0000-4000-8000-000000000002"
        now = datetime.now(UTC)
        with session_scope(test_session_factory) as session:
            session.add(
                InvestigationRecord(
                    id=col1_id,
                    name="Ambiguous Alpha",
                    description="Collision 1",
                    target_scope="example.com",
                    created_at=now,
                )
            )
            session.add(
                InvestigationRecord(
                    id=col2_id,
                    name="Ambiguous Beta",
                    description="Collision 2",
                    target_scope="example.com",
                    created_at=now,
                )
            )

        with pytest.raises(AmbiguousInvestigationError) as exc_info:
            evidence_repo.get_investigation("aaaa1111")
        assert "ambiguous" in str(exc_info.value).lower()

        # 7. Prefix resolution works with snapshot creation and filtering
        snap = evidence_repo.create_snapshot(prefix_8, label="Prefix Snap")
        assert snap.investigation_id == inv.id

        snaps_filtered = evidence_repo.list_snapshots(investigation_id=prefix_8)
        assert len(snaps_filtered) == 1
        assert snaps_filtered[0].id == snap.id

    def test_entity_deduplication(self, evidence_repo):
        # 1. Create initial entity
        ent1, created1 = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "  Example.COM. ")
        assert created1 is True
        assert ent1.normalized_value == "example.com"

        # 2. Query with different formatting of the same entity
        ent2, created2 = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "example.com")
        assert created2 is False
        assert ent2.id == ent1.id
        assert ent2.normalized_value == "example.com"

        # 3. Verify total entity count is 1
        entities = evidence_repo.list_entities()
        assert len(entities) == 1

    def test_foreign_key_enforcement_on_observations(self, evidence_repo):
        # Observation referencing non-existent entity must fail
        with pytest.raises((DatabaseIntegrityError, NotFoundError)):
            evidence_repo.record_observation(
                entity_id="non-existent-uuid",
                collector_name="mock_dns",
                collector_version="0.1.0",
                source_reference="synthetic://ref",
                observed_at=datetime.now(UTC),
                data={"ip": "1.2.3.4"},
            )

    def test_foreign_key_cascade_deletion(self, evidence_repo, test_session_factory):
        # Register entity
        ent, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "target.local")

        # Record observation
        obs = evidence_repo.record_observation(
            entity_id=ent.id,
            collector_name="mock_dns",
            collector_version="0.1.0",
            source_reference="synthetic://ref",
            observed_at=datetime.now(UTC),
            data={"status": "active"},
        )

        # Delete entity directly from DB
        with session_scope(test_session_factory) as session:
            record = session.get(EntityRecord, ent.id)
            assert record is not None
            session.delete(record)

        # Verify observation was cascade-deleted
        with pytest.raises(NotFoundError):
            evidence_repo.get_observation(obs.id)

    def test_relationship_evidence_linkage_and_verification(self, evidence_repo):
        # Create domain and IP entities
        domain_ent, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "example.com")
        ip_ent, _ = evidence_repo.get_or_create_entity(EntityType.IPV4, "93.184.215.14")

        # Create relationship
        rel, created = evidence_repo.create_relationship(
            source_entity_id=domain_ent.id,
            target_entity_id=ip_ent.id,
            relationship_type=RelationshipType.RESOLVES_TO,
        )
        assert created is True
        assert not rel.is_verified
        assert evidence_repo.is_relationship_verified(rel.id) is False

        # Record supporting observation for the domain entity
        obs = evidence_repo.record_observation(
            entity_id=domain_ent.id,
            collector_name="mock_dns",
            collector_version="0.1.0",
            source_reference="synthetic://mock-dns/example.com",
            observed_at=datetime.now(UTC),
            data={"record_type": "A", "address": "93.184.215.14"},
            status=CollectionStatus.SUCCESS,
        )

        # Link evidence to relationship
        link = evidence_repo.link_evidence(
            relationship_id=rel.id,
            observation_id=obs.id,
            notes="Direct authoritative A record resolution",
        )
        assert link.relationship_id == rel.id
        assert link.observation_id == obs.id

        # Verify relationship is now verified
        assert evidence_repo.is_relationship_verified(rel.id) is True

        rel_model, supporting_obs = evidence_repo.get_relationship_with_evidence(rel.id)
        assert rel_model.is_verified is True
        assert len(supporting_obs) == 1
        assert supporting_obs[0].id == obs.id

    def test_disallow_self_relationship(self, evidence_repo):
        ent, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "loop.local")
        with pytest.raises(DatabaseIntegrityError):
            evidence_repo.create_relationship(
                source_entity_id=ent.id,
                target_entity_id=ent.id,
                relationship_type=RelationshipType.RESOLVES_TO,
            )
