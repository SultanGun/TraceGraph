"""Unit tests for snapshot persistence, immutability, and database cascade deletion."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from tracegraph.core.enums import EntityType, RelationshipType
from tracegraph.core.exceptions import AmbiguousSnapshotError, NotFoundError
from tracegraph.snapshots.engine import diff_snapshots
from tracegraph.storage.database import session_scope
from tracegraph.storage.schema import SnapshotRecord


class TestSnapshotStorage:
    """Storage-layer tests verifying snapshot records, immutability, and cascade lifecycle."""

    def test_snapshot_creation_and_retrieval(self, evidence_repo):
        """Creating and fetching a snapshot preserves all entities, relationships, and metadata."""
        inv = evidence_repo.create_investigation("Storage Test Inv", target_scope="example.com")
        ent, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "example.com")
        evidence_repo.record_observation(
            entity_id=ent.id,
            investigation_id=inv.id,
            collector_name="mock_dns",
            collector_version="0.1.0",
            source_reference="mock://dns",
            observed_at=datetime.now(UTC),
            data={"ip": "93.184.215.14"},
        )

        snap = evidence_repo.create_snapshot(inv.id, label="Baseline Scan")
        assert snap.id is not None
        assert snap.investigation_id == inv.id
        assert snap.label == "Baseline Scan"
        assert snap.entity_count == 1
        assert snap.observation_count == 1
        assert len(snap.content_digest) == 64

        fetched = evidence_repo.get_snapshot(snap.id)
        assert fetched.id == snap.id
        assert fetched.content_digest == snap.content_digest
        assert fetched.entity_count == 1
        assert fetched.data.entities[0].normalized_value == "example.com"

    def test_snapshot_immutability_guarantee(self, evidence_repo):
        """Subsequent collections and investigation changes must NEVER rewrite an older snapshot."""
        inv = evidence_repo.create_investigation("Immutability Inv", target_scope="example.com")
        ent1, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "example.com")
        evidence_repo.record_observation(
            entity_id=ent1.id,
            investigation_id=inv.id,
            collector_name="mock_dns",
            collector_version="0.1.0",
            source_reference="mock://dns",
            observed_at=datetime.now(UTC),
            data={"status": "initial"},
        )

        # Snapshot 1: captured with 1 entity and 1 observation
        snap1 = evidence_repo.create_snapshot(inv.id, label="Snapshot 1")
        initial_digest = snap1.content_digest
        assert snap1.entity_count == 1

        # Now simulate subsequent investigation activity (adding new entities & observations)
        ent2, _ = evidence_repo.get_or_create_entity(EntityType.IPV4, "93.184.215.14")
        rel, _ = evidence_repo.create_relationship(
            source_entity_id=ent1.id,
            target_entity_id=ent2.id,
            relationship_type=RelationshipType.RESOLVES_TO,
        )
        obs2 = evidence_repo.record_observation(
            entity_id=ent2.id,
            investigation_id=inv.id,
            collector_name="mock_dns",
            collector_version="0.1.0",
            source_reference="mock://dns",
            observed_at=datetime.now(UTC),
            data={"status": "second_run"},
        )
        evidence_repo.link_evidence(rel.id, obs2.id)

        # Snapshot 2: captured with 2 entities, 1 relationship, 2 observations
        snap2 = evidence_repo.create_snapshot(inv.id, label="Snapshot 2")
        assert snap2.entity_count == 2
        assert snap2.relationship_count == 1
        assert snap2.content_digest != initial_digest

        # IMMUTABILITY INVARIANT: Re-fetch Snapshot 1 and verify it was NOT mutated
        snap1_refetched = evidence_repo.get_snapshot(snap1.id)
        assert snap1_refetched.entity_count == 1
        assert snap1_refetched.relationship_count == 0
        assert snap1_refetched.observation_count == 1
        assert snap1_refetched.content_digest == initial_digest
        assert len(snap1_refetched.data.entities) == 1
        assert snap1_refetched.data.entities[0].normalized_value == "example.com"

    def test_snapshot_integrity_verification_and_tamper_detection(
        self, evidence_repo, test_session_factory
    ):
        """Repository verify_snapshot_integrity returns True normally, False if tampered in DB."""
        inv = evidence_repo.create_investigation("Integrity Inv")
        ent, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "target.org")
        evidence_repo.record_observation(
            entity_id=ent.id,
            investigation_id=inv.id,
            collector_name="mock_dns",
            collector_version="0.1.0",
            source_reference="mock://dns",
            observed_at=datetime.now(UTC),
            data={"a": 1},
        )

        snap = evidence_repo.create_snapshot(inv.id)
        assert evidence_repo.verify_snapshot_integrity(snap.id) is True

        # Tamper directly in SQLite table
        with session_scope(test_session_factory) as session:
            session.execute(
                text(
                    "UPDATE snapshots SET snapshot_data = '{\"tampered\": true}' "
                    "WHERE id = :id;"
                ),
                {"id": snap.id},
            )

        # Integrity check should detect tampering
        assert evidence_repo.verify_snapshot_integrity(snap.id) is False

    def test_cascade_deletion_with_investigation(self, evidence_repo, test_session_factory):
        """Deleting an investigation cascades and removes all associated snapshots."""
        from tracegraph.storage.schema import InvestigationRecord

        inv = evidence_repo.create_investigation("Cascade Test")
        snap = evidence_repo.create_snapshot(inv.id, label="Will be deleted")

        # Delete investigation
        with session_scope(test_session_factory) as session:
            rec = session.get(InvestigationRecord, inv.id)
            session.delete(rec)

        with pytest.raises(NotFoundError):
            evidence_repo.get_snapshot(snap.id)

    def test_multi_investigation_evidence_isolation(self, evidence_repo):
        """Relationship supporting evidence in a snapshot must never leak foreign observations."""
        inv1 = evidence_repo.create_investigation("Investigation Alpha")
        inv2 = evidence_repo.create_investigation("Investigation Beta")

        ent_domain, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "target.corp")
        ent_ip, _ = evidence_repo.get_or_create_entity(EntityType.IPV4, "198.51.100.1")
        rel, _ = evidence_repo.create_relationship(
            source_entity_id=ent_domain.id,
            target_entity_id=ent_ip.id,
            relationship_type=RelationshipType.RESOLVES_TO,
        )

        # Investigation 1 records observation 1
        obs1 = evidence_repo.record_observation(
            entity_id=ent_domain.id,
            investigation_id=inv1.id,
            collector_name="dns",
            collector_version="1.0.0",
            source_reference="dns://alpha",
            observed_at=datetime.now(UTC),
            data={"ip": "198.51.100.1"},
        )
        evidence_repo.link_evidence(rel.id, obs1.id)

        # Investigation 2 records observation 2 for the same global relationship
        obs2 = evidence_repo.record_observation(
            entity_id=ent_domain.id,
            investigation_id=inv2.id,
            collector_name="dns",
            collector_version="1.0.0",
            source_reference="dns://beta",
            observed_at=datetime.now(UTC),
            data={"ip": "198.51.100.1"},
        )
        evidence_repo.link_evidence(rel.id, obs2.id)

        # Capture snapshot for Investigation 1
        snap1_a = evidence_repo.create_snapshot(inv1.id, label="Inv1 Baseline")
        assert len(snap1_a.data.observations) == 1
        assert snap1_a.data.observations[0].id == obs1.id
        assert len(snap1_a.data.relationships) == 1
        # Invariant: Supporting observation IDs must contain ONLY obs1, NOT obs2
        assert snap1_a.data.relationships[0].supporting_observation_ids == [obs1.id]
        assert obs2.id not in snap1_a.data.relationships[0].supporting_observation_ids

        # Now simulate subsequent activity in Investigation 2
        obs3 = evidence_repo.record_observation(
            entity_id=ent_domain.id,
            investigation_id=inv2.id,
            collector_name="rdap",
            collector_version="1.0.0",
            source_reference="rdap://beta",
            observed_at=datetime.now(UTC),
            data={"extra": "data"},
        )
        evidence_repo.link_evidence(rel.id, obs3.id)

        # Capture second snapshot for Investigation 1
        snap1_b = evidence_repo.create_snapshot(inv1.id, label="Inv1 Recheck")
        assert snap1_b.data.relationships[0].supporting_observation_ids == [obs1.id]

        # Diff between Inv1 snapshots must show ZERO changes (Inv2 activity has zero effect on Inv1)
        diff_res = diff_snapshots(snap1_a, snap1_b)
        assert diff_res.summary.total_changes == 0
        assert diff_res.is_identical is True

    def test_asn_and_certificate_round_trip_parity_and_zero_diff(self, evidence_repo):
        """Preserve canonical casing for ASN and Certificate fingerprints in snapshots."""
        inv = evidence_repo.create_investigation("Hardware & Cert Audit")
        asn_ent, _ = evidence_repo.get_or_create_entity(EntityType.ASN, "AS15169")
        cert_ent, _ = evidence_repo.get_or_create_entity(EntityType.CERTIFICATE, "AABBCCDDEEFF")

        evidence_repo.record_observation(
            entity_id=asn_ent.id,
            investigation_id=inv.id,
            collector_name="bgp",
            collector_version="1.0",
            source_reference="bgp://asn",
            observed_at=datetime.now(UTC),
            data={"asn": "AS15169"},
        )
        evidence_repo.record_observation(
            entity_id=cert_ent.id,
            investigation_id=inv.id,
            collector_name="tls",
            collector_version="1.0",
            source_reference="tls://cert",
            observed_at=datetime.now(UTC),
            data={"fingerprint": "AABBCCDDEEFF"},
        )

        snap_created = evidence_repo.create_snapshot(inv.id, label="Parity Test")
        snap_fetched = evidence_repo.get_snapshot(snap_created.id)

        # Check in-memory vs fetched casing parity
        norm_values_created = {
            e.entity_type: e.normalized_value for e in snap_created.data.entities
        }
        norm_values_fetched = {
            e.entity_type: e.normalized_value for e in snap_fetched.data.entities
        }

        assert norm_values_created[EntityType.ASN] == "AS15169"
        assert norm_values_fetched[EntityType.ASN] == "AS15169"
        assert norm_values_created[EntityType.CERTIFICATE] == "AABBCCDDEEFF"
        assert norm_values_fetched[EntityType.CERTIFICATE] == "AABBCCDDEEFF"

        # Diffing created against fetched MUST produce 0 changes
        diff = diff_snapshots(snap_created, snap_fetched)
        assert diff.summary.total_changes == 0
        assert diff.is_identical is True

        # Digest integrity verified
        assert evidence_repo.verify_snapshot_integrity(snap_created.id) is True
        assert evidence_repo.verify_snapshot_integrity(snap_fetched.id) is True

    def test_snapshot_id_prefix_resolution(self, evidence_repo, test_session_factory):
        """Snapshot retrieval resolves unique prefixes of at least 8 characters."""
        inv = evidence_repo.create_investigation("Prefix Resolution Test")
        snap = evidence_repo.create_snapshot(inv.id, label="Prefix Test Snap")

        # 1. Full UUID lookup works
        full_res = evidence_repo.get_snapshot(snap.id)
        assert full_res.id == snap.id

        # 2. 8-character unique prefix works
        prefix_8 = snap.id[:8]
        p8_res = evidence_repo.get_snapshot(prefix_8)
        assert p8_res.id == snap.id

        # 3. 12-character unique prefix works
        prefix_12 = snap.id[:12]
        p12_res = evidence_repo.get_snapshot(prefix_12)
        assert p12_res.id == snap.id

        # 4. Prefix shorter than 8 characters is rejected with NotFoundError
        with pytest.raises(NotFoundError):
            evidence_repo.get_snapshot(snap.id[:7])

        # 5. Non-existent prefix raises NotFoundError
        with pytest.raises(NotFoundError):
            evidence_repo.get_snapshot("ffffffff-ffff")

        # 6. Ambiguous prefix matching multiple snapshots raises AmbiguousSnapshotError
        # Insert two colliding records with identical 8-character prefixes
        col1_id = "11112222-aaaa-4000-8000-000000000001"
        col2_id = "11112222-bbbb-4000-8000-000000000002"
        now = datetime.now(UTC)
        with session_scope(test_session_factory) as session:
            session.add(
                SnapshotRecord(
                    id=col1_id,
                    investigation_id=inv.id,
                    schema_version="3.0.0",
                    created_at=now,
                    content_digest="d" * 64,
                    snapshot_data={"investigation_id": inv.id},
                )
            )
            session.add(
                SnapshotRecord(
                    id=col2_id,
                    investigation_id=inv.id,
                    schema_version="3.0.0",
                    created_at=now,
                    content_digest="d" * 64,
                    snapshot_data={"investigation_id": inv.id},
                )
            )

        with pytest.raises(AmbiguousSnapshotError) as exc_info:
            evidence_repo.get_snapshot("11112222")
        assert "ambiguous" in str(exc_info.value).lower()
