"""Tests for deterministic snapshot canonicalization, digest stability, and tamper detection."""

import copy

from tracegraph.snapshots.canonical import (
    canonicalize_snapshot_content,
    compute_content_digest,
    normalize_iso_timestamp,
    serialize_canonical_json,
    verify_snapshot_integrity,
)
from tracegraph.snapshots.models import (
    SnapshotContent,
    SnapshotEntityModel,
    SnapshotEvidenceLinkModel,
    SnapshotModel,
    SnapshotObservationModel,
    SnapshotRelationshipModel,
)


def create_sample_content(reverse_order: bool = False) -> SnapshotContent:
    """Build a deterministic sample snapshot content with multiple entities and relationships."""
    e1 = SnapshotEntityModel(
        id="ent-1",
        entity_type="DOMAIN",
        raw_value="example.com",
        normalized_value="example.com",
        created_at="2026-10-27T10:00:00Z",
    )
    e2 = SnapshotEntityModel(
        id="ent-2",
        entity_type="IPV4",
        raw_value="93.184.215.14",
        normalized_value="93.184.215.14",
        created_at="2026-10-27T10:01:00Z",
    )
    e3 = SnapshotEntityModel(
        id="ent-3",
        entity_type="DOMAIN",
        raw_value="sub.example.com",
        normalized_value="sub.example.com",
        created_at="2026-10-27T10:02:00Z",
    )

    r1 = SnapshotRelationshipModel(
        id="rel-1",
        source_entity_id="ent-1",
        target_entity_id="ent-2",
        relationship_type="RESOLVES_TO",
        source_normalized_value="example.com",
        source_entity_type="DOMAIN",
        target_normalized_value="93.184.215.14",
        target_entity_type="IPV4",
        created_at="2026-10-27T10:05:00Z",
        supporting_observation_ids=["obs-2", "obs-1"],
    )
    r2 = SnapshotRelationshipModel(
        id="rel-2",
        source_entity_id="ent-3",
        target_entity_id="ent-1",
        relationship_type="SUBDOMAIN_OF",
        source_normalized_value="sub.example.com",
        source_entity_type="DOMAIN",
        target_normalized_value="example.com",
        target_entity_type="DOMAIN",
        created_at="2026-10-27T10:06:00Z",
        supporting_observation_ids=["obs-1"],
    )

    o1 = SnapshotObservationModel(
        id="obs-1",
        entity_id="ent-1",
        collector_name="live_dns",
        collector_version="0.2.0",
        source_reference="udp://8.8.8.8:53",
        observed_at="2026-10-27T10:03:00Z",
        ingested_at="2026-10-27T10:04:00Z",
        status="SUCCESS",
        data={"query": "example.com", "answers": ["93.184.215.14"]},
    )
    o2 = SnapshotObservationModel(
        id="obs-2",
        entity_id="ent-2",
        collector_name="rdap",
        collector_version="0.2.0",
        source_reference="https://rdap.arin.net/registry/ip/93.184.215.14",
        observed_at="2026-10-27T10:04:30Z",
        ingested_at="2026-10-27T10:04:45Z",
        status="SUCCESS",
        data={"handle": "NET-93-184-215-0-1", "name": "EDGECAST-NET"},
    )

    l1 = SnapshotEvidenceLinkModel(
        id="link-1",
        relationship_id="rel-1",
        observation_id="obs-1",
        created_at="2026-10-27T10:07:00Z",
    )
    l2 = SnapshotEvidenceLinkModel(
        id="link-2",
        relationship_id="rel-1",
        observation_id="obs-2",
        created_at="2026-10-27T10:07:10Z",
    )

    entities = [e3, e2, e1] if reverse_order else [e1, e2, e3]
    relationships = [r2, r1] if reverse_order else [r1, r2]
    observations = [o2, o1] if reverse_order else [o1, o2]
    links = [l2, l1] if reverse_order else [l1, l2]

    return SnapshotContent(
        investigation_id="inv-sample-123",
        investigation_name="Sample Intelligence Target",
        target_scope="example.com",
        entities=entities,
        relationships=relationships,
        observations=observations,
        evidence_links=links,
    )


class TestSnapshotCanonicalization:
    """Tests verifying deterministic canonical representation and digest computation."""

    def test_digest_stability_regardless_of_list_order(self):
        """Identical content in different collection orders must yield identical SHA-256."""
        content_a = create_sample_content(reverse_order=False)
        content_b = create_sample_content(reverse_order=True)

        digest_a = compute_content_digest(content_a)
        digest_b = compute_content_digest(content_b)

        assert digest_a == digest_b
        assert len(digest_a) == 64

    def test_canonical_json_serialization_is_compact_and_sorted(self):
        """Canonical JSON must sort dictionary keys and eliminate insignificant whitespace."""
        content = create_sample_content()
        canon_dict = canonicalize_snapshot_content(content)
        json_str = serialize_canonical_json(canon_dict)

        # Compact format: no whitespace after colons or commas
        assert ": " not in json_str
        assert ", " not in json_str
        assert '"investigation_id":"inv-sample-123"' in json_str

    def test_timestamp_normalization(self):
        """Timestamps in various valid formats must normalize to uniform UTC ISO strings."""
        assert normalize_iso_timestamp("2026-10-27T10:00:00+00:00") == "2026-10-27T10:00:00Z"
        assert normalize_iso_timestamp("2026-10-27T10:00:00Z") == "2026-10-27T10:00:00Z"
        assert normalize_iso_timestamp("2026-10-27 10:00:00") == "2026-10-27T10:00:00Z"

    def test_tamper_detection(self):
        """Modifying any field in snapshot payload must fail integrity verification."""
        content = create_sample_content()
        digest = compute_content_digest(content)

        snapshot = SnapshotModel(
            id="snap-test-1",
            investigation_id=content.investigation_id,
            label="Original Baseline",
            content_digest=digest,
            entity_count=len(content.entities),
            relationship_count=len(content.relationships),
            observation_count=len(content.observations),
            data=content,
        )

        assert verify_snapshot_integrity(snapshot) is True

        # Tamper 1: modify an entity raw_value
        tampered_content = copy.deepcopy(content)
        tampered_content.entities[0].raw_value = "attacker-domain.org"
        tampered_snap = SnapshotModel(
            id=snapshot.id,
            investigation_id=snapshot.investigation_id,
            content_digest=snapshot.content_digest,
            data=tampered_content,
        )
        assert verify_snapshot_integrity(tampered_snap) is False

        # Tamper 2: modify observation payload
        tampered_content2 = copy.deepcopy(content)
        tampered_content2.observations[0].data["injected"] = "malicious_entry"
        tampered_snap2 = SnapshotModel(
            id=snapshot.id,
            investigation_id=snapshot.investigation_id,
            content_digest=snapshot.content_digest,
            data=tampered_content2,
        )
        assert verify_snapshot_integrity(tampered_snap2) is False

    def test_empty_snapshot_content_has_deterministic_digest(self):
        """An empty investigation snapshot must serialize and compute a consistent digest."""
        empty_content = SnapshotContent(
            investigation_id="inv-empty",
            investigation_name="Empty Scope",
            target_scope="",
            entities=[],
            relationships=[],
            observations=[],
            evidence_links=[],
        )
        digest1 = compute_content_digest(empty_content)
        digest2 = compute_content_digest(empty_content)
        assert digest1 == digest2
        assert len(digest1) == 64

    def test_asn_and_certificate_casing_preserved(self):
        """ASN and Certificate fingerprint normalized values must preserve canonical uppercase."""
        content = SnapshotContent(
            investigation_id="inv-case-test",
            investigation_name="Casing Scope",
            target_scope="*",
            entities=[
                SnapshotEntityModel(
                    id="e-asn",
                    entity_type="ASN",
                    raw_value="as15169",
                    normalized_value="AS15169",
                    created_at="2026-10-27T10:00:00Z",
                ),
                SnapshotEntityModel(
                    id="e-cert",
                    entity_type="CERTIFICATE",
                    raw_value="aa:bb:cc:dd",
                    normalized_value="AABBCCDD",
                    created_at="2026-10-27T10:00:00Z",
                ),
            ],
            relationships=[],
            observations=[],
            evidence_links=[],
        )
        canon = canonicalize_snapshot_content(content)
        ents = {e["entity_type"]: e["normalized_value"] for e in canon["entities"]}
        assert ents["ASN"] == "AS15169"
        assert ents["CERTIFICATE"] == "AABBCCDD"

    def test_nested_datetime_in_observation_data_is_canonicalized(self):
        """Nested datetime objects within observation data dictionaries must serialize cleanly."""
        from datetime import UTC, datetime

        sample_dt = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
        content = SnapshotContent(
            investigation_id="inv-dt",
            investigation_name="Datetime Scope",
            target_scope="*",
            entities=[],
            relationships=[],
            observations=[
                SnapshotObservationModel(
                    id="obs-dt",
                    entity_id="ent-1",
                    collector_name="live_dns",
                    collector_version="0.2.0",
                    source_reference="dns://test",
                    observed_at="2026-10-27T12:00:00Z",
                    ingested_at="2026-10-27T12:00:00Z",
                    status="SUCCESS",
                    data={"scanned_at": sample_dt, "nested": {"event_time": sample_dt}},
                )
            ],
            evidence_links=[],
        )
        digest = compute_content_digest(content)
        assert len(digest) == 64
        canon = canonicalize_snapshot_content(content)
        assert canon["observations"][0]["data"]["scanned_at"] == "2026-10-27T12:00:00Z"
        assert canon["observations"][0]["data"]["nested"]["event_time"] == "2026-10-27T12:00:00Z"
