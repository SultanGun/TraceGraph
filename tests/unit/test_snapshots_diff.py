"""Unit tests for the snapshot diff engine, change detection, and invariant rules."""

import copy

import pytest

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import CrossInvestigationDiffError
from tracegraph.snapshots.canonical import compute_content_digest
from tracegraph.snapshots.engine import diff_snapshots
from tracegraph.snapshots.models import (
    ChangeCategory,
    ChangeType,
    SnapshotContent,
    SnapshotEntityModel,
    SnapshotModel,
    SnapshotObservationModel,
    SnapshotRelationshipModel,
)


def make_snapshot(
    content: SnapshotContent, snap_id: str, label: str | None = None
) -> SnapshotModel:
    digest = compute_content_digest(content)
    return SnapshotModel(
        id=snap_id,
        investigation_id=content.investigation_id,
        label=label,
        content_digest=digest,
        entity_count=len(content.entities),
        relationship_count=len(content.relationships),
        observation_count=len(content.observations),
        data=content,
    )


class TestSnapshotDiffEngine:
    """Tests verifying snapshot diff calculations, change types, and temporal intelligence rules."""

    def test_identical_snapshots_return_zero_changes(self):
        """Comparing two identical snapshots must report is_identical=True and 0 changes."""
        content = SnapshotContent(
            investigation_id="inv-100",
            investigation_name="Baseline",
            target_scope="example.com",
            entities=[
                SnapshotEntityModel(
                    id="e1",
                    entity_type=EntityType.DOMAIN,
                    raw_value="example.com",
                    normalized_value="example.com",
                    created_at="2026-10-27T10:00:00Z",
                )
            ],
            relationships=[],
            observations=[],
            evidence_links=[],
        )
        snap_a = make_snapshot(content, "snap-a", "Baseline")
        snap_b = make_snapshot(content, "snap-b", "Target")

        diff = diff_snapshots(snap_a, snap_b)
        assert diff.is_identical is True
        assert diff.summary.total_changes == 0
        assert len(diff.changes) == 0

    def test_cross_investigation_comparison_rejected(self):
        """Diffing snapshots from different investigations raises CrossInvestigationDiffError."""
        content_a = SnapshotContent(
            investigation_id="inv-AAA",
            investigation_name="Investigation Alpha",
            target_scope="a.com",
        )
        content_b = SnapshotContent(
            investigation_id="inv-BBB",
            investigation_name="Investigation Beta",
            target_scope="b.com",
        )
        snap_a = make_snapshot(content_a, "snap-a")
        snap_b = make_snapshot(content_b, "snap-b")

        with pytest.raises(CrossInvestigationDiffError, match="different investigations"):
            diff_snapshots(snap_a, snap_b)

    def test_added_and_unobserved_entities_detected(self):
        """Entities present in B not A are ADDED; entities in A not B are UNOBSERVED."""
        e1 = SnapshotEntityModel(
            id="e1",
            entity_type=EntityType.DOMAIN,
            raw_value="example.com",
            normalized_value="example.com",
            created_at="2026-10-27T10:00:00Z",
        )
        e2_ip = SnapshotEntityModel(
            id="e2",
            entity_type=EntityType.IPV4,
            raw_value="93.184.215.14",
            normalized_value="93.184.215.14",
            created_at="2026-10-27T10:00:00Z",
        )
        e3_new = SnapshotEntityModel(
            id="e3",
            entity_type=EntityType.IPV6,
            raw_value="2606:2800:220:1:248:1893:25c8:1946",
            normalized_value="2606:2800:220:1:248:1893:25c8:1946",
            created_at="2026-10-27T11:00:00Z",
        )

        content_a = SnapshotContent(
            investigation_id="inv-1",
            investigation_name="Infra Monitor",
            entities=[e1, e2_ip],
        )
        # Snapshot B dropped e2_ip, kept e1, added e3_new
        content_b = SnapshotContent(
            investigation_id="inv-1",
            investigation_name="Infra Monitor",
            entities=[e1, e3_new],
        )

        snap_a = make_snapshot(content_a, "snap-a")
        snap_b = make_snapshot(content_b, "snap-b")

        diff = diff_snapshots(snap_a, snap_b)

        assert diff.summary.added_entities == 1
        assert diff.summary.unobserved_entities == 1

        added_changes = [c for c in diff.changes if c.change_type == ChangeType.ADDED]
        assert len(added_changes) == 1
        assert "2606:2800" in added_changes[0].identifier

        unobs_changes = [c for c in diff.changes if c.change_type == ChangeType.UNOBSERVED]
        assert len(unobs_changes) == 1
        assert "93.184.215.14" in unobs_changes[0].identifier
        # Crucial requirement: explanation must distinguish unobserved from decommissioning proof
        assert "does not imply infrastructure decommissioning" in unobs_changes[0].explanation

    def test_relationship_changes_and_evidence_updates(self):
        """Added, removed, and evidence-modified relationships must be categorized accurately."""
        e_dom = SnapshotEntityModel(
            id="e1",
            entity_type=EntityType.DOMAIN,
            raw_value="example.com",
            normalized_value="example.com",
            created_at="2026-10-27T10:00:00Z",
        )
        e_ip1 = SnapshotEntityModel(
            id="e2",
            entity_type=EntityType.IPV4,
            raw_value="93.184.215.14",
            normalized_value="93.184.215.14",
            created_at="2026-10-27T10:00:00Z",
        )
        e_ip2 = SnapshotEntityModel(
            id="e3",
            entity_type=EntityType.IPV4,
            raw_value="93.184.215.15",
            normalized_value="93.184.215.15",
            created_at="2026-10-27T10:00:00Z",
        )

        r_baseline = SnapshotRelationshipModel(
            id="r1",
            source_entity_id="e1",
            target_entity_id="e2",
            relationship_type=RelationshipType.RESOLVES_TO,
            source_normalized_value="example.com",
            source_entity_type="DOMAIN",
            target_normalized_value="93.184.215.14",
            target_entity_type="IPV4",
            created_at="2026-10-27T10:00:00Z",
            supporting_observation_ids=["obs-1"],
        )

        # In B, r_baseline has an additional observation ("obs-2"), and a new link exists
        r_updated = copy.deepcopy(r_baseline)
        r_updated.supporting_observation_ids = ["obs-1", "obs-2"]

        r_new = SnapshotRelationshipModel(
            id="r2",
            source_entity_id="e1",
            target_entity_id="e3",
            relationship_type=RelationshipType.RESOLVES_TO,
            source_normalized_value="example.com",
            source_entity_type="DOMAIN",
            target_normalized_value="93.184.215.15",
            target_entity_type="IPV4",
            created_at="2026-10-27T11:00:00Z",
            supporting_observation_ids=["obs-2"],
        )

        content_a = SnapshotContent(
            investigation_id="inv-rel",
            investigation_name="Rel Test",
            entities=[e_dom, e_ip1],
            relationships=[r_baseline],
        )
        content_b = SnapshotContent(
            investigation_id="inv-rel",
            investigation_name="Rel Test",
            entities=[e_dom, e_ip1, e_ip2],
            relationships=[r_updated, r_new],
        )

        snap_a = make_snapshot(content_a, "snap-a")
        snap_b = make_snapshot(content_b, "snap-b")

        diff = diff_snapshots(snap_a, snap_b)

        assert diff.summary.added_relationships == 1
        assert diff.summary.modified_evidence == 1

        ev_changes = [c for c in diff.changes if c.category == ChangeCategory.EVIDENCE]
        assert len(ev_changes) == 1
        assert "+1 new observation" in ev_changes[0].explanation

    def test_collector_failure_warning_flags_incompleteness(self):
        """Failed observations in target snapshot must generate warnings about unobserved items."""
        failed_obs = SnapshotObservationModel(
            id="obs-fail-1",
            entity_id="e1",
            collector_name="live_dns",
            collector_version="0.2.0",
            source_reference="udp://1.1.1.1:53",
            observed_at="2026-10-27T12:00:00Z",
            ingested_at="2026-10-27T12:00:01Z",
            status=CollectionStatus.TIMEOUT,
            error_details="Query timed out after 5.0s",
        )

        content_a = SnapshotContent(
            investigation_id="inv-warn",
            investigation_name="Warning Test",
            observations=[],
        )
        content_b = SnapshotContent(
            investigation_id="inv-warn",
            investigation_name="Warning Test",
            observations=[failed_obs],
        )

        snap_a = make_snapshot(content_a, "snap-a")
        snap_b = make_snapshot(content_b, "snap-b")

        diff = diff_snapshots(snap_a, snap_b)
        assert diff.has_collector_failures is True
        assert len(diff.collector_failure_warnings) == 1
        assert "TIMEOUT" in diff.collector_failure_warnings[0]
        assert "collection errors" in diff.collector_failure_warnings[0]
