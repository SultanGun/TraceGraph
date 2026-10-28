"""Snapshot diff engine for TraceGraph evidence graphs."""

import logging

from tracegraph.core.enums import CollectionStatus
from tracegraph.core.exceptions import CrossInvestigationDiffError
from tracegraph.snapshots.models import (
    ChangeCategory,
    ChangeType,
    DiffChange,
    DiffSummary,
    SnapshotDiffResult,
    SnapshotModel,
    SnapshotRelationshipModel,
)

logger = logging.getLogger(__name__)


def diff_snapshots(
    snapshot_a: SnapshotModel,
    snapshot_b: SnapshotModel,
) -> SnapshotDiffResult:
    """Compare two snapshots belonging to the same investigation and detect infrastructure changes.

    Safety & Provenance Guarantees:
    - Strictly rejects cross-investigation snapshot comparisons.
    - Never infers entity deletion solely from collector failure or missing observations.
    - Explicitly flags collector failures that could cause false absence of evidence.
    - Order of elements does not produce false changes.
    """
    if snapshot_a.investigation_id != snapshot_b.investigation_id:
        raise CrossInvestigationDiffError(
            f"Cannot compare snapshots across different investigations: "
            f"'{snapshot_a.investigation_id}' vs '{snapshot_b.investigation_id}'"
        )

    changes: list[DiffChange] = []
    collector_warnings: list[str] = []

    # 1. Collector Failure & Incomplete Data Warnings
    failed_obs_b = [
        o
        for o in snapshot_b.data.observations
        if o.status in (CollectionStatus.FAILED, CollectionStatus.TIMEOUT)
    ]
    for fo in failed_obs_b:
        warn = (
            f"Target snapshot contains collector failure: '{fo.collector_name}' "
            f"against '{fo.source_reference}' (status: {fo.status}). "
            "Unobserved entities or relationships may result from collection errors "
            "rather than real infrastructure decommissioning."
        )
        collector_warnings.append(warn)

    # 2. Entity Differences
    a_ents = {(e.entity_type, e.normalized_value): e for e in snapshot_a.data.entities}
    b_ents = {(e.entity_type, e.normalized_value): e for e in snapshot_b.data.entities}

    all_ent_keys = sorted(set(a_ents.keys()) | set(b_ents.keys()))

    added_entities_cnt = 0
    unobserved_entities_cnt = 0
    modified_entities_cnt = 0

    for key in all_ent_keys:
        e_type, e_norm = key
        ident = f"[{e_type}] {e_norm}"

        if key in b_ents and key not in a_ents:
            b_item = b_ents[key]
            changes.append(
                DiffChange(
                    category=ChangeCategory.ENTITY,
                    change_type=ChangeType.ADDED,
                    identifier=ident,
                    previous_value=None,
                    current_value=b_item.raw_value,
                    explanation=(
                        f"Infrastructure entity '{ident}' observed in target snapshot "
                        "(not present in baseline snapshot)"
                    ),
                )
            )
            added_entities_cnt += 1
        elif key in a_ents and key not in b_ents:
            a_item = a_ents[key]
            changes.append(
                DiffChange(
                    category=ChangeCategory.ENTITY,
                    change_type=ChangeType.UNOBSERVED,
                    identifier=ident,
                    previous_value=a_item.raw_value,
                    current_value=None,
                    explanation=(
                        f"Infrastructure entity '{ident}' recorded in baseline snapshot was "
                        "not observed in target snapshot (unobserved in current collection run; "
                        "does not imply infrastructure decommissioning)"
                    ),
                )
            )
            unobserved_entities_cnt += 1
        else:
            a_item = a_ents[key]
            b_item = b_ents[key]
            if a_item.raw_value != b_item.raw_value:
                changes.append(
                    DiffChange(
                        category=ChangeCategory.ENTITY,
                        change_type=ChangeType.MODIFIED,
                        identifier=ident,
                        previous_value=a_item.raw_value,
                        current_value=b_item.raw_value,
                        explanation=(
                            f"Entity raw representation changed from '{a_item.raw_value}' "
                            f"to '{b_item.raw_value}'"
                        ),
                    )
                )
                modified_entities_cnt += 1

    # 3. Relationship Differences
    def rel_key(r: SnapshotRelationshipModel) -> tuple[str, str, str, str, str]:
        return (
            r.source_entity_type,
            r.source_normalized_value,
            r.relationship_type,
            r.target_entity_type,
            r.target_normalized_value,
        )

    a_rels = {rel_key(r): r for r in snapshot_a.data.relationships}
    b_rels = {rel_key(r): r for r in snapshot_b.data.relationships}

    all_rel_keys = sorted(set(a_rels.keys()) | set(b_rels.keys()))

    added_rels_cnt = 0
    removed_rels_cnt = 0
    modified_ev_cnt = 0

    for r_key in all_rel_keys:
        src_t, src_v, r_type, tgt_t, tgt_v = r_key
        ident = f"[{src_t}] {src_v} --[{r_type}]--> [{tgt_t}] {tgt_v}"

        if r_key in b_rels and r_key not in a_rels:
            b_r = b_rels[r_key]
            changes.append(
                DiffChange(
                    category=ChangeCategory.RELATIONSHIP,
                    change_type=ChangeType.ADDED,
                    identifier=ident,
                    previous_value=None,
                    current_value=(
                        f"Verified by {len(b_r.supporting_observation_ids)} observation(s)"
                    ),
                    evidence_references=b_r.supporting_observation_ids,
                    explanation=(
                        f"New infrastructure relationship '{ident}' discovered and verified"
                    ),
                )
            )
            added_rels_cnt += 1
        elif r_key in a_rels and r_key not in b_rels:
            a_r = a_rels[r_key]
            changes.append(
                DiffChange(
                    category=ChangeCategory.RELATIONSHIP,
                    change_type=ChangeType.REMOVED,
                    identifier=ident,
                    previous_value=(
                        f"Supported by {len(a_r.supporting_observation_ids)} observation(s)"
                    ),
                    current_value=None,
                    evidence_references=a_r.supporting_observation_ids,
                    explanation=(
                        f"Relationship '{ident}' was recorded in baseline snapshot "
                        "but not observed in target snapshot"
                    ),
                )
            )
            removed_rels_cnt += 1
        else:
            a_r = a_rels[r_key]
            b_r = b_rels[r_key]
            a_ev = set(a_r.supporting_observation_ids)
            b_ev = set(b_r.supporting_observation_ids)

            if a_ev != b_ev:
                gained = len(b_ev - a_ev)
                lost = len(a_ev - b_ev)
                changes.append(
                    DiffChange(
                        category=ChangeCategory.EVIDENCE,
                        change_type=ChangeType.MODIFIED,
                        identifier=ident,
                        previous_value=sorted(list(a_ev)),
                        current_value=sorted(list(b_ev)),
                        evidence_references=sorted(list(b_ev)),
                        explanation=(
                            f"Supporting evidence for relationship '{ident}' updated "
                            f"(+{gained} new observation(s), -{lost} prior observation(s))"
                        ),
                    )
                )
                modified_ev_cnt += 1

    # 4. Observation Differences
    a_obs_ids = {o.id for o in snapshot_a.data.observations}
    new_obs_cnt = 0
    for o in snapshot_b.data.observations:
        if o.id not in a_obs_ids:
            changes.append(
                DiffChange(
                    category=ChangeCategory.OBSERVATION,
                    change_type=ChangeType.ADDED,
                    identifier=f"{o.collector_name} ({o.id[:8]})",
                    previous_value=None,
                    current_value=f"Status: {o.status} ({o.source_reference})",
                    evidence_references=[o.id],
                    explanation=(
                        f"New observation collected by {o.collector_name} v{o.collector_version} "
                        f"at {o.observed_at}"
                    ),
                )
            )
            new_obs_cnt += 1

    summary = DiffSummary(
        total_changes=len(changes),
        added_entities=added_entities_cnt,
        unobserved_entities=unobserved_entities_cnt,
        modified_entities=modified_entities_cnt,
        added_relationships=added_rels_cnt,
        removed_relationships=removed_rels_cnt,
        modified_evidence=modified_ev_cnt,
        new_observations=new_obs_cnt,
        collector_failures=len(failed_obs_b),
    )

    return SnapshotDiffResult(
        investigation_id=snapshot_a.investigation_id,
        investigation_name=snapshot_a.data.investigation_name,
        snapshot_a_id=snapshot_a.id,
        snapshot_a_label=snapshot_a.label,
        snapshot_a_created_at=snapshot_a.created_at,
        snapshot_a_digest=snapshot_a.content_digest,
        snapshot_b_id=snapshot_b.id,
        snapshot_b_label=snapshot_b.label,
        snapshot_b_created_at=snapshot_b.created_at,
        snapshot_b_digest=snapshot_b.content_digest,
        summary=summary,
        changes=changes,
        has_collector_failures=bool(failed_obs_b),
        collector_failure_warnings=collector_warnings,
    )
