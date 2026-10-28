"""TraceGraph snapshot and temporal diff subpackage."""

from tracegraph.snapshots.canonical import (
    canonicalize_data_dict,
    canonicalize_entity,
    canonicalize_evidence_link,
    canonicalize_observation,
    canonicalize_relationship,
    canonicalize_snapshot_content,
    compute_content_digest,
    normalize_iso_timestamp,
    serialize_canonical_json,
    verify_snapshot_integrity,
)
from tracegraph.snapshots.engine import diff_snapshots
from tracegraph.snapshots.exporter import (
    format_diff_console,
    format_diff_json,
    format_diff_markdown,
)
from tracegraph.snapshots.models import (
    ChangeCategory,
    ChangeType,
    DiffChange,
    DiffSummary,
    SnapshotBaseModel,
    SnapshotContent,
    SnapshotDiffResult,
    SnapshotEntityModel,
    SnapshotEvidenceLinkModel,
    SnapshotModel,
    SnapshotObservationModel,
    SnapshotRelationshipModel,
)

__all__ = [
    "ChangeCategory",
    "ChangeType",
    "DiffChange",
    "DiffSummary",
    "SnapshotBaseModel",
    "SnapshotContent",
    "SnapshotDiffResult",
    "SnapshotEntityModel",
    "SnapshotEvidenceLinkModel",
    "SnapshotModel",
    "SnapshotObservationModel",
    "SnapshotRelationshipModel",
    "canonicalize_data_dict",
    "canonicalize_entity",
    "canonicalize_evidence_link",
    "canonicalize_observation",
    "canonicalize_relationship",
    "canonicalize_snapshot_content",
    "compute_content_digest",
    "diff_snapshots",
    "format_diff_console",
    "format_diff_json",
    "format_diff_markdown",
    "normalize_iso_timestamp",
    "serialize_canonical_json",
    "verify_snapshot_integrity",
]
