"""Pydantic data models for TraceGraph snapshots, canonical state, and diff records."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class ChangeCategory(StrEnum):
    """Category of infrastructure or evidence component experiencing change."""

    ENTITY = "ENTITY"
    RELATIONSHIP = "RELATIONSHIP"
    OBSERVATION = "OBSERVATION"
    EVIDENCE = "EVIDENCE"


class ChangeType(StrEnum):
    """Classification of change between two snapshots.

    Distinguishes observed absence from proof of entity deletion.
    """

    ADDED = "ADDED"
    UNOBSERVED = "UNOBSERVED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"


class SnapshotBaseModel(BaseModel):
    """Base model with standard TraceGraph configuration."""

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="forbid",
    )


class SnapshotEntityModel(SnapshotBaseModel):
    """Captured state of an infrastructure entity."""

    id: str
    entity_type: EntityType
    raw_value: str
    normalized_value: str
    created_at: str


class SnapshotRelationshipModel(SnapshotBaseModel):
    """Captured state of a directional relationship with supporting evidence IDs."""

    id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: RelationshipType
    source_normalized_value: str
    source_entity_type: str
    target_normalized_value: str
    target_entity_type: str
    created_at: str
    supporting_observation_ids: list[str] = Field(default_factory=list)


class SnapshotObservationModel(SnapshotBaseModel):
    """Captured state of a discrete observation."""

    id: str
    entity_id: str
    collector_name: str
    collector_version: str
    source_reference: str
    observed_at: str
    ingested_at: str
    status: CollectionStatus
    data: dict[str, Any] = Field(default_factory=dict)
    error_details: Any | None = None


class SnapshotEvidenceLinkModel(SnapshotBaseModel):
    """Captured state of an explicit relationship-observation evidence link."""

    id: str
    relationship_id: str
    observation_id: str
    created_at: str
    notes: str | None = None


class SnapshotContent(SnapshotBaseModel):
    """Structured representation of an investigation's evidence graph at snapshot time."""

    investigation_id: str
    investigation_name: str
    target_scope: str = ""
    entities: list[SnapshotEntityModel] = Field(default_factory=list)
    relationships: list[SnapshotRelationshipModel] = Field(default_factory=list)
    observations: list[SnapshotObservationModel] = Field(default_factory=list)
    evidence_links: list[SnapshotEvidenceLinkModel] = Field(default_factory=list)


class SnapshotModel(SnapshotBaseModel):
    """Complete snapshot record with metadata and SHA-256 content digest."""

    id: str
    investigation_id: str
    label: str | None = None
    schema_version: str = "3.0.0"
    created_at: datetime = Field(default_factory=utc_now)
    content_digest: str
    entity_count: int = 0
    relationship_count: int = 0
    observation_count: int = 0
    data: SnapshotContent

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


class DiffChange(SnapshotBaseModel):
    """Individual atomic change detected between two snapshots."""

    category: ChangeCategory
    change_type: ChangeType
    identifier: str
    previous_value: Any | None = None
    current_value: Any | None = None
    evidence_references: list[str] = Field(default_factory=list)
    explanation: str


class DiffSummary(SnapshotBaseModel):
    """Aggregate statistics for snapshot diff."""

    total_changes: int = 0
    added_entities: int = 0
    unobserved_entities: int = 0
    modified_entities: int = 0
    added_relationships: int = 0
    removed_relationships: int = 0
    modified_evidence: int = 0
    new_observations: int = 0
    collector_failures: int = 0


class SnapshotDiffResult(SnapshotBaseModel):
    """Complete diff result between two snapshots of the same investigation."""

    investigation_id: str
    investigation_name: str
    snapshot_a_id: str
    snapshot_a_label: str | None = None
    snapshot_a_created_at: datetime
    snapshot_a_digest: str
    snapshot_b_id: str
    snapshot_b_label: str | None = None
    snapshot_b_created_at: datetime
    snapshot_b_digest: str
    summary: DiffSummary
    changes: list[DiffChange] = Field(default_factory=list)
    has_collector_failures: bool = False
    collector_failure_warnings: list[str] = Field(default_factory=list)

    @property
    def is_identical(self) -> bool:
        """True if snapshots have identical logical state (0 changes)."""
        return self.summary.total_changes == 0
