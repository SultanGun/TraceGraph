"""Validated Pydantic data models for TraceGraph OSINT evidence graph."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.normalizers import normalize_entity_value


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


def generate_uuid() -> str:
    """Generate RFC 4122 UUID4 string."""
    return str(uuid.uuid4())


class TraceGraphBaseModel(BaseModel):
    """Base model with standard configuration."""

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="forbid",
    )


class InvestigationModel(TraceGraphBaseModel):
    """Investigation boundary tracking configuration, goals, and metadata."""

    id: str = Field(default_factory=generate_uuid, description="Unique UUID for investigation")
    name: str = Field(..., min_length=1, max_length=255, description="Investigation title or name")
    description: str | None = Field(default=None, description="Detailed scope or objective")
    target_scope: str = Field(
        default="", description="Declared target scope (domain, CIDR, or comma-separated targets)"
    )
    created_at: datetime = Field(
        default_factory=utc_now, description="Investigation creation timestamp in UTC"
    )
    config_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Execution parameters, target scopes, or tags"
    )

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


class EntityModel(TraceGraphBaseModel):
    """Distinct infrastructure artifact (e.g. domain, IP address, autonomous system)."""

    id: str = Field(default_factory=generate_uuid, description="Unique UUID for entity")
    entity_type: EntityType = Field(..., description="Classification of infrastructure node")
    raw_value: str = Field(..., min_length=1, max_length=1024, description="Original input value")
    normalized_value: str = Field(
        default="", description="Canonicalized and normalized value to prevent duplicates"
    )
    created_at: datetime = Field(
        default_factory=utc_now, description="Entity registration timestamp in UTC"
    )

    @model_validator(mode="after")
    def populate_and_validate_normalized_value(self) -> "EntityModel":
        # If normalized_value was not provided or needs canonical check, normalize raw_value
        expected = normalize_entity_value(self.entity_type, self.raw_value)
        if not self.normalized_value:
            self.normalized_value = expected
        elif self.normalized_value != expected:
            # Re-normalize if raw_value differs or ensure correctness
            self.normalized_value = expected
        return self

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


class ObservationModel(TraceGraphBaseModel):
    """Factual observation collected by an identified collector at a specific point in time.

    Temporal Intelligence Distinction:
    - `observed_at`: The exact UTC timestamp when remote/synthetic evidence was collected.
    - `ingested_at`: The exact UTC timestamp when evidence was recorded into local storage.
    """

    id: str = Field(default_factory=generate_uuid, description="Unique UUID for observation")
    entity_id: str = Field(..., min_length=1, description="Target entity UUID")
    investigation_id: str | None = Field(
        default=None, description="Associated investigation UUID for this observation"
    )
    collector_name: str = Field(
        ..., min_length=1, max_length=100, description="Unique name of collector"
    )
    collector_version: str = Field(
        ..., min_length=1, max_length=50, description="Semver version of collector"
    )
    source_reference: str = Field(
        ..., min_length=1, max_length=1024, description="Origin provenance (URI, path, or fixture)"
    )
    observed_at: datetime = Field(
        ..., description="UTC timestamp when the observation occurred at the source"
    )
    ingested_at: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when the observation was stored locally",
    )
    data: dict[str, Any] = Field(
        default_factory=dict, description="Structured observed evidence payload"
    )
    status: CollectionStatus = Field(
        default=CollectionStatus.SUCCESS, description="Outcome of collection execution"
    )
    error_details: dict[str, Any] | str | None = Field(
        default=None, description="Diagnostic error details if collection failed"
    )

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)


class RelationshipModel(TraceGraphBaseModel):
    """Directional association between two infrastructure entities.

    Evidence Provenance Guarantee:
    An unsupported relationship must never be presented as verified.
    `is_verified` is true only when supported by one or more linked Observation records.
    """

    id: str = Field(default_factory=generate_uuid, description="Unique UUID for relationship")
    source_entity_id: str = Field(..., min_length=1, description="Origin entity UUID")
    target_entity_id: str = Field(..., min_length=1, description="Destination entity UUID")
    relationship_type: RelationshipType = Field(
        ..., description="Classification of directional link"
    )
    created_at: datetime = Field(
        default_factory=utc_now, description="Relationship registration timestamp in UTC"
    )
    supporting_observation_ids: list[str] = Field(
        default_factory=list,
        description="List of observation IDs that provide direct evidence for this link",
    )

    @property
    def is_verified(self) -> bool:
        """A relationship is verified if and only if supported by at least one observation."""
        return len(self.supporting_observation_ids) > 0

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)

    @model_validator(mode="after")
    def disallow_self_relationship_unless_allowed(self) -> "RelationshipModel":
        if self.source_entity_id == self.target_entity_id:
            raise ValueError("source_entity_id and target_entity_id cannot be identical")
        return self


class EvidenceLinkModel(TraceGraphBaseModel):
    """Explicit join associating a Relationship with a supporting Observation."""

    id: str = Field(default_factory=generate_uuid, description="Unique UUID for evidence link")
    relationship_id: str = Field(..., min_length=1, description="Associated relationship UUID")
    observation_id: str = Field(..., min_length=1, description="Supporting observation UUID")
    created_at: datetime = Field(
        default_factory=utc_now, description="Evidence association timestamp in UTC"
    )
    notes: str | None = Field(default=None, description="Optional analyst context or extract notes")

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)
