"""SQLAlchemy declarative schema for TraceGraph evidence graph and metadata."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
)
from sqlalchemy.orm import (
    relationship as orm_relationship,
)


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy entities."""


class MetadataRecord(Base):
    """Key-value storage for workspace settings and schema version."""

    __tablename__ = "metadata"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class InvestigationRecord(Base):
    """Scope boundary for investigations."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    config_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )


class EntityRecord(Base):
    """Infrastructure node (domain, IP, ASN, etc.) with uniqueness guarantees."""

    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    raw_value: Mapped[str] = mapped_column(String(1024), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    observations: Mapped[list["ObservationRecord"]] = orm_relationship(
        "ObservationRecord", back_populates="entity", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("entity_type", "normalized_value", name="uq_entity_type_normalized_value"),
        Index("idx_entity_type_normalized", "entity_type", "normalized_value"),
    )


class ObservationRecord(Base):
    """Discrete evidence collected at a verified time from an identified collector."""

    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entity_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    collector_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    collector_version: Mapped[str] = mapped_column(String(50), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(1024), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    error_details: Mapped[dict[str, Any] | str | None] = mapped_column(JSON, nullable=True)

    entity: Mapped["EntityRecord"] = orm_relationship("EntityRecord", back_populates="observations")
    evidence_links: Mapped[list["RelationshipEvidenceRecord"]] = orm_relationship(
        "RelationshipEvidenceRecord", back_populates="observation", cascade="all, delete-orphan"
    )


class RelationshipRecord(Base):
    """Directional edge between two entities."""

    __tablename__ = "relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_entity_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_entity_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    evidence_links: Mapped[list["RelationshipEvidenceRecord"]] = orm_relationship(
        "RelationshipEvidenceRecord", back_populates="relationship", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "source_entity_id",
            "target_entity_id",
            "relationship_type",
            name="uq_rel_source_target_type",
        ),
    )


class RelationshipEvidenceRecord(Base):
    """Join table linking a Relationship to its supporting Observation evidence."""

    __tablename__ = "relationship_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    relationship_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("relationships.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    observation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("observations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    relationship: Mapped["RelationshipRecord"] = orm_relationship(
        "RelationshipRecord", back_populates="evidence_links"
    )
    observation: Mapped["ObservationRecord"] = orm_relationship(
        "ObservationRecord", back_populates="evidence_links"
    )

    __table_args__ = (
        UniqueConstraint("relationship_id", "observation_id", name="uq_relationship_observation"),
    )
