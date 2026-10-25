"""Data access repository for investigations, entities, observations, and verified relationships."""

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import DatabaseIntegrityError, NotFoundError
from tracegraph.core.normalizers import validate_and_normalize
from tracegraph.evidence.models import (
    EntityModel,
    EvidenceLinkModel,
    InvestigationModel,
    ObservationModel,
    RelationshipModel,
    generate_uuid,
)
from tracegraph.storage.database import session_scope
from tracegraph.storage.schema import (
    EntityRecord,
    InvestigationRecord,
    ObservationRecord,
    RelationshipEvidenceRecord,
    RelationshipRecord,
)

logger = logging.getLogger(__name__)


class EvidenceRepository:
    """Repository managing lifecycle of entities, observations, and verified relationships."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory

    # -------------------------------------------------------------------------
    # Investigations
    # -------------------------------------------------------------------------

    def create_investigation(
        self,
        name: str,
        description: str | None = None,
        config_metadata: dict[str, Any] | None = None,
        investigation_id: str | None = None,
    ) -> InvestigationModel:
        """Create a new investigation scope."""
        inv_id = investigation_id or generate_uuid()
        meta = config_metadata or {}
        model = InvestigationModel(
            id=inv_id,
            name=name,
            description=description,
            created_at=datetime.now(UTC),
            config_metadata=meta,
        )

        with session_scope(self.session_factory) as session:
            record = InvestigationRecord(
                id=model.id,
                name=model.name,
                description=model.description,
                created_at=model.created_at,
                config_metadata=model.config_metadata,
            )
            session.add(record)

        return model

    def get_investigation(self, investigation_id: str) -> InvestigationModel:
        """Retrieve an investigation by ID."""
        with session_scope(self.session_factory) as session:
            record = session.get(InvestigationRecord, investigation_id)
            if not record:
                raise NotFoundError(f"Investigation '{investigation_id}' not found")
            return InvestigationModel(
                id=record.id,
                name=record.name,
                description=record.description,
                created_at=record.created_at,
                config_metadata=record.config_metadata,
            )

    # -------------------------------------------------------------------------
    # Entities (Deduplication & Canonicalization)
    # -------------------------------------------------------------------------

    def get_or_create_entity(
        self,
        entity_type: EntityType | str,
        raw_value: str,
    ) -> tuple[EntityModel, bool]:
        """Retrieve existing entity or register a new one using strict normalization.

        Returns (EntityModel, created_bool).
        Prevents duplicate entities through (entity_type, normalized_value) uniqueness.
        """
        typed_type, normalized = validate_and_normalize(entity_type, raw_value)

        with session_scope(self.session_factory) as session:
            # Query for existing normalized entity
            stmt = select(EntityRecord).where(
                EntityRecord.entity_type == typed_type.value,
                EntityRecord.normalized_value == normalized,
            )
            existing = session.execute(stmt).scalar_one_or_none()

            if existing:
                return (
                    EntityModel(
                        id=existing.id,
                        entity_type=EntityType(existing.entity_type),
                        raw_value=existing.raw_value,
                        normalized_value=existing.normalized_value,
                        created_at=existing.created_at,
                    ),
                    False,
                )

            # Insert new entity record
            new_id = generate_uuid()
            new_record = EntityRecord(
                id=new_id,
                entity_type=typed_type.value,
                raw_value=raw_value.strip(),
                normalized_value=normalized,
                created_at=datetime.now(UTC),
            )
            session.add(new_record)
            session.flush()

            model = EntityModel(
                id=new_record.id,
                entity_type=EntityType(new_record.entity_type),
                raw_value=new_record.raw_value,
                normalized_value=new_record.normalized_value,
                created_at=new_record.created_at,
            )
            return model, True

    def get_entity(self, entity_id: str) -> EntityModel:
        """Retrieve an entity by ID."""
        with session_scope(self.session_factory) as session:
            record = session.get(EntityRecord, entity_id)
            if not record:
                raise NotFoundError(f"Entity '{entity_id}' not found")
            return EntityModel(
                id=record.id,
                entity_type=EntityType(record.entity_type),
                raw_value=record.raw_value,
                normalized_value=record.normalized_value,
                created_at=record.created_at,
            )

    def list_entities(
        self,
        entity_type: EntityType | str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EntityModel]:
        """List entities with optional type filter."""
        with session_scope(self.session_factory) as session:
            stmt = select(EntityRecord).order_by(EntityRecord.created_at.desc())
            if entity_type:
                t_val = (
                    entity_type.value
                    if isinstance(entity_type, EntityType)
                    else str(entity_type).upper()
                )
                stmt = stmt.where(EntityRecord.entity_type == t_val)
            stmt = stmt.limit(limit).offset(offset)

            records = session.execute(stmt).scalars().all()
            return [
                EntityModel(
                    id=r.id,
                    entity_type=EntityType(r.entity_type),
                    raw_value=r.raw_value,
                    normalized_value=r.normalized_value,
                    created_at=r.created_at,
                )
                for r in records
            ]

    # -------------------------------------------------------------------------
    # Observations (Evidence Provenance)
    # -------------------------------------------------------------------------

    def record_observation(
        self,
        entity_id: str,
        collector_name: str,
        collector_version: str,
        source_reference: str,
        observed_at: datetime,
        data: dict[str, Any],
        status: CollectionStatus = CollectionStatus.SUCCESS,
        error_details: dict[str, Any] | str | None = None,
        ingested_at: datetime | None = None,
        observation_id: str | None = None,
    ) -> ObservationModel:
        """Store an observation record linked to an existing entity."""
        obs_id = observation_id or generate_uuid()
        ingest_time = ingested_at or datetime.now(UTC)

        model = ObservationModel(
            id=obs_id,
            entity_id=entity_id,
            collector_name=collector_name,
            collector_version=collector_version,
            source_reference=source_reference,
            observed_at=observed_at,
            ingested_at=ingest_time,
            data=data,
            status=status,
            error_details=error_details,
        )

        with session_scope(self.session_factory) as session:
            # Verify foreign key entity exists
            entity = session.get(EntityRecord, entity_id)
            if not entity:
                raise NotFoundError(f"Target entity '{entity_id}' does not exist")

            record = ObservationRecord(
                id=model.id,
                entity_id=model.entity_id,
                collector_name=model.collector_name,
                collector_version=model.collector_version,
                source_reference=model.source_reference,
                observed_at=model.observed_at,
                ingested_at=model.ingested_at,
                data=model.data,
                status=model.status if isinstance(model.status, str) else model.status.value,
                error_details=model.error_details,
            )
            session.add(record)

        return model

    def get_observation(self, observation_id: str) -> ObservationModel:
        """Retrieve an observation record by ID."""
        with session_scope(self.session_factory) as session:
            record = session.get(ObservationRecord, observation_id)
            if not record:
                raise NotFoundError(f"Observation '{observation_id}' not found")
            return ObservationModel(
                id=record.id,
                entity_id=record.entity_id,
                collector_name=record.collector_name,
                collector_version=record.collector_version,
                source_reference=record.source_reference,
                observed_at=record.observed_at,
                ingested_at=record.ingested_at,
                data=record.data,
                status=CollectionStatus(record.status),
                error_details=record.error_details,
            )

    def list_observations_for_entity(self, entity_id: str) -> list[ObservationModel]:
        """List all observations collected for a specific entity."""
        with session_scope(self.session_factory) as session:
            stmt = (
                select(ObservationRecord)
                .where(ObservationRecord.entity_id == entity_id)
                .order_by(ObservationRecord.observed_at.desc())
            )
            records = session.execute(stmt).scalars().all()
            return [
                ObservationModel(
                    id=r.id,
                    entity_id=r.entity_id,
                    collector_name=r.collector_name,
                    collector_version=r.collector_version,
                    source_reference=r.source_reference,
                    observed_at=r.observed_at,
                    ingested_at=r.ingested_at,
                    data=r.data,
                    status=CollectionStatus(r.status),
                    error_details=r.error_details,
                )
                for r in records
            ]

    # -------------------------------------------------------------------------
    # Relationships & Evidence Linkage
    # -------------------------------------------------------------------------

    def create_relationship(
        self,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: RelationshipType | str,
        relationship_id: str | None = None,
    ) -> tuple[RelationshipModel, bool]:
        """Create or fetch a directional relationship between two entities.

        Returns (RelationshipModel, created_bool).
        """
        if source_entity_id == target_entity_id:
            raise DatabaseIntegrityError(
                "Relationship source and target entities cannot be identical"
            )

        rel_type_str = (
            relationship_type.value
            if isinstance(relationship_type, RelationshipType)
            else str(relationship_type)
        )
        r_type = RelationshipType(rel_type_str)

        with session_scope(self.session_factory) as session:
            # Check source and target entities exist
            if not session.get(EntityRecord, source_entity_id):
                raise NotFoundError(f"Source entity '{source_entity_id}' not found")
            if not session.get(EntityRecord, target_entity_id):
                raise NotFoundError(f"Target entity '{target_entity_id}' not found")

            stmt = select(RelationshipRecord).where(
                RelationshipRecord.source_entity_id == source_entity_id,
                RelationshipRecord.target_entity_id == target_entity_id,
                RelationshipRecord.relationship_type == r_type.value,
            )
            existing = session.execute(stmt).scalar_one_or_none()
            if existing:
                evidence_ids = [e.observation_id for e in existing.evidence_links]
                return (
                    RelationshipModel(
                        id=existing.id,
                        source_entity_id=existing.source_entity_id,
                        target_entity_id=existing.target_entity_id,
                        relationship_type=r_type,
                        created_at=existing.created_at,
                        supporting_observation_ids=evidence_ids,
                    ),
                    False,
                )

            new_id = relationship_id or generate_uuid()
            new_rel = RelationshipRecord(
                id=new_id,
                source_entity_id=source_entity_id,
                target_entity_id=target_entity_id,
                relationship_type=r_type.value,
                created_at=datetime.now(UTC),
            )
            session.add(new_rel)
            session.flush()

            model = RelationshipModel(
                id=new_rel.id,
                source_entity_id=new_rel.source_entity_id,
                target_entity_id=new_rel.target_entity_id,
                relationship_type=r_type,
                created_at=new_rel.created_at,
                supporting_observation_ids=[],
            )
            return model, True

    def link_evidence(
        self,
        relationship_id: str,
        observation_id: str,
        notes: str | None = None,
    ) -> EvidenceLinkModel:
        """Explicitly link an observation as supporting evidence for a relationship."""
        link_id = generate_uuid()
        now = datetime.now(UTC)

        with session_scope(self.session_factory) as session:
            rel = session.get(RelationshipRecord, relationship_id)
            if not rel:
                raise NotFoundError(f"Relationship '{relationship_id}' not found")
            obs = session.get(ObservationRecord, observation_id)
            if not obs:
                raise NotFoundError(f"Observation '{observation_id}' not found")

            # Check if link already exists
            stmt = select(RelationshipEvidenceRecord).where(
                RelationshipEvidenceRecord.relationship_id == relationship_id,
                RelationshipEvidenceRecord.observation_id == observation_id,
            )
            existing = session.execute(stmt).scalar_one_or_none()
            if existing:
                return EvidenceLinkModel(
                    id=existing.id,
                    relationship_id=existing.relationship_id,
                    observation_id=existing.observation_id,
                    created_at=existing.created_at,
                    notes=existing.notes,
                )

            record = RelationshipEvidenceRecord(
                id=link_id,
                relationship_id=relationship_id,
                observation_id=observation_id,
                created_at=now,
                notes=notes,
            )
            session.add(record)

        return EvidenceLinkModel(
            id=link_id,
            relationship_id=relationship_id,
            observation_id=observation_id,
            created_at=now,
            notes=notes,
        )

    def get_relationship_with_evidence(
        self, relationship_id: str
    ) -> tuple[RelationshipModel, list[ObservationModel]]:
        """Retrieve relationship and all supporting observation records."""
        with session_scope(self.session_factory) as session:
            rel = session.get(RelationshipRecord, relationship_id)
            if not rel:
                raise NotFoundError(f"Relationship '{relationship_id}' not found")

            obs_records = [link.observation for link in rel.evidence_links]
            obs_models = [
                ObservationModel(
                    id=o.id,
                    entity_id=o.entity_id,
                    collector_name=o.collector_name,
                    collector_version=o.collector_version,
                    source_reference=o.source_reference,
                    observed_at=o.observed_at,
                    ingested_at=o.ingested_at,
                    data=o.data,
                    status=CollectionStatus(o.status),
                    error_details=o.error_details,
                )
                for o in obs_records
            ]

            rel_model = RelationshipModel(
                id=rel.id,
                source_entity_id=rel.source_entity_id,
                target_entity_id=rel.target_entity_id,
                relationship_type=RelationshipType(rel.relationship_type),
                created_at=rel.created_at,
                supporting_observation_ids=[o.id for o in obs_models],
            )
            return rel_model, obs_models

    def is_relationship_verified(self, relationship_id: str) -> bool:
        """Return True if relationship has at least one supporting observation."""
        with session_scope(self.session_factory) as session:
            count = session.scalar(
                select(func.count(RelationshipEvidenceRecord.id)).where(
                    RelationshipEvidenceRecord.relationship_id == relationship_id
                )
            )
            return bool(count and count > 0)

    def list_relationships(
        self,
        source_id: str | None = None,
        target_id: str | None = None,
        limit: int = 100,
    ) -> list[RelationshipModel]:
        """List relationships with verification status and supporting observation IDs."""
        with session_scope(self.session_factory) as session:
            stmt = select(RelationshipRecord).order_by(RelationshipRecord.created_at.desc())
            if source_id:
                stmt = stmt.where(RelationshipRecord.source_entity_id == source_id)
            if target_id:
                stmt = stmt.where(RelationshipRecord.target_entity_id == target_id)
            stmt = stmt.limit(limit)

            records = session.execute(stmt).scalars().all()
            results: list[RelationshipModel] = []
            for r in records:
                obs_ids = [link.observation_id for link in r.evidence_links]
                results.append(
                    RelationshipModel(
                        id=r.id,
                        source_entity_id=r.source_entity_id,
                        target_entity_id=r.target_entity_id,
                        relationship_type=RelationshipType(r.relationship_type),
                        created_at=r.created_at,
                        supporting_observation_ids=obs_ids,
                    )
                )
            return results
