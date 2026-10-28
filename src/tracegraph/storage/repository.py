"""Data access repository for investigations, entities, observations, and verified relationships."""

import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import (
    AmbiguousSnapshotError,
    DatabaseIntegrityError,
    NotFoundError,
)
from tracegraph.core.normalizers import validate_and_normalize
from tracegraph.evidence.models import (
    EntityModel,
    EvidenceLinkModel,
    InvestigationModel,
    ObservationModel,
    RelationshipModel,
    generate_uuid,
)
from tracegraph.snapshots.canonical import (
    canonicalize_snapshot_content,
    compute_content_digest,
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
from tracegraph.storage.database import session_scope
from tracegraph.storage.schema import (
    EntityRecord,
    InvestigationRecord,
    ObservationRecord,
    RelationshipEvidenceRecord,
    RelationshipRecord,
    SnapshotRecord,
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
        target_scope: str = "",
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
            target_scope=target_scope,
            created_at=datetime.now(UTC),
            config_metadata=meta,
        )

        with session_scope(self.session_factory) as session:
            record = InvestigationRecord(
                id=model.id,
                name=model.name,
                description=model.description,
                target_scope=model.target_scope,
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
                target_scope=record.target_scope,
                created_at=record.created_at,
                config_metadata=record.config_metadata,
            )

    def list_investigations(self, limit: int = 100, offset: int = 0) -> list[InvestigationModel]:
        """List investigations ordered by creation time descending."""
        with session_scope(self.session_factory) as session:
            stmt = (
                select(InvestigationRecord)
                .order_by(InvestigationRecord.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            records = session.execute(stmt).scalars().all()
            return [
                InvestigationModel(
                    id=r.id,
                    name=r.name,
                    description=r.description,
                    target_scope=r.target_scope,
                    created_at=r.created_at,
                    config_metadata=r.config_metadata,
                )
                for r in records
            ]

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
        investigation_id: str | None = None,
        observation_id: str | None = None,
    ) -> ObservationModel:
        """Store an observation record linked to an existing entity and optional investigation."""
        obs_id = observation_id or generate_uuid()
        ingest_time = ingested_at or datetime.now(UTC)

        model = ObservationModel(
            id=obs_id,
            entity_id=entity_id,
            investigation_id=investigation_id,
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

            # Verify investigation if provided
            if investigation_id:
                inv = session.get(InvestigationRecord, investigation_id)
                if not inv:
                    raise NotFoundError(f"Investigation '{investigation_id}' does not exist")

            record = ObservationRecord(
                id=model.id,
                entity_id=model.entity_id,
                investigation_id=model.investigation_id,
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
                investigation_id=record.investigation_id,
                collector_name=record.collector_name,
                collector_version=record.collector_version,
                source_reference=record.source_reference,
                observed_at=record.observed_at,
                ingested_at=record.ingested_at,
                data=record.data,
                status=CollectionStatus(record.status),
                error_details=record.error_details,
            )

    def list_observations_for_investigation(
        self, investigation_id: str
    ) -> list[ObservationModel]:
        """List all observations associated with a specific investigation."""
        with session_scope(self.session_factory) as session:
            stmt = (
                select(ObservationRecord)
                .where(ObservationRecord.investigation_id == investigation_id)
                .order_by(ObservationRecord.observed_at.desc())
            )
            records = session.execute(stmt).scalars().all()
            return [
                ObservationModel(
                    id=r.id,
                    entity_id=r.entity_id,
                    investigation_id=r.investigation_id,
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
                    investigation_id=r.investigation_id,
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
                    investigation_id=o.investigation_id,
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

    # -------------------------------------------------------------------------
    # Snapshots (Immutable Evidence Graph Captures)
    # -------------------------------------------------------------------------

    def _build_snapshot_content(
        self, session: Session, investigation_id: str
    ) -> SnapshotContent:
        """Extract complete evidence graph for an investigation from the database."""
        inv = session.get(InvestigationRecord, investigation_id)
        if not inv:
            raise NotFoundError(f"Investigation '{investigation_id}' not found")

        # 1. Query observations for this investigation
        obs_records = (
            session.execute(
                select(ObservationRecord)
                .where(ObservationRecord.investigation_id == investigation_id)
                .order_by(ObservationRecord.observed_at.asc())
            )
            .scalars()
            .all()
        )
        obs_ids = {o.id for o in obs_records}

        # 2. Query evidence links connecting to these observations
        link_records: list[RelationshipEvidenceRecord] = []
        if obs_ids:
            link_records = list(
                session.execute(
                    select(RelationshipEvidenceRecord).where(
                        RelationshipEvidenceRecord.observation_id.in_(obs_ids)
                    )
                )
                .scalars()
                .all()
            )

        # 3. Query relationships referenced by these evidence links
        rel_ids = {link.relationship_id for link in link_records}
        rel_records: list[RelationshipRecord] = []
        if rel_ids:
            rel_records = list(
                session.execute(
                    select(RelationshipRecord).where(RelationshipRecord.id.in_(rel_ids))
                )
                .scalars()
                .all()
            )

        # 4. Identify all referenced entities
        ent_ids = {o.entity_id for o in obs_records}
        for r in rel_records:
            ent_ids.add(r.source_entity_id)
            ent_ids.add(r.target_entity_id)

        ent_records: list[EntityRecord] = []
        if ent_ids:
            ent_records = list(
                session.execute(select(EntityRecord).where(EntityRecord.id.in_(ent_ids)))
                .scalars()
                .all()
            )
        ent_map = {e.id: e for e in ent_records}

        # 5. Build snapshot entity models
        snap_entities = [
            SnapshotEntityModel(
                id=e.id,
                entity_type=EntityType(e.entity_type),
                raw_value=e.raw_value,
                normalized_value=e.normalized_value,
                created_at=e.created_at.isoformat(),
            )
            for e in ent_records
        ]

        # 6. Build snapshot observation models
        snap_observations = [
            SnapshotObservationModel(
                id=o.id,
                entity_id=o.entity_id,
                collector_name=o.collector_name,
                collector_version=o.collector_version,
                source_reference=o.source_reference,
                observed_at=o.observed_at.isoformat(),
                ingested_at=o.ingested_at.isoformat(),
                status=CollectionStatus(o.status),
                data=o.data or {},
                error_details=o.error_details,
            )
            for o in obs_records
        ]

        # 7. Build snapshot relationship models
        snap_relationships = []
        for r in rel_records:
            src = ent_map.get(r.source_entity_id)
            tgt = ent_map.get(r.target_entity_id)
            if not src or not tgt:
                continue
            supp_obs = sorted(
                [link.observation_id for link in r.evidence_links if link.observation_id in obs_ids]
            )
            snap_relationships.append(
                SnapshotRelationshipModel(
                    id=r.id,
                    source_entity_id=r.source_entity_id,
                    target_entity_id=r.target_entity_id,
                    relationship_type=RelationshipType(r.relationship_type),
                    source_normalized_value=src.normalized_value,
                    source_entity_type=src.entity_type,
                    target_normalized_value=tgt.normalized_value,
                    target_entity_type=tgt.entity_type,
                    created_at=r.created_at.isoformat(),
                    supporting_observation_ids=supp_obs,
                )
            )

        # 8. Build snapshot evidence link models
        snap_evidence_links = [
            SnapshotEvidenceLinkModel(
                id=link.id,
                relationship_id=link.relationship_id,
                observation_id=link.observation_id,
                created_at=link.created_at.isoformat(),
                notes=link.notes,
            )
            for link in link_records
        ]

        return SnapshotContent(
            investigation_id=inv.id,
            investigation_name=inv.name,
            target_scope=inv.target_scope,
            entities=snap_entities,
            relationships=snap_relationships,
            observations=snap_observations,
            evidence_links=snap_evidence_links,
        )

    def create_snapshot(
        self,
        investigation_id: str,
        label: str | None = None,
        snapshot_id: str | None = None,
    ) -> SnapshotModel:
        """Create an immutable point-in-time snapshot of an investigation's state."""
        sid = snapshot_id or generate_uuid()
        with session_scope(self.session_factory) as session:
            content = self._build_snapshot_content(session, investigation_id)
            digest = compute_content_digest(content)
            canon_dict = canonicalize_snapshot_content(content)
            serialized_canon = serialize_canonical_json(canon_dict)
            persisted_data = json.loads(serialized_canon)

            rec = SnapshotRecord(
                id=sid,
                investigation_id=investigation_id,
                label=label,
                schema_version="3.0.0",
                created_at=datetime.now(UTC),
                content_digest=digest,
                entity_count=len(content.entities),
                relationship_count=len(content.relationships),
                observation_count=len(content.observations),
                snapshot_data=persisted_data,
            )
            session.add(rec)
            session.flush()

            return SnapshotModel(
                id=rec.id,
                investigation_id=rec.investigation_id,
                label=rec.label,
                schema_version=rec.schema_version,
                created_at=rec.created_at,
                content_digest=rec.content_digest,
                entity_count=rec.entity_count,
                relationship_count=rec.relationship_count,
                observation_count=rec.observation_count,
                data=SnapshotContent(**persisted_data),
            )

    def _resolve_snapshot_record(self, session: Session, snapshot_id: str) -> SnapshotRecord:
        """Resolve a SnapshotRecord by full UUID or unique prefix of at least 8 characters."""
        clean_id = snapshot_id.strip()
        record = session.get(SnapshotRecord, clean_id)
        if not record and len(clean_id) >= 8:
            matches = list(
                session.execute(
                    select(SnapshotRecord).where(SnapshotRecord.id.startswith(clean_id))
                )
                .scalars()
                .all()
            )
            if len(matches) == 1:
                record = matches[0]
            elif len(matches) > 1:
                raise AmbiguousSnapshotError(
                    f"Snapshot identifier prefix '{clean_id}' is ambiguous "
                    f"({len(matches)} matches found)."
                )
        if not record:
            raise NotFoundError(f"Snapshot '{clean_id}' not found")
        return record

    def get_snapshot(self, snapshot_id: str) -> SnapshotModel:
        """Retrieve a snapshot record by full UUID or unique prefix of at least 8 characters."""
        with session_scope(self.session_factory) as session:
            record = self._resolve_snapshot_record(session, snapshot_id)
            return SnapshotModel(
                id=record.id,
                investigation_id=record.investigation_id,
                label=record.label,
                schema_version=record.schema_version,
                created_at=record.created_at,
                content_digest=record.content_digest,
                entity_count=record.entity_count,
                relationship_count=record.relationship_count,
                observation_count=record.observation_count,
                data=SnapshotContent(**record.snapshot_data),
            )

    def list_snapshots(
        self,
        investigation_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SnapshotModel]:
        """List snapshots ordered by creation time descending with optional investigation filter."""
        with session_scope(self.session_factory) as session:
            stmt = select(SnapshotRecord).order_by(SnapshotRecord.created_at.desc())
            if investigation_id:
                stmt = stmt.where(SnapshotRecord.investigation_id == investigation_id)
            stmt = stmt.limit(limit).offset(offset)

            records = session.execute(stmt).scalars().all()
            return [
                SnapshotModel(
                    id=r.id,
                    investigation_id=r.investigation_id,
                    label=r.label,
                    schema_version=r.schema_version,
                    created_at=r.created_at,
                    content_digest=r.content_digest,
                    entity_count=r.entity_count,
                    relationship_count=r.relationship_count,
                    observation_count=r.observation_count,
                    data=SnapshotContent(**r.snapshot_data),
                )
                for r in records
            ]

    def verify_snapshot_integrity(self, snapshot_id: str) -> bool:
        """Verify content integrity of a stored snapshot against its content_digest."""
        with session_scope(self.session_factory) as session:
            record = self._resolve_snapshot_record(session, snapshot_id)
            try:
                content = SnapshotContent(**record.snapshot_data)
                return verify_snapshot_integrity(
                    {"content_digest": record.content_digest, "data": content}
                )
            except Exception:
                return False
