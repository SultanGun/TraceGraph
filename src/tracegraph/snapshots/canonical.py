"""Deterministic canonical serialization and content digest computation for snapshots."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from tracegraph.snapshots.models import (
    SnapshotContent,
    SnapshotEntityModel,
    SnapshotEvidenceLinkModel,
    SnapshotModel,
    SnapshotObservationModel,
    SnapshotRelationshipModel,
)


def normalize_iso_timestamp(ts: datetime | str) -> str:
    """Normalize any datetime or ISO string to canonical UTC format: YYYY-MM-DDTHH:MM:SSZ."""
    if isinstance(ts, str):
        clean = ts.strip()
        try:
            dt = datetime.fromisoformat(clean)
        except ValueError:
            return clean
    else:
        dt = ts

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)

    if dt.microsecond == 0:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonicalize_data_dict(val: Any) -> Any:
    """Recursively sort dictionary keys and normalize values for deterministic serialization."""
    if isinstance(val, dict):
        return {
            str(k): canonicalize_data_dict(v)
            for k, v in sorted(val.items(), key=lambda item: str(item[0]))
        }
    if isinstance(val, (list, tuple)):
        return [canonicalize_data_dict(item) for item in val]
    if isinstance(val, set):
        return sorted([canonicalize_data_dict(item) for item in val], key=str)
    if isinstance(val, datetime):
        return normalize_iso_timestamp(val)
    return val


def canonicalize_entity(ent: SnapshotEntityModel | dict[str, Any]) -> dict[str, Any]:
    """Produce deterministic representation of an entity."""
    d = ent if isinstance(ent, dict) else ent.model_dump()
    return {
        "created_at": normalize_iso_timestamp(d.get("created_at", "")),
        "entity_type": str(d.get("entity_type", "")).upper(),
        "id": str(d.get("id", "")),
        "normalized_value": str(d.get("normalized_value", "")).strip(),
        "raw_value": str(d.get("raw_value", "")).strip(),
    }


def canonicalize_relationship(rel: SnapshotRelationshipModel | dict[str, Any]) -> dict[str, Any]:
    """Produce deterministic representation of a relationship."""
    d = rel if isinstance(rel, dict) else rel.model_dump()
    obs_ids = sorted(str(oid) for oid in d.get("supporting_observation_ids", []))
    return {
        "created_at": normalize_iso_timestamp(d.get("created_at", "")),
        "id": str(d.get("id", "")),
        "relationship_type": str(d.get("relationship_type", "")).upper(),
        "source_entity_id": str(d.get("source_entity_id", "")),
        "source_entity_type": str(d.get("source_entity_type", "")).upper(),
        "source_normalized_value": str(d.get("source_normalized_value", "")).strip(),
        "supporting_observation_ids": obs_ids,
        "target_entity_id": str(d.get("target_entity_id", "")),
        "target_entity_type": str(d.get("target_entity_type", "")).upper(),
        "target_normalized_value": str(d.get("target_normalized_value", "")).strip(),
    }


def canonicalize_observation(obs: SnapshotObservationModel | dict[str, Any]) -> dict[str, Any]:
    """Produce deterministic representation of an observation."""
    d = obs if isinstance(obs, dict) else obs.model_dump()
    return {
        "collector_name": str(d.get("collector_name", "")).strip().lower(),
        "collector_version": str(d.get("collector_version", "")).strip(),
        "data": canonicalize_data_dict(d.get("data", {})),
        "entity_id": str(d.get("entity_id", "")),
        "error_details": canonicalize_data_dict(d.get("error_details")),
        "id": str(d.get("id", "")),
        "ingested_at": normalize_iso_timestamp(d.get("ingested_at", "")),
        "observed_at": normalize_iso_timestamp(d.get("observed_at", "")),
        "source_reference": str(d.get("source_reference", "")).strip(),
        "status": str(d.get("status", "")).upper(),
    }


def canonicalize_evidence_link(link: SnapshotEvidenceLinkModel | dict[str, Any]) -> dict[str, Any]:
    """Produce deterministic representation of an evidence link."""
    d = link if isinstance(link, dict) else link.model_dump()
    return {
        "created_at": normalize_iso_timestamp(d.get("created_at", "")),
        "id": str(d.get("id", "")),
        "notes": d.get("notes"),
        "observation_id": str(d.get("observation_id", "")),
        "relationship_id": str(d.get("relationship_id", "")),
    }


def canonicalize_snapshot_content(content: SnapshotContent | dict[str, Any]) -> dict[str, Any]:
    """Convert snapshot content into a strictly ordered canonical representation.

    Guarantees:
    - Entities sorted deterministically by (entity_type, normalized_value).
    - Relationships sorted deterministically by (source_type, source_val,
      rel_type, target_type, target_val).
    - Observations sorted deterministically by (collector_name, source_reference, observed_at, id).
    - Evidence links sorted deterministically by (relationship_id, observation_id).
    - All sub-dictionaries key-sorted with normalized timestamps.
    """
    raw = content if isinstance(content, dict) else content.model_dump()

    raw_entities = raw.get("entities", [])
    canon_entities = [canonicalize_entity(e) for e in raw_entities]
    canon_entities.sort(key=lambda x: (x["entity_type"], x["normalized_value"], x["id"]))

    raw_rels = raw.get("relationships", [])
    canon_rels = [canonicalize_relationship(r) for r in raw_rels]
    canon_rels.sort(
        key=lambda x: (
            x["source_entity_type"],
            x["source_normalized_value"],
            x["relationship_type"],
            x["target_entity_type"],
            x["target_normalized_value"],
            x["id"],
        )
    )

    raw_obs = raw.get("observations", [])
    canon_obs = [canonicalize_observation(o) for o in raw_obs]
    canon_obs.sort(
        key=lambda x: (
            x["collector_name"],
            x["source_reference"],
            x["observed_at"],
            x["id"],
        )
    )

    raw_links = raw.get("evidence_links", [])
    canon_links = [canonicalize_evidence_link(link) for link in raw_links]
    canon_links.sort(key=lambda x: (x["relationship_id"], x["observation_id"], x["id"]))

    return {
        "entities": canon_entities,
        "evidence_links": canon_links,
        "investigation_id": str(raw.get("investigation_id", "")),
        "investigation_name": str(raw.get("investigation_name", "")),
        "observations": canon_obs,
        "relationships": canon_rels,
        "target_scope": str(raw.get("target_scope", "")),
    }


def serialize_canonical_json(canonical_dict: dict[str, Any]) -> str:
    """Serialize canonical dictionary to compact, deterministic JSON string."""
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_content_digest(content: SnapshotContent | dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hex digest of the canonical snapshot content."""
    canon_dict = canonicalize_snapshot_content(content)
    serialized = serialize_canonical_json(canon_dict)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_snapshot_integrity(snapshot: SnapshotModel | dict[str, Any]) -> bool:
    """Verify that a snapshot's stored content_digest matches recomputed digest of its data.

    Returns True if intact, False if tampered or corrupt.
    """
    if isinstance(snapshot, SnapshotModel):
        stored_digest = snapshot.content_digest
        data = snapshot.data
    else:
        stored_digest = snapshot.get("content_digest", "")
        data = snapshot.get("snapshot_data") or snapshot.get("data") or {}

    expected_digest = compute_content_digest(data)
    return stored_digest == expected_digest
