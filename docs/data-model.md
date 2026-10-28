# TraceGraph Data Model & Evidence Schema

This document details the relational schema, entity validation rules, deduplication strategy, snapshot architecture, and evidence provenance invariants implemented in TraceGraph.

---

## 1. Entity-Relationship Overview

```mermaid
erDiagram
    INVESTIGATION {
        string id PK
        string name
        string description
        string target_scope
        datetime created_at
        json config_metadata
    }

    ENTITY {
        string id PK
        string entity_type
        string raw_value
        string canonical_value
        datetime created_at
    }

    OBSERVATION {
        string id PK
        string entity_id FK
        string investigation_id FK
        string collector_name
        string collector_version
        string source_reference
        datetime observed_at
        datetime ingested_at
        json data
        string status
        json error_details
    }

    RELATIONSHIP {
        string id PK
        string source_entity_id FK
        string target_entity_id FK
        string relationship_type
        datetime created_at
    }

    RELATIONSHIP_EVIDENCE {
        string id PK
        string relationship_id FK
        string observation_id FK
        datetime created_at
        string notes
    }

    SNAPSHOT {
        string id PK
        string investigation_id FK
        string label
        string schema_version
        datetime created_at
        string content_digest
        integer entity_count
        integer relationship_count
        integer observation_count
        json snapshot_data
    }

    METADATA {
        string key PK
        string value
        datetime updated_at
    }

    INVESTIGATION ||--o{ OBSERVATION : "contains"
    INVESTIGATION ||--o{ SNAPSHOT : "has snapshots"
    ENTITY ||--o{ OBSERVATION : "is observed by"
    ENTITY ||--o{ RELATIONSHIP : "is source of"
    ENTITY ||--o{ RELATIONSHIP : "is target of"
    RELATIONSHIP ||--o{ RELATIONSHIP_EVIDENCE : "is substantiated by"
    OBSERVATION ||--o{ RELATIONSHIP_EVIDENCE : "substantiates"
```

---

## 2. Table Specifications

### 2.1 `investigations`
Tracks discrete scoping boundaries and investigation parameters.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `name` | VARCHAR(255) | NO | Investigation title or reference code. |
| `description` | TEXT | YES | Objective, scope notes, or incident ticket. |
| `target_scope` | TEXT | NO | Declared target scope definition (e.g. `example.com, 93.184.215.0/24`). Default `""` (unrestricted). |
| `created_at` | DATETIME | NO | UTC creation timestamp. |
| `config_metadata`| JSON | NO | Parameters, allowed target scopes, and tags. |

### 2.2 `entities`
Represents infrastructure nodes.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `entity_type` | VARCHAR(50) | NO | Classification (`DOMAIN`, `IPV4`, `IPV6`, `ASN`, `CIDR`, `NAMESERVER`, etc.). |
| `raw_value` | VARCHAR(1024) | NO | Original input as provided by user or collector. |
| `canonical_value` | VARCHAR(1024) | NO | Canonicalized representation used for deduplication. |
| `created_at` | DATETIME | NO | UTC registration timestamp. |

**Constraints & Indexes:**
- `UNIQUE(entity_type, canonical_value)`: Prevents duplicate entity insertion across the workspace.
- `INDEX(entity_type, canonical_value)`: Fast lookup during ingestion.

### 2.3 `observations`
Discrete evidence collected from an identified source.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `entity_id` | VARCHAR(36) | NO | Foreign Key to `entities.id` (ON DELETE CASCADE). |
| `investigation_id` | VARCHAR(36) | YES | Foreign Key to `investigations.id` (ON DELETE CASCADE). Indexed. |
| `collector_name` | VARCHAR(100) | NO | Collector identity (e.g. `live_dns`, `rdap`, `mock_dns`). |
| `collector_version`| VARCHAR(50) | NO | Collector semver version. |
| `source_reference` | VARCHAR(1024) | NO | Provenance URI, resolver, or registry URL. |
| `observed_at` | DATETIME | NO | UTC timestamp when observed at source. |
| `ingested_at` | DATETIME | NO | UTC timestamp when stored locally. |
| `data` | JSON | NO | Raw structured telemetry payload. |
| `status` | VARCHAR(20) | NO | `SUCCESS`, `EMPTY`, `FAILED`, or `TIMEOUT`. |
| `error_details` | JSON | YES | Diagnostic information if status is not `SUCCESS`. |

### 2.4 `relationships`
Directional link between two infrastructure entities.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `source_entity_id` | VARCHAR(36) | NO | Foreign Key to `entities.id` (ON DELETE CASCADE). |
| `target_entity_id` | VARCHAR(36) | NO | Foreign Key to `entities.id` (ON DELETE CASCADE). |
| `relationship_type`| VARCHAR(50) | NO | Relationship verb (`RESOLVES_TO`, `HOSTED_ON`, etc.). |
| `created_at` | DATETIME | NO | UTC timestamp of relationship registration. |

**Constraints & Indexes:**
- `UNIQUE(source_entity_id, target_entity_id, relationship_type)`: Prevents duplicate edges.

### 2.5 `relationship_evidence`
Join table connecting a relationship to its supporting observation records.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `relationship_id` | VARCHAR(36) | NO | Foreign Key to `relationships.id` (ON DELETE CASCADE). |
| `observation_id` | VARCHAR(36) | NO | Foreign Key to `observations.id` (ON DELETE CASCADE). |
| `created_at` | DATETIME | NO | UTC timestamp of evidence association. |
| `notes` | TEXT | YES | Analyst extraction notes. |

**Constraints:**
- `UNIQUE(relationship_id, observation_id)`: Prevents redundant linking.

### 2.6 `snapshots`
Point-in-time immutable capture of an investigation's evidence graph.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `investigation_id` | VARCHAR(36) | NO | Foreign Key to `investigations.id` (ON DELETE CASCADE). Indexed. |
| `label` | VARCHAR(255) | YES | Optional user label (e.g. `Baseline Scan`, `Pre-cutover`). |
| `schema_version` | VARCHAR(50) | NO | Schema format version (e.g. `3.0.0`). |
| `created_at` | DATETIME | NO | UTC capture timestamp. Indexed. |
| `content_digest` | VARCHAR(64) | NO | SHA-256 hash of canonicalized JSON content. Indexed. |
| `entity_count` | INTEGER | NO | Total entities in snapshot graph. |
| `relationship_count` | INTEGER | NO | Total relationships in snapshot graph. |
| `observation_count` | INTEGER | NO | Total observations in snapshot graph. |
| `snapshot_data` | JSON | NO | Canonical snapshot payload including entities, rels, obs, and links. |

### 2.7 `metadata`
Key-value workspace configuration and schema state.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `key` | VARCHAR(100) | NO | Primary Key (e.g. `schema_version`). |
| `value` | TEXT | NO | Associated configuration value. |
| `updated_at` | DATETIME | NO | UTC update timestamp. |

---

## 3. Provenance & Verification Rules

1. **Unsupported Edge Invariant:** A relationship without at least one linked row in `relationship_evidence` evaluates `is_verified = False`. The platform must never label an unlinked relationship as verified.
2. **Snapshot Immutability Invariant:** Snapshots store a self-contained, canonical serialization of the investigation's graph at capture time. Subsequent collections, entity mutations, or relationship additions never alter previously taken snapshots.
3. **Cryptographic Content Digest:** Every snapshot computes a deterministic SHA-256 digest of canonicalized content (`entities`, `relationships`, `observations`, and `evidence_links` sorted by canonical domain keys with normalized UTC ISO timestamps). Tampering with any byte inside `snapshot_data` invalidates `verify_snapshot_integrity()`.
4. **Cascading Integrity:** Deleting an entity cascades and deletes its dependent observations and relationships. Deleting an investigation cascades and removes all associated observations and snapshots.
5. **Temporal Distinction:**
   - `observed_at` represents real-world timestamp of the artifact.
   - `ingested_at` represents storage time in TraceGraph.
   This guarantees that historical replays and imported archives maintain truthful telemetry timelines.

---

## 4. Normalization Rules

| Entity Type | Input Example | Normalized Output | Strategy |
| :--- | :--- | :--- | :--- |
| `DOMAIN` | ` Example.COM. ` | `example.com` | Strip, lower, rstrip trailing dot, IDNA encoding. |
| `IPV4` | ` 093.184.215.014 ` | `93.184.215.14` | Canonical dotted-decimal via `ipaddress.IPv4Address`. |
| `IPV6` | ` 2606:2800:0220:0001:0248:1893:25C8:1946 ` | `2606:2800:220:1:248:1893:25c8:1946` | Canonical lowercase compressed via `ipaddress.IPv6Address`. |
| `ASN` | ` as15169 ` | `AS15169` | Canonical uppercase `AS` prefix + integer. |
| `CIDR` | ` 192.168.1.1/24 ` | `192.168.1.0/24` | Network representation via `ipaddress.ip_network(strict=False)`. |
| `NAMESERVER` | ` NS1.EXAMPLE.COM ` | `ns1.example.com` | Lowercase FQDN. |
| `CERTIFICATE`| ` aa:bb:cc:dd ` | `AABBCCDD` | Strip colons/spaces, uppercase hex fingerprint. |

---

## 5. Schema Versioning & Migrations

TraceGraph uses explicit, versioned relational schema tracking via the `metadata` table.

### Schema Version History
- **v1.0.0 (v0.1.0-alpha):** Initial foundation with unassociated observations and implicit investigation boundaries.
- **v2.0.0 (v0.2.0-alpha):** Added `target_scope` column to `investigations` and `investigation_id` column to `observations`.
- **v3.0.0 (v0.3.0-alpha):** Added `snapshots` table with foreign key cascade to `investigations` and indexes on `investigation_id`, `created_at`, and `content_digest`.

### Migration Mechanics (`src/tracegraph/storage/migrations.py`)
- Upgrades are executed sequentially in forward-only transactions:
  1. `1.0.0 -> 2.0.0`: Adds `target_scope` and `investigation_id`, builds index, and backfills legacy observations to `legacy-v0.1-investigation`.
  2. `2.0.0 -> 3.0.0`: Creates `snapshots` table with foreign keys, checks, and performance indexes.
  3. Updates `metadata` record `schema_version` to `'3.0.0'`.
- Migrations are automatically applied whenever `tracegraph init` or workspace verification runs on an existing database. Zero data loss is guaranteed.
