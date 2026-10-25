# TraceGraph Data Model & Evidence Schema

This document details the relational schema, entity validation rules, deduplication strategy, and evidence provenance invariants implemented in TraceGraph.

---

## 1. Entity-Relationship Overview

```mermaid
erDiagram
    INVESTIGATION {
        string id PK
        string name
        string description
        datetime created_at
        json config_metadata
    }

    ENTITY {
        string id PK
        string entity_type
        string raw_value
        string normalized_value
        datetime created_at
    }

    OBSERVATION {
        string id PK
        string entity_id FK
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

    METADATA {
        string key PK
        string value
        datetime updated_at
    }

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
| `created_at` | DATETIME | NO | UTC creation timestamp. |
| `config_metadata`| JSON | NO | Parameters, allowed target scopes, and tags. |

### 2.2 `entities`
Represents infrastructure nodes.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `entity_type` | VARCHAR(50) | NO | Classification (`DOMAIN`, `IPV4`, `IPV6`, `ASN`, `CIDR`, `NAMESERVER`, etc.). |
| `raw_value` | VARCHAR(1024) | NO | Original input as provided by user or collector. |
| `normalized_value` | VARCHAR(1024) | NO | Canonicalized representation used for deduplication. |
| `created_at` | DATETIME | NO | UTC registration timestamp. |

**Constraints & Indexes:**
- `UNIQUE(entity_type, normalized_value)`: Prevents duplicate entity insertion across the workspace.
- `INDEX(entity_type, normalized_value)`: Fast lookup during ingestion.

### 2.3 `observations`
Discrete evidence collected from an identified source.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR(36) | NO | Primary Key (UUIDv4). |
| `entity_id` | VARCHAR(36) | NO | Foreign Key to `entities.id` (ON DELETE CASCADE). |
| `collector_name` | VARCHAR(100) | NO | Collector identity (e.g. `mock_dns`). |
| `collector_version`| VARCHAR(50) | NO | Collector semver version. |
| `source_reference` | VARCHAR(1024) | NO | Provenance URI, synthetic fixture, or file path. |
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

### 2.6 `metadata`
Key-value workspace configuration and schema state.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `key` | VARCHAR(100) | NO | Primary Key (e.g. `schema_version`). |
| `value` | TEXT | NO | Associated configuration value. |
| `updated_at` | DATETIME | NO | UTC update timestamp. |

---

## 3. Provenance & Verification Rules

1. **Unsupported Edge Invariant:** A relationship without at least one linked row in `relationship_evidence` evaluates `is_verified = False`. The platform must never label an unlinked relationship as verified.
2. **Cascading Integrity:** Deleting an entity cascades and deletes its dependent observations and relationships. Deleting an observation removes its corresponding evidence link rows without destroying the underlying entities.
3. **Temporal Distinction:**
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
