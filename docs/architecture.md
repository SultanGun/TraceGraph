# TraceGraph Architecture

> **Local-first, evidence-first OSINT infrastructure intelligence platform.**

## 1. Architectural Philosophy

TraceGraph is engineered for authorized, defensive investigations of internet infrastructure. In conventional OSINT tooling, relationships between assets (such as domains, IPs, autonomous systems, and certificates) are often aggregated without strict attribution, resulting in untraceable inferences or hallucinated connections when paired with AI systems.

TraceGraph establishes a strict **evidence-first invariant**:
> *No entity relationship can be presented as verified unless it is directly supported by immutable observation telemetry with full provenance.*

```mermaid
flowchart TD
    CLI["CLI Layer (Typer / Rich)"] --> Pipeline["Investigation Pipeline"]
    Pipeline --> Collectors["Collector Subsystem (BaseCollector / MockDNS)"]
    Collectors --> Normalizer["Core Normalizers & Validators"]
    Normalizer --> EvModel["Evidence Data Models (Pydantic)"]
    EvModel --> Repo["Evidence Repository"]
    Repo --> SQLite[("Local SQLite Database (Foreign Keys Enforced)")]
    
    subgraph StorageLayer["Storage & Integrity Boundary"]
        Repo
        SQLite
    end
    
    subgraph ProvenanceRules["Integrity Rules"]
        PR1["Entities Deduplicated by (type, normalized_value)"]
        PR2["Unsupported Relationships -> UNVERIFIED"]
        PR3["Supported Relationships -> VERIFIED"]
    end
    
    Repo -.-> ProvenanceRules
```

---

## 2. Core Pillars

### 2.1 Evidence Provenance
Every observation stored in TraceGraph contains:
- **Collector Identity and Version:** The exact software unit that performed the collection.
- **Source Reference:** The source artifact URI or synthetic fixture (e.g. `synthetic://mock-dns/example.com`).
- **Observation Timestamp:** The exact UTC timestamp when the observation occurred.
- **Ingestion Timestamp:** The UTC timestamp when the record entered local storage.
- **Observed Data:** Raw, unmanipulated structured telemetry.

### 2.2 Reproducible Investigations
Investigations define clear scope boundaries. All observations, entities, and relationship links are stored locally inside transactional SQLite storage. The state of an investigation can be fully audited, replayed, and inspected without depending on ephemeral external SaaS platforms.

### 2.3 Temporal Intelligence
Infrastructure moves across time. TraceGraph distinguishes between:
- **Observation Time (`observed_at`):** When the external artifact or DNS query occurred.
- **Ingestion Time (`ingested_at`):** When the TraceGraph system ingested and normalized the data.
This separation allows future snapshot comparisons to detect infrastructure migrations, IP reassignments, and CDN changes over time.

### 2.4 AI-Ready Architecture
Future machine learning and agentic workflows must interact with TraceGraph through strict citation constraints:
- AI agents cannot insert relationships directly without attaching supporting observations.
- Analysis outputs must cite the underlying `observation_id`.
- If supporting evidence is missing, the relationship must display as `[UNVERIFIED]`.

---

## 3. Subsystem Breakdown

### 3.1 CLI Layer (`src/tracegraph/cli/`)
Built with Typer and Rich. Exposes high-level commands:
- `tracegraph version`: Reports installed version.
- `tracegraph init`: Bootstraps local workspace and database with idempotency safeguards.
- `tracegraph status`: Inspects database connectivity, foreign-key enforcement, and schema version.

### 3.2 Core & Normalizers (`src/tracegraph/core/`)
- **Enumerations (`enums.py`):** Canonical types for entities (`DOMAIN`, `IPV4`, `IPV6`, `ASN`, `CIDR`, `NAMESERVER`, `CERTIFICATE`, `URL`), relationships (`RESOLVES_TO`, `HOSTED_ON`, `BELONGS_TO`, `SUBDOMAIN_OF`, `SERVED_BY`, `CERTIFIED_BY`, `ASSOCIATED_WITH`), and collection outcomes (`SUCCESS`, `EMPTY`, `FAILED`, `TIMEOUT`).
- **Normalizers (`normalizers.py`):** Converts raw user inputs and collector artifacts into canonical representation to eliminate duplicates (e.g., lowercase FQDNs, canonical IP strings via `ipaddress`, canonical `AS<number>`).
- **Exceptions (`exceptions.py`):** Domain error hierarchy ensuring clear error propagation.

### 3.3 Evidence Data Model (`src/tracegraph/evidence/`)
- Pydantic models for `InvestigationModel`, `EntityModel`, `ObservationModel`, `RelationshipModel`, and `EvidenceLinkModel`.
- Enforces UTC timezone awareness on all timestamps.
- Implements `RelationshipModel.is_verified` calculated from supporting observation links.

### 3.4 Storage Subsystem (`src/tracegraph/storage/`)
- **Database Engine (`database.py`):** SQLite connection pool with listener enforcing `PRAGMA foreign_keys = ON;`.
- **Relational Schema (`schema.py`):** SQLAlchemy declarative models with foreign key cascades, unique constraints, and indexes.
- **Repository (`repository.py`):** Atomically manages entity deduplication, observation logging, relationship generation, and evidence joins.
- **Workspace Lifecycle (`workspace.py`):** Validates database integrity before connection, enforces schema versioning, and provides idempotency.

### 3.5 Collectors Subsystem (`src/tracegraph/collectors/`)
- **BaseCollector (`base.py`):** Abstract class defining validation, timeout enforcement, duration measurement, and structured `CollectorResult`.
- **MockDNSCollector (`mock.py`):** Deterministic synthetic collector for testing and verification without making external network requests.

### 3.6 Reporting Subsystem (`src/tracegraph/reports/`)
- Formats evidence graphs into Rich tables and structured JSON/dict summaries with explicit `[VERIFIED]` and `[UNVERIFIED]` status badges.

---

## 4. Storage & Reliability Guarantees

1. **Foreign Key Enforcement:** SQLite does not enforce foreign keys by default. TraceGraph enforces `PRAGMA foreign_keys = ON;` on every connection via SQLAlchemy event listeners.
2. **Transaction Safety:** All multi-step write operations (e.g. creating relationships and linking observations) run inside `session_scope` context managers that automatically rollback on error.
3. **Safe Initialization:** `tracegraph init` will never overwrite or truncate an existing healthy database. If an existing database is corrupted, initialization fails cleanly with an explanatory diagnostic message rather than wiping the file.
