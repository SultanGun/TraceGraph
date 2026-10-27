# TraceGraph

> **Local-first, evidence-first OSINT infrastructure intelligence platform.**

TraceGraph is an open-source, local-first intelligence platform engineered for authorized defensive investigations of public internet infrastructure. Every relationship and discovery is anchored in verifiable observation evidence with explicit provenance.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-v0.2.0--alpha-orange.svg)]()

---

## 💡 Core Differentiators

- **Evidence Provenance:** Every observation explicitly records the originating collector identity, version, source reference, observation timestamp, and ingestion timestamp in UTC. Unsupported relationships are never presented as verified findings.
- **Reproducible Investigations:** Collection runs, declared scope boundaries, and discrete entity linkages are preserved in local SQLite storage with enforced foreign-key integrity.
- **Strict Scope Boundaries:** Target scopes (domains, wildcards, CIDRs, IPs) are validated prior to initiating network queries.
- **Defensive & Privacy-Preserving:** Bounded collection with SSRF defense (blocking private, loopback, and reserved ranges), rate limiting, and automated vCard PII sanitization.
- **Temporal Intelligence:** Clean separation between observation time (when raw telemetry was observed) and ingestion time (when records entered storage), providing snapshot comparison capabilities.
- **AI-Ready Architecture:** Designed from the ground up so that future AI reasoning modules must cite verifiable database evidence rather than hallucinating infrastructure links.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12 or higher (tested with Python 3.12, 3.13, and 3.14)
- SQLite 3.35+ (standard with Python)

### Installation

Install in editable development mode from the repository root:

```bash
pip install -e .
```

To install development dependencies (pytest, pytest-cov, ruff):

```bash
pip install -e ".[dev]"
```

---

## 🛠️ CLI Workflow

TraceGraph provides a modern CLI interface powered by Typer and Rich.

### 1. Initialize Workspace

Create a new local investigation workspace and initialize the SQLite evidence database (schema v2.0.0):

```bash
# Initialize default workspace in .tracegraph/
tracegraph init

# Or specify an explicit workspace directory
tracegraph init --workspace /path/to/custom_workspace
```

`tracegraph init` is idempotent and upgrades legacy v1.0.0 databases automatically.

### 2. Inspect Status

Inspect workspace connectivity, database integrity, schema version, and entity counters:

```bash
tracegraph status
```

### 3. Create an Investigation Scope

Establish an investigation boundary with a declared target scope:

```bash
tracegraph investigate new "Incident-2026-Alpha" \
  --scope "example.com, *.example.com, 93.184.215.0/24" \
  --desc "Infrastructure assessment of target perimeters"
```

List existing investigations:

```bash
tracegraph investigate list
```

Inspect investigation details:

```bash
tracegraph investigate show <investigation-id>
```

### 4. Collect Evidence

Execute bounded collectors against targets within the declared investigation scope:

#### Live DNS Resolution (`live_dns`)
Performs live DNS resolution for `A`, `AAAA`, `NS`, and `MX` records using configurable recursive resolvers:

```bash
tracegraph collect example.com --collector live_dns
```

> **Note:** DNS queries represent **live DNS resolution** directly against authoritative or configured resolvers, not historical passive DNS archives. Does not perform port scans, brute-force subdomain discovery, or exploitation.

#### Bounded RDAP (`rdap`)
Queries public IP address allocations via standards-compliant RFC 7484 bootstrap routing (ARIN bootstrap routing to RIPE, APNIC, LACNIC, and AFRINIC):

```bash
tracegraph collect 93.184.215.14 --collector rdap
```

> **Safety & Privacy:**
> - Strictly refuses private, loopback, and reserved addresses (SSRF defense).
> - Automatically strips individual personal data (`vcardArray`, contact names, personal phone numbers, and emails).
> - Discovers CIDR block allocations and links them via `BELONGS_TO` relationships.
> - Never invents ownership or registration claims without explicit registry data.

#### Deterministic Mock Collector (`mock_dns`)
Deterministic offline collector for verification and testing without network access:

```bash
tracegraph collect example.com --collector mock_dns
```

### 5. Generate Evidence-Backed Report

Generate a Markdown investigation report containing metadata, declared scope, collected observations, entity discoveries, and verified relationship citations:

```bash
# Display report in terminal
tracegraph report <investigation-id>

# Export report directly to Markdown file
tracegraph report <investigation-id> --output investigation_report.md
```

---

## 📊 Core Data Architecture

| Concept | Purpose | Integrity Rule |
| :--- | :--- | :--- |
| **Investigation** | Defines target scope boundary, targets, and execution configuration. | Immutable created timestamp, unique UUIDv4. |
| **Entity** | Distinct infrastructure artifact (domain, IP, ASN, CIDR, etc.). | Strict normalization and unique `(entity_type, canonical_value)` constraint to prevent duplicate nodes. |
| **Observation** | Concrete evidence collected by an identified collector. | Contains investigation reference, source reference, collector version, observation timestamp, and ingestion timestamp. |
| **Relationship** | Directional link between two infrastructure entities (e.g., `RESOLVES_TO`, `BELONGS_TO`, `SERVED_BY`). | Unique directional edge constraint. Foreign key cascade to entities. |
| **Evidence Link** | Join table linking Relationships to supporting Observations. | **Provenance rule:** A relationship is only considered `[VERIFIED]` if backed by at least one observation. Unsupported links are flagged `[UNVERIFIED]`. |

---

## 🛡️ Scope & Safe Use Policy

TraceGraph is strictly designed for authorized, defensive investigations:

1. **Scope Authorization:** Only investigate domains, IP addresses, and infrastructure you own or have explicit written permission to assess.
2. **Passive and Controlled:** The core system does not perform aggressive port scanning, exploitation, vulnerability assessment, or credential gathering.
3. **Local Sovereignty:** All investigation databases, evidence logs, and configuration files reside on your local machine.

---

## 🔧 Troubleshooting

### 1. `Database table creation failed` or Permission Denied
Ensure your user account has write permissions to the designated workspace directory. TraceGraph creates the database file `tracegraph.db` with enforced SQLite foreign keys.

### 2. `Database file exists but is corrupted`
If an invalid or corrupted file occupies the workspace database path (`tracegraph.db`), TraceGraph refuses to overwrite it to prevent data loss. Move or back up the corrupt file before re-running `tracegraph init`.

### 3. Missing Dependencies
If running in a minimal environment, ensure essential dependencies are installed:
```bash
pip install typer pydantic sqlalchemy rich
```

---

## 📚 Documentation

For deeper details, consult the comprehensive documentation guides:
- [Architecture & Design Principles](docs/architecture.md)
- [Evidence Data Model & Schema](docs/data-model.md)
- [Threat Model & Defensive Boundaries](docs/threat-model.md)

---

## ⚖️ License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
