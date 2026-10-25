# TraceGraph

> **Local-first, evidence-first OSINT infrastructure intelligence platform.**

TraceGraph is an open-source, local-first intelligence platform engineered for authorized defensive investigations of public internet infrastructure. Every relationship and discovery is anchored in verifiable observation evidence with explicit provenance.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)]()

---

## 💡 Core Differentiators

- **Evidence Provenance:** Every observation explicitly records the originating collector identity, version, source reference, observation timestamp, and ingestion timestamp in UTC. Unsupported relationships are never presented as verified.
- **Reproducible Investigations:** Collection runs, configuration scopes, and discrete entity linkages are preserved in local SQLite storage with enforced foreign-key integrity.
- **Temporal Intelligence:** Clean separation between observation time (when raw telemetry was observed) and ingestion time (when records entered storage), providing snapshot comparison capabilities.
- **AI-Ready Architecture:** Designed from the ground up so that future AI reasoning modules must cite verifiable database evidence rather than hallucinating infrastructure links.
- **Defensive & Local-First:** Operates completely offline by default. Zero telemetry, zero external network calls during initialization, and zero credential collection.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12 or higher (Python 3.14 compatible)
- SQLite 3.35+ (standard with Python)

### Installation

Install in editable development mode from the repository root:

```bash
pip install -e .
```

To install development dependencies (pytest, ruff):

```bash
pip install -e ".[dev]"
```

---

## 🛠️ CLI Usage

TraceGraph provides a modern CLI interface powered by Typer and Rich.

### Check Version

```bash
tracegraph version
# Output: TraceGraph v0.1.0-alpha
```

Or view CLI help options:

```bash
tracegraph --help
```

### Initialize Workspace

Create a new local investigation workspace and initialize the SQLite evidence database:

```bash
# Initialize default workspace in .tracegraph/
tracegraph init

# Or specify a custom workspace directory
tracegraph init --workspace /path/to/custom_workspace
```

`tracegraph init` is safe and idempotent:
- It creates required schema tables and metadata.
- It will **never** overwrite or destroy an existing healthy database.
- Rerunning `tracegraph init` against an initialized workspace safely confirms its current state.

### Inspect Status

Inspect workspace connectivity, database integrity, schema version, and entity counters:

```bash
# Check default workspace
tracegraph status

# Check specific workspace
tracegraph status --workspace /path/to/custom_workspace
```

Example status table output:

```text
               TraceGraph System & Workspace Status               
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property              ┃ Value                                  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ TraceGraph Version    │ v0.1.0-alpha                           │
│ Workspace Directory   │ /path/to/workspace/.tracegraph         │
│ Workspace Exists      │ Yes                                    │
│ Database Path         │ /path/to/workspace/.tracegraph/traceg… │
│ Database File Exists  │ Yes                                    │
│ Database Connectivity │ CONNECTED (Foreign keys ON)            │
│ Schema Status         │ INITIALIZED (Schema v1.0.0)            │
│ Total Entities        │ 4                                      │
│ Total Observations    │ 4                                      │
│ Total Relationships   │ 3                                      │
└───────────────────────┴────────────────────────────────────────┘
```

---

## 📊 Core Data Architecture

| Concept | Purpose | Integrity Rule |
| :--- | :--- | :--- |
| **Investigation** | Defines scope boundary, targets, and execution configuration. | Immutable created timestamp, unique identifier. |
| **Entity** | Distinct infrastructure artifact (domain, IP, ASN, CIDR, etc.). | Strict normalization and unique `(entity_type, normalized_value)` constraint to prevent duplicate nodes. |
| **Observation** | Concrete evidence collected by an identified collector. | Contains source reference, collector version, observation timestamp, and ingestion timestamp. |
| **Relationship** | Directional link between two infrastructure entities (e.g., `RESOLVES_TO`). | Unique directional edge constraint. Foreign key cascade to entities. |
| **Evidence Link** | Join table linking Relationships to supporting Observations. | **Provenance rule:** A relationship is only considered `verified` if backed by at least one observation. Unsupported links cannot be presented as verified findings. |

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
