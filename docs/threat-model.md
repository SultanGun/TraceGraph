# TraceGraph Threat Model & Defensive Security Architecture

## 1. Scope & Objective

TraceGraph is a defensive OSINT infrastructure intelligence platform designed for authorized security practitioners, incident responders, and network defenders. This document defines the threat landscape, trust boundaries, architectural mitigations, and operational constraints governing the system.

---

## 2. Trust Boundaries

```
[ Untrusted Remote / User Inputs ]
   │
   ▼ (Input Validation & Normalization Boundary)
[ Core Domain Normalizers & Validators ]
   │
   ▼ (Type-Checked & Validated Boundary)
[ Collector Subsystem (Mock / Synthetic / Passive) ]
   │
   ▼ (Evidence Boundary)
[ Storage Subsystem (SQLAlchemy / Transactional SQLite) ]
   │
   ▼ (Local Persistence Boundary)
[ Local Disk: .tracegraph/tracegraph.db ]
```

### Trust Zones
1. **Untrusted Input Zone:** External domain strings, IP strings, command line arguments, and remote DNS/OSINT payloads.
2. **Execution Boundary:** Collector interface, Pydantic validation models, and normalization logic.
3. **Persistence Boundary:** Local filesystem and SQLite database with foreign-key constraints.

---

## 3. Threat Analysis & Mitigations

### 3.1 Command Injection & Shell Execution
- **Threat:** Malicious domain names containing shell metacharacters (e.g. `example.com; rm -rf /`) attempting to execute arbitrary commands.
- **Mitigation:**
  - TraceGraph **never** constructs or executes shell commands using user or target inputs.
  - Subprocesses are strictly avoided in core operations.
  - Domain names are strictly validated against RFC 1035 label syntax and IDNA rules.

### 3.2 SQL Injection
- **Threat:** Manipulated entity values or observation queries injecting SQL commands into local storage.
- **Mitigation:**
  - All database interactions use SQLAlchemy 2.0 ORM and parameterized queries.
  - Zero raw string formatting or string concatenation is used for SQL generation.

### 3.3 Path Traversal
- **Threat:** Malicious `--workspace` argument attempting to overwrite sensitive system directories (e.g. `../../etc` or `C:\Windows`).
- **Mitigation:**
  - Workspace paths are resolved using `pathlib.Path.resolve()`.
  - Non-destructive database creation: `init_workspace` checks whether the target file already exists and inspects its integrity before executing table creation. It refuses to overwrite arbitrary files.

### 3.4 Data Tampering & Evidence Provenance Spoofing
- **Threat:** An adversary or hallucinating AI injecting phantom relationships without proof.
- **Mitigation:**
  - Relational schema requires an explicit join row in `relationship_evidence` pointing to a valid foreign-key `observation_id`.
  - The model property `is_verified` is strictly boolean-computed based on evidence presence. An unlinked relationship can never be displayed or treated as verified.

### 3.5 Network Scanning & Abuse of Service
- **Threat:** Weaponizing OSINT collectors for active denial-of-service, vulnerability exploitation, or scanning unauthorized targets.
- **Mitigation:**
  - TraceGraph core collector interface enforces passive collection only.
  - Zero port scanning, zero exploit payloads, and zero credential bruteforcing functionality.
  - Collectors enforce mandatory timeouts.

### 3.6 Secret & Telemetry Leakage
- **Threat:** Accidental transmission of internal infrastructure details or exposure of secrets in status displays.
- **Mitigation:**
  - Zero telemetry or phone-home requests.
  - `tracegraph status` explicitly displays only workspace paths and counter metrics. It **never** dumps environment variables or auth tokens.

---

## 4. Defensive Operational Guidelines

1. **Authorization Verification:** TraceGraph must only be directed at domain names and infrastructure where the operator has explicit defensive authority or where publicly available passive records are permitted to be collected.
2. **Local Sovereignty:** Databases are stored on local storage. Operators are responsible for filesystem-level encryption (e.g. BitLocker, LUKS) to protect accumulated investigative intelligence.
3. **Audit Trail:** Maintain the integrity of the `observations` table. Never manually alter timestamps or source references in `tracegraph.db`.
