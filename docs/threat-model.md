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

### 3.7 SSRF & Private Network Enumeration Protection
- **Threat:** Malicious target inputs (e.g. `127.0.0.1`, `169.254.169.254`, `10.0.0.1`, `::1`) attempting Server-Side Request Forgery against cloud metadata endpoints or local internal services via RDAP or DNS collectors.
- **Mitigation:**
  - `src/tracegraph/core/scope.py` implements strict RFC checking (`is_public_ip` and `assert_public_ip`).
  - Blocks RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 6890 loopbacks (`127.0.0.0/8`, `::1/128`), RFC 3927 link-local addresses (`169.254.0.0/16`), RFC 6598 carrier-grade NAT (`100.64.0.0/10`), RFC 5737 documentation test networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), unique local IPv6 (`fc00::/7`), and multicast ranges.
  - Collector input validation rejects non-public targets immediately before any network socket or HTTP request is initiated.

### 3.8 Scope Escapes & Target Boundary Enforcement
- **Threat:** Operators or scripts collecting data against unauthorized targets outside the declared investigation scope.
- **Mitigation:**
  - Every collection run requires an active investigation.
  - `ScopeValidator` enforces that targets strictly match the declared scope (exact domain, subdomain wildcard `*.domain.com`, IP, CIDR block, or explicit unrestricted `*`).
  - Target out of scope causes immediate command termination with exit code 1 prior to collector instantiation.

### 3.9 Personal Data Minimization (PII Sanitization)
- **Threat:** Ingestion of personal contact details (individual names, personal email addresses, phone numbers) from registry RDAP responses into investigative databases.
- **Mitigation:**
  - `RDAPCollector` sanitizes payloads before storage.
  - Strips all `vcardArray` structures, individual contact emails, telephone numbers, and postal addresses.
  - Preserves only public organization/network handles, entity roles, CIDR ranges, and registration dates.
  - Never invents ownership or registration claims without explicit registry data.

### 3.10 Insecure Redirect & Response Flood Protection
- **Threat:** Malicious RDAP or DNS redirect chains routing requests to insecure HTTP endpoints or returning multi-megabyte payloads to exhaust memory.
- **Mitigation:**
  - Enforces HTTPS-only scheme on all RDAP redirect targets (`Location` headers).
  - Maximum redirect limit of 3.
  - Response size hard limit capped at 512 KB (`Content-Length` and received byte inspection).
  - Conservative rate-limiting delay between requests.

---

## 4. Defensive Operational Guidelines

1. **Authorization Verification:** TraceGraph must only be directed at domain names and infrastructure where the operator has explicit defensive authority or where publicly available passive records are permitted to be collected.
2. **Local Sovereignty:** Databases are stored on local storage. Operators are responsible for filesystem-level encryption (e.g. BitLocker, LUKS) to protect accumulated investigative intelligence.
3. **Audit Trail:** Maintain the integrity of the `observations` table. Never manually alter timestamps or source references in `tracegraph.db`.
