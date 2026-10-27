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
- **Threat:** Malicious target inputs (e.g. `127.0.0.1`, `169.254.169.254`, `10.0.0.1`, `::1`, `::ffff:127.0.0.1`) attempting Server-Side Request Forgery against cloud metadata endpoints or local internal services via RDAP or DNS collectors.
- **Mitigation:**
  - `src/tracegraph/core/scope.py` implements strict RFC checking (`is_public_ip` and `assert_public_ip`).
  - Blocks RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 6890 loopbacks (`127.0.0.0/8`, `::1/128`), RFC 3927 link-local addresses (`169.254.0.0/16`), RFC 6598 carrier-grade NAT (`100.64.0.0/10`), RFC 5737 documentation test networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), unique local IPv6 (`fc00::/7`), link-local IPv6 (`fe80::/10`), and multicast ranges (`224.0.0.0/4`, `ff00::/8`).
  - Explicitly detects and extracts IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`), validating the embedded IPv4 address against disallowed network boundaries.
  - Rejects inputs without valid IP delimiters (`.` or `:`) to block integer or octal IP encoding bypasses.
  - Collector input validation rejects non-public targets immediately before any network socket or HTTP request is initiated.

### 3.8 Scope Escapes & Target Boundary Enforcement
- **Threat:** Operators or scripts collecting data against unauthorized targets outside the declared investigation scope.
- **Mitigation:**
  - Every collection run requires an active investigation.
  - `ScopeValidator` enforces that targets strictly match the declared scope (exact domain, subdomain wildcard `*.domain.com`, IP, CIDR block, or explicit unrestricted `*`).
  - Safely handles CIDR cross-version evaluations (IPv4 CIDR vs IPv6 network) without throwing unhandled TypeErrors.
  - Target out of scope causes immediate command termination with exit code 1 prior to collector instantiation.

### 3.9 Personal Data Minimization (PII Sanitization)
- **Threat:** Ingestion of personal contact details (individual names, personal email addresses, phone numbers) from registry RDAP responses into investigative databases.
- **Mitigation:**
  - `RDAPCollector` sanitizes payloads before storage.
  - Strips all `vcardArray` structures, individual contact emails, telephone numbers, and postal addresses.
  - Preserves only public organization/network handles, entity roles, CIDR ranges, and registration dates.
  - Never invents ownership or registration claims without explicit registry data.

### 3.10 Insecure Redirect, SSRF & Response Flood Protection
- **Threat:** Malicious RDAP redirect chains routing requests to insecure HTTP endpoints, internal services, cloud metadata services, circular loops, or returning multi-megabyte payloads to exhaust memory.
- **Mitigation:**
  - **Redirect Policy:**
    - Scheme must strictly be `https`.
    - Relative URLs are safely resolved via `urljoin(current_url, loc)`.
    - Destination hostnames are validated prior to connection: rejects `localhost`, internal domain suffixes (`.local`, `.internal`, `.lan`, `.home.arpa`), and non-public IP literals.
    - Redirect destination host must match an allowed authoritative RDAP registry list (`rdap.arin.net`, `rdap.ripe.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net`, `rdap.iana.org`, `data.iana.org`, `rdap.nic.mil`) or the operator's configured bootstrap host.
    - Circular redirect detection: tracks visited URLs and aborts immediately upon loop detection.
    - Maximum redirect depth capped at 3 hops.
  - **Streaming Response Size Enforcement:**
    - Checks `Content-Length` header upfront; aborts if greater than 512 KB (`MAX_RDAP_RESPONSE_BYTES`).
    - Uses `client.stream("GET", ...)` to read data in 8 KB chunks. Running byte count is evaluated per chunk; connection is severed immediately if bytes exceed 512 KB, preventing memory exhaustion attacks from chunked responses or misleading headers.
  - **Rate Limiting:**
    - Conservative delay enforced before *every* outbound request, including each individual redirect hop.
    - Throttling protected by a thread-safe mutex lock.
  - **Database Integrity Invariant:**
    - If collection outcome is `FAILED` or `TIMEOUT`, the observation is recorded for provenance audit, but **zero** entity relationships are created or linked.

---

## 4. Known Architectural Limitations & Residual Risks

1. **DNS Rebinding in Standard HTTP Client:**
   While TraceGraph validates hostnames against allowlists and validates IP literals before connection, standard user-space HTTP clients (such as HTTPX) rely on the operating system resolver during socket connect. An authorized host whose DNS records are maliciously poisoned or dynamically changed between lookup and socket creation cannot be completely mitigated without custom TCP transport socket-level IP pinning.
2. **Bootstrap Availability:**
   TraceGraph defaults to the ARIN RFC 7484 bootstrap endpoint. If this endpoint is unreachable or returning HTTP 5xx errors, lookups will fail gracefully with a timeout or network error rather than silent data corruption. Operators should configure alternative or local mirror endpoints via `--bootstrap-url` in restricted enterprise networks.
3. **Unrestricted Scope Flag (`*`):**
   Investigations created with `--scope "*"` or legacy v0.1 migrations explicitly permit collection against any public target. Operators must exercise caution to ensure investigations are scoped to authorized assets. Target SSRF and private IP protections remain enforced even under unrestricted scope.

---

## 4. Defensive Operational Guidelines

1. **Authorization Verification:** TraceGraph must only be directed at domain names and infrastructure where the operator has explicit defensive authority or where publicly available passive records are permitted to be collected.
2. **Local Sovereignty:** Databases are stored on local storage. Operators are responsible for filesystem-level encryption (e.g. BitLocker, LUKS) to protect accumulated investigative intelligence.
3. **Audit Trail:** Maintain the integrity of the `observations` table. Never manually alter timestamps or source references in `tracegraph.db`.
