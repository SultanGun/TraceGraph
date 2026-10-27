# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-alpha] - 2026-10-26

### Added
- **Live DNS Collector (`live_dns`):**
  - Live recursive and authoritative DNS resolution for `A`, `AAAA`, `NS`, and `MX` records using `dnspython`.
  - Configurable resolver nameservers and explicit query timeouts.
  - Generates verifiable `RESOLVES_TO`, `SERVED_BY`, and `MAIL_EXCHANGER_FOR` relationships.
  - Distinguishes between `SUCCESS`, `EMPTY` (NXDOMAIN / NoAnswer), `TIMEOUT`, and `FAILED` collection outcomes.
- **Bounded RDAP Collector (`rdap`):**
  - Standards-compliant RDAP client using `httpx` with RFC 7484 bootstrap routing.
  - Automatic vCard PII sanitization (strips personal contact names, individual phone numbers, and emails).
  - Generates `BELONGS_TO` relationships between IP addresses and discovered CIDR allocations.
  - Defense-in-depth protections: HTTPS-only redirects, max 3 redirects, 512 KB response size cap, and rate limiting.
- **Investigation & Scope CLI Subsystem:**
  - `tracegraph investigate new <name> [--scope <scope>] [--desc <description>]`: Register new investigation boundaries.
  - `tracegraph investigate list`: Tabular overview of all registered investigations.
  - `tracegraph investigate show <id>`: Inspect detailed parameters and observation counters.
  - Pre-collection scope enforcement: `ScopeValidator` evaluates domain wildcards, CIDRs, and IPs before network access.
  - Immediate exit code 1 and error reporting on scope violations.
- **Reporting Engine:**
  - `tracegraph report <investigation-id> [--output <file>]`: Compiles comprehensive Markdown reports.
  - Features investigation metrics, declared scopes, observation provenance, and relationship verification tables annotated with `[VERIFIED]` / `[UNVERIFIED]` status badges and observation IDs.
- **Relational Schema v2.0.0 & Automated Migrations:**
  - Added `target_scope` column to `investigations` table.
  - Added `investigation_id` foreign key column and index to `observations` table.
  - Implemented transactional schema migration engine (`migrations.py`) upgrading v1.0.0 databases to v2.0.0.
  - Backfills legacy unassociated observations into an auto-created `legacy-v0.1-investigation` record without data loss.
- **SSRF & Network Safety:**
  - Strict IP validation blocking RFC 1918, RFC 6890, RFC 6598, RFC 3927, RFC 5737, and multicast addresses.

### Security
- **RDAP Redirect Destination & SSRF Hardening:**
  - Enforced strict destination validation on all HTTP redirect destinations (`Location` header).
  - Blocked redirects to loopback (`127.0.0.1`, `::1`, `localhost`), link-local (`169.254.0.0/16`), private RFC 1918, and internal domain names (`.local`, `.internal`, `.lan`, `.home.arpa`).
  - Added authoritative RIR registry host allowlist (`rdap.arin.net`, `rdap.ripe.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net`, `rdap.iana.org`, `data.iana.org`, `rdap.nic.mil`).
  - Implemented circular redirect loop detection and relative URL resolution.
- **Streaming Response Size Enforcement:**
  - Migrated HTTP client to chunked streaming (`client.stream`), evaluating running byte counts during download to prevent memory exhaustion / DoS from chunked or misleading headers.
- **IPv4-Mapped IPv6 & IPv6 Disallowed Range Handling:**
  - Hardened `is_public_ip` to unpack and validate IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`).
  - Added explicit disallowed IPv6 blocks for documentation (`2001:db8::/32`), discard prefix (`100::/64`), unique local (`fc00::/7`), and link-local (`fe80::/10`).
  - Rejected integer/hex formatted inputs without IP delimiters.
- **Scope & Scope Boundary Crash Prevention:**
  - Fixed unhandled `TypeError` in `ScopeValidator` during cross-version CIDR comparisons (IPv4 CIDR vs IPv6 network).
  - Added target validation in `LiveDNSCollector` to reject localhost and RFC 6761/6762 special-use internal domains.
- **Database Consistency Invariant:**
  - Enforced that collection runs with `FAILED` or `TIMEOUT` status record observations for provenance auditing but never create or link entity relationships.

### Changed
- Bumped package version to `0.2.0-alpha` (`0.2.0a1`).
- Upgraded `CURRENT_SCHEMA_VERSION` to `2.0.0`.
- Updated test suite with 100% offline mocks and dependency injection (total 86 tests).

---

## [0.1.0-alpha] - 2026-10-25

### Added
- **Core Foundation:**
  - Python 3.12+ package skeleton with `src/` layout and `pyproject.toml`.
  - Typer CLI with `tracegraph version`, `tracegraph init`, and `tracegraph status`.
  - Pydantic models for `InvestigationModel`, `EntityModel`, `ObservationModel`, `RelationshipModel`, and `EvidenceLinkModel`.
  - SQLAlchemy relational schema with foreign key enforcement (`PRAGMA foreign_keys = ON;`).
  - Normalization engine for domains, IPv4, IPv6, ASNs, CIDRs, nameservers, and certificate hashes.
  - Deterministic `MockDNSCollector` utilizing local synthetic fixtures for offline testing.
  - MIT License and initial architectural documentation.
