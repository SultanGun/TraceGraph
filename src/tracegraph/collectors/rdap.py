"""Bounded RDAP collector for public IP address registries."""

import ipaddress
import json
import logging
import threading
import time
from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from tracegraph.collectors.base import (
    BaseCollector,
    CollectorResult,
    DiscoveredEntity,
    DiscoveredRelationship,
)
from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import (
    CollectorExecutionError,
    CollectorTimeoutError,
    CollectorValidationError,
)
from tracegraph.core.normalizers import normalize_cidr
from tracegraph.core.scope import is_public_ip

logger = logging.getLogger(__name__)

DEFAULT_RDAP_BOOTSTRAP_URL = "https://rdap.arin.net/registry/ip"
MAX_RDAP_RESPONSE_BYTES = 512 * 1024  # 512 KB limit to prevent response flood
DEFAULT_RDAP_TIMEOUT = 10.0

# Authorized authoritative Regional Internet Registry RDAP domains
DEFAULT_ALLOWED_RDAP_HOSTS: frozenset[str] = frozenset({
    "rdap.arin.net",
    "rdap.ripe.net",
    "rdap.apnic.net",
    "rdap.lacnic.net",
    "rdap.afrinic.net",
    "rdap.iana.org",
    "data.iana.org",
    "rdap.nic.mil",
})


class RDAPCollector(BaseCollector):
    """Standards-compliant, bounded RDAP collector for public IP registrations.

    Safety & Privacy Constraints:
    - Only queries globally routable public IP addresses (SSRF defense).
    - Uses standard RIR bootstrap routing (RFC 7484).
    - Enforces strict response size limits and timeouts while streaming.
    - Strips personal contact information (vCard PII) from evidence data.
    - Validates all redirect destination hosts against allowed RDAP registries.
    - Rejects redirects to private, loopback, link-local, or internal hosts.
    - Prevents circular redirect loops and limits redirect depth.
    - Does not invent ownership claims without explicit registry evidence.
    """

    name: str = "rdap"
    version: str = "0.2.0"
    supported_entity_types: set[EntityType] = {EntityType.IPV4, EntityType.IPV6}

    def __init__(
        self,
        http_client: httpx.Client | None = None,
        bootstrap_url: str = DEFAULT_RDAP_BOOTSTRAP_URL,
        timeout: float = DEFAULT_RDAP_TIMEOUT,
        rate_limit_delay: float = 0.5,
        allowed_hosts: set[str] | None = None,
    ) -> None:
        self._custom_client = http_client
        self.bootstrap_url = bootstrap_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time: float = 0.0
        self._rate_limit_lock = threading.Lock()

        # Build allowed hosts set, always including bootstrap host
        bootstrap_host = urlparse(self.bootstrap_url).hostname or ""
        self.allowed_hosts: set[str] = (
            set(allowed_hosts) if allowed_hosts else set(DEFAULT_ALLOWED_RDAP_HOSTS)
        )
        if bootstrap_host:
            self.allowed_hosts.add(bootstrap_host.lower())

    def _get_source_reference(self, target: str) -> str:
        return f"{self.bootstrap_url}/{target}"

    def validate_input(self, target: str, entity_type: EntityType | str) -> tuple[EntityType, str]:
        """Validate IP address and ensure it is globally routable (not private/reserved)."""
        typed_type, normalized = super().validate_input(target, entity_type)

        try:
            ip = ipaddress.ip_address(normalized)
        except ValueError as e:
            raise CollectorValidationError(f"Invalid IP address '{target}': {e}") from e

        # Reject IPv4-mapped IPv6 if non-public
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            if not is_public_ip(str(ip.ipv4_mapped)):
                raise CollectorValidationError(
                    f"Target '{target}' is an IPv4-mapped private, loopback, or reserved address. "
                    "RDAP queries are only permitted for globally routable public IP addresses."
                )

        if not is_public_ip(normalized):
            raise CollectorValidationError(
                f"Target '{target}' is a private, loopback, or reserved IP address. "
                "RDAP queries are only permitted for globally routable public IP addresses."
            )

        return typed_type, normalized

    def _apply_rate_limit(self) -> None:
        """Enforce conservative interval between RDAP queries in a thread-safe manner."""
        with self._rate_limit_lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
            self._last_request_time = time.time()

    def _validate_destination_url(self, target_url: str) -> None:
        """Validate destination URL against SSRF, loopback, and unauthorized host risks."""
        parsed = urlparse(target_url)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise CollectorExecutionError(
                f"Insecure redirect rejected: RDAP endpoints must use HTTPS ({target_url})"
            )

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            raise CollectorExecutionError(
                f"Prohibited destination: missing hostname in '{target_url}'"
            )

        # Reject loopback, link-local, and internal domain suffixes
        if (
            hostname in ("localhost", "127.0.0.1", "::1")
            or hostname.endswith((".local", ".internal", ".lan", ".localhost", ".home.arpa"))
        ):
            raise CollectorExecutionError(
                f"Prohibited redirect destination: internal or loopback host '{hostname}'"
            )

        # If hostname is an IP literal, ensure it is a public IP
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if not is_public_ip(str(ip_obj)):
                raise CollectorExecutionError(
                    f"Prohibited redirect destination: non-public IP literal '{hostname}'"
                )
        except ValueError:
            pass

        # Registry allowlist check
        if self.allowed_hosts:
            is_allowed = (
                hostname in self.allowed_hosts
                or any(hostname.endswith("." + h) for h in self.allowed_hosts)
            )
            if not is_allowed:
                raise CollectorExecutionError(
                    f"Prohibited redirect destination: untrusted host '{hostname}' "
                    "not in authorized RDAP registry allowlist"
                )

    def _safe_fetch(self, url: str) -> tuple[int, dict[str, Any], str]:
        """Fetch RDAP JSON with redirect validation, size checks, and timeout protection."""
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "TraceGraph/0.2.0 (Defensive Intelligence Platform; +https://tracegraph.org)",
        }

        # Check client
        client = self._custom_client
        should_close = False
        if client is None:
            client = httpx.Client(timeout=self.timeout, follow_redirects=False)
            should_close = True

        current_url = url
        redirect_count = 0
        max_redirects = 3
        visited_urls: set[str] = set()

        try:
            while redirect_count <= max_redirects:
                # 1. Circular redirect check
                if current_url in visited_urls:
                    raise CollectorExecutionError(
                        f"Circular redirect loop detected: '{current_url}' visited multiple times"
                    )
                visited_urls.add(current_url)

                # 2. Validate scheme, SSRF, and destination host
                self._validate_destination_url(current_url)

                # 3. Apply rate limit before every outbound request (initial + redirect hops)
                self._apply_rate_limit()

                # 4. Stream response to enforce size limits while downloading
                try:
                    with client.stream("GET", current_url, headers=headers) as resp:
                        # Handle redirects
                        if resp.status_code in (301, 302, 307, 308):
                            loc = resp.headers.get("Location")
                            if not loc:
                                raise CollectorExecutionError(
                                    f"RDAP redirect HTTP {resp.status_code} missing Location"
                                )
                            new_url = urljoin(current_url, loc)
                            redirect_count += 1
                            current_url = new_url
                            continue

                        # Check Content-Length header upfront if present
                        content_len = resp.headers.get("Content-Length")
                        if content_len:
                            try:
                                if int(content_len) > MAX_RDAP_RESPONSE_BYTES:
                                    limit_kb = MAX_RDAP_RESPONSE_BYTES // 1024
                                    raise CollectorExecutionError(
                                        f"RDAP response exceeds limit ({limit_kb} KB)"
                                    )
                            except ValueError:
                                pass

                        # Stream body chunks with strict byte limit
                        body_chunks: list[bytes] = []
                        total_bytes = 0
                        for chunk in resp.iter_bytes(chunk_size=8192):
                            total_bytes += len(chunk)
                            if total_bytes > MAX_RDAP_RESPONSE_BYTES:
                                raise CollectorExecutionError(
                                    f"RDAP response exceeds limit ({MAX_RDAP_RESPONSE_BYTES} bytes)"
                                )
                            body_chunks.append(chunk)

                        body_bytes = b"".join(body_chunks)
                        status_code = resp.status_code

                except httpx.TimeoutException as e:
                    raise CollectorTimeoutError(
                        f"RDAP request to '{current_url}' timed out: {e}"
                    ) from e
                except httpx.RequestError as e:
                    raise CollectorExecutionError(
                        f"RDAP network error for '{current_url}': {e}"
                    ) from e

                if status_code == 404:
                    return 404, {}, current_url

                if status_code == 429:
                    raise CollectorExecutionError(
                        f"RDAP rate limit exceeded (HTTP 429) at '{current_url}'"
                    )

                if status_code >= 400:
                    raise CollectorExecutionError(
                        f"RDAP query failed with HTTP {status_code} at '{current_url}'"
                    )

                # Parse JSON
                try:
                    text_payload = body_bytes.decode("utf-8", errors="replace")
                    data = json.loads(text_payload)
                    if not isinstance(data, dict):
                        raise ValueError("RDAP root payload must be a JSON object")
                    return status_code, data, current_url
                except Exception as e:
                    raise CollectorExecutionError(
                        f"Malformed JSON returned by RDAP server '{current_url}': {e}"
                    ) from e

            raise CollectorExecutionError(
                f"RDAP request exceeded maximum redirect limit ({max_redirects})"
            )
        finally:
            if should_close:
                client.close()

    def _sanitize_rdap_payload(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Strip personal contact information (vCards, individual phone numbers, emails).

        Preserves public network handles, names, CIDR ranges, and registration events.
        """
        sanitized: dict[str, Any] = {
            "handle": raw_data.get("handle"),
            "name": raw_data.get("name"),
            "startAddress": raw_data.get("startAddress"),
            "endAddress": raw_data.get("endAddress"),
            "ipVersion": raw_data.get("ipVersion"),
            "type": raw_data.get("type"),
            "country": raw_data.get("country"),
            "parentHandle": raw_data.get("parentHandle"),
            "events": [],
            "cidr0_cidrs": [],
            "entities": [],
        }

        # Extract CIDRs if present
        cidrs = raw_data.get("cidr0_cidrs", [])
        if isinstance(cidrs, list):
            for c in cidrs:
                if isinstance(c, dict) and "v4prefix" in c and "length" in c:
                    sanitized["cidr0_cidrs"].append(f"{c['v4prefix']}/{c['length']}")
                elif isinstance(c, dict) and "v6prefix" in c and "length" in c:
                    sanitized["cidr0_cidrs"].append(f"{c['v6prefix']}/{c['length']}")

        # Extract registration events (registration date, last modified date)
        events = raw_data.get("events", [])
        if isinstance(events, list):
            for ev in events:
                if isinstance(ev, dict) and "eventAction" in ev and "eventDate" in ev:
                    sanitized["events"].append(
                        {"action": ev["eventAction"], "date": ev["eventDate"]}
                    )

        # Sanitize entity references (keep only handle and roles, strip vCard PII)
        entities = raw_data.get("entities", [])
        if isinstance(entities, list):
            for ent in entities:
                if isinstance(ent, dict):
                    clean_ent = {
                        "handle": ent.get("handle"),
                        "roles": ent.get("roles", []),
                    }
                    sanitized["entities"].append(clean_ent)

        return sanitized

    def _execute_collection(
        self,
        target: str,
        entity_type: EntityType,
        timeout: float,
        observed_at: datetime,
    ) -> CollectorResult:
        query_url = f"{self.bootstrap_url}/{target}"

        status_code, raw_json, final_url = self._safe_fetch(query_url)

        if status_code == 404:
            return CollectorResult(
                status=CollectionStatus.EMPTY,
                collector_name=self.name,
                collector_version=self.version,
                source_reference=final_url,
                observed_at=observed_at,
                duration_seconds=0.0,
                data={
                    "query": target,
                    "status_code": 404,
                    "notice": "IP address not found in authoritative RDAP registry",
                },
                discovered_entities=[],
                discovered_relationships=[],
            )

        sanitized_data = self._sanitize_rdap_payload(raw_json)
        sanitized_data["query"] = target
        sanitized_data["final_url"] = final_url
        sanitized_data["status_code"] = status_code

        discovered_entities: list[DiscoveredEntity] = []
        discovered_relationships: list[DiscoveredRelationship] = []

        target_entity = DiscoveredEntity(entity_type, target)

        # Extract CIDRs as entities & relationships
        for cidr_str in sanitized_data.get("cidr0_cidrs", []):
            try:
                norm_cidr = normalize_cidr(cidr_str)
                cidr_ent = DiscoveredEntity(EntityType.CIDR, norm_cidr)
                discovered_entities.append(cidr_ent)
                discovered_relationships.append(
                    DiscoveredRelationship(
                        source=target_entity,
                        relationship_type=RelationshipType.BELONGS_TO,
                        target=cidr_ent,
                    )
                )
            except Exception as e:
                logger.debug("Failed parsing CIDR from RDAP: %s", e)

        # If startAddress and endAddress exist and no cidr0_cidrs was present
        has_cidr = bool(sanitized_data.get("cidr0_cidrs"))
        has_range = bool(sanitized_data.get("startAddress") and sanitized_data.get("endAddress"))
        if not has_cidr and has_range:
            try:
                start_ip = ipaddress.ip_address(sanitized_data["startAddress"])
                end_ip = ipaddress.ip_address(sanitized_data["endAddress"])
                summarized = list(ipaddress.summarize_address_range(start_ip, end_ip))
                for net in summarized:
                    norm_cidr = str(net)
                    cidr_ent = DiscoveredEntity(EntityType.CIDR, norm_cidr)
                    discovered_entities.append(cidr_ent)
                    discovered_relationships.append(
                        DiscoveredRelationship(
                            source=target_entity,
                            relationship_type=RelationshipType.BELONGS_TO,
                            target=cidr_ent,
                        )
                    )
            except Exception as e:
                logger.debug("Failed summarizing address range: %s", e)

        # Deduplicate entities & relationships
        unique_entities: list[DiscoveredEntity] = []
        seen_entities: set[tuple[EntityType, str]] = set()
        for ent in discovered_entities:
            key = (ent.entity_type, ent.raw_value)
            if key not in seen_entities:
                seen_entities.add(key)
                unique_entities.append(ent)

        unique_relationships: list[DiscoveredRelationship] = []
        seen_relationships: set[tuple[Any, ...]] = set()
        for rel in discovered_relationships:
            key = (rel.source, rel.relationship_type, rel.target)
            if key not in seen_relationships:
                seen_relationships.add(key)
                unique_relationships.append(rel)

        return CollectorResult(
            status=CollectionStatus.SUCCESS,
            collector_name=self.name,
            collector_version=self.version,
            source_reference=final_url,
            observed_at=observed_at,
            duration_seconds=0.0,
            data=sanitized_data,
            discovered_entities=unique_entities,
            discovered_relationships=unique_relationships,
        )
