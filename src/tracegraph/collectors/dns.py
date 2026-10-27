"""Live DNS resolution collector using dnspython for defensive infrastructure investigations."""

import logging
from datetime import datetime
from typing import Any

import dns.exception
import dns.resolver

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
from tracegraph.core.normalizers import normalize_domain, normalize_ipv4, normalize_ipv6

logger = logging.getLogger(__name__)


class LiveDNSCollector(BaseCollector):
    """Live DNS resolution collector for authoritative infrastructure mapping.

    Notice:
    This collector executes live forward DNS queries against designated or system resolvers.
    It does NOT provide historical passive DNS data and does NOT prove ownership.
    """

    name: str = "live_dns"
    version: str = "0.2.0"
    supported_entity_types: set[EntityType] = {EntityType.DOMAIN}

    def __init__(
        self,
        resolver: dns.resolver.Resolver | None = None,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._custom_resolver = resolver
        self.nameservers = nameservers
        self.default_timeout = timeout

    def validate_input(self, target: str, entity_type: EntityType | str) -> tuple[EntityType, str]:
        """Validate domain name and reject special-use, loopback, and internal domains."""
        typed_type, normalized = super().validate_input(target, entity_type)

        clean = normalized.lower().rstrip(".")
        disallowed_suffixes = (".localhost", ".local", ".internal", ".lan", ".home.arpa")
        if clean == "localhost" or any(clean.endswith(s) for s in disallowed_suffixes):
            raise CollectorValidationError(
                f"Target '{target}' is a special-use, loopback, or internal domain. "
                "Live DNS queries are only permitted for public internet infrastructure."
            )

        return typed_type, normalized

    def _get_resolver(self, timeout: float) -> dns.resolver.Resolver:
        if self._custom_resolver is not None:
            return self._custom_resolver

        res = dns.resolver.Resolver()
        if self.nameservers:
            res.nameservers = self.nameservers
        res.timeout = timeout
        res.lifetime = timeout
        return res

    def _get_source_reference(self, target: str) -> str:
        if self.nameservers:
            servers = ",".join(self.nameservers)
            return f"dns://[{servers}]/{target}"
        return f"dns://system/{target}"

    def _execute_collection(
        self,
        target: str,
        entity_type: EntityType,
        timeout: float,
        observed_at: datetime,
    ) -> CollectorResult:
        resolver = self._get_resolver(timeout)
        source_ref = self._get_source_reference(target)

        records: dict[str, Any] = {"A": [], "AAAA": [], "NS": [], "MX": []}
        discovered_entities: list[DiscoveredEntity] = []
        discovered_relationships: list[DiscoveredRelationship] = []

        query_types = ["A", "AAAA", "NS", "MX"]
        had_nxdomain = False
        had_timeout = False
        had_failure = False
        total_answers_count = 0
        failure_messages: list[str] = []

        target_entity = DiscoveredEntity(EntityType.DOMAIN, target)

        for qtype in query_types:
            try:
                answers = resolver.resolve(target, qtype, lifetime=timeout)
                for rdata in answers:
                    total_answers_count += 1
                    if qtype == "A":
                        try:
                            norm_ip = normalize_ipv4(str(rdata.address))
                            records["A"].append(norm_ip)
                            ip_ent = DiscoveredEntity(EntityType.IPV4, norm_ip)
                            discovered_entities.append(ip_ent)
                            discovered_relationships.append(
                                DiscoveredRelationship(
                                    source=target_entity,
                                    relationship_type=RelationshipType.RESOLVES_TO,
                                    target=ip_ent,
                                )
                            )
                        except Exception as e:
                            logger.debug("Failed normalizing A record: %s", e)

                    elif qtype == "AAAA":
                        try:
                            norm_ip = normalize_ipv6(str(rdata.address))
                            records["AAAA"].append(norm_ip)
                            ip_ent = DiscoveredEntity(EntityType.IPV6, norm_ip)
                            discovered_entities.append(ip_ent)
                            discovered_relationships.append(
                                DiscoveredRelationship(
                                    source=target_entity,
                                    relationship_type=RelationshipType.RESOLVES_TO,
                                    target=ip_ent,
                                )
                            )
                        except Exception as e:
                            logger.debug("Failed normalizing AAAA record: %s", e)

                    elif qtype == "NS":
                        try:
                            ns_target = str(rdata.target).rstrip(".")
                            norm_ns = normalize_domain(ns_target)
                            records["NS"].append(norm_ns)
                            ns_ent = DiscoveredEntity(EntityType.NAMESERVER, norm_ns)
                            discovered_entities.append(ns_ent)
                            discovered_relationships.append(
                                DiscoveredRelationship(
                                    source=target_entity,
                                    relationship_type=RelationshipType.SERVED_BY,
                                    target=ns_ent,
                                )
                            )
                        except Exception as e:
                            logger.debug("Failed normalizing NS record: %s", e)

                    elif qtype == "MX":
                        try:
                            mx_target = str(rdata.exchange).rstrip(".")
                            norm_mx = normalize_domain(mx_target)
                            records["MX"].append(
                                {"preference": int(rdata.preference), "exchange": norm_mx}
                            )
                            mx_ent = DiscoveredEntity(EntityType.DOMAIN, norm_mx)
                            discovered_entities.append(mx_ent)
                            discovered_relationships.append(
                                DiscoveredRelationship(
                                    source=target_entity,
                                    relationship_type=RelationshipType.MAIL_EXCHANGER_FOR,
                                    target=mx_ent,
                                )
                            )
                        except Exception as e:
                            logger.debug("Failed normalizing MX record: %s", e)

            except dns.resolver.NXDOMAIN:
                had_nxdomain = True
                break  # NXDOMAIN means the entire domain does not exist
            except dns.resolver.NoAnswer:
                # Domain exists, but this specific record type does not
                continue
            except dns.exception.Timeout:
                had_timeout = True
                failure_messages.append(f"{qtype}: Query timed out")
            except dns.resolver.NoNameservers:
                had_failure = True
                failure_messages.append(f"{qtype}: No nameservers responded (SERVFAIL)")
            except Exception as e:
                had_failure = True
                failure_messages.append(f"{qtype}: {e}")

        # Deduplicate discovered entities and relationships preserving order
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

        data = {
            "query": target,
            "query_types": query_types,
            "records": records,
            "resolver": source_ref,
            "provenance": "live_dns_resolution",
            "notice": "Live DNS resolution. Does not establish legal ownership.",
        }

        # Determine outcome status
        if total_answers_count > 0:
            return CollectorResult(
                status=CollectionStatus.SUCCESS,
                collector_name=self.name,
                collector_version=self.version,
                source_reference=source_ref,
                observed_at=observed_at,
                duration_seconds=0.0,
                data=data,
                discovered_entities=unique_entities,
                discovered_relationships=unique_relationships,
            )

        if had_nxdomain or (not had_timeout and not had_failure):
            return CollectorResult(
                status=CollectionStatus.EMPTY,
                collector_name=self.name,
                collector_version=self.version,
                source_reference=source_ref,
                observed_at=observed_at,
                duration_seconds=0.0,
                data=data,
                discovered_entities=[],
                discovered_relationships=[],
            )

        if had_timeout:
            raise CollectorTimeoutError(
                f"Live DNS query for '{target}' timed out: {'; '.join(failure_messages)}"
            )

        raise CollectorExecutionError(
            f"Live DNS query for '{target}' failed: {'; '.join(failure_messages)}"
        )
