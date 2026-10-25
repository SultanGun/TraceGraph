"""Deterministic mock DNS collector utilizing local synthetic test fixtures."""

from datetime import datetime
from typing import Any

from tracegraph.collectors.base import (
    BaseCollector,
    CollectorResult,
    DiscoveredEntity,
    DiscoveredRelationship,
)
from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import CollectorExecutionError, CollectorTimeoutError

# Pre-seeded local synthetic fixtures for deterministic offline testing
DEFAULT_MOCK_FIXTURES: dict[str, dict[str, Any]] = {
    "example.com": {
        "status": CollectionStatus.SUCCESS,
        "records": {
            "A": ["93.184.215.14"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "NS": ["a.iana-servers.net", "b.iana-servers.net"],
        },
        "entities": [
            DiscoveredEntity(EntityType.IPV4, "93.184.215.14"),
            DiscoveredEntity(EntityType.IPV6, "2606:2800:220:1:248:1893:25c8:1946"),
            DiscoveredEntity(EntityType.NAMESERVER, "a.iana-servers.net"),
            DiscoveredEntity(EntityType.NAMESERVER, "b.iana-servers.net"),
        ],
        "relationships": [
            DiscoveredRelationship(
                source=DiscoveredEntity(EntityType.DOMAIN, "example.com"),
                relationship_type=RelationshipType.RESOLVES_TO,
                target=DiscoveredEntity(EntityType.IPV4, "93.184.215.14"),
            ),
            DiscoveredRelationship(
                source=DiscoveredEntity(EntityType.DOMAIN, "example.com"),
                relationship_type=RelationshipType.RESOLVES_TO,
                target=DiscoveredEntity(EntityType.IPV6, "2606:2800:220:1:248:1893:25c8:1946"),
            ),
            DiscoveredRelationship(
                source=DiscoveredEntity(EntityType.DOMAIN, "example.com"),
                relationship_type=RelationshipType.SERVED_BY,
                target=DiscoveredEntity(EntityType.NAMESERVER, "a.iana-servers.net"),
            ),
        ],
    },
    "sub.example.com": {
        "status": CollectionStatus.SUCCESS,
        "records": {
            "A": ["93.184.215.15"],
            "CNAME": ["example.com"],
        },
        "entities": [
            DiscoveredEntity(EntityType.IPV4, "93.184.215.15"),
            DiscoveredEntity(EntityType.DOMAIN, "example.com"),
        ],
        "relationships": [
            DiscoveredRelationship(
                source=DiscoveredEntity(EntityType.DOMAIN, "sub.example.com"),
                relationship_type=RelationshipType.SUBDOMAIN_OF,
                target=DiscoveredEntity(EntityType.DOMAIN, "example.com"),
            ),
            DiscoveredRelationship(
                source=DiscoveredEntity(EntityType.DOMAIN, "sub.example.com"),
                relationship_type=RelationshipType.RESOLVES_TO,
                target=DiscoveredEntity(EntityType.IPV4, "93.184.215.15"),
            ),
        ],
    },
    "empty.test": {
        "status": CollectionStatus.EMPTY,
        "records": {},
        "entities": [],
        "relationships": [],
    },
    "empty-domain.test": {
        "status": CollectionStatus.EMPTY,
        "records": {},
        "entities": [],
        "relationships": [],
    },
}


class MockDNSCollector(BaseCollector):
    """Deterministic, local synthetic DNS collector for defensive OSINT infrastructure testing.

    Features:
    - Purely local execution; never makes external network calls.
    - Deterministic responses for known synthetic domain fixtures.
    - Explicitly simulates SUCCESS, EMPTY, TIMEOUT, and FAILED states.
    - Provides verifiable source references and timestamps.
    """

    name: str = "mock_dns"
    version: str = "0.1.0"
    supported_entity_types: set[EntityType] = {EntityType.DOMAIN}

    def __init__(
        self,
        fixtures: dict[str, dict[str, Any]] | None = None,
        simulate_timeout_targets: set[str] | None = None,
        simulate_failure_targets: set[str] | None = None,
    ) -> None:
        self.fixtures = dict(DEFAULT_MOCK_FIXTURES)
        if fixtures:
            self.fixtures.update(fixtures)
        self.simulate_timeout_targets = simulate_timeout_targets or {
            "timeout.test",
            "slow-dns.test",
        }
        self.simulate_failure_targets = simulate_failure_targets or {
            "failure.test",
            "servfail.test",
        }

    def register_fixture(
        self,
        domain: str,
        status: CollectionStatus,
        records: dict[str, Any],
        entities: list[DiscoveredEntity],
        relationships: list[DiscoveredRelationship],
    ) -> None:
        """Register or override a synthetic fixture for deterministic tests."""
        self.fixtures[domain.lower()] = {
            "status": status,
            "records": records,
            "entities": entities,
            "relationships": relationships,
        }

    def _get_source_reference(self, target: str) -> str:
        return f"synthetic://mock-dns/{target}"

    def _execute_collection(
        self,
        target: str,
        entity_type: EntityType,
        timeout: float,
        observed_at: datetime,
    ) -> CollectorResult:
        source_ref = self._get_source_reference(target)

        # 1. Simulate explicit timeout targets
        if target in self.simulate_timeout_targets:
            raise CollectorTimeoutError(
                f"Synthetic DNS query to '{target}' exceeded configured timeout of {timeout}s"
            )

        # 2. Simulate explicit server failure targets
        if target in self.simulate_failure_targets:
            raise CollectorExecutionError(
                f"Synthetic DNS resolution failure: SERVFAIL received for '{target}'"
            )

        # 3. Lookup fixture
        fixture = self.fixtures.get(target)
        if not fixture:
            # Unrecognized domain defaults to deterministic EMPTY status (NXDOMAIN / no records)
            return CollectorResult(
                status=CollectionStatus.EMPTY,
                collector_name=self.name,
                collector_version=self.version,
                source_reference=source_ref,
                observed_at=observed_at,
                duration_seconds=0.0,
                data={
                    "query": target,
                    "answers": [],
                    "notice": "Target not found in synthetic DNS database",
                },
                discovered_entities=[],
                discovered_relationships=[],
            )

        status: CollectionStatus = fixture["status"]
        records: dict[str, Any] = fixture.get("records", {})
        entities: list[DiscoveredEntity] = fixture.get("entities", [])
        relationships: list[DiscoveredRelationship] = fixture.get("relationships", [])

        return CollectorResult(
            status=status,
            collector_name=self.name,
            collector_version=self.version,
            source_reference=source_ref,
            observed_at=observed_at,
            duration_seconds=0.0,
            data={
                "query": target,
                "records": records,
                "protocol": "synthetic-dns",
            },
            discovered_entities=entities,
            discovered_relationships=relationships,
        )
