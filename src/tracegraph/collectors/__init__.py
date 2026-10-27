"""Collector interface, live resolvers, and deterministic synthetic implementations."""

from tracegraph.collectors.base import (
    BaseCollector,
    CollectorResult,
    DiscoveredEntity,
    DiscoveredRelationship,
)
from tracegraph.collectors.dns import LiveDNSCollector
from tracegraph.collectors.mock import MockDNSCollector
from tracegraph.collectors.rdap import RDAPCollector

__all__ = [
    "BaseCollector",
    "CollectorResult",
    "DiscoveredEntity",
    "DiscoveredRelationship",
    "MockDNSCollector",
    "LiveDNSCollector",
    "RDAPCollector",
]
