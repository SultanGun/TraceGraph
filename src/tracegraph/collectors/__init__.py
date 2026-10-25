"""Collector interface and deterministic synthetic implementations."""

from tracegraph.collectors.base import (
    BaseCollector,
    CollectorResult,
    DiscoveredEntity,
    DiscoveredRelationship,
)
from tracegraph.collectors.mock import MockDNSCollector

__all__ = [
    "BaseCollector",
    "CollectorResult",
    "DiscoveredEntity",
    "DiscoveredRelationship",
    "MockDNSCollector",
]
