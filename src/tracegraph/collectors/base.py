"""Abstract base class and data containers for defensive OSINT collectors."""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from tracegraph.core.enums import CollectionStatus, EntityType, RelationshipType
from tracegraph.core.exceptions import (
    CollectorError,
    CollectorTimeoutError,
    CollectorValidationError,
)
from tracegraph.core.normalizers import validate_and_normalize


@dataclass(frozen=True)
class DiscoveredEntity:
    """An infrastructure node discovered during collection."""

    entity_type: EntityType
    raw_value: str


@dataclass(frozen=True)
class DiscoveredRelationship:
    """A directional relationship between two discovered entities."""

    source: DiscoveredEntity
    relationship_type: RelationshipType
    target: DiscoveredEntity


@dataclass
class CollectorResult:
    """Structured, verifiable result returned by a collector run."""

    status: CollectionStatus
    collector_name: str
    collector_version: str
    source_reference: str
    observed_at: datetime
    duration_seconds: float
    data: dict[str, Any] = field(default_factory=dict)
    discovered_entities: list[DiscoveredEntity] = field(default_factory=list)
    discovered_relationships: list[DiscoveredRelationship] = field(default_factory=list)
    error_message: str | None = None
    error_details: dict[str, Any] | None = None

    @property
    def is_successful(self) -> bool:
        """True if collection completed with findings."""
        return self.status == CollectionStatus.SUCCESS

    @property
    def is_empty(self) -> bool:
        """True if collection completed successfully but yielded zero findings."""
        return self.status == CollectionStatus.EMPTY

    @property
    def is_failure(self) -> bool:
        """True if collection encountered an unrecoverable error or timeout."""
        return self.status in (CollectionStatus.FAILED, CollectionStatus.TIMEOUT)


class BaseCollector(ABC):
    """Abstract interface for all OSINT infrastructure collectors.

    Principles:
    - Never scan or exploit without explicit scope.
    - Provide complete provenance: collector identity, source reference, and timestamp.
    - Deterministic, observable error handling and status differentiation.
    """

    name: str = "base_collector"
    version: str = "0.1.0"
    supported_entity_types: set[EntityType] = set()

    def validate_input(self, target: str, entity_type: EntityType | str) -> tuple[EntityType, str]:
        """Validate that input target matches supported types and is well-formed.

        Returns (EntityType, normalized_target).
        Raises CollectorValidationError on invalid input.
        """
        try:
            typed_type, normalized = validate_and_normalize(entity_type, target)
        except Exception as e:
            raise CollectorValidationError(f"Invalid target '{target}': {e}") from e

        if typed_type not in self.supported_entity_types:
            supported = ", ".join(t.value for t in self.supported_entity_types)
            raise CollectorValidationError(
                f"Collector '{self.name}' does not support entity type '{typed_type.value}'. "
                f"Supported types: {supported}"
            )

        return typed_type, normalized

    def collect(
        self,
        target: str,
        entity_type: EntityType | str,
        timeout: float = 10.0,
    ) -> CollectorResult:
        """Execute collection with input validation, timeout protection, and tracking."""
        typed_type, normalized = self.validate_input(target, entity_type)

        start_time = time.perf_counter()
        observed_at = datetime.now(UTC)

        try:
            result = self._execute_collection(
                target=normalized,
                entity_type=typed_type,
                timeout=timeout,
                observed_at=observed_at,
            )
            duration = round(time.perf_counter() - start_time, 4)
            result.duration_seconds = duration
            return result
        except CollectorTimeoutError as e:
            duration = round(time.perf_counter() - start_time, 4)
            return CollectorResult(
                status=CollectionStatus.TIMEOUT,
                collector_name=self.name,
                collector_version=self.version,
                source_reference=self._get_source_reference(normalized),
                observed_at=observed_at,
                duration_seconds=duration,
                error_message=str(e),
                error_details={"timeout_limit": timeout},
            )
        except CollectorError as e:
            duration = round(time.perf_counter() - start_time, 4)
            return CollectorResult(
                status=CollectionStatus.FAILED,
                collector_name=self.name,
                collector_version=self.version,
                source_reference=self._get_source_reference(normalized),
                observed_at=observed_at,
                duration_seconds=duration,
                error_message=str(e),
            )
        except Exception as e:
            duration = round(time.perf_counter() - start_time, 4)
            return CollectorResult(
                status=CollectionStatus.FAILED,
                collector_name=self.name,
                collector_version=self.version,
                source_reference=self._get_source_reference(normalized),
                observed_at=observed_at,
                duration_seconds=duration,
                error_message=f"Unhandled collector crash: {e}",
                error_details={"exception_type": type(e).__name__},
            )

    @abstractmethod
    def _execute_collection(
        self,
        target: str,
        entity_type: EntityType,
        timeout: float,
        observed_at: datetime,
    ) -> CollectorResult:
        """Internal execution method implemented by subclasses."""

    @abstractmethod
    def _get_source_reference(self, target: str) -> str:
        """Generate human- and audit-readable source provenance identifier."""
