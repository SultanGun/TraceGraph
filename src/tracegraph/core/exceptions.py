"""Custom domain exceptions for TraceGraph."""


class TraceGraphError(Exception):
    """Base exception for all TraceGraph errors."""


class WorkspaceError(TraceGraphError):
    """Raised when an operation on a workspace fails."""


class WorkspaceAlreadyInitializedError(WorkspaceError):
    """Raised when trying to initialize an existing workspace without idempotency."""


class WorkspaceNotInitializedError(WorkspaceError):
    """Raised when an operation requires an initialized workspace that does not exist."""


class DatabaseError(TraceGraphError):
    """Base exception for database failures."""


class DatabaseIntegrityError(DatabaseError):
    """Raised when a unique constraint or foreign key check fails."""


class NotFoundError(DatabaseError):
    """Raised when an expected database record is not found."""


class MigrationError(DatabaseError):
    """Raised when database schema migration fails."""


class ModelValidationError(TraceGraphError):
    """Raised when model inputs or entities fail domain validation."""


class ScopeError(TraceGraphError):
    """Raised when target or operation falls outside authorized investigation scope."""


class CollectorError(TraceGraphError):
    """Base exception for collector execution failures."""


class CollectorValidationError(CollectorError):
    """Raised when collector target input fails validation."""


class CollectorTimeoutError(CollectorError):
    """Raised when collector execution exceeds configured timeout."""


class CollectorExecutionError(CollectorError):
    """Raised when collector execution crashes or encounters unexpected errors."""


class SnapshotError(TraceGraphError):
    """Base exception for snapshot and diff failures."""


class CrossInvestigationDiffError(SnapshotError):
    """Raised when attempting to compare snapshots from different investigations."""


class SnapshotIntegrityError(SnapshotError):
    """Raised when snapshot content fails hash digest verification or is corrupted."""


class AmbiguousSnapshotError(SnapshotError):
    """Raised when an abbreviated snapshot identifier matches multiple snapshots."""
