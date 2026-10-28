"""Workspace lifecycle management, database bootstrapping, and environment status inspection."""

import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import tracegraph
from tracegraph.core.exceptions import (
    DatabaseError,
    WorkspaceAlreadyInitializedError,
    WorkspaceError,
)
from tracegraph.storage.database import (
    check_connection,
    create_session_factory,
    create_storage_engine,
    init_database,
    session_scope,
)
from tracegraph.storage.migrations import (
    LATEST_SCHEMA_VERSION,
    apply_migrations,
    get_current_schema_version,
)
from tracegraph.storage.schema import (
    EntityRecord,
    MetadataRecord,
    ObservationRecord,
    RelationshipRecord,
    SnapshotRecord,
)

logger = logging.getLogger(__name__)

DEFAULT_WORKSPACE_DIRNAME = ".tracegraph"
DEFAULT_DB_FILENAME = "tracegraph.db"
CURRENT_SCHEMA_VERSION = LATEST_SCHEMA_VERSION


@dataclass
class WorkspaceStatus:
    """Diagnostic status of a TraceGraph local workspace."""

    version: str
    workspace_path: Path
    db_path: Path
    directory_exists: bool
    db_exists: bool
    db_connected: bool
    is_initialized: bool
    schema_version: str | None
    entity_count: int = 0
    observation_count: int = 0
    relationship_count: int = 0
    snapshot_count: int = 0
    error_message: str | None = None


def resolve_workspace_path(explicit_path: Path | str | None = None) -> Path:
    """Resolve workspace directory from explicit argument, env var, or current directory default."""
    if explicit_path is not None:
        return Path(explicit_path).resolve()

    env_path = os.environ.get("TRACEGRAPH_WORKSPACE")
    if env_path:
        return Path(env_path).resolve()

    return (Path.cwd() / DEFAULT_WORKSPACE_DIRNAME).resolve()


def is_valid_sqlite_db(db_path: Path) -> bool:
    """Verify that a file is an uncorrupted SQLite database."""
    if not db_path.is_file():
        return False
    try:
        # SQLite files start with 16-byte magic header "SQLite format 3\x00"
        with open(db_path, "rb") as f:
            header = f.read(16)
            if header != b"SQLite format 3\x00":
                return False

        # Verify quick sqlite integrity check
        conn = sqlite3.connect(str(db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA quick_check;")
            res = cursor.fetchone()
            return bool(res and res[0] == "ok")
        finally:
            conn.close()
    except Exception:
        return False


def get_workspace_status(workspace_dir: Path | str | None = None) -> WorkspaceStatus:
    """Inspect and return current status of the workspace and persistence layer."""
    ws_path = resolve_workspace_path(workspace_dir)
    db_path = ws_path / DEFAULT_DB_FILENAME

    dir_exists = ws_path.is_dir()
    db_exists = db_path.is_file()

    if not dir_exists or not db_exists:
        return WorkspaceStatus(
            version=tracegraph.__version__,
            workspace_path=ws_path,
            db_path=db_path,
            directory_exists=dir_exists,
            db_exists=db_exists,
            db_connected=False,
            is_initialized=False,
            schema_version=None,
        )

    # Validate sqlite integrity before SQLAlchemy connection
    if not is_valid_sqlite_db(db_path):
        return WorkspaceStatus(
            version=tracegraph.__version__,
            workspace_path=ws_path,
            db_path=db_path,
            directory_exists=dir_exists,
            db_exists=True,
            db_connected=False,
            is_initialized=False,
            schema_version=None,
            error_message="Database file exists but is corrupted or not a valid SQLite database",
        )

    engine = create_storage_engine(db_path)
    try:
        if not check_connection(engine):
            return WorkspaceStatus(
                version=tracegraph.__version__,
                workspace_path=ws_path,
                db_path=db_path,
                directory_exists=dir_exists,
                db_exists=True,
                db_connected=False,
                is_initialized=False,
                schema_version=None,
                error_message="Unable to establish SQLite connection or enforce foreign keys",
            )

        schema_ver = get_current_schema_version(engine)
        if schema_ver and schema_ver != LATEST_SCHEMA_VERSION:
            try:
                schema_ver = apply_migrations(engine)
            except Exception as e:
                logger.warning("Auto-migration failed: %s", e)

        session_factory = create_session_factory(engine)
        entity_cnt = 0
        obs_cnt = 0
        rel_cnt = 0
        snap_cnt = 0

        with session_scope(session_factory) as session:
            entity_cnt = session.query(EntityRecord).count()
            obs_cnt = session.query(ObservationRecord).count()
            rel_cnt = session.query(RelationshipRecord).count()
            try:
                snap_cnt = session.query(SnapshotRecord).count()
            except Exception:
                snap_cnt = 0

        is_init = schema_ver is not None

        return WorkspaceStatus(
            version=tracegraph.__version__,
            workspace_path=ws_path,
            db_path=db_path,
            directory_exists=dir_exists,
            db_exists=True,
            db_connected=True,
            is_initialized=is_init,
            schema_version=schema_ver,
            entity_count=entity_cnt,
            observation_count=obs_cnt,
            relationship_count=rel_cnt,
            snapshot_count=snap_cnt,
        )
    except Exception as e:
        logger.debug("Failed checking workspace status: %s", e)
        return WorkspaceStatus(
            version=tracegraph.__version__,
            workspace_path=ws_path,
            db_path=db_path,
            directory_exists=dir_exists,
            db_exists=True,
            db_connected=False,
            is_initialized=False,
            schema_version=None,
            error_message=f"Database inspection error: {e}",
        )
    finally:
        engine.dispose()


def init_workspace(
    workspace_dir: Path | str | None = None,
    allow_idempotent: bool = True,
) -> WorkspaceStatus:
    """Initialize a local TraceGraph workspace and database.

    Guarantees:
    - Never overwrites an existing healthy database.
    - Idempotent when existing workspace is already initialized.
    - Fails safely if path cannot be created or file is corrupt.
    """
    ws_path = resolve_workspace_path(workspace_dir)

    # Validate parent path is safe to create
    try:
        ws_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise WorkspaceError(f"Cannot create workspace directory at '{ws_path}': {e}") from e

    db_path = ws_path / DEFAULT_DB_FILENAME

    # Check if database already exists
    if db_path.exists():
        if not db_path.is_file():
            raise WorkspaceError(f"Path '{db_path}' exists but is not a regular file")

        if not is_valid_sqlite_db(db_path):
            raise WorkspaceError(
                f"Existing file at '{db_path}' is corrupted or not a valid SQLite database. "
                "Refusing to overwrite."
            )

        # Inspect if schema is already valid
        status = get_workspace_status(ws_path)
        if status.is_initialized:
            if not allow_idempotent:
                raise WorkspaceAlreadyInitializedError(
                    f"Workspace at '{ws_path}' is already initialized "
                    f"(schema v{status.schema_version})"
                )
            logger.info("Workspace already initialized at %s", ws_path)
            return status

    # Bootstrap new database schema
    engine = create_storage_engine(db_path)
    try:
        init_database(engine)
        session_factory = create_session_factory(engine)

        # Record schema metadata
        now = datetime.now(UTC)
        with session_scope(session_factory) as session:
            session.add(
                MetadataRecord(
                    key="schema_version",
                    value=CURRENT_SCHEMA_VERSION,
                    updated_at=now,
                )
            )
            session.add(
                MetadataRecord(
                    key="tracegraph_version",
                    value=tracegraph.__version__,
                    updated_at=now,
                )
            )
            session.add(
                MetadataRecord(
                    key="created_at",
                    value=now.isoformat(),
                    updated_at=now,
                )
            )

        logger.info("Successfully initialized TraceGraph workspace at %s", ws_path)
        return get_workspace_status(ws_path)
    except Exception as e:
        logger.error("Failed to initialize workspace: %s", e)
        raise DatabaseError(f"Failed to bootstrap database at '{db_path}': {e}") from e
    finally:
        engine.dispose()
