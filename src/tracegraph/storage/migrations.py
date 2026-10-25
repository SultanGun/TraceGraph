"""Database schema versioning and transactional migrations."""

import logging
from datetime import UTC, datetime

from sqlalchemy import Engine, text

from tracegraph.core.exceptions import MigrationError

logger = logging.getLogger(__name__)

LATEST_SCHEMA_VERSION = "2.0.0"


def get_current_schema_version(engine: Engine) -> str | None:
    """Retrieve schema version from metadata table."""
    try:
        with engine.connect() as conn:
            # Check if metadata table exists
            table_check = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata';")
            ).scalar()
            if not table_check:
                return None

            result = conn.execute(
                text("SELECT value FROM metadata WHERE key='schema_version';")
            ).scalar()
            return str(result) if result else None
    except Exception as e:
        logger.debug("Failed to check schema version: %s", e)
        return None


def migrate_v1_to_v2(conn) -> None:
    """Migrate SQLite schema from v1.0.0 to v2.0.0.

    Changes:
    - Add target_scope column to investigations table.
    - Add investigation_id column and foreign key index to observations table.
    - Assign existing unassigned observations to a designated legacy migration investigation.
    """
    logger.info("Migrating database schema from v1.0.0 to v2.0.0...")

    # 1. Inspect existing columns in investigations
    inv_cols = [
        row[1] for row in conn.execute(text("PRAGMA table_info(investigations);")).fetchall()
    ]
    if "target_scope" not in inv_cols:
        conn.execute(
            text("ALTER TABLE investigations ADD COLUMN target_scope TEXT NOT NULL DEFAULT '';")
        )

    # 2. Inspect existing columns in observations
    obs_cols = [
        row[1] for row in conn.execute(text("PRAGMA table_info(observations);")).fetchall()
    ]
    if "investigation_id" not in obs_cols:
        conn.execute(
            text(
                "ALTER TABLE observations ADD COLUMN investigation_id VARCHAR(36) "
                "REFERENCES investigations(id) ON DELETE CASCADE;"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_observations_investigation_id "
                "ON observations(investigation_id);"
            )
        )

    # 3. Associate legacy observations if any exist with NULL investigation_id
    null_obs_count = conn.execute(
        text("SELECT COUNT(*) FROM observations WHERE investigation_id IS NULL;")
    ).scalar()

    if null_obs_count and null_obs_count > 0:
        legacy_id = "legacy-v0.1-investigation"
        now_iso = datetime.now(UTC).isoformat()
        conn.execute(
            text(
                "INSERT OR IGNORE INTO investigations "
                "(id, name, description, target_scope, created_at, config_metadata) "
                "VALUES (:id, :name, :description, :target_scope, :created_at, :meta);"
            ),
            {
                "id": legacy_id,
                "name": "Legacy Migration Investigation",
                "description": "Auto-created scope boundary for v0.1.0 observations",
                "target_scope": "*",
                "created_at": now_iso,
                "meta": "{}",
            },
        )
        conn.execute(
            text(
                "UPDATE observations SET investigation_id = :legacy_id "
                "WHERE investigation_id IS NULL;"
            ),
            {"legacy_id": legacy_id},
        )

    # 4. Update metadata record
    now_iso = datetime.now(UTC).isoformat()
    conn.execute(
        text(
            "UPDATE metadata SET value = '2.0.0', updated_at = :updated_at "
            "WHERE key = 'schema_version';"
        ),
        {"updated_at": now_iso},
    )


def apply_migrations(engine: Engine) -> str:
    """Evaluate and sequentially execute pending database schema migrations."""
    current_ver = get_current_schema_version(engine)
    if not current_ver:
        raise MigrationError("Cannot migrate uninitialized database. Run 'init' first.")

    if current_ver == LATEST_SCHEMA_VERSION:
        return current_ver

    try:
        with engine.begin() as conn:
            if current_ver == "1.0.0":
                migrate_v1_to_v2(conn)
                current_ver = "2.0.0"

        logger.info("Successfully migrated schema to v%s", current_ver)
        return current_ver
    except Exception as e:
        raise MigrationError(f"Migration failed from v{current_ver}: {e}") from e
