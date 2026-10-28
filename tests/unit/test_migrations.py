"""Unit tests for database schema versioning and migrations."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, text

from tracegraph.core.exceptions import MigrationError
from tracegraph.storage.migrations import (
    LATEST_SCHEMA_VERSION,
    apply_migrations,
    get_current_schema_version,
)


def create_v1_database(engine):
    """Set up an exact SQLite database matching TraceGraph v0.1.0-alpha (schema v1.0.0)."""
    with engine.begin() as conn:
        # 1. Metadata table
        conn.execute(
            text(
                "CREATE TABLE metadata ("
                "key VARCHAR(64) PRIMARY KEY, "
                "value TEXT NOT NULL, "
                "updated_at TEXT NOT NULL"
                ");"
            )
        )
        now_iso = datetime.now(UTC).isoformat()
        conn.execute(
            text(
                "INSERT INTO metadata (key, value, updated_at) "
                "VALUES ('schema_version', '1.0.0', :now);"
            ),
            {"now": now_iso},
        )

        # 2. Investigations table (v1 had NO target_scope)
        conn.execute(
            text(
                "CREATE TABLE investigations ("
                "id VARCHAR(36) PRIMARY KEY, "
                "name VARCHAR(255) NOT NULL, "
                "description TEXT NOT NULL DEFAULT '', "
                "created_at TEXT NOT NULL, "
                "config_metadata TEXT NOT NULL DEFAULT '{}'"
                ");"
            )
        )

        # 3. Entities table
        conn.execute(
            text(
                "CREATE TABLE entities ("
                "id VARCHAR(36) PRIMARY KEY, "
                "entity_type VARCHAR(32) NOT NULL, "
                "raw_value TEXT NOT NULL, "
                "canonical_value TEXT NOT NULL, "
                "created_at TEXT NOT NULL, "
                "CONSTRAINT uq_entity_type_canonical UNIQUE (entity_type, canonical_value)"
                ");"
            )
        )

        # 4. Observations table (v1 had NO investigation_id)
        conn.execute(
            text(
                "CREATE TABLE observations ("
                "id VARCHAR(36) PRIMARY KEY, "
                "entity_id VARCHAR(36) NOT NULL REFERENCES entities(id) ON DELETE CASCADE, "
                "collector_name VARCHAR(64) NOT NULL, "
                "collector_version VARCHAR(32) NOT NULL, "
                "source_reference TEXT NOT NULL, "
                "observed_at TEXT NOT NULL, "
                "ingested_at TEXT NOT NULL, "
                "status VARCHAR(32) NOT NULL, "
                "observed_data TEXT NOT NULL DEFAULT '{}', "
                "error_details TEXT"
                ");"
            )
        )


def create_v2_database(engine):
    """Set up an exact SQLite database matching TraceGraph v0.2.0-alpha (schema v2.0.0)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE metadata ("
                "key VARCHAR(64) PRIMARY KEY, "
                "value TEXT NOT NULL, "
                "updated_at TEXT NOT NULL"
                ");"
            )
        )
        now_iso = datetime.now(UTC).isoformat()
        conn.execute(
            text(
                "INSERT INTO metadata (key, value, updated_at) "
                "VALUES ('schema_version', '2.0.0', :now);"
            ),
            {"now": now_iso},
        )

        conn.execute(
            text(
                "CREATE TABLE investigations ("
                "id VARCHAR(36) PRIMARY KEY, "
                "name VARCHAR(255) NOT NULL, "
                "description TEXT, "
                "target_scope TEXT NOT NULL DEFAULT '', "
                "created_at DATETIME NOT NULL, "
                "config_metadata JSON NOT NULL DEFAULT '{}'"
                ");"
            )
        )

        conn.execute(
            text(
                "CREATE TABLE entities ("
                "id VARCHAR(36) PRIMARY KEY, "
                "entity_type VARCHAR(50) NOT NULL, "
                "raw_value VARCHAR(1024) NOT NULL, "
                "normalized_value VARCHAR(1024) NOT NULL, "
                "created_at DATETIME NOT NULL, "
                "CONSTRAINT uq_entity_type_normalized_value UNIQUE (entity_type, normalized_value)"
                ");"
            )
        )

        conn.execute(
            text(
                "CREATE TABLE observations ("
                "id VARCHAR(36) PRIMARY KEY, "
                "entity_id VARCHAR(36) NOT NULL REFERENCES entities(id) ON DELETE CASCADE, "
                "investigation_id VARCHAR(36) REFERENCES investigations(id) ON DELETE CASCADE, "
                "collector_name VARCHAR(100) NOT NULL, "
                "collector_version VARCHAR(50) NOT NULL, "
                "source_reference VARCHAR(1024) NOT NULL, "
                "observed_at DATETIME NOT NULL, "
                "ingested_at DATETIME NOT NULL, "
                "data JSON NOT NULL DEFAULT '{}', "
                "status VARCHAR(20) NOT NULL, "
                "error_details JSON"
                ");"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX idx_observations_investigation_id "
                "ON observations(investigation_id);"
            )
        )


class TestMigrations:
    """Test suite for schema migrations."""

    def test_get_current_schema_version_empty_db(self, tmp_path):
        db_path = tmp_path / "empty.db"
        engine = create_engine(f"sqlite:///{db_path}")

        version = get_current_schema_version(engine)
        assert version is None

    def test_apply_migrations_uninitialized_raises(self, tmp_path):
        db_path = tmp_path / "empty.db"
        engine = create_engine(f"sqlite:///{db_path}")

        with pytest.raises(MigrationError, match="Cannot migrate uninitialized"):
            apply_migrations(engine)

    def test_migrate_v1_to_v3_success(self, tmp_path):
        db_path = tmp_path / "v1.db"
        engine = create_engine(f"sqlite:///{db_path}")
        create_v1_database(engine)

        # Check v1 version
        assert get_current_schema_version(engine) == "1.0.0"

        # Insert sample v1 entity and observation
        now_iso = datetime.now(UTC).isoformat()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO entities "
                    "(id, entity_type, raw_value, canonical_value, created_at) "
                    "VALUES ('ent-1', 'DOMAIN', 'example.com', 'example.com', :now);"
                ),
                {"now": now_iso},
            )
            conn.execute(
                text(
                    "INSERT INTO observations ("
                    "id, entity_id, collector_name, collector_version, source_reference, "
                    "observed_at, ingested_at, status, observed_data"
                    ") VALUES ("
                    "'obs-1', 'ent-1', 'mock_dns', '0.1.0', 'mock://dns', "
                    ":now, :now, 'SUCCESS', '{}');"
                ),
                {"now": now_iso},
            )

        # Execute migration
        new_version = apply_migrations(engine)
        assert new_version == LATEST_SCHEMA_VERSION
        assert new_version == "3.0.0"
        assert get_current_schema_version(engine) == "3.0.0"

        # Verify investigations table has target_scope
        with engine.connect() as conn:
            inv_rows = conn.execute(text("PRAGMA table_info(investigations);")).fetchall()
            inv_cols = [row[1] for row in inv_rows]
            assert "target_scope" in inv_cols

            # Verify observations table has investigation_id
            obs_rows = conn.execute(text("PRAGMA table_info(observations);")).fetchall()
            obs_cols = [row[1] for row in obs_rows]
            assert "investigation_id" in obs_cols

            # Verify index exists
            idx_rows = conn.execute(text("PRAGMA index_list(observations);")).fetchall()
            indexes = [row[1] for row in idx_rows]
            assert "idx_observations_investigation_id" in indexes

            # Verify legacy observation was backfilled
            obs_row = conn.execute(
                text("SELECT id, investigation_id FROM observations WHERE id = 'obs-1';")
            ).fetchone()
            assert obs_row is not None
            assert obs_row[1] == "legacy-v0.1-investigation"

            # Verify legacy investigation record was created
            legacy_query = (
                "SELECT id, target_scope FROM investigations "
                "WHERE id = 'legacy-v0.1-investigation';"
            )
            inv_row = conn.execute(text(legacy_query)).fetchone()
            assert inv_row is not None
            assert inv_row[1] == "*"

            # Verify snapshots table exists
            snap_check = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshots';")
            ).scalar()
            assert snap_check == "snapshots"

            snap_idx_rows = conn.execute(text("PRAGMA index_list(snapshots);")).fetchall()
            snap_indexes = [row[1] for row in snap_idx_rows]
            assert "idx_snapshots_investigation_id" in snap_indexes
            assert "idx_snapshots_created_at" in snap_indexes
            assert "idx_snapshots_content_digest" in snap_indexes

    def test_migrate_v2_to_v3_success(self, tmp_path):
        db_path = tmp_path / "v2.db"
        engine = create_engine(f"sqlite:///{db_path}")
        create_v2_database(engine)

        assert get_current_schema_version(engine) == "2.0.0"

        new_version = apply_migrations(engine)
        assert new_version == "3.0.0"
        assert get_current_schema_version(engine) == "3.0.0"

        with engine.connect() as conn:
            snap_check = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshots';")
            ).scalar()
            assert snap_check == "snapshots"

            idx_rows = conn.execute(text("PRAGMA index_list(snapshots);")).fetchall()
            indexes = [row[1] for row in idx_rows]
            assert "idx_snapshots_investigation_id" in indexes
            assert "idx_snapshots_created_at" in indexes
            assert "idx_snapshots_content_digest" in indexes

    def test_apply_migrations_idempotency(self, tmp_path):
        db_path = tmp_path / "v1.db"
        engine = create_engine(f"sqlite:///{db_path}")
        create_v1_database(engine)

        v_first = apply_migrations(engine)
        assert v_first == "3.0.0"

        # Second call should be a no-op
        v_second = apply_migrations(engine)
        assert v_second == "3.0.0"

        with engine.connect() as conn:
            idx_rows = conn.execute(text("PRAGMA index_list(snapshots);")).fetchall()
            indexes = [row[1] for row in idx_rows]
            assert "idx_snapshots_content_digest" in indexes
