"""Integration tests for Typer CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from tracegraph.cli.main import app
from tracegraph.core.enums import EntityType
from tracegraph.storage.database import create_session_factory, create_storage_engine
from tracegraph.storage.repository import EvidenceRepository
from tracegraph.storage.workspace import DEFAULT_DB_FILENAME

runner = CliRunner()


class TestCLICommands:
    def test_help_command(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "TraceGraph" in result.stdout
        assert "version" in result.stdout
        assert "init" in result.stdout
        assert "status" in result.stdout

    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "TraceGraph v0.1.0-alpha" in result.stdout

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "TraceGraph v0.1.0-alpha" in result.stdout

    def test_status_uninitialized_workspace(self, tmp_path: Path):
        ws_dir = tmp_path / "uninit_ws"
        result = runner.invoke(app, ["status", "--workspace", str(ws_dir)])
        assert result.exit_code == 0
        assert "NOT INITIALIZED" in result.stdout
        assert "DISCONNECTED" in result.stdout

    def test_init_and_status_lifecycle(self, tmp_path: Path):
        ws_dir = tmp_path / "lifecycle_ws"

        # 1. Initialize
        init_res = runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        assert init_res.exit_code == 0
        assert "Workspace ready" in init_res.stdout
        assert "Schema version: 1.0.0" in init_res.stdout

        # Verify database file created
        db_path = ws_dir / DEFAULT_DB_FILENAME
        assert db_path.is_file()

        # 2. Check status
        status_res = runner.invoke(app, ["status", "--workspace", str(ws_dir)])
        assert status_res.exit_code == 0
        assert "CONNECTED" in status_res.stdout
        assert "INITIALIZED" in status_res.stdout
        assert "Schema v1.0.0" in status_res.stdout

        # 3. Repeated init (Idempotency)
        repeat_res = runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        assert repeat_res.exit_code == 0
        assert "Workspace ready" in repeat_res.stdout

    def test_existing_database_preservation(self, tmp_path: Path):
        ws_dir = tmp_path / "preserve_ws"

        # 1. Init workspace
        res1 = runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        assert res1.exit_code == 0

        # 2. Insert record into database directly
        db_path = ws_dir / DEFAULT_DB_FILENAME
        engine = create_storage_engine(db_path)
        factory = create_session_factory(engine)
        repo = EvidenceRepository(factory)
        ent, created = repo.get_or_create_entity(EntityType.DOMAIN, "canary-preserved.test")
        assert created is True
        engine.dispose()

        # 3. Run init again
        res2 = runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        assert res2.exit_code == 0

        # 4. Verify record was preserved and not wiped
        engine2 = create_storage_engine(db_path)
        factory2 = create_session_factory(engine2)
        repo2 = EvidenceRepository(factory2)
        preserved = repo2.list_entities()
        engine2.dispose()

        assert len(preserved) == 1
        assert preserved[0].normalized_value == "canary-preserved.test"

    def test_corrupted_database_fails_safely(self, tmp_path: Path):
        ws_dir = tmp_path / "corrupt_ws"
        ws_dir.mkdir(parents=True, exist_ok=True)
        corrupt_db = ws_dir / DEFAULT_DB_FILENAME

        # Write invalid non-SQLite content
        corrupt_db.write_text("CORRUPTED_NON_SQLITE_DATA", encoding="utf-8")

        # tracegraph init must refuse to overwrite and fail with code 1
        init_res = runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        assert init_res.exit_code != 0
        assert "Refusing to overwrite" in init_res.output or "corrupted" in init_res.output
        assert corrupt_db.read_text(encoding="utf-8") == "CORRUPTED_NON_SQLITE_DATA"

        # tracegraph status must detect the corruption
        status_res = runner.invoke(app, ["status", "--workspace", str(ws_dir)])
        assert status_res.exit_code == 0
        assert "corrupted" in status_res.stdout.lower()
