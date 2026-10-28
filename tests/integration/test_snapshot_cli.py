"""Integration tests for the TraceGraph snapshot and diff CLI workflows."""

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from tracegraph.cli.main import app


class TestSnapshotCLIWorkflow:
    """Integration test suite covering CLI snapshot capture, listing, show, and diff."""

    def test_full_snapshot_and_diff_lifecycle(self, tmp_path: Path):
        runner = CliRunner()
        ws_dir = tmp_path / "ws_snapshot"

        # 1. Initialize workspace
        res_init = runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        assert res_init.exit_code == 0

        # Check status has Total Snapshots
        res_status = runner.invoke(app, ["status", "--workspace", str(ws_dir)])
        assert res_status.exit_code == 0
        assert "Total Snapshots" in res_status.stdout

        # 2. Create investigation
        res_inv = runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Acme Security Audit",
                "--scope",
                "example.com",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_inv.exit_code == 0

        # 3. First collection run (Baseline)
        res_col1 = runner.invoke(
            app,
            [
                "collect",
                "example.com",
                "--collector",
                "mock_dns",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_col1.exit_code == 0

        # 4. Take Snapshot 1
        res_snap1 = runner.invoke(
            app,
            [
                "snapshot",
                "create",
                "--label",
                "Baseline Scan",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_snap1.exit_code == 0
        assert "Investigation Snapshot Created" in res_snap1.stdout
        assert "Baseline Scan" in res_snap1.stdout

        # 5. List snapshots
        res_list = runner.invoke(app, ["snapshot", "list", "--workspace", str(ws_dir)])
        assert res_list.exit_code == 0
        assert "Baseline Scan" in res_list.stdout

        # Extract snapshot 1 ID from output
        match1 = re.search(r"Snapshot ID:\s+([a-f0-9\-]{36})", res_snap1.stdout)
        assert match1 is not None, f"Failed to parse snapshot ID from output: {res_snap1.stdout}"
        snap1_id = match1.group(1)

        # 6. Show Snapshot 1 with integrity verification
        res_show = runner.invoke(
            app,
            ["snapshot", "show", snap1_id, "--verify", "--workspace", str(ws_dir)],
        )
        assert res_show.exit_code == 0
        assert "VERIFIED (Digest matches canonical content)" in res_show.stdout

        # 7. Collect another target in the same investigation
        res_col2 = runner.invoke(
            app,
            [
                "collect",
                "sub.example.com",
                "--collector",
                "mock_dns",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_col2.exit_code == 0

        # 8. Take Snapshot 2
        res_snap2 = runner.invoke(
            app,
            [
                "snapshot",
                "create",
                "--label",
                "Subdomain Expansion",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_snap2.exit_code == 0
        match2 = re.search(r"Snapshot ID:\s+([a-f0-9\-]{36})", res_snap2.stdout)
        assert match2 is not None, f"Failed to parse snapshot 2 ID from output: {res_snap2.stdout}"
        snap2_id = match2.group(1)

        # 9. Compare Snapshots (Console Output)
        res_diff_console = runner.invoke(
            app,
            ["snapshot", "diff", snap1_id, snap2_id, "--workspace", str(ws_dir)],
        )
        assert res_diff_console.exit_code == 0
        assert "TraceGraph Snapshot Comparison" in res_diff_console.stdout
        assert "ADDED" in res_diff_console.stdout

        # 10. Compare Snapshots (Markdown Export to file)
        md_file = tmp_path / "diff_report.md"
        res_diff_md = runner.invoke(
            app,
            [
                "snapshot",
                "diff",
                snap1_id,
                snap2_id,
                "--format",
                "markdown",
                "--output",
                str(md_file),
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_diff_md.exit_code == 0
        assert md_file.is_file()
        md_content = md_file.read_text(encoding="utf-8")
        assert "# TraceGraph Infrastructure Diff Report" in md_content
        assert "Acme Security Audit" in md_content
        assert "Observed Absence vs. Absence of Evidence" in md_content

        # 11. Compare Snapshots (JSON Export to file)
        json_file = tmp_path / "diff_export.json"
        res_diff_json = runner.invoke(
            app,
            [
                "snapshot",
                "diff",
                snap1_id,
                snap2_id,
                "--format",
                "json",
                "--output",
                str(json_file),
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_diff_json.exit_code == 0
        assert json_file.is_file()
        data = json.loads(json_file.read_text(encoding="utf-8"))
        assert data["investigation_name"] == "Acme Security Audit"
        assert data["summary"]["total_changes"] > 0
        assert data["summary"]["added_entities"] > 0

    def test_cross_investigation_diff_rejected(self, tmp_path: Path):
        """Diffing snapshots from different investigations must exit with error 1."""
        runner = CliRunner()
        ws_dir = tmp_path / "ws_cross"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])

        # Create 2 investigations
        runner.invoke(
            app,
            ["investigate", "new", "Inv 1", "--scope", "*", "--workspace", str(ws_dir)],
        )
        runner.invoke(
            app,
            ["investigate", "new", "Inv 2", "--scope", "*", "--workspace", str(ws_dir)],
        )

        from tracegraph.storage.database import create_session_factory, create_storage_engine
        from tracegraph.storage.repository import EvidenceRepository

        engine = create_storage_engine(ws_dir / "tracegraph.db")
        repo = EvidenceRepository(create_session_factory(engine))
        invs = repo.list_investigations()

        snap1 = repo.create_snapshot(invs[0].id)
        snap2 = repo.create_snapshot(invs[1].id)

        res = runner.invoke(
            app,
            ["snapshot", "diff", snap1.id, snap2.id, "--workspace", str(ws_dir)],
        )
        assert res.exit_code == 1
        assert "Cannot compare snapshots across different investigations" in res.stderr

    def test_cli_snapshot_prefix_resolution(self, tmp_path: Path):
        """CLI show and diff must resolve unique 8-character snapshot ID prefixes."""
        runner = CliRunner()
        ws_dir = tmp_path / "ws_prefix"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Prefix Audit",
                "--scope",
                "example.com",
                "--workspace",
                str(ws_dir),
            ],
        )
        runner.invoke(app, ["collect", "example.com", "--workspace", str(ws_dir)])

        # Create 2 snapshots
        res_snap1 = runner.invoke(
            app, ["snapshot", "create", "--label", "Scan 1", "--workspace", str(ws_dir)]
        )
        match1 = re.search(r"Snapshot ID:\s+([a-f0-9\-]{36})", res_snap1.stdout)
        assert match1 is not None
        snap1_id = match1.group(1)

        runner.invoke(app, ["collect", "sub.example.com", "--workspace", str(ws_dir)])
        res_snap2 = runner.invoke(
            app, ["snapshot", "create", "--label", "Scan 2", "--workspace", str(ws_dir)]
        )
        match2 = re.search(r"Snapshot ID:\s+([a-f0-9\-]{36})", res_snap2.stdout)
        assert match2 is not None
        snap2_id = match2.group(1)

        # 1. Test 'snapshot show' using 8-character prefix
        res_show_prefix = runner.invoke(
            app, ["snapshot", "show", snap1_id[:8], "--verify", "--workspace", str(ws_dir)]
        )
        assert res_show_prefix.exit_code == 0
        assert snap1_id in res_show_prefix.stdout
        assert "VERIFIED" in res_show_prefix.stdout

        # 2. Test 'snapshot diff' using 8-character prefixes for both arguments
        res_diff_prefix = runner.invoke(
            app, ["snapshot", "diff", snap1_id[:8], snap2_id[:8], "--workspace", str(ws_dir)]
        )
        assert res_diff_prefix.exit_code == 0
        assert "TraceGraph Snapshot Comparison" in res_diff_prefix.stdout

        # 3. Test 'snapshot show' with prefix shorter than 8 characters is rejected
        res_show_short = runner.invoke(
            app, ["snapshot", "show", snap1_id[:7], "--workspace", str(ws_dir)]
        )
        assert res_show_short.exit_code == 1
        assert f"Snapshot '{snap1_id[:7]}' not found" in res_show_short.stderr

    def test_cli_label_pipe_and_rich_markup_safety(self, tmp_path: Path):
        """Pipes in labels and brackets in names must not break Markdown or Rich markup."""
        runner = CliRunner()
        ws_dir = tmp_path / "ws_safety"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])
        runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Target [internal] Corp",
                "--scope",
                "example.com",
                "--workspace",
                str(ws_dir),
            ],
        )
        runner.invoke(app, ["collect", "example.com", "--workspace", str(ws_dir)])

        # Create snapshots with label containing pipe character and brackets
        res_snap1 = runner.invoke(
            app,
            [
                "snapshot",
                "create",
                "--label",
                "Pre | Post Cutover [v1]",
                "--workspace",
                str(ws_dir),
            ],
        )
        match1 = re.search(r"Snapshot ID:\s+([a-f0-9\-]{36})", res_snap1.stdout)
        assert match1 is not None
        snap1_id = match1.group(1)

        res_snap2 = runner.invoke(
            app,
            [
                "snapshot",
                "create",
                "--label",
                "Final | Complete [v2]",
                "--workspace",
                str(ws_dir),
            ],
        )
        match2 = re.search(r"Snapshot ID:\s+([a-f0-9\-]{36})", res_snap2.stdout)
        assert match2 is not None
        snap2_id = match2.group(1)

        # Console diff with rich markup safety
        res_console = runner.invoke(
            app,
            ["snapshot", "diff", snap1_id[:8], snap2_id[:8], "--workspace", str(ws_dir)],
        )
        assert res_console.exit_code == 0
        assert "TraceGraph Snapshot Comparison" in res_console.stdout

        # Markdown diff to file
        md_file = tmp_path / "safety_report.md"
        res_md = runner.invoke(
            app,
            [
                "snapshot",
                "diff",
                snap1_id[:8],
                snap2_id[:8],
                "--format",
                "markdown",
                "--output",
                str(md_file),
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_md.exit_code == 0
        assert md_file.is_file()
        md_content = md_file.read_text(encoding="utf-8")

        # In Markdown, verify table line for Label has escaped pipe (\\|) so table is not broken
        label_line = next(
            line for line in md_content.splitlines() if line.startswith("| **Label** |")
        )
        assert "Pre \\| Post Cutover [v1]" in label_line
        assert "Final \\| Complete [v2]" in label_line
