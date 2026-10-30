"""Integration tests for investigation, collection, and reporting CLI workflows."""

import re
from pathlib import Path

from typer.testing import CliRunner

from tracegraph.cli.main import app

runner = CliRunner()


class TestInvestigationWorkflow:
    """Full investigation workflow testing."""

    def test_investigate_lifecycle(self, tmp_path: Path):
        ws_dir = tmp_path / "ws_inv"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])

        # 1. List when empty
        res_empty = runner.invoke(app, ["investigate", "list", "--workspace", str(ws_dir)])
        assert res_empty.exit_code == 0
        assert "No investigations found" in res_empty.stdout

        # 2. Create investigation
        res_new = runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Project Alpha",
                "--scope",
                "example.com, 93.184.215.0/24",
                "--desc",
                "Defensive infrastructure audit",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_new.exit_code == 0
        assert "Investigation Created" in res_new.stdout
        assert "Project Alpha" in res_new.stdout

        # Extract UUID from output
        match = re.search(r"ID:\s+([a-f0-9\-]{36})", res_new.stdout)
        assert match is not None
        inv_id = match.group(1)

        # 3. List contains newly created investigation
        res_list = runner.invoke(app, ["investigate", "list", "--workspace", str(ws_dir)])
        assert res_list.exit_code == 0
        assert inv_id in res_list.stdout
        assert "Alpha" in res_list.stdout

        # 4. Show investigation details
        res_show = runner.invoke(app, ["investigate", "show", inv_id, "--workspace", str(ws_dir)])
        assert res_show.exit_code == 0
        assert "Investigation Details" in res_show.stdout
        assert "Total Observations: 0" in res_show.stdout

        # 5. Show invalid ID fails
        res_invalid = runner.invoke(
            app,
            [
                "investigate",
                "show",
                "00000000-0000-0000-0000-000000000000",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_invalid.exit_code == 1
        assert "not found" in res_invalid.stderr

    def test_collect_scope_enforcement_and_execution(self, tmp_path: Path):
        ws_dir = tmp_path / "ws_collect"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])

        # Create scoped investigation
        res_new = runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Scoped Scope",
                "--scope",
                "example.com, *.example.com",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_new.exit_code == 0
        inv_id = re.search(r"ID:\s+([a-f0-9\-]{36})", res_new.stdout).group(1)

        # 1. Attempt collecting target out of scope -> MUST FAIL before running collector
        res_out_of_scope = runner.invoke(
            app,
            [
                "collect",
                "unauthorized-target.org",
                "--collector",
                "mock_dns",
                "--investigation",
                inv_id,
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_out_of_scope.exit_code == 1
        assert "Scope Violation" in res_out_of_scope.stderr
        normalized_err = " ".join(res_out_of_scope.stderr.split())
        assert "outside declared investigation scope" in normalized_err

        # 2. Collect in-scope target -> SUCCESS
        res_in_scope = runner.invoke(
            app,
            [
                "collect",
                "example.com",
                "--collector",
                "mock_dns",
                "--investigation",
                inv_id,
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_in_scope.exit_code == 0
        assert "Status: SUCCESS" in res_in_scope.stdout
        assert "Discovered Entities: 4" in res_in_scope.stdout
        assert "Verified Relationships: 3" in res_in_scope.stdout

        # 3. Repeat collection on same target -> idempotent entity handling, distinct observation
        res_repeat = runner.invoke(
            app,
            [
                "collect",
                "example.com",
                "--collector",
                "mock_dns",
                "--investigation",
                inv_id,
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_repeat.exit_code == 0

    def test_collect_failure_exit_code(self, tmp_path: Path):
        ws_dir = tmp_path / "ws_fail"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])

        res_new = runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Fail Investigation",
                "--scope",
                "*",
                "--workspace",
                str(ws_dir),
            ],
        )
        inv_id = re.search(r"ID:\s+([a-f0-9\-]{36})", res_new.stdout).group(1)

        # mock_dns simulates a failure when querying failure.test
        res_fail = runner.invoke(
            app,
            [
                "collect",
                "failure.test",
                "--collector",
                "mock_dns",
                "--investigation",
                inv_id,
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_fail.exit_code == 1
        assert "Collection Failed" in res_fail.stderr

    def test_collect_target_incompatibility(self, tmp_path: Path):
        ws_dir = tmp_path / "ws_incompat"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])

        runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Incompat Investigation",
                "--scope",
                "*",
                "--workspace",
                str(ws_dir),
            ],
        )

        # mock_dns only supports DOMAIN, passing an IP address must fail gracefully
        res_incompat = runner.invoke(
            app,
            [
                "collect",
                "93.184.215.14",
                "--collector",
                "mock_dns",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_incompat.exit_code == 1
        assert "Target Incompatibility" in res_incompat.stderr

    def test_report_generation_console_and_file(self, tmp_path: Path):
        ws_dir = tmp_path / "ws_report"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])

        res_new = runner.invoke(
            app,
            [
                "investigate",
                "new",
                "Operation Blue Shield",
                "--scope",
                "example.com",
                "--desc",
                "Assessment of example.com infrastructure",
                "--workspace",
                str(ws_dir),
            ],
        )
        inv_id = re.search(r"ID:\s+([a-f0-9\-]{36})", res_new.stdout).group(1)

        # Run collection
        runner.invoke(
            app,
            [
                "collect",
                "example.com",
                "--collector",
                "mock_dns",
                "--investigation",
                inv_id,
                "--workspace",
                str(ws_dir),
            ],
        )

        # 1. Report to console (rendered Markdown)
        res_rep_console = runner.invoke(
            app,
            ["report", inv_id, "--workspace", str(ws_dir)],
        )
        assert res_rep_console.exit_code == 0
        assert "TraceGraph Investigation Report: Operation Blue Shield" in res_rep_console.stdout
        assert "mock_dns" in res_rep_console.stdout
        assert "VERIFIED" in res_rep_console.stdout

        # 2. Report to file
        report_file = tmp_path / "blue_shield_report.md"
        res_rep_file = runner.invoke(
            app,
            ["report", inv_id, "--output", str(report_file), "--workspace", str(ws_dir)],
        )
        assert res_rep_file.exit_code == 0
        assert "Report written to" in res_rep_file.stdout
        assert report_file.is_file()

        content = report_file.read_text(encoding="utf-8")
        assert "# TraceGraph Investigation Report: Operation Blue Shield" in content
        assert "93.184.215.14" in content
        assert "RESOLVES_TO" in content

    def test_investigation_prefix_cli_resolution(self, tmp_path: Path):
        """CLI commands accept unique investigation ID prefixes >= 8 characters."""
        ws_dir = tmp_path / "ws_prefix"
        runner.invoke(app, ["init", "--workspace", str(ws_dir)])

        # 1. Create investigation
        res_new = runner.invoke(
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
        assert res_new.exit_code == 0
        match = re.search(r"ID:\s+([a-f0-9\-]{36})", res_new.stdout)
        assert match is not None
        full_id = match.group(1)
        prefix_8 = full_id[:8]

        # 2. Collect using prefix
        res_col = runner.invoke(
            app,
            [
                "collect",
                "example.com",
                "--collector",
                "mock_dns",
                "--investigation",
                prefix_8,
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_col.exit_code == 0

        # 3. Investigate show using prefix
        res_show = runner.invoke(
            app,
            ["investigate", "show", prefix_8, "--workspace", str(ws_dir)],
        )
        assert res_show.exit_code == 0
        assert "Prefix Audit" in res_show.stdout
        assert "Investigation Details" in res_show.stdout

        # 4. Report generation using prefix
        rep_file = tmp_path / "prefix_report.md"
        res_rep = runner.invoke(
            app,
            [
                "report",
                prefix_8,
                "--output",
                str(rep_file),
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_rep.exit_code == 0
        assert "Report written to" in res_rep.stdout
        assert rep_file.is_file()

        # 5. Snapshot create and list using investigation prefix
        res_snap = runner.invoke(
            app,
            [
                "snapshot",
                "create",
                prefix_8,
                "--label",
                "Prefix Snap Test",
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_snap.exit_code == 0

        res_list = runner.invoke(
            app,
            [
                "snapshot",
                "list",
                "-i",
                prefix_8,
                "--workspace",
                str(ws_dir),
            ],
        )
        assert res_list.exit_code == 0
        assert "Prefix Snap Test" in res_list.stdout

        # 6. Prefix shorter than 8 characters is rejected
        res_short = runner.invoke(
            app,
            ["investigate", "show", full_id[:7], "--workspace", str(ws_dir)],
        )
        assert res_short.exit_code == 1
        assert "not found" in (res_short.stderr + res_short.stdout).lower()

        # 7. Non-existent prefix is rejected
        res_unknown = runner.invoke(
            app,
            ["report", "ffffffff-ffff", "--workspace", str(ws_dir)],
        )
        assert res_unknown.exit_code == 1
        assert "not found" in (res_unknown.stderr + res_unknown.stdout).lower()
