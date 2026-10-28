"""Presentation and export formatters for snapshot comparison and diff results."""

import json
from typing import Any

from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from tracegraph.snapshots.models import ChangeType, SnapshotDiffResult


def _escape_md_cell(text: str | None) -> str:
    """Escape pipe characters and linebreaks for safe inclusion in Markdown table cells."""
    if not text:
        return "None"
    return text.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").strip()


def format_diff_console(diff: SnapshotDiffResult) -> tuple[Panel, Table, list[Panel]]:
    """Format snapshot diff result into Rich components for console presentation."""
    # 1. Header panel with escaped markup
    a_label = f" ({escape(diff.snapshot_a_label)})" if diff.snapshot_a_label else ""
    b_label = f" ({escape(diff.snapshot_b_label)})" if diff.snapshot_b_label else ""
    esc_inv_name = escape(diff.investigation_name)
    esc_inv_id = escape(diff.investigation_id)

    header_text = (
        f"[bold cyan]Investigation:[/bold cyan] {esc_inv_name}\n"
        f"  ID: {esc_inv_id}\n"
        f"[bold white]Baseline Snapshot A:[/bold white] {diff.snapshot_a_id}{a_label}\n"
        f"  • Created: {diff.snapshot_a_created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"  • Digest:  {diff.snapshot_a_digest[:16]}...\n"
        f"[bold white]Target Snapshot B:[/bold white]   {diff.snapshot_b_id}{b_label}\n"
        f"  • Created: {diff.snapshot_b_created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"  • Digest:  {diff.snapshot_b_digest[:16]}...\n"
        f"[bold white]Total Changes Detected:[/bold white] "
        f"[bold yellow]{diff.summary.total_changes}[/bold yellow]"
    )
    header_panel = Panel(
        header_text,
        title="[bold]TraceGraph Snapshot Comparison[/bold]",
        border_style="cyan",
    )

    # 2. Changes Table
    table = Table(title="Detected Infrastructure & Evidence Graph Changes", show_lines=True)
    table.add_column("Category", style="cyan", width=14)
    table.add_column("Change", style="bold", width=12)
    table.add_column("Identifier", style="white")
    table.add_column("Explanation & Evidence", style="dim")

    for chg in diff.changes:
        if chg.change_type == ChangeType.ADDED:
            badge = "[bold green][ADDED][/bold green]"
        elif chg.change_type == ChangeType.UNOBSERVED:
            badge = "[bold yellow][UNOBSERVED][/bold yellow]"
        elif chg.change_type == ChangeType.REMOVED:
            badge = "[bold red][REMOVED][/bold red]"
        else:
            badge = "[bold magenta][MODIFIED][/bold magenta]"

        detail_lines = [escape(chg.explanation)]
        if chg.evidence_references:
            refs = ", ".join(r[:8] for r in chg.evidence_references)
            detail_lines.append(f"[italic]Evidence IDs: {refs}[/italic]")

        table.add_row(
            str(chg.category),
            badge,
            escape(chg.identifier),
            "\n".join(detail_lines),
        )

    # 3. Warnings panels if collector failures occurred
    warning_panels: list[Panel] = []
    if diff.has_collector_failures:
        for w in diff.collector_failure_warnings:
            warning_panels.append(
                Panel(
                    f"[bold yellow]Collection Alert:[/bold yellow] {escape(w)}",
                    title="[bold yellow]Data Incompleteness Notice[/bold yellow]",
                    border_style="yellow",
                )
            )

    return header_panel, table, warning_panels


def format_diff_markdown(diff: SnapshotDiffResult) -> str:
    """Generate professional GitHub-Flavored Markdown report for snapshot diff."""
    clean_inv_name = diff.investigation_name.replace("`", "'")
    lines: list[str] = [
        "# TraceGraph Infrastructure Diff Report",
        "",
        f"**Investigation:** `{clean_inv_name}` (`{diff.investigation_id}`)  ",
        f"**Generated:** `{diff.snapshot_b_created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
        "",
        "## 1. Snapshot Metadata",
        "",
        "| Attribute | Baseline Snapshot (A) | Target Snapshot (B) |",
        "| :--- | :--- | :--- |",
        f"| **Snapshot ID** | `{diff.snapshot_a_id}` | `{diff.snapshot_b_id}` |",
        (
            f"| **Label** | {_escape_md_cell(diff.snapshot_a_label)} | "
            f"{_escape_md_cell(diff.snapshot_b_label)} |"
        ),
        (
            f"| **Captured (UTC)** | `{diff.snapshot_a_created_at.isoformat()}` | "
            f"`{diff.snapshot_b_created_at.isoformat()}` |"
        ),
        (
            f"| **SHA-256 Digest** | `{diff.snapshot_a_digest}` | "
            f"`{diff.snapshot_b_digest}` |"
        ),
        "",
        "## 2. Executive Summary of Changes",
        "",
        "| Change Metric | Count | Description |",
        "| :--- | :---: | :--- |",
        (
            f"| **Total Changes** | **{diff.summary.total_changes}** | "
            "All detected modifications across entities and edges |"
        ),
        (
            f"| **Added Entities** | {diff.summary.added_entities} | "
            "Newly discovered infrastructure nodes |"
        ),
        (
            f"| **Unobserved Entities** | {diff.summary.unobserved_entities} | "
            "Previously recorded entities not seen in target run |"
        ),
        (
            f"| **Modified Entities** | {diff.summary.modified_entities} | "
            "Entities whose raw values or metadata changed |"
        ),
        (
            f"| **Added Relationships** | {diff.summary.added_relationships} | "
            "Newly verified infrastructure links |"
        ),
        (
            f"| **Removed Relationships** | {diff.summary.removed_relationships} | "
            "Relationships absent in target collection |"
        ),
        (
            f"| **Evidence Updates** | {diff.summary.modified_evidence} | "
            "Existing links with changed observation proofs |"
        ),
        (
            f"| **New Observations** | {diff.summary.new_observations} | "
            "New discrete collection runs |"
        ),
        (
            f"| **Collector Failures** | {diff.summary.collector_failures} | "
            "Target observations resulting in errors or timeouts |"
        ),
        "",
    ]

    if diff.has_collector_failures:
        lines.append("> [!WARNING]")
        lines.append("> **Incomplete Observation Context Detected**")
        for warn in diff.collector_failure_warnings:
            lines.append(f"> - {warn}")
        lines.append("")

    lines.append("## 3. Detailed Change Log")
    lines.append("")

    if not diff.changes:
        lines.append(
            "_No logical changes detected between snapshots. Infrastructure state is identical._"
        )
        lines.append("")
    else:
        lines.append(
            "| Category | Change Type | Component Identifier | Explanation | Supporting Evidence |"
        )
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in diff.changes:
            ev_str = (
                ", ".join(f"`{r[:8]}`" for r in c.evidence_references)
                if c.evidence_references
                else "—"
            )
            clean_ident = _escape_md_cell(c.identifier)
            clean_expl = _escape_md_cell(c.explanation)
            lines.append(
                f"| `{c.category}` | **{c.change_type}** | `{clean_ident}` | "
                f"{clean_expl} | {ev_str} |"
            )
        lines.append("")

    lines.extend([
        "## 4. Methodology & Temporal Intelligence Notes",
        "",
        (
            "- **Observed Absence vs. Absence of Evidence:** In OSINT intelligence, an entity "
            "or relationship marked `UNOBSERVED` signifies that collectors did not observe "
            "the item during the collection window. It does not provide proof of decommissioning."
        ),
        (
            "- **Content Integrity:** Each snapshot's SHA-256 digest validates deterministic "
            "content serialization. The digest remains invariant to key order, timestamp "
            "formatting artifacts, and internal database IDs."
        ),
        "",
        "---",
        "_Report produced by TraceGraph v0.3.0 Evidence Graph Engine_",
    ])

    return "\n".join(lines)


def format_diff_json(diff: SnapshotDiffResult, indent: int = 2) -> str:
    """Export snapshot diff result as structured JSON."""
    raw: dict[str, Any] = diff.model_dump(mode="json")
    return json.dumps(raw, indent=indent, sort_keys=True)
