"""Command Line Interface implementation for TraceGraph using Typer."""

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import tracegraph
from tracegraph.core.exceptions import WorkspaceError
from tracegraph.storage.workspace import (
    get_workspace_status,
    init_workspace,
    resolve_workspace_path,
)

app = typer.Typer(
    name="tracegraph",
    help="TraceGraph: Local-first, evidence-first OSINT infrastructure intelligence platform.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    """Option callback for --version flag."""
    if value:
        console.print(f"TraceGraph v{tracegraph.__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Display installed TraceGraph version.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """TraceGraph OSINT platform CLI entry point."""


@app.command(name="version", help="Display installed TraceGraph version.")
def version_cmd() -> None:
    """Display the installed TraceGraph version."""
    console.print(f"TraceGraph v{tracegraph.__version__}")


@app.command(name="init", help="Initialize a local TraceGraph workspace and SQLite database.")
def init_cmd(
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Explicit directory path for TraceGraph workspace (default: .tracegraph).",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Initialize a local TraceGraph workspace and SQLite schema idempotently and safely."""
    target_ws = resolve_workspace_path(workspace)

    try:
        status = init_workspace(target_ws, allow_idempotent=True)
    except WorkspaceError as e:
        err_console.print(f"[bold red]Initialization Error:[/bold red] {e}")
        raise typer.Exit(code=1) from e
    except Exception as e:
        err_console.print(f"[bold red]Unexpected Failure:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    if status.is_initialized:
        console.print(
            Panel(
                f"[bold green]Workspace ready:[/bold green] {status.workspace_path}\n"
                f"[bold cyan]Database file:[/bold cyan] {status.db_path}\n"
                f"[bold cyan]Schema version:[/bold cyan] {status.schema_version}\n"
                "[bold cyan]Status:[/bold cyan] Connected and verified (SQLite foreign keys ON)",
                title="[bold]TraceGraph Initialization[/bold]",
                border_style="green",
            )
        )
    else:
        err_console.print(
            f"[bold red]Error:[/bold red] Workspace at '{target_ws}' could not be initialized. "
            f"{status.error_message or ''}"
        )
        raise typer.Exit(code=1)


@app.command(
    name="status",
    help="Display workspace path, database connectivity, and initialization status.",
)
def status_cmd(
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Explicit directory path for TraceGraph workspace to inspect.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Display the status of the TraceGraph environment without printing sensitive variables."""
    target_ws = resolve_workspace_path(workspace)
    status = get_workspace_status(target_ws)

    table = Table(title="TraceGraph System & Workspace Status", show_header=False, show_lines=True)
    table.add_column("Property", style="bold cyan", width=24)
    table.add_column("Value", style="white")

    ws_exists_badge = "[green]Yes[/green]" if status.directory_exists else "[yellow]No[/yellow]"
    db_exists_badge = "[green]Yes[/green]" if status.db_exists else "[yellow]No[/yellow]"

    table.add_row("TraceGraph Version", f"v{status.version}")
    table.add_row("Workspace Directory", str(status.workspace_path))
    table.add_row("Workspace Exists", ws_exists_badge)
    table.add_row("Database Path", str(status.db_path))
    table.add_row("Database File Exists", db_exists_badge)

    # Connectivity
    conn_badge = (
        "[bold green]CONNECTED (Foreign keys ON)[/bold green]"
        if status.db_connected
        else "[bold red]DISCONNECTED[/bold red]"
    )
    table.add_row("Database Connectivity", conn_badge)

    # Schema & initialization status
    if status.is_initialized:
        table.add_row(
            "Schema Status",
            f"[bold green]INITIALIZED[/bold green] (Schema v{status.schema_version})",
        )
        table.add_row("Total Entities", str(status.entity_count))
        table.add_row("Total Observations", str(status.observation_count))
        table.add_row("Total Relationships", str(status.relationship_count))
    else:
        table.add_row(
            "Schema Status",
            "[bold yellow]NOT INITIALIZED[/bold yellow] (Run 'tracegraph init' to create)",
        )

    if status.error_message:
        table.add_row("Diagnostic Notice", f"[bold red]{status.error_message}[/bold red]")

    console.print(table)


def cli_entrypoint() -> None:
    """Main CLI entry point callable directly by console script."""
    app()


if __name__ == "__main__":
    cli_entrypoint()
