"""Command Line Interface implementation for TraceGraph using Typer."""

import ipaddress
from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

import tracegraph
from tracegraph.collectors.base import BaseCollector
from tracegraph.collectors.dns import LiveDNSCollector
from tracegraph.collectors.mock import MockDNSCollector
from tracegraph.collectors.rdap import RDAPCollector
from tracegraph.core.enums import CollectionStatus, EntityType
from tracegraph.core.exceptions import NotFoundError, ScopeError, WorkspaceError
from tracegraph.core.scope import ScopeValidator
from tracegraph.evidence.models import RelationshipModel
from tracegraph.reports.formatter import generate_markdown_report
from tracegraph.storage.database import create_session_factory, create_storage_engine
from tracegraph.storage.repository import EvidenceRepository
from tracegraph.storage.workspace import (
    DEFAULT_DB_FILENAME,
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

investigate_app = typer.Typer(
    name="investigate",
    help="Manage investigation boundaries, scopes, and target authorizations.",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(investigate_app, name="investigate")

console = Console()
err_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    """Option callback for --version flag."""
    if value:
        console.print(f"TraceGraph v{tracegraph.__version__}")
        raise typer.Exit(0)


def _get_repo(target_ws: Path) -> EvidenceRepository:
    """Retrieve repository instance for an initialized workspace."""
    status = get_workspace_status(target_ws)
    if not status.is_initialized:
        err_console.print(
            f"[bold red]Workspace Error:[/bold red] Workspace at '{target_ws}' is not initialized. "
            "Run 'tracegraph init' first."
        )
        raise typer.Exit(code=1)
    engine = create_storage_engine(target_ws / DEFAULT_DB_FILENAME)
    session_factory = create_session_factory(engine)
    return EvidenceRepository(session_factory)


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

    conn_badge = (
        "[bold green]CONNECTED (Foreign keys ON)[/bold green]"
        if status.db_connected
        else "[bold red]DISCONNECTED[/bold red]"
    )
    table.add_row("Database Connectivity", conn_badge)

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


# =============================================================================
# Investigation Commands
# =============================================================================


@investigate_app.command(name="new", help="Create a new investigation boundary and declared scope.")
def investigate_new_cmd(
    name: str = typer.Argument(..., help="Investigation name or reference identifier."),
    scope: str = typer.Option(
        "",
        "--scope",
        "-s",
        help="Declared target scope (e.g. 'example.com, 93.184.215.0/24' or '*' for unrestricted).",
    ),
    description: str | None = typer.Option(
        None, "--desc", "-d", help="Objective, scope notes, or incident reference."
    ),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Explicit directory path for TraceGraph workspace.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Create a new investigation scope."""
    target_ws = resolve_workspace_path(workspace)
    repo = _get_repo(target_ws)

    inv = repo.create_investigation(
        name=name,
        description=description,
        target_scope=scope,
    )

    console.print(
        Panel(
            f"[bold cyan]ID:[/bold cyan] {inv.id}\n"
            f"[bold cyan]Name:[/bold cyan] {inv.name}\n"
            f"[bold cyan]Declared Scope:[/bold cyan] {inv.target_scope or 'Unrestricted (*)'}\n"
            f"[bold cyan]Created (UTC):[/bold cyan] {inv.created_at.isoformat()}\n"
            f"[bold cyan]Description:[/bold cyan] {inv.description or 'None'}",
            title="[bold green]Investigation Created[/bold green]",
            border_style="green",
        )
    )


@investigate_app.command(name="list", help="List all investigations in the workspace.")
def investigate_list_cmd(
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Explicit directory path for TraceGraph workspace.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """List all investigations registered in this workspace."""
    target_ws = resolve_workspace_path(workspace)
    repo = _get_repo(target_ws)

    invs = repo.list_investigations()
    if not invs:
        console.print(
            "[yellow]No investigations found. Create one with "
            "'tracegraph investigate new <name>'.[/yellow]"
        )
        return

    table = Table(title="Investigations", show_lines=True)
    table.add_column("ID", style="cyan", width=36)
    table.add_column("Name", style="bold white")
    table.add_column("Declared Scope", style="magenta")
    table.add_column("Created (UTC)", style="dim")

    for inv in invs:
        table.add_row(
            inv.id,
            inv.name,
            inv.target_scope or "*",
            inv.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print(table)


@investigate_app.command(name="show", help="Show details for a specific investigation.")
def investigate_show_cmd(
    investigation_id: str = typer.Argument(..., help="Investigation UUID."),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Explicit directory path for TraceGraph workspace.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Display information about a specific investigation."""
    target_ws = resolve_workspace_path(workspace)
    repo = _get_repo(target_ws)

    try:
        inv = repo.get_investigation(investigation_id)
    except NotFoundError:
        err_console.print(
            f"[bold red]Error:[/bold red] Investigation '{investigation_id}' not found."
        )
        raise typer.Exit(code=1)

    obs = repo.list_observations_for_investigation(inv.id)

    console.print(
        Panel(
            f"[bold cyan]ID:[/bold cyan] {inv.id}\n"
            f"[bold cyan]Name:[/bold cyan] {inv.name}\n"
            f"[bold cyan]Declared Scope:[/bold cyan] {inv.target_scope or 'Unrestricted (*)'}\n"
            f"[bold cyan]Created (UTC):[/bold cyan] {inv.created_at.isoformat()}\n"
            f"[bold cyan]Total Observations:[/bold cyan] {len(obs)}\n"
            f"[bold cyan]Description:[/bold cyan] {inv.description or 'None'}",
            title="[bold green]Investigation Details[/bold green]",
            border_style="green",
        )
    )


# =============================================================================
# Collection Command
# =============================================================================


def _detect_entity_type(target: str) -> EntityType:
    """Infer EntityType from target string."""
    clean = target.strip()
    try:
        ip = ipaddress.ip_address(clean)
        return EntityType.IPV6 if ip.version == 6 else EntityType.IPV4
    except ValueError:
        pass

    if "/" in clean:
        return EntityType.CIDR

    return EntityType.DOMAIN


def _get_collector(collector_name: str) -> BaseCollector:
    """Factory creating collector instance by name."""
    c_lower = collector_name.strip().lower()
    if c_lower in ("live_dns", "dns"):
        return LiveDNSCollector()
    if c_lower in ("rdap", "rdap_ip"):
        return RDAPCollector()
    if c_lower in ("mock_dns", "mock"):
        return MockDNSCollector()

    valid_collectors = "live_dns, rdap, mock_dns"
    raise ValueError(
        f"Unknown collector '{collector_name}'. Supported collectors: {valid_collectors}"
    )


@app.command(
    name="collect",
    help="Execute bounded data collection against a target within an investigation.",
)
def collect_cmd(
    target: str = typer.Argument(..., help="Target domain or IP address to investigate."),
    collector_name: str = typer.Option(
        ...,
        "--collector",
        "-c",
        help="Collector to execute ('live_dns', 'rdap', 'mock_dns').",
    ),
    investigation_id: str | None = typer.Option(
        None,
        "--investigation",
        "-i",
        help="Target investigation UUID. If omitted and 1 exists, it is selected.",
    ),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Explicit directory path for TraceGraph workspace.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Execute bounded OSINT collection and record verifiable evidence."""
    target_ws = resolve_workspace_path(workspace)
    repo = _get_repo(target_ws)

    # 1. Resolve Investigation
    invs = repo.list_investigations()
    selected_inv = None
    if investigation_id:
        try:
            selected_inv = repo.get_investigation(investigation_id)
        except NotFoundError:
            err_console.print(
                f"[bold red]Error:[/bold red] Investigation '{investigation_id}' not found."
            )
            raise typer.Exit(code=1)
    else:
        if len(invs) == 0:
            err_console.print(
                "[bold red]Workflow Error:[/bold red] No investigations exist in this workspace.\n"
                "Create one first with:\n  "
                "[bold cyan]tracegraph investigate new <name> --scope <target>[/bold cyan]"
            )
            raise typer.Exit(code=1)
        if len(invs) == 1:
            selected_inv = invs[0]
            console.print(
                f"[dim]Active investigation: {selected_inv.name} ({selected_inv.id[:8]})[/dim]"
            )
        else:
            err_console.print(
                "[bold red]Error:[/bold red] Multiple investigations exist. "
                "Please specify one with --investigation <id>."
            )
            table = Table(title="Available Investigations", show_lines=False)
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="bold")
            table.add_column("Scope", style="magenta")
            for i in invs:
                table.add_row(i.id, i.name, i.target_scope or "*")
            err_console.print(table)
            raise typer.Exit(code=1)

    # 2. Scope Validation
    entity_type = _detect_entity_type(target)
    if selected_inv.target_scope:
        scope_validator = ScopeValidator(selected_inv.target_scope)
        try:
            scope_validator.assert_in_scope(target, entity_type)
        except ScopeError as e:
            err_console.print(f"[bold red]Scope Violation:[/bold red] {e}")
            raise typer.Exit(code=1) from e

    # 3. Instantiate Collector
    try:
        collector = _get_collector(collector_name)
    except ValueError as e:
        err_console.print(f"[bold red]Collector Error:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    # 4. Check collector compatibility
    if entity_type not in collector.supported_entity_types:
        supported = ", ".join(t.value for t in collector.supported_entity_types)
        err_console.print(
            f"[bold red]Target Incompatibility:[/bold red] Collector '{collector.name}' does not "
            f"support entity type '{entity_type.value}'. Supported types: {supported}"
        )
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]Collecting:[/bold cyan] {target} via {collector.name} v{collector.version}..."
    )

    # 5. Execute Collection
    result = collector.collect(target, entity_type)

    # 6. Transactional Persistence
    try:
        # Register or get target root entity
        root_entity, _ = repo.get_or_create_entity(entity_type, target)

        # Store observation
        err_info = (
            result.error_message
            or (str(result.error_details) if result.error_details else None)
        )
        obs = repo.record_observation(
            entity_id=root_entity.id,
            investigation_id=selected_inv.id,
            collector_name=result.collector_name,
            collector_version=result.collector_version,
            source_reference=result.source_reference,
            observed_at=result.observed_at,
            data=result.data,
            status=result.status,
            error_details=err_info,
        )

        created_rel_count = 0
        for disc_rel in result.discovered_relationships:
            src_ent, _ = repo.get_or_create_entity(
                disc_rel.source.entity_type, disc_rel.source.raw_value
            )
            tgt_ent, _ = repo.get_or_create_entity(
                disc_rel.target.entity_type, disc_rel.target.raw_value
            )
            rel, _ = repo.create_relationship(src_ent.id, tgt_ent.id, disc_rel.relationship_type)
            repo.link_evidence(
                relationship_id=rel.id,
                observation_id=obs.id,
                notes=f"Discovered by {result.collector_name} from {result.source_reference}",
            )
            created_rel_count += 1

    except Exception as e:
        err_console.print(
            f"[bold red]Storage Error:[/bold red] Failed persisting collection results: {e}"
        )
        raise typer.Exit(code=1) from e

    # 7. Presentation & Outcome Exit Codes
    if result.status == CollectionStatus.SUCCESS:
        console.print(
            Panel(
                f"[bold green]Status:[/bold green] SUCCESS\n"
                f"[bold cyan]Source:[/bold cyan] {result.source_reference}\n"
                f"[bold cyan]Observation ID:[/bold cyan] {obs.id}\n"
                f"[bold cyan]Discovered Entities:[/bold cyan] {len(result.discovered_entities)}\n"
                f"[bold cyan]Verified Relationships:[/bold cyan] {created_rel_count}\n"
                f"[bold cyan]Duration:[/bold cyan] {result.duration_seconds}s",
                title=f"[bold]Collection Result ({collector.name})[/bold]",
                border_style="green",
            )
        )
    elif result.status == CollectionStatus.EMPTY:
        console.print(
            Panel(
                f"[bold yellow]Status:[/bold yellow] EMPTY (0 records returned)\n"
                f"[bold cyan]Source:[/bold cyan] {result.source_reference}\n"
                f"[bold cyan]Observation ID:[/bold cyan] {obs.id}\n"
                f"[bold cyan]Duration:[/bold cyan] {result.duration_seconds}s",
                title=f"[bold]Collection Result ({collector.name})[/bold]",
                border_style="yellow",
            )
        )
    else:
        err_msg = result.error_message or "No specific error details"
        err_console.print(
            Panel(
                f"[bold red]Status:[/bold red] {result.status}\n"
                f"[bold cyan]Source:[/bold cyan] {result.source_reference}\n"
                f"[bold cyan]Observation ID:[/bold cyan] {obs.id}\n"
                f"[bold red]Error:[/bold red] {err_msg}",
                title=f"[bold red]Collection Failed ({collector.name})[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)


# =============================================================================
# Reporting Command
# =============================================================================


@app.command(name="report", help="Generate an evidence-backed Markdown investigation report.")
def report_cmd(
    investigation_id: str = typer.Argument(..., help="Investigation UUID to generate report for."),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to write Markdown report.",
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
    ),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Explicit directory path for TraceGraph workspace.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Generate Markdown report with full evidence provenance and verification status."""
    target_ws = resolve_workspace_path(workspace)
    repo = _get_repo(target_ws)

    try:
        inv = repo.get_investigation(investigation_id)
    except NotFoundError:
        err_console.print(
            f"[bold red]Error:[/bold red] Investigation '{investigation_id}' not found."
        )
        raise typer.Exit(code=1)

    obs_list = repo.list_observations_for_investigation(inv.id)
    all_ents = {e.id: e for e in repo.list_entities(limit=1000)}
    all_rels = repo.list_relationships(limit=1000)

    # Filter relationships relevant to the investigation's observations
    investigation_obs_ids = {o.id for o in obs_list}
    relevant_rels: list[RelationshipModel] = []
    for r in all_rels:
        # If relationship is substantiated by any observation in this investigation
        if any(oid in investigation_obs_ids for oid in r.supporting_observation_ids):
            relevant_rels.append(r)

    # Relevant entities
    relevant_ent_ids = set()
    for o in obs_list:
        relevant_ent_ids.add(o.entity_id)
    for r in relevant_rels:
        relevant_ent_ids.add(r.source_entity_id)
        relevant_ent_ids.add(r.target_entity_id)

    relevant_ents = {eid: all_ents[eid] for eid in relevant_ent_ids if eid in all_ents}

    markdown_content = generate_markdown_report(
        investigation=inv,
        observations=obs_list,
        entities_by_id=relevant_ents,
        relationships=relevant_rels,
    )

    if output:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(markdown_content, encoding="utf-8")
            console.print(f"[bold green]Report written to:[/bold green] {output}")
        except Exception as e:
            err_console.print(f"[bold red]File Error:[/bold red] Failed writing report: {e}")
            raise typer.Exit(code=1) from e
    else:
        console.print(Markdown(markdown_content))


def cli_entrypoint() -> None:
    """Main CLI entry point callable directly by console script."""
    app()


if __name__ == "__main__":
    cli_entrypoint()
