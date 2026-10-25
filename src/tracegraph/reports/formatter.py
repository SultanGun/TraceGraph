"""Evidence graph reporting and presentation formatting."""

from typing import Any

from rich.table import Table

from tracegraph.evidence.models import (
    EntityModel,
    InvestigationModel,
    ObservationModel,
    RelationshipModel,
)


def format_evidence_table(
    relationships: list[RelationshipModel],
    entities_by_id: dict[str, EntityModel],
    observations_by_id: dict[str, ObservationModel] | None = None,
) -> Table:
    """Format relationships and supporting evidence provenance into a Rich Table."""
    table = Table(title="TraceGraph Infrastructure Evidence Graph", show_lines=True)

    table.add_column("Status", style="bold", width=12)
    table.add_column("Source Entity", style="cyan")
    table.add_column("Relationship", style="magenta")
    table.add_column("Target Entity", style="cyan")
    table.add_column("Supporting Evidence", style="dim")

    obs_map = observations_by_id or {}

    for rel in relationships:
        source_ent = entities_by_id.get(rel.source_entity_id)
        target_ent = entities_by_id.get(rel.target_entity_id)

        source_label = (
            f"[{source_ent.entity_type}] {source_ent.normalized_value}"
            if source_ent
            else rel.source_entity_id[:8]
        )
        target_label = (
            f"[{target_ent.entity_type}] {target_ent.normalized_value}"
            if target_ent
            else rel.target_entity_id[:8]
        )

        if rel.is_verified:
            status_badge = "[bold green][VERIFIED][/bold green]"
            evidence_lines = []
            for obs_id in rel.supporting_observation_ids:
                obs = obs_map.get(obs_id)
                if obs:
                    evidence_lines.append(
                        f"• {obs.collector_name} v{obs.collector_version} ({obs.source_reference})"
                    )
                else:
                    evidence_lines.append(f"• Obs: {obs_id[:8]}")
            evidence_desc = "\n".join(evidence_lines)
        else:
            status_badge = "[bold red][UNVERIFIED][/bold red]"
            evidence_desc = "No supporting observations linked!"

        table.add_row(
            status_badge,
            source_label,
            rel.relationship_type,
            target_label,
            evidence_desc,
        )

    return table


def build_investigation_summary(
    investigation_name: str,
    entity_count: int,
    observation_count: int,
    relationship_count: int,
    verified_relationship_count: int,
) -> dict[str, Any]:
    """Build structured summary dictionary for an investigation."""
    unverified_count = relationship_count - verified_relationship_count
    return {
        "investigation": investigation_name,
        "entity_count": entity_count,
        "observation_count": observation_count,
        "total_relationships": relationship_count,
        "verified_relationships": verified_relationship_count,
        "unverified_relationships": unverified_count,
        "evidence_integrity": (
            "100% verified"
            if unverified_count == 0 and relationship_count > 0
            else "unverified edges detected"
            if unverified_count > 0
            else "no relationships"
        ),
    }


def generate_markdown_report(
    investigation: InvestigationModel,
    observations: list[ObservationModel],
    entities_by_id: dict[str, EntityModel],
    relationships: list[RelationshipModel],
) -> str:
    """Generate a comprehensive, evidence-backed Markdown investigation report."""
    verified_cnt = sum(1 for r in relationships if r.is_verified)
    unverified_cnt = len(relationships) - verified_cnt

    if unverified_cnt == 0 and len(relationships) > 0:
        integrity_status = "100% verified"
    elif unverified_cnt > 0:
        integrity_status = "Unverified edges detected"
    else:
        integrity_status = "No relationships recorded"

    lines: list[str] = [
        f"# TraceGraph Investigation Report: {investigation.name}",
        "",
        "## 1. Investigation Metadata",
        "",
        f"- **Investigation ID:** `{investigation.id}`",
        f"- **Declared Scope:** `{investigation.target_scope or 'Unrestricted'}`",
        f"- **Created At (UTC):** `{investigation.created_at.isoformat()}`",
        f"- **Description:** {investigation.description or 'No description provided'}",
        "",
        "## 2. Integrity & Metrics Summary",
        "",
        "| Metric | Count |",
        "| :--- | :--- |",
        f"| Total Infrastructure Entities | {len(entities_by_id)} |",
        f"| Total Observations Logged | {len(observations)} |",
        f"| Total Relationships | {len(relationships)} |",
        f"| Verified Relationships | {verified_cnt} |",
        f"| Unverified Relationships | {unverified_cnt} |",
        f"| Provenance Integrity | {integrity_status} |",
        "",
        "## 3. Discovered Infrastructure Entities",
        "",
        "| Entity Type | Normalized Value | Registered (UTC) |",
        "| :--- | :--- | :--- |",
    ]

    for ent in entities_by_id.values():
        lines.append(
            f"| `{ent.entity_type}` | `{ent.normalized_value}` | `{ent.created_at.isoformat()}` |"
        )

    lines.extend([
        "",
        "## 4. Observations & Provenance Log",
        "",
        "| Collector | Version | Status | Observed (UTC) | Ingested (UTC) | Source Reference |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    obs_map = {o.id: o for o in observations}
    for obs in observations:
        err_str = f" (Error: {obs.error_details})" if obs.error_details else ""
        lines.append(
            f"| `{obs.collector_name}` | `v{obs.collector_version}` | **{obs.status}**{err_str} | "
            f"`{obs.observed_at.isoformat()}` | `{obs.ingested_at.isoformat()}` | "
            f"`{obs.source_reference}` |"
        )

    lines.extend([
        "",
        "## 5. Evidence Graph & Verifiable Relationships",
        "",
        "| Status | Source Entity | Relationship | Target Entity | Supporting Evidence |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    for rel in relationships:
        src = entities_by_id.get(rel.source_entity_id)
        tgt = entities_by_id.get(rel.target_entity_id)
        src_label = (
            f"`{src.entity_type}` {src.normalized_value}" if src else rel.source_entity_id[:8]
        )
        tgt_label = (
            f"`{tgt.entity_type}` {tgt.normalized_value}" if tgt else rel.target_entity_id[:8]
        )

        if rel.is_verified:
            badge = "✅ **VERIFIED**"
            citations = []
            for obs_id in rel.supporting_observation_ids:
                o = obs_map.get(obs_id)
                if o:
                    citations.append(f"{o.collector_name} ({o.source_reference})")
                else:
                    citations.append(f"Obs:{obs_id[:8]}")
            evidence_str = "; ".join(citations)
        else:
            badge = "⚠️ **UNVERIFIED**"
            evidence_str = "No supporting observations linked"

        lines.append(
            f"| {badge} | {src_label} | `{rel.relationship_type}` | {tgt_label} | "
            f"{evidence_str} |"
        )

    lines.extend([
        "",
        "## 6. Defensive Scope & Attribution Policy",
        "",
        "1. **Attribution Boundaries:** Technical co-location, DNS resolution, and RDAP data "
        "reflect connectivity at observed timestamps and do not constitute legal proof "
        "of organizational affiliation or malicious intent.",
        "2. **Evidence Preservation:** Every verified relationship is immutably linked to "
        "observation records stored in the local TraceGraph SQLite database.",
        "",
    ])

    return "\n".join(lines)
