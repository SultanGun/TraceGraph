"""Evidence graph reporting and presentation formatting."""

from typing import Any

from rich.table import Table

from tracegraph.evidence.models import EntityModel, ObservationModel, RelationshipModel


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
