"""Integration test verifying end-to-end evidence ingestion, linkage, and reporting."""

from tracegraph.collectors.mock import MockDNSCollector
from tracegraph.core.enums import EntityType, RelationshipType
from tracegraph.reports.formatter import (
    build_investigation_summary,
    format_evidence_table,
)
from tracegraph.storage.repository import EvidenceRepository


class TestEvidencePipelineFlow:
    def test_complete_investigation_evidence_cycle(self, evidence_repo: EvidenceRepository):
        # 1. Start investigation
        inv = evidence_repo.create_investigation(
            name="Operation DryRun",
            description="End-to-end integration test of evidence provenance",
            config_metadata={"target": "example.com"},
        )
        assert inv.id is not None

        # 2. Register root entity
        root_entity, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "example.com")

        # 3. Execute mock collection
        collector = MockDNSCollector()
        result = collector.collect(root_entity.normalized_value, EntityType.DOMAIN)
        assert result.is_successful is True

        # 4. Ingest observation into repository
        obs_record = evidence_repo.record_observation(
            entity_id=root_entity.id,
            collector_name=result.collector_name,
            collector_version=result.collector_version,
            source_reference=result.source_reference,
            observed_at=result.observed_at,
            data=result.data,
            status=result.status,
        )
        assert obs_record.id is not None

        # 5. Ingest discovered entities and relationships
        created_rel_ids: list[str] = []
        for discovered_rel in result.discovered_relationships:
            src_ent, _ = evidence_repo.get_or_create_entity(
                discovered_rel.source.entity_type, discovered_rel.source.raw_value
            )
            tgt_ent, _ = evidence_repo.get_or_create_entity(
                discovered_rel.target.entity_type, discovered_rel.target.raw_value
            )

            rel, _ = evidence_repo.create_relationship(
                source_entity_id=src_ent.id,
                target_entity_id=tgt_ent.id,
                relationship_type=discovered_rel.relationship_type,
            )

            # Link the observation as proof for this relationship
            evidence_repo.link_evidence(
                relationship_id=rel.id,
                observation_id=obs_record.id,
                notes="Verified via synthetic DNS response",
            )
            created_rel_ids.append(rel.id)

        # 6. Verify all ingested relationships evaluate to is_verified == True
        for rel_id in created_rel_ids:
            rel_model, obs_list = evidence_repo.get_relationship_with_evidence(rel_id)
            assert rel_model.is_verified is True
            assert len(obs_list) == 1
            assert obs_list[0].id == obs_record.id

        # 7. Add an unsupported relationship and confirm it evaluates to is_verified == False
        unrelated_ent, _ = evidence_repo.get_or_create_entity(EntityType.DOMAIN, "unrelated.org")
        unsupported_rel, _ = evidence_repo.create_relationship(
            source_entity_id=root_entity.id,
            target_entity_id=unrelated_ent.id,
            relationship_type=RelationshipType.ASSOCIATED_WITH,
        )
        assert unsupported_rel.is_verified is False
        assert evidence_repo.is_relationship_verified(unsupported_rel.id) is False

        # 8. Test Reporting Formatter
        all_rels = evidence_repo.list_relationships()
        all_ents = {e.id: e for e in evidence_repo.list_entities()}
        all_obs = {obs_record.id: obs_record}

        table = format_evidence_table(all_rels, all_ents, all_obs)
        assert table.row_count == len(all_rels)

        verified_cnt = sum(1 for r in all_rels if r.is_verified)
        summary = build_investigation_summary(
            investigation_name=inv.name,
            entity_count=len(all_ents),
            observation_count=1,
            relationship_count=len(all_rels),
            verified_relationship_count=verified_cnt,
        )
        assert summary["total_relationships"] == len(created_rel_ids) + 1
        assert summary["verified_relationships"] == len(created_rel_ids)
        assert summary["unverified_relationships"] == 1
        assert summary["evidence_integrity"] == "unverified edges detected"
