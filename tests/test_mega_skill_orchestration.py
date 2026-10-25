#!/usr/bin/env python3
"""
test_mega_skill_orchestration.py: End-to-End Mega-Skill Intent & Tool Integration Tests
=====================================================================================
Verifies:
1. Natural language intent classification and routing across the 4 specialist swarms.
2. End-to-end compilation and execution of the unified Attack Surface Audit DAG.
3. Concrete integration of local tool adapters inside specialist agent execution nodes:
   - ADHX Threat Intel IOC extraction (Threat Radar)
   - Attack Tree Mermaid generation (GitHub DevOps)
   - DuckDB OLAP telemetry aggregations (Marketing Growth)
   - FFmpeg media pipeline inspection (Social Swarm)
   - Everything Search file indexing (DevOps PR Auditor)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path("A:/") if Path("A:/").exists() else Path("C:/AgyHut")
SYSTEM_DIR = WORKSPACE_ROOT / "system"
SCRIPTS_DIR = SYSTEM_DIR / "scripts"
ORBIT_SRC = WORKSPACE_ROOT / "projects" / "orbit-security" / "src"

for p in (str(SCRIPTS_DIR), str(ORBIT_SRC)):
    if p not in sys.path and Path(p).exists():
        sys.path.insert(0, p)

swarm_orchestrator = pytest.importorskip("swarm_orchestrator", reason="swarm_orchestrator sibling script not present")


class TestMegaSkillIntentRouting:
    def test_route_github_release_intent(self):
        pipeline = swarm_orchestrator.route_intent_to_dag("Draft release for v4.2 with changelog and signed tags")
        assert pipeline.task_id.startswith("swarm_github_")
        assert "node_pr_audit" in pipeline.nodes
        assert "node_release_sentinel" in pipeline.nodes
        assert "node_showcase_builder" in pipeline.nodes

    def test_route_threat_intel_intent(self):
        pipeline = swarm_orchestrator.route_intent_to_dag("Harvest recent DEFCON talks on eBPF and draft threat advisory")
        assert pipeline.task_id.startswith("swarm_threat_")
        assert "node_zero_day_sniffer" in pipeline.nodes
        assert "node_cve_synthesizer" in pipeline.nodes
        assert "node_advisory_drafter" in pipeline.nodes

    def test_route_attack_surface_audit_intent(self):
        pipeline = swarm_orchestrator.route_intent_to_dag("Audit public attack surface of target.com and generate client briefing")
        assert pipeline.task_id.startswith("swarm_audit_")
        assert "node_header_probe" in pipeline.nodes
        assert "node_attack_tree" in pipeline.nodes
        assert "node_client_briefing" in pipeline.nodes

    def test_route_marketing_growth_intent(self):
        pipeline = swarm_orchestrator.route_intent_to_dag("Analyze last 30 days of DNS telemetry and export parquet for Shopify push")
        assert pipeline.task_id.startswith("swarm_growth_")
        assert "node_growth_strategy" in pipeline.nodes
        assert "node_technical_copy" in pipeline.nodes
        assert "node_funnel_optimization" in pipeline.nodes

    def test_route_social_roast_intent(self):
        pipeline = swarm_orchestrator.route_intent_to_dag("Craft verified perimeter roast with terminal teaser video attachment")
        assert pipeline.task_id.startswith("swarm_social_")
        assert "node_roast_crafter" in pipeline.nodes
        assert "node_thread_architect" in pipeline.nodes
        assert "node_community_sentinel" in pipeline.nodes


class TestMegaSkillExecutionAndToolIntegration:
    def test_execute_attack_surface_audit_dag(self):
        dag = swarm_orchestrator.compile_attack_surface_audit_dag("target.com")
        assert len(dag.nodes) == 3
        res = swarm_orchestrator.execute_dag(dag)
        assert res["status"] == "COMPLETED"
        assert len(res["artifacts"]) == 3

    def test_threat_radar_adhx_tool_integration(self):
        dag = swarm_orchestrator.compile_threat_intel_dag("Critical eBPF Zero-Day")
        res = swarm_orchestrator.execute_dag(dag)
        assert res["status"] == "COMPLETED"
        sniffer_node = dag.nodes["node_zero_day_sniffer"]
        assert "ADHX" in sniffer_node.output or "threat" in sniffer_node.output.lower()
        assert sniffer_node.artifact["payload"].get("iocs_extracted") is True

    def test_github_devops_attack_tree_and_es_integration(self):
        dag = swarm_orchestrator.compile_github_release_dag("v4.2.0")
        res = swarm_orchestrator.execute_dag(dag)
        assert res["status"] == "COMPLETED"
        showcase_node = dag.nodes["node_showcase_builder"]
        assert "Mermaid" in showcase_node.output or "attack tree" in showcase_node.output.lower()
        assert showcase_node.artifact["payload"].get("attack_tree_format") == "mermaid"

        pr_node = dag.nodes["node_pr_audit"]
        assert "Everything" in pr_node.output or "AST static check passed" in pr_node.output
        assert pr_node.artifact["payload"].get("es_indexed") is True

    def test_marketing_growth_duckdb_integration(self):
        dag = swarm_orchestrator.compile_marketing_campaign_dag("Shopify Plus Tier Conversion")
        res = swarm_orchestrator.execute_dag(dag)
        assert res["status"] == "COMPLETED"
        growth_node = dag.nodes["node_growth_strategy"]
        assert "DuckDB" in growth_node.output or "Market signal analysis complete" in growth_node.output
        assert growth_node.artifact["payload"].get("olap_analytics_engine") == "DuckDBEngine"

    def test_social_swarm_ffmpeg_integration(self):
        dag = swarm_orchestrator.compile_social_engagement_dag("Avex Designs")
        res = swarm_orchestrator.execute_dag(dag)
        assert res["status"] == "COMPLETED"
        thread_node = dag.nodes["node_thread_architect"]
        assert "FFmpeg" in thread_node.output or "ASCII diagrams" in thread_node.output
        assert thread_node.artifact["payload"].get("media_generator") == "FFmpegRenderer"
