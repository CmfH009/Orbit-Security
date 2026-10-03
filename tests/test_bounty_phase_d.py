"""Unit tests for Phase D: Cockpit 3D Visual HUD 2.0 & Continuous 24/7 Operations.

Tests:
1. BountyAttackGraph.build_from_ecosystem (autonomous graph generation from programs and disclosures).
2. BountyAttackGraph.export_constellation_hubs (3D WebGL / Canvas constellation schema & color mapping).
3. BountyRadarSupervisor auto-sync of attack surface topology after sweep.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.bounty_graph import BountyAttackGraph
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyRadarSupervisor,
    BountyScopeIngester,
    BountyTakeoverSweeper,
    BountyVulnerability,
)
from orbit_security.models import Severity


class TestBountyPhaseD:
    """Test suite for Phase D graph building, constellation export, and daemon integration."""

    def test_build_from_ecosystem_with_mocks(self, tmp_path):
        # 1. Create mock programs file
        progs_file = tmp_path / "test_programs.json"
        progs_data = {
            "version": "1.0",
            "programs": [
                {
                    "program_id": "test_corp",
                    "name": "TestCorp Security",
                    "platform": "hackerone",
                    "policy_url": "https://hackerone.com/test_corp",
                    "in_scope": ["*.testcorp.com", "api.testcorp.com"],
                    "out_of_scope": ["dev.testcorp.com"],
                    "bounty_tier": "cash",
                    "max_bounty": 25000,
                    "state": "active",
                }
            ],
        }
        progs_file.write_text(json.dumps(progs_data, indent=2), encoding="utf-8")

        # 2. Create mock disclosures folder
        disc_dir = tmp_path / "disclosures"
        disc_dir.mkdir(parents=True)
        sample_md = """# [Subdomain Takeover] Unclaimed S3 Bucket on blog.testcorp.com

**Program:** TestCorp Security (Hackerone)  
**Asset (In-Scope Target):** `blog.testcorp.com`  
**Weakness:** `CWE-284: Improper Access Control`  
**Severity:** `HIGH` (CVSS 3.1: **8.6**)  
**Bounty Viability Grade:** `HIGH_CONFIDENCE`  

- **Vulnerability Category:** `Cloud Storage Takeover`
- **Affected Provider/Service:** `AWS S3`

1. Query DNS CNAME:
   ```bash
   dig blog.testcorp.com CNAME +short
   # Output: testcorp-orphaned-bucket.s3.amazonaws.com
   ```
Observe evidence: `NoSuchBucket: The specified bucket does not exist`
"""
        (disc_dir / "test_disclosure.md").write_text(sample_md, encoding="utf-8")

        # 3. Build graph
        out_dir = tmp_path / "graph_out"
        graph = BountyAttackGraph.build_from_ecosystem(
            programs_path=progs_file,
            disclosures_dir=disc_dir,
            output_dir=out_dir,
            save_disk=True,
        )

        assert len(graph.nodes) >= 4  # program, domains, vuln, cname, provider
        assert "prog:test_corp" in graph.nodes
        assert "domain:testcorp.com" in graph.nodes
        assert "domain:blog.testcorp.com" in graph.nodes
        assert any(n["type"] == "VULNERABILITY" for n in graph.nodes.values())
        assert any(n["type"] == "CNAME_TARGET" for n in graph.nodes.values())

        # Verify saved JSON
        saved_json = out_dir / "bounty_attack_surface.json"
        assert saved_json.exists()
        loaded = json.loads(saved_json.read_text(encoding="utf-8"))
        assert loaded["stats"]["programs"] >= 1
        assert loaded["stats"]["vulnerabilities"] >= 1

    def test_export_constellation_hubs(self):
        graph = BountyAttackGraph()
        prog = BountyProgram(
            program_id="shopify",
            name="Shopify",
            platform="hackerone",
            policy_url="https://hackerone.com/shopify",
            in_scope=["*.myshopify.com"],
            out_of_scope=[],
        )
        graph.ingest_program(prog)

        vuln_high = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="partner.myshopify.com",
            cname_target="dangling.trafficmanager.net",
            flaw_type="subdomain_takeover",
            provider="Azure Traffic Manager",
            severity=Severity.HIGH,
            cvss_score=8.6,
            evidence="NoSuchHost",
            bounty_viability="HIGH_CONFIDENCE",
        )
        graph.ingest_vulnerability(vuln_high)

        vuln_info = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="mail.myshopify.com",
            flaw_type="mail_spoofing",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            evidence="Missing DMARC p=reject",
            bounty_viability="INFORMATIONAL_LOW",
        )
        graph.ingest_vulnerability(vuln_info)

        cdata = graph.export_constellation_hubs()
        assert cdata["ok"] is True
        assert "hubs" in cdata
        assert "links" in cdata
        assert cdata["total_nodes"] == len(graph.nodes)
        assert cdata["total_links"] == len(graph.edges)

        hubs = cdata["hubs"]
        # Verify 3D coordinates
        for h in hubs:
            assert isinstance(h["x"], (int, float))
            assert isinstance(h["y"], (int, float))
            assert isinstance(h["z"], (int, float))
            assert "category" in h
            assert "color" in h

        # Check color differentiation
        high_hub = next(h for h in hubs if "subdomain_takeover" in h["id"])
        assert high_hub["color"] == "#ef4444"  # Red for high confidence cash ready

        info_hub = next(h for h in hubs if "mail_spoofing" in h["id"])
        assert info_hub["color"] == "#fbbf24"  # Amber for informational

    def test_run_sweep_syncs_attack_graph(self, tmp_path):
        ingester = BountyScopeIngester(data_path=tmp_path / "programs.json")
        ingester.programs = {
            "demo": BountyProgram(
                program_id="demo",
                name="Demo Corp",
                platform="hackerone",
                policy_url="https://hackerone.com/demo",
                in_scope=["demo.com"],
                out_of_scope=[],
                state="active",
            )
        }
        ingester.save()

        sweeper = BountyTakeoverSweeper()
        state_file = tmp_path / "state.json"
        sup = BountyRadarSupervisor(
            ingester=ingester, sweeper=sweeper, state_file=state_file
        )

        out_graph_dir = tmp_path / "graphify"
        res = sup.run_sweep(
            program_id="demo",
            force_now=True,
            save_disclosures=False,
            sync_attack_graph=True,
            output_dir=out_graph_dir,
        )

        assert res["status"] == "COMPLETED"
        graph_file = out_graph_dir / "bounty_attack_surface.json"
        assert graph_file.exists()
