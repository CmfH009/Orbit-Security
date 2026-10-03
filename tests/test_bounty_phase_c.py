"""Unit tests for Phase C: Graph-Driven Attack Surface Modeling & Agentic Swarm.

Tests:
1. BountyAttackGraph (relational attack surface topology, centrality, and JSON persistence).
2. GemmaTriageCopilot (policy compliance checks, evidence auditing, and Gemma triage decisions).
3. ResponsibleDisclosureDrafter.export_cryptographic_bundle (SHA-256 manifest and zip packaging).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import zipfile
import pytest

from orbit_security.bounty_graph import BountyAttackGraph
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyVulnerability,
    ResponsibleDisclosureDrafter,
)
from orbit_security.bounty_triage_copilot import (
    GemmaTriageCopilot,
    TriageDecision,
)
from orbit_security.models import Severity


class TestBountyAttackGraph:
    """Tests for Phase C Milestone C.1 GraphRAG Attack Surface Topology Engine."""

    def test_add_node_and_edge(self):
        graph = BountyAttackGraph()
        n1 = graph.add_node("prog:shopify", "Shopify", "BOUNTY_PROGRAM")
        n2 = graph.add_node("domain:shopify.com", "shopify.com", "PERIMETER_DOMAIN")
        graph.add_edge("prog:shopify", "domain:shopify.com", relation="MONITORS_DOMAIN")

        assert n1["degree"] == 1
        assert n1["out_degree"] == 1
        assert n2["degree"] == 1
        assert n2["in_degree"] == 1
        assert len(graph.edges) == 1
        assert graph.edges[0]["relation"] == "MONITORS_DOMAIN"

    def test_ingest_program(self):
        graph = BountyAttackGraph()
        prog = BountyProgram(
            program_id="gitlab",
            name="GitLab",
            platform="hackerone",
            policy_url="https://hackerone.com/gitlab",
            in_scope=["*.gitlab.com", "about.gitlab.com"],
            out_of_scope=["staging.gitlab.com"],
            bounty_tier="cash",
            max_bounty=35000,
        )
        graph.ingest_program(prog)

        assert "prog:gitlab" in graph.nodes
        assert "domain:gitlab.com" in graph.nodes
        assert "domain:about.gitlab.com" in graph.nodes
        assert "domain:staging.gitlab.com" in graph.nodes
        assert graph.nodes["domain:staging.gitlab.com"]["meta"].get("out_of_scope") is True

    def test_ingest_vulnerability_and_centrality(self):
        graph = BountyAttackGraph()
        prog = BountyProgram(
            program_id="acme",
            name="Acme",
            platform="bugcrowd",
            policy_url="https://bugcrowd.com/acme",
            in_scope=["*.acme.com"],
            out_of_scope=[],
        )
        graph.ingest_program(prog)

        vuln = BountyVulnerability(
            program_id="acme",
            program_name="Acme",
            platform="bugcrowd",
            target_domain="blog.acme.com",
            cname_target="acme.github.io",
            flaw_type="subdomain_takeover",
            provider="GitHub Pages",
            severity=Severity.HIGH,
            cvss_score=7.5,
            evidence="CNAME acme.github.io returned 404 Not Found",
        )
        graph.ingest_vulnerability(vuln)

        assert "cname:acme.github.io" in graph.nodes
        assert "provider:github_pages" in graph.nodes
        assert any(n["type"] == "VULNERABILITY" for n in graph.nodes.values())

        centrality = graph.calculate_centrality()
        assert len(centrality) > 0
        # Highest degree node should have degree >= 1
        assert centrality[0][1] >= 1

    def test_export_topology_and_save(self, tmp_path):
        graph = BountyAttackGraph(output_dir=tmp_path)
        graph.add_node("prog:test", "Test", "BOUNTY_PROGRAM")
        graph.add_node("domain:test.com", "test.com", "PERIMETER_DOMAIN")
        graph.add_edge("prog:test", "domain:test.com", "MONITORS_DOMAIN")

        dest = graph.save(tmp_path / "custom_attack_surface.json")
        assert dest.exists()

        data = json.loads(dest.read_text(encoding="utf-8"))
        assert data["stats"]["total_nodes"] == 2
        assert data["stats"]["total_edges"] == 1
        assert len(data["nodes"]) == 2


class TestGemmaTriageCopilot:
    """Tests for Phase C Milestone C.2 Gemma 4 AI Triage Co-Pilot."""

    def test_scope_detection(self):
        in_scope = ["*.shopify.com", "myshopify.com"]
        assert GemmaTriageCopilot.is_target_in_scope("admin.shopify.com", in_scope) is True
        assert GemmaTriageCopilot.is_target_in_scope("shopify.com", in_scope) is True
        assert GemmaTriageCopilot.is_target_in_scope("myshopify.com", in_scope) is True
        assert GemmaTriageCopilot.is_target_in_scope("other-shopify.com", in_scope) is False

    def test_out_of_scope_detection(self):
        out_of_scope = ["community.shopify.com", "*.internal.shopify.com"]
        assert GemmaTriageCopilot.is_target_out_of_scope("community.shopify.com", out_of_scope) is True
        assert GemmaTriageCopilot.is_target_out_of_scope("dev.internal.shopify.com", out_of_scope) is True
        assert GemmaTriageCopilot.is_target_out_of_scope("checkout.shopify.com", out_of_scope) is False

    def test_audit_rejected_out_of_scope(self):
        program = BountyProgram(
            program_id="shopify",
            name="Shopify",
            platform="hackerone",
            policy_url="https://hackerone.com/shopify",
            in_scope=["*.shopify.com"],
            out_of_scope=["community.shopify.com"],
            bounty_tier="cash",
        )
        vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="community.shopify.com",
            flaw_type="mail_spoofing",
            severity=Severity.HIGH,
            evidence="Valid SPF and DMARC missing",
        )
        decision = GemmaTriageCopilot.audit_finding(vuln, program)
        assert decision.verdict == "REJECTED_OUT_OF_SCOPE"
        assert decision.policy_compliance is False

    def test_audit_rejected_low_signal(self):
        program = BountyProgram(
            program_id="stripe",
            name="Stripe",
            platform="hackerone",
            policy_url="https://hackerone.com/stripe",
            in_scope=["*.stripe.com"],
            out_of_scope=[],
            bounty_tier="cash",
        )
        vuln = BountyVulnerability(
            program_id="stripe",
            program_name="Stripe",
            platform="hackerone",
            target_domain="docs.stripe.com",
            flaw_type="cors_wildcard_origin",
            severity=Severity.LOW,
            bounty_viability="INFORMATIONAL_LOW",
            evidence="Access-Control-Allow-Origin: * on static content",
        )
        decision = GemmaTriageCopilot.audit_finding(vuln, program)
        assert decision.verdict == "REJECTED_LOW_SIGNAL"

    def test_audit_needs_more_info_on_weak_evidence(self):
        program = BountyProgram(
            program_id="github",
            name="GitHub",
            platform="hackerone",
            policy_url="https://hackerone.com/github",
            in_scope=["*.github.com"],
            out_of_scope=[],
            bounty_tier="cash",
        )
        vuln = BountyVulnerability(
            program_id="github",
            program_name="GitHub",
            platform="hackerone",
            target_domain="api.github.com",
            flaw_type="subdomain_takeover",
            severity=Severity.HIGH,
            evidence="short",  # Less than 15 chars
        )
        decision = GemmaTriageCopilot.audit_finding(vuln, program)
        assert decision.verdict == "NEEDS_MORE_INFO"

    def test_audit_accepted_high_priority(self):
        program = BountyProgram(
            program_id="github",
            name="GitHub",
            platform="hackerone",
            policy_url="https://hackerone.com/github",
            in_scope=["*.github.com"],
            out_of_scope=[],
            bounty_tier="cash",
        )
        vuln = BountyVulnerability(
            program_id="github",
            program_name="GitHub",
            platform="hackerone",
            target_domain="legacy-docs.github.com",
            cname_target="github-docs.s3.amazonaws.com",
            flaw_type="cloud_storage_takeover",
            provider="AWS S3",
            severity=Severity.HIGH,
            bounty_viability="HIGH_CONFIDENCE",
            evidence="Dangling CNAME points to unallocated S3 bucket with NoSuchBucket error response.",
        )
        decision = GemmaTriageCopilot.audit_finding(vuln, program)
        assert decision.verdict == "ACCEPTED_HIGH_PRIORITY"
        assert decision.confidence_score >= 0.95
        assert decision.policy_compliance is True

    def test_audit_with_mock_ai_verdict(self):
        program = BountyProgram(
            program_id="uber",
            name="Uber",
            platform="hackerone",
            policy_url="https://hackerone.com/uber",
            in_scope=["*.uber.com"],
            out_of_scope=[],
            bounty_tier="cash",
        )
        vuln = BountyVulnerability(
            program_id="uber",
            program_name="Uber",
            platform="hackerone",
            target_domain="graphql.uber.com",
            flaw_type="graphql_introspection",
            severity=Severity.MEDIUM,
            bounty_viability="HIGH_CONFIDENCE",
            evidence="Exposed GraphQL schema introspection on /graphql endpoint.",
        )
        mock_ai = {
            "verdict": "ACCEPTED_STANDARD",
            "confidence": 0.92,
            "reasoning": "Gemma 4 Critic verified production introspection disclosure.",
            "action": "Queue for responsible disclosure export.",
        }
        decision = GemmaTriageCopilot.audit_finding(vuln, program, use_ai=True, mock_ai_verdict=mock_ai)
        assert decision.verdict == "ACCEPTED_STANDARD"
        assert decision.confidence_score == 0.92


class TestCryptographicDisclosureBundler:
    """Tests for Phase C Milestone C.3 Automated Coordinated Disclosure Bundler."""

    def test_export_cryptographic_bundle(self, tmp_path):
        vuln = BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="assets.shopify.com",
            cname_target="shopify-assets.s3.amazonaws.com",
            flaw_type="cloud_storage_takeover",
            provider="AWS S3",
            severity=Severity.HIGH,
            cvss_score=8.6,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N",
            evidence="Dangling CNAME points to unallocated S3 bucket with NoSuchBucket response.",
            remediation="Claim matching bucket name in AWS or remove CNAME record.",
            bounty_viability="HIGH_CONFIDENCE",
        )
        program = BountyProgram(
            program_id="shopify",
            name="Shopify",
            platform="hackerone",
            policy_url="https://hackerone.com/shopify",
            in_scope=["*.shopify.com"],
            out_of_scope=[],
            bounty_tier="cash",
            max_bounty=50000,
        )

        res = ResponsibleDisclosureDrafter.export_cryptographic_bundle(
            vuln=vuln,
            program=program,
            output_dir=tmp_path,
        )

        bundle_dir = res["bundle_dir"]
        zip_path = res["zip_path"]
        manifest = res["manifest"]

        assert bundle_dir.exists()
        assert zip_path.exists()
        assert res["total_files"] >= 6

        # Verify key files are present in the folder
        expected_files = [
            "hackerone_report.md",
            "bugcrowd_report.md",
            "security_txt_advisory.txt",
            "technical_evidence.txt",
            "metadata.json",
            "manifest_sha256.json",
        ]
        for ef in expected_files:
            assert (bundle_dir / ef).exists(), f"Missing expected file {ef}"

        # Verify SHA-256 integrity manifest matches actual files
        for fname, recorded_sha in manifest.items():
            actual_bytes = (bundle_dir / fname).read_bytes()
            computed_sha = hashlib.sha256(actual_bytes).hexdigest()
            assert recorded_sha == computed_sha, f"SHA-256 mismatch for {fname}"

        # Verify Zip file can be opened and contains all files
        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()
            for ef in expected_files:
                assert ef in namelist

        # Verify zip SHA-256 hash matches
        computed_zip_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        assert res["zip_sha256"] == computed_zip_sha
