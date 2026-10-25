#!/usr/bin/env python3
"""
test_client_portal.py: Unit & Integration Tests for Client Threat Portal Exporter
=================================================================================
Verifies:
1. ClientBriefingData data model contracts and serialization roundtrips.
2. AttackTree to Mermaid conversion from OSINT and perimetral findings.
3. DuckDB in-process OLAP analytics on findings and telemetry samples.
4. RFC 9116 PGP-signed responsible disclosure advisory generation.
5. HTML, Markdown, JSON, and PDF report export pipelines.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path("A:/") if Path("A:/").exists() else Path("C:/AgyHut")
ORBIT_SRC = WORKSPACE_ROOT / "projects" / "orbit-security" / "src"
if str(ORBIT_SRC) not in sys.path and ORBIT_SRC.exists():
    sys.path.insert(0, str(ORBIT_SRC))

from orbit_security.reporting.client_portal import (
    ClientThreatPortalExporter,
    ClientBriefingData,
    FindingItem,
    SeverityLevel,
)
from orbit_security.tools.duckdb_analytics import DuckDBEngine


@pytest.fixture
def sample_findings():
    return [
        {
            "title": "Dangling CNAME Takeover Detected",
            "category": "dns",
            "severity": "CRITICAL",
            "score": 9.5,
            "description": "Perimeter subdomain points to an abandoned storage endpoint.",
            "target": "assets.target.com",
            "evidence": "CNAME fastly.target.com -> NXDOMAIN",
            "remediation": "Delete DNS CNAME or claim the bucket immediately."
        },
        {
            "title": "Weak TLS Cipher Suite Supported",
            "category": "tls",
            "severity": "HIGH",
            "score": 7.0,
            "description": "Server negotiates TLS 1.0/1.1 with CBC ciphers.",
            "target": "api.target.com",
            "evidence": "TLSv1.0 ECDHE-RSA-AES128-SHA",
            "remediation": "Enforce TLS 1.3 and disable legacy ciphers."
        },
        {
            "title": "Missing Strict-Transport-Security (HSTS)",
            "category": "headers",
            "severity": "MEDIUM",
            "score": 5.0,
            "description": "HSTS header missing from root domain response.",
            "target": "target.com",
            "evidence": "Header omitted in 301 and 200 responses",
            "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."
        }
    ]


@pytest.fixture
def sample_telemetry():
    return [
        {"domain": "target.com", "response_time_ms": 22.5, "status": "NOERROR"},
        {"domain": "assets.target.com", "response_time_ms": 110.0, "status": "NXDOMAIN"},
        {"domain": "api.target.com", "response_time_ms": 45.0, "status": "NOERROR"},
    ]


class TestClientThreatPortalExporter:
    def test_client_briefing_data_roundtrip(self):
        data = ClientBriefingData(
            domain="example.com",
            client_name="Example Corp",
            score=82,
            grade="B+",
            findings=[{"title": "Test Finding", "severity": "LOW"}],
            mermaid_attack_tree="flowchart TD\nA-->B",
            executive_summary="Sample summary"
        )
        d = data.to_dict()
        assert d["domain"] == "example.com"
        assert d["score"] == 82
        assert d["grade"] == "B+"

        restored = ClientBriefingData.from_dict(d)
        assert restored.domain == "example.com"
        assert restored.score == 82
        assert restored.grade == "B+"

    def test_compile_from_audit_basic(self, sample_findings):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit(
            domain="target.com",
            findings=sample_findings,
            client_name="Target Agency",
            initial_score=68
        )
        assert briefing.domain == "target.com"
        assert briefing.client_name == "Target Agency"
        assert briefing.score == 68
        assert briefing.grade == "C"
        assert len(briefing.findings) == 3
        assert len(briefing.care_plan_tiers) == 3

    def test_mermaid_attack_tree_generation(self, sample_findings):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit("target.com", sample_findings)
        assert briefing.mermaid_attack_tree.startswith(("flowchart ", "graph "))
        assert "target.com" in briefing.mermaid_attack_tree
        assert "Dangling CNAME" in briefing.mermaid_attack_tree

    def test_duckdb_olap_metrics(self, sample_findings, sample_telemetry):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit(
            "target.com",
            sample_findings,
            telemetry_samples=sample_telemetry
        )
        metrics = briefing.duckdb_metrics
        assert metrics["total_findings"] == 3
        assert "severity_breakdown" in metrics
        assert metrics["severity_breakdown"].get("CRITICAL") == 1
        assert metrics["severity_breakdown"].get("HIGH") == 1
        assert metrics["severity_breakdown"].get("MEDIUM") == 1

        if metrics.get("engine") == "duckdb_native_olap":
            assert metrics["average_finding_score"] > 5.0
            assert "telemetry_stats" in metrics

    def test_pgp_advisory_synthesis(self, sample_findings):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit("target.com", sample_findings)
        advisory = briefing.pgp_advisory
        assert advisory["verified"] is True
        assert "target.com" in advisory["rfc9116_contact"]
        assert "-----BEGIN PGP SIGNED MESSAGE-----" in advisory["pgp_armored_block"]
        assert "-----BEGIN PGP SIGNATURE-----" in advisory["pgp_armored_block"]
        assert "-----END PGP SIGNATURE-----" in advisory["pgp_armored_block"]

    def test_export_html(self, sample_findings, tmp_path):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit("target.com", sample_findings)
        html_file = tmp_path / "report.html"
        html_content = exporter.export_html(briefing, output_path=html_file)

        assert html_file.exists()
        assert "<!DOCTYPE html>" in html_content
        assert "target.com" in html_content
        assert "mermaid" in html_content
        assert "Dangling CNAME" in html_content
        assert "Starter Care Plan" in html_content
        assert "-----BEGIN PGP SIGNED MESSAGE-----" in html_content

    def test_export_markdown(self, sample_findings, tmp_path):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit("target.com", sample_findings)
        md_file = tmp_path / "report.md"
        md_content = exporter.export_markdown(briefing, output_path=md_file)

        assert md_file.exists()
        assert "# 🛸 Project ORBIT Security Briefing" in md_content
        assert "```mermaid" in md_content
        assert "Dangling CNAME Takeover Detected" in md_content
        assert "| Severity | Finding Count |" in md_content

    def test_export_json(self, sample_findings, tmp_path):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit("target.com", sample_findings)
        json_file = tmp_path / "report.json"
        json_content = exporter.export_json(briefing, output_path=json_file)

        assert json_file.exists()
        parsed = json.loads(json_content)
        assert parsed["domain"] == "target.com"
        assert len(parsed["findings"]) == 3

    def test_export_pdf(self, sample_findings, tmp_path):
        exporter = ClientThreatPortalExporter()
        briefing = exporter.compile_from_audit("target.com", sample_findings)
        pdf_file = tmp_path / "report.pdf"
        ok = exporter.export_pdf(briefing, output_path=pdf_file)
        assert ok is True
        assert pdf_file.exists()
        assert pdf_file.stat().st_size > 500

    def test_export_html_xss_sanitization(self, tmp_path):
        exporter = ClientThreatPortalExporter()
        malicious_findings = [
            {
                "title": "<script>alert('xss_title')</script>",
                "category": "<img src=x onerror=alert(1)>",
                "severity": "HIGH",
                "score": 8.0,
                "description": "Exploit with <iframe src=evil.com>",
                "target": "target.com<script>",
                "evidence": "Payload: <script>document.cookie</script>",
                "remediation": "Escape <b>everything</b> & always"
            }
        ]
        briefing = exporter.compile_from_audit("target.com<script>", malicious_findings, client_name="Corp<script>")
        html_file = tmp_path / "xss_report.html"
        html_content = exporter.export_html(briefing, output_path=html_file)

        assert html_file.exists()
        assert "<script>alert('xss_title')</script>" not in html_content
        assert "&lt;script&gt;alert(&#x27;xss_title&#x27;)&lt;/script&gt;" in html_content or "&lt;script&gt;" in html_content
        assert "<img src=x onerror=alert(1)>" not in html_content
        assert "<iframe src=evil.com>" not in html_content

    def test_from_dict_extra_fields_resilience(self):
        data = {
            "domain": "safe.com",
            "client_name": "Safe Corp",
            "score": 90,
            "grade": "A",
            "unknown_extra_field_from_future_version": "should_not_crash"
        }
        briefing = ClientBriefingData.from_dict(data)
        assert briefing.domain == "safe.com"
        assert briefing.grade == "A"
