"""
test_bounty_active_prober.py: Unit & Integration Test Suite for Active Bounty Probing
====================================================================================
Tests active TLS/CORS probing, Mermaid Attack Tree compilation, Sandbox verification gate,
Dual Packaging (HackerOne Markdown + RFC 9116 PGP advisory), and Rolling Worker cycles.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
import pytest

from orbit_security.bounty_active_prober import (
    BountyActiveProber,
    BountyRollingWorker,
    ActiveProbeFinding,
)
from orbit_security.bounty_rolling_daemon import BountyRollingDaemon
from orbit_security.bounty_radar import BountyProgram
from orbit_security.exploit_sandbox import OperatorExploitSandbox
from orbit_security.tools.xh_probe import ProbeResult, SecurityHeaderAudit, CertificateInfo


@pytest.fixture
def temp_disclosures_and_state():
    tmp = Path(tempfile.mkdtemp())
    state_f = tmp / "radar_state.json"
    yield tmp, state_f
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_program():
    return BountyProgram(
        program_id="test_program",
        name="Test Program Inc",
        platform="hackerone",
        in_scope=["*.testprogram.com", "testprogram.com"],
        max_bounty=15000,
        excluded_vulnerabilities=[]
    )


class TestBountyActiveProber:
    """Tests the BountyActiveProber inspection and packaging logic."""

    def test_finding_dataclass_serialization(self):
        finding = ActiveProbeFinding(
            program_id="test_prog",
            target_domain="api.testprogram.com",
            flaw_type="missing_hsts",
            severity="MEDIUM",
            score=5.0,
            evidence="Strict-Transport-Security header omitted",
            remediation="Add Strict-Transport-Security header"
        )
        d = finding.to_dict()
        assert d["target_domain"] == "api.testprogram.com"
        assert d["flaw_type"] == "missing_hsts"
        assert d["score"] == 5.0

    def test_probe_host_active_offline_mode(self):
        prober = BountyActiveProber()
        # In offline mode without mock, xh probe returns mock result or handles gracefully
        findings = prober.probe_host_active("example.com", offline=True)
        assert isinstance(findings, list)

    def test_probe_program_scope_filtering(self, sample_program):
        prober = BountyActiveProber()
        # Mock probe_host_active to return one in-scope flaw and one out-of-scope flaw
        sample_program.excluded_vulnerabilities = ["out_of_scope_flaw"]

        def mock_probe_host(host, offline=False):
            return [
                ActiveProbeFinding(
                    program_id="generic",
                    target_domain=host,
                    flaw_type="cors_wildcard",
                    severity="HIGH",
                    score=7.5
                ),
                ActiveProbeFinding(
                    program_id="generic",
                    target_domain=host,
                    flaw_type="out_of_scope_flaw",
                    severity="LOW",
                    score=2.0
                )
            ]

        prober.probe_host_active = mock_probe_host
        anomalies = prober.probe_program(sample_program, max_subdomains=2)
        assert len(anomalies) > 0
        for anom in anomalies:
            assert anom.flaw_type == "cors_wildcard"

    def test_verify_and_package_finding_confirmed(self, temp_disclosures_and_state, sample_program):
        tmp_dir, state_file = temp_disclosures_and_state
        prober = BountyActiveProber(disclosures_dir=tmp_dir, state_file=state_file)

        finding = ActiveProbeFinding(
            program_id=sample_program.program_id,
            target_domain="blog.testprogram.com",
            flaw_type="subdomain_takeover",
            severity="CRITICAL",
            score=9.0,
            cname_target="testprogram.github.io",
            provider="github",
            evidence="There is no GitHub Pages site here",
            remediation="Remove dangling CNAME or configure GitHub Pages"
        )

        # Mock sandbox to confirm exploitability with confidence 0.95
        mock_res = {
            "exit_code": 0,
            "stdout": "STATUS: 404\nThere is no GitHub Pages site here.\n",
            "stderr": "",
            "duration_ms": 32.5,
            "status_code": 404,
            "response_headers": {"Server": "GitHub.com"},
            "response_body_preview": "There is no GitHub Pages site here."
        }

        orig_verify = OperatorExploitSandbox.verify_vulnerability
        prober.sandbox.verify_vulnerability = lambda f, **kw: orig_verify(f, mock_execution=mock_res)

        try:
            pkg = prober.verify_and_package_finding(finding, sample_program, min_confidence=0.85)
            assert pkg is not None
            assert pkg["program_id"] == "test_program"
            assert "mermaid_attack_tree" in pkg
            assert "flowchart" in pkg["mermaid_attack_tree"] or "graph" in pkg["mermaid_attack_tree"]
            assert pkg["pgp_advisory"]["verified"] is True
            assert "BEGIN PGP SIGNED MESSAGE" in pkg["pgp_advisory"]["pgp_armored_block"]

            # Verify files written to disk
            md_path = Path(pkg["markdown_report_path"])
            assert md_path.exists()
            content = md_path.read_text(encoding="utf-8")
            assert "HackerOne" in content or "Vulnerability Report" in content
            assert "blog.testprogram.com" in content

            # Verify state was updated
            assert state_file.exists()
            with open(state_file, "r", encoding="utf-8") as sf:
                state = json.load(sf)
                assert state.get("total_vulnerabilities_found", 0) >= 1
        finally:
            prober.sandbox.verify_vulnerability = orig_verify

    def test_verify_and_package_finding_rejected_by_confidence_gate(self, temp_disclosures_and_state, sample_program):
        tmp_dir, state_file = temp_disclosures_and_state
        prober = BountyActiveProber(disclosures_dir=tmp_dir, state_file=state_file)

        finding = ActiveProbeFinding(
            program_id=sample_program.program_id,
            target_domain="dev.testprogram.com",
            flaw_type="missing_hsts",
            severity="LOW",
            score=3.0,
            evidence="Inconclusive header test"
        )

        # Mock sandbox to return low confidence (0.50)
        from orbit_security.exploit_sandbox import SandboxVerificationReport, EvidenceDiffResult
        prober.sandbox.verify_vulnerability = lambda f, **kw: SandboxVerificationReport(
            target_domain=f.target_domain,
            flaw_type=f.flaw_type,
            curl_script="curl https://dev.testprogram.com",
            python_script="pass",
            execution=None, # type: ignore
            diff=EvidenceDiffResult(
                is_confirmed=False,
                remediation_detected=False,
                confidence_score=0.40,
                status_match=False,
                signature_matches=[],
                missing_signatures=["Strict-Transport-Security"],
                ascii_diff_table="",
                summary="Unconfirmed"
            ),
            timestamp_utc="2026-10-24T00:00:00Z"
        )

        pkg = prober.verify_and_package_finding(finding, sample_program, min_confidence=0.85)
        assert pkg is None


class TestBountyRollingWorker:
    """Tests continuous round-robin scheduling and execution cycles."""

    def test_worker_load_active_programs(self):
        worker = BountyRollingWorker()
        programs = worker.load_programs()
        assert len(programs) >= 20
        assert any(p.program_id == "shopify" for p in programs)

    def test_worker_run_one_cycle_offline(self):
        worker = BountyRollingWorker()
        cycle_result = worker.run_one_cycle(offline=True)
        assert cycle_result is not None
        assert "program_id" in cycle_result
        assert "program_name" in cycle_result
        assert "confirmed_count" in cycle_result
        assert isinstance(cycle_result["findings"], list)

    def test_rolling_pointer_advances_round_robin(self):
        worker = BountyRollingWorker()
        p1 = worker.run_one_cycle(offline=True)
        p2 = worker.run_one_cycle(offline=True)
        assert p1["program_id"] != p2["program_id"]


class TestBountyRollingDaemon:
    """Tests the daemon wrapper and CLI execution pathways."""

    def test_daemon_sweep_specific_program(self):
        daemon = BountyRollingDaemon(offline=True)
        res = daemon.sweep_program("shopify")
        assert res is not None
        assert res["program_id"] == "shopify"
        assert res["program_name"] == "Shopify"

    def test_daemon_sweep_nonexistent_program(self):
        daemon = BountyRollingDaemon(offline=True)
        res = daemon.sweep_program("non_existent_program_xyz_123")
        assert res is None

    def test_daemon_sweep_one_cycle(self):
        daemon = BountyRollingDaemon(offline=True)
        res = daemon.sweep_one_cycle()
        assert res is not None
        assert "program_id" in res
