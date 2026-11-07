"""Unit tests for Full-Scope 27-Program Bounty Radar & Severity Triage (Roadmap W4.2).

Verifies:
1. 27 registered programs inventory in data/bounty_programs.json.
2. Full scope iteration across programs in BountyRadar.scan_all_programs().
3. Operational exit gate enforcement (programs_scanned >= 20).
4. Severity triage prioritizing takeover/RCE classes over low-severity CORS noise.
5. Atomic state persistence and per-program watermark tracking.
6. CLI exit gate validation in scripts/run_bounty_radar.py.
7. Gitignore state isolation for data/bounty_radar_state.json.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest

from orbit_security.models import Severity


def test_27_registered_programs_present():
    """Verifies that all 27 canonical registered programs are present and active."""
    from orbit_security.bounty_radar import BountyScopeIngester

    ingester = BountyScopeIngester()
    programs = ingester.list_programs()
    assert len(programs) >= 27

    canonical_27 = [
        "shopify",
        "gitlab",
        "starbucks",
        "yahoo",
        "paypal",
        "uber",
        "github",
        "epicgames",
        "coinbase",
        "valve",
        "hyatt",
        "deptofdefense",
        "automattic",
        "rockstargames",
        "slack",
        "xiaomi",
        "flutteruki",
        "elastic",
        "expediagroup_bbp",
        "amazonvrp",
        "mercadolibre",
        "superbet",
        "playtika",
        "eternal",
        "trip_com",
        "khealth",
        "spotify",
    ]
    registered_ids = {p.program_id for p in programs}
    for cid in canonical_27:
        assert cid in registered_ids, f"Canonical program {cid} missing from registry"
        prog = ingester.get_program(cid)
        assert prog is not None
        assert prog.state == "active"
        assert len(prog.in_scope) > 0
        assert any("*" in scope for scope in prog.in_scope)


def test_bounty_radar_scan_all_programs_iterates_full_scope(tmp_path):
    """Verifies scan_all_programs() iterates all programs and returns programs_scanned >= 27."""
    from orbit_security.bounty_radar import BountyRadar, BountyScopeIngester

    state_file = tmp_path / "bounty_radar_state.json"
    ingester = BountyScopeIngester()

    mock_sweeper = MagicMock()
    mock_sweeper.sweep_program.return_value = []

    radar = BountyRadar(
        ingester=ingester,
        sweeper=mock_sweeper,
        state_file=state_file,
    )

    result = radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=True,
        save_disclosures=False,
        sync_attack_graph=False,
    )

    assert result["status"] == "COMPLETED"
    assert result["programs_scanned"] >= 27
    assert result["exit_gate_passed"] is True
    assert len(result["programs_list"]) >= 27
    assert mock_sweeper.sweep_program.call_count >= 27


def test_bounty_radar_exit_gate_enforcement(tmp_path):
    """Asserts RuntimeError on insufficient programs scanned when enforce_exit_gate=True."""
    from orbit_security.bounty_radar import BountyProgram, BountyRadar, BountyScopeIngester

    state_file = tmp_path / "bounty_radar_state.json"

    mock_ingester = MagicMock(spec=BountyScopeIngester)
    mock_programs = [
        BountyProgram(
            program_id=f"prog_{i}",
            name=f"Prog {i}",
            state="active",
            in_scope=["*.example.com"],
        )
        for i in range(5)
    ]
    mock_ingester.list_programs.return_value = mock_programs
    mock_ingester.data_path = tmp_path / "bounty_programs.json"

    mock_sweeper = MagicMock()
    mock_sweeper.sweep_program.return_value = []

    radar = BountyRadar(
        ingester=mock_ingester,
        sweeper=mock_sweeper,
        state_file=state_file,
    )

    with pytest.raises(RuntimeError, match="Bounty Radar Exit Gate Failed"):
        radar.scan_all_programs(
            force_now=True,
            min_programs_scanned=20,
            enforce_exit_gate=True,
            save_disclosures=False,
            sync_attack_graph=False,
        )

    res = radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=False,
        save_disclosures=False,
        sync_attack_graph=False,
    )
    assert res["status"] == "COMPLETED"
    assert res["exit_gate_passed"] is False
    assert res["programs_scanned"] == 5


def test_severity_triage_prioritizes_takeover_over_cors(tmp_path):
    """Verifies actionable takeovers, open cloud buckets, and OAuth redirect hijacks sort above low-severity CORS noise."""
    from orbit_security.bounty_radar import (
        HIGH_IMPACT_FLAW_TYPES,
        BountyProgram,
        BountyRadar,
        BountyScopeIngester,
        BountyVulnerability,
        sort_findings_by_triage,
    )

    findings = [
        BountyVulnerability(
            program_id="shopify",
            program_name="Shopify",
            platform="hackerone",
            target_domain="cdn.shopify.com",
            flaw_type="cors_wildcard_origin",
            provider="API Gateway CORS",
            severity=Severity.LOW,
            cvss_score=3.7,
            bounty_viability="INFORMATIONAL_LOW",
        ),
        BountyVulnerability(
            program_id="gitlab",
            program_name="GitLab",
            platform="hackerone",
            target_domain="assets.gitlab.com",
            flaw_type="subdomain_takeover",
            provider="AWS S3",
            severity=Severity.HIGH,
            cvss_score=8.6,
            bounty_viability="HIGH_CONFIDENCE",
        ),
        BountyVulnerability(
            program_id="uber",
            program_name="Uber",
            platform="hackerone",
            target_domain="storage.uber.com",
            flaw_type="open_cloud_bucket",
            provider="Google Cloud Storage",
            severity=Severity.HIGH,
            cvss_score=8.6,
            bounty_viability="HIGH_CONFIDENCE",
        ),
        BountyVulnerability(
            program_id="coinbase",
            program_name="Coinbase",
            platform="hackerone",
            target_domain="auth.coinbase.com",
            flaw_type="oauth_redirect_uri_hijack",
            provider="OAuth IdP",
            severity=Severity.HIGH,
            cvss_score=8.1,
            bounty_viability="HIGH_CONFIDENCE",
        ),
        BountyVulnerability(
            program_id="starbucks",
            program_name="Starbucks",
            platform="hackerone",
            target_domain="api.starbucks.com",
            flaw_type="graphql_introspection",
            provider="GraphQL",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            bounty_viability="CONDITIONAL",
        ),
    ]

    triaged = sort_findings_by_triage(findings)
    triaged_flaws = [f.flaw_type for f in triaged]

    top_3_flaws = set(triaged_flaws[:3])
    assert top_3_flaws == {"subdomain_takeover", "open_cloud_bucket", "oauth_redirect_uri_hijack"}

    assert triaged_flaws.index("graphql_introspection") < triaged_flaws.index("cors_wildcard_origin")
    assert triaged_flaws[-1] == "cors_wildcard_origin"

    state_file = tmp_path / "bounty_radar_state.json"
    mock_ingester = MagicMock(spec=BountyScopeIngester)
    mock_prog = BountyProgram(
        program_id="prog_all",
        name="Prog All",
        state="active",
        in_scope=["*.example.com"],
    )
    mock_ingester.list_programs.return_value = [mock_prog] * 20
    mock_ingester.data_path = tmp_path / "bounty_programs.json"

    mock_sweeper = MagicMock()
    mock_sweeper.sweep_program.side_effect = [findings] + [[] for _ in range(19)]

    radar = BountyRadar(
        ingester=mock_ingester,
        sweeper=mock_sweeper,
        state_file=state_file,
    )
    radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=True,
        save_disclosures=False,
        sync_attack_graph=False,
        dispatch_alerts=False,
    )

    recent_flaws = [r["flaw_type"] for r in radar.state["recent_findings"]]
    assert set(recent_flaws[:3]) == {"subdomain_takeover", "open_cloud_bucket", "oauth_redirect_uri_hijack"}
    assert recent_flaws.index("graphql_introspection") < recent_flaws.index("cors_wildcard_origin")
    assert recent_flaws[-1] == "cors_wildcard_origin"


def test_atomic_state_persistence_and_watermarks(tmp_path):
    """Verifies _save_state() uses atomic rename, recording watermarks, sweep_window_utc, and programs_scanned_count."""
    from orbit_security.bounty_radar import (
        BountyProgram,
        BountyRadar,
        BountyScopeIngester,
        BountyVulnerability,
    )

    state_file = tmp_path / "bounty_radar_state.json"
    mock_ingester = MagicMock(spec=BountyScopeIngester)
    programs = [
        BountyProgram(
            program_id=f"prog_{i}",
            name=f"Program {i}",
            state="active",
            in_scope=["*.test.com"],
        )
        for i in range(21)
    ]
    mock_ingester.list_programs.return_value = programs
    mock_ingester.data_path = tmp_path / "bounty_programs.json"

    mock_vuln = BountyVulnerability(
        program_id="prog_0",
        program_name="Program 0",
        platform="hackerone",
        target_domain="sub.test.com",
        flaw_type="subdomain_takeover",
        severity=Severity.HIGH,
        cvss_score=8.6,
        bounty_viability="HIGH_CONFIDENCE",
    )

    mock_sweeper = MagicMock()
    mock_sweeper.sweep_program.side_effect = [[mock_vuln]] + [[] for _ in range(20)]

    radar = BountyRadar(
        ingester=mock_ingester,
        sweeper=mock_sweeper,
        state_file=state_file,
    )

    radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=True,
        save_disclosures=False,
        sync_attack_graph=False,
        dispatch_alerts=False,
    )

    assert state_file.exists()
    assert not (tmp_path / "bounty_radar_state.tmp").exists()

    with open(state_file, "r", encoding="utf-8") as f:
        saved_state = json.load(f)

    assert "last_sweep_utc" in saved_state
    assert saved_state["last_sweep_utc"] is not None
    assert "sweep_window_utc" in saved_state
    assert "start" in saved_state["sweep_window_utc"]
    assert "end" in saved_state["sweep_window_utc"]
    assert "duration_seconds" in saved_state["sweep_window_utc"]
    assert saved_state["programs_scanned_count"] >= 20
    assert "watermarks" in saved_state
    assert len(saved_state["watermarks"]) >= 21
    assert "prog_0" in saved_state["watermarks"]
    assert saved_state["watermarks"]["prog_0"]["findings_count"] == 1
    assert saved_state["watermarks"]["prog_0"]["high_impact_count"] == 1
    assert "last_scanned_utc" in saved_state["watermarks"]["prog_0"]
    assert isinstance(saved_state["recent_findings"], list)
    assert len(saved_state["recent_findings"]) == 1


def test_cli_exit_gate_validation(monkeypatch, tmp_path):
    """Verifies CLI scripts/run_bounty_radar.py calls scan_all_programs() and enforces exit code 1 if < 20 programs scanned."""
    import scripts.run_bounty_radar as run_bounty_radar

    # Case A: >= 20 programs scanned -> completes cleanly without error exit
    mock_res_success = {
        "status": "COMPLETED",
        "programs_scanned": 27,
        "vulnerabilities_found": 0,
        "disclosed_files": [],
        "crypto_bundles": [],
    }
    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.scan_all_programs.return_value = mock_res_success

        monkeypatch.setattr(sys, "argv", ["run_bounty_radar.py", "--now"])
        run_bounty_radar.main()
        instance.scan_all_programs.assert_called_once()

    # Case B: Exit gate failure (< 20 programs scanned) -> sys.exit(1)
    mock_res_failure = {
        "status": "COMPLETED",
        "programs_scanned": 15,
        "vulnerabilities_found": 0,
        "disclosed_files": [],
        "crypto_bundles": [],
    }
    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.scan_all_programs.return_value = mock_res_failure

        monkeypatch.setattr(sys, "argv", ["run_bounty_radar.py", "--now"])
        with pytest.raises(SystemExit) as exc_info:
            run_bounty_radar.main()
        assert exc_info.value.code == 1

    # Case C: RuntimeError raised from gate enforcement -> sys.exit(1)
    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.scan_all_programs.side_effect = RuntimeError("Bounty Radar Exit Gate Failed")

        monkeypatch.setattr(sys, "argv", ["run_bounty_radar.py", "--now"])
        with pytest.raises(SystemExit) as exc_info:
            run_bounty_radar.main()
        assert exc_info.value.code == 1


def test_gitignore_enforces_radar_state_isolation():
    """Verifies data/bounty_radar_state.json is listed in .gitignore."""
    gitignore_path = Path(__file__).resolve().parent.parent / ".gitignore"
    assert gitignore_path.exists(), ".gitignore does not exist"
    content = gitignore_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines()]
    assert any("data/bounty_radar_state.json" in line for line in lines), (
        "data/bounty_radar_state.json must be listed in .gitignore"
    )
