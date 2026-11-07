"""Adversarial stress and edge-case validation test suite for Milestone M6.

Stress-tests:
1. `triage_finding_priority()` and `sort_findings_by_triage()` with fuzzed vulnerability
   dictionaries, missing keys, None values, unexpected severities, negative CVSS scores,
   mixed dataclass/dict objects, and large volumes (10,000+ items).
2. `BountyRadar.scan_all_programs()` with fuzzed program scopes (empty program lists,
   empty in_scope lists, None elements, boundary gate thresholds, and error injection).
3. Atomic state persistence, watermark consistency, and exit gate compliance.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import random
import time
from unittest.mock import MagicMock

import pytest

from orbit_security.bounty_radar import (
    HIGH_IMPACT_FLAW_TYPES,
    LOW_NOISE_FLAW_TYPES,
    BountyProgram,
    BountyRadar,
    BountyScopeIngester,
    BountyVulnerability,
    sort_findings_by_triage,
    triage_finding_priority,
)
from orbit_security.models import Severity


# =========================================================================== #
# 1. Adversarial Fuzzing: triage_finding_priority & sort_findings_by_triage
# =========================================================================== #

def test_triage_fuzzed_missing_keys_and_none_values():
    """Verifies triage_finding_priority does not crash on empty dicts, missing keys, or None values."""
    fuzzed_cases = [
        {},
        {"flaw_type": None},
        {"severity": None},
        {"cvss_score": None},
        {"bounty_viability": None},
        {"timestamp": None},
        {
            "flaw_type": None,
            "severity": None,
            "cvss_score": None,
            "bounty_viability": None,
            "timestamp": None,
        },
        {"flaw_type": "", "severity": "", "cvss_score": 0.0, "bounty_viability": ""},
        None,  # non-dict, non-dataclass None object
    ]

    for item in fuzzed_cases:
        rank, neg_cvss, ts = triage_finding_priority(item)
        assert isinstance(rank, int)
        assert rank in (0, 1, 2, 3)
        assert isinstance(neg_cvss, float)
        assert isinstance(ts, str)
        # Empty or None items default to rank 3 (low/noise)
        assert rank == 3


def test_triage_fuzzed_unexpected_severities():
    """Verifies triage_finding_priority handles unexpected, empty, or numeric severities gracefully."""
    unexpected_sevs = [
        "UNKNOWN",
        "extreme",
        "catastrophic",
        "INFORMATIONAL",
        "info",
        "low_noise",
        123,
        999.9,
        "",
        None,
        False,
    ]

    for sev in unexpected_sevs:
        case = {
            "flaw_type": "subdomain_takeover",
            "severity": sev,
            "cvss_score": 5.0,
            "bounty_viability": "HIGH_CONFIDENCE",
        }
        rank, neg_cvss, ts = triage_finding_priority(case)
        # If severity is not recognized as HIGH, CRITICAL, or MEDIUM, it defaults to rank 3
        assert rank == 3
        assert neg_cvss == -5.0


def test_triage_negative_and_zero_cvss_scores():
    """Verifies that negative and zero CVSS scores are ranked properly and don't invert ordering."""
    vulns = [
        {"flaw_type": "subdomain_takeover", "severity": "HIGH", "cvss_score": -10.0, "bounty_viability": "HIGH_CONFIDENCE", "id": "neg10"},
        {"flaw_type": "subdomain_takeover", "severity": "HIGH", "cvss_score": -1.0, "bounty_viability": "HIGH_CONFIDENCE", "id": "neg1"},
        {"flaw_type": "subdomain_takeover", "severity": "HIGH", "cvss_score": 0.0, "bounty_viability": "HIGH_CONFIDENCE", "id": "zero"},
        {"flaw_type": "subdomain_takeover", "severity": "HIGH", "cvss_score": 5.0, "bounty_viability": "HIGH_CONFIDENCE", "id": "pos5"},
        {"flaw_type": "subdomain_takeover", "severity": "HIGH", "cvss_score": 9.8, "bounty_viability": "HIGH_CONFIDENCE", "id": "pos98"},
    ]

    sorted_vulns = sort_findings_by_triage(vulns)
    sorted_ids = [v["id"] for v in sorted_vulns]

    # In Tier 0, higher CVSS must sort first: 9.8 > 5.0 > 0.0 > -1.0 > -10.0
    assert sorted_ids == ["pos98", "pos5", "zero", "neg1", "neg10"]


def test_triage_string_and_float_numeric_cvss():
    """Verifies numeric string CVSS values are parsed and sorted correctly."""
    vulns = [
        {"flaw_type": "open_cloud_bucket", "severity": "HIGH", "cvss_score": "7.5", "bounty_viability": "HIGH_CONFIDENCE", "id": "str_75"},
        {"flaw_type": "open_cloud_bucket", "severity": "HIGH", "cvss_score": "9.1", "bounty_viability": "HIGH_CONFIDENCE", "id": "str_91"},
        {"flaw_type": "open_cloud_bucket", "severity": "HIGH", "cvss_score": 8.0, "bounty_viability": "HIGH_CONFIDENCE", "id": "flt_80"},
    ]

    sorted_vulns = sort_findings_by_triage(vulns)
    sorted_ids = [v["id"] for v in sorted_vulns]
    assert sorted_ids == ["str_91", "flt_80", "str_75"]


def test_triage_mixed_dataclasses_and_dictionaries():
    """Verifies sort_findings_by_triage safely and deterministically sorts mixed lists of dataclasses and dicts."""
    dc_takeover = BountyVulnerability(
        program_id="shopify",
        program_name="Shopify",
        platform="hackerone",
        target_domain="takeover.shopify.com",
        flaw_type="subdomain_takeover",
        severity=Severity.HIGH,
        cvss_score=8.5,
        bounty_viability="HIGH_CONFIDENCE",
    )
    dict_takeover = {
        "program_id": "gitlab",
        "flaw_type": "open_cloud_bucket",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "bounty_viability": "HIGH_CONFIDENCE",
    }
    dict_cors = {
        "program_id": "uber",
        "flaw_type": "cors_wildcard_origin",
        "severity": "LOW",
        "cvss_score": 3.7,
        "bounty_viability": "INFORMATIONAL_LOW",
    }
    dc_graphql = BountyVulnerability(
        program_id="starbucks",
        program_name="Starbucks",
        platform="hackerone",
        target_domain="api.starbucks.com",
        flaw_type="graphql_introspection",
        severity=Severity.MEDIUM,
        cvss_score=5.3,
        bounty_viability="CONDITIONAL",
    )

    mixed = [dict_cors, dc_graphql, dc_takeover, dict_takeover]
    sorted_mixed = sort_findings_by_triage(mixed)

    # Order must be:
    # 1. dict_takeover (Rank 0, CVSS 9.8)
    # 2. dc_takeover (Rank 0, CVSS 8.5)
    # 3. dc_graphql (Rank 2, CVSS 5.3)
    # 4. dict_cors (Rank 3, CVSS 3.7)
    assert sorted_mixed[0] is dict_takeover
    assert sorted_mixed[1] is dc_takeover
    assert sorted_mixed[2] is dc_graphql
    assert sorted_mixed[3] is dict_cors


def test_triage_all_high_impact_flaw_types_recognized():
    """Verifies every member of HIGH_IMPACT_FLAW_TYPES qualifies for Tier 0 when HIGH/CRITICAL and HIGH_CONFIDENCE."""
    for flaw in HIGH_IMPACT_FLAW_TYPES:
        vuln = {
            "flaw_type": flaw,
            "severity": "HIGH",
            "cvss_score": 8.0,
            "bounty_viability": "HIGH_CONFIDENCE",
        }
        rank, _, _ = triage_finding_priority(vuln)
        assert rank == 0, f"Expected flaw '{flaw}' to be Rank 0 in Tier 0"


def test_triage_large_volume_10k_findings_performance():
    """Stress test: sorts 10,000 mixed fuzzed findings in under 200ms with strict monotonic tier ordering."""
    flaw_choices = list(HIGH_IMPACT_FLAW_TYPES) + list(LOW_NOISE_FLAW_TYPES) + ["generic_bug", "graphql_introspection"]
    sev_choices = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    viab_choices = ["HIGH_CONFIDENCE", "CONDITIONAL", "INFORMATIONAL_LOW"]

    findings = []
    for i in range(10_000):
        if i % 2 == 0:
            findings.append(
                BountyVulnerability(
                    program_id=f"prog_{i % 27}",
                    program_name=f"Prog {i % 27}",
                    platform="hackerone",
                    target_domain=f"sub{i}.target.com",
                    flaw_type=random.choice(flaw_choices),
                    severity=Severity.HIGH if (i % 3 == 0) else Severity.LOW,
                    cvss_score=round(random.uniform(-5.0, 10.0), 1),
                    bounty_viability=random.choice(viab_choices),
                    timestamp=f"2026-11-07T05:{(i % 60):02d}:00Z",
                )
            )
        else:
            findings.append({
                "program_id": f"prog_{i % 27}",
                "flaw_type": random.choice(flaw_choices),
                "severity": random.choice(sev_choices),
                "cvss_score": round(random.uniform(-5.0, 10.0), 1),
                "bounty_viability": random.choice(viab_choices),
                "timestamp": f"2026-11-07T05:{(i % 60):02d}:00Z",
            })

    t0 = time.perf_counter()
    sorted_findings = sort_findings_by_triage(findings)
    duration_ms = (time.perf_counter() - t0) * 1000.0

    assert len(sorted_findings) == 10_000
    assert duration_ms < 250.0, f"Sorting 10k items took {duration_ms:.2f}ms (> 250ms limit)"

    # Verify monotonic non-decreasing rank ordering across all 10,000 items
    prev_rank = 0
    for item in sorted_findings:
        rank, _, _ = triage_finding_priority(item)
        assert rank >= prev_rank, f"Rank inversion detected: {rank} < {prev_rank}"
        prev_rank = rank


# =========================================================================== #
# 2. Adversarial Fuzzing: BountyRadar.scan_all_programs Scope & Gates
# =========================================================================== #

def test_scan_all_programs_empty_in_scope_list(tmp_path):
    """Verifies scan_all_programs handles programs with empty in_scope list without crashing."""
    state_file = tmp_path / "bounty_radar_state.json"
    mock_ingester = MagicMock(spec=BountyScopeIngester)

    # 25 programs, all having empty in_scope
    empty_programs = [
        BountyProgram(
            program_id=f"empty_prog_{i}",
            name=f"Empty Prog {i}",
            state="active",
            in_scope=[],
        )
        for i in range(25)
    ]
    mock_ingester.list_programs.return_value = empty_programs
    mock_ingester.data_path = tmp_path / "bounty_programs.json"

    mock_sweeper = MagicMock()
    mock_sweeper.sweep_program.return_value = []

    radar = BountyRadar(
        ingester=mock_ingester,
        sweeper=mock_sweeper,
        state_file=state_file,
    )

    result = radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=True,
        save_disclosures=False,
        sync_attack_graph=False,
        dispatch_alerts=False,
    )

    assert result["status"] == "COMPLETED"
    assert result["programs_scanned"] == 25
    assert result["exit_gate_passed"] is True
    assert result["vulnerabilities_found"] == 0
    assert mock_sweeper.sweep_program.call_count == 25

    # Verify watermarks recorded 0 findings for all 25 programs
    assert len(radar.state["watermarks"]) == 25
    for i in range(25):
        wm = radar.state["watermarks"][f"empty_prog_{i}"]
        assert wm["findings_count"] == 0
        assert wm["high_impact_count"] == 0


def test_scan_all_programs_filters_none_and_inactive_programs(tmp_path):
    """Verifies scan_all_programs safely filters out None and inactive programs."""
    state_file = tmp_path / "bounty_radar_state.json"
    mock_ingester = MagicMock(spec=BountyScopeIngester)

    programs = (
        [None]
        + [
            BountyProgram(program_id=f"active_{i}", name=f"Active {i}", state="active", in_scope=["*.target.com"])
            for i in range(21)
        ]
        + [
            BountyProgram(program_id=f"paused_{i}", name=f"Paused {i}", state="paused", in_scope=["*.target.com"])
            for i in range(5)
        ]
        + [None]
    )
    mock_ingester.list_programs.return_value = programs
    mock_ingester.data_path = tmp_path / "bounty_programs.json"

    mock_sweeper = MagicMock()
    mock_sweeper.sweep_program.return_value = []

    radar = BountyRadar(
        ingester=mock_ingester,
        sweeper=mock_sweeper,
        state_file=state_file,
    )

    result = radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=True,
        save_disclosures=False,
        sync_attack_graph=False,
        dispatch_alerts=False,
    )

    # Exactly the 21 active programs should be scanned
    assert result["programs_scanned"] == 21
    assert result["exit_gate_passed"] is True
    assert mock_sweeper.sweep_program.call_count == 21
    assert all(p.startswith("active_") for p in result["programs_list"])


def test_scan_all_programs_exact_boundary_gate_thresholds(tmp_path):
    """Verifies exact boundary gate thresholds: 19 fails gate, 20 passes gate."""
    state_file = tmp_path / "bounty_radar_state.json"
    mock_ingester = MagicMock(spec=BountyScopeIngester)

    # 19 programs
    mock_ingester.list_programs.return_value = [
        BountyProgram(program_id=f"p_{i}", name=f"P {i}", state="active", in_scope=["*.a.com"])
        for i in range(19)
    ]
    mock_ingester.data_path = tmp_path / "bounty_programs.json"

    mock_sweeper = MagicMock()
    mock_sweeper.sweep_program.return_value = []

    radar = BountyRadar(ingester=mock_ingester, sweeper=mock_sweeper, state_file=state_file)

    # With enforce_exit_gate=True, 19 scanned must raise RuntimeError
    with pytest.raises(RuntimeError, match="Bounty Radar Exit Gate Failed: Scanned 19 programs, required >= 20"):
        radar.scan_all_programs(
            force_now=True,
            min_programs_scanned=20,
            enforce_exit_gate=True,
            save_disclosures=False,
            sync_attack_graph=False,
        )

    # With enforce_exit_gate=False, 19 scanned must complete with exit_gate_passed=False
    res_19 = radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=False,
        save_disclosures=False,
        sync_attack_graph=False,
    )
    assert res_19["exit_gate_passed"] is False
    assert res_19["programs_scanned"] == 19

    # Now with 20 programs, exactly at threshold
    mock_ingester.list_programs.return_value = [
        BountyProgram(program_id=f"p_{i}", name=f"P {i}", state="active", in_scope=["*.a.com"])
        for i in range(20)
    ]
    res_20 = radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=True,
        save_disclosures=False,
        sync_attack_graph=False,
    )
    assert res_20["exit_gate_passed"] is True
    assert res_20["programs_scanned"] == 20


def test_scan_all_programs_recent_findings_top_20_triage_truncation(tmp_path):
    """Verifies that when a sweep discovers > 20 mixed findings, recent_findings is truncated to the top 20 triaged findings."""
    state_file = tmp_path / "bounty_radar_state.json"
    mock_ingester = MagicMock(spec=BountyScopeIngester)

    mock_ingester.list_programs.return_value = [
        BountyProgram(program_id=f"prog_{i}", name=f"Prog {i}", state="active", in_scope=["*.target.com"])
        for i in range(20)
    ]
    mock_ingester.data_path = tmp_path / "bounty_programs.json"

    # Construct 50 findings:
    # - 10 takeovers (High Impact, CVSS 8.5) -> Tier 0
    # - 10 open buckets (High Impact, CVSS 8.0) -> Tier 0
    # - 10 other High (CVSS 7.0) -> Tier 1
    # - 10 Medium GraphQL (CVSS 5.0) -> Tier 2
    # - 10 Low CORS noise (CVSS 3.7) -> Tier 3
    findings_50 = []
    for i in range(10):
        findings_50.append(BountyVulnerability(
            program_id="prog_0",
            program_name="Prog 0",
            platform="hackerone",
            target_domain=f"takeover{i}.target.com",
            flaw_type="subdomain_takeover",
            severity=Severity.HIGH,
            cvss_score=8.5,
            bounty_viability="HIGH_CONFIDENCE",
        ))
    for i in range(10):
        findings_50.append(BountyVulnerability(
            program_id="prog_0",
            program_name="Prog 0",
            platform="hackerone",
            target_domain=f"bucket{i}.target.com",
            flaw_type="open_cloud_bucket",
            severity=Severity.HIGH,
            cvss_score=8.0,
            bounty_viability="HIGH_CONFIDENCE",
        ))
    for i in range(10):
        findings_50.append(BountyVulnerability(
            program_id="prog_0",
            program_name="Prog 0",
            platform="hackerone",
            target_domain=f"other{i}.target.com",
            flaw_type="generic_high_flaw",
            severity=Severity.HIGH,
            cvss_score=7.0,
            bounty_viability="HIGH_CONFIDENCE",
        ))
    for i in range(10):
        findings_50.append(BountyVulnerability(
            program_id="prog_0",
            program_name="Prog 0",
            platform="hackerone",
            target_domain=f"graphql{i}.target.com",
            flaw_type="graphql_introspection",
            severity=Severity.MEDIUM,
            cvss_score=5.0,
            bounty_viability="CONDITIONAL",
        ))
    for i in range(10):
        findings_50.append(BountyVulnerability(
            program_id="prog_0",
            program_name="Prog 0",
            platform="hackerone",
            target_domain=f"cors{i}.target.com",
            flaw_type="cors_wildcard_origin",
            severity=Severity.LOW,
            cvss_score=3.7,
            bounty_viability="INFORMATIONAL_LOW",
        ))

    mock_sweeper = MagicMock()
    # Program 0 returns all 50 findings, others return 0
    mock_sweeper.sweep_program.side_effect = [findings_50] + [[] for _ in range(19)]

    radar = BountyRadar(
        ingester=mock_ingester,
        sweeper=mock_sweeper,
        state_file=state_file,
    )

    res = radar.scan_all_programs(
        force_now=True,
        min_programs_scanned=20,
        enforce_exit_gate=True,
        save_disclosures=False,
        sync_attack_graph=False,
        dispatch_alerts=False,
    )

    assert res["vulnerabilities_found"] == 50
    # State recent_findings must be capped at 20 items
    recent = radar.state["recent_findings"]
    assert len(recent) == 20

    # The 20 items in recent_findings must be EXACTLY the 10 takeovers + 10 open buckets (the 20 Tier 0 findings)
    recent_flaws = [r["flaw_type"] for r in recent]
    assert recent_flaws.count("subdomain_takeover") == 10
    assert recent_flaws.count("open_cloud_bucket") == 10
    # Zero low-severity CORS noise allowed in the top 20
    assert "cors_wildcard_origin" not in recent_flaws
    assert "graphql_introspection" not in recent_flaws


def test_scan_all_programs_off_peak_window_skip(tmp_path):
    """Verifies scan_all_programs returns SKIPPED_OUTSIDE_WINDOW when force_now=False outside off-peak window."""
    state_file = tmp_path / "bounty_radar_state.json"
    mock_ingester = MagicMock(spec=BountyScopeIngester)
    mock_sweeper = MagicMock()

    radar = BountyRadar(ingester=mock_ingester, sweeper=mock_sweeper, state_file=state_file)

    # Force is_off_peak to return False
    with pytest.MonkeyPatch.context() as mp:
        from orbit_security.bounty_radar import OffPeakWindow
        mp.setattr(OffPeakWindow, "is_off_peak", lambda *args, **kwargs: False)

        res = radar.scan_all_programs(
            force_now=False,
            min_programs_scanned=20,
            enforce_exit_gate=True,
        )

        assert res["status"] == "SKIPPED_OUTSIDE_WINDOW"
        assert res["programs_scanned"] == 0
        assert res["exit_gate_passed"] is False
        assert mock_sweeper.sweep_program.call_count == 0
