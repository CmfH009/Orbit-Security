#!/usr/bin/env python3
"""
Unit and integration tests for Milestone M7:
Cohort 7–11 Outreach Disposition Reconciler & Social Governor Ledger Unification.

Verifies:
1. test_reconcile_dispositions_zero_undispositioned:
   Reconciles 50 total agencies across Cohorts 7–11 with exactly 0 un-dispositioned records.
2. test_quarantine_hard_blocks_all_46_bounced_addresses:
   Verifies all 46 bounced/suppressed addresses from data/bounced_agencies.json are
   recorded in data/quarantined_addresses.json and hard-blocked from follow-up sequences.
3. test_reconcile_cli_exit_code_zero:
   Verifies scripts/reconcile_outreach_dispositions.py --check and --audit exit 0.
4. test_social_governor_spacing_ledger_detection:
   Verifies check_social_spacing_governor() detects operator manual posts and enforces
   the 8.0h spacing cooldown ledger.
5. test_social_swarm_idles_cleanly_without_refusal_exception:
   Verifies SocialEngagementSwarm enters PACED_IDLE without raising refusal exceptions
   or entering refusal loops when spacing is active.
6. test_social_swarm_permits_post_after_spacing_cooldown:
   Verifies posting permission is restored once the 8.0h spacing interval elapses.
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module", autouse=True)
def _ensure_baseline_outreach_state_seeded():
    from scripts.reconcile_outreach_dispositions import ensure_baseline_outreach_state

    ensure_baseline_outreach_state(REPO_ROOT, create_quarantine_if_missing=True)


def test_reconcile_dispositions_zero_undispositioned():
    """Verifies that all 50 agencies across Cohorts 7–11 have 0 un-dispositioned records."""
    from scripts.reconcile_outreach_dispositions import (
        reconcile_dispositions,
        audit_cohort_dispositions,
        CANONICAL_DISPOSITIONS,
    )

    result = audit_cohort_dispositions(repo_root=REPO_ROOT)
    assert result["total_targets"] == 50, f"Expected 50 total targets, got {result['total_targets']}"
    assert result["undispositioned_count"] == 0, (
        f"Found {result['undispositioned_count']} un-dispositioned targets: {result.get('undispositioned_items')}"
    )

    # Detailed breakdown per cohort
    cohort_breakdown = result.get("cohorts", {})
    for c_id in (7, 8, 9, 10, 11):
        c_key = f"cohort_{c_id}"
        assert c_key in cohort_breakdown, f"Missing {c_key} in breakdown"
        c_data = cohort_breakdown[c_key]
        assert c_data["count"] == 10, f"Expected 10 agencies in {c_key}, found {c_data['count']}"
        assert c_data["undispositioned_count"] == 0, (
            f"Expected 0 un-dispositioned in {c_key}, found {c_data['undispositioned_count']}"
        )

    # Verify every target has an accepted canonical disposition
    for target in result["targets"]:
        disp = target.get("disposition")
        assert disp in CANONICAL_DISPOSITIONS, (
            f"Target {target.get('domain')} has non-canonical disposition: '{disp}'"
        )


def test_quarantine_hard_blocks_all_46_bounced_addresses():
    """Verifies that all 46 entries in bounced_agencies.json are quarantined and blocked."""
    from scripts.reconcile_outreach_dispositions import (
        is_quarantined,
        load_quarantined_addresses,
        filter_quarantined_targets,
    )

    bounced_file = REPO_ROOT / "data" / "bounced_agencies.json"
    assert bounced_file.exists(), f"bounced_agencies.json missing at {bounced_file}"
    with open(bounced_file, "r", encoding="utf-8") as f:
        bounced_data: Dict[str, Any] = json.load(f)

    assert len(bounced_data) == 46, f"Expected exactly 46 bounced entries, found {len(bounced_data)}"

    quarantine_file = REPO_ROOT / "data" / "quarantined_addresses.json"
    assert quarantine_file.exists(), f"quarantined_addresses.json missing at {quarantine_file}"
    quarantine = load_quarantined_addresses(quarantine_file=quarantine_file)
    assert quarantine["total_quarantined"] >= 46

    # Verify all 46 bounced_email addresses are hard-blocked
    for domain, info in bounced_data.items():
        bounced_email = info.get("bounced_email", "").strip()
        assert bounced_email, f"Entry {domain} missing bounced_email"
        assert is_quarantined(bounced_email, quarantine_data=quarantine) is True, (
            f"Expected {bounced_email} to be quarantined"
        )
        # Test case-insensitivity
        assert is_quarantined(bounced_email.upper(), quarantine_data=quarantine) is True

    # Test sequence filtering on a mixed list
    sample_targets = [
        {"agency_domain": "clean-example.com", "contact_email": "hello@clean-example.com"},
        {"agency_domain": "swankyagency.com", "contact_email": "hello@swankyagency.com"},
        {"agency_domain": "another-clean.com", "contact_email": "contact@another-clean.com"},
        {"agency_domain": "anatta.io", "contact_email": "hello@anatta.io"},
    ]
    filtered = filter_quarantined_targets(sample_targets, quarantine_data=quarantine)
    filtered_emails = [t["contact_email"] for t in filtered]
    assert "hello@swankyagency.com" not in filtered_emails
    assert "hello@anatta.io" not in filtered_emails
    assert "hello@clean-example.com" in filtered_emails
    assert "contact@another-clean.com" in filtered_emails


def test_reconcile_cli_exit_code_zero():
    """Verifies that reconcile_outreach_dispositions.py --check and --audit run cleanly and exit 0."""
    script_path = REPO_ROOT / "scripts" / "reconcile_outreach_dispositions.py"
    assert script_path.exists(), f"Script missing: {script_path}"

    # 1. Run with --check
    check_cmd = [sys.executable, str(script_path), "--check"]
    proc_check = subprocess.run(
        check_cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc_check.returncode == 0, (
        f"--check failed with exit code {proc_check.returncode}\nSTDOUT:\n{proc_check.stdout}\nSTDERR:\n{proc_check.stderr}"
    )
    assert "0 undispositioned" in proc_check.stdout.lower() or "check passed" in proc_check.stdout.lower()

    # 2. Run with --audit
    audit_cmd = [sys.executable, str(script_path), "--audit"]
    proc_audit = subprocess.run(
        audit_cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc_audit.returncode == 0, (
        f"--audit failed with exit code {proc_audit.returncode}\nSTDOUT:\n{proc_audit.stdout}\nSTDERR:\n{proc_audit.stderr}"
    )
    assert "cohort_7" in proc_audit.stdout or "Cohort 7" in proc_audit.stdout
    assert "cohort_11" in proc_audit.stdout or "Cohort 11" in proc_audit.stdout


def test_social_governor_spacing_ledger_detection():
    """Verifies check_social_spacing_governor() detects operator manual posts and active cooldown."""
    from orbit_security.social_swarm import (
        check_social_spacing_governor,
        ingest_manual_operator_post,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        state_file = tmp_path / "social_daemon_state.json"

        # Case 1: Post executed 1.5 hours ago (spacing = 8.0h)
        recent_time = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1.5)
        ).isoformat()
        initial_state = {
            "pid": 1234,
            "status": "ACTIVE",
            "timestamp": recent_time,
            "last_post_timestamp": recent_time,
            "circuit_state": "CLOSED",
            "quotas": {
                "min_post_spacing_hours": 8.0,
                "hourly_executed": {"POST": 1},
                "hourly_limits": {"posts": 1},
                "daily_executed": {"posts_count": 1},
                "daily_caps": {"posts": 2},
            },
        }
        state_file.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")

        status = check_social_spacing_governor(state_file=state_file)
        assert status["ok"] is True
        assert status["post_allowed"] is False
        assert status["status"] == "PACED_IDLE"
        assert 22000 <= status["cooldown_remaining_seconds"] <= 24500  # ~6.5h = 23,400s

        # Case 2: Ingest a manual operator post and confirm spacing recalculation
        manual_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ingest_res = ingest_manual_operator_post(
            post_text="Perimeter telemetry manual briefing",
            timestamp_utc=manual_time,
            state_file=state_file,
        )
        assert ingest_res["ok"] is True
        assert ingest_res["manual_post_recorded"] is True

        # Re-check governor
        status_after_manual = check_social_spacing_governor(state_file=state_file)
        assert status_after_manual["ok"] is True
        assert status_after_manual["post_allowed"] is False
        assert status_after_manual["manual_post_detected"] is True
        assert status_after_manual["status"] == "PACED_IDLE"
        assert status_after_manual["cooldown_remaining_seconds"] >= 28000  # ~8.0h = 28,800s


def test_social_swarm_idles_cleanly_without_refusal_exception():
    """Verifies SocialEngagementSwarm idles cleanly without refusal exceptions or retry loops."""
    from orbit_security.social_swarm import SocialEngagementSwarm

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        state_file = tmp_path / "social_daemon_state.json"
        queue_file = tmp_path / "social_staged_queue.json"

        # Active spacing window: 2.0h ago
        recent_time = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2.0)
        ).isoformat()
        state_file.write_text(
            json.dumps(
                {
                    "pid": 5678,
                    "status": "ACTIVE",
                    "timestamp": recent_time,
                    "last_post_timestamp": recent_time,
                    "quotas": {
                        "min_post_spacing_hours": 8.0,
                        "hourly_executed": {"POST": 1},
                        "hourly_limits": {"posts": 1},
                        "daily_executed": {"posts_count": 1},
                        "daily_caps": {"posts": 2},
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        swarm = SocialEngagementSwarm(queue_file=queue_file, state_file=state_file)

        # Execute social cycle while spacing is active — must return PACED_IDLE cleanly
        # and NOT raise RuntimeError or QuotaExceededError or enter a refusal loop
        sample = {
            "agency_name": "Avex Designs",
            "domain": "avexdesigns.com",
            "score": 35,
            "rescued_score": 85,
        }
        res1 = swarm.run_social_cycle(audit_sample=sample, threat_topic="DNS Hygiene")
        assert res1["ok"] is True
        assert res1["status"] == "PACED_IDLE"
        assert res1["post_allowed"] is False
        assert "pacing" in res1["reason"].lower() or "spacing" in res1["reason"].lower()

        # Idempotent second call should not crash or enter refusal retry loops
        res2 = swarm.run_social_cycle(audit_sample=sample, threat_topic="DNS Hygiene")
        assert res2["ok"] is True
        assert res2["status"] == "PACED_IDLE"


def test_social_swarm_permits_post_after_spacing_cooldown():
    """Verifies post permission is granted after 8.0h spacing interval elapses."""
    from orbit_security.social_swarm import check_social_spacing_governor

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        state_file = tmp_path / "social_daemon_state.json"

        # Post executed 8.5 hours ago (> 8.0h min spacing) and daily posts < cap
        elapsed_time = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=8.5)
        ).isoformat()
        state_file.write_text(
            json.dumps(
                {
                    "pid": 9999,
                    "status": "ACTIVE",
                    "timestamp": elapsed_time,
                    "last_post_timestamp": elapsed_time,
                    "quotas": {
                        "min_post_spacing_hours": 8.0,
                        "hourly_executed": {"POST": 0},
                        "hourly_limits": {"posts": 1},
                        "daily_executed": {"posts_count": 1},
                        "daily_caps": {"posts": 2},
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        status = check_social_spacing_governor(state_file=state_file)
        assert status["ok"] is True
        assert status["post_allowed"] is True
        assert status["cooldown_remaining_seconds"] == 0.0
        assert status["status"] in ("READY", "PERMITTED", "ACTIVE")
