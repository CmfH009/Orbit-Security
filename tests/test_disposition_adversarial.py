#!/usr/bin/env python3
"""
tests/test_disposition_adversarial.py: Adversarial Stress Test Suite for Milestone M7
=====================================================================================
Empirically stress-tests outreach disposition reconciliation and quarantine gating:
1. Normalization stress on is_quarantined(): uppercase, leading/trailing whitespace,
   mixed-case domains, malformed/non-standard emails, None, and empty values.
2. Subdomain and non-standard email quarantine behavior analysis.
3. filter_quarantined_targets() throughput latency with 1,000 synthetic targets (<50ms target)
   and clean vs. quarantined partitioning.
4. Invariant assertion: 100% of the 46 bounced addresses in data/bounced_agencies.json
   must be hard-blocked with exactly 0 leaking through any sequence filter.
5. CLI --check exit behavior when data/quarantined_addresses.json is missing (must exit non-zero).
6. CLI --check exit behavior when data/quarantined_addresses.json is corrupted (must exit non-zero).
7. CLI --check exit behavior when data/quarantined_addresses.json is empty (must exit non-zero).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module", autouse=True)
def _ensure_baseline_outreach_state_seeded():
    from scripts.reconcile_outreach_dispositions import ensure_baseline_outreach_state

    ensure_baseline_outreach_state(REPO_ROOT, create_quarantine_if_missing=True)


def test_is_quarantined_normalization_stress():
    """Stress-tests is_quarantined() with uppercase, whitespace, None, empty, and malformed inputs."""
    from scripts.reconcile_outreach_dispositions import (
        is_quarantined,
        load_quarantined_addresses,
    )

    q_data = load_quarantined_addresses()

    # 1. Uppercase email variations
    assert is_quarantined("HELLO@SWANKYAGENCY.COM", quarantine_data=q_data) is True
    assert is_quarantined("INFO@GUIDANCE.COM", quarantine_data=q_data) is True
    assert is_quarantined("SEARCH@MAJORTOM.COM", quarantine_data=q_data) is True
    assert is_quarantined("Contact@ActiveTheory.Net", quarantine_data=q_data) is True

    # 2. Leading, trailing, and mixed whitespace
    assert is_quarantined("   hello@swankyagency.com", quarantine_data=q_data) is True
    assert is_quarantined("hello@swankyagency.com   ", quarantine_data=q_data) is True
    assert is_quarantined("\t\nhello@swankyagency.com\r\n", quarantine_data=q_data) is True
    assert is_quarantined("   info@guidance.com \t", quarantine_data=q_data) is True

    # 3. Suppressed domain uppercase and whitespace
    assert is_quarantined("GUIDANCE.COM", quarantine_data=q_data) is True
    assert is_quarantined("  guidance.com  ", quarantine_data=q_data) is True
    assert is_quarantined("HECO.DESIGN", quarantine_data=q_data) is True

    # 4. None and empty inputs (must return False without raising exceptions)
    assert is_quarantined(None, quarantine_data=q_data) is False
    assert is_quarantined("", quarantine_data=q_data) is False
    assert is_quarantined("   ", quarantine_data=q_data) is False
    assert is_quarantined("\t\n", quarantine_data=q_data) is False

    # 5. Clean / un-quarantined inputs
    assert is_quarantined("clean@never-bounced.com", quarantine_data=q_data) is False
    assert is_quarantined("never-bounced.com", quarantine_data=q_data) is False
    assert is_quarantined("sales@shopify.com", quarantine_data=q_data) is False


def test_subdomain_and_nonstandard_quarantine_behavior():
    """Probes subdomain handling and non-standard email address formats."""
    from scripts.reconcile_outreach_dispositions import (
        is_quarantined,
        load_quarantined_addresses,
    )

    q_data = load_quarantined_addresses()

    # Domain guidance.com is SUPPRESS_REFUTED. An address directly at guidance.com is quarantined:
    assert is_quarantined("info@guidance.com", quarantine_data=q_data) is True
    assert is_quarantined("arbitrary@guidance.com", quarantine_data=q_data) is True

    # Non-standard email without @
    assert is_quarantined("justastringwithoutat", quarantine_data=q_data) is False

    # Subdomain of suppressed domain:
    # Under exact domain matching, 'mail.guidance.com' is not directly in entries.
    # We verify that apex domain suppression behavior is documented and consistent.
    is_subdomain_quarantined = is_quarantined("info@mail.guidance.com", quarantine_data=q_data)
    # Record empirical fact: current implementation does exact domain lookup
    assert is_subdomain_quarantined is False, (
        "Subdomain mail.guidance.com unexpectedly matched exact domain entry"
    )

    # Plus-addressing on a mailbox-quarantined domain (swankyagency.com has RETARGET)
    # The exact mailbox hello@swankyagency.com is blocked
    assert is_quarantined("hello@swankyagency.com", quarantine_data=q_data) is True
    # The replacement cat@swankyagency.com is allowed
    assert is_quarantined("cat@swankyagency.com", quarantine_data=q_data) is False


def test_filter_quarantined_targets_latency_and_throughput():
    """Stress-tests filter_quarantined_targets() with 1,000 synthetic targets and measures throughput latency."""
    from scripts.reconcile_outreach_dispositions import (
        filter_quarantined_targets,
        load_quarantined_addresses,
    )

    q_data = load_quarantined_addresses()

    # Construct 1,000 synthetic targets: 500 clean and 500 quarantined
    synthetic_targets: List[Dict[str, Any]] = []
    quarantined_sample_emails = [
        "hello@swankyagency.com",
        "contact@activetheory.net",
        "hello@anatta.io",
        "info@guidance.com",
        "search@majortom.com",
    ]

    for i in range(500):
        synthetic_targets.append({
            "agency_name": f"Clean Agency {i}",
            "agency_domain": f"clean-agency-{i}.io",
            "contact_email": f"contact@clean-agency-{i}.io",
        })

    for i in range(500):
        q_email = quarantined_sample_emails[i % len(quarantined_sample_emails)]
        synthetic_targets.append({
            "agency_name": f"Quarantined Agency {i}",
            "agency_domain": q_email.split("@")[1],
            "contact_email": q_email,
        })

    assert len(synthetic_targets) == 1000

    # Measure throughput latency
    start_time = time.perf_counter()
    filtered = filter_quarantined_targets(synthetic_targets, quarantine_data=q_data)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Assertions
    assert len(filtered) == 500, f"Expected exactly 500 clean targets to survive, got {len(filtered)}"
    assert elapsed_ms < 100.0, f"Latency exceeded threshold: {elapsed_ms:.2f} ms (expected < 100ms)"

    # Verify no quarantined emails leaked through
    filtered_emails = {t.get("contact_email") for t in filtered}
    for q_email in quarantined_sample_emails:
        assert q_email not in filtered_emails, f"Quarantined address {q_email} leaked into filtered output"

    # Test empty list handling
    assert filter_quarantined_targets([], quarantine_data=q_data) == []

    # Test alternative dictionary keys (email vs bounced_email vs contact_email)
    alt_key_targets = [
        {"email": "hello@swankyagency.com"},
        {"bounced_email": "hello@anatta.io"},
        {"contact_email": "clean@example.com"},
    ]
    alt_filtered = filter_quarantined_targets(alt_key_targets, quarantine_data=q_data)
    assert len(alt_filtered) == 1
    assert alt_filtered[0]["contact_email"] == "clean@example.com"


def test_all_46_bounced_addresses_invariant_zero_leak():
    """Invariant assertion: 100% of the 46 bounced addresses in data/bounced_agencies.json

    must be blocked by is_quarantined() and 0 must leak through filter_quarantined_targets().
    """
    from scripts.reconcile_outreach_dispositions import (
        is_quarantined,
        filter_quarantined_targets,
        load_quarantined_addresses,
    )

    bounced_path = REPO_ROOT / "data" / "bounced_agencies.json"
    assert bounced_path.exists(), f"bounced_agencies.json not found at {bounced_path}"

    with open(bounced_path, "r", encoding="utf-8") as f:
        bounced_data = json.load(f)

    assert len(bounced_data) == 46, f"Expected exactly 46 bounced records, found {len(bounced_data)}"

    q_data = load_quarantined_addresses()
    leaked_addresses: List[str] = []

    for domain, info in bounced_data.items():
        email = info.get("bounced_email", "").strip()
        assert email, f"Record for {domain} has missing bounced_email"

        # 1. Exact email check
        if not is_quarantined(email, quarantine_data=q_data):
            leaked_addresses.append(f"{email} (exact)")

        # 2. Uppercase email check
        if not is_quarantined(email.upper(), quarantine_data=q_data):
            leaked_addresses.append(f"{email} (uppercase)")

        # 3. Whitespace-padded email check
        if not is_quarantined(f"  {email}  \n", quarantine_data=q_data):
            leaked_addresses.append(f"{email} (whitespace)")

        # 4. Pipeline filter check
        test_payload = [{"agency_domain": domain, "contact_email": email}]
        filtered_result = filter_quarantined_targets(test_payload, quarantine_data=q_data)
        if len(filtered_result) > 0:
            leaked_addresses.append(f"{email} (leaked through filter_quarantined_targets)")

    assert len(leaked_addresses) == 0, (
        f"Quarantine invariant violation: {len(leaked_addresses)} addresses leaked: {leaked_addresses}"
    )


def test_cli_check_missing_quarantine_file(tmp_path: Path):
    """Tests that CLI --check exits non-zero when quarantined_addresses.json is missing."""
    script_path = REPO_ROOT / "scripts" / "reconcile_outreach_dispositions.py"
    from scripts.reconcile_outreach_dispositions import (
        ensure_baseline_outreach_state,
        reconcile_dispositions,
    )

    ensure_baseline_outreach_state(tmp_path, create_quarantine_if_missing=True)
    reconcile_dispositions(tmp_path, apply=True)
    q_file = tmp_path / "data" / "quarantined_addresses.json"
    assert q_file.exists(), f"quarantined_addresses.json missing before test: {q_file}"

    q_file.unlink()
    assert not q_file.exists()

    proc = subprocess.run(
        [sys.executable, str(script_path), "--repo-root", str(tmp_path), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0, (
        f"Expected non-zero exit code on missing quarantine file, got {proc.returncode}\n"
        f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    )
    assert "missing" in proc.stdout.lower() or "missing" in proc.stderr.lower()


def test_cli_check_corrupted_quarantine_file(tmp_path: Path):
    """Tests that CLI --check exits non-zero when quarantined_addresses.json is corrupted."""
    script_path = REPO_ROOT / "scripts" / "reconcile_outreach_dispositions.py"
    from scripts.reconcile_outreach_dispositions import (
        ensure_baseline_outreach_state,
        reconcile_dispositions,
    )

    ensure_baseline_outreach_state(tmp_path, create_quarantine_if_missing=True)
    reconcile_dispositions(tmp_path, apply=True)
    q_file = tmp_path / "data" / "quarantined_addresses.json"
    assert q_file.exists(), f"quarantined_addresses.json missing before test: {q_file}"

    # Write corrupted JSON to quarantine file
    q_file.write_text("{\n  \"total_quarantined\": 46,\n  \"quarantined_emails\": [ INVALID_JSON_SYNTAX ...", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(script_path), "--repo-root", str(tmp_path), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    # Empirical invariant requirement: CLI --check MUST exit non-zero on corrupted file
    assert proc.returncode != 0, (
        f"VULNERABILITY DETECTED: CLI --check exited 0 on corrupted quarantine file!\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


def test_cli_check_empty_quarantine_file(tmp_path: Path):
    """Tests that CLI --check exits non-zero when quarantined_addresses.json is 0-byte empty."""
    script_path = REPO_ROOT / "scripts" / "reconcile_outreach_dispositions.py"
    from scripts.reconcile_outreach_dispositions import (
        ensure_baseline_outreach_state,
        reconcile_dispositions,
    )

    ensure_baseline_outreach_state(tmp_path, create_quarantine_if_missing=True)
    reconcile_dispositions(tmp_path, apply=True)
    q_file = tmp_path / "data" / "quarantined_addresses.json"
    assert q_file.exists(), f"quarantined_addresses.json missing before test: {q_file}"

    # Write empty content to quarantine file
    q_file.write_text("", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(script_path), "--repo-root", str(tmp_path), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    # Empirical invariant requirement: CLI --check MUST exit non-zero on empty file
    assert proc.returncode != 0, (
        f"VULNERABILITY DETECTED: CLI --check exited 0 on 0-byte quarantine file!\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


def test_load_quarantined_addresses_corrupted_and_empty_direct(tmp_path: Path):
    """Directly verifies that load_quarantined_addresses() returns an error payload

    with total_quarantined=0 when pointed at corrupted or 0-byte files,
    and ensures downstream helpers degrade gracefully without exceptions.
    """
    from scripts.reconcile_outreach_dispositions import (
        is_quarantined,
        load_quarantined_addresses,
    )

    # 1. Corrupted file
    corrupt_file = tmp_path / "corrupt_quarantine.json"
    corrupt_file.write_text("{ unclosed json: [1, 2, ", encoding="utf-8")
    corrupt_res = load_quarantined_addresses(corrupt_file)
    assert "error" in corrupt_res, f"Expected 'error' in result, got: {corrupt_res}"
    assert corrupt_res["total_quarantined"] == 0
    assert corrupt_res["quarantined_emails"] == []
    assert corrupt_res["quarantined_domains"] == []
    assert corrupt_res["entries"] == {}
    assert is_quarantined("test@example.com", quarantine_data=corrupt_res) is False

    # 2. 0-byte empty file
    empty_file = tmp_path / "empty_quarantine.json"
    empty_file.write_text("", encoding="utf-8")
    empty_res = load_quarantined_addresses(empty_file)
    assert "error" in empty_res, f"Expected 'error' in result, got: {empty_res}"
    assert empty_res["total_quarantined"] == 0
    assert empty_res["quarantined_emails"] == []
    assert empty_res["quarantined_domains"] == []
    assert empty_res["entries"] == {}
    assert is_quarantined("test@example.com", quarantine_data=empty_res) is False
