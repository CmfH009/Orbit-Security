"""Empirical Adversarial Test Suite: Outreach Reconciler Cohort Fault Tolerance.

Stress-tests:
1. Reconciler --check exit code on empty cohort JSON array (target count deficiency).
2. Reconciler --check exit code on 0-byte cohort file.
3. Reconciler --check exit code on malformed / truncated JSON in cohort file.
4. Reconciler --check exit code on undispositioned / null statuses in cohort items.
5. Reconciler --check exit code on empty / corrupted Cohort 11 manifest.
6. Reconciler --check exit code 0 under standard healthy baseline.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "reconcile_outreach_dispositions.py"


@pytest.fixture
def isolated_repo(tmp_path: Path) -> Path:
    """Creates a hermetic, isolated repository directory with genuine baseline cohort data."""
    from scripts.reconcile_outreach_dispositions import (
        ensure_baseline_outreach_state,
        reconcile_dispositions,
    )

    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    outbound_c11 = tmp_path / "outbound_queue" / "cohort_11"
    outbound_c11.mkdir(parents=True, exist_ok=True)

    # Copy actual baseline files if present on disk
    c11_src = REPO_ROOT / "outbound_queue" / "cohort_11" / "cohort_11_manifest.json"
    if c11_src.exists():
        shutil.copy2(c11_src, outbound_c11 / "cohort_11_manifest.json")

    dc_src = REPO_ROOT / "data" / "dispatched_campaigns.json"
    if dc_src.exists():
        shutil.copy2(dc_src, data_dir / "dispatched_campaigns.json")

    ensure_baseline_outreach_state(tmp_path, create_quarantine_if_missing=True)
    reconcile_dispositions(tmp_path, apply=True)
    return tmp_path


def test_baseline_check_exits_zero():
    """Verify clean baseline passes --check with exit code 0."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, f"Expected 0 on baseline, got {proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
    assert "Reconciler check passed" in proc.stdout


def test_empty_cohort_file_causes_check_to_fail_nonzero(isolated_repo: Path):
    """Verify --check exits non-zero when a cohort file contains empty array []."""
    c8_file = isolated_repo / "data" / "cohort_8_staged.json"
    c8_file.write_text("[]", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--repo-root", str(isolated_repo), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0, f"Expected non-zero exit on empty cohort, got 0:\n{proc.stdout}"
    assert "Expected 50 total targets" in proc.stdout


def test_zero_byte_cohort_file_causes_check_to_fail_nonzero(isolated_repo: Path):
    """Verify --check exits non-zero when a cohort file is 0 bytes."""
    c8_file = isolated_repo / "data" / "cohort_8_staged.json"
    c8_file.write_text("", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--repo-root", str(isolated_repo), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0, f"Expected non-zero exit on 0-byte cohort, got 0:\n{proc.stdout}"


def test_corrupted_syntax_cohort_file_causes_check_to_fail_nonzero(isolated_repo: Path):
    """Verify --check exits non-zero when a cohort file contains corrupted JSON."""
    c8_file = isolated_repo / "data" / "cohort_8_staged.json"
    c8_file.write_text("[{'unclosed': true, ", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--repo-root", str(isolated_repo), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0, f"Expected non-zero exit on corrupt JSON, got 0:\n{proc.stdout}"


def test_undispositioned_target_causes_check_to_fail_nonzero(isolated_repo: Path):
    """Verify --check exits non-zero when a target has an unrecognized or missing disposition."""
    c9_file = isolated_repo / "data" / "cohort_9_staged.json"
    items = json.loads(c9_file.read_text(encoding="utf-8"))
    # Inject undispositioned status
    items[0]["status"] = "INVALID_UNRECOGNIZED_STATUS"
    items[0]["agency_domain"] = "unknown-arbitrary-domain-999.com"
    c9_file.write_text(json.dumps(items, indent=2), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--repo-root", str(isolated_repo), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0, f"Expected non-zero exit on undispositioned item, got 0:\n{proc.stdout}"
    assert "Undispositioned targets detected" in proc.stdout


def test_empty_cohort_11_manifest_causes_check_to_fail_nonzero(isolated_repo: Path):
    """Verify --check exits non-zero when cohort 11 manifest has 0 targets."""
    c11_file = isolated_repo / "outbound_queue" / "cohort_11" / "cohort_11_manifest.json"
    c11_file.write_text(json.dumps({"cohort": "cohort_11", "targets": []}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--repo-root", str(isolated_repo), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0, f"Expected non-zero exit on empty cohort 11, got 0:\n{proc.stdout}"
    assert "Expected 50 total targets" in proc.stdout


def test_corrupted_cohort_11_manifest_causes_check_to_fail_nonzero(isolated_repo: Path):
    """Verify --check exits non-zero when cohort 11 manifest contains malformed JSON."""
    c11_file = isolated_repo / "outbound_queue" / "cohort_11" / "cohort_11_manifest.json"
    c11_file.write_text("NOT_VALID_JSON{{{", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--repo-root", str(isolated_repo), "--check"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0, f"Expected non-zero exit on corrupt cohort 11, got 0:\n{proc.stdout}"
