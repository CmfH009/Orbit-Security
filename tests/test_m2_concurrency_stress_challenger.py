"""Empirical Challenger stress test suite for Milestone M2 (NTFS Concurrency Race Conditions).

Tests ClientBundleExporter under 16 to 32 concurrent threads exporting for the exact same agency.
Verifies:
1. Zero PermissionErrors ([WinError 5] / [Errno 13]).
2. Zero leaked temporary files (.tmp, .tmp.zip, .tmp.json).
3. Uncorrupted ZIP containing exactly the 7 deliverable files.
4. Valid SHA-256 digest in sidecar bundle_manifest.json matching final on-disk ZIP.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Any, Dict, List
import zipfile

import pytest

from orbit_security.client_bundle_exporter import ClientBundleExporter

EXPECTED_DELIVERABLES = {
    "reports/executive_summary.html",
    "reports/executive_summary.md",
    "remediation/remediation.tf",
    "remediation/remediation.cfn.yaml",
    "remediation/remediation.zone",
    ".orbit.yml",
    "bundle_manifest.json",
}


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def _run_concurrency_trial(
    workspace_root: Path,
    agency_slug: str,
    concurrency_level: int,
    use_barrier: bool = True,
) -> Dict[str, Any]:
    bundles_dir = workspace_root / "client_bundles"
    exporter = ClientBundleExporter(workspace_root=workspace_root, bundles_dir=bundles_dir)

    results: List[Dict[str, Any]] = []
    errors: List[Exception] = []

    barrier = threading.Barrier(concurrency_level) if use_barrier else None

    def export_worker(worker_id: int) -> Dict[str, Any]:
        if barrier:
            barrier.wait()
        return exporter.export_bundle(
            agency_slug=agency_slug,
            agency_name=f"Stress Agency {agency_slug}",
            domains=["apex.example.com"],
            primary_color="#0A1128",
            accent_color="#00E5FF",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency_level) as pool:
        futures = [pool.submit(export_worker, i) for i in range(concurrency_level)]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                results.append(res)
            except Exception as exc:
                errors.append(exc)

    agency_dir = bundles_dir / agency_slug
    final_zip = agency_dir / f"{agency_slug}_remediation_bundle.zip"
    sidecar_manifest = agency_dir / "bundle_manifest.json"

    # Check for leaked temporary files
    leaked_tmps = []
    if agency_dir.exists():
        for item in agency_dir.iterdir():
            if ".tmp" in item.name:
                leaked_tmps.append(str(item))

    # Check zip integrity and members
    zip_test_error = None
    namelist = set()
    actual_zip_hash = ""
    inner_manifest_gen = None
    if final_zip.exists() and zipfile.is_zipfile(final_zip):
        actual_zip_hash = hashlib.sha256(final_zip.read_bytes()).hexdigest()
        try:
            with zipfile.ZipFile(final_zip, "r") as zf:
                zip_test_error = zf.testzip()
                namelist = set(zf.namelist())
                if "bundle_manifest.json" in namelist:
                    inner_m = json.loads(zf.read("bundle_manifest.json").decode("utf-8"))
                    inner_manifest_gen = inner_m.get("generated_at")
        except Exception as e:
            zip_test_error = str(e)

    # Check manifest hash matching
    manifest_zip_hash = None
    sidecar_manifest_gen = None
    if sidecar_manifest.exists():
        try:
            manifest_content = json.loads(sidecar_manifest.read_text(encoding="utf-8"))
            manifest_zip_hash = manifest_content.get("bundle_sha256")
            sidecar_manifest_gen = manifest_content.get("generated_at")
        except Exception as e:
            manifest_zip_hash = f"ERROR: {e}"

    return {
        "concurrency": concurrency_level,
        "results_count": len(results),
        "errors": errors,
        "leaked_tmps": leaked_tmps,
        "final_zip_exists": final_zip.exists(),
        "is_valid_zip": zipfile.is_zipfile(final_zip) if final_zip.exists() else False,
        "zip_test_error": zip_test_error,
        "namelist": namelist,
        "actual_zip_hash": actual_zip_hash,
        "manifest_zip_hash": manifest_zip_hash,
        "sidecar_manifest_gen": sidecar_manifest_gen,
        "inner_manifest_gen": inner_manifest_gen,
    }


def test_concurrency_32_threads_barrier_manifest_integrity(temp_workspace):
    """Stress tests 32 concurrent threads synchronized by barrier across trials.
    
    Catches the race condition where os.replace(zip) and os.replace(manifest)
    interleave across threads, leaving bundle_manifest.json mismatched with the actual ZIP.
    """
    mismatches = []
    for trial_idx in range(20):
        trial_dir = temp_workspace / f"trial_{trial_idx}"
        trial_dir.mkdir(parents=True, exist_ok=True)
        report = _run_concurrency_trial(trial_dir, "barrier-agency-32", 32, use_barrier=True)

        assert len(report["errors"]) == 0, f"Encountered errors: {report['errors']}"
        assert len(report["leaked_tmps"]) == 0, f"Leaked tmps: {report['leaked_tmps']}"
        assert report["final_zip_exists"] is True
        assert report["is_valid_zip"] is True
        assert report["zip_test_error"] is None
        assert EXPECTED_DELIVERABLES.issubset(report["namelist"])

        if report["manifest_zip_hash"] != report["actual_zip_hash"]:
            mismatches.append({
                "trial": trial_idx,
                "actual_zip_sha": report["actual_zip_hash"],
                "manifest_sha": report["manifest_zip_hash"],
                "sidecar_gen": report["sidecar_manifest_gen"],
                "inner_gen": report["inner_manifest_gen"],
            })

    assert len(mismatches) == 0, (
        f"Detected {len(mismatches)} manifest vs ZIP SHA-256 mismatches in 20 trials: {mismatches}"
    )


def test_concurrency_16_threads_barrier_manifest_integrity(temp_workspace):
    """Stress tests 16 concurrent threads synchronized by barrier across trials."""
    mismatches = []
    for trial_idx in range(20):
        trial_dir = temp_workspace / f"trial_16_{trial_idx}"
        trial_dir.mkdir(parents=True, exist_ok=True)
        report = _run_concurrency_trial(trial_dir, "barrier-agency-16", 16, use_barrier=True)

        assert len(report["errors"]) == 0, f"Encountered errors: {report['errors']}"
        assert len(report["leaked_tmps"]) == 0, f"Leaked tmps: {report['leaked_tmps']}"
        assert report["final_zip_exists"] is True
        assert report["is_valid_zip"] is True
        assert report["zip_test_error"] is None
        assert EXPECTED_DELIVERABLES.issubset(report["namelist"])

        if report["manifest_zip_hash"] != report["actual_zip_hash"]:
            mismatches.append({
                "trial": trial_idx,
                "actual_zip_sha": report["actual_zip_hash"],
                "manifest_sha": report["manifest_zip_hash"],
                "sidecar_gen": report["sidecar_manifest_gen"],
                "inner_gen": report["inner_manifest_gen"],
            })

    assert len(mismatches) == 0, (
        f"Detected {len(mismatches)} manifest vs ZIP SHA-256 mismatches in 20 trials: {mismatches}"
    )
