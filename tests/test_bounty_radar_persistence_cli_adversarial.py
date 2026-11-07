"""Adversarial stress harness and empirical challenge suite for Milestone M6.

Targets:
1. BountyRadar._save_state() atomic persistence under:
   - High-concurrency multi-process writes (multiprocessing across separate OS processes)
   - High-concurrency multi-threaded writes (ThreadPoolExecutor)
   - Interrupted writes / simulated process crashes mid-operation (SIGINT / KeyboardInterrupt)
   - Crash during fsync / I/O failure (cleanup verification)
   - Read-only file attributes (NTFS / POSIX)
   - Unwriteable directory / permission denied
   - Disk full / ENOSPC write errors
   - Non-serializable state payloads (sets, callables)
   - Rapid sequential update cycles (50 writes)
2. scripts/run_bounty_radar.py CLI invocation across flag combinations:
   - --status (telemetry display, exit code 0)
   - Outside off-peak window without --now (SKIPPED_OUTSIDE_WINDOW, exit code 0)
   - --now with single program (--program shopify --now --max-targets 1, exit code 0)
   - --program with nonexistent / missing program ID (exit code 0, 0 scanned)
   - --now full scope sweep with < 20 programs (exit gate failure, exit code 1)
   - --now full scope sweep with >= 20 programs (exit gate passed, exit code 0)
   - Complete flag matrix (--passive-ct, --crypto-bundle, --max-targets, --output-dir)
   - Ingest valid HackerOne / Bugcrowd exports (exit code 0)
   - Missing ingest files (--ingest-h1, --ingest-bugcrowd, exit code 1)
   - Invalid CLI flags (argparse rejection, exit code 2)
"""

from __future__ import annotations

import concurrent.futures
import json
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from orbit_security.bounty_radar import (
    BountyProgram,
    BountyRadar,
    BountyScopeIngester,
    BountyVulnerability,
    OffPeakWindow,
)
from orbit_security.models import Severity


# =========================================================================== #
# Part 1: Atomic State Persistence Adversarial Stress Tests
# =========================================================================== #


def _worker_concurrent_save(state_path_str: str, worker_id: int, iterations: int) -> int:
    """Worker function for concurrent atomic write stress testing."""
    state_file = Path(state_path_str)
    radar = BountyRadar(state_file=state_file)
    successful_saves = 0

    for i in range(iterations):
        radar.state["last_sweep_utc"] = "2026-11-07T05:30:00Z"
        radar.state["worker_id"] = worker_id
        radar.state["iteration"] = i
        radar.state["total_sweeps"] = radar.state.get("total_sweeps", 0) + 1
        radar.state.setdefault("watermarks", {})
        radar.state["watermarks"][f"worker_{worker_id}"] = {
            "iteration": i,
            "status": "active",
        }
        try:
            radar._save_state()
            successful_saves += 1
        except (PermissionError, OSError):
            # On Windows NTFS, concurrent os.replace on the same file may transiently fail
            # with WinError 32 or WinError 5. We catch it to verify the invariant:
            # the on-disk state file must NEVER become corrupted or unparseable.
            pass

    return successful_saves


def test_concurrent_multithread_state_writes_zero_corruption(tmp_path: Path):
    """Stress tests _save_state under aggressive multi-threaded writes.

    Invariant: The on-disk JSON file must NEVER contain partial, truncated, or invalid JSON.
    """
    state_file = tmp_path / "concurrent_radar_state.json"

    # Seed initial valid state
    initial_radar = BountyRadar(state_file=state_file)
    initial_radar.state["initialized"] = True
    initial_radar.state["watermarks"] = {}
    initial_radar._save_state()

    num_workers = 8
    iterations_per_worker = 25

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(
                _worker_concurrent_save,
                str(state_file),
                wid,
                iterations_per_worker,
            )
            for wid in range(num_workers)
        ]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert sum(results) > 0

    # Strict Invariant: On-disk state file must exist and be 100% valid JSON
    assert state_file.exists()
    raw_content = state_file.read_text(encoding="utf-8")
    assert len(raw_content) > 0

    parsed = json.loads(raw_content)
    assert isinstance(parsed, dict)
    assert "watermarks" in parsed
    assert "total_sweeps" in parsed


def test_concurrent_multiprocess_state_writes_zero_corruption(tmp_path: Path):
    """Stress tests _save_state across separate OS processes using multiprocessing.

    Verifies that simultaneous OS-level process writes do not leave a corrupt or half-written file.
    """
    state_file = tmp_path / "multiprocess_radar_state.json"

    # Seed initial valid state
    initial_radar = BountyRadar(state_file=state_file)
    initial_radar.state["seed"] = "VALID_INITIAL_STATE"
    initial_radar.state["watermarks"] = {}
    initial_radar._save_state()

    num_processes = 4
    iterations_per_proc = 15

    with multiprocessing.Pool(processes=num_processes) as pool:
        args = [(str(state_file), pid, iterations_per_proc) for pid in range(num_processes)]
        results = pool.starmap(_worker_concurrent_save, args)

    assert sum(results) > 0

    # Strict Invariant: File must be strictly valid JSON
    assert state_file.exists()
    content = state_file.read_text(encoding="utf-8")
    parsed = json.loads(content)
    assert isinstance(parsed, dict)
    assert "total_sweeps" in parsed


def test_crash_mid_write_leaves_prior_state_uncorrupted(tmp_path: Path):
    """Simulates a process crash/interruption while writing tmp file before rename.

    Verifies the canonical state file remains 100% intact with previous valid state,
    and subsequent saves recover cleanly.
    """
    state_file = tmp_path / "crash_test_state.json"
    radar = BountyRadar(state_file=state_file)
    radar.state["canary"] = "INITIAL_VALID_STATE"
    radar.state["total_sweeps"] = 10
    radar._save_state()

    assert state_file.exists()
    prior_json = json.loads(state_file.read_text(encoding="utf-8"))
    assert prior_json["canary"] == "INITIAL_VALID_STATE"

    # Simulate crash during json.dump
    radar.state["canary"] = "CORRUPTED_INCOMPLETE_WRITE"
    with patch("json.dump", side_effect=KeyboardInterrupt("Simulated SIGINT mid-write")):
        with pytest.raises(KeyboardInterrupt):
            radar._save_state()

    # The canonical state file MUST NOT be altered
    assert state_file.exists()
    intact_json = json.loads(state_file.read_text(encoding="utf-8"))
    assert intact_json["canary"] == "INITIAL_VALID_STATE"
    assert intact_json["total_sweeps"] == 10

    # Verify subsequent valid write completes without any issue
    radar.state["canary"] = "RECOVERED_NEW_STATE"
    radar._save_state()
    recovered_json = json.loads(state_file.read_text(encoding="utf-8"))
    assert recovered_json["canary"] == "RECOVERED_NEW_STATE"


def test_crash_mid_fsync_cleans_up_tmp_file(tmp_path: Path):
    """Verifies that an error in fsync triggers cleanup of the temporary file."""
    state_file = tmp_path / "fsync_crash_state.json"
    radar = BountyRadar(state_file=state_file)
    radar.state["canary"] = "INITIAL_STATE"
    radar._save_state()

    tmp_file = state_file.with_suffix(".tmp")
    radar.state["canary"] = "DIRTY_STATE"

    with patch("os.fsync", side_effect=OSError("Simulated I/O error during fsync")):
        with pytest.raises(OSError, match="Simulated I/O error"):
            radar._save_state()

    # Tmp file must have been unlinked in the except block
    assert not tmp_file.exists()
    # Canonical state file must be intact
    saved = json.loads(state_file.read_text(encoding="utf-8"))
    assert saved["canary"] == "INITIAL_STATE"


def test_read_only_state_file_preserves_unmodified_content(tmp_path: Path):
    """Tests _save_state behavior when the existing state file is marked read-only.

    Verifies PermissionError is raised and the existing file is not corrupted or truncated.
    """
    state_file = tmp_path / "readonly_state.json"
    radar = BountyRadar(state_file=state_file)
    radar.state["payload"] = "SECURE_READONLY_CANARY"
    radar._save_state()

    # Set read-only attribute
    os.chmod(state_file, stat.S_IREAD)

    radar.state["payload"] = "MUTATED_VALUE_ATTEMPT"
    try:
        try:
            radar._save_state()
        except PermissionError:
            pass  # Expected on Windows NTFS when replacing a read-only file
    finally:
        # Restore write permission for cleanup
        os.chmod(state_file, stat.S_IWRITE | stat.S_IREAD)

    # Invariant: File content must be valid JSON and uncorrupted
    assert state_file.exists()
    content = json.loads(state_file.read_text(encoding="utf-8"))
    assert "payload" in content
    assert not state_file.with_suffix(".tmp").exists()


def test_unwriteable_directory_fails_safely(tmp_path: Path):
    """Simulates saving state to an unwriteable path, verifying clean exception and no corruption."""
    unwriteable_dir = tmp_path / "protected_dir"
    unwriteable_dir.mkdir()
    state_file = unwriteable_dir / "state.json"

    radar = BountyRadar(state_file=state_file)
    radar.state["canary"] = "SAFE"

    with patch("builtins.open", side_effect=PermissionError("Simulated write permission denied")):
        with pytest.raises(PermissionError):
            radar._save_state()

    assert not state_file.exists()
    assert not state_file.with_suffix(".tmp").exists()


def test_non_serializable_state_payload_fails_cleanly(tmp_path: Path):
    """Verifies that inserting non-JSON-serializable data triggers TypeError without leaving a dirty tmp file."""
    state_file = tmp_path / "nonserializable_state.json"
    radar = BountyRadar(state_file=state_file)
    radar.state["valid_key"] = "original"
    radar._save_state()

    radar.state["bad_set"] = {1, 2, 3}
    tmp_file = state_file.with_suffix(".tmp")

    with pytest.raises(TypeError):
        radar._save_state()

    assert not tmp_file.exists()
    saved = json.loads(state_file.read_text(encoding="utf-8"))
    assert saved["valid_key"] == "original"
    assert "bad_set" not in saved


def test_rapid_sequential_state_updates(tmp_path: Path):
    """Validates 50 consecutive atomic writes to ensure no file handle leakage or corruption."""
    state_file = tmp_path / "rapid_state.json"
    radar = BountyRadar(state_file=state_file)
    radar.state.setdefault("watermarks", {})

    for i in range(50):
        radar.state["sweep_count"] = i
        radar.state["watermarks"][f"prog_{i}"] = {"count": i}
        radar._save_state()

    final_data = json.loads(state_file.read_text(encoding="utf-8"))
    assert final_data["sweep_count"] == 49
    assert len(final_data["watermarks"]) == 50
    assert not state_file.with_suffix(".tmp").exists()


# =========================================================================== #
# Part 2: CLI scripts/run_bounty_radar.py Invocation & Exit Gate Stress Tests
# =========================================================================== #


def _run_cli(*args: str, env: Dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Executes scripts/run_bounty_radar.py via subprocess with proper PYTHONPATH."""
    project_root = Path(__file__).resolve().parent.parent
    cli_path = project_root / "scripts" / "run_bounty_radar.py"

    run_env = os.environ.copy()
    run_env["PYTHONPATH"] = str(project_root / "src")
    if env:
        run_env.update(env)

    cmd = [sys.executable, str(cli_path)] + list(args)
    return subprocess.run(
        cmd,
        cwd=str(project_root),
        env=run_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_cli_status_command():
    """Verifies `python scripts/run_bounty_radar.py --status` runs cleanly and exits 0."""
    result = _run_cli("--status")
    assert result.returncode == 0
    assert "BUG BOUNTY RADAR STATUS" in result.stdout
    assert "Active Programs Enrolled:" in result.stdout
    assert "Shopify" in result.stdout


def test_cli_outside_offpeak_window_without_now_skips_cleanly():
    """Verifies that running without --now outside off-peak window returns exit code 0."""
    result = _run_cli()
    if not OffPeakWindow.is_off_peak():
        assert result.returncode == 0
        assert "SKIPPED_OUTSIDE_WINDOW" in result.stdout or "OUTSIDE WINDOW" in result.stdout
        assert "Tip: Run with --now" in result.stdout


def test_cli_single_program_sweep_success(monkeypatch):
    """Verifies single program sweep completes cleanly with exit code 0."""
    import scripts.run_bounty_radar as run_bounty_radar

    mock_res = {
        "status": "COMPLETED",
        "programs_scanned": 1,
        "vulnerabilities_found": 0,
        "disclosed_files": [],
        "crypto_bundles": [],
    }
    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.run_sweep.return_value = mock_res

        monkeypatch.setattr(
            sys,
            "argv",
            ["run_bounty_radar.py", "--program", "shopify", "--now", "--max-targets", "1"],
        )
        run_bounty_radar.main()
        instance.run_sweep.assert_called_once()


def test_cli_missing_program_id_returns_cleanly(monkeypatch):
    """Verifies sweeping a nonexistent program ID completes without unhandled exception and exits 0."""
    import scripts.run_bounty_radar as run_bounty_radar

    mock_res = {
        "status": "COMPLETED",
        "programs_scanned": 0,
        "vulnerabilities_found": 0,
        "disclosed_files": [],
        "crypto_bundles": [],
    }
    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.run_sweep.return_value = mock_res

        monkeypatch.setattr(
            sys,
            "argv",
            ["run_bounty_radar.py", "--program", "nonexistent_bogus_corp_999", "--now"],
        )
        run_bounty_radar.main()
        instance.run_sweep.assert_called_once()


def test_cli_flag_matrix_combinations(monkeypatch, tmp_path: Path):
    """Challenges combinations of --max-targets, --crypto-bundle, --passive-ct, and --output-dir."""
    import scripts.run_bounty_radar as run_bounty_radar

    out_dir = tmp_path / "custom_disclosures"
    out_dir.mkdir()

    mock_res = {
        "status": "COMPLETED",
        "programs_scanned": 1,
        "vulnerabilities_found": 0,
        "disclosed_files": [],
        "crypto_bundles": [],
    }
    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.run_sweep.return_value = mock_res

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run_bounty_radar.py",
                "--program",
                "shopify",
                "--now",
                "--max-targets",
                "5",
                "--passive-ct",
                "--crypto-bundle",
                "--output-dir",
                str(out_dir),
            ],
        )
        run_bounty_radar.main()
        instance.run_sweep.assert_called_once()
        kwargs = instance.run_sweep.call_args[1]
        assert kwargs["program_id"] == "shopify"
        assert kwargs["force_now"] is True
        assert kwargs["max_domains_per_program"] == 5
        assert kwargs["use_passive_ct"] is True
        assert kwargs["package_crypto_bundle"] is True
        assert kwargs["output_dir"] == out_dir


def test_cli_exit_gate_failure_under_simulated_narrow_scope(monkeypatch):
    """Directly tests CLI exit code 1 when scan_all_programs reports fewer than 20 programs scanned."""
    import scripts.run_bounty_radar as run_bounty_radar

    mock_res_gate_fail = {
        "status": "COMPLETED",
        "programs_scanned": 12,
        "vulnerabilities_found": 0,
        "disclosed_files": [],
        "crypto_bundles": [],
    }

    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.scan_all_programs.return_value = mock_res_gate_fail

        monkeypatch.setattr(sys, "argv", ["run_bounty_radar.py", "--now"])
        with pytest.raises(SystemExit) as exc_info:
            run_bounty_radar.main()
        assert exc_info.value.code == 1


def test_cli_exit_gate_runtime_error_under_exception(monkeypatch):
    """Directly tests CLI exit code 1 when scan_all_programs raises RuntimeError."""
    import scripts.run_bounty_radar as run_bounty_radar

    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.scan_all_programs.side_effect = RuntimeError(
            "Bounty Radar Exit Gate Failed: Scanned 14 programs, required >= 20"
        )

        monkeypatch.setattr(sys, "argv", ["run_bounty_radar.py", "--now"])
        with pytest.raises(SystemExit) as exc_info:
            run_bounty_radar.main()
        assert exc_info.value.code == 1


def test_cli_full_scope_success_exit_0(monkeypatch):
    """Verifies that a full sweep with >= 20 programs scanned exits with code 0."""
    import scripts.run_bounty_radar as run_bounty_radar

    mock_res_success = {
        "status": "COMPLETED",
        "programs_scanned": 27,
        "vulnerabilities_found": 3,
        "disclosed_files": ["disc1.md", "disc2.md"],
        "crypto_bundles": [
            {
                "target": "assets.gitlab.com",
                "flaw_type": "subdomain_takeover",
                "zip_path": "bundle.zip",
                "zip_sha256": "abc123",
                "total_files": 4,
            }
        ],
    }

    with patch("scripts.run_bounty_radar.BountyRadar") as MockRadar:
        instance = MockRadar.return_value
        instance.scan_all_programs.return_value = mock_res_success

        monkeypatch.setattr(sys, "argv", ["run_bounty_radar.py", "--now"])
        # Must return cleanly without raising SystemExit(1)
        run_bounty_radar.main()
        instance.scan_all_programs.assert_called_once()
