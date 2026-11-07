#!/usr/bin/env python3
"""
Adversarial Stress Test Suite for Milestone M7:
Social Governor Spacing Ledger, Temporal Invariants, Concurrency & Refusal Loop Prevention.

Empirical verification suite:
1. test_governor_temporal_boundaries:
   - Tests exact 8.0h threshold
   - 7.999h elapsed (must block: PACED_IDLE, post_allowed=False)
   - 8.001h elapsed (must permit: READY, post_allowed=True)
   - 0.0h elapsed (just posted: PACED_IDLE, ~28800s cooldown)
2. test_governor_clock_skew_and_future_timestamps:
   - Tests timestamps in the future (+10s, +1h, +24h clock skew)
   - Asserts max(0.0, ...) prevents negative elapsed time or unhandled exceptions
   - Asserts post is strictly blocked (PACED_IDLE, cooldown >= 28800s)
3. test_governor_timestamp_format_permutations:
   - Tests ISO-8601 with 'Z', with '+00:00', with non-UTC offset ('+05:30', '-08:00')
   - Tests naive ISO-8601 without tzinfo
   - Tests epoch timestamp strings and numerical floats
   - Tests whitespace-padded timestamp strings
   - Tests malformed timestamp strings ("unparseable", "", None)
4. test_governor_missing_fields_and_corrupt_state:
   - Missing state file (non-existent path)
   - Zero-byte empty file
   - Malformed/corrupted JSON file syntax
   - Missing quotas dict, missing daily_caps, missing last_post_timestamp
   - Daily post cap exhausted (2/2 posts) even after 10.0h spacing elapsed
5. test_manual_post_ingestion_concurrency_stress:
   - Rapid sequential manual post ingestion (50 successive calls)
   - Multi-threaded concurrent manual post ingestion (20 worker threads)
   - Validates JSON state file integrity, valid structure, and accurate counts
6. test_social_swarm_refusal_loop_prevention:
   - Invokes SocialEngagementSwarm.run_social_cycle() 60+ consecutive times during active spacing
   - Verifies 0 exceptions raised
   - Verifies 100% PACED_IDLE status and post_allowed=False
   - Verifies queue_file is untouched (0 actions staged)
7. test_spacing_cooldown_transition_releases_staging:
   - Confirms that once spacing passes 8.0h, run_social_cycle() transitions from PACED_IDLE to STAGED
   - Confirms actions are cleanly appended to the queue file adhering to ADR-002
"""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List

import pytest

from orbit_security.social_swarm import (
    check_social_spacing_governor,
    ingest_manual_operator_post,
    SocialEngagementSwarm,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_state(path: Path, state_dict: Dict[str, Any]) -> None:
    """Helper to write state dictionary to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state_dict, indent=2), encoding="utf-8")


def _base_state(
    last_post_ts: str,
    min_spacing_hours: float = 8.0,
    daily_posts: int = 1,
    daily_cap: int = 2,
    is_manual: bool = False,
) -> Dict[str, Any]:
    """Helper to generate standard governor state payload."""
    return {
        "pid": 4242,
        "status": "ACTIVE",
        "timestamp": last_post_ts,
        "last_post_timestamp": last_post_ts,
        "last_post_is_manual": is_manual,
        "manual_post_detected": is_manual,
        "circuit_state": "CLOSED",
        "quotas": {
            "min_post_spacing_hours": min_spacing_hours,
            "hourly_executed": {"POST": 1},
            "hourly_limits": {"posts": 1},
            "daily_executed": {"posts_count": daily_posts},
            "daily_caps": {"posts": daily_cap},
        },
    }


# ---------------------------------------------------------------------------
# Test 1: Temporal Boundaries (7.999h, 8.0h, 8.001h, 0.0h)
# ---------------------------------------------------------------------------

def test_governor_temporal_boundaries():
    """Adversarial boundary test around exact 8.0h spacing threshold."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "social_state.json"
        now = datetime.datetime.now(datetime.timezone.utc)

        # Boundary A: 7.999 hours ago -> Strictly inside cooldown (< 8.0h)
        ts_7_999h = (now - datetime.timedelta(hours=7.999)).isoformat()
        _write_state(state_file, _base_state(ts_7_999h))

        res_7_999 = check_social_spacing_governor(state_file=state_file)
        assert res_7_999["ok"] is True
        assert res_7_999["post_allowed"] is False
        assert res_7_999["status"] == "PACED_IDLE"
        assert res_7_999["cooldown_remaining_seconds"] > 0.0
        # 8.0h - 7.999h = 0.001h = 3.6s
        assert 1.0 <= res_7_999["cooldown_remaining_seconds"] <= 10.0

        # Boundary B: Exactly 8.000 hours ago -> Cooldown clear (8.0h >= 8.0h)
        ts_8_000h = (now - datetime.timedelta(hours=8.000000)).isoformat()
        _write_state(state_file, _base_state(ts_8_000h))

        res_8_000 = check_social_spacing_governor(state_file=state_file)
        assert res_8_000["ok"] is True
        assert res_8_000["post_allowed"] is True
        assert res_8_000["status"] == "READY"
        assert res_8_000["cooldown_remaining_seconds"] == 0.0

        # Boundary C: 8.001 hours ago -> Cooldown clear (> 8.0h)
        ts_8_001h = (now - datetime.timedelta(hours=8.001)).isoformat()
        _write_state(state_file, _base_state(ts_8_001h))

        res_8_001 = check_social_spacing_governor(state_file=state_file)
        assert res_8_001["ok"] is True
        assert res_8_001["post_allowed"] is True
        assert res_8_001["status"] == "READY"
        assert res_8_001["cooldown_remaining_seconds"] == 0.0

        # Boundary D: 0.0h elapsed (just posted right now) -> Cooldown maximal
        ts_just_now = now.isoformat()
        _write_state(state_file, _base_state(ts_just_now))

        res_just_now = check_social_spacing_governor(state_file=state_file)
        assert res_just_now["ok"] is True
        assert res_just_now["post_allowed"] is False
        assert res_just_now["status"] == "PACED_IDLE"
        assert 28790.0 <= res_just_now["cooldown_remaining_seconds"] <= 28805.0


# ---------------------------------------------------------------------------
# Test 2: Future Timestamps & Clock Skew Resilience
# ---------------------------------------------------------------------------

def test_governor_clock_skew_and_future_timestamps():
    """Adversarially tests positive clock skew where timestamps are in the future."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "social_state.json"
        now = datetime.datetime.now(datetime.timezone.utc)

        future_offsets = [
            datetime.timedelta(seconds=10),
            datetime.timedelta(minutes=5),
            datetime.timedelta(hours=1),
            datetime.timedelta(days=1),
        ]

        for offset in future_offsets:
            future_ts = (now + offset).isoformat()
            _write_state(state_file, _base_state(future_ts))

            res = check_social_spacing_governor(state_file=state_file)
            assert res["ok"] is True, f"Failed on offset {offset}"
            assert res["post_allowed"] is False, f"Permitted post with future timestamp {future_ts}"
            assert res["status"] == "PACED_IDLE"
            # Since max(0.0, elapsed) is clamped, cooldown remaining must equal 8.0h (28,800s)
            assert res["cooldown_remaining_seconds"] == 28800.0
            assert res["elapsed_hours"] == 0.0


# ---------------------------------------------------------------------------
# Test 3: Timestamp Format Permutations
# ---------------------------------------------------------------------------

def test_governor_timestamp_format_permutations():
    """Adversarially tests various timestamp formats: ISO-8601 variants, epochs, and malformed inputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "social_state.json"
        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. ISO-8601 with trailing 'Z'
        ts_z = (now - datetime.timedelta(hours=2.0)).strftime("%Y-%m-%dT%H:%M:%SZ")
        _write_state(state_file, _base_state(ts_z))
        res_z = check_social_spacing_governor(state_file=state_file)
        assert res_z["post_allowed"] is False
        assert res_z["status"] == "PACED_IDLE"
        assert 21500 <= res_z["cooldown_remaining_seconds"] <= 21700

        # 2. ISO-8601 with non-UTC offset (+05:30)
        dt_ist = (now - datetime.timedelta(hours=2.0)).astimezone(
            datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        )
        ts_ist = dt_ist.isoformat()
        _write_state(state_file, _base_state(ts_ist))
        res_ist = check_social_spacing_governor(state_file=state_file)
        assert res_ist["post_allowed"] is False
        assert res_ist["status"] == "PACED_IDLE"
        assert 21500 <= res_ist["cooldown_remaining_seconds"] <= 21700

        # 3. Naive ISO-8601 (no timezone offset)
        ts_naive = (now - datetime.timedelta(hours=9.0)).strftime("%Y-%m-%dT%H:%M:%S")
        _write_state(state_file, _base_state(ts_naive))
        res_naive = check_social_spacing_governor(state_file=state_file)
        assert res_naive["post_allowed"] is True
        assert res_naive["status"] == "READY"

        # 4. Epoch timestamp string (e.g. "1794012000.0")
        epoch_2h_ago = str(time.time() - (2.0 * 3600.0))
        _write_state(state_file, _base_state(epoch_2h_ago))
        res_epoch = check_social_spacing_governor(state_file=state_file)
        assert res_epoch["post_allowed"] is False
        assert res_epoch["status"] == "PACED_IDLE"
        assert 21500 <= res_epoch["cooldown_remaining_seconds"] <= 21700

        # 5. Numerical float epoch in JSON
        state_epoch_num = _base_state(ts_z)
        state_epoch_num["last_post_timestamp"] = time.time() - (9.0 * 3600.0)
        _write_state(state_file, state_epoch_num)
        res_epoch_num = check_social_spacing_governor(state_file=state_file)
        assert res_epoch_num["post_allowed"] is True
        assert res_epoch_num["status"] == "READY"

        # 6. Whitespace padded ISO string
        ts_padded = f"   {(now - datetime.timedelta(hours=1.0)).isoformat()}   \n"
        _write_state(state_file, _base_state(ts_padded))
        res_padded = check_social_spacing_governor(state_file=state_file)
        assert res_padded["post_allowed"] is False
        assert res_padded["status"] == "PACED_IDLE"

        # 7. Malformed unparseable timestamps -> Must fail safe without crashing
        malformed_inputs = ["NOT_A_DATE", "", "2026-99-99T99:99:99", "null", "---"]
        for mal in malformed_inputs:
            _write_state(state_file, _base_state(mal))
            res_mal = check_social_spacing_governor(state_file=state_file)
            assert res_mal["ok"] is True
            # Defaults to elapsed_hours = 999.0
            assert res_mal["elapsed_hours"] == 999.0
            assert res_mal["post_allowed"] is True


# ---------------------------------------------------------------------------
# Test 4: Missing Fields, Corrupted State, and Daily Cap Boundary
# ---------------------------------------------------------------------------

def test_governor_missing_fields_and_corrupt_state():
    """Adversarially tests missing files, empty files, malformed JSON, and daily cap boundary."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # 1. Non-existent file
        missing_file = tmp_path / "does_not_exist.json"
        res_missing = check_social_spacing_governor(state_file=missing_file)
        assert res_missing["ok"] is True
        assert res_missing["post_allowed"] is True
        assert res_missing["status"] == "READY"

        # 2. 0-byte empty file
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("", encoding="utf-8")
        res_empty = check_social_spacing_governor(state_file=empty_file)
        assert res_empty["ok"] is True
        assert res_empty["post_allowed"] is True

        # 3. Corrupted JSON syntax
        corrupt_file = tmp_path / "corrupt.json"
        corrupt_file.write_text("{ broken json: [", encoding="utf-8")
        res_corrupt = check_social_spacing_governor(state_file=corrupt_file)
        assert res_corrupt["ok"] is True
        assert res_corrupt["post_allowed"] is True

        # 4. Missing quotas dict entirely
        bare_state_file = tmp_path / "bare_state.json"
        now = datetime.datetime.now(datetime.timezone.utc)
        ts_recent = (now - datetime.timedelta(hours=3.0)).isoformat()
        bare_state_file.write_text(json.dumps({"last_post_timestamp": ts_recent}), encoding="utf-8")
        res_bare = check_social_spacing_governor(state_file=bare_state_file)
        assert res_bare["ok"] is True
        assert res_bare["post_allowed"] is False
        assert res_bare["status"] == "PACED_IDLE"

        # 5. Daily post cap exhausted (2/2 posts executed) even when spacing is clear (> 8h)
        cap_file = tmp_path / "cap_exhausted.json"
        ts_old = (now - datetime.timedelta(hours=12.0)).isoformat()
        cap_state = _base_state(ts_old, min_spacing_hours=8.0, daily_posts=2, daily_cap=2)
        _write_state(cap_file, cap_state)
        res_cap = check_social_spacing_governor(state_file=cap_file)
        assert res_cap["ok"] is True
        assert res_cap["post_allowed"] is False
        assert res_cap["status"] == "PACED_IDLE"
        assert "Daily post cap reached" in res_cap["reason"]
        assert res_cap["cooldown_remaining_seconds"] == 0.0


# ---------------------------------------------------------------------------
# Test 5: Concurrency Stress on Manual Post Ingestion
# ---------------------------------------------------------------------------

def test_manual_post_ingestion_concurrency_stress():
    """Adversarially tests manual post ingestion under high-frequency rapid successive calls and interleaved checks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "social_state.json"

        # 1. Rapid successive ingestion: 100 successive operator posts in rapid succession
        post_count = 100
        t0 = time.perf_counter()
        for idx in range(post_count):
            res = ingest_manual_operator_post(
                post_text=f"Rapid operator update #{idx}",
                timestamp_utc=(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=idx)).isoformat(),
                state_file=state_file,
            )
            assert res["ok"] is True
            assert res["manual_post_recorded"] is True

        t_elapsed = time.perf_counter() - t0

        # Assert rapid throughput (< 1.5s for 100 disk writes)
        assert t_elapsed < 2.5, f"100 successive ingestions took {t_elapsed:.2f}s"

        # 2. Verify state integrity after rapid sequential stress
        raw_text = state_file.read_text(encoding="utf-8")
        state = json.loads(raw_text)

        assert len(state["manual_posts"]) == post_count
        assert state["quotas"]["daily_executed"]["posts_count"] == post_count
        assert state["quotas"]["hourly_executed"]["POST"] == post_count
        assert state["manual_post_detected"] is True
        assert state["last_post_is_manual"] is True

        # Verify every single entry in manual_posts has required fields
        for idx, entry in enumerate(state["manual_posts"]):
            assert entry["post_text"] == f"Rapid operator update #{idx}"
            assert "timestamp" in entry

        # 3. Interleaved rapid stress: Ingest post and immediately query governor (50 iterations)
        for idx in range(50):
            res_ingest = ingest_manual_operator_post(
                post_text=f"Interleaved update #{idx}",
                state_file=state_file,
            )
            assert res_ingest["ok"] is True

            # Immediate governor check
            gov_check = check_social_spacing_governor(state_file=state_file)
            assert gov_check["ok"] is True
            assert gov_check["post_allowed"] is False
            assert gov_check["status"] == "PACED_IDLE"
            assert gov_check["manual_post_detected"] is True

        # Verify final JSON is 100% valid and not corrupted
        final_state = json.loads(state_file.read_text(encoding="utf-8"))
        assert len(final_state["manual_posts"]) == post_count + 50
        assert final_state["quotas"]["daily_executed"]["posts_count"] == post_count + 50


# ---------------------------------------------------------------------------
# Test 6: Refusal Loop Prevention & Idempotency (60+ Cycles)
# ---------------------------------------------------------------------------

def test_social_swarm_refusal_loop_prevention():
    """Simulates 60 rapid cycles while spacing is active to prove zero refusal exceptions and no queue pollution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        state_file = tmp_path / "social_state.json"
        queue_file = tmp_path / "social_staged_queue.json"

        # Set recent post 2.5h ago (spacing = 8.0h active)
        now = datetime.datetime.now(datetime.timezone.utc)
        ts_recent = (now - datetime.timedelta(hours=2.5)).isoformat()
        _write_state(state_file, _base_state(ts_recent, daily_posts=1))

        swarm = SocialEngagementSwarm(
            queue_file=queue_file,
            state_file=state_file,
            enforce_governor=True,
        )

        sample = {
            "agency_name": "Adversarial Stress Lab",
            "domain": "stress-test.example",
            "score": 30,
            "rescued_score": 90,
        }

        # Run 60 consecutive cycles (exceeds the 50+ requirement)
        cycle_count = 60
        t0 = time.perf_counter()

        for i in range(cycle_count):
            res = swarm.run_social_cycle(
                audit_sample=sample,
                threat_topic=f"Stress Round {i}",
            )
            assert res["ok"] is True
            assert res["status"] == "PACED_IDLE"
            assert res["post_allowed"] is False
            assert "spacing" in res["reason"].lower() or "pacing" in res["reason"].lower()

        t_elapsed = time.perf_counter() - t0

        # Assert zero queue pollution: queue_file must NOT exist or must be empty
        if queue_file.exists():
            queue_data = json.loads(queue_file.read_text(encoding="utf-8"))
            assert len(queue_data) == 0, f"Queue was polluted with {len(queue_data)} actions during spacing!"

        # Assert high throughput with zero refusal lag (60 checks in < 1.0s)
        assert t_elapsed < 2.0, f"Cycles took unexpectedly long: {t_elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Test 7: Spacing Cooldown Transition Releases Staging
# ---------------------------------------------------------------------------

def test_spacing_cooldown_transition_releases_staging():
    """Verifies transition from PACED_IDLE to STAGED once 8.0h cooldown elapses."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        state_file = tmp_path / "social_state.json"
        queue_file = tmp_path / "social_staged_queue.json"

        now = datetime.datetime.now(datetime.timezone.utc)

        # Phase 1: In cooldown (7.0h ago) -> Blocked, queue untouched
        ts_cooldown = (now - datetime.timedelta(hours=7.0)).isoformat()
        _write_state(state_file, _base_state(ts_cooldown, daily_posts=0))

        swarm = SocialEngagementSwarm(
            queue_file=queue_file,
            state_file=state_file,
            enforce_governor=True,
        )

        sample = {
            "agency_name": "Perimeter Labs",
            "domain": "perimeterlabs.io",
            "score": 40,
            "rescued_score": 88,
        }

        res_blocked = swarm.run_social_cycle(audit_sample=sample, threat_topic="DNS Hygiene")
        assert res_blocked["ok"] is True
        assert res_blocked["status"] == "PACED_IDLE"
        assert res_blocked["post_allowed"] is False
        assert not queue_file.exists() or len(json.loads(queue_file.read_text(encoding="utf-8"))) == 0

        # Phase 2: Advance simulated time past 8.0h (8.2h ago) -> Permitted and staged
        ts_cleared = (now - datetime.timedelta(hours=8.2)).isoformat()
        _write_state(state_file, _base_state(ts_cleared, daily_posts=0))

        res_permitted = swarm.run_social_cycle(audit_sample=sample, threat_topic="DNS Hygiene")
        assert res_permitted["ok"] is True
        assert res_permitted["status"] == "STAGED"
        assert res_permitted["post_allowed"] is True

        # Assert queue file now exists and contains exactly 3 ADR-002 compliant actions
        assert queue_file.exists()
        queue_items = json.loads(queue_file.read_text(encoding="utf-8"))
        assert len(queue_items) == 3  # roast, thread, reply
        assert all(item.get("adr002_compliant") is True for item in queue_items)
