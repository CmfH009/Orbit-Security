"""Hardcore stress test suite for Orbit Recursive Orchestrator (orbit-orchestrator).

Tests:
1. Deep recursion depth bounds (depth 1 to 20 without stack overflow).
2. High-throughput sequential state transitions (100+ rapid state changes).
3. Concurrent multi-threaded Blackboard SQLite WAL stress (10 threads, 500 events).
4. Adversarial corrupted inputs (malformed JSON, massive payloads, SQLi/XSS).
5. Thermal emergency spike handling & circuit recovery.
"""

import concurrent.futures
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure skills script and src are importable
SKILL_SCRIPT_DIR = Path("A:/.agents/skills/orbit-orchestrator/scripts")
if not SKILL_SCRIPT_DIR.exists():
    SKILL_SCRIPT_DIR = Path(r"C:\AgyHut\.agents\skills\orbit-orchestrator\scripts")

SYSTEM_SCRIPTS_DIR = Path("A:/system/scripts")
if not SYSTEM_SCRIPTS_DIR.exists():
    SYSTEM_SCRIPTS_DIR = Path(r"C:\AgyHut\system\scripts")

for p in (SKILL_SCRIPT_DIR, SYSTEM_SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

orbit_recursive_module = pytest.importorskip("orbit_recursive_loop", reason="orbit_recursive_loop script not present")
OrbitRecursiveOrchestrator = orbit_recursive_module.OrbitRecursiveOrchestrator
RecursiveTransition = orbit_recursive_module.RecursiveTransition
from orbit_security.blackboard import Blackboard, get_blackboard


@pytest.fixture
def temp_blackboard(tmp_path):
    """Provides an isolated SQLite WAL blackboard in a temporary directory."""
    db_file = tmp_path / "stress_blackboard.db"
    bb = Blackboard(db_path=db_file)
    return bb


# ============================================================================
# 1. Recursion Boundary & Deep Chain Stress Tests
# ============================================================================

def test_orchestrator_recursion_depth_limiter():
    """Asserts orchestrator strictly enforces max_depth bounds without infinite recursion."""
    orch = OrbitRecursiveOrchestrator(max_depth=5, dry_run=True)
    transitions = orch.execute_recursive_cycle()
    assert len(transitions) <= 5
    assert all(t.depth <= 5 for t in transitions)


def test_orchestrator_extreme_depth_budget():
    """Asserts orchestrator handles high depth budgets (depth=20) cleanly without stack overflow."""
    orch = OrbitRecursiveOrchestrator(max_depth=20, dry_run=True)
    transitions = orch.execute_recursive_cycle()
    assert len(transitions) <= 20
    for idx, t in enumerate(transitions):
        assert t.depth == idx + 1
        assert t.status == "DRY_RUN_OK"


# ============================================================================
# 2. High-Throughput Rapid Transition Stress (100 Iterations)
# ============================================================================

def test_high_throughput_rapid_state_transitions():
    """Stress tests 100 rapid state evaluations and transitions in sub-second time."""
    orch = OrbitRecursiveOrchestrator(max_depth=3, dry_run=True)
    start_time = time.perf_counter()

    for i in range(100):
        mock_state = {
            "timestamp": f"2026-10-24T05:00:{i % 60:02d}Z",
            "staged_pitches": 10,
            "verified_executives": i % 11,
            "social_status": "DRIVER_UNAVAILABLE" if i % 2 == 0 else "ACTIVE",
        }
        trans = orch.resolve_next_skill(mock_state, depth=1)
        assert trans is not None
        assert trans.source_skill in orch.ORBIT_SKILLS
        assert trans.target_skill in orch.ORBIT_SKILLS

    elapsed = time.perf_counter() - start_time
    assert elapsed < 2.0, f"100 evaluations took too long: {elapsed:.2f}s"


# ============================================================================
# 3. Concurrent Multi-Threaded Blackboard SQLite WAL Stress
# ============================================================================

def test_concurrent_multi_threaded_blackboard_hammer(temp_blackboard):
    """Hammers the SQLite WAL blackboard with 10 threads publishing 50 events concurrently (500 events)."""
    thread_count = 10
    events_per_thread = 50
    total_expected = thread_count * events_per_thread

    def worker_push(thread_id: int):
        for seq in range(events_per_thread):
            temp_blackboard.publish(
                event_type="STRESS_EVENT",
                payload={"thread": thread_id, "seq": seq, "data": "A" * 128},
                source=f"worker_{thread_id}",
                topic="stress_test"
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(worker_push, t) for t in range(thread_count)]
        for f in concurrent.futures.as_completed(futures):
            f.result()  # Re-raises exceptions if any thread failed

    # Assert exactly 500 events were safely committed to SQLite WAL
    recent = temp_blackboard.get_recent(limit=1000, event_type="STRESS_EVENT")
    assert len(recent) == total_expected, f"Expected {total_expected} events, got {len(recent)}"

    # Run database integrity check
    import sqlite3
    with sqlite3.connect(temp_blackboard.db_path) as con:
        res = con.execute("PRAGMA integrity_check;").fetchall()
        assert res == [("ok",)], f"Database corruption detected: {res}"


# ============================================================================
# 4. Adversarial Corrupted Input & Injection Handling
# ============================================================================

def test_adversarial_malformed_json_resilience(tmp_path):
    """Verifies orchestrator does not crash when manifest files contain corrupted JSON."""
    bad_manifest = tmp_path / "pilot_manifest.json"
    bad_manifest.write_text("{ this is completely corrupted json !!!", encoding="utf-8")

    orch = OrbitRecursiveOrchestrator(max_depth=3, dry_run=True)
    with patch("orbit_recursive_loop.PROJECT_ROOT", tmp_path):
        state = orch.assess_pipeline_state()
        # Should gracefully fallback to defaults
        assert state["staged_pitches"] == 0
        assert state["verified_executives"] == 0


def test_adversarial_sqli_and_xss_in_blackboard(temp_blackboard):
    """Verifies SQL injection strings and XSS vectors in event payloads are properly parameterized."""
    malicious_payloads = [
        {"input": "'; DROP TABLE events; --"},
        {"input": "<script>alert('xss')</script>"},
        {"input": "UNION SELECT id, payload FROM events WHERE '1'='1"},
        {"input": "Robert'); DROP TABLE students;--"},
        {"huge_blob": "X" * 100_000},  # 100KB payload
    ]

    for p in malicious_payloads:
        ev_id = temp_blackboard.publish(
            event_type="SECURITY_TEST",
            payload=p,
            source="adversarial_test",
            topic="security"
        )
        assert ev_id > 0

    # Ensure table wasn't dropped and events are intact
    recent = temp_blackboard.get_recent(limit=10, event_type="SECURITY_TEST")
    assert len(recent) == len(malicious_payloads)


# ============================================================================
# 5. Thermal Emergency & Backoff Handling Under Load
# ============================================================================

def test_thermal_emergency_throttle_invariance():
    """Tests orchestrator behaves safely when simulated CPU temperature hits critical levels (>=90C)."""
    mock_supervisor = MagicMock()
    mock_supervisor.services = {
        "orbit_security": MagicMock(),
        "inbox": MagicMock(),
        "dns_cache": MagicMock(),
        "ollama": MagicMock(),
        "video_generator": MagicMock(),
    }
    mock_supervisor.governor_state = {"temp_c": 94.5}

    from orbit_daemon import OrbitMasterSupervisor
    # Should throttle heavy auxiliary services without killing core services
    throttled = OrbitMasterSupervisor.emergency_thermal_protection(mock_supervisor)
    assert throttled is True

    # Core services must not have been stopped
    stopped_calls = [call[0][0] for call in mock_supervisor.stop_service.call_args_list]
    assert "orbit_security" not in stopped_calls
    assert "dns_cache" not in stopped_calls
    assert "inbox" not in stopped_calls
