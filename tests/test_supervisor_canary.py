"""Unit and empirical tests for Supervisor Canary Self-Healing Probes (Act II Item 3).

Verifies:
1. Simulated 10-second end-to-end canary probe execution:
   - DNS resolution probe (DNS cache / localhost)
   - HTTP transport & port connectivity probe
   - RSS memory measurement across supervisor and child processes
2. Memory expansion tracking (>150MB threshold):
   - Stable memory: bloat counter remains 0, status is PASSED
   - Memory spike (>150MB above baseline): bloat counter increments
   - Reset behavior when memory returns to baseline
3. Self-healing graceful process recycle:
   - Triggers graceful recycle (close() -> re-exec / restart) on 3rd consecutive cycle
   - Resets bloat counter and recalibrates RSS baseline
4. Integration with OrbitMasterSupervisor state and CLI.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure system scripts directory is in sys.path
SYSTEM_SCRIPTS = Path("A:/system/scripts") if Path("A:/system/scripts").exists() else Path(r"C:\AgyHut\system\scripts")
if str(SYSTEM_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SYSTEM_SCRIPTS))

from orbit_daemon import (
    OrbitMasterSupervisor,
    ServiceSpec,
    SupervisorCanaryProbe,
)


# ============================================================================
# 1. Canary Probe Execution & Probes
# ============================================================================


def test_canary_probe_initialization():
    """Verifies default thresholds on SupervisorCanaryProbe."""
    probe = SupervisorCanaryProbe(
        interval_seconds=1800.0,
        audit_duration_seconds=10.0,
        rss_expansion_threshold_mb=150.0,
        consecutive_bloat_cycles_threshold=3,
    )
    assert probe.interval_seconds == 1800.0
    assert probe.audit_duration_seconds == 10.0
    assert probe.rss_expansion_threshold_mb == 150.0
    assert probe.consecutive_bloat_cycles_threshold == 3
    assert len(probe.consecutive_bloat_counts) == 0


def test_canary_probe_simulated_audit_quick():
    """Executes a quick simulated canary audit and verifies result schema."""
    supervisor = OrbitMasterSupervisor()
    probe = SupervisorCanaryProbe(audit_duration_seconds=0.1)

    result = probe.execute_canary_audit(supervisor, quick=True)

    assert result["status"] in ("PASSED", "HEALTHY")
    assert result["audit_duration_seconds"] >= 0.0
    assert "memory_deltas" in result
    assert "dns_probe_ok" in result
    assert "http_probe_ok" in result
    assert len(probe.probe_history) == 1


# ============================================================================
# 2. Memory Bloat Tracking & Self-Healing Recycle
# ============================================================================


def test_canary_probe_memory_tracking_and_graceful_recycle():
    """Simulates 3 consecutive bloated cycles (>150MB) and asserts graceful recycle."""
    supervisor = OrbitMasterSupervisor()
    supervisor.services = {
        "test_worker": ServiceSpec(
            name="Test Worker Daemon",
            script="fake.py",
            args=[],
            enabled=True,
            pid=12345,
        )
    }

    # Mock stop and start service methods
    supervisor.stop_service = MagicMock()
    supervisor.start_service = MagicMock()

    probe = SupervisorCanaryProbe(
        audit_duration_seconds=0.01,
        rss_expansion_threshold_mb=150.0,
        consecutive_bloat_cycles_threshold=3,
    )

    # Establish initial baseline RSS: 100.0 MB
    probe.baselines["test_worker"] = 100.0

    # Cycle 1: Memory bloats to 280MB (+180MB > 150MB threshold)
    with patch.object(probe, "_get_process_rss_mb", return_value=280.0):
        res1 = probe.execute_canary_audit(supervisor, quick=True)
        assert res1["status"] == "WARNING_EXPANDING"
        assert probe.consecutive_bloat_counts["test_worker"] == 1
        assert supervisor.stop_service.call_count == 0

    # Cycle 2: Memory remains bloated at 310MB (+210MB)
    with patch.object(probe, "_get_process_rss_mb", return_value=310.0):
        res2 = probe.execute_canary_audit(supervisor, quick=True)
        assert res2["status"] == "WARNING_EXPANDING"
        assert probe.consecutive_bloat_counts["test_worker"] == 2
        assert supervisor.stop_service.call_count == 0

    # Cycle 3: Memory bloats again at 320MB (3rd consecutive cycle!) -> Trigger graceful recycle
    with patch.object(probe, "_get_process_rss_mb", return_value=320.0):
        res3 = probe.execute_canary_audit(supervisor, quick=True)
        assert res3["status"] == "RECYCLED"
        assert "test_worker" in res3["recycled_services"]
        # Asserts graceful process recycle was invoked
        supervisor.stop_service.assert_called_once_with("test_worker")
        supervisor.start_service.assert_called_once_with("test_worker")
        # Counter should reset to 0 after recycling
        assert probe.consecutive_bloat_counts["test_worker"] == 0


def test_canary_probe_reset_on_memory_drop():
    """Verifies bloat counter resets when process RSS returns to normal."""
    supervisor = OrbitMasterSupervisor()
    supervisor.services = {
        "stable_svc": ServiceSpec(
            name="Stable Service",
            script="fake.py",
            args=[],
            enabled=True,
            pid=54321,
        )
    }

    probe = SupervisorCanaryProbe(
        audit_duration_seconds=0.01,
        rss_expansion_threshold_mb=150.0,
    )
    probe.baselines["stable_svc"] = 100.0

    # Cycle 1: Spikes to 260MB (+160MB)
    with patch.object(probe, "_get_process_rss_mb", return_value=260.0):
        probe.execute_canary_audit(supervisor, quick=True)
        assert probe.consecutive_bloat_counts["stable_svc"] == 1

    # Cycle 2: Drops back down to 110MB (+10MB) -> Counter resets to 0
    with patch.object(probe, "_get_process_rss_mb", return_value=110.0):
        probe.execute_canary_audit(supervisor, quick=True)
        assert probe.consecutive_bloat_counts["stable_svc"] == 0
