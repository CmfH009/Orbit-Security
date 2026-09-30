#!/usr/bin/env python3
"""End-to-end integration tests for SocialDaemon."""

import pytest
from orbit_security.circuit_breaker import BreakerState
from orbit_security.social_daemon import SocialDaemon


@pytest.fixture
def dry_daemon():
    return SocialDaemon(nominal_interval_seconds=3600, dry_run=True)


def test_daemon_hourly_cycle_dry_run(dry_daemon):
    """Verifies that SocialDaemon completes an hourly cycle without errors in dry-run mode."""
    result = dry_daemon.execute_hourly_cycle()
    assert result["status"] == "COMPLETED"
    assert result["actions_count"] >= 1
    assert result["duration_seconds"] >= 0.0

    # Verify state persistence
    summary = dry_daemon.quota_manager.get_status_summary()
    assert summary is not None

    # Verify circuit breaker is healthy
    assert dry_daemon.circuit_breaker.state == BreakerState.CLOSED


def test_daemon_status_and_snapshot(dry_daemon):
    """Verifies status snapshot export."""
    snapshot = dry_daemon.state_manager.export_json_snapshot()
    assert "today_metrics" in snapshot
    assert "current_utc_date" in snapshot
    assert "last_updated_utc" in snapshot
