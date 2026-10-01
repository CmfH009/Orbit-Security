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


def test_daemon_live_mode_driver_protection():
    """Verifies that live mode does not fabricate actions when driver is missing."""
    daemon = SocialDaemon(nominal_interval_seconds=3600, dry_run=False, driver=None)
    # Force driver to None (simulate unavailable driver environment)
    daemon.driver = None
    daemon._ensure_driver = lambda: None

    res = daemon.publish_original_post(text="Test post without driver")
    assert res["status"] == "DRIVER_UNAVAILABLE"

    cycle_res = daemon.execute_hourly_cycle()
    assert cycle_res["status"] == "DRIVER_UNAVAILABLE"


def test_daemon_follow_user_mock():
    """Verifies that follow_user calls driver when available."""
    from orbit_security.desktop_x_bridge import DesktopAutomationDriver
    mock_drv = DesktopAutomationDriver(mock_mode=True)
    daemon = SocialDaemon(nominal_interval_seconds=3600, dry_run=False, driver=mock_drv)

    # Test single follow execution
    assert hasattr(daemon.driver, "follow_user")
    ok = daemon.driver.follow_user("testuser")
    assert ok is True
    assert any(a["action"] == "follow_user" for a in mock_drv.action_history)

