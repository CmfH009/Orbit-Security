#!/usr/bin/env python3
"""Tests for twice-a-day post scaling and continuous engagement pacing."""

import datetime
import pytest
from unittest.mock import MagicMock, patch

from orbit_security.quota_manager import QuotaBudget, SocialQuotaManager
from orbit_security.social_daemon import SocialDaemon
from orbit_security.social_state import SocialStateManager


@pytest.fixture
def temp_state_manager(tmp_path):
    return SocialStateManager(
        db_path=tmp_path / "test_pacing.db",
        json_export_path=tmp_path / "test_pacing.json",
    )


def test_quota_budget_defaults():
    """Verify that posting is scaled to 2 per day with 8-hour spacing by default."""
    budget = QuotaBudget()
    assert budget.max_daily_posts == 2
    assert budget.min_post_spacing_hours == 8.0
    assert budget.max_hourly_posts == 1
    # Automated follows and replies are permanently disabled to prevent account flags
    assert budget.max_daily_replies == 0
    assert budget.max_daily_follows == 0
    assert budget.max_daily_likes == 50
    assert budget.max_daily_reposts == 10


def test_post_spacing_and_daily_cap(temp_state_manager):
    """Verify post spacing prevents clustering and daily cap restricts to exactly 2 posts."""
    quota_mgr = SocialQuotaManager(state_manager=temp_state_manager)

    # Initially, no posts recorded -> POST is permitted
    assert quota_mgr.can_perform("POST") is True

    # Record first post at T = 0
    t0 = datetime.datetime.now(datetime.timezone.utc)
    temp_state_manager.record_action(
        tweet_id="post_1",
        action_type="POST",
        status="SUCCESS",
        metadata={"created_at_utc": t0.isoformat()},
    )
    quota_mgr.record_hourly_action("POST")

    # Immediate second post in the same cycle/hour -> blocked by hourly burst and spacing
    assert quota_mgr.can_perform("POST") is False

    # Reset hourly burst (simulate next cycle 2 hours later)
    quota_mgr.reset_hourly_cycle()

    # Still blocked by 8-hour inter-post spacing!
    assert quota_mgr.can_perform("POST") is False

    # BUT follows and replies (comments) are disabled, while likes and reposts are permitted!
    assert quota_mgr.can_perform("FOLLOW") is False
    assert quota_mgr.can_perform("REPLY") is False
    assert quota_mgr.can_perform("LIKE") is True
    assert quota_mgr.can_perform("REPOST") is True

    # Simulate 8.5 hours passing since post 1
    t_later = t0 + datetime.timedelta(hours=8.5)
    quota_mgr._get_now_utc = lambda: t_later

    # Now second post of the day is permitted!
    assert quota_mgr.can_perform("POST") is True

    # Record second post
    temp_state_manager.record_action(
        tweet_id="post_2",
        action_type="POST",
        status="SUCCESS",
        metadata={"created_at_utc": (t0 + datetime.timedelta(hours=9)).isoformat()},
    )
    quota_mgr.record_hourly_action("POST")

    # Reset hourly burst again
    quota_mgr.reset_hourly_cycle()

    # Even 10 hours after second post, daily cap (2) is reached for the day!
    t_evening = t0 + datetime.timedelta(hours=19)
    quota_mgr._get_now_utc = lambda: t_evening

    # 3rd post is blocked by max_daily_posts == 2
    assert quota_mgr.can_perform("POST") is False

    # Yet likes and reposts continue while follows and replies are disabled
    assert quota_mgr.can_perform("FOLLOW") is False
    assert quota_mgr.can_perform("REPLY") is False
    assert quota_mgr.can_perform("LIKE") is True
    assert quota_mgr.can_perform("REPOST") is True


def test_daemon_continues_other_activities_when_post_blocked(tmp_path):
    """Verify that SocialDaemon continues harvesting and liking even when POST is blocked."""
    sm = SocialStateManager(
        db_path=tmp_path / "test_social_cont.db",
        json_export_path=tmp_path / "test_social_cont.json",
    )
    # Pre-record 2 posts today so POST quota is already maxed out
    for i in range(2):
        sm.record_action(
            tweet_id=f"prior_post_{i}",
            action_type="POST",
            status="SUCCESS",
        )

    daemon = SocialDaemon(
        nominal_interval_seconds=3600,
        dry_run=True,
        state_file=tmp_path / "daemon_state.json",
        state_manager=sm,
    )

    # Verify quota manager sees POST as blocked
    assert daemon.quota_manager.can_perform("POST") is False
    assert daemon.quota_manager.can_perform("FOLLOW") is False
    assert daemon.quota_manager.can_perform("REPLY") is False
    assert daemon.quota_manager.can_perform("LIKE") is True

    # Execute cycle
    res = daemon.execute_hourly_cycle()
    assert res["status"] == "COMPLETED"
    # Actions like likes/reposts/replies/follows are performed despite 0 posts
    assert res["actions_count"] >= 1

    # Verify no new POST was made today (still exactly 2)
    daily = sm.get_daily_metrics()
    assert daily["posts_count"] == 2
