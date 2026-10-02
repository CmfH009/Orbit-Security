"""Empirical verification for social_state.py atomic upsert and quota deduplication."""

import time
import pytest
from orbit_security.social_state import SocialStateManager


def test_atomic_upsert_preserves_created_at_and_prevents_quota_inflation(tmp_path):
    db_file = tmp_path / "test_social_state.db"
    manager = SocialStateManager(db_path=db_file)

    # 1. First record: SUCCESS action
    first_res = manager.record_action(
        tweet_id="tweet_9999",
        action_type="REPLY",
        author_handle="target_user",
        target_domain="example.com",
        audit_score=85,
        content_snippet="First attempt",
        status="SUCCESS",
    )
    assert first_res is True

    # Check metrics
    metrics1 = manager.get_daily_metrics()
    assert metrics1["replies_count"] == 1
    assert manager.is_interacted("tweet_9999", "REPLY") is True

    # Retrieve initial creation time
    with manager._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT created_at_utc, content_snippet FROM social_actions WHERE tweet_id = ? AND action_type = ?",
            ("tweet_9999", "REPLY"),
        )
        row1 = cursor.fetchone()
        orig_created_at = row1["created_at_utc"]
        assert row1["content_snippet"] == "First attempt"

    # Wait a small moment to ensure clock tick
    time.sleep(0.05)

    # 2. Re-record same action (retry or duplicate probe)
    second_res = manager.record_action(
        tweet_id="tweet_9999",
        action_type="REPLY",
        author_handle="target_user",
        target_domain="example.com",
        audit_score=85,
        content_snippet="Second attempt update",
        status="SUCCESS",
    )
    assert second_res is True

    # Verify quota was NOT incremented again
    metrics2 = manager.get_daily_metrics()
    assert metrics2["replies_count"] == 1, "Replies count should remain 1, not inflated to 2"

    # Verify created_at_utc was preserved, but content_snippet was updated
    with manager._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT created_at_utc, content_snippet FROM social_actions WHERE tweet_id = ? AND action_type = ?",
            ("tweet_9999", "REPLY"),
        )
        row2 = cursor.fetchone()
        assert row2["created_at_utc"] == orig_created_at, "Original created_at_utc must be preserved across upsert"
        assert row2["content_snippet"] == "Second attempt update"
