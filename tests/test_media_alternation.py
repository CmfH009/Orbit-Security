"""Unit & Integration tests for media alternation and anti-repetition generation.

Verifies:
1. Strict alternation: IMAGE -> VIDEO -> IMAGE -> VIDEO across sequential posts.
2. Anti-repetition: If media was recently posted, a fresh asset is autonomously synthesized.
3. Zero naked link posts: All posts have an explicit media attachment to avoid generic OG cards.
4. Metadata persistence: media_type and media_path recorded in SQLite state.
"""

import os
from pathlib import Path
import tempfile
import pytest

from orbit_security.creative_engine import CreativeEngine
from orbit_security.content_queue import ContentQueue
from orbit_security.social_state import SocialStateManager
from orbit_security.social_daemon import SocialDaemon
from orbit_security.media_generator import MediaGenerator


@pytest.fixture
def temp_env():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "test_social.db"
        json_path = tmp_path / "test_social_history.json"
        sm = SocialStateManager(db_path=db_path, json_export_path=json_path)
        yield {
            "root": tmp_path,
            "db_path": db_path,
            "json_path": json_path,
            "state_manager": sm,
        }


def test_media_metadata_recording_and_retrieval(temp_env):
    sm = temp_env["state_manager"]

    # 1. Record an image post
    sm.record_action(
        tweet_id="post_img_1",
        action_type="POST",
        status="SUCCESS",
        metadata={"media_path": "assets/test_img_1.jpg", "media_type": "image"},
    )

    last_info = sm.get_last_post_media_info()
    assert last_info is not None
    assert last_info["tweet_id"] == "post_img_1"
    assert last_info["media_type"] == "image"
    assert last_info["media_path"] == "assets/test_img_1.jpg"

    recent = sm.get_recent_media_paths()
    assert "test_img_1.jpg" in recent

    # 2. Record a video post
    sm.record_action(
        tweet_id="post_vid_1",
        action_type="POST",
        status="SUCCESS",
        metadata={"media_path": "assets/test_vid_1.mp4", "media_type": "video"},
    )

    last_info_2 = sm.get_last_post_media_info()
    assert last_info_2["tweet_id"] == "post_vid_1"
    assert last_info_2["media_type"] == "video"

    recent_2 = sm.get_recent_media_paths()
    assert "test_vid_1.mp4" in recent_2
    assert "test_img_1.jpg" in recent_2


def test_content_queue_strict_alternation(temp_env):
    sm = temp_env["state_manager"]
    cq = ContentQueue()

    # Post 1: First item in queue
    p1 = cq.get_next_queued_post(sm, allow_generative=True)
    assert p1 is not None
    t1 = p1["media_type"]
    assert t1 in ("image", "video")
    assert p1["media_path"] is not None
    assert Path(p1["media_path"]).exists()

    # Simulate posting p1
    sm.record_action(
        tweet_id=p1["id"],
        action_type="POST",
        status="SUCCESS",
        metadata={"media_path": p1["media_path"], "media_type": t1},
    )

    # Post 2: Must be opposite of t1
    p2 = cq.get_next_queued_post(sm, allow_generative=True)
    assert p2 is not None
    t2 = p2["media_type"]
    assert t2 in ("image", "video")
    assert t2 != t1, f"Expected alternation from {t1}, got {t2}"
    assert p2["media_path"] is not None
    assert Path(p2["media_path"]).exists()

    # Simulate posting p2
    sm.record_action(
        tweet_id=p2["id"],
        action_type="POST",
        status="SUCCESS",
        metadata={"media_path": p2["media_path"], "media_type": t2},
    )

    # Post 3: Must be opposite of t2 (same as t1)
    p3 = cq.get_next_queued_post(sm, allow_generative=True)
    assert p3 is not None
    t3 = p3["media_type"]
    assert t3 == t1, f"Expected alternation back to {t1}, got {t3}"
    assert p3["media_path"] is not None
    assert Path(p3["media_path"]).exists()

    # Assert p1 and p3 don't reuse the exact same media
    assert Path(p1["media_path"]).name != Path(p3["media_path"]).name


def test_anti_repetition_dynamic_generation(temp_env):
    sm = temp_env["state_manager"]
    cq = ContentQueue()

    # Pre-populate recent media with the static image that caused the issue
    sm.record_action(
        tweet_id="legacy_post_1",
        action_type="POST",
        status="SUCCESS",
        metadata={"media_path": "orbit_cats_pounce.jpg", "media_type": "video"},
    )
    sm.record_action(
        tweet_id="legacy_post_2",
        action_type="POST",
        status="SUCCESS",
        metadata={"media_path": "orbit_cname_blackhole.jpg", "media_type": "video"},
    )

    # Next post must be an image
    next_post = cq.get_next_queued_post(sm, allow_generative=True)
    assert next_post is not None
    assert next_post["media_type"] == "image"
    # Guaranteed not to be orbit_cname_blackhole.jpg or orbit_cats_pounce.jpg
    assert Path(next_post["media_path"]).name != "orbit_cname_blackhole.jpg"
    assert Path(next_post["media_path"]).name != "orbit_cats_pounce.jpg"
    assert Path(next_post["media_path"]).exists()


def test_social_daemon_dry_run_cycle_alternation(temp_env):
    sm = temp_env["state_manager"]
    daemon = SocialDaemon(
        nominal_interval_seconds=3600,
        dry_run=True,
        state_file=temp_env["root"] / "daemon_state.json",
    )
    daemon.state_manager = sm
    daemon.content_queue = ContentQueue()
    daemon.force_cycle = True

    # Run publication 1
    res1 = daemon.publish_original_post(text="Post 1 Test")
    assert res1["status"] == "SUCCESS"
    t1 = res1.get("media_type")

    # Reset hourly quota to simulate next cycle
    daemon.quota_manager.reset_hourly_cycle()

    # Run publication 2
    res2 = daemon.publish_original_post(text="Post 2 Test")
    assert res2["status"] == "SUCCESS"
    t2 = res2.get("media_type")

    # Verify alternation
    assert t1 != t2, f"Expected media alternation, but got {t1} then {t2}"
