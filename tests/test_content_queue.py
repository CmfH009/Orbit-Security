"""Unit tests for Orbit Security ContentQueue & Staged Social Post Rotation."""

import sqlite3
from pathlib import Path
import pytest

from orbit_security.content_queue import ContentQueue
from orbit_security.social_state import SocialStateManager


@pytest.fixture
def temp_state_manager(tmp_path):
    db_file = tmp_path / "test_social.db"
    json_file = tmp_path / "test_social.json"
    mgr = SocialStateManager(db_path=db_file, json_export_path=json_file)
    return mgr


def test_content_queue_loading():
    queue = ContentQueue()
    assert len(queue.items) >= 14
    
    # Check trilogy
    trilogy_items = [it for it in queue.items if it["category"] == "video_trilogy"]
    assert len(trilogy_items) == 3
    assert trilogy_items[0]["id"] == "video_trilogy_1"
    assert "Astro-Cat" in trilogy_items[0]["title"]
    
    # Check thread
    thread_items = [it for it in queue.items if it["category"] == "master_thread"]
    assert len(thread_items) == 7
    assert thread_items[0]["id"] == "cname_thread_1"
    assert thread_items[6]["id"] == "cname_thread_7"

    # Check evergreen
    evergreen_items = [it for it in queue.items if it["category"] == "evergreen"]
    assert len(evergreen_items) >= 4


def test_content_queue_sequential_rotation(temp_state_manager):
    queue = ContentQueue()
    
    # 1. First item should be video_trilogy_1
    p1 = queue.get_next_queued_post(temp_state_manager)
    assert p1 is not None
    assert p1["id"] == "video_trilogy_1"
    
    # Record success for p1
    temp_state_manager.record_action(
        tweet_id=p1["id"],
        action_type="POST",
        author_handle="_arsoncode",
        status="SUCCESS"
    )
    
    # 2. Second item should be video_trilogy_2
    p2 = queue.get_next_queued_post(temp_state_manager)
    assert p2 is not None
    assert p2["id"] == "video_trilogy_2"
    
    # Record success for p2
    temp_state_manager.record_action(
        tweet_id=p2["id"],
        action_type="POST",
        author_handle="_arsoncode",
        status="SUCCESS"
    )
    
    # 3. Third item should be video_trilogy_3
    p3 = queue.get_next_queued_post(temp_state_manager)
    assert p3 is not None
    assert p3["id"] == "video_trilogy_3"
    
    temp_state_manager.record_action(
        tweet_id=p3["id"],
        action_type="POST",
        author_handle="_arsoncode",
        status="SUCCESS"
    )
    
    # 4. Fourth item should be cname_thread_1
    p4 = queue.get_next_queued_post(temp_state_manager)
    assert p4 is not None
    assert p4["id"] == "cname_thread_1"


def test_content_queue_evergreen_wrap_around(temp_state_manager):
    queue = ContentQueue()
    
    # Mark all base items as posted
    for item in queue.items:
        temp_state_manager.record_action(
            tweet_id=item["id"],
            action_type="POST",
            author_handle="_arsoncode",
            status="SUCCESS"
        )
        
    # Queue should now rotate to evergreen with _r1 suffix
    next_item = queue.get_next_queued_post(temp_state_manager)
    assert next_item is not None
    assert next_item["id"].endswith("_r1")
    assert next_item["category"] == "evergreen"
