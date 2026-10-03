#!/usr/bin/env python3
"""Unit tests for Orbit Security DraftManager and on-demand dispatch."""

import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from orbit_security.draft_manager import DraftManager, SocialDraft


@pytest.fixture
def temp_draft_manager(tmp_path):
    # Setup mock creative engine and queue to avoid heavy model generation during tests
    dm = DraftManager(project_root=tmp_path)
    return dm


def test_draft_manifest_lifecycle(temp_draft_manager, tmp_path):
    dm = temp_draft_manager
    draft = SocialDraft(
        id="test_draft_1",
        title="RFC 7489 Breakdown",
        text="DMARC p=reject is your defense against domain spoofing. 🧵",
        pillar="break_and_fix",
        status="DRAFT",
    )
    dm._drafts[draft.id] = draft
    dm._save_manifest()

    assert dm.manifest_file.exists()
    assert dm.deck_file.exists()

    with open(dm.manifest_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_drafts"] == 1
    assert data["pending_drafts"] == 1
    assert data["drafts"][0]["id"] == "test_draft_1"

    # Reload from disk
    dm2 = DraftManager(project_root=tmp_path)
    loaded = dm2.get_draft("test_draft_1")
    assert loaded is not None
    assert loaded.title == "RFC 7489 Breakdown"


def test_mark_posted(temp_draft_manager):
    dm = temp_draft_manager
    draft = SocialDraft(
        id="test_draft_mark",
        title="Dangling CNAME Warning",
        text="Clean up your dangling DNS records.",
        status="DRAFT",
    )
    dm._drafts[draft.id] = draft
    dm._save_manifest()

    ok = dm.mark_posted("test_draft_mark")
    assert ok is True
    updated = dm.get_draft("test_draft_mark")
    assert updated.status == "POSTED"
    assert updated.posted_at_utc is not None


def test_send_next_draft_with_desktop_automation(temp_draft_manager):
    dm = temp_draft_manager
    draft = SocialDraft(
        id="draft_auto_1",
        title="Subdomain Takeover Anatomy",
        text="Anatomy of a dangling CNAME.",
        status="DRAFT",
    )
    dm._drafts[draft.id] = draft
    dm._save_manifest()

    mock_driver = MagicMock()
    mock_driver.is_available.return_value = True
    mock_driver.post_tweet.return_value = True

    with patch("orbit_security.desktop_x_bridge.DesktopAutomationDriver", return_value=mock_driver):
        res = dm.send_next_draft()

    assert res["success"] is True
    assert res["draft_id"] == "draft_auto_1"
    assert res["mode"] == "DESKTOP_AUTOMATION"
    mock_driver.post_tweet.assert_called_once()

    updated = dm.get_draft("draft_auto_1")
    assert updated.status == "POSTED"


def test_send_next_draft_fallback_browser(temp_draft_manager):
    dm = temp_draft_manager
    draft = SocialDraft(
        id="draft_fallback_1",
        title="DNS Drift Defense",
        text="Catching DNS drift in under 800ms.",
        status="DRAFT",
    )
    dm._drafts[draft.id] = draft
    dm._save_manifest()

    mock_driver = MagicMock()
    mock_driver.is_available.return_value = False

    with patch("orbit_security.desktop_x_bridge.DesktopAutomationDriver", return_value=mock_driver):
        with patch("webbrowser.open") as mock_web_open:
            with patch.object(dm, "copy_to_clipboard", return_value=True):
                res = dm.send_next_draft()

    assert res["success"] is True
    assert res["draft_id"] == "draft_fallback_1"
    assert res["mode"] == "OPERATOR_COMPOSER_CLIPBOARD"
    mock_web_open.assert_called_once_with("https://x.com/compose/post")

    updated = dm.get_draft("draft_fallback_1")
    assert updated.status == "POSTED"
