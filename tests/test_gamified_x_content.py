#!/usr/bin/env python3
"""
Test Suite for Orbit Security Gamified Infosec Stack & Cyber Arcade X Content Staging
Empirical verification of character limits, Twitter v3 compliance, media paths,
prospect domain exclusion, and DraftManager integration.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
import pytest

from orbit_security.draft_manager import DraftManager, SocialDraft
from scripts.stage_gamified_showcase_x import (
    ALL_POSTS,
    MASTER_THREAD_POSTS,
    STANDALONE_POSTS,
    HELD_VARIANTS,
    twitter_v3_char_count,
    x_standard_weighted_length,
    verify_all_posts,
    export_validation_manifest,
    stage_to_drafts,
)
from scripts.validate_x_post_lengths import (
    validate_manifest,
    load_manifest,
    THIRD_PARTY_DOMAINS,
    X_LIMIT,
)
from scripts.stage_x_thread import verify_thread as verify_original_thread

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_original_stage_x_thread_passes_verification():
    """Confirms the master 7-part dangling CNAME thread passes Twitter v3 character audit."""
    assert verify_original_thread() is True, "Original 7-part thread should pass <= 280 chars"


def test_gamified_showcase_post_counts():
    """Verifies that all 12 showcase posts (8 thread + 4 standalone) exist."""
    assert len(MASTER_THREAD_POSTS) == 8, "Expected 8 master thread tweets"
    assert len(STANDALONE_POSTS) == 4, "Expected 4 standalone pillar posts"
    assert len(ALL_POSTS) == 12, "Expected 12 total showcase posts"


@pytest.mark.parametrize("post", ALL_POSTS, ids=lambda p: p["id"])
def test_each_post_within_x_limits(post):
    """Verifies that each post complies with both Twitter v3 and X standard weighted limits."""
    text = post["text"]
    v3_count, raw_len, url_count = twitter_v3_char_count(text)
    x_std_count = x_standard_weighted_length(text)

    assert v3_count <= X_LIMIT, (
        f"Post [{post['id']}] exceeds Twitter v3 limit: {v3_count} > {X_LIMIT}"
    )
    assert x_std_count <= X_LIMIT, (
        f"Post [{post['id']}] exceeds X standard limit: {x_std_count} > {X_LIMIT}"
    )
    # Ensure comfortable positive headroom of at least 10 characters
    assert (X_LIMIT - v3_count) >= 10, (
        f"Post [{post['id']}] has dangerously tight v3 headroom: {X_LIMIT - v3_count}"
    )
    assert (X_LIMIT - x_std_count) >= 10, (
        f"Post [{post['id']}] has dangerously tight X-std headroom: {X_LIMIT - x_std_count}"
    )


@pytest.mark.parametrize("post", ALL_POSTS, ids=lambda p: p["id"])
def test_no_third_party_domains_in_posts(post):
    """Ensures no private third-party client domains leak into marketing copy."""
    lowered = post["text"].lower()
    for domain in THIRD_PARTY_DOMAINS:
        assert domain not in lowered, (
            f"Post [{post['id']}] mentions restricted third-party client domain: {domain}"
        )


@pytest.mark.parametrize("post", ALL_POSTS, ids=lambda p: p["id"])
def test_media_assets_exist(post):
    """Verifies that every attached media asset exists on the physical filesystem."""
    attachment = post.get("attachment")
    assert attachment is not None, f"Post [{post['id']}] has no media attachment specified"
    p = Path(attachment)
    assert p.exists(), f"Post [{post['id']}] media file missing on disk: {attachment}"
    assert p.stat().st_size > 0, f"Post [{post['id']}] media file is 0 bytes: {attachment}"


def test_core_features_coverage():
    """
    Confirms that all 4 newly implemented conversion & gamified features are explicitly covered
    in the staged posts:
    1. 16-Subdomain DoH Perimeter Scanner (orbit_radar.js)
    2. Visual Attack Tree & Takeover Simulator
    3. White-Label Agency Portal Customizer
    4. Astro-Cat Chief Perimeter Sentinel & Arcade Defense Mode
    """
    all_text = " ".join(p["text"] for p in ALL_POSTS)

    # Feature 1: DoH Perimeter Scanner
    assert "DoH" in all_text
    assert "RFC 8484" in all_text
    assert "RFC 7505" in all_text or "Null-MX" in all_text
    assert "PDF" in all_text

    # Feature 2: Visual Attack Tree & Takeover Simulator
    assert "Attack Tree" in all_text
    assert "Simulator" in all_text or "Simulate" in all_text
    assert "#simulate" in all_text

    # Feature 3: White-Label Agency Portal Customizer
    assert "Customizer" in all_text or "customizer" in all_text
    assert "WCAG" in all_text
    assert "orbit-core.html" in all_text
    assert "$250/mo" in all_text

    # Feature 4: Astro-Cat & Arcade Defense
    assert "Astro-Cat" in all_text
    assert "Web Audio" in all_text
    assert "Arcade Defense" in all_text
    assert "#arcadeDefense" in all_text


def test_validation_manifest_export_and_checker(tmp_path):
    """Verifies export_validation_manifest and tests it against validate_x_post_lengths."""
    manifest_path = tmp_path / "test_manifest.json"
    out = export_validation_manifest(out_path=manifest_path)
    assert out.exists()

    manifest_data = load_manifest(out)
    report = validate_manifest(manifest_data, manifest_path=out)

    assert report["ok"] is True, f"Validation failures: {report.get('failures')}"
    assert report["post_count"] == 12
    assert report["held_count"] == len(HELD_VARIANTS)
    assert len(report["failures"]) == 0


def test_draft_manager_integration(tmp_path):
    """Verifies that staged showcase drafts cleanly hydrate into DraftManager with compliant character counts."""
    dm = DraftManager(project_root=REPO_ROOT)
    drafts = dm.list_drafts()
    draft_ids = {d.id for d in drafts}

    for p in ALL_POSTS:
        assert p["id"] in draft_ids, f"Post [{p['id']}] missing from DraftManager active deck"

    # Assert EVERY draft in DraftManager respects character limit
    for draft in drafts:
        assert draft.character_count <= X_LIMIT, (
            f"Draft [{draft.id}] character_count exceeds limit: {draft.character_count} > {X_LIMIT}"
        )

    # Verify manifest.json on disk has compliant stored character counts
    manifest_path = REPO_ROOT / "data" / "drafts" / "manifest.json"
    assert manifest_path.exists()
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
    for d in manifest_data.get("drafts", []):
        stored_count = d.get("character_count")
        assert stored_count is not None
        assert stored_count <= X_LIMIT, (
            f"Stored character_count in manifest.json exceeds {X_LIMIT} for draft [{d.get('id')}]: {stored_count}"
        )

    # Verify DRAFTS.md contains NO character count violations (> 280)
    deck_path = REPO_ROOT / "data" / "drafts" / "DRAFTS.md"
    assert deck_path.exists()
    deck_text = deck_path.read_text(encoding="utf-8")
    char_matches = re.findall(r"- \*\*Characters:\*\* `(\d+)/280`", deck_text)
    assert len(char_matches) > 0, "No character counters found in DRAFTS.md"
    for count_str in char_matches:
        count = int(count_str)
        assert count <= X_LIMIT, f"Found violating character count in DRAFTS.md: {count}/280"

    # Verify media assets staged into data/drafts/media/
    media_dir = REPO_ROOT / "data" / "drafts" / "media"
    assert media_dir.exists()
    for p in ALL_POSTS:
        att = p.get("attachment")
        if att:
            staged_file = media_dir / Path(att).name
            assert staged_file.exists(), f"Draft media missing from data/drafts/media/: {staged_file}"
            assert staged_file.stat().st_size > 0, f"Draft media is empty: {staged_file}"


def test_social_draft_weighted_character_count():
    """Tests that SocialDraft.character_count correctly weights URLs to 23 chars."""
    short_url_post = SocialDraft(
        id="test_url_weight",
        title="Test URL Weight",
        text="Check out https://cmfh009.github.io/Orbit-Security/ for live scanning.",
    )
    # "Check out " (10) + URL (23) + " for live scanning." (19) = 52
    assert short_url_post.character_count == 52
