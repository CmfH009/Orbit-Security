"""Unit tests for Creative Copy & Media Engine (creative_engine.py)."""

from pathlib import Path
import tempfile
import pytest

from orbit_security.creative_engine import CreativeEngine, POST_BLUEPRINTS
from orbit_security.marketing_strategy import ContentPillar


def test_post_blueprints_validity():
    assert len(POST_BLUEPRINTS) >= 5
    for bp in POST_BLUEPRINTS:
        assert "id" in bp
        assert "text" in bp
        assert "pillar" in bp
        assert isinstance(bp["pillar"], ContentPillar)
        # Verify text contains Orbit URL
        assert "https://cmfh009.github.io/Orbit-Security/" in bp["text"]


def test_generate_next_post_with_media():
    with tempfile.TemporaryDirectory() as tmpdir:
        ce = CreativeEngine(project_root=Path(tmpdir))
        post = ce.generate_next_post()
        assert post.id is not None
        assert len(post.text) > 50
        assert post.hook_score >= 0.50
        if post.media_path:
            assert Path(post.media_path).exists()


def test_generate_next_post_filter_by_pillar():
    with tempfile.TemporaryDirectory() as tmpdir:
        ce = CreativeEngine(project_root=Path(tmpdir))
        post = ce.generate_next_post(target_pillar=ContentPillar.BREAK_AND_FIX)
        assert post.pillar == ContentPillar.BREAK_AND_FIX
