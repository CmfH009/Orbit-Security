"""Unit tests for Dynamic Video Generator (video_generator.py)."""

from pathlib import Path
import tempfile
import pytest

from orbit_security.video_generator import VideoGenerator


def test_generate_video_short():
    with tempfile.TemporaryDirectory() as tmpdir:
        vg = VideoGenerator(project_root=Path(tmpdir))
        vid_path = vg.generate_video_short(
            script_text="Orbit Security automated perimeter defense test.",
            title="unit_test_clip",
        )
        assert vid_path.exists()
        assert vid_path.suffix == ".mp4"
        assert vid_path.stat().st_size > 10000
