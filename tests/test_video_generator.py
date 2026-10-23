"""Unit tests for Dynamic Video Generator (video_generator.py)."""

from pathlib import Path
import shutil
import tempfile
import pytest

from orbit_security.video_generator import VideoGenerator


@pytest.mark.skipif(
    shutil.which("ffmpeg") is None,
    reason="ffmpeg is not on PATH; video muxing is an external-tool capability, not product logic",
)
def test_generate_video_short():
    with tempfile.TemporaryDirectory() as tmpdir:
        vg = VideoGenerator(project_root=Path(tmpdir))
        vid_path, metadata = vg.generate_video_short(
            script_text="Orbit Security automated perimeter defense test.",
            title="unit_test_clip",
        )
        assert vid_path.exists()
        assert vid_path.suffix == ".mp4"
        assert vid_path.stat().st_size > 10000
        # Validate metadata
        assert "degraded_audio" in metadata
        assert "voice_backend" in metadata
        assert "dsp_applied" in metadata
        assert "output_size" in metadata
        assert metadata["output_size"] == vid_path.stat().st_size
