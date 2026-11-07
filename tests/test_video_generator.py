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


def test_degraded_audio_raises_error_when_not_allowed():
    """W4.3: Degraded TTS assets must raise DegradedAudioError and never publish silently."""
    from unittest.mock import MagicMock, patch
    from orbit_security.video_generator import DegradedAudioError

    with tempfile.TemporaryDirectory() as tmpdir:
        vg = VideoGenerator(project_root=Path(tmpdir))
        with patch.object(vg.voice_engine, "synthesize_speech", side_effect=RuntimeError("TTS engine unreachable")):
            with pytest.raises(DegradedAudioError) as exc_info:
                vg.generate_video_short(
                    script_text="Test narration that should fail",
                    title="fail_clip",
                    allow_degraded=False,
                )
            assert "Voice narration failed" in str(exc_info.value)
            assert "degraded assets can never be published" in str(exc_info.value)


@pytest.mark.skipif(
    shutil.which("ffmpeg") is None,
    reason="ffmpeg is not on PATH; video muxing is an external-tool capability, not product logic",
)
def test_allow_degraded_flag_permits_silent_fallback():
    """When allow_degraded=True is explicitly passed, fallback to silent WAV is allowed."""
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as tmpdir:
        vg = VideoGenerator(project_root=Path(tmpdir))
        with patch.object(vg.voice_engine, "synthesize_speech", side_effect=RuntimeError("TTS upstream error")):
            vid_path, metadata = vg.generate_video_short(
                script_text="Fallback audio test",
                title="silent_clip",
                allow_degraded=True,
            )
            assert vid_path.exists()
            assert metadata["degraded_audio"] is True
            assert metadata["voice_backend"] == "silent_fallback"


def test_creative_engine_blocks_publishing_degraded_audio():
    """W4.3: Creative engine must block publishing of degraded audio videos."""
    from unittest.mock import MagicMock, patch
    from orbit_security.creative_engine import CreativeEngine, ContentPillar
    from orbit_security.video_generator import DegradedAudioError

    with tempfile.TemporaryDirectory() as tmpdir:
        ce = CreativeEngine(project_root=Path(tmpdir))
        mock_vid_path = Path(tmpdir) / "test.mp4"
        mock_vid_path.write_bytes(b"dummy")
        mock_meta = {"degraded_audio": True, "voice_backend": "silent_fallback"}

        with patch.object(ce.video_gen, "generate_video_short", return_value=(mock_vid_path, mock_meta)):
            with patch.object(ce.media_gen, "generate_doh_speed_benchmark", return_value=Path(tmpdir) / "card.png"):
                # Force dynamic video post
                post = ce.generate_next_post(
                    target_media_type="video",
                )
                # Video synthesis error caught, so media_path does not point to degraded video
                assert post.media_path != str(mock_vid_path)

