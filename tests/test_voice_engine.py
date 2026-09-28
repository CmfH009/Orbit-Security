"""Tests for Orbit Security Cat Voice Engine, Voice Profiles, and DSP Filtering."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from orbit_security.voice_model import CatVoiceEngine, VoiceProfile


def test_voice_profile_serialization():
    profile = VoiceProfile(
        name="test_cat",
        tts_voice="en-US-ChristopherNeural",
        rate="+4%",
        pitch="-3Hz",
        highpass_hz=300,
        lowpass_hz=3500,
        metadata={"author": "carson"},
    )
    data = profile.to_dict()
    assert data["name"] == "test_cat"
    assert data["highpass_hz"] == 300
    assert data["metadata"]["author"] == "carson"

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "profile.json"
        profile.save(json_path)
        assert json_path.exists()

        loaded = VoiceProfile.load(json_path)
        assert loaded.name == profile.name
        assert loaded.tts_voice == profile.tts_voice
        assert loaded.pitch == profile.pitch
        assert loaded.rate == profile.rate


def test_cat_voice_engine_initialization():
    engine = CatVoiceEngine()
    assert engine.profile.tts_voice == "en-US-ChristopherNeural"
    assert engine.profile.lowpass_hz == 3800

    custom = VoiceProfile(name="custom_drone", pitch="+5Hz")
    custom_engine = CatVoiceEngine(default_profile=custom)
    assert custom_engine.profile.pitch == "+5Hz"



@pytest.mark.asyncio
async def test_dsp_filter_pipeline(tmp_path):
    # Create a 0.5s dummy sine audio wav using ffmpeg
    dummy_wav = tmp_path / "dummy.wav"
    output_wav = tmp_path / "filtered.wav"

    import subprocess
    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        "sine=frequency=440:duration=0.5",
        "-ar",
        "48000",
        "-ac",
        "1",
        str(dummy_wav),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert dummy_wav.exists()

    engine = CatVoiceEngine()
    out = engine.apply_helmet_dsp(dummy_wav, output_wav, add_chirps=False)
    assert out.exists()
    assert out.stat().st_size > 1000


def test_dsp_missing_file_raises():
    engine = CatVoiceEngine()
    with pytest.raises(FileNotFoundError):
        engine.apply_helmet_dsp("non_existent_file_xyz.wav", "output.wav")


def test_gemini_backend_configuration():
    prof = VoiceProfile(
        engine_backend="gemini",
        gemini_voice="Charon",
        gemini_style_prompt="Say in a relaxed founder tone:"
    )
    assert prof.engine_backend == "gemini"
    assert prof.gemini_voice == "Charon"
    assert prof.gemini_style_prompt == "Say in a relaxed founder tone:"
    data = prof.to_dict()
    assert data["gemini_voice"] == "Charon"
    assert data["engine_backend"] == "gemini"

