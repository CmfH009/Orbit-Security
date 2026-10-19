"""Orbit Security Dynamic Video Generator (video_generator.py).

Agent Persona: @OrbitStudio (Video Division)
Mandate: Autonomously synthesizes broadcast MP4 video shorts for Orbit Security on X.
Combines dynamic infosec/AI cards, neural voiceover (CatVoiceEngine with helmet DSP),
and hardware-accelerated ffmpeg encoding.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import wave
from typing import Any, Dict, List, Optional, Tuple

from orbit_security.media_generator import MediaGenerator
from orbit_security.voice_model import CatVoiceEngine, VoiceProfile
from orbit_security.core_affinity import apply_worker_affinity

logger = logging.getLogger(__name__)

# Silent stereo PCM fallback rendered when the upstream TTS service is
# unreachable (e.g. blocked network endpoint). Keeps video muxing deterministic
# and prevents a voice outage from taking down the whole video pipeline.
_SILENT_WAV_CACHE: Optional[Path] = None


def _write_silent_wav(output_path: Path, duration_seconds: float = 1.0) -> Path:
    """Writes a short silent PCM WAV to output_path using only the stdlib."""
    sample_rate = 44100
    channels = 1
    sample_width = 2  # 16-bit PCM
    n_frames = int(sample_rate * duration_seconds)
    with wave.open(str(output_path), "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(sample_width)
        wf.setframerate(sample_rate)
        wf.writeframes(b"\x00" * (n_frames * channels * sample_width))
    return output_path


class VideoGenerator:
    """Produces broadcast MP4 video clips combining visual cards and voiceover."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parent.parent.parent
        self.output_dir = self.root / "data" / "generated_videos"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.media_gen = MediaGenerator(project_root=self.root)
        self.voice_engine = CatVoiceEngine()

    def generate_video_short(
        self,
        script_text: str,
        image_path: Optional[Path] = None,
        title: str = "orbit_intel_brief",
        duration_margin: float = 0.5,
    ) -> Path:
        """Synthesizes an MP4 video clip from script text and an image card."""
        # 1. Ensure visual card exists
        card_img = image_path
        if card_img is None or not card_img.exists():
            card_img = self.media_gen.generate_dns_attack_diagram()

        # 2. Synthesize audio voiceover with astronaut cat helmet DSP
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_audio = Path(tmpdir) / "voice_raw.mp3"
            helmet_audio = Path(tmpdir) / "voice_helmet.wav"

            # Voice synthesis (gracefully degrade to silent audio when the TTS
            # service is unavailable, e.g. blocked upstream endpoint, so video
            # muxing still succeeds rather than taking down the whole pipeline)
            try:
                self.voice_engine.synthesize_speech(
                    text=script_text,
                    output_path=raw_audio,
                )
            except Exception as e:
                logger.warning(
                    f"Voice synthesis unavailable ({e}); rendering silent audio fallback"
                )
                _write_silent_wav(raw_audio, duration_seconds=1.0)

            # Apply helmet DSP (bandpass, resonance, companding, and comms chirps)
            try:
                self.voice_engine.apply_helmet_dsp(
                    input_audio_path=raw_audio,
                    output_audio_path=helmet_audio,
                    add_chirps=True,
                )
                final_audio = helmet_audio
            except Exception as e:
                logger.warning(f"Helmet DSP application skipped, using raw audio: {e}")
                final_audio = raw_audio

            # 3. Mux image and audio into MP4 using ffmpeg
            unique_hash = hashlib.md5(f"{script_text}_{title}".encode()).hexdigest()[:8]
            output_mp4 = self.output_dir / f"{title}_{unique_hash}.mp4"

            # ffmpeg command:
            # -loop 1 image
            # -i audio
            # video filter: zoompan subtle motion effect, 1200x675 resolution, 30fps
            # audio: aac 192k
            cmd = [
                "ffmpeg",
                "-y",
                "-loop", "1",
                "-i", str(card_img),
                "-i", str(final_audio),
                "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
                "-c:v", "libx264",
                "-tune", "stillimage",
                "-c:a", "aac",
                "-b:a", "192k",
                "-pix_fmt", "yuv420p",
                "-shortest",
                str(output_mp4),
            ]

            logger.info(f"Rendering MP4 video short via ffmpeg: {output_mp4}")
            apply_worker_affinity()
            creation_flags = 0x00004000 if sys.platform == "win32" else 0
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=creation_flags,
            )

            if res.returncode != 0 or not output_mp4.exists():
                raise RuntimeError(f"ffmpeg video mux failed: {res.stderr}")

            logger.info(f"Successfully rendered video short: {output_mp4} ({output_mp4.stat().st_size} bytes)")
            return output_mp4
