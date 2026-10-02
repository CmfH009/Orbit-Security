"""Orbit Security: Astronaut Cat Voice Engine and Acoustic Profiler.

Provides neural voice generation, acoustic DSP astronaut helmet filtering,
user voice profile analysis, and broadcast video voiceover muxing.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import edge_tts


@dataclass
class VoiceProfile:
    """Acoustic profile settings for voice synthesis and DSP shaping."""

    name: str = "carson_astronaut_cat"
    engine_backend: str = "gemini"  # "gemini" or "edge"
    gemini_voice: str = "Charon"  # Charon (grounded/dry wit), Achird, Puck, Zubenelgenubi
    gemini_style_prompt: str = "Say in a calm, conversational, confident founder voice with subtle dry humor:"
    tts_voice: str = "en-US-ChristopherNeural"
    rate: str = "+5%"
    pitch: str = "-2Hz"
    volume: str = "+0%"
    highpass_hz: int = 260
    lowpass_hz: int = 3800
    peak_hz: int = 1750
    peak_gain_db: float = 2.8
    compand_gain_db: float = 3.5
    intro_chirp: bool = True
    outro_chirp: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VoiceProfile:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str | Path) -> VoiceProfile:
        p = Path(path)
        if not p.exists():
            return cls()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


class CatVoiceEngine:
    """Synthesizes and transforms voice tracks into Orbit Security's astronaut cat persona."""

    def __init__(self, default_profile: Optional[VoiceProfile] = None):
        self.profile = default_profile or VoiceProfile()

    async def _async_synthesize(
        self,
        text: str,
        output_path: str | Path,
        profile: Optional[VoiceProfile] = None,
    ) -> Path:
        prof = profile or self.profile
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        communicate = edge_tts.Communicate(
            text=text,
            voice=prof.tts_voice,
            rate=prof.rate,
            pitch=prof.pitch,
            volume=prof.volume,
        )
        await communicate.save(str(out))
        return out

    def synthesize_gemini_speech(
        self,
        text: str,
        output_path: str | Path,
        profile: Optional[VoiceProfile] = None,
    ) -> Path:
        """Generates natural, expressive speech audio via Gemini 3.1 Flash TTS."""
        import base64
        import wave
        from google import genai

        prof = profile or self.profile
        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        client = genai.Client()
        prompt_input = (
            f"{prof.gemini_style_prompt}\n{text}"
            if prof.gemini_style_prompt
            else text
        )
        tts = client.interactions.create(
            model="gemini-3.1-flash-tts-preview",
            input=prompt_input,
            response_format={"type": "audio"},
            generation_config={"speech_config": [{"voice": prof.gemini_voice}]},
        )
        raw_pcm = base64.b64decode(tts.output_audio.data)
        with wave.open(str(out), "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(24000)
            wf.writeframes(raw_pcm)
        return out

    def synthesize_speech(
        self,
        text: str,
        output_path: str | Path,
        profile: Optional[VoiceProfile] = None,
        engine_backend: Optional[str] = None,
    ) -> Path:
        """Generates speech audio using either Gemini Flash TTS (natural) or edge-tts."""
        prof = profile or self.profile
        backend = engine_backend or prof.engine_backend
        if backend == "gemini" and os.environ.get("GEMINI_API_KEY"):
            try:
                return self.synthesize_gemini_speech(text, output_path, profile=prof)
            except Exception as e:
                # Fallback to edge_tts if Gemini API unavailable
                pass
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, self._async_synthesize(text, output_path, prof)).result()
        return asyncio.run(self._async_synthesize(text, output_path, prof))


    def apply_helmet_dsp(
        self,
        input_audio_path: str | Path,
        output_audio_path: str | Path,
        profile: Optional[VoiceProfile] = None,
        add_chirps: Optional[bool] = None,
    ) -> Path:
        """Applies zero-g astronaut helmet comms filter with bandpass, resonance, and companding."""
        prof = profile or self.profile
        inp = Path(input_audio_path).resolve()
        out = Path(output_audio_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if not inp.exists():
            raise FileNotFoundError(f"Input audio file not found: {inp}")

        chirp_flag = prof.intro_chirp if add_chirps is None else add_chirps

        with tempfile.TemporaryDirectory() as tmpdir:
            filtered_wav = Path(tmpdir) / "filtered.wav"

            # Construct audio DSP filter graph
            # 1. Highpass cuts sub-bass boom
            # 2. Lowpass simulates comms radio ceiling
            # 3. Peaking EQ boosts mid-presence / visor resonance
            # 4. Compand adds punchy radio broadcast leveling
            af_chain = (
                f"highpass=f={prof.highpass_hz},"
                f"lowpass=f={prof.lowpass_hz},"
                f"equalizer=f={prof.peak_hz}:t=q:w=1.5:g={prof.peak_gain_db},"
                f"compand=attacks=0.01:decays=0.1:points=-80/-80|-30/-15|0/-3:gain={prof.compand_gain_db}"
            )

            cmd_filter = [
                "ffmpeg",
                "-y",
                "-i",
                str(inp),
                "-af",
                af_chain,
                "-ar",
                "48000",
                "-ac",
                "1",
                str(filtered_wav),
            ]
            subprocess.run(cmd_filter, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if chirp_flag:
                # Generate a subtle 45ms radio blip/chirp (1600Hz decaying tone)
                intro_chirp_wav = Path(tmpdir) / "intro_chirp.wav"
                outro_chirp_wav = Path(tmpdir) / "outro_chirp.wav"

                cmd_chirp_intro = [
                    "ffmpeg",
                    "-y",
                    "-f",
                    "lavfi",
                    "-i",
                    "sine=frequency=1650:duration=0.045",
                    "-af",
                    "volume=0.35,afade=t=out:st=0.03:d=0.015",
                    "-ar",
                    "48000",
                    "-ac",
                    "1",
                    str(intro_chirp_wav),
                ]
                subprocess.run(cmd_chirp_intro, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                cmd_chirp_outro = [
                    "ffmpeg",
                    "-y",
                    "-f",
                    "lavfi",
                    "-i",
                    "sine=frequency=1250:duration=0.040",
                    "-af",
                    "volume=0.25,afade=t=out:st=0.025:d=0.015",
                    "-ar",
                    "48000",
                    "-ac",
                    "1",
                    str(outro_chirp_wav),
                ]
                subprocess.run(cmd_chirp_outro, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                concat_list = Path(tmpdir) / "concat.txt"
                with open(concat_list, "w", encoding="utf-8") as f:
                    f.write(f"file '{intro_chirp_wav.as_posix()}'\n")
                    f.write(f"file '{filtered_wav.as_posix()}'\n")
                    f.write(f"file '{outro_chirp_wav.as_posix()}'\n")

                cmd_concat = [
                    "ffmpeg",
                    "-y",
                    "-f",
                    "concat",
                    "-safe",
                    "0",
                    "-i",
                    str(concat_list),
                    "-c:a",
                    "pcm_s16le",
                    str(out),
                ]
                subprocess.run(cmd_concat, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                shutil.copy2(filtered_wav, out)

        return out

    def render_ad_video(
        self,
        video_path: str | Path,
        voice_audio_path: str | Path,
        output_video_path: str | Path,
        bg_audio_path: Optional[str | Path] = None,
        bg_duck_db: float = -20.0,
    ) -> Path:
        """Muxes the astronaut cat voiceover onto the video, looping smoothly and leveling audio."""
        vid = Path(video_path).resolve()
        voice = Path(voice_audio_path).resolve()
        out = Path(output_video_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if not vid.exists():
            raise FileNotFoundError(f"Source video not found: {vid}")
        if not voice.exists():
            raise FileNotFoundError(f"Voice audio not found: {voice}")

        # Get voice audio duration
        probe_cmd = [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(voice),
        ]
        res = subprocess.run(probe_cmd, check=True, stdout=subprocess.PIPE, text=True)
        voice_dur = float(res.stdout.strip())
        target_dur = max(voice_dur + 0.5, 5.0)

        with tempfile.TemporaryDirectory() as tmpdir:
            # If bg_audio is not provided, extract audio from the video if available
            bg_source = bg_audio_path
            if not bg_source:
                extracted_bg = Path(tmpdir) / "video_ambient.wav"
                cmd_extract = [
                    "ffmpeg",
                    "-y",
                    "-i",
                    str(vid),
                    "-vn",
                    "-ar",
                    "48000",
                    "-ac",
                    "2",
                    str(extracted_bg),
                ]
                p = subprocess.run(cmd_extract, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if p.returncode == 0 and extracted_bg.exists() and extracted_bg.stat().st_size > 1000:
                    bg_source = extracted_bg

            # Build complex filter graph:
            # 1. Loop video stream to target_dur
            # 2. Mix voiceover (prominent) + ambient bg (ducked)
            # 3. Audio leveling with loudnorm
            if bg_source and Path(bg_source).exists():
                filter_complex = (
                    f"[0:v]loop=loop=-1:size=32767:start=0,setpts=N/FRAME_RATE/TB[v];"
                    f"[1:a]volume=1.0[voice];"
                    f"[2:a]aloop=loop=-1:size=2e+09,volume={bg_duck_db}dB[bg];"
                    f"[voice][bg]amix=inputs=2:duration=first:dropout_transition=2[aout]"
                )
                cmd_mux = [
                    "ffmpeg",
                    "-y",
                    "-i",
                    str(vid),
                    "-i",
                    str(voice),
                    "-i",
                    str(bg_source),
                    "-filter_complex",
                    filter_complex,
                    "-map",
                    "[v]",
                    "-map",
                    "[aout]",
                    "-t",
                    f"{target_dur:.2f}",
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv420p",
                    "-preset",
                    "fast",
                    "-crf",
                    "18",
                    "-c:a",
                    "aac",
                    "-b:a",
                    "192k",
                    "-movflags",
                    "+faststart",
                    str(out),
                ]
            else:
                filter_complex = (
                    f"[0:v]loop=loop=-1:size=32767:start=0,setpts=N/FRAME_RATE/TB[v]"
                )
                cmd_mux = [
                    "ffmpeg",
                    "-y",
                    "-i",
                    str(vid),
                    "-i",
                    str(voice),
                    "-filter_complex",
                    filter_complex,
                    "-map",
                    "[v]",
                    "-map",
                    "1:a",
                    "-t",
                    f"{target_dur:.2f}",
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv420p",
                    "-preset",
                    "fast",
                    "-crf",
                    "18",
                    "-c:a",
                    "aac",
                    "-b:a",
                    "192k",
                    "-movflags",
                    "+faststart",
                    str(out),
                ]

            subprocess.run(cmd_mux, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return out

    def analyze_voice_sample(
        self,
        audio_path: str | Path,
        gemini_api_key: Optional[str] = None,
    ) -> VoiceProfile:
        """Analyzes an input audio recording using Gemini 3.8 Flash to profile pitch, cadence, and timbre."""
        audio_file = Path(audio_path).resolve()
        if not audio_file.exists():
            raise FileNotFoundError(f"Audio file not found: {audio_file}")

        key = gemini_api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            # Fallback to local acoustic estimation
            return VoiceProfile(
                name="user_custom_voice",
                tts_voice="en-US-ChristopherNeural",
                pitch="-2Hz",
                rate="+5%",
                metadata={"source": str(audio_file), "mode": "local_fallback"},
            )

        from google import genai

        client = genai.Client(api_key=key)
        uploaded = client.files.upload(file=str(audio_file))

        prompt = (
            "Analyze this speaker's voice in detail. Return a valid JSON object with these keys: "
            "'gender' (Male/Female), 'estimated_age' (int or str), 'pitch_hz' (low, mid, or high), "
            "'vocal_pace' (slow, natural, fast), 'energy' (calm, authoritative, energetic), "
            "'recommended_edge_voice' (one of 'en-US-ChristopherNeural', 'en-US-EricNeural', 'en-US-GuyNeural', 'en-US-AndrewNeural'), "
            "'recommended_pitch_offset' (e.g. '-3Hz', '0Hz', '+2Hz'), 'recommended_rate_offset' (e.g. '+3%', '+6%', '-2%'), "
            "'summary' (short 1-2 sentence description)."
        )

        resp = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=[uploaded, prompt],
        )

        match = re.search(r"\{[\s\S]*\}", resp.text)
        meta = {}
        if match:
            try:
                meta = json.loads(match.group(0))
            except Exception:
                meta = {"raw": resp.text}

        rec_voice = meta.get("recommended_edge_voice", "en-US-ChristopherNeural")
        rec_pitch = meta.get("recommended_pitch_offset", "-2Hz")
        rec_rate = meta.get("recommended_rate_offset", "+5%")

        profile = VoiceProfile(
            name=f"calibrated_{Path(audio_file).stem}",
            tts_voice=rec_voice,
            pitch=rec_pitch,
            rate=rec_rate,
            metadata=meta,
        )
        return profile
