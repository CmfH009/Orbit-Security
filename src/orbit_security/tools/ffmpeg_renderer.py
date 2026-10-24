"""Automation wrapper around ffmpeg.exe and ffprobe.exe.

Enables programmatic creation of high-definition video clips, radar teasers,
animated security GIFs from terminal frames, media telemetry probing, and
audio extraction for Project ORBIT.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import logging
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class FFmpegError(Exception):
    """Base exception for FFmpeg/FFprobe operations."""
    pass


class FFmpegNotInstalledError(FFmpegError):
    """Raised when ffmpeg or ffprobe binary cannot be found."""
    pass


@dataclass
class MediaStream:
    """Represents an individual video or audio stream."""
    index: int
    codec_type: str
    codec_name: str
    width: Optional[int] = None
    height: Optional[int] = None
    fps: Optional[float] = None
    bit_rate: Optional[int] = None
    duration: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "codec_type": self.codec_type,
            "codec_name": self.codec_name,
            "width": self.width,
            "height": self.height,
            "fps": self.fps,
            "bit_rate": self.bit_rate,
            "duration": self.duration,
        }


@dataclass
class MediaInfo:
    """Full multimedia inspection output from ffprobe."""
    format_name: str
    duration: float
    size_bytes: int
    bit_rate: int
    streams: List[MediaStream] = field(default_factory=list)

    @property
    def video_stream(self) -> Optional[MediaStream]:
        for s in self.streams:
            if s.codec_type == "video":
                return s
        return None

    @property
    def audio_stream(self) -> Optional[MediaStream]:
        for s in self.streams:
            if s.codec_type == "audio":
                return s
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format_name": self.format_name,
            "duration": self.duration,
            "size_bytes": self.size_bytes,
            "bit_rate": self.bit_rate,
            "streams": [s.to_dict() for s in self.streams],
        }


class FFmpegRenderer:
    """Automation wrapper for FFmpeg and FFprobe CLI tools."""

    def __init__(
        self,
        ffmpeg_path: Optional[str] = None,
        ffprobe_path: Optional[str] = None,
    ):
        self.ffmpeg_path = ffmpeg_path or self._locate_binary("ffmpeg.exe", "ffmpeg")
        self.ffprobe_path = ffprobe_path or self._locate_binary("ffprobe.exe", "ffprobe")

    @classmethod
    def _locate_binary(cls, win_name: str, unix_name: str) -> Optional[str]:
        for name in [win_name, unix_name]:
            path = shutil.which(name)
            if path:
                return path

        common_locations = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / win_name,
            Path("C:/Program Files/ffmpeg/bin") / win_name,
            Path("C:/ffmpeg/bin") / win_name,
        ]
        for loc in common_locations:
            if loc.is_file():
                return str(loc)
        return None

    def is_ffmpeg_installed(self) -> bool:
        return bool(self.ffmpeg_path and os.path.isfile(self.ffmpeg_path))

    def is_ffprobe_installed(self) -> bool:
        return bool(self.ffprobe_path and os.path.isfile(self.ffprobe_path))

    def probe_media(self, file_path: Union[str, Path], timeout_sec: float = 10.0) -> MediaInfo:
        """Inspect media file streams, codec, resolution, and duration with ffprobe."""
        if not self.is_ffprobe_installed():
            raise FFmpegNotInstalledError("ffprobe binary is not installed.")

        p = Path(file_path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Media file not found: {p}")

        cmd = [
            self.ffprobe_path,
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            str(p),
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        except subprocess.TimeoutExpired as e:
            raise FFmpegError(f"ffprobe timed out on {p}") from e

        if proc.returncode != 0:
            raise FFmpegError(f"ffprobe failed (code {proc.returncode}): {proc.stderr}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise FFmpegError(f"Failed to parse ffprobe JSON output: {proc.stdout[:200]}") from e

        fmt = data.get("format", {})
        duration = float(fmt.get("duration", 0.0))
        size_bytes = int(fmt.get("size", 0))
        bit_rate = int(fmt.get("bit_rate", 0))
        format_name = fmt.get("format_name", "")

        streams: List[MediaStream] = []
        for s in data.get("streams", []):
            fps = None
            r_fps = s.get("r_frame_rate", "")
            if "/" in r_fps:
                try:
                    num, den = map(float, r_fps.split("/"))
                    fps = num / den if den != 0 else None
                except Exception:
                    pass

            bit_r = int(s["bit_rate"]) if "bit_rate" in s and str(s["bit_rate"]).isdigit() else None
            dur = float(s["duration"]) if "duration" in s else None

            streams.append(
                MediaStream(
                    index=int(s.get("index", 0)),
                    codec_type=s.get("codec_type", "unknown"),
                    codec_name=s.get("codec_name", "unknown"),
                    width=s.get("width"),
                    height=s.get("height"),
                    fps=fps,
                    bit_rate=bit_r,
                    duration=dur,
                )
            )

        return MediaInfo(
            format_name=format_name,
            duration=duration,
            size_bytes=size_bytes,
            bit_rate=bit_rate,
            streams=streams,
        )

    def create_gif(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        fps: int = 15,
        width: int = 640,
        loop: int = 0,
        timeout_sec: float = 60.0,
    ) -> Path:
        """Convert a video clip into a high-fidelity animated GIF using 2-pass palettegen."""
        if not self.is_ffmpeg_installed():
            raise FFmpegNotInstalledError("ffmpeg is not installed.")

        src = Path(input_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Source video file not found: {src}")

        dst = Path(output_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        # 2-pass palette filter produces significantly crisper GIFs without banding
        # Using scale={width}:-2 ensures the calculated height is always an even number
        filter_str = f"fps={fps},scale={width}:-2:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse"

        cmd = [
            self.ffmpeg_path,
            "-y",
            "-i", str(src),
            "-vf", filter_str,
            "-loop", str(loop),
            str(dst),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if proc.returncode != 0:
            raise FFmpegError(f"create_gif failed (code {proc.returncode}): {proc.stderr}")

        return dst

    def render_video_from_frames(
        self,
        frame_paths: List[Union[str, Path]],
        output_path: Union[str, Path],
        fps: int = 30,
        crf: int = 20,
        audio_path: Optional[Union[str, Path]] = None,
        timeout_sec: float = 60.0,
    ) -> Path:
        """Stitch a sequence of images into an H.264 MP4 video."""
        if not self.is_ffmpeg_installed():
            raise FFmpegNotInstalledError("ffmpeg is not installed.")

        if not frame_paths:
            raise ValueError("No frames provided to render.")

        dst = Path(output_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            concat_file = tmp_path / "frames.txt"
            duration_per_frame = 1.0 / fps

            with open(concat_file, "w", encoding="utf-8") as f:
                for fp in frame_paths:
                    norm = str(Path(fp).resolve()).replace("\\", "/")
                    f.write(f"file '{norm}'\n")
                    f.write(f"duration {duration_per_frame:.4f}\n")
                # Last line repeat required by ffmpeg concat demuxer
                last_norm = str(Path(frame_paths[-1]).resolve()).replace("\\", "/")
                f.write(f"file '{last_norm}'\n")

            cmd = [
                self.ffmpeg_path,
                "-y",
                "-f", "concat",
                "-safe", "0",
                "-i", str(concat_file),
            ]

            if audio_path and Path(audio_path).is_file():
                cmd.extend(["-i", str(Path(audio_path).resolve()), "-c:a", "aac", "-shortest"])

            # pad=ceil(iw/2)*2:ceil(ih/2)*2 ensures odd dimensions never crash libx264 yuv420p
            cmd.extend([
                "-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2",
                "-c:v", "libx264",
                "-pix_fmt", "yuv420p",
                "-crf", str(crf),
                "-r", str(fps),
                str(dst),
            ])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
            if proc.returncode != 0:
                raise FFmpegError(f"render_video_from_frames failed: {proc.stderr}")

        return dst

    def extract_clip(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        start_sec: float,
        duration_sec: float,
        timeout_sec: float = 30.0,
    ) -> Path:
        """Cut a segment from a video without re-encoding when possible."""
        if not self.is_ffmpeg_installed():
            raise FFmpegNotInstalledError("ffmpeg is not installed.")

        src = Path(input_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Source media file not found: {src}")

        dst = Path(output_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            self.ffmpeg_path,
            "-y",
            "-ss", f"{start_sec:.2f}",
            "-i", str(src),
            "-t", f"{duration_sec:.2f}",
            "-c", "copy",
            str(dst),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if proc.returncode != 0:
            # Fallback with re-encoding if stream copy fails on keyframes
            cmd = [
                self.ffmpeg_path,
                "-y",
                "-ss", f"{start_sec:.2f}",
                "-i", str(src),
                "-t", f"{duration_sec:.2f}",
                "-c:v", "libx264",
                "-c:a", "aac",
                str(dst),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
            if proc.returncode != 0:
                raise FFmpegError(f"extract_clip failed: {proc.stderr}")

        return dst

    def extract_audio(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        format: str = "mp3",
        bitrate: str = "192k",
        timeout_sec: float = 30.0,
    ) -> Path:
        """Extract audio track from video file."""
        if not self.is_ffmpeg_installed():
            raise FFmpegNotInstalledError("ffmpeg is not installed.")

        src = Path(input_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Source media file not found: {src}")

        dst = Path(output_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        codec = "libmp3lame" if format.lower() == "mp3" else "aac"
        cmd = [
            self.ffmpeg_path,
            "-y",
            "-i", str(src),
            "-vn",
            "-c:a", codec,
            "-b:a", bitrate,
            str(dst),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if proc.returncode != 0:
            raise FFmpegError(f"extract_audio failed: {proc.stderr}")

        return dst

    def generate_terminal_teaser(
        self,
        title: str,
        subtitle: str,
        findings: List[str],
        output_path: Union[str, Path],
        duration_sec: float = 4.0,
        fps: int = 25,
        width: int = 1280,
        height: int = 720,
    ) -> Path:
        """Programmatically generate a stylized retro cyber terminal radar teaser."""
        try:
            from PIL import Image, ImageDraw, ImageFont
        except ImportError:
            raise FFmpegError("Pillow is required for generating terminal teaser frames.")

        dst = Path(output_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        total_frames = int(duration_sec * fps)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            frame_files: List[Path] = []

            for frame_idx in range(total_frames):
                # Dark navy cyber background
                img = Image.new("RGB", (width, height), color=(10, 14, 23))
                draw = ImageDraw.Draw(img)

                # Grid scanlines
                for y in range(0, height, 4):
                    draw.line([(0, y), (width, y)], fill=(15, 20, 32), width=1)

                # Header bar
                draw.rectangle([(40, 30), (width - 40, 90)], fill=(16, 26, 46), outline=(0, 230, 153), width=2)
                draw.text((60, 48), f"[ORBIT SEC PERIMETER RADAR] :: {title.upper()}", fill=(0, 230, 153))

                # Subtitle & Status
                draw.text((60, 110), f"STATUS: ACTIVE SCAN // {subtitle}", fill=(136, 153, 175))

                # Radar sweep indicator animation
                angle = (frame_idx / total_frames) * 2 * math.pi
                cx, cy, radius = width - 150, 200, 60
                draw.ellipse([(cx - radius, cy - radius), (cx + radius, cy + radius)], outline=(0, 204, 255), width=2)
                rx = cx + int(radius * math.cos(angle))
                ry = cy + int(radius * math.sin(angle))
                draw.line([(cx, cy), (rx, ry)], fill=(0, 204, 255), width=2)

                # Findings reveal progression
                revealed_count = min(len(findings), int((frame_idx / (total_frames * 0.75)) * len(findings)) + 1)
                y_pos = 180
                for i in range(revealed_count):
                    f_text = findings[i]
                    draw.rectangle([(60, y_pos), (width - 260, y_pos + 45)], fill=(20, 32, 54), outline=(255, 77, 79), width=1)
                    draw.text((80, y_pos + 12), f"! [ALERT] {f_text}", fill=(255, 120, 117))
                    y_pos += 60

                # Footer
                draw.text((60, height - 50), f"ORBIT AUTONOMOUS SECURITY SENTINEL | FRAME {frame_idx + 1:03d}/{total_frames}", fill=(70, 90, 120))

                frame_file = tmp_path / f"frame_{frame_idx:04d}.png"
                img.save(frame_file)
                frame_files.append(frame_file)

            if dst.suffix.lower() == ".gif":
                temp_mp4 = tmp_path / "temp_teaser.mp4"
                self.render_video_from_frames(frame_files, temp_mp4, fps=fps)
                self.create_gif(temp_mp4, dst, fps=fps, width=width)
            else:
                self.render_video_from_frames(frame_files, dst, fps=fps)

        return dst

    async def async_create_gif(self, *args: Any, **kwargs: Any) -> Path:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.create_gif(*args, **kwargs))

    async def async_render_video_from_frames(self, *args: Any, **kwargs: Any) -> Path:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.render_video_from_frames(*args, **kwargs))

    async def async_probe_media(self, *args: Any, **kwargs: Any) -> MediaInfo:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.probe_media(*args, **kwargs))

    async def async_extract_clip(self, *args: Any, **kwargs: Any) -> Path:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.extract_clip(*args, **kwargs))

    async def async_extract_audio(self, *args: Any, **kwargs: Any) -> Path:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.extract_audio(*args, **kwargs))

    async def async_generate_terminal_teaser(self, *args: Any, **kwargs: Any) -> Path:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.generate_terminal_teaser(*args, **kwargs))


# Default instance
default_renderer = FFmpegRenderer()
