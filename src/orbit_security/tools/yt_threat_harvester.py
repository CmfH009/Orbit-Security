"""Media Harvester wrapper around yt-dlp for Cyber Threat Intelligence (CTI).

Downloads and extracts audio, transcripts, and metadata from security conference talks
(DEF CON, Black Hat, CCC, USENIX) and exploit walkthrough videos for ingestion into
Project ORBIT analysis pipelines.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class YTDLPError(Exception):
    """Base exception for yt-dlp threat harvesting operations."""
    pass


class YTDLPNotInstalledError(YTDLPError):
    """Raised when yt-dlp binary is not installed."""
    pass


class VideoExtractionError(YTDLPError):
    """Raised when metadata or media extraction fails."""
    pass


@dataclass
class VideoMetadata:
    """Rich metadata for a harvested security talk or walkthrough."""
    id: str
    title: str
    uploader: str
    channel: str
    duration: float
    view_count: int
    description: str
    tags: List[str] = field(default_factory=list)
    upload_date: str = ""
    webpage_url: str = ""
    thumbnail: str = ""
    chapters: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VideoMetadata:
        raw_dur = data.get("duration", 0.0)
        try:
            duration = float(raw_dur or 0.0)
        except (ValueError, TypeError):
            duration = 0.0

        raw_views = data.get("view_count", 0)
        try:
            view_count = int(float(raw_views or 0))
        except (ValueError, TypeError):
            view_count = 0

        return cls(
            id=str(data.get("id", "")),
            title=data.get("title") or data.get("fulltitle") or "",
            uploader=data.get("uploader") or data.get("uploader_id") or "",
            channel=data.get("channel") or "",
            duration=duration,
            view_count=view_count,
            description=data.get("description") or "",
            tags=data.get("tags") or [],
            upload_date=str(data.get("upload_date") or ""),
            webpage_url=data.get("webpage_url") or data.get("original_url") or "",
            thumbnail=data.get("thumbnail") or "",
            chapters=data.get("chapters") or [],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "uploader": self.uploader,
            "channel": self.channel,
            "duration": self.duration,
            "view_count": self.view_count,
            "description": self.description,
            "tags": self.tags,
            "upload_date": self.upload_date,
            "webpage_url": self.webpage_url,
            "thumbnail": self.thumbnail,
            "chapters": self.chapters,
        }


@dataclass
class HarvestResult:
    """Complete harvest bundle with threat intel extraction."""
    video_id: str
    title: str
    audio_path: Optional[Path] = None
    subtitles_path: Optional[Path] = None
    metadata: Optional[VideoMetadata] = None
    threat_intel: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "video_id": self.video_id,
            "title": self.title,
            "audio_path": str(self.audio_path) if self.audio_path else None,
            "subtitles_path": str(self.subtitles_path) if self.subtitles_path else None,
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "threat_intel": self.threat_intel,
        }


class YTThreatHarvester:
    """Automated security conference media harvester wrapping yt-dlp."""

    CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    MITRE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

    SECURITY_TOOLS = [
        "metasploit", "burpsuite", "burp suite", "ghidra", "ida pro", "nmap", "nuclei",
        "bloodhound", "mimikatz", "wireshark", "subfinder", "amass", "sqlmap", "hashcat",
        "john the ripper", "ffuf", "gobuster", "radare2", "impacket", "responder"
    ]

    ATTACK_VECTORS = [
        "rce", "remote code execution", "ssrf", "server-side request forgery",
        "sqli", "sql injection", "xss", "cross-site scripting", "subdomain takeover",
        "deserialization", "buffer overflow", "privilege escalation", "privesc",
        "zero-day", "0-day", "kernel exploit", "bof", "heap overflow", "auth bypass"
    ]

    PLATFORMS = [
        "shopify", "wordpress", "aws", "azure", "gcp", "kubernetes", "k8s",
        "linux", "windows", "ios", "android", "docker", "cisco", "fortinet"
    ]

    def __init__(self, yt_dlp_path: Optional[str] = None):
        self.yt_dlp_path = yt_dlp_path or self._locate_binary()

    @classmethod
    def _locate_binary(cls) -> Optional[str]:
        for name in ["yt-dlp.exe", "yt-dlp"]:
            path = shutil.which(name)
            if path:
                return path

        common_locations = [
            Path(r"C:\Python314\Scripts\yt-dlp.exe"),
            Path(r"C:\Python313\Scripts\yt-dlp.exe"),
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / "yt-dlp.exe",
        ]
        for loc in common_locations:
            if loc.is_file():
                return str(loc)
        return None

    def is_installed(self) -> bool:
        return bool(self.yt_dlp_path and os.path.isfile(self.yt_dlp_path))

    def get_video_info(self, url: str, timeout_sec: float = 30.0) -> VideoMetadata:
        """Fetch video metadata and chapter markers without downloading media."""
        if not self.is_installed():
            raise YTDLPNotInstalledError("yt-dlp binary is not installed.")

        cmd = [
            self.yt_dlp_path,
            "--dump-json",
            "--skip-download",
            "--no-warnings",
            url,
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        except subprocess.TimeoutExpired as e:
            raise YTDLPError(f"yt-dlp metadata retrieval timed out after {timeout_sec}s for {url}") from e

        if proc.returncode != 0:
            raise VideoExtractionError(f"yt-dlp metadata extraction failed: {proc.stderr}")

        # If search returned multiple lines or single json
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip().startswith("{")]
        if not lines:
            raise VideoExtractionError("No valid JSON metadata returned by yt-dlp.")

        try:
            data = json.loads(lines[0])
            return VideoMetadata.from_dict(data)
        except json.JSONDecodeError as e:
            raise VideoExtractionError(f"Failed to parse yt-dlp JSON: {e}")

    def extract_threat_intel(self, meta: VideoMetadata) -> Dict[str, Any]:
        """Analyze talk title, description, tags, and chapters for CTI indicators."""
        chapter_titles = " ".join(str(c.get("title", "")) for c in meta.chapters if isinstance(c, dict))
        tags_str = " ".join(str(t) for t in meta.tags if t)
        combined_text = f"{meta.title}\n{meta.description}\n{tags_str}\n{chapter_titles}"
        lower_text = combined_text.lower()

        cves = sorted(list(set(m.upper() for m in self.CVE_REGEX.findall(combined_text))))
        mitre = sorted(list(set(m.upper() for m in self.MITRE_REGEX.findall(combined_text))))

        tools_detected = [t for t in self.SECURITY_TOOLS if t in lower_text]
        vectors_detected = [v for v in self.ATTACK_VECTORS if v in lower_text]
        platforms_detected = [p for p in self.PLATFORMS if p in lower_text]

        return {
            "cves": cves,
            "mitre_attack": mitre,
            "detected_tools": tools_detected,
            "attack_vectors": vectors_detected,
            "affected_platforms": platforms_detected,
            "has_chapters": bool(meta.chapters),
            "threat_relevance_score": min(100, len(cves) * 30 + len(vectors_detected) * 15 + len(tools_detected) * 10),
        }

    def download_audio(
        self,
        url: str,
        output_dir: Union[str, Path],
        audio_format: str = "mp3",
        audio_quality: str = "192K",
        filename_template: str = "%(id)s.%(ext)s",
        timeout_sec: float = 180.0,
    ) -> Path:
        """Download and convert media stream into extracted audio."""
        if not self.is_installed():
            raise YTDLPNotInstalledError("yt-dlp binary is not installed.")

        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_template = str(out_dir / filename_template)

        cmd = [
            self.yt_dlp_path,
            "-x",
            "--audio-format", audio_format,
            "--audio-quality", audio_quality,
            "-o", out_template,
            "--no-playlist",
            "--no-warnings",
            url,
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if proc.returncode != 0:
            raise VideoExtractionError(f"Audio extraction failed: {proc.stderr}")

        # Locate generated audio file
        candidates = list(out_dir.glob(f"*.{audio_format}"))
        if not candidates:
            # Fallback to other common audio container extensions
            candidates = list(out_dir.glob("*.mp3")) + list(out_dir.glob("*.m4a")) + list(out_dir.glob("*.opus")) + list(out_dir.glob("*.wav")) + list(out_dir.glob("*.aac"))

        if candidates:
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            return candidates[0]

        raise VideoExtractionError(f"No audio file in format '{audio_format}' was produced in {out_dir}")

    def download_subtitles(
        self,
        url: str,
        output_dir: Union[str, Path],
        sub_lang: str = "en",
        timeout_sec: float = 60.0,
    ) -> Optional[Path]:
        """Download transcript / subtitles for rapid keyword text searching."""
        if not self.is_installed():
            raise YTDLPNotInstalledError("yt-dlp binary is not installed.")

        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_template = str(out_dir / "%(id)s.%(ext)s")

        cmd = [
            self.yt_dlp_path,
            "--write-subs",
            "--write-auto-subs",
            "--sub-lang", sub_lang,
            "--skip-download",
            "--convert-subs", "vtt",
            "-o", out_template,
            "--no-warnings",
            url,
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if proc.returncode != 0:
            logger.debug(f"Subtitle download completed with notice: {proc.stderr}")

        candidates = list(out_dir.glob("*.vtt")) + list(out_dir.glob("*.srt"))
        if candidates:
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            return candidates[0]

        return None

    def search_security_talks(
        self,
        query: str,
        max_results: int = 5,
        conference: Optional[str] = None,
        timeout_sec: float = 30.0,
    ) -> List[VideoMetadata]:
        """Search YouTube for conference talks matching query."""
        if not self.is_installed():
            raise YTDLPNotInstalledError("yt-dlp is not installed.")

        full_query = f"{conference} {query}" if conference else query
        search_target = f"ytsearch{max_results}:{full_query}"

        cmd = [
            self.yt_dlp_path,
            "--dump-json",
            "--skip-download",
            "--flat-playlist",
            "--no-warnings",
            search_target,
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        except subprocess.TimeoutExpired as e:
            raise YTDLPError(f"Search timed out after {timeout_sec}s") from e

        results: List[VideoMetadata] = []
        for line in proc.stdout.splitlines():
            line_str = line.strip()
            if line_str.startswith("{"):
                try:
                    data = json.loads(line_str)
                    results.append(VideoMetadata.from_dict(data))
                except json.JSONDecodeError:
                    continue

        if proc.returncode != 0 and not results:
            raise VideoExtractionError(f"yt-dlp search failed (code {proc.returncode}): {proc.stderr}")

        return results

    def harvest_threat_intel(
        self,
        url: str,
        output_dir: Union[str, Path],
        download_audio_track: bool = False,
        download_subs: bool = True,
    ) -> HarvestResult:
        """Run complete security conference talk intelligence harvesting pipeline."""
        meta = self.get_video_info(url)
        intel = self.extract_threat_intel(meta)

        safe_id = re.sub(r'[\\/*?:"<>|]', "_", meta.id) or "video"
        out_path = Path(output_dir).resolve() / safe_id
        out_path.mkdir(parents=True, exist_ok=True)

        audio_file = None
        if download_audio_track:
            try:
                audio_file = self.download_audio(url, out_path)
            except Exception as e:
                logger.warning(f"Audio download failed for {url}: {e}")

        subs_file = None
        if download_subs:
            try:
                subs_file = self.download_subtitles(url, out_path)
            except Exception as e:
                logger.warning(f"Subtitles download failed for {url}: {e}")

        return HarvestResult(
            video_id=meta.id,
            title=meta.title,
            audio_path=audio_file,
            subtitles_path=subs_file,
            metadata=meta,
            threat_intel=intel,
        )

    async def async_get_video_info(self, url: str, **kwargs: Any) -> VideoMetadata:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.get_video_info(url, **kwargs))

    async def async_harvest_threat_intel(self, url: str, output_dir: Union[str, Path], **kwargs: Any) -> HarvestResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.harvest_threat_intel(url, output_dir, **kwargs))

    async def async_search_security_talks(self, *args: Any, **kwargs: Any) -> List[VideoMetadata]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.search_security_talks(*args, **kwargs))

    async def async_download_audio(self, *args: Any, **kwargs: Any) -> Path:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.download_audio(*args, **kwargs))

    async def async_download_subtitles(self, *args: Any, **kwargs: Any) -> Optional[Path]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.download_subtitles(*args, **kwargs))


# Default instance
default_harvester = YTThreatHarvester()
