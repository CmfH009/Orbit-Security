"""Gemini API Multimodal Tool Return & Google Files API Adapter.

Implements frontier multimodal tool return specifications for Gemini 3.x models:
- Eliminates context-bloating inline base64 bytes by uploading rich media & documents
  (PDFs, PPT, ODS, PNG, MP4) to Google Files API and returning clean URI pointers.
- Supports both modern Gemini Interactions API (`function_result` with content blocks)
  and classic GenerateContent API (`functionResponse` with `fileData`).
- Integrates media processing directives (`STATIC` vs `AGENTIC`) for model-driven navigation.
- Automatically adapts MCP tool execution outputs into verified multimodal returns.
"""

from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import httpx

logger = logging.getLogger("orbit_security.gemini_multimodal")

# Ensure rich Office & OpenDocument MIME types are properly registered
_EXTRA_MIME_TYPES = {
    ".pdf": "application/pdf",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".ppt": "application/vnd.ms-powerpoint",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".mp3": "audio/mp3",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".html": "text/html",
    ".csv": "text/csv",
    ".json": "application/json",
    ".md": "text/markdown",
}
for ext, mime in _EXTRA_MIME_TYPES.items():
    mimetypes.add_type(mime, ext)


class MediaProcessingMode(str, Enum):
    """Directives controlling how the model ingests media content."""
    UNSPECIFIED = "MEDIA_PROCESSING_UNSPECIFIED"
    STATIC = "STATIC"       # Fixed-rate frame extraction; all frames in context
    AGENTIC = "AGENTIC"     # Dynamic model-guided navigation; optimal for long docs/video


class MultimodalDocumentType(str, Enum):
    DOCUMENT = "document"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"


@dataclass
class MediaProcessingConfig:
    """Media processing parameters for Gemini Interactions API."""
    mode: MediaProcessingMode = MediaProcessingMode.AGENTIC
    fps: Optional[int] = None
    start_offset: Optional[str] = None  # e.g., "10.5s"
    end_offset: Optional[str] = None    # e.g., "30s"

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"type": self.mode.value.lower()}
        if self.fps is not None:
            data["fps"] = self.fps
        if self.start_offset is not None:
            data["start_offset"] = self.start_offset
        if self.end_offset is not None:
            data["end_offset"] = self.end_offset
        return data


@dataclass
class UploadedArtifact:
    """Represents a file uploaded to the Google Files API."""
    file_name: str          # e.g. "files/abc-123"
    uri: str                # e.g. "https://generativelanguage.googleapis.com/v1beta/files/abc-123"
    mime_type: str
    display_name: str = ""
    size_bytes: int = 0
    sha256: str = ""
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GoogleFilesApiAdapter:
    """Lightweight client adapter for the Google Gemini Files API.

    Provides fast, deduplicated artifact uploads and URI generation.
    """

    BASE_URL = "https://generativelanguage.googleapis.com"
    UPLOAD_ENDPOINT = "https://generativelanguage.googleapis.com/upload/v1beta/files"

    def __init__(self, api_key: Optional[str] = None, timeout_s: float = 30.0):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
        self.timeout_s = timeout_s
        self._cache_by_hash: Dict[str, UploadedArtifact] = {}

    @staticmethod
    def detect_mime_type(file_path: Union[str, Path]) -> str:
        """Determines the standard MIME type for an artifact."""
        p = Path(file_path)
        ext = p.suffix.lower()
        if ext in _EXTRA_MIME_TYPES:
            return _EXTRA_MIME_TYPES[ext]
        mime, _ = mimetypes.guess_type(str(p))
        return mime or "application/octet-stream"

    @staticmethod
    def compute_sha256(file_path: Union[str, Path]) -> str:
        """Computes SHA-256 hash of file content for deduplication."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def upload_file(
        self,
        file_path: Union[str, Path],
        display_name: Optional[str] = None,
        mime_type: Optional[str] = None,
    ) -> UploadedArtifact:
        """Uploads a local audit or media file to Google Files API.

        Uses in-memory SHA256 cache to avoid re-uploading identical files.
        """
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Artifact file not found: {p}")

        file_hash = self.compute_sha256(p)
        if file_hash in self._cache_by_hash:
            logger.debug(f"Returning cached Files API URI for {p.name} ({file_hash[:8]})")
            return self._cache_by_hash[file_hash]

        resolved_mime = mime_type or self.detect_mime_type(p)
        resolved_name = display_name or p.name
        file_bytes = p.read_bytes()
        file_size = len(file_bytes)

        # In offline/test environments without an active API key, produce a deterministic simulated URI
        if not self.api_key:
            simulated_id = f"local-{file_hash[:12]}"
            artifact = UploadedArtifact(
                file_name=f"files/{simulated_id}",
                uri=f"{self.BASE_URL}/v1beta/files/{simulated_id}",
                mime_type=resolved_mime,
                display_name=resolved_name,
                size_bytes=file_size,
                sha256=file_hash,
            )
            self._cache_by_hash[file_hash] = artifact
            return artifact

        # Real upload using resumable or multipart POST
        headers = {
            "x-goog-api-key": self.api_key,
            "X-Goog-Upload-Protocol": "multipart",
        }

        # Build multipart payload
        metadata = {
            "file": {
                "display_name": resolved_name,
                "mime_type": resolved_mime,
            }
        }

        files = {
            "metadata": (None, json.dumps(metadata), "application/json; charset=UTF-8"),
            "file": (p.name, file_bytes, resolved_mime),
        }

        with httpx.Client(timeout=self.timeout_s) as client:
            resp = client.post(
                self.UPLOAD_ENDPOINT,
                headers={"x-goog-api-key": self.api_key},
                files=files,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"Files API upload failed [{resp.status_code}]: {resp.text}"
                )

            data = resp.json().get("file", {})
            file_name = data.get("name", f"files/{file_hash[:12]}")
            file_uri = data.get("uri") or f"{self.BASE_URL}/v1beta/{file_name}"

            artifact = UploadedArtifact(
                file_name=file_name,
                uri=file_uri,
                mime_type=data.get("mimeType", resolved_mime),
                display_name=data.get("displayName", resolved_name),
                size_bytes=int(data.get("sizeBytes", file_size)),
                sha256=file_hash,
                created_at=data.get("createTime"),
            )
            self._cache_by_hash[file_hash] = artifact
            return artifact


@dataclass
class MultimodalToolReturn:
    """Standardized multimodal tool return payload.

    Serializes to both Gemini Interactions API and classic GenerateContent schemas.
    """
    tool_name: str
    call_id: str
    summary_text: str
    artifacts: List[UploadedArtifact] = field(default_factory=list)
    media_processing: Optional[MediaProcessingConfig] = None

    def _classify_content_type(self, mime_type: str) -> str:
        """Maps mime type to Gemini Interactions content type."""
        if mime_type.startswith("image/"):
            return "image"
        elif mime_type.startswith("video/"):
            return "video"
        elif mime_type.startswith("audio/"):
            return "audio"
        else:
            return "document"

    def to_interactions_function_result(self) -> Dict[str, Any]:
        """Converts return to Gemini Interactions API `function_result` step."""
        result_blocks: List[Dict[str, Any]] = [
            {"type": "text", "text": self.summary_text}
        ]

        for art in self.artifacts:
            block_type = self._classify_content_type(art.mime_type)
            block: Dict[str, Any] = {
                "type": block_type,
                "uri": art.uri,
                "mime_type": art.mime_type,
            }
            if block_type == "video" and self.media_processing:
                block["media_processing"] = self.media_processing.to_dict()
            result_blocks.append(block)

        return {
            "type": "function_result",
            "name": self.tool_name,
            "call_id": self.call_id,
            "result": result_blocks,
        }

    def to_generate_content_part(self) -> Dict[str, Any]:
        """Converts return to classic Gemini `functionResponse` part with `fileData`."""
        response_data: Dict[str, Any] = {
            "summary": self.summary_text,
            "status": "success",
        }

        if self.artifacts:
            primary = self.artifacts[0]
            response_data["fileData"] = {
                "fileUri": primary.uri,
                "mimeType": primary.mime_type,
            }
            if len(self.artifacts) > 1:
                response_data["additional_files"] = [
                    {"fileUri": a.uri, "mimeType": a.mime_type, "name": a.display_name}
                    for a in self.artifacts[1:]
                ]

        return {
            "functionResponse": {
                "name": self.tool_name,
                "response": response_data,
            }
        }


def adapt_mcp_result_to_multimodal(
    tool_name: str,
    call_id: str,
    raw_result: Dict[str, Any],
    files_adapter: Optional[GoogleFilesApiAdapter] = None,
) -> MultimodalToolReturn:
    """Inspects MCP or tool execution output, extracts generated files,
    uploads them to Files API, and constructs a clean MultimodalToolReturn.
    """
    adapter = files_adapter or GoogleFilesApiAdapter()
    artifacts: List[UploadedArtifact] = []

    # Check for direct artifact_path or file path in result
    candidates: List[str] = []
    if "artifact_path" in raw_result and raw_result["artifact_path"]:
        candidates.append(str(raw_result["artifact_path"]))
    if "file_path" in raw_result and raw_result["file_path"]:
        candidates.append(str(raw_result["file_path"]))
    if "pdf_path" in raw_result and raw_result["pdf_path"]:
        candidates.append(str(raw_result["pdf_path"]))

    # Scan string result for file paths matching known extensions
    result_text = str(raw_result.get("result") or raw_result.get("message") or "")
    for ext in (".pdf", ".pptx", ".ods", ".png", ".jpg", ".mp4", ".html"):
        if ext in result_text:
            for word in result_text.split():
                clean_word = word.strip(" '\"`(),;:")
                if clean_word.endswith(ext) and Path(clean_word).exists():
                    candidates.append(clean_word)

    seen_paths = set()
    for path_str in candidates:
        p = Path(path_str).resolve()
        if p.is_file() and p not in seen_paths:
            seen_paths.add(p)
            try:
                uploaded = adapter.upload_file(p)
                artifacts.append(uploaded)
            except Exception as e:
                logger.warning(f"Failed to upload artifact {p} to Files API: {e}")

    summary = raw_result.get("result") or raw_result.get("summary") or f"Executed {tool_name}"
    if not isinstance(summary, str):
        summary = json.dumps(summary)

    return MultimodalToolReturn(
        tool_name=tool_name,
        call_id=call_id,
        summary_text=summary,
        artifacts=artifacts,
    )
