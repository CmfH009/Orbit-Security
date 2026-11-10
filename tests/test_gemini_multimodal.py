"""Unit tests for Gemini API Multimodal Tool Return & Files API Adapter.

Validates:
1. Google Files API Adapter:
   - Upload of security audit artifacts (PDF, PNG, PPT, ODS, etc.).
   - Deduplication / caching via SHA-256 digest.
   - Resumable upload protocol handling.
   - Generation of clean `fileData` pointers and Files API URIs (`files/{file_id}`).
2. Multimodal Tool Response Formatter:
   - Interactions API schema (`FunctionResultSubcontent` for document, image, audio, video).
   - GenerateContent API schema (`parts` with `fileData`).
   - MediaProcessing flags (`STATIC` vs `AGENTIC`, start/end offsets, fps).
   - Rich document support (PDF, PPTX, ODS, HTML).
   - Replacement of inline raw base64 bloat with clean URI pointers.
3. MCP Tool Adapter:
   - Wrapping tool execution results containing file paths or artifact outputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from orbit_security.tools.gemini_multimodal import (
    GoogleFilesApiAdapter,
    MediaProcessingConfig,
    MediaProcessingMode,
    MultimodalDocumentType,
    MultimodalToolReturn,
    UploadedArtifact,
    adapt_mcp_result_to_multimodal,
)


@pytest.fixture
def temp_audit_pdf(tmp_path: Path) -> Path:
    """Creates a temporary sample audit PDF file."""
    pdf_path = tmp_path / "orbit_security_audit.pdf"
    pdf_path.write_bytes(b"%PDF-1.7 ... Fake audit report binary contents for testing ...")
    return pdf_path


@pytest.fixture
def temp_audit_pptx(tmp_path: Path) -> Path:
    """Creates a temporary sample executive PPT presentation file."""
    ppt_path = tmp_path / "board_briefing.pptx"
    ppt_path.write_bytes(b"PK\x03\x04 fake powerpoint presentation zip container")
    return ppt_path


@pytest.fixture
def temp_audit_ods(tmp_path: Path) -> Path:
    """Creates a temporary sample spreadsheet file."""
    ods_path = tmp_path / "cve_matrix.ods"
    ods_path.write_bytes(b"PK\x03\x04 fake open document spreadsheet container")
    return ods_path


class TestGoogleFilesApiAdapter:
    """Tests for uploading artifacts and managing Google Files API URIs."""

    def test_detect_mime_type(self, temp_audit_pdf: Path, temp_audit_pptx: Path, temp_audit_ods: Path):
        adapter = GoogleFilesApiAdapter(api_key="test-api-key")
        assert adapter.detect_mime_type(temp_audit_pdf) == "application/pdf"
        assert adapter.detect_mime_type(temp_audit_pptx) == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        assert adapter.detect_mime_type(temp_audit_ods) == "application/vnd.oasis.opendocument.spreadsheet"

    def test_upload_artifact_success(self, temp_audit_pdf: Path):
        adapter = GoogleFilesApiAdapter(api_key="test-api-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "file": {
                "name": "files/audit-123456",
                "uri": "https://generativelanguage.googleapis.com/v1beta/files/audit-123456",
                "displayName": "orbit_security_audit.pdf",
                "mimeType": "application/pdf",
                "sizeBytes": "1024",
                "state": "ACTIVE",
            }
        }

        with patch("httpx.Client.post", return_value=mock_response):
            artifact = adapter.upload_file(temp_audit_pdf, display_name="Q4 Security Audit")

            assert isinstance(artifact, UploadedArtifact)
            assert artifact.file_name == "files/audit-123456"
            assert artifact.uri == "https://generativelanguage.googleapis.com/v1beta/files/audit-123456"
            assert artifact.mime_type == "application/pdf"
            assert artifact.sha256 == hashlib.sha256(temp_audit_pdf.read_bytes()).hexdigest()

    def test_upload_artifact_cached_deduplication(self, temp_audit_pdf: Path):
        adapter = GoogleFilesApiAdapter(api_key="test-api-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "file": {
                "name": "files/audit-dedup-1",
                "uri": "https://generativelanguage.googleapis.com/v1beta/files/audit-dedup-1",
                "mimeType": "application/pdf",
            }
        }

        with patch("httpx.Client.post", return_value=mock_response) as mock_post:
            # First upload triggers HTTP POST
            art1 = adapter.upload_file(temp_audit_pdf)
            assert mock_post.call_count == 1

            # Second upload of the same file uses in-memory sha256 cache without HTTP request
            art2 = adapter.upload_file(temp_audit_pdf)
            assert mock_post.call_count == 1
            assert art1.uri == art2.uri


class TestMultimodalToolReturn:
    """Tests formatting function responses for Gemini APIs without base64 bloat."""

    def test_interactions_api_document_format(self):
        uploaded = UploadedArtifact(
            file_name="files/cve-summary-pdf",
            uri="https://generativelanguage.googleapis.com/v1beta/files/cve-summary-pdf",
            mime_type="application/pdf",
            display_name="CVE Summary.pdf",
            size_bytes=4096,
            sha256="abcdef123456",
        )

        tool_return = MultimodalToolReturn(
            tool_name="generate_security_audit",
            call_id="call_sec_99",
            summary_text="Generated Executive Security Audit Report (4 findings).",
            artifacts=[uploaded],
            media_processing=MediaProcessingConfig(mode=MediaProcessingMode.AGENTIC),
        )

        interaction_result = tool_return.to_interactions_function_result()

        assert interaction_result["type"] == "function_result"
        assert interaction_result["name"] == "generate_security_audit"
        assert interaction_result["call_id"] == "call_sec_99"

        result_blocks = interaction_result["result"]
        assert len(result_blocks) == 2
        assert result_blocks[0] == {
            "type": "text",
            "text": "Generated Executive Security Audit Report (4 findings).",
        }
        assert result_blocks[1] == {
            "type": "document",
            "uri": "https://generativelanguage.googleapis.com/v1beta/files/cve-summary-pdf",
            "mime_type": "application/pdf",
        }

    def test_media_processing_flags(self):
        config_agentic = MediaProcessingConfig(mode=MediaProcessingMode.AGENTIC)
        assert config_agentic.mode.value == "AGENTIC"

        config_static = MediaProcessingConfig(
            mode=MediaProcessingMode.STATIC,
            start_offset="5.0s",
            end_offset="30.0s",
            fps=2,
        )
        as_dict = config_static.to_dict()
        assert as_dict["type"] == "static"
        assert as_dict["fps"] == 2
        assert as_dict["start_offset"] == "5.0s"
        assert as_dict["end_offset"] == "30.0s"

    def test_classic_generate_content_filedata_format(self):
        uploaded = UploadedArtifact(
            file_name="files/diagram-png",
            uri="https://generativelanguage.googleapis.com/v1beta/files/diagram-png",
            mime_type="image/png",
            display_name="attack_graph.png",
            size_bytes=2048,
            sha256="1234567890ab",
        )

        tool_return = MultimodalToolReturn(
            tool_name="render_attack_tree",
            call_id="call_tree_42",
            summary_text="Attack tree visual diagram rendered.",
            artifacts=[uploaded],
        )

        classic_part = tool_return.to_generate_content_part()
        assert "functionResponse" in classic_part
        response_data = classic_part["functionResponse"]
        assert response_data["name"] == "render_attack_tree"
        assert response_data["response"]["fileData"] == {
            "fileUri": "https://generativelanguage.googleapis.com/v1beta/files/diagram-png",
            "mimeType": "image/png",
        }

    def test_mcp_result_adaptation(self, temp_audit_pdf: Path):
        mcp_raw_result = {
            "status": "success",
            "tool": "export_client_briefing",
            "result": f"Report successfully generated at {temp_audit_pdf}",
            "artifact_path": str(temp_audit_pdf),
        }

        mock_adapter = MagicMock(spec=GoogleFilesApiAdapter)
        mock_adapter.upload_file.return_value = UploadedArtifact(
            file_name="files/briefing-001",
            uri="https://generativelanguage.googleapis.com/v1beta/files/briefing-001",
            mime_type="application/pdf",
            display_name="orbit_security_audit.pdf",
            size_bytes=100,
            sha256="abc",
        )

        multimodal_result = adapt_mcp_result_to_multimodal(
            tool_name="export_client_briefing",
            call_id="call_mcp_1",
            raw_result=mcp_raw_result,
            files_adapter=mock_adapter,
        )

        assert isinstance(multimodal_result, MultimodalToolReturn)
        assert len(multimodal_result.artifacts) == 1
        assert multimodal_result.artifacts[0].file_name == "files/briefing-001"

    def test_video_and_audio_content_formatting(self):
        video_art = UploadedArtifact(
            file_name="files/radar-video",
            uri="https://generativelanguage.googleapis.com/v1beta/files/radar-video",
            mime_type="video/mp4",
            display_name="radar_teaser.mp4",
        )
        audio_art = UploadedArtifact(
            file_name="files/briefing-audio",
            uri="https://generativelanguage.googleapis.com/v1beta/files/briefing-audio",
            mime_type="audio/mp3",
            display_name="voice_debrief.mp3",
        )

        tool_return = MultimodalToolReturn(
            tool_name="render_multimodal_briefing",
            call_id="call_media_101",
            summary_text="Video teaser and spoken debrief generated.",
            artifacts=[video_art, audio_art],
            media_processing=MediaProcessingConfig(
                mode=MediaProcessingMode.STATIC,
                fps=4,
                start_offset="0.0s",
                end_offset="15.0s",
            ),
        )

        res = tool_return.to_interactions_function_result()
        blocks = res["result"]
        assert len(blocks) == 3
        assert blocks[0]["type"] == "text"
        assert blocks[1]["type"] == "video"
        assert blocks[1]["media_processing"] == {
            "type": "static",
            "fps": 4,
            "start_offset": "0.0s",
            "end_offset": "15.0s",
        }
        assert blocks[2]["type"] == "audio"

    def test_offline_mode_simulation_when_no_api_key(self, temp_audit_pdf: Path):
        adapter = GoogleFilesApiAdapter(api_key="")
        art = adapter.upload_file(temp_audit_pdf)
        assert art.file_name.startswith("files/local-")
        assert "generativelanguage.googleapis.com" in art.uri
        assert art.mime_type == "application/pdf"

    def test_upload_missing_file_raises_error(self, tmp_path: Path):
        adapter = GoogleFilesApiAdapter(api_key="test")
        with pytest.raises(FileNotFoundError):
            adapter.upload_file(tmp_path / "non_existent_file.pdf")

    def test_client_portal_export_and_upload(self, tmp_path: Path):
        from orbit_security.reporting.client_portal import ClientBriefingData, ClientThreatPortalExporter
        exporter = ClientThreatPortalExporter()
        briefing = ClientBriefingData(
            domain="testcorp.internal",
            client_name="TestCorp",
            score=88,
            grade="B+",
            executive_summary="Comprehensive perimeter security assessment findings.",
            findings=[
                {"title": "Open Redis Port", "category": "Network", "severity": "HIGH"}
            ],
        )
        pdf_out = tmp_path / "audit_deliverable.pdf"
        artifact = exporter.export_and_upload_to_files_api(briefing, pdf_out)
        assert isinstance(artifact, UploadedArtifact)
        assert artifact.file_name.startswith("files/")
        assert artifact.mime_type == "application/pdf"
        assert pdf_out.exists()
