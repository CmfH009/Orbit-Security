"""Unit tests for orbit_security.gemini_cli_bridge (TDD).

Validates:
1. Binary resolution and execution of gemini-api CLI.
2. Exit-code 0 success with machine-parsable JSON stdout and dry-run flag detection.
3. Exit-code 1 runtime error and structured error envelope parsing.
4. Exit-code 2 usage / syntax error.
5. Exit-code 3 authentication / authorization error with failover to local Ollama/deterministic fallback.
6. Rate limit / 429 quota exhaustion detection and failover.
7. Non-blocking disk-only TTS generation with path output.
8. Async subprocess execution parity.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from orbit_security.gemini_cli_bridge import (
    GeminiCLIBridge,
    GeminiCLIResult,
    GeminiRuntimeError,
    GeminiUsageError,
    GeminiAuthError,
)
from orbit_security.triage_agent import LocalTriageAgent, TriageRemediationSpec
from orbit_security.inbox_triage_bridge import InboundTriageDecision, TriageAction


@pytest.fixture
def bridge():
    return GeminiCLIBridge()


def test_bridge_binary_resolution():
    bridge = GeminiCLIBridge()
    assert bridge.binary_path != ""
    assert "gemini-api" in bridge.binary_path


def test_handle_process_result_exit_code_0(bridge):
    sample_stdout = json.dumps({
        "response": "Analysis complete",
        "score": 9.5
    })
    result = bridge._handle_process_result(returncode=0, stdout=sample_stdout, stderr="")
    assert result.exit_code == 0
    assert result.success is True
    assert result.data["response"] == "Analysis complete"
    assert result.data["score"] == 9.5
    assert result.dry_run is False


def test_handle_process_result_exit_code_0_dry_run(bridge):
    sample_stdout = json.dumps({
        "dry_run": True,
        "request": {"method": "POST"}
    })
    result = bridge._handle_process_result(returncode=0, stdout=sample_stdout, stderr="")
    assert result.exit_code == 0
    assert result.success is True
    assert result.dry_run is True


def test_handle_process_result_exit_code_1_runtime(bridge):
    err_json = json.dumps({
        "error_type": "CLI_VALIDATION",
        "message": "Invalid schema parameter",
        "exit_code": 1
    })
    result = bridge._handle_process_result(returncode=1, stdout="", stderr=err_json)
    assert result.exit_code == 1
    assert result.success is False
    assert result.error_type == "CLI_VALIDATION"
    assert "Invalid schema parameter" in result.error_message


def test_handle_process_result_exit_code_2_usage(bridge):
    err_text = "Error: unknown flag --invalid"
    result = bridge._handle_process_result(returncode=2, stdout="", stderr=err_text)
    assert result.exit_code == 2
    assert result.success is False
    assert result.error_type == "USAGE_ERROR"
    assert "unknown flag" in result.error_message


def test_handle_process_result_exit_code_3_auth(bridge):
    auth_err_json = json.dumps({
        "error_type": "authentication_error",
        "message": "Missing API Key or identity",
        "exit_code": 3
    })
    result = bridge._handle_process_result(returncode=3, stdout="", stderr=auth_err_json)
    assert result.exit_code == 3
    assert result.success is False
    assert result.error_type == "authentication_error"
    assert "Missing API Key" in result.error_message


def test_handle_process_result_rate_limit_detection(bridge):
    stderr_text = "HTTP 429 Too Many Requests: RESOURCE_EXHAUSTED"
    result = bridge._handle_process_result(returncode=1, stdout="", stderr=stderr_text)
    assert result.exit_code == 3
    assert result.error_type == "RATE_LIMIT_EXCEEDED"
    assert "RESOURCE_EXHAUSTED" in result.error_message


def test_generate_automatic_failover_on_exit_code_3(bridge):
    fallback_mock = MagicMock(return_value={"status": "triage_via_ollama", "cve": "CVE-2024-TEST"})

    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=3,
            success=False,
            error_type="authentication_error",
            error_message="API key not found",
            stderr="Auth failed",
        )

        res = bridge.generate(
            prompt="Triage CVE-2024-TEST",
            fallback_fn=fallback_mock,
        )

        assert res.success is True
        assert res.failed_over is True
        assert res.data["status"] == "triage_via_ollama"
        fallback_mock.assert_called_once()


def test_triage_vulnerability_with_fallback(bridge, tmp_path):
    from orbit_security.blackboard import Blackboard
    bb = Blackboard(db_path=tmp_path / "bb.db")
    agent = LocalTriageAgent(ollama_url="http://127.0.0.1:99999/api/chat", blackboard=bb)

    payload = {"target": "auth.example.com", "cve_id": "CVE-2024-21887"}

    # Mock execute_cli to return exit code 3 (unauthenticated in headless agent mode)
    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=3,
            success=False,
            error_type="authentication_error",
            error_message="Credential missing",
        )

        spec, cli_res = bridge.triage_vulnerability(
            event_type="CISA_KEV_MATCH_DETECTED",
            payload=payload,
            fallback_agent=agent,
        )

        assert spec is not None
        assert isinstance(spec, TriageRemediationSpec)
        assert spec.cve_id == "CVE-2024-21887"
        assert spec.threat_level == "CRITICAL"
        assert cli_res.failed_over is True


def test_tts_disk_artifact_invocation(bridge, tmp_path):
    out_dir = str(tmp_path / "tts_out")
    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=0,
            success=True,
            stdout=f"{out_dir}\\alert.wav",
        )

        res = bridge.tts("Critical security alert detected", out_dir_or_file=out_dir)
        assert res.success is True
        assert "alert.wav" in res.stdout
        mock_exec.assert_called_once()
        args = mock_exec.call_args[0][0]
        assert "tts" in args
        assert "--out" in args
        assert out_dir in args


def test_dry_run_generate_integration(bridge):
    """Executes live offline --dry-run call against local gemini-api binary."""
    res = bridge.generate(prompt="Test connection", dry_run=True)
    assert res.exit_code == 0
    assert res.success is True
    assert res.dry_run is True
    assert isinstance(res.data, dict)
    assert res.data.get("dry_run") is True
    assert res.data.get("request", {}).get("method") == "POST"


@pytest.mark.asyncio
async def test_generate_async_execution(bridge):
    fallback_mock = AsyncMock(return_value={"async_triage": True})

    with patch.object(bridge, "execute_cli_async") as mock_async_exec:
        mock_async_exec.return_value = GeminiCLIResult(
            exit_code=3,
            success=False,
            error_type="authentication_error",
        )

        res = await bridge.generate_async("Async test", fallback_fn=fallback_mock)
        assert res.success is True
        assert res.failed_over is True
        assert res.data["async_triage"] is True


def test_execute_json_success_with_schema(bridge):
    payload = {
        "sender": "lead@agency.com",
        "subject": "Re: Pricing",
        "intent": "INQUIRY_PRICING",
        "confidence": 0.95,
        "reasoning": "Agency asked for monitoring price.",
        "recommended_action": "AUTONOMOUS_REPLY",
        "suggested_tier": "monitoring",
        "portal_link_requested": False,
        "draft_reply_subject": "Re: Pricing",
        "draft_reply_body": "Monitoring is $499/mo.\n\nBest,\nCarson Haynes",
        "provider_resolved": "GEMINI_CLI",
    }
    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=0,
            success=True,
            data=payload,
            stdout=json.dumps(payload),
        )
        res = bridge.execute_json("Analyze this message", schema=InboundTriageDecision)
        assert res.success is True
        assert res.exit_code == 0
        assert isinstance(res.data, InboundTriageDecision)
        assert res.data.intent == "INQUIRY_PRICING"
        assert res.data.recommended_action == TriageAction.AUTONOMOUS_REPLY


def test_execute_json_markdown_wrapped_json(bridge):
    payload = {"status": "ok", "count": 42}
    wrapped_text = f"```json\n{json.dumps(payload)}\n```"

    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=0,
            success=True,
            data=wrapped_text,
            stdout=wrapped_text,
        )
        res = bridge.execute_json("Extract data")
        assert res.success is True
        assert res.data == payload


def test_execute_json_invalid_json_returns_error(bridge):
    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=0,
            success=True,
            data="Not valid json at all",
            stdout="Not valid json at all",
        )
        res = bridge.execute_json("Extract data")
        assert res.success is False
        assert res.exit_code == 1
        assert res.error_type == "JSON_DECODE_ERROR"


def test_execute_json_schema_validation_error(bridge):
    # Missing required fields according to InboundTriageDecision
    bad_payload = {"sender": "lead@agency.com"}
    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=0,
            success=True,
            data=bad_payload,
            stdout=json.dumps(bad_payload),
        )
        res = bridge.execute_json("Analyze", schema=InboundTriageDecision)
        assert res.success is False
        assert res.exit_code == 1
        assert res.error_type == "SCHEMA_VALIDATION_ERROR"


def test_execute_json_subprocess_failure_forwarded(bridge):
    with patch.object(bridge, "execute_cli") as mock_exec:
        mock_exec.return_value = GeminiCLIResult(
            exit_code=2,
            success=False,
            error_type="USAGE_ERROR",
            error_message="Unknown flag",
        )
        res = bridge.execute_json("Analyze", schema=InboundTriageDecision)
        assert res.success is False
        assert res.exit_code == 2
        assert res.error_type == "USAGE_ERROR"
