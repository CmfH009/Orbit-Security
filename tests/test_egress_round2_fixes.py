"""Unit tests verifying Round 2 ROE-EGRESS-001 hardening across all 6 assigned modules."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock, patch

import pytest

from orbit_security import egress_guard
from orbit_security.ast_sentinel import check_file_egress_compliance
from orbit_security.egress_guard import EgressViolationError
from orbit_security.inbox_agent import InboxAgent
from orbit_security.network_bonding import (
    create_bonded_http_client,
    is_balancing_proxy_running,
)
from orbit_security.playtest_guard import HeadlessPlaytestGuard
from orbit_security.tools.deploy_oracle_sentinel import verify_cockpit_shuttle_handshake
from orbit_security.tools.gemini_multimodal import GoogleFilesApiAdapter
from orbit_security.tools.koa_gemma_router import KoaGemmaDecisionRouter

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_inbox_agent_stripe_polling_uses_guarded_api_allowlist(
    tmp_path: Path, monkeypatch
) -> None:
    agent = InboxAgent(state_file=str(tmp_path / "inbox_state.json"))
    agent.dispatcher = MagicMock()

    captured_engines: List[Any] = []
    real_factory = egress_guard.create_guarded_httpx_client

    def spy_factory(roe_engine, **kwargs):
        captured_engines.append(roe_engine)
        return real_factory(roe_engine=roe_engine, **kwargs)

    monkeypatch.setattr(egress_guard, "create_guarded_httpx_client", spy_factory)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": []}

    with patch.dict("os.environ", {"STRIPE_SECRET_KEY": "sk_test_hermetic"}):
        with patch("httpx.Client.get", return_value=mock_resp):
            assert agent.check_stripe_payments() == []

    assert len(captured_engines) == 1
    roe = captured_engines[0]
    assert roe.is_target_permitted("api.stripe.com") is True
    assert roe.is_target_permitted("169.254.169.254") is False
    assert roe.is_target_permitted("evil.example") is False

    guarded_client = real_factory(roe_engine=roe, resolver=lambda _: ("93.184.216.34",))
    with guarded_client:
        with pytest.raises(EgressViolationError) as exc_info:
            guarded_client.get("https://evil.example/v1/checkout/sessions")
        assert exc_info.value.code == "ROE_SCOPE_BLOCKED"


def test_network_bonding_rejects_non_loopback_proxy_probes(monkeypatch) -> None:
    def fail_if_called(*args, **kwargs):  # noqa: ARG001
        raise AssertionError("Socket or HTTP probe must not execute for non-loopback proxy")

    monkeypatch.setattr("socket.socket", fail_if_called)
    monkeypatch.setattr("urllib.request.urlopen", fail_if_called)

    assert is_balancing_proxy_running("http://169.254.169.254:8989") is False
    assert is_balancing_proxy_running("https://evil.example:8989") is False


@pytest.mark.asyncio
async def test_network_bonding_client_enforces_egress_and_merges_hooks() -> None:
    async def custom_response_hook(response):  # noqa: ARG001
        return None

    client = create_bonded_http_client(
        timeout=3.0,
        use_proxy=False,
        event_hooks={"response": [custom_response_hook]},
    )
    try:
        assert len(client.event_hooks.get("request", [])) >= 1
        assert custom_response_hook in client.event_hooks.get("response", [])
        assert len(client.event_hooks.get("response", [])) >= 2

        with pytest.raises(EgressViolationError) as loopback_exc:
            await client.get("http://127.0.0.1:8080/admin")
        assert loopback_exc.value.code == "ROE_SCOPE_BLOCKED"

        with pytest.raises(EgressViolationError) as metadata_exc:
            await client.get("http://169.254.169.254/latest/meta-data/")
        assert metadata_exc.value.code == "ROE_SCOPE_BLOCKED"
    finally:
        await client.aclose()


def test_playtest_guard_port_bounds_and_offline_probe() -> None:
    guard = HeadlessPlaytestGuard()
    for bad_port in (0, -1, 65536, True):
        with pytest.raises(ValueError):
            guard.verify_live_server_probes(port=bad_port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]

    res = guard.verify_live_server_probes(port=closed_port)
    assert res["ok"] is True
    assert res["server_online"] is False


def test_deploy_oracle_sentinel_rejects_invalid_loopback_ports() -> None:
    for bad_port in (0, -10, 70000, False):
        with pytest.raises(ValueError):
            verify_cockpit_shuttle_handshake(port=bad_port)


def test_gemini_multimodal_uses_guarded_google_files_api_client(
    tmp_path: Path, monkeypatch
) -> None:
    sample_pdf = tmp_path / "sample.pdf"
    sample_pdf.write_bytes(b"%PDF-1.7 test payload")

    adapter = GoogleFilesApiAdapter(api_key="test-gemini-key")
    captured_engines: List[Any] = []
    real_factory = egress_guard.create_guarded_httpx_client

    def spy_factory(roe_engine, **kwargs):
        captured_engines.append(roe_engine)
        return real_factory(roe_engine=roe_engine, **kwargs)

    monkeypatch.setattr(
        "orbit_security.tools.gemini_multimodal.create_guarded_httpx_client",
        spy_factory,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "file": {
            "name": "files/guarded-1",
            "uri": "https://generativelanguage.googleapis.com/v1beta/files/guarded-1",
            "mimeType": "application/pdf",
        }
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        artifact = adapter.upload_file(sample_pdf)

    assert artifact.file_name == "files/guarded-1"
    assert len(captured_engines) == 1
    roe = captured_engines[0]
    assert roe.is_target_permitted("generativelanguage.googleapis.com") is True
    assert roe.is_target_permitted("evil.example") is False
    assert roe.is_target_permitted("169.254.169.254") is False

    guarded_client = real_factory(roe_engine=roe, resolver=lambda _: ("93.184.216.34",))
    with guarded_client:
        with pytest.raises(EgressViolationError):
            guarded_client.post("https://evil.example/upload")


def test_koa_gemma_router_validates_loopback_ollama_url() -> None:
    for bad_url in (
        "http://169.254.169.254:11434",
        "https://evil.example:11434",
        "file:///etc/passwd",
        "ftp://localhost:11434",
    ):
        with pytest.raises(ValueError):
            KoaGemmaDecisionRouter(ollama_url=bad_url)

    router_localhost = KoaGemmaDecisionRouter(ollama_url="http://localhost:11434/")
    assert router_localhost.ollama_url == "http://localhost:11434"
    sync_client = router_localhost._get_sync_client()
    try:
        assert sync_client is not None
    finally:
        sync_client.close()

    router_ip = KoaGemmaDecisionRouter(ollama_url="http://127.0.0.1:11434")
    assert router_ip.ollama_url == "http://127.0.0.1:11434"


def test_ast_sentinel_zero_egress_violations_across_round2_modules() -> None:
    targets = [
        REPO_ROOT / "src" / "orbit_security" / "inbox_agent.py",
        REPO_ROOT / "src" / "orbit_security" / "network_bonding.py",
        REPO_ROOT / "src" / "orbit_security" / "playtest_guard.py",
        REPO_ROOT / "src" / "orbit_security" / "tools" / "deploy_oracle_sentinel.py",
        REPO_ROOT / "src" / "orbit_security" / "tools" / "gemini_multimodal.py",
        REPO_ROOT / "src" / "orbit_security" / "tools" / "koa_gemma_router.py",
    ]
    for path in targets:
        violations = check_file_egress_compliance(path, path.read_text(encoding="utf-8"))
        assert violations == [], f"Unexpected ROE-EGRESS-001 violations in {path}: {violations}"
