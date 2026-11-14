"""Tests for Sprint 2: Browser Companion (port 8765) & SPA/DOM Sandbox Verifier Bridge."""

from __future__ import annotations

import base64
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from orbit_security.bounty_active_prober import BountyActiveProber
from orbit_security.bounty_radar import BountyProgram
from orbit_security.blackboard import Blackboard
from orbit_security.egress_guard import EgressViolationError
from orbit_security.exploit_sandbox import (
    BrowserCompanionClient,
    OdysseusBrowserVerifier,
)
from orbit_security.report_verifier import EmpiricalEvidenceArtifact, ReportCriticVerifier


def _public_resolver(hostname: str) -> tuple[str, ...]:
    if hostname.startswith("internal."):
        return ("169.254.169.254",)
    if hostname.endswith("example.com"):
        return ("93.184.216.34",)
    if hostname.endswith("evil.com"):
        return ("198.51.100.42",)
    return ("169.254.169.254",)


class _MockCompanionHandler(BaseHTTPRequestHandler):
    """Loopback handler mimicking browser-companion POST /api/browser/action."""

    actions_received = []

    def log_message(self, format, *args):  # noqa: A002
        return

    def do_POST(self):
        if self.path == "/api/browser/action":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            action_req = json.loads(raw) if raw else {}
            type(self).actions_received.append(action_req)
            act = action_req.get("action")
            if act == "navigate":
                resp = {"action": "navigate", "success": True, "data": {"url": action_req.get("url")}}
            elif act == "get_dom":
                resp = {
                    "action": "get_dom",
                    "success": True,
                    "domMarkdown": "<div>Loaded SPA</div><script>el.innerHTML = location.hash;</script>//# sourceMappingURL=main.bundle.js.map",
                }
            elif act == "screenshot":
                png_bytes = base64.b64encode(b"\x89PNG\r\n\x1a\nMOCKSCREENSHOT").decode("ascii")
                resp = {"action": "screenshot", "success": True, "data": png_bytes, "screenshotBase64": png_bytes}
            elif act == "evaluate":
                resp = {
                    "action": "evaluate",
                    "success": True,
                    "data": {
                        "har": [{"url": "https://app.example.com/main.bundle.js.map", "status": 200}],
                        "redirects": [],
                    },
                }
            else:
                resp = {"action": str(act), "success": False, "error": "unsupported"}
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture()
def mock_companion():
    _MockCompanionHandler.actions_received = []
    server = HTTPServer(("127.0.0.1", 0), _MockCompanionHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _MockCompanionHandler
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def sample_program():
    return BountyProgram(
        program_id="prog-example",
        name="Example Bounty",
        in_scope=["*.example.com"],
        out_of_scope=["blocked.example.com"],
    )


class TestZeroTrustGatesBrowserAdapters:
    def test_companion_rejects_non_loopback_bridge_url(self):
        with pytest.raises(ValueError, match="loopback"):
            BrowserCompanionClient(http_url="https://evil.com:8765")

    def test_companion_blocks_out_of_scope_before_dispatch(self, mock_companion, sample_program, tmp_path):
        http_url, handler = mock_companion
        bb = Blackboard(db_path=tmp_path / "bb_roe.db")
        client = BrowserCompanionClient(http_url=http_url, blackboard=bb, resolver=_public_resolver)

        with pytest.raises(EgressViolationError):
            client.verify_authenticated_target(
                "https://evil.com/admin",
                program=sample_program,
            )

        assert handler.actions_received == []
        blocked_events = bb.get_recent(limit=5, event_type="ROE_SCOPE_BLOCKED")
        assert len(blocked_events) == 1

    def test_odysseus_blocks_redirect_hop_and_bogon_ip(self, sample_program, tmp_path):
        bb = Blackboard(db_path=tmp_path / "bb_redir.db")
        called = []

        def fake_runner(url: str):
            called.append(url)
            return {
                "status_code": 200,
                "dom_html": "<div>ok</div>",
                "redirect_chain": ["https://blocked.example.com/oauth"],
                "har_entries": [],
                "screenshot_bytes": b"",
            }

        verifier = OdysseusBrowserVerifier(
            page_runner=fake_runner,
            blackboard=bb,
            resolver=_public_resolver,
        )

        # Pre-flight redirect chain validation catches blocked.example.com
        with pytest.raises(EgressViolationError) as exc_info:
            verifier.verify_spa_target(
                "https://app.example.com/login",
                program=sample_program,
                redirect_hops=["https://blocked.example.com/oauth"],
            )
        assert exc_info.value.code == "ROE_REDIRECT_BLOCKED"
        assert called == []

        # Bogon IP resolution rejected before invoking runner
        with pytest.raises(EgressViolationError) as bogon_exc:
            verifier.verify_spa_target(
                "https://internal.example.com/meta",
                program=sample_program,
            )
        assert bogon_exc.value.code == "ROE_BOGON_BLOCKED"
        assert called == []


class TestBrowserVerificationAndEvidenceArtifacts:
    def test_companion_client_captures_hashed_evidence_artifacts(self, mock_companion, sample_program):
        http_url, handler = mock_companion
        client = BrowserCompanionClient(http_url=http_url, resolver=_public_resolver)

        res = client.verify_authenticated_target(
            "https://app.example.com/dashboard",
            program=sample_program,
        )

        assert res["ok"] is True
        assert res["transport"] == "http_bridge"
        assert len(handler.actions_received) >= 3
        assert "sourcemap_exposure" in res["detected_flaws"]
        assert "dom_xss_sink" in res["detected_flaws"]

        artifacts = res["artifacts"]
        assert len(artifacts) >= 2
        for art in artifacts:
            assert isinstance(art, EmpiricalEvidenceArtifact)
            assert re.match(r"^ev_[0-9a-f]{12}$", art.artifact_id)

        verdict = ReportCriticVerifier.verify_briefing_pitch(
            pitch_text="Verified sourcemap exposure on app.example.com endpoint /main.bundle.js.map returning HTTP 200.",
            target_domain="app.example.com",
            core_finding="sourcemap_exposure",
            artifacts=artifacts,
            require_artifact_grounding=True,
        )
        assert verdict.passed is True
        assert verdict.verified_artifact_ids

    def test_companion_offline_degrades_gracefully(self, sample_program):
        client = BrowserCompanionClient(http_url="http://127.0.0.1:1", resolver=_public_resolver)
        res = client.verify_authenticated_target("https://app.example.com/", program=sample_program)
        assert res["ok"] is False
        assert "error" in res
        assert res["artifacts"] == []

    def test_odysseus_verifier_detects_sink_sourcemap_and_takeover(self, sample_program):
        def fake_runner(url: str):
            return {
                "status_code": 404,
                "final_url": url,
                "dom_html": (
                    "<html><body>There isn't a GitHub Pages site here."
                    "<script>document.write(userInput);</script>"
                    "//# sourceMappingURL=/static/app.js.map</body></html>"
                ),
                "screenshot_bytes": b"PNGDATA-TAKEOVER-PROOF",
                "har_entries": [
                    {"request": {"url": url}, "response": {"status": 404}},
                    {"request": {"url": f"{url}static/app.js.map"}, "response": {"status": 200}},
                ],
            }

        verifier = OdysseusBrowserVerifier(page_runner=fake_runner, resolver=_public_resolver)
        res = verifier.verify_spa_target("https://app.example.com/", program=sample_program)

        assert res["ok"] is True
        flaws = set(res["detected_flaws"])
        assert {"dom_xss_sink", "sourcemap_exposure", "client_subdomain_takeover"}.issubset(flaws)
        assert any(a.artifact_id.startswith("ev_") and len(a.artifact_id) == 15 for a in res["artifacts"])

    def test_prober_integrates_browser_verification(self, sample_program, tmp_path):
        bb = Blackboard(db_path=tmp_path / "bb_prober.db")
        prober = BountyActiveProber(disclosures_dir=tmp_path, blackboard=bb)

        def fake_runner(url: str):
            return {
                "status_code": 200,
                "final_url": url,
                "dom_html": "<script>target.innerHTML = payload;</script>//# sourceMappingURL=app.js.map",
                "screenshot_bytes": b"PROBER-SCREENSHOT",
                "har_entries": [{"request": {"url": url}, "response": {"status": 200}}],
            }

        result = prober.verify_browser_surface(
            url="https://app.example.com/",
            program=sample_program,
            verifier=OdysseusBrowserVerifier(page_runner=fake_runner, blackboard=bb, resolver=_public_resolver),
        )
        assert result["ok"] is True
        assert result["artifacts"]
        events = bb.get_recent(limit=5, event_type="BROWSER_SANDBOX_EVIDENCE")
        assert len(events) == 1
        assert events[0]["payload"]["artifact_ids"]
