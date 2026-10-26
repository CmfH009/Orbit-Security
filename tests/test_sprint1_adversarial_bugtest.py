"""Adversarial bugtest for Sprint 1 deliverables.

Covers three deferred minors:
1. ``remediation_summary.txt`` must list the optional executive PDF.
2. ``generate_takeover_poc_proof()`` must degrade gracefully (and flag the
   fallback) when a CNAME target cannot resolve.
3. The HMAC-signed ``/api/orbit/radar/action`` endpoint must reject tampered
   domain/action/token combinations with HTTP 403.
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.error
import urllib.request

import pytest

from orbit_security.cli import generate_takeover_poc_proof
from orbit_security.radar_telemetry import (
    RadarTelemetryHTTPHandler,
    RadarTelemetryService,
    generate_action_token,
    verify_action_token,
)
from orbit_security.remediation import DnsRemediationGenerator


def test_remediation_summary_lists_pdf_when_generated(tmp_path):
    domain = "fuzzbrand.com"
    out_dir = tmp_path / "fuzz_out"

    pkg = DnsRemediationGenerator.generate_full_package(
        domain=domain,
        output_dir=out_dir,
        generate_pdf=True,
    )

    summary_text = (out_dir / "remediation_summary.txt").read_text(encoding="utf-8")
    assert "remediation.zone" in summary_text
    assert "remediation.tf" in summary_text
    assert "security.txt" in summary_text
    assert ".pdf" in summary_text
    assert pkg["pdf_file"] is not None
    assert out_dir.joinpath("remediation_summary.txt").exists()
    assert pkg["pdf_file"].endswith(".pdf")


def test_remediation_summary_omits_pdf_when_not_generated(tmp_path):
    out_dir = tmp_path / "no_pdf_out"

    pkg = DnsRemediationGenerator.generate_full_package(
        domain="nopdfbrand.com",
        output_dir=out_dir,
        generate_pdf=False,
    )

    summary_text = (out_dir / "remediation_summary.txt").read_text(encoding="utf-8")
    assert pkg["pdf_file"] is None
    assert ".pdf" not in summary_text


def test_takeover_poc_handles_unresolved_cname_notice():
    subdomain = "ghost.unresolvedtarget123.com"
    poc = generate_takeover_poc_proof(subdomain, cname_target="target.unresolved.local")

    assert "safe_harbor_notice" in poc
    assert "target.unresolved.local" in poc["curl_command"]
    # Reserved / non-public TLD must be reported as an assigned placeholder.
    assert poc["fallback_assigned"] is True
    assert "did not resolve" in poc["safe_harbor_notice"].lower()


def test_takeover_poc_marks_resolvable_cname_as_non_fallback():
    poc = generate_takeover_poc_proof("shop.acmebrand.com", cname_target="shops.myshopify.com")

    assert poc["fallback_assigned"] is False
    assert "did not resolve" not in poc["safe_harbor_notice"].lower()


def test_takeover_poc_handles_blank_cname_target():
    poc = generate_takeover_poc_proof("ghost.acmebrand.com", cname_target="")

    assert poc["fallback_assigned"] is True
    assert poc["cname_target"].endswith(".unresolved.cname")
    assert poc["safe_harbor_notice"]


def test_action_endpoint_tampered_token_rejection(tmp_path):
    domain = "attackertarget.com"
    valid_token = generate_action_token(domain, "stage_retainer")

    # Tampered domain with valid token
    assert verify_action_token("otherdomain.com", "stage_retainer", valid_token) is False
    # Tampered action with valid token
    assert verify_action_token(domain, "unauthorized_action", valid_token) is False
    # Missing / truncated tokens
    assert verify_action_token(domain, "stage_retainer", "") is False
    assert verify_action_token(domain, "stage_retainer", valid_token[:8]) is False


@pytest.fixture
def action_server(tmp_path):
    """Live loopback HTTP server bound to an isolated telemetry service."""
    service = RadarTelemetryService(
        queries_file=tmp_path / "adversarial_queries.jsonl",
        leads_file=tmp_path / "adversarial_leads.json",
        campaigns_dir=tmp_path / "adversarial_campaigns",
    )

    class IsolatedHandler(RadarTelemetryHTTPHandler):
        pass

    IsolatedHandler.service = service
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), IsolatedHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=3.0)


def _action_status(base_url: str, query: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"{base_url}/api/orbit/radar/action?{query}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") or "{}"
        return exc.code, json.loads(body) if body.startswith("{") else {"raw": body}


def test_action_endpoint_rejects_tampered_domain_tokens(action_server):
    valid_token = generate_action_token("attackertarget.com", "stage_retainer")
    status, payload = _action_status(
        action_server,
        f"action=stage_retainer&domain=evil.example&token={valid_token}",
    )

    assert status == 403
    assert payload.get("ok") is False


def test_action_endpoint_rejects_tampered_action_tokens(action_server):
    domain = "attackertarget.com"
    valid_token = generate_action_token(domain, "stage_retainer")
    status, payload = _action_status(
        action_server,
        f"action=delete_everything&domain={domain}&token={valid_token}",
    )

    assert status == 403
    assert payload.get("ok") is False


def test_action_endpoint_rejects_missing_or_malformed_tokens(action_server):
    domain = "attackertarget.com"
    for query in (
        f"action=stage_retainer&domain={domain}",
        f"action=stage_retainer&domain={domain}&token=deadbeefdeadbeef",
        f"action=stage_retainer&domain={domain}&token={generate_action_token(domain, 'stage_retainer')[:8]}",
    ):
        status, payload = _action_status(action_server, query)
        assert status == 403, query
        assert payload.get("ok") is False


def test_action_token_is_case_and_whitespace_normalized():
    token = generate_action_token("Attackertarget.COM", "stage_retainer")
    assert verify_action_token("  attackertarget.com  ", "stage_retainer", token) is True
    assert verify_action_token("attackertarget.com", "STAGE_RETAINER", token) is False
