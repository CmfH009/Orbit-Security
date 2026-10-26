import json
import pytest
from orbit_security.radar_telemetry import (
    format_discord_radar_embed,
    generate_action_token,
    verify_action_token,
    RadarTelemetryHandler,
)


def test_format_discord_radar_embed_contains_action_components():
    record = {"domain": "smartmouseco.com", "score": 85, "grade": "B", "trigger_source": "radar_submit"}
    enrichment = {"registrar": "GoDaddy", "tech_stack": ["Shopify"]}
    base_url = "https://orbit-security-api.run.app"
    
    payload = format_discord_radar_embed(record, enrichment=enrichment, base_url=base_url)
    
    assert "components" in payload
    assert len(payload["components"]) > 0
    action_row = payload["components"][0]
    assert action_row["type"] == 1
    buttons = action_row["components"]
    assert len(buttons) >= 2
    assert any("Generate Retainer" in b["label"] or "Stage Retainer" in b["label"] for b in buttons)
    retainer_btn = next(b for b in buttons if "Retainer" in b["label"])
    assert "action=stage_retainer" in retainer_btn["url"]
    assert "domain=smartmouseco.com" in retainer_btn["url"]


def test_action_token_generation_and_verification():
    domain = "testbrand.com"
    token = generate_action_token(domain, action="stage_retainer")
    assert isinstance(token, str)
    assert len(token) > 0
    assert verify_action_token(domain, action="stage_retainer", token=token) is True
    assert verify_action_token(domain, action="stage_retainer", token="invalid") is False
    assert verify_action_token("otherdomain.com", action="stage_retainer", token=token) is False


def test_radar_action_http_handler_stage_retainer(tmp_path, monkeypatch):
    import http.server
    import threading
    import urllib.request
    import urllib.error
    from orbit_security.radar_lead_enricher import RadarLeadEnricher
    from orbit_security.radar_telemetry import RadarTelemetryService, RadarTelemetryHTTPHandler

    # Mock enrich_domain to prevent real external DNS/HTTP lookups during test
    monkeypatch.setattr(
        RadarLeadEnricher,
        "enrich_domain",
        lambda self, domain, **kw: {"domain": domain, "registrar": "Mock Registrar", "tech_stack": ["Shopify"]},
    )

    service = RadarTelemetryService(
        queries_file=tmp_path / "queries.jsonl",
        leads_file=tmp_path / "leads.json",
        campaigns_dir=tmp_path / "campaigns",
    )

    class CustomHandler(RadarTelemetryHTTPHandler):
        pass

    CustomHandler.service = service
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CustomHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    domain = "triggerbrand.com"
    token = generate_action_token(domain, "stage_retainer")

    try:
        # 1. Valid token triggers staging
        url_valid = f"http://127.0.0.1:{port}/api/orbit/radar/action?action=stage_retainer&domain={domain}&token={token}"
        req = urllib.request.Request(url_valid)
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["action"] == "stage_retainer"
            assert data["domain"] == domain
            assert "deliverables" in data

        # 2. Invalid token rejected with 403
        url_invalid = f"http://127.0.0.1:{port}/api/orbit/radar/action?action=stage_retainer&domain={domain}&token=badtoken"
        req_bad = urllib.request.Request(url_invalid)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_bad, timeout=5)
        assert exc_info.value.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()
