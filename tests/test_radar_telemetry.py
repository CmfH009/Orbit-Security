"""tests/test_radar_telemetry.py: Unit and integration tests for Radar Telemetry & Observer.
====================================================================================
Tests:
- Domain normalization & RFC-compliant validation
- JSONL persistence with thread safety & deduplication
- Blackboard WAL publication (RADAR_DOMAIN_ENTERED)
- Query retrieval, filtering, and aggregate metrics
- HTTP endpoint integration (POST, GET, OPTIONS with CORS)
- Webhook dispatching for high-confidence alerts
- CLI interface execution
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request
import pytest

from orbit_security.radar_telemetry import (
    RadarQueryRecord,
    RadarTelemetryService,
    RadarTelemetryHTTPHandler,
    parse_user_agent_summary,
    format_discord_radar_embed,
)
from orbit_security.radar_lead_enricher import RadarLeadEnricher
from orbit_security.radar_proposal_stager import RadarRetainerProposalStager
from orbit_security.blackboard import (
    EVENT_RADAR_DOMAIN_ENTERED,
    EVENT_RADAR_LEAD_ENRICHED,
    EVENT_RADAR_PROPOSAL_STAGED,
    TOPIC_TELEMETRY,
    Blackboard,
    get_blackboard,
)


@pytest.fixture(autouse=True)
def _isolate_webhook_env(monkeypatch):
    """Keeps radar alerts from reaching real Discord/Slack endpoints during tests.

    Enrichment threads resolve webhook URLs from ``os.environ`` at dispatch time, so
    an inherited ``.env`` value would let unrelated tests post live records to a real
    workspace. Tests that exercise webhook delivery inject the URL explicitly.
    """
    for var in (
        "ORBIT_RADAR_WEBHOOK_URL",
        "ORBIT_DISCORD_WEBHOOK_URL",
        "DISCORD_WEBHOOK_URL",
        "SLACK_WEBHOOK_URL",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def temp_service(tmp_path):
    log_file = tmp_path / "test_radar_queries.jsonl"
    leads_file = tmp_path / "test_enriched_leads.json"
    campaigns_dir = tmp_path / "outbound_campaigns"
    service = RadarTelemetryService(
        queries_file=log_file,
        leads_file=leads_file,
        campaigns_dir=campaigns_dir,
        dedup_window_seconds=1.0,
    )
    yield service
    service.clear_queries()


class TestDomainValidationAndNormalization:
    """Verifies domain cleaning and security boundary gating."""

    def test_normalize_valid_domains(self):
        assert RadarTelemetryService.normalize_domain("https://Shopify.com/path?arg=1") == "shopify.com"
        assert RadarTelemetryService.normalize_domain("http://unbounce.com:8080/") == "unbounce.com"
        assert RadarTelemetryService.normalize_domain("  clientbrand.co.uk.  ") == "clientbrand.co.uk"
        assert RadarTelemetryService.normalize_domain("sub.domain.example.org") == "sub.domain.example.org"

    def test_reject_invalid_and_internal_domains(self):
        assert RadarTelemetryService.is_valid_domain("shopify.com") is True
        assert RadarTelemetryService.is_valid_domain("sub.client.com") is True
        assert RadarTelemetryService.is_valid_domain("cmfh009.github.io") is True

        # Malformed / incomplete
        assert RadarTelemetryService.is_valid_domain("") is False
        assert RadarTelemetryService.is_valid_domain("notadomain") is False
        assert RadarTelemetryService.is_valid_domain("http://") is False
        assert RadarTelemetryService.is_valid_domain("-invalid-.com") is False

        # Restricted / SSRF loopbacks
        assert RadarTelemetryService.is_valid_domain("localhost") is False
        assert RadarTelemetryService.is_valid_domain("server.internal") is False
        assert RadarTelemetryService.is_valid_domain("gateway.local") is False
        assert RadarTelemetryService.is_valid_domain("router.home.arpa") is False
        assert RadarTelemetryService.is_valid_domain("test.localhost") is False


class TestTelemetryRecordingAndPersistence:
    """Tests JSONL persistence, deduplication, and metrics."""

    def test_record_valid_query(self, temp_service):
        res = temp_service.record_query({
            "domain": "shopify.com",
            "trigger_source": "radar_submit",
            "audit_result": {
                "score": 85,
                "grade": "B",
                "risk_label": "LOW RISK",
                "dmarc_status": "pass",
                "spf_status": "pass",
            },
            "session_id": "sess_123",
            "referrer": "https://google.com",
        }, client_ip="192.168.1.100")

        assert res["ok"] is True
        assert res["domain"] == "shopify.com"
        assert res["score"] == 85
        assert res["grade"] == "B"
        assert "id" in res
        assert "recorded_at" in res

        # Verify persisted file
        queries = temp_service.get_recent_queries()
        assert len(queries) == 1
        q = queries[0]
        assert q["domain"] == "shopify.com"
        assert q["score"] == 85
        assert q["grade"] == "B"
        assert q["session_id"] == "sess_123"
        assert q["client_ip"] == "192.168.1.100"

    def test_reject_invalid_query_recording(self, temp_service):
        res = temp_service.record_query({
            "domain": "localhost",
            "trigger_source": "radar_submit",
        })
        assert res["ok"] is False
        assert "Invalid or restricted" in res["error"]
        assert len(temp_service.get_recent_queries()) == 0

    def test_deduplication_window(self, temp_service):
        # First probe
        res1 = temp_service.record_query({
            "domain": "github.io",
            "session_id": "sess_dedup",
            "score": 90,
            "grade": "A",
        })
        assert res1["ok"] is True

        # Second rapid identical probe within window
        res2 = temp_service.record_query({
            "domain": "github.io",
            "session_id": "sess_dedup",
            "score": 90,
            "grade": "A",
        })
        assert res2["ok"] is True

        # File should only contain 1 entry due to dedup
        queries = temp_service.get_recent_queries()
        assert len(queries) == 1

    def test_query_statistics_calculation(self, temp_service):
        temp_service.record_query({"domain": "alpha.com", "score": 95, "grade": "A+"})
        temp_service.record_query({"domain": "beta.com", "score": 75, "grade": "B"})
        temp_service.record_query({"domain": "gamma.com", "score": 40, "grade": "F"})

        stats = temp_service.get_query_stats()
        assert stats["total_probes"] == 3
        assert stats["unique_domains"] == 3
        assert stats["grade_breakdown"].get("A+") == 1
        assert stats["grade_breakdown"].get("B") == 1
        assert stats["grade_breakdown"].get("F") == 1
        assert stats["latest_probe"]["domain"] == "gamma.com"

    def test_query_filtering_by_domain(self, temp_service):
        temp_service.record_query({"domain": "apple.com", "score": 90, "grade": "A"})
        temp_service.record_query({"domain": "microsoft.com", "score": 85, "grade": "B"})
        temp_service.record_query({"domain": "apple-dev.com", "score": 70, "grade": "C"})

        apple_queries = temp_service.get_recent_queries(domain="apple")
        assert len(apple_queries) == 2
        domains = [q["domain"] for q in apple_queries]
        assert "apple.com" in domains
        assert "apple-dev.com" in domains
        assert "microsoft.com" not in domains


class TestBlackboardIntegration:
    """Verifies that queries publish to SQLite WAL event bus for Cockpit SSE HUD."""

    def test_blackboard_event_published(self, tmp_path):
        db_file = tmp_path / "test_blackboard.db"
        bb = Blackboard(db_path=db_file)
        sub_queue = bb.subscribe(maxsize=10)

        log_file = tmp_path / "bb_test_queries.jsonl"
        service = RadarTelemetryService(
            queries_file=log_file,
            leads_file=tmp_path / "bb_leads.json",
            campaigns_dir=tmp_path / "bb_campaigns",
        )

        # Monkey-patch get_blackboard in blackboard module
        import orbit_security.blackboard as bb_mod
        orig_get_bb = bb_mod.get_blackboard
        bb_mod._GLOBAL_BLACKBOARD = bb

        try:
            res = service.record_query({
                "domain": "monstersamonguspodcast.com",
                "score": 30,
                "grade": "F",
                "trigger_source": "radar_submit",
            })
            assert res["ok"] is True

            # Check queue received event
            event = sub_queue.get(timeout=2.0)
            assert event["event_type"] == EVENT_RADAR_DOMAIN_ENTERED
            assert event["topic"] == TOPIC_TELEMETRY
            assert event["payload"]["domain"] == "monstersamonguspodcast.com"
            assert event["payload"]["score"] == 30
            assert event["payload"]["grade"] == "F"
        finally:
            bb.unsubscribe(sub_queue)
            bb_mod._GLOBAL_BLACKBOARD = orig_get_bb()


class TestRadarTelemetryHTTPServer:
    """Tests HTTP endpoints: GET, POST, OPTIONS (CORS preflight)."""

    @pytest.fixture
    def test_server(self, tmp_path):
        import http.server
        log_file = tmp_path / "server_test_queries.jsonl"
        srv_service = RadarTelemetryService(
            queries_file=log_file,
            leads_file=tmp_path / "srv_leads.json",
            campaigns_dir=tmp_path / "srv_campaigns",
        )

        class CustomHandler(RadarTelemetryHTTPHandler):
            service = srv_service

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CustomHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        yield f"http://127.0.0.1:{port}", srv_service
        httpd.shutdown()
        httpd.server_close()

    def test_cors_options_preflight(self, test_server):
        base_url, _ = test_server
        req = urllib.request.Request(
            f"{base_url}/api/orbit/radar/telemetry",
            headers={
                "Origin": "https://cmfh009.github.io",
                "Access-Control-Request-Private-Network": "true",
            },
            method="OPTIONS",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            assert resp.headers.get("Access-Control-Allow-Origin") in ("https://cmfh009.github.io", "*")
            assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")
            assert resp.headers.get("Access-Control-Allow-Private-Network") == "true"

    def test_post_query_telemetry(self, test_server):
        base_url, srv_service = test_server
        payload = {
            "domain": "targetbrand.com",
            "trigger_source": "radar_submit",
            "audit_result": {
                "score": 75,
                "grade": "B",
                "risk_label": "MODERATE",
            },
        }
        req = urllib.request.Request(
            f"{base_url}/api/orbit/radar/telemetry",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Origin": "https://cmfh009.github.io"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert data["domain"] == "targetbrand.com"
            assert data["grade"] == "B"

        queries = srv_service.get_recent_queries()
        assert len(queries) == 1
        assert queries[0]["domain"] == "targetbrand.com"

    def test_get_queries_and_stats(self, test_server):
        base_url, srv_service = test_server
        srv_service.record_query({"domain": "seeded.com", "score": 80, "grade": "B"})

        req = urllib.request.Request(f"{base_url}/api/orbit/radar/telemetry", method="GET")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert data["count"] == 1
            assert data["queries"][0]["domain"] == "seeded.com"
            assert data["stats"]["total_probes"] == 1


class TestUserAgentAndDiscordEmbeds:
    """Tests User-Agent device parsing and Discord Rich Embed webhook alerts."""

    def test_parse_android_chrome_mobile_ua(self):
        ua = (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36"
        )
        info = parse_user_agent_summary(ua, screen_resolution="412x883")
        assert info["device_type"] == "Mobile"
        assert "Android" in info["os"]
        assert "Chrome" in info["browser"]
        assert info["screen"] == "412x883"
        assert "412x883" in info["summary"]

    def test_parse_iphone_safari_ua(self):
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
        info = parse_user_agent_summary(ua, screen_resolution="390x844")
        assert info["device_type"] == "Mobile"
        assert "iOS" in info["os"]
        assert "Safari" in info["browser"]

    def test_format_discord_radar_embed_with_enrichment_and_proposal(self):
        record = {
            "id": "rad_1792970510_c3d7b9d1",
            "domain": "smartmouseco.com",
            "score": 65,
            "grade": "C",
            "risk_label": "MODERATE RISK",
            "trigger_source": "audit_complete",
            "dmarc_status": "missing",
            "spf_status": "pass",
            "cname_status": "pass",
            "user_agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36",
            "screen_resolution": "412x883",
            "timestamp": "2026-10-25T23:21:50+00:00",
        }
        enrichment = {
            "domain": "smartmouseco.com",
            "company_profile": {"company_name": "Smart Mouse Co"},
            "registrar": "Cloudflare, Inc.",
            "tech_stack": ["Shopify", "Cloudflare"],
            "mx_provider": "Google Workspace",
            "public_apis_osint": {"security_osint_count": 312, "total_catalog_apis": 1425},
        }
        proposal = {
            "domain_slug": "smartmouseco_com",
            "pdf_path": "outbound_campaigns/smartmouseco_com/smartmouseco_com_security_audit.pdf",
            "remediation_path": "outbound_campaigns/smartmouseco_com/dns_remediation_plan.md",
            "proposal_path": "outbound_campaigns/smartmouseco_com/retainer_proposal.md",
        }
        payload = format_discord_radar_embed(record, enrichment=enrichment, proposal=proposal)
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert "smartmouseco.com" in embed["title"]
        field_Map = {f["name"]: f["value"] for f in embed["fields"]}
        assert any("smartmouseco.com" in v for v in field_Map.values())
        assert any("65/100" in v and "C" in v for v in field_Map.values())
        assert any("Android" in v and "412x883" in v for v in field_Map.values())
        assert any("Shopify" in v and "Cloudflare" in v for v in field_Map.values())
        assert any("smartmouseco_com_security_audit.pdf" in v for v in field_Map.values())

    def test_discord_webhook_http_dispatch(self, tmp_path):
        import http.server

        received = []

        class MockWebhookHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                received.append(body)
                self.send_response(204)
                self.end_headers()

            def log_message(self, format_str, *args):
                pass

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockWebhookHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        try:
            webhook_url = f"http://127.0.0.1:{port}/webhook"

            service = RadarTelemetryService(
                queries_file=tmp_path / "wh_queries.jsonl",
                leads_file=tmp_path / "wh_leads.json",
                campaigns_dir=tmp_path / "outbound_campaigns",
                radar_webhook_url=webhook_url,
            )
            res = service.record_query(
                {
                    "domain": "smartmouseco.com",
                    "score": 72,
                    "grade": "C",
                    "user_agent": "Mozilla/5.0 (Linux; Android 10; K) Chrome/155.0.0.0 Mobile",
                    "screen_resolution": "412x883",
                },
                enrich_async=False,
            )
            assert res["ok"] is True
            assert len(received) == 1
            payload = received[0]
            assert "embeds" in payload
            embed = payload["embeds"][0]
            assert "smartmouseco.com" in embed["title"]
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_submit_then_audit_complete_not_dropped(self, temp_service):
        # 1. Initial radar_submit (score is None)
        res1 = temp_service.record_query({
            "domain": "smartmouseco.com",
            "session_id": "sess_mobile_1",
            "trigger_source": "radar_submit",
            "score": None,
            "grade": None,
        })
        assert res1["ok"] is True

        # 2. Follow-up audit_complete 100ms later with score & grade
        res2 = temp_service.record_query({
            "domain": "smartmouseco.com",
            "session_id": "sess_mobile_1",
            "trigger_source": "audit_complete",
            "score": 82,
            "grade": "B",
        })
        assert res2["ok"] is True

        queries = temp_service.get_recent_queries(domain="smartmouseco.com")
        assert len(queries) == 2
        assert any(q["score"] == 82 and q["grade"] == "B" for q in queries)


class TestRadarLeadEnricherAndProposalStager:
    """Tests OSINT lead enrichment (public_apis_osint.py) and automated retainer proposal staging."""

    def test_lead_enricher_public_apis_osint(self, tmp_path):
        leads_file = tmp_path / "enriched_leads.json"
        enricher = RadarLeadEnricher(leads_file=leads_file)
        profile = enricher.enrich_domain("avexdesigns.com", network_probe=False)

        assert profile["domain"] == "avexdesigns.com"
        assert "public_apis_osint" in profile
        osint = profile["public_apis_osint"]
        assert osint["bridge_available"] is True
        assert osint["total_catalog_apis"] > 1000
        assert osint["security_osint_count"] > 100
        # Executive OSINT lookup for known agency
        assert profile["leadership"]["resolved"] is True
        assert profile["leadership"]["email"] == "john@avexdesigns.com"

        # Verify persisted to leads_file
        saved = enricher.get_enriched_lead("avexdesigns.com")
        assert saved is not None
        assert saved["domain"] == "avexdesigns.com"

    def test_retainer_proposal_stager_generates_pdf_and_remediation(self, tmp_path):
        campaigns_dir = tmp_path / "outbound_campaigns"
        stager = RadarRetainerProposalStager(campaigns_dir=campaigns_dir)

        enrichment = {
            "domain": "smartmouseco.com",
            "company_profile": {
                "company_name": "Smart Mouse Co",
                "title": "Smart Mouse Co — Ergonomic Precision Hardware",
            },
            "registrar": "Cloudflare, Inc.",
            "dns_provider": "Cloudflare",
            "tech_stack": ["Shopify", "Cloudflare"],
            "mx_provider": "Google Workspace",
            "dmarc_status": "missing",
            "spf_status": "pass",
            "computed_score": 68,
            "computed_grade": "C",
            "public_apis_osint": {
                "bridge_available": True,
                "total_catalog_apis": 1425,
                "security_osint_count": 312,
                "domain_matches": [],
                "pivot_domains": ["api.securitytrails.com", "urlscan.io"],
            },
        }
        res = stager.stage_campaign(
            domain="smartmouseco.com",
            query_record={"domain": "smartmouseco.com", "score": 68, "grade": "C"},
            enrichment=enrichment,
        )

        assert res["ok"] is True
        assert res["domain_slug"] == "smartmouseco_com"

        pdf_path = Path(res["pdf_path"])
        remediation_path = Path(res["remediation_path"])
        proposal_path = Path(res["proposal_path"])
        pitch_path = Path(res["pitch_path"])

        assert pdf_path.exists()
        assert pdf_path.read_bytes().startswith(b"%PDF-")
        assert remediation_path.exists()
        rem_text = remediation_path.read_text(encoding="utf-8")
        assert "_dmarc" in rem_text
        assert "v=DMARC1" in rem_text
        assert "Cloudflare" in rem_text

        assert proposal_path.exists()
        prop_text = proposal_path.read_text(encoding="utf-8")
        assert "Smart Mouse Co" in prop_text
        assert "smartmouseco.com" in prop_text
        assert "Shopify" in prop_text

        assert pitch_path.exists()
        pitch_text = pitch_path.read_text(encoding="utf-8")
        assert "Subject:" in pitch_text
        assert "smartmouseco.com" in pitch_text

    def test_leads_summary_deliverable_reader(self, tmp_path):
        service = RadarTelemetryService(
            queries_file=tmp_path / "queries.jsonl",
            leads_file=tmp_path / "leads.json",
            campaigns_dir=tmp_path / "outbound_campaigns",
        )
        res = service.record_query(
            {
                "domain": "smartmouseco.com",
                "score": 68,
                "grade": "C",
                "dmarc_status": "missing",
                "spf_status": "pass",
                "user_agent": "Mozilla/5.0 (Linux; Android 10; K) Chrome/155.0.0.0 Mobile",
                "screen_resolution": "412x883",
            },
            enrich_async=False,
            network_probe=False,
        )
        assert res["ok"] is True

        leads = service.get_enriched_leads_summary(limit=10)
        assert len(leads) == 1
        lead = leads[0]
        assert lead["domain"] == "smartmouseco.com"
        assert lead["score"] == 68
        assert lead["grade"] == "C"
        assert lead["deliverables"]["staged"] is True
        assert lead["deliverables"]["has_pdf"] is True
        assert lead["deliverables"]["has_retainer_proposal"] is True

        # Deliverable content reader
        prop_doc = service.get_deliverable_content("smartmouseco.com", "retainer_proposal")
        assert prop_doc["ok"] is True
        assert "smartmouseco.com" in prop_doc["content"]

        pdf_doc = service.get_deliverable_content("smartmouseco.com", "pdf")
        assert pdf_doc["ok"] is True
        assert pdf_doc["is_binary"] is True

        # Reject invalid deliverable type or domain
        bad_doc = service.get_deliverable_content("smartmouseco.com", "../../etc/passwd")
        assert bad_doc["ok"] is False

    def test_security_ssrf_ip_anonymization_and_tunnel_access_control(self, tmp_path, monkeypatch):
        import http.server
        from orbit_security.radar_telemetry import anonymize_client_ip
        from orbit_security.radar_lead_enricher import verify_public_target_host, _SafePassiveRedirectHandler

        # 1. GDPR/CCPA IP anonymization: public IPs truncated & hashed; loopback/RFC1918 preserved
        anon_v4 = anonymize_client_ip("203.0.113.45")
        assert anon_v4 is not None
        assert anon_v4.startswith("203.0.113.0/24#")
        assert "45" not in anon_v4.split("#")[0]

        anon_v6 = anonymize_client_ip("2001:db8:abcd:1234::1")
        assert anon_v6 is not None
        assert "/48#" in anon_v6

        assert anonymize_client_ip("127.0.0.1") == "127.0.0.1"
        assert anonymize_client_ip("192.168.1.100") == "192.168.1.100"

        # 2. SSRF & Redirect protection
        assert verify_public_target_host("localhost") is False
        assert verify_public_target_host("127.0.0.1") is False
        assert verify_public_target_host("169.254.169.254") is False
        assert verify_public_target_host("100.64.0.1") is False

        handler = _SafePassiveRedirectHandler()
        dummy_req = urllib.request.Request("https://example.com")
        with pytest.raises(urllib.error.URLError):
            handler.redirect_request(
                dummy_req, None, 302, "Found", {}, "http://127.0.0.1:9090/api/orbit/radar/leads"
            )
        with pytest.raises(urllib.error.URLError):
            handler.redirect_request(
                dummy_req, None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data/"
            )
        with pytest.raises(urllib.error.URLError):
            handler.redirect_request(
                dummy_req, None, 302, "Found", {}, "file:///etc/passwd"
            )

        # 3. HTTP server tunnel access control & payload cap
        monkeypatch.setenv("ORBIT_TELEMETRY_TOKEN", "sec_token_test_999")
        service = RadarTelemetryService(
            queries_file=tmp_path / "sec_queries.jsonl",
            leads_file=tmp_path / "sec_leads.json",
            campaigns_dir=tmp_path / "outbound_campaigns",
        )

        class BoundHandler(RadarTelemetryHTTPHandler):
            pass

        BoundHandler.service = service
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        try:
            # Direct loopback GET /api/orbit/radar/leads is allowed (200)
            req_local = urllib.request.Request(f"http://127.0.0.1:{port}/api/orbit/radar/leads")
            with urllib.request.urlopen(req_local, timeout=5) as resp:
                assert resp.status == 200
                assert resp.headers.get("X-Content-Type-Options") == "nosniff"
                assert resp.headers.get("X-Frame-Options") == "DENY"

            # Forwarded public tunnel GET /api/orbit/radar/leads without Bearer token is blocked (403)
            req_tunnel_unauth = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/orbit/radar/leads",
                headers={"X-Forwarded-For": "203.0.113.88"},
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_tunnel_unauth, timeout=5)
            assert exc_info.value.code == 403

            # Forwarded public tunnel GET /api/orbit/radar/leads WITH valid Bearer token is allowed (200)
            req_tunnel_auth = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/orbit/radar/leads",
                headers={
                    "X-Forwarded-For": "203.0.113.88",
                    "Authorization": "Bearer sec_token_test_999",
                },
            )
            with urllib.request.urlopen(req_tunnel_auth, timeout=5) as resp_auth:
                assert resp_auth.status == 200

            # Oversized POST (>16KB) is rejected with 413
            huge_body = json.dumps({"domain": "shopify.com", "pad": "A" * 20000}).encode("utf-8")
            req_huge = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/orbit/radar/telemetry",
                data=huge_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_413:
                urllib.request.urlopen(req_huge, timeout=5)
            assert exc_413.value.code == 413
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_deep_scan_dkim_caa_ct_score_backprop_and_tunnel_watchdog(self, tmp_path, monkeypatch):
        from orbit_security.radar_telemetry import RadarTunnelWatchdog

        # 1. Deep-Scan OSINT: DKIM selectors, CAA records, and CT log subdomains
        enricher = RadarLeadEnricher(leads_file=tmp_path / "deep_leads.json")

        def fake_doh(name: str, record_type: str = "TXT"):
            if name == "google._domainkey.smartmouseco.com" and record_type == "TXT":
                return ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"]
            if name == "smartmouseco.com" and record_type in ("CAA", "257"):
                return ['0 issue "letsencrypt.org"']
            if name == "_dmarc.smartmouseco.com" and record_type == "TXT":
                return []
            if name == "smartmouseco.com" and record_type == "TXT":
                return ["v=spf1 include:_spf.google.com ~all"]
            if name == "smartmouseco.com" and record_type == "NS":
                return ["dns1.registrar-servers.com."]
            return []

        monkeypatch.setattr(enricher, "_query_doh_txt_or_ns", fake_doh)
        monkeypatch.setattr(
            enricher,
            "_harvest_ct_subdomains",
            lambda dom, limit=15: [f"shop.{dom}", f"auth.{dom}", f"cdn.{dom}"],
        )
        monkeypatch.setattr(enricher, "_lookup_rdap_registrar", lambda dom, ns: "NameCheap, Inc.")
        monkeypatch.setattr(
            enricher,
            "_probe_http_profile_and_stack",
            lambda dom: {"tech_signals": ["Shopify"], "title": "Smart Mouse Co", "site_name": "Smart Mouse Co", "description": "Store"},
        )

        lead = enricher.enrich_and_persist("smartmouseco.com", network_probe=True)
        assert lead["dkim_status"] == "pass"
        assert "google" in lead["dkim_selectors_found"]
        assert lead["caa_status"] == "pass"
        assert len(lead["caa_records"]) == 1
        assert "shop.smartmouseco.com" in lead["ct_subdomains"]
        assert lead["ct_subdomain_count"] == 3

        # 2. Enriched Score Back-Propagation into get_recent_queries() & get_query_stats()
        service = RadarTelemetryService(
            queries_file=tmp_path / "backprop_queries.jsonl",
            leads_file=tmp_path / "deep_leads.json",
            campaigns_dir=tmp_path / "outbound_campaigns",
        )
        # Record a raw radar_submit query WITHOUT score/grade
        service.record_query(
            {
                "domain": "smartmouseco.com",
                "trigger_source": "radar_submit",
            },
            background_enrich=False,
        )
        recent = service.get_recent_queries(limit=10)
        assert len(recent) == 1
        assert recent[0]["score"] == lead["computed_score"]
        assert recent[0]["grade"] == lead["computed_grade"]
        assert recent[0]["dkim_status"] == "pass"
        assert recent[0]["caa_status"] == "pass"

        stats = service.get_query_stats()
        assert stats["grade_breakdown"].get("PENDING", 0) == 0
        assert stats["grade_breakdown"].get(lead["computed_grade"], 0) == 1

        # Stage proposal and verify DKIM/CAA/CT subdomains appear in deliverables
        staged = service.proposal_stager.stage_proposal(recent[0], lead)
        remediation_text = Path(staged["dns_remediation_path"]).read_text(encoding="utf-8")
        proposal_text = Path(staged["retainer_proposal_path"]).read_text(encoding="utf-8")
        assert "DKIM" in remediation_text
        assert "shop.smartmouseco.com" in proposal_text

        # 3. Self-Healing Public Telemetry Tunnel Watchdog
        watchdog = RadarTunnelWatchdog(state_file=tmp_path / "tunnel_state.json")
        line1 = "93ac679bcacf1b.lhr.life tunneled with tls termination, https://93ac679bcacf1b.lhr.life"
        url1 = watchdog.extract_tunnel_url(line1)
        assert url1 == "https://93ac679bcacf1b.lhr.life"

        state1 = watchdog.record_tunnel_rotation(url1, sync_assets=False)
        assert state1["telemetry_endpoint"] == "https://93ac679bcacf1b.lhr.life/api/orbit/radar/telemetry"
        assert state1["rotation_count"] == 1

        line2 = "21ebe34e0d176c.lhr.life tunneled with tls termination, https://21ebe34e0d176c.lhr.life"
        url2 = watchdog.extract_tunnel_url(line2)
        state2 = watchdog.record_tunnel_rotation(url2, sync_assets=False)
        assert state2["telemetry_endpoint"] == "https://21ebe34e0d176c.lhr.life/api/orbit/radar/telemetry"
        assert state2["rotation_count"] == 2

    def test_contact_email_lead_capture_and_surfacing(self, tmp_path):
        service = RadarTelemetryService(
            queries_file=tmp_path / "email_queries.jsonl",
            leads_file=tmp_path / "email_leads.json",
            campaigns_dir=tmp_path / "email_campaigns",
             onboarding_file=tmp_path / "onboardings.json",
        )
        res = service.record_query(
            {
                "domain": "clientbrand.com",
                "trigger_source": "audit_complete",
                "contact_email": "CTO@ClientBrand.com",
                "audit_result": {
                    "score": 68,
                    "grade": "D",
                    "risk_label": "HIGH RISK",
                },
            },
            background_enrich=False,
        )
        assert res["ok"] is True
        assert res["contact_email"] == "cto@clientbrand.com"

        recent = service.get_recent_queries(limit=10)
        assert len(recent) == 1
        assert recent[0]["contact_email"] == "cto@clientbrand.com"

        captured = service.get_captured_email_leads()
        assert len(captured) == 1
        assert captured[0]["contact_email"] == "cto@clientbrand.com"
        assert captured[0]["domain"] == "clientbrand.com"

        summary = service.get_enriched_leads_summary(limit=10)
        assert len(summary) == 1
        assert summary[0]["contact_email"] == "cto@clientbrand.com"

        stats = service.get_query_stats()
        assert stats["captured_emails_count"] == 1

    def test_agency_onboarding_persistence_and_http_endpoint(self, tmp_path):
        import http.server

        service = RadarTelemetryService(
            queries_file=tmp_path / "onb_queries.jsonl",
            leads_file=tmp_path / "onb_leads.json",
            campaigns_dir=tmp_path / "onb_campaigns",
            onboarding_file=tmp_path / "agency_onboardings.json",
        )

        ref_id_1 = service.compute_client_reference_id("apex-studio", "ops@apexstudio.io")
        ref_id_2 = service.compute_client_reference_id("apex-studio", "ops@apexstudio.io")
        assert ref_id_1 == ref_id_2
        assert ref_id_1.startswith("apex-studio-")

        class BoundHandler(RadarTelemetryHTTPHandler):
            pass

        BoundHandler.service = service
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        try:
            payload = {
                "event": "AGENCY_ONBOARDING",
                "agency_id": "apex-studio",
                "agency_name": "Apex Digital Studio",
                "contact_email": "ops@apexstudio.io",
                "support_email": "security@apexstudio.io",
                "website": "https://apexstudio.io",
                "tier": "Scale",
                "custom_domain": "trust.apexstudio.io",
                "tagline": "Enterprise Web & Perimeter Engineering",
                "primary_color": "#112233",
                "accent_color": "#00ff88",
            }
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/orbit/onboarding",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                body = json.loads(resp.read().decode("utf-8"))
                assert body["ok"] is True
                assert body["client_reference_id"] == ref_id_1
                assert body["agency_id"] == "apex-studio"

            by_ref = service.get_onboarding_record(client_reference_id=ref_id_1)
            assert by_ref is not None
            assert by_ref["agency_name"] == "Apex Digital Studio"
            assert by_ref["primary_color"] == "#112233"
            assert by_ref["accent_color"] == "#00ff88"
            assert by_ref["custom_domain"] == "trust.apexstudio.io"

            by_email = service.get_onboarding_record(email="OPS@apexstudio.io")
            assert by_email is not None
            assert by_email["client_reference_id"] == ref_id_1
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_tunnel_watchdog_verify_health_marks_offline_when_unreachable(self, tmp_path):
        import http.server
        from orbit_security.radar_telemetry import RadarTunnelWatchdog

        state_file = tmp_path / "radar_tunnel_state.json"
        status_box = {"code": 200, "body": b'{"status":"ok"}'}

        class _HealthHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status_box["code"])
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(status_box["body"])

            def log_message(self, format, *args):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), _HealthHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        try:
            initial_ts = "2026-11-03T11:43:48.782731+00:00"
            state_file.write_text(
                json.dumps(
                    {
                        "tunnel_base_url": f"http://127.0.0.1:{port}",
                        "telemetry_endpoint": f"http://127.0.0.1:{port}/api/orbit/radar/telemetry",
                        "rotation_count": 4,
                        "updated_at": initial_ts,
                        "status": "active",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            watchdog = RadarTunnelWatchdog(state_file=state_file, repo_root=tmp_path)

            # 1. Reachable HTTP 200 remains active
            healthy = watchdog.verify_tunnel_health(timeout=2.0, persist=True)
            assert healthy["status"] == "active"
            assert healthy["stale"] is False
            assert healthy["http_status"] == 200

            # 2. HTTP 502 dead tunnel marks persisted state offline/stale and preserves last_active_at
            status_box["code"] = 502
            status_box["body"] = b"no tunnel"
            dead = watchdog.verify_tunnel_health(timeout=2.0, persist=True)
            assert dead["status"] == "offline"
            assert dead["stale"] is True
            assert dead["http_status"] == 502
            assert "502" in (dead.get("last_error") or "")
            assert dead.get("last_active_at") is not None

            persisted = json.loads(state_file.read_text(encoding="utf-8"))
            assert persisted["status"] == "offline"
            assert persisted["stale"] is True
            assert persisted["http_status"] == 502
        finally:
            httpd.shutdown()
            httpd.server_close()

        # 3. Connection refused on closed port also reports offline
        refused = watchdog.verify_tunnel_health(timeout=1.0, persist=True)
        assert refused["status"] == "offline"
        assert refused["stale"] is True
        assert refused["http_status"] is None
        assert refused.get("last_error")

    def test_run_server_and_cli_default_to_loopback(self):
        import inspect
        import orbit_security.radar_telemetry as rt

        sig = inspect.signature(rt.run_server)
        assert sig.parameters["host"].default == "127.0.0.1"
        assert "127.0.0.1" in (rt.main.__code__.co_consts or ())
        assert "0.0.0.0" not in (rt.main.__code__.co_consts or ())


class TestDnsFixpackStripeWebhookAndSlugFallback:
    """Tests DNS fixpack synthesis, Stripe webhook handling, and raw-slug onboarding resolution."""

    def test_raw_slug_get_onboarding_record_fallback(self, tmp_path):
        service = RadarTelemetryService(
            queries_file=tmp_path / "slug_queries.jsonl",
            leads_file=tmp_path / "slug_leads.json",
            campaigns_dir=tmp_path / "slug_campaigns",
            onboarding_file=tmp_path / "slug_onboardings.json",
        )
        saved = service.record_onboarding(
            {
                "agency_id": "apex-studio",
                "agency_name": "Apex Studio",
                "contact_email": "ops@apexstudio.io",
                "website": "https://apexstudio.io",
                "tier": "Growth",
            }
        )
        assert saved["ok"] is True
        assert saved["client_reference_id"].startswith("apex-studio-")

        # Raw slug from landing/index.html Stripe Payment Link (no -<8hex> suffix)
        resolved = service.get_onboarding_record(client_reference_id="apex-studio")
        assert resolved is not None
        assert resolved["agency_id"] == "apex-studio"
        assert resolved["agency_name"] == "Apex Studio"
        assert resolved["contact_email"] == "ops@apexstudio.io"

        # Underscore agency_id should also resolve from hyphenated landing slug
        service.record_onboarding(
            {
                "agency_id": "nova_digital",
                "agency_name": "Nova Digital",
                "contact_email": "sec@novadigital.io",
            }
        )
        resolved_norm = service.get_onboarding_record(client_reference_id="nova-digital")
        assert resolved_norm is not None
        assert resolved_norm["agency_id"] == "nova_digital"

    def test_generate_dns_fixpack_service_and_validation(self, temp_service):
        bad_empty = temp_service.generate_dns_fixpack({"domain": ""})
        assert bad_empty["ok"] is False
        assert "Invalid or missing domain" in bad_empty["error"]

        bad_local = temp_service.generate_dns_fixpack({"domain": "localhost"})
        assert bad_local["ok"] is False

        res = temp_service.generate_dns_fixpack(
            {
                "domain": "https://10up.com/about",
                "spf_record": "v=spf1 include:_spf.google.com ~all",
                "dmarc_record": "v=DMARC1; p=reject;",
                "provider": "cloudflare",
                "client_ips": ["192.0.2.1", "198.51.100.5"],
            }
        )
        assert res["ok"] is True
        assert res["domain"] == "10up.com"
        assert "ip4:192.0.2.1" in res["flattened_spf"]
        assert "ip4:198.51.100.5" in res["flattened_spf"]
        assert res["optimized_lookups"] == 0
        assert 'resource "cloudflare_record"' in res["terraform_snippet"]
        assert "IN    TXT" in res["bind_zone_snippet"]
        assert res["cloudflare_api_json"]["type"] == "TXT"
        assert len(res["sha256_hash"]) == 64

    def test_handle_stripe_webhook_service_method(self, tmp_path, monkeypatch):
        from orbit_security.stripe_webhook import generate_stripe_signature

        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_radar_123")
        service = RadarTelemetryService(
            queries_file=tmp_path / "wh_queries.jsonl",
            leads_file=tmp_path / "wh_leads.json",
            campaigns_dir=tmp_path / "wh_campaigns",
            onboarding_file=tmp_path / "wh_onboardings.json",
        )
        service.record_onboarding(
            {
                "agency_id": "pixel-forge",
                "agency_name": "Pixel Forge Agency",
                "contact_email": "billing@pixelforge.example.com",
                "website": "https://pixelforge.example.com",
                "tier": "Growth",
            }
        )

        event = {
            "id": "evt_test_001",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_001",
                    "customer": "cus_test_001",
                    "subscription": "sub_test_001",
                    "client_reference_id": "pixel-forge",
                    "amount_total": 5900,
                    "currency": "usd",
                    "customer_details": {
                        "email": "billing@pixelforge.example.com",
                        "name": "Pixel Forge Agency",
                    },
                }
            },
        }
        raw_body = json.dumps(event).encode("utf-8")

        # Invalid signature returns (400, ERROR)
        bad_code, bad_res = service.handle_stripe_webhook(raw_body, sig_header="t=1,v1=bad")
        assert bad_code == 400
        assert bad_res["status"] == "ERROR"

        # Valid signature provisions via stored onboarding record and returns 200
        sig = generate_stripe_signature(raw_body, "whsec_test_radar_123")
        ok_code, ok_res = service.handle_stripe_webhook(raw_body, sig_header=sig)
        assert ok_code == 200
        assert ok_res["status"] == "PROVISIONED"
        assert ok_res["agency_id"] == "pixel-forge"
        assert ok_res["agency_name"] == "Pixel Forge Agency"

    def test_http_dns_fixpack_and_stripe_webhook_endpoints(self, tmp_path, monkeypatch):
        import http.server
        from orbit_security.stripe_webhook import generate_stripe_signature

        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_http_test_456")
        srv_service = RadarTelemetryService(
            queries_file=tmp_path / "http_queries.jsonl",
            leads_file=tmp_path / "http_leads.json",
            campaigns_dir=tmp_path / "http_campaigns",
            onboarding_file=tmp_path / "http_onboardings.json",
        )
        srv_service.record_onboarding(
            {
                "agency_id": "beacon-web",
                "agency_name": "Beacon Web Partners",
                "contact_email": "ops@beaconweb.org",
                "website": "https://beaconweb.org",
                "tier": "Starter",
            }
        )

        class BoundHandler(RadarTelemetryHTTPHandler):
            service = srv_service

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        try:
            # 1. Valid POST /api/orbit/dns-fixpack
            req_fp = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/orbit/dns-fixpack",
                data=json.dumps(
                    {
                        "domain": "beaconweb.org",
                        "spf_record": "v=spf1 include:_spf.google.com ~all",
                        "client_ips": ["203.0.113.20"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req_fp, timeout=5) as resp:
                assert resp.status == 200
                fp_body = json.loads(resp.read().decode("utf-8"))
                assert fp_body["ok"] is True
                assert fp_body["domain"] == "beaconweb.org"
                assert "203.0.113.20" in fp_body["flattened_spf"]

            # 2. Invalid domain on /api/dns-fixpack returns 400
            req_bad_fp = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/dns-fixpack",
                data=json.dumps({"domain": ""}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_fp:
                urllib.request.urlopen(req_bad_fp, timeout=5)
            assert exc_fp.value.code == 400

            # 3. Valid signed POST /api/stripe/webhook
            wh_payload = json.dumps(
                {
                    "id": "evt_http_001",
                    "type": "checkout.session.completed",
                    "data": {
                        "object": {
                            "id": "cs_http_001",
                            "customer": "cus_http_001",
                            "subscription": "sub_http_001",
                            "client_reference_id": "beacon-web",
                            "amount_total": 2900,
                            "currency": "usd",
                            "customer_details": {"email": "ops@beaconweb.org"},
                        }
                    },
                }
            ).encode("utf-8")
            sig = generate_stripe_signature(wh_payload, "whsec_http_test_456")
            req_wh = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/stripe/webhook",
                data=wh_payload,
                headers={"Content-Type": "application/json", "Stripe-Signature": sig},
                method="POST",
            )
            with urllib.request.urlopen(req_wh, timeout=5) as resp_wh:
                assert resp_wh.status == 200
                wh_res = json.loads(resp_wh.read().decode("utf-8"))
                assert wh_res["status"] == "PROVISIONED"
                assert wh_res["agency_id"] == "beacon-web"

            # 4. Bad signature on /stripe/webhook returns 400
            req_bad_wh = urllib.request.Request(
                f"http://127.0.0.1:{port}/stripe/webhook",
                data=wh_payload,
                headers={"Content-Type": "application/json", "Stripe-Signature": "t=1,v1=invalid"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_wh:
                urllib.request.urlopen(req_bad_wh, timeout=5)
            assert exc_wh.value.code == 400
        finally:
            httpd.shutdown()
            httpd.server_close()



