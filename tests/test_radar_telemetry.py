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

    def test_discord_webhook_http_dispatch(self, tmp_path, monkeypatch):
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
            monkeypatch.setenv("ORBIT_RADAR_WEBHOOK_URL", webhook_url)

            service = RadarTelemetryService(
                queries_file=tmp_path / "wh_queries.jsonl",
                leads_file=tmp_path / "wh_leads.json",
                campaigns_dir=tmp_path / "outbound_campaigns",
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
            assert len(received) >= 1
            payload = received[-1]
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

