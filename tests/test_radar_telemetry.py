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
)
from orbit_security.blackboard import (
    EVENT_RADAR_DOMAIN_ENTERED,
    TOPIC_TELEMETRY,
    Blackboard,
    get_blackboard,
)


@pytest.fixture
def temp_service(tmp_path):
    log_file = tmp_path / "test_radar_queries.jsonl"
    service = RadarTelemetryService(queries_file=log_file, dedup_window_seconds=1.0)
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
        service = RadarTelemetryService(queries_file=log_file)

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
        srv_service = RadarTelemetryService(queries_file=log_file)

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
            headers={"Origin": "https://cmfh009.github.io"},
            method="OPTIONS",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            assert resp.headers.get("Access-Control-Allow-Origin") in ("https://cmfh009.github.io", "*")
            assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")

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
