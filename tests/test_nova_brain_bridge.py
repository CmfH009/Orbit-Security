"""Tests for Sprint 1: Nova Brain (port 8200) Briefing & Blackboard Bridge."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest

from orbit_security.blackboard import (
    HIGH_SIGNAL_NOVA_BRAIN_EVENTS,
    Blackboard,
    is_high_signal_nova_event,
)
from orbit_security.hypernote_briefing import BriefingSourceCollector


class _MockNovaBrainHandler(BaseHTTPRequestHandler):
    """Lightweight loopback handler mimicking Nova Brain REST API routes."""

    vitals_payload = {
        "ram_used_mb": 8192.5,
        "ram_rss_mb": 420.1,
        "governor_state": "GREEN",
        "acpi_temp_c": 52.0,
        "active_model": "gemma4:12b",
        "active_tasks": 1,
        "blackboard_events_total": 42,
    }
    stored_memories = []

    def log_message(self, format, *args):  # noqa: A002
        return

    def do_GET(self):
        if self.path == "/vitals":
            body = json.dumps(self.vitals_payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            body = json.dumps({"status": "ok"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/memory/store":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            payload = json.loads(raw) if raw else {}
            type(self).stored_memories.append(payload)
            body = json.dumps({"status": "ok", "entry_id": len(self.stored_memories)}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture()
def mock_nova_brain():
    _MockNovaBrainHandler.stored_memories = []
    server = HTTPServer(("127.0.0.1", 0), _MockNovaBrainHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _MockNovaBrainHandler
    finally:
        server.shutdown()
        server.server_close()


class TestBriefingSourceCollectorNovaBrain:
    def test_collect_supervisor_health_queries_nova_brain_vitals_first(self, mock_nova_brain, tmp_path):
        base_url, _ = mock_nova_brain
        missing_state = tmp_path / "does_not_exist.json"
        collector = BriefingSourceCollector(nova_brain_url=base_url)

        health = collector.collect_supervisor_health(state_file=missing_state)

        assert health["source"] == "nova_brain"
        assert health["memory_band"] == "green"
        assert health["nova_brain"]["active_model"] == "gemma4:12b"
        assert health["nova_brain"]["ram_used_mb"] == pytest.approx(8192.5)
        assert isinstance(health["ram_available_mb"], (int, float))
        assert health["ram_available_mb"] > 0
        assert "services" in health
        assert health["services"]["Nova Brain IPC"]["active"] is True

    def test_collect_supervisor_health_falls_back_to_state_file_plus_psutil(self, tmp_path):
        state_file = tmp_path / "orbit_daemon_state.json"
        state_file.write_text(
            json.dumps(
                {
                    "supervisor_pid": 99911,
                    "bounty_radar": {"status": "ACTIVE", "total_vulnerabilities_found": 4},
                    "services": {"Orbit Security Sentinel": {"active": True, "port": None}},
                }
            ),
            encoding="utf-8",
        )
        collector = BriefingSourceCollector(nova_brain_url="http://127.0.0.1:1")

        health = collector.collect_supervisor_health(state_file=state_file)

        assert health["source"] == "state_file"
        assert health["supervisor_pid"] == 99911
        assert health["bounty_radar"]["total_vulnerabilities_found"] == 4
        # Live hardware telemetry must come from psutil rather than hardcoded constants
        assert health["ram_available_mb"] > 0
        assert 0.0 <= health["ram_percent"] <= 100.0

    def test_collect_supervisor_health_never_uses_hardcoded_synthetic_values(self, tmp_path):
        missing_state = tmp_path / "missing_daemon_state.json"
        collector = BriefingSourceCollector(nova_brain_url="http://127.0.0.1:1")

        vm = psutil.virtual_memory()
        health = collector.collect_supervisor_health(state_file=missing_state)

        assert health["source"] == "psutil"
        assert health["supervisor_pid"] == os.getpid()
        assert health["supervisor_pid"] != 11056
        assert health["ram_available_mb"] != 3673
        expected_avail = round(vm.available / (1024 * 1024))
        assert abs(health["ram_available_mb"] - expected_avail) <= 512
        assert "services" in health


class TestBlackboardNovaBrainBridge:
    def test_high_signal_classifier(self):
        assert is_high_signal_nova_event("ROE_REDIRECT_BLOCKED", "egress_guard", {}) is True
        assert is_high_signal_nova_event("ROE_BOGON_BLOCKED", "egress_guard", {}) is True
        assert is_high_signal_nova_event("BOUNTY_VULN_VERIFIED", "bounty_prober", {}) is True
        assert is_high_signal_nova_event("REPORT_CRITIC_VERIFIED", "ReportCriticVerifier", {}) is True
        assert is_high_signal_nova_event("ANY_EVENT", "ReportCriticVerifier", {}) is True
        assert is_high_signal_nova_event(
            "ADVISORY_GATE", "publisher", {"verified_artifact_ids": ["ev_1234567890ab"]}
        ) is True
        assert is_high_signal_nova_event("HEARTBEAT_PING", "daemon", {}) is False
        assert "ROE_REDIRECT_BLOCKED" in HIGH_SIGNAL_NOVA_BRAIN_EVENTS

    def test_blackboard_streams_high_signal_events_to_nova_brain(self, mock_nova_brain, tmp_path):
        base_url, handler = mock_nova_brain
        bb = Blackboard(db_path=tmp_path / "bb.db", nova_brain_url=base_url)

        ev1 = bb.publish(
            event_type="ROE_REDIRECT_BLOCKED",
            payload={"hostname": "169.254.169.254", "reason": "cross_host_redirect"},
            source="egress_guard",
            topic="security",
        )
        ev2 = bb.publish(
            event_type="BOUNTY_VULN_VERIFIED",
            payload={"target_domain": "vuln.example.com", "flaw_type": "subdomain_takeover"},
            source="bounty_active_prober",
            topic="bounty_radar",
        )
        ev3 = bb.publish(
            event_type="REPORT_CRITIC_RECEIPT",
            payload={"target_domain": "example.com", "verified_artifact_ids": ["ev_abcdef123456"]},
            source="ReportCriticVerifier",
            topic="audit",
        )
        # Noisy heartbeat must NOT be sent to episodic store
        bb.publish(
            event_type="PROACTIVE_HEARTBEAT",
            payload={"tick": 1},
            source="daemon",
            topic="proactive_heartbeat",
        )

        assert ev1 > 0 and ev2 > 0 and ev3 > 0
        assert len(handler.stored_memories) == 3
        first = handler.stored_memories[0]
        assert "ROE_REDIRECT_BLOCKED" in first["summary"]
        assert first["category"] in ("SECURITY_EVENT", "LESSON")
        assert first["details"]["event_type"] == "ROE_REDIRECT_BLOCKED"
        assert "roe_redirect_blocked" in first["tags"]

    def test_blackboard_fails_non_blockingly_when_nova_brain_offline(self, tmp_path):
        bb = Blackboard(db_path=tmp_path / "bb_offline.db", nova_brain_url="http://127.0.0.1:1")

        ev_id = bb.publish(
            event_type="ROE_BOGON_BLOCKED",
            payload={"hostname": "127.0.0.1", "reason": "bogon_ip"},
            source="egress_guard",
            topic="security",
        )

        assert isinstance(ev_id, int)
        assert ev_id > 0
        recent = bb.get_recent(limit=5, event_type="ROE_BOGON_BLOCKED")
        assert len(recent) == 1
        assert recent[0]["payload"]["hostname"] == "127.0.0.1"
