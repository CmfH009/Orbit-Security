"""Tests for Sprint 5: Non-blocking Attack Surface Topology Bridge."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from orbit_security.blackboard import Blackboard
from orbit_security.bounty_graph import BountyAttackGraph
from orbit_security.gods_eye_bridge import GodsEyeTopologyBridge


class _MockTopologySinkHandler(BaseHTTPRequestHandler):
    received_payloads = []

    def log_message(self, format, *args):  # noqa: A002
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        if raw:
            type(self).received_payloads.append(json.loads(raw))
        body = json.dumps({"status": "ok"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def mock_topology_sink():
    _MockTopologySinkHandler.received_payloads = []
    server = HTTPServer(("127.0.0.1", 0), _MockTopologySinkHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/api/orbit/topology", _MockTopologySinkHandler
    finally:
        server.shutdown()
        server.server_close()


class TestGodsEyeTopologyBridge:
    def test_rejects_non_loopback_endpoint(self):
        with pytest.raises(ValueError, match="loopback"):
            GodsEyeTopologyBridge(endpoint_url="https://remote.example.com/ingest")

    def test_translates_all_five_event_families_and_updates_bounty_graph(self):
        graph = BountyAttackGraph()
        bridge = GodsEyeTopologyBridge(graph=graph)

        events = [
            {
                "id": 1,
                "event_type": "ROE_REDIRECT_BLOCKED",
                "source": "egress_guard",
                "payload": {"source_url": "https://app.example.com", "hostname": "evil.com", "reason": "cross_host"},
            },
            {
                "id": 2,
                "event_type": "ROE_BOGON_BLOCKED",
                "source": "egress_guard",
                "payload": {"hostname": "169.254.169.254", "reason": "metadata_ip"},
            },
            {
                "id": 3,
                "event_type": "CT_LOG_NEW_SUBDOMAIN",
                "source": "ct_stream_daemon",
                "payload": {"subdomain": "api.example.com", "apex_domain": "example.com"},
            },
            {
                "id": 4,
                "event_type": "BOUNTY_VULN_VERIFIED",
                "source": "bounty_active_prober",
                "payload": {
                    "program_id": "example",
                    "target_domain": "dev.example.com",
                    "flaw_type": "subdomain_takeover",
                    "severity": "HIGH",
                },
            },
            {
                "id": 5,
                "event_type": "AGENCY_TEARDOWN_PUBLISHED",
                "source": "agency_teardown_publisher",
                "payload": {"target_domain": "agency-client.com", "audit_score": 62.5},
            },
        ]

        payloads = [bridge.translate_event(ev) for ev in events]
        assert all(p is not None for p in payloads)
        assert payloads[0]["edges"][0]["relation"] == "ROE_REDIRECT_BLOCKED"
        assert "ROE_BLOCKED_TARGET" in {n["node_type"] for n in payloads[1]["nodes"]}
        assert payloads[2]["edges"][0]["relation"] == "HAS_SUBDOMAIN"
        assert payloads[3]["edges"][0]["relation"] == "HAS_EXPOSURE"
        assert payloads[4]["edges"][0]["relation"] == "TEARDOWN_AUDITED"

        # Graph mirror updated cleanly
        assert "domain:api.example.com" in graph.nodes
        assert "domain:dev.example.com" in graph.nodes
        assert "domain:agency-client.com" in graph.nodes

    def test_blackboard_enqueue_non_blocking_when_sink_offline_and_streams_when_online(
        self, mock_topology_sink, tmp_path
    ):
        endpoint_url, handler = mock_topology_sink

        # Offline bridge drops without blocking publisher
        offline_bridge = GodsEyeTopologyBridge(endpoint_url="http://127.0.0.1:1")
        bb_off = Blackboard(db_path=tmp_path / "bb_off.db", topology_bridge=offline_bridge)
        ev_id = bb_off.publish(
            event_type="CT_LOG_NEW_SUBDOMAIN",
            payload={"subdomain": "cdn.example.com", "apex_domain": "example.com"},
            source="ct_stream_daemon",
            topic="threat_intel",
        )
        assert ev_id > 0
        flushed = offline_bridge.flush(max_items=10)
        assert flushed["dropped"] >= 1

        # Online loopback bridge streams translated spatial topology payload cleanly
        online_bridge = GodsEyeTopologyBridge(endpoint_url=endpoint_url)
        bb_on = Blackboard(db_path=tmp_path / "bb_on.db", topology_bridge=online_bridge)
        bb_on.publish(
            event_type="BOUNTY_VULN_VERIFIED",
            payload={"program_id": "example", "target_domain": "vuln.example.com", "flaw_type": "cors_wildcard", "severity": "HIGH"},
            source="bounty_active_prober",
            topic="bounty_radar",
        )
        # Mundane events are ignored cleanly
        bb_on.publish(
            event_type="PROACTIVE_HEARTBEAT",
            payload={"tick": 1},
            source="daemon",
            topic="proactive_heartbeat",
        )
        res = online_bridge.flush(max_items=10)
        assert res["sent"] == 1
        assert len(handler.received_payloads) == 1
        assert handler.received_payloads[0]["event_type"] == "BOUNTY_VULN_VERIFIED"
        assert handler.received_payloads[0]["geospatial_globe_compatible"] is False
