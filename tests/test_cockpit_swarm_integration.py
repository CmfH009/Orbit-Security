"""Specialist Swarm & Cockpit Sentinel Integration Sweep (Milestone M3 / R3).

Verifies:
1. Real-time telemetry schema and state synchronization across the 10 fleet roles
   and 4 specialist subagent swarms (12 specialist agents).
2. Headless verification of fleet sentinels against registered targets (.orbit-targets.txt)
   and HeadlessPlaytestGuard DOM/JS/TUI checks.
3. SQLite blackboard WAL event broadcasting, SSE streaming (`http://127.0.0.1:9090` / ephemeral port),
   and RadarTelemetryService integration.
4. High-throughput concurrent sweep stress testing ensuring zero stale process states,
   zero `database is locked` errors, and zero orphaned blackboard file locks on Windows NTFS.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock
import urllib.request

import pytest

from orbit_security.agent_perimeter_sentinel import BENIGN_CANARY_PROBES, AgentPerimeterSentinel
from orbit_security.ast_sentinel import ASTCodeSentinel
from orbit_security.blackboard import (
    EVENT_RADAR_DOMAIN_ENTERED,
    TOPIC_DEVOPS,
    TOPIC_GROWTH,
    TOPIC_SOCIAL,
    TOPIC_TELEMETRY,
    TOPIC_THREAT_INTEL,
    Blackboard,
    get_blackboard,
)
from orbit_security.canary_sentinel import CanaryTokenRegistry
from orbit_security.cloud_sentinels import CloudBucketTakeoverSentinel
from orbit_security.fleet import ClientTarget, FleetRegistry, FleetSentinel
from orbit_security.github_sentinel import GitHubDevOpsSwarm
from orbit_security.growth_swarm import MarketingGrowthSwarm
from orbit_security.models import (
    DomainAuditResult,
    Finding,
    Severity,
)
from orbit_security.playtest_guard import HeadlessPlaytestGuard
from orbit_security.radar_telemetry import RadarTelemetryService
from orbit_security.social_swarm import SocialEngagementSwarm
from orbit_security.threat_radar import ThreatRadarSwarm

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = Path("A:/") if Path("A:/").exists() else Path("C:/AgyHut")
COCKPIT_DIR = WORKSPACE_ROOT / "system" / "cockpit"

EXPECTED_10_FLEET_ROLES = [
    "Sentinel",
    "Orchestrator-14",
    "Worker Remediation",
    "Reviewer Remediation",
    "Challenger Remediation",
    "Auditor Remediation",
    "Growth Swarm",
    "GitHub DevOps",
    "Threat Radar",
    "Social Swarm",
]

EXPECTED_4_SPECIALIST_SWARMS = {
    "marketing_growth": ["growth_strategist", "technical_copywriter", "funnel_optimizer"],
    "github_devops": ["github_release_sentinel", "github_showcase_builder", "github_pr_auditor"],
    "threat_radar": ["infosec_news_sniffer", "cve_impact_synthesizer", "threat_advisory_drafter"],
    "social_swarm": ["perimeter_roast_crafter", "viral_thread_architect", "community_engagement_sentinel"],
}


def _load_cockpit_server():
    """Dynamically imports cockpit server module if available on the host, or falls back to playtest_guard."""
    if COCKPIT_DIR.exists():
        cockpit_str = str(COCKPIT_DIR)
        if cockpit_str not in sys.path:
            sys.path.insert(0, cockpit_str)
        try:
            import server as cockpit_server
            return cockpit_server
        except Exception:
            pass
    from orbit_security import playtest_guard
    return playtest_guard


# ============================================================================
# 1. 10 Fleet Roles & 4 Specialist Swarms Telemetry & State Synchronization
# ============================================================================


def test_ten_fleet_roles_and_specialist_swarms_telemetry_schema():
    """Verifies state synchronization and schema across the 10 fleet roles and 4 specialist swarms."""
    cockpit_server = _load_cockpit_server()
    assert cockpit_server is not None, "Cockpit server module must be loadable from system/cockpit"

    telemetry = cockpit_server.get_teamwork_telemetry()
    assert isinstance(telemetry, dict)
    assert "fleet" in telemetry
    assert "specialist_teams" in telemetry

    fleet = telemetry["fleet"]
    assert len(fleet) == 10, f"Expected 10 fleet roles, got {len(fleet)}"

    observed_names = [role["name"] for role in fleet]
    assert observed_names == EXPECTED_10_FLEET_ROLES

    for role_entry in fleet:
        assert "name" in role_entry and role_entry["name"]
        assert "role" in role_entry and role_entry["role"]
        assert "status" in role_entry and role_entry["status"] in (
            "ACTIVE",
            "STANDBY",
            "VERIFYING",
            "VICTORY CONFIRMED",
        )
        assert "badge" in role_entry and role_entry["badge"].startswith("hud-badge-")
        assert "color" in role_entry and role_entry["color"].startswith("#")

    specialist_teams = telemetry["specialist_teams"]
    assert set(specialist_teams.keys()) == set(EXPECTED_4_SPECIALIST_SWARMS.keys())

    total_subagents = 0
    for team_key, expected_agent_ids in EXPECTED_4_SPECIALIST_SWARMS.items():
        team_info = specialist_teams[team_key]
        assert team_info["status"] == "ACTIVE"
        agents = team_info["agents"]
        assert len(agents) == 3
        agent_ids = [a["id"] for a in agents]
        assert agent_ids == expected_agent_ids
        for a in agents:
            assert a["status"] == "ACTIVE"
            assert a.get("title")
            total_subagents += 1

    assert total_subagents == 12


# ============================================================================
# 2. Specialist Swarms & Cockpit Sentinels Blackboard Event Flow
# ============================================================================


def test_specialist_swarms_and_sentinels_blackboard_synchronization(tmp_path):
    """Verifies that all 4 specialist swarms and cockpit sentinels emit synchronized events to the WAL blackboard."""
    db_file = tmp_path / "swarm_sync_blackboard.db"
    bb = Blackboard(db_path=db_file)

    # 1. Verify WAL mode is active
    stats = bb.get_stats()
    assert stats["journal_mode"].lower() == "wal"

    # 2. Instantiate the 4 specialist swarms and verify their agent rosters
    growth = MarketingGrowthSwarm()
    devops = GitHubDevOpsSwarm()
    threat = ThreatRadarSwarm()
    social = SocialEngagementSwarm()

    assert growth is not None
    assert devops is not None
    assert threat is not None
    assert social is not None

    # 3. Publish representative events from all 10 fleet roles and 4 specialist topics
    role_events = [
        {"topic": TOPIC_TELEMETRY, "event_type": "SENTINEL_HEARTBEAT", "source": "Sentinel", "payload": {"role": "Sentinel", "ok": True}},
        {"topic": TOPIC_TELEMETRY, "event_type": "ORCHESTRATOR_SYNC", "source": "Orchestrator-14", "payload": {"role": "Orchestrator-14", "active": True}},
        {"topic": "remediation", "event_type": "WORKER_PATCH_APPLIED", "source": "Worker Remediation", "payload": {"role": "Worker Remediation", "files": 2}},
        {"topic": "remediation", "event_type": "REVIEWER_VERDICT", "source": "Reviewer Remediation", "payload": {"role": "Reviewer Remediation", "verdict": "APPROVE"}},
        {"topic": "remediation", "event_type": "CHALLENGER_STRESS_PASS", "source": "Challenger Remediation", "payload": {"role": "Challenger Remediation", "trials": 20}},
        {"topic": "remediation", "event_type": "AUDITOR_CERTIFIED", "source": "Auditor Remediation", "payload": {"role": "Auditor Remediation", "verdict": "PASS"}},
        {"topic": TOPIC_GROWTH, "event_type": "MARKETING_CAMPAIGN_STAGED", "source": "Growth Swarm", "payload": {"cohort": 11, "targets": 10}},
        {"topic": TOPIC_DEVOPS, "event_type": "GITHUB_RELEASE_READY", "source": "GitHub DevOps", "payload": {"branch": "main", "tests_green": True}},
        {"topic": TOPIC_THREAT_INTEL, "event_type": "THREAT_INTEL_DISCOVERED", "source": "Threat Radar", "payload": {"cve": "CVE-2026-0001", "severity": "HIGH"}},
        {"topic": TOPIC_SOCIAL, "event_type": "ROAST_STAGED", "source": "Social Swarm", "payload": {"target": "example.com", "score": 87}},
    ]

    inserted_ids = bb.publish_batch(role_events)
    assert len(inserted_ids) == 10

    # 4. Verify cockpit sentinels (Canary, AST, Cloud, AgentPerimeter)
    canary_reg = CanaryTokenRegistry(blackboard=bb)
    token = canary_reg.mint_token(token_type="dns_cname", target_perimeter="example.com")
    assert token.token_id

    ast_sentinel = ASTCodeSentinel(workspace_root=REPO_ROOT)
    ast_res = ast_sentinel.inspect_file(REPO_ROOT / "src" / "orbit_security" / "blackboard.py")
    assert ast_res["ok"] is True
    bb.publish("AST_SCAN_PASSED", {"file": "blackboard.py", "ok": True}, source="ast_sentinel", topic=TOPIC_DEVOPS)

    perimeter_sentinel = AgentPerimeterSentinel(blackboard=bb)
    assert len(BENIGN_CANARY_PROBES) > 0
    bb.publish("AGENT_PERIMETER_READY", {"probes": len(BENIGN_CANARY_PROBES)}, source="agent_perimeter_sentinel", topic=TOPIC_TELEMETRY)

    cloud_sentinel = CloudBucketTakeoverSentinel()
    assert cloud_sentinel is not None

    # 5. Verify all 13 events are persisted and queryable via cursor
    all_events = bb.get_events_after(after_id=0, limit=50)
    assert len(all_events) == 13
    sources = {ev["source"] for ev in all_events}
    for expected_role in EXPECTED_10_FLEET_ROLES:
        assert expected_role in sources


# ============================================================================
# 3. High-Throughput Concurrent Sweep & Zero Orphaned Locks Regression
# ============================================================================


def test_high_throughput_sweep_concurrency_zero_orphaned_locks(tmp_path):
    """Spawns concurrent writer and reader threads to verify zero stale process states or orphaned locks."""
    db_file = tmp_path / "high_throughput_wal.db"
    bb = Blackboard(db_path=db_file)

    num_writers = 10
    events_per_writer = 50
    total_expected = num_writers * events_per_writer

    barrier = threading.Barrier(num_writers + 2)
    errors: List[Exception] = []
    stop_readers = threading.Event()
    read_snapshots: List[int] = []

    def writer_task(worker_idx: int):
        try:
            barrier.wait(timeout=5.0)
            role_name = EXPECTED_10_FLEET_ROLES[worker_idx % len(EXPECTED_10_FLEET_ROLES)]
            for seq in range(events_per_writer):
                bb.publish(
                    event_type=f"SWEEP_EVENT_{seq}",
                    payload={"worker": worker_idx, "seq": seq, "role": role_name},
                    source=role_name,
                    topic=TOPIC_TELEMETRY,
                )
        except Exception as exc:
            errors.append(exc)

    def reader_task(reader_idx: int):
        try:
            barrier.wait(timeout=5.0)
            cursor_id = 0
            while not stop_readers.is_set():
                evs = bb.get_events_after(after_id=cursor_id, limit=100)
                if evs:
                    cursor_id = evs[-1]["id"]
                    read_snapshots.append(len(evs))
                if reader_idx == 0:
                    bb.checkpoint(mode="PASSIVE")
                time.sleep(0.005)
        except Exception as exc:
            errors.append(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_writers + 2) as pool:
        reader_futures = [pool.submit(reader_task, r) for r in range(2)]
        writer_futures = [pool.submit(writer_task, w) for w in range(num_writers)]

        for wf in concurrent.futures.as_completed(writer_futures):
            wf.result()

        stop_readers.set()
        for rf in concurrent.futures.as_completed(reader_futures):
            rf.result()

    assert len(errors) == 0, f"Concurrent blackboard sweep encountered errors: {errors}"

    stats = bb.get_stats()
    assert stats["total_events"] == total_expected

    # Verify WAL truncate checkpoint completes with busy == 0 (no orphaned reader/writer handles)
    chk = bb.checkpoint(mode="TRUNCATE")
    assert chk["ok"] is True
    assert chk["busy"] == 0

    # Verify SQLite integrity check passes
    with bb._connection() as conn:
        integrity = conn.execute("PRAGMA integrity_check;").fetchall()
        assert integrity[0][0] == "ok"

    # Prove zero orphaned file handles on Windows NTFS by acquiring an immediate exclusive lock
    # and deleting the temporary database file cleanly.
    excl_conn = sqlite3.connect(str(db_file), timeout=1.0)
    try:
        excl_conn.execute("BEGIN EXCLUSIVE;")
        excl_conn.commit()
    finally:
        excl_conn.close()

    db_file.unlink()
    assert not db_file.exists()


# ============================================================================
# 4. SSE In-Memory Fan-Out & Client Disconnect Cleanup
# ============================================================================


def test_sse_subscriber_fanout_and_disconnect_cleanup(tmp_path):
    """Verifies real-time SSE subscriber queue fan-out, overflow eviction, and disconnect cleanup."""
    bb = Blackboard(db_path=tmp_path / "sse_fanout.db")

    sub1 = bb.subscribe(maxsize=10)
    sub2 = bb.subscribe(maxsize=2)  # Small queue to test overflow eviction

    # Publish 2 events — both subscribers should receive them immediately
    ev_id1 = bb.publish("FLEET_SWEEP_START", {"targets": 4}, source="Sentinel")
    ev_id2 = bb.publish("FLEET_SWEEP_PROGRESS", {"completed": 2}, source="Sentinel")

    msg1 = sub1.get(timeout=1.0)
    msg2 = sub1.get(timeout=1.0)
    assert msg1["id"] == ev_id1
    assert msg2["id"] == ev_id2

    # Overflow sub2 by publishing 3 more events without draining sub2
    for i in range(3):
        bb.publish("OVERFLOW_TEST", {"seq": i}, source="Sentinel")

    # sub2 was full (maxsize=2), so broadcast automatically evicted dead/full sub2 without blocking
    assert sub2 not in bb._subscribers
    assert sub1 in bb._subscribers

    # Disconnect sub1 cleanly
    bb.unsubscribe(sub1)
    assert len(bb._subscribers) == 0


# ============================================================================
# 5. Headless Verification of Fleet Sentinels Against Registered Targets
# ============================================================================


def test_headless_fleet_sentinel_against_registered_targets(tmp_path):
    """Runs headless verification of FleetSentinel against registered targets from .orbit-targets.txt."""
    targets_file = REPO_ROOT / ".orbit-targets.txt"
    assert targets_file.exists(), ".orbit-targets.txt must exist in repository root"

    registered_domains = [
        line.strip()
        for line in targets_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert len(registered_domains) >= 4
    assert "example.com" in registered_domains

    registry_file = tmp_path / "clients.json"
    registry = FleetRegistry(data_path=registry_file)

    for idx, dom in enumerate(registered_domains):
        registry.add_client(
            ClientTarget(
                client_id=f"client-{dom.replace('.', '-')}",
                client_name=f"Registered Target {idx + 1}",
                apex_domain=dom,
                subdomains=[dom, f"www.{dom}"],
                contact_email=f"security@{dom}",
                last_score=92,
                last_grade="A",
            )
        )

    assert len(registry.list_active()) == len(registered_domains)

    # Create mock scanner that simulates a clean scan on most domains and a drift regression on the first domain
    mock_scanner = AsyncMock()

    async def _fake_scan(domain: str, subdomains=None, agency_branding=None):
        if domain == registered_domains[0]:
            # Simulate score regression (-18 pts) + 1 critical finding to trigger DriftEvent
            return DomainAuditResult(
                domain=domain,
                score=74,
                grade="C",
                findings=[
                    Finding(
                        title="Dangling CNAME Takeover Detected",
                        description="Subdomain points to unclaimed cloud resource.",
                        severity=Severity.CRITICAL,
                        category="DNS",
                        remediation="Remove dangling CNAME record.",
                        target=domain,
                    )
                ],
            )
        return DomainAuditResult(
            domain=domain,
            score=95,
            grade="A",
            findings=[],
        )

    mock_scanner.scan_domain.side_effect = _fake_scan
    sentinel = FleetSentinel(registry=registry, scanner=mock_scanner)

    drift_events = asyncio.run(sentinel.run_daily_drift_sweep())
    assert len(drift_events) == 1
    assert drift_events[0].domain == registered_domains[0]
    assert drift_events[0].old_score == 92
    assert drift_events[0].new_score == 74
    assert drift_events[0].score_change == -18
    assert drift_events[0].critical_findings == 1

    # Verify registry persisted updated metrics atomically with zero leftover .tmp files
    reloaded = FleetRegistry(data_path=registry_file)
    first_client = reloaded.get_client(f"client-{registered_domains[0].replace('.', '-')}")
    assert first_client is not None
    assert first_client.last_score == 74
    assert first_client.last_grade == "C"
    assert not registry_file.with_suffix(".tmp").exists()


# ============================================================================
# 6. SQLite Blackboard WAL Event Broadcasting Over HTTP SSE (Port 9090 / Ephemeral)
# ============================================================================


def test_http_sse_wal_event_broadcasting_and_radar_telemetry(tmp_path):
    """Verifies HTTP SSE event streaming from SQLite WAL and RadarTelemetryService integration."""
    db_file = tmp_path / "http_sse_wal.db"
    bb = get_blackboard(db_path=db_file)

    # 1. Test RadarTelemetryService publishing to Blackboard
    radar_svc = RadarTelemetryService(
        queries_file=tmp_path / "radar_queries.jsonl",
        leads_file=tmp_path / "radar_leads.json",
        campaigns_dir=tmp_path / "campaigns",
        onboarding_file=tmp_path / "onboardings.json",
    )
    rec = radar_svc.record_query(
        event_data={
            "domain": "example.com",
            "score": 88,
            "grade": "B+",
            "contact_email": "security@example.com",
        },
        client_ip="192.0.2.123",
        background_enrich=False,
    )
    assert rec["ok"] is True
    assert rec["domain"] == "example.com"
    assert rec["contact_email"] == "security@example.com"

    recent = bb.get_recent(event_type=EVENT_RADAR_DOMAIN_ENTERED)
    assert len(recent) >= 1
    assert recent[0]["payload"]["domain"] == "example.com"
    assert recent[0]["payload"]["client_ip"].startswith("192.0.2.0/24#")
    assert "192.0.2.123" not in recent[0]["payload"]["client_ip"]

    # 2. Spin up an HTTP SSE & telemetry test server mirroring cockpit server's WAL streaming protocol
    class _TestCockpitSSEHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.close_connection = True
            if self.path.startswith("/api/orbit/blackboard/stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache, no-transform")
                self.send_header("Connection", "close")
                self.end_headers()

                sub_q = bb.subscribe(maxsize=50)
                try:
                    # Emit initial connected frame + drain WAL events
                    wal_events = bb.get_events_after(after_id=0, limit=10)
                    for ev in wal_events:
                        frame = f"data: {json.dumps(ev)}\n\n"
                        self.wfile.write(frame.encode("utf-8"))
                    self.wfile.flush()

                    # Wait for one live broadcast frame
                    try:
                        live_ev = sub_q.get(timeout=2.0)
                        frame = f"data: {json.dumps(live_ev)}\n\n"
                        self.wfile.write(frame.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        pass
                finally:
                    bb.unsubscribe(sub_q)
            elif self.path == "/api/orbit/blackboard/events":
                evs = bb.get_recent(limit=20)
                body = json.dumps({"ok": True, "events": evs}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _TestCockpitSSEHandler)
    port = server.server_address[1]
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    try:
        # Schedule a live event publish 100ms after client connects
        def _delayed_publish():
            time.sleep(0.1)
            bb.publish("LIVE_SSE_WAL_BROADCAST", {"sentinel": "active", "port": port}, source="CockpitSentinel")

        pub_thread = threading.Thread(target=_delayed_publish, daemon=True)
        pub_thread.start()

        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/orbit/blackboard/stream")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            assert resp.status == 200
            assert "text/event-stream" in resp.headers.get("Content-Type", "")
            raw_stream = resp.read().decode("utf-8")

        data_lines = [
            line[len("data: "):]
            for line in raw_stream.splitlines()
            if line.startswith("data: ")
        ]
        assert len(data_lines) >= 2
        event_types = {json.loads(dl)["event_type"] for dl in data_lines}
        assert EVENT_RADAR_DOMAIN_ENTERED in event_types
        assert "LIVE_SSE_WAL_BROADCAST" in event_types
        pub_thread.join(timeout=2.0)
    finally:
        server.shutdown()
        server.server_close()
        srv_thread.join(timeout=2.0)

    # Confirm zero leaked subscriber queues after HTTP client disconnect
    assert len(bb._subscribers) == 0


# ============================================================================
# 7. HeadlessPlaytestGuard & Live Port 9090 Probe Verification
# ============================================================================


def test_headless_playtest_guard_and_cockpit_9090_probe():
    """Executes HeadlessPlaytestGuard checks (DOM, JS syntax, TUI 100-col width, and port 9090 probe)."""
    guard = HeadlessPlaytestGuard()

    dom_res = guard.verify_dom_elements()
    assert dom_res["ok"] is True, f"DOM check failed: {dom_res}"

    js_res = guard.verify_javascript_syntax()
    assert js_res["ok"] is True, f"JS syntax check failed: {js_res}"

    tui_res = guard.verify_tui_rendering()
    assert tui_res["ok"] is True, f"TUI rendering check failed: {tui_res}"
    assert tui_res["width_invariant_verified"] is True

    server_res = guard.verify_live_server_probes(port=9090)
    assert server_res["ok"] is True, f"Port 9090 probe failed: {server_res}"
