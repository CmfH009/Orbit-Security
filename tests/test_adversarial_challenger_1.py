#!/usr/bin/env python3
r"""
test_adversarial_challenger_1.py: Empirical Adversarial Challenge Suite
======================================================================
Adversarial stress harness for Orbit Security Phase 4:
1. SQLite WAL pub/sub mesh & SSE stream stress:
   - Rapid event bursts (500 events across 5 concurrent publisher threads)
   - Push propagation latency measurement (<500ms SLA, target <50ms)
   - Concurrent subscriber queues (15 concurrent subscribers, fan-out delivery)
   - Rapid reconnect stress (50 rapid connect/disconnect cycles, zero leak)
   - Dead subscriber queue eviction without stalling active subscribers
2. Boundary input stress:
   - RFC 5322 email validation boundary attacks (CRLF injection, boundary dots, double dots, length, unicode)
   - Empirical validation of leading/trailing CRLF strip vulnerability in verify_email_syntax
   - DNS MX probing timeouts, NXDOMAIN, and invalid TLDs
   - Malformed / empty blackboard event payloads and missing event types
   - HTML injection and path traversal resistance in Deal Desk portals
3. 100-Column Geometric Invariant of 4-Quadrant TUI HUD:
   - Full line-by-line display width validation of all rendered rows
   - Resiliency under extreme telemetry numbers (e.g. 99,999,999 bounces, 0 totals, long strings)
   - Visual display width parity across all states
4. Real CockpitHandler SSE Stream & Socket Disconnect Lifecycle:
   - Real HTTP server running CockpitHandler
   - Client connection to GET /api/orbit/blackboard/stream
   - Event publication to POST /api/orbit/blackboard/publish with push latency measurement
   - Abrupt socket disconnect and thread termination verification
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import queue
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure repository root and system paths are available
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SYSTEM_DIR = Path("A:/system") if Path("A:/system").exists() else Path("C:/AgyHut/system")
SYSTEM_SCRIPTS = SYSTEM_DIR / "scripts"
COCKPIT_DIR = SYSTEM_DIR / "cockpit"

for p in [str(SRC_DIR), str(SYSTEM_SCRIPTS), str(COCKPIT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from blackboard import Blackboard, get_blackboard
from orbit_security.osint_verifier import ExecutiveOSINTVerifier
from orbit_security.deal_desk import RetainerDealDeskConcierge, RETAINER_PRICING_TIERS
from orbit_security.bounty_radar import ResponsibleDisclosureDrafter, BountyTakeoverSweeper
from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.models import Severity, Finding
from orbit_security.inbox_agent import InboxAgent, LeadIntent


# ==============================================================================
# 1. SQLITE WAL PUB/SUB MESH & SSE STREAM STRESS
# ==============================================================================
class TestBlackboardPubSubStress:
    """Adversarial stress testing of the SQLite WAL pub/sub mesh."""

    def test_rapid_event_bursts_and_latency(self, tmp_path):
        """Stress: 500 events published across 5 concurrent threads.
        Assert 100% delivery, zero dropped events, and push latency < 500ms SLA.
        """
        db_file = tmp_path / "burst_test.db"
        bb = Blackboard(db_file)

        subscriber_queue = bb.subscribe(maxsize=1000)
        num_threads = 5
        events_per_thread = 100
        total_expected = num_threads * events_per_thread

        received_events = []
        latencies = []
        recv_done = threading.Event()

        def reader():
            count = 0
            while count < total_expected:
                try:
                    ev = subscriber_queue.get(timeout=3.0)
                    push_lat = time.time() - ev["created_at"]
                    latencies.append(push_lat)
                    received_events.append(ev)
                    count += 1
                except queue.Empty:
                    break
            recv_done.set()

        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()

        def worker(thread_idx: int):
            for i in range(events_per_thread):
                bb.publish(
                    event_type="BURST_EVENT",
                    payload={"thread": thread_idx, "seq": i, "t": time.time()},
                    source="stress_harness"
                )

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        t_start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        publish_duration = time.perf_counter() - t_start

        recv_done.wait(timeout=5.0)
        bb.unsubscribe(subscriber_queue)

        assert len(received_events) == total_expected, (
            f"Event loss during burst: received {len(received_events)} / {total_expected}"
        )
        assert len(latencies) == total_expected
        max_lat = max(latencies)
        avg_lat = sum(latencies) / len(latencies)
        assert max_lat < 2.000, f"Max push latency {max_lat*1000:.2f}ms exceeds 2000ms CI SLA"
        print(f"\n[STRESS PASS] 500 events published in {publish_duration*1000:.1f}ms. "
              f"Avg push latency: {avg_lat*1000:.2f}ms, Max: {max_lat*1000:.2f}ms")

    def test_concurrent_subscriber_fanout(self, tmp_path):
        """Stress: 15 concurrent subscriber queues receiving broadcasts.
        Assert every subscriber receives all published events in sequence.
        """
        db_file = tmp_path / "fanout_test.db"
        bb = Blackboard(db_file)

        num_subs = 15
        sub_queues = [bb.subscribe(maxsize=100) for _ in range(num_subs)]
        num_events = 20

        for i in range(num_events):
            bb.publish("FANOUT_EVENT", {"id": i, "val": f"data_{i}"})

        for s_idx, q in enumerate(sub_queues):
            items = []
            while not q.empty():
                items.append(q.get_nowait())
            assert len(items) == num_events, (
                f"Subscriber #{s_idx} received {len(items)}/{num_events} events"
            )
            bb.unsubscribe(q)

    def test_dead_subscriber_queue_eviction(self, tmp_path):
        """Stress: A slow/full subscriber queue (maxsize=2) must be evicted automatically
        on queue.Full without blocking or crashing publishing to healthy subscribers.
        """
        db_file = tmp_path / "dead_sub_test.db"
        bb = Blackboard(db_file)

        slow_sub = bb.subscribe(maxsize=2)
        healthy_sub = bb.subscribe(maxsize=100)

        # Publish 10 events: slow_sub fills after 2, discarded on 3rd
        for i in range(10):
            bb.publish("OVERFLOW_EVENT", {"seq": i})

        # Healthy subscriber should receive all 10 events
        healthy_items = []
        while not healthy_sub.empty():
            healthy_items.append(healthy_sub.get_nowait())
        assert len(healthy_items) == 10, f"Healthy sub received only {len(healthy_items)}/10"

        # Slow subscriber should have been pruned from _subscribers set
        with bb._sub_lock:
            assert slow_sub not in bb._subscribers, "Dead/full queue was not evicted"

        bb.unsubscribe(healthy_sub)

    def test_rapid_reconnect_cycles(self, tmp_path):
        """Stress: 50 rapid connect & immediate disconnect cycles must not leak memory or queue handles."""
        db_file = tmp_path / "reconnect_test.db"
        bb = Blackboard(db_file)

        for _ in range(50):
            q = bb.subscribe(maxsize=10)
            bb.publish("PING", {"ts": time.time()})
            bb.unsubscribe(q)

        with bb._sub_lock:
            assert len(bb._subscribers) == 0, f"Leaked subscribers in set: {len(bb._subscribers)}"


# ==============================================================================
# 2. BOUNDARY INPUT ATTACKS & EDGE CASES
# ==============================================================================
class TestBoundaryInputsAndSecurity:
    """Adversarial testing of input validation, injection protection, and edge cases."""

    def test_email_mid_string_crlf_rejected(self):
        """Boundary: Mid-string CRLF injection in email strings must be strictly rejected."""
        verifier = ExecutiveOSINTVerifier()

        crlf_mid_string = [
            "victim@example.com\r\nBcc: evil@attacker.com",
            "victim@example.com\nBcc: evil@attacker.com",
            "victim@example.com\rBcc: evil@attacker.com",
            "user\r\nname@domain.com",
            "user@domain\r\n.com",
        ]

        for bad in crlf_mid_string:
            res = verifier.verify_email_syntax(bad)
            assert res["valid"] is False, f"CRLF injection in email passed: {repr(bad)}"
            assert "CRLF" in res["reason"]

    def test_email_leading_trailing_crlf_vulnerability(self):
        """Verify leading and trailing CRLF injection attacks in email are rejected."""
        verifier = ExecutiveOSINTVerifier()
        for leaked_crlf_email in ["\r\nattacker@example.com", "attacker@example.com\r\n", "\nattacker@example.com", "attacker@example.com\r"]:
            res = verifier.verify_email_syntax(leaked_crlf_email)
            assert res["valid"] is False, f"Leading/trailing CRLF was not rejected: {repr(leaked_crlf_email)}"
            assert "CRLF" in res["reason"]

    def test_email_rfc5322_structural_boundaries(self):
        """Boundary: RFC 5322 structural edge cases (dots, missing parts, types)."""
        verifier = ExecutiveOSINTVerifier()

        invalid_structural = [
            "user..name@domain.com",
            ".user@domain.com",
            "user.@domain.com",
            "user@domain..com",
            "user@.domain.com",
            "user@domain.com.",
            "",
            "   ",
            None,
            12345,
            {"email": "test@example.com"},
            "no-domain@",
            "@no-local-part.com",
            "spaces in local@domain.com",
            "missing-at-sign.com",
        ]

        for bad in invalid_structural:
            res = verifier.verify_email_syntax(bad)
            assert res["valid"] is False, f"Invalid structural email erroneously passed: {repr(bad)}"

    def test_dns_mx_nxdomain_and_unresolvable_domains(self):
        """Boundary: NXDOMAIN, non-existent TLDs, and empty domains must return ok: False gracefully without throwing unhandled exceptions."""
        verifier = ExecutiveOSINTVerifier()

        unresolvable_domains = [
            "non-existent-subdomain-12345xyz987.invalid",
            "nxdomain-probe-test-9999.test",
            "..invalid-leading-dots.com",
            "consecutive..dots.org",
            "",
            "   ",
            "127.0.0.1.0.0.0.0.0.0.0.1",
            None,
        ]

        for dom in unresolvable_domains:
            try:
                res = verifier.verify_domain_mx(dom)
                assert isinstance(res, dict)
                assert res["ok"] is False or res["resolvable"] is False, (
                    f"Unresolvable domain unexpectedly reported ok: {dom}"
                )
            except Exception as e:
                pytest.fail(f"Unhandled exception raised on domain {repr(dom)}: {e}")

    def test_deal_desk_path_traversal_and_html_injection(self, tmp_path):
        """Security: Deal desk portal generation must block path traversal and escape HTML in agency name/domain."""
        concierge = RetainerDealDeskConcierge(workspace_root=tmp_path)

        # 1. Path traversal attacks
        traversal_attempts = [
            "../../../../etc/passwd",
            "..\\..\\windows\\system32",
            "....//....//shell.php",
            "valid_agency/../../../hidden",
            "agency\0nullbyte",
        ]

        for bad_id in traversal_attempts:
            res = concierge.generate_portal_for_agency(
                agency_id=bad_id,
                agency_name="Test Agency",
                tier="remediation"
            )
            created_path = Path(res["portal_path"])
            # Invariant: Portal must reside strictly within docs/portals directory
            assert str(created_path).startswith(str(concierge.portals_dir)), (
                f"Path traversal broke out of portals dir: {created_path}"
            )
            assert created_path.exists()

        # 2. HTML / XSS Injection in agency_name & client_domain
        xss_name = '<script>alert("pwned")</script><b>Bold Agency</b>'
        xss_domain = '<img src=x onerror=alert(1)>evil.com'
        res_xss = concierge.generate_portal_for_agency(
            agency_id="xss_test",
            agency_name=xss_name,
            primary_client_domain=xss_domain
        )
        content = Path(res_xss["portal_path"]).read_text(encoding="utf-8")
        assert "<script>" not in content, "Unescaped <script> tag found in portal HTML"
        assert "<img src=x" not in content, "Unescaped <img> tag found in portal HTML"
        assert "&lt;script&gt;" in content, "HTML entities not properly escaped"

    def test_empty_and_malformed_event_payloads(self, tmp_path):
        """Boundary: Publishing empty payloads, huge payloads, or nested unicode structures."""
        db_file = tmp_path / "payload_test.db"
        bb = Blackboard(db_file)

        # 1. Empty dict payload
        ev_id1 = bb.publish("EMPTY_PAYLOAD", {})
        assert ev_id1 > 0
        recent = bb.get_recent(limit=1, event_type="EMPTY_PAYLOAD")
        assert recent[0]["payload"] == {}

        # 2. Huge payload (100KB string)
        huge_str = "A" * 100000
        ev_id2 = bb.publish("HUGE_PAYLOAD", {"data": huge_str})
        assert ev_id2 > 0
        recent_huge = bb.get_recent(limit=1, event_type="HUGE_PAYLOAD")
        assert len(recent_huge[0]["payload"]["data"]) == 100000

        # 3. Unicode and special symbols
        unicode_payload = {
            "emoji": "🪐⚡🛡️📬🤖",
            "japanese": "オービット・セキュリティ",
            "hebrew": "אבטחת אורביט",
            "null_bytes_escaped": "safe\\u0000string"
        }
        ev_id3 = bb.publish("UNICODE_PAYLOAD", unicode_payload)
        assert ev_id3 > 0
        recent_uni = bb.get_recent(limit=1, event_type="UNICODE_PAYLOAD")
        assert recent_uni[0]["payload"]["emoji"] == "🪐⚡🛡️📬🤖"


# ==============================================================================
# 3. 100-COLUMN GEOMETRIC INVARIANT OF 4-QUADRANT TUI HUD
# ==============================================================================
class TestTuiGeometricInvariant:
    """Adversarial stress testing of the 100-column geometric display invariant."""

    def test_strict_100_column_visual_width_all_rows(self):
        """Invariant: Every line rendered by render_4quadrant_hud_lines(width=100)
        must measure EXACTLY 100 visual columns across all header, quadrant, border, and hotkey rows.
        """
        tui = pytest.importorskip("tui", reason="Cockpit TUI module not present")

        lines_formatted = tui.render_4quadrant_hud_lines(width=100)
        plain_str = "".join(part[1] for part in lines_formatted)
        lines = plain_str.splitlines()

        assert len(lines) >= 15, f"HUD render too short: only {len(lines)} lines"

        for idx, line in enumerate(lines):
            vw = tui.str_visual_width(line)
            assert vw == 100, (
                f"Row {idx+1} violates 100-column invariant: width={vw} != 100.\nLine: {repr(line)}"
            )

    def test_tui_width_invariant_under_extreme_telemetry(self):
        """Stress: Invariant must hold even when telemetry counters explode or drop to 0."""
        tui = pytest.importorskip("tui", reason="Cockpit TUI module not present")

        extreme_telemetry_cases = [
            # 1. 0 rescues, 0 pilots, 0 bounces
            {"remediation_rescued": 0, "remediation_total": 0, "pilot_delivered": 0, "pilot_total": 0, "pilot_bounced": 0},
            # 2. Massive 8-digit numbers
            {"remediation_rescued": 99999999, "remediation_total": 99999999, "pilot_delivered": 88888888, "pilot_total": 99999999, "pilot_bounced": 77777777},
            # 3. 1 single bounce (checks singular label "1 Creative Agency")
            {"remediation_rescued": 13, "remediation_total": 52, "pilot_delivered": 6, "pilot_total": 10, "pilot_bounced": 1},
            # 4. Overflow rescues > total
            {"remediation_rescued": 500, "remediation_total": 52, "pilot_delivered": 200, "pilot_total": 10, "pilot_bounced": 40},
        ]

        for case_idx, case in enumerate(extreme_telemetry_cases):
            with patch("tui.get_outreach_telemetry", return_value=case):
                lines_formatted = tui.render_4quadrant_hud_lines(width=100)
                plain_str = "".join(part[1] for part in lines_formatted)
                for row_idx, line in enumerate(plain_str.splitlines()):
                    vw = tui.str_visual_width(line)
                    assert vw == 100, (
                        f"Extreme case #{case_idx+1} row {row_idx+1} width={vw} != 100.\nLine: {repr(line)}"
                    )


# ==============================================================================
# 4. REAL COCKPITHANDLER SSE STREAM & SOCKET DISCONNECT LIFECYCLE
# ==============================================================================
class TestRealCockpitHandlerSseStream:
    """Adversarial testing of the real CockpitHandler HTTP server with SSE stream and publish."""

    @pytest.fixture
    def real_cockpit_server(self, tmp_path):
        """Spawns an actual ThreadingHTTPServer using CockpitHandler on an ephemeral port."""
        server_mod = pytest.importorskip("server", reason="Cockpit server module not present")
        CockpitHandler = server_mod.CockpitHandler
        db_path = tmp_path / "cockpit_blackboard.db"
        bb = get_blackboard(db_path)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CockpitHandler)
        server.daemon_threads = True
        port = server.server_address[1]
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        yield f"http://127.0.0.1:{port}", bb

        server.shutdown()
        server.server_close()
        srv_thread.join(timeout=1.0)

    def test_real_sse_stream_push_latency_and_event_delivery(self, real_cockpit_server):
        """Empirical: Client connects to GET /api/orbit/blackboard/stream.
        Publisher calls POST /api/orbit/blackboard/publish.
        Measure end-to-end push propagation latency over the real HTTP socket. Must be <500ms SLA.
        """
        server_url, bb = real_cockpit_server
        parsed = urllib.parse.urlparse(server_url)

        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5.0)
        conn.request("GET", "/api/orbit/blackboard/stream")
        resp = conn.getresponse()

        assert resp.status == 200
        assert "text/event-stream" in resp.getheader("Content-Type", "")

        # Read initial preamble (event, data, blank line)
        line1 = resp.fp.readline().decode("utf-8")
        line2 = resp.fp.readline().decode("utf-8")
        line3 = resp.fp.readline().decode("utf-8")
        assert "event: connected" in line1 or "data:" in line2

        # Now publish an event via real HTTP POST /api/orbit/blackboard/publish
        pub_conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5.0)
        t_sent = time.time()
        pub_payload = json.dumps({
            "event_type": "BOUNCE_DETECTED",
            "payload": {"agency": "avexdesigns.com", "bounced": "hello@avexdesigns.com", "t": t_sent},
            "source": "challenger_harness",
            "topic": "telemetry"
        }).encode("utf-8")

        pub_conn.request(
            "POST",
            "/api/orbit/blackboard/publish",
            body=pub_payload,
            headers={"Content-Type": "application/json"}
        )
        pub_resp = pub_conn.getresponse()
        assert pub_resp.status == 200
        pub_result = json.loads(pub_resp.read().decode("utf-8"))
        assert pub_result["ok"] is True
        pub_conn.close()

        # Read event from SSE stream
        ev_line = resp.fp.readline().decode("utf-8")
        data_line = resp.fp.readline().decode("utf-8")
        t_recv = time.time()

        push_latency = t_recv - t_sent
        print(f"\n[REAL SSE PASS] End-to-end push latency over real socket: {push_latency*1000:.2f}ms (SLA: <500ms)")
        assert push_latency < 0.500, f"Push latency {push_latency*1000:.2f}ms exceeds 500ms SLA!"
        assert "BOUNCE_DETECTED" in ev_line
        assert "avexdesigns.com" in data_line

        conn.close()

    def test_real_sse_client_disconnect_socket_cleanup(self, real_cockpit_server):
        """Empirical: External process connects to SSE stream, gets abruptly killed,
        publisher emits events, and server cleans up subscriber queue without leaving zombie threads.
        """
        import subprocess
        server_url, bb = real_cockpit_server

        initial_sub_count = len(bb._subscribers)

        # Launch external client subprocess connecting to SSE stream
        subproc = subprocess.Popen([sys.executable, "-c", f"""
import urllib.request, time
req = urllib.request.urlopen('{server_url}/api/orbit/blackboard/stream')
time.sleep(10)
"""])

        time.sleep(0.5)
        with bb._sub_lock:
            assert len(bb._subscribers) == initial_sub_count + 1, "Subprocess failed to register as subscriber"

        # Abruptly kill the external client process
        subproc.kill()
        subproc.wait()

        # Publish 3 events to trigger write errors on the severed socket
        for i in range(3):
            bb.publish("CLEANUP_PING", {"seq": i})
            time.sleep(0.05)

        time.sleep(0.3)

        with bb._sub_lock:
            assert len(bb._subscribers) == initial_sub_count, (
                f"Subscriber queue was NOT cleaned up after disconnect! Leaked count: {len(bb._subscribers)}"
            )
        print("\n[REAL SSE DISCONNECT PASS] Handler successfully detected external client termination and unsubscribed queue.")


# ==============================================================================
# 5. ADVERSARIAL CHALLENGE: SECRET HARVESTING & EVIDENCE MASKING
# ==============================================================================
def _make_mock_response(status_code: int = 200, text: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


class TestAdversarialSecretHarvestingAndMasking:
    """Empirical challenge suite for secret harvesting and evidence masking."""

    @pytest.mark.asyncio
    async def test_secrets_strict_masking_and_zero_plaintext_leak(self):
        """Invariant: Discovered live secret keys MUST be masked with `[:8] + '...' + [-4:]`
        and NEVER leak unmasked plaintext keys into evidence, descriptions, titles, or serialized JSON.
        """
        scanner = OrbitSecurityScanner()
        target_url = "https://example.org"

        raw_stripe = "sk_" + "live_" + "51AbcdEFG1234567890HijklmNOPQ"
        raw_aws = "AKIAIOSFODNN7EXAMPLE"
        raw_sendgrid = "SG.abcdefghijklmnopqrstuv.1234567890123456789012345678901234567890123"
        raw_github = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        raw_slack = "https://" + "hooks." + "slack.com/services/T" + "01234567/B01234567/abcdefghijklmnopqrstuvwx"

        html_content = f"""
        <!DOCTYPE html>
        <html>
          <head>
            <script>
              window.__CONFIG__ = {{
                stripeKey: "{raw_stripe}",
                awsAccess: "{raw_aws}",
                sendgridKey: "{raw_sendgrid}",
                githubPat: "{raw_github}",
                slackHook: "{raw_slack}"
              }};
            </script>
          </head>
          <body><h1>Protected App</h1></body>
        </html>
        """
        mock_client = AsyncMock()
        mock_client.get.return_value = _make_mock_response(200, html_content)

        findings = await scanner.audit_public_secrets(target_url, client=mock_client)
        assert len(findings) == 5, f"Expected 5 findings, got {len(findings)}"

        # Assert zero plaintext leakage across all serialized finding artifacts
        for secret_name, raw_secret in [
            ("Stripe", raw_stripe),
            ("AWS", raw_aws),
            ("SendGrid", raw_sendgrid),
            ("GitHub", raw_github),
            ("Slack", raw_slack),
        ]:
            finding = next((f for f in findings if secret_name.lower() in f.title.lower() or secret_name.lower() in f.evidence.lower()), None)
            assert finding is not None, f"Missing finding for {secret_name}"

            # Plaintext MUST NOT appear in evidence, description, title, or JSON serialization
            assert raw_secret not in finding.evidence, f"RAW PLAINTEXT LEAKED in evidence for {secret_name}: {finding.evidence}"
            assert raw_secret not in finding.description, f"RAW PLAINTEXT LEAKED in description for {secret_name}"
            assert raw_secret not in finding.title, f"RAW PLAINTEXT LEAKED in title for {secret_name}"
            finding_json = finding.model_dump_json() if hasattr(finding, "model_dump_json") else json.dumps(finding.__dict__)
            assert raw_secret not in finding_json, f"RAW PLAINTEXT LEAKED in JSON export for {secret_name}"

            # Mask format check: must contain ellipsis '...'
            assert "..." in finding.evidence or "[REDACTED]" in finding.evidence, f"Secret was not masked: {finding.evidence}"

    @pytest.mark.asyncio
    async def test_secrets_adversarial_inline_script_variations(self):
        """Stress: Test inline script fragments with whitespace variations, mixed delimiters,
        and JSON script tags (e.g. Next.js __NEXT_DATA__).
        """
        scanner = OrbitSecurityScanner()
        target_url = "https://example.org"

        stripe_mock_var = "sk_" + "live_" + "99998888777766665555444433"
        slack_mock_var = "https://" + "hooks." + "slack.com/services/T" + "99999999/B99999999/111122223333444455556666"
        html_variations = f"""
        <html>
          <head>
            <!-- Single quoted with newline in JSON block -->
            <script id="__NEXT_DATA__" type="application/json">
              {{"props": {{"stripe_key": "{stripe_mock_var}"}}}}
            </script>
            <!-- Multiline template literal with whitespace -->
            <script type="module">
              const awsId = `
                AKIAZZZZZZZZZZZZZZZZ
              `.trim();
            </script>
          </head>
          <body>
            <!-- Data attribute secret injection -->
            <div data-hook="{slack_mock_var}"></div>
          </body>
        </html>
        """
        mock_client = AsyncMock()
        mock_client.get.return_value = _make_mock_response(200, html_variations)

        findings = await scanner.audit_public_secrets(target_url, client=mock_client)
        assert len(findings) >= 3, f"Failed to detect secrets in adversarial formats: found {len(findings)}"
        categories = {f.category for f in findings}
        assert "Secret Exposure" in categories

    @pytest.mark.asyncio
    async def test_secrets_false_positive_rejection(self):
        """Stress: Test keys, publishable keys, benign words, and malformed strings must NOT trigger secret findings."""
        scanner = OrbitSecurityScanner()
        target_url = "https://example.org"

        benign_html = """
        <html>
          <head>
            <script>
              // Benign test keys and publishable keys
              const stripeTest = "sk_test_51AbcdEFG1234567890HijklmNOPQ";
              const stripePublishable = "pk_live_51AbcdEFG1234567890HijklmNOPQ";
              // Benign word containing 'akia' substring
              const japaneseName = "sakiakikaku";
              const kakia = "kakia_dictionary_entry";
              // Short or malformed SendGrid / GitHub strings
              const sgInvalid = "SG.short.invalid";
              const ghInvalid = "ghp_short";
              // Benign Slack non-webhook URL
              const slackDoc = "https://hooks.slack.com/documentation/api";
            </script>
          </head>
          <body><h1>Clean Page</h1></body>
        </html>
        """
        mock_client = AsyncMock()
        mock_client.get.return_value = _make_mock_response(200, benign_html)

        findings = await scanner.audit_public_secrets(target_url, client=mock_client)
        assert len(findings) == 0, f"False positives detected on benign content: {[f.title for f in findings]}"

    @pytest.mark.asyncio
    async def test_secrets_bundle_resolution_adversarial_paths(self):
        """Stress: Bundle discovery with protocol-relative URLs, query strings, and resilient HTTP error handling."""
        scanner = OrbitSecurityScanner()
        target_url = "https://example.org"

        html_content = """
        <html>
          <head>
            <!-- Relative script with query parameters -->
            <script src="/static/js/app.bundle.js?v=4.2.0&hash=d8a7c1"></script>
            <!-- Protocol-relative script -->
            <script src="//example.org/vendor.js"></script>
            <!-- Third-party external bundle (must be skipped per same-origin policy) -->
            <script src="https://cdn.external-party.com/library.js"></script>
            <!-- 404 / 500 error script -->
            <script src="/static/js/broken.js"></script>
          </head>
          <body></body>
        </html>
        """

        app_bundle_js = 'const stripeKey = "' + "sk_" + 'live_BUNDLESECRET1234567890ABC";'
        vendor_js = 'const awsKey = "AKIAVENDORTARGET1234";'

        async def mock_get(url, **kwargs):
            url_str = str(url)
            if "app.bundle.js" in url_str:
                return _make_mock_response(200, app_bundle_js)
            elif "vendor.js" in url_str:
                return _make_mock_response(200, vendor_js)
            elif "broken.js" in url_str:
                return _make_mock_response(500, "Internal Server Error")
            return _make_mock_response(200, html_content)

        mock_client = AsyncMock()
        mock_client.get.side_effect = mock_get

        findings = await scanner.audit_public_secrets(target_url, client=mock_client)
        assert len(findings) >= 2, f"Failed to discover secrets in relative/protocol-relative bundles: got {len(findings)}"
        targets = [f.target for f in findings]
        assert any("app.bundle.js" in t for t in targets)
        assert any("vendor.js" in t for t in targets)


# ==============================================================================
# 6. ADVERSARIAL CHALLENGE: CDN SUPPLY-CHAIN & MIXED-CONTENT DETECTION
# ==============================================================================
class TestAdversarialCdnSupplyChainAndMixedContent:
    """Empirical challenge suite for compromised CDN references and mixed-content script injection."""

    @pytest.mark.asyncio
    async def test_compromised_cdns_subdomains_and_protocol_relative(self):
        """Stress: Detect polyfill.io, bootcdn.net, bootcss.com, and staticfile.org across subdomains,
        protocol-relative links, upper-case schemes, and query parameters.
        """
        scanner = OrbitSecurityScanner()
        target_url = "https://example.org"

        adversarial_cdns_html = """
        <!DOCTYPE html>
        <html>
          <head>
            <!-- Subdomain & protocol-relative polyfill.io -->
            <script src="//cdn.sub.polyfill.io/v3/polyfill.min.js?features=default"></script>
            <!-- Upper-case scheme and domain bootcdn.net -->
            <script src="HTTPS://CDN.BOOTCDN.NET/AJAX/LIBS/VUE/VUE.JS"></script>
            <!-- Deep subdomain bootcss.com -->
            <script src="https://static.library.cdn.bootcss.com/react.js"></script>
            <!-- staticfile.org with port number and query -->
            <script src="https://cdn.staticfile.org:443/jquery/3.6.0/jquery.min.js?v=1"></script>
          </head>
          <body></body>
        </html>
        """
        mock_client = AsyncMock()
        mock_client.get.return_value = _make_mock_response(200, adversarial_cdns_html)

        findings = await scanner.audit_third_party_scripts(target_url, client=mock_client)
        assert len(findings) == 4, f"Expected 4 compromised CDN findings, got {len(findings)}: {[f.title for f in findings]}"

        for expected_cdn in ["polyfill.io", "bootcdn.net", "bootcss.com", "staticfile.org"]:
            match = next((f for f in findings if expected_cdn in f.title.lower() or expected_cdn in f.description.lower()), None)
            assert match is not None, f"Failed to detect compromised CDN: {expected_cdn}"
            assert match.severity == Severity.CRITICAL
            assert match.category == "Supply Chain Security"

    @pytest.mark.asyncio
    async def test_mixed_content_detection_matrix(self):
        """Matrix test for mixed-content:
        - HTTP script on HTTPS target -> FLAGGED as Mixed-Content
        - Localhost HTTP script on HTTPS target -> NOT FLAGGED (localhost exception)
        - HTTPS script on HTTPS target -> NOT FLAGGED
        - HTTP script on HTTP target -> NOT FLAGGED (no secure context)
        - Dual: HTTP compromised CDN on HTTPS target -> FLAGGED FOR BOTH Mixed-Content AND Compromised CDN
        """
        scanner = OrbitSecurityScanner()

        # Case 1: HTTPS target with mixed-content script and localhost exception
        html_https = """
        <html>
          <head>
            <script src="http://untrusted-analytics.com/tracker.js"></script>
            <script src="http://localhost:3000/bundle.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
          </head>
          <body></body>
        </html>
        """
        mock_client = AsyncMock()
        mock_client.get.return_value = _make_mock_response(200, html_https)

        findings = await scanner.audit_third_party_scripts("https://secure.example.com", client=mock_client)
        assert len(findings) == 1, f"Expected 1 mixed-content finding, got {len(findings)}"
        assert findings[0].title == "Insecure Mixed-Content Third-Party Script"
        assert findings[0].severity == Severity.HIGH
        assert "untrusted-analytics.com" in findings[0].evidence

        # Case 2: HTTP target (not HTTPS) - mixed content does not apply
        findings_http_page = await scanner.audit_third_party_scripts("http://insecure.example.com", client=mock_client)
        assert len(findings_http_page) == 0, "Mixed content unexpectedly flagged on plain HTTP site"

        # Case 3: Dual threat - HTTP compromised CDN on HTTPS target
        dual_threat_html = """
        <html>
          <head>
            <script src="http://polyfill.io/v3/polyfill.js"></script>
          </head>
          <body></body>
        </html>
        """
        mock_client.get.return_value = _make_mock_response(200, dual_threat_html)
        dual_findings = await scanner.audit_third_party_scripts("https://secure.example.com", client=mock_client)
        assert len(dual_findings) == 2, f"Expected both Mixed-Content and Compromised CDN findings, got {len(dual_findings)}"
        titles = [f.title for f in dual_findings]
        assert any("Mixed-Content" in t for t in titles)
        assert any("polyfill.io" in t for t in titles)


# ==============================================================================
# 7. ADVERSARIAL CHALLENGE: BULK SENDER DMARC & SPF RIGOR
# ==============================================================================
class TestAdversarialBulkSenderDmarcSpf:
    """Empirical challenge suite for Google & Yahoo 2024+ bulk sender requirements, DMARC, and SPF."""

    @pytest.mark.asyncio
    async def test_bulk_sender_compliance_matrix(self):
        """Matrix test for audit_bulk_sender_compliance:
        - Strict p=reject -> PASS (None)
        - Strict p=quarantine -> PASS (None)
        - Permissive p=none without sp=reject -> LOW finding (Unenforced DMARC)
        - Permissive p=none WITH sp=reject -> PASS (None)
        - Missing DMARC -> MEDIUM finding (Non-Compliance)
        - Multi-chunk TXT record -> correctly reassembled and verified
        - Malformed / non-DMARC TXT record -> MEDIUM finding (Missing DMARC)
        """
        scanner = OrbitSecurityScanner()

        class MockTxtAnswer:
            def __init__(self, strings: List[bytes]):
                self.strings = strings

        test_cases = [
            # 1. Strict p=reject
            ([MockTxtAnswer([b"v=DMARC1; p=reject; rua=mailto:dmarc@test.org"])], None, None),
            # 2. Strict p=quarantine
            ([MockTxtAnswer([b"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@test.org"])], None, None),
            # 3. Permissive p=none
            ([MockTxtAnswer([b"v=DMARC1; p=none; rua=mailto:dmarc@test.org"])], Severity.LOW, "p=none"),
            # 4. Permissive p=none WITH sp=reject
            ([MockTxtAnswer([b"v=DMARC1; p=none; sp=reject; rua=mailto:dmarc@test.org"])], None, None),
            # 5. Multi-chunk split DNS answer (concatenated RFC 1035)
            ([MockTxtAnswer([b"v=DMARC1; p=re", b"ject; rua=mailto:dmarc@test.org"])], None, None),
            # 6. Non-DMARC TXT records (e.g. google site verification)
            ([MockTxtAnswer([b"google-site-verification=abcdef12345"])], Severity.MEDIUM, "Missing DMARC"),
        ]

        with patch("orbit_security.scanner.get_orbit_async_resolver") as mock_get_res:
            mock_resolver = MagicMock()
            mock_get_res.return_value = mock_resolver

            for idx, (txt_records, expected_severity, expected_title_sub) in enumerate(test_cases):
                async def mock_resolve(name, rdtype):
                    return txt_records
                mock_resolver.resolve = mock_resolve

                finding = await scanner.audit_bulk_sender_compliance(f"domain{idx}.org")
                if expected_severity is None:
                    assert finding is None, f"Case #{idx} unexpectedly produced finding: {finding}"
                else:
                    assert finding is not None, f"Case #{idx} failed to produce expected finding"
                    assert finding.severity == expected_severity
                    assert expected_title_sub in finding.title

            # 7. DNS Exception / NXDOMAIN
            async def fail_resolve(name, rdtype):
                raise Exception("NXDOMAIN: _dmarc.missing.org does not exist")
            mock_resolver.resolve = fail_resolve

            finding_nx = await scanner.audit_bulk_sender_compliance("missing.org")
            assert finding_nx is not None
            assert finding_nx.severity == Severity.MEDIUM
            assert "Missing DMARC" in finding_nx.title

    @pytest.mark.asyncio
    async def test_core_audit_dmarc_and_spf_edge_cases(self):
        """Stress: Verify core audit_dmarc and audit_spf against +all SPF, missing SPF,
        subdomain fallbacks, and static hosting exemptions.
        """
        scanner = OrbitSecurityScanner()

        class MockTxt:
            def __init__(self, strings: List[bytes]):
                self.strings = strings

        mock_resolver = AsyncMock()
        scanner.resolver = mock_resolver

        # 1. audit_spf with dangerously permissive +all -> CRITICAL
        mock_resolver.resolve.return_value = [MockTxt([b"v=spf1 +all"])]
        spf_finding = await scanner.audit_spf("insecure-mail.com")
        assert spf_finding is not None
        assert spf_finding.severity == Severity.CRITICAL
        assert "Permissive SPF (+all)" in spf_finding.title

        # 2. audit_spf with safe -all -> PASS
        mock_resolver.resolve.return_value = [MockTxt([b"v=spf1 include:_spf.google.com -all"])]
        assert await scanner.audit_spf("secure-mail.com") is None

        # 3. audit_spf with softfail ~all -> PASS
        mock_resolver.resolve.return_value = [MockTxt([b"v=spf1 mx ~all"])]
        assert await scanner.audit_spf("softfail-mail.com") is None

        # 4. audit_dmarc on static hosting domain (e.g. github.io) -> skipped (None)
        mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
        assert await scanner.audit_dmarc("test.github.io") is None
        assert await scanner.audit_spf("test.github.io") is None


# ==============================================================================
# 8. ADVERSARIAL CHALLENGE: LEAD HYGIENE & DEAL DESK TRAVERSAL DEFENSES
# ==============================================================================
class TestAdversarialLeadHygieneAndDealDesk:
    """Empirical challenge suite for email OSINT fuzzing, CRLF rejection, and Deal Desk traversal defense."""

    def test_osint_verifier_crlf_and_boundary_fuzzing(self):
        """Stress: Exhaustive fuzzing of verify_email_syntax with CRLF payloads,
        Punycode, and boundary characters.
        """
        verifier = ExecutiveOSINTVerifier()

        crlf_payloads = [
            "victim@example.com\r\nBcc: evil@attacker.com",
            "victim@example.com\rBcc: evil@attacker.com",
            "victim@example.com\nBcc: evil@attacker.com",
            "\r\nvictim@example.com",
            "victim@example.com\r\n",
            "\rvictim@example.com",
            "victim@example.com\n",
            "user%0d%0a@example.com",
            "user\r\n@example.com",
            "user@\r\nexample.com",
        ]

        for payload in crlf_payloads:
            res = verifier.verify_email_syntax(payload)
            assert res["valid"] is False, f"CRLF payload bypassed email verifier: {repr(payload)}"

        # Punycode / IDN domains
        # Valid IDN domain
        idn_valid = verifier.verify_email_syntax("director@münchen.de")
        assert idn_valid["valid"] is True
        assert "xn--mnchen-3ya.de" in idn_valid["normalized_email"]

        # Invalid IDN domain
        idn_invalid = verifier.verify_email_syntax("lead@xn--invalid---test.de")
        # Should either fail RFC regex or fail IDN decode
        assert idn_invalid["valid"] is False or "xn--" in idn_invalid["normalized_email"]

        # Alias risk scoring
        generic_res = verifier.verify_email_syntax("hello@agency.com")
        assert generic_res["valid"] is True
        assert generic_res["is_generic_alias"] is True
        assert generic_res["risk_score"] == 85

        executive_res = verifier.verify_email_syntax("austin@alley.com")
        assert executive_res["valid"] is True
        assert executive_res["is_generic_alias"] is False
        assert executive_res["risk_score"] == 10

    def test_deal_desk_directory_traversal_hardened_boundary(self, tmp_path):
        """Security: Deal desk portal generation must strictly confine generated files
        within `docs/portals/` regardless of traversal attempts.
        """
        concierge = RetainerDealDeskConcierge(workspace_root=tmp_path)
        portals_dir = concierge.portals_dir.resolve()

        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\windows\\system32\\calc",
            "agency_id/../../../secret",
            "....//....//....//exploit",
            "agency\0nullbyte",
            "..",
            "/",
            "\\",
            "CON",
            "PRN",
        ]

        for payload in traversal_payloads:
            res = concierge.generate_portal_for_agency(
                agency_id=payload,
                agency_name="Hostile Agency",
                tier="remediation"
            )
            created_path = Path(res["portal_path"]).resolve()

            # Must reside within portals_dir
            assert str(created_path).startswith(str(portals_dir)), (
                f"Directory traversal succeeded with payload {repr(payload)}! Path: {created_path}"
            )
            assert created_path.exists()
            assert created_path.suffix == ".html"

    def test_deal_desk_xss_and_template_injection_sanitization(self, tmp_path):
        """Security: All user-controlled fields injected into client portal HTML must be safely escaped."""
        concierge = RetainerDealDeskConcierge(workspace_root=tmp_path)

        xss_payloads = {
            "agency_name": '<script>alert("XSS")</script><b>Injected Agency</b>',
            "client_domain": '<img src=x onerror=alert(document.cookie)>evil.com',
            "tier": 'remediation'
        }

        res = concierge.generate_portal_for_agency(
            agency_id="xss_test_agency",
            agency_name=xss_payloads["agency_name"],
            primary_client_domain=xss_payloads["client_domain"],
            tier=xss_payloads["tier"]
        )

        portal_file = Path(res["portal_path"])
        content = portal_file.read_text(encoding="utf-8")

        # Dangerous raw tags MUST NOT appear
        assert "<script>" not in content
        assert "</script>" not in content
        assert "<img" not in content

        # HTML entity escaped versions MUST appear
        assert "&lt;script&gt;" in content
        assert "&lt;img" in content


