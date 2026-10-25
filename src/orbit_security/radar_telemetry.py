#!/usr/bin/env python3
"""orbit_security.radar_telemetry: Real-Time Radar Query Telemetry & Observer.
=============================================================================
Provides real-time visibility and telemetry ingestion whenever a domain is
entered into the ORBIT // PERIMETER RADAR TERMINAL (https://cmfh009.github.io/Orbit-Security/).

Key Features:
- Structured JSONL persistence (data/radar_queries.jsonl) with atomic append.
- Decoupled SQLite WAL Blackboard event bus dispatch (RADAR_DOMAIN_ENTERED)
  for real-time streaming to the Orbit Aerospace Cockpit HUD / SSE stream (<500ms).
- Rich webhook alerting to Discord and Slack via WebhookDispatcher.
- Standalone zero-dependency HTTP server with full CORS support.
- CLI streaming monitor (--tail) and aggregate statistics (--stats).
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import http.server
import json
import logging
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request

logger = logging.getLogger("orbit_security.radar_telemetry")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"
DEFAULT_QUERIES_FILE = DATA_DIR / "radar_queries.jsonl"

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
RESTRICTED_DOMAINS = {
    "localhost",
    "localdomain",
    "internal",
    "lan",
    "home.arpa",
}


@dataclass
class RadarQueryRecord:
    id: str
    domain: str
    raw_input: str
    timestamp: str
    timestamp_epoch: float
    trigger_source: str
    score: Optional[int] = None
    grade: Optional[str] = None
    risk_label: Optional[str] = None
    dmarc_status: Optional[str] = None
    spf_status: Optional[str] = None
    cname_status: Optional[str] = None
    is_nxdomain: bool = False
    is_lookup_failed: bool = False
    session_id: Optional[str] = None
    source_url: Optional[str] = None
    referrer: Optional[str] = None
    user_agent: Optional[str] = None
    screen_resolution: Optional[str] = None
    client_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RadarTelemetryService:
    """Thread-safe telemetry recorder and observer for perimeter radar probes."""

    def __init__(
        self,
        queries_file: Optional[Path] = None,
        dedup_window_seconds: float = 3.0,
    ):
        self.queries_file = Path(queries_file) if queries_file else DEFAULT_QUERIES_FILE
        self.queries_file.parent.mkdir(parents=True, exist_ok=True)
        self.dedup_window_seconds = dedup_window_seconds
        self._lock = threading.Lock()
        self._recent_probes_cache: Dict[str, float] = {}

    @staticmethod
    def normalize_domain(domain_raw: str) -> str:
        """Sanitizes raw input string to lowercase fully qualified domain name."""
        if not domain_raw or not isinstance(domain_raw, str):
            return ""
        clean = domain_raw.strip().lower()
        clean = re.sub(r"^https?://", "", clean)
        clean = re.sub(r"/.*$", "", clean)
        clean = re.sub(r"\?.*$", "", clean)
        clean = re.sub(r":\d+$", "", clean)
        clean = clean.rstrip(".")
        return clean

    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        if not domain or len(domain) > 253:
            return False
        if not DOMAIN_REGEX.match(domain):
            return False
        parts = domain.split(".")
        if any(p in RESTRICTED_DOMAINS for p in parts):
            return False
        if domain.endswith((".local", ".internal", ".localhost", ".localdomain", ".test", ".example", ".invalid", ".home.arpa", ".lan", ".arpa")):
            return False
        return True

    def _is_duplicate(self, domain: str, session_id: str, now_epoch: float) -> bool:
        cache_key = f"{domain}:{session_id or 'none'}"
        last_time = self._recent_probes_cache.get(cache_key, 0.0)
        # Purge stale keys
        if len(self._recent_probes_cache) > 200:
            self._recent_probes_cache = {
                k: v for k, v in self._recent_probes_cache.items()
                if (now_epoch - v) < self.dedup_window_seconds * 2
            }
        if (now_epoch - last_time) < self.dedup_window_seconds:
            return True
        self._recent_probes_cache[cache_key] = now_epoch
        return False

    def record_query(self, event_data: Dict[str, Any], client_ip: str = "") -> Dict[str, Any]:
        """Validates, records, and dispatches a radar domain query event."""
        raw_input = str(event_data.get("domain") or event_data.get("target") or event_data.get("raw_input") or "").strip()
        domain = self.normalize_domain(raw_input)

        if not self.is_valid_domain(domain):
            return {
                "ok": False,
                "error": f"Invalid or restricted domain target: '{raw_input}'",
                "domain": domain,
            }

        now = datetime.datetime.now(datetime.timezone.utc)
        now_epoch = now.timestamp()
        session_id = str(event_data.get("session_id") or "")[:64]
        trigger_source = str(event_data.get("trigger_source") or "radar_submit")[:32]

        # Extract audit result details if provided
        audit = event_data.get("audit_result") or {}
        score = audit.get("score") if audit.get("score") is not None else event_data.get("score")
        if score is not None:
            try:
                score = max(0, min(100, int(score)))
            except (ValueError, TypeError):
                score = None

        grade = audit.get("grade") or event_data.get("grade")
        if grade:
            grade = str(grade)[:4].upper()

        risk_label = audit.get("risk_label") or event_data.get("risk_label")
        dmarc_status = audit.get("dmarc_status") or event_data.get("dmarc_status")
        spf_status = audit.get("spf_status") or event_data.get("spf_status")
        cname_status = audit.get("cname_status") or event_data.get("cname_status")
        is_nxdomain = bool(audit.get("is_nxdomain") or event_data.get("is_nxdomain"))
        is_lookup_failed = bool(audit.get("is_lookup_failed") or event_data.get("is_lookup_failed"))

        # Deterministic unique query ID
        hash_seed = f"{domain}:{now_epoch}:{session_id}:{client_ip}"
        query_id = f"rad_{int(now_epoch)}_{hashlib.sha256(hash_seed.encode('utf-8')).hexdigest()[:8]}"

        record = RadarQueryRecord(
            id=query_id,
            domain=domain,
            raw_input=raw_input,
            timestamp=now.isoformat(),
            timestamp_epoch=now_epoch,
            trigger_source=trigger_source,
            score=score,
            grade=grade,
            risk_label=str(risk_label)[:32] if risk_label else None,
            dmarc_status=str(dmarc_status)[:16] if dmarc_status else None,
            spf_status=str(spf_status)[:16] if spf_status else None,
            cname_status=str(cname_status)[:16] if cname_status else None,
            is_nxdomain=is_nxdomain,
            is_lookup_failed=is_lookup_failed,
            session_id=session_id or None,
            source_url=str(event_data.get("source_url") or "")[:256] or None,
            referrer=str(event_data.get("referrer") or "")[:256] or None,
            user_agent=str(event_data.get("user_agent") or "")[:256] or None,
            screen_resolution=str(event_data.get("screen_resolution") or "")[:32] or None,
            client_ip=str(client_ip)[:64] if client_ip else None,
        )

        record_dict = record.to_dict()

        # Check deduplication window to avoid double-logging fast repeated clicks
        with self._lock:
            is_dup = self._is_duplicate(domain, session_id, now_epoch)
            if not is_dup:
                try:
                    with open(self.queries_file, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(record_dict) + "\n")
                except Exception as ex:
                    logger.warning(f"Failed to append radar query to {self.queries_file}: {ex}")

        # Broadcast to local Blackboard event bus
        self._publish_to_blackboard(record_dict)

        # Dispatch rich webhook notification if configured
        self._dispatch_webhooks(record_dict)

        return {
            "ok": True,
            "id": query_id,
            "domain": domain,
            "score": score,
            "grade": grade,
            "recorded_at": now.isoformat(),
            "trigger_source": trigger_source,
        }

    def _publish_to_blackboard(self, record_dict: Dict[str, Any]) -> None:
        """Publishes RADAR_DOMAIN_ENTERED event to Blackboard event bus for Cockpit SSE HUD."""
        try:
            sec_src = str(REPO_ROOT / "src")
            if sec_src not in sys.path:
                sys.path.insert(0, sec_src)
            from orbit_security.blackboard import (
                EVENT_RADAR_DOMAIN_ENTERED,
                TOPIC_TELEMETRY,
                publish_event,
            )
            publish_event(
                event_type=EVENT_RADAR_DOMAIN_ENTERED,
                payload=record_dict,
                source="radar_terminal",
                topic=TOPIC_TELEMETRY,
            )
        except Exception as ex:
            logger.debug(f"Blackboard event publication notice: {ex}")

    def _dispatch_webhooks(self, record: Dict[str, Any]) -> None:
        """Dispatches an alert to configured Discord / Slack webhooks."""
        discord_url = os.environ.get("ORBIT_RADAR_WEBHOOK_URL") or os.environ.get("DISCORD_WEBHOOK_URL")
        slack_url = os.environ.get("SLACK_WEBHOOK_URL")

        if not discord_url and not slack_url:
            return

        def _worker():
            try:
                domain = record.get("domain", "")
                score = record.get("score")
                grade = record.get("grade") or "N/A"
                source = record.get("trigger_source") or "terminal"
                ts = record.get("timestamp", "")[:19]

                score_text = f"{score}/100" if score is not None else "Pending"
                title = f"🎯 Orbit Radar Probe Detected: {domain}"
                summary = (
                    f"**Target Domain:** `{domain}`\n"
                    f"**Perimeter Hygiene:** {score_text} (Grade: `{grade}`)\n"
                    f"**Trigger Source:** `{source}`\n"
                    f"**Source URL:** {record.get('source_url') or 'https://cmfh009.github.io/Orbit-Security/'}\n"
                    f"**Timestamp:** {ts} UTC"
                )

                if discord_url:
                    payload = {
                        "username": "ORBIT Radar Sentinel",
                        "avatar_url": "https://cmfh009.github.io/Orbit-Security/assets/logo.png",
                        "embeds": [
                            {
                                "title": title,
                                "description": summary,
                                "color": 0x10B981 if (score and score >= 75) else 0xEF4444,
                                "footer": {"text": "Project ORBIT // Perimeter Radar Terminal Live Telemetry"},
                            }
                        ],
                    }
                    req = urllib.request.Request(
                        discord_url,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json", "User-Agent": "OrbitRadarTelemetry/1.0"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5.0) as _:
                        pass

                if slack_url:
                    payload = {
                        "text": f"{title}\n{summary}",
                    }
                    req = urllib.request.Request(
                        slack_url,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json", "User-Agent": "OrbitRadarTelemetry/1.0"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5.0) as _:
                        pass
            except Exception as ex:
                logger.warning(f"Webhook dispatch failed: {ex}")

        threading.Thread(target=_worker, daemon=True).start()

    def get_recent_queries(
        self, limit: int = 50, domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Reads recent queries from JSONL in reverse chronological order."""
        if not self.queries_file.exists():
            return []
        queries: List[Dict[str, Any]] = []
        target = self.normalize_domain(domain) if domain else None
        try:
            with open(self.queries_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if target and target not in record.get("domain", ""):
                            continue
                        queries.append(record)
                    except json.JSONDecodeError:
                        continue
        except Exception as ex:
            logger.warning(f"Failed to read queries from {self.queries_file}: {ex}")
            return []

        queries.reverse()
        return queries[:limit]

    def get_query_stats(self) -> Dict[str, Any]:
        """Calculates aggregate metrics across recorded perimeter radar probes."""
        if not self.queries_file.exists():
            return {
                "total_probes": 0,
                "unique_domains": 0,
                "top_domains": [],
                "grade_breakdown": {},
                "latest_probe": None,
            }

        domain_counts: Dict[str, int] = {}
        grade_counts: Dict[str, int] = {}
        total = 0
        latest: Optional[Dict[str, Any]] = None

        try:
            with open(self.queries_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        total += 1
                        d = record.get("domain", "unknown")
                        domain_counts[d] = domain_counts.get(d, 0) + 1
                        g = record.get("grade") or "PENDING"
                        grade_counts[g] = grade_counts.get(g, 0) + 1
                        latest = record
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

        sorted_domains = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        top_domains = [{"domain": d, "probes": count} for d, count in sorted_domains]

        return {
            "total_probes": total,
            "unique_domains": len(domain_counts),
            "top_domains": top_domains,
            "grade_breakdown": grade_counts,
            "latest_probe": latest,
        }

    def clear_queries(self) -> None:
        """Truncates the query log file (primarily for testing suites)."""
        with self._lock:
            self._recent_probes_cache.clear()
            if self.queries_file.exists():
                try:
                    self.queries_file.write_text("", encoding="utf-8")
                except Exception:
                    pass


# =============================================================================
# Standalone HTTP Ingestion Handler & Server
# =============================================================================

class RadarTelemetryHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Zero-dependency HTTP handler for incoming telemetry beacons from the browser."""

    service = RadarTelemetryService()

    def send_cors_headers(self, status: int = 200, content_type: str = "application/json"):
        origin = self.headers.get("Origin", "*")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", origin or "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Orbit-Session, X-Requested-With",
        )
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "86400")

    def do_OPTIONS(self):
        self.send_cors_headers(200, "text/plain")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/api/orbit/radar/telemetry", "/api/radar/telemetry"):
            q_params = urllib.parse.parse_qs(parsed.query)
            limit = int(q_params.get("limit", [50])[0])
            domain = q_params.get("domain", [None])[0]
            queries = self.service.get_recent_queries(limit=limit, domain=domain)
            stats = self.service.get_query_stats()
            body = json.dumps({"ok": True, "count": len(queries), "stats": stats, "queries": queries}).encode("utf-8")
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path in ("/api/health", "/health"):
            body = b'{"status": "ok", "service": "orbit-radar-telemetry"}'
            self.send_cors_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_cors_headers(404, "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/api/orbit/radar/telemetry", "/api/radar/telemetry"):
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
                data = json.loads(raw_body)
            except Exception as ex:
                err_body = json.dumps({"ok": False, "error": f"Invalid JSON payload: {ex}"}).encode("utf-8")
                self.send_cors_headers(400, "application/json")
                self.send_header("Content-Length", str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
                return

            client_ip = self.client_address[0] if hasattr(self, "client_address") and self.client_address else "127.0.0.1"
            res = self.service.record_query(data, client_ip=client_ip)
            status_code = 200 if res.get("ok") else 400
            body = json.dumps(res).encode("utf-8")
            self.send_cors_headers(status_code, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_cors_headers(404, "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format_str, *args):
        pass  # Silent logging to prevent console pollution


def run_server(port: int = 9095, host: str = "0.0.0.0") -> None:
    server_address = (host, port)
    httpd = http.server.ThreadingHTTPServer(server_address, RadarTelemetryHTTPHandler)
    print(f"[ORBIT-TELEMETRY] Listening on http://{host}:{port}/api/orbit/radar/telemetry")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        print("\n[ORBIT-TELEMETRY] Server terminated.")


# =============================================================================
# CLI Tail & Stats Functions
# =============================================================================

def run_tail(poll_interval: float = 1.0, limit: int = 10) -> None:
    """Streams live incoming perimeter queries to stdout in retro cyber format."""
    service = RadarTelemetryService()
    print("=" * 78)
    print("ORBIT // PERIMETER RADAR TERMINAL - LIVE INBOUND PROBE STREAM")
    print(f"Log source: {service.queries_file}")
    print("Press Ctrl+C to stop.")
    print("=" * 78)

    seen_ids = set()
    initial_queries = service.get_recent_queries(limit=limit)
    for q in reversed(initial_queries):
        seen_ids.add(q.get("id"))
        _print_query_line(q)

    while True:
        try:
            time.sleep(poll_interval)
            latest = service.get_recent_queries(limit=20)
            for q in reversed(latest):
                qid = q.get("id")
                if qid and qid not in seen_ids:
                    seen_ids.add(qid)
                    _print_query_line(q)
        except KeyboardInterrupt:
            print("\n[Tail terminated]")
            break


def _print_query_line(q: Dict[str, Any]) -> None:
    domain = q.get("domain", "unknown")
    score = q.get("score")
    grade = q.get("grade") or "--"
    src = q.get("trigger_source", "submit")
    ts = q.get("timestamp", "")[:19].replace("T", " ")
    score_str = f"{score:>3}/100" if score is not None else "  ---  "
    print(f"[{ts}] [{grade:^3}] ({score_str}) PROBE: {domain:<32} [via: {src}]")


def run_stats() -> None:
    """Prints a structured summary of domain inquiries to stdout."""
    service = RadarTelemetryService()
    stats = service.get_query_stats()
    print("=" * 60)
    print("ORBIT // PERIMETER RADAR TERMINAL INQUIRY METRICS")
    print("=" * 60)
    print(f"Total Radar Probes Logged : {stats['total_probes']}")
    print(f"Unique Domains Audited     : {stats['unique_domains']}")
    print("-" * 60)
    print("Top Probed Domains:")
    for item in stats.get("top_domains", []):
        print(f"  • {item['domain']:<35} : {item['probes']} probe(s)")
    print("-" * 60)
    print("Security Hygiene Breakdown:")
    for grade, count in sorted(stats.get("grade_breakdown", {}).items()):
        print(f"  • Grade {grade:<8} : {count}")
    print("=" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="radar_telemetry",
        description="ORBIT Radar Terminal Inbound Query Telemetry Service & Observer",
    )
    parser.add_argument("--tail", action="store_true", help="Live tail inbound queries")
    parser.add_argument("--stats", action="store_true", help="Display inquiry statistics")
    parser.add_argument("--serve", action="store_true", help="Run standalone ingestion HTTP server")
    parser.add_argument("--port", type=int, default=9095, help="Port for server (default: 9095)")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--probe", help="Emit manual test probe for specified domain")

    args = parser.parse_args()

    if args.probe:
        service = RadarTelemetryService()
        res = service.record_query({"domain": args.probe, "trigger_source": "cli_test"})
        print(json.dumps(res, indent=2))
        return 0

    if args.serve:
        run_server(port=args.port, host=args.host)
        return 0

    if args.tail:
        run_tail()
        return 0

    if args.stats:
        run_stats()
        return 0

    # Default action: show stats
    run_stats()
    return 0


if __name__ == "__main__":
    sys.exit(main())
