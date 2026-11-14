#!/usr/bin/env python3
r"""
src/orbit_security/blackboard.py: Decoupled SQLite WAL Blackboard Event Bus
==========================================================================
Provides high-performance, asynchronous, non-blocking event publishing
and subscribing for Project ORBIT micro-daemons, Cockpit, TUI, and Sentinels.

Features:
- SQLite WAL mode (PRAGMA journal_mode=WAL) with busy timeout for high concurrency
- Atomic event publishing with JSON payloads
- Filtered retrieval by event type or topic
- Unprocessed event cursor for workers/subscribers
- In-memory fan-out subscriber queue mesh with thread-safe broadcast
- Dual-write persistence to orbit_events.db archive when available
- Zero third-party dependencies (pure Python stdlib sqlite3)
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import functools
import json
import logging
import os
import queue
import random
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
import urllib.request
from urllib.parse import urlsplit

HIGH_SIGNAL_NOVA_BRAIN_EVENTS = frozenset({
    "ROE_REDIRECT_BLOCKED",
    "ROE_BOGON_BLOCKED",
    "BOUNTY_VULN_VERIFIED",
    "REPORT_CRITIC_RECEIPT",
    "REPORT_CRITIC_VERIFIED",
})


def is_high_signal_nova_event(
    event_type: str,
    source: str,
    payload: Optional[Dict[str, Any]] = None,
) -> bool:
    """Returns True when an Orbit blackboard event should be recorded in Nova Brain episodic memory."""
    ev_upper = str(event_type or "").strip().upper()
    src_str = str(source or "").strip()
    if ev_upper in HIGH_SIGNAL_NOVA_BRAIN_EVENTS:
        return True
    if src_str == "ReportCriticVerifier" or "REPORT_CRITIC" in ev_upper:
        return True
    if isinstance(payload, dict) and (
        "verified_artifact_ids" in payload or "critic_receipt" in payload
    ):
        return True
    return False


def _is_loopback_ipc_url(url: Optional[str]) -> bool:
    if not url:
        return False
    try:
        host = (urlsplit(str(url)).hostname or "").strip().lower()
        return host in {"127.0.0.1", "localhost", "::1"}
    except Exception:
        return False

logger = logging.getLogger("orbit_security.blackboard")

# Canonical Base Paths
WORKSPACE_ROOT = Path("A:/") if Path("A:/").exists() else Path("C:/AgyHut")
SYSTEM_DIR = WORKSPACE_ROOT / "system"
STATE_DIR = SYSTEM_DIR / "state"

if STATE_DIR.exists():
    DEFAULT_BLACKBOARD_DB = STATE_DIR / "blackboard.db"
else:
    # Standalone or CI environment fallback within repository tree
    _REPO_ROOT = Path(__file__).resolve().parent.parent.parent
    DEFAULT_BLACKBOARD_DB = _REPO_ROOT / "data" / "blackboard.db"


def wal_retry(max_retries: int = 5, initial_backoff: float = 0.05, max_backoff: float = 1.0):
    """Decorator executing SQLite transactions with exponential backoff and jitter on database lock."""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_backoff
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    err_msg = str(e).lower()
                    if "locked" in err_msg or "busy" in err_msg:
                        if attempt == max_retries - 1:
                            logger.error(f"WAL operation {func.__name__} failed after {max_retries} attempts: {e}")
                            raise
                        jitter = random.uniform(0.8, 1.2)
                        sleep_time = min(delay * jitter, max_backoff)
                        logger.warning(
                            f"SQLite WAL lock contention on {func.__name__} (attempt {attempt + 1}/{max_retries}); "
                            f"retrying in {sleep_time:.3f}s: {e}"
                        )
                        time.sleep(sleep_time)
                        delay *= 2.0
                    else:
                        raise
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _running_under_pytest() -> bool:
    """Detects an active pytest run without importing pytest."""
    return bool(
        os.environ.get("PYTEST_CURRENT_TEST")
        or os.environ.get("PYTEST_VERSION")
        or "pytest" in sys.modules
    )


def resolve_blackboard_path(db_path: Optional[Path] = None) -> Path:
    """Resolves the blackboard DB path with explicit isolation guards.

    Mirrors system/scripts/blackboard.py so both packages agree on the same
    database, and so pytest runs never write into production state.
    """
    if db_path is not None:
        return Path(db_path)
    env_path = os.environ.get("ORBIT_BLACKBOARD_DB")
    if env_path:
        return Path(env_path)
    if _running_under_pytest() and os.environ.get("ORBIT_ALLOW_PROD_BLACKBOARD") != "1":
        return Path(tempfile.gettempdir()) / f"orbit_pytest_blackboard_{os.getpid()}.db"
    return DEFAULT_BLACKBOARD_DB

# Canonical Event Topics
TOPIC_TELEMETRY = "telemetry"
TOPIC_GROWTH = "growth"
TOPIC_DEVOPS = "devops"
TOPIC_THREAT_INTEL = "threat_intel"
TOPIC_SOCIAL = "social"
TOPIC_REMEDIATION = "remediation"

# Canonical Event Types
EVENT_THREAT_INTEL_DISCOVERED = "THREAT_INTEL_DISCOVERED"
EVENT_ROAST_STAGED = "ROAST_STAGED"
EVENT_GITHUB_RELEASE_READY = "GITHUB_RELEASE_READY"
EVENT_PORTAL_CONVERSION = "PORTAL_CONVERSION"
EVENT_VIRAL_THREAD_COMPOSED = "VIRAL_THREAD_COMPOSED"
EVENT_COMMUNITY_ENGAGEMENT_QUEUED = "COMMUNITY_ENGAGEMENT_QUEUED"
EVENT_MARKETING_CAMPAIGN_STAGED = "MARKETING_CAMPAIGN_STAGED"
EVENT_PR_AUDIT_COMPLETED = "PR_AUDIT_COMPLETED"
EVENT_SHOWCASE_UPDATED = "SHOWCASE_UPDATED"
EVENT_RADAR_DOMAIN_ENTERED = "RADAR_DOMAIN_ENTERED"
EVENT_RADAR_LEAD_ENRICHED = "RADAR_LEAD_ENRICHED"
EVENT_RADAR_PROPOSAL_STAGED = "RADAR_PROPOSAL_STAGED"
EVENT_OPENCODE_REMEDIATION_STAGED = "OPENCODE_REMEDIATION_STAGED"
EVENT_OPENCODE_REMEDIATION_VERIFIED = "OPENCODE_REMEDIATION_VERIFIED"


class Blackboard:
    """Decoupled SQLite WAL Event Mesh for Orbit services."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        nova_brain_url: Optional[str] = None,
        topology_bridge: Optional[Any] = None,
    ):
        self.db_path = resolve_blackboard_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._subscribers: Set[queue.Queue] = set()
        self._sub_lock = threading.Lock()
        self.topology_bridge = topology_bridge
        if nova_brain_url is not None:
            self.nova_brain_url: Optional[str] = str(nova_brain_url).rstrip("/")
        else:
            env_url = os.environ.get("ORBIT_NOVA_BRAIN_URL")
            if env_url:
                self.nova_brain_url = str(env_url).rstrip("/")
            elif not _running_under_pytest() and os.environ.get("ORBIT_NOVA_BRAIN_ENABLED", "1") != "0":
                self.nova_brain_url = "http://127.0.0.1:8200"
            else:
                self.nova_brain_url = None
        self._init_db()

    @contextlib.contextmanager
    def _connection(self):
        """Context manager guaranteeing connection close to prevent handle leaks on Windows."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False
        )
        sync_mode = "OFF" if _running_under_pytest() else "NORMAL"
        conn.execute(f"PRAGMA synchronous = {sync_mode};")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _get_connection(self) -> sqlite3.Connection:
        """Legacy accessor returning raw connection."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False
        )
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row
        return conn

    @wal_retry()
    def _init_db(self):
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blackboard_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL DEFAULT 'telemetry',
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    processed INTEGER DEFAULT 0
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_bb_event_type_time
                ON blackboard_events (event_type, created_at DESC);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_bb_topic_processed
                ON blackboard_events (topic, processed);
            """)
            conn.commit()

    def subscribe(self, maxsize: int = 100) -> queue.Queue:
        """Subscribes an in-memory queue to live blackboard events."""
        q = queue.Queue(maxsize=maxsize)
        with self._sub_lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Unregisters an in-memory event subscriber queue."""
        with self._sub_lock:
            self._subscribers.discard(q)

    def _forward_to_nova_brain(self, event: Dict[str, Any]) -> bool:
        """Forwards high-signal security events non-blockingly into Nova Brain /api/memory/store."""
        if not self.nova_brain_url or not _is_loopback_ipc_url(self.nova_brain_url):
            return False
        ev_type = str(event.get("event_type") or "")
        source = str(event.get("source") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if not is_high_signal_nova_event(ev_type, source, payload):
            return False

        target_ref = (
            payload.get("target_domain")
            or payload.get("hostname")
            or payload.get("target_url")
            or payload.get("domain")
            or "orbit"
        )
        detail_msg = payload.get("reason") or payload.get("flaw_type") or event.get("topic") or "security_event"
        summary = f"[Orbit Security] {ev_type} on {target_ref} ({detail_msg})"
        body = json.dumps(
            {
                "summary": summary,
                "category": "SECURITY_EVENT",
                "session_id": "orbit-security",
                "details": {
                    "event_id": event.get("id"),
                    "event_type": ev_type,
                    "source": source,
                    "topic": event.get("topic"),
                    "payload": payload,
                },
                "tags": ["orbit-security", ev_type.lower(), str(event.get("topic") or "security").lower()],
            },
            default=str,
        ).encode("utf-8")
        store_url = f"{self.nova_brain_url}/api/memory/store"
        try:
            req = urllib.request.Request(
                store_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=0.5) as resp:  # roe-exempt: local Nova Brain loopback IPC
                return 200 <= getattr(resp, "status", 200) < 300
        except Exception as exc:
            logger.debug("Non-blocking Nova Brain forward skipped (%s): %s", store_url, exc)
            return False

    def broadcast(self, event: Dict[str, Any]) -> None:
        """Thread-safe broadcast of an event dictionary to all active subscribers.
        Discards full or dead queues to prevent stalling publishers.
        """
        with self._sub_lock:
            dead_queues = []
            for q in list(self._subscribers):
                try:
                    q.put_nowait(event)
                except (queue.Full, Exception):
                    dead_queues.append(q)
            for dead_q in dead_queues:
                self._subscribers.discard(dead_q)

    @wal_retry()
    def publish(
        self,
        event_type: str,
        payload: Dict[str, Any],
        source: str = "orbit",
        topic: str = "telemetry"
    ) -> int:
        """Publishes an event to the blackboard. Returns inserted event ID."""
        now = time.time()
        payload_json = json.dumps(payload, default=str)
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO blackboard_events (topic, event_type, source, payload, created_at, processed)
                VALUES (?, ?, ?, ?, ?, 0);
            """, (topic, event_type, source, payload_json, now))
            ev_id = cur.lastrowid
            if ev_id and ev_id % 500 == 0 and topic in ("telemetry", "proactive_heartbeat"):
                cur.execute(
                    "DELETE FROM blackboard_events WHERE topic IN ('telemetry', 'proactive_heartbeat') AND id < ?",
                    (max(0, ev_id - 5000),)
                )
            conn.commit()

        event_dict = {
            "id": ev_id,
            "topic": topic,
            "event_type": event_type,
            "source": source,
            "payload": payload,
            "created_at": now,
            "processed": False,
            "iso_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        }
        self.broadcast(event_dict)
        self._forward_to_nova_brain(event_dict)
        if self.topology_bridge is not None:
            try:
                self.topology_bridge.enqueue_event(event_dict)
            except Exception:
                pass
        return ev_id

    @wal_retry()
    def publish_batch(
        self,
        events: List[Dict[str, Any]],
        default_source: str = "shuttle",
        default_topic: str = "telemetry",
    ) -> List[int]:
        """Atomically publishes a list of events to the blackboard in a single transaction."""
        if not events:
            return []
        now = time.time()
        to_insert = []
        parsed_events = []
        for e in events:
            ev_topic = str(e.get("topic") or default_topic).strip()
            ev_type = str(e.get("event_type") or "EVENT").strip()
            ev_source = str(e.get("source") or default_source).strip()
            payload = e.get("payload") or {}
            payload_json = json.dumps(payload, default=str)
            created_at = float(e.get("created_at") or now)
            to_insert.append((ev_topic, ev_type, ev_source, payload_json, created_at))
            parsed_events.append({
                "topic": ev_topic,
                "event_type": ev_type,
                "source": ev_source,
                "payload": payload,
                "created_at": created_at,
            })

        inserted_ids = []
        with self._connection() as conn:
            cur = conn.cursor()
            for item in to_insert:
                cur.execute("""
                    INSERT INTO blackboard_events (topic, event_type, source, payload, created_at, processed)
                    VALUES (?, ?, ?, ?, ?, 0);
                """, item)
                inserted_ids.append(cur.lastrowid)
            conn.commit()

        for idx, ev_id in enumerate(inserted_ids):
            event_dict = {
                "id": ev_id,
                **parsed_events[idx],
                "processed": False
            }
            self.broadcast(event_dict)
            self._forward_to_nova_brain(event_dict)
            if self.topology_bridge is not None:
                try:
                    self.topology_bridge.enqueue_event(event_dict)
                except Exception:
                    pass

        return inserted_ids

    @wal_retry()
    def get_recent(
        self,
        limit: int = 50,
        event_type: Optional[str] = None,
        topic: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves most recent events matching filters."""
        query = "SELECT id, topic, event_type, source, payload, created_at, processed FROM blackboard_events"
        params: List[Any] = []
        where_clauses: List[str] = []

        if event_type:
            where_clauses.append("event_type = ?")
            params.append(event_type)
        if topic:
            where_clauses.append("topic = ?")
            params.append(topic)

        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        events = []
        for r in rows:
            try:
                p = json.loads(r["payload"])
            except Exception:
                p = {"raw": r["payload"]}
            events.append({
                "id": r["id"],
                "topic": r["topic"],
                "event_type": r["event_type"],
                "source": r["source"],
                "payload": p,
                "created_at": r["created_at"],
                "processed": bool(r["processed"]),
                "iso_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"]))
            })
        return events

    @wal_retry()
    def get_unprocessed(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        mark_processed: bool = False
    ) -> List[Dict[str, Any]]:
        """Fetches unprocessed events for worker queues."""
        query = "SELECT id, topic, event_type, source, payload, created_at, processed FROM blackboard_events WHERE processed = 0"
        params: List[Any] = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY id ASC LIMIT ?"
        params.append(limit)

        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

            events = []
            ids_to_mark = []
            for r in rows:
                ids_to_mark.append(r["id"])
                try:
                    p = json.loads(r["payload"])
                except Exception:
                    p = {"raw": r["payload"]}
                events.append({
                    "id": r["id"],
                    "topic": r["topic"],
                    "event_type": r["event_type"],
                    "source": r["source"],
                    "payload": p,
                    "created_at": r["created_at"],
                    "processed": False
                })

            if mark_processed and ids_to_mark:
                placeholders = ",".join("?" for _ in ids_to_mark)
                conn.execute(
                    f"UPDATE blackboard_events SET processed = 1 WHERE id IN ({placeholders})",
                    ids_to_mark
                )
                conn.commit()

        return events

    @wal_retry()
    def get_events_after(
        self,
        after_id: int = 0,
        limit: int = 100,
        topic: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves events with id > after_id for incremental shuttle replication."""
        query = "SELECT id, topic, event_type, source, payload, created_at, processed FROM blackboard_events WHERE id > ?"
        params: List[Any] = [int(after_id)]

        if topic:
            query += " AND topic = ?"
            params.append(topic)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY id ASC LIMIT ?"
        params.append(int(limit))

        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        events = []
        for r in rows:
            try:
                p = json.loads(r["payload"])
            except Exception:
                p = {"raw": r["payload"]}
            events.append({
                "id": r["id"],
                "topic": r["topic"],
                "event_type": r["event_type"],
                "source": r["source"],
                "payload": p,
                "created_at": r["created_at"],
                "processed": bool(r["processed"]),
                "iso_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"]))
            })
        return events

    @wal_retry()
    def get_max_event_id(self) -> int:
        """Returns the maximum event ID currently recorded in the blackboard."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(MAX(id), 0) FROM blackboard_events;")
            row = cur.fetchone()
            return int(row[0]) if row and row[0] is not None else 0

    @wal_retry()
    def mark_processed(self, event_id: int) -> bool:
        """Marks an event as processed."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE blackboard_events SET processed = 1 WHERE id = ?", (event_id,))
            conn.commit()
            return cur.rowcount > 0

    @wal_retry()
    def clear(self):
        """Clears all events (useful for testing)."""
        with self._connection() as conn:
            conn.execute("DELETE FROM blackboard_events;")
            conn.commit()

    @wal_retry()
    def checkpoint(self, mode: str = "PASSIVE") -> Dict[str, Any]:
        """Flushes SQLite WAL journal to the main database safely.
        Valid modes: PASSIVE, FULL, RESTART, TRUNCATE.
        """
        mode_clean = str(mode or "PASSIVE").upper().strip()
        if mode_clean not in ("PASSIVE", "FULL", "RESTART", "TRUNCATE"):
            mode_clean = "PASSIVE"
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(f"PRAGMA wal_checkpoint({mode_clean});")
            row = cur.fetchone()
            busy = row[0] if row else 0
            log_frames = row[1] if row and len(row) > 1 else 0
            checkpointed_frames = row[2] if row and len(row) > 2 else 0
            return {
                "mode": mode_clean,
                "busy": busy,
                "log_frames": log_frames,
                "checkpointed_frames": checkpointed_frames,
                "ok": busy == 0
            }

    @wal_retry()
    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics on the blackboard database."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as total FROM blackboard_events;")
            total = cur.fetchone()["total"]
            cur.execute("SELECT COUNT(*) as unprocessed FROM blackboard_events WHERE processed = 0;")
            unprocessed = cur.fetchone()["unprocessed"]
            cur.execute("PRAGMA journal_mode;")
            journal_mode = cur.fetchone()[0]

        return {
            "db_path": str(self.db_path),
            "journal_mode": journal_mode,
            "total_events": total,
            "unprocessed_events": unprocessed,
            "exists": self.db_path.exists(),
            "size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0
        }

    def create_litestream_snapshot(self, snapshot_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Performs a WAL checkpoint and writes an atomic SQLite online backup + SHA-256 manifest (Project #18)."""
        import hashlib

        snap_root = Path(snapshot_dir or (self.db_path.parent / "snapshots"))
        snap_root.mkdir(parents=True, exist_ok=True)
        chk = self.checkpoint("TRUNCATE")

        ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snap_file = snap_root / f"{self.db_path.stem}_snapshot_{ts_slug}.db"

        with self._connection() as src_conn:
            dst_conn = sqlite3.connect(str(snap_file), timeout=10.0)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()

        raw_bytes = snap_file.read_bytes()
        sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
        stats = self.get_stats()

        manifest = {
            "ok": True,
            "source_db": str(self.db_path),
            "snapshot_path": str(snap_file),
            "size_bytes": len(raw_bytes),
            "sha256": sha256_hex,
            "total_events": stats["total_events"],
            "checkpoint": chk,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        manifest_file = snap_root / f"{snap_file.stem}.manifest.json"
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def render_retro_tui_dashboard(self, width: int = 84) -> str:
        """Renders a Retro TUI Cockpit Terminal frame for SSH / Termux sessions (Project #29)."""
        try:
            w = max(68, min(int(width), 200))
        except (ValueError, TypeError):
            w = 84
        border = "+" + ("-" * (w - 2)) + "+"
        stats = self.get_stats()
        recent = self.get_recent(limit=5)

        def _pad(text: str) -> str:
            inner = text[: w - 4]
            return f"| {inner:<{w - 4}} |"

        lines = [
            border,
            _pad("ORBIT SECURITY // RETRO TUI COCKPIT (SSH / TERMUX MODE)"),
            _pad(f"WAL JOURNAL: {str(stats['journal_mode']).upper()} | EVENTS: {stats['total_events']} | OUTREACH FREEZE: LOCKED"),
            border,
            _pad("[RECENT TELEMETRY & SENTINEL STREAM]"),
        ]
        if not recent:
            lines.append(_pad("  (No events recorded yet)"))
        else:
            for ev in recent:
                ev_line = f"#{ev['id']} [{ev['iso_time'][-8:]}] {ev['event_type']} ({ev['source']})"
                lines.append(_pad(ev_line))
        lines.append(border)
        return "\n".join(lines)


# Singleton accessor
_GLOBAL_BLACKBOARD: Optional[Blackboard] = None


def get_blackboard(db_path: Optional[Path] = None) -> Blackboard:
    global _GLOBAL_BLACKBOARD
    if _GLOBAL_BLACKBOARD is None or db_path is not None:
        _GLOBAL_BLACKBOARD = Blackboard(db_path)
    return _GLOBAL_BLACKBOARD


def publish_event(
    event_type: str,
    payload: dict,
    source: str = "orbit",
    topic: str = "telemetry"
) -> int:
    """Publishes an event to both blackboard.db (SSE mesh) and orbit_events.db (WAL archive).
    Guarantees strict connection lifecycle cleanup on Windows to prevent lock leaks.
    """
    ev_id = get_blackboard().publish(event_type, payload, source=source, topic=topic)

    repo_data = Path(__file__).resolve().parent.parent.parent / "data"
    orbit_events_db = repo_data / "orbit_events.db"

    try:
        if repo_data.exists():
            payload_json = json.dumps(payload, default=str)
            now_iso = datetime.now(timezone.utc).isoformat()
            conn = sqlite3.connect(str(orbit_events_db), timeout=10.0)
            try:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                conn.execute("PRAGMA busy_timeout = 5000;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        topic TEXT NOT NULL,
                        source TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        processed_at TIMESTAMP NULL
                    )
                """)
                conn.execute(
                    "INSERT INTO events (event_type, topic, source, payload, created_at) VALUES (?, ?, ?, ?, ?)",
                    (event_type, topic, source, payload_json, now_iso)
                )
                if ev_id and ev_id % 500 == 0 and topic in ("telemetry", "proactive_heartbeat"):
                    conn.execute(
                        "DELETE FROM events WHERE topic IN ('telemetry', 'proactive_heartbeat') AND id < (SELECT COALESCE(MAX(id), 0) - 5000 FROM events)"
                    )
                conn.commit()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
    except Exception:
        pass

    return ev_id


def get_recent_events(limit: int = 50, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    return get_blackboard().get_recent(limit=limit, event_type=event_type)


def get_events_after(after_id: int = 0, limit: int = 100, topic: Optional[str] = None, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    return get_blackboard().get_events_after(after_id=after_id, limit=limit, topic=topic, event_type=event_type)


def get_max_event_id() -> int:
    return get_blackboard().get_max_event_id()


def subscribe(maxsize: int = 100) -> queue.Queue:
    return get_blackboard().subscribe(maxsize=maxsize)


def unsubscribe(q: queue.Queue) -> None:
    return get_blackboard().unsubscribe(q)


def broadcast(event: Dict[str, Any]) -> None:
    return get_blackboard().broadcast(event)


def checkpoint(mode: str = "PASSIVE") -> Dict[str, Any]:
    return get_blackboard().checkpoint(mode=mode)


__all__ = [
    "Blackboard",
    "get_blackboard",
    "publish_event",
    "get_recent_events",
    "subscribe",
    "unsubscribe",
    "broadcast",
    "checkpoint",
    "wal_retry",
    "DEFAULT_BLACKBOARD_DB",
    "TOPIC_TELEMETRY",
    "TOPIC_GROWTH",
    "TOPIC_DEVOPS",
    "TOPIC_THREAT_INTEL",
    "TOPIC_SOCIAL",
    "EVENT_THREAT_INTEL_DISCOVERED",
    "EVENT_ROAST_STAGED",
    "EVENT_GITHUB_RELEASE_READY",
    "EVENT_PORTAL_CONVERSION",
    "EVENT_VIRAL_THREAD_COMPOSED",
    "EVENT_COMMUNITY_ENGAGEMENT_QUEUED",
    "EVENT_MARKETING_CAMPAIGN_STAGED",
    "EVENT_PR_AUDIT_COMPLETED",
    "EVENT_SHOWCASE_UPDATED",
    "EVENT_RADAR_DOMAIN_ENTERED",
    "EVENT_RADAR_LEAD_ENRICHED",
    "EVENT_RADAR_PROPOSAL_STAGED",
]
