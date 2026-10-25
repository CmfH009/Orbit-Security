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
import json
import os
import queue
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

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

# Canonical Event Topics
TOPIC_TELEMETRY = "telemetry"
TOPIC_GROWTH = "growth"
TOPIC_DEVOPS = "devops"
TOPIC_THREAT_INTEL = "threat_intel"
TOPIC_SOCIAL = "social"

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


class Blackboard:
    """Decoupled SQLite WAL Event Mesh for Orbit services."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_BLACKBOARD_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._subscribers: Set[queue.Queue] = set()
        self._sub_lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _connection(self):
        """Context manager guaranteeing connection close to prevent handle leaks on Windows."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False
        )
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 10000;")
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
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connection() as conn:
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
            conn.commit()
            ev_id = cur.lastrowid

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
        return ev_id

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

        return inserted_ids

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

    def mark_processed(self, event_id: int) -> bool:
        """Marks an event as processed."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE blackboard_events SET processed = 1 WHERE id = ?", (event_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear(self):
        """Clears all events (useful for testing)."""
        with self._connection() as conn:
            conn.execute("DELETE FROM blackboard_events;")
            conn.commit()

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
]
