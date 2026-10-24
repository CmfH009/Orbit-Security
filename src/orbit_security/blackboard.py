#!/usr/bin/env python3
"""Proxy/re-export of blackboard event bus for orbit_security package."""
from pathlib import Path
import sys

_SYSTEM_SCRIPTS = Path("A:/system/scripts") if Path("A:/system/scripts").exists() else Path("C:/AgyHut/system/scripts")
if str(_SYSTEM_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SYSTEM_SCRIPTS))

from datetime import datetime, timezone
import json
import sqlite3

from blackboard import (
    Blackboard,
    get_blackboard,
    publish_event as _system_publish_event,
    get_recent_events,
    subscribe,
    unsubscribe,
    broadcast,
    checkpoint,
    DEFAULT_BLACKBOARD_DB,
    TOPIC_TELEMETRY,
    TOPIC_GROWTH,
    TOPIC_DEVOPS,
    TOPIC_THREAT_INTEL,
    TOPIC_SOCIAL,
    EVENT_THREAT_INTEL_DISCOVERED,
    EVENT_ROAST_STAGED,
    EVENT_GITHUB_RELEASE_READY,
    EVENT_PORTAL_CONVERSION,
    EVENT_VIRAL_THREAD_COMPOSED,
    EVENT_COMMUNITY_ENGAGEMENT_QUEUED,
    EVENT_MARKETING_CAMPAIGN_STAGED,
    EVENT_PR_AUDIT_COMPLETED,
    EVENT_SHOWCASE_UPDATED,
)

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
]

def publish_event(
    event_type: str,
    payload: dict,
    source: str = "orbit",
    topic: str = "telemetry"
) -> int:
    """Publishes an event to both blackboard.db (SSE mesh) and orbit_events.db (WAL archive).
    Guarantees strict connection lifecycle cleanup on Windows to prevent lock leaks.
    """
    ev_id = _system_publish_event(event_type, payload, source=source, topic=topic)

    orbit_events_db = Path("A:/projects/orbit-security/data/orbit_events.db")
    if not orbit_events_db.exists():
        orbit_events_db = Path(r"C:\AgyHut\projects\orbit-security\data\orbit_events.db")

    try:
        if orbit_events_db.parent.exists():
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

