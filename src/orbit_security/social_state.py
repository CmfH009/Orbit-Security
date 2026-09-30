"""Orbit Security Social State & Deduplication Engine (social_state.py).

Provides robust SQLite (WAL mode) persistence, in-memory O(1) deduplication,
midnight UTC rollover tracking, and atomic JSON telemetry mirroring.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class SocialStateManager:
    """Manages persistent action deduplication, daily rollover counters, and audit telemetry."""

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        json_export_path: Optional[str | Path] = None,
    ):
        base_dir = Path(__file__).resolve().parent.parent.parent
        data_dir = base_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        self.db_path = Path(db_path) if db_path else data_dir / "orbit_social.db"
        self.json_export_path = Path(json_export_path) if json_export_path else data_dir / "social_history.json"
        self.lock = threading.Lock()

        # In-memory deduplication cache: set of (tweet_id, action_type)
        self._dedup_cache: Set[Tuple[str, str]] = set()

        self._init_db()
        self._load_dedup_cache()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self):
        """Initializes database schema with WAL mode and compound indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS social_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tweet_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    author_handle TEXT,
                    target_domain TEXT,
                    audit_score INTEGER,
                    content_snippet TEXT,
                    status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILED', 'SIMULATED')),
                    error_message TEXT,
                    created_at_utc TEXT NOT NULL,
                    metadata_json TEXT
                );
                """
            )
            cursor.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_dedup 
                ON social_actions (tweet_id, action_type);
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_actions_date 
                ON social_actions (created_at_utc);
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_quota_history (
                    date_utc TEXT PRIMARY KEY,
                    posts_count INTEGER DEFAULT 0,
                    replies_count INTEGER DEFAULT 0,
                    likes_count INTEGER DEFAULT 0,
                    reposts_count INTEGER DEFAULT 0,
                    follows_count INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    circuit_trips_count INTEGER DEFAULT 0,
                    updated_at_utc TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS circuit_incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    breaker_type TEXT NOT NULL,
                    status_entered TEXT NOT NULL,
                    trigger_detail TEXT NOT NULL,
                    cooldown_seconds INTEGER NOT NULL,
                    tripped_at_utc TEXT NOT NULL,
                    resolved_at_utc TEXT
                );
                """
            )
            conn.commit()

    def _load_dedup_cache(self):
        """Hydrates the in-memory deduplication set from SQLite."""
        with self.lock:
            self._dedup_cache.clear()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT tweet_id, action_type FROM social_actions WHERE status = 'SUCCESS'"
                )
                for row in cursor.fetchall():
                    self._dedup_cache.add((str(row["tweet_id"]), str(row["action_type"])))

    def is_interacted(self, tweet_id: str, action_type: str) -> bool:
        """O(1) in-memory check if tweet has already received this action."""
        key = (str(tweet_id), str(action_type).upper())
        with self.lock:
            if key in self._dedup_cache:
                return True

        # Fallback query
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM social_actions WHERE tweet_id = ? AND action_type = ? AND status = 'SUCCESS' LIMIT 1",
                (str(tweet_id), str(action_type).upper()),
            )
            found = cursor.fetchone() is not None
            if found:
                with self.lock:
                    self._dedup_cache.add(key)
            return found

    def record_action(
        self,
        tweet_id: str,
        action_type: str,
        author_handle: Optional[str] = None,
        target_domain: Optional[str] = None,
        audit_score: Optional[int] = None,
        content_snippet: Optional[str] = None,
        status: str = "SUCCESS",
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Records an action atomically in SQLite and updates the in-memory cache."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        date_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        act_upper = str(action_type).upper()

        meta_str = json.dumps(metadata or {}, ensure_ascii=False)

        with self.lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO social_actions 
                        (tweet_id, action_type, author_handle, target_domain, audit_score, content_snippet, status, error_message, created_at_utc, metadata_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(tweet_id),
                            act_upper,
                            author_handle,
                            target_domain,
                            audit_score,
                            content_snippet,
                            status,
                            error_message,
                            now_utc,
                            meta_str,
                        ),
                    )

                    # Update daily counts if successful
                    if status == "SUCCESS":
                        col_map = {
                            "ORIGINAL_POST": "posts_count",
                            "POST": "posts_count",
                            "REPLY": "replies_count",
                            "LIKE": "likes_count",
                            "REPOST": "reposts_count",
                            "RETWEET": "reposts_count",
                            "FOLLOW": "follows_count",
                        }
                        col = col_map.get(act_upper)
                        if col:
                            cursor.execute(
                                f"""
                                INSERT INTO daily_quota_history (date_utc, {col}, updated_at_utc)
                                VALUES (?, 1, ?)
                                ON CONFLICT(date_utc) DO UPDATE SET 
                                    {col} = {col} + 1,
                                    updated_at_utc = excluded.updated_at_utc
                                """,
                                (date_utc, now_utc),
                            )
                    elif status == "FAILED":
                        cursor.execute(
                            """
                            INSERT INTO daily_quota_history (date_utc, errors_count, updated_at_utc)
                            VALUES (?, 1, ?)
                            ON CONFLICT(date_utc) DO UPDATE SET 
                                errors_count = errors_count + 1,
                                updated_at_utc = excluded.updated_at_utc
                            """,
                            (date_utc, now_utc),
                        )

                    conn.commit()

                if status == "SUCCESS":
                    self._dedup_cache.add((str(tweet_id), act_upper))
                return True
            except Exception as e:
                logger.error(f"Failed to record social action: {e}")
                return False

    def get_daily_metrics(self, date_utc: Optional[str] = None) -> Dict[str, int]:
        """Fetches active counter totals for given date (defaults to current UTC day)."""
        target_date = date_utc or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM daily_quota_history WHERE date_utc = ? LIMIT 1",
                (target_date,),
            )
            row = cursor.fetchone()
            if not row:
                return {
                    "posts_count": 0,
                    "replies_count": 0,
                    "likes_count": 0,
                    "reposts_count": 0,
                    "follows_count": 0,
                    "errors_count": 0,
                }
            return {
                "posts_count": row["posts_count"],
                "replies_count": row["replies_count"],
                "likes_count": row["likes_count"],
                "reposts_count": row["reposts_count"],
                "follows_count": row["follows_count"],
                "errors_count": row["errors_count"],
            }

    def export_json_snapshot(self) -> Dict[str, Any]:
        """Generates a comprehensive JSON snapshot mirroring the state for git/HUD viewing."""
        today_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        daily_metrics = self.get_daily_metrics(today_utc)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT tweet_id, action_type, author_handle, target_domain, audit_score, status, created_at_utc 
                FROM social_actions 
                ORDER BY id DESC LIMIT 50
                """
            )
            recent_actions = [dict(r) for r in cursor.fetchall()]

        snapshot = {
            "last_updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "current_utc_date": today_utc,
            "today_metrics": daily_metrics,
            "total_cached_actions": len(self._dedup_cache),
            "recent_actions": recent_actions,
        }

        # Atomic file write to avoid corrupt partial reads
        tmp_file = self.json_export_path.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
            tmp_file.replace(self.json_export_path)
        except Exception as e:
            logger.error(f"Error exporting JSON snapshot: {e}")
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass

        return snapshot
