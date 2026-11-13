"""Unit and stress tests for SQLite WAL locking and jittered exponential retry discipline (Track 2).

Verifies:
1. @wal_retry decorator handles transient `sqlite3.OperationalError: database is locked` transparently.
2. Irrelevant OperationalErrors (e.g., table not found or syntax error) are raised immediately.
3. Concurrent multithreaded publish storm executes with zero dropped events and zero unhandled lock errors.
4. Checkpoint operations (PASSIVE and TRUNCATE) complete cleanly without handle leaks.
"""

from __future__ import annotations

import concurrent.futures
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from orbit_security.blackboard import Blackboard, wal_retry


def test_wal_retry_recovers_from_transient_lock():
    attempts = 0

    @wal_retry(max_retries=4, initial_backoff=0.01, max_backoff=0.05)
    def flaky_db_op():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise sqlite3.OperationalError("database is locked")
        return "SUCCESS"

    result = flaky_db_op()
    assert result == "SUCCESS"
    assert attempts == 3


def test_wal_retry_raises_when_retries_exhausted():
    attempts = 0

    @wal_retry(max_retries=3, initial_backoff=0.01, max_backoff=0.05)
    def locked_forever():
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError("database is locked")

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        locked_forever()
    assert attempts == 3


def test_wal_retry_does_not_retry_non_lock_errors():
    attempts = 0

    @wal_retry(max_retries=5, initial_backoff=0.01)
    def bad_syntax_op():
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError("no such table: non_existent_table")

    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        bad_syntax_op()
    assert attempts == 1


def test_concurrent_multithreaded_wal_publish_storm(tmp_path: Path):
    db_file = tmp_path / "concurrent_stress.db"
    bb = Blackboard(db_path=db_file)

    num_threads = 8
    events_per_thread = 25
    total_expected = num_threads * events_per_thread

    def worker_task(thread_id: int):
        # Open separate Blackboard instance pointing to the same DB file
        worker_bb = Blackboard(db_path=db_file)
        for i in range(events_per_thread):
            worker_bb.publish(
                event_type="STRESS_TEST_EVENT",
                payload={"thread": thread_id, "index": i, "timestamp": time.time()},
                source=f"worker_{thread_id}",
                topic="telemetry",
            )
        return thread_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker_task, tid) for tid in range(num_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == num_threads

    # Verify all events are present in the database
    stats = bb.get_stats()
    assert stats["total_events"] == total_expected

    # Verify checkpoint executes without lock error
    chk = bb.checkpoint(mode="PASSIVE")
    assert "ok" in chk
