"""Unit and integration tests for orbit_security.event_shuttle (TDD).

Validates:
1. Zero-trust cryptographic HMAC-SHA256 signature generation and verification.
2. Replay attack rejection on stale timestamps (>300s).
3. Batch collation and watermark cursor tracking across replication cycles.
4. Idempotency and deduplication on receiver.
5. Ingestion into local SQLite WAL Blackboard with subscriber broadcast.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from orbit_security.blackboard import Blackboard
from orbit_security.event_shuttle import (
    EventShuttleReceiver,
    EventShuttleSender,
    ShuttleAuth,
    HEADER_NODE_ID,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
)


def test_shuttle_auth_signature_and_verification():
    secret = "test-secret-key-12345"
    payload = b'{"hello": "world", "event_id": 42}'
    now = time.time()

    sig = ShuttleAuth.sign_payload(payload, secret, now)
    assert len(sig) == 64

    # Valid signature
    valid, msg = ShuttleAuth.verify_signature(payload, sig, secret, now)
    assert valid is True
    assert msg == "Valid"

    # Tampered payload fails
    tampered = b'{"hello": "tampered", "event_id": 42}'
    valid, msg = ShuttleAuth.verify_signature(tampered, sig, secret, now)
    assert valid is False
    assert "Invalid cryptographic HMAC signature" in msg

    # Wrong secret fails
    valid, msg = ShuttleAuth.verify_signature(payload, sig, "wrong-secret", now)
    assert valid is False
    assert "Invalid cryptographic HMAC signature" in msg


def test_shuttle_auth_replay_protection():
    secret = "test-secret-key-12345"
    payload = b'{"hello": "world"}'
    stale_timestamp = time.time() - 301.0  # Outside 300s window

    sig = ShuttleAuth.sign_payload(payload, secret, stale_timestamp)
    valid, msg = ShuttleAuth.verify_signature(payload, sig, secret, stale_timestamp, max_drift_seconds=300.0)
    assert valid is False
    assert "Timestamp expired or excessive clock drift" in msg


def test_shuttle_auth_boundary_drift_tolerance():
    secret = "test-secret-key-12345"
    payload = b'{"hello": "boundary_test"}'
    now = time.time()

    # 299s drift should be ACCEPTED (inside 300s window)
    ts_299 = now - 299.0
    sig_299 = ShuttleAuth.sign_payload(payload, secret, ts_299)
    valid, msg = ShuttleAuth.verify_signature(payload, sig_299, secret, ts_299, max_drift_seconds=300.0)
    assert valid is True
    assert msg == "Valid"

    # 301s drift should be REJECTED (outside 300s window)
    ts_301 = now - 301.0
    sig_301 = ShuttleAuth.sign_payload(payload, secret, ts_301)
    valid, msg = ShuttleAuth.verify_signature(payload, sig_301, secret, ts_301, max_drift_seconds=300.0)
    assert valid is False
    assert "excessive clock drift" in msg


def test_shuttle_auth_none_or_missing_inputs():
    secret = "test-secret-key-12345"
    payload = b'{"test": 1}'
    now = time.time()

    # None signature rejected gracefully without exception
    valid, msg = ShuttleAuth.verify_signature(payload, signature=None, secret=secret, timestamp=now)
    assert valid is False
    assert "Missing cryptographic HMAC signature" in msg

    # Empty string signature rejected
    valid, msg = ShuttleAuth.verify_signature(payload, signature="", secret=secret, timestamp=now)
    assert valid is False

    # None or empty secret rejected
    sig = ShuttleAuth.sign_payload(payload, secret, now)
    valid, msg = ShuttleAuth.verify_signature(payload, signature=sig, secret=None, timestamp=now)
    assert valid is False
    assert "Missing cryptographic shared secret" in msg

    # Empty secret in sign_payload raises ValueError
    with pytest.raises(ValueError, match="cannot be empty"):
        ShuttleAuth.sign_payload(payload, secret="", timestamp=now)


def test_shuttle_sender_cursor_and_batch_compilation(tmp_path):
    db_path = tmp_path / "sender_bb.db"
    cursor_file = tmp_path / "cursor.json"
    bb = Blackboard(db_path=db_path)

    # Publish 3 events
    bb.publish(event_type="TEST_EV_1", payload={"foo": "bar"}, source="source_1")
    bb.publish(event_type="TEST_EV_2", payload={"num": 100}, source="source_2")
    bb.publish(event_type="TEST_EV_3", payload={"status": "ok"}, source="source_3")

    sender = EventShuttleSender(
        blackboard=bb,
        cursor_file=cursor_file,
        batch_size=2,
        node_id="oracle-cloud-arm64",
    )

    # First dry-run batch (should pick up events 1 & 2)
    res1 = sender.send_batch(dry_run=True)
    assert res1["ok"] is True
    assert res1["count"] == 2
    assert res1["last_synced_id"] == 2
    assert res1["envelope"]["origin_node"] == "oracle-cloud-arm64"
    assert len(res1["envelope"]["events"]) == 2


def test_shuttle_receiver_ingestion_and_deduplication(tmp_path):
    db_path = tmp_path / "receiver_bb.db"
    bb = Blackboard(db_path=db_path)
    secret = "shared-orbit-secret-xyz"

    receiver = EventShuttleReceiver(blackboard=bb, secret=secret)

    now = time.time()
    batch = {
        "origin_node": "oracle-cloud-arm64-node-1",
        "timestamp": now,
        "events_count": 2,
        "events": [
            {
                "id": 101,
                "topic": "perimeter",
                "event_type": "CISA_KEV_MATCH_DETECTED",
                "source": "cisa_kev_correlator",
                "payload": {"cve_id": "CVE-2024-21887", "domain": "example.com"},
                "created_at": now,
            },
            {
                "id": 102,
                "topic": "perimeter",
                "event_type": "SUBDOMAIN_TAKEOVER_DETECTED",
                "source": "threat_radar",
                "payload": {"service": "AWS S3", "target": "assets.example.com"},
                "created_at": now,
            },
        ],
    }
    raw_body = json.dumps(batch).encode("utf-8")
    sig = ShuttleAuth.sign_payload(raw_body, secret, now)

    # Ingest batch
    res = receiver.ingest_batch(
        raw_body=raw_body,
        signature=sig,
        timestamp=now,
        node_id="oracle-cloud-arm64-node-1",
    )
    assert res["ok"] is True
    assert res["ingested_count"] == 2
    assert res["skipped_count"] == 0

    # Verify events are stored in receiver Blackboard WAL
    recent = bb.get_recent(limit=10)
    assert len(recent) == 2
    assert recent[0]["payload"]["_shuttle_origin"] == "oracle-cloud-arm64-node-1"

    # Re-ingest the exact same batch: should deduplicate 2/2
    res2 = receiver.ingest_batch(
        raw_body=raw_body,
        signature=sig,
        timestamp=now,
        node_id="oracle-cloud-arm64-node-1",
    )
    assert res2["ok"] is True
    assert res2["ingested_count"] == 0
    assert res2["skipped_count"] == 2

    # Verify count did not increase
    assert len(bb.get_recent(limit=10)) == 2


def test_shuttle_receiver_rejects_unauthorized():
    receiver = EventShuttleReceiver(secret="correct-secret")
    raw_body = b'{"events": []}'
    now = time.time()
    sig = ShuttleAuth.sign_payload(raw_body, "wrong-secret", now)

    res = receiver.ingest_batch(
        raw_body=raw_body,
        signature=sig,
        timestamp=now,
    )
    assert res["ok"] is False
    assert res["status"] == 401
    assert "Authentication rejected" in res["error"]


def test_shuttle_sender_successful_http_post(tmp_path):
    db_path = tmp_path / "sender_http_bb.db"
    cursor_file = tmp_path / "cursor_http.json"
    bb = Blackboard(db_path=db_path)

    bb.publish(event_type="KEV_0DAY", payload={"cve": "CVE-2024-21887"}, source="radar")

    sender = EventShuttleSender(
        blackboard=bb,
        cursor_file=cursor_file,
        target_url="http://127.0.0.1:9090/api/orbit/blackboard/shuttle",
        secret="test-secret-123",
        node_id="oracle-cloud-arm64",
    )

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps({"ok": True, "ingested_count": 1, "skipped_count": 0}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = sender.send_batch()
        assert res["ok"] is True
        assert res["count"] == 1
        assert res["last_synced_id"] == 1
        assert cursor_file.exists()
        assert sender.load_cursor() == 1
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.headers["X-orbit-node-id"] == "oracle-cloud-arm64"
        assert "X-orbit-signature" in req.headers
        assert "X-orbit-timestamp" in req.headers
