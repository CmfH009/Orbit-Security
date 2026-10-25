"""orbit_security.event_shuttle: Private Encrypted Blackboard Event Shuttle.
=================================================================================
Provides zero-trust, authenticated event replication from remote cloud nodes
(e.g., Oracle Always Free ARM64) to the local Orbit Web Cockpit over Tailscale.

Features:
- Pure stdlib HMAC-SHA256 zero-trust transport authentication and integrity verification.
- Replay protection with strict timestamp window tolerance (+- 300s clock skew window).
- Cursor-based WAL watermark replication with persistent sync state.
- Idempotent deduplication on the receiver to prevent double-counting or repeated alerts.
- Immediate fan-out to local Blackboard pub/sub mesh and Cockpit HUD SSE stream (:9090).
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("orbit_security.event_shuttle")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CURSOR_FILE = REPO_ROOT / "data" / "shuttle_cursor.json"
DEFAULT_SHUTTLE_SECRET = "orbit-zero-trust-mesh-secret-v1"

HEADER_SIGNATURE = "X-Orbit-Signature"
HEADER_TIMESTAMP = "X-Orbit-Timestamp"
HEADER_NODE_ID = "X-Orbit-Node-Id"


class ShuttleAuth:
    """Zero-trust HMAC-SHA256 cryptographic signature generator and verifier."""

    @staticmethod
    def get_secret() -> str:
        return os.environ.get("ORBIT_SHUTTLE_SECRET", DEFAULT_SHUTTLE_SECRET).strip()

    @staticmethod
    def sign_payload(payload_bytes: bytes, secret: str, timestamp: float) -> str:
        """Generates deterministic HMAC-SHA256 signature over timestamp:payload."""
        if not secret:
            raise ValueError("Shuttle secret key cannot be empty")
        msg = f"{int(timestamp)}:".encode("utf-8") + (payload_bytes or b"")
        return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(
        payload_bytes: bytes,
        signature: Optional[str],
        secret: Optional[str],
        timestamp: float,
        max_drift_seconds: float = 300.0,
    ) -> Tuple[bool, str]:
        """Validates timestamp freshness and cryptographic HMAC-SHA256 signature."""
        if not secret:
            return False, "Missing cryptographic shared secret"
        if not signature or not isinstance(signature, str):
            return False, "Missing cryptographic HMAC signature"

        now = time.time()
        try:
            ts_float = float(timestamp)
        except (TypeError, ValueError):
            return False, "Invalid timestamp format"

        drift = abs(now - ts_float)
        if drift > max_drift_seconds:
            return False, f"Timestamp expired or excessive clock drift (drift: {drift:.1f}s)"

        try:
            expected = ShuttleAuth.sign_payload(payload_bytes or b"", secret, ts_float)
        except Exception as ex:
            return False, f"Signature calculation failure: {ex}"

        if not hmac.compare_digest(
            str(signature or "").strip().lower().encode("utf-8"),
            expected.strip().lower().encode("utf-8"),
        ):
            return False, "Invalid cryptographic HMAC signature"

        return True, "Valid"


class EventShuttleSender:
    """Client shuttle shipping local WAL blackboard events to a remote Cockpit instance."""

    def __init__(
        self,
        blackboard: Any = None,
        target_url: Optional[str] = None,
        secret: Optional[str] = None,
        node_id: Optional[str] = None,
        cursor_file: Optional[Path] = None,
        batch_size: int = 50,
    ):
        if blackboard is None:
            from orbit_security.blackboard import get_blackboard
            self.bb = get_blackboard()
        else:
            self.bb = blackboard

        if target_url is None:
            env_url = os.environ.get("ORBIT_SHUTTLE_TARGET_URL", "").strip()
            env_ip = os.environ.get("ORBIT_COCKPIT_TAILSCALE_IP", "").strip()
            if env_url:
                target_url = env_url
            elif env_ip:
                target_url = f"http://{env_ip}:9090/api/orbit/blackboard/shuttle"
            else:
                target_url = "http://127.0.0.1:9090/api/orbit/blackboard/shuttle"

        self.target_url = target_url.rstrip("/")
        self.secret = secret or ShuttleAuth.get_secret()
        self.node_id = node_id or os.environ.get("ORBIT_NODE_ID", "oracle-cloud-arm64-1")
        self.cursor_file = Path(cursor_file or DEFAULT_CURSOR_FILE)
        self.batch_size = max(1, min(batch_size, 500))

    def load_cursor(self) -> int:
        """Loads last replicated event ID watermark from persistent storage."""
        if not self.cursor_file.exists():
            return 0
        try:
            data = json.loads(self.cursor_file.read_text(encoding="utf-8"))
            return int(data.get("last_synced_id", 0))
        except Exception as ex:
            logger.debug(f"Failed to load cursor from {self.cursor_file}: {ex}")
            return 0

    def save_cursor(self, last_id: int):
        """Persists replicated event ID watermark to disk atomically."""
        try:
            self.cursor_file.parent.mkdir(parents=True, exist_ok=True)
            tmp_file = self.cursor_file.with_suffix(".tmp")
            content = json.dumps({
                "last_synced_id": int(last_id),
                "node_id": self.node_id,
                "updated_at": time.time(),
            }, indent=2)
            tmp_file.write_text(content, encoding="utf-8")
            os.replace(tmp_file, self.cursor_file)
        except Exception as ex:
            logger.warning(f"Failed to persist shuttle cursor: {ex}")

    def send_batch(self, dry_run: bool = False) -> Dict[str, Any]:
        """Pulls next batch of events from local blackboard and replicates to target Cockpit."""
        last_id = self.load_cursor()
        events = self.bb.get_events_after(after_id=last_id, limit=self.batch_size)

        if not events:
            return {"ok": True, "count": 0, "last_synced_id": last_id, "status": "idle"}

        new_last_id = max(e["id"] for e in events)
        now_ts = time.time()

        batch_envelope = {
            "origin_node": self.node_id,
            "timestamp": now_ts,
            "events_count": len(events),
            "events": events,
        }
        body_bytes = json.dumps(batch_envelope, default=str).encode("utf-8")
        signature = ShuttleAuth.sign_payload(body_bytes, self.secret, now_ts)

        if dry_run:
            return {
                "ok": True,
                "count": len(events),
                "last_synced_id": new_last_id,
                "status": "dry_run",
                "envelope": batch_envelope,
            }

        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"Orbit-EventShuttle/{self.node_id}",
            HEADER_SIGNATURE: signature,
            HEADER_TIMESTAMP: str(now_ts),
            HEADER_NODE_ID: self.node_id,
        }

        try:
            req = urllib.request.Request(
                self.target_url,
                data=body_bytes,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                if resp.status == 200 and resp_data.get("ok"):
                    self.save_cursor(new_last_id)
                    logger.info(f"Replicated {len(events)} events to {self.target_url} (watermark: {new_last_id})")
                    return {
                        "ok": True,
                        "count": len(events),
                        "last_synced_id": new_last_id,
                        "receiver_response": resp_data,
                    }
                else:
                    return {
                        "ok": False,
                        "error": resp_data.get("error", f"HTTP {resp.status}"),
                        "last_synced_id": last_id,
                    }
        except urllib.error.HTTPError as ex:
            err_body = ex.read().decode("utf-8", errors="ignore")
            logger.warning(f"Shuttle push HTTP error {ex.code}: {err_body}")
            return {"ok": False, "error": f"HTTP {ex.code}: {err_body}", "last_synced_id": last_id}
        except Exception as ex:
            logger.warning(f"Shuttle transport failure: {ex}")
            return {"ok": False, "error": str(ex), "last_synced_id": last_id}

    def run_daemon(self, interval_sec: float = 3.0, stop_event: Optional[threading.Event] = None):
        """Continuous event replication loop."""
        logger.info(f"Orbit Event Shuttle daemon starting -> {self.target_url} ({self.node_id})")
        while not (stop_event and stop_event.is_set()):
            try:
                res = self.send_batch()
                if res.get("count", 0) == 0:
                    time.sleep(interval_sec)
                else:
                    # If backlog exists, continue immediately without sleeping
                    time.sleep(0.1)
            except Exception as ex:
                logger.error(f"Unexpected error in shuttle loop: {ex}")
                time.sleep(interval_sec)


class EventShuttleReceiver:
    """Receiver ingesting shuttled events into local blackboard with deduplication."""

    def __init__(
        self,
        blackboard: Any = None,
        secret: Optional[str] = None,
        attack_graph: Any = None,
    ):
        if blackboard is None:
            from orbit_security.blackboard import get_blackboard
            self.bb = get_blackboard()
        else:
            self.bb = blackboard

        self.secret = secret or ShuttleAuth.get_secret()
        self.attack_graph = attack_graph
        self._seen_hashes: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def _event_fingerprint(self, origin_node: str, ev: Dict[str, Any]) -> str:
        """Deterministic fingerprint for event deduplication."""
        remote_id = ev.get("id")
        ev_type = ev.get("event_type", "")
        created_at = ev.get("created_at", 0.0)
        source = ev.get("source", "")
        raw = f"{origin_node}:{remote_id}:{ev_type}:{source}:{created_at}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def ingest_batch(
        self,
        raw_body: bytes,
        signature: str,
        timestamp: float,
        node_id: str = "remote-node",
    ) -> Dict[str, Any]:
        """Validates payload authenticity and ingests events into the local blackboard."""
        valid, msg = ShuttleAuth.verify_signature(
            payload_bytes=raw_body,
            signature=signature,
            secret=self.secret,
            timestamp=timestamp,
        )
        if not valid:
            return {"ok": False, "error": f"Authentication rejected: {msg}", "status": 401}

        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception as ex:
            return {"ok": False, "error": f"Malformed JSON: {ex}", "status": 400}

        if not isinstance(data, dict):
            return {"ok": False, "error": "Malformed JSON: root must be an object", "status": 400}

        origin_node = str(data.get("origin_node") or node_id)[:128]
        events = data.get("events", [])
        if not isinstance(events, list):
            return {"ok": False, "error": "Malformed JSON: 'events' must be a list", "status": 400}
        ingested_count = 0
        skipped_count = 0

        with self._lock:
            to_publish = []
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                fp = self._event_fingerprint(origin_node, ev)
                if fp in self._seen_hashes:
                    skipped_count += 1
                    continue

                self._seen_hashes[fp] = time.time()
                if len(self._seen_hashes) > 10000:
                    self._seen_hashes.popitem(last=False)

                ev_type = ev.get("event_type", "SHUTTLE_EVENT")
                payload = ev.get("payload", {})
                if isinstance(payload, dict):
                    # Tag payload with provenance metadata
                    payload_enriched = dict(payload)
                    payload_enriched["_shuttle_origin"] = origin_node
                    payload_enriched["_shuttle_remote_id"] = ev.get("id")
                else:
                    payload_enriched = {
                        "data": payload,
                        "_shuttle_origin": origin_node,
                        "_shuttle_remote_id": ev.get("id"),
                    }

                source = f"shuttle:{origin_node}"
                topic = ev.get("topic", "telemetry")

                to_publish.append({
                    "event_type": ev_type,
                    "payload": payload_enriched,
                    "source": source,
                    "topic": topic,
                    "created_at": ev.get("created_at") or time.time(),
                })

            constellation_synced = False
            constellation_nodes = 0
            if to_publish:
                if hasattr(self.bb, "publish_batch"):
                    self.bb.publish_batch(to_publish)
                else:
                    for item in to_publish:
                        self.bb.publish(
                            event_type=item["event_type"],
                            payload=item["payload"],
                            source=item["source"],
                            topic=item["topic"],
                        )
                ingested_count = len(to_publish)

                if self.attack_graph is not None:
                    try:
                        sync_summary = self.attack_graph.ingest_shuttle_events(
                            to_publish,
                            save_disk=True,
                        )
                        if sync_summary.get("events_processed", 0) > 0:
                            constellation_synced = True
                            constellation_nodes = sync_summary.get("total_nodes", 0)
                            self.bb.publish(
                                event_type="CONSTELLATION_SYNC_UPDATED",
                                payload={
                                    "origin_node": origin_node,
                                    "events_processed": sync_summary["events_processed"],
                                    "total_nodes": constellation_nodes,
                                    "total_edges": sync_summary.get("total_edges", 0),
                                },
                                source="shuttle_constellation_sync",
                                topic="telemetry",
                            )
                    except Exception as ex:
                        logger.debug(f"Constellation sync skipped: {ex}")

        logger.info(f"Ingested {ingested_count} events from node {origin_node} ({skipped_count} skipped)")
        return {
            "ok": True,
            "origin_node": origin_node,
            "ingested_count": ingested_count,
            "skipped_count": skipped_count,
            "constellation_synced": constellation_synced,
            "constellation_nodes": constellation_nodes,
        }


def main():
    parser = argparse.ArgumentParser(description="Orbit Private Blackboard Event Shuttle")
    parser.add_argument("--daemon", action="store_true", help="Run background shuttle sender daemon")
    parser.add_argument("--send-once", action="store_true", help="Send one batch of pending events")
    parser.add_argument("--target", default=None, help="Target Cockpit URL (defaults to ORBIT_SHUTTLE_TARGET_URL or :9090)")
    parser.add_argument("--node-id", default=None, help="Origin node identifier")
    parser.add_argument("--interval", type=float, default=3.0, help="Polling interval in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Simulate batch compilation without network POST")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    sender = EventShuttleSender(target_url=args.target, node_id=args.node_id)

    if args.send_once or args.dry_run:
        res = sender.send_batch(dry_run=args.dry_run)
        print(json.dumps(res, indent=2))
    elif args.daemon:
        sender.run_daemon(interval_sec=args.interval)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
