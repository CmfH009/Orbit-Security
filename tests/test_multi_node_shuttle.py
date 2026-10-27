"""Tests for Multi-Node Distributed Cluster Synchronization in Event Shuttle."""

import json
import time
import unittest
from unittest.mock import MagicMock
from orbit_security.event_shuttle import (
    EventShuttleSender,
    EventShuttleReceiver,
    ShuttleAuth,
)


class TestMultiNodeShuttle(unittest.TestCase):
    def setUp(self):
        self.mock_sender_bb = MagicMock(spec=["get_events_after", "publish"])
        self.mock_receiver_bb = MagicMock(spec=["publish"])
        self.secret = "test-multi-node-cluster-secret"

    def test_multi_node_metadata_tagging_in_sender(self):
        self.mock_sender_bb.get_events_after.return_value = [
            {"id": 101, "event_type": "THREAT_FOUND", "payload": {"cve": "CVE-2026-9999"}, "topic": "threat_intel"}
        ]

        sender = EventShuttleSender(
            blackboard=self.mock_sender_bb,
            secret=self.secret,
            node_id="oracle-ashburn-worker-1",
            node_region="us-ashburn-1",
            node_provider="oracle",
        )

        res = sender.send_batch(dry_run=True)
        self.assertTrue(res["ok"])
        envelope = res["envelope"]

        self.assertEqual(envelope["origin_node"], "oracle-ashburn-worker-1")
        self.assertEqual(envelope["origin_region"], "us-ashburn-1")
        self.assertEqual(envelope["origin_provider"], "oracle")
        self.assertEqual(envelope["events_count"], 1)

    def test_multi_node_ingestion_and_provenance_enrichment(self):
        receiver = EventShuttleReceiver(
            blackboard=self.mock_receiver_bb,
            secret=self.secret,
        )

        now_ts = time.time()
        batch_payload = {
            "origin_node": "gcp-frankfurt-worker-2",
            "origin_region": "europe-west3",
            "origin_provider": "gcp",
            "timestamp": now_ts,
            "events_count": 1,
            "events": [
                {
                    "id": 555,
                    "event_type": "DNS_TAKEOVER_ALERT",
                    "payload": {"subdomain": "de.client.com"},
                    "topic": "security",
                }
            ],
        }

        body_bytes = json.dumps(batch_payload).encode("utf-8")
        sig = ShuttleAuth.sign_payload(body_bytes, self.secret, now_ts)

        res = receiver.ingest_batch(
            raw_body=body_bytes,
            signature=sig,
            timestamp=now_ts,
            node_id="gcp-frankfurt-worker-2",
        )

        self.assertTrue(res["ok"])
        self.assertEqual(res["ingested_count"], 1)

        # Verify blackboard publishing enriched payload
        self.mock_receiver_bb.publish.assert_called_once()
        call_kwargs = self.mock_receiver_bb.publish.call_args[1]
        self.assertEqual(call_kwargs["source"], "shuttle:gcp-frankfurt-worker-2")
        self.assertEqual(call_kwargs["payload"]["_shuttle_origin"], "gcp-frankfurt-worker-2")
        self.assertEqual(call_kwargs["payload"]["_shuttle_region"], "europe-west3")
        self.assertEqual(call_kwargs["payload"]["_shuttle_provider"], "gcp")
        self.assertEqual(call_kwargs["payload"]["_shuttle_remote_id"], 555)


if __name__ == "__main__":
    unittest.main()
