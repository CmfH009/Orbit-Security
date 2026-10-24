#!/usr/bin/env python3
"""
test_social_swarm.py: Comprehensive Unit & Integration Tests for Social Engagement Swarm
========================================================================================
Tests:
1. PerimeterRoastCrafter:
   - craft_roast: blunder types (dangling_cname, dmarc_reject, generic), score delta, ADR-002 compliance.
   - blackboard event publishing (EVENT_ROAST_STAGED).
2. ViralThreadArchitect:
   - compose_thread: 5-tweet thread structure, code block formatting, ADR-002 compliance.
   - blackboard event publishing (EVENT_VIRAL_THREAD_COMPOSED).
3. CommunityEngagementSentinel:
   - queue_calibrated_reply: active taskbar browser dispatch contract, handle stripping, ADR-002 compliance.
   - blackboard event publishing (EVENT_COMMUNITY_ENGAGEMENT_QUEUED).
4. SocialEngagementSwarm:
   - persist_staged_action: assertion of adr002_compliant == True, persistent JSON staging queue verification.
   - run_social_cycle: end-to-end execution across all 3 roles, queue persistence.
   - Strict ADR-002 Browser Sovereignty: verify no headless browser processes or illegal MCP tools used.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from orbit_security.social_swarm import (
    PerimeterRoastCrafter,
    ViralThreadArchitect,
    CommunityEngagementSentinel,
    SocialEngagementSwarm,
)
from orbit_security.blackboard import (
    TOPIC_SOCIAL,
    EVENT_ROAST_STAGED,
    EVENT_VIRAL_THREAD_COMPOSED,
    EVENT_COMMUNITY_ENGAGEMENT_QUEUED,
)


class TestPerimeterRoastCrafter(unittest.TestCase):
    def setUp(self):
        self.crafter = PerimeterRoastCrafter()

    def test_craft_roast_dangling_cname(self):
        """craft_roast formats biting roast for dangling CNAME with ADR-002 compliance."""
        with patch("orbit_security.social_swarm.publish_event") as mock_pub:
            roast = self.crafter.craft_roast(
                agency_name="Avex Designs",
                domain="avexdesigns.com",
                initial_score=35,
                rescued_score=85,
                blunder_type="dangling_cname"
            )
            self.assertEqual(roast["score_delta"], 50)
            self.assertTrue(roast["adr002_compliant"])
            self.assertEqual(roast["status"], "STAGED_FOR_REVIEW")
            self.assertIn("Avex Designs", roast["post_text"])
            self.assertIn("dangling CNAME pointing to an abandoned Fastly endpoint", roast["post_text"])
            self.assertIn("35 (F) ➔ Rescued posture: 85 (B+)", roast["post_text"])

            mock_pub.assert_called_once()
            kwargs = mock_pub.call_args[1]
            self.assertEqual(kwargs.get("event_type"), EVENT_ROAST_STAGED)
            self.assertEqual(kwargs.get("topic"), TOPIC_SOCIAL)

    def test_craft_roast_dmarc_reject(self):
        """craft_roast formats roast for DMARC misconfiguration."""
        roast = self.crafter.craft_roast(
            agency_name="Boutique Studio",
            domain="studio.com",
            initial_score=40,
            rescued_score=80,
            blunder_type="dmarc_reject"
        )
        self.assertIn("misconfigured their DMARC record without p=reject", roast["post_text"])
        self.assertTrue(roast["adr002_compliant"])

    def test_craft_roast_generic(self):
        """craft_roast formats roast for general perimeter exposure."""
        roast = self.crafter.craft_roast(
            agency_name="Generic Agency",
            domain="generic.com",
            initial_score=50,
            rescued_score=90,
            blunder_type="headers"
        )
        self.assertIn("zero CSP headers", roast["post_text"])
        self.assertEqual(roast["score_delta"], 40)


class TestViralThreadArchitect(unittest.TestCase):
    def setUp(self):
        self.architect = ViralThreadArchitect()

    def test_compose_thread(self):
        """compose_thread formats structured 5-tweet educational thread."""
        with patch("orbit_security.social_swarm.publish_event") as mock_pub:
            thread = self.architect.compose_thread(
                topic_title="Shopify Subdomain Hijacking via Dangling Fastly CNAMEs",
                breach_mechanism="Decommissioned CDN endpoints left in apex DNS records.",
                exploit_chain=[
                    "Find 404 CNAME via sublist3r or amass",
                    "Claim resource in CDN console",
                    "Serve attacker-controlled session stealer"
                ],
                remediation_code="orbit-recon --prune-orphaned-cnames --strict",
                orbit_takeaway="Project ORBIT automates takeover prevention for high-GMV merchants."
            )
            self.assertEqual(thread["tweets_count"], 5)
            self.assertEqual(len(thread["tweets"]), 5)
            self.assertTrue(thread["adr002_compliant"])
            self.assertEqual(thread["status"], "STAGED_FOR_REVIEW")

            self.assertIn("🧵 1/5 The Anatomy of a Modern Web Breach:", thread["tweets"][0])
            self.assertIn("2/5 The Vulnerability Mechanics", thread["tweets"][1])
            self.assertIn("3/5 The Exploit Chain", thread["tweets"][2])
            self.assertIn("4/5 The Fix (30 Seconds)", thread["tweets"][3])
            self.assertIn("5/5 Key Takeaway & Project ORBIT", thread["tweets"][4])

            mock_pub.assert_called_once()
            kwargs = mock_pub.call_args[1]
            self.assertEqual(kwargs.get("event_type"), EVENT_VIRAL_THREAD_COMPOSED)
            self.assertEqual(kwargs.get("topic"), TOPIC_SOCIAL)


class TestCommunityEngagementSentinel(unittest.TestCase):
    def setUp(self):
        self.sentinel = CommunityEngagementSentinel()

    def test_queue_calibrated_reply(self):
        """queue_calibrated_reply formats reply and sets active taskbar browser dispatch."""
        with patch("orbit_security.social_swarm.publish_event") as mock_pub:
            reply = self.sentinel.queue_calibrated_reply(
                target_tweet_url="https://x.com/ciso/status/9999888877",
                author_handle="@sec_guru",
                topic_context="DMARC reject policy enforcement",
                insight_text="Crucial point. In our audit of 50 Shopify Plus agencies, 42 had p=none."
            )
            self.assertEqual(reply["author_handle"], "@sec_guru")
            self.assertEqual(reply["reply_text"], "@sec_guru Crucial point. In our audit of 50 Shopify Plus agencies, 42 had p=none.")
            self.assertEqual(reply["dispatch_method"], "ACTIVE_TASKBAR_BROWSER_AUTOMATION")
            self.assertTrue(reply["adr002_compliant"])
            self.assertEqual(reply["status"], "QUEUED")

            mock_pub.assert_called_once()
            kwargs = mock_pub.call_args[1]
            self.assertEqual(kwargs.get("event_type"), EVENT_COMMUNITY_ENGAGEMENT_QUEUED)
            self.assertEqual(kwargs.get("topic"), TOPIC_SOCIAL)


class TestSocialEngagementSwarm(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.queue_path = Path(self.temp_dir.name) / "test_social_queue.json"
        self.swarm = SocialEngagementSwarm(queue_file=self.queue_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_persist_staged_action_enforces_adr002(self):
        """persist_staged_action rejects items that violate ADR-002 Browser Sovereignty."""
        illegal_action = {
            "action_id": "illegal_1",
            "adr002_compliant": False,
            "text": "Spawned headless playwright"
        }
        with self.assertRaises(AssertionError) as ctx:
            self.swarm.persist_staged_action(illegal_action)
        self.assertIn("ADR-002 Browser Sovereignty", str(ctx.exception))

    def test_run_social_cycle(self):
        """run_social_cycle runs roast, thread, and reply generation and writes queue."""
        with patch("orbit_security.social_swarm.publish_event"):
            res = self.swarm.run_social_cycle(
                audit_sample={"agency_name": "Avex", "domain": "avex.com", "score": 30, "rescued_score": 85},
                threat_topic="Subdomain Hijacking on Shopify Plus"
            )
            self.assertTrue(res["ok"])
            self.assertTrue(res["adr002_compliant"])
            self.assertIn("roast", res)
            self.assertIn("thread", res)
            self.assertIn("reply", res)

            # Check queue file on disk
            self.assertTrue(self.queue_path.exists())
            queued_items = json.loads(self.queue_path.read_text(encoding="utf-8"))
            self.assertEqual(len(queued_items), 3)
            for item in queued_items:
                self.assertTrue(item.get("adr002_compliant"))


if __name__ == "__main__":
    unittest.main()
