"""Tests for Canary Sentinel Honeypot and Tripwire Engine."""

import unittest
from unittest.mock import MagicMock
from orbit_security.canary_sentinel import (
    CanaryTokenRegistry,
    CanaryToken,
    TOPIC_CANARY,
    EVENT_CANARY_TRIPWIRE_TRIGGERED,
    EVENT_CANARY_TOKEN_MINTED,
)


class TestCanarySentinel(unittest.TestCase):
    def setUp(self):
        self.mock_blackboard = MagicMock()
        self.registry = CanaryTokenRegistry(blackboard=self.mock_blackboard)

    def test_mint_aws_key_token(self):
        token = self.registry.mint_token("aws_key", "internal.acme.com")
        self.assertTrue(token.token_id.startswith("AKIA"))
        self.assertEqual(token.target_perimeter, "internal.acme.com")
        self.assertIn("aws_access_key_id", token.decoy_payload)
        self.assertEqual(self.registry.active_tokens_count(), 1)

        self.mock_blackboard.publish.assert_called_with(
            event_type=EVENT_CANARY_TOKEN_MINTED,
            topic=TOPIC_CANARY,
            payload=token.to_dict(),
            source="canary_sentinel",
        )

    def test_record_tripwire_hit(self):
        token = self.registry.mint_token("dns_cname", "api.corp.net")
        self.assertEqual(token.trigger_count, 0)

        alert = self.registry.record_tripwire_hit(
            token_id=token.token_id,
            source_ip="198.51.100.42",
            user_agent="Masscan/1.3",
            request_details={"subdomain_query": "canary-test"},
        )

        self.assertIsNotNone(alert)
        self.assertEqual(alert["source_ip"], "198.51.100.42")
        self.assertEqual(alert["trigger_count"], 1)
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(token.trigger_count, 1)

        self.mock_blackboard.publish.assert_called_with(
            event_type=EVENT_CANARY_TRIPWIRE_TRIGGERED,
            topic=TOPIC_CANARY,
            payload=alert,
            source="canary_sentinel",
        )

    def test_unknown_token_probe(self):
        alert = self.registry.record_tripwire_hit("nonexistent-token", "1.2.3.4")
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
