#!/usr/bin/env python3
"""
test_growth_swarm.py: Comprehensive Unit & Integration Tests for Growth Swarm
=============================================================================
Tests:
1. GrowthStrategist:
   - analyze_market_signals: empty target handling, sorting by priority_score, tier recommendations.
   - stage_campaign: brief payload formation, tier price lookup, blackboard event publishing.
2. TechnicalCopywriter:
   - draft_audit_outreach: score delta calculation, zero-fluff text formatting, fallback items.
   - draft_case_study: markdown formatting, stats inclusion.
3. FunnelOptimizer:
   - evaluate_pricing_strategy: empty history handling, tier breakdown, MRR calculation, best tier selection.
   - record_conversion: custom amount vs default tier amount, blackboard event publishing, payload integrity.
4. MarketingGrowthSwarm:
   - run_cycle: end-to-end execution across all 3 roles, validation of returned structure.
5. Blackboard Event Integration:
   - MARKETING_CAMPAIGN_STAGED and PORTAL_CONVERSION topics and event validation.
"""

from __future__ import annotations

import json
import time
import unittest
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock

from orbit_security.growth_swarm import (
    GrowthStrategist,
    TechnicalCopywriter,
    FunnelOptimizer,
    MarketingGrowthSwarm,
    GROWTH_PRICING_TIERS,
)
from orbit_security.blackboard import (
    get_blackboard,
    TOPIC_GROWTH,
    EVENT_MARKETING_CAMPAIGN_STAGED,
    EVENT_PORTAL_CONVERSION,
)


class TestGrowthStrategist(unittest.TestCase):
    def setUp(self):
        self.strategist = GrowthStrategist(campaign_name="Test Outbound")

    def test_analyze_market_signals_empty(self):
        """Empty agencies list returns default zero state."""
        res = self.strategist.analyze_market_signals([])
        self.assertEqual(res["total_targets"], 0)
        self.assertEqual(res["prioritized"], [])
        self.assertEqual(res["recommended_tier"], "starter")
        self.assertIsNone(res.get("top_candidate"))

    def test_analyze_market_signals_prioritization(self):
        """Agencies are prioritized by vulnerability count and lower security score."""
        agencies = [
            {"agency_id": "a1", "agency_name": "Agency High Risk", "domain": "risk.com", "score": 10, "vulnerabilities": ["v1", "v2", "v3", "v4", "v5"]},
            {"agency_id": "a2", "agency_name": "Agency Med Risk", "domain": "med.com", "score": 60, "vulnerabilities": ["v1"]},
            {"agency_id": "a3", "agency_name": "Agency Low Risk", "domain": "low.com", "score": 95, "vulnerabilities": []},
        ]
        res = self.strategist.analyze_market_signals(agencies)
        self.assertEqual(res["total_targets"], 3)
        self.assertIsNotNone(res["top_candidate"])
        self.assertEqual(res["top_candidate"]["agency_id"], "a1")
        self.assertGreater(res["prioritized"][0]["priority_score"], res["prioritized"][1]["priority_score"])
        self.assertGreater(res["prioritized"][1]["priority_score"], res["prioritized"][2]["priority_score"])

        # Check recommended tiers based on priority score thresholds (>70: sovereign, >40: pro, <=40: starter)
        self.assertEqual(res["prioritized"][0]["recommended_tier"], "sovereign")
        self.assertEqual(res["prioritized"][2]["recommended_tier"], "starter")

    def test_stage_campaign_event_publishing(self):
        """stage_campaign broadcasts MARKETING_CAMPAIGN_STAGED to topic growth."""
        target_agencies = [
            {"agency_id": "a1", "agency_name": "Avex Designs", "domain": "avex.com", "score": 35, "vulnerabilities": ["cname"]},
        ]
        with patch("orbit_security.growth_swarm.publish_event") as mock_pub:
            brief = self.strategist.stage_campaign("Q4 High-Yield Push", target_agencies, tier="pro")
            self.assertEqual(brief["campaign_name"], "Q4 High-Yield Push")
            self.assertEqual(brief["tier"], "pro")
            self.assertEqual(brief["tier_price"], 5000)
            self.assertEqual(brief["targets_count"], 1)
            self.assertEqual(brief["status"], "STAGED")

            mock_pub.assert_called_once()
            args, kwargs = mock_pub.call_args
            self.assertEqual(kwargs.get("event_type"), EVENT_MARKETING_CAMPAIGN_STAGED)
            self.assertEqual(kwargs.get("topic"), TOPIC_GROWTH)
            self.assertEqual(kwargs.get("source"), "growth_strategist")


class TestTechnicalCopywriter(unittest.TestCase):
    def setUp(self):
        self.copywriter = TechnicalCopywriter()

    def test_draft_audit_outreach_custom_items(self):
        """draft_audit_outreach formats rigorous audit copy and computes score delta."""
        res = self.copywriter.draft_audit_outreach(
            agency_name="Avex Designs",
            recipient_name="Alex",
            domain="avexdesigns.com",
            initial_score=35,
            rescued_score=85,
            remediated_items=["Dangling CNAME endpoint purged", "BIMI and DMARC enforced"]
        )
        self.assertIn("35 ➔ 85 / +50 pts", res["subject"])
        self.assertIn("Alex", res["body"])
        self.assertIn("Dangling CNAME endpoint purged", res["body"])
        self.assertIn("BIMI and DMARC enforced", res["body"])
        self.assertEqual(res["score_delta"], 50)
        self.assertGreater(res["word_count"], 20)
        self.assertEqual(res["domain"], "avexdesigns.com")

    def test_draft_audit_outreach_fallbacks(self):
        """draft_audit_outreach falls back gracefully when remediated_items is empty."""
        res = self.copywriter.draft_audit_outreach(
            agency_name="Shopify Boutique",
            recipient_name="CTO",
            domain="boutique.io",
            initial_score=90,
            rescued_score=80,  # delta <= 0
            remediated_items=[]
        )
        self.assertEqual(res["score_delta"], 0)
        self.assertIn("Dangling CNAME takeover blocked", res["body"])

    def test_draft_case_study(self):
        """draft_case_study formats valid markdown case study."""
        case_md = self.copywriter.draft_case_study(
            client_name="High-GMV Apparel",
            industry="Fashion E-Commerce",
            findings_count=7,
            rescued_score=92
        )
        self.assertIn("# Case Study: High-GMV Apparel (Fashion E-Commerce)", case_md)
        self.assertIn("7 critical exposure vectors resolved", case_md)
        self.assertIn("92/100", case_md)


class TestFunnelOptimizer(unittest.TestCase):
    def setUp(self):
        self.optimizer = FunnelOptimizer()

    def test_evaluate_pricing_strategy_empty(self):
        """Empty historical conversions return default tier recommendation."""
        res = self.optimizer.evaluate_pricing_strategy([])
        self.assertEqual(res["total_conversions"], 0)
        self.assertEqual(res["mrr_total_usd"], 0)
        self.assertEqual(res["highest_performing_tier"], "pro")

    def test_evaluate_pricing_strategy_with_data(self):
        """Computes tier breakdown, total MRR, and selects highest-performing tier."""
        conversions = [
            {"tier": "starter"},
            {"tier": "pro"},
            {"tier": "pro"},
            {"tier": "sovereign"},
        ]
        res = self.optimizer.evaluate_pricing_strategy(conversions)
        self.assertEqual(res["total_conversions"], 4)
        self.assertEqual(res["tier_breakdown"]["starter"], 1)
        self.assertEqual(res["tier_breakdown"]["pro"], 2)
        self.assertEqual(res["tier_breakdown"]["sovereign"], 1)
        expected_mrr = 2500*1 + 5000*2 + 10000*1
        self.assertEqual(res["mrr_total_usd"], expected_mrr)
        self.assertEqual(res["highest_performing_tier"], "pro")

    def test_record_conversion_event_publishing(self):
        """record_conversion creates payload and broadcasts PORTAL_CONVERSION event."""
        with patch("orbit_security.growth_swarm.publish_event") as mock_pub:
            conv = self.optimizer.record_conversion(
                agency_id="agency_99",
                agency_name="Luxe Digital",
                tier="sovereign",
                stripe_session_id="cs_test_12345"
            )
            self.assertEqual(conv["tier"], "sovereign")
            self.assertEqual(conv["amount_usd"], 10000)
            self.assertEqual(conv["stripe_session_id"], "cs_test_12345")
            self.assertTrue(conv["conversion_id"].startswith("conv_"))

            mock_pub.assert_called_once()
            args, kwargs = mock_pub.call_args
            self.assertEqual(kwargs.get("event_type"), EVENT_PORTAL_CONVERSION)
            self.assertEqual(kwargs.get("topic"), TOPIC_GROWTH)
            self.assertEqual(kwargs.get("source"), "funnel_optimizer")


class TestMarketingGrowthSwarm(unittest.TestCase):
    def test_run_cycle(self):
        """MarketingGrowthSwarm runs full cycle across strategist, copywriter, and optimizer."""
        swarm = MarketingGrowthSwarm()
        target_agencies = [
            {"agency_id": "a1", "agency_name": "Avex", "contact_name": "Alex", "domain": "avex.com", "score": 30, "rescued_score": 85},
            {"agency_id": "a2", "agency_name": "Anatta", "contact_name": "Nirav", "domain": "anatta.io", "score": 45, "rescued_score": 80},
        ]
        result = swarm.run_cycle(target_agencies)
        self.assertTrue(result["ok"])
        self.assertIn("campaign", result)
        self.assertIn("copy_samples", result)
        self.assertEqual(len(result["copy_samples"]), 2)
        self.assertIn("starter", result["active_tiers"])
        self.assertIn("pro", result["active_tiers"])
        self.assertIn("sovereign", result["active_tiers"])


if __name__ == "__main__":
    unittest.main()
