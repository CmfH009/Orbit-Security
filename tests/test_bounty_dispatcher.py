"""Tests for Bug Bounty Submission Dispatcher Engine."""

import unittest
from unittest.mock import MagicMock
from orbit_security.bounty_dispatcher import (
    BountySubmissionDispatcher,
    VulnerabilityReport,
    TOPIC_DISPATCH,
    EVENT_DISPATCH_STAGED,
    EVENT_DISPATCH_SUBMITTED,
)


class TestBountyDispatcher(unittest.TestCase):
    def setUp(self):
        self.mock_blackboard = MagicMock()
        self.dispatcher = BountySubmissionDispatcher(blackboard=self.mock_blackboard)

    def test_stage_report(self):
        report = self.dispatcher.stage_report(
            program_id="shopify",
            title="Dangling Fastly CNAME Subdomain Takeover",
            severity="High",
            vulnerability_type="Subdomain Takeover",
            target_asset="promo.brand.com",
            summary="A dangling CNAME record points to an unclaimed Fastly service.",
            impact="An attacker could claim the subdomain and intercept customer authentication tokens.",
            steps=[
                "Run dig promo.brand.com to observe Fastly CNAME.",
                "Send curl request observing 503 Fastly domain not found error.",
            ],
            remediation="Remove the DNS CNAME record from Route53.",
            evidence="dig CNAME promo.brand.com -> error: domain not registered",
            cvss_score=7.5,
        )

        self.assertTrue(report.report_id.startswith("bounty-rep-"))
        self.assertEqual(report.program_id, "shopify")
        self.assertEqual(report.cvss_score, 7.5)

        # Markdown formatting check
        md = report.to_markdown()
        self.assertIn("# Dangling Fastly CNAME Subdomain Takeover", md)
        self.assertIn("1. Run dig promo.brand.com", md)
        self.assertIn("Project ORBIT", md)

        # Blackboard event check
        self.mock_blackboard.publish.assert_called_once()
        call_args = self.mock_blackboard.publish.call_args[1]
        self.assertEqual(call_args["event_type"], EVENT_DISPATCH_STAGED)
        self.assertEqual(call_args["topic"], TOPIC_DISPATCH)

    def test_dispatch_report_dry_run(self):
        report = self.dispatcher.stage_report(
            program_id="gitlab",
            title="Exposed GraphQL Introspection Endpoint",
            severity="Medium",
            vulnerability_type="Information Disclosure",
            target_asset="staging.gitlab.com/graphql",
            summary="Production GraphQL schema introspection is enabled.",
            impact="Attackers can map private API queries and mutations.",
            steps=["Send POST with __schema query."],
            remediation="Disable introspection in production environment.",
            evidence="{ \"data\": { \"__schema\": { \"types\": [...] } } }",
            cvss_score=5.3,
        )

        dispatch_res = self.dispatcher.dispatch_report(
            report_id=report.report_id,
            platform="hackerone",
            dry_run=True,
        )

        self.assertEqual(dispatch_res["status"], "SIMULATED_SUCCESS")
        self.assertIn("mock", dispatch_res["submission_id"])
        self.assertEqual(dispatch_res["platform"], "hackerone")


if __name__ == "__main__":
    unittest.main()
