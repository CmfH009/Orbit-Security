#!/usr/bin/env python3
"""
test_x_infosec_radar.py: Comprehensive Unit & Integration Tests for Threat Radar Swarm
======================================================================================
Tests:
1. InfosecNewsSniffer:
   - parse_advisory_item: CVSS thresholds (7.0), zero-day bypass, CVE prefix filtering, severity categorisation.
   - ingest_feed: batch filtering, blackboard event broadcasting (EVENT_THREAT_INTEL_DISCOVERED).
2. CVEImpactSynthesizer:
   - synthesize_brief: 2-minute executive briefing composition, exploitability tagging, read time estimate.
3. ThreatAdvisoryDrafter:
   - generate_pgp_signature_block: PGP armor formatting, Key-ID embedding, hash digest generation.
   - draft_responsible_disclosure: RFC 9116 format, disclosure window, PGP signature verification.
4. ThreatRadarSwarm:
   - process_incoming_threat: full end-to-end ingestion -> synthesis -> disclosure draft.
   - threshold rejection handling.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock

from orbit_security.threat_radar import (
    InfosecNewsSniffer,
    CVEImpactSynthesizer,
    ThreatAdvisoryDrafter,
    ThreatRadarSwarm,
    DUMMY_PGP_KEY_ID,
)
from orbit_security.blackboard import (
    TOPIC_THREAT_INTEL,
    EVENT_THREAT_INTEL_DISCOVERED,
)


class TestInfosecNewsSniffer(unittest.TestCase):
    def setUp(self):
        self.sniffer = InfosecNewsSniffer(min_cvss_threshold=7.0)

    def test_parse_advisory_item_valid_critical(self):
        """High-CVSS items (>=9.0) are categorized as CRITICAL."""
        raw = {
            "cve_id": "cve-2026-1192",
            "title": "Shopify GraphQL Auth Bypass",
            "cvss": 9.8,
            "affected_software": "Storefront API",
            "exploit_available": True
        }
        res = self.sniffer.parse_advisory_item(raw)
        self.assertIsNotNone(res)
        self.assertEqual(res["cve_id"], "CVE-2026-1192")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertEqual(res["cvss"], 9.8)
        self.assertTrue(res["exploit_available"])

    def test_parse_advisory_item_high(self):
        """CVSS between 7.0 and 8.9 is categorized as HIGH."""
        raw = {
            "cve_id": "CVE-2026-3041",
            "title": "Dangling CNAME Takeover in DNS Manager",
            "cvss": 7.5,
            "affected_software": "Cloudflare DNS API",
        }
        res = self.sniffer.parse_advisory_item(raw)
        self.assertIsNotNone(res)
        self.assertEqual(res["severity"], "HIGH")

    def test_parse_advisory_item_below_threshold_filtered(self):
        """Items below CVSS threshold (7.0) without zero-day flag are discarded."""
        raw = {
            "cve_id": "CVE-2026-0001",
            "title": "Minor Information Leak",
            "cvss": 4.2,
            "is_zero_day": False
        }
        self.assertIsNone(self.sniffer.parse_advisory_item(raw))

    def test_parse_advisory_item_zero_day_exception(self):
        """Zero-day items are captured regardless of initial CVSS score."""
        raw = {
            "cve_id": "CVE-2026-9999",
            "title": "Unauthenticated Fastly Zero-Day Desync",
            "cvss": 5.0,
            "is_zero_day": True
        }
        res = self.sniffer.parse_advisory_item(raw)
        self.assertIsNotNone(res)
        self.assertEqual(res["severity"], "MEDIUM")

    def test_ingest_feed_broadcasting(self):
        """ingest_feed processes list of raw feeds and broadcasts THREAT_INTEL_DISCOVERED."""
        feed = [
            {"cve_id": "CVE-2026-1001", "title": "Critical RCE", "cvss": 9.6},
            {"cve_id": "CVE-2026-1002", "title": "Low Impact Info Leak", "cvss": 3.1},
            {"cve_id": "CVE-2026-1003", "title": "High Impact Privilege Escalation", "cvss": 8.1},
        ]
        with patch("orbit_security.threat_radar.publish_event") as mock_pub:
            discovered = self.sniffer.ingest_feed(feed)
            self.assertEqual(len(discovered), 2)
            self.assertEqual(mock_pub.call_count, 2)

            first_call_kwargs = mock_pub.call_args_list[0][1]
            self.assertEqual(first_call_kwargs.get("event_type"), EVENT_THREAT_INTEL_DISCOVERED)
            self.assertEqual(first_call_kwargs.get("topic"), TOPIC_THREAT_INTEL)
            self.assertEqual(first_call_kwargs.get("source"), "infosec_news_sniffer")


class TestCVEImpactSynthesizer(unittest.TestCase):
    def setUp(self):
        self.synthesizer = CVEImpactSynthesizer()

    def test_synthesize_brief(self):
        """synthesize_brief formats executive briefing text with mitigation actions."""
        cve_record = {
            "cve_id": "CVE-2026-4401",
            "title": "Shopify Reverse Proxy Header Desynchronization",
            "cvss": 9.2,
            "severity": "CRITICAL",
            "affected_software": "Storefront Edge Router",
            "exploit_available": True
        }
        res = self.synthesizer.synthesize_brief(cve_record)
        self.assertEqual(res["cve_id"], "CVE-2026-4401")
        self.assertEqual(res["cvss"], 9.2)
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertIn("Public PoC Available", res["brief_text"])
        self.assertIn("Root Cause:", res["brief_text"])
        self.assertIn("Immediate Action:", res["brief_text"])
        self.assertEqual(res["estimated_read_seconds"], 90)


class TestThreatAdvisoryDrafter(unittest.TestCase):
    def setUp(self):
        self.drafter = ThreatAdvisoryDrafter(pgp_key_id="0xORBIT9F2A71BC")

    def test_generate_pgp_signature_block(self):
        """generate_pgp_signature_block creates structured ASCII-armored PGP block."""
        block = self.drafter.generate_pgp_signature_block("Sample advisory payload text")
        self.assertIn("-----BEGIN PGP SIGNATURE-----", block)
        self.assertIn("-----END PGP SIGNATURE-----", block)
        self.assertIn("Key-ID: 0xORBIT9F2A71BC", block)
        self.assertIn("Version: Project ORBIT Sovereign Security Sentinel v1.4", block)

    def test_draft_responsible_disclosure(self):
        """draft_responsible_disclosure formats RFC 9116 compliant advisory with signature."""
        res = self.drafter.draft_responsible_disclosure(
            target_domain="boutique-brand.com",
            vulnerability_title="Dangling S3 Bucket Subdomain Takeover",
            proof_details="Subdomain assets.boutique-brand.com resolves to CNAME nonexistent-bucket.s3.amazonaws.com",
            security_email="security@boutique-brand.com"
        )
        self.assertEqual(res["target_domain"], "boutique-brand.com")
        self.assertEqual(res["security_email"], "security@boutique-brand.com")
        self.assertEqual(res["status"], "DRAFTED_PGP_SIGNED")
        self.assertIn("CONFIDENTIAL SECURITY DISCLOSURE // RFC 9116", res["advisory_text"])
        self.assertIn("90-day responsible disclosure window", res["advisory_text"])
        self.assertIn("-----BEGIN PGP SIGNATURE-----", res["advisory_text"])
        self.assertIn(res["signature_block"], res["advisory_text"])


class TestThreatRadarSwarm(unittest.TestCase):
    def test_process_incoming_threat_accepted(self):
        """process_incoming_threat processes high-severity threat into brief and advisory."""
        with patch("orbit_security.threat_radar.publish_event"):
            swarm = ThreatRadarSwarm()
            raw_alert = {
                "cve_id": "CVE-2026-8800",
                "title": "Shopify App Proxy Remote Code Execution",
                "cvss": 9.4,
                "affected_software": "Shopify App Proxy Middleware",
                "exploit_available": True,
                "target_domain": "enterprise-brand.com",
                "security_email": "infosec@enterprise-brand.com"
            }
            res = swarm.process_incoming_threat(raw_alert)
            self.assertTrue(res["ok"])
            self.assertEqual(res["threat"]["cve_id"], "CVE-2026-8800")
            self.assertEqual(res["brief"]["severity"], "CRITICAL")
            self.assertEqual(res["advisory"]["target_domain"], "enterprise-brand.com")

    def test_process_incoming_threat_rejected(self):
        """process_incoming_threat rejects threats below CVSS threshold."""
        swarm = ThreatRadarSwarm()
        low_alert = {
            "cve_id": "CVE-2026-0002",
            "title": "Informational banner disclosure",
            "cvss": 2.1
        }
        res = swarm.process_incoming_threat(low_alert)
        self.assertFalse(res["ok"])
        self.assertIn("CVSS below threshold", res["reason"])


if __name__ == "__main__":
    unittest.main()
