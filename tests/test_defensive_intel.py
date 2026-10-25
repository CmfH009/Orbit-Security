"""Unit tests for Orbit Passive Defensive Intelligence Expansion (TDD).

Validates:
1. Certificate Transparency (CT) log monitor (caching, SAN extraction, anomaly detection).
2. Exploit Prediction Scoring System (EPSS) correlator (caching, tiering, KEV fusion).
3. Passive dangling CNAME takeover detection (S3, GitHub Pages, NXDOMAIN patterns).
4. SQLite WAL Blackboard event publishing across all defensive intelligence streams.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from orbit_security.blackboard import Blackboard
from orbit_security.cert_transparency import (
    BUILTIN_CT_FALLBACK,
    CertificateTransparencyMonitor,
)
from orbit_security.cname_takeover import PassiveTakeoverDetector
from orbit_security.epss import BUILTIN_EPSS_FALLBACK, EpssCorrelator


# ==============================================================================
# 1. Certificate Transparency (CT) Tests
# ==============================================================================

def test_ct_monitor_offline_fixture_and_san_parsing(tmp_path):
    cache_file = tmp_path / "test_ct_cache.json"
    monitor = CertificateTransparencyMonitor(cache_file=cache_file)

    certs = monitor.fetch_certificates("example.com")
    assert len(certs) == 2
    assert certs[0].common_name == "example.com"
    assert "api.example.com" in certs[0].san_domains
    assert "staging.example.com" in certs[0].san_domains
    assert "assets.example.com" in certs[1].san_domains


def test_ct_monitor_subdomain_discovery_and_blackboard_event(tmp_path):
    db_path = tmp_path / "ct_bb.db"
    bb = Blackboard(db_path=db_path)
    monitor = CertificateTransparencyMonitor()

    # Initial baseline knows only apex and www
    baseline = {"example.com", "www.example.com"}
    res = monitor.discover_subdomains("example.com", known_baselines=baseline, blackboard=bb)

    assert "api.example.com" in res["new_subdomains"]
    assert "staging.example.com" in res["new_subdomains"]
    assert "assets.example.com" in res["new_subdomains"]

    # Verify Blackboard published new subdomain events
    recent = bb.get_recent(limit=10, event_type="CT_LOG_NEW_SUBDOMAIN")
    assert len(recent) == 3
    discovered_subs = {e["payload"]["subdomain"] for e in recent}
    assert "api.example.com" in discovered_subs
    assert "staging.example.com" in discovered_subs


# ==============================================================================
# 2. EPSS (Exploit Prediction Scoring System) Tests
# ==============================================================================

def test_epss_offline_scoring_and_tiering(tmp_path):
    cache_file = tmp_path / "test_epss_cache.json"
    correlator = EpssCorrelator(cache_file=cache_file)

    # Ivanti 0-day
    rec = correlator.get_score("CVE-2024-21887")
    assert rec is not None
    assert rec.cve_id == "CVE-2024-21887"
    assert rec.epss_score >= 0.90
    assert rec.tier == "CRITICAL"

    # Apache path traversal
    rec_apache = correlator.get_score("CVE-2021-41773")
    assert rec_apache is not None
    assert rec_apache.epss_score >= 0.90
    assert rec_apache.tier == "CRITICAL"

    # Lower scoring vulnerability
    rec_apple = correlator.get_score("CVE-2023-38606")
    assert rec_apple is not None
    assert rec_apple.tier == "ELEVATED"


def test_epss_correlation_with_blackboard(tmp_path):
    db_path = tmp_path / "epss_bb.db"
    bb = Blackboard(db_path=db_path)
    correlator = EpssCorrelator()

    records = correlator.correlate_cves(
        cve_ids=["CVE-2024-21887", "CVE-2023-38606"],
        domain="vpn.target.corp",
        blackboard=bb,
        threshold=0.35,
    )
    assert len(records) == 2

    # Only CVE-2024-21887 exceeds 0.35 threshold
    recent = bb.get_recent(limit=10, event_type="EPSS_SCORE_EVALUATED")
    assert len(recent) == 1
    assert recent[0]["payload"]["cve_id"] == "CVE-2024-21887"
    assert recent[0]["payload"]["high_threat"] is True


def test_epss_and_cisa_kev_fusion(tmp_path):
    from orbit_security.cisa_kev import CisaKevCatalog
    db_path = tmp_path / "fusion_bb.db"
    bb = Blackboard(db_path=db_path)

    kev_catalog = CisaKevCatalog()
    epss_correlator = EpssCorrelator()

    results = epss_correlator.correlate_with_cisa_kev(
        cve_ids=["CVE-2024-21887", "CVE-2023-38606"],
        cisa_kev_catalog=kev_catalog,
        domain="gateway.example.com",
        blackboard=bb,
    )

    # CVE-2024-21887 is both in CISA KEV and has EPSS > 0.90 -> CRITICAL_ACTUALLY_EXPLOITED_IN_WILD
    ivanti_res = next(r for r in results if r["cve_id"] == "CVE-2024-21887")
    assert ivanti_res["in_cisa_kev"] is True
    assert ivanti_res["threat_level"] == "CRITICAL_ACTUALLY_EXPLOITED_IN_WILD"

    # Blackboard must have received fusion event
    recent = bb.get_recent(limit=10, event_type="CRITICAL_0DAY_CORRELATED")
    assert len(recent) == 1
    assert recent[0]["payload"]["cve_id"] == "CVE-2024-21887"


# ==============================================================================
# 3. Passive Dangling CNAME Takeover Tests
# ==============================================================================

def test_passive_cname_takeover_s3_bucket(tmp_path):
    db_path = tmp_path / "takeover_bb.db"
    bb = Blackboard(db_path=db_path)
    detector = PassiveTakeoverDetector()

    # Simulated S3 bucket takeover scenario
    finding = detector.evaluate_cname(
        domain="static.example.com",
        cname_target="my-orphaned-bucket.s3.amazonaws.com",
        body_snippet="<Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>",
        blackboard=bb,
    )

    assert finding is not None
    assert finding.provider == "AWS S3"
    assert finding.severity == "CRITICAL"
    assert "NoSuchBucket" in finding.fingerprint_matched
    assert "create the matching S3 bucket" in finding.remediation

    # Verify Blackboard published event
    recent = bb.get_recent(limit=10, event_type="SUBDOMAIN_TAKEOVER_DETECTED")
    assert len(recent) == 1
    assert recent[0]["payload"]["service"] == "AWS S3"


def test_passive_cname_takeover_github_pages(tmp_path):
    detector = PassiveTakeoverDetector()

    finding = detector.evaluate_cname(
        domain="docs.example.com",
        cname_target="user.github.io",
        body_snippet="There isn't a GitHub Pages site here.",
    )

    assert finding is not None
    assert finding.provider == "GitHub Pages"
    assert finding.severity == "CRITICAL"


def test_passive_cname_safe_domain_returns_none():
    detector = PassiveTakeoverDetector()

    finding = detector.evaluate_cname(
        domain="api.example.com",
        cname_target="cdn.cloudflare.net",
        body_snippet="<html>Safe content</html>",
    )
    assert finding is None


def test_ct_monitor_rejects_suffix_collision_spoofing():
    # If a certificate contains attacker-example.com or phishing-example.com,
    # it must NOT be extracted as a subdomain of example.com
    fixture = {
        "example.com": [
            {
                "id": 99999,
                "common_name": "attacker-example.com",
                "name_value": "attacker-example.com\nphishing-example.com\nvalid.example.com",
                "issuer_name": "Attacker CA",
            }
        ]
    }
    monitor = CertificateTransparencyMonitor(offline_fixtures=fixture)
    certs = monitor.fetch_certificates("example.com")
    assert len(certs) == 1
    # Only valid.example.com should be extracted
    assert "valid.example.com" in certs[0].san_domains
    assert "attacker-example.com" not in certs[0].san_domains
    assert "phishing-example.com" not in certs[0].san_domains


def test_passive_cname_takeover_handles_recon_lowercase_dict():
    detector = PassiveTakeoverDetector()

    # recon.py produces lowercase "cname"
    dns_records = {
        "cname": "orphaned-demo.s3.amazonaws.com",
        "a_records": [],
    }
    findings = detector.evaluate_dns_records(
        domain="test.example.com",
        records=dns_records,
        body_snippet="<Code>NoSuchBucket</Code>",
    )
    assert len(findings) == 1
    assert findings[0].provider == "AWS S3"
    assert findings[0].severity == "CRITICAL"


def test_passive_cname_takeover_rejects_subdomain_spoofing():
    detector = PassiveTakeoverDetector()
    # Attacker host has "github.io" as a subdomain prefix, not the suffix
    finding = detector.evaluate_cname(
        domain="sub.victim.com",
        cname_target="github.io.attacker-controlled.net",
        is_nxdomain=True,
    )
    assert finding is None


def test_passive_cname_takeover_nxdomain_detection(tmp_path):
    db_path = tmp_path / "nx_bb.db"
    bb = Blackboard(db_path=db_path)
    detector = PassiveTakeoverDetector()

    # AWS Elastic Beanstalk is an nxdomain=True provider
    finding = detector.evaluate_cname(
        domain="static.example.com",
        cname_target="orphaned-app.elasticbeanstalk.com",
        is_nxdomain=True,
        blackboard=bb,
    )
    assert finding is not None
    assert finding.provider == "AWS Elastic Beanstalk"
    assert "NXDOMAIN" in finding.fingerprint_matched
