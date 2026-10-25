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


# ==============================================================================
# 4. Project #6: Continuous CT Stream Daemon & Takeover Chaining Tests
# ==============================================================================

def test_ct_stream_daemon_watermark_persistence_across_restarts(tmp_path):
    from orbit_security.cert_transparency import CtStreamDaemon

    db_path = tmp_path / "ct_daemon_bb.db"
    watermark_file = tmp_path / "ct_watermark.json"
    cache_file = tmp_path / "ct_cache.json"
    bb = Blackboard(db_path=db_path)

    daemon1 = CtStreamDaemon(
        watermark_file=watermark_file,
        cache_file=cache_file,
        blackboard=bb,
    )
    res1 = daemon1.poll_domain("example.com")
    assert res1["new_certificates"] == 2
    assert "api.example.com" in res1["new_subdomains"]
    assert "staging.example.com" in res1["new_subdomains"]
    assert watermark_file.exists()

    # Restart daemon with same watermark file: no duplicate discoveries
    daemon2 = CtStreamDaemon(
        watermark_file=watermark_file,
        cache_file=cache_file,
        blackboard=bb,
    )
    res2 = daemon2.poll_domain("example.com")
    assert res2["new_certificates"] == 0
    assert res2["new_subdomains"] == []


def test_ct_stream_daemon_automatic_cname_takeover_chaining(tmp_path):
    from orbit_security.cert_transparency import CtStreamDaemon

    db_path = tmp_path / "ct_chain_bb.db"
    watermark_file = tmp_path / "ct_chain_watermark.json"
    bb = Blackboard(db_path=db_path)

    # Provide simulated DNS/HTTP resolution for newly discovered CT subdomains
    cname_probe_map = {
        "staging.example.com": {
            "cname": "orphaned-staging-bucket.s3.amazonaws.com",
            "body_snippet": "<Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>",
        },
        "api.example.com": {
            "cname": "safe-lb.cloudflare.net",
            "body_snippet": "OK",
        },
    }

    daemon = CtStreamDaemon(
        watermark_file=watermark_file,
        blackboard=bb,
        cname_probe_map=cname_probe_map,
    )
    res = daemon.poll_domain("example.com")
    assert len(res["takeover_findings"]) == 1
    assert res["takeover_findings"][0]["domain"] == "staging.example.com"
    assert res["takeover_findings"][0]["provider"] == "AWS S3"

    takeover_events = bb.get_recent(limit=10, event_type="SUBDOMAIN_TAKEOVER_DETECTED")
    assert len(takeover_events) == 1
    assert takeover_events[0]["payload"]["domain"] == "staging.example.com"


def test_bounty_rolling_daemon_ct_sweep_integration(tmp_path):
    from orbit_security.bounty_rolling_daemon import BountyRollingDaemon

    programs_file = tmp_path / "test_programs.json"
    programs_file.write_text(
        json.dumps({
            "programs": [
                {
                    "program_id": "example_bbp",
                    "name": "Example Corp BBP",
                    "platform": "hackerone",
                    "policy_url": "https://hackerone.com/example",
                    "in_scope": ["*.example.com", "example.com"],
                    "out_of_scope": [],
                    "bounty_tier": "cash",
                    "max_bounty": 10000,
                }
            ]
        }),
        encoding="utf-8",
    )
    state_file = tmp_path / "radar_state.json"
    watermark_file = tmp_path / "ct_watermark.json"

    daemon = BountyRollingDaemon(
        programs_path=programs_file,
        state_file=state_file,
        ct_watermark_file=watermark_file,
        offline=True,
    )
    ct_res = daemon.sweep_ct_logs_for_program("example_bbp")
    assert ct_res is not None
    assert ct_res["program_id"] == "example_bbp"
    assert ct_res["domains_polled"] >= 1
    assert "api.example.com" in ct_res["new_subdomains"]


# ==============================================================================
# 5. Wave B (Projects #4, #7, #9): White-Label Fleet PDF, Takeover Playground,
#    and Zero-Knowledge Agency Scorecard Tests
# ==============================================================================

def test_white_label_fleet_pdf_generation(tmp_path):
    from orbit_security.agency_retainer import AgencyRetainerManager
    from orbit_security.reporter import ReportGenerator

    retainers_json = tmp_path / "agency_retainers.json"
    mgr = AgencyRetainerManager(data_path=retainers_json)

    # Trigger two scans on candykittens.co.uk so score_delta is populated (+4 improved)
    mgr.update_site_audit("eastside-co", "candykittens.co.uk", score=85, grade="B", critical_count=0, high_count=1)
    mgr.update_site_audit("eastside-co", "candykittens.co.uk", score=89, grade="A", critical_count=0, high_count=0)

    agency = mgr.get_agency("eastside-co")
    assert agency is not None

    pdf_out = tmp_path / "eastside_fleet_posture.pdf"
    highlights = [
        {
            "cve": "CVE-2024-21887",
            "vendor": "Ivanti",
            "product": "Connect Secure",
            "epss": 0.9421,
            "is_cisa_kev": True,
        }
    ]
    res_path = ReportGenerator.generate_white_label_fleet_pdf(
        agency=agency,
        output_path=str(pdf_out),
        kev_epss_highlights=highlights,
    )
    assert Path(res_path).exists()
    raw_bytes = Path(res_path).read_bytes()
    assert raw_bytes.startswith(b"%PDF-")
    assert len(raw_bytes) > 1500

    # Also test AgencyRetainerManager convenience method
    exported_pdf = mgr.export_agency_posture_pdf("eastside-co", output_dir=tmp_path)
    assert exported_pdf.exists()
    assert exported_pdf.read_bytes().startswith(b"%PDF-")


def test_takeover_poc_simulator_and_presets():
    detector = PassiveTakeoverDetector()

    presets = detector.export_playground_presets()
    assert len(presets) >= 5
    preset_ids = {p["id"] for p in presets}
    assert "aws_s3" in preset_ids
    assert "github_pages" in preset_ids

    # Simulate vulnerable S3 takeover PoC
    poc_vuln = detector.simulate_poc_scenario(
        domain="media.client-store.com",
        cname_target="orphaned-client-media.s3.amazonaws.com",
        http_response_body="<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
        is_nxdomain=False,
    )
    assert poc_vuln["vulnerable"] is True
    assert poc_vuln["provider"] == "AWS S3"
    assert poc_vuln["severity"] == "CRITICAL"
    assert poc_vuln["cvss_score"] >= 8.0
    assert "dig +short CNAME media.client-store.com" in poc_vuln["dig_command"]
    assert "NoSuchBucket" in poc_vuln["fingerprint_matched"]
    assert len(poc_vuln["remediation_steps"]) >= 2

    # Simulate safe CNAME
    poc_safe = detector.simulate_poc_scenario(
        domain="shop.client-store.com",
        cname_target="shops.myshopify.com",
        http_response_body="<html>Welcome to Active Store</html>",
        is_nxdomain=False,
    )
    assert poc_safe["vulnerable"] is False
    assert poc_safe["severity"] == "SAFE"


def test_zero_knowledge_fleet_scorecard_evaluation():
    from orbit_security.scoring import evaluate_zero_knowledge_fleet_scorecard

    domains_payload = [
        {
            "domain": "flagship.brand.com",
            "findings": [
                {"title": "Missing BIMI Record", "severity": "LOW"},
                {"title": "Missing Content Security Policy (CSP)", "severity": "LOW"},
            ],
        },
        {
            "domain": "legacy-promo.brand.com",
            "findings": [
                {
                    "title": "Dangling CNAME / Subdomain Takeover Risk (AWS S3)",
                    "severity": "CRITICAL",
                    "class_key": "dangling-cname-takeover",
                }
            ],
        },
        {
            "domain": "mail-gateway.brand.com",
            "findings": [
                {"title": "DMARC Policy Set to p=none (Monitoring Only)", "severity": "MEDIUM"},
            ],
        },
    ]

    scorecard = evaluate_zero_knowledge_fleet_scorecard(
        domains_payload=domains_payload,
        agency_name="Eastside Co",
    )
    assert scorecard["agency_name"] == "Eastside Co"
    assert scorecard["zero_knowledge_mode"] is True
    assert scorecard["total_domains"] == 3
    assert scorecard["at_risk_domains"] == 1
    assert len(scorecard["zk_verification_sha256"]) == 64

    by_domain = {d["domain"]: d for d in scorecard["domain_results"]}
    # R1: Hygiene-only domain still scores 100 / A+
    assert by_domain["flagship.brand.com"]["score"] == 100
    assert by_domain["flagship.brand.com"]["grade"] == "A+"
    # R2: Critical takeover finding caps domain at <= 59 (D)
    assert by_domain["legacy-promo.brand.com"]["score"] <= 59
    assert by_domain["legacy-promo.brand.com"]["grade"] == "D"
    # Medium DMARC finding scores 90 / A
    assert by_domain["mail-gateway.brand.com"]["score"] == 90
    assert by_domain["mail-gateway.brand.com"]["grade"] == "A"


def test_takeover_playground_and_zk_scorecard_web_ui_parity():
    root = Path(__file__).resolve().parent.parent
    landing_html = (root / "landing" / "index.html").read_text(encoding="utf-8")
    docs_html = (root / "docs" / "index.html").read_text(encoding="utf-8")
    landing_js = (root / "landing" / "assets" / "orbit_radar.js").read_text(encoding="utf-8")
    docs_js = (root / "docs" / "assets" / "orbit_radar.js").read_text(encoding="utf-8")

    assert 'id="takeover-poc-playground"' in landing_html
    assert 'id="zk-agency-scorecard"' in landing_html
    assert landing_html == docs_html

    assert "function runTakeoverPocSimulation" in landing_js
    assert "function loadTakeoverPreset" in landing_js
    assert "function runZeroKnowledgeBatchScorecard" in landing_js
    assert "function exportZeroKnowledgeScorecardJson" in landing_js
    assert landing_js == docs_js


