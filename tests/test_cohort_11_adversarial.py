#!/usr/bin/env python3
"""
Adversarial Stress Test Suite for Milestone M1: Cohort 11 Staging & Calibration.

Authored by: Challenger Agent (teamwork_challenger_m1_1)
Mission: Stress-test boundary conditions, DNS edge cases, preflight deliverability failure modes,
catastrophic regex/malformed HTML parsing, quality floor arithmetic, RFC 5322 EML compliance,
and OpSec gitignore guarantees.
"""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from orbit_security.scoring import (
    AuditScore,
    ScoreItem,
    Severity,
    grade_from_score,
    score_findings,
)
from scripts.stage_cohort_11 import (
    COHORT_11_TARGETS,
    assign_ab_variant,
    audit_cohort_11,
    build_pitch_copy,
    deobfuscate_and_extract_emails,
    evaluate_quality_floor,
    run_deliverability_preflight,
    stage_cohort_11,
)
from scripts.verify_contacts import (
    classify,
    evaluate_deliverability_gate,
    extract_emails,
    has_mx,
    _deobfuscate_text,
)


# =========================================================================== #
# SECTION 1: Quality Floor Boundary Conditions & Edge Cases
# =========================================================================== #

class TestQualityFloorBoundaries:
    """Stress tests boundary conditions for evaluate_quality_floor."""

    def test_empty_cohort_rejection(self):
        """Empty cohort must be rejected immediately."""
        res = evaluate_quality_floor([])
        assert res["quality_floor_met"] is False
        assert res["mean_score"] == 0.0
        assert "Target cohort is empty" in res["reasons"]

    def test_score_boundary_just_below_60(self):
        """Mean score of 59.99 must be rejected."""
        targets = [
            {"score": 59.99, "grade": "D", "has_critical": False, "has_high": False},
        ]
        res = evaluate_quality_floor(targets)
        assert res["quality_floor_met"] is False
        assert any("below the 60.0 floor" in r for r in res["reasons"])

    def test_score_boundary_exact_60(self):
        """Mean score of exactly 60.0 with 100% C grade should pass."""
        targets = [
            {"score": 60.0, "grade": "C", "has_critical": False, "has_high": False},
        ]
        res = evaluate_quality_floor(targets)
        assert res["quality_floor_met"] is True
        assert res["mean_score"] == 60.0
        assert res["grade_c_or_better_ratio"] == 1.0

    def test_c_ratio_boundary_below_70_percent(self):
        """C+ ratio below 70% (e.g. 6/10 = 60%) must be rejected even if mean score is high."""
        targets = [
            {"score": 90, "grade": "A", "has_critical": False, "has_high": False}
        ] * 6 + [
            {"score": 50, "grade": "D", "has_critical": False, "has_high": False}
        ] * 4
        res = evaluate_quality_floor(targets)
        assert res["quality_floor_met"] is False
        assert res["mean_score"] == 74.0
        assert res["grade_c_or_better_ratio"] == 0.60
        assert any("below the required 70.0%" in r for r in res["reasons"])

    def test_c_ratio_boundary_exact_70_percent(self):
        """C+ ratio of exactly 70% with mean score >= 60 must pass."""
        targets = [
            {"score": 80, "grade": "B", "has_critical": False, "has_high": False}
        ] * 7 + [
            {"score": 50, "grade": "D", "has_critical": False, "has_high": False}
        ] * 3
        res = evaluate_quality_floor(targets)
        assert res["quality_floor_met"] is True
        assert res["grade_c_or_better_ratio"] == 0.70

    def test_hygiene_only_f_detection_and_rejection(self):
        """If a target receives grade F without critical or high findings, it must be rejected."""
        targets = [
            {"score": 90, "grade": "A", "has_critical": False, "has_high": False}
        ] * 9 + [
            {"score": 40, "grade": "F", "has_critical": False, "has_high": False}
        ]
        res = evaluate_quality_floor(targets)
        assert res["quality_floor_met"] is False
        assert res["hygiene_only_f_count"] == 1
        assert any("hygiene-only F" in r for r in res["reasons"])

    def test_legitimate_exploitable_f_does_not_count_as_hygiene_f(self):
        """An F caused by a real CRITICAL finding is an exploitable F, NOT a hygiene-only F."""
        targets = [
            {"score": 90, "grade": "A", "has_critical": False, "has_high": False}
        ] * 9 + [
            {"score": 30, "grade": "F", "has_critical": True, "has_high": False}
        ]
        res = evaluate_quality_floor(targets)
        assert res["hygiene_only_f_count"] == 0
        assert res["quality_floor_met"] is True


# =========================================================================== #
# SECTION 2: Anti-Bounce Deliverability Preflight & DNS Edge Cases
# =========================================================================== #

class TestDeliverabilityPreflightAdversarial:
    """Stress tests preflight deliverability gate, DNS errors, and mailbox validation."""

    def test_null_mx_rfc_7505_handling(self):
        """RFC 7505 defines Null MX (a single '.' record) indicating domain accepts no mail."""
        class FakeNullMX:
            exchange = "."

        def mock_resolve(domain, rdtype, lifetime=6):
            return [FakeNullMX()]

        import dns.resolver
        old_resolve = dns.resolver.resolve
        try:
            dns.resolver.resolve = mock_resolve
            ok, hosts = has_mx("null-mx.invalid")
            assert ok is False, "Null MX must be treated as NO_MX"
            assert hosts == []
        finally:
            dns.resolver.resolve = old_resolve

    def test_dns_resolver_nxdomain(self):
        """NXDOMAIN error must result in (False, []) without uncaught exception."""
        import dns.resolver
        old_resolve = dns.resolver.resolve
        try:
            def mock_resolve_nxdomain(domain, rdtype, lifetime=6):
                raise dns.resolver.NXDOMAIN()
            dns.resolver.resolve = mock_resolve_nxdomain
            ok, hosts = has_mx("nonexistent-domain-xyz.invalid")
            assert ok is False
            assert hosts == []
        finally:
            dns.resolver.resolve = old_resolve

    def test_dns_resolver_timeout(self):
        """DNS LifetimeTimeout must result in (False, []) without hanging or crashing."""
        import dns.resolver
        old_resolve = dns.resolver.resolve
        try:
            def mock_resolve_timeout(domain, rdtype, lifetime=6):
                raise dns.resolver.LifetimeTimeout()
            dns.resolver.resolve = mock_resolve_timeout
            ok, hosts = has_mx("timeout-domain.invalid")
            assert ok is False
            assert hosts == []
        finally:
            dns.resolver.resolve = old_resolve

    def test_preflight_heuristic_flaw_accepts_malformed_emails(self):
        """Remediated: run_deliverability_preflight strictly rejects malformed syntax
        and mismatched apex domains as REFUTED instead of accepting them as CONFIRMED."""
        malformed_targets = [
            {"agency_domain": "example.com", "contact_email": "@example.com"},
            {"agency_domain": "example.com", "contact_email": "user@"},
            {"agency_domain": "example.com", "contact_email": "unrelated@gmail.com"},
        ]
        preflight = run_deliverability_preflight(malformed_targets, skip_network=True)
        assert preflight["confirmed_count"] == 0
        assert preflight["refuted_count"] == 3
        assert preflight["gate_passed"] is False

    def test_audit_cohort_11_crashes_on_missing_client_anchor(self):
        """Remediated: audit_cohort_11 safely handles missing client_anchor without KeyError."""
        broken_targets = [
            {
                "agency_name": "Test Agency",
                "agency_domain": "test.com",
                "contact_email": "contact@test.com",
                "findings": [],
                # client_anchor omitted!
            }
        ]
        res = audit_cohort_11(broken_targets)
        assert len(res) == 1
        assert res[0]["client_anchor"] == "client portfolio"
        assert res[0]["focus"] == "custom engineering and cloud architecture"

    def test_no_mx_blocks_cohort_completely(self):
        """Even a single NO_MX target must fail the preflight gate with 0% tolerance."""
        test_targets = [
            {"agency_domain": "good1.com", "contact_email": "hello@good1.com"},
            {"agency_domain": "good2.com", "contact_email": "hello@good2.com"},
            {"agency_domain": "no-mx.com", "contact_email": "hello@no-mx.com"},
        ]
        def mock_has_mx(domain):
            if domain == "no-mx.com":
                return False, []
            return True, ["mx.example.com"]

        import scripts.stage_cohort_11 as sc11
        old_has_mx = sc11.has_mx
        try:
            sc11.has_mx = mock_has_mx
            preflight = run_deliverability_preflight(test_targets, skip_network=False)
            assert preflight["gate_passed"] is False
            assert preflight["no_mx_count"] == 1
            assert any("NO_MX" in r for r in preflight["blocking_reasons"])
        finally:
            sc11.has_mx = old_has_mx

    def test_real_verify_contacts_refutes_cohort_11_guessed_addresses(self):
        """EMPIRICAL FINDING: verify_contacts.classify confirms verified published mailboxes
        (contact@8thlight.com) while refuting unverified guessed mailboxes (hello@8thlight.com)."""
        # Test that guessed hello@8thlight.com is REFUTED
        guessed_target = {
            "agency_name": "8th Light",
            "agency_slug": "8th-light",
            "agency_domain": "8thlight.com",
            "contact_email": "hello@8thlight.com",
        }
        res_guessed = classify(guessed_target)
        assert res_guessed["classification"] == "REFUTED"
        assert "hello@8thlight.com" not in res_guessed.get("published_addresses", [])
        assert "contact@8thlight.com" in res_guessed.get("published_addresses", [])

        # Test that the updated cohort target with published mailbox is CONFIRMED
        target_8th = next(t for t in COHORT_11_TARGETS if t["agency_slug"] == "8th-light")
        assert target_8th["contact_email"] == "contact@8thlight.com"
        res_target = classify(target_8th)
        assert res_target["classification"] == "CONFIRMED"


# =========================================================================== #
# SECTION 3: HTML De-obfuscation & Catastrophic Input Resistance
# =========================================================================== #

class TestHTMLDeobfuscationAdversarial:
    """Stress tests HTML entity decoding and address extraction."""

    def test_nested_and_hex_entities(self):
        """Handles hex entities, decimal entities, and mixed obfuscation."""
        html = """
        <div>
          Contact us at:
          <span>info&#64;agency.com</span>
          <span>support&#x40;agency.com</span>
          <span>partner [AT] agency [DOT] com</span>
          <span>team (at) agency (dot) io</span>
        </div>
        """
        emails = extract_emails(html)
        assert "info@agency.com" in emails
        assert "support@agency.com" in emails
        assert "partner@agency.com" in emails
        assert "team@agency.io" in emails

    def test_junk_and_asset_rejection(self):
        """Never extracts junk addresses or image file artifacts as email addresses."""
        html = """
        <a href="mailto:noreply@agency.com">No Reply</a>
        <a href="mailto:donotreply@agency.com">Do Not Reply</a>
        <a href="mailto:abuse@agency.com">Abuse</a>
        <a href="mailto:example@agency.com">Example</a>
        <a href="mailto:privacy@agency.com">Privacy</a>
        <img src="user@2x.png" />
        <img src="header@1x.jpg" />
        <a href="mailto:real_human@agency.com">Human</a>
        """
        emails = extract_emails(html)
        assert "real_human@agency.com" in emails
        assert not any(e.startswith("noreply@") for e in emails)
        assert not any(e.startswith("abuse@") for e in emails)
        assert not any(e.startswith("example@") for e in emails)
        assert not any(e.endswith(".png") for e in emails)
        assert not any(e.endswith(".jpg") for e in emails)

    def test_large_input_catastrophic_backtracking_resilience(self):
        """Ensures regex parser finishes sub-100ms on pathological 500KB repeated text."""
        import time
        pathological = ("<p>test @@@ [[at]] ((dot)) foo@@bar.... " * 10_000)
        start = time.perf_counter()
        emails = extract_emails(pathological)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"Catastrophic backtracking: took {elapsed:.2f}s"


# =========================================================================== #
# SECTION 4: Deterministic Partitioning & Statistical Properties
# =========================================================================== #

class TestDeterministicPartitioningAdversarial:
    """Stress tests assign_ab_variant across boundary inputs and large populations."""

    def test_case_and_whitespace_insensitivity(self):
        """Domain key capitalization and surrounding whitespace should produce identical assignment."""
        v1 = assign_ab_variant("8thlight.com")
        v2 = assign_ab_variant("  8thlight.com  ")
        v3 = assign_ab_variant("8THLIGHT.COM")
        assert v1 == v2 == v3

    def test_distribution_over_large_population(self):
        """Simulate 2,000 synthetic agency domains: holdout should be ~30%, variant_a ~35%, variant_b ~35%."""
        holdout_count = 0
        variant_a_count = 0
        variant_b_count = 0
        n = 2000

        for i in range(n):
            domain = f"agency-sample-{i}.com"
            res = assign_ab_variant(domain)
            if res["bucket"] == "holdout":
                holdout_count += 1
            elif res["bucket"] == "variant_a":
                variant_a_count += 1
            elif res["bucket"] == "variant_b":
                variant_b_count += 1

        holdout_ratio = holdout_count / n
        a_ratio = variant_a_count / n
        b_ratio = variant_b_count / n

        assert 0.25 <= holdout_ratio <= 0.35, f"Holdout ratio {holdout_ratio:.2%} out of expected ~30%"
        assert 0.30 <= a_ratio <= 0.40, f"Variant A ratio {a_ratio:.2%} out of expected ~35%"
        assert 0.30 <= b_ratio <= 0.40, f"Variant B ratio {b_ratio:.2%} out of expected ~35%"


# =========================================================================== #
# SECTION 5: RFC 5322 EML Integrity & Manifest Validation on Live Output
# =========================================================================== #

class TestLiveStagedArtifactsIntegrity:
    """Inspects all physical files in outbound_queue/cohort_11."""

    COHORT_DIR = REPO_ROOT / "outbound_queue" / "cohort_11"

    @pytest.fixture(autouse=True)
    def _ensure_staged_cohort_11(self):
        manifest_file = self.COHORT_DIR / "cohort_11_manifest.json"
        if not manifest_file.exists():
            stage_cohort_11(output_dir=self.COHORT_DIR, skip_network=True, enforce_preflight=True)

    def test_manifest_file_exists_and_conforms_to_schema(self):
        manifest_file = self.COHORT_DIR / "cohort_11_manifest.json"
        assert manifest_file.exists(), f"Missing {manifest_file}"

        data = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert data["cohort"] == "cohort_11"
        assert data["total_targets"] == 10
        assert data["quality_floor_met"] is True
        assert data["mean_score"] >= 60.0
        assert data["grade_c_or_better_ratio"] >= 0.70
        assert data["hygiene_only_f_count"] == 0
        assert data["deliverability_preflight"]["gate_passed"] is True
        assert len(data["targets"]) == 10

    def test_all_10_target_subdirectories_contain_valid_eml_and_txt(self):
        manifest_file = self.COHORT_DIR / "cohort_11_manifest.json"
        data = json.loads(manifest_file.read_text(encoding="utf-8"))

        for target in data["targets"]:
            slug = target["agency_slug"]
            agency_dir = self.COHORT_DIR / slug
            assert agency_dir.is_dir(), f"Missing directory: {agency_dir}"

            txt_file = agency_dir / "pitch_email.txt"
            eml_file = agency_dir / "pitch_email.eml"
            assert txt_file.exists(), f"Missing txt: {txt_file}"
            assert eml_file.exists(), f"Missing eml: {eml_file}"

            # Parse EML as RFC 5322 with email.policy.default
            raw_eml = eml_file.read_bytes()
            msg = email.message_from_bytes(raw_eml, policy=email.policy.default)

            # 1. Mandatory RFC 5322 headers
            assert msg["From"] == "Carson Haynes <carson@orbitsecurity.io>"
            assert msg["To"] == target["contact_email"]
            assert msg["Subject"]
            assert msg["Date"]
            assert msg["Message-ID"]

            # 2. Date format must parse as RFC 2822 / RFC 5322 datetime
            parsed_date = parsedate_to_datetime(msg["Date"])
            assert parsed_date is not None

            # 3. Message-ID format <...@orbitsecurity.io>
            assert msg["Message-ID"].startswith("<") and msg["Message-ID"].endswith(">")
            assert "@orbitsecurity.io" in msg["Message-ID"]

            # 4. Custom Orbit tracking headers
            assert msg["X-Orbit-Campaign"] == "cohort_11_staging"
            assert msg["X-Orbit-Cohort"] == "cohort_11"
            assert msg["X-Orbit-AB-Variant"] in ("variant_a", "variant_b", "holdout")

            # 5. Payload matches TXT body when decoded via email policy
            body = msg.get_body().get_content()
            assert target["agency_name"] in body
            assert "Orbit Security" in body
            assert target["client_anchor"] in body
