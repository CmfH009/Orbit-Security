#!/usr/bin/env python3
"""Tests for Ground-Truth Sentinel & CVD Compliance Gate."""

import datetime
import pytest
from orbit_security.ground_truth_gate import GroundTruthGate, GateVerdict
from orbit_security.models import DomainAuditResult, Finding, Severity


@pytest.fixture
def gate():
    return GroundTruthGate(max_audit_age_minutes=30)


@pytest.fixture
def valid_audit():
    return DomainAuditResult(
        domain="targetbrand.com",
        score=78,
        grade="B+",
        findings=[
            Finding(
                category="Email Authentication",
                title="DMARC Monitoring Mode (p=none)",
                description="DMARC record is set to p=none.",
                remediation="Upgrade policy from p=none to p=quarantine in DNS manager.",
                severity=Severity.MEDIUM,
                target="_dmarc.targetbrand.com",
            )
        ],
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )


def test_cvd_blocks_unsolicited_roast(gate, valid_audit):
    reply_text = "🛡️ Orbit Roast: targetbrand.com\n\n📊 Score: 78/100 (Grade: B+)\n✉️ DMARC: Monitoring mode"
    verdict = gate.validate_inbound_roast(
        domain="targetbrand.com",
        reply_text=reply_text,
        audit_result=valid_audit,
        is_explicit_request=False,  # Unsolicited!
    )
    assert not verdict.is_approved
    assert "CVD Policy Violation" in verdict.rejection_reason
    assert not verdict.cvd_safe


def test_cvd_approves_explicit_inbound_request(gate, valid_audit):
    reply_text = "🛡️ Orbit Roast: targetbrand.com\n\n📊 Score: 78/100 (Grade: B+)\n✉️ DMARC: Monitoring mode\nhttps://cmfh009.github.io/Orbit-Security/"
    verdict = gate.validate_inbound_roast(
        domain="targetbrand.com",
        reply_text=reply_text,
        audit_result=valid_audit,
        is_explicit_request=True,
    )
    assert verdict.is_approved
    assert verdict.audit_hash is not None
    assert verdict.cvd_safe
    assert verdict.rfc_compliant


def test_rfc7489_accuracy_rejection(gate, valid_audit):
    # Falsely claiming "compromised" on p=none
    reply_text = "🛡️ Orbit Roast: targetbrand.com\n\n📊 Score: 78/100 (Grade: B+)\nDomain is hacked due to DMARC p=none!"
    verdict = gate.validate_inbound_roast(
        domain="targetbrand.com",
        reply_text=reply_text,
        audit_result=valid_audit,
        is_explicit_request=True,
    )
    assert not verdict.is_approved
    assert "RFC 7489 Inaccuracy" in verdict.rejection_reason


def test_score_inconsistency_rejection(gate, valid_audit):
    # Text says 95/100 but audit was 78/100
    reply_text = "🛡️ Orbit Roast: targetbrand.com\n\n📊 Score: 95/100 (Grade: A)\n✉️ DMARC: Monitoring mode"
    verdict = gate.validate_inbound_roast(
        domain="targetbrand.com",
        reply_text=reply_text,
        audit_result=valid_audit,
        is_explicit_request=True,
    )
    assert not verdict.is_approved
    assert "Score Inconsistency" in verdict.rejection_reason


def test_stale_scan_rejection(gate):
    stale_audit = DomainAuditResult(
        domain="targetbrand.com",
        score=78,
        grade="B+",
        findings=[],
        timestamp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2),
    )
    reply_text = "🛡️ Orbit Roast: targetbrand.com\n\n📊 Score: 78/100 (Grade: B+)"
    verdict = gate.validate_inbound_roast(
        domain="targetbrand.com",
        reply_text=reply_text,
        audit_result=stale_audit,
        is_explicit_request=True,
    )
    assert not verdict.is_approved
    assert "Stale Scan Ground-Truth" in verdict.rejection_reason


def test_proactive_post_cvd_check(gate):
    # Proactively exposing a client domain without opt-in
    post_text = "Discovered that privateclient.com is vulnerable to subdomain takeover via unbounce."
    verdict = gate.validate_proactive_post(post_text, referenced_domains=["privateclient.com"])
    assert not verdict.is_approved
    assert "CVD Risk" in verdict.rejection_reason

    # Clean general educational post is approved
    safe_post = "How dangling CNAMEs can compromise web perimeters when SaaS campaigns end. 🧵👇"
    safe_verdict = gate.validate_proactive_post(safe_post)
    assert safe_verdict.is_approved
