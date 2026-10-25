"""Unit tests for orbit_security.private_alerting (TDD).

Validates:
1. Strict invariant: Commercial outreach is frozen and cannot be triggered.
2. Alert synthesis across KEV, Takeover, and EPSS fusion events.
3. Alert deduplication logic within TTL window.
4. HMAC-SHA256 signature generation for private webhook alerts.
5. Blackboard audit trail logging (PRIVATE_DEFENSIVE_ALERT_DISPATCHED).
"""

from __future__ import annotations

import hmac
import hashlib
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from orbit_security.blackboard import Blackboard
from orbit_security.private_alerting import (
    COMMERCIAL_OUTREACH_FROZEN,
    OutreachFrozenViolation,
    PrivateAlertSentinel,
    PrivateDefensiveAlert,
)


def test_commercial_outreach_strictly_frozen():
    assert COMMERCIAL_OUTREACH_FROZEN is True, "Commercial outreach must be strictly frozen per directive"

    sentinel = PrivateAlertSentinel()
    with pytest.raises(OutreachFrozenViolation) as excinfo:
        sentinel.trigger_commercial_outreach()

    assert "strictly frozen per user directive" in str(excinfo.value)


def test_alert_formatting_across_threat_types():
    sentinel = PrivateAlertSentinel()

    # 1. CISA KEV alert
    kev_alert = sentinel.format_alert(
        event_type="CISA_KEV_MATCH_DETECTED",
        payload={
            "cve_id": "CVE-2024-21887",
            "domain": "vpn.example.com",
            "product": "Ivanti Connect Secure",
            "action_required": "Apply emergency mitigations immediately.",
        },
    )
    assert kev_alert is not None
    assert kev_alert.severity == "CRITICAL"
    assert "CVE-2024-21887" in kev_alert.summary
    assert kev_alert.target_domain == "vpn.example.com"

    # 2. Subdomain Takeover alert
    takeover_alert = sentinel.format_alert(
        event_type="SUBDOMAIN_TAKEOVER_DETECTED",
        payload={
            "service": "AWS S3",
            "domain": "assets.example.com",
            "cname_target": "orphaned-bucket.s3.amazonaws.com",
            "remediation": "Claim bucket or remove CNAME.",
        },
    )
    assert takeover_alert is not None
    assert takeover_alert.severity == "CRITICAL"
    assert "AWS S3" in takeover_alert.summary

    # 3. EPSS high threat alert
    epss_alert = sentinel.format_alert(
        event_type="EPSS_SCORE_EVALUATED",
        payload={
            "cve_id": "CVE-2021-41773",
            "domain": "web.example.com",
            "epss_score": 0.974,
            "high_threat": True,
        },
    )
    assert epss_alert is not None
    assert epss_alert.severity == "HIGH"
    assert "97.4%" in epss_alert.summary


def test_alert_deduplication_and_force(tmp_path):
    db_path = tmp_path / "alert_bb.db"
    bb = Blackboard(db_path=db_path)

    sentinel = PrivateAlertSentinel(
        blackboard=bb,
        enable_desktop_notifications=False,
        dedup_ttl_seconds=3600.0,
    )

    alert = PrivateDefensiveAlert(
        alert_id="test-alert-1",
        event_type="CISA_KEV_MATCH_DETECTED",
        target_domain="target.corp",
        severity="CRITICAL",
        summary="Critical Ivanti 0-day",
        action_required="Patch now",
        details={"cve_id": "CVE-2024-21887"},
    )

    # First dispatch succeeds
    res1 = sentinel.dispatch_alert(alert)
    assert res1["dispatched"] is True

    # Immediate second dispatch is identified as duplicate
    res2 = sentinel.dispatch_alert(alert)
    assert res2["dispatched"] is False
    assert res2["reason"] == "duplicate_within_ttl"

    # Forced dispatch bypasses deduplication
    res3 = sentinel.dispatch_alert(alert, force=True)
    assert res3["dispatched"] is True


def test_private_alert_hmac_signing():
    secret = "test-secret-signing-key"
    sentinel = PrivateAlertSentinel(signing_secret=secret)

    body = b'{"alert_id": "alert-123", "domain": "example.com"}'
    ts = 1700000000.0
    sig = sentinel.sign_alert_payload(body, ts)

    expected_msg = f"{int(ts)}:".encode("utf-8") + body
    expected_sig = hmac.new(secret.encode("utf-8"), expected_msg, hashlib.sha256).hexdigest()
    assert sig == expected_sig


def test_blackboard_audit_event_logged(tmp_path):
    db_path = tmp_path / "audit_bb.db"
    bb = Blackboard(db_path=db_path)

    sentinel = PrivateAlertSentinel(
        blackboard=bb,
        enable_desktop_notifications=False,
    )

    alert = PrivateDefensiveAlert(
        alert_id="test-audit-alert",
        event_type="SUBDOMAIN_TAKEOVER_DETECTED",
        target_domain="orphaned.example.com",
        severity="CRITICAL",
        summary="AWS S3 bucket takeover",
        action_required="Remove CNAME",
        details={"service": "AWS S3"},
    )

    res = sentinel.dispatch_alert(alert)
    assert res["dispatched"] is True

    # Verify event published into Blackboard WAL
    recent = bb.get_recent(limit=10, event_type="PRIVATE_DEFENSIVE_ALERT_DISPATCHED")
    assert len(recent) == 1
    assert recent[0]["payload"]["alert_id"] == "test-audit-alert"
    assert recent[0]["payload"]["domain"] == "orphaned.example.com"
