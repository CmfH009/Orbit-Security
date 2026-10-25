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


def test_private_webhook_dispatch_success(tmp_path):
    db_path = tmp_path / "alert_bb.db"
    bb = Blackboard(db_path=db_path)
    webhook_url = "https://hooks.slack.com/services/T00/B00/X00"
    secret = "wh-secret-key"

    sentinel = PrivateAlertSentinel(
        blackboard=bb,
        webhook_url=webhook_url,
        signing_secret=secret,
        enable_desktop_notifications=False,
    )

    alert = PrivateDefensiveAlert(
        alert_id="alert-wh-1",
        event_type="CISA_KEV_MATCH_DETECTED",
        target_domain="gateway.target.corp",
        severity="CRITICAL",
        summary="CISA KEV Match",
        action_required="Emergency patch",
        details={"cve_id": "CVE-2024-21887"},
    )

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = sentinel.dispatch_alert(alert)
        assert res["dispatched"] is True
        assert res["webhook_sent"] is True

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.get_full_url() == webhook_url
        assert "X-orbit-alert-signature" in req.headers or "X-Orbit-Alert-Signature" in req.headers
        assert "X-orbit-timestamp" in req.headers or "X-Orbit-Timestamp" in req.headers


# ==============================================================================
# Project #8: Real-Time Threat Notification Bridge (Discord / Telegram / Matrix)
# ==============================================================================

def test_discord_embed_payload_formatting():
    sentinel = PrivateAlertSentinel()
    alert = PrivateDefensiveAlert(
        alert_id="alert-disc-1",
        event_type="CISA_KEV_MATCH_DETECTED",
        target_domain="vpn.example.com",
        severity="CRITICAL",
        summary="CISA KEV Weaponized 0-Day detected on vpn.example.com: CVE-2024-21887",
        action_required="Apply vendor patch immediately.",
        details={"cve_id": "CVE-2024-21887"},
    )

    payload = sentinel.format_discord_payload(alert)
    assert "embeds" in payload
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert "vpn.example.com" in embed["title"]
    assert embed["color"] == 0xEF4444
    field_names = [f["name"] for f in embed["fields"]]
    assert "Target Domain" in field_names
    assert "Action Required" in field_names


def test_telegram_bot_payload_formatting():
    sentinel = PrivateAlertSentinel(telegram_chat_id="-100123456789")
    alert = PrivateDefensiveAlert(
        alert_id="alert-tg-1",
        event_type="SUBDOMAIN_TAKEOVER_DETECTED",
        target_domain="cdn.example.com",
        severity="CRITICAL",
        summary="High-Confidence Subdomain Takeover on cdn.example.com via AWS S3",
        action_required="Remove orphaned CNAME record.",
        details={"service": "AWS S3"},
    )

    payload = sentinel.format_telegram_payload(alert)
    assert payload["chat_id"] == "-100123456789"
    assert payload["parse_mode"] == "HTML"
    assert "cdn.example.com" in payload["text"]
    assert "AWS S3" in payload["text"]


def test_matrix_room_message_payload_formatting():
    sentinel = PrivateAlertSentinel()
    alert = PrivateDefensiveAlert(
        alert_id="alert-mtx-1",
        event_type="CRITICAL_0DAY_CORRELATED",
        target_domain="auth.example.com",
        severity="CRITICAL",
        summary="Fused KEV+EPSS Threat on auth.example.com: CVE-2024-21887",
        action_required="Emergency vendor remediation mandated.",
        details={"cve_id": "CVE-2024-21887", "epss_score": 0.974},
    )

    payload = sentinel.format_matrix_payload(alert)
    assert payload["msgtype"] == "m.text"
    assert payload["format"] == "org.matrix.custom.html"
    assert "auth.example.com" in payload["body"]
    assert "<strong>" in payload["formatted_body"]


def test_multi_channel_bridge_dispatch_discord_telegram_matrix(tmp_path):
    db_path = tmp_path / "bridge_bb.db"
    bb = Blackboard(db_path=db_path)

    sentinel = PrivateAlertSentinel(
        blackboard=bb,
        discord_webhook_url="https://discord.com/api/webhooks/111/222",
        telegram_bot_token="123456:ABC-DEF",
        telegram_chat_id="-100987654",
        matrix_homeserver_url="https://matrix.example.org",
        matrix_room_id="!secops:example.org",
        matrix_access_token="syt_secret_token",
        enable_desktop_notifications=False,
    )

    alert = PrivateDefensiveAlert(
        alert_id="alert-bridge-all",
        event_type="CISA_KEV_MATCH_DETECTED",
        target_domain="edge.example.com",
        severity="CRITICAL",
        summary="CISA KEV Match on edge.example.com",
        action_required="Isolate appliance",
        details={"cve_id": "CVE-2026-104935"},
    )

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = sentinel.dispatch_alert(alert)
        assert res["dispatched"] is True
        assert res["discord_sent"] is True
        assert res["telegram_sent"] is True
        assert res["matrix_sent"] is True
        assert mock_urlopen.call_count == 3
        assert COMMERCIAL_OUTREACH_FROZEN is True

