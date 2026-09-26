from unittest.mock import MagicMock, patch
import pytest

from orbit_security.models import Finding, Severity
from orbit_security.notifications import AlertPayload, WebhookDispatcher


def test_alert_deduplication():
    dispatcher = WebhookDispatcher(deduplication_ttl_seconds=3600)
    finding = Finding(
        title="Dangling CNAME to Unbounce",
        severity=Severity.CRITICAL,
        category="takeover",
        description="Abandoned SaaS subdomain",
        remediation="Remove CNAME",
        target="promo.example.com",
    )
    payload = AlertPayload(
        client_name="Test Agency Client",
        apex_domain="example.com",
        current_score=65,
        current_grade="C",
        previous_score=95,
        previous_grade="A+",
        findings=[finding],
    )

    assert dispatcher.is_duplicate(payload) is False
    dispatcher.mark_sent(payload)
    assert dispatcher.is_duplicate(payload) is True


def test_slack_block_kit_formatting():
    dispatcher = WebhookDispatcher()
    finding = Finding(
        title="Missing DMARC Enforcement",
        severity=Severity.HIGH,
        category="email",
        description="p=none allows spoofing",
        remediation="Set p=quarantine",
        target="_dmarc.example.com",
    )
    payload = AlertPayload(
        client_name="Apex Client",
        apex_domain="example.com",
        current_score=75,
        current_grade="B",
        previous_score=90,
        previous_grade="A",
        findings=[finding],
    )

    slack_data = dispatcher.format_slack_blocks(payload)
    assert "blocks" in slack_data
    blocks = slack_data["blocks"]
    assert any("Apex Client" in str(b) for b in blocks)
    assert any("Missing DMARC Enforcement" in str(b) for b in blocks)


def test_discord_embed_formatting():
    dispatcher = WebhookDispatcher()
    finding = Finding(
        title="Subdomain Takeover Risk",
        severity=Severity.CRITICAL,
        category="takeover",
        description="Unbounce 404",
        remediation="Delete record",
        target="promo.client.com",
    )
    payload = AlertPayload(
        client_name="VIP Client",
        apex_domain="client.com",
        current_score=50,
        current_grade="C",
        previous_score=100,
        previous_grade="A+",
        findings=[finding],
    )

    discord_data = dispatcher.format_discord_embed(payload)
    assert "embeds" in discord_data
    embed = discord_data["embeds"][0]
    assert "VIP Client" in embed["title"]
    assert embed["color"] == 0xEF4444  # Red for CRITICAL


@patch("urllib.request.urlopen")
def test_dispatch_webhook_success(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    dispatcher = WebhookDispatcher()
    success = dispatcher.dispatch_webhook("https://hooks.slack.com/services/mock", {"text": "hello"})
    assert success is True
