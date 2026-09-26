"""Orbit Security Webhook Notifications Dispatcher (notifications.py).

Dispatches rich, real-time alert payloads to Slack and Discord webhooks
when client domain drift, dangling CNAME takeovers, or security regressions occur.
Includes alert deduplication and safe failure handling.
"""

from dataclasses import dataclass, field
import datetime
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

from orbit_security.models import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class AlertPayload:
    client_name: str
    apex_domain: str
    current_score: int
    current_grade: str
    previous_score: Optional[int]
    previous_grade: Optional[str]
    findings: List[Finding]
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


class WebhookDispatcher:
    def __init__(self, deduplication_ttl_seconds: int = 3600):
        self.deduplication_ttl = deduplication_ttl_seconds
        self._sent_cache: Dict[str, float] = {}

    def _compute_hash(self, payload: AlertPayload) -> str:
        """Computes deterministic hash for deduplication based on domain, score, and finding titles."""
        finding_keys = sorted([f"{f.severity}:{f.category}:{f.title}" for f in payload.findings])
        raw = f"{payload.apex_domain}:{payload.current_score}:{','.join(finding_keys)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, payload: AlertPayload) -> bool:
        """Checks if identical alert was dispatched recently."""
        h = self._compute_hash(payload)
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if h in self._sent_cache:
            if now - self._sent_cache[h] < self.deduplication_ttl:
                return True
        return False

    def mark_sent(self, payload: AlertPayload):
        """Records hash into deduplication cache."""
        h = self._compute_hash(payload)
        self._sent_cache[h] = datetime.datetime.now(datetime.timezone.utc).timestamp()

    def format_slack_blocks(self, payload: AlertPayload) -> Dict[str, Any]:
        """Builds Slack Block Kit payload with colored status and breakdown."""
        score_diff = ""
        if payload.previous_score is not None:
            delta = payload.current_score - payload.previous_score
            sign = "+" if delta > 0 else ""
            score_diff = f" (Drift: {sign}{delta} pts from {payload.previous_score})"

        has_critical = any(f.severity == Severity.CRITICAL for f in payload.findings)
        header_emoji = "🚨" if has_critical else ("⚠️" if payload.current_score < 75 else "🛡️")

        critical_count = sum(1 for f in payload.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in payload.findings if f.severity == Severity.HIGH)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{header_emoji} Orbit Security Alert: {payload.client_name}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Target Domain:*\n`{payload.apex_domain}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Hygiene Score:*\n*{payload.current_score}/100* (Grade: {payload.current_grade}){score_diff}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical Findings:*\n{critical_count}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*High Risk Findings:*\n{high_count}",
                    },
                ],
            },
            {"type": "divider"},
        ]

        # Add top findings
        if payload.findings:
            findings_text = ""
            for f in payload.findings[:5]:
                severity_icon = "🔴" if f.severity == Severity.CRITICAL else ("🟠" if f.severity == Severity.HIGH else "🟡")
                findings_text += f"{severity_icon} *[{f.severity}]* {f.title} — `{f.target}`\n"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Key Security Findings:*\n{findings_text}",
                },
            })

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Orbit Sentinel Engine // Automated Fleet Patrol // {payload.timestamp[:19]} UTC",
                }
            ],
        })

        return {"blocks": blocks}

    def format_discord_embed(self, payload: AlertPayload) -> Dict[str, Any]:
        """Builds Discord Embed payload."""
        has_critical = any(f.severity == Severity.CRITICAL for f in payload.findings)
        color = 0xEF4444 if has_critical else (0xF59E0B if payload.current_score < 75 else 0x10B981)

        fields = [
            {"name": "Apex Domain", "value": f"`{payload.apex_domain}`", "inline": True},
            {"name": "Hygiene Score", "value": f"**{payload.current_score}/100** ({payload.current_grade})", "inline": True},
            {"name": "Total Findings", "value": str(len(payload.findings)), "inline": True},
        ]

        if payload.findings:
            finding_lines = []
            for f in payload.findings[:5]:
                prefix = "🚨" if f.severity == Severity.CRITICAL else ("⚠️" if f.severity == Severity.HIGH else "ℹ️")
                finding_lines.append(f"{prefix} **[{f.severity}]** {f.title} (`{f.target}`)")
            fields.append({
                "name": "Top Exposure Findings",
                "value": "\n".join(finding_lines),
                "inline": False,
            })

        embed = {
            "title": f"🛡️ Orbit Sentinel Alert: {payload.client_name}",
            "description": f"Automated perimeter scan detected posture update for `{payload.apex_domain}`.",
            "color": color,
            "fields": fields,
            "footer": {
                "text": "Orbit Security // Client Retainer Sentinel",
            },
            "timestamp": payload.timestamp,
        }

        return {"embeds": [embed]}

    def dispatch_webhook(
        self,
        webhook_url: str,
        payload_data: Dict[str, Any],
        timeout_seconds: float = 5.0,
    ) -> bool:
        """Sends JSON payload via HTTP POST to webhook endpoint."""
        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload_data).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "OrbitSecurity-Sentinel/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
                return response.status in (200, 204)
        except urllib.error.HTTPError as e:
            logger.warning(f"Webhook HTTP error {e.code}: {e.reason}")
            return False
        except Exception as e:
            logger.warning(f"Webhook dispatch failed: {str(e)}")
            return False

    def send_alert(
        self,
        payload: AlertPayload,
        slack_webhook_url: Optional[str] = None,
        discord_webhook_url: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, bool]:
        """Dispatches alerts to configured endpoints with deduplication."""
        results = {"slack": False, "discord": False}

        if not force and self.is_duplicate(payload):
            logger.info(f"Skipping duplicate alert for {payload.apex_domain}")
            return results

        if slack_webhook_url:
            slack_data = self.format_slack_blocks(payload)
            results["slack"] = self.dispatch_webhook(slack_webhook_url, slack_data)

        if discord_webhook_url:
            discord_data = self.format_discord_embed(payload)
            results["discord"] = self.dispatch_webhook(discord_webhook_url, discord_data)

        if results["slack"] or results["discord"]:
            self.mark_sent(payload)

        return results
