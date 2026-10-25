"""orbit_security.private_alerting: Closed-Loop Private Triage & Alerting Sentinel.
===================================================================================
Dispatches secure, authenticated alerts to private operations channels (Slack/Discord
webhooks and native desktop notifications) on high-severity KEV and takeover discoveries.

CRITICAL SAFETY DIRECTIVE:
All commercial Deal Desk dispatches and cold email outreach remain strictly FROZEN.
This module is strictly defensive and internal-facing; it never contacts external prospects.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from orbit_security.notifications import WebhookDispatcher

logger = logging.getLogger("orbit_security.private_alerting")

# STRICT SAFETY INVARIANT: Commercial Deal Desk and outreach are strictly frozen
COMMERCIAL_OUTREACH_FROZEN: bool = True

TARGET_DEFENSIVE_EVENT_TYPES: Set[str] = {
    "CISA_KEV_MATCH_DETECTED",
    "SUBDOMAIN_TAKEOVER_DETECTED",
    "CRITICAL_0DAY_CORRELATED",
    "EPSS_SCORE_EVALUATED",
}


class OutreachFrozenViolation(RuntimeError):
    """Raised when an attempt is made to trigger commercial outreach while frozen."""
    pass


@dataclass
class PrivateDefensiveAlert:
    alert_id: str
    event_type: str
    target_domain: str
    severity: str
    summary: str
    action_required: str
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class PrivateAlertSentinel:
    """Monitors defensive blackboard discoveries and routes private alerts."""

    def __init__(
        self,
        blackboard: Any = None,
        webhook_url: Optional[str] = None,
        signing_secret: Optional[str] = None,
        dedup_ttl_seconds: float = 3600.0,
        enable_desktop_notifications: bool = True,
    ):
        if blackboard is None:
            from orbit_security.blackboard import get_blackboard
            self.bb = get_blackboard()
        else:
            self.bb = blackboard

        self.webhook_url = webhook_url or os.environ.get("ORBIT_PRIVATE_WEBHOOK_URL")
        self.signing_secret = signing_secret or os.environ.get("ORBIT_ALERT_SECRET", "orbit-private-alert-secret-v1")
        self.dedup_ttl = dedup_ttl_seconds
        self.enable_desktop_notifications = enable_desktop_notifications
        self._sent_hashes: Dict[str, float] = {}

    def _compute_hash(self, event_type: str, domain: str, key_token: str) -> str:
        """Deterministic hash for deduplicating identical threat alerts."""
        raw = f"{event_type}:{domain.lower()}:{key_token.lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, alert_hash: str) -> bool:
        """Checks if alert was dispatched within the TTL window."""
        now = time.time()
        last_ts = self._sent_hashes.get(alert_hash)
        if last_ts and (now - last_ts) < self.dedup_ttl:
            return True
        return False

    def mark_dispatched(self, alert_hash: str):
        """Records alert hash into deduplication cache and prunes expired hashes."""
        now = time.time()
        self._sent_hashes[alert_hash] = now
        if len(self._sent_hashes) > 1000:
            self._sent_hashes = {h: ts for h, ts in self._sent_hashes.items() if (now - ts) < self.dedup_ttl}

    def format_alert(self, event_type: str, payload: Dict[str, Any]) -> Optional[PrivateDefensiveAlert]:
        """Synthesizes structured alert from defensive Blackboard event."""
        domain = payload.get("domain") or payload.get("target") or "unknown"

        if event_type == "CISA_KEV_MATCH_DETECTED":
            cve = payload.get("cve_id", "Unknown CVE")
            product = payload.get("product", "Server Component")
            action = payload.get("action_required", "Patch immediately.")
            return PrivateDefensiveAlert(
                alert_id=f"alert-kev-{cve}-{int(time.time())}",
                event_type=event_type,
                target_domain=domain,
                severity="CRITICAL",
                summary=f"CISA KEV Weaponized 0-Day detected on {domain}: {cve} ({product})",
                action_required=action,
                details=payload,
            )

        elif event_type == "SUBDOMAIN_TAKEOVER_DETECTED":
            service = payload.get("service") or payload.get("provider") or "Cloud Service"
            cname = payload.get("cname_target", "")
            action = payload.get("remediation", "Remove orphaned CNAME record or claim resource.")
            return PrivateDefensiveAlert(
                alert_id=f"alert-takeover-{service}-{int(time.time())}",
                event_type=event_type,
                target_domain=domain,
                severity="CRITICAL",
                summary=f"High-Confidence Subdomain Takeover on {domain} via {service} ({cname})",
                action_required=action,
                details=payload,
            )

        elif event_type == "CRITICAL_0DAY_CORRELATED":
            cve = payload.get("cve_id", "Unknown CVE")
            epss = payload.get("epss_score", 0.0)
            return PrivateDefensiveAlert(
                alert_id=f"alert-fusion-{cve}-{int(time.time())}",
                event_type=event_type,
                target_domain=domain,
                severity="CRITICAL",
                summary=f"Fused KEV+EPSS Threat on {domain}: {cve} (EPSS: {epss:.1%}, Actively Exploited)",
                action_required="Emergency vendor remediation mandated.",
                details=payload,
            )

        elif event_type == "EPSS_SCORE_EVALUATED":
            if not payload.get("high_threat"):
                return None
            cve = payload.get("cve_id", "Unknown CVE")
            epss = payload.get("epss_score", 0.0)
            return PrivateDefensiveAlert(
                alert_id=f"alert-epss-{cve}-{int(time.time())}",
                event_type=event_type,
                target_domain=domain,
                severity="HIGH",
                summary=f"High Exploit Probability on {domain}: {cve} (EPSS: {epss:.1%})",
                action_required="Audit external exposure and schedule patching window.",
                details=payload,
            )

        return None

    def sign_alert_payload(self, body_bytes: bytes, timestamp: float) -> str:
        """Signs alert webhook payload with HMAC-SHA256."""
        msg = f"{int(timestamp)}:".encode("utf-8") + body_bytes
        return hmac.new(self.signing_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

    def dispatch_alert(self, alert: PrivateDefensiveAlert, force: bool = False) -> Dict[str, Any]:
        """Dispatches alert to private webhook and desktop notification with deduplication."""
        # Commercial guard: assert frozen
        if not COMMERCIAL_OUTREACH_FROZEN:
            raise OutreachFrozenViolation("Commercial outreach must be strictly frozen.")

        # Compute deduplication token
        key_token = alert.details.get("cve_id") or alert.details.get("service") or alert.summary
        alert_hash = self._compute_hash(alert.event_type, alert.target_domain, key_token)

        if not force and self.is_duplicate(alert_hash):
            logger.info(f"Skipping duplicate alert for {alert.target_domain} ({key_token})")
            return {"dispatched": False, "reason": "duplicate_within_ttl", "alert_id": alert.alert_id}

        results: Dict[str, Any] = {
            "dispatched": True,
            "alert_id": alert.alert_id,
            "webhook_sent": False,
            "desktop_notified": False,
        }

        # 1. Desktop Notification
        if self.enable_desktop_notifications:
            title = f"🛡️ Orbit Alert: [{alert.severity}] {alert.target_domain}"
            msg = f"{alert.summary}\nAction: {alert.action_required}"
            try:
                results["desktop_notified"] = WebhookDispatcher.send_windows_toast(title, msg)
            except Exception as ex:
                logger.debug(f"Desktop notification failed: {ex}")

        # 2. Private Webhook
        if self.webhook_url:
            now_ts = time.time()
            envelope = asdict(alert)
            body_bytes = json.dumps(envelope, default=str).encode("utf-8")
            sig = self.sign_alert_payload(body_bytes, now_ts)
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "OrbitSecurity-PrivateAlerting/1.0",
                "X-Orbit-Alert-Signature": sig,
                "X-Orbit-Timestamp": str(now_ts),
            }
            try:
                req = urllib.request.Request(self.webhook_url, data=body_bytes, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    results["webhook_sent"] = resp.status in (200, 204)
            except Exception as ex:
                logger.warning(f"Private webhook alert failed: {ex}")

        # 3. Publish private alert log to Blackboard WAL
        if self.bb:
            try:
                self.bb.publish(
                    event_type="PRIVATE_DEFENSIVE_ALERT_DISPATCHED",
                    payload={
                        "alert_id": alert.alert_id,
                        "event_type": alert.event_type,
                        "domain": alert.target_domain,
                        "severity": alert.severity,
                        "summary": alert.summary,
                        "desktop_notified": results["desktop_notified"],
                        "webhook_sent": results["webhook_sent"],
                    },
                    source="private_alert_sentinel",
                    topic="telemetry",
                )
            except Exception as ex:
                logger.debug(f"Failed to record alert event to blackboard: {ex}")

        self.mark_dispatched(alert_hash)
        return results

    def triage_event(self, event_type: str, payload: Dict[str, Any], force: bool = False) -> Optional[Dict[str, Any]]:
        """Processes a single incoming threat event through the private alert pipeline."""
        if event_type not in TARGET_DEFENSIVE_EVENT_TYPES:
            return None

        alert = self.format_alert(event_type, payload)
        if not alert:
            return None

        return self.dispatch_alert(alert, force=force)

    def trigger_commercial_outreach(self, *args, **kwargs):
        """Strict guard preventing commercial outreach."""
        raise OutreachFrozenViolation(
            "CRITICAL: Commercial Deal Desk and outreach are strictly frozen per user directive."
        )
