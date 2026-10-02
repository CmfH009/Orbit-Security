"""Orbit Security Circuit Breaker & Incident Sentinel (circuit_breaker.py).

Prevents account suspension, shadowbanning, and runaway automated loops by tripping
into QUARANTINE mode upon detecting auth invalidation, CAPTCHA challenges, or rate limits.
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime
from enum import Enum
import json
import logging
import os
import random
import time
from typing import Any, Dict, Optional, Tuple

from orbit_security.notifications import WebhookDispatcher
from orbit_security.social_state import SocialStateManager

logger = logging.getLogger(__name__)


class BreakerState(str, Enum):
    CLOSED = "CLOSED"        # Normal operations
    HALF_OPEN = "HALF_OPEN"  # Single probe action allowed
    OPEN = "OPEN"            # Tripped / Operations quarantined


class TriggerType(str, Enum):
    AUTH = "AUTH"                  # Logged out, cookies dead, 401/403
    CAPTCHA = "CAPTCHA"            # Arkose challenge, bot verification
    RATE_LIMIT = "RATE_LIMIT"      # 429 Too Many Requests, limit modal
    NETWORK = "NETWORK"            # Socket drop, DNS failure


@dataclass
class BreakerConfig:
    auth_cooldown_seconds: int = 86400       # 24h (requires operator manual review)
    captcha_cooldown_seconds: int = 10800    # 3 hours
    rate_limit_cooldown_seconds: int = 3600  # 1 hour
    network_base_cooldown_seconds: int = 300 # 5 minutes


class SocialCircuitBreaker:
    """Monitors platform responses, trips on anti-bot indicators, and sends alerts."""

    def __init__(
        self,
        state_manager: SocialStateManager,
        config: Optional[BreakerConfig] = None,
        webhook_dispatcher: Optional[WebhookDispatcher] = None,
    ):
        self.state_manager = state_manager
        self.config = config or BreakerConfig()
        self.webhook_dispatcher = webhook_dispatcher or WebhookDispatcher()

        self.state: BreakerState = BreakerState.CLOSED
        self.last_trip_time: float = 0.0
        self.current_cooldown: float = 0.0
        self.trip_reason: Optional[str] = None
        self.trip_type: Optional[TriggerType] = None
        self.consecutive_failures: int = 0

    def is_available(self) -> Tuple[bool, str]:
        """Checks whether the circuit breaker permits social actions."""
        now = time.time()
        if self.state == BreakerState.CLOSED:
            return True, "Nominal"

        if self.state == BreakerState.OPEN:
            elapsed = now - self.last_trip_time
            if elapsed >= self.current_cooldown:
                logger.info("Circuit breaker cooldown expired. Entering HALF_OPEN probe state.")
                self.state = BreakerState.HALF_OPEN
                return True, "Half-Open Probe Mode"
            else:
                remaining_s = int(self.current_cooldown - elapsed)
                return False, f"Circuit OPEN ({self.trip_type}): {remaining_s}s remaining"

        if self.state == BreakerState.HALF_OPEN:
            return True, "Half-Open Probe Active"

        return False, "Unknown Breaker State"

    def trip(self, trigger: TriggerType, reason: str):
        """Trips the circuit breaker into OPEN quarantine mode and emits alert."""
        self.state = BreakerState.OPEN
        self.last_trip_time = time.time()
        self.trip_type = trigger
        self.trip_reason = reason
        self.consecutive_failures += 1

        # Calculate cooldown with exponential backoff and jitter
        if trigger == TriggerType.AUTH:
            cooldown = self.config.auth_cooldown_seconds
        elif trigger == TriggerType.CAPTCHA:
            cooldown = self.config.captcha_cooldown_seconds
        elif trigger == TriggerType.RATE_LIMIT:
            # 1hr base, exponentially scaled if repeated
            base = self.config.rate_limit_cooldown_seconds
            cooldown = min(14400, base * (2 ** (self.consecutive_failures - 1)))
        elif trigger == TriggerType.NETWORK:
            base = self.config.network_base_cooldown_seconds
            cooldown = min(3600, base * (2 ** (self.consecutive_failures - 1)))
        else:
            cooldown = 1800

        # Inject jitter (+/- 10%)
        jitter = random.uniform(-0.1, 0.1) * cooldown
        self.current_cooldown = max(60.0, cooldown + jitter)

        logger.critical(
            f"🚨 [CIRCUIT BREAKER TRIPPED] Type: {trigger.value} | Reason: {reason} | "
            f"Cooldown: {int(self.current_cooldown)}s"
        )

        # Log incident in persistent SQLite
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.state_manager._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO circuit_incidents 
                    (breaker_type, status_entered, trigger_detail, cooldown_seconds, tripped_at_utc)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (trigger.value, "OPEN", reason, int(self.current_cooldown), now_utc),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Error persisting circuit incident: {e}")

        # Send Webhook Alert
        self._dispatch_webhook_alert(trigger, reason, int(self.current_cooldown))

    def record_probe_success(self):
        """Called when a probe in HALF_OPEN succeeds, restoring CLOSED state."""
        if self.state == BreakerState.HALF_OPEN:
            logger.info("Probe succeeded. Circuit Breaker restored to CLOSED (Nominal).")
            self.state = BreakerState.CLOSED
            self.consecutive_failures = 0
            self.trip_reason = None
            self.trip_type = None

    def reset(self):
        """Forces manual reset back to CLOSED nominal state."""
        self.state = BreakerState.CLOSED
        self.consecutive_failures = 0
        self.trip_reason = None
        self.trip_type = None
        self.current_cooldown = 0.0
        logger.info("Circuit breaker manually reset to CLOSED.")

    def _dispatch_webhook_alert(self, trigger: TriggerType, reason: str, cooldown_s: int):
        """Sends rich alert payload to Discord and Slack via WebhookDispatcher."""
        title = f"🚨 Orbit Security Social Sentinel: Circuit Tripped [{trigger.value}]"
        desc = (
            f"**Action Quarantined:** Social actions halted immediately.\n"
            f"**Reason:** `{reason}`\n"
            f"**Cooldown:** `{cooldown_s // 60}` minutes ({cooldown_s}s)\n"
            f"**Trigger Type:** `{trigger.value}`\n"
            f"**Timestamp:** `{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`"
        )

        # Build Discord embed
        embed = {
            "title": title,
            "description": desc,
            "color": 0xFF0033 if trigger in (TriggerType.AUTH, TriggerType.CAPTCHA) else 0xFFA500,
            "footer": {"text": "Project ORBIT Autonomous Sentinel"},
        }
        discord_payload = {"embeds": [embed]}

        # Build Slack block payload
        slack_payload = {
            "text": f"*{title}*\n{desc}"
        }

        # Dispatch using WebhookDispatcher
        discord_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        if discord_url:
            try:
                self.webhook_dispatcher.dispatch_webhook(
                    discord_url,
                    discord_payload,
                )
            except Exception as e:
                logger.warning(f"Failed to dispatch Discord alert: {e}")

        slack_url = os.getenv("SLACK_WEBHOOK_URL", "")
        if slack_url:
            try:
                self.webhook_dispatcher.dispatch_webhook(
                    slack_url,
                    slack_payload,
                )
            except Exception as e:
                logger.warning(f"Failed to dispatch Slack alert: {e}")
