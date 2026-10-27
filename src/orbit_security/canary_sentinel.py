"""Orbit Security: Live Adversarial Canary Honeypot & Tripwire Sentinel (canary_sentinel.py).
====================================================================================
Deploys and tracks canary assets (fake AWS tokens, dummy database strings, unique DNS tokens)
across decommissioned or sensitive perimeters. Probing attempts trigger immediate
intruder alerts on the SQLite WAL Blackboard.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from orbit_security.blackboard import Blackboard, get_blackboard

logger = logging.getLogger("orbit_security.canary_sentinel")

TOPIC_CANARY = "canary"
EVENT_CANARY_TRIPWIRE_TRIGGERED = "CANARY_TRIPWIRE_TRIGGERED"
EVENT_CANARY_TOKEN_MINTED = "CANARY_TOKEN_MINTED"


@dataclass
class CanaryToken:
    token_id: str
    token_type: str  # 'aws_key', 'dns_cname', 'http_webhook', 'db_conn'
    target_perimeter: str
    decoy_payload: str
    created_at: str
    status: str = "ACTIVE"
    trigger_count: int = 0
    last_triggered_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CanaryTokenRegistry:
    """Manages creation, verification, and persistence of adversarial canary tokens."""

    def __init__(self, blackboard: Optional[Blackboard] = None):
        self.blackboard = blackboard or get_blackboard()
        self._tokens: Dict[str, CanaryToken] = {}

    def mint_token(self, token_type: str, target_perimeter: str) -> CanaryToken:
        """Mints a unique decoy token associated with a monitored perimeter."""
        raw_id = secrets.token_hex(8)
        created_at = datetime.now(timezone.utc).isoformat()

        if token_type == "aws_key":
            key_id = f"AKIA{raw_id[:16].upper()}"
            decoy_payload = f"aws_access_key_id = {key_id}\naws_secret_access_key = {secrets.token_hex(20)}"
            token_id = key_id
        elif token_type == "dns_cname":
            token_id = f"canary-{raw_id[:8]}"
            decoy_payload = f"{token_id}.canary.{target_perimeter}"
        else:
            token_id = f"canary-http-{raw_id}"
            decoy_payload = f"https://canary.orbit-security.dev/t/{token_id}"

        token = CanaryToken(
            token_id=token_id,
            token_type=token_type,
            target_perimeter=target_perimeter,
            decoy_payload=decoy_payload,
            created_at=created_at,
        )
        self._tokens[token_id] = token

        self.blackboard.publish(
            event_type=EVENT_CANARY_TOKEN_MINTED,
            topic=TOPIC_CANARY,
            payload=token.to_dict(),
            source="canary_sentinel",
        )
        return token

    def record_tripwire_hit(
        self,
        token_id: str,
        source_ip: str,
        user_agent: str = "Unknown",
        request_details: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Handles a triggered tripwire token, increments count, and emits high-priority alert."""
        token = self._tokens.get(token_id)
        if not token:
            logger.warning("Unregistered canary token probe detected: %s", token_id)
            return None

        token.trigger_count += 1
        now_utc = datetime.now(timezone.utc).isoformat()
        token.last_triggered_at = now_utc

        alert_payload = {
            "token_id": token.token_id,
            "token_type": token.token_type,
            "target_perimeter": token.target_perimeter,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "trigger_count": token.trigger_count,
            "triggered_at": now_utc,
            "details": request_details or {},
            "severity": "CRITICAL",
        }

        self.blackboard.publish(
            event_type=EVENT_CANARY_TRIPWIRE_TRIGGERED,
            topic=TOPIC_CANARY,
            payload=alert_payload,
            source="canary_sentinel",
        )
        return alert_payload

    def get_token(self, token_id: str) -> Optional[CanaryToken]:
        return self._tokens.get(token_id)

    def active_tokens_count(self) -> int:
        return sum(1 for t in self._tokens.values() if t.status == "ACTIVE")
