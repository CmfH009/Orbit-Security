from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
import time
from typing import Any, Dict, List, Optional

CANONICAL_PRICING: Dict[str, Dict[str, Any]] = {
    "monitoring": {
        "monthly": 499,
        "annual": 4990,
        "features": ["Continuous DNS radar", "DMARC/SPF monitor", "Subdomain takeover watcher", "Daily diffs"]
    },
    "remediation": {
        "monthly": 1499,
        "annual": 14990,
        "features": ["Active patching", "Direct DNS takeover mitigation", "DMARC alignment hands-on", "Monthly pentest audit"]
    },
    "enterprise": {
        "monthly": 4999,
        "features": ["Up to 25 agency client domains", "White-label client portals", "Dedicated Slack/email channel", "4-hour SLA"]
    }
}

CANONICAL_URLS: Dict[str, str] = {
    "booking": "https://cal.com/orbit-security",
    "portal_root": "https://orbit-security.com/portals/",
    "sample_audit": "https://orbit-security.com/sample_audit.pdf"
}

FORBIDDEN_PROMISES: List[str] = [
    "soc 2", "soc2", "iso 27001", "iso27001", "hardware", "on-premise install",
    "physical security", "guaranteed zero bugs", "pci-dss certification"
]

ADVERSARIAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b"),
    re.compile(r"(?i)\bsystem\s+prompt\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+in\s+developer\s+mode\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?security\s+polic(?:y|ies)\b"),
    re.compile(r"(?i)\bjailbreak\b"),
]


class PromptInjectionSanitizer:
    """Sanitizes inbound email text before LLM exposure."""

    @classmethod
    def sanitize(cls, raw_text: str, max_chars: int = 4000) -> str:
        if not raw_text:
            return ""
        # 1. Truncate
        text = str(raw_text)[:max_chars]

        # 2. Neutralize XML and code fences (case-insensitive)
        text = re.sub(
            r"(?i)<(/?)(\s*)(system|prompt|context)(\s*)>",
            lambda m: f"[{m.group(1)}{m.group(3).lower()}]",
            text,
        )
        text = text.replace("```", "'''")

        # 3. Redact known adversarial injection patterns
        for pattern in ADVERSARIAL_PATTERNS:
            text = pattern.sub("[REDACTED_ADVERSARIAL_INPUT]", text)

        return text.strip()


class GuardrailStatus(str, Enum):
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    HELD_FOR_REVIEW = "HELD_FOR_REVIEW"


@dataclass
class GuardrailEvaluationResult:
    status: GuardrailStatus
    violation_layer: Optional[str] = None
    violation_code: Optional[str] = None
    reason: Optional[str] = None


class AutonomousReplyGuardrail:
    """Synchronous 4-layer deterministic safety gate for outbound email replies."""

    def __init__(self, max_global_per_hour: int = 10, domain_window_seconds: int = 86400):
        self.max_global_per_hour = max_global_per_hour
        self.domain_window_seconds = domain_window_seconds
        self._domain_history: Dict[str, List[float]] = {}
        self._global_history: List[float] = []

    def evaluate(
        self,
        draft_reply: str,
        sender: str,
        subject: str,
        inbound_headers: Optional[Dict[str, str]] = None,
        leads_state: Optional[Dict[str, Any]] = None,
    ) -> GuardrailEvaluationResult:
        now = time.time()
        inbound_headers = inbound_headers or {}
        leads_state = leads_state or {}
        sender_lower = (sender or "").strip().lower()
        domain = sender_lower.split("@")[-1] if "@" in sender_lower else ""

        # --- Layer 1: Anti-Loop & Header Check ---
        leads_dict = (leads_state.get("leads") or {}) if isinstance(leads_state, dict) else {}
        lead_entry = leads_dict.get(sender_lower) or {}
        if lead_entry.get("auto_replies_count", 0) >= 1:
            return GuardrailEvaluationResult(
                status=GuardrailStatus.BLOCKED,
                violation_layer="LAYER_1_ANTI_LOOP",
                violation_code="ANTI_LOOP_DETECTED",
                reason=f"Auto-reply already dispatched to {sender_lower} in this thread."
            )

        headers_lower = {k.lower(): v for k, v in inbound_headers.items()}
        auto_sub = headers_lower.get("auto-submitted", "").lower()
        if auto_sub and auto_sub != "no":
            return GuardrailEvaluationResult(
                status=GuardrailStatus.BLOCKED,
                violation_layer="LAYER_1_ANTI_LOOP",
                violation_code="AUTO_RESPONDER_DETECTED",
                reason=f"Inbound header Auto-Submitted: {auto_sub}"
            )
        if "x-autoreply" in headers_lower:
            return GuardrailEvaluationResult(
                status=GuardrailStatus.BLOCKED,
                violation_layer="LAYER_1_ANTI_LOOP",
                violation_code="AUTO_RESPONDER_DETECTED",
                reason="X-Autoreply header detected."
            )
        if re.search(r"(?i)^(?:automatic reply|out of office|undeliverable|delivery status notification)", subject or ""):
            return GuardrailEvaluationResult(
                status=GuardrailStatus.BLOCKED,
                violation_layer="LAYER_1_ANTI_LOOP",
                violation_code="AUTO_RESPONDER_DETECTED",
                reason="Subject matches automated response pattern."
            )

        # --- Layer 2: Leak & Persona Guard ---
        draft_reply = draft_reply or ""
        body_lower = draft_reply.lower()
        ai_markers = ["as an ai", "language model", "system prompt", "gemini", "ollama", "chatgpt"]
        for marker in ai_markers:
            if marker in body_lower:
                return GuardrailEvaluationResult(
                    status=GuardrailStatus.BLOCKED,
                    violation_layer="LAYER_2_LEAK_GUARD",
                    violation_code="AI_BOILERPLATE_LEAK",
                    reason=f"Draft reply contains prohibited AI marker: '{marker}'"
                )

        if re.search(r"[A-Za-z]:\\[\w\\]+|\/(?:home|var|usr|etc)\/[\w\/]+", draft_reply):
            return GuardrailEvaluationResult(
                status=GuardrailStatus.BLOCKED,
                violation_layer="LAYER_2_LEAK_GUARD",
                violation_code="SYSTEM_PATH_LEAK",
                reason="Draft reply leaks filesystem paths."
            )

        # --- Layer 3: Canonical Facts Gate ---
        price_matches = re.findall(r"\$(\d{1,3}(?:,\d{3})*|\d+)", draft_reply)
        valid_prices = {499, 1499, 4999, 4990, 14990}
        for match in price_matches:
            val = int(match.replace(",", ""))
            if val not in valid_prices:
                return GuardrailEvaluationResult(
                    status=GuardrailStatus.BLOCKED,
                    violation_layer="LAYER_3_CANONICAL_FACTS",
                    violation_code="UNAUTHORIZED_PRICE_DISCREPANCY",
                    reason=f"Price ${val} is not a canonical Orbit Security tier price."
                )

        for promise in FORBIDDEN_PROMISES:
            if re.search(rf"\b{re.escape(promise)}\b", body_lower):
                return GuardrailEvaluationResult(
                    status=GuardrailStatus.BLOCKED,
                    violation_layer="LAYER_3_CANONICAL_FACTS",
                    violation_code="UNAUTHORIZED_SCOPE_PROMISE",
                    reason=f"Draft promises out-of-scope deliverable: '{promise}'"
                )

        # --- Layer 4: Rate Limiter & Suppression ---
        domain_times = [t for t in self._domain_history.get(domain, []) if now - t < self.domain_window_seconds]
        if len(domain_times) >= 1:
            return GuardrailEvaluationResult(
                status=GuardrailStatus.BLOCKED,
                violation_layer="LAYER_4_RATE_LIMIT",
                violation_code="DOMAIN_RATE_LIMIT_EXCEEDED",
                reason=f"Already sent 1 reply to domain {domain} in past 24 hours."
            )

        self._global_history = [t for t in self._global_history if now - t < 3600]
        if len(self._global_history) >= self.max_global_per_hour:
            return GuardrailEvaluationResult(
                status=GuardrailStatus.BLOCKED,
                violation_layer="LAYER_4_RATE_LIMIT",
                violation_code="GLOBAL_BURST_CAP_EXCEEDED",
                reason="Global hourly auto-reply cap of 10 reached."
            )

        # All checks passed
        return GuardrailEvaluationResult(
            status=GuardrailStatus.APPROVED,
            violation_layer=None,
            violation_code=None,
            reason="All 4 guardrail integrity checks passed."
        )

    def record_dispatch(self, sender: str) -> None:
        """Records a successful dispatch into rolling rate-limit token buckets."""
        now = time.time()
        domain = sender.strip().lower().split("@")[-1] if "@" in sender else "unknown"
        if domain not in self._domain_history:
            self._domain_history[domain] = []
        self._domain_history[domain].append(now)
        self._global_history.append(now)
