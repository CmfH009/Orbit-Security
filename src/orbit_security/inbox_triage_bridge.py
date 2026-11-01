from __future__ import annotations

from enum import Enum
import json
import logging
import os
from typing import Any, Optional
import urllib.request
import urllib.error
from pydantic import BaseModel, Field

from orbit_security.inbox_guardrail import PromptInjectionSanitizer

logger = logging.getLogger("orbit_security.inbox_triage_bridge")


class TriageAction(str, Enum):
    AUTONOMOUS_REPLY = "AUTONOMOUS_REPLY"
    ESCALATE_TO_CARSON = "ESCALATE_TO_CARSON"
    ARCHIVE_NO_ACTION = "ARCHIVE_NO_ACTION"
    SUPPRESS_UNSUBSCRIBE = "SUPPRESS_UNSUBSCRIBE"


class InboundTriageDecision(BaseModel):
    """Structured decision contract for inbound email triage."""
    sender: str
    subject: str
    intent: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_action: TriageAction
    suggested_tier: Optional[str] = None
    portal_link_requested: bool = False
    draft_reply_subject: Optional[str] = None
    draft_reply_body: Optional[str] = None
    provider_resolved: str = "GEMINI_CLI"


class InboxTriageBridge:
    """Manages 3-tier failover for inbound email triage and response generation."""

    def __init__(self, gemini_bridge: Optional[Any] = None, ollama_url: Optional[str] = None):
        if gemini_bridge is not None:
            self.gemini_bridge = gemini_bridge
        else:
            try:
                from orbit_security.gemini_cli_bridge import GeminiCLIBridge
                self.gemini_bridge = GeminiCLIBridge()
            except Exception:
                self.gemini_bridge = None
        self.ollama_url = ollama_url or os.environ.get("ORBIT_OLLAMA_URL", "http://127.0.0.1:11434/api/chat")

    def triage_inbound_message(
        self,
        sender: str,
        subject: str,
        body: str,
        timeout: float = 15.0,
    ) -> InboundTriageDecision:
        clean_body = PromptInjectionSanitizer.sanitize(body)

        # 1. Tier 1: Gemini CLI Subprocess
        if self.gemini_bridge is not None:
            try:
                prompt = self._build_prompt(sender, subject, clean_body)
                res = self.gemini_bridge.execute_json(
                    prompt=prompt,
                    schema=InboundTriageDecision,
                    timeout=timeout,
                )
                if res and res.success and res.data:
                    if isinstance(res.data, dict):
                        data = res.data
                    elif hasattr(res.data, "model_dump"):
                        data = res.data.model_dump()
                    else:
                        data = res.data.dict()
                    data["provider_resolved"] = "GEMINI_CLI"
                    return InboundTriageDecision(**data)
            except Exception as ex:
                logger.warning(f"Gemini CLI bridge failed ({ex}); attempting Tier 2 Ollama")

        # 2. Tier 2: Local Ollama
        try:
            return self._call_local_ollama(sender, subject, clean_body, timeout=timeout)
        except Exception as ex:
            logger.warning(f"Local Ollama triage failed ({ex}); attempting Tier 3 Fallback")

        # 3. Tier 3: Deterministic Safe Fallback
        return self._deterministic_fallback(sender, subject, clean_body)

    def _build_prompt(self, sender: str, subject: str, clean_body: str) -> str:
        return (
            "You are Orbit Security's autonomous deal desk concierge.\n"
            "Analyze this inbound agency email and output a strict JSON InboundTriageDecision:\n"
            f"Sender: {sender}\n"
            f"Subject: {subject}\n"
            f"Body:\n{clean_body}\n\n"
            "Canonical Pricing: Monitoring: $499/mo, Remediation: $1,499/mo, Enterprise: $4,999/mo.\n"
            "Booking link: https://cal.com/orbit-security\n"
            "Sign all replies as:\nBest,\nCarson Haynes\nFounder, Orbit Security\n"
        )

    def _call_local_ollama(
        self, sender: str, subject: str, body: str, timeout: float = 15.0
    ) -> InboundTriageDecision:
        prompt = self._build_prompt(sender, subject, body)
        req_payload = {
            "model": "qwen2.5-coder:7b-instruct-q4_K_M",
            "messages": [{"role": "user", "content": prompt}],
            "format": InboundTriageDecision.model_json_schema(),
            "options": {"temperature": 0.1},
            "keep_alive": "0",
            "stream": False,
        }
        req = urllib.request.Request(
            self.ollama_url,
            data=json.dumps(req_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw = json.loads(resp.read().decode("utf-8"))
                content = raw.get("message", {}).get("content", "{}")
                data = json.loads(content)
                data["provider_resolved"] = "OLLAMA_LOCAL"
                return InboundTriageDecision(**data)
        raise RuntimeError("Ollama responded with non-200 status")

    def _deterministic_fallback(
        self, sender: str, subject: str, body: str
    ) -> InboundTriageDecision:
        lower = body.lower()
        if any(w in lower for w in ["price", "cost", "how much", "rate", "fee"]):
            intent = "INQUIRY_PRICING"
            action = TriageAction.AUTONOMOUS_REPLY
            reply = (
                "Hi there,\n\n"
                "Thanks for reaching out to Orbit Security. Our continuous perimeter monitoring "
                "retainer is $499/mo, and active remediation is $1,499/mo.\n\n"
                "You can book an intro briefing directly with me here: https://cal.com/orbit-security\n\n"
                "Best,\nCarson Haynes\nFounder, Orbit Security"
            )
        else:
            intent = "REQUEST_HUMAN"
            action = TriageAction.ESCALATE_TO_CARSON
            reply = (
                "Hi there,\n\n"
                "Thanks for contacting Orbit Security. Carson Haynes (Founder) has received your note "
                "and will follow up directly within 24 hours.\n\n"
                "Best,\nCarson Haynes\nFounder, Orbit Security"
            )

        return InboundTriageDecision(
            sender=sender,
            subject=f"Re: {subject}" if not subject.lower().startswith("re:") else subject,
            intent=intent,
            confidence=0.7,
            reasoning="Deterministic template fallback used because LLM endpoints were unreachable.",
            recommended_action=action,
            suggested_tier="monitoring",
            portal_link_requested=False,
            draft_reply_subject=f"Re: {subject}" if not subject.lower().startswith("re:") else subject,
            draft_reply_body=reply,
            provider_resolved="DETERMINISTIC_FALLBACK",
        )
