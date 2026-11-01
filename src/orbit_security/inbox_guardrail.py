from __future__ import annotations

import re
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

        # 2. Neutralize XML and code fences
        text = text.replace("<system>", "[system]").replace("</system>", "[/system]")
        text = text.replace("<prompt>", "[prompt]").replace("</prompt>", "[/prompt]")
        text = text.replace("<context>", "[context]").replace("</context>", "[/context]")
        text = text.replace("```", "'''")

        # 3. Redact known adversarial injection patterns
        for pattern in ADVERSARIAL_PATTERNS:
            text = pattern.sub("[REDACTED_ADVERSARIAL_INPUT]", text)

        return text.strip()
