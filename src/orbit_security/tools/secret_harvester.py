"""orbit_security.tools.secret_harvester: Client JavaScript Bundle Secret Harvester.

Performs deterministic regex and heuristic analysis against client JavaScript bundles
to discover leaked API tokens, third-party integration secrets, and private cloud resources.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger("orbit_security.tools.secret_harvester")


@dataclass
class SecretMatch:
    pattern_name: str
    matched_value: str
    redacted_value: str
    confidence: str
    context_snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecretHarvester:
    """Detects high-entropy and structured API secrets embedded in client scripts."""

    PATTERNS = [
        (
            "AWS Access Key ID",
            re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
            "High",
        ),
        (
            "Stripe Live Secret Key",
            re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,34})\b"),
            "High",
        ),
        (
            "Google Cloud API Key",
            re.compile(r"\b(AIza[0-9A-Za-z\\-_]{35})\b"),
            "High",
        ),
        (
            "GitHub Personal Access Token",
            re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
            "High",
        ),
        (
            "GitLab Personal Access Token",
            re.compile(r"\b(glpat-[0-9a-zA-Z]{20})\b"),
            "High",
        ),
        (
            "Slack Webhook URL",
            re.compile(r"\b(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+)\b"),
            "High",
        ),
        (
            "JSON Web Token (JWT)",
            re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
            "Medium",
        ),
        (
            "Cloud Storage URI",
            re.compile(r"\b((?:s3|gs):\/\/[a-z0-9\.\-_]{3,63})\b"),
            "Medium",
        ),
    ]

    def redact(self, secret: str) -> str:
        if len(secret) <= 8:
            return "****"
        return f"{secret[:4]}...{secret[-4:]}"

    def scan_text(self, text: str) -> List[SecretMatch]:
        """Scans arbitrary text or JavaScript code for credential patterns."""
        if not text:
            return []

        matches: List[SecretMatch] = []
        for name, pattern, confidence in self.PATTERNS:
            for m in pattern.finditer(text):
                val = m.group(1)
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                snippet = text[start:end].replace("\n", " ").strip()
                matches.append(
                    SecretMatch(
                        pattern_name=name,
                        matched_value=val,
                        redacted_value=self.redact(val),
                        confidence=confidence,
                        context_snippet=snippet,
                    )
                )

        return matches
