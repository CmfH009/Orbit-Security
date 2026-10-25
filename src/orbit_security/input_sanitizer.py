"""orbit_security.input_sanitizer: Deterministic Input Sanitization & Threat Neutralization.
====================================================================================
Guards the Orbit Security engine and autonomous agents against:
- Malformed domain inputs & command injection attempts.
- Path traversal sequences (../).
- Indirect prompt injection payloads inside security.txt, DNS TXT, and email bodies.
- ANSI escape injection and terminal corruption.
- CRLF HTTP response splitting.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List

# RFC 1123 compliant domain regex (labels 1-63 chars, alphanumeric with internal hyphens)
_DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_ILLEGAL_DOMAIN_CHARS_REGEX = re.compile(r"[;|<>&`$\s\\/'\"{}\[\]()^~*?!]")
_ANSI_ESCAPE_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

# Known indirect prompt injection signatures (case-insensitive)
_PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|previous)\s+constraints", re.IGNORECASE),
    re.compile(r"forget\s+(the\s+)?rules\s+above", re.IGNORECASE),
    re.compile(r"\b(DAN|jailbreak|unrestricted\s+assistant)\b", re.IGNORECASE),
    re.compile(r"(\r?\n|^)human\s*:.*?(\r?\n|^)assistant\s*:", re.IGNORECASE | re.DOTALL),
    re.compile(r"<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]", re.IGNORECASE),
]


class SecurityValidationError(ValueError):
    """Raised when an external input violates strict security bounds."""
    pass


def sanitize_domain(domain: str) -> str:
    """Validates and normalizes a target domain according to RFC 1123.
    
    Raises:
        SecurityValidationError: if domain contains command injection chars,
                                invalid labels, or exceeds 253 total characters.
    """
    if not domain or not isinstance(domain, str):
        raise SecurityValidationError("Domain must be a non-empty string")

    clean = domain.strip().lower().rstrip(".")
    if not clean or len(clean) > 253:
        raise SecurityValidationError(f"Domain length invalid (length: {len(clean)})")

    # Reject any shell metacharacters or command injection patterns immediately
    if _ILLEGAL_DOMAIN_CHARS_REGEX.search(clean):
        raise SecurityValidationError(f"Illegal character detected in domain: '{clean}'")

    if ".." in clean or clean.startswith("-") or clean.endswith("-"):
        raise SecurityValidationError(f"Invalid domain formatting: '{clean}'")

    labels = clean.split(".")
    if len(labels) < 2:
        raise SecurityValidationError(f"Domain must contain at least one dot: '{clean}'")

    for label in labels:
        if not label or len(label) > 63:
            raise SecurityValidationError(f"Domain label invalid length: '{label}'")
        if not _DOMAIN_LABEL_REGEX.match(label):
            raise SecurityValidationError(f"Domain label violates RFC 1123: '{label}'")

    return clean


def contains_prompt_injection_indicators(text: str) -> bool:
    """Detects whether text contains common indirect prompt injection payloads."""
    if not text or not isinstance(text, str):
        return False

    normalized = unicodedata.normalize("NFKC", text)
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(normalized):
            return True
    return False


def sanitize_external_text(
    text: str,
    max_length: int = 4096,
    strip_injection: bool = False,
) -> str:
    """Cleans untrusted external text (DNS records, security.txt, email headers).
    
    - Strips ANSI escape sequences.
    - Strips null bytes and non-printable control characters.
    - Normalizes unicode representations.
    - Enforces max length bounds.
    - Optionally neutralizes detected prompt injection clauses.
    """
    if not text:
        return ""

    if not isinstance(text, str):
        text = str(text)

    # 1. Strip ANSI codes and control characters
    text = _ANSI_ESCAPE_REGEX.sub("", text)
    text = _CONTROL_CHAR_REGEX.sub("", text)

    # 2. Normalize unicode (NFKC)
    text = unicodedata.normalize("NFKC", text)

    # 3. Optional injection stripping
    if strip_injection:
        for pattern in _PROMPT_INJECTION_PATTERNS:
            text = pattern.sub("[FILTERED_SECURITY_INJECTION]", text)

    # 4. Enforce strict max length truncation
    if len(text) > max_length:
        text = text[:max_length]

    return text.strip()


def sanitize_header_value(header: str) -> str:
    """Sanitizes an HTTP header value to prevent CRLF injection / response splitting."""
    if not header or not isinstance(header, str):
        return ""
    # Strip carriage return and newline characters entirely
    clean = header.replace("\r", " ").replace("\n", " ").strip()
    return _CONTROL_CHAR_REGEX.sub("", clean)
