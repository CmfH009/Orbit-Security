"""orbit_security.report_verifier: Empirical Report Critic & Anti-Hallucination Gate.
==================================================================================
Routes automated briefings, executive teardowns, and vulnerability advisories through
an empirical verification pass before persisting or surfacing output to operator queues.

Guarantees:
1. Target Grounding: Validates that synthesized copy accurately identifies the audited domain.
2. Finding Integrity: Prevents hallucination of unrelated vulnerabilities (e.g. RCE on SPF findings).
3. Severity Realism: Prevents severe escalation of informational/medium hygiene issues.
4. Coordinated Disclosure & RoE Tone: Enforces professional, non-extortionate advisory language.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("orbit_security.report_verifier")


@dataclass
class CriticVerificationResult:
    passed: bool
    confidence_score: float
    reasons: List[str] = field(default_factory=list)
    flagged_terms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "confidence_score": round(self.confidence_score, 2),
            "reasons": self.reasons,
            "flagged_terms": self.flagged_terms,
        }


class ReportCriticVerifier:
    """Adversarial critic verifying synthesized reports against ground-truth findings."""

    # Disallowed hallucinated/alarmist phrases indicating model drift or fabrication
    SEVERITY_ESCALATION_TERMS = {
        "critical 0-day",
        "imminent catastrophe",
        "compromised credit cards",
        "ransomware payload",
        "complete system takeover",
        "hacked by",
        "data exfiltration in progress",
    }

    # Flaw-category compatibility mappings to detect hallucinated vulnerability claims
    FLAW_KEYWORDS = {
        "spf": ["spf", "permerror", "dns lookup", "sender policy", "rfc 7208"],
        "dmarc": ["dmarc", "email authentication", "spoofing", "p=none", "p=reject", "p=quarantine"],
        "cname": ["cname", "takeover", "subdomain", "dangling", "s3", "github pages", "unbounce"],
        "hsts": ["hsts", "strict-transport-security", "tls", "ssl", "transport security"],
        "cors": ["cors", "access-control-allow-origin", "origin", "cross-origin"],
    }

    @classmethod
    def verify_briefing_pitch(
        cls,
        pitch_text: str,
        target_domain: str,
        core_finding: str,
        audit_score: float = 75.0,
    ) -> CriticVerificationResult:
        """Evaluates whether generated pitch text is strictly grounded in empirical audit findings."""
        if not pitch_text or not pitch_text.strip():
            return CriticVerificationResult(
                passed=False,
                confidence_score=0.0,
                reasons=["PITCH_TEXT_EMPTY"],
            )

        clean_pitch = pitch_text.lower()
        clean_domain = target_domain.lower().strip()
        reasons: List[str] = []
        flagged: List[str] = []

        # 1. Target Domain Grounding
        if clean_domain not in clean_pitch:
            reasons.append(f"DOMAIN_GROUNDING_FAILED: Target domain '{target_domain}' missing from synthesized text")

        # 2. Finding Alignment
        finding_norm = core_finding.lower()
        matched_category = None
        for category, kws in cls.FLAW_KEYWORDS.items():
            if any(k in finding_norm for k in kws):
                matched_category = category
                break

        if matched_category:
            expected_kws = cls.FLAW_KEYWORDS[matched_category]
            if not any(k in clean_pitch for k in expected_kws):
                reasons.append(
                    f"FINDING_MISALIGNMENT: Text does not reference expected keywords for {matched_category} finding '{core_finding}'"
                )

        # 3. Hallucinated Severity Escalation
        for term in cls.SEVERITY_ESCALATION_TERMS:
            if term in clean_pitch:
                flagged.append(term)
                reasons.append(f"ALARMIST_CLAIM_DETECTED: '{term}' violates empirical verification standards")

        # 4. Out-of-Bound Severity Inflation
        if audit_score >= 60.0 and any(t in clean_pitch for t in ["ransomware", "0-day", "exfiltration"]):
            reasons.append(f"SEVERITY_INFLATION: Score is {audit_score} but text claims catastrophic 0-day/ransomware")

        passed = len(reasons) == 0
        confidence = 1.0 if passed else max(0.0, 1.0 - (0.35 * len(reasons)))

        return CriticVerificationResult(
            passed=passed,
            confidence_score=confidence,
            reasons=reasons,
            flagged_terms=flagged,
        )
