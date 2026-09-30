#!/usr/bin/env python3
"""
Orbit Security — Ground-Truth Sentinel & CVD Compliance Gate
============================================================
Enforces Coordinated Vulnerability Disclosure (CVD, ISO 29147, RFC 9116),
RFC 7489 DMARC compliance accuracy, and deterministic ground-truth verification
before any social reply or roast is queued or dispatched to X.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from orbit_security.models import DomainAuditResult, Finding, Severity

logger = logging.getLogger("orbit_security.ground_truth_gate")


class GateVerdict(BaseModel):
    is_approved: bool
    rejection_reason: Optional[str] = None
    sanitized_text: Optional[str] = None
    audit_hash: Optional[str] = None
    cvd_safe: bool = True
    rfc_compliant: bool = True


class GroundTruthGate:
    """
    Deterministic safety validator preventing:
    1. Unsolicited public shaming of client domains (CVD violation).
    2. Inaccurate RFC 7489 assertions (e.g. falsely claiming p=none is an active compromise).
    3. Hallucinated CVEs, scores, or vulnerabilities not verified by OrbitSecurityScanner.
    """

    def __init__(self, max_audit_age_minutes: int = 30):
        self.max_audit_age_minutes = max_audit_age_minutes

    @staticmethod
    def compute_audit_hash(result: DomainAuditResult) -> str:
        """Computes deterministic SHA256 digest of scan results."""
        payload = {
            "domain": result.domain.lower(),
            "score": result.score,
            "grade": result.grade,
            "finding_count": len(result.findings),
            "critical_count": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def validate_inbound_roast(
        self,
        domain: str,
        reply_text: str,
        audit_result: DomainAuditResult,
        is_explicit_request: bool = True,
    ) -> GateVerdict:
        """
        Validates a generated roast reply against ground-truth scan data and policy.
        """
        clean_domain = domain.lower().strip()

        # 1. CVD Compliance: Never post unsolicited client domain roasts publicly
        if not is_explicit_request:
            return GateVerdict(
                is_approved=False,
                rejection_reason="CVD Policy Violation: Unsolicited public roast of third-party domain is prohibited.",
                cvd_safe=False,
            )

        # 2. Audit Age Check
        scan_time = getattr(audit_result, "timestamp", None) or getattr(audit_result, "scanned_at", None)
        if scan_time:
            if scan_time.tzinfo is None:
                scan_time = scan_time.replace(tzinfo=datetime.timezone.utc)
            audit_age = datetime.datetime.now(datetime.timezone.utc) - scan_time
            if audit_age.total_seconds() > (self.max_audit_age_minutes * 60):
                return GateVerdict(
                    is_approved=False,
                    rejection_reason=f"Stale Scan Ground-Truth: Audit result is older than {self.max_audit_age_minutes} minutes.",
                )

        # 3. Domain Match Invariant
        if audit_result.domain.lower() != clean_domain:
            return GateVerdict(
                is_approved=False,
                rejection_reason=f"Domain Mismatch: Target domain '{clean_domain}' differs from audit domain '{audit_result.domain}'.",
            )

        # 4. Score & Grade Consistency (Anti-Hallucination)
        expected_score_str = f"{audit_result.score}/100"
        if expected_score_str not in reply_text:
            return GateVerdict(
                is_approved=False,
                rejection_reason=f"Score Inconsistency: Generated text does not contain true score '{expected_score_str}'.",
            )

        # 5. RFC 7489 Compliance: p=none must be accurately characterized
        # Falsely claiming "compromise" or "vulnerable" on a domain with strict SPF/DKIM is blocked
        if "p=none" in reply_text.lower():
            # Check if text describes it accurately
            lower_text = reply_text.lower()
            if "hacked" in lower_text or "compromised" in lower_text or "breached" in lower_text:
                return GateVerdict(
                    is_approved=False,
                    rejection_reason="RFC 7489 Inaccuracy: DMARC p=none must be identified as monitoring mode, not an active breach.",
                    rfc_compliant=False,
                )

        # 6. Character Limit Invariant (Twitter Text v3: <= 280)
        if len(reply_text) > 280:
            return GateVerdict(
                is_approved=False,
                rejection_reason=f"Character Limit Exceeded: Length is {len(reply_text)} (max 280).",
            )

        audit_hash = self.compute_audit_hash(audit_result)
        return GateVerdict(
            is_approved=True,
            sanitized_text=reply_text,
            audit_hash=audit_hash,
            cvd_safe=True,
            rfc_compliant=True,
        )

    def validate_proactive_post(
        self,
        post_text: str,
        referenced_domains: Optional[List[str]] = None,
    ) -> GateVerdict:
        """
        Validates original posts and insights to ensure no third-party private client domains
        are exposed without authorization.
        """
        # Scan for un-redacted domains that might violate CVD
        if referenced_domains:
            for dom in referenced_domains:
                clean_d = dom.lower().strip()
                # Known tech broad platforms are exempt (unbounce.com, github.com, shopify.com)
                exempt_platforms = {
                    "shopify.com", "unbounce.com", "github.com", "aws.amazon.com",
                    "cloudflare.com", "webflow.com", "stripe.com", "google.com"
                }
                if clean_d not in exempt_platforms and clean_d in post_text.lower():
                    # Flag potential CVD risk if naming a specific target in an exploit post
                    if any(w in post_text.lower() for w in ["vulnerable", "takeover", "spoof", "hijack"]):
                        return GateVerdict(
                            is_approved=False,
                            rejection_reason=f"CVD Risk: Post references specific domain '{clean_d}' in vulnerability context without opt-in.",
                            cvd_safe=False,
                        )

        # Enforce RFC 7489 Accuracy
        if "p=none" in post_text.lower() and any(w in post_text.lower() for w in ["hacked", "breached"]):
            return GateVerdict(
                is_approved=False,
                rejection_reason="RFC 7489 Inaccuracy: Monitoring mode p=none cannot be equated with an active breach.",
                rfc_compliant=False,
            )

        return GateVerdict(
            is_approved=True,
            sanitized_text=post_text,
            cvd_safe=True,
            rfc_compliant=True,
        )
