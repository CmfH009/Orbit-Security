"""orbit_security.cname_takeover: Passive Dangling CNAME Subdomain Takeover Detector.
===================================================================================
Analyzes DNS CNAME mappings and passive perimeter fingerprints against known
vulnerable cloud providers (AWS S3, CloudFront, GitHub Pages, Heroku, Azure, etc.).

Features:
- Completely passive: operates on DNS record data and passive HTTP response banners.
- Ingests canonical SaasSignature rules from orbit_security.signatures.
- Accurate NXDOMAIN and service error pattern matching.
- Standardized SQLite WAL Blackboard event publishing (SUBDOMAIN_TAKEOVER_DETECTED).
- Immediate, actionable vendor remediation recipes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES, SaasSignature

logger = logging.getLogger("orbit_security.cname_takeover")


@dataclass
class TakeoverFinding:
    domain: str
    provider: str
    cname_target: str
    fingerprint_matched: str
    remediation: str
    severity: str = "CRITICAL"
    timestamp: float = 0.0


class PassiveTakeoverDetector:
    """Evaluates DNS CNAME configurations for dangling cloud tenant vulnerabilities."""

    def __init__(self, signatures: Optional[List[SaasSignature]] = None):
        self.signatures = signatures or SAAS_TAKEOVER_SIGNATURES

    def evaluate_cname(
        self,
        domain: str,
        cname_target: str,
        body_snippet: Optional[str] = None,
        is_nxdomain: bool = False,
        blackboard: Any = None,
    ) -> Optional[TakeoverFinding]:
        """Passively evaluates a single CNAME target against SaaS takeover patterns."""
        if not cname_target or not domain:
            return None

        clean_domain = domain.strip().lower()
        clean_cname = cname_target.strip().lower().rstrip(".")
        clean_body = (body_snippet or "").lower()

        for sig in self.signatures:
            # Check if CNAME matches provider pattern (e.g. s3.amazonaws.com, github.io)
            matches_pattern = any(p.lower() in clean_cname for p in sig.cname_patterns)
            if not matches_pattern:
                continue

            # Condition 1: Provider is vulnerable via NXDOMAIN and canonical name is NXDOMAIN
            if sig.nxdomain and is_nxdomain:
                finding = TakeoverFinding(
                    domain=clean_domain,
                    provider=sig.name,
                    cname_target=clean_cname,
                    fingerprint_matched="NXDOMAIN (Dangling Service Endpoint)",
                    remediation=sig.remediation,
                    severity="CRITICAL",
                    timestamp=time.time(),
                )
                self._publish_if_connected(finding, blackboard)
                return finding

            # Condition 2: Provider error fingerprint present in passive response body
            if clean_body:
                for fp in sig.fingerprints:
                    if fp.lower() in clean_body:
                        finding = TakeoverFinding(
                            domain=clean_domain,
                            provider=sig.name,
                            cname_target=clean_cname,
                            fingerprint_matched=fp,
                            remediation=sig.remediation,
                            severity="CRITICAL",
                            timestamp=time.time(),
                        )
                        self._publish_if_connected(finding, blackboard)
                        return finding

            # Condition 3: If no body is provided but target is an unmistakable unallocated bucket/tenant
            # (e.g. s3 bucket or unbounce page that is known dangling)
            if is_nxdomain:
                finding = TakeoverFinding(
                    domain=clean_domain,
                    provider=sig.name,
                    cname_target=clean_cname,
                    fingerprint_matched="Dangling CNAME points to unresolvable provider host",
                    remediation=sig.remediation,
                    severity="CRITICAL",
                    timestamp=time.time(),
                )
                self._publish_if_connected(finding, blackboard)
                return finding

        return None

    def evaluate_dns_records(
        self,
        domain: str,
        records: Dict[str, List[str]],
        body_snippet: Optional[str] = None,
        is_nxdomain: bool = False,
        blackboard: Any = None,
    ) -> List[TakeoverFinding]:
        """Evaluates DNS record mapping (CNAME, A, etc.) for domain."""
        findings: List[TakeoverFinding] = []
        cnames = (
            records.get("CNAME")
            or records.get("cname")
            or records.get("cnames")
            or records.get("CNAMES")
            or []
        )
        if isinstance(cnames, str):
            cnames = [cnames]

        for cname in cnames:
            f = self.evaluate_cname(
                domain=domain,
                cname_target=cname,
                body_snippet=body_snippet,
                is_nxdomain=is_nxdomain,
                blackboard=blackboard,
            )
            if f:
                findings.append(f)

        return findings

    def _publish_if_connected(self, finding: TakeoverFinding, blackboard: Any):
        """Dispatches finding to SQLite WAL Blackboard if connected."""
        if not blackboard:
            return
        try:
            blackboard.publish(
                event_type="SUBDOMAIN_TAKEOVER_DETECTED",
                payload={
                    "domain": finding.domain,
                    "service": finding.provider,
                    "cname_target": finding.cname_target,
                    "evidence": finding.fingerprint_matched,
                    "remediation": finding.remediation,
                    "severity": finding.severity,
                },
                source="cname_takeover_detector",
                topic="perimeter",
            )
        except Exception as ex:
            logger.debug(f"Failed to publish takeover blackboard event: {ex}")
