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
            # using strict exact or dot-prefixed suffix matching to prevent substring spoofing
            matches_pattern = False
            for p in sig.cname_patterns:
                p_clean = p.lower().lstrip(".")
                if clean_cname == p_clean or clean_cname.endswith(f".{p_clean}"):
                    matches_pattern = True
                    break
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

    def export_playground_presets(self) -> List[Dict[str, Any]]:
        """Returns canonical Subdomain Takeover PoC Playground presets (Project #7)."""
        return [
            {
                "id": "aws_s3",
                "label": "AWS S3 Orphaned Bucket",
                "domain": "media.client-store.com",
                "cname_target": "orphaned-client-media.s3.amazonaws.com",
                "http_response_body": "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
                "is_nxdomain": False,
                "provider": "AWS S3",
            },
            {
                "id": "github_pages",
                "label": "GitHub Pages Unclaimed Repo",
                "domain": "docs.agency-client.io",
                "cname_target": "legacy-org.github.io",
                "http_response_body": "There isn't a GitHub Pages site here.",
                "is_nxdomain": False,
                "provider": "GitHub Pages",
            },
            {
                "id": "vercel",
                "label": "Vercel Deleted Deployment",
                "domain": "preview.brand-campaign.com",
                "cname_target": "cname.vercel-dns.com",
                "http_response_body": "The deployment could not be found on Vercel. DEPLOYMENT_NOT_FOUND",
                "is_nxdomain": False,
                "provider": "Vercel",
            },
            {
                "id": "shopify",
                "label": "Shopify Expired Storefront",
                "domain": "outlet.dtc-retailer.com",
                "cname_target": "shops.myshopify.com",
                "http_response_body": "Sorry, this shop is currently unavailable.",
                "is_nxdomain": False,
                "provider": "Shopify",
            },
            {
                "id": "azure_nxdomain",
                "label": "Azure App Service NXDOMAIN",
                "domain": "portal.enterprise-client.net",
                "cname_target": "retired-app-prod.azurewebsites.net",
                "http_response_body": "",
                "is_nxdomain": True,
                "provider": "Microsoft Azure",
            },
        ]

    def simulate_poc_scenario(
        self,
        domain: str,
        cname_target: str,
        http_response_body: str = "",
        is_nxdomain: bool = False,
    ) -> Dict[str, Any]:
        """Simulates a non-destructive Subdomain Takeover Proof-of-Concept trace (Project #7)."""
        clean_domain = (domain or "sub.example.com").strip().lower()
        clean_cname = (cname_target or "").strip().lower().rstrip(".")

        finding = self.evaluate_cname(
            domain=clean_domain,
            cname_target=clean_cname,
            body_snippet=http_response_body,
            is_nxdomain=is_nxdomain,
            blackboard=None,
        )

        dig_cmd = f"dig +short CNAME {clean_domain}"
        curl_cmd = f"curl -sIL https://{clean_domain} | head -n 20"

        if finding:
            return {
                "vulnerable": True,
                "domain": clean_domain,
                "cname_target": clean_cname,
                "provider": finding.provider,
                "severity": finding.severity,
                "cvss_score": 8.2,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
                "fingerprint_matched": finding.fingerprint_matched,
                "dig_command": dig_cmd,
                "curl_command": curl_cmd,
                "remediation": finding.remediation,
                "remediation_steps": [
                    f"1. Immediate DNS Lockdown: Delete the dangling CNAME record `{clean_domain} -> {clean_cname}` in your DNS zone (Cloudflare / Route53).",
                    f"2. Vendor Tenant Claim: {finding.remediation}",
                    f"3. Verification: Run `{dig_cmd}` and confirm empty response before closing incident ticket.",
                ],
                "safe_harbor_notice": "100% Passive Simulation — Zero third-party cloud buckets or tenants were registered.",
            }

        return {
            "vulnerable": False,
            "domain": clean_domain,
            "cname_target": clean_cname,
            "provider": "None / Protected",
            "severity": "SAFE",
            "cvss_score": 0.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "fingerprint_matched": "No unclaimed cloud tenant signature detected",
            "dig_command": dig_cmd,
            "curl_command": curl_cmd,
            "remediation": "No action required. Target CNAME resolves to an active or non-vulnerable endpoint.",
            "remediation_steps": [
                f"1. Verified `{clean_domain} -> {clean_cname}` does not match unclaimed SaaS takeover signatures.",
                "2. Continue automated 24/7 CT log and CNAME drift surveillance.",
            ],
            "safe_harbor_notice": "100% Passive Simulation — Zero third-party cloud buckets or tenants were registered.",
        }
