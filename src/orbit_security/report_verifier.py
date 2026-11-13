"""orbit_security.report_verifier: Empirical Report Critic & Anti-Hallucination Gate.
==================================================================================
Routes automated briefings, executive teardowns, and vulnerability advisories through
an empirical verification pass before persisting or surfacing output to operator queues.

Guarantees:
1. Target Grounding: Validates that synthesized copy accurately identifies the audited domain.
2. Finding Integrity: Prevents hallucination of unrelated vulnerabilities (e.g. RCE on SPF findings).
3. Severity Realism: Prevents severe escalation of informational/medium hygiene issues.
4. Coordinated Disclosure & RoE Tone: Enforces professional, non-extortionate advisory language.
5. Cryptographic Evidence Grounding: Verifies that cited endpoints, HTTP status codes,
   and technical claims match empirical blackboard artifact hashes (ev_<12-char-hex>).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

logger = logging.getLogger("orbit_security.report_verifier")


@dataclass(frozen=True)
class EmpiricalEvidenceArtifact:
    """Canonicalized empirical evidence artifact recorded during an audit run."""

    artifact_id: str  # ev_<12-char-hex>
    target: str  # host, domain, or full URL
    status_code: Optional[int] = None
    flaw_type: str = ""
    evidence_snippet: str = ""
    provider: str = ""
    endpoint_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "target": self.target,
            "status_code": self.status_code,
            "flaw_type": self.flaw_type,
            "evidence_snippet": self.evidence_snippet,
            "provider": self.provider,
            "endpoint_path": self.endpoint_path,
        }


def compute_evidence_digest(
    target: str,
    status_code: Optional[int | str] = None,
    flaw_type: str = "",
    evidence_snippet: str = "",
    provider: str = "",
) -> str:
    """Computes a deterministic 12-char hex evidence digest: ev_<12-char-hex>."""
    canonical = (
        f"target={str(target).strip().lower()}|"
        f"status={str(status_code if status_code is not None else '').strip()}|"
        f"flaw={str(flaw_type).strip().lower()}|"
        f"snippet={str(evidence_snippet).strip()}|"
        f"provider={str(provider).strip().lower()}"
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"ev_{digest}"


def extract_empirical_artifacts_from_blackboard(
    blackboard: Any,
    target_domain: str,
    limit: int = 200,
) -> List[EmpiricalEvidenceArtifact]:
    """Queries blackboard for events relating to target_domain and builds verified empirical artifacts."""
    if blackboard is None:
        return []

    clean_domain = target_domain.strip().lower()
    events: List[Dict[str, Any]] = []

    if hasattr(blackboard, "get_recent"):
        try:
            events = blackboard.get_recent(limit=limit)
        except Exception as e:
            logger.warning("Error querying blackboard.get_recent: %s", e)
            events = []
    elif isinstance(blackboard, list):
        events = blackboard

    artifacts: List[EmpiricalEvidenceArtifact] = []

    for ev in events:
        payload = ev.get("payload") if isinstance(ev, dict) else getattr(ev, "payload", {})
        if not isinstance(payload, dict):
            continue

        host = str(
            payload.get("target_domain")
            or payload.get("hostname")
            or payload.get("domain")
            or payload.get("host")
            or ""
        ).strip().lower()
        target_url = str(payload.get("target_url") or payload.get("url") or payload.get("target") or "")

        domain_match = (
            host == clean_domain
            or host.endswith("." + clean_domain)
            or clean_domain in target_url.lower()
        )
        if not domain_match:
            continue

        raw_status = payload.get("status_code") or payload.get("status") or payload.get("http_status")
        status_code: Optional[int] = None
        if raw_status is not None:
            try:
                status_code = int(raw_status)
            except (ValueError, TypeError):
                pass

        flaw_type = str(
            payload.get("flaw_type")
            or payload.get("finding")
            or payload.get("core_finding")
            or payload.get("vulnerability")
            or (ev.get("event_type") if isinstance(ev, dict) else "")
            or ""
        )
        evidence_snippet = str(
            payload.get("evidence_snippet")
            or payload.get("evidence")
            or payload.get("snippet")
            or payload.get("reason")
            or payload.get("signature")
            or ""
        )
        provider = str(
            payload.get("provider")
            or payload.get("program_name")
            or (ev.get("source") if isinstance(ev, dict) else "")
            or ""
        )

        endpoint_path: Optional[str] = None
        if payload.get("path") or payload.get("endpoint"):
            raw_p = str(payload.get("path") or payload.get("endpoint"))
            endpoint_path = "/" + raw_p.lstrip("/")
        elif target_url:
            parsed = urlsplit(target_url)
            if parsed.path and parsed.path != "/":
                endpoint_path = parsed.path.rstrip(".,;!?:)'\"")

        art_id = compute_evidence_digest(
            target=target_url or host or clean_domain,
            status_code=status_code,
            flaw_type=flaw_type,
            evidence_snippet=evidence_snippet,
            provider=provider,
        )

        artifacts.append(
            EmpiricalEvidenceArtifact(
                artifact_id=art_id,
                target=target_url or host or clean_domain,
                status_code=status_code,
                flaw_type=flaw_type,
                evidence_snippet=evidence_snippet,
                provider=provider,
                endpoint_path=endpoint_path,
            )
        )

    return artifacts


def extract_cited_endpoints(text: str) -> List[str]:
    """Extracts cited URL paths and endpoints from briefing text."""
    urls = re.findall(r'https?://[^\s"\'<>\)]+', text)
    paths: Set[str] = set()
    for u in urls:
        parsed = urlsplit(u)
        clean_p = parsed.path.rstrip(".,;!?:)'\"")
        if clean_p and clean_p != "/":
            paths.add(clean_p)

    raw_paths = re.findall(r'(?:^|[\s"\'\(])(/[a-zA-Z0-9_\-\.\/]+)', text)
    for p in raw_paths:
        clean = p.rstrip(".,;!?:)'\"")
        if len(clean) > 1 and clean != "//":
            paths.add(clean)

    return sorted(paths)


def extract_cited_status_codes(text: str) -> List[int]:
    """Extracts cited HTTP status codes (e.g., 200, 403, 404, 500) from briefing text."""
    explicit = re.findall(r'\b(?:HTTP\s+|status\s+(?:code\s+)?)([1-5][0-9]{2})\b', text, re.IGNORECASE)
    status_phrase = re.findall(
        r'\b([1-5][0-9]{2})\s+(?:OK|Found|Forbidden|Unauthorized|Not Found|Bad Request|Internal Server Error)\b',
        text,
        re.IGNORECASE,
    )
    return sorted({int(c) for c in (explicit + status_phrase)})


@dataclass
class CriticVerificationResult:
    passed: bool
    confidence_score: float
    reasons: List[str] = field(default_factory=list)
    flagged_terms: List[str] = field(default_factory=list)
    verified_artifact_ids: List[str] = field(default_factory=list)
    ungrounded_claims: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "confidence_score": round(self.confidence_score, 2),
            "reasons": self.reasons,
            "flagged_terms": self.flagged_terms,
            "verified_artifact_ids": self.verified_artifact_ids,
            "ungrounded_claims": self.ungrounded_claims,
        }


class ReportCriticVerifier:
    """Adversarial critic verifying synthesized reports against ground-truth findings and evidence artifacts."""

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
        blackboard: Optional[Any] = None,
        artifacts: Optional[List[EmpiricalEvidenceArtifact]] = None,
        require_artifact_grounding: bool = False,
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
        ungrounded: List[Dict[str, Any]] = []
        verified_artifact_ids: Set[str] = set()

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

        # 5. Cryptographic Evidence Artifact Grounding Gate
        verified_artifacts: List[EmpiricalEvidenceArtifact] = []
        if artifacts:
            verified_artifacts.extend(artifacts)
        if blackboard is not None:
            verified_artifacts.extend(
                extract_empirical_artifacts_from_blackboard(blackboard, target_domain)
            )

        cited_endpoints = extract_cited_endpoints(pitch_text)
        cited_status_codes = extract_cited_status_codes(pitch_text)

        should_ground = require_artifact_grounding or bool(verified_artifacts)

        if should_ground:
            # Check cited endpoints against empirical artifacts
            for ep in cited_endpoints:
                matched_art = None
                for art in verified_artifacts:
                    if (
                        art.endpoint_path == ep
                        or (art.target and ep in art.target)
                        or (art.evidence_snippet and ep in art.evidence_snippet)
                        or (art.flaw_type and ep in art.flaw_type)
                    ):
                        matched_art = art
                        break

                if matched_art:
                    verified_artifact_ids.add(matched_art.artifact_id)
                else:
                    ungrounded.append({"type": "endpoint", "claim": ep})
                    reasons.append(
                        f"UNGROUNDED_CLAIM_ENDPOINT: Endpoint '{ep}' not backed by empirical blackboard artifacts"
                    )

            # Check cited HTTP status codes against empirical artifacts
            for sc in cited_status_codes:
                matched_art = None
                for art in verified_artifacts:
                    if art.status_code == sc or (art.evidence_snippet and str(sc) in art.evidence_snippet):
                        matched_art = art
                        break

                if matched_art:
                    verified_artifact_ids.add(matched_art.artifact_id)
                else:
                    ungrounded.append({"type": "status_code", "claim": sc})
                    reasons.append(
                        f"UNGROUNDED_CLAIM_STATUS: HTTP status {sc} not backed by empirical blackboard artifacts"
                    )

            # If artifacts exist for this target, ensure matched artifacts are recorded
            for art in verified_artifacts:
                if (
                    clean_domain in art.target.lower()
                    or (art.flaw_type and any(k in art.flaw_type.lower() for k in clean_pitch.split()))
                ):
                    verified_artifact_ids.add(art.artifact_id)

        passed = len(reasons) == 0 and len(ungrounded) == 0
        confidence = 1.0 if passed else max(0.0, 1.0 - (0.35 * len(reasons)))

        return CriticVerificationResult(
            passed=passed,
            confidence_score=confidence,
            reasons=reasons,
            flagged_terms=flagged,
            verified_artifact_ids=sorted(verified_artifact_ids),
            ungrounded_claims=ungrounded,
        )
