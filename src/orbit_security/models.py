from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# Severity + the whole scoring model live in `orbit_security.scoring` so the
# audit deliverable (this module) and the Recon CLI (`orbit_security.recon`)
# cannot drift apart. `Severity` is re-exported here for backwards
# compatibility: `from orbit_security.models import Severity` still works.
from orbit_security.scoring import Severity, score_findings

__all__ = ["Severity", "Finding", "VulnerabilityFinding", "AgencyBranding", "DomainAuditResult"]


class Finding(BaseModel):
    title: str
    severity: Severity
    category: str = "DNS Security"
    description: str
    remediation: str
    target: str = ""
    evidence: str = ""


VulnerabilityFinding = Finding


class AgencyBranding(BaseModel):
    agency_name: str = "Apex Digital Studio"
    agency_tagline: str = "Managed Web & Security Operations"
    primary_color: str = "#0F172A"
    accent_color: str = "#2563EB"
    support_email: str = "ops@apexdigital.io"
    website: str = "https://apexdigital.io"


class DomainAuditResult(BaseModel):
    domain: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    score: int = 100
    grade: str = "A+"
    findings: List[Finding] = Field(default_factory=list)
    subdomains_scanned: List[str] = Field(default_factory=list)
    agency_branding: AgencyBranding = Field(default_factory=AgencyBranding)
    osint_intel: Optional[Dict[str, Any]] = Field(default_factory=dict)

    def calculate_grade_and_score(self):
        """Compute the executive grade with the shared exploitability model.

        Scoring rules (see `orbit_security.scoring` for the full spec):

        1. Hygiene / best-practice-only findings (BIMI, MTA-STS, TLS-RPT, CAA,
           missing CSP / X-Frame-Options / X-Content-Type-Options, incomplete
           HSTS, missing security.txt, ...) are still reported in the
           deliverable but never cost score.
        2. Repeats of the same finding class are discounted and capped, so a
           large estate is not punished for being large.
        3. A domain with zero CRITICAL and zero HIGH findings can never fall
           below grade C - "F" means actively exploitable.
        4. Grade bands are unchanged: A+ >= 95, A >= 88, B >= 75, C >= 60,
           D >= 45, F < 45.
        """
        result = score_findings(self.findings)
        self.score = result.score
        self.grade = result.grade
        return self.grade, self.score
