from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    target: str
    evidence: str = ""


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

    def calculate_grade_and_score(self):
        penalty = 0
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                penalty += 35
            elif f.severity == Severity.HIGH:
                penalty += 20
            elif f.severity == Severity.MEDIUM:
                penalty += 10
            elif f.severity == Severity.LOW:
                penalty += 5

        self.score = max(0, 100 - penalty)
        if self.score >= 95:
            self.grade = "A+"
        elif self.score >= 88:
            self.grade = "A"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 45:
            self.grade = "D"
        else:
            self.grade = "F"
        return self.grade, self.score
