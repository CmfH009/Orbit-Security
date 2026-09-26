import os
import tempfile
import pytest
from orbit_security.models import DomainAuditResult, Finding, Severity, AgencyBranding
from orbit_security.reporter import ReportGenerator


def test_markdown_report_generation():
    audit = DomainAuditResult(domain="clientcorp.com")
    audit.findings.append(
        Finding(
            title="Dangling CNAME / Subdomain Takeover Risk (Unbounce)",
            severity=Severity.CRITICAL,
            category="Subdomain & DNS",
            description="Subdomain promo.clientcorp.com points to unclaimed Unbounce page",
            remediation="Delete CNAME record in DNS",
            target="promo.clientcorp.com",
            evidence="CNAME unbouncepages.com"
        )
    )
    audit.calculate_grade_and_score()

    md = ReportGenerator.generate_markdown(audit)
    assert "# 🛡️ Client Security & Domain Health Audit" in md
    assert "clientcorp.com" in md
    assert "CRITICAL" in md
    assert "promo.clientcorp.com" in md


def test_pdf_report_generation():
    audit = DomainAuditResult(
        domain="clientcorp.com",
        agency_branding=AgencyBranding(
            agency_name="Quantum Web Agency",
            agency_tagline="Enterprise Development & Care Plans",
            support_email="security@quantumagency.com",
            website="https://quantumagency.com"
        )
    )
    audit.findings.append(
        Finding(
            title="Missing DMARC Email Protection",
            severity=Severity.HIGH,
            category="Email Authentication",
            description="No DMARC policy found",
            remediation="Add TXT record for _dmarc.clientcorp.com",
            target="_dmarc.clientcorp.com",
            evidence="No TXT record found"
        )
    )
    audit.calculate_grade_and_score()

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "test_audit.pdf")
        ReportGenerator.generate_pdf(audit, pdf_path)
        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 1000  # Non-trivial PDF generated
