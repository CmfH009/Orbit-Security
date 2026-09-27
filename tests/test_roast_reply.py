import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.generate_roast_reply import (
    clean_domain,
    extract_dmarc_status,
    extract_key_finding,
    generate_roast_tweet,
)
from orbit_security.models import DomainAuditResult, Finding, Severity


def test_clean_domain():
    assert clean_domain("https://candykittens.co.uk/") == "candykittens.co.uk"
    assert clean_domain("http://carawayhome.com:443/shop") == "carawayhome.com"
    assert clean_domain("  sub.example.com  ") == "sub.example.com"


def test_dmarc_status_enforced():
    result = DomainAuditResult(domain="example.com")
    status, finding = extract_dmarc_status(result)
    assert status == "Enforced (Bouncer active)"
    assert finding is None


def test_dmarc_status_vulnerable():
    result = DomainAuditResult(
        domain="example.com",
        findings=[
            Finding(
                title="DMARC Policy in Inactive Monitoring Mode (p=none)",
                severity=Severity.MEDIUM,
                category="Email Authentication",
                description="Test description",
                remediation="Test remediation",
                target="_dmarc.example.com",
            )
        ],
    )
    status, finding = extract_dmarc_status(result)
    assert "Vulnerable" in status
    assert "p=none" in status
    assert finding is not None


def test_extract_key_finding_takeover():
    takeover_finding = Finding(
        title="Subdomain Takeover Detected",
        severity=Severity.CRITICAL,
        category="DNS Routing",
        description="Dangling CNAME points to unclaimed AWS S3",
        remediation="Remove CNAME",
        target="promo.example.com",
    )
    result = DomainAuditResult(domain="example.com", findings=[takeover_finding])
    key = extract_key_finding(result, None)
    assert "Dangling CNAME takeover on promo.example.com" in key


def test_extract_key_finding_csp_and_clickjacking():
    csp_finding = Finding(
        title="Missing Content Security Policy (CSP)",
        severity=Severity.LOW,
        category="Application Security",
        description="Missing CSP",
        remediation="Add CSP",
        target="https://example.com",
    )
    xfo_finding = Finding(
        title="Missing X-Frame-Options (Clickjacking Protection)",
        severity=Severity.LOW,
        category="Application Security",
        description="Missing XFO",
        remediation="Add XFO",
        target="https://example.com",
    )
    result = DomainAuditResult(domain="example.com", findings=[csp_finding, xfo_finding])
    key = extract_key_finding(result, None)
    assert "Missing CSP & X-Frame-Options (Clickjacking)" in key


def test_generate_roast_tweet_length_enforcement():
    # Long domain and verbose finding
    long_domain = "really-long-subdomain-name-for-enterprise-brand-audit.agency-testing.co.uk"
    super_long_finding = (
        "Severely unmaintained legacy application server with multiple missing defense-in-depth "
        "headers including Content Security Policy, X-Frame-Options clickjacking mitigation, and HSTS."
    )
    tweet = generate_roast_tweet(
        domain=long_domain,
        score=45,
        grade="D",
        dmarc_status="Vulnerable (p=none bouncer)",
        key_finding=super_long_finding,
    )
    assert len(tweet) <= 280
    assert "https://cmfh009.github.io/Orbit-Security/" in tweet
    assert "45/100" in tweet
