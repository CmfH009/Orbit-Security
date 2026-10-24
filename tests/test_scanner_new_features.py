"""Unit tests for newly added high-value scanner capabilities:
1. Public JavaScript secret/token leak detection (audit_public_secrets)
2. Third-party script supply-chain risk monitoring (audit_third_party_scripts)
3. Google & Yahoo 2024+ bulk sender compliance audit (audit_bulk_sender_compliance)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.models import Severity


@pytest.fixture
def scanner():
    return OrbitSecurityScanner()


def _mock_response(status_code: int = 200, text: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


@pytest.mark.asyncio
async def test_audit_public_secrets_inline_stripe_and_aws(scanner):
    target_url = "https://example.org"
    stripe_mock_key = "sk_" + "live_" + "51AbcdEFG1234567890HijklmNOPQ"
    html_content = f"""
    <!DOCTYPE html>
    <html>
      <head>
        <title>Demo Store</title>
        <script>
          const stripeKey = "{stripe_mock_key}";
          const awsId = "AKIAIOSFODNN7EXAMPLE";
        </script>
      </head>
      <body><h1>Store</h1></body>
    </html>
    """
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response(200, html_content)

    findings = await scanner.audit_public_secrets(target_url, client=mock_client)

    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("Live Stripe Secret Key" in t for t in titles)
    assert any("AWS Access Key ID" in t for t in titles)

    stripe_finding = next(f for f in findings if "Stripe" in f.title)
    assert stripe_finding.severity == Severity.CRITICAL
    assert "sk_live_" in stripe_finding.evidence
    assert "..." in stripe_finding.evidence  # Evidence is masked!


@pytest.mark.asyncio
async def test_audit_public_secrets_in_bundle(scanner):
    target_url = "https://example.org"
    html_content = """
    <html><head><script src="/static/app.bundle.js"></script></head><body></body></html>
    """
    js_content = """
    function sendMail() {
        const sg = "SG.abcdefghijklmnopqrstuv.1234567890123456789012345678901234567890123";
        const gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    }
    """

    async def mock_get(url, **kwargs):
        if "app.bundle.js" in str(url):
            return _mock_response(200, js_content)
        return _mock_response(200, html_content)

    mock_client = AsyncMock()
    mock_client.get.side_effect = mock_get

    findings = await scanner.audit_public_secrets(target_url, client=mock_client)

    assert len(findings) >= 2
    severities = [f.severity for f in findings]
    assert Severity.CRITICAL in severities


@pytest.mark.asyncio
async def test_audit_third_party_scripts_compromised_polyfill_and_mixed_content(scanner):
    target_url = "https://example.org"
    html_content = """
    <!DOCTYPE html>
    <html>
      <head>
        <script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
        <script src="http://untrusted-cdn.com/tracker.js"></script>
      </head>
      <body></body>
    </html>
    """
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response(200, html_content)

    findings = await scanner.audit_third_party_scripts(target_url, client=mock_client)

    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("polyfill.io" in t for t in titles)
    assert any("Mixed-Content" in t for t in titles)


@pytest.mark.asyncio
async def test_audit_bulk_sender_compliance_missing_dmarc(scanner):
    with patch("orbit_security.scanner.get_orbit_async_resolver") as mock_res:
        resolver_inst = MagicMock()
        mock_res.return_value = resolver_inst

        async def fail_resolve(name, rdtype):
            raise Exception("NXDOMAIN")

        resolver_inst.resolve = fail_resolve

        finding = await scanner.audit_bulk_sender_compliance("missingdmarc.org")
        assert finding is not None
        assert "Missing DMARC" in finding.title
        assert finding.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_audit_bulk_sender_compliance_p_none_warning(scanner):
    class MockAnswer:
        strings = [b"v=DMARC1; p=none; sp=none; rua=mailto:reports@test.org"]

    with patch("orbit_security.scanner.get_orbit_async_resolver") as mock_res:
        resolver_inst = MagicMock()
        mock_res.return_value = resolver_inst

        async def mock_resolve(name, rdtype):
            return [MockAnswer()]

        resolver_inst.resolve = mock_resolve

        finding = await scanner.audit_bulk_sender_compliance("nonepolicy.org")
        assert finding is not None
        assert "p=none" in finding.title
        assert finding.severity == Severity.LOW


@pytest.mark.asyncio
async def test_audit_public_secrets_slack_webhook(scanner):
    target_url = "https://example.org"
    slack_mock_hook = "https://" + "hooks." + "slack.com/services/T" + "01234567/B01234567/abcdefghijklmnopqrstuvwx"
    html_content = f"""
    <html><head><script>
    const webhook = "{slack_mock_hook}";
    </script></head><body></body></html>
    """
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response(200, html_content)

    findings = await scanner.audit_public_secrets(target_url, client=mock_client)
    assert len(findings) >= 1
    slack_f = next((f for f in findings if "Slack" in f.title), None)
    assert slack_f is not None
    assert slack_f.severity == Severity.HIGH
    assert slack_f.category == "Secret Exposure"
    assert "..." in slack_f.evidence


@pytest.mark.asyncio
async def test_audit_third_party_scripts_compromised_bootcdn(scanner):
    target_url = "https://example.org"
    html_content = """
    <html><head>
    <script src="https://cdn.bootcdn.net/ajax/libs/vue/3.2.37/vue.global.prod.min.js"></script>
    </head><body></body></html>
    """
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response(200, html_content)

    findings = await scanner.audit_third_party_scripts(target_url, client=mock_client)
    assert len(findings) >= 1
    boot_f = next((f for f in findings if "bootcdn.net" in f.title), None)
    assert boot_f is not None
    assert boot_f.severity == Severity.CRITICAL
    assert boot_f.category == "Supply Chain Security"


@pytest.mark.asyncio
async def test_audit_bulk_sender_compliance_strict_pass(scanner):
    class MockAnswer:
        strings = [b"v=DMARC1; p=reject; rua=mailto:reports@test.org"]

    with patch("orbit_security.scanner.get_orbit_async_resolver") as mock_res:
        resolver_inst = MagicMock()
        mock_res.return_value = resolver_inst

        async def mock_resolve(name, rdtype):
            return [MockAnswer()]

        resolver_inst.resolve = mock_resolve

        finding = await scanner.audit_bulk_sender_compliance("strictpolicy.org")
        assert finding is None


def test_pilot_audit_report_generation_with_pdf(tmp_path):
    from orbit_security.models import DomainAuditResult, Finding, AgencyBranding
    from orbit_security.reporter import ReportGenerator

    audit = DomainAuditResult(
        domain="10up.com",
        agency_branding=AgencyBranding(
            agency_name="10up",
            agency_tagline="Enterprise WordPress VIP & Publishing",
            support_email="ops@10up.com",
            website="https://10up.com"
        )
    )
    audit.findings.append(
        Finding(
            title="Google & Yahoo 2024 Bulk Sender Risk: Unenforced DMARC Policy (p=none)",
            severity=Severity.LOW,
            category="Email Authentication",
            description="DMARC set to p=none.",
            remediation="Escalate to p=quarantine or p=reject.",
            target="_dmarc.10up.com",
            evidence="v=DMARC1; p=none;"
        )
    )
    audit.calculate_grade_and_score()

    pdf_file = tmp_path / "10up_pilot_audit_report.pdf"
    ReportGenerator.generate_pdf(audit, str(pdf_file))
    assert pdf_file.exists()
    assert pdf_file.stat().st_size > 5000

    md_content = ReportGenerator.generate_markdown(audit)
    assert "Retainer & Infrastructure Care Plan Recommendations" in md_content
