import pytest
from orbit_security.remediation import DnsRemediationGenerator


def test_generate_dmarc_fix():
    snippets = DnsRemediationGenerator.generate_dmarc_fix(
        domain="agencyclient.com",
        policy="reject",
        report_email="dmarc@agencyclient.com",
    )

    assert len(snippets) >= 2
    cf = next(s for s in snippets if s.provider == "Cloudflare")
    assert cf.record_type == "TXT"
    assert cf.host_name == "_dmarc"
    assert "p=reject" in cf.record_value
    assert "rua=mailto:dmarc@agencyclient.com" in cf.record_value
    assert 'resource "cloudflare_record"' in cf.terraform_hcl

    route53 = next(s for s in snippets if s.provider == "AWS Route 53")
    assert route53.host_name == "_dmarc.agencyclient.com"
    assert 'resource "aws_route53_record"' in route53.terraform_hcl


def test_generate_spf_fix():
    snippets = DnsRemediationGenerator.generate_spf_fix(
        domain="agencyclient.com",
        include_providers=["_spf.google.com", "shops.shopify.com"],
        hard_fail=True,
    )

    assert len(snippets) >= 1
    cf = snippets[0]
    assert "include:_spf.google.com" in cf.record_value
    assert "include:shops.shopify.com" in cf.record_value
    assert "-all" in cf.record_value


def test_generate_takeover_remediation():
    instructions = DnsRemediationGenerator.generate_takeover_remediation(
        subdomain="campaign.brand.com",
        saas_provider="Unbounce",
        cname_target="unbouncepages.com",
    )

    assert instructions["subdomain"] == "campaign.brand.com"
    assert instructions["saas_provider"] == "Unbounce"
    assert "Delete the dangling CNAME" in instructions["action_immediate"]
    assert "orbit-recon campaign.brand.com" in instructions["cli_verification"]
