import pytest
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES


def test_takeover_signatures_contain_key_providers():
    providers = {sig.saas_provider.lower(): sig for sig in SAAS_TAKEOVER_SIGNATURES}
    assert "github pages" in providers or "github" in providers
    assert "aws s3" in providers or "amazon s3" in providers
    assert "shopify" in providers
    assert "webflow" in providers


def test_simulate_takeover_poc_generation():
    from orbit_security.cli import generate_takeover_poc_proof
    
    subdomain = "shop.acmebrand.com"
    cname_target = "shops.myshopify.com"
    poc = generate_takeover_poc_proof(subdomain, cname_target=cname_target, provider="Shopify")
    
    assert poc["subdomain"] == subdomain
    assert poc["cname_target"] == cname_target
    assert "curl -sI" in poc["curl_command"]
    assert "Host: shop.acmebrand.com" in poc["curl_command"]
    assert "remediation" in poc
    assert "safe_harbor_notice" in poc
