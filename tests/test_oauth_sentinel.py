"""Unit tests for OAuthFlowSentinel (test_oauth_sentinel.py)."""

import pytest

from orbit_security.models import Severity
from orbit_security.oauth_sentinel import (
    OAuthFlowSentinel,
    OAuthFinding,
    OAuthFlawType,
)


def test_oauth_finding_to_dict():
    finding = OAuthFinding(
        vulnerable=True,
        flaw_type=OAuthFlawType.REDIRECT_URI_HIJACK.value,
        target_domain="auth.target.com",
        auth_endpoint="https://auth.target.com/oauth/authorize",
        client_id="client_123",
        redirect_uri="https://attacker.victim.com/callback",
        variant="subdomain_injection",
        severity=Severity.HIGH,
        cvss_score=8.1,
    )
    d = finding.to_dict()
    assert d["vulnerable"] is True
    assert d["flaw_type"] == "oauth_redirect_uri_hijack"
    assert d["severity"] == "HIGH"
    assert d["cvss_score"] == 8.1
    assert "CWE-601" in d["cwe_id"]


def test_redirect_uri_flexibility_positive():
    mock_responses = {
        "subdomain_injection": (302, "", {"location": "https://attacker.victim.com/callback?code=xyz123"}),
        "suffix_evasion": (400, "invalid_redirect_uri", {}),
        "path_traversal": (400, "invalid_redirect_uri", {}),
        "protocol_downgrade": (400, "invalid_redirect_uri", {}),
    }

    findings = OAuthFlowSentinel.audit_redirect_uri_flexibility(
        auth_url="https://auth.victim.com/oauth/authorize",
        valid_client_id="web-portal",
        base_redirect="https://victim.com/callback",
        mock_responses=mock_responses,
    )

    assert len(findings) == 1
    assert findings[0].vulnerable is True
    assert findings[0].variant == "subdomain_injection"
    assert findings[0].cvss_score == 8.1
    assert "subdomain_injection" in findings[0].evidence


def test_redirect_uri_flexibility_path_traversal():
    mock_responses = {
        "subdomain_injection": (400, "invalid_redirect_uri", {}),
        "suffix_evasion": (400, "invalid_redirect_uri", {}),
        "path_traversal": (302, "", {"location": "https://victim.com/callback/../../open-redirect?code=sec456"}),
        "protocol_downgrade": (400, "invalid_redirect_uri", {}),
    }

    findings = OAuthFlowSentinel.audit_redirect_uri_flexibility(
        auth_url="https://auth.victim.com/oauth/authorize",
        valid_client_id="web-portal",
        base_redirect="https://victim.com/callback",
        mock_responses=mock_responses,
    )

    assert len(findings) == 1
    assert findings[0].variant == "path_traversal"


def test_redirect_uri_flexibility_negative():
    mock_responses = {
        "subdomain_injection": (400, "invalid_redirect_uri", {}),
        "suffix_evasion": (400, "invalid_redirect_uri", {}),
        "path_traversal": (400, "invalid_redirect_uri", {}),
        "protocol_downgrade": (400, "invalid_redirect_uri", {}),
    }

    findings = OAuthFlowSentinel.audit_redirect_uri_flexibility(
        auth_url="https://auth.victim.com/oauth/authorize",
        valid_client_id="web-portal",
        base_redirect="https://victim.com/callback",
        mock_responses=mock_responses,
    )

    assert len(findings) == 0


def test_state_parameter_enforcement_missing_state():
    mock_resp = (302, "", {"location": "https://victim.com/callback?code=abc789"})
    finding = OAuthFlowSentinel.audit_state_parameter_enforcement(
        auth_url="https://auth.victim.com/oauth/authorize",
        client_id="web-portal",
        redirect_uri="https://victim.com/callback",
        mock_response=mock_resp,
    )

    assert finding is not None
    assert finding.vulnerable is True
    assert finding.flaw_type == OAuthFlawType.LOGIN_CSRF.value
    assert finding.cvss_score == 4.3
    assert "CWE-352" in finding.cwe_id


def test_state_parameter_enforcement_required_state():
    mock_resp = (400, "state parameter is mandatory", {})
    finding = OAuthFlowSentinel.audit_state_parameter_enforcement(
        auth_url="https://auth.victim.com/oauth/authorize",
        client_id="web-portal",
        redirect_uri="https://victim.com/callback",
        mock_response=mock_resp,
    )
    assert finding is None


def test_pkce_enforcement_missing():
    # Returns 400 with invalid_code rather than complaining about code_verifier
    mock_resp = (400, '{"error": "invalid_grant", "error_description": "Authorization code expired"}', {})
    finding = OAuthFlowSentinel.audit_pkce_enforcement(
        token_url="https://auth.victim.com/oauth/token",
        client_id="mobile-app",
        mock_response=mock_resp,
    )
    assert finding is not None
    assert finding.vulnerable is True
    assert finding.flaw_type == OAuthFlawType.MISSING_PKCE.value
    assert finding.cvss_score == 6.5


def test_pkce_enforcement_present():
    mock_resp = (400, '{"error": "invalid_request", "error_description": "Missing code_verifier"}', {})
    finding = OAuthFlowSentinel.audit_pkce_enforcement(
        token_url="https://auth.victim.com/oauth/token",
        client_id="mobile-app",
        mock_response=mock_resp,
    )
    assert finding is None


def test_oidc_metadata_insecure_none_algorithm():
    mock_config = {
        "issuer": "https://auth.victim.com",
        "authorization_endpoint": "https://auth.victim.com/authorize",
        "token_endpoint": "https://auth.victim.com/token",
        "id_token_signing_alg_values_supported": ["RS256", "none"],
    }
    findings = OAuthFlowSentinel.audit_oidc_metadata(
        domain="auth.victim.com",
        mock_config=mock_config,
    )

    none_findings = [f for f in findings if f.flaw_type == OAuthFlawType.OIDC_INSECURE_SIGNING.value]
    assert len(none_findings) == 1
    assert none_findings[0].cvss_score == 9.8
    assert none_findings[0].severity == Severity.CRITICAL


def test_oidc_metadata_internal_leak():
    mock_config = {
        "issuer": "https://auth.victim.com",
        "authorization_endpoint": "https://auth.victim.com/authorize",
        "token_endpoint": "http://10.200.4.15:8080/token",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    findings = OAuthFlowSentinel.audit_oidc_metadata(
        domain="auth.victim.com",
        mock_config=mock_config,
    )

    leak_findings = [f for f in findings if f.flaw_type == OAuthFlawType.OIDC_INTERNAL_LEAK.value]
    assert len(leak_findings) == 1
    assert "10.200.4.15" in leak_findings[0].evidence


def test_audit_target_unified():
    mock_oidc = {
        "issuer": "https://auth.victim.com",
        "id_token_signing_alg_values_supported": ["RS256", "none"],
    }
    result = OAuthFlowSentinel.audit_target(
        target_domain="auth.victim.com",
        mock_oidc=mock_oidc,
    )
    assert result is not None
    assert result["vulnerable"] is True
    assert result["flaw_type"] == OAuthFlawType.OIDC_INSECURE_SIGNING.value


def test_ssrf_host_blocking():
    assert OAuthFlowSentinel.audit_oidc_metadata("127.0.0.1") == []
    assert OAuthFlowSentinel.audit_oidc_metadata("169.254.169.254") == []
    assert OAuthFlowSentinel.audit_redirect_uri_flexibility("http://127.0.0.1/auth", "client", "https://victim.com") == []
