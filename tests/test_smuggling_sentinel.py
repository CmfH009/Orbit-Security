"""Unit tests for HttpRequestSmugglingSentinel (test_smuggling_sentinel.py)."""

import pytest

from orbit_security.models import Severity
from orbit_security.smuggling_sentinel import (
    HttpRequestSmugglingSentinel,
    SmugglingFinding,
    SmugglingFlawType,
)


def test_smuggling_finding_to_dict():
    finding = SmugglingFinding(
        vulnerable=True,
        flaw_type=SmugglingFlawType.CL_TE.value,
        target_domain="api.example.com",
        path="/",
        variant="CL.TE (Differential Timing)",
        delta_ms=2500.0,
        status_code=504,
        evidence="Backend timed out waiting for chunk terminator",
    )
    d = finding.to_dict()
    assert d["vulnerable"] is True
    assert d["flaw_type"] == "http_request_smuggling_cl_te"
    assert d["severity"] == "CRITICAL"
    assert d["cvss_score"] == 9.1
    assert "CWE-444" in d["cwe_id"]
    assert d["delta_ms"] == 2500.0


def test_cl_te_audit_positive_mock():
    finding = HttpRequestSmugglingSentinel.audit_cl_te(
        domain="app.target.com",
        path="/api/v1/ping",
        mock_latency_ms=2800.0,
        mock_status=504,
    )
    assert finding is not None
    assert finding.vulnerable is True
    assert finding.flaw_type == SmugglingFlawType.CL_TE.value
    assert finding.delta_ms == 2800.0
    assert "CL.TE desync" in finding.evidence


def test_cl_te_audit_negative_mock():
    finding = HttpRequestSmugglingSentinel.audit_cl_te(
        domain="app.target.com",
        path="/",
        mock_latency_ms=120.0,
        mock_status=200,
    )
    assert finding is None


def test_te_cl_audit_positive_mock():
    finding = HttpRequestSmugglingSentinel.audit_te_cl(
        domain="checkout.victim.com",
        path="/checkout",
        mock_latency_ms=3100.0,
        mock_status=504,
        mock_supported_variant="spaced_header",
    )
    assert finding is not None
    assert finding.vulnerable is True
    assert finding.flaw_type == SmugglingFlawType.TE_CL.value
    assert "spaced_header" in finding.variant
    assert "spaced_header" in finding.evidence


def test_te_cl_audit_negative_mock():
    finding = HttpRequestSmugglingSentinel.audit_te_cl(
        domain="checkout.victim.com",
        path="/",
        mock_latency_ms=85.0,
        mock_status=200,
        mock_supported_variant="spaced_header",
    )
    assert finding is None


def test_h2_downgrade_positive_mock():
    finding = HttpRequestSmugglingSentinel.audit_h2_te_downgrade(
        domain="gateway.victim.com",
        path="/",
        mock_h2_downgrade=True,
    )
    assert finding is not None
    assert finding.vulnerable is True
    assert finding.flaw_type == SmugglingFlawType.H2_TE_DOWNGRADE.value
    assert "H2.TE" in finding.variant


def test_h2_downgrade_negative_mock():
    finding = HttpRequestSmugglingSentinel.audit_h2_te_downgrade(
        domain="gateway.victim.com",
        path="/",
        mock_h2_downgrade=False,
    )
    assert finding is None


def test_audit_target_unified_cl_te():
    result = HttpRequestSmugglingSentinel.audit_target(
        target_domain="secure.target.com",
        path="/",
        mock_cl_te={"latency_ms": 2400.0, "status": 504},
    )
    assert result is not None
    assert result["vulnerable"] is True
    assert result["flaw_type"] == "http_request_smuggling_cl_te"


def test_audit_target_unified_te_cl():
    result = HttpRequestSmugglingSentinel.audit_target(
        target_domain="secure.target.com",
        path="/",
        mock_te_cl={"latency_ms": 2600.0, "status": 504, "variant": "tab_prefixed"},
    )
    assert result is not None
    assert result["vulnerable"] is True
    assert result["flaw_type"] == "http_request_smuggling_te_cl"
    assert "tab_prefixed" in result["variant"]


def test_audit_target_unified_h2():
    result = HttpRequestSmugglingSentinel.audit_target(
        target_domain="secure.target.com",
        path="/",
        mock_h2={"downgrade": True},
    )
    assert result is not None
    assert result["vulnerable"] is True
    assert result["flaw_type"] == "http_request_smuggling_h2_downgrade"


def test_ssrf_host_blocking():
    assert HttpRequestSmugglingSentinel.audit_cl_te("127.0.0.1") is None
    assert HttpRequestSmugglingSentinel.audit_cl_te("169.254.169.254") is None
    assert HttpRequestSmugglingSentinel.audit_te_cl("localhost") is None
    assert HttpRequestSmugglingSentinel.audit_h2_te_downgrade("0.0.0.0") is None
