"""Unit tests for DependencyConfusionSentinel (test_dependency_sentinel.py)."""

import pytest

from orbit_security.models import Severity
from orbit_security.dependency_sentinel import (
    DependencyConfusionSentinel,
    DependencyFinding,
    DependencyStatus,
    PackageEcosystem,
)


def test_dependency_finding_to_dict():
    finding = DependencyFinding(
        vulnerable=True,
        package_name="@target/internal-auth",
        ecosystem="npm",
        target_domain="target.com",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        evidence="Package is unclaimed on public npm",
    )
    d = finding.to_dict()
    assert d["vulnerable"] is True
    assert d["package_name"] == "@target/internal-auth"
    assert d["severity"] == "CRITICAL"
    assert d["cvss_score"] == 9.8
    assert "CWE-427" in d["cwe_id"]


def test_is_internal_naming_pattern():
    assert DependencyConfusionSentinel.is_internal_naming_pattern("@target/auth") is True
    assert DependencyConfusionSentinel.is_internal_naming_pattern("target-internal") is True
    assert DependencyConfusionSentinel.is_internal_naming_pattern("payments-core") is True
    assert DependencyConfusionSentinel.is_internal_naming_pattern("corp-sdk") is True
    assert DependencyConfusionSentinel.is_internal_naming_pattern("acme-billing", custom_org_names=["acme"]) is True

    # Standard public packages should NOT match
    assert DependencyConfusionSentinel.is_internal_naming_pattern("react") is False
    assert DependencyConfusionSentinel.is_internal_naming_pattern("lodash") is False
    assert DependencyConfusionSentinel.is_internal_naming_pattern("express") is False
    assert DependencyConfusionSentinel.is_internal_naming_pattern("requests") is False


def test_harvest_package_references():
    js_source = """
    import { AuthManager } from '@victimcorp/auth-lib';
    const payments = require('victim-core');
    const lodash = require('lodash');
    """
    pkgs = DependencyConfusionSentinel.harvest_package_references(js_source)
    names = {name for name, _ in pkgs}
    assert "@victimcorp/auth-lib" in names
    assert "victim-core" in names
    assert "lodash" not in names


def test_harvest_package_references_json_block():
    package_json = """
    {
      "name": "frontend",
      "dependencies": {
        "@myorg/ui-components": "^2.1.0",
        "react": "^18.2.0",
        "myorg-infra": "1.0.0"
      }
    }
    """
    pkgs = DependencyConfusionSentinel.harvest_package_references(package_json, custom_org_names=["myorg"])
    names = {name for name, _ in pkgs}
    assert "@myorg/ui-components" in names
    assert "myorg-infra" in names
    assert "react" not in names


def test_harvest_python_packages():
    reqs = """
    flask==2.3.2
    corp-internal>=1.0.0
    pydantic==2.0
    """
    pkgs = DependencyConfusionSentinel.harvest_package_references(reqs)
    names = {name for name, _ in pkgs}
    assert "corp-internal" in names
    assert "flask" not in names


def test_check_npm_registry_mock():
    # 404 indicates unclaimed namespace
    status_unclaimed = DependencyConfusionSentinel.check_npm_registry_availability(
        "@target/unclaimed-pkg", mock_status=404
    )
    assert status_unclaimed.is_claimed_publicly is False
    assert status_unclaimed.status_code == 404

    # 200 indicates claimed package
    status_claimed = DependencyConfusionSentinel.check_npm_registry_availability(
        "@target/claimed-pkg", mock_status=200
    )
    assert status_claimed.is_claimed_publicly is True


def test_check_pypi_registry_mock():
    status_unclaimed = DependencyConfusionSentinel.check_pypi_registry_availability(
        "target-corp-internal", mock_status=404
    )
    assert status_unclaimed.is_claimed_publicly is False

    status_claimed = DependencyConfusionSentinel.check_pypi_registry_availability(
        "target-corp-internal", mock_status=200
    )
    assert status_claimed.is_claimed_publicly is True


def test_evaluate_bounty_impact_unclaimed():
    status = DependencyStatus(
        package_name="@victim/corp-auth",
        ecosystem="npm",
        is_claimed_publicly=False,
        status_code=404,
        registry_url="https://registry.npmjs.org/@victim%2fcorp-auth",
        is_internal_pattern=True,
    )
    finding = DependencyConfusionSentinel.evaluate_bounty_impact(
        package_name="@victim/corp-auth",
        ecosystem="npm",
        target_domain="victim.com",
        status=status,
    )
    assert finding is not None
    assert finding.vulnerable is True
    assert finding.cvss_score == 9.8
    assert finding.severity == Severity.CRITICAL
    assert "UNCLAIMED" in finding.evidence


def test_evaluate_bounty_impact_claimed():
    status = DependencyStatus(
        package_name="@victim/corp-auth",
        ecosystem="npm",
        is_claimed_publicly=True,
        status_code=200,
        registry_url="https://registry.npmjs.org/@victim%2fcorp-auth",
        is_internal_pattern=True,
    )
    finding = DependencyConfusionSentinel.evaluate_bounty_impact(
        package_name="@victim/corp-auth",
        ecosystem="npm",
        target_domain="victim.com",
        status=status,
    )
    assert finding is None


def test_audit_source_code_end_to_end():
    source = "const sdk = require('@victim/internal-sdk');"
    mock_npm = {"@victim/internal-sdk": 404}

    findings = DependencyConfusionSentinel.audit_source_code(
        source_text=source,
        target_domain="victim.com",
        mock_npm_statuses=mock_npm,
    )
    assert len(findings) == 1
    assert findings[0].package_name == "@victim/internal-sdk"
    assert findings[0].vulnerable is True


def test_audit_target_unified():
    source = "const sdk = require('@victim/internal-sdk');"
    mock_npm = {"@victim/internal-sdk": 404}

    result = DependencyConfusionSentinel.audit_target(
        target_domain="victim.com",
        source_text=source,
        mock_npm=mock_npm,
    )
    assert result is not None
    assert result["vulnerable"] is True
    assert result["flaw_type"] == "dependency_confusion_namespace_takeover"
    assert result["cvss_score"] == 9.8
