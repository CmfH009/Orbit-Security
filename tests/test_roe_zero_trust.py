"""Unit and empirical tests for Zero-Trust Rules of Engagement (RoE) validation engine.

Verifies:
1. Scope checking: exact hostnames, wildcard prefixes (*.target.com), and apex domain handling.
2. Exclusion enforcement: exact exclusions and wildcard exclusion patterns (*.internal.target.com).
3. Zero-trust boundary invariance: targets matching in_scope but also matching out_of_scope are denied.
4. RulesOfEngagementEngine action validation: target and vulnerability category checking.
5. BountyActiveProber RoE integration: out-of-scope targets are never actively probed.
6. BountyRollingDaemon RoE integration: CT log discovery and cloud sentinel fleets filter out excluded targets.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.bounty_radar import (
    BountyProgram,
    RulesOfEngagementEngine,
    is_target_in_scope,
    is_target_out_of_scope,
    is_target_permitted,
)
from orbit_security.bounty_active_prober import ActiveProbeFinding, BountyActiveProber
from orbit_security.bounty_rolling_daemon import BountyRollingDaemon


def test_target_scope_matching():
    in_scope = ["*.shopify.com", "*.myshopify.com", "partner.shopifyapps.com"]

    assert is_target_in_scope("shopify.com", in_scope) is True
    assert is_target_in_scope("admin.shopify.com", in_scope) is True
    assert is_target_in_scope("checkout.staging.myshopify.com", in_scope) is True
    assert is_target_in_scope("partner.shopifyapps.com", in_scope) is True

    # Out of scope / domain mismatch
    assert is_target_in_scope("other-shopify.com", in_scope) is False
    assert is_target_in_scope("api.shopifyapps.com", in_scope) is False
    assert is_target_in_scope("google.com", in_scope) is False
    assert is_target_in_scope("", in_scope) is False


def test_target_exclusion_matching():
    out_of_scope = ["community.shopify.com", "*.internal.shopify.com", "corp.target.com"]

    assert is_target_out_of_scope("community.shopify.com", out_of_scope) is True
    assert is_target_out_of_scope("dev.internal.shopify.com", out_of_scope) is True
    assert is_target_out_of_scope("corp.target.com", out_of_scope) is True

    assert is_target_out_of_scope("admin.shopify.com", out_of_scope) is False
    assert is_target_out_of_scope("shopify.com", out_of_scope) is False
    assert is_target_out_of_scope("", out_of_scope) is False


def test_strict_zero_trust_permission():
    in_scope = ["*.target.com"]
    out_of_scope = ["community.target.com", "*.secret.target.com"]

    # Allowed: in scope and not in out-of-scope
    assert is_target_permitted("api.target.com", in_scope, out_of_scope) is True
    assert is_target_permitted("target.com", in_scope, out_of_scope) is True

    # Blocked: in scope but explicitly excluded
    assert is_target_permitted("community.target.com", in_scope, out_of_scope) is False
    assert is_target_permitted("db.secret.target.com", in_scope, out_of_scope) is False

    # Blocked: not in scope
    assert is_target_permitted("attacker.com", in_scope, out_of_scope) is False


def test_bounty_program_roe_methods():
    prog = BountyProgram(
        program_id="test_roe_prog",
        name="Test RoE Program",
        in_scope=["*.corp.com"],
        out_of_scope=["legacy.corp.com"],
        excluded_vulnerabilities=["mail_spoofing"],
    )

    assert prog.is_target_in_scope("api.corp.com") is True
    assert prog.is_target_permitted("api.corp.com") is True

    # Excluded target
    assert prog.is_target_in_scope("legacy.corp.com") is False
    assert prog.is_target_permitted("legacy.corp.com") is False

    # Excluded vector
    assert prog.is_vulnerability_in_scope("mail_spoofing") is False
    assert prog.is_vulnerability_in_scope("subdomain_takeover") is True


def test_rules_of_engagement_engine_validation():
    prog = BountyProgram(
        program_id="test_roe_prog",
        name="Test RoE Program",
        in_scope=["*.corp.com"],
        out_of_scope=["unauthorized.corp.com"],
        excluded_vulnerabilities=["cors_wildcard_origin"],
    )

    # Valid action
    ok, reason = RulesOfEngagementEngine.validate_action(prog, "portal.corp.com", "subdomain_takeover")
    assert ok is True
    assert reason == "ACTION_PERMITTED"

    # Out of scope target
    ok, reason = RulesOfEngagementEngine.validate_action(prog, "unauthorized.corp.com", "subdomain_takeover")
    assert ok is False
    assert "TARGET_EXPLICITLY_OUT_OF_SCOPE" in reason

    # Target not in scope
    ok, reason = RulesOfEngagementEngine.validate_action(prog, "external.com", "subdomain_takeover")
    assert ok is False
    assert "TARGET_NOT_IN_SCOPE" in reason

    # Flaw excluded by policy
    ok, reason = RulesOfEngagementEngine.validate_action(prog, "portal.corp.com", "cors_wildcard_origin")
    assert ok is False
    assert "FLAW_TYPE_EXCLUDED_BY_POLICY" in reason


def test_bounty_active_prober_respects_roe():
    prober = BountyActiveProber()
    probed_hosts: List[str] = []

    def fake_probe_host_active(host: str, offline: bool = False, **kwargs):
        probed_hosts.append(host)
        return []

    prober.probe_host_active = fake_probe_host_active

    prog = BountyProgram(
        program_id="test_prober_prog",
        name="Test Prober",
        in_scope=["*.target.com"],
        out_of_scope=["api.target.com", "admin.target.com"],
    )

    # probe_program expands prefixes like "api", "admin", "dev", "staging", etc.
    prober.probe_program(prog, max_subdomains=5, offline=True)

    # Ensure out-of-scope targets were strictly NEVER passed to probe_host_active
    assert "api.target.com" not in probed_hosts
    assert "admin.target.com" not in probed_hosts


def test_bounty_rolling_daemon_ct_sweep_respects_roe():
    daemon = BountyRollingDaemon(offline=True, enable_ct=True)

    # Mock worker load_programs to return a program with an exclusion
    prog = BountyProgram(
        program_id="prog_with_exclusion",
        name="Exclusion Program",
        in_scope=["*.target.com"],
        out_of_scope=["forbidden.target.com"],
    )
    daemon.worker.load_programs = MagicMock(return_value=[prog])

    # Mock ct_daemon poll_domains returning both permitted and excluded subdomains
    mock_poll = [{
        "new_certificates": 2,
        "new_subdomains": ["allowed.target.com", "forbidden.target.com"],
        "takeover_findings": [
            {"domain": "allowed.target.com", "flaw_type": "subdomain_takeover"},
            {"domain": "forbidden.target.com", "flaw_type": "subdomain_takeover"},
        ],
    }]
    daemon.ct_daemon.poll_domains = MagicMock(return_value=mock_poll)

    res = daemon.sweep_ct_logs_for_program("prog_with_exclusion")
    assert res is not None
    assert "allowed.target.com" in res["new_subdomains"]
    assert "forbidden.target.com" not in res["new_subdomains"]
    assert len(res["takeover_findings"]) == 1
    assert res["takeover_findings"][0]["domain"] == "allowed.target.com"
