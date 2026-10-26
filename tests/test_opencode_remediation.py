#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_opencode_remediation.py: Unit & Empirical Tests for OpenCode Remediation
==================================================================================
Tests:
1. Target component inference across perimeter findings (DNS, Nginx, Apache, Code)
2. Deterministic fallback generation for DMARC, SPF, Takeovers, Dotfiles, CORS
3. Verification engine logic (balanced braces, token validation, DNS sanity)
4. Blackboard event publishing to SQLite WAL bus
5. File persistence and conventional commit metadata
6. AST Code Sentinel auto-fix for unimported stdlib modules
"""

from __future__ import annotations

import ast
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.blackboard import Blackboard, EVENT_OPENCODE_REMEDIATION_STAGED, EVENT_OPENCODE_REMEDIATION_VERIFIED
from orbit_security.opencode_remediation import OpenCodeRemediationSynthesizer, RemediationPatchArtifact
from orbit_security.ast_sentinel import ASTCodeSentinel


@pytest.fixture
def temp_blackboard(tmp_path):
    """Provides an isolated SQLite WAL Blackboard instance."""
    db_file = tmp_path / "test_blackboard.db"
    return Blackboard(db_path=db_file)


@pytest.fixture
def synthesizer(tmp_path, temp_blackboard):
    """Provides an OpenCodeRemediationSynthesizer wired to temp directories."""
    patches_dir = tmp_path / "patches"
    return OpenCodeRemediationSynthesizer(
        blackboard=temp_blackboard,
        patches_dir=patches_dir,
        model_name="google/gemini-2.5-flash",
    )


def test_infer_target_component(synthesizer):
    """Verifies finding description routing to the right architecture layer."""
    assert synthesizer._infer_target_component("Missing DMARC Policy", "No TXT record", "") == "dns"
    assert synthesizer._infer_target_component("Exposed .git Repository", "Found .git/HEAD", "") == "nginx"
    assert synthesizer._infer_target_component("Insecure Apache .htaccess", "AllowOverride All", "") == "apache"
    assert synthesizer._infer_target_component("Unpinned GitHub Action", "uses: actions/checkout@v2", "") == "code"


def test_deterministic_fallback_generation(synthesizer):
    """Verifies deterministic synthesis generates valid configurations."""
    # 1. DMARC
    patch, commit = synthesizer._generate_deterministic_fallback("example.com", "F-01", "Missing DMARC", "dns", "")
    assert "v=DMARC1; p=quarantine" in patch
    assert commit.startswith("fix(dns):")

    # 2. Exposed Git / Env
    patch, commit = synthesizer._generate_deterministic_fallback("client.io", "F-02", "Exposed .env file", "nginx", "")
    assert "location ~* (/\\.git|/\\.env" in patch
    assert "deny all;" in patch
    assert commit.startswith("fix(nginx):")

    # 3. CORS
    patch, commit = synthesizer._generate_deterministic_fallback("api.co", "F-03", "Permissive CORS Wildcard", "nginx", "")
    assert "Access-Control-Allow-Origin" in patch
    assert commit.startswith("fix(cors):")


def test_patch_verification_engine(synthesizer):
    """Verifies static verification catches syntax errors, unbalanced braces, and leaks."""
    # Valid Nginx block
    valid_nginx = "location /secure { deny all; }"
    ok, notes = synthesizer.verify_patch("nginx", valid_nginx)
    assert ok is True

    # Unbalanced braces in Nginx
    broken_nginx = "location /secure { deny all; "
    ok, notes = synthesizer.verify_patch("nginx", broken_nginx)
    assert ok is False
    assert "Unbalanced braces" in notes

    # Empty patch
    ok, notes = synthesizer.verify_patch("dns", "   ")
    assert ok is False

    # Forbidden prompt token leakage
    leaked_patch = "Here is the code: location / { return 200; }"
    ok, notes = synthesizer.verify_patch("nginx", leaked_patch)
    assert ok is False
    assert "forbidden token" in notes


def test_end_to_end_synthesis_and_blackboard_publish(synthesizer, temp_blackboard):
    """Tests end-to-end remediation lifecycle and SQLite WAL blackboard publication."""
    artifact = synthesizer.synthesize_remediation(
        domain="agency-client.com",
        finding_id="ORBIT-SEC-09",
        finding_title="Exposed .git directory",
        severity="CRITICAL",
        description="Publicly exposed git object database detected via HTTP 200 on /.git/config",
        evidence="[core] repositoryformatversion = 0",
        force_fallback=True,
    )

    assert artifact.domain == "agency-client.com"
    assert artifact.target_component == "nginx"
    assert artifact.verification_passed is True
    assert artifact.generator == "deterministic_engine"
    assert Path(artifact.file_path).exists()
    assert "deny all;" in artifact.patch_content

    # Verify Blackboard received the staged and verified events
    events = temp_blackboard.get_recent(limit=10)
    event_types = [e["event_type"] for e in events]
    assert EVENT_OPENCODE_REMEDIATION_STAGED in event_types
    assert EVENT_OPENCODE_REMEDIATION_VERIFIED in event_types


def test_ast_sentinel_auto_fix(tmp_path):
    """Verifies ASTCodeSentinel auto_fix_missing_imports injects missing stdlib modules cleanly."""
    sentinel = ASTCodeSentinel()
    test_py = tmp_path / "sample_omission.py"
    test_py.write_text(
        '"""Sample module with omitted imports."""\n'
        'from __future__ import annotations\n\n'
        'def handle_request():\n'
        '    now = time.time()\n'
        '    data = json.dumps({"timestamp": now})\n'
        '    return data\n',
        encoding="utf-8"
    )

    # Pre-check should detect missing 'time' and 'json'
    inspection = sentinel.inspect_file(test_py)
    assert inspection["ok"] is False
    missing_mods = {m["module"] for m in inspection["missing_imports"]}
    assert "time" in missing_mods
    assert "json" in missing_mods

    # Auto-fix
    fixed, fixed_list = sentinel.auto_fix_missing_imports(test_py)
    assert fixed is True
    assert "json" in fixed_list
    assert "time" in fixed_list

    # Re-inspection must be 100% clean
    clean_check = sentinel.inspect_file(test_py)
    assert clean_check["ok"] is True
    assert len(clean_check["missing_imports"]) == 0
