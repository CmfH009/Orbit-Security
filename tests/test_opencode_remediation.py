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


def test_remediation_default_model_and_call_opencode_uses_file_and_archived(monkeypatch, tmp_path):
    """Verifies local zero-cost default model, native exe preference, and --file/--archived invocation."""
    import subprocess

    synth = OpenCodeRemediationSynthesizer(patches_dir=tmp_path / "patches", enable_blackboard=False)
    assert synth.model_name == "ollama/qwen2.5-coder:3b"
    synth.opencode_bin = "opencode.exe"

    seen_cmds = []

    def _fake_run(cmd, *args, **kwargs):
        seen_cmds.append((list(cmd), kwargs.get("env")))
        assert "--archived" in cmd
        assert "--file" in cmd
        file_idx = cmd.index("--file") + 1
        assert Path(cmd[file_idx]).exists()
        return subprocess.CompletedProcess(
            cmd,
            0,
            "Commit: fix(nginx): deny dotfiles\n```nginx\nlocation ~ /\\.git { deny all; }\n```\n",
            "",
        )

    monkeypatch.setattr("orbit_security.opencode_remediation.subprocess.run", _fake_run)
    patch_content, commit_msg = synth._call_opencode(
        domain="example.com",
        finding_id="F-99",
        finding_title="Exposed .git",
        severity="CRITICAL",
        description="Exposed repo",
        evidence="200 OK",
        component="nginx",
    )
    assert commit_msg == "fix(nginx): deny dotfiles"
    assert "deny all;" in patch_content
    assert len(seen_cmds) == 1


def test_create_remediation_pull_request_with_local_repo_creates_branch_and_commits(monkeypatch, tmp_path):
    """When local_repo_dir is supplied, git branch/add/commit/push run before gh pr create."""
    import subprocess

    synth = OpenCodeRemediationSynthesizer(patches_dir=tmp_path / "patches", enable_blackboard=False)
    artifact = RemediationPatchArtifact(
        domain="example.com",
        finding_id="12345678abcd",
        finding_title="Missing DMARC",
        severity="HIGH",
        target_component="dns",
        patch_content='_dmarc.example.com. 300 IN TXT "v=DMARC1; p=quarantine;"',
        commit_message="fix(dns): add DMARC",
        verification_passed=True,
        verification_notes="ok",
        created_at="2026-11-18T00:00:00Z",
        generator="opencode",
    )

    seen_cmds = []

    def _fake_run(cmd, *args, **kwargs):
        seen_cmds.append(list(cmd))
        if cmd[:2] == ["gh", "pr"]:
            return subprocess.CompletedProcess(cmd, 0, "https://github.com/org/repo/pull/7\n", "")
        return subprocess.CompletedProcess(cmd, 0, "ok", "")

    monkeypatch.setattr("orbit_security.opencode_remediation.subprocess.run", _fake_run)
    res = synth.create_remediation_pull_request(
        artifact=artifact,
        repo_target="org/repo",
        dry_run=False,
        local_repo_dir=tmp_path,
    )
    assert res["success"] is True
    assert res["pr_url"] == "https://github.com/org/repo/pull/7"
    assert any(c[:3] == ["git", "checkout", "-B"] for c in seen_cmds)
    assert any(c[:2] == ["git", "commit"] for c in seen_cmds)
    assert any(c[:2] == ["git", "push"] for c in seen_cmds)
