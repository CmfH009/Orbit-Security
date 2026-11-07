#!/usr/bin/env python3
"""
Unit tests for Milestone M1: Stage & Calibrate Cohort 11 (Roadmap W2.2 & W2.4).

Verifies:
1. Quality floor thresholds: mean score >= 60.0, >= 70% at grade C+ or higher, zero hygiene-only F grades.
2. Mailbox validation & anti-bounce preflight gate (0 NO_MX, 0 REFUTED, HTML entity de-obfuscation).
3. Deterministic A/B variant and 30% holdout split.
4. RFC 5322 .eml draft formatting, required headers, and plain text pitch copies.
5. Campaign manifest schema and metrics in outbound_queue/cohort_11/cohort_11_manifest.json.
6. OPSEC gitignore enforcement for outbound_queue/.
7. CLI entrypoint behaviors (--preflight, --stage, --output-dir).
"""

from __future__ import annotations

import email
from email.message import EmailMessage
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_cohort_11_targets_definition():
    """Verifies that Cohort 11 contains exactly 10 fresh, uncontacted premier digital consultancies."""
    from scripts.stage_cohort_11 import COHORT_11_TARGETS

    assert len(COHORT_11_TARGETS) == 10
    expected_domains = {
        "8thlight.com",
        "atomicobject.com",
        "headway.io",
        "launchpadlab.com",
        "crema.us",
        "nerdery.com",
        "txidigital.com",
        "revelry.co",
        "nebulab.com",
        "subvisual.com",
    }
    actual_domains = {t["agency_domain"] for t in COHORT_11_TARGETS}
    assert actual_domains == expected_domains

    for target in COHORT_11_TARGETS:
        assert target["agency_name"], "Missing agency name"
        assert target["agency_domain"], "Missing agency domain"
        assert "@" in target["contact_email"], f"Invalid contact email: {target['contact_email']}"
        assert target["contact_email"].endswith("@" + target["agency_domain"]), (
            f"Contact email {target['contact_email']} does not match apex domain {target['agency_domain']}"
        )
        assert target["client_anchor"], "Missing client anchor"
        assert target["focus"], "Missing agency focus specialization"


def test_cohort_11_quality_floor_thresholds():
    """Verifies R1 quality floor: mean score >= 60.0, >= 70% grade C+ (score >= 60), zero hygiene-only Fs."""
    from scripts.stage_cohort_11 import audit_cohort_11, evaluate_quality_floor

    audited = audit_cohort_11()
    assert len(audited) == 10

    floor_result = evaluate_quality_floor(audited)
    assert floor_result["quality_floor_met"] is True, f"Quality floor failed: {floor_result}"
    assert floor_result["mean_score"] >= 60.0, f"Mean score {floor_result['mean_score']} < 60.0"
    assert floor_result["grade_c_or_better_ratio"] >= 0.70, (
        f"C+ ratio {floor_result['grade_c_or_better_ratio']} < 70%"
    )
    assert floor_result["hygiene_only_f_count"] == 0, (
        f"Found {floor_result['hygiene_only_f_count']} hygiene-only F grades"
    )

    # Validate individual scores and grades
    for target in audited:
        assert "score" in target
        assert "grade" in target
        assert 0 <= target["score"] <= 100
        assert target["grade"] in ("A+", "A", "B", "C", "D", "F")
        if target["grade"] in ("A+", "A", "B", "C"):
            assert target["score"] >= 60


def test_exploitability_floor_prevents_hygiene_only_f_grades():
    """Verifies that an agency with only low/hygiene findings is bounded at score 60 (grade C)."""
    from orbit_security.scoring import ScoreItem, Severity, score_findings

    # Multiple low & hygiene findings without Critical or High
    findings = [
        ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
        ScoreItem(title="Missing Permissions-Policy Header", severity=Severity.INFO),
        ScoreItem(title="Missing Referrer-Policy Header", severity=Severity.INFO),
        ScoreItem(title="Missing X-Frame-Options Header", severity=Severity.INFO),
        ScoreItem(title="Missing Strict-Transport-Security (HSTS) Header", severity=Severity.MEDIUM),
        ScoreItem(title="DMARC Policy Set to Monitoring Only (p=none)", severity=Severity.MEDIUM),
    ]
    res = score_findings(findings)
    assert res.has_critical is False
    assert res.has_high is False
    assert res.score >= 60
    assert res.grade in ("A+", "A", "B", "C")
    assert res.grade != "F"


def test_cohort_11_mailbox_validation_and_preflight(monkeypatch: pytest.MonkeyPatch):
    """Verifies deliverability preflight integration, MX validation, and de-obfuscation."""
    from scripts.stage_cohort_11 import (
        COHORT_11_TARGETS,
        deobfuscate_and_extract_emails,
        run_deliverability_preflight,
        validate_candidate_mailbox,
    )

    # 1. Strict syntax & apex domain validation
    assert validate_candidate_mailbox("@example.com", "example.com")[0] is False
    assert validate_candidate_mailbox("user@", "example.com")[0] is False
    assert validate_candidate_mailbox("attacker@evil.com", "8thlight.com")[0] is False
    assert validate_candidate_mailbox("contact@8thlight.com", "8thlight.com")[0] is True
    assert validate_candidate_mailbox("ahoy@headway.io", "headway.io")[0] is True

    # 2. HTML entity and pattern de-obfuscation check
    obfuscated_html = """
    <html>
      <body>
        <p>Contact us: <a href="mailto:hello&#64;8thlight.com">hello&#64;8thlight.com</a></p>
        <p>Engineering: contact [at] atomicobject [dot] com</p>
        <p>Partners: hello(at)headway(dot)io</p>
        <p>Ignore: example@test.com and noreply@8thlight.com</p>
      </body>
    </html>
    """
    extracted = deobfuscate_and_extract_emails(obfuscated_html)
    assert "hello@8thlight.com" in extracted
    assert "contact@atomicobject.com" in extracted
    assert "hello@headway.io" in extracted
    assert "example@test.com" not in extracted
    assert "noreply@8thlight.com" not in extracted

    # 3. Hermetic preflight gate test with valid MX mocks
    monkeypatch.setattr(
        "scripts.stage_cohort_11.has_mx",
        lambda domain: (True, ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]),
    )
    preflight = run_deliverability_preflight(COHORT_11_TARGETS, skip_network=True)
    assert preflight["gate_passed"] is True
    assert preflight["no_mx_count"] == 0
    assert preflight["refuted_count"] == 0
    assert preflight["total_checked"] == 10
    assert len(preflight["blocking_reasons"]) == 0

    # 4. Verify gate rejection when a target has NO_MX
    bad_targets = [
        {"agency_domain": "broken-mx.invalid", "contact_email": "hello@broken-mx.invalid"},
    ]
    monkeypatch.setattr("scripts.stage_cohort_11.has_mx", lambda domain: (False, []))
    failing_preflight = run_deliverability_preflight(bad_targets, skip_network=False)
    assert failing_preflight["gate_passed"] is False
    assert failing_preflight["no_mx_count"] == 1
    assert any("NO_MX" in r for r in failing_preflight["blocking_reasons"])

    # 5. Verify gate rejection when candidate mailbox is malformed or mismatched
    malformed_targets = [
        {"agency_domain": "8thlight.com", "contact_email": "@8thlight.com"},
        {"agency_domain": "8thlight.com", "contact_email": "attacker@evil.com"},
    ]
    syntax_preflight = run_deliverability_preflight(malformed_targets, skip_network=True)
    assert syntax_preflight["gate_passed"] is False
    assert syntax_preflight["refuted_count"] == 2


def test_cohort_11_ab_allocation_and_holdout_split():
    """Verifies deterministic A/B variant and exact 30% holdout split."""
    from scripts.stage_cohort_11 import (
        COHORT_11_TARGETS,
        assign_ab_variant,
        build_pitch_copy,
        partition_cohort_targets,
    )

    # 1. Exact discrete quotas across Cohort 11: exactly 3 holdouts (30%), 4 A, 3 B
    variants_assigned = [assign_ab_variant(t["agency_domain"]) for t in COHORT_11_TARGETS]
    holdout_count = sum(1 for v in variants_assigned if v["bucket"] == "holdout")
    var_a_count = sum(1 for v in variants_assigned if v["bucket"] == "variant_a")
    var_b_count = sum(1 for v in variants_assigned if v["bucket"] == "variant_b")

    assert holdout_count == 3, f"Expected exactly 3 holdout targets (30%), got {holdout_count}"
    assert var_a_count == 4, f"Expected 4 variant_a targets, got {var_a_count}"
    assert var_b_count == 3, f"Expected 3 variant_b targets, got {var_b_count}"
    assert holdout_count + var_a_count + var_b_count == 10

    # 2. Permutation invariance (order of targets does not change assignments)
    p1 = partition_cohort_targets(COHORT_11_TARGETS)
    p2 = partition_cohort_targets(list(reversed(COHORT_11_TARGETS)))
    assert p1 == p2, "Cohort partitioning must be invariant to input ordering"

    # 3. Determinism and case/whitespace insensitivity
    for t in COHORT_11_TARGETS:
        dom = t["agency_domain"]
        assert assign_ab_variant(dom) == assign_ab_variant(dom)
        assert assign_ab_variant(dom) == assign_ab_variant(dom.upper())
        assert assign_ab_variant(dom) == assign_ab_variant(f"  {dom}  ")

    # 4. Copy check
    target_sample = COHORT_11_TARGETS[0]
    subject_a, body_a = build_pitch_copy(target_sample, "variant_a")
    subject_b, body_b = build_pitch_copy(target_sample, "variant_b")
    subject_h, body_h = build_pitch_copy(target_sample, "holdout")

    assert "White-label security audits" in subject_a
    assert "Automated DMARC & subdomain takeover guard" in subject_b
    assert "Holdout Control" in subject_h or "holdout" in body_h.lower()
    assert target_sample["agency_name"] in body_a
    assert target_sample["client_anchor"] in body_a


def test_stage_cohort_11_generates_valid_rf_5322_eml_and_manifest(tmp_path: Path):
    """Verifies that stage_cohort_11 generates RFC 5322 .eml drafts and a valid manifest."""
    from scripts.stage_cohort_11 import stage_cohort_11

    out_dir = tmp_path / "outbound_queue" / "cohort_11"
    manifest = stage_cohort_11(output_dir=out_dir, skip_network=True)

    assert out_dir.exists()
    manifest_path = out_dir / "cohort_11_manifest.json"
    assert manifest_path.exists()

    # Verify manifest JSON
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_data["cohort"] == "cohort_11"
    assert manifest_data["total_targets"] == 10
    assert manifest_data["quality_floor_met"] is True
    assert manifest_data["mean_score"] >= 60.0
    assert manifest_data["deliverability_preflight"]["gate_passed"] is True

    ab_summary = manifest_data["ab_split_summary"]
    assert ab_summary["variant_a"] == 4
    assert ab_summary["variant_b"] == 3
    assert ab_summary["holdout"] == 3
    assert ab_summary["variant_a"] + ab_summary["variant_b"] + ab_summary["holdout"] == 10

    # Verify drafts per agency
    assert len(manifest_data["targets"]) == 10
    for target in manifest_data["targets"]:
        slug = target["agency_slug"]
        agency_dir = out_dir / slug
        assert agency_dir.is_dir()

        txt_path = agency_dir / "pitch_email.txt"
        eml_path = agency_dir / "pitch_email.eml"
        assert txt_path.exists(), f"Missing {txt_path}"
        assert eml_path.exists(), f"Missing {eml_path}"

        # Verify TXT content
        txt_content = txt_path.read_text(encoding="utf-8")
        assert f"Subject: {target['subject']}" in txt_content
        assert target["agency_name"] in txt_content

        # Verify RFC 5322 EML structure and headers
        eml_bytes = eml_path.read_bytes()
        msg = email.message_from_bytes(eml_bytes)
        # Normalize folded RFC 5322 whitespace in headers
        unfolded_subject = re.sub(r"\s+", " ", str(msg["Subject"])).strip()
        assert unfolded_subject == target["subject"]
        assert msg["Date"], "Missing Date header"
        assert msg["Message-ID"], "Missing Message-ID header"
        assert msg["X-Orbit-Cohort"] == "cohort_11"
        assert msg["X-Orbit-AB-Variant"] == target["ab_variant"]
        assert msg["X-Orbit-Campaign"] == "cohort_11_staging"


def test_outbound_queue_is_gitignored():
    """Verifies R4 / OPSEC: outbound_queue/ must be gitignored to keep client targets uncommitted."""
    gitignore_path = REPO_ROOT / ".gitignore"
    assert gitignore_path.exists(), ".gitignore file missing"
    content = gitignore_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
    assert any("outbound_queue" in line for line in lines), "outbound_queue/ is not in .gitignore"

    # Git check-ignore validation
    try:
        res = subprocess.run(
            ["git", "check-ignore", "outbound_queue/cohort_11/cohort_11_manifest.json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, "Git does not ignore outbound_queue/cohort_11/ files"
    except FileNotFoundError:
        pytest.skip("git binary not available in environment")


def test_cli_preflight_entrypoint():
    """Verifies CLI execution of scripts/stage_cohort_11.py --preflight returns exit code 0."""
    python_exe = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if not python_exe.exists():
        python_exe = Path(sys.executable)

    script_path = REPO_ROOT / "scripts" / "stage_cohort_11.py"
    res = subprocess.run(
        [str(python_exe), str(script_path), "--preflight", "--skip-network"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"CLI preflight failed (code {res.returncode}):\n{res.stdout}\n{res.stderr}"
    assert "Cohort 11 Preflight Deliverability Gate: PASSED" in res.stdout


def test_audit_cohort_11_safe_dict_access_missing_keys():
    """Verifies that audit_cohort_11() safely handles missing client_anchor, focus, or minimal dicts without KeyError."""
    from scripts.stage_cohort_11 import audit_cohort_11

    # Case 1: Missing client_anchor
    targets_missing_anchor = [
        {
            "agency_name": "Anchorless Agency",
            "agency_domain": "anchorless.io",
            "contact_email": "hello@anchorless.io",
            "findings": [],
        }
    ]
    audited_1 = audit_cohort_11(targets_missing_anchor)
    assert len(audited_1) == 1
    assert audited_1[0]["client_anchor"] == "client portfolio"
    assert audited_1[0]["focus"] == "custom engineering and cloud architecture"
    assert audited_1[0]["agency_slug"] == "anchorless-agency"

    # Case 2: Missing focus
    targets_missing_focus = [
        {
            "agency_name": "Focusless Studio",
            "agency_domain": "focusless.com",
            "contact_email": "contact@focusless.com",
            "client_anchor": "acme.com",
            "findings": [],
        }
    ]
    audited_2 = audit_cohort_11(targets_missing_focus)
    assert len(audited_2) == 1
    assert audited_2[0]["client_anchor"] == "acme.com"
    assert audited_2[0]["focus"] == "custom engineering and cloud architecture"

    # Case 3: Completely empty dict
    audited_empty = audit_cohort_11([{}])
    assert len(audited_empty) == 1
    assert audited_empty[0]["agency_name"] == "Unknown Agency"
    assert audited_empty[0]["agency_slug"] == "unknown-agency"
    assert audited_empty[0]["agency_domain"] == ""
    assert audited_empty[0]["contact_email"] == ""
    assert audited_empty[0]["client_anchor"] == "client portfolio"
    assert audited_empty[0]["focus"] == "custom engineering and cloud architecture"
    assert audited_empty[0]["score"] == 100


def test_audit_cohort_11_preserves_custom_attributes():
    """Verifies that audit_cohort_11() preserves custom client_anchor and focus when provided."""
    from scripts.stage_cohort_11 import audit_cohort_11

    custom_targets = [
        {
            "agency_name": "Custom Agency Inc",
            "agency_slug": "custom-agency",
            "agency_domain": "customagency.com",
            "contact_email": "team@customagency.com",
            "client_anchor": "enterprise-client.org",
            "focus": "cloud security architectures",
            "findings": [],
        }
    ]
    audited = audit_cohort_11(custom_targets)
    assert audited[0]["client_anchor"] == "enterprise-client.org"
    assert audited[0]["focus"] == "cloud security architectures"
    assert audited[0]["agency_slug"] == "custom-agency"


def test_cli_preflight_is_strictly_read_only(tmp_path: Path):
    """Verifies CLI --preflight executes validation and exits 0 WITHOUT writing any files to disk."""
    python_exe = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if not python_exe.exists():
        python_exe = Path(sys.executable)

    script_path = REPO_ROOT / "scripts" / "stage_cohort_11.py"
    target_out_dir = tmp_path / "read_only_preflight_out"

    res = subprocess.run(
        [
            str(python_exe),
            str(script_path),
            "--preflight",
            "--skip-network",
            "--output-dir",
            str(target_out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"CLI preflight failed:\n{res.stdout}\n{res.stderr}"
    assert "Cohort 11 Preflight Deliverability Gate: PASSED" in res.stdout
    assert "successfully staged" not in res.stdout
    # Must NOT create output directory or write manifest
    assert not target_out_dir.exists() or len(list(target_out_dir.iterdir())) == 0
    assert not (target_out_dir / "cohort_11_manifest.json").exists()


def test_cli_stage_flag_executes_staging(tmp_path: Path):
    """Verifies CLI --stage executes draft generation and writes manifest to specified output directory."""
    python_exe = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if not python_exe.exists():
        python_exe = Path(sys.executable)

    script_path = REPO_ROOT / "scripts" / "stage_cohort_11.py"
    target_out_dir = tmp_path / "staged_cohort_out"

    res = subprocess.run(
        [
            str(python_exe),
            str(script_path),
            "--stage",
            "--skip-network",
            "--output-dir",
            str(target_out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"CLI staging failed:\n{res.stdout}\n{res.stderr}"
    assert "Cohort 11 successfully staged in:" in res.stdout
    assert target_out_dir.exists()
    assert (target_out_dir / "cohort_11_manifest.json").exists()

    manifest_data = json.loads((target_out_dir / "cohort_11_manifest.json").read_text(encoding="utf-8"))
    assert manifest_data["total_targets"] == 10
    assert len(list(target_out_dir.glob("*/*.eml"))) == 10


def test_cli_no_flags_displays_help_without_staging(tmp_path: Path):
    """Verifies running stage_cohort_11.py with no flags displays help without touching disk."""
    python_exe = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if not python_exe.exists():
        python_exe = Path(sys.executable)

    script_path = REPO_ROOT / "scripts" / "stage_cohort_11.py"
    target_out_dir = tmp_path / "empty_cohort_out"

    res = subprocess.run(
        [str(python_exe), str(script_path), "--output-dir", str(target_out_dir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    assert "usage:" in res.stdout.lower() or "options:" in res.stdout.lower()
    assert not target_out_dir.exists()
