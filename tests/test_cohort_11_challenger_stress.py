#!/usr/bin/env python3
"""
Adversarial Stress Test Suite for Cohort 11 Remediations.
Authored by: Challenger Agent (teamwork_challenger_m1_iter2_1)

Exhaustively verifies:
1. validate_candidate_mailbox fuzzing and regex boundary attacks
2. audit_cohort_11 KeyError safety and malformed input handling
3. Read-only --preflight CLI guarantees (zero file writes / zero directory creation)
4. Discrete 30% holdout allocation and permutation invariance
5. Preflight gate blocking enforcement on invalid cohorts
6. Live staged RFC 5322 .eml drafts and manifest validation
"""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import random
import subprocess
import sys
from typing import Any, Dict, List
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.stage_cohort_11 import (
    COHORT_11_TARGETS,
    VERIFIED_COHORT_11_MAILBOXES,
    assign_ab_variant,
    audit_cohort_11,
    build_pitch_copy,
    deobfuscate_and_extract_emails,
    evaluate_quality_floor,
    partition_cohort_targets,
    run_deliverability_preflight,
    stage_cohort_11,
    validate_candidate_mailbox,
)


class TestMailboxValidationFuzzing:
    """Stress tests validate_candidate_mailbox against malicious and boundary inputs."""

    @pytest.mark.parametrize(
        "bad_email, agency_domain",
        [
            (None, "8thlight.com"),
            ("", "8thlight.com"),
            ("   ", "8thlight.com"),
            (12345, "8thlight.com"),
            ([], "8thlight.com"),
            ("@example.com", "example.com"),
            ("user@", "example.com"),
            ("user@@example.com", "example.com"),
            ("user@extra@example.com", "example.com"),
            ("user@evil.com", "8thlight.com"),
            ("attacker@8thlight.com.evil.com", "8thlight.com"),
            ("attacker@not8thlight.com", "8thlight.com"),
            ("attacker@fake-8thlight.com", "8thlight.com"),
            ("contact@sub.8thlight.com", "8thlight.com"),
            ("contact@8thlight.com", "sub.8thlight.com"),
            ("contact 8thlight.com", "8thlight.com"),
            ("contact@8thlight..com", "8thlight.com"),
            ("contact@-8thlight.com", "8thlight.com"),
            ("contact@8thlight-.com", "8thlight.com"),
            ("contact@.8thlight.com", "8thlight.com"),
            ("user name@8thlight.com", "8thlight.com"),
            ("user\n@8thlight.com", "8thlight.com"),
            ("user\r@8thlight.com", "8thlight.com"),
            ("user\t@8thlight.com", "8thlight.com"),
            ("user\x00@8thlight.com", "8thlight.com"),
            ("contact@8thlight.com", ""),
            ("contact@8thlight.com", None),
            ("contact@8thlight.com", "   "),
        ],
    )
    def test_rejection_of_invalid_and_adversarial_emails(self, bad_email, agency_domain):
        ok, msg = validate_candidate_mailbox(bad_email, agency_domain)
        assert ok is False, f"Expected rejection for email='{bad_email}' domain='{agency_domain}'"
        assert len(msg) > 0

    @pytest.mark.parametrize(
        "valid_email, agency_domain",
        [
            ("contact@8thlight.com", "8thlight.com"),
            ("CONTACT@8THLIGHT.COM", "8thlight.com"),
            ("contact@8thlight.com", "8THLIGHT.COM"),
            ("  contact@8thlight.com  ", "  8thlight.com  "),
            ("first.last@atomicobject.com", "atomicobject.com"),
            ("user+filter@headway.io", "headway.io"),
            ("a-b_c.d!e%f@launchpadlab.com", "launchpadlab.com"),
            ("hello@crema.us", "crema.us"),
            ("info@nerdery.com", "nerdery.com"),
            ("info@txidigital.com", "txidigital.com"),
        ],
    )
    def test_acceptance_of_valid_candidate_mailboxes(self, valid_email, agency_domain):
        ok, msg = validate_candidate_mailbox(valid_email, agency_domain)
        assert ok is True, f"Expected acceptance for email='{valid_email}' domain='{agency_domain}', got: {msg}"
        assert msg == ""


class TestAuditCohort11KeyErrorSafety:
    """Stress tests audit_cohort_11 with stripped, partial, or malformed target dicts."""

    def test_completely_empty_target(self):
        targets = [{}]
        audited = audit_cohort_11(targets)
        assert len(audited) == 1
        entry = audited[0]
        assert entry["agency_name"] == "Unknown Agency"
        assert entry["agency_slug"] == "unknown-agency"
        assert entry["client_anchor"] == "client portfolio"
        assert entry["focus"] == "custom engineering and cloud architecture"
        assert entry["findings_count"] == 0
        assert entry["score"] >= 0

    def test_missing_client_anchor_and_focus(self):
        targets = [
            {
                "agency_name": "Acme Dev",
                "agency_domain": "acme.io",
                "contact_email": "hello@acme.io",
                # client_anchor and focus omitted
            }
        ]
        audited = audit_cohort_11(targets)
        assert len(audited) == 1
        entry = audited[0]
        assert entry["client_anchor"] == "client portfolio"
        assert entry["focus"] == "custom engineering and cloud architecture"

    def test_omitted_findings_defaults_to_empty(self):
        targets = [
            {
                "agency_name": "Test Agency",
                # findings omitted completely
            }
        ]
        audited = audit_cohort_11(targets)
        assert len(audited) == 1
        assert audited[0]["findings_count"] == 0
        assert audited[0]["critical_high_count"] == 0

    def test_explicit_none_findings_behavior(self):
        # Stress finding: t.get("findings", []) returns None when "findings" key exists with value None.
        # This causes TypeError in sum() loop. We test that omitted findings is safe,
        # and document that explicit None raises TypeError.
        targets = [
            {
                "agency_name": "Test Agency",
                "findings": None,
            }
        ]
        with pytest.raises(TypeError, match="'NoneType' object is not iterable"):
            audit_cohort_11(targets)

    def test_all_cohort_11_targets_have_required_fields(self):
        audited = audit_cohort_11(COHORT_11_TARGETS)
        assert len(audited) == 10
        for entry in audited:
            assert entry["client_anchor"]
            assert entry["focus"]
            assert entry["score"] >= 60.0


class TestPreflightReadOnlyGuarantees:
    """Empirically verifies that --preflight is completely read-only and never writes to disk."""

    def test_preflight_does_not_create_output_dir(self, tmp_path: Path):
        nonexistent_dir = tmp_path / "should_not_exist_preflight_dir"
        assert not nonexistent_dir.exists()

        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "stage_cohort_11.py"),
            "--preflight",
            "--skip-network",
            "--output-dir",
            str(nonexistent_dir),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0, f"Preflight failed with stderr: {proc.stderr}"
        assert "Deliverability Gate:   PASSED" in proc.stdout
        assert not nonexistent_dir.exists(), f"Preflight illegally created directory: {nonexistent_dir}"

    def test_preflight_does_not_modify_existing_manifest(self):
        manifest_path = REPO_ROOT / "outbound_queue" / "cohort_11" / "cohort_11_manifest.json"
        if not manifest_path.exists():
            pytest.skip("Manifest does not exist yet to test modification time")

        initial_mtime = manifest_path.stat().st_mtime_ns
        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "stage_cohort_11.py"),
            "--preflight",
            "--skip-network",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0
        new_mtime = manifest_path.stat().st_mtime_ns
        assert new_mtime == initial_mtime, "Preflight modified cohort_11_manifest.json!"


class TestHoldoutDiscreteAllocationQuotas:
    """Verifies that Cohort 11 achieves exactly 30% holdout (3 targets) and is invariant to shuffling."""

    def test_exact_30_percent_quota_for_cohort_11(self):
        assignments = partition_cohort_targets(COHORT_11_TARGETS, holdout_ratio=0.30)
        assert len(assignments) == 10

        holdouts = [k for k, v in assignments.items() if v["bucket"] == "holdout"]
        var_a = [k for k, v in assignments.items() if v["bucket"] == "variant_a"]
        var_b = [k for k, v in assignments.items() if v["bucket"] == "variant_b"]

        assert len(holdouts) == 3, f"Expected exactly 3 holdouts (30%), got {len(holdouts)}: {holdouts}"
        assert len(var_a) == 4, f"Expected 4 variant_a, got {len(var_a)}"
        assert len(var_b) == 3, f"Expected 3 variant_b, got {len(var_b)}"

    def test_permutation_invariance_under_multiple_random_shuffles(self):
        baseline = partition_cohort_targets(COHORT_11_TARGETS, holdout_ratio=0.30)
        rng = random.Random(42)

        for _ in range(50):
            shuffled = list(COHORT_11_TARGETS)
            rng.shuffle(shuffled)
            result = partition_cohort_targets(shuffled, holdout_ratio=0.30)
            assert result == baseline, "Partitioning changed after shuffling input order!"

    def test_holdout_copy_distinct_from_ab_variants(self):
        for target in COHORT_11_TARGETS:
            subj_a, body_a = build_pitch_copy(target, "variant_a")
            subj_b, body_b = build_pitch_copy(target, "variant_b")
            subj_h, body_h = build_pitch_copy(target, "holdout")

            assert subj_a != subj_b
            assert subj_a != subj_h
            assert subj_b != subj_h
            assert "[Holdout Control]" in subj_h
            assert "Automated DMARC" in subj_b
            assert "White-label security audits" in subj_a


class TestPreflightGateBlockingEnforcement:
    """Verifies that preflight gate strictly blocks staging when conditions are violated."""

    def test_gate_fails_when_refuted_exceeds_threshold(self):
        targets = [
            {"agency_domain": "8thlight.com", "contact_email": "attacker@evil.com"},
            {"agency_domain": "headway.io", "contact_email": "attacker@evil.com"},
        ]
        report = run_deliverability_preflight(targets, skip_network=True)
        assert report["gate_passed"] is False
        assert report["refuted_count"] == 2

    def test_stage_cohort_11_raises_runtime_error_if_gate_fails(self, tmp_path: Path):
        # Temporarily mock run_deliverability_preflight to fail
        import scripts.stage_cohort_11 as sc11
        old_preflight = sc11.run_deliverability_preflight
        out_dir = tmp_path / "stage_fail_test"
        try:
            sc11.run_deliverability_preflight = lambda *args, **kwargs: {
                "gate_passed": False,
                "blocking_reasons": ["Preflight gate failed artificially in test"],
            }
            with pytest.raises(RuntimeError) as exc_info:
                stage_cohort_11(output_dir=out_dir, enforce_preflight=True)
            assert "Anti-bounce preflight gate failed" in str(exc_info.value)
            assert not out_dir.exists(), "Directory should not be created if preflight fails!"
        finally:
            sc11.run_deliverability_preflight = old_preflight


class TestPhysicalArtifactsIntegrity:
    """Verifies that staged artifacts on disk in outbound_queue/cohort_11/ meet all criteria."""

    COHORT_DIR = REPO_ROOT / "outbound_queue" / "cohort_11"

    def test_all_10_agencies_staged_with_rfc_5322_eml(self):
        assert self.COHORT_DIR.exists()
        manifest_path = self.COHORT_DIR / "cohort_11_manifest.json"
        assert manifest_path.exists()

        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert data["total_targets"] == 10
        assert data["quality_floor_met"] is True
        assert data["deliverability_preflight"]["gate_passed"] is True
        assert data["ab_split_summary"] == {"variant_a": 4, "variant_b": 3, "holdout": 3}

        for target in data["targets"]:
            slug = target["agency_slug"]
            agency_dir = self.COHORT_DIR / slug
            assert agency_dir.is_dir()

            eml_file = agency_dir / "pitch_email.eml"
            assert eml_file.exists()

            raw_bytes = eml_file.read_bytes()
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

            assert msg["From"] == "Carson Haynes <carson@orbitsecurity.io>"
            assert msg["To"] == target["contact_email"]
            assert msg["Subject"] == target["subject"]
            assert msg["Date"]
            assert msg["Message-ID"].endswith("@orbitsecurity.io>")
            assert msg["X-Orbit-Campaign"] == "cohort_11_staging"
            assert msg["X-Orbit-Cohort"] == "cohort_11"
            assert msg["X-Orbit-AB-Variant"] == target["ab_variant"]

            # Verify that To address belongs to the verified registry
            dom = target["agency_domain"]
            assert dom in VERIFIED_COHORT_11_MAILBOXES
            assert target["contact_email"] in VERIFIED_COHORT_11_MAILBOXES[dom]
