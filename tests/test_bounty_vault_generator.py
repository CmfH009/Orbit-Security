"""Unit tests for the Pre-KYC Remediation Vault & Submission Readiness Compiler."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from scripts.bounty_vault_generator import (
    classify_finding_tier,
    consolidate_program_findings,
    compute_cvss_profile,
    render_remediation_dossier,
    build_vault_manifest,
)


def test_classify_finding_tier_separates_ready_from_auth_needed_and_noise():
    bucket_finding = {
        "program": "AlphaCorp",
        "host": "cdn.alpha-example.com",
        "url": "https://cdn.alpha-example.com/",
        "code": 200,
        "verdict": "OPEN_BUCKET_LISTING",
        "score": 6,
    }
    assert classify_finding_tier(bucket_finding) == "TIER_1_READY"

    cors_html_finding = {
        "program": "BetaCommerce",
        "host": "checkout.beta-example.com",
        "url": "https://checkout.beta-example.com/",
        "code": 200,
        "cors_origin": "https://example.org",
        "cors_credentials": "true",
        "reflected": True,
        "verdict": "REFLECTED_PUBLIC_HTML",
        "score": 5,
    }
    assert classify_finding_tier(cors_html_finding) == "TIER_2_NEEDS_AUTH_PROOF"

    low_score_noise = {
        "program": "ExampleCorp",
        "host": "static.example.com",
        "url": "https://static.example.com/",
        "code": 200,
        "verdict": "SAFE_OR_DEAD",
        "score": 1,
    }
    assert classify_finding_tier(low_score_noise) == "TIER_3_SUPPRESSED"


def test_consolidate_program_findings_groups_same_program_and_verdict():
    raw_items = [
        {
            "program": "BetaCommerce",
            "host": "checkout-co.beta-example.com",
            "url": "https://checkout-co.beta-example.com/",
            "code": 200,
            "verdict": "REFLECTED_PUBLIC_HTML",
            "score": 5,
        },
        {
            "program": "BetaCommerce",
            "host": "checkout-mx.beta-example.com",
            "url": "https://checkout-mx.beta-example.com/",
            "code": 200,
            "verdict": "REFLECTED_PUBLIC_HTML",
            "score": 5,
        },
        {
            "program": "AlphaCorp",
            "host": "cdn.alpha-example.com",
            "url": "https://cdn.alpha-example.com/",
            "code": 200,
            "verdict": "OPEN_BUCKET_LISTING",
            "score": 6,
        },
    ]

    grouped = consolidate_program_findings(raw_items)
    assert len(grouped) == 2

    alpha_group = next(g for g in grouped if g["program"] == "AlphaCorp")
    assert alpha_group["tier"] == "TIER_1_READY"
    assert alpha_group["hosts"] == ["cdn.alpha-example.com"]

    beta_group = next(g for g in grouped if g["program"] == "BetaCommerce")
    assert beta_group["tier"] == "TIER_2_NEEDS_AUTH_PROOF"
    assert len(beta_group["hosts"]) == 2
    assert "checkout-co.beta-example.com" in beta_group["hosts"]
    assert "checkout-mx.beta-example.com" in beta_group["hosts"]


def test_compute_cvss_profile_returns_standard_cwe_and_vector():
    bucket_cvss = compute_cvss_profile("OPEN_BUCKET_LISTING")
    assert bucket_cvss["cwe"] == "CWE-200"
    assert bucket_cvss["base_score"] == 5.3
    assert "CVSS:3.1/" in bucket_cvss["vector"]

    cors_cvss = compute_cvss_profile("REFLECTED_PUBLIC_HTML")
    assert cors_cvss["cwe"] == "CWE-942"
    assert cors_cvss["base_score"] >= 5.0


def test_render_remediation_dossier_contains_remediation_and_cwe():
    group = {
        "program": "AlphaCorp",
        "verdict": "OPEN_BUCKET_LISTING",
        "tier": "TIER_1_READY",
        "max_score": 6,
        "hosts": ["cdn.alpha-example.com"],
        "urls": ["https://cdn.alpha-example.com/"],
        "notes": ["S3/GCS bucket directory listing open."],
    }
    md = render_remediation_dossier(group)
    assert "# Remediation Dossier: AlphaCorp" in md
    assert "CWE-200" in md
    assert "cdn.alpha-example.com" in md
    assert "## Defensive Remediation Steps" in md


def test_build_vault_manifest_writes_queue_and_summary(tmp_path: Path):
    matrix_path = tmp_path / "live_verification_matrix.json"
    matrix_path.write_text(
        json.dumps(
            [
                {
                    "program": "AlphaCorp",
                    "host": "cdn.alpha-example.com",
                    "url": "https://cdn.alpha-example.com/",
                    "code": 200,
                    "verdict": "OPEN_BUCKET_LISTING",
                    "score": 6,
                    "notes": "Open storage listing",
                },
                {
                    "program": "BetaCommerce",
                    "host": "checkout.beta-example.com",
                    "url": "https://checkout.beta-example.com/",
                    "code": 200,
                    "verdict": "REFLECTED_PUBLIC_HTML",
                    "score": 5,
                    "cors_credentials": "true",
                    "reflected": True,
                    "notes": "CORS header reflection",
                },
            ]
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "vault_out"
    manifest = build_vault_manifest(matrix_path=matrix_path, output_dir=out_dir)

    assert manifest["tier_1_count"] == 1
    assert manifest["tier_2_count"] == 1
    assert (out_dir / "VAULT_LAUNCH_QUEUE.json").exists()
    assert (out_dir / "VAULT_READINESS_REPORT.md").exists()
