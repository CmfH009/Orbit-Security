#!/usr/bin/env python3
"""
Unit tests for Roadmap W2.1b (scripts/stage_score_corrections.py) and
Roadmap W2.4 (scripts/stage_fleet_pilot.py deliverability preflight gate & A/B split).

All test fixtures use synthetic example domains in tmp_path to maintain strict OPSEC.
"""

from __future__ import annotations

import email
import json
from pathlib import Path

import pytest


SAMPLE_RESCUED_AUDIT_MD = """# Executive Security Audit: `alpha-studio.example.org`
**Date:** October 24, 2026
**Prepared For:** Alpha Studio Engineering & Leadership
**Overall Security Score:** **35/100 (Grade F)**

---

### 1. Subdomain Takeover & Dangling DNS
* **Status:** PASS (0 dangling CNAME records identified across 16 subdomains)

### 2. Email Authentication & Anti-Spoofing (SPF / DMARC)
* **SPF Record:** `v=spf1 include:_spf.google.com ~all`
* **DMARC Record:** `v=DMARC1; p=none; rua=mailto:dmarc@alpha-studio.example.org`

| MEDIUM | DMARC Policy Set to Monitoring Only (p=none) | `alpha-studio.example.org` | DMARC is present (`v=DMARC1; p=none;`), which logs spoofing attempts but does not block unauthorized senders. |
| LOW | Missing Strict-Transport-Security (HSTS) Header | `alpha-studio.example.org` | HTTP response headers do not enforce HSTS preload. |
| LOW | Missing Content-Security-Policy (CSP) Header | `alpha-studio.example.org` | Main document does not declare a strict CSP header. |
"""

SAMPLE_STILL_FAILING_AUDIT_MD = """# Executive Security Audit: `broken-perimeter.example.org`
**Date:** October 24, 2026
**Prepared For:** Broken Perimeter Agency
**Overall Security Score:** **20/100 (Grade F)**

---

| CRITICAL | Subdomain Takeover Vulnerability (Dangling CNAME) | `dev.broken-perimeter.example.org` | Subdomain points to an unclaimed cloud instance. |
| HIGH | Missing DMARC Policy | `broken-perimeter.example.org` | No `_dmarc` TXT record exists (`_dmarc.broken-perimeter.example.org`). |
| HIGH | Missing SPF Record | `broken-perimeter.example.org` | No `v=spf1` record found on apex domain. |
"""


def test_identify_and_stage_rescued_score_corrections(tmp_path: Path):
    """Verifies W2.1b: Cohorts 7-10 rescued agencies are identified and staged with candid .eml + updated audit reports."""
    from scripts.stage_score_corrections import (
        identify_rescued_cohort_agencies,
        stage_score_corrections,
    )

    data_dir = tmp_path / "data"
    audits_dir = data_dir / "generated_audits"
    out_dir = tmp_path / "outbound_queue" / "score_corrections"

    # Seed Cohort 7 and Cohort 8 staged files
    alpha_dir = audits_dir / "alpha-studio.example.org"
    alpha_dir.mkdir(parents=True, exist_ok=True)
    alpha_md = alpha_dir / "alpha-studio.example.org_audit.md"
    alpha_md.write_text(SAMPLE_RESCUED_AUDIT_MD, encoding="utf-8")

    broken_dir = audits_dir / "broken-perimeter.example.org"
    broken_dir.mkdir(parents=True, exist_ok=True)
    broken_md = broken_dir / "broken-perimeter.example.org_audit.md"
    broken_md.write_text(SAMPLE_STILL_FAILING_AUDIT_MD, encoding="utf-8")

    cohort_7 = [
        {
            "agency": "Alpha Studio",
            "domain": "alpha-studio.example.org",
            "to_email": "ops@alpha-studio.example.org",
            "score": "35/100 (Grade F)",
            "md_path": str(alpha_md),
        },
        {
            "agency": "Broken Perimeter Agency",
            "domain": "broken-perimeter.example.org",
            "to_email": "security@broken-perimeter.example.org",
            "score": "20/100 (Grade F)",
            "md_path": str(broken_md),
        },
    ]
    (data_dir / "cohort_7_staged.json").write_text(json.dumps(cohort_7), encoding="utf-8")

    bounces_path = data_dir / "bounced_agencies.json"
    bounces_path.write_text(json.dumps({"bounced_emails": [], "bounced_domains": []}), encoding="utf-8")

    identified = identify_rescued_cohort_agencies(
        cohorts=(7, 8, 9, 10),
        data_dir=data_dir,
        audits_dir=audits_dir,
        bounces_path=bounces_path,
    )
    assert identified["rescued_count"] == 1
    rescued_item = identified["rescued_agencies"][0]
    assert rescued_item["domain"] == "alpha-studio.example.org"
    assert rescued_item["old_grade"] == "F"
    assert rescued_item["new_grade"] in ("C+", "B", "B+", "A-", "A", "A+")
    assert rescued_item["delta"] > 0

    manifest = stage_score_corrections(
        cohorts=(7, 8, 9, 10),
        data_dir=data_dir,
        audits_dir=audits_dir,
        output_dir=out_dir,
        bounces_path=bounces_path,
    )

    assert manifest["staged_count"] == 1
    assert (out_dir / "score_corrections_manifest.json").exists()

    staged_entry = manifest["entries"][0]
    eml_path = Path(staged_entry["eml_path"])
    audit_path = Path(staged_entry["updated_audit_path"])
    assert eml_path.exists()
    assert audit_path.exists()

    # Inspect the updated audit markdown report
    updated_md_text = audit_path.read_text(encoding="utf-8")
    assert f"{rescued_item['new_score']}/100 (Grade {rescued_item['new_grade']})" in updated_md_text
    assert "35/100 (Grade F)" in updated_md_text

    # Parse the staged .eml file and verify candid, non-apologetic founder tone + attachment
    msg = email.message_from_bytes(eml_path.read_bytes())
    assert msg["To"] == "ops@alpha-studio.example.org"
    assert "alpha-studio.example.org" in msg["Subject"]
    assert f"{rescued_item['new_score']}/100" in msg["Subject"]

    body_parts = []
    attachment_names = []
    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        if "attachment" in disp:
            attachment_names.append(part.get_filename())
        elif part.get_content_type() == "text/plain":
            body_parts.append(part.get_payload(decode=True).decode("utf-8", errors="replace"))

    full_body = "\n".join(body_parts)
    assert "35/100" in full_body
    assert f"{rescued_item['new_score']}/100" in full_body
    # Candid & non-apologetic: no groveling "sorry"/"apologize" language
    assert "sorry" not in full_body.lower()
    assert "apologize" not in full_body.lower()
    assert any(name and name.endswith("_updated_audit.md") for name in attachment_names)


def test_stage_fleet_pilot_deliverability_preflight_and_ab_split(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verifies W2.4: evaluate_deliverability_gate preflight check and deterministic 2-variant A/B + 30% holdout split."""
    import scripts.stage_fleet_pilot as sfp

    out_dir = tmp_path / "outreach_pilot"
    portals_dir = tmp_path / "portals"
    portals_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sfp, "OUTREACH_DIR", out_dir)
    monkeypatch.setattr(sfp, "PORTALS_DIR", portals_dir)

    # 1. Verify deterministic variant assignment produces variant_a, variant_b, and holdout (~30%)
    assignments = [sfp.assign_ab_variant(f"agency-{i}.example.com") for i in range(100)]
    counts = {
        "variant_a": sum(1 for a in assignments if a["bucket"] == "variant_a"),
        "variant_b": sum(1 for a in assignments if a["bucket"] == "variant_b"),
        "holdout": sum(1 for a in assignments if a["bucket"] == "holdout"),
    }
    assert counts["variant_a"] > 20
    assert counts["variant_b"] > 20
    assert 20 <= counts["holdout"] <= 40

    # Deterministic across repeated calls
    assert sfp.assign_ab_variant("10up.com") == sfp.assign_ab_variant("10up.com")

    # 2. Generate pilot drafts with preflight deliverability gate enabled
    manifest = sfp.generate_pilot_drafts(followup=True, run_preflight=True)
    assert manifest["total_agencies"] == len(sfp.PILOT_AGENCIES)
    assert "deliverability_preflight" in manifest
    assert manifest["deliverability_preflight"]["passed"] is True
    assert "ab_split_summary" in manifest
    ab_summary = manifest["ab_split_summary"]
    assert ab_summary["variant_a"] + ab_summary["variant_b"] + ab_summary["holdout"] == manifest["total_agencies"]

    for agency in manifest["agencies"]:
        assert agency["ab_variant"] in ("variant_a", "variant_b", "holdout")
        assert "ab_subject_line" in agency
        assert "ab_opening_line" in agency

    # 3. Verify preflight gate blocks staging when deliverability gate fails and enforce_preflight=True
    monkeypatch.setattr(
        sfp,
        "run_deliverability_preflight",
        lambda agencies, **kwargs: {
            "passed": False,
            "verified_ratio": 0.40,
            "generic_inbox_ratio": 0.50,
            "violations": ["verified_ratio 40.0% < required 85.0%"],
        },
    )
    with pytest.raises(RuntimeError, match="Deliverability preflight gate failed"):
        sfp.generate_pilot_drafts(followup=True, run_preflight=True, enforce_preflight=True)


def test_dependabot_auto_merge_workflow_and_uv_build_constraint():
    """Verifies Track 4: pyproject.toml uv_build constraint and .github/workflows/dependabot-auto-merge.yml."""
    import yaml

    repo_root = Path(__file__).resolve().parent.parent
    pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires = ["uv_build>=0.11.19,<0.15.0"]' in pyproject_text

    wf_path = repo_root / ".github" / "workflows" / "dependabot-auto-merge.yml"
    assert wf_path.exists()
    wf_data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
    assert "jobs" in wf_data
    assert "dependabot" in wf_data["jobs"]
    job = wf_data["jobs"]["dependabot"]
    assert "dependabot[bot]" in str(job.get("if", ""))
    steps_str = json.dumps(job.get("steps", []))
    assert "dependabot/fetch-metadata" in steps_str
    assert "gh pr review --approve" in steps_str
    assert "gh pr merge" in steps_str

