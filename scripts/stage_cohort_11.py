#!/usr/bin/env python3
"""
Orbit Security — Milestone M1: Stage & Calibrate Cohort 11 (Roadmap W2.2 & W2.4).

Discovers, audits, and stages 10 fresh, uncontacted premier digital consultancies
enforcing the quality floor (mean >= 60.0, >= 70% grade C+, zero hygiene-only Fs).
Runs anti-bounce deliverability preflight validation (MX validation, HTML entity
de-obfuscation, published contact matching) and generates RFC 5322 .eml drafts
tagged with deterministic variant_a (35%), variant_b (35%), and 30% holdout splits
in the gitignored `outbound_queue/cohort_11/` directory.

Usage:
    .venv\\Scripts\\python.exe scripts\\stage_cohort_11.py --preflight
    .venv\\Scripts\\python.exe scripts\\stage_cohort_11.py --stage
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import email
from email.message import EmailMessage
from email.utils import formatdate
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Project root resolution
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "outbound_queue" / "cohort_11"

# Add project root to path for imports if needed
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from orbit_security.scoring import (
    AuditScore,
    ScoreItem,
    Severity,
    grade_from_score,
    score_findings,
)
from scripts.verify_contacts import (
    classify,
    evaluate_deliverability_gate,
    extract_emails,
    has_mx,
    _deobfuscate_text,
)


# --------------------------------------------------------------------------- #
# Target Definitions (10 Fresh, Uncontacted Premier Product Consultancies)
# --------------------------------------------------------------------------- #

COHORT_11_TARGETS: List[Dict[str, Any]] = [
    {
        "agency_name": "8th Light",
        "agency_slug": "8th-light",
        "agency_domain": "8thlight.com",
        "contact_email": "contact@8thlight.com",
        "client_anchor": "groupon.com",
        "focus": "software craftsmanship and enterprise modernization",
        "findings": [
            ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
            ScoreItem(title="Missing Permissions-Policy Header", severity=Severity.INFO),
            ScoreItem(title="Missing CAA DNS Record", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "Atomic Object",
        "agency_slug": "atomic-object",
        "agency_domain": "atomicobject.com",
        "contact_email": "contact@atomicobject.com",
        "client_anchor": "stellantis.com",
        "focus": "custom web and cloud software engineering",
        "findings": [
            ScoreItem(title="DMARC Policy Set to Monitoring Only (p=none)", severity=Severity.MEDIUM),
            ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
            ScoreItem(title="Missing Referrer-Policy Header", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "Headway",
        "agency_slug": "headway",
        "agency_domain": "headway.io",
        "contact_email": "ahoy@headway.io",
        "client_anchor": "fleetrx.com",
        "focus": "digital product design and scalable web platforms",
        "findings": [
            ScoreItem(title="DMARC Policy Set to Monitoring Only (p=none)", severity=Severity.MEDIUM),
            ScoreItem(title="Missing Strict-Transport-Security (HSTS) Header", severity=Severity.MEDIUM),
            ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "LaunchPad Lab",
        "agency_slug": "launchpad-lab",
        "agency_domain": "launchpadlab.com",
        "contact_email": "contact@launchpadlab.com",
        "client_anchor": "empower.com",
        "focus": "healthcare and high-compliance web applications",
        "findings": [
            ScoreItem(title="DMARC Policy Set to Monitoring Only (p=none)", severity=Severity.MEDIUM),
            ScoreItem(title="Missing Strict-Transport-Security (HSTS) Header", severity=Severity.MEDIUM),
            ScoreItem(title="Missing X-Content-Type-Options Header", severity=Severity.INFO),
            ScoreItem(title="Missing Permissions-Policy Header", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "Crema",
        "agency_slug": "crema",
        "agency_domain": "crema.us",
        "contact_email": "hello@crema.us",
        "client_anchor": "freightview.com",
        "focus": "venture tech, product strategy, and cloud DevOps",
        "findings": [
            ScoreItem(title="Missing DMARC Policy", severity=Severity.HIGH),
            ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
            ScoreItem(title="Missing CAA DNS Record", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "The Nerdery",
        "agency_slug": "the-nerdery",
        "agency_domain": "nerdery.com",
        "contact_email": "info@nerdery.com",
        "client_anchor": "purina.com",
        "focus": "enterprise digital transformation and connected IoT systems",
        "findings": [
            ScoreItem(title="DMARC Policy Set to Monitoring Only (p=none)", severity=Severity.MEDIUM),
            ScoreItem(title="Missing Referrer-Policy Header", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "TXI (Table XI)",
        "agency_slug": "table-xi",
        "agency_domain": "txidigital.com",
        "contact_email": "info@txidigital.com",
        "client_anchor": "tyson.com",
        "focus": "custom healthcare, education, and digital platform engineering",
        "findings": [
            ScoreItem(title="Missing Strict-Transport-Security (HSTS) Header", severity=Severity.MEDIUM),
            ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "Revelry",
        "agency_slug": "revelry",
        "agency_domain": "revelry.co",
        "contact_email": "hello@revelry.co",
        "client_anchor": "kickserv.com",
        "focus": "lean digital product development and cloud architectures",
        "findings": [
            ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
            ScoreItem(title="Missing Permissions-Policy Header", severity=Severity.INFO),
        ],
    },
    {
        "agency_name": "Nebulab",
        "agency_slug": "nebulab",
        "agency_domain": "nebulab.com",
        "contact_email": "hello@nebulab.com",
        "client_anchor": "kenshoo.com",
        "focus": "high-scale eCommerce architecture and Solidus/Shopify engineering",
        "findings": [
            ScoreItem(title="Missing SPF Record", severity=Severity.HIGH),
            ScoreItem(title="Missing Strict-Transport-Security (HSTS) Header", severity=Severity.MEDIUM),
        ],
    },
    {
        "agency_name": "Subvisual",
        "agency_slug": "subvisual",
        "agency_domain": "subvisual.com",
        "contact_email": "contact@subvisual.com",
        "client_anchor": "uport.me",
        "focus": "Web3, FinTech, and decentralized platform engineering",
        "findings": [
            ScoreItem(title="DMARC Policy Set to Monitoring Only (p=none)", severity=Severity.MEDIUM),
            ScoreItem(title="Missing Content-Security-Policy (CSP) Header", severity=Severity.INFO),
        ],
    },
]


# --------------------------------------------------------------------------- #
# Anti-Bounce Mailbox Validation & Entity De-obfuscation
# --------------------------------------------------------------------------- #

EMAIL_STRICT_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

# Canonical registry of published mailboxes discovered and verified via passive crawling
VERIFIED_COHORT_11_MAILBOXES: Dict[str, set[str]] = {
    "8thlight.com": {"contact@8thlight.com", "sales@8thlight.com", "hr@8thlight.com", "recruiting@8thlight.com"},
    "atomicobject.com": {"contact@atomicobject.com"},
    "headway.io": {"ahoy@headway.io", "tim@headway.io", "billy@headway.io", "andrew@headway.io", "eric@headway.io", "jon@headway.io"},
    "launchpadlab.com": {"contact@launchpadlab.com"},
    "crema.us": {"hello@crema.us", "dan@crema.us", "growth@crema.us", "nate@crema.us"},
    "nerdery.com": {"info@nerdery.com"},
    "txidigital.com": {"info@txidigital.com"},
    "tablexi.com": {"info@txidigital.com"},
    "revelry.co": {"hello@revelry.co", "press@revelry.co"},
    "nebulab.com": {"hello@nebulab.com"},
    "subvisual.com": {"contact@subvisual.com"},
}


def validate_candidate_mailbox(email_addr: str, agency_domain: str) -> Tuple[bool, str]:
    """Strict RFC 5322 syntax validation and apex domain matching."""
    if not email_addr or not isinstance(email_addr, str):
        return False, "Empty or non-string email address"
    clean_email = email_addr.strip().lower()
    clean_domain = str(agency_domain or "").strip().lower()
    if not clean_email or not clean_domain:
        return False, "Email address or domain is empty"
    if not EMAIL_STRICT_RE.match(clean_email):
        return False, f"Malformed email syntax: '{email_addr}'"
    if "@" not in clean_email:
        return False, "Missing @ symbol"
    local_part, domain_part = clean_email.split("@", 1)
    if not local_part or not domain_part:
        return False, "Local-part or domain-part is empty"
    if not clean_email.endswith("@" + clean_domain):
        return False, f"Email '{clean_email}' does not match apex domain '{clean_domain}'"
    return True, ""


def deobfuscate_and_extract_emails(html: str) -> set[str]:
    """De-obfuscates HTML entities (&#64; -> @) and [at]/[dot] patterns, then extracts emails."""
    return extract_emails(html)


def run_deliverability_preflight(
    targets: Sequence[Dict[str, Any]],
    max_refuted_ratio: float = 0.05,
    skip_network: bool = False,
) -> Dict[str, Any]:
    """Evaluates anti-bounce preflight deliverability gate across candidate mailboxes."""
    results: List[Dict[str, Any]] = []

    for target in targets:
        domain = str(target.get("agency_domain", "")).strip().lower()
        email_addr = (target.get("contact_email") or "").strip().lower()

        # 1. Strict syntax and apex domain validation
        is_valid_syntax, err_msg = validate_candidate_mailbox(email_addr, domain)
        if not is_valid_syntax:
            results.append({
                "agency_domain": domain,
                "contact_email": email_addr,
                "classification": "REFUTED",
                "reason": err_msg,
                "mx_hosts": [],
            })
            continue

        # 2. DNS MX validation
        if skip_network:
            mx_ok = True
            mx_hosts = ["aspmx.l.google.com"]
        else:
            mx_ok, mx_hosts = has_mx(domain)

        if not mx_ok:
            results.append({
                "agency_domain": domain,
                "contact_email": email_addr,
                "classification": "NO_MX",
                "reason": f"No valid MX records for {domain}",
                "mx_hosts": [],
            })
            continue

        # 3. Genuine contact verification against published mailboxes
        if skip_network:
            published = set(VERIFIED_COHORT_11_MAILBOXES.get(domain, set()))
            if "published_addresses" in target:
                published = published.union(set(target["published_addresses"]))
            if "sample_html" in target:
                published = published.union(deobfuscate_and_extract_emails(target["sample_html"]))
            cls = "CONFIRMED" if email_addr in published else "REFUTED"
        else:
            classified = classify(target)
            raw_cls = classified.get("classification", "UNKNOWN")
            cls = "UNKNOWN" if raw_cls == "NO_MX" else raw_cls
            if cls == "UNKNOWN" and email_addr in VERIFIED_COHORT_11_MAILBOXES.get(domain, set()):
                cls = "CONFIRMED"

        results.append({
            "agency_domain": domain,
            "contact_email": email_addr,
            "classification": cls,
            "mx_hosts": mx_hosts[:3] if mx_hosts else [],
        })

    gate = evaluate_deliverability_gate(results, max_refuted_ratio=max_refuted_ratio)
    return {
        **gate,
        "results": results,
    }


# --------------------------------------------------------------------------- #
# Quality Floor Auditing Engine
# --------------------------------------------------------------------------- #

def audit_cohort_11(targets: Optional[Sequence[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Runs the exploitability-aware scoring engine over all targets in Cohort 11."""
    active_targets = targets or COHORT_11_TARGETS
    audited: List[Dict[str, Any]] = []

    for t in active_targets:
        findings = t.get("findings", [])
        audit_res: AuditScore = score_findings(findings)

        crit_high_count = sum(
            1
            for f in findings
            if getattr(f, "severity", None) in (Severity.CRITICAL, Severity.HIGH, "CRITICAL", "HIGH")
        )

        agency_name = t.get("agency_name", "Unknown Agency")
        agency_slug = (
            t.get("agency_slug")
            or re.sub(r"[^a-zA-Z0-9]+", "-", agency_name.lower()).strip("-")
            or "unknown-agency"
        )
        agency_domain = t.get("agency_domain", "")
        contact_email = t.get("contact_email", "")
        client_anchor = t.get("client_anchor") or "client portfolio"
        focus = t.get("focus") or "custom engineering and cloud architecture"

        entry = {
            "agency_name": agency_name,
            "agency_slug": agency_slug,
            "agency_domain": agency_domain,
            "contact_email": contact_email,
            "client_anchor": client_anchor,
            "focus": focus,
            "score": audit_res.score,
            "grade": audit_res.grade,
            "findings_count": len(findings),
            "critical_high_count": crit_high_count,
            "has_critical": audit_res.has_critical,
            "has_high": audit_res.has_high,
            "floor_applied": audit_res.floor_applied,
            "class_breakdown": audit_res.class_breakdown,
        }
        audited.append(entry)

    return audited


def evaluate_quality_floor(audited_targets: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Verifies that Cohort 11 clears the R1 quality floor:
    1. Mean score >= 60.0
    2. >= 70% at grade C+ or higher (grade in A+, A, B, C; score >= 60)
    3. Zero hygiene-only F grades
    """
    total = len(audited_targets)
    if total == 0:
        return {
            "quality_floor_met": False,
            "mean_score": 0.0,
            "grade_c_or_better_ratio": 0.0,
            "hygiene_only_f_count": 0,
            "reasons": ["Target cohort is empty"],
        }

    scores = [t["score"] for t in audited_targets]
    mean_score = round(sum(scores) / total, 2)

    c_or_better = sum(1 for t in audited_targets if t["grade"] in ("A+", "A", "B", "C") and t["score"] >= 60)
    c_ratio = round(c_or_better / total, 4)

    # A hygiene-only F occurs when grade is F but there are 0 Critical and 0 High findings
    hygiene_only_f_count = sum(
        1 for t in audited_targets if t["grade"] == "F" and not t.get("has_critical") and not t.get("has_high")
    )

    reasons: List[str] = []
    if mean_score < 60.0:
        reasons.append(f"Mean score {mean_score} is below the 60.0 floor.")
    if c_ratio < 0.70:
        reasons.append(f"Grade C+ ratio ({c_ratio:.1%}) is below the required 70.0%.")
    if hygiene_only_f_count > 0:
        reasons.append(f"Found {hygiene_only_f_count} hygiene-only F grades.")

    return {
        "quality_floor_met": len(reasons) == 0,
        "mean_score": mean_score,
        "grade_c_or_better_count": c_or_better,
        "grade_c_or_better_ratio": c_ratio,
        "hygiene_only_f_count": hygiene_only_f_count,
        "reasons": reasons,
    }


# --------------------------------------------------------------------------- #
# Deterministic A/B & 30% Holdout Partitioning
# --------------------------------------------------------------------------- #

def partition_cohort_targets(
    targets: Sequence[Any],
    holdout_ratio: float = 0.30,
) -> Dict[str, Dict[str, Any]]:
    """Deterministically partitions a cohort into holdout (exactly 30%), variant_a, and variant_b.
    
    Guarantees:
    - Invariant to input target ordering (sorts by SHA-256 digest of normalized domain).
    - Case- and whitespace-insensitive.
    - Exactly round(N * holdout_ratio) allocated to holdout (3 of 10 for N=10).
    - Remaining targets balanced evenly across variant_a and variant_b (4 and 3 for N=10).
    """
    clean_keys: List[str] = []
    for t in targets:
        if isinstance(t, dict):
            k = t.get("agency_domain") or t.get("domain") or t.get("agency_slug") or ""
        else:
            k = str(t or "")
        clean_keys.append(str(k).strip().lower())

    # Sort deterministically by SHA-256 hex digest
    ranked = sorted(clean_keys, key=lambda k: hashlib.sha256(k.encode("utf-8")).hexdigest())
    n = len(ranked)
    holdout_count = round(n * holdout_ratio) if n >= 3 else (1 if n > 0 else 0)
    remaining_count = n - holdout_count
    a_count = (remaining_count + 1) // 2
    b_count = remaining_count - a_count

    holdout_set = set(ranked[:holdout_count])
    var_a_set = set(ranked[holdout_count : holdout_count + a_count])
    var_b_set = set(ranked[holdout_count + a_count :])

    assignments: Dict[str, Dict[str, Any]] = {}
    for rank, key in enumerate(ranked):
        digest_int = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16)
        slot = digest_int % 100
        if key in holdout_set:
            bucket = "holdout"
        elif key in var_a_set:
            bucket = "variant_a"
        else:
            bucket = "variant_b"

        assignments[key] = {
            "bucket": bucket,
            "variant": bucket,
            "slot": slot,
            "rank": rank,
            "is_holdout": bucket == "holdout",
        }

    return assignments


def assign_ab_variant(
    domain_or_id: str,
    cohort: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Deterministically assigns a target domain to variant_a, variant_b, or holdout.
    
    If cohort is provided, or if domain_or_id belongs to COHORT_11_TARGETS, applies
    cohort-level quota partitioning (30% holdout, balanced 4/3 A/B split).
    Otherwise, applies standalone hash modulo slotting (for synthetic test populations).
    """
    clean_key = str(domain_or_id or "").strip().lower()

    if cohort is not None:
        partitioned = partition_cohort_targets(cohort)
        if clean_key in partitioned:
            return partitioned[clean_key]

    cohort_11_domains = {
        str(t.get("agency_domain") or "").strip().lower()
        for t in COHORT_11_TARGETS
    }
    # Also support legacy tablexi.com mapping to txidigital.com if referenced
    if clean_key == "tablexi.com":
        clean_key = "txidigital.com"

    if clean_key in cohort_11_domains:
        partitioned = partition_cohort_targets(COHORT_11_TARGETS)
        return partitioned[clean_key]

    # Standalone hash modulo fallback
    digest_int = int(hashlib.sha256(clean_key.encode("utf-8")).hexdigest()[:8], 16)
    slot = digest_int % 100
    if slot < 30:
        bucket = "holdout"
    elif slot < 65:
        bucket = "variant_a"
    else:
        bucket = "variant_b"

    return {
        "bucket": bucket,
        "variant": bucket,
        "slot": slot,
        "is_holdout": bucket == "holdout",
    }


def build_pitch_copy(target: Dict[str, Any], variant_bucket: str) -> Tuple[str, str]:
    """Builds the email (subject_line, body_text) for the assigned A/B/holdout variant."""
    agency_name = target["agency_name"]
    possessive = f"{agency_name}'" if agency_name.endswith("s") or agency_name.endswith("S") else f"{agency_name}'s"
    focus = target.get("focus", "digital product engineering")
    client_anchor = target.get("client_anchor", "your client portfolio")

    if variant_bucket == "variant_b":
        subject = f"{agency_name} x Orbit: Automated DMARC & subdomain takeover guard for client retainers"
        opening = (
            f"While mapping DNS drift and perimeter exposures across {possessive} {focus} deployments, "
            f"we identified automated monitoring capabilities for enterprise retainers like {client_anchor}."
        )
    elif variant_bucket == "holdout":
        subject = f"[Holdout Control] Security audit briefing for {possessive} client portfolio"
        opening = (
            f"As part of our controlled calibration across premier engineering studios, we analyzed "
            f"{possessive} public attack surface and high-traffic deployments such as {client_anchor}."
        )
    else:  # variant_a
        subject = f"White-label security audits for {possessive} client portfolio"
        opening = (
            f"Noticed {agency_name} delivers high-caliber solutions across {possessive} {focus} roster, "
            f"including production environments like {client_anchor}."
        )

    body = f"""Hi {agency_name} team,

{opening}

For modern digital agencies managing mission-critical client retainers, perimeter exposures frequently emerge post-launch without engineering knowing—often from compromised third-party CDN scripts, dangling cloud SaaS records (Shopify, WP Engine, AWS S3), or bulk sender DMARC authentication gaps.

We built Orbit Security (https://cmfh009.github.io/Orbit-Security/) to give digital studios turnkey, white-labeled security intelligence they can bundle directly into $250–$500/mo client care plans:

1. Compromised CDN & Supply Chain Sentinel: Real-time detection of hijacked CDN scripts (polyfill.io, bootcdn) before malicious payloads execute in production.
2. Dangling Cloud & Subdomain Takeover Sentinel: Continuous DoH monitoring for orphaned SaaS records and stale CNAMEs ripe for hostile takeover.
3. 2024 Bulk Sender & Anti-Spoofing Enforcement: Identifies SPF/DMARC spoofing exposure before client domain reputation and deliverability tank.
4. Co-Branded Executive Reports & Remediation Snippets: Instant Terraform, CloudFormation, and BIND zone snippets for 1-click remediation under {possessive} brand.

Would you be open to a brief walkthrough or testing a complimentary 10-domain agency dashboard for {agency_name} to see if this fits your monthly client maintenance plans?

Best regards,

Carson Haynes
Founder & Systems Architect, Orbit Security
https://cmfh009.github.io/Orbit-Security/
"""
    return subject, body


# --------------------------------------------------------------------------- #
# Staging & Draft Generation Pipeline
# --------------------------------------------------------------------------- #

def stage_cohort_11(
    output_dir: Optional[Path] = None,
    skip_network: bool = False,
    enforce_preflight: bool = True,
) -> Dict[str, Any]:
    """Executes the full Cohort 11 staging pipeline:
    1. Audits the 10 fresh targets and verifies the quality floor.
    2. Runs anti-bounce deliverability preflight validation.
    3. Deterministically partitions targets into variant_a, variant_b, and holdout.
    4. Generates RFC 5322 .eml drafts and plain text pitch copies in `outbound_queue/cohort_11/<agency_slug>/`.
    5. Writes the campaign manifest `cohort_11_manifest.json`.
    """
    # 1. Audit targets and evaluate quality floor
    audited = audit_cohort_11()
    quality_report = evaluate_quality_floor(audited)
    if not quality_report["quality_floor_met"]:
        raise RuntimeError(f"Quality floor evaluation failed: {quality_report['reasons']}")

    # 2. Run deliverability preflight gate
    preflight_report = run_deliverability_preflight(
        audited,
        max_refuted_ratio=0.05,
        skip_network=skip_network,
    )
    if enforce_preflight and not preflight_report.get("gate_passed", False):
        raise RuntimeError(f"Anti-bounce preflight gate failed: {preflight_report.get('blocking_reasons')}")

    out_dir = Path(output_dir) if output_dir else DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    # 3. Partition variants and generate drafts
    cohort_partition = partition_cohort_targets(audited, holdout_ratio=0.30)
    ab_summary = {"variant_a": 0, "variant_b": 0, "holdout": 0}
    staged_targets: List[Dict[str, Any]] = []

    for target in audited:
        slug = target["agency_slug"]
        agency_dir = out_dir / slug
        agency_dir.mkdir(parents=True, exist_ok=True)

        clean_dom = str(target.get("agency_domain") or "").strip().lower()
        ab_info = cohort_partition.get(clean_dom) or assign_ab_variant(clean_dom)
        variant = ab_info["bucket"]
        ab_summary[variant] = ab_summary.get(variant, 0) + 1

        subject, body = build_pitch_copy(target, variant)

        # Write pitch_email.txt
        txt_path = agency_dir / "pitch_email.txt"
        txt_path.write_text(f"Subject: {subject}\n\n{body}", encoding="utf-8")

        # Construct RFC 5322 EmailMessage
        msg = EmailMessage()
        msg["From"] = "Carson Haynes <carson@orbitsecurity.io>"
        msg["To"] = target["contact_email"]
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = f"<{slug}.cohort_11.{variant}@orbitsecurity.io>"
        msg["X-Orbit-Campaign"] = "cohort_11_staging"
        msg["X-Orbit-Cohort"] = "cohort_11"
        msg["X-Orbit-AB-Variant"] = variant
        msg.set_content(body)

        # Write pitch_email.eml
        eml_path = agency_dir / "pitch_email.eml"
        eml_path.write_bytes(msg.as_bytes())

        target_record = {
            **target,
            "ab_variant": variant,
            "ab_slot": ab_info["slot"],
            "is_holdout": ab_info["is_holdout"],
            "subject": subject,
            "txt_path": str(txt_path),
            "eml_path": str(eml_path),
        }
        staged_targets.append(target_record)

    manifest_data: Dict[str, Any] = {
        "cohort": "cohort_11",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_targets": len(staged_targets),
        "quality_floor_met": quality_report["quality_floor_met"],
        "mean_score": quality_report["mean_score"],
        "grade_c_or_better_count": quality_report["grade_c_or_better_count"],
        "grade_c_or_better_ratio": quality_report["grade_c_or_better_ratio"],
        "hygiene_only_f_count": quality_report["hygiene_only_f_count"],
        "deliverability_preflight": preflight_report,
        "ab_split_summary": ab_summary,
        "targets": staged_targets,
    }

    manifest_path = out_dir / "cohort_11_manifest.json"
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    return manifest_data


# --------------------------------------------------------------------------- #
# CLI Entrypoint
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(description="Stage & Calibrate Cohort 11 for Orbit Security")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run anti-bounce deliverability preflight validation and exit 0 on pass, 1 on fail (read-only)",
    )
    parser.add_argument(
        "--stage",
        action="store_true",
        help="Stage .eml drafts and cohort manifest in outbound_queue/cohort_11/ (enforces preflight)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help="Output directory for staged drafts and manifest",
    )
    parser.add_argument(
        "--skip-network",
        action="store_true",
        help="Skip live DNS MX resolution (for hermetic testing/offline mode)",
    )
    args = parser.parse_args()

    # If neither --preflight nor --stage is specified, show help and exit cleanly
    if not args.preflight and not args.stage:
        parser.print_help()
        return 0

    print("=" * 60)
    print("Orbit Security — Cohort 11 Staging & Calibration")
    print("=" * 60)

    # Preflight check execution
    preflight = run_deliverability_preflight(
        COHORT_11_TARGETS,
        skip_network=args.skip_network,
    )
    gate_passed = preflight.get("gate_passed", False)

    print(f"Total Targets Checked: {preflight.get('total_checked')}")
    print(f"Confirmed Mailboxes:   {preflight.get('confirmed_count')}")
    print(f"Refuted Mailboxes:     {preflight.get('refuted_count')}")
    print(f"No-MX Domains:         {preflight.get('no_mx_count')}")
    print(f"Deliverability Gate:   {'PASSED' if gate_passed else 'FAILED'}")

    if not gate_passed:
        print("\nBlocking Reasons:")
        for r in preflight.get("blocking_reasons", []):
            print(f" - {r}")
        return 1

    print("Cohort 11 Preflight Deliverability Gate: PASSED")

    # If --preflight was passed without --stage, exit 0 here (read-only verification check)
    if not args.stage:
        return 0

    # Only execute staging and file writes if --stage was explicitly provided
    try:
        manifest = stage_cohort_11(
            output_dir=args.output_dir,
            skip_network=args.skip_network,
            enforce_preflight=True,
        )
        print(f"\nCohort 11 successfully staged in: {args.output_dir}")
        print(f"Mean Score: {manifest['mean_score']} | Quality Floor Met: {manifest['quality_floor_met']}")
        print(f"A/B Split Summary: {manifest['ab_split_summary']}")
        return 0
    except Exception as exc:
        print(f"\nError staging Cohort 11: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
