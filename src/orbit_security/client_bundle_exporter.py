"""Orbit Security White-Label Client Remediation & Export Bundle Generator (Milestone M2).

Generates atomic, white-labeled client remediation ZIP packages containing:
1. Branded executive summary HTML and Markdown reports styled with agency colors via CSS variables.
2. Tailored Terraform (HCL) and AWS CloudFormation (YAML) remediation templates for detected
   misconfigurations (dangling CNAMEs, SPF, DMARC, CAA, and S3 bucket security blocks).
3. BIND-compatible RFC 1035 DNS zone remediation files.
4. Ready-to-run .orbit.yml perimeter sentinel configuration.
5. Cryptographic SHA-256 integrity checksums and bundle manifests.
"""

from __future__ import annotations

import datetime
import functools
import hashlib
import html
import json
import logging
import os
from pathlib import Path
import random
import re
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import uuid
import zipfile

import yaml

from orbit_security.agency_retainer import AgencyRetainer, AgencyRetainerManager

logger = logging.getLogger("orbit_security.client_bundle_exporter")

# Default repo root
DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

_AGENCY_LOCKS_MUTEX = threading.Lock()
_AGENCY_LOCKS: Dict[str, threading.Lock] = {}


class _hybrid_method:
    """Descriptor enabling a method to be called cleanly on either an instance or a class."""

    def __init__(self, fn):
        self.fn = fn
        functools.update_wrapper(self, fn)

    def __get__(self, instance, owner):
        if instance is None:
            instance = owner()

        @functools.wraps(self.fn)
        def wrapper(*args, **kwargs):
            return self.fn(instance, *args, **kwargs)

        return wrapper


def _get_agency_lock(lock_key: str) -> threading.Lock:
    """Returns a thread-safe lock scoped to a specific agency output directory."""
    with _AGENCY_LOCKS_MUTEX:
        lock = _AGENCY_LOCKS.get(lock_key)
        if lock is None:
            lock = threading.Lock()
            _AGENCY_LOCKS[lock_key] = lock
        return lock


def _sanitize_hex_color(color: Optional[str], default: str) -> str:
    """Validates and returns a normalized hex color (#RRGGBB or #RGB)."""
    if not color:
        return default
    c = str(color).strip()
    if re.match(r"^#(?:[0-9a-fA-F]{3}){1,2}$", c):
        return c
    return default


def _finding_get(f: Any, key: str, default: Any = None) -> Any:
    """Polymorphic helper to extract attributes from finding dicts or model objects."""
    if isinstance(f, dict):
        return f.get(key, default)
    val = getattr(f, key, None)
    if val is not None:
        if hasattr(val, "value"):
            return val.value
        return val
    return default


class ClientBundleExporter:
    """Generates atomic, white-labeled client remediation ZIP bundles for agency retainers."""

    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        bundles_dir: Optional[Path] = None,
        retainer_manager: Optional[AgencyRetainerManager] = None,
    ):
        self.workspace_root = Path(workspace_root) if workspace_root else DEFAULT_REPO_ROOT
        self.bundles_dir = Path(bundles_dir) if bundles_dir else self.workspace_root / "data" / "client_bundles"
        self.bundles_dir.mkdir(parents=True, exist_ok=True)
        self.retainer_manager = retainer_manager or AgencyRetainerManager(
            data_path=self.workspace_root / "data" / "agency_retainers.json"
        )

    def generate_html_report(
        self,
        agency_name: str,
        tagline: str,
        primary_color: str,
        accent_color: str,
        domains: List[str],
        findings: List[Dict[str, Any]],
        support_email: str = "security@agency.example.com",
        tier: str = "Scale Retainer",
        generated_at: Optional[str] = None,
    ) -> str:
        """Generates a responsive executive HTML audit report with CSS custom variables for agency branding."""
        now_str = generated_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        pri = _sanitize_hex_color(primary_color, "#0B132B")
        acc = _sanitize_hex_color(accent_color, "#48CAE4")

        # Compute summary metrics
        crit_count = sum(1 for f in findings if str(_finding_get(f, "severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for f in findings if str(_finding_get(f, "severity", "")).upper() == "HIGH")
        med_count = sum(1 for f in findings if str(_finding_get(f, "severity", "")).upper() in ("MEDIUM", "MODERATE"))
        total_findings = len(findings)

        # Grade calculation
        if crit_count > 0:
            grade = "C"
            score = 72
        elif high_count > 0:
            grade = "B"
            score = 84
        elif med_count > 0:
            grade = "A-"
            score = 90
        else:
            grade = "A+"
            score = 98

        # Build domain list HTML
        domain_items_html = "".join(
            f'<span class="domain-pill">{html.escape(d)}</span>' for d in domains
        )

        # Build findings rows HTML
        findings_html = ""
        for i, f in enumerate(findings, 1):
            sev = str(_finding_get(f, "severity", "MEDIUM")).upper()
            sev_class = "badge-crit" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else "badge-med")
            cat = html.escape(str(_finding_get(f, "category", "Perimeter")))
            title = html.escape(str(_finding_get(f, "title", f"Security Advisory #{i}")))
            sub = html.escape(str(_finding_get(f, "subdomain") or _finding_get(f, "domain") or _finding_get(f, "target") or (domains[0] if domains else "Apex")))
            desc = html.escape(str(_finding_get(f, "description", "Vulnerability detected on target asset.")))
            rem = html.escape(str(_finding_get(f, "remediation") or "Apply DNS/Cloud remediation configuration included in this bundle."))

            findings_html += f"""
            <div class="finding-card">
              <div class="finding-header">
                <div>
                  <span class="sev-badge {sev_class}">{sev}</span>
                  <span class="cat-badge">{cat}</span>
                  <h3 class="finding-title">{title}</h3>
                </div>
                <code class="target-host">{sub}</code>
              </div>
              <p class="finding-desc">{desc}</p>
              <div class="finding-remediation">
                <strong>Remediation Action:</strong> {rem}
              </div>
            </div>
            """

        if not findings_html:
            findings_html = """
            <div class="finding-card">
              <div class="finding-header">
                <span class="sev-badge badge-med">BASELINE</span>
                <h3 class="finding-title">Baseline Perimeter Hardening</h3>
              </div>
              <p class="finding-desc">No active critical exploits detected. Enforce proactive SPF, DMARC reject policies, CAA, and S3 bucket protection.</p>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Executive Security Remediation Audit — {html.escape(agency_name)}</title>
  <style>
    :root {{
      --primary: {pri};
      --card-bg: {pri};
      --accent: {acc};
      --bg-dark: #0A0E17;
      --surface: #111827;
      --surface-border: rgba(255, 255, 255, 0.1);
      --text: #F8FAFC;
      --text-muted: #94A3B8;
      --danger: #EF4444;
      --warning: #F59E0B;
      --success: #10B981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg-dark);
      color: var(--text);
      line-height: 1.6;
      padding: 40px 20px;
    }}
    .container {{
      max-width: 960px;
      margin: 0 auto;
    }}
    .header {{
      background: var(--card-bg);
      border: 1px solid var(--surface-border);
      border-radius: 12px;
      padding: 32px;
      margin-bottom: 24px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
    }}
    .badge-tier {{
      display: inline-block;
      background: var(--accent);
      color: #000;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      padding: 4px 10px;
      border-radius: 9999px;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }}
    .title {{
      font-size: 1.85rem;
      font-weight: 800;
      margin-bottom: 6px;
    }}
    .tagline {{
      color: var(--text-muted);
      font-size: 1rem;
      margin-bottom: 16px;
    }}
    .meta-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 20px;
      font-size: 0.85rem;
      color: var(--text-muted);
      border-top: 1px solid var(--surface-border);
      padding-top: 16px;
    }}
    .meta-item strong {{ color: var(--text); }}
    .score-card {{
      display: grid;
      grid-template-columns: 140px 1fr;
      gap: 24px;
      background: var(--surface);
      border: 1px solid var(--surface-border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      align-items: center;
    }}
    .grade-box {{
      background: rgba(0, 0, 0, 0.4);
      border: 2px solid var(--accent);
      border-radius: 12px;
      text-align: center;
      padding: 16px;
    }}
    .grade-val {{
      font-size: 2.75rem;
      font-weight: 900;
      color: var(--accent);
      line-height: 1;
    }}
    .score-val {{
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-top: 4px;
    }}
    .stat-pills {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }}
    .stat-pill {{
      flex: 1;
      min-width: 120px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--surface-border);
      border-radius: 8px;
      padding: 12px;
    }}
    .stat-pill .num {{ font-size: 1.4rem; font-weight: 700; }}
    .stat-pill .label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }}
    .section-title {{
      font-size: 1.25rem;
      font-weight: 700;
      margin: 28px 0 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .section-title::before {{
      content: "";
      width: 4px;
      height: 18px;
      background: var(--accent);
      border-radius: 2px;
    }}
    .domain-pills {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 24px;
    }}
    .domain-pill {{
      background: var(--surface);
      border: 1px solid var(--surface-border);
      color: var(--accent);
      padding: 6px 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 0.88rem;
    }}
    .finding-card {{
      background: var(--surface);
      border: 1px solid var(--surface-border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 10px;
      gap: 12px;
    }}
    .finding-title {{
      font-size: 1.1rem;
      font-weight: 600;
      display: inline;
      margin-left: 8px;
    }}
    .target-host {{
      background: rgba(0, 0, 0, 0.3);
      padding: 4px 8px;
      border-radius: 4px;
      color: var(--accent);
      font-size: 0.85rem;
    }}
    .sev-badge {{
      display: inline-block;
      font-size: 0.7rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
    }}
    .badge-crit {{ background: var(--danger); color: #FFF; }}
    .badge-high {{ background: #DC2626; color: #FFF; }}
    .badge-med {{ background: var(--warning); color: #000; }}
    .cat-badge {{
      display: inline-block;
      background: rgba(255, 255, 255, 0.1);
      font-size: 0.7rem;
      padding: 2px 8px;
      border-radius: 4px;
      margin-left: 4px;
    }}
    .finding-desc {{
      color: var(--text-muted);
      font-size: 0.92rem;
      margin-bottom: 12px;
    }}
    .finding-remediation {{
      background: rgba(0, 0, 0, 0.25);
      border-left: 3px solid var(--accent);
      padding: 10px 14px;
      font-size: 0.88rem;
      border-radius: 0 4px 4px 0;
    }}
    .footer {{
      margin-top: 40px;
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      border-top: 1px solid var(--surface-border);
      padding-top: 20px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="badge-tier">{html.escape(tier)}</div>
      <h1 class="title">Client Perimeter Remediation Bundle</h1>
      <div class="tagline">{html.escape(agency_name)} &bull; {html.escape(tagline)}</div>
      <div class="meta-row">
        <div class="meta-item"><strong>Generated:</strong> {now_str}</div>
        <div class="meta-item"><strong>Contact:</strong> {html.escape(support_email)}</div>
        <div class="meta-item"><strong>Status:</strong> Active Managed Retainer</div>
      </div>
    </div>

    <div class="score-card">
      <div class="grade-box">
        <div class="grade-val">{grade}</div>
        <div class="score-val">Score: {score}/100</div>
      </div>
      <div class="stat-pills">
        <div class="stat-pill">
          <div class="num" style="color: var(--danger);">{crit_count}</div>
          <div class="label">Critical Risks</div>
        </div>
        <div class="stat-pill">
          <div class="num" style="color: #F87171;">{high_count}</div>
          <div class="label">High Risks</div>
        </div>
        <div class="stat-pill">
          <div class="num" style="color: var(--warning);">{med_count}</div>
          <div class="label">Medium Risks</div>
        </div>
        <div class="stat-pill">
          <div class="num">{len(domains)}</div>
          <div class="label">Client Domains</div>
        </div>
      </div>
    </div>

    <h2 class="section-title">Covered Client Domains</h2>
    <div class="domain-pills">
      {domain_items_html}
    </div>

    <h2 class="section-title">Perimeter Vulnerabilities & Action Items</h2>
    {findings_html}

    <div class="footer">
      Generated automatically by Orbit Security Multi-Tenant Engine for {html.escape(agency_name)}.<br>
      Deliverables include Terraform HCL, AWS CloudFormation, BIND zone records, and .orbit.yml sentinels.
    </div>
  </div>
</body>
</html>"""

    def generate_markdown_report(
        self,
        agency_name: str,
        primary_color: str,
        accent_color: str,
        domains: List[str],
        findings: List[Dict[str, Any]],
        tier: str = "Scale Retainer",
        generated_at: Optional[str] = None,
    ) -> str:
        """Generates a clean GFM markdown executive summary audit report."""
        now_str = generated_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        pri = _sanitize_hex_color(primary_color, "#0B132B")
        acc = _sanitize_hex_color(accent_color, "#48CAE4")

        crit_count = sum(1 for f in findings if str(_finding_get(f, "severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for f in findings if str(_finding_get(f, "severity", "")).upper() == "HIGH")
        grade = "C" if crit_count > 0 else ("B" if high_count > 0 else "A")

        lines = [
            f"# Orbit Security Executive Remediation Report — {agency_name}",
            "",
            f"**Agency Partner**: {agency_name}  ",
            f"**Retainer Tier**: {tier}  ",
            f"**Audit Timestamp**: {now_str}  ",
            f"**Brand Primary Color**: `{pri}`  ",
            f"**Brand Accent Color**: `{acc}`  ",
            f"**Executive Security Grade**: **{grade}**  ",
            "",
            "## 1. Monitored Client Perimeter Targets",
            "",
        ]

        for d in domains:
            lines.append(f"- `{d}`")

        lines.extend([
            "",
            "## 2. Identified Vulnerabilities & Remediation Steps",
            "",
            "| # | Severity | Category | Target | Finding | Recommended Action |",
            "|---|---|---|---|---|---|",
        ])

        if not findings:
            lines.append("| 1 | INFO | Baseline | Perimeter | Proactive hardening required | Apply SPF -all, DMARC reject, and S3 bucket protection |")
        else:
            for idx, f in enumerate(findings, 1):
                sev = str(_finding_get(f, "severity", "MEDIUM")).upper()
                cat = str(_finding_get(f, "category", "DNS"))
                tgt = str(_finding_get(f, "subdomain") or _finding_get(f, "domain") or _finding_get(f, "target") or (domains[0] if domains else "Apex"))
                title = str(_finding_get(f, "title", f"Finding {idx}"))
                rem = str(_finding_get(f, "remediation") or "Apply Terraform/CloudFormation configuration in this bundle.")
                lines.append(f"| {idx} | **{sev}** | {cat} | `{tgt}` | {title} | {rem} |")

        lines.extend([
            "",
            "## 3. Included Infrastructure & Automation Deliverables",
            "",
            "1. `remediation/remediation.tf`: Terraform HCL for Cloudflare and AWS Route 53 DNS records + AWS S3 bucket security blocks (`aws_s3_bucket_public_access_block`, `aws_s3_bucket_versioning`).",
            "2. `remediation/remediation.cfn.yaml`: AWS CloudFormation YAML template with `AWS::Route53::RecordSet` and `AWS::S3::Bucket` security policies.",
            "3. `remediation/remediation.zone`: BIND RFC 1035 zone file for 1-click import into DNS management consoles.",
            "4. `.orbit.yml`: Declarative Orbit Security sentinel configuration for continuous drift detection and perimeter defense.",
            "5. `bundle_manifest.json`: Cryptographic SHA-256 verification hashes for all bundle assets.",
            "",
            "---",
            f"*Confidential security documentation prepared for {agency_name}.*",
        ])

        return "\n".join(lines) + "\n"

    def generate_terraform_snippets(
        self,
        domains: List[str],
        findings: List[Dict[str, Any]],
        agency_slug: str = "agency",
    ) -> str:
        """Generates Terraform HCL blocks for DNS records (SPF, DMARC, CAA, dangling CNAMEs) and S3 bucket security."""
        primary_domain = domains[0] if domains else "example.com"

        # Check for specific findings
        dangling_cnames = [f for f in findings if "CNAME" in str(_finding_get(f, "title", "")).upper() or _finding_get(f, "cname_target")]

        cname_blocks = []
        if dangling_cnames:
            for i, c in enumerate(dangling_cnames, 1):
                sub = _finding_get(c, "subdomain") or _finding_get(c, "domain") or _finding_get(c, "target") or f"sub{i}.{primary_domain}"
                if sub.lower().endswith(f".{primary_domain.lower()}"):
                    name_part = sub[: -len(f".{primary_domain.lower()}")].strip(".") or "@"
                elif sub.lower() == primary_domain.lower():
                    name_part = "@"
                else:
                    name_part = sub.split(".")[0] if "." in sub else sub
                cname_blocks.append(f"""# Dangling CNAME Remediation: {sub}
# Option A: Safely route to decommission placeholder or update Cloudflare record:
resource "cloudflare_record" "remediated_cname_{i}" {{
  zone_id = var.cloudflare_zone_id
  name    = "{name_part}"
  content = "decommissioned.invalid"
  type    = "CNAME"
  ttl     = 300
}}""")
        else:
            cname_blocks.append("""# Dangling CNAME Protection:
# (No active dangling CNAMEs detected; review existing DNS pointers periodically)""")

        tf_code = f"""# ==============================================================================
# Orbit Security — Automated Terraform Remediation Blueprint
# Agency: {agency_slug} | Primary Domain: {primary_domain}
# ==============================================================================

terraform {{
  required_providers {{
    cloudflare = {{
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }}
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

variable "cloudflare_zone_id" {{
  type        = string
  description = "Cloudflare Zone ID for {primary_domain}"
  default     = ""
}}

variable "route53_zone_id" {{
  type        = string
  description = "AWS Route 53 Hosted Zone ID for {primary_domain}"
  default     = ""
}}

variable "s3_bucket_name" {{
  type        = string
  description = "Name of the client S3 asset bucket to harden"
  default     = "{agency_slug}-hardened-assets"
}}

variable "agency_slug" {{
  type        = string
  description = "Unique slug of the agency managing this perimeter"
  default     = "{agency_slug}"
}}

# ------------------------------------------------------------------------------
# 1. Strict DMARC Reject Policy
# ------------------------------------------------------------------------------
resource "cloudflare_record" "dmarc_cloudflare" {{
  zone_id = var.cloudflare_zone_id
  name    = "_dmarc"
  content = "v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r;"
  type    = "TXT"
  ttl     = 300
}}

resource "aws_route53_record" "dmarc_route53" {{
  zone_id = var.route53_zone_id
  name    = "_dmarc.{primary_domain}"
  type    = "TXT"
  ttl     = 300
  records = ["v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r;"]
}}

# ------------------------------------------------------------------------------
# 2. Strict SPF Hard-Fail Enforcement (-all)
# ------------------------------------------------------------------------------
resource "cloudflare_record" "spf_cloudflare" {{
  zone_id = var.cloudflare_zone_id
  name    = "@"
  content = "v=spf1 include:_spf.google.com -all"
  type    = "TXT"
  ttl     = 300
}}

resource "aws_route53_record" "spf_route53" {{
  zone_id = var.route53_zone_id
  name    = "{primary_domain}"
  type    = "TXT"
  ttl     = 300
  records = ["v=spf1 include:_spf.google.com -all"]
}}

# ------------------------------------------------------------------------------
# 3. Certificate Authority Authorization (CAA) Records
# ------------------------------------------------------------------------------
resource "cloudflare_record" "caa_letsencrypt" {{
  zone_id = var.cloudflare_zone_id
  name    = "@"
  type    = "CAA"
  ttl     = 300
  data = {{
    flags = 0
    tag   = "issue"
    value = "letsencrypt.org"
  }}
}}

# ------------------------------------------------------------------------------
# 4. Dangling CNAME Remediation
# ------------------------------------------------------------------------------
{chr(10).join(cname_blocks)}

# ------------------------------------------------------------------------------
# 5. Cloud S3 Storage Hardening & Takeover Elimination
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "remediation_bucket" {{
  bucket = var.s3_bucket_name

  tags = {{
    ManagedBy = "OrbitSecurity"
    Agency    = var.agency_slug
  }}
}}

resource "aws_s3_bucket_public_access_block" "remediation_bucket_pab" {{
  bucket = aws_s3_bucket.remediation_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}

resource "aws_s3_bucket_versioning" "remediation_bucket_versioning" {{
  bucket = aws_s3_bucket.remediation_bucket.id

  versioning_configuration {{
    status = "Enabled"
  }}
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_bucket_encryption" {{
  bucket = aws_s3_bucket.remediation_bucket.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
"""
        return tf_code

    def generate_cloudformation_snippets(
        self,
        domains: List[str],
        findings: List[Dict[str, Any]],
        agency_slug: str = "agency",
    ) -> str:
        """Generates AWS CloudFormation YAML template with Route53 and S3 Bucket hardening resources."""
        primary_domain = domains[0] if domains else "example.com"

        cfn_dict: Dict[str, Any] = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Orbit Security Automated CloudFormation Remediation Template for {agency_slug} ({primary_domain})",
            "Parameters": {
                "HostedZoneId": {
                    "Type": "String",
                    "Description": "AWS Route 53 Hosted Zone ID for the client domain",
                    "Default": "Z0123456789ABCDEF",
                },
                "ClientDomain": {
                    "Type": "String",
                    "Description": "Target Apex Domain for DNS record sets",
                    "Default": primary_domain,
                },
                "S3BucketName": {
                    "Type": "String",
                    "Description": "Client S3 bucket name to harden and secure against dangling takeovers",
                    "Default": f"{agency_slug}-hardened-assets",
                },
            },
            "Resources": {
                "DmarcRecordSet": {
                    "Type": "AWS::Route53::RecordSet",
                    "Properties": {
                        "HostedZoneId": {"Ref": "HostedZoneId"},
                        "Name": {"Fn::Sub": "_dmarc.${ClientDomain}."},
                        "Type": "TXT",
                        "TTL": "300",
                        "ResourceRecords": ['"v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r;"'],
                    },
                },
                "SpfRecordSet": {
                    "Type": "AWS::Route53::RecordSet",
                    "Properties": {
                        "HostedZoneId": {"Ref": "HostedZoneId"},
                        "Name": {"Fn::Sub": "${ClientDomain}."},
                        "Type": "TXT",
                        "TTL": "300",
                        "ResourceRecords": ['"v=spf1 include:_spf.google.com -all"'],
                    },
                },
                "CaaRecordSet": {
                    "Type": "AWS::Route53::RecordSet",
                    "Properties": {
                        "HostedZoneId": {"Ref": "HostedZoneId"},
                        "Name": {"Fn::Sub": "${ClientDomain}."},
                        "Type": "CAA",
                        "TTL": "300",
                        "ResourceRecords": ['0 issue "letsencrypt.org"', '0 issue "digicert.com"'],
                    },
                },
                "HardenedS3Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {"Ref": "S3BucketName"},
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "BlockPublicPolicy": True,
                            "IgnorePublicAcls": True,
                            "RestrictPublicBuckets": True,
                        },
                        "VersioningConfiguration": {
                            "Status": "Enabled",
                        },
                        "BucketEncryption": {
                            "ServerSideEncryptionConfiguration": [
                                {
                                    "ServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "AES256"
                                    }
                                }
                            ]
                        },
                        "Tags": [
                            {"Key": "ManagedBy", "Value": "OrbitSecurity"},
                            {"Key": "Agency", "Value": agency_slug},
                        ],
                    },
                },
            },
            "Outputs": {
                "DmarcRecord": {
                    "Description": "DMARC TXT record configured with strict reject enforcement",
                    "Value": {"Ref": "DmarcRecordSet"},
                },
                "HardenedBucketArn": {
                    "Description": "ARN of the hardened and secured S3 bucket",
                    "Value": {"Fn::GetAtt": ["HardenedS3Bucket", "Arn"]},
                },
            },
        }

        # Add any CNAME decommissioning record sets if findings exist
        for i, f in enumerate(findings, 1):
            sub_val = _finding_get(f, "subdomain") or _finding_get(f, "domain") or _finding_get(f, "target")
            if "CNAME" in str(_finding_get(f, "title", "")).upper() and sub_val:
                sub = str(sub_val).rstrip(".")
                res_id = f"RemediatedCnameRecord{i}"
                cfn_dict["Resources"][res_id] = {
                    "Type": "AWS::Route53::RecordSet",
                    "Properties": {
                        "HostedZoneId": {"Ref": "HostedZoneId"},
                        "Name": f"{sub}.",
                        "Type": "TXT",
                        "TTL": "300",
                        "ResourceRecords": ['"remediated-decommissioned-by-orbit"'],
                    },
                }

        return yaml.dump(cfn_dict, sort_keys=False, default_flow_style=False)

    def generate_zone_file(
        self,
        domains: List[str],
        findings: List[Dict[str, Any]],
        agency_name: str = "Agency",
    ) -> str:
        """Generates an RFC 1035 BIND-compatible DNS zone file importable into DNS providers."""
        primary_domain = domains[0] if domains else "example.com"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        lines = [
            f"; Orbit Security RFC 1035 BIND Zone Remediation File",
            f"; Agency: {agency_name}",
            f"; Primary Target: {primary_domain}",
            f"; Generated At: {now_iso}",
            f"$ORIGIN {primary_domain}.",
            "$TTL 300",
            "",
            "; --- Email Security Enforcement ---",
            '_dmarc\tIN\tTXT\t"v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r;"',
            '@\tIN\tTXT\t"v=spf1 include:_spf.google.com -all"',
            '@\tIN\tCAA\t0 issue "letsencrypt.org"',
            '@\tIN\tCAA\t0 issue "digicert.com"',
            "",
            "; --- Subdomain Hardening ---",
        ]

        for f in findings:
            f_title = str(_finding_get(f, "title", "")).upper()
            f_sub = _finding_get(f, "subdomain") or _finding_get(f, "domain") or _finding_get(f, "target")
            if "CNAME" in f_title and f_sub:
                sub = str(f_sub)
                sub_label = sub.replace(f".{primary_domain}", "").replace(primary_domain, "@")
                lines.append(f"; Dangling CNAME Remediation for {sub}")
                lines.append(f'{sub_label}\tIN\tTXT\t"remediated-decommissioned-by-orbit"')

        lines.append("")
        return "\n".join(lines)

    def generate_orbit_sentinel_config(
        self,
        agency_slug: str,
        agency_name: str,
        domains: List[str],
        tier: str = "Scale",
        support_email: str = "ops@agency.example.com",
    ) -> str:
        """Generates a declarative .orbit.yml sentinel perimeter configuration using PyYAML."""
        targets = [
            {"domain": d, "monitored": True, "priority": "high" if i == 0 else "medium"}
            for i, d in enumerate(domains)
        ]

        config: Dict[str, Any] = {
            "version": "1.0",
            "agency": {
                "slug": agency_slug,
                "name": agency_name,
                "tier": tier,
                "support_email": support_email,
            },
            "targets": targets,
            "sentinels": {
                "cname_takeover": {
                    "enabled": True,
                    "interval": "15m",
                    "alert_on": [
                        "dangling_dns",
                        "nxdomain_cname",
                        "cloud_bucket_dangling",
                    ],
                },
                "cloud_buckets": {
                    "enabled": True,
                    "interval": "1h",
                    "alert_on": [
                        "open_s3_listing",
                        "nosuchbucket_takeover",
                        "public_acl_drift",
                    ],
                },
                "email_security": {
                    "enabled": True,
                    "interval": "6h",
                    "enforce": {
                        "spf_hardfail": True,
                        "dmarc_reject": True,
                    },
                },
                "agent_perimeter": {
                    "enabled": True,
                    "interval": "30m",
                    "features": [
                        "synthetic_heartbeat",
                        "dns_drift_detection",
                        "ssl_expiry_monitoring",
                    ],
                },
            },
            "reporting": {
                "format": ["html", "markdown", "json"],
                "retention_days": 90,
            },
        }

        return yaml.dump(config, sort_keys=False, default_flow_style=False)

    def export_bundle(
        self,
        agency_slug: str,
        agency_name: Optional[str] = None,
        domains: Optional[List[str]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        primary_color: Optional[str] = None,
        accent_color: Optional[str] = None,
        support_email: Optional[str] = None,
        tagline: Optional[str] = None,
        tier: Optional[str] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Atomically compiles and exports the complete white-label remediation ZIP bundle."""
        clean_slug = re.sub(r"[^a-zA-Z0-9_-]", "", agency_slug.lower().strip())
        if not clean_slug:
            clean_slug = "agency"

        # Lookup agency retainer if parameters are omitted
        ret: Optional[AgencyRetainer] = None
        if self.retainer_manager and hasattr(self.retainer_manager, "agencies"):
            ret = self.retainer_manager.agencies.get(clean_slug) or self.retainer_manager.agencies.get(agency_slug)

        ret_name = ret.agency_name if ret else None
        if ret_name and ret_name.lower().replace(" ", "-") == clean_slug:
            ret_name = clean_slug.replace("-", " ").replace("_", " ").title()
        resolved_name = agency_name or ret_name or clean_slug.replace("-", " ").replace("_", " ").title()
        resolved_primary = _sanitize_hex_color(primary_color or (ret.primary_color if ret else None), "#0B132B")
        resolved_accent = _sanitize_hex_color(accent_color or (ret.accent_color if ret else None), "#48CAE4")
        resolved_email = support_email or (ret.support_email if ret else f"security@{clean_slug}.example.com")
        resolved_tagline = tagline or (ret.agency_tagline if ret else "Managed Web & Security Operations")
        resolved_tier = tier or (ret.tier.value if ret and hasattr(ret.tier, "value") else "Scale Retainer")

        # Resolve domains
        resolved_domains = list(domains) if domains else []
        if not resolved_domains and ret and ret.client_domains:
            for cd in ret.client_domains:
                d_name = getattr(cd, "domain", cd) if not isinstance(cd, str) else cd
                if d_name and d_name not in resolved_domains:
                    resolved_domains.append(d_name)
        if not resolved_domains:
            resolved_domains = [f"{clean_slug}.com"]

        # Resolve findings
        resolved_findings = list(findings) if findings is not None else []
        if not resolved_findings:
            # Provide baseline hardening findings if none were passed
            resolved_findings = [
                {
                    "id": "FIND-BASE-01",
                    "title": "Strict DMARC Policy Enforcement",
                    "subdomain": f"_dmarc.{resolved_domains[0]}",
                    "severity": "HIGH",
                    "category": "Email",
                    "description": "Enforce strict p=reject or p=quarantine to prevent unauthorized sender spoofing.",
                    "remediation": "Deploy TXT record _dmarc with p=reject.",
                },
                {
                    "id": "FIND-BASE-02",
                    "title": "Strict SPF Hard-Fail Enforcement",
                    "subdomain": resolved_domains[0],
                    "severity": "MEDIUM",
                    "category": "Email",
                    "description": "Transition SPF record from permissive ~all to strict -all.",
                    "remediation": "Update apex TXT SPF record to include authorized relays and terminate with -all.",
                },
                {
                    "id": "FIND-BASE-03",
                    "title": "Cloud S3 Storage Bucket Hardening",
                    "subdomain": f"assets.{resolved_domains[0]}",
                    "bucket_name": f"{clean_slug}-static-assets",
                    "severity": "HIGH",
                    "category": "Cloud",
                    "description": "Block all public ACLs and bucket policies; enforce versioning and AES256 server-side encryption.",
                    "remediation": "Apply aws_s3_bucket_public_access_block and aws_s3_bucket_versioning.",
                },
            ]

        # Determine target output directories
        target_dir = Path(output_dir) if output_dir else self.bundles_dir
        agency_bundle_dir = target_dir / clean_slug
        agency_bundle_dir.mkdir(parents=True, exist_ok=True)
        final_zip_path = agency_bundle_dir / f"{clean_slug}_remediation_bundle.zip"

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Assemble deliverables inside a temporary staging directory
        with tempfile.TemporaryDirectory() as tmp_stage:
            stage_path = Path(tmp_stage)
            reports_dir = stage_path / "reports"
            remediation_dir = stage_path / "remediation"
            reports_dir.mkdir(parents=True, exist_ok=True)
            remediation_dir.mkdir(parents=True, exist_ok=True)

            # 1. reports/executive_summary.html
            html_content = self.generate_html_report(
                agency_name=resolved_name,
                tagline=resolved_tagline,
                primary_color=resolved_primary,
                accent_color=resolved_accent,
                domains=resolved_domains,
                findings=resolved_findings,
                support_email=resolved_email,
                tier=resolved_tier,
                generated_at=now_iso,
            )
            html_path = reports_dir / "executive_summary.html"
            html_path.write_text(html_content, encoding="utf-8")

            # 2. reports/executive_summary.md
            md_content = self.generate_markdown_report(
                agency_name=resolved_name,
                primary_color=resolved_primary,
                accent_color=resolved_accent,
                domains=resolved_domains,
                findings=resolved_findings,
                tier=resolved_tier,
                generated_at=now_iso,
            )
            md_path = reports_dir / "executive_summary.md"
            md_path.write_text(md_content, encoding="utf-8")

            # 3. remediation/remediation.tf
            tf_content = self.generate_terraform_snippets(
                domains=resolved_domains,
                findings=resolved_findings,
                agency_slug=clean_slug,
            )
            tf_path = remediation_dir / "remediation.tf"
            tf_path.write_text(tf_content, encoding="utf-8")

            # 4. remediation/remediation.cfn.yaml
            cfn_content = self.generate_cloudformation_snippets(
                domains=resolved_domains,
                findings=resolved_findings,
                agency_slug=clean_slug,
            )
            cfn_path = remediation_dir / "remediation.cfn.yaml"
            cfn_path.write_text(cfn_content, encoding="utf-8")

            # 5. remediation/remediation.zone
            zone_content = self.generate_zone_file(
                domains=resolved_domains,
                findings=resolved_findings,
                agency_name=resolved_name,
            )
            zone_path = remediation_dir / "remediation.zone"
            zone_path.write_text(zone_content, encoding="utf-8")

            # 6. .orbit.yml
            orbit_content = self.generate_orbit_sentinel_config(
                agency_slug=clean_slug,
                agency_name=resolved_name,
                domains=resolved_domains,
                tier=resolved_tier,
                support_email=resolved_email,
            )
            orbit_path = stage_path / ".orbit.yml"
            orbit_path.write_text(orbit_content, encoding="utf-8")

            # 7. bundle_manifest.json
            files_to_hash = [
                ("reports/executive_summary.html", html_path),
                ("reports/executive_summary.md", md_path),
                ("remediation/remediation.tf", tf_path),
                ("remediation/remediation.cfn.yaml", cfn_path),
                ("remediation/remediation.zone", zone_path),
                (".orbit.yml", orbit_path),
            ]

            file_entries: List[Dict[str, Any]] = []
            for rel_name, f_path in files_to_hash:
                raw_bytes = f_path.read_bytes()
                f_hash = hashlib.sha256(raw_bytes).hexdigest()
                file_entries.append({
                    "path": rel_name,
                    "sha256": f_hash,
                    "size_bytes": len(raw_bytes),
                })

            manifest_dict = {
                "agency_slug": clean_slug,
                "agency_name": resolved_name,
                "tier": resolved_tier,
                "primary_color": resolved_primary,
                "accent_color": resolved_accent,
                "domains": resolved_domains,
                "findings_count": len(resolved_findings),
                "generated_at": now_iso,
                "bundle_name": f"{clean_slug}_remediation_bundle.zip",
                "files": file_entries,
            }
            manifest_path = stage_path / "bundle_manifest.json"
            manifest_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")
            manifest_path.write_bytes(manifest_bytes)

            file_entries.append({
                "path": "bundle_manifest.json",
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "size_bytes": len(manifest_bytes),
            })

            # Atomic creation:
            # Write archive to a temporary file on the same target volume,
            # then os.replace to guarantee atomic replacement semantics.
            temp_zip_name = f"{clean_slug}_bundle_{uuid.uuid4().hex[:8]}.tmp.zip"
            temp_zip_path = agency_bundle_dir / temp_zip_name

            bundle_sha256 = ""
            try:
                with zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for root, _, filenames in os.walk(stage_path):
                        for fn in filenames:
                            full_fp = Path(root) / fn
                            arcname = full_fp.relative_to(stage_path).as_posix()
                            zf.write(full_fp, arcname=arcname)

                # Verify zip integrity prior to atomic rename
                if not zipfile.is_zipfile(temp_zip_path):
                    raise RuntimeError("Generated zip failed integrity verification")

                # Compute final bundle SHA256 on the isolated temporary file BEFORE os.replace.
                # On Windows NTFS, reading final_zip_path after os.replace holds an open handle
                # which causes concurrent os.replace() calls to fail with PermissionError (WinError 5).
                bundle_sha256 = hashlib.sha256(temp_zip_path.read_bytes()).hexdigest()

                # Prepare sidecar manifest in temporary file prior to entering critical section
                sidecar_manifest = agency_bundle_dir / "bundle_manifest.json"
                manifest_dict["bundle_sha256"] = bundle_sha256
                sidecar_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")
                temp_manifest_name = f"{clean_slug}_manifest_{uuid.uuid4().hex[:8]}.tmp.json"
                temp_manifest_path = agency_bundle_dir / temp_manifest_name
                temp_manifest_path.write_bytes(sidecar_bytes)

                # Synchronize ZIP and sidecar manifest replacement atomically per agency directory
                lock_key = str(agency_bundle_dir.resolve()).lower()
                with _get_agency_lock(lock_key):
                    max_replace_attempts = 10
                    for attempt in range(max_replace_attempts):
                        try:
                            os.replace(temp_zip_path, final_zip_path)
                            break
                        except (PermissionError, OSError) as e:
                            if attempt < max_replace_attempts - 1:
                                backoff = (0.01 * (1.5 ** attempt)) + random.uniform(0.005, 0.02)
                                time.sleep(backoff)
                            else:
                                if final_zip_path.exists() and zipfile.is_zipfile(final_zip_path):
                                    logger.warning(
                                        f"Transient lock on {final_zip_path} persisted after {max_replace_attempts} attempts; "
                                        f"destination already exists as valid ZIP ({e}). Falling back to existing bundle."
                                    )
                                    bundle_sha256 = hashlib.sha256(final_zip_path.read_bytes()).hexdigest()
                                    manifest_dict["bundle_sha256"] = bundle_sha256
                                    temp_manifest_path.write_bytes(json.dumps(manifest_dict, indent=2).encode("utf-8"))
                                    break
                                raise

                    for attempt in range(max_replace_attempts):
                        try:
                            os.replace(temp_manifest_path, sidecar_manifest)
                            break
                        except (PermissionError, OSError):
                            if attempt < max_replace_attempts - 1:
                                time.sleep(0.005 * (attempt + 1) + random.uniform(0.002, 0.01))
                            elif sidecar_manifest.exists():
                                break
                            else:
                                raise
            finally:
                if temp_zip_path.exists():
                    try:
                        temp_zip_path.unlink()
                    except Exception:
                        pass
                if "temp_manifest_path" in locals() and temp_manifest_path.exists():
                    try:
                        temp_manifest_path.unlink()
                    except Exception:
                        pass

        all_file_names = [e["path"] for e in file_entries]

        logger.info(
            f"Successfully exported atomic remediation bundle for {clean_slug}: "
            f"{final_zip_path} (SHA256: {bundle_sha256[:12]}...)"
        )

        return {
            "ok": True,
            "bundle_path": str(final_zip_path),
            "sha256": bundle_sha256,
            "files": all_file_names,
            "agency_slug": clean_slug,
            "agency_name": resolved_name,
            "generated_at": now_iso,
        }

    @_hybrid_method
    def export_dns_fixpack(
        self,
        domain: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        output_dir: Optional[Path] = None,
        contact_email: Optional[str] = None,
        policy: str = "quarantine",
        report_email: Optional[str] = None,
        spf_record: Optional[str] = None,
        ca_list: Optional[List[str]] = None,
        as_dict: bool = False,
    ) -> Path | Dict[str, Any]:
        """Generates an atomic 1-click DNS fix pack ZIP bundle for the given domain."""
        from orbit_security.remediation import DnsRemediationGenerator
        from orbit_security.input_sanitizer import sanitize_domain, SecurityValidationError
        from orbit_security.scanner import is_safe_host

        try:
            clean_domain = sanitize_domain(str(domain))
        except SecurityValidationError as sve:
            raise SecurityValidationError(f"Invalid domain for fix pack export: '{domain}': {sve}") from sve

        if not is_safe_host(clean_domain):
            raise SecurityValidationError(f"SSRF blocked: Host '{clean_domain}' is not a safe target")

        domain_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", clean_domain)

        if output_dir:
            fixpack_dir = Path(output_dir).resolve()
        else:
            fixpack_dir = (self.bundles_dir / domain_slug).resolve()

        final_zip_path = (fixpack_dir / f"{domain_slug}_dns_fixpack.zip").resolve()
        try:
            final_zip_path.relative_to(fixpack_dir)
        except ValueError:
            raise SecurityValidationError(f"Path traversal detected: {final_zip_path} escapes {fixpack_dir}")

        fixpack_dir.mkdir(parents=True, exist_ok=True)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Generate fix contents
        effective_report_email = report_email or contact_email
        tf_content = DnsRemediationGenerator.generate_dns_fixes_tf(
            domain=clean_domain,
            findings=findings,
            policy=policy,
            report_email=effective_report_email,
            spf_record=spf_record,
            ca_list=ca_list,
        )
        zone_content = DnsRemediationGenerator.generate_zone_file(
            domain=clean_domain,
            findings=findings,
            policy=policy,
            report_email=effective_report_email,
            spf_record=spf_record,
            ca_list=ca_list,
        )
        sec_txt = DnsRemediationGenerator.generate_security_txt(
            domain=clean_domain,
            contact_email=contact_email,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            stage_path = Path(tmpdir).resolve()
            zone_filename = os.path.basename(f"{clean_domain}.zone")
            zone_file = (stage_path / zone_filename).resolve()
            try:
                zone_file.relative_to(stage_path)
            except ValueError:
                raise SecurityValidationError(f"Zone file path escapes staging directory: {zone_file}")

            (stage_path / "dns_fixes.tf").write_text(tf_content, encoding="utf-8")
            zone_file.write_text(zone_content, encoding="utf-8")
            (stage_path / "security.txt").write_text(sec_txt, encoding="utf-8")

            # Collect files and checksums
            file_entries = []
            for item in sorted(stage_path.iterdir()):
                if item.is_file():
                    content = item.read_bytes()
                    file_entries.append({
                        "path": item.name,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size_bytes": len(content),
                    })

            # Write fixpack_manifest.json
            manifest_dict = {
                "domain": clean_domain,
                "generated_at": now_iso,
                "bundle_name": f"{domain_slug}_dns_fixpack.zip",
                "files": file_entries,
            }
            manifest_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")
            (stage_path / "fixpack_manifest.json").write_bytes(manifest_bytes)
            file_entries.append({
                "path": "fixpack_manifest.json",
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "size_bytes": len(manifest_bytes),
            })

            # Atomic creation:
            temp_zip_name = f"{domain_slug}_fixpack_{uuid.uuid4().hex[:8]}.tmp.zip"
            temp_zip_path = fixpack_dir / temp_zip_name

            bundle_sha256 = ""
            try:
                with zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for root, _, filenames in os.walk(stage_path):
                        for fn in sorted(filenames):
                            full_fp = Path(root) / fn
                            arcname = full_fp.relative_to(stage_path).as_posix()
                            zf.write(full_fp, arcname=arcname)

                if not zipfile.is_zipfile(temp_zip_path):
                    raise RuntimeError("Generated fixpack zip failed integrity verification")

                bundle_sha256 = hashlib.sha256(temp_zip_path.read_bytes()).hexdigest()

                # Prepare sidecar manifest in temporary file
                sidecar_manifest = fixpack_dir / "fixpack_manifest.json"
                manifest_dict["bundle_sha256"] = bundle_sha256
                sidecar_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")
                temp_manifest_name = f"{domain_slug}_manifest_{uuid.uuid4().hex[:8]}.tmp.json"
                temp_manifest_path = fixpack_dir / temp_manifest_name
                temp_manifest_path.write_bytes(sidecar_bytes)

                # Mutex lock per target directory
                lock_key = str(fixpack_dir.resolve()).lower()
                with _get_agency_lock(lock_key):
                    max_replace_attempts = 10
                    for attempt in range(max_replace_attempts):
                        try:
                            os.replace(temp_zip_path, final_zip_path)
                            break
                        except (PermissionError, OSError) as e:
                            if attempt < max_replace_attempts - 1:
                                backoff = (0.01 * (1.5 ** attempt)) + random.uniform(0.005, 0.02)
                                time.sleep(backoff)
                            else:
                                if final_zip_path.exists() and zipfile.is_zipfile(final_zip_path):
                                    logger.warning(
                                        f"Transient lock on {final_zip_path} persisted after {max_replace_attempts} attempts; "
                                        f"falling back to existing bundle ({e})."
                                    )
                                    bundle_sha256 = hashlib.sha256(final_zip_path.read_bytes()).hexdigest()
                                    manifest_dict["bundle_sha256"] = bundle_sha256
                                    temp_manifest_path.write_bytes(json.dumps(manifest_dict, indent=2).encode("utf-8"))
                                    break
                                raise

                    for attempt in range(max_replace_attempts):
                        try:
                            os.replace(temp_manifest_path, sidecar_manifest)
                            break
                        except (PermissionError, OSError):
                            if attempt < max_replace_attempts - 1:
                                time.sleep(0.005 * (attempt + 1) + random.uniform(0.002, 0.01))
                            elif sidecar_manifest.exists():
                                break
                            else:
                                raise
            finally:
                if temp_zip_path.exists():
                    try:
                        temp_zip_path.unlink()
                    except Exception:
                        pass
                if "temp_manifest_path" in locals() and temp_manifest_path.exists():
                    try:
                        temp_manifest_path.unlink()
                    except Exception:
                        pass

        all_file_names = [e["path"] for e in file_entries]

        logger.info(
            f"Successfully exported atomic DNS fix pack for {clean_domain}: "
            f"{final_zip_path} (SHA256: {bundle_sha256[:12]}...)"
        )

        if as_dict:
            return {
                "ok": True,
                "fixpack_path": str(final_zip_path),
                "zip_path": final_zip_path,
                "sha256": bundle_sha256,
                "files": all_file_names,
                "domain": clean_domain,
                "generated_at": now_iso,
            }
        return final_zip_path

