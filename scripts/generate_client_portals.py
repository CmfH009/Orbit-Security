#!/usr/bin/env python3
"""scripts/generate_client_portals.py: Generates white-label, co-branded HTML audit portals per agency.

Reads agency retainers from data/agency_retainers.json and renders one
standalone, mobile-responsive HTML portal per agency at
<output-dir>/<agency-slug>.html (slug derived from agency_id, e.g.
bluestout -> bluestout.html). Each portal is co-branded with the agency's
name, tagline, support email, website/custom domain and accent colors.

Usage:
    # Dry-run: print the plan for the first 3 agencies without writing files
    python scripts/generate_client_portals.py --dry-run --limit 3

    # Only process agencies whose agency_id contains "eastside" (case-insensitive)
    python scripts/generate_client_portals.py --agency eastside

    # Live run: generate portals for all agencies
    python scripts/generate_client_portals.py

    # Live run: limited batch to a custom output directory
    python scripts/generate_client_portals.py --limit 10 --output-dir docs/portals
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure local src/ is on sys.path (same pattern as other scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.agency_retainer import (
    AgencyClientSite,
    AgencyRetainer,
    AgencyRetainerManager,
)

DEFAULT_RETAINERS_PATH = PROJECT_ROOT / "data" / "agency_retainers.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "docs" / "portals"
# Where run_cohort_outreach.py writes per-client audit PDFs.
AUDIT_PDF_ROOT = PROJECT_ROOT / "data" / "generated_audits"

REPORT_DATE = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
REPORT_YEAR = datetime.now(timezone.utc).year

# Score-to-badge color per requirement: green A-C, yellow D, red F.
GRADE_COLORS = {
    "A+": "#10B981",
    "A": "#10B981",
    "B": "#10B981",
    "C": "#10B981",
    "D": "#F59E0B",
    "F": "#EF4444",
}

STATUS_COLORS = {
    "active": "#10B981",
    "paused": "#94A3B8",
}


def slugify(name: str) -> str:
    """Convert an agency id/name to a filesystem-safe slug."""
    slug = (name or "unknown-agency").lower().strip()
    for ch in (" ", ".", "/", "_"):
        slug = slug.replace(ch, "-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def grade_color(grade: Optional[str]) -> str:
    """Return the badge color for a client grade (green A-C, yellow D, red F)."""
    return GRADE_COLORS.get(((grade or "F").strip().upper() or "F"), "#EF4444")


def status_color(status: Optional[str]) -> str:
    return STATUS_COLORS.get(((status or "active").strip().lower()), "#94A3B8")


def format_last_scanned(value: Optional[str]) -> str:
    if not value:
        return "Not scanned yet"
    return value[:16].replace("T", " ") + " UTC"


def delta_badge(site) -> str:
    """Return inline HTML for a score-change badge next to the score.

    Shows a colored trend arrow and signed delta (e.g. "↑ +12", "↓ -8",
    "→ 0") once a second scan establishes history, or a muted "baseline"
    marker on the very first scan.
    """
    trend = site.get_score_trend()
    if trend == "baseline":
        return (
            "<span class='delta-badge' style='color:#94a3b8; border-color:#94a3b855; "
            "background:#94a3b81a;' title='First scan — baseline established'>baseline</span>"
        )

    delta = int(site.score_delta or 0)
    color = "#10B981" if trend == "improved" else ("#EF4444" if trend == "declined" else "#94A3B8")
    arrow = "↑" if trend == "improved" else ("↓" if trend == "declined" else "→")
    sign = "+" if delta > 0 else ""
    return (
        f"<span class='delta-badge' style='color:{color}; border-color:{color}55; "
        f"background:{color}1a;' title='Change since last scan'>{arrow} {sign}{delta}</span>"
    )


def find_client_pdf(agency_slug: str, domain: str) -> Optional[Path]:
    """Locate a previously generated audit PDF for a client domain, if any."""
    candidate = AUDIT_PDF_ROOT / agency_slug / f"{domain}_audit.pdf"
    return candidate if candidate.exists() else None


def pdf_href(output_dir: Path, pdf: Optional[Path]) -> str:
    """Return an output-relative link to a client audit PDF, or '#' placeholder."""
    if pdf is None:
        return "#"
    try:
        return os.path.relpath(pdf.resolve(), output_dir.resolve()).replace("\\", "/")
    except ValueError:
        return "#"


def portal_css(primary: str, accent: str) -> str:
    """Inline CSS for the portal (no external dependencies, mobile-responsive)."""
    return f"""
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background: #090b12;
        color: #e2e8f0;
        line-height: 1.5;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 0 20px; }}
    .portal-header {{
        background: #0b1019;
        border-bottom: 1px solid #1f2937;
        position: sticky;
        top: 0;
        z-index: 20;
    }}
    .header-inner {{ display: flex; align-items: center; justify-content: space-between; padding: 14px 0; }}
    .brand {{ display: flex; align-items: center; gap: 12px; }}
    .brand-mark {{
        width: 44px; height: 44px; border-radius: 10px; display: grid; place-items: center;
        font-size: 20px; color: #fff;
        background: linear-gradient(135deg, {accent}, {primary});
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35);
    }}
    .brand-name {{ font-size: 20px; font-weight: 800; letter-spacing: -0.4px; color: #fff; }}
    .brand-tagline {{ font-size: 12.5px; color: #94a3b8; }}
    .portal-meta {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .meta-link {{
        font-size: 12.5px; color: {accent}; text-decoration: none;
        border: 1px solid rgba(74, 144, 226, 0.35);
        padding: 6px 12px; border-radius: 6px;
        display: inline-flex; align-items: center; justify-content: center;
        min-height: 48px; min-width: 48px; box-sizing: border-box;
    }}
    .meta-link:hover {{ opacity: 0.9; }}
    .tier-badge {{
        font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 6px;
        background: {primary}1a; color: {accent}; border: 1px solid {primary}4d;
    }}
    .dashboard {{ padding: 32px 0 24px; }}
    .section-title {{
        font-size: 16px; font-weight: 800; color: #fff;
        margin-bottom: 14px; letter-spacing: 0.5px; text-transform: uppercase;
    }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }}
    .stat-card {{
        background: #0f172a; border: 1px solid #1e293b; border-radius: 12px;
        padding: 16px 14px; text-align: center;
    }}
    .stat-label {{
        font-size: 11px; font-weight: 700; text-transform: uppercase;
        color: #94a3b8; letter-spacing: 0.4px; margin-bottom: 8px; display: block;
    }}
    .stat-value {{
        font-size: 26px; font-weight: 900; font-variant-numeric: tabular-nums;
        color: #fff; display: block;
    }}
    .stat-card.crit .stat-value {{ color: #ef4444; }}
    .stat-card.high .stat-value {{ color: #f59e0b; }}
    .stat-card.med .stat-value {{ color: #d97706; }}
    .clients {{ padding: 0 0 48px; }}
    .table-wrap {{
        overflow-x: auto; border: 1px solid #1e293b; border-radius: 12px;
        background: #0f172a;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{
        background: #0b1019; text-align: left; color: #94a3b8;
        font-size: 11px; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.5px; padding: 12px 16px; border-bottom: 1px solid #1e293b;
    }}
    th.text-center, td.text-center {{ text-align: center; }}
    th.text-right, td.text-right {{ text-align: right; }}
    td {{
        padding: 12px 16px; color: #cbd5e1; border-bottom: 1px solid #1e293b;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: #111827; }}
    .client-dot {{
        width: 8px; height: 8px; border-radius: 50%; display: inline-block;
    }}
    .client-info {{ margin-left: 10px; }}
    .client-name {{ font-weight: 700; color: #fff; font-size: 14px; }}
    .client-domain {{ font-size: 12px; color: #94a3b8; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .score-badge {{
        display: inline-block; font-size: 12px; font-weight: 800; font-variant-numeric: tabular-nums;
        padding: 4px 10px; border-radius: 6px; border: 1px solid;
    }}
    .delta-badge {{
        display: inline-block; font-size: 11px; font-weight: 700; font-variant-numeric: tabular-nums;
        padding: 2px 8px; border-radius: 6px; border: 1px solid; margin-left: 6px; white-space: nowrap;
    }}
    .findings {{
        font-size: 12.5px; font-variant-numeric: tabular-nums;
    }}
    .findings .crit {{ color: #ef4444; font-weight: 700; }}
    .findings .high {{ color: #f59e0b; font-weight: 700; }}
    .findings .med {{ color: #d97706; font-weight: 700; }}
    .status-badge {{
        display: inline-flex; align-items: center; gap: 6px;
        font-size: 11.5px; font-weight: 700; padding: 3px 10px; border-radius: 999px;
    }}
    .status-dot {{ width: 6px; height: 6px; border-radius: 50%; }}
    .font-arcade {{ font-family: 'Press Start 2P', monospace, cursive; }}
    .font-pixel {{ font-family: 'Silkscreen', monospace; }}
    .scanlines {{
        background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.15) 50%);
        background-size: 100% 4px;
    }}
    .card-glass {{
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.75) 0%, rgba(6, 10, 22, 0.90) 100%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        box-shadow: inset 0 1px 1px 0 rgba(255, 255, 255, 0.1), 0 12px 35px -10px rgba(2, 6, 23, 0.8);
        backdrop-filter: blur(16px);
    }}
    .nav-btn {{
        display: inline-flex; align-items: center; justify-content: center; gap: 6px;
        font-size: 11.5px; font-weight: 700; text-decoration: none;
        padding: 8px 14px; min-height: 48px; min-width: 48px; box-sizing: border-box; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.1);
        color: #94a3b8; transition: all 0.15s ease;
    }}
    .nav-btn:hover {{ color: #fff; border-color: rgba(255, 255, 255, 0.25); background: rgba(255, 255, 255, 0.05); }}
    .nav-btn-highlight {{ color: {accent}; border-color: {accent}55; background: {accent}1a; }}
    .nav-btn-highlight:hover {{ border-color: {accent}; }}
    .btn {{
        display: inline-flex; align-items: center; justify-content: center; gap: 6px;
        font-size: 12.5px; font-weight: 700; text-decoration: none;
        padding: 8px 16px; min-height: 48px; min-width: 48px; box-sizing: border-box; border-radius: 8px; border: 1px solid;
    }}
    .btn-primary {{
        background: {accent}; color: #090b12; border-color: {accent};
    }}
    .btn-primary:hover {{ opacity: 0.9; }}
    .btn-ghost {{
        background: transparent; color: #94a3b8; border-color: #334155;
    }}
    .btn-ghost:hover {{ border-color: #64748b; color: #e2e8f0; }}
    .btn-disabled {{
        pointer-events: none; opacity: 0.45; cursor: not-allowed;
    }}
    footer {{
        border-top: 1px solid #1f2937; background: #0a0c11;
        padding: 26px 0; color: #64748b; font-size: 12px; text-align: center;
    }}
    footer a {{ color: {accent}; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; min-height: 48px; min-width: 48px; padding: 0 8px; }}
    footer a:hover {{ text-decoration: underline; }}
    @media (max-width: 768px) {{
        .stats-grid {{ grid-template-columns: repeat(3, 1fr); }}
        .header-inner {{ flex-direction: column; align-items: stretch; gap: 14px; }}
        .portal-meta {{ justify-content: center; }}
        table {{ font-size: 12px; }}
        th, td {{ padding: 10px 12px; }}
    }}
    """


def render_portal_html(
    agency: AgencyRetainer,
    pdf_hrefs: Dict[str, str],
) -> str:
    """Render a single agency's white-label client audit portal as HTML."""
    domains = list(agency.client_domains)
    total_clients = len(domains)
    avg_score = int(sum(d.last_score for d in domains) / total_clients) if total_clients else 100
    critical_total = sum(d.critical_findings for d in domains)
    high_total = sum(d.high_findings for d in domains)
    medium_total = sum(d.medium_findings for d in domains)

    primary = agency.primary_color or "#0F172A"
    accent = agency.accent_color or "#3B82F6"
    agency_name = html.escape(agency.agency_name)
    tagline = html.escape(agency.agency_tagline or "")
    support_email = html.escape(agency.support_email or "")
    website_url = f"https://{agency.custom_domain}" if agency.custom_domain else (agency.website or "https://example.com")
    website_label = html.escape(agency.custom_domain or agency.website or "agency website")
    tier_label = f"{agency.tier.value} Retainer"

    rows: List[str] = []
    for site in domains:
        color = grade_color(site.last_grade)
        score_text = f"{site.last_score}/100 ({site.last_grade})"
        score_html = f"""
                    <span class="score-badge" style="color: {color}; border-color: {color}55; background: {color}1a;">
                        {score_text}
                    </span>{delta_badge(site)}
                """
        findings_text = (
            f"<span class='crit'>{site.critical_findings}</span> Critical / "
            f"<span class='high'>{site.high_findings}</span> High / "
            f"<span class='med'>{site.medium_findings}</span> Medium"
        )
        pdf_link = pdf_hrefs.get(site.domain, "#")
        has_pdf = pdf_link != "#"
        btn_class = "btn btn-primary" if has_pdf else "btn btn-ghost btn-disabled"
        btn_label = "Download PDF Audit" if has_pdf else "No PDF Audit"
        btn_title = (
            f"Download co-branded audit PDF for {html.escape(site.client_name)}"
            if has_pdf
            else "No generated audit PDF found for this client yet"
        )
        status = (site.status or "active").strip().lower()
        status_color_hex = status_color(status)
        status_label = status.capitalize()
        rows.append(f"""
            <tr>
                <td class="client-cell">
                    <span class="client-dot" style="background: {color}"></span>
                    <div class="client-info">
                        <div class="client-name">{html.escape(site.client_name)}</div>
                        <div class="client-domain">{html.escape(site.domain)}</div>
                    </div>
                </td>
                <td class="text-center">
                    {score_html}
                </td>
                <td class="text-center">
                    <span class="status-badge" style="color: {status_color_hex}; border: 1px solid {status_color_hex}55; background: {status_color_hex}1a;">
                        <span class="status-dot" style="background: {status_color_hex}"></span>
                        {html.escape(status_label)}
                    </span>
                </td>
                <td class="text-center findings">{findings_text}</td>
                <td class="text-center" style="font-size: 12px; color: #94a3b8; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;">
                    {html.escape(format_last_scanned(site.last_scanned))}
                </td>
                <td class="text-right">
                    <a href="{html.escape(pdf_link)}" class="{btn_class}" title="{btn_title}">{btn_label}</a>
                </td>
            </tr>
        """)

    rows_joined = "\n".join(rows)
    css = portal_css(primary, accent)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{agency_name} | Client Security Audit Portal — Orbit Security</title>
    <link rel="stylesheet" href="../assets/styles.min.css">
    <style>{css}</style>
</head>
<body>
    <header class="portal-header">
        <div class="container">
            <div class="header-inner">
                <div class="brand">
                    <div class="brand-mark font-pixel">🛡️</div>
                    <div class="brand-info">
                        <div class="brand-name font-pixel">{agency_name}</div>
                        <div class="brand-tagline">{tagline}</div>
                    </div>
                </div>
                <div class="portal-meta">
                    <a href="../index.html#audit-preview" class="nav-btn nav-btn-highlight font-pixel" title="View Executive Audit Teardown Studio">🔬 Teardown Studio</a>
                    <a href="../signup.html" class="nav-btn nav-btn-highlight font-pixel" title="Self-Serve Tier Upgrade">⚡ Upgrade Retainer</a>
                    <a href="../fleet.html" class="nav-btn" title="Multi-Domain Fleet Command Center">🛰️ Fleet Command</a>
                    <a href="index.html" class="nav-btn" title="All Agency Demo Portals">🏢 All Portals</a>
                    <a href="mailto:{support_email}" class="meta-link">✉ {support_email}</a>
                    <a href="{html.escape(website_url)}" class="meta-link" target="_blank" rel="noopener">🌐 {website_label}</a>
                    <span class="tier-badge font-arcade">{tier_label}</span>
                </div>
            </div>
        </div>
    </header>

    <section class="dashboard">
        <div class="container">
            <div class="section-title">Dashboard Summary</div>
            <div class="stats-grid">
                <div class="stat-card card-glass">
                    <span class="stat-label">Total Clients</span>
                    <span class="stat-value">{total_clients}</span>
                </div>
                <div class="stat-card card-glass">
                    <span class="stat-label">Average Score</span>
                    <span class="stat-value">{avg_score}/100</span>
                </div>
                <div class="stat-card card-glass crit">
                    <span class="stat-label">Critical Findings</span>
                    <span class="stat-value">{critical_total}</span>
                </div>
                <div class="stat-card card-glass high">
                    <span class="stat-label">High Findings</span>
                    <span class="stat-value">{high_total}</span>
                </div>
                <div class="stat-card card-glass med">
                    <span class="stat-label">Medium Findings</span>
                    <span class="stat-value">{medium_total}</span>
                </div>
            </div>
        </div>
    </section>

    <section class="clients">
        <div class="container">
            <div class="section-title">Client Portfolio</div>
            <div class="table-wrap card-glass">
                <table>
                    <thead>
                        <tr>
                            <th>Client &amp; Domain</th>
                            <th class="text-center">Score</th>
                            <th class="text-center">Status</th>
                            <th class="text-center">Findings (C / H / M)</th>
                            <th class="text-center">Last Scanned</th>
                            <th class="text-right">Audit PDF</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_joined}
                    </tbody>
                </table>
            </div>
        </div>
    </section>

    <footer>
        <div class="container">
            <p>
                © {REPORT_YEAR} <strong>Orbit Security Labs</strong> &bull;
                White-label client audit portal for <strong>{agency_name}</strong> &bull;
                <a href="../index.html#audit-preview">Executive Audit Studio</a> &bull;
                <a href="../signup.html">Upgrade Retainer</a> &bull;
                <a href="../fleet.html">Fleet Command</a> &bull;
                Report generated {REPORT_DATE}
            </p>
        </div>
    </footer>
</body>
</html>"""


def generate_portals(
    agencies: List[AgencyRetainer],
    output_dir: Path,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Generate (or dry-run plan) portals for a list of agencies.

    Each agency is wrapped in try/continue so one failure never crashes the
    batch. Returns (generated, failed) counts.
    """
    generated = 0
    failed = 0
    output_dir = Path(output_dir)

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    for agency in agencies:
        try:
            agency_slug = slugify(agency.agency_id)
            pdf_hrefs: Dict[str, str] = {}
            for site in agency.client_domains:
                pdf = None if dry_run else find_client_pdf(agency_slug, site.domain)
                pdf_hrefs[site.domain] = pdf_href(output_dir, pdf) if pdf else "#"

            html_text = render_portal_html(agency, pdf_hrefs)
            portal_path = output_dir / f"{agency_slug}.html"

            if dry_run:
                print(
                    f"[DRY-RUN] Would generate {portal_path} for {agency.agency_name} "
                    f"({len(agency.client_domains)} clients)"
                )
            else:
                portal_path.write_text(html_text, encoding="utf-8")
                print(
                    f"[✓] Portal generated for {agency.agency_name} "
                    f"({len(agency.client_domains)} clients)"
                )
            generated += 1
        except Exception as exc:  # noqa: BLE001 - isolate agency failures
            failed += 1
            name = getattr(agency, "agency_name", "UNKNOWN")
            print(f"[❌] Portal failed for {name}: {exc}")

    return generated, failed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Orbit Security: White-Label Client Audit Portal Generator"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max agencies to process (default: all)",
    )
    parser.add_argument(
        "--agency",
        type=str,
        default=None,
        help="Only process agencies whose agency_id contains this substring (case-insensitive)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(DEFAULT_OUTPUT_DIR),
        help="Custom output directory (default: docs/portals)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print plan without writing HTML files",
    )
    args = parser.parse_args()

    retainers_path = DEFAULT_RETAINERS_PATH
    if not retainers_path.exists():
        print(f"[❌] Retainers file not found: {retainers_path}")
        sys.exit(1)

    manager = AgencyRetainerManager(data_path=retainers_path)
    agencies = manager.list_agencies()

    if args.agency:
        needle = args.agency.lower()
        agencies = [a for a in agencies if needle in a.agency_id.lower()]

    if args.limit is not None:
        agencies = agencies[: args.limit]

    output_dir = Path(args.output_dir)

    print("=" * 70)
    print("🛡️  ORBIT SECURITY: WHITE-LABEL CLIENT AUDIT PORTAL GENERATOR")
    print("=" * 70)
    print(f"Retainers file : {retainers_path}")
    print(f"Agencies to process : {len(agencies)}")
    print(f"Output dir     : {output_dir}")
    print(f"Dry run        : {args.dry_run}")
    print("=" * 70)

    if args.dry_run:
        print("\n[DRY-RUN] No HTML files will be written.\n")

    generated, failed = generate_portals(agencies, output_dir, dry_run=args.dry_run)

    print("\n" + "=" * 70)
    print(f"{generated} portals generated, {failed} failed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
