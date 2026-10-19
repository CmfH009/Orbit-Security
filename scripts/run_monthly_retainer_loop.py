#!/usr/bin/env python3
r"""Orbit Security Monthly Retainer Automation Engine (scripts/run_monthly_retainer_loop.py).

Runs the full monthly retainer cycle across every active client in data/clients.json:

    scan -> detect score changes -> update agency retainer audit -> generate co-branded PDF
    -> email the PDF to the client contact -> flag at-risk agencies (score drop >= threshold).

By default emails are NOT sent over SMTP. Instead a personalized .eml draft is exported to
outbound_campaigns/monthly/ so they can be reviewed and sent from any desktop mail client.
Pass --send-email to actually deliver via SMTP (requires SMTP_HOST/SMTP_USER/SMTP_PASSWORD).

Clients are processed one at a time inside try/continue so a single scan/PDF/email failure
never aborts the whole batch.

Windows Task Scheduler registration (run from an elevated PowerShell prompt):

    schtasks.exe /Create /TN "OrbitMonthlyRetainerLoop" /TR "python A:\projects\orbit-security\scripts\run_monthly_retainer_loop.py" /SC monthly /MO 1 /D 1 /RU "$env:USERNAME" /RL HIGHEST /F

CLI:
    --limit N           Max clients to process (default: all active clients)
    --agency <id>       Only process clients for a specific agency_id
    --dry-run           Print the plan without scanning/emailing/writing
    --output-dir        Custom output directory for PDFs (default: data/generated_audits)
    --send-email        Actually send emails via SMTP (default: export .eml drafts only)
    --min-score-drop N  Flag agencies whose client score dropped by >= N points (default: 10)
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

# Make `orbit_security` importable when launched as a standalone script.
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dotenv import load_dotenv

load_dotenv(REPO_ROOT / ".env", override=False)

from orbit_security.agency_retainer import AgencyRetainerManager  # noqa: E402
from orbit_security.mailer import EmailDispatcher  # noqa: E402
from orbit_security.models import AgencyBranding, Severity  # noqa: E402
from orbit_security.reporter import ReportGenerator  # noqa: E402
from orbit_security.scanner import OrbitSecurityScanner  # noqa: E402

DEFAULT_CLIENTS_PATH = REPO_ROOT / "data" / "clients.json"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "generated_audits"
DEFAULT_EML_DIR = REPO_ROOT / "outbound_campaigns" / "monthly"


def resolve_repo_path(value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else REPO_ROOT / p


def build_branding(client: dict) -> AgencyBranding:
    """Co-branded report identity for a client's agency.

    agency_name from agency_id, support_email=contact_email,
    website=https://<apex_domain>.
    """
    return AgencyBranding(
        agency_name=str(client.get("agency_id", "orbit-security")),
        agency_tagline="Managed Web & Security Operations",
        support_email=str(client.get("contact_email", "")),
        website=f"https://{client.get('apex_domain', '')}",
    )


def severity_counts(findings: List) -> tuple[int, int, int]:
    critical = high = medium = 0
    for finding in findings:
        sev = getattr(finding, "severity", None)
        if sev == Severity.CRITICAL:
            critical += 1
        elif sev == Severity.HIGH:
            high += 1
        elif sev == Severity.MEDIUM:
            medium += 1
    return critical, high, medium


def ensure_retainer_records(
    manager: AgencyRetainerManager, agency_id: str, domain: str, client_name: str
) -> None:
    """Make sure the agency and client domain exist so update_site_audit persists."""
    if manager.get_agency(agency_id) is None:
        manager.register_agency(
            agency_id=agency_id,
            agency_name=agency_id,
            support_email="",
            website="",
        )
    agency = manager.get_agency(agency_id)
    tracked = {site.domain for site in agency.client_domains}
    clean_domain = domain.strip().lower()
    if clean_domain not in tracked:
        manager.add_client_domain(agency_id, domain, client_name=client_name or clean_domain)


def score_change_label(score_delta: Optional[int]) -> str:
    if score_delta is None:
        return "baseline"
    if score_delta > 0:
        return "improved"
    if score_delta < 0:
        return "declined"
    return "stable"


def build_email_body(
    client: dict,
    result,
    score: int,
    grade: str,
    critical: int,
    high: int,
    medium: int,
    score_delta: Optional[int],
    pdf_path: str,
) -> str:
    client_name = client.get("client_name") or client.get("client_id", "there")
    apex_domain = result.domain
    support_email = result.agency_branding.support_email or "your agency"
    total = critical + high + medium

    change = score_change_label(score_delta)
    if change == "baseline":
        change_line = "This is your first scan; the score above establishes your monthly baseline."
    elif change == "improved":
        change_line = f"Your score improved by {score_delta} points since the last scan."
    elif change == "declined":
        change_line = f"Your score declined by {abs(score_delta)} points since the last scan."
    else:
        change_line = "Your score is stable compared to the last scan."

    return "\n".join(
        [
            f"Hi {client_name} team,",
            "",
            "Here is your monthly Orbit Security perimeter audit.",
            "",
            f"Audited domain: {apex_domain}",
            f"Security score: {score} / 100",
            f"Executive grade: {grade}",
            f"Score change: {change_line}",
            f"Critical findings: {critical}",
            f"High findings: {high}",
            f"Medium findings: {medium}",
            f"Total findings: {total} (of {len(result.findings)})",
            f"Subdomains scanned: {len(result.subdomains_scanned)}",
            "",
            "Your co-branded PDF audit report is attached to this email.",
            "",
            "Please review the findings and remediation recommendations. For assisted "
            f"remediation or questions, contact your agency at {support_email}.",
            "",
            "Regards,",
            "Orbit Security",
        ]
    )


async def process_client(
    client: dict,
    scanner: OrbitSecurityScanner,
    manager: AgencyRetainerManager,
    dispatcher: EmailDispatcher,
    output_dir: Path,
    eml_dir: Path,
    send_email: bool,
    dry_run: bool,
    min_score_drop: int,
) -> dict:
    """Scan one client and return a result summary dict. Never raises."""
    client_id = client.get("client_id", "<unknown>")
    client_name = client.get("client_name", client_id)
    apex_domain = client["apex_domain"]
    subdomains = list(client.get("subdomains") or [])
    agency_id = client.get("agency_id", "orbit-security")
    contact_email = client.get("contact_email", "")
    old_score = client.get("last_score")

    summary = {
        "client_id": client_id,
        "client_name": client_name,
        "apex_domain": apex_domain,
        "agency_id": agency_id,
        "contact_email": contact_email,
        "old_score": old_score,
        "scanned": False,
        "score": None,
        "grade": None,
        "score_delta": None,
        "score_drop": None,
        "at_risk": False,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "pdf": None,
        "email_sent": False,
        "email_skipped": False,
        "error": None,
    }

    try:
        branding = build_branding(client)
        result = await scanner.scan_domain(
            apex_domain, subdomains=subdomains, agency_branding=branding
        )

        score = int(result.score)
        grade = str(result.grade)
        critical, high, medium = severity_counts(result.findings)

        score_delta: Optional[int] = None
        score_drop: Optional[int] = None
        if isinstance(old_score, (int, float)) and old_score is not None:
            score_delta = score - int(old_score)
            score_drop = int(old_score) - score
        at_risk = score_drop is not None and score_drop >= min_score_drop

        # Persist audit metrics to the agency retainer ledger.
        ensure_retainer_records(manager, agency_id, apex_domain, client_name)
        manager.update_site_audit(
            agency_id, apex_domain, score, grade, critical, high, medium
        )

        # Co-branded PDF audit.
        pdf_path = output_dir / agency_id / f"{apex_domain}_audit.pdf"
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        ReportGenerator.generate_pdf(result, str(pdf_path))
        summary["pdf"] = str(pdf_path)

        # Personalized email delivery (or .eml draft export).
        subject = (
            f"[Orbit Security] Monthly retainer audit for {apex_domain} — "
            f"Grade {grade} (Score {score}/100)"
        )
        body = build_email_body(
            client,
            result,
            score,
            grade,
            critical,
            high,
            medium,
            score_delta,
            str(pdf_path),
        )

        if dry_run:
            summary["email_skipped"] = True  # plan only, nothing sent/written
        elif send_email:
            if dispatcher.is_configured():
                ok = dispatcher.send_email(
                    contact_email,
                    subject,
                    body,
                    pdf_attachment_path=str(pdf_path),
                )
                summary["email_sent"] = bool(ok)
            else:
                # SMTP not configured: fall back to an exported .eml draft.
                eml_path = eml_dir / f"{agency_id}_{apex_domain}_audit.eml"
                eml_path.parent.mkdir(parents=True, exist_ok=True)
                dispatcher.export_eml(
                    contact_email, subject, body, str(pdf_path), str(eml_path)
                )
                summary["email_skipped"] = True
        else:
            eml_path = eml_dir / f"{agency_id}_{apex_domain}_audit.eml"
            eml_path.parent.mkdir(parents=True, exist_ok=True)
            dispatcher.export_eml(
                contact_email, subject, body, str(pdf_path), str(eml_path)
            )
            summary["email_skipped"] = True  # draft exported, not sent

        summary["scanned"] = True
        summary["score"] = score
        summary["grade"] = grade
        summary["score_delta"] = score_delta
        summary["score_drop"] = score_drop
        summary["at_risk"] = at_risk
        summary["critical"] = critical
        summary["high"] = high
        summary["medium"] = medium
    except Exception as exc:  # noqa: BLE001 - one client must never abort the batch
        summary["error"] = f"{type(exc).__name__}: {exc}"

    return summary


def load_clients(path: Path) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("clients", [])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Orbit Security monthly retainer automation engine."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max clients to process (default: all active clients).",
    )
    parser.add_argument(
        "--agency",
        default=None,
        help="Only process clients for a specific agency_id.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan without scanning/emailing/writing.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Custom output directory for PDFs (default: data/generated_audits).",
    )
    parser.add_argument(
        "--send-email",
        action="store_true",
        help="Actually send emails via SMTP (default: export .eml drafts only).",
    )
    parser.add_argument(
        "--min-score-drop",
        type=int,
        default=10,
        help="Flag agencies whose client score dropped by >= N points since last scan (default: 10).",
    )
    args = parser.parse_args()

    output_dir = resolve_repo_path(args.output_dir)
    eml_dir = resolve_repo_path("outbound_campaigns/monthly")

    clients = load_clients(DEFAULT_CLIENTS_PATH)
    clients = [c for c in clients if str(c.get("status", "")).lower() == "active"]
    if args.agency:
        clients = [c for c in clients if str(c.get("agency_id")) == args.agency]
    if args.limit is not None:
        clients = clients[: args.limit]

    if args.dry_run:
        print("ORBIT SECURITY — MONTHLY RETAINER LOOP (DRY-RUN, no changes)")
        print(f"  Clients that would be processed: {len(clients)}")
        for c in clients:
            print(
                f"  - {c.get('client_id')} | {c.get('client_name')} | "
                f"{c.get('apex_domain')} | agency={c.get('agency_id')} -> {c.get('contact_email')} "
                f"| last_score={c.get('last_score')}"
            )
        print("  (No scans, retainer updates, PDFs, or emails will be sent/written.)")
        return 0

    print("ORBIT SECURITY — MONTHLY RETAINER LOOP")
    print(f"  Clients to process: {len(clients)}")
    print(f"  PDF output dir: {output_dir}")
    print(f"  EML draft dir: {eml_dir}")
    print(f"  Send email via SMTP: {args.send_email}")
    print(f"  Min score drop to flag at-risk: {args.min_score_drop}")
    print()

    scanner = OrbitSecurityScanner()
    manager = AgencyRetainerManager()
    dispatcher = EmailDispatcher()

    async def run_all() -> List[dict]:
        return [
            await process_client(
                client,
                scanner,
                manager,
                dispatcher,
                output_dir,
                eml_dir,
                args.send_email,
                False,
                args.min_score_drop,
            )
            for client in clients
        ]

    summaries = asyncio.run(run_all())

    processed = 0
    scans_ok = 0
    scans_fail = 0
    emails_sent = 0
    emails_skipped = 0
    at_risk = 0

    for summary in summaries:
        processed += 1
        if summary["error"]:
            scans_fail += 1
            print(
                f"  [FAIL] {summary['client_id']} ({summary['apex_domain']}): {summary['error']}"
            )
            continue
        scans_ok += 1
        delta = summary["score_delta"]
        delta_str = "N/A" if delta is None else f"{delta:+d}"
        print(
            f"  [OK] {summary['client_id']} ({summary['apex_domain']}) "
            f"score={summary['score']} grade={summary['grade']} "
            f"delta={delta_str} "
            f"C={summary['critical']} H={summary['high']} M={summary['medium']} "
            f"pdf={summary['pdf']}"
        )
        if summary["at_risk"]:
            at_risk += 1
            print(
                f"      [AT-RISK] score drop {summary['score_drop']} >= {args.min_score_drop}"
            )
        if summary["email_sent"]:
            emails_sent += 1
            print(
                f"      [EMAIL SENT] {summary['client_id']} -> {summary['contact_email']}"
            )
        elif summary["email_skipped"]:
            emails_skipped += 1
            print(
                f"      [EMAIL SKIPPED/draft] {summary['client_id']} -> {summary['contact_email']}"
            )

    print()
    print("Monthly Retainer Loop Complete")
    print("==============================")
    print(f"Clients processed:  {processed}")
    print(f"Scans succeeded:    {scans_ok}")
    print(f"Scans failed:       {scans_fail}")
    print(f"Emails sent:        {emails_sent}")
    print(f"Emails skipped:     {emails_skipped} (SMTP not configured)")
    print(f"At-risk clients:    {at_risk} (score drop >= {args.min_score_drop})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
