import argparse
import asyncio
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agency_sentry.models import AgencyBranding, Severity
from agency_sentry.reporter import ReportGenerator
from agency_sentry.scanner import AgencySentryScanner

console = Console()


async def run_scan(args):
    console.print(
        Panel.fit(
            f"[bold cyan]AgencySentry[/bold cyan] — [yellow]External Attack Surface & Subdomain Hygiene Sentinel[/yellow]\n"
            f"[dim]Auditing target:[/dim] [bold white]{args.domain}[/bold white]",
            border_style="cyan"
        )
    )

    branding = AgencyBranding(
        agency_name=args.agency_name,
        support_email=args.agency_email,
        website=args.agency_website or "https://apexdigital.io"
    )

    subdomains = []
    if args.subdomains:
        subdomains = [s.strip() for s in args.subdomains.split(",") if s.strip()]

    scanner = AgencySentryScanner()
    with console.status(f"[bold green]Running deterministic perimeter checks on {args.domain}...[/bold green]"):
        result = await scanner.scan_domain(args.domain, subdomains=subdomains, agency_branding=branding)

    # Render Terminal Results
    score_color = "green" if result.score >= 88 else ("yellow" if result.score >= 70 else "red")

    summary_table = Table(title=f"Perimeter Audit Summary: {result.domain}", border_style="dim")
    summary_table.add_column("Metric", style="bold cyan")
    summary_table.add_column("Value", style="bold white")

    summary_table.add_row("Security Score", f"[{score_color}]{result.score} / 100[/{score_color}]")
    summary_table.add_row("Executive Grade", f"[{score_color}]{result.grade}[/{score_color}]")
    summary_table.add_row("Subdomains Scanned", str(len(result.subdomains_scanned)))
    summary_table.add_row("Total Findings", str(len(result.findings)))
    console.print(summary_table)

    if result.findings:
        findings_table = Table(title="Detected Vulnerabilities & Perimeter Gaps", border_style="red")
        findings_table.add_column("Severity", style="bold", width=12)
        findings_table.add_column("Category", style="cyan", width=20)
        findings_table.add_column("Title & Target", style="white")
        findings_table.add_column("Remediation", style="green")

        for f in result.findings:
            sev_badge = {
                Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
                Severity.HIGH: "[bold orange3]HIGH[/bold orange3]",
                Severity.MEDIUM: "[bold yellow]MEDIUM[/bold yellow]",
                Severity.LOW: "[bold blue]LOW[/bold blue]",
                Severity.INFO: "[dim]INFO[/dim]",
            }.get(f.severity, f.severity.value)

            findings_table.add_row(
                sev_badge,
                f.category,
                f"[bold]{f.title}[/bold]\n[dim]{f.target}[/dim]",
                f.remediation
            )
        console.print(findings_table)
    else:
        console.print("[bold green]✔ Zero perimeter vulnerabilities detected. Domain is hardened.[/bold green]")

    # Export Reports
    if args.output_pdf:
        ReportGenerator.generate_pdf(result, args.output_pdf)
        console.print(f"[bold green]✔ White-label PDF audit generated:[/bold green] [underline]{os.path.abspath(args.output_pdf)}[/underline]")

    if args.output_md:
        md_content = ReportGenerator.generate_markdown(result)
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(md_content)
        console.print(f"[bold green]✔ Markdown audit generated:[/bold green] [underline]{os.path.abspath(args.output_md)}[/underline]")


def main():
    parser = argparse.ArgumentParser(
        description="AgencySentry: White-Label Attack Surface & Subdomain Hygiene Sentinel"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a domain and generate white-label security audit reports")
    scan_parser.add_argument("domain", help="Target apex domain (e.g. acmebrand.com)")
    scan_parser.add_argument("--subdomains", help="Comma-separated subdomains to inspect")
    scan_parser.add_argument("--agency-name", default="Apex Digital Studio", help="Agency name for co-branded report")
    scan_parser.add_argument("--agency-email", default="ops@apexdigital.io", help="Agency support email")
    scan_parser.add_argument("--agency-website", default="https://apexdigital.io", help="Agency website URL")
    scan_parser.add_argument("--output-pdf", help="Destination path for PDF report (e.g. audit.pdf)")
    scan_parser.add_argument("--output-md", help="Destination path for Markdown report (e.g. audit.md)")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(run_scan(args))


if __name__ == "__main__":
    main()
