import argparse
import asyncio
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from orbit_security.models import AgencyBranding, Severity
from orbit_security.reporter import ReportGenerator
from orbit_security.scanner import OrbitSecurityScanner

console = Console()


async def run_scan(args):
    console.print(
        Panel.fit(
            f"[bold cyan]Orbit Security[/bold cyan] — [yellow]External Attack Surface & Subdomain Hygiene Sentinel[/yellow]\n"
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

    scanner = OrbitSecurityScanner()
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
        description="Orbit Security: White-Label Attack Surface & Subdomain Hygiene Sentinel"
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
    # Social command
    social_parser = subparsers.add_parser("social", help="Autonomous hourly engagement & outreach daemon on X")
    social_parser.add_argument("--status", action="store_true", help="Display current daemon health, quotas, and database metrics")
    social_parser.add_argument("--once", action="store_true", help="Execute single hourly cycle and exit immediately")
    social_parser.add_argument("--post", action="store_true", help="Publish a thought leadership post or educational breakdown")
    social_parser.add_argument("--text", help="Custom text content for original post")
    social_parser.add_argument("--media", help="Optional path to image or video media attachment")
    social_parser.add_argument("--daemon", action="store_true", help="Run continuous 24/7 background execution loop")
    social_parser.add_argument("--dry-run", action="store_true", help="Simulate actions without mutating external X state")
    social_parser.add_argument("--reset-circuit", action="store_true", help="Reset tripped circuit breaker to CLOSED")
    social_parser.add_argument("--interval", type=int, default=3600, help="Base execution interval in seconds")
    social_parser.add_argument("--driver-mode", choices=["auto", "desktop", "browser"], default="auto", help="Driver mode: auto (prioritize active desktop window), desktop, or browser")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(run_scan(args))
    elif args.command == "social":
        from orbit_security.circuit_breaker import SocialCircuitBreaker
        from orbit_security.quota_manager import SocialQuotaManager
        from orbit_security.social_daemon import SocialDaemon
        from orbit_security.social_state import SocialStateManager

        if args.reset_circuit:
            state_mgr = SocialStateManager()
            breaker = SocialCircuitBreaker(state_manager=state_mgr)
            breaker.reset()
            console.print("[bold green]✔ Circuit breaker successfully reset to CLOSED.[/bold green]")
            return

        if args.status or (not args.daemon and not args.once and not args.post):
            state_mgr = SocialStateManager()
            quota_mgr = SocialQuotaManager(state_manager=state_mgr)
            summary = quota_mgr.get_status_summary()

            table = Table(title="Orbit Security Social Sentinel Status", border_style="cyan")
            table.add_column("Dimension", style="bold cyan")
            table.add_column("Value", style="bold white")
            table.add_row("Time-of-Day Band", f"{summary['time_of_day_band']} ({summary['velocity_multiplier']}x)")
            table.add_row("Cached Interactions", str(len(state_mgr._dedup_cache)))
            table.add_row("Posts (Hour/Day)", f"{summary['hourly_executed'].get('POST', 0)}/{summary['hourly_limits']['posts']} | {summary['daily_executed'].get('posts_count', 0)}/{summary['daily_caps']['posts']}")
            table.add_row("Replies (Hour/Day)", f"{summary['hourly_executed'].get('REPLY', 0)}/{summary['hourly_limits']['replies']} | {summary['daily_executed'].get('replies_count', 0)}/{summary['daily_caps']['replies']}")
            table.add_row("Likes (Hour/Day)", f"{summary['hourly_executed'].get('LIKE', 0)}/{summary['hourly_limits']['likes']} | {summary['daily_executed'].get('likes_count', 0)}/{summary['daily_caps']['likes']}")
            table.add_row("Reposts (Hour/Day)", f"{summary['hourly_executed'].get('REPOST', 0)}/{summary['hourly_limits']['reposts']} | {summary['daily_executed'].get('reposts_count', 0)}/{summary['daily_caps']['reposts']}")
            console.print(table)
            return

        daemon = SocialDaemon(
            nominal_interval_seconds=args.interval,
            dry_run=args.dry_run,
            driver_mode=args.driver_mode,
        )
        if args.post:
            console.print("[cyan]Publishing thought leadership post...[/cyan]")
            post_res = daemon.publish_original_post(text=args.text, media_path=args.media)
            console.print(f"[bold green]✔ Post published:[/bold green] {post_res}")
        elif args.once:
            console.print("[cyan]Executing single hourly cycle...[/cyan]")
            res = daemon.execute_hourly_cycle()
            console.print(f"[bold green]✔ Single cycle completed:[/bold green] {res}")
        elif args.daemon:
            console.print("[cyan]Launching continuous 24/7 background social sentinel...[/cyan]")
            daemon.run_loop()


def main_recon():
    from orbit_security.recon import main as recon_main
    recon_main()


if __name__ == "__main__":
    main()

