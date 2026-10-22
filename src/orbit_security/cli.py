import argparse
import asyncio
import datetime
import os
import sys
from pathlib import Path
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

    # Render Passive OSINT Intelligence summary
    osint = result.osint_intel or {}
    if osint.get("bridge_available"):
        osint_table = Table(
            title="Passive OSINT Intelligence (public-apis catalog)", border_style="dim"
        )
        osint_table.add_column("Metric", style="bold cyan")
        osint_table.add_column("Value", style="bold white")
        osint_table.add_row("Catalog APIs Indexed", str(osint.get("total_catalog_apis", 0)))
        osint_table.add_row("Security / OSINT Endpoints", str(osint.get("security_osint_count", 0)))
        osint_table.add_row("Domain Matches", str(len(osint.get("domain_matches", []))))
        osint_table.add_row("Pivot Domains", str(len(osint.get("pivot_domains", []))))
        console.print(osint_table)

        matches = osint.get("domain_matches", [])
        if matches:
            match_table = Table(title="OSINT Domain Matches", border_style="green")
            match_table.add_column("API", style="bold white", width=28)
            match_table.add_column("Category", style="cyan", width=20)
            match_table.add_column("Link", style="dim")
            for m in matches[:10]:
                match_table.add_row(
                    m.get("name", ""),
                    m.get("category", ""),
                    m.get("link", ""),
                )
            console.print(match_table)

    # Export Reports
    if args.output_pdf:
        ReportGenerator.generate_pdf(result, args.output_pdf)
        console.print(f"[bold green]✔ White-label PDF audit generated:[/bold green] [underline]{os.path.abspath(args.output_pdf)}[/underline]")

    if args.output_md:
        md_content = ReportGenerator.generate_markdown(result)
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(md_content)
        console.print(f"[bold green]✔ Markdown audit generated:[/bold green] [underline]{os.path.abspath(args.output_md)}[/underline]")


async def run_disclose(args, now_utc: datetime.datetime | None = None):
    """Automated bounty-radar -> disclosure pipeline.

    Sweeps enrolled bug bounty programs for subdomain takeover / mail-spoofing
    findings, generates HackerOne-compliant disclosure reports, and dispatches
    HIGH_CONFIDENCE alerts via Discord/Slack webhooks.

    Args:
        args: Parsed CLI namespace for the ``disclose`` subcommand.
        now_utc: Optional injectable clock (timezone-aware UTC). Defaults to
            ``datetime.now(timezone.utc)``. Injecting it keeps the off-peak
            window decision deterministic for tests and dry-run previews.
    """
    from orbit_security.bounty_radar import (
        BountyScopeIngester,
        BountyRadarSupervisor,
        BountyVulnerability,
        OffPeakWindow,
    )
    from orbit_security.models import Severity

    # --- Triage / view / copy / json / grade delegation -----------------------
    if args.list or args.view or args.copy or args.json or args.grade:
        scripts_dir = Path(__file__).resolve().parent.parent.parent / "scripts"
        if str(scripts_dir) not in sys.path:
            sys.path.insert(0, str(scripts_dir))
        import triage_bounties

        output_dir = Path(args.output_dir) if args.output_dir else triage_bounties.DISCLOSURES_DIR
        disclosures = triage_bounties.load_all_disclosures(disclosures_dir=output_dir)

        if args.view:
            target = args.view.strip().lower()
            match = next(
                (d for d in disclosures if target in d["target_domain"].lower()), None
            )
            if not match:
                console.print(
                    f"[bold red]✘ No disclosure found matching domain '{args.view}'.[/bold red]"
                )
                return 1
            console.print("\n" + match["content"] + "\n")
            return 0

        if args.copy:
            target = args.copy.strip().lower()
            match = next(
                (d for d in disclosures if target in d["target_domain"].lower()), None
            )
            if not match:
                console.print(
                    f"[bold red]✘ No disclosure found matching domain '{args.copy}'.[/bold red]"
                )
                return 1
            ok = triage_bounties.copy_to_clipboard(match["content"])
            if ok:
                console.print(
                    f"[bold green]✔ Copied HackerOne report for '{match['target_domain']}' to clipboard![/bold green]"
                )
            else:
                console.print(
                    "[bold yellow]⚠ Could not copy automatically. Use --view to display full text.[/bold yellow]"
                )
            return 0

        filtered = disclosures
        if args.grade:
            filtered = [d for d in filtered if d.get("viability") == args.grade]

        if args.json:
            export_data = [
                {k: v for k, v in d.items() if k != "content"} for d in filtered
            ]
            console.print_json(data=export_data)
            return 0

        # Default: summary table (--list or no filter)
        if not filtered:
            console.print(
                "[yellow]No vulnerability disclosures match the selected filter criteria.[/yellow]"
            )
            return 0
        table = Table(title="Orbit Security Bug Bounty Disclosure Triage", border_style="cyan")
        table.add_column("Viability Grade", style="bold cyan")
        table.add_column("Target Domain", style="bold white")
        table.add_column("Program", style="dim")
        table.add_column("Severity", style="magenta")
        table.add_column("Discovered Date", style="green")
        for d in filtered:
            grade = d.get("viability", "UNKNOWN")
            grade_badge = (
                f"🎯 {grade}"
                if grade == "HIGH_CONFIDENCE"
                else (f"⚠️ {grade}" if grade == "CONDITIONAL" else f"ℹ️ {grade}")
            )
            date_short = d.get("date_discovered", "")[:10]
            table.add_row(
                grade_badge[:18],
                d.get("target_domain", "")[:24],
                d.get("program", "")[:22],
                d.get("severity", "")[:10],
                date_short[:19],
            )
        console.print(table)
        return 0

    # --- Sweep -> disclose pipeline -------------------------------------------
    ingester = BountyScopeIngester()
    supervisor = BountyRadarSupervisor(ingester=ingester)

    # --- Dry-run preview (no external probing) ---------------------------------
    if args.dry_run:
        now_utc = now_utc or datetime.datetime.now(datetime.timezone.utc)
        in_window = OffPeakWindow.is_off_peak(now_utc)
        would_bypass = args.now or in_window

        programs = (
            [ingester.get_program(args.program)]
            if args.program
            else [p for p in ingester.list_programs() if p.state == "active"]
        )
        programs = programs[: args.max_targets] if args.program else programs[:25]

        console.print("[bold yellow]DRY-RUN — no external targets will be probed[/bold yellow]\n")
        console.print(
            f"Off-peak window (2:00 AM - 5:00 AM MST): "
            f"{'IN WINDOW' if in_window else 'OUTSIDE WINDOW'}  "
            f"{'--now would bypass' if args.now else ''}"
        )
        console.print(
            f"Sweep would{' ' if would_bypass else ' NOT '}execute "
            f"{'(blocked by off-peak window; add --now to force)' if not would_bypass else ''}\n"
        )

        table = Table(title="Programs That Would Be Swept", border_style="cyan")
        table.add_column("Program ID", style="bold cyan")
        table.add_column("Name", style="bold white")
        table.add_column("Platform", style="dim")
        table.add_column("In-Scope Patterns", style="green", justify="right")
        table.add_column("Max Targets/Program", style="magenta", justify="right")
        total_patterns = 0
        for prog in programs:
            if prog is None:
                console.print(
                    f"[bold yellow]⚠ Program '{args.program}' not found. Skipping.[/bold yellow]"
                )
                continue
            pattern_count = len(prog.in_scope)
            total_patterns += pattern_count
            table.add_row(
                prog.program_id,
                prog.name,
                prog.platform,
                str(pattern_count),
                str(args.max_targets),
            )
        console.print(table)
        console.print(
            f"\nTotal in-scope patterns across {len(programs)} program(s): {total_patterns}"
        )
        console.print(
            f"Disclosures would be saved to: {args.output_dir or 'data/disclosures'}"
        )
        console.print(
            "HIGH_CONFIDENCE alerts would be dispatched via configured webhooks."
        )
        console.print(
            "\n[dim]Remove --dry-run to execute the live sweep.[/dim]"
        )
        return 0

    output_dir = Path(args.output_dir) if args.output_dir else None

    with console.status("[bold green]Running bounty-radar sweep...[/bold green]"):
        res = supervisor.run_sweep(
            program_id=args.program,
            force_now=args.now,
            max_domains_per_program=args.max_targets,
            use_passive_ct=args.passive_ct,
            save_disclosures=True,
            output_dir=output_dir,
        )

    if res.get("status") == "SKIPPED_OUTSIDE_WINDOW":
        console.print(f"[bold yellow]⚠ {res.get('message')}[/bold yellow]")
        console.print("Tip: Run with --now to bypass the off-peak restriction.")
        return 0

    programs_scanned = res.get("programs_scanned", 0)
    vulnerabilities_found = res.get("vulnerabilities_found", 0)
    disclosed_files = res.get("disclosed_files", [])

    console.print(f"\n[bold green]✔ Sweep Completed.[/bold green]")
    console.print(f"  • Programs Scanned:      {programs_scanned}")
    console.print(f"  • Vulnerabilities Found: {vulnerabilities_found}")
    if disclosed_files:
        console.print(f"\n📄 Generated HackerOne Disclosures ({len(disclosed_files)}):")
        for f in disclosed_files:
            console.print(f"  - {f}")
    else:
        console.print(
            "  • No new takeover or spoofing vulnerabilities detected in scanned scopes."
        )

    # Dispatch HIGH_CONFIDENCE bounty alerts via Discord/Slack webhooks.
    programs_by_id = {p.program_id: p for p in ingester.list_programs()}
    alert_count = 0
    for v_dict in res.get("vulnerabilities", []):
        if v_dict.get("bounty_viability") != "HIGH_CONFIDENCE":
            continue
        prog = programs_by_id.get(v_dict.get("program_id"))
        if prog is None:
            continue
        sev = v_dict.get("severity")
        if isinstance(sev, str):
            try:
                sev = Severity(sev)
            except ValueError:
                sev = Severity.HIGH
        vuln = BountyVulnerability(**{**v_dict, "severity": sev})
        try:
            alert_res = supervisor.dispatch_bounty_alert(
                vuln,
                prog,
                discord_webhook_url=args.webhook_discord,
                slack_webhook_url=args.webhook_slack,
            )
            if alert_res.get("dispatched"):
                alert_count += 1
        except Exception as alert_err:  # noqa: BLE001
            console.print(
                f"[bold yellow]⚠ Failed to dispatch alert for {vuln.target_domain}: {alert_err}[/bold yellow]"
            )

    if alert_count:
        console.print(
            f"[bold green]✔ Dispatched {alert_count} HIGH_CONFIDENCE bounty alert(s).[/bold green]"
        )

    console.print(
        "\n[dim]Run [bold]disclose --list[/bold] to review generated disclosures.[/dim]"
    )
    return 0


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

    # Drafts command (Agent-assisted manual review & clipboard staging)
    drafts_parser = subparsers.add_parser("drafts", help="Agent-assisted local X draft deck & staging workflow")
    drafts_parser.add_argument("--list", action="store_true", help="List all staged drafts and their status")
    drafts_parser.add_argument("--generate", action="store_true", help="Generate a fresh batch of high-signal drafts")
    drafts_parser.add_argument("--count", type=int, default=5, help="Number of drafts to generate (default: 5)")
    drafts_parser.add_argument("--copy", metavar="DRAFT_ID", help="Copy draft text to Windows clipboard")
    drafts_parser.add_argument("--open", metavar="DRAFT_ID", help="Reveal draft media attachment in Windows Explorer")
    drafts_parser.add_argument("--mark-posted", metavar="DRAFT_ID", help="Mark a draft as posted and log into history")
    drafts_parser.add_argument("--send-next", action="store_true", help="Send off the next pending staged draft")

    # Disclose command (automated bounty-radar -> disclosure pipeline)
    disclose_parser = subparsers.add_parser(
        "disclose", help="Automated bug-bounty radar sweep and HackerOne disclosure pipeline"
    )
    disclose_parser.add_argument(
        "--program", "-p", help="Specific program ID to sweep (e.g. 'shopify')"
    )
    disclose_parser.add_argument(
        "--now", action="store_true", help="Force sweep immediately (bypass off-peak window)"
    )
    disclose_parser.add_argument(
        "--max-targets",
        type=int,
        default=15,
        help="Max expanded subdomains per wildcard scope (default: 15)",
    )
    disclose_parser.add_argument(
        "--passive-ct",
        action="store_true",
        help="Use Certificate Transparency passive discovery (crt.sh)",
    )
    disclose_parser.add_argument(
        "--output-dir",
        default="data/disclosures",
        help="Directory to save generated disclosures (default: data/disclosures)",
    )
    disclose_parser.add_argument(
        "--webhook-discord", help="Discord webhook URL for HIGH_CONFIDENCE alerts"
    )
    disclose_parser.add_argument(
        "--webhook-slack", help="Slack webhook URL for HIGH_CONFIDENCE alerts"
    )
    disclose_parser.add_argument(
        "--list", action="store_true", help="List existing disclosures in data/disclosures"
    )
    disclose_parser.add_argument("--view", help="View full disclosure for a domain")
    disclose_parser.add_argument("--copy", help="Copy disclosure to clipboard for a domain")
    disclose_parser.add_argument(
        "--json", action="store_true", help="Output disclosures as JSON"
    )
    disclose_parser.add_argument(
        "--grade",
        choices=["HIGH_CONFIDENCE", "CONDITIONAL", "INFORMATIONAL_LOW"],
        help="Filter by bounty viability grade",
    )
    disclose_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be swept without probing external targets",
    )

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
    elif args.command == "drafts":
        from orbit_security.draft_manager import DraftManager

        mgr = DraftManager()

        if args.generate:
            console.print(f"[cyan]Synthesizing {args.count} publish-ready X drafts with multimodal media...[/cyan]")
            drafts = mgr.generate_draft_batch(count=args.count)
            console.print(f"[bold green]✔ Successfully generated {len(drafts)} drafts![/bold green]")
            console.print(f"[dim]Staged into: {mgr.deck_file}[/dim]\n")

        elif args.copy:
            draft = mgr.get_draft(args.copy)
            if not draft:
                console.print(f"[bold red]✘ Draft '{args.copy}' not found.[/bold red]")
                return
            ok = mgr.copy_to_clipboard(args.copy)
            if ok:
                console.print(f"[bold green]✔ Draft '{args.copy}' text copied to clipboard![/bold green] ({draft.character_count}/280 chars)")
                if draft.media_path and Path(draft.media_path).exists():
                    console.print(f"[cyan]📁 Attached Media:[/cyan] {draft.media_path}")
            else:
                console.print(f"[bold yellow]⚠ Could not copy automatically. Draft text:[/bold yellow]\n{draft.text}")
            return

        elif args.open:
            draft = mgr.get_draft(args.open)
            if not draft:
                console.print(f"[bold red]✘ Draft '{args.open}' not found.[/bold red]")
                return
            if draft.media_path and Path(draft.media_path).exists():
                mgr.open_media(args.open)
                console.print(f"[bold green]✔ Opened media for '{args.open}':[/bold green] {draft.media_path}")
            else:
                console.print(f"[yellow]No media attachment found for '{args.open}'.[/yellow]")
            return

        elif args.mark_posted:
            ok = mgr.mark_posted(args.mark_posted)
            if ok:
                console.print(f"[bold green]✔ Draft '{args.mark_posted}' marked as POSTED and recorded into history.[/bold green]")
            else:
                console.print(f"[bold red]✘ Draft '{args.mark_posted}' not found.[/bold red]")
            return

        elif args.send_next:
            console.print("[cyan]Dispatching next staged draft...[/cyan]")
            res = mgr.send_next_draft()
            if res.get("success"):
                console.print(f"[bold green]✔ Successfully dispatched draft [{res['draft_id']}]: '{res['title']}'[/bold green]")
                console.print(f"[dim]Mode: {res['mode']}[/dim]")
            else:
                console.print(f"[bold red]✘ Failed to send draft: {res.get('error')}[/bold red]")
            return

        # Default or --list: render draft table
        drafts = mgr.list_drafts()
        if not drafts:
            console.print("[yellow]No drafts staged yet. Run [bold]python -m orbit_security.cli drafts --generate[/bold] to stage a fresh batch.[/yellow]")
            return

        table = Table(title="Orbit Security Staged Draft Deck", border_style="cyan")
        table.add_column("ID", style="bold cyan")
        table.add_column("Title", style="bold white")
        table.add_column("Pillar", style="dim")
        table.add_column("Chars", style="magenta")
        table.add_column("Media Asset", style="green")
        table.add_column("Status", style="bold")

        for d in drafts:
            status_style = "green" if d.status == "DRAFT" else ("blue" if d.status == "POSTED" else "dim")
            media_name = Path(d.media_path).name if d.media_path else "-"
            table.add_row(
                d.id,
                d.title[:35],
                d.pillar,
                f"{d.character_count}/280",
                f"{d.media_type.upper()}: {media_name[:24]}",
                f"[{status_style}]{d.status}[/{status_style}]"
            )
        console.print(table)
        console.print(f"[dim]Markdown Deck: {mgr.deck_file}[/dim]")

    elif args.command == "disclose":
        exit_code = asyncio.run(run_disclose(args))
        return exit_code


def main_recon():
    from orbit_security.recon import main as recon_main
    recon_main()


if __name__ == "__main__":
    main()

