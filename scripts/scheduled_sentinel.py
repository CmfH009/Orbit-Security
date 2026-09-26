#!/usr/bin/env python3
"""Orbit Security Scheduled Fleet Sentinel (scripts/scheduled_sentinel.py).

Autonomous daily drift monitor and monthly co-branded PDF audit pipeline
for web & Shopify agency retainer fleets.
"""

import argparse
import asyncio
import datetime
import json
import os
from pathlib import Path
import sys
from typing import Optional

# Ensure project src is in python path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from orbit_security.fleet import ClientTarget, FleetRegistry, FleetSentinel
from orbit_security.models import AgencyBranding

console = Console()


async def run_daily_sweep(sentinel: FleetSentinel, agency_branding: Optional[AgencyBranding] = None):
    console.print(
        Panel.fit(
            "[bold cyan]Orbit Security Fleet Sentinel[/bold cyan] — [bold green]Continuous Zero-Drift Sweep[/bold green]\n"
            f"[dim]Initiating automated perimeter scan across active client retainer fleet at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            border_style="cyan",
        )
    )

    active_clients = sentinel.registry.list_active()
    console.print(f"[bold]Active Fleet Clients:[/bold] [cyan]{len(active_clients)}[/cyan]\n")

    drift_events = await sentinel.run_daily_drift_sweep(agency_branding=agency_branding)

    # Render Client Status Table
    status_table = Table(title="Fleet Retainer Health Status", border_style="dim")
    status_table.add_column("Client ID", style="bold cyan")
    status_table.add_column("Client Name", style="white")
    status_table.add_column("Apex Domain", style="dim")
    status_table.add_column("Plan", style="magenta")
    status_table.add_column("Score", style="bold")
    status_table.add_column("Grade", style="bold")
    status_table.add_column("Last Scanned", style="dim")

    for client in active_clients:
        score_val = client.last_score if client.last_score is not None else "N/A"
        grade_val = client.last_grade if client.last_grade is not None else "N/A"
        score_color = (
            "green"
            if isinstance(score_val, int) and score_val >= 88
            else ("yellow" if isinstance(score_val, int) and score_val >= 70 else "red")
        )

        status_table.add_row(
            client.client_id,
            client.client_name,
            client.apex_domain,
            client.retainer_plan,
            f"[{score_color}]{score_val}[/{score_color}]",
            f"[{score_color}]{grade_val}[/{score_color}]",
            (client.last_scanned[:19].replace("T", " ") if client.last_scanned else "Pending"),
        )
    console.print(status_table)

    if drift_events:
        alert_table = Table(title="🚨 Perimeter Regressions & Drift Detected", border_style="red")
        alert_table.add_column("Client", style="bold red")
        alert_table.add_column("Domain", style="white")
        alert_table.add_column("Delta", style="red")
        alert_table.add_column("Current Score", style="bold yellow")
        alert_table.add_column("Critical Findings", style="bold red")

        for d in drift_events:
            alert_table.add_row(
                d.client_name,
                d.domain,
                f"{d.score_change} pts",
                str(d.new_score),
                str(d.critical_findings),
            )
        console.print(alert_table)
    else:
        console.print("\n[bold green]✔ All client perimeters verified stable. Zero negative security drift.[/bold green]\n")


async def run_monthly_batch(
    sentinel: FleetSentinel,
    output_dir: Path,
    agency_branding: Optional[AgencyBranding] = None,
):
    console.print(
        Panel.fit(
            "[bold cyan]Orbit Security Fleet Sentinel[/bold cyan] — [bold yellow]Monthly Executive PDF Batch[/bold yellow]\n"
            f"[dim]Generating co-branded PDF audits into: {output_dir}[/dim]",
            border_style="yellow",
        )
    )

    reports = await sentinel.run_monthly_report_batch(output_dir, agency_branding)

    console.print(f"\n[bold green]✔ Generated {len(reports)} executive white-label audit reports:[/bold green]")
    for r in reports:
        console.print(f"  • [cyan]{r.name}[/cyan] [dim]({r})[/dim]")


def main():
    parser = argparse.ArgumentParser(description="Orbit Security Scheduled Fleet Sentinel")
    parser.add_argument(
        "--mode",
        choices=["daily-drift", "monthly-batch", "list-clients"],
        default="daily-drift",
        help="Sentinel execution mode",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/fleet",
        help="Output directory for monthly PDF reports",
    )
    parser.add_argument("--agency-name", default="Apex Digital Studio", help="Agency name for white-label reports")
    parser.add_argument("--agency-email", default="ops@apexdigital.io", help="Agency support email")
    parser.add_argument("--agency-website", default="https://apexdigital.io", help="Agency website")

    args = parser.parse_args()

    registry = FleetRegistry()
    sentinel = FleetSentinel(registry=registry)

    branding = AgencyBranding(
        agency_name=args.agency_name,
        support_email=args.agency_email,
        website=args.agency_website,
    )

    if args.mode == "list-clients":
        clients = registry.list_active()
        console.print(f"[bold cyan]Active Fleet Clients ({len(clients)}):[/bold cyan]")
        for c in clients:
            console.print(f"  • [bold]{c.client_name}[/bold] ({c.apex_domain}) — Plan: {c.retainer_plan}")
    elif args.mode == "daily-drift":
        asyncio.run(run_daily_sweep(sentinel, agency_branding=branding))
    elif args.mode == "monthly-batch":
        out_path = Path(args.output_dir) / datetime.datetime.now().strftime("%Y-%m")
        asyncio.run(run_monthly_batch(sentinel, out_path, agency_branding=branding))


if __name__ == "__main__":
    main()
