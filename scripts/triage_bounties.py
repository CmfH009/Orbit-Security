#!/usr/bin/env python3
"""scripts/triage_bounties.py: Fast Triage, Review & Clipboard Helper for Bug Bounty Disclosures.

Usage:
    # List all generated vulnerability reports with viability grades
    python scripts/triage_bounties.py

    # Filter for high-confidence / cash-ready takeover findings
    python scripts/triage_bounties.py --grade HIGH_CONFIDENCE

    # View full Markdown report for a target domain
    python scripts/triage_bounties.py --view starbucksreserve.com

    # Copy report directly to clipboard for pasting into HackerOne
    python scripts/triage_bounties.py --copy starbucksreserve.com

    # Export findings as JSON
    python scripts/triage_bounties.py --json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DISCLOSURES_DIR = PROJECT_ROOT / "data" / "disclosures"


def parse_disclosure_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Extracts structured metadata from a HackerOne disclosure Markdown file."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception:
        return None

    lines = content.splitlines()
    if not lines:
        return None

    title = lines[0].lstrip("# ").strip()
    prog_match = re.search(r"\*\*Program:\*\*\s*(.+)", content)
    asset_match = re.search(r"\*\*Asset\s*\(In-Scope Target\):\*\*\s*`?([^`\n]+)`?", content)
    weakness_match = re.search(r"\*\*Weakness:\*\*\s*`?([^`\n]+)`?", content)
    sev_match = re.search(r"\*\*Severity:\*\*\s*(.+)", content)
    grade_match = re.search(r"\*\*Bounty Viability Grade:\*\*\s*`?([^`\n]+)`?", content)
    date_match = re.search(r"\*\*Date Discovered:\*\*\s*([^\n]+)", content)

    target_domain = asset_match.group(1).strip() if asset_match else file_path.stem
    program = prog_match.group(1).strip() if prog_match else "Unknown"
    weakness = weakness_match.group(1).strip() if weakness_match else "N/A"
    severity = sev_match.group(1).replace("`", "").strip() if sev_match else "N/A"
    viability = grade_match.group(1).strip() if grade_match else "INFORMATIONAL_LOW"
    date_str = date_match.group(1).strip() if date_match else "N/A"

    return {
        "file_path": str(file_path),
        "filename": file_path.name,
        "title": title,
        "target_domain": target_domain,
        "program": program,
        "weakness": weakness,
        "severity": severity,
        "viability": viability,
        "date_discovered": date_str,
        "content": content,
    }


def load_all_disclosures(
    disclosures_dir: Optional[Path] = None, include_archived: bool = False
) -> List[Dict[str, Any]]:
    """Loads all disclosure files from disk."""
    dir_path = disclosures_dir or DISCLOSURES_DIR
    if not dir_path.exists():
        return []

    disclosures: List[Dict[str, Any]] = []
    pattern = "**/*.md" if include_archived else "*.md"
    for file_path in dir_path.glob(pattern):
        parsed = parse_disclosure_file(file_path)
        if parsed:
            disclosures.append(parsed)

    # Sort newest first
    disclosures.sort(key=lambda d: d.get("date_discovered", ""), reverse=True)
    return disclosures


def archive_disclosure(domain: str, disclosures_dir: Optional[Path] = None) -> Optional[Path]:
    """Moves disclosure matching domain to archive/ subfolder."""
    base_dir = disclosures_dir or DISCLOSURES_DIR
    archive_dir = base_dir / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    target = domain.strip().lower()
    for file_path in base_dir.glob("*.md"):
        parsed = parse_disclosure_file(file_path)
        if parsed and target in parsed.get("target_domain", "").lower():
            dest = archive_dir / file_path.name
            file_path.rename(dest)
            return dest
    return None


def copy_to_clipboard(text: str) -> bool:
    """Copies text to system clipboard via PowerShell or clip.exe."""
    try:
        proc = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
        proc.communicate(input=text.encode("utf-8"))
        return proc.returncode == 0
    except Exception:
        pass
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "Set-Clipboard -Value $input"]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        proc.communicate(input=text.encode("utf-8"))
        return proc.returncode == 0
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Bug Bounty Triage & HackerOne Report Export Helper"
    )
    parser.add_argument("--grade", choices=["HIGH_CONFIDENCE", "CONDITIONAL", "INFORMATIONAL_LOW"],
                        help="Filter by bounty viability grade")
    parser.add_argument("--program", "-p", help="Filter by program name or substring")
    parser.add_argument("--view", help="View full markdown disclosure for target domain")
    parser.add_argument("--copy", help="Copy full markdown disclosure for target domain to clipboard")
    parser.add_argument("--json", action="store_true", help="Output disclosures as JSON")
    parser.add_argument("--archive", help="Move disclosure report for target domain to archive directory")
    parser.add_argument("--include-archived", action="store_true", help="Include archived reports in listing")
    parser.add_argument("--clean-informational", action="store_true",
                        help="Purge all INFORMATIONAL_LOW reports from disclosures directory")

    args = parser.parse_args()

    if args.archive:
        dest = archive_disclosure(args.archive)
        if dest:
            print(f"✓ Archived disclosure for '{args.archive}' to {dest.name}")
        else:
            print(f"Error: No active disclosure found matching domain '{args.archive}'.")
        return

    disclosures = load_all_disclosures(include_archived=args.include_archived)

    if args.clean_informational:
        removed = 0
        for d in disclosures:
            if d.get("viability") == "INFORMATIONAL_LOW":
                p = Path(d["file_path"])
                if p.exists():
                    p.unlink()
                    removed += 1
        print(f"✓ Removed {removed} INFORMATIONAL_LOW disclosure report(s).")
        return

    if args.view:
        target = args.view.strip().lower()
        match = next((d for d in disclosures if target in d["target_domain"].lower()), None)
        if not match:
            print(f"Error: No disclosure found matching domain '{args.view}'.")
            sys.exit(1)
        print("\n" + match["content"] + "\n")
        return

    if args.copy:
        target = args.copy.strip().lower()
        match = next((d for d in disclosures if target in d["target_domain"].lower()), None)
        if not match:
            print(f"Error: No disclosure found matching domain '{args.copy}'.")
            sys.exit(1)
        ok = copy_to_clipboard(match["content"])
        if ok:
            print(f"✓ Successfully copied HackerOne report for '{match['target_domain']}' to clipboard!")
        else:
            print(f"⚠️ Failed to copy report automatically. Use --view to display full text.")
        return

    # Filter disclosures
    filtered = disclosures
    if args.grade:
        filtered = [d for d in filtered if d.get("viability") == args.grade]
    if args.program:
        filtered = [d for d in filtered if args.program.lower() in d.get("program", "").lower()]

    if args.json:
        export_data = [
            {k: v for k, v in d.items() if k != "content"}
            for d in filtered
        ]
        print(json.dumps(export_data, indent=2))
        return

    # Summary table
    print("\n" + "=" * 90)
    print(" 🎯 ORBIT SECURITY: BUG BOUNTY DISCLOSURE TRIAGE DASHBOARD")
    print("=" * 90)

    if not filtered:
        print("  • No vulnerability disclosures match the selected filter criteria.")
        print("=" * 90 + "\n")
        return

    print(f" Found {len(filtered)} disclosure report(s):\n")
    fmt = "  {:<18} | {:<24} | {:<22} | {:<10} | {:<19}"
    print(fmt.format("VIABILITY GRADE", "TARGET DOMAIN", "PROGRAM", "SEVERITY", "DISCOVERED DATE"))
    print("  " + "-" * 88)

    for d in filtered:
        grade = d.get("viability", "UNKNOWN")
        grade_badge = f"🎯 {grade}" if grade == "HIGH_CONFIDENCE" else (f"⚠️ {grade}" if grade == "CONDITIONAL" else f"ℹ️ {grade}")
        date_short = d.get("date_discovered", "")[:10]
        print(fmt.format(
            grade_badge[:18],
            d.get("target_domain", "")[:24],
            d.get("program", "")[:22],
            d.get("severity", "")[:10],
            date_short[:19],
        ))

    print("=" * 90)
    print(" Tips:")
    print("   • View full report:    python scripts/triage_bounties.py --view <domain>")
    print("   • Copy to clipboard:   python scripts/triage_bounties.py --copy <domain>")
    print("   • Filter cash-ready:   python scripts/triage_bounties.py --grade HIGH_CONFIDENCE\n")


if __name__ == "__main__":
    main()
