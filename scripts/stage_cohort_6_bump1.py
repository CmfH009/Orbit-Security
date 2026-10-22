#!/usr/bin/env python3
"""Orbit Security: Pre-Stage Cohort 6 Bump #1 Follow-Up Campaign.

Generates structured JSON index and Markdown matrix tracking all 9 eligible
Cohort 6 agencies, their client domain anchors, elapsed hours, and staged EML files.
"""

from datetime import datetime
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DISPATCHED_PATH = REPO_ROOT / "data" / "dispatched_campaigns.json"
STAGED_JSON = REPO_ROOT / "data" / "cohort_6_bump1_staged.json"
MATRIX_MD = REPO_ROOT / "data" / "cohort_6_bump1_matrix.md"
FOLLOWUPS_DIR = REPO_ROOT / "outbound_campaigns" / "followups"

def main():
    disp = json.loads(DISPATCHED_PATH.read_text(encoding="utf-8"))
    now = datetime.now()
    c6_agencies = []

    for domain, info in disp.items():
        if info.get("cohort") == 6 and info.get("status") == "SENT":
            eml_file = f"bump1_{domain}.eml"
            eml_path = FOLLOWUPS_DIR / eml_file
            disp_dt = datetime.strptime(info["dispatched_at"], "%Y-%m-%d %H:%M:%S")
            elapsed = round((now - disp_dt).total_seconds() / 3600.0, 1)

            c6_agencies.append({
                "agency_name": info.get("agency_name"),
                "agency_domain": domain,
                "contact_email": info.get("contact_email"),
                "client_domain": info.get("client_domain"),
                "dispatched_at": info.get("dispatched_at"),
                "elapsed_hours": elapsed,
                "eml_file": eml_file,
                "eml_exists": eml_path.exists(),
                "status": "STAGED_READY",
                "suggested_send_window": "T+36h to T+48h (Tomorrow morning 04:00 - 10:00 MST)"
            })

    STAGED_JSON.write_text(json.dumps(c6_agencies, indent=2), encoding="utf-8")

    lines = [
        "# Cohort 6: Bump #1 Follow-Up Campaign Matrix",
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')} | **Total Staged Candidates:** {len(c6_agencies)}",
        "",
        "| # | Agency | Contact Email | Client Anchor | Dispatched At | Elapsed | Status | Draft File |",
        "|---|--------|---------------|---------------|---------------|---------|--------|------------|",
    ]

    for idx, a in enumerate(c6_agencies, 1):
        lines.append(
            f"| {idx} | **{a['agency_name']}** (`{a['agency_domain']}`) | `{a['contact_email']}` | `{a['client_domain']}` | {a['dispatched_at']} | {a['elapsed_hours']}h | 🟢 `{a['status']}` | `{a['eml_file']}` |"
        )

    lines.extend([
        "",
        "### Follow-Up Value Angle & Copy Template:",
        "```text",
        "Subject: Re: Co-branded perimeter hygiene audit for <client_domain>",
        "",
        "Hey <agency_name> team,",
        "",
        "Quick bump on this — wanted to make sure the white-label perimeter audit for <client_domain> didn't get buried over the weekend.",
        "",
        "We also pushed our live 16-bit Fleet Command Center if your developers or account leads want to test passive DoH lookups across your full client roster:",
        "https://cmfh009.github.io/Orbit-Security/fleet.html",
        "",
        "Happy to walk through any DMARC or DNS drift remediation steps, or configure automated monthly reporting for your retainer care plans.",
        "",
        "Best,",
        "Carson Haynes",
        "Founder, Orbit Security",
        "carsonmail009@gmail.com",
        "https://cmfh009.github.io/Orbit-Security/",
        "```",
        "",
        "### Execution Guidance:",
        "- Run `python scripts/run_followup_campaign.py --cohort 6 --min-hours 36 --send` to dispatch automatically once the 36h threshold is reached tomorrow.",
    ])

    MATRIX_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"[✔] Successfully staged {len(c6_agencies)} Bump #1 drafts and created matrix at {MATRIX_MD.name}")

if __name__ == "__main__":
    main()
