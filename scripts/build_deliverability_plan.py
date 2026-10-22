#!/usr/bin/env python3
"""Orbit Security — deliverability recovery plan.

Turns the contact verification results into an operator-ready plan:

    SUPPRESS_NO_MX   the domain cannot receive mail at all -> drop permanently
    SUPPRESS_REFUTED the domain accepts mail but not the address we guessed
                     -> suppress the guessed address, optionally re-target the
                        published one
    RETARGET         a published address was found -> re-target candidate
    CONFIRMED        the guessed address IS published -> keep it, the bounce
                     was a mailbox-level rejection, not a data problem
    UNKNOWN          no published address could be found -> inconclusive

Reads:  data/contact_verification/verification.json
Writes: data/contact_verification/recovery_plan.json
        data/contact_verification/recovery_plan.md

Nothing is sent and nothing is suppressed automatically. This produces the
decision list; the operator applies it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFICATION = REPO_ROOT / "data" / "contact_verification" / "verification.json"
OUT_DIR = VERIFICATION.parent

# Which published address is most likely to be a prospect-facing inbox.
PREFERRED_LOCALS = ("newbiz", "newbusiness", "inquiries", "info", "hello", "hi", "biz",
                    "sales", "contact", "team", "studio", "enquiries", "work", "general")


def pick_replacement(addresses: list[str]) -> str | None:
    """Choose the most prospect-like published address."""
    if not addresses:
        return None
    for preferred in PREFERRED_LOCALS:
        for addr in addresses:
            if addr.split("@")[0].lower() == preferred:
                return addr
    return addresses[0]


def build_plan() -> dict:
    data = json.loads(VERIFICATION.read_text(encoding="utf-8"))
    rows = []
    for r in data.get("results", []):
        classification = r.get("classification")
        replacements = r.get("replacement_addresses", [])
        chosen = pick_replacement(replacements)
        if classification == "NO_MX":
            action, reason = "SUPPRESS_NO_MX", "domain publishes no mail exchanger"
        elif classification == "REFUTED" and chosen:
            action, reason = "RETARGET", f"guessed address absent; agency publishes {chosen}"
        elif classification == "REFUTED":
            action, reason = "SUPPRESS_REFUTED", "agency publishes mail, but not the address we guessed"
        elif classification == "CONFIRMED":
            action, reason = "NO_ACTION", "guessed address is published; bounce was mailbox-level"
        else:
            action, reason = "UNKNOWN", "no published address found; inconclusive"
        rows.append({
            "agency_domain": r.get("agency_domain"),
            "agency_name": r.get("agency_name"),
            "guessed_email": r.get("contact_email"),
            "classification": classification,
            "action": action,
            "replacement_email": chosen if action == "RETARGET" else None,
            "reason": reason,
        })
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["action"]] = counts.get(row["action"], 0) + 1
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(VERIFICATION.relative_to(REPO_ROOT)),
        "checked": len(rows),
        "action_counts": counts,
        "rows": rows,
    }


def render_markdown(plan: dict) -> str:
    counts = plan["action_counts"]
    retarget = [r for r in plan["rows"] if r["action"] == "RETARGET"]
    suppress = [r for r in plan["rows"] if r["action"].startswith("SUPPRESS")]

    out = []
    out.append("# Orbit Security - Deliverability Recovery Plan")
    out.append("")
    out.append(f"**Generated:** {plan['generated_utc']} | **Source:** `{plan['source']}`")
    out.append("")
    out.append("## What this is")
    out.append("")
    out.append("43 of 178 dispatched campaigns hard-bounced. The domains were fine - 43 of the 46 bounced")
    out.append("have valid MX records, and their mail providers are statistically identical to the")
    out.append("delivered set. The problem was the specific mailbox: we guessed role addresses that")
    out.append("often do not exist. This plan verifies the mailbox instead of the domain.")
    out.append("")
    out.append("## Actions")
    out.append("")
    out.append("| Action | Count | Meaning |")
    out.append("|---|---|---|")
    out.append(f"| RETARGET | {counts.get('RETARGET', 0)} | a published address exists on their own site - re-target this one |")
    out.append(f"| SUPPRESS_NO_MX | {counts.get('SUPPRESS_NO_MX', 0)} | the domain cannot receive mail at all - drop permanently |")
    out.append(f"| SUPPRESS_REFUTED | {counts.get('SUPPRESS_REFUTED', 0)} | domain accepts mail, but not the address we guessed |")
    out.append(f"| NO_ACTION | {counts.get('NO_ACTION', 0)} | guessed address is published; the bounce was mailbox-level |")
    out.append(f"| UNKNOWN | {counts.get('UNKNOWN', 0)} | no published address found - inconclusive, needs manual review |")
    out.append("")
    out.append("## Re-target list")
    out.append("")
    out.append("| Agency | Domain | We guessed | Use instead |")
    out.append("|---|---|---|---|")
    for r in retarget:
        out.append(f"| {r['agency_name'] or r['agency_domain']} | `{r['agency_domain']}` | `{r['guessed_email']}` | **`{r['replacement_email']}`** |")
    out.append("")
    out.append("## Suppress list")
    out.append("")
    out.append("| Agency | Domain | We guessed | Reason |")
    out.append("|---|---|---|---|")
    for r in suppress:
        out.append(f"| {r['agency_name'] or r['agency_domain']} | `{r['agency_domain']}` | `{r['guessed_email']}` | {r['reason']} |")
    out.append("")
    out.append("## Operator procedure")
    out.append("")
    out.append("1. Apply the suppress list to `data/bounced_agencies.json` (add the guessed address, keep")
    out.append("   the replacement out of the suppression list so it can be used).")
    out.append("2. Re-stage the re-target list as a fresh cohort using the published address.")
    out.append("3. Run `scripts/verify_contacts.py` over every new cohort **before** dispatch. A REFUTED")
    out.append("   or NO_MX agency should never enter a send queue.")
    out.append("4. Re-measure with `scripts/outreach_metrics.py` after the next cohort lands.")
    out.append("")
    out.append("## Structural fix")
    out.append("")
    out.append("Stop guessing. `scripts/verify_contacts.py` reads the agency's own published contact page")
    out.append("and checks the exact address before it enters a send queue. Wire it into the cohort")
    out.append("launcher as a pre-flight gate and the bounce rate becomes a function of target quality,")
    out.append("not of guessing.")
    out.append("")
    return "\n".join(out)


def main() -> int:
    if not VERIFICATION.exists():
        print(f"missing {VERIFICATION} - run scripts/verify_contacts.py first")
        return 1
    plan = build_plan()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "recovery_plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (OUT_DIR / "recovery_plan.md").write_text(render_markdown(plan), encoding="utf-8")

    print(f"Recovery plan for {plan['checked']} agencies")
    for action, count in sorted(plan["action_counts"].items(), key=lambda kv: -kv[1]):
        print(f"   {action:<18} {count:>3}")
    print(f"\nWrote {OUT_DIR / 'recovery_plan.json'}")
    print(f"Wrote {OUT_DIR / 'recovery_plan.md'}")

    # every RETARGET row must carry a replacement
    bad = [r for r in plan["rows"] if r["action"] == "RETARGET" and not r["replacement_email"]]
    if bad:
        print(f"FAIL: {len(bad)} RETARGET rows have no replacement address")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
