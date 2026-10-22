#!/usr/bin/env python3
"""Orbit Security — Outreach & Revenue Metrics (Phase 2 gate instrumentation).

Single source of truth for the numbers the ROADMAP Phase 2 exit gates depend on:

    * outreach volume + hard-bounce rate          (<= 3% target)
    * cohort audit-quality floor                  (mean >= 60, >= 7/10 grade C+)
    * inbound intent mix + escalation count       (>= 8% reply-rate target)
    * follow-up cadence coverage

Reads only; never mutates state. Emits a human table and, with --json, a
machine-readable snapshot for the daily briefing.

Usage:
    .venv\\Scripts\\python.exe scripts\\outreach_metrics.py
    .venv\\Scripts\\python.exe scripts\\outreach_metrics.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA = REPO_ROOT / "data"

# Intents that represent a genuine commercial conversation.
HIGH_INTENT = {"INTERESTED", "LEAD", "PRICING", "DEMO", "SERVICE_INQUIRY", "BUY"}
# Intents that are noise for pipeline purposes (auto-replies, receipts, bounces).
NOISE = {"MARKETING_NEWSLETTER", "TICKET_ACKNOWLEDGED", "OUT_OF_OFFICE", "BOUNCE"}
# An explicit rejection is worse than noise: it is a real person saying no.
REJECTION = {"NOT_INTERESTED"}
# Unclassified replies are not conversations yet.
UNCLEAR = {"UNCLEAR"}


def _load(name: str, default):
    path = DATA / name
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[warn] could not read {path}: {exc}", file=sys.stderr)
        return default


def _iter_records(payload):
    """Normalise dict/list payloads into a list of record dicts."""
    if isinstance(payload, dict):
        return [v for v in payload.values() if isinstance(v, dict)]
    if isinstance(payload, list):
        return [v for v in payload if isinstance(v, dict)]
    return []


def collect_campaigns() -> list[dict]:
    return _iter_records(_load("dispatched_campaigns.json", {}))


def collect_followups() -> list[dict]:
    return _iter_records(_load("dispatched_followups.json", {}))


def collect_bounces() -> list[dict]:
    return _iter_records(_load("bounced_agencies.json", {}))


def collect_leads() -> list[dict]:
    return _iter_records(_load("leads_state.json", {}))


def collect_cohorts() -> list[dict]:
    """Every cohort staged/dispatched manifest, newest first."""
    cohorts = []
    for path in sorted(DATA.glob("cohort_*_staged.json")):
        records = _iter_records(_load(path.name, {}))
        if not records:
            continue
        cohorts.append({
            "cohort": path.stem.replace("_staged", ""),
            "records": records,
        })
    def _cohort_num(name: str) -> int:
        m = re.search(r"(\d+)", name)
        return int(m.group(1)) if m else -1

    cohorts.sort(key=lambda c: _cohort_num(c["cohort"]), reverse=True)
    return cohorts


def grade_rank(grade: str) -> int:
    order = {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5}
    return order.get((grade or "").upper(), 6)


def compute() -> dict:
    campaigns = collect_campaigns()
    followups = collect_followups()
    bounces = collect_bounces()
    leads = collect_leads()

    sent = [c for c in campaigns if str(c.get("status", "")).upper() == "SENT"]
    # Campaigns the registry marked BOUNCED are hard bounces. The denominator
    # is every dispatched campaign, not just the ones marked SENT: a bounce is
    # still an attempt that reached the sending infrastructure.
    bounced_campaigns = [c for c in campaigns if str(c.get("status", "")).upper() == "BOUNCED"]
    bounced_domains = {b.get("agency_domain") or b.get("agency_name") for b in bounces}

    # A bounce only counts against the registry if we actually dispatched to that
    # agency; the suppression list predates the campaign registry and contains
    # historical entries. Report both so the rate is not overstated.
    registry_domains = set()
    for c in campaigns:
        domain = c.get("agency_domain") or c.get("agency_name")
        if domain:
            registry_domains.add(domain)
    attributed_bounces = {d for d in bounced_domains if d in registry_domains}
    unattributed_bounces = {d for d in bounced_domains if d not in registry_domains}

    # ---- cohort quality ----
    cohort_rows = []
    for cohort in collect_cohorts():
        scores = [r["score"] for r in cohort["records"] if isinstance(r.get("score"), (int, float))]
        grades = [str(r.get("grade", "")).upper() for r in cohort["records"]]
        if not scores:
            continue
        good = sum(1 for g in grades if grade_rank(g) <= grade_rank("C"))
        f_grades = sum(1 for g in grades if g.upper() == "F")
        cohort_rows.append({
            "cohort": cohort["cohort"],
            "audits": len(scores),
            "mean_score": round(statistics.mean(scores), 1),
            "min_score": min(scores),
            "grades": dict(Counter(grades)),
            "f_grades": f_grades,
            "grade_c_or_better": good,
            "meets_floor": (statistics.mean(scores) >= 60 and good >= 0.7 * len(scores)),
        })

    # ---- inbound ----
    intents = Counter(str(l.get("intent", "UNCLEAR")).upper() for l in leads)
    high_intent = sum(v for k, v in intents.items() if k in HIGH_INTENT)
    escalated = sum(1 for l in leads if l.get("escalated"))
    meaningful = sum(
        v for k, v in intents.items()
        if k not in NOISE and k not in REJECTION and k not in UNCLEAR
    )
    rejections = sum(v for k, v in intents.items() if k in REJECTION)

    total_sent = len(campaigns)
    bounce_rate = round(100.0 * len(bounced_campaigns) / total_sent, 2) if total_sent else 0.0
    reply_rate = round(100.0 * meaningful / total_sent, 2) if total_sent else 0.0
    # A reply rate measured against every dispatched campaign is the honest
    # denominator: a bounce is an attempt that produced no conversation.

    return {
        "generated_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "outreach": {
            "campaigns_registered": len(campaigns),
            "campaigns_sent": len(sent),
            "campaigns_dispatched": total_sent,
            "campaigns_bounced": len(bounced_campaigns),
            "followups_sent": len(followups),
            "hard_bounces": len(bounced_domains),
            "hard_bounces_attributed": len(attributed_bounces),
            "hard_bounces_unattributed": len(unattributed_bounces),
            "hard_bounce_rate_pct": bounce_rate,
            "bounce_rate_target_pct": 3.0,
            "bounce_rate_ok": bounce_rate <= 3.0,
        },
        "inbound": {
            "tracked_threads": len(leads),
            "intent_mix": dict(intents),
            "meaningful_threads": meaningful,
            "explicit_rejections": rejections,
            "high_intent_threads": high_intent,
            "escalations": escalated,
            "reply_rate_pct": reply_rate,
            "reply_rate_target_pct": 8.0,
            "reply_rate_ok": reply_rate >= 8.0,
            "rejection_rate_pct": round(100.0 * rejections / total_sent, 2) if total_sent else 0.0,
        },
        "cohort_quality": {
            "rows": cohort_rows,
            "target_mean_score": 60.0,
            "target_grade_c_or_better_ratio": 0.7,
        },
    }


def render(snapshot: dict) -> str:
    out = []
    bar = "=" * 68
    out.append(bar)
    out.append(" ORBIT SECURITY - OUTREACH & REVENUE METRICS")
    out.append(bar)

    o = snapshot["outreach"]
    out.append("\nOUTREACH")
    out.append(f"  campaigns registered      : {o['campaigns_registered']}")
    out.append(f"  campaigns dispatched      : {o['campaigns_dispatched']}")
    out.append(f"  campaigns sent (no bounce): {o['campaigns_sent']}")
    out.append(f"  campaigns hard-bounced    : {o['campaigns_bounced']}")
    out.append(f"  follow-ups sent           : {o['followups_sent']}")
    out.append(f"  hard bounces              : {o['hard_bounces']}"
               f"  ({o['hard_bounces_attributed']} attributed to registry,"
               f" {o['hard_bounces_unattributed']} historical)")
    out.append(f"  hard bounce rate          : {o['hard_bounce_rate_pct']}%"
               f"  target <= {o['bounce_rate_target_pct']}%"
               f"  [{'PASS' if o['bounce_rate_ok'] else 'FAIL'}]")

    i = snapshot["inbound"]
    out.append("\nINBOUND")
    out.append(f"  tracked threads           : {i['tracked_threads']}")
    out.append(f"  meaningful threads        : {i['meaningful_threads']}")
    out.append(f"  explicit rejections       : {i['explicit_rejections']}")
    out.append(f"  high-intent threads       : {i['high_intent_threads']}")
    out.append(f"  escalations               : {i['escalations']}")
    out.append(f"  reply rate                : {i['reply_rate_pct']}%"
               f"  target >= {i['reply_rate_target_pct']}%"
               f"  [{'PASS' if i['reply_rate_ok'] else 'FAIL'}]")
    for intent, count in sorted(i["intent_mix"].items(), key=lambda kv: -kv[1]):
        out.append(f"    - {intent:<24} {count}")
    out.append(f"  rejection rate            : {i['rejection_rate_pct']}% of sent campaigns")

    out.append("\nCOHORT AUDIT QUALITY")
    rows = snapshot["cohort_quality"]["rows"]
    if not rows:
        out.append("  (no cohort manifests found)")
    for r in rows:
        out.append(f"  {r['cohort']:<14} n={r['audits']:<3} mean={r['mean_score']:<6}"
                   f" min={r['min_score']:<4} C+={r['grade_c_or_better']}/{r['audits']}"
                   f"  F={r['f_grades']}  grades={r['grades']}"
                   f"  [{'PASS' if r['meets_floor'] else 'FAIL'}]")

    out.append("\n" + bar)
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Orbit Security outreach/revenue metrics")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    snapshot = compute()
    if args.json:
        print(json.dumps(snapshot, indent=2))
    else:
        print(render(snapshot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
