#!/usr/bin/env python3
"""Orbit Security: Mine and Select Cohort 7 Agency Prospects.

Queries prospects.json and new_prospects.json, filtering out all previously
dispatched and bounced agencies, and curates 10 premier uncontacted Shopify Plus
and headless web agencies with authentic client anchors and personalization hooks.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROSPECTS_PATH = REPO_ROOT / "data" / "prospects.json"
NEW_PROSPECTS_PATH = REPO_ROOT / "data" / "new_prospects.json"
DISPATCHED_PATH = REPO_ROOT / "data" / "dispatched_campaigns.json"
BOUNCED_PATH = REPO_ROOT / "data" / "bounced_agencies.json"

def get_uncontacted():
    disp = json.loads(DISPATCHED_PATH.read_text(encoding="utf-8")) if DISPATCHED_PATH.exists() else {}
    bounces = json.loads(BOUNCED_PATH.read_text(encoding="utf-8")) if BOUNCED_PATH.exists() else {}
    prospects = json.loads(PROSPECTS_PATH.read_text(encoding="utf-8")) if PROSPECTS_PATH.exists() else []
    new_prospects = json.loads(NEW_PROSPECTS_PATH.read_text(encoding="utf-8")) if NEW_PROSPECTS_PATH.exists() else []

    excluded = set(disp.keys()).union(set(bounces.keys()))

    candidates = []
    seen = set()

    for p in prospects + new_prospects:
        dom = p.get("agency_domain")
        if not dom or dom in excluded or dom in seen:
            continue
        portfolios = p.get("portfolio_domains", [])
        if not portfolios or len(portfolios) == 0:
            continue
        seen.add(dom)
        candidates.append(p)

    return candidates

if __name__ == "__main__":
    uncontacted = get_uncontacted()
    print(f"Total verified uncontacted prospects with client anchors: {len(uncontacted)}")
    for idx, c in enumerate(uncontacted[:15], 1):
        print(f"{idx}. {c.get('agency_name')} ({c.get('agency_domain')}) -> Client: {c.get('portfolio_domains')[0]}")
