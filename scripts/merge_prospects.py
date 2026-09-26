"""Orbit Security Prospect Ingestion & Deduplication Pipeline.

Merges new curated agency records into data/prospects.json safely.
"""

import json
import os
import sys


def merge_prospects():
    base_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    main_file = os.path.join(base_dir, "prospects.json")
    new_file = os.path.join(base_dir, "new_prospects.json")

    if not os.path.exists(new_file):
        print(f"[!] No new_prospects.json found at {new_file}")
        return

    with open(main_file, "r", encoding="utf-8") as f:
        existing = json.load(f)

    with open(new_file, "r", encoding="utf-8") as f:
        new_data = json.load(f)

    existing_domains = {p["agency_domain"].lower() for p in existing}
    added = 0

    for item in new_data:
        domain = item.get("agency_domain", "").strip().lower()
        if not domain:
            continue
        if domain not in existing_domains:
            existing.append(item)
            existing_domains.add(domain)
            added += 1

    with open(main_file, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    print(f"[✔] Successfully merged {added} new agencies into {main_file}.")
    print(f"[*] Total Agency Prospects in Pipeline: {len(existing)}")


if __name__ == "__main__":
    merge_prospects()
