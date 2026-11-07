#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI Runner for Generative Engine Optimization (GEO) Prompt Panel.

Usage:
  python scripts/run_geo_panel.py --dry-run
  python scripts/run_geo_panel.py --summary
  python scripts/run_geo_panel.py --engines mock
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure src is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.geo_panel import GeoPromptPanel, CANONICAL_QUERIES


def format_table(results) -> str:
    lines = [
        "=" * 84,
        f"{'#':<3} | {'ENGINE':<8} | {'MENTION':<7} | {'CITED':<6} | {'SCORE':<5} | {'QUERY':<45}",
        "-" * 84,
    ]
    for i, r in enumerate(results, 1):
        m_str = "YES" if r.mentioned else "NO"
        c_str = "YES" if r.cited else "NO"
        q_trunc = (r.query[:42] + "...") if len(r.query) > 45 else r.query
        lines.append(f"{i:<3} | {r.engine:<8} | {m_str:<7} | {c_str:<6} | {r.score:<5.2f} | {q_trunc:<45}")
    lines.append("=" * 84)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Run GEO Prompt Panel and AI Citation Tracker")
    parser.add_argument("--dry-run", action="store_true", help="Execute panel probes without writing to disk")
    parser.add_argument("--summary", action="store_true", help="Display scorecard summary from historical JSONL log")
    parser.add_argument("--engines", nargs="+", default=["mock"], help="Target AI engine names (e.g. mock, gemini, ollama)")
    parser.add_argument("--log-file", type=str, default=None, help="Custom path for geo_panels.jsonl output")
    args = parser.parse_args()

    custom_log = Path(args.log_file) if args.log_file else None
    panel = GeoPromptPanel(log_file=custom_log)

    if args.summary:
        summary_delta = panel.get_latest_summary_and_delta(log_file=custom_log)
        print("\n=== Orbit Security GEO Prompt Panel Scorecard & Delta ===")
        print(json.dumps(summary_delta, indent=2))
        return 0

    print(f"[*] Booting GEO Prompt Panel: {len(CANONICAL_QUERIES)} queries across {args.engines} engines...")
    results = panel.run_panel(engines=args.engines, dry_run=args.dry_run)
    print(format_table(results))

    scorecard = panel.calculate_scorecard([r.to_dict() for r in results])
    print("\n--- Panel Batch Metrics ---")
    print(f"Mention Rate: {scorecard['mention_rate_pct']}% | Citation Rate: {scorecard['citation_rate_pct']}% | Authority Score: {scorecard['composite_authority_score']}%")
    if args.dry_run:
        print("[!] Dry-run enabled: Results were not persisted to JSONL.")
    else:
        summary_delta = panel.get_latest_summary_and_delta(log_file=custom_log, batch_size=len(results))
        d = summary_delta["delta"]
        print(
            f"[Δ vs Previous Batch] Mention: {d['mention_rate_delta_pct']:+.1f}% | "
            f"Citation: {d['citation_rate_delta_pct']:+.1f}% | "
            f"Authority: {d['authority_score_delta']:+.1f} pts"
        )
        print(f"[✓] Appended {len(results)} probe records to {panel.log_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
