#!/usr/bin/env python3
"""Refresh the numbers in ``docs/benchmark/BENCHMARK.md``.

``docs/benchmark/BENCHMARK.md`` is the published source of truth for the
benchmark page. Its prose is written by hand; its *numbers* come from a
benchmark run. This script is the bridge: it takes the hand-written template
(``scripts/benchmark_page.template.md``), substitutes every ``{{fact|format}}``
placeholder with the measured value, and appends a ``<!--bind:fact format-->``
marker next to each one.

``scripts/build_benchmark_page.py`` then verifies every marker against
``docs/benchmark/benchmark_results.json`` and refuses to build the page if any
published number has drifted from the measurement.

Workflow
--------
    .venv\\Scripts\\python.exe scripts\\run_benchmark.py --repeat 5 \\
        --out docs\\benchmark\\benchmark_results.json
    .venv\\Scripts\\python.exe scripts\\render_benchmark_md.py
    .venv\\Scripts\\python.exe scripts\\build_benchmark_page.py
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build_benchmark_page import FORMATTERS, build_facts  # noqa: E402

TEMPLATE_PATH = SCRIPTS_DIR / "benchmark_page.template.md"
DEFAULT_RESULTS = REPO_ROOT / "docs" / "benchmark" / "benchmark_results.json"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "benchmark" / "BENCHMARK.md"

PLACEHOLDER_RE = re.compile(r"\{\{([A-Za-z0-9_]+)\|([a-z0-9]+)\}\}")


def per_domain_table(facts: Dict[str, Any]) -> str:
    """Render the per-domain breakdown table from the measurement samples."""
    rows = facts.get("per_domain_rows") or []
    lines = [
        "| Domain | Grade(s) observed | Score(s) | Median active time | Fastest | "
        "Slowest | DNS queries | OS resolver lookups | HTTP requests |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def span(values: List[Any]) -> str:
        if not values:
            return "n/a"
        if len(values) == 1:
            return str(values[0])
        return f"{min(values)}-{max(values)}"

    for row in rows:
        lines.append(
            f"| `{row['domain']}` | {row['grade']} | {row['score']} | "
            f"{row['active_p50']:,.0f} ms | {row['active_min']:,.0f} ms | "
            f"{row['active_max']:,.0f} ms | {span(row['dns_queries'])} | "
            f"{span(row['os_dns_lookups'])} | {span(row['http_requests'])} |"
        )
    return "\n".join(lines)


def render(template: str, facts: Dict[str, Any]) -> str:
    template = template.replace("{{PER_DOMAIN_TABLE}}", per_domain_table(facts))

    def substitute(match: "re.Match[str]") -> str:
        name, fmt = match.group(1), match.group(2)
        if name not in facts:
            raise SystemExit(f"unknown fact '{name}' in the template")
        if fmt not in FORMATTERS:
            raise SystemExit(f"unknown format '{fmt}' for fact '{name}'")
        value = facts[name]
        rendered = "not measured" if value is None else FORMATTERS[fmt](value)
        return f"{rendered}<!--bind:{name} {fmt}-->"

    out = PLACEHOLDER_RE.sub(substitute, template)
    leftover = re.findall(r"\{\{[^}]+\}\}", out)
    if leftover:
        raise SystemExit(f"unresolved placeholders left in the output: {leftover}")
    return out


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(
        prog="render_benchmark_md.py",
        description="Refresh the measured numbers inside docs/benchmark/BENCHMARK.md.",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=DEFAULT_RESULTS,
        help="Measurement JSON to read (default: docs/benchmark/benchmark_results.json).",
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=TEMPLATE_PATH,
        help="Markdown template to fill (default: scripts/benchmark_page.template.md).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Where to write the rendered markdown (default: docs/benchmark/BENCHMARK.md).",
    )
    args = parser.parse_args(argv)

    results_path = args.results if args.results.is_absolute() else REPO_ROOT / args.results
    template_path = args.template if args.template.is_absolute() else REPO_ROOT / args.template
    out_path = args.out if args.out.is_absolute() else REPO_ROOT / args.out

    if not results_path.is_file():
        print(f"ERROR: missing measurement file {results_path}", file=sys.stderr)
        return 2
    if not template_path.is_file():
        print(f"ERROR: missing template {template_path}", file=sys.stderr)
        return 2

    results = json.loads(results_path.read_text(encoding="utf-8"))
    facts = build_facts(results)
    facts["cpu_count"] = (results.get("environment") or {}).get("cpu_count")

    out = render(template_path.read_text(encoding="utf-8"), facts)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(out, encoding="utf-8", newline="\n")
    print(f"wrote {out_path} ({len(out):,} chars)")
    print(f"bind markers: {out.count('<!--bind:')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
