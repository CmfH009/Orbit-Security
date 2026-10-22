#!/usr/bin/env python3
"""Render the Orbit Security benchmark page from its source of truth.

Inputs
------
``docs/benchmark/BENCHMARK.md``          - the prose, tables and JSON-LD.
``docs/benchmark/benchmark_results.json`` - the machine-readable measurements.

Outputs
-------
``docs/benchmark/index.html``   - the published page.
``landing/benchmark/index.html``- byte-identical mirror of the same page.
``landing/benchmark/BENCHMARK.md`` / ``landing/benchmark/benchmark_results.json``
                               - byte-identical mirrors so the landing/ and
                                 docs/ trees stay in parity.

The build is deterministic: it uses no clock and no randomness, only the two
input files, so re-running it always produces the same bytes.

It also *fails* when the prose and the data disagree. Every measured value
that appears in the markdown carries a ``<!--bind:fact|fmt-->`` marker; the
marker is resolved against ``benchmark_results.json`` and compared with the
literal text in the markdown. A stale number therefore breaks the build
instead of shipping.

Usage
-----
    .venv\\Scripts\\python.exe scripts\\build_benchmark_page.py
    .venv\\Scripts\\python.exe scripts\\build_benchmark_page.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
LANDING_DIR = REPO_ROOT / "landing"

BENCH_DIR = "benchmark"
MD_PATH = DOCS_DIR / BENCH_DIR / "BENCHMARK.md"
JSON_PATH = DOCS_DIR / BENCH_DIR / "benchmark_results.json"
HTML_DOCS = DOCS_DIR / BENCH_DIR / "index.html"
HTML_LANDING = LANDING_DIR / BENCH_DIR / "index.html"
MD_LANDING = LANDING_DIR / BENCH_DIR / "BENCHMARK.md"
JSON_LANDING = LANDING_DIR / BENCH_DIR / "benchmark_results.json"

SITE_ORIGIN = "https://cmfh009.github.io/Orbit-Security"
CANONICAL = f"{SITE_ORIGIN}/benchmark/index.html"

#: The page's single H1. The markdown source carries the same title as its
#: first heading; the generator asserts that they match and renders the title
#: only once, in the hero, so the page never ships two H1 elements.
HERO_TITLE = "Orbit Security Audit Benchmark"

#: ``<!--bind:fact format-->`` markers tie a published number in the markdown
#: to the measurement it came from. The format is separated by a space (not a
#: pipe) so a marker never breaks a markdown table row.
BIND_RE = re.compile(r"<!--\s*bind:([A-Za-z0-9_.]+)\s+([a-z0-9]+)\s*-->")
FENCE_RE = re.compile(r"^```([A-Za-z0-9_-]*)\s*$")
CODE_PLACEHOLDER = "\ue000{}\ue001"


class BuildError(RuntimeError):
    """Raised when the prose and the measurement data disagree."""


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #


def fmt_int(value: Any) -> str:
    return f"{int(value):,}"


def fmt_thousands(value: Any) -> str:
    return f"{int(value):,}"


def fmt_ms0(value: Any) -> str:
    return f"{int(round(float(value))):,} ms"


def fmt_ms1(value: Any) -> str:
    return f"{float(value):,.1f} ms"


def fmt_s2(value: Any) -> str:
    return f"{float(value) / 1000.0:.2f} s"


def fmt_pct1(value: Any) -> str:
    return f"{float(value) * 100:.1f}%"


def fmt_pct0(value: Any) -> str:
    return f"{float(value) * 100:.0f}%"


def fmt_num1(value: Any) -> str:
    return f"{float(value):,.1f}"


def fmt_raw(value: Any) -> str:
    return str(value)


def fmt_yesno(value: Any) -> str:
    return "yes" if value else "no"


def fmt_date(value: Any) -> str:
    return str(value)[:10]


FORMATTERS = {
    "int": fmt_int,
    "thousands": fmt_thousands,
    "ms0": fmt_ms0,
    "ms1": fmt_ms1,
    "s2": fmt_s2,
    "pct1": fmt_pct1,
    "pct0": fmt_pct0,
    "num1": fmt_num1,
    "raw": fmt_raw,
    "date": fmt_date,
    "yesno": fmt_yesno,
}


# --------------------------------------------------------------------------- #
# Facts: the published numbers, derived from the measurement JSON
# --------------------------------------------------------------------------- #


def build_facts(results: Dict[str, Any]) -> Dict[str, Any]:
    """Derive every publishable fact from the raw measurement document."""
    m = results.get("measurements", {})
    lat = m.get("audit_latency", {})
    sig = m.get("signature_coverage", {})
    guards = m.get("false_positive_guards", {})
    scoring = m.get("scoring_stability", {})

    wall = lat.get("wall_ms") or {}
    active = lat.get("active_ms") or {}
    phase = lat.get("phase_breakdown") or {}

    facts: Dict[str, Any] = {
        "generated_utc": results.get("generated_utc"),
        "generated_date": (results.get("generated_utc") or "")[:10],
        "duration_s": results.get("duration_s"),
        "repo_commit": results.get("repo_commit"),
        "command_line": results.get("command_line"),
        "targets": ", ".join(lat.get("targets") or []),
        "target_count": len(lat.get("targets") or []),
        "repeat": lat.get("repeat"),
        "sample_count": lat.get("samples_usable"),
        "samples_total": lat.get("samples_total"),
        "samples_failed": lat.get("samples_failed"),
        "latency_status": lat.get("status"),
        "wall_min": wall.get("min"),
        "wall_p50": wall.get("p50"),
        "wall_p90": wall.get("p90"),
        "wall_p95": wall.get("p95"),
        "wall_p99": wall.get("p99"),
        "wall_max": wall.get("max"),
        "wall_mean": wall.get("mean"),
        "active_min": active.get("min"),
        "active_p50": active.get("p50"),
        "active_p90": active.get("p90"),
        "active_p95": active.get("p95"),
        "active_p99": active.get("p99"),
        "active_max": active.get("max"),
        "active_mean": active.get("mean"),
        "phase_dns_p50": (phase.get("dns_ms") or {}).get("p50"),
        "phase_http_p50": (phase.get("http_ms") or {}).get("p50"),
        "phase_scoring_p50": (phase.get("scoring_ms") or {}).get("p50"),
        "throttle_p50": (phase.get("throttle_sleep_ms") or {}).get("p50"),
        "cold_active_p50": ((lat.get("dns_cache_split") or {}).get("cold_repeat_1") or {}).get(
            "active_ms", {}
        ).get("p50"),
        "warm_active_p50": ((lat.get("dns_cache_split") or {}).get("warm_repeats_2_plus") or {}).get(
            "active_ms", {}
        ).get("p50"),
        "cold_dns_p50": ((lat.get("dns_cache_split") or {}).get("cold_repeat_1") or {}).get(
            "dns_ms", {}
        ).get("p50"),
        "warm_dns_p50": ((lat.get("dns_cache_split") or {}).get("warm_repeats_2_plus") or {}).get(
            "dns_ms", {}
        ).get("p50"),
        "cold_samples": ((lat.get("dns_cache_split") or {}).get("cold_repeat_1") or {}).get("samples"),
        "warm_samples": ((lat.get("dns_cache_split") or {}).get("warm_repeats_2_plus") or {}).get("samples"),
        "local_dns_cache_running": (results.get("environment") or {}).get(
            "local_dns_cache_daemon_running"
        ),
        "cpu_count": (results.get("environment") or {}).get("cpu_count"),
        "python_version": (results.get("environment") or {}).get("python_version"),
        "os_name": (results.get("environment") or {}).get("os"),
        "provider_signatures": sig.get("provider_signatures"),
        "fingerprint_entries": sig.get("fingerprint_entries"),
        "distinct_fingerprints": sig.get("distinct_provider_fingerprints"),
        "hostname_classes": sig.get("distinct_dangling_hostname_classes"),
        "nxdomain_providers": sig.get("providers_using_nxdomain_verification"),
        "static_suffixes": guards.get("static_host_suffixes_guarded"),
        "parked_fingerprints": guards.get("parked_page_fingerprints"),
        "reserved_domains": guards.get("rfc2606_reserved_domains"),
        "guard_cases": (guards.get("guard_self_test") or {}).get("cases"),
        "guard_passed": (guards.get("guard_self_test") or {}).get("passed"),
        "audits_parsed": scoring.get("audits_parsed"),
        "findings_parsed": scoring.get("findings_parsed"),
        "findings_scored_as_risk": scoring.get("findings_scored_as_risk"),
        "findings_reported_as_hygiene": scoring.get("findings_reported_as_hygiene"),
        "audits_with_critical_or_high": scoring.get("audits_with_critical_or_high"),
        "audits_without_critical_or_high": scoring.get("audits_without_critical_or_high"),
        "findings_critical": (scoring.get("findings_by_severity") or {}).get("CRITICAL"),
        "findings_high": (scoring.get("findings_by_severity") or {}).get("HIGH"),
        "findings_medium": (scoring.get("findings_by_severity") or {}).get("MEDIUM"),
        "findings_low": (scoring.get("findings_by_severity") or {}).get("LOW"),
        "findings_info": (scoring.get("findings_by_severity") or {}).get("INFO"),
        "legacy_failing": scoring.get("failing_before_d_or_f"),
        "new_failing": scoring.get("failing_after_d_or_f"),
        "grade_changed": scoring.get("audits_whose_grade_changed"),
        "rescued_from_df": scoring.get("rescued_from_d_or_f"),
        "newly_failing": scoring.get("newly_failing"),
        "floor_applied": scoring.get("exploitability_floor_applied"),
        "mean_score_delta": scoring.get("mean_score_delta"),
        "parser_fidelity_ok": scoring.get("parser_fidelity_ok"),
        "grade_stability_rate": (lat.get("grade_stability") or {}).get(
            "grade_stability_rate"
        ),
        "grade_stable_domains": (lat.get("grade_stability") or {}).get(
            "domains_with_identical_grade_across_repeats"
        ),
    }

    grades = scoring.get("grade_distribution") or {}
    for grade in ("A+", "A", "B", "C", "D", "F"):
        facts[f"grade_{grade.replace('+', 'plus')}"] = grades.get(grade, 0)

    facts["grade_distribution_text"] = ", ".join(
        f"{grade} {count}" for grade, count in grades.items()
    )

    targets = lat.get("targets") or []
    per_domain = lat.get("per_domain") or {}
    samples = lat.get("samples") or []
    samples_by_domain: Dict[str, List[Dict[str, Any]]] = {}
    for sample in samples:
        samples_by_domain.setdefault(str(sample.get("domain")), []).append(sample)

    facts["per_domain_rows"] = [
        {
            "domain": domain,
            "wall_p50": (per_domain.get(domain, {}).get("wall_ms") or {}).get("p50"),
            "active_p50": (per_domain.get(domain, {}).get("active_ms") or {}).get("p50"),
            "active_min": (per_domain.get(domain, {}).get("active_ms") or {}).get("min"),
            "active_max": (per_domain.get(domain, {}).get("active_ms") or {}).get("max"),
            "grade": ", ".join(per_domain.get(domain, {}).get("grades_observed") or []),
            "score": ", ".join(
                str(s) for s in (per_domain.get(domain, {}).get("scores_observed") or [])
            ),
            "dns_queries": sorted(
                {
                    s.get("dns_queries")
                    for s in samples_by_domain.get(domain, [])
                    if s.get("dns_queries") is not None
                }
            ),
            "os_dns_lookups": sorted(
                {
                    s.get("os_dns_lookups")
                    for s in samples_by_domain.get(domain, [])
                    if s.get("os_dns_lookups") is not None
                }
            ),
            "http_requests": sorted(
                {
                    s.get("http_requests")
                    for s in samples_by_domain.get(domain, [])
                    if s.get("http_requests") is not None
                }
            ),
        }
        for domain in targets
    ]

    # Total outbound operations actually issued during the run.
    facts["total_http_requests"] = sum(
        int(s.get("http_requests") or 0) for s in samples
    )
    facts["total_dns_operations"] = sum(
        int(s.get("dns_queries") or 0) + int(s.get("os_dns_lookups") or 0) for s in samples
    )
    facts["min_os_dns_lookups"] = min(
        (int(s.get("os_dns_lookups") or 0) for s in samples), default=None
    )
    facts["max_os_dns_lookups"] = max(
        (int(s.get("os_dns_lookups") or 0) for s in samples), default=None
    )

    # Typical per-audit request counts (the mode of the per-audit totals).
    def _mode(values: Sequence[Any]) -> Optional[int]:
        counts: Dict[int, int] = {}
        for value in values:
            if value is None:
                continue
            counts[int(value)] = counts.get(int(value), 0) + 1
        if not counts:
            return None
        return max(counts.items(), key=lambda kv: (kv[1], -kv[0]))[0]

    facts["http_requests_per_audit"] = _mode(
        [s.get("http_requests") for s in samples]
    )
    facts["dns_queries_per_audit"] = _mode([s.get("dns_queries") for s in samples])
    facts["dns_ops_per_audit"] = _mode(
        [
            (int(s.get("dns_queries") or 0) + int(s.get("os_dns_lookups") or 0))
            for s in samples
        ]
    )

    return facts


# --------------------------------------------------------------------------- #
# Assertion: the prose must agree with the data
# --------------------------------------------------------------------------- #


def verify_bindings(md_text: str, facts: Dict[str, Any]) -> List[str]:
    """Check every ``<!--bind:fact|fmt-->`` marker against the facts."""
    problems: List[str] = []
    for match in BIND_RE.finditer(md_text):
        fact_name, fmt_name = match.group(1), match.group(2)
        if fact_name not in facts:
            problems.append(f"unknown fact '{fact_name}' referenced by a bind marker")
            continue
        if fmt_name not in FORMATTERS:
            problems.append(f"unknown format '{fmt_name}' for fact '{fact_name}'")
            continue
        value = facts[fact_name]
        if value is None:
            expected = "not measured"
        else:
            expected = FORMATTERS[fmt_name](value)
        prefix = md_text[: match.start()].rstrip()
        if not prefix.endswith(expected):
            problems.append(
                f"fact '{fact_name}' should read '{expected}' in BENCHMARK.md "
                f"but the text ends with '{prefix[-60:]}'"
            )
    if not BIND_RE.search(md_text):
        problems.append(
            "BENCHMARK.md contains no <!--bind:...--> markers, so none of its "
            "numbers can be verified against benchmark_results.json"
        )
    return problems


def verify_jsonld(ld: Dict[str, Any], facts: Dict[str, Any], md_text: str) -> List[str]:
    """Check the JSON-LD graph against the facts and the page body."""
    problems: List[str] = []
    graph = ld.get("@graph") or []

    required_dataset = {
        "@id",
        "name",
        "description",
        "creator",
        "temporalCoverage",
        "distribution",
        "license",
        "isAccessibleForFree",
        "variableMeasured",
    }
    datasets = [n for n in graph if n.get("@type") == "Dataset"]
    if not datasets:
        problems.append("the JSON-LD graph has no Dataset node")
    else:
        missing = required_dataset - set(datasets[0].keys())
        if missing:
            problems.append(f"Dataset node is missing {sorted(missing)}")

    faq_nodes = [n for n in graph if n.get("@type") == "FAQPage"]
    if not faq_nodes:
        problems.append("the JSON-LD graph has no FAQPage node")
    else:
        questions = faq_nodes[0].get("mainEntity") or []
        if not 4 <= len(questions) <= 6:
            problems.append(
                f"FAQPage must answer 4-6 questions, found {len(questions)}"
            )
        for q in questions:
            name = (q.get("name") or "").strip()
            if not name:
                problems.append("a FAQPage question has an empty name")
                continue
            if name not in md_text:
                problems.append(
                    f"FAQPage question '{name[:60]}' does not appear in the page body"
                )
            answer = ((q.get("acceptedAnswer") or {}).get("text") or "").strip()
            if not answer:
                problems.append(f"FAQPage question '{name[:60]}' has no answer text")

    # The Dataset node must carry the measured numbers, not invented ones.
    date = facts.get("generated_date")
    expectations = [
        ("dateModified", date),
        ("datePublished", date),
        ("temporalCoverage", f"{date}/{date}" if date else None),
    ]
    for dataset in datasets:
        for path, expected in expectations:
            if not expected:
                continue
            actual = ld_get(dataset, path)
            if actual != expected:
                problems.append(
                    f"Dataset.{path} is '{actual}' but benchmark_results.json "
                    f"says '{expected}'"
                )
    return problems


def ld_get(obj: Any, path: str) -> Any:
    """Resolve a dotted path such as ``a.b[0].c`` inside a JSON-LD node."""
    current = obj
    for part in path.split("."):
        m = re.match(r"^([A-Za-z0-9_]+)(?:\[(\d+)\])?$", part)
        if not m:
            return None
        key, index = m.group(1), m.group(2)
        if isinstance(current, dict):
            if key not in current:
                return None
            current = current[key]
        else:
            return None
        if index is not None:
            if not isinstance(current, list) or int(index) >= len(current):
                return None
            current = current[int(index)]
    return current


# --------------------------------------------------------------------------- #
# A small, deterministic Markdown renderer
# --------------------------------------------------------------------------- #

INLINE_CODE_RE = re.compile(r"`([^`]+)`")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
ITALIC_RE = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?!\*)")


def escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_inline(text: str) -> str:
    """Escape, then apply code / bold / italic / link formatting.

    Code spans are lifted out first so that emphasis can wrap them, then
    restored at the end with their content HTML-escaped.
    """
    text = BIND_RE.sub("", text)
    code_spans: List[str] = []

    def _stash(match: "re.Match[str]") -> str:
        code_spans.append(match.group(1))
        return CODE_PLACEHOLDER.format(len(code_spans) - 1)

    text = INLINE_CODE_RE.sub(_stash, text)
    text = escape_html(text)
    text = LINK_RE.sub(
        lambda m: (
            f'<a href="{m.group(2)}" class="text-emerald-400 hover:underline">'
            f"{m.group(1)}</a>"
        ),
        text,
    )
    text = BOLD_RE.sub(r"<strong>\1</strong>", text)
    text = ITALIC_RE.sub(r"<em>\1</em>", text)

    for index, span in enumerate(code_spans):
        text = text.replace(
            CODE_PLACEHOLDER.format(index),
            '<code class="px-1.5 py-0.5 rounded bg-slate-950/80 border border-slate-800 '
            'text-cyan-300 text-xs font-mono">'
            + escape_html(span)
            + "</code>",
        )
    return text


HEADING_CLASS = {
    1: "text-3xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight font-pixel",
    2: "text-2xl sm:text-xl font-bold text-white tracking-tight mt-12 mb-5",
    3: "text-lg font-bold text-cyan-400 mt-8 mb-3 tracking-wide",
    4: "text-base font-bold text-emerald-400 mt-7 mb-2 tracking-wide",
    5: "text-sm font-bold text-slate-200 mt-5 mb-2",
    6: "text-sm font-bold text-slate-300 mt-4 mb-2",
}


def render_markdown(md: str) -> str:
    """Render the markdown subset used by BENCHMARK.md into HTML."""
    lines = md.splitlines()
    out: List[str] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]

        # Fenced code block
        fence = FENCE_RE.match(line.strip())
        if fence:
            lang = fence.group(1)
            i += 1
            buf: List[str] = []
            while i < n and not FENCE_RE.match(lines[i].strip()):
                buf.append(lines[i])
                i += 1
            i += 1  # closing fence
            if lang == "json" and '"@context"' in "\n".join(buf):
                # The JSON-LD block is injected into <head> instead of being
                # rendered inline; build_page() adds the copy-paste panel.
                continue
            out.append(
                '<pre class="mt-5 mb-5 p-4 rounded-xl bg-slate-950/90 border border-slate-800 '
                'overflow-x-auto text-xs sm:text-xs leading-relaxed">'
                f'<code class="font-mono text-cyan-300">'
                f"{escape_html(BIND_RE.sub('', chr(10).join(buf)))}</code></pre>"
            )
            continue

        # Horizontal rule
        if re.match(r"^\s*(-{3,}|\*{3,})\s*$", line):
            out.append('<hr class="my-10 border-slate-800">')
            i += 1
            continue

        # Heading
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            level = len(heading.group(1))
            text = render_inline(heading.group(2).strip())
            out.append(f'<h{level} class="{HEADING_CLASS[level]}">{text}</h{level}>')
            i += 1
            continue

        # Table
        if line.strip().startswith("|") and i + 1 < n and re.match(
            r"^\s*\|?[\s:\-|]+\|[\s:\-|]*$", lines[i + 1]
        ):
            header = _split_row(line)
            i += 2
            body: List[List[str]] = []
            while i < n and lines[i].strip().startswith("|"):
                body.append(_split_row(lines[i]))
                i += 1
            out.append(_render_table(header, body))
            continue

        # Blockquote
        if line.strip().startswith(">"):
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            out.append(
                '<blockquote class="mt-5 mb-5 pl-6 border-l-2 border-cyan-500/60 text-slate-300 '
                'text-sm sm:text-base italic leading-relaxed">'
                + render_inline(" ".join(p.strip() for p in buf).strip())
                + "</blockquote>"
            )
            continue

        # Lists
        if re.match(r"^\s*([-*]|\d+\.)\s+", line):
            ordered = bool(re.match(r"^\s*\d+\.\s+", line))
            items: List[str] = []
            while i < n and re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                item = re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i])
                item_lines = [item]
                i += 1
                while i < n and lines[i].strip() and not re.match(
                    r"^\s*([-*]|\d+\.)\s+", lines[i]
                ) and not lines[i].strip().startswith("|") and not FENCE_RE.match(
                    lines[i].strip()
                ):
                    item_lines.append(lines[i].strip())
                    i += 1
                items.append(render_inline(" ".join(item_lines).strip()))
            tag = "ol" if ordered else "ul"
            cls = "list-disc" if not ordered else ""
            style_attr = ' style="list-style-type: decimal"' if ordered else ""
            out.append(
                f'<{tag} class="mt-4 mb-4 space-y-2 {cls} pl-6 text-sm sm:text-base '
                f'text-slate-300 leading-relaxed"{style_attr}>'
                + "".join(f"<li>{it}</li>" for it in items)
                + f"</{tag}>"
            )
            continue

        # Blank line
        if not line.strip():
            i += 1
            continue

        # Pure HTML comment (used for source notes): never rendered.
        stripped = line.strip()
        if stripped.startswith("<!--") and stripped.endswith("-->"):
            i += 1
            continue

        # Paragraph
        buf = []
        while i < n and lines[i].strip() and not FENCE_RE.match(lines[i].strip()):
            if re.match(r"^(#{1,6})\s+", lines[i]):
                break
            if lines[i].strip().startswith("|") and i + 1 < n and re.match(
                r"^\s*\|?[\s:\-|]+\|[\s:\-|]*$", lines[i + 1]
            ):
                break
            if lines[i].strip().startswith(">"):
                break
            if re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                break
            buf.append(lines[i].strip())
            i += 1
        text = render_inline(" ".join(buf).strip())
        out.append(f'<p class="mt-4 mb-4 text-sm sm:text-base text-slate-300 leading-relaxed">{text}</p>')

    return "\n".join(out)


def _split_row(line: str) -> List[str]:
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


def _render_table(header: Sequence[str], body: Sequence[Sequence[str]]) -> str:
    head = "".join(
        f'<th class="p-3 sm:p-4 font-bold text-cyan-300 font-mono text-[11px] sm:text-xs '
        f'uppercase tracking-wider whitespace-nowrap">{render_inline(h)}</th>'
        for h in header
    )
    rows = []
    for row in body:
        cells = "".join(
            f'<td class="p-3 sm:p-4 text-xs sm:text-sm text-slate-300">'
            f"{render_inline(c)}</td>"
            for c in row
        )
        rows.append(f'<tr class="border-t border-slate-800/80 hover:bg-slate-900/80">{cells}</tr>')
    return (
        '<div class="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40 mt-6 mb-6">'
        '<table class="w-full text-left">'
        f'<thead class="bg-slate-900/90 border-b border-slate-800">{head}</thead>'
        f'<tbody class="divide-y divide-slate-800/60">{"".join(rows)}</tbody>'
        "</table></div>"
    )


# --------------------------------------------------------------------------- #
# Page assembly
# --------------------------------------------------------------------------- #


def stat_card(value: str, label: str, accent: str = "text-cyan-400") -> str:
    return (
        f'<div class="p-4 sm:p-5 rounded-xl bg-slate-900/60 border border-slate-800">'
        f'<div class="text-xl sm:text-xl font-extrabold {accent} font-mono">{value}</div>'
        f'<div class="text-[10px] sm:text-xs text-slate-400 uppercase tracking-wider mt-1.5">{label}</div>'
        "</div>"
    )


def build_page(md: str, results: Dict[str, Any], facts: Dict[str, Any], ld_json: str) -> str:
    # The title lives in the hero; strip it from the body so the page has
    # exactly one H1. A mismatch is a build error, not a silent edit.
    first_heading = ""
    body_md = md
    for line in md.splitlines():
        if line.startswith("# "):
            first_heading = line[2:].strip()
            break
    if first_heading != HERO_TITLE:
        raise BuildError(
            f"the first heading of BENCHMARK.md is {first_heading!r} but the page "
            f"title is {HERO_TITLE!r} - keep them identical"
        )
    body_md = "\n".join(
        line for line in md.splitlines() if line.strip() != f"# {HERO_TITLE}"
    )

    body_html = render_markdown(body_md)

    if facts.get("latency_status") == "measured":
        p50_active = fmt_ms0(facts.get("active_p50"))
        p50_wall = fmt_ms0(facts.get("wall_p50"))
        p95_active = fmt_ms0(facts.get("active_p95"))
    else:
        p50_active = p50_wall = p95_active = "not measured"

    cards = "".join(
        [
            stat_card(p50_active, "Median audit latency (active)", "text-cyan-400"),
            stat_card(p95_active, "p95 audit latency (active)", "text-emerald-400"),
            stat_card(p50_wall, "Median wall clock at 1 req/s", "text-purple-400"),
            stat_card(fmt_int(facts.get("provider_signatures") or 0), "Takeover provider signatures", "text-amber-400"),
            stat_card(fmt_int(facts.get("distinct_fingerprints") or 0), "Distinct provider fingerprints", "text-cyan-400"),
            stat_card(fmt_int(facts.get("audits_parsed") or 0), "Stored audits re-scored", "text-emerald-400"),
        ]
    )

    command = facts.get("command_line") or ".venv\\Scripts\\python.exe scripts\\run_benchmark.py"

    ld_panel = (
        '<details class="mt-5 rounded-xl border border-slate-800 bg-slate-950/70">'
        '<summary class="cursor-pointer px-4 py-3 text-xs font-mono uppercase '
        'tracking-wider text-cyan-400 transition-colors">'
        "Copy-paste ready JSON-LD (Dataset + FAQPage)</summary>"
        '<pre class="px-4 pb-4 text-[11px] sm:text-xs leading-relaxed overflow-x-auto '
        'text-slate-300 font-mono whitespace-pre">'
        f"{escape_html(ld_json)}</pre></details>"
    )

    return f"""<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orbit Security Audit Benchmark | Reproducible Latency, Signature Coverage &amp; Scoring Data</title>
    <meta name="description" content="An open, reproducible benchmark of Orbit Security: measured per-domain audit latency, takeover signature coverage, false-positive guard behaviour and grading stability over {facts.get('audits_parsed') or 0} real client audits.">
    <meta name="author" content="Carson Haynes | Founder, Orbit Security">
    <meta name="keywords" content="security benchmark, audit latency, subdomain takeover signatures, false positive prevention, security grading, reproducible benchmark, Orbit Security">
    <link rel="canonical" href="{CANONICAL}">

    <meta property="og:type" content="article">
    <meta property="og:url" content="{CANONICAL}">
    <meta property="og:title" content="Orbit Security Audit Benchmark | Reproducible Perimeter Data">
    <meta property="og:description" content="Measured audit latency, takeover signature coverage and grading stability - with the exact command, the date and the limits, published as open data.">
    <meta property="og:image" content="{SITE_ORIGIN}/assets/og-image.png">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="Orbit Security Audit Benchmark | Reproducible Perimeter Data">
    <meta name="twitter:description" content="Measured audit latency, takeover signature coverage and grading stability - with the exact command, the date and the limits.">
    <meta name="twitter:image" content="{SITE_ORIGIN}/assets/og-image.png">
    <link rel="icon" href="../favicon.ico">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2310b981'><path d='M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z'/></svg>">

    <!-- Structured data: the benchmark as a machine-readable Dataset + FAQPage -->
    <script type="application/ld+json">
{ld_json}
    </script>

    <link rel="stylesheet" href="../assets/styles.min.css">
    <style>
        .font-mono {{ font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace; }}
        .font-pixel {{ font-family: 'Silkscreen', monospace; }}
        .font-arcade {{ font-family: 'Press Start 2P', monospace; }}
        .pixel-box-emerald {{
            box-shadow: 4px 4px 0px #064e3b;
            border: 2px solid #10b981;
        }}
        .pixel-box-cyan {{
            box-shadow: 4px 4px 0px #164e63;
            border: 2px solid #06b6d4;
        }}
        .pixel-btn {{
            box-shadow: 0 0 0 1px rgba(16, 185, 129, 0.3), 0 2px 4px rgba(0, 0, 0, 0.4);
            transition: box-shadow 0.15s ease, border-color 0.15s ease;
        }}
        .pixel-btn:hover {{
            box-shadow: 0 0 16px rgba(16, 185, 129, 0.35);
            border-color: #34d399;
        }}
        .scanlines {{
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.18) 50%);
            background-size: 100% 4px;
        }}
    </style>
</head>
<body class="bg-slate-950 text-slate-100 font-sans antialiased selection:bg-emerald-500 selection:text-white" style="background-color: #060a16;">

    <!-- Header Navigation -->
    <header class="sticky top-0 z-50 backdrop-blur-md bg-slate-950/90 border-b border-slate-800">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 h-16 sm:h-20 flex items-center justify-between">
            <div class="flex items-center gap-2.5 sm:gap-3 group">
                <a href="../index.html" class="flex items-center gap-2.5 sm:gap-3 group">
                    <div class="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20 group-hover:shadow-emerald-500/30 transition-all pixel-box-emerald flex-shrink-0">
                        <svg class="w-5 h-5 sm:w-6 sm:h-6 text-slate-950 font-bold" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                    <div class="flex items-center">
                        <span class="text-lg sm:text-xl font-bold tracking-tight text-white font-pixel" style="color:#ffffff; white-space:nowrap;">Orbit Security</span>
                        <span class="hidden sm:inline-block text-[9px] ml-1.5 px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-arcade uppercase">BENCHMARK</span>
                    </div>
                </a>
            </div>

            <nav class="hidden md:flex items-center gap-3.5 gap-4 text-xs font-medium text-slate-300" style="white-space:nowrap;">
                <a href="../index.html#audit-preview" class="hover:text-emerald-400 transition-colors">Audit Studio</a>
                <a href="../fleet.html" class="hover:text-emerald-400 transition-colors flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>Fleet</a>
                <a href="../index.html#pricing" class="hover:text-emerald-400 transition-colors">Pricing</a>
                <a href="../about.html" class="hover:text-emerald-400 transition-colors">About Us</a>
                <a href="./index.html" class="text-cyan-400 font-semibold border-b border-cyan-400 pb-1">Benchmark</a>
            </nav>

            <div class="flex items-center gap-3">
                <a href="../index.html" class="text-xs font-mono text-slate-400 hover:text-emerald-400 transition-colors hidden sm:inline-block">&larr; Back to Hub</a>
                <a href="../index.html#pricing" class="px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-all pixel-btn shadow-md shadow-emerald-500/20">
                    Get Protected
                </a>
            </div>
        </div>
    </header>

    <main class="flex-1 w-full">
        <!-- Methodology hero -->
        <section class="relative overflow-hidden border-b border-slate-800/80 bg-slate-950/60">
            <div class="absolute inset-0 scanlines pointer-events-none" style="opacity:0.22"></div>
            <div class="relative max-w-7xl mx-auto px-4 sm:px-6 py-12 sm:py-12">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full text-[10px] sm:text-xs font-arcade text-cyan-300 bg-slate-950/80 border border-cyan-500/30 mb-6">
                    <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                    OPEN METHODOLOGY - MEASURED {facts.get('generated_date') or ''}
                </div>
                <h1 class="text-2xl sm:text-4xl font-extrabold text-white tracking-tight max-w-4xl leading-tight font-pixel">
                    {escape_html(HERO_TITLE)}
                </h1>
                <p class="mt-5 text-sm sm:text-base text-slate-400 max-w-3xl leading-relaxed">
                    Every number Orbit Security publishes about its own speed and coverage is measured here by a script anyone can run, on a dated sample, with the limits stated up front. If a measurement could not be taken, this page says so instead of estimating.
                </p>

                <div class="mt-8 grid grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
{cards}
                </div>

                <div class="mt-8 p-4 sm:p-5 rounded-xl bg-slate-950/80 border border-slate-800">
                    <div class="text-[10px] uppercase tracking-wider text-slate-500 font-mono mb-2">Exact command that produced this page</div>
                    <pre class="text-xs sm:text-xs text-cyan-300 font-mono overflow-x-auto whitespace-pre-wrap">{escape_html(command)}</pre>
                </div>

                <div class="mt-6 flex flex-wrap gap-3">
                    <a href="./benchmark_results.json" class="px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition-all pixel-btn shadow-lg shadow-cyan-500/20">Download the raw JSON</a>
                    <a href="../about.html" class="px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-white font-medium text-xs transition-all pixel-btn">See the claims this tests</a>
                </div>
            </div>
        </section>

        <!-- Body, rendered from docs/benchmark/BENCHMARK.md -->
        <article class="max-w-4xl mx-auto px-4 sm:px-6 py-12 sm:py-12">
{body_html}
{ld_panel}
        </article>

        <!-- CTA -->
        <section class="max-w-4xl mx-auto px-4 sm:px-6 pb-20">
            <div class="p-6 rounded-2xl bg-gradient-to-r from-emerald-950/40 via-slate-900 to-cyan-500 border border-emerald-500/30 text-center pixel-box-emerald">
                <h2 class="text-2xl font-extrabold text-white mb-3">Want the same measurements on your own estate?</h2>
                <p class="text-slate-300 text-sm max-w-2xl mx-auto mb-6">
                    Run the identical harness against a client list you are authorised to scan. Same code path, same rate limit, same output format.
                </p>
                <div class="flex flex-wrap items-center justify-center gap-4">
                    <a href="../index.html#audit-preview" class="px-6 py-3 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm transition-all pixel-btn shadow-lg shadow-emerald-500/20">Run Free Domain Audit</a>
                    <a href="../signup.html" class="px-6 py-3 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-white font-medium text-sm transition-all pixel-btn">Explore Agency Tiers</a>
                </div>
            </div>
        </section>
    </main>

    <!-- Footer -->
    <footer class="relative z-10 py-12 bg-slate-950 border-t border-slate-900 text-slate-500 text-xs">
        <div class="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
            <p>&copy; 2026 Orbit Security Operations. All rights reserved.</p>
            <div class="flex flex-wrap items-center gap-6">
                <a href="../about.html" class="text-emerald-400 hover:underline">About Us</a>
                <a href="../terms.html" class="text-slate-400 hover:text-white transition-colors">Terms of Service</a>
                <a href="../privacy.html" class="text-slate-400 hover:text-white transition-colors">Privacy Policy</a>
                <a href="../disclaimer.html" class="text-slate-400 hover:text-white transition-colors">RFC Disclaimer</a>
            </div>
        </div>
    </footer>

</body>
</html>
"""


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def strip_markers(value: Any) -> Any:
    """Remove ``<!--bind:...-->`` markers from every string in a JSON tree."""
    if isinstance(value, str):
        return BIND_RE.sub("", value)
    if isinstance(value, list):
        return [strip_markers(v) for v in value]
    if isinstance(value, dict):
        return {k: strip_markers(v) for k, v in value.items()}
    return value


def extract_jsonld(md: str) -> Tuple[str, Dict[str, Any]]:
    """Pull the first fenced ```json block out of the markdown."""
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        if FENCE_RE.match(lines[i].strip()) and lines[i].strip().startswith("```json"):
            i += 1
            buf = []
            while i < len(lines) and not FENCE_RE.match(lines[i].strip()):
                buf.append(lines[i])
                i += 1
            raw = "\n".join(buf).strip()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise BuildError(f"the JSON-LD block is not valid JSON: {exc}") from exc
            return raw, strip_markers(parsed)
        i += 1
    raise BuildError("BENCHMARK.md has no ```json block - the JSON-LD is missing")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_benchmark_page.py",
        description="Render docs/benchmark/index.html + the landing/ mirror from the markdown and the measurement JSON.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the prose against the data and report drift without writing files.",
    )
    parser.add_argument(
        "--md",
        type=Path,
        default=MD_PATH,
        help="Path to the source markdown (default: docs/benchmark/BENCHMARK.md).",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=JSON_PATH,
        help="Path to the measurement JSON (default: docs/benchmark/benchmark_results.json).",
    )
    args = parser.parse_args(argv)

    md_path = args.md if args.md.is_absolute() else REPO_ROOT / args.md
    results_path = args.results if args.results.is_absolute() else REPO_ROOT / args.results

    if not md_path.is_file():
        print(f"ERROR: missing {md_path}", file=sys.stderr)
        return 2
    if not results_path.is_file():
        print(f"ERROR: missing {results_path}", file=sys.stderr)
        return 2

    md = md_path.read_text(encoding="utf-8")
    results = json.loads(results_path.read_text(encoding="utf-8"))
    facts = build_facts(results)

    problems: List[str] = []
    problems.extend(verify_bindings(md, facts))

    try:
        ld_raw, ld = extract_jsonld(md)
    except BuildError as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        return 1
    problems.extend(verify_jsonld(ld, facts, md))

    if problems:
        print("BUILD FAILED - BENCHMARK.md and benchmark_results.json disagree:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    # The published JSON-LD must not contain the build-time bind markers.
    ld_clean = json.dumps(ld, indent=2, ensure_ascii=False)
    if BIND_RE.search(ld_clean):
        print("BUILD FAILED: a bind marker survived into the JSON-LD", file=sys.stderr)
        return 1
    if "<!--" in ld_clean:
        print("BUILD FAILED: an HTML comment survived into the JSON-LD", file=sys.stderr)
        return 1

    if args.check:
        print(f"OK - {len(BIND_RE.findall(md))} bound value(s) match benchmark_results.json.")
        print("OK - JSON-LD Dataset + FAQPage are consistent with the page body.")
        return 0

    page = build_page(md, results, facts, ld_clean)

    # The rendered page must carry valid, marker-free JSON-LD.
    for block in re.findall(
        r'<script type="application/ld\+json">(.*?)</script>', page, re.DOTALL
    ):
        try:
            json.loads(block)
        except json.JSONDecodeError as exc:
            print(f"BUILD FAILED: the rendered JSON-LD is not valid JSON: {exc}", file=sys.stderr)
            return 1
        if "bind:" in block or "<!--" in block:
            print("BUILD FAILED: a build marker leaked into the rendered JSON-LD", file=sys.stderr)
            return 1

    HTML_DOCS.parent.mkdir(parents=True, exist_ok=True)
    HTML_LANDING.parent.mkdir(parents=True, exist_ok=True)

    HTML_DOCS.write_text(page, encoding="utf-8", newline="\n")
    shutil.copyfile(HTML_DOCS, HTML_LANDING)
    shutil.copyfile(md_path, MD_LANDING)
    shutil.copyfile(results_path, JSON_LANDING)

    docs_hash = sha256(HTML_DOCS)
    landing_hash = sha256(HTML_LANDING)
    if docs_hash != landing_hash:
        print("BUILD FAILED: docs/ and landing/ copies differ", file=sys.stderr)
        return 1

    print(f"wrote {HTML_DOCS.relative_to(REPO_ROOT)}  ({HTML_DOCS.stat().st_size:,} bytes)")
    print(f"wrote {HTML_LANDING.relative_to(REPO_ROOT)} (byte-identical mirror)")
    print(f"wrote {MD_LANDING.relative_to(REPO_ROOT)} (byte-identical mirror)")
    print(f"wrote {JSON_LANDING.relative_to(REPO_ROOT)} (byte-identical mirror)")
    print(f"md5 docs   : {md5(HTML_DOCS)}")
    print(f"md5 landing: {md5(HTML_LANDING)}")
    print(f"bound values verified against benchmark_results.json: {len(BIND_RE.findall(md))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
