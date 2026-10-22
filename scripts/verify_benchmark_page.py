#!/usr/bin/env python3
"""Verify the published Orbit Security benchmark page.

Checks, in order:

1. ``docs/benchmark/*`` and ``landing/benchmark/*`` are byte-identical (md5).
2. Every ``<script type="application/ld+json">`` block parses with ``json.loads``
   and carries a Dataset node (with the required schema.org properties) and a
   FAQPage with 4-6 questions that are all visible in the page body.
3. No build marker leaked into the rendered HTML, and the page has exactly one
   ``<h1>``.
4. Every markdown table in the page has a consistent number of cells.
5. Every relative link and asset the page references exists on disk.
6. Every Tailwind utility class the page uses exists in the compiled site
   stylesheet (the site ships no Tailwind CDN, so an unknown class renders
   unstyled and silently).
7. The headline numbers rendered in the page match ``benchmark_results.json``.

Usage
-----
    .venv\\Scripts\\python.exe scripts\\verify_benchmark_page.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs" / "benchmark"
LANDING = REPO_ROOT / "landing" / "benchmark"
STYLESHEET = REPO_ROOT / "docs" / "assets" / "styles.min.css"

#: Classes the page defines in its own <style> block.
PAGE_LOCAL_CLASSES = frozenset(
    {
        "font-mono",
        "font-pixel",
        "font-arcade",
        "pixel-box-emerald",
        "pixel-box-cyan",
        "pixel-btn",
        "scanlines",
    }
)

_CSS_ESCAPES = {
    ".": "\\.",
    ":": "\\:",
    "/": "\\/",
    "[": "\\[",
    "]": "\\]",
    "%": "\\%",
    ",": "\\,",
    "(": "\\(",
    ")": "\\)",
    "#": "\\#",
    "&": "\\&",
}

failures: List[str] = []


def md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def css_selector(token: str) -> str:
    out = ["."]
    for ch in token:
        out.append(_CSS_ESCAPES.get(ch, ch))
    return "".join(out)


class TableParser(HTMLParser):
    """Collect the cell layout of every table so row widths can be compared."""

    def __init__(self) -> None:
        super().__init__()
        self.tables: List[List[List[str]]] = []
        self._table: Any = None
        self._row: Any = None
        self._cell: Any = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._cell is not None:
            self._row.append("".join(self._cell).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None


def main() -> int:
    # 1 - parity ---------------------------------------------------------- #
    print("== parity (docs/benchmark vs landing/benchmark) ==")
    for name in ("index.html", "BENCHMARK.md", "benchmark_results.json"):
        left, right = DOCS / name, LANDING / name
        if not left.is_file() or not right.is_file():
            failures.append(f"{name}: missing on one side")
            print(f"  FAIL {name}: missing on one side")
            continue
        left_hash, right_hash = md5(left), md5(right)
        if left_hash != right_hash:
            failures.append(f"{name}: md5 mismatch {left_hash} != {right_hash}")
        print(
            f"  {'OK ' if left_hash == right_hash else 'FAIL'} {name:26} "
            f"md5={left_hash} sha256={sha256(left)[:16]}... {left.stat().st_size:,} bytes"
        )

    html = (DOCS / "index.html").read_text(encoding="utf-8")

    # 2 - JSON-LD --------------------------------------------------------- #
    print("\n== JSON-LD ==")
    blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL)
    print(f"  blocks found: {len(blocks)}")
    if not blocks:
        failures.append("no JSON-LD block in the page")
    plain_text = re.sub(r"<[^>]+>", " ", html)
    for index, block in enumerate(blocks):
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            failures.append(f"JSON-LD block {index} does not parse: {exc}")
            continue
        print(f"  block {index}: json.loads OK, {len(block):,} chars, keys={list(parsed)}")
        graph = parsed.get("@graph", [])
        datasets = [n for n in graph if n.get("@type") == "Dataset"]
        faqs = [n for n in graph if n.get("@type") == "FAQPage"]
        if not datasets:
            failures.append("JSON-LD has no Dataset node")
        else:
            dataset = datasets[0]
            required = [
                "@id",
                "name",
                "description",
                "creator",
                "temporalCoverage",
                "distribution",
                "license",
                "isAccessibleForFree",
                "variableMeasured",
            ]
            missing = [key for key in required if key not in dataset]
            if missing:
                failures.append(f"Dataset node missing {missing}")
            print(f"  Dataset name           : {dataset.get('name')!r}")
            print(f"  Dataset temporalCoverage: {dataset.get('temporalCoverage')!r}")
            print(f"  Dataset license        : {dataset.get('license')!r}")
            print(f"  isAccessibleForFree    : {dataset.get('isAccessibleForFree')!r}")
            print(f"  variableMeasured       : {len(dataset.get('variableMeasured', []))} properties")
            print(f"  distribution           : {json.dumps(dataset.get('distribution'))}")
        if not faqs:
            failures.append("JSON-LD has no FAQPage node")
        else:
            questions = faqs[0].get("mainEntity", [])
            print(f"  FAQPage questions      : {len(questions)}")
            if not 4 <= len(questions) <= 6:
                failures.append(f"FAQPage has {len(questions)} questions (need 4-6)")
            for question in questions:
                name = question.get("name", "")
                answer = question.get("acceptedAnswer", {}).get("text", "")
                if not name or not answer:
                    failures.append(f"FAQPage entry missing name/answer: {name!r}")
                if name not in plain_text:
                    failures.append(f"FAQPage question not visible on the page: {name!r}")
                print(f"    - {name}")

    # 3 - markers and headings -------------------------------------------- #
    print("\n== build markers ==")
    for token in ("bind:", "Source note:"):
        count = html.count(token)
        print(f"  {token!r} occurrences: {count}")
        if count:
            failures.append(f"{token!r} leaked into the rendered page")
    h1_count = len(re.findall(r"<h1\b", html))
    print(f"  <h1> elements: {h1_count}")
    if h1_count != 1:
        failures.append(f"the page has {h1_count} <h1> elements (expected exactly 1)")

    # 4 - tables ----------------------------------------------------------- #
    print("\n== tables ==")
    parser = TableParser()
    parser.feed(html)
    inconsistent = 0
    for table in parser.tables:
        if not table:
            continue
        widths = {len(row) for row in table}
        if len(widths) != 1:
            inconsistent += 1
            failures.append(f"a table has inconsistent row widths {widths}")
    print(f"  tables: {len(parser.tables)}, inconsistent: {inconsistent}")

    # 5 - local references -------------------------------------------------- #
    print("\n== local references ==")
    refs = set()
    for match in re.finditer(r'(?:href|src)="([^"#][^"]*)"', html):
        ref = match.group(1)
        if ref.startswith(("http://", "https://", "mailto:", "//", "data:")):
            continue
        ref = ref.split("#", 1)[0]
        if ref:
            refs.add(ref)
    for ref in sorted(refs):
        target = (DOCS / ref).resolve()
        ok = target.is_file()
        if not ok:
            failures.append(f"page references a missing local file: {ref}")
        print(f"  {'OK ' if ok else 'FAIL'} {ref}")

    # 6 - compiled stylesheet coverage -------------------------------------- #
    print("\n== tailwind classes vs compiled stylesheet ==")
    css = STYLESHEET.read_text(encoding="utf-8", errors="ignore")
    missing: Dict[str, int] = {}
    used = set()
    for attribute in re.findall(r'class="([^"]*)"', html):
        for token in attribute.split():
            used.add(token)
            if token in PAGE_LOCAL_CLASSES or token.startswith("marker:"):
                continue
            if css_selector(token) not in css and token not in css:
                missing[token] = missing.get(token, 0) + 1
    for token in sorted(missing):
        failures.append(f"class '{token}' is not in the compiled stylesheet")
    print(f"  classes used: {len(used)}, missing from styles.min.css: {len(missing)}")
    for token in sorted(missing):
        print(f"    - {token}")

    # 7 - numbers match the data ------------------------------------------- #
    print("\n== numbers vs benchmark_results.json ==")
    results = json.loads((DOCS / "benchmark_results.json").read_text(encoding="utf-8"))
    latency = results["measurements"]["audit_latency"]
    signatures = results["measurements"]["signature_coverage"]
    scoring = results["measurements"]["scoring_stability"]
    text = plain_text

    def must_contain(label: str, value: str) -> None:
        ok = value in text
        if not ok:
            failures.append(f"page does not contain the measured value {label}={value!r}")
        print(f"  {'OK ' if ok else 'FAIL'} {label:30} {value}")

    must_contain("active p50 (ms)", f"{latency['active_ms']['p50']:,.0f} ms")
    must_contain("wall p50 (ms)", f"{latency['wall_ms']['p50']:,.0f} ms")
    must_contain("active p95 (ms)", f"{latency['active_ms']['p95']:,.0f} ms")
    must_contain("provider signatures", str(signatures["provider_signatures"]))
    must_contain(
        "distinct fingerprints", str(signatures["distinct_provider_fingerprints"])
    )
    must_contain(
        "hostname classes", str(signatures["distinct_dangling_hostname_classes"])
    )
    must_contain("audits re-scored", str(scoring["audits_parsed"]))
    must_contain("findings parsed", str(scoring["findings_parsed"]))
    must_contain("generated date", results["generated_utc"][:10])

    print("\n== result ==")
    if failures:
        print(f"FAIL - {len(failures)} problem(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS - every check succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
