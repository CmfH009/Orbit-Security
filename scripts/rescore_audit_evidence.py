#!/usr/bin/env python3
"""Offline before/after re-score of the on-disk audit evidence.

Re-scores every ``data/generated_audits/*/*_audit.md`` deliverable with the
legacy flat-penalty model and with the current exploitability-aware model
(``orbit_security.scoring``) and prints a comparison table.

The audit files themselves are READ-ONLY evidence - this script never writes
to them.

Usage:
    .venv\\Scripts\\python.exe scripts\\rescore_audit_evidence.py
    .venv\\Scripts\\python.exe scripts\\rescore_audit_evidence.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.scoring import (  # noqa: E402
    ScoreItem,
    Severity,
    grade_from_score,
    score_findings,
)

AUDIT_ROOT = REPO_ROOT / "data" / "generated_audits"

# `### 3. Missing SMTP TLS Reporting (TLS-RPT RFC 8460) (⚪ **INFO**)`
FINDING_RE = re.compile(
    r"^###\s+\d+\.\s+(?P<title>.+?)\s*\([^()]*\*\*(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO)\*\*\)\s*$"
)

# `**Executive Grade:** **F** (Score: 40/100)`
GRADE_RE = re.compile(
    r"\*\*Executive Grade:\*\*\s*\*\*(?P<grade>[A-F]\+?)\*\*\s*"
    r"\(Score:\s*(?P<score>\d+)/100\)"
)

#: The legacy flat model that produced the false "F" grades.
LEGACY_PENALTY: Dict[str, int] = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}


class ParsedFinding(NamedTuple):
    title: str
    severity: str


class ParsedAudit(NamedTuple):
    path: Path
    findings: List[ParsedFinding]
    header_grade: Optional[str]
    header_score: Optional[int]


def legacy_grade_and_score(severities: List[str]) -> tuple:
    """The pre-2026-10-22 model: flat penalty per finding, no floor, no cap."""
    penalty = sum(LEGACY_PENALTY.get(sev, 0) for sev in severities)
    score = max(0, 100 - penalty)
    return grade_from_score(score), score


def parse_audit(path: Path) -> ParsedAudit:
    text = path.read_text(encoding="utf-8")
    findings: List[ParsedFinding] = []
    header_grade: Optional[str] = None
    header_score: Optional[int] = None

    for line in text.splitlines():
        grade_match = GRADE_RE.search(line)
        if grade_match:
            header_grade = grade_match.group("grade")
            header_score = int(grade_match.group("score"))
            continue
        finding_match = FINDING_RE.match(line.strip())
        if finding_match:
            findings.append(
                ParsedFinding(
                    title=finding_match.group("title").strip(),
                    severity=finding_match.group("severity"),
                )
            )

    return ParsedAudit(path, findings, header_grade, header_score)


def rescore(audit: ParsedAudit) -> Dict[str, object]:
    severities = [f.severity for f in audit.findings]
    old_grade, old_score = legacy_grade_and_score(severities)

    items = [
        ScoreItem(
            title=f.title,
            severity=Severity(f.severity),
            category="",
        )
        for f in audit.findings
    ]
    new = score_findings(items)

    rel = audit.path.relative_to(AUDIT_ROOT.parent.parent)
    return {
        "file": str(rel).replace("\\", "/"),
        "findings": len(audit.findings),
        "header_grade": audit.header_grade,
        "header_score": audit.header_score,
        "old_score": old_score,
        "old_grade": old_grade,
        "new_score": new.score,
        "new_grade": new.grade,
        "delta": new.score - old_score,
        "floor_applied": new.floor_applied,
    }


def print_table(rows: List[Dict[str, object]]) -> None:
    headers = ("file", "find", "old", "new", "delta")
    name_w = max([len("file")] + [len(str(r["file"])) for r in rows])
    print(
        f"{headers[0]:<{name_w}}  {headers[1]:>4}  {headers[2]:>10}  "
        f"{headers[3]:>10}  {headers[4]:>6}"
    )
    print("-" * (name_w + 4 + 4 + 12 + 12 + 8))
    for r in rows:
        old = f"{r['old_score']}/100 {r['old_grade']}"
        new = f"{r['new_score']}/100 {r['new_grade']}"
        delta = f"{r['delta']:+d}"
        print(
            f"{str(r['file']):<{name_w}}  {r['findings']:>4}  {old:>10}  "
            f"{new:>10}  {delta:>6}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-score the on-disk audit evidence with the old and new models."
    )
    parser.add_argument(
        "--audits-dir",
        default=str(AUDIT_ROOT),
        help="Directory containing the generated audit markdown (read-only).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    args = parser.parse_args()

    audits_dir = Path(args.audits_dir)
    files = sorted(audits_dir.glob("*/*_audit.md"))
    if not files:
        print(f"No audit files found under {audits_dir}", file=sys.stderr)
        return 1

    rows: List[Dict[str, object]] = []
    mismatches: List[str] = []
    for path in files:
        parsed = parse_audit(path)
        row = rescore(parsed)
        rows.append(row)
        # Sanity check: the legacy model must reproduce the score printed in
        # the deliverable, otherwise the parser is not faithful.
        if parsed.header_score is not None and parsed.header_score != row["old_score"]:
            mismatches.append(
                f"{row['file']}: header {parsed.header_score} != recomputed {row['old_score']}"
            )

    if args.json:
        print(json.dumps({"rows": rows, "parser_mismatches": mismatches}, indent=2))
        return 0

    print(f"Re-scored {len(rows)} audit deliverable(s) from {audits_dir}")
    print(f"Legacy model: flat penalty per finding (CRITICAL 35 / HIGH 20 / MEDIUM 10 / LOW 5).")
    print(f"New model:    exploitability-aware (hygiene=0, class caps, C floor / D ceiling).")
    print()
    print_table(rows)
    print()

    old_fail = [r for r in rows if r["old_grade"] in ("D", "F")]
    new_fail = [r for r in rows if r["new_grade"] in ("D", "F")]
    rescued = [r for r in rows if r["old_grade"] in ("D", "F") and r["new_grade"] not in ("D", "F")]
    worsened = [r for r in rows if r["old_grade"] not in ("D", "F") and r["new_grade"] in ("D", "F")]
    deltas = [int(r["delta"]) for r in rows]

    print("SUMMARY")
    print(f"  audits re-scored ............ {len(rows)}")
    print(f"  failing before (D/F) ........ {len(old_fail)}")
    print(f"  failing after  (D/F) ........ {len(new_fail)}")
    print(f"  rescued from D/F ............ {len(rescued)}")
    print(f"  newly failing ............... {len(worsened)}")
    print(f"  average score delta ......... {sum(deltas) / len(deltas):+.1f}")
    print(f"  best delta .................. {max(deltas):+d}")
    print(f"  worst delta ................. {min(deltas):+d}")
    if mismatches:
        print()
        print("PARSER SANITY CHECK FAILURES (legacy score did not match the header):")
        for m in mismatches:
            print(f"  - {m}")
    else:
        print()
        print("Parser sanity check: legacy model reproduces every published header score.")

    if rescued:
        print()
        print("RESCUED FROM A FAILING GRADE:")
        for r in rescued:
            print(
                f"  - {r['file']}: {r['old_score']}/{r['old_grade']} -> "
                f"{r['new_score']}/{r['new_grade']} ({r['delta']:+d})"
            )
    if worsened:
        print()
        print("NEWLY FAILING:")
        for r in worsened:
            print(
                f"  - {r['file']}: {r['old_score']}/{r['old_grade']} -> "
                f"{r['new_score']}/{r['new_grade']} ({r['delta']:+d})"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
