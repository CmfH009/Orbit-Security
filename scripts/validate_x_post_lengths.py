#!/usr/bin/env python3
"""Orbit Security - X post length validator for the "roast F grades" campaign.

READ-ONLY over ``data/roast_f_grades_posts.json`` (never writes to it).

Rules enforced
--------------
1. Every publishable post in ``posts`` must fit inside X's 280 weighted characters.
   Weighted length follows the X / t.co model: every ``http://`` or ``https://`` URL
   counts as exactly 23 characters, every other unicode code point counts as 1.
2. Every entry in ``held_variants`` must carry an explicit "do not publish" guard
   (guard marker in its notes/text, or an explicit structural hold flag).
   Held variants are printed as DO-NOT-PUBLISH and are never publishable.
3. Extra safety net (mirrors manifest ``publish_policy.never``): no third-party
   client domain may appear in publishable copy.

Exit codes
----------
0 = PASS, 1 = FAIL (validation error), 2 = usage / IO error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "data" / "roast_f_grades_posts.json"

# X hard limit for a single post.
X_LIMIT = 280

# X counts every shortened (t.co) link as this many characters.
URL_WEIGHT = 23

# A URL per the X counting model: scheme http:// or https:// followed by non-space.
URL_RE = re.compile(r"https?://[^\s]+")

# Bare-domain tokens (e.g. "github.com/org/repo") that X would also shorten to 23
# characters in production. The specified weighting rule only covers http(s):// URLs,
# so these are reported as an ADVISORY (informational, never a failure).
BARE_DOMAIN_RE = re.compile(r"(?<![\w@/])(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s]*)?", re.IGNORECASE)

# Markers that prove a variant was explicitly flagged as held / do-not-publish.
HOLD_GUARD_MARKERS: Tuple[str, ...] = (
    "do not publish",
    "do-not-publish",
    "do not post",
    "do-not-post",
    "don't publish",
    "dont publish",
    "never publish",
    "never post",
    "held",
    "on hold",
)

# Third-party client domains that must never appear in published copy.
THIRD_PARTY_DOMAINS: Tuple[str, ...] = (
    "aljazeera.com",
    "grammy.com",
    "uchicago.edu",
    "kff.org",
    "humanmade.com",
    "lullabot.com",
    "rtcamp.com",
    "palantir.net",
    "alley.com",
    "tighten.com",
    "fourkitchens.com",
    "fixel.com",
    "dekode.no",
    "webdevstudios.com",
)


# --------------------------------------------------------------------------- #
# Length helpers
# --------------------------------------------------------------------------- #
def raw_length(text: str) -> int:
    """Raw character count. Python ``len`` counts unicode code points, which is
    the unit X uses (an emoji such as U+1F9F5 counts as 1, not 4)."""
    return len(text)


def weighted_length(text: str) -> int:
    """X 'weighted' length: every http(s):// URL counts as 23 chars, every other
    unicode code point counts as 1."""
    total = 0
    cursor = 0
    for match in URL_RE.finditer(text):
        total += len(text[cursor:match.start()])
        total += URL_WEIGHT
        cursor = match.end()
    total += len(text[cursor:])
    return total


def find_bare_domains(text: str) -> List[str]:
    """Return bare-domain tokens (no http(s):// scheme) present in the text.

    Advisory only - X shortens these to 23 characters in production, so the
    operator can see how much real-world headroom exists beyond the strict rule.
    """
    hits: List[str] = []
    for match in BARE_DOMAIN_RE.finditer(text):
        token = match.group(0)
        # Skip anything already covered by the http(s):// rule.
        start = match.start()
        prefix = text[max(0, start - 8):start].lower()
        if "http://" in prefix or "https://" in prefix:
            continue
        if token.lower() in {d.lower() for d in THIRD_PARTY_DOMAINS}:
            continue
        hits.append(token)
    return hits


def third_party_hits(text: str) -> List[str]:
    """Third-party client domains found in a piece of copy."""
    lowered = text.lower()
    return [d for d in THIRD_PARTY_DOMAINS if d in lowered]


def hold_guard_present(variant: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Detect an explicit 'do not publish' guard on a held variant.

    Structural flags (``publish: false``, ``hold: true``, ``status: HELD``) count
    as a guard, as do guard markers inside the notes or text fields.
    """
    found: List[str] = []

    if variant.get("publish") is False:
        found.append("publish=false")
    if variant.get("hold") is True:
        found.append("hold=true")
    status = str(variant.get("status", "")).strip().upper()
    if status in {"HELD", "DO_NOT_PUBLISH", "DO-NOT-PUBLISH", "BLOCKED"}:
        found.append(f"status={status}")

    haystack = " ".join(
        str(variant.get(key, "")) for key in ("notes", "text", "reason", "comment")
    ).lower()
    for marker in HOLD_GUARD_MARKERS:
        if marker in haystack:
            found.append(f"marker:'{marker}'")
            break

    return (bool(found), found)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def load_manifest(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Manifest root must be a JSON object: {path}")
    return data


def validate_manifest(manifest: Dict[str, Any], manifest_path: Optional[Path] = None) -> Dict[str, Any]:
    """Run every validation rule and return a machine-readable report."""
    posts = list(manifest.get("posts") or [])
    held = list(manifest.get("held_variants") or [])
    failures: List[Dict[str, Any]] = []

    post_rows: List[Dict[str, Any]] = []
    seen_ids: Dict[str, int] = {}

    for index, post in enumerate(posts):
        pid = str(post.get("id", f"<post#{index}>"))
        text = str(post.get("text", ""))
        raw = raw_length(text)
        weighted = weighted_length(text)
        headroom = X_LIMIT - weighted
        domains = third_party_hits(text)
        bare = find_bare_domains(text)

        row = {
            "id": pid,
            "type": str(post.get("type", "unknown")),
            "position": post.get("position"),
            "raw_chars": raw,
            "weighted_chars": weighted,
            "headroom": headroom,
            "within_limit": weighted <= X_LIMIT,
            "urls_23char": len(URL_RE.findall(text)),
            "bare_domain_advisory": bare,
            "third_party_domains": domains,
            "text": text,
        }
        post_rows.append(row)

        if weighted > X_LIMIT:
            failures.append(
                {
                    "rule": "weighted_length",
                    "id": pid,
                    "message": (
                        f"post '{pid}' is {weighted} weighted chars "
                        f"(raw {raw}) - {weighted - X_LIMIT} over the {X_LIMIT} limit"
                    ),
                    "weighted_chars": weighted,
                    "raw_chars": raw,
                    "limit": X_LIMIT,
                }
            )
        if domains:
            failures.append(
                {
                    "rule": "third_party_domain",
                    "id": pid,
                    "message": (
                        f"post '{pid}' names third-party client domain(s): "
                        f"{', '.join(domains)} - never publish these"
                    ),
                    "domains": domains,
                }
            )
        seen_ids[pid] = seen_ids.get(pid, 0) + 1

    for pid, count in seen_ids.items():
        if count > 1:
            failures.append(
                {
                    "rule": "duplicate_id",
                    "id": pid,
                    "message": f"duplicate post id '{pid}' appears {count} times",
                }
            )

    held_rows: List[Dict[str, Any]] = []
    for index, variant in enumerate(held):
        vid = str(variant.get("id", f"<held#{index}>"))
        guarded, markers = hold_guard_present(variant)
        held_rows.append(
            {
                "id": vid,
                "type": str(variant.get("type", "unknown")),
                "status": "DO-NOT-PUBLISH",
                "guard_present": guarded,
                "guard_markers": markers,
                "raw_chars": raw_length(str(variant.get("text", ""))),
                "weighted_chars": weighted_length(str(variant.get("text", ""))),
                "notes": str(variant.get("notes", "")),
            }
        )
        if not guarded:
            failures.append(
                {
                    "rule": "missing_hold_guard",
                    "id": vid,
                    "message": (
                        f"held variant '{vid}' has NO explicit do-not-publish guard - "
                        "refusing to treat it as held until one is added"
                    ),
                }
            )

    # Held ids must never collide with publishable ids.
    publishable_ids = {row["id"] for row in post_rows}
    for row in held_rows:
        if row["id"] in publishable_ids:
            failures.append(
                {
                    "rule": "held_id_collision",
                    "id": row["id"],
                    "message": (
                        f"id '{row['id']}' appears in both posts and held_variants - "
                        "publishable ids take precedence, held copy must be renamed"
                    ),
                }
            )

    return {
        "ok": not failures,
        "manifest": str(manifest_path) if manifest_path else None,
        "manifest_id": manifest.get("id"),
        "limit": X_LIMIT,
        "url_weight": URL_WEIGHT,
        "post_count": len(post_rows),
        "held_count": len(held_rows),
        "posts": post_rows,
        "held_variants": held_rows,
        "failures": failures,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_table(report: Dict[str, Any]) -> str:
    headers = ("ID", "TYPE", "RAW CHARS", "WEIGHTED CHARS", "HEADROOM", "STATUS")
    rows: List[Tuple[str, ...]] = []
    for row in report["posts"]:
        status = "OK" if row["within_limit"] else "TOO LONG"
        rows.append(
            (
                row["id"],
                row["type"],
                str(row["raw_chars"]),
                str(row["weighted_chars"]),
                str(row["headroom"]),
                status,
            )
        )
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(cells: Sequence[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    out = [fmt(headers), "  ".join("-" * w for w in widths)]
    for row in rows:
        out.append(fmt(row))
    return "\n".join(out)


def render_report(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("=" * 78)
    lines.append("ORBIT SECURITY - X POST LENGTH VALIDATOR")
    if report.get("manifest"):
        lines.append(f"Manifest: {report['manifest']}")
    lines.append(f"Manifest ID: {report.get('manifest_id')}")
    lines.append(f"X limit: {report['limit']} weighted chars (URLs = {report['url_weight']})")
    lines.append("=" * 78)
    lines.append("")
    lines.append(render_table(report))
    lines.append("")

    advisory_lines: List[str] = []
    for row in report["posts"]:
        for token in row["bare_domain_advisory"]:
            advisory_lines.append(
                f"  - '{row['id']}': bare domain '{token}' counted literally "
                f"({len(token)} chars); X would shorten it to {report['url_weight']}"
            )
    if advisory_lines:
        lines.append("ADVISORY (informational, not a failure):")
        lines.extend(advisory_lines)
        lines.append("")

    lines.append("HELD VARIANTS - DO NOT PUBLISH:")
    if not report["held_variants"]:
        lines.append("  (none)")
    for row in report["held_variants"]:
        guard = "; ".join(row["guard_markers"]) if row["guard_markers"] else "NO GUARD FOUND"
        lines.append(f"  [DO-NOT-PUBLISH] {row['id']} ({row['type']}) - guard: {guard}")
        lines.append(f"      notes: {row['notes']}")
    lines.append("")

    if report["ok"]:
        lines.append("RESULT: PASS - all publishable posts are within the X limit and every")
        lines.append("        held variant carries an explicit do-not-publish guard.")
    else:
        lines.append(f"RESULT: FAIL - {len(report['failures'])} violation(s):")
        for failure in report["failures"]:
            lines.append(f"  [FAIL] {failure['rule']}: {failure['message']}")
    lines.append("=" * 78)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate X post lengths for the roast F grades campaign (read-only)."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help=f"Path to the post manifest (default: {DEFAULT_MANIFEST})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human table.",
    )
    args = parser.parse_args(argv)

    manifest_path = args.manifest
    if not manifest_path.exists():
        print(f"[FAIL] Manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] Could not read manifest {manifest_path}: {exc}", file=sys.stderr)
        return 2

    report = validate_manifest(manifest, manifest_path)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_report(report))

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
