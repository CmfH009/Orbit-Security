#!/usr/bin/env python3
"""Parity guard between the `landing/` source tree and the `docs/` deployed tree.

`landing/` is the source of truth for the marketing site; `docs/` is the copy
that GitHub Pages serves.  Any file that exists in BOTH trees must be
byte-identical, otherwise the deployed site silently drifts from source.

Usage
-----
    python scripts/sync_landing_to_docs.py            # report only (safe default)
    python scripts/sync_landing_to_docs.py --check    # report, exit 1 on drift (CI)
    python scripts/sync_landing_to_docs.py --apply    # copy landing/ -> docs/ for drifted files
    python scripts/sync_landing_to_docs.py --help     # full option list

Rules (deliberately conservative)
---------------------------------
* Only files present in BOTH trees are compared.  A file that exists in only
  one tree is reported as informational and is NEVER copied over or deleted.
* `docs/.nojekyll` (and any other dot-file marker) is never written.
* `--apply` only ever overwrites a `docs/` file that already exists in
  `landing/`; it never creates brand new files in `docs/` and never deletes.
* Nothing is written unless `--apply` is passed explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LANDING = REPO_ROOT / "landing"
DEFAULT_DOCS = REPO_ROOT / "docs"

# Extensions considered "shared site assets" for parity purposes:
# html, css, js, pdf, images, fonts, media and the small text/xml artifacts
# that the deployed site also carries (robots.txt, sitemap.xml, security.txt).
SHARED_EXTENSIONS = frozenset(
    {
        # markup / code
        ".html",
        ".htm",
        ".css",
        ".js",
        ".mjs",
        ".cjs",
        ".json",
        ".xml",
        ".txt",
        ".webmanifest",
        # documents
        ".pdf",
        # images
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".avif",
        ".ico",
        ".bmp",
        ".tif",
        ".tiff",
        # fonts
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
        # media
        ".mp4",
        ".webm",
        ".mov",
    }
)

# Files that must never be written by --apply, even if they show up in both
# trees.  `.nojekyll` is a GitHub Pages marker, not a content file.
PROTECTED_DOCS_PATHS = frozenset({".nojekyll"})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def sha256(path: Path) -> str:
    """Return the hex sha256 digest of a file (streamed, memory safe)."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_shared(rel_path: str) -> bool:
    """True when the relative path is a parity-relevant shared asset."""
    if rel_path in PROTECTED_DOCS_PATHS:
        return False
    # Dot-files such as the `.nojekyll` marker are never synced. Only the FILE
    # name is checked, so `.well-known/security.txt` stays a normal shared
    # asset and is compared like any other.
    if Path(rel_path).name.startswith("."):
        return False
    return Path(rel_path).suffix.lower() in SHARED_EXTENSIONS


def collect(tree: Path) -> dict[str, Path]:
    """Map relative posix paths -> absolute paths for parity-relevant files."""
    found: dict[str, Path] = {}
    if not tree.is_dir():
        return found
    for path in tree.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(tree).as_posix()
        if is_shared(rel):
            found[rel] = path
    return found


def human_size(n: int) -> str:
    return f"{n:,} B"


def rule(char: str = "-", width: int = 78) -> str:
    return char * width


def print_table(rows: list[tuple[str, str]], title: str) -> None:
    """Print a simple two-column summary table."""
    left = max((len(r[0]) for r in rows), default=0)
    print(rule("="))
    print(title)
    print(rule("="))
    print(f"{'Metric'.ljust(left)}  Count")
    print(rule())
    for label, value in rows:
        print(f"{label.ljust(left)}  {value}")
    print(rule("="))


# --------------------------------------------------------------------------- #
# Core logic
# --------------------------------------------------------------------------- #
def compare(landing: Path, docs: Path) -> dict:
    """Compare the two trees and return a structured report."""
    landing_files = collect(landing)
    docs_files = collect(docs)

    shared = sorted(set(landing_files) & set(docs_files))
    landing_only = sorted(set(landing_files) - set(docs_files))
    docs_only = sorted(set(docs_files) - set(landing_files))

    identical: list[str] = []
    mismatched: list[dict] = []
    for rel in shared:
        src = landing_files[rel]
        dst = docs_files[rel]
        src_hash = sha256(src)
        dst_hash = sha256(dst)
        if src_hash == dst_hash:
            identical.append(rel)
        else:
            mismatched.append(
                {
                    "path": rel,
                    "landing_bytes": src.stat().st_size,
                    "docs_bytes": dst.stat().st_size,
                    "landing_sha": src_hash,
                    "docs_sha": dst_hash,
                }
            )

    return {
        "landing_files": landing_files,
        "docs_files": docs_files,
        "shared": shared,
        "identical": identical,
        "mismatched": mismatched,
        "landing_only": landing_only,
        "docs_only": docs_only,
    }


def apply_sync(report: dict, landing: Path, docs: Path) -> list[str]:
    """Copy drifted files from landing/ -> docs/. Returns list of copied rel paths."""
    copied: list[str] = []
    for entry in report["mismatched"]:
        rel = entry["path"]
        if rel in PROTECTED_DOCS_PATHS:
            print(f"  SKIP (protected) {rel}")
            continue
        src = landing / rel
        dst = docs / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel)
        print(
            f"  COPIED  {rel}  "
            f"({human_size(entry['docs_bytes'])} -> {human_size(entry['landing_bytes'])}, "
            f"sha {entry['docs_sha'][:8]} -> {entry['landing_sha'][:8]})"
        )
    return copied


def render_report(report: dict, landing: Path, docs: Path) -> None:
    """Print the human-readable parity report."""
    print()
    print(rule("="))
    print("Orbit Security - landing/docs parity check")
    print(f"  source (truth): {landing}")
    print(f"  deployed copy : {docs}")
    print(rule("="))
    print()

    if report["mismatched"]:
        print("DRIFT - the following shared files differ:")
        print()
        path_w = max(len(m["path"]) for m in report["mismatched"])
        path_w = min(max(path_w, len("Path")), 52)
        print(f"{'Path'.ljust(path_w)}  {'landing':>12}  {'docs':>12}  sha(land)/sha(docs)")
        print(rule())
        for m in report["mismatched"]:
            print(
                f"{m['path'].ljust(path_w)}  "
                f"{human_size(m['landing_bytes']):>12}  "
                f"{human_size(m['docs_bytes']):>12}  "
                f"{m['landing_sha'][:8]}/{m['docs_sha'][:8]}"
            )
        print()
    else:
        print("OK - every shared file in landing/ and docs/ is byte-identical.")
        print()

    if report["landing_only"]:
        print("Only in landing/ (informational - never copied, never deleted):")
        for rel in report["landing_only"]:
            print(f"  + {rel}")
        print()

    if report["docs_only"]:
        print("Only in docs/ (informational - never copied, never deleted):")
        for rel in report["docs_only"]:
            print(f"  - {rel}")
        print()

    print_table(
        [
            ("Shared files compared", str(len(report["shared"]))),
            ("  identical", str(len(report["identical"]))),
            ("  mismatched (drift)", str(len(report["mismatched"]))),
            ("Only in landing/ (skipped)", str(len(report["landing_only"]))),
            ("Only in docs/ (skipped)", str(len(report["docs_only"]))),
        ],
        "Summary",
    )
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sync_landing_to_docs.py",
        description=(
            "Compare the landing/ source tree against the docs/ deployed tree "
            "and (optionally) re-sync drifted shared files."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="report only and exit non-zero when any shared file has drifted (CI mode)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="copy drifted shared files from landing/ to docs/ (source of truth)",
    )
    parser.add_argument(
        "--landing",
        type=Path,
        default=DEFAULT_LANDING,
        help=f"source tree (default: {DEFAULT_LANDING})",
    )
    parser.add_argument(
        "--docs",
        type=Path,
        default=DEFAULT_DOCS,
        help=f"deployed tree (default: {DEFAULT_DOCS})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only print the summary table",
    )
    args = parser.parse_args(argv)

    landing = args.landing.resolve()
    docs = args.docs.resolve()

    if not landing.is_dir():
        print(f"ERROR: landing tree not found: {landing}", file=sys.stderr)
        return 2
    if not docs.is_dir():
        print(f"ERROR: docs tree not found: {docs}", file=sys.stderr)
        return 2

    report = compare(landing, docs)

    if args.apply:
        if report["mismatched"]:
            print(f"Applying {len(report['mismatched'])} drifted file(s) from {landing} -> {docs}")
        else:
            print("Nothing to apply - trees are already in sync.")
        copied = apply_sync(report, landing, docs)
        # Re-verify after applying.
        report = compare(landing, docs)
        if not args.quiet:
            render_report(report, landing, docs)
        else:
            print_table(
                [
                    ("Files copied", str(len(copied))),
                    ("Shared files compared", str(len(report["shared"]))),
                    ("  mismatched (drift)", str(len(report["mismatched"]))),
                ],
                "Summary",
            )
        if report["mismatched"]:
            print(f"ERROR: {len(report['mismatched'])} file(s) still drifted after --apply.", file=sys.stderr)
            return 1
        return 0

    if not args.quiet:
        render_report(report, landing, docs)
    else:
        print_table(
            [
                ("Shared files compared", str(len(report["shared"]))),
                ("  identical", str(len(report["identical"]))),
                ("  mismatched (drift)", str(len(report["mismatched"]))),
            ],
            "Summary",
        )

    if args.check and report["mismatched"]:
        sys.stdout.flush()
        print(
            f"FAIL: {len(report['mismatched'])} shared file(s) drifted between "
            f"{landing.name}/ and {docs.name}/.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
