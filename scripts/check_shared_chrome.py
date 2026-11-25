#!/usr/bin/env python3
"""Verify shared header/footer chrome, script load order, and asset ?v= parity across Orbit Security pages."""

from __future__ import annotations

import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent

SHARED_PAGES = [
    "index.html",
    "labs.html",
    "audit.html",
    "fleet.html",
    "signup.html",
    "about.html",
    "benchmark/index.html",
    "portals/index.html",
]

TRACKED_ASSETS = (
    "styles.min.css",
    "simple_cat_data.js",
    "simple_cat.js",
    "orbit_radar.js",
    "orbit_labs.js",
    "landing_ui.js",
)


def check_tree(tree_name: str) -> list[str]:
    tree_dir = REPO_ROOT / tree_name
    errors: list[str] = []
    asset_versions: dict[str, dict[str, set[str]]] = {a: {} for a in TRACKED_ASSETS}

    for rel in SHARED_PAGES:
        page_path = tree_dir / rel
        if not page_path.is_file():
            errors.append(f"[{tree_name}] Missing shared page: {rel}")
            continue
        html = page_path.read_text(encoding="utf-8")

        # 1. Sticky header invariants
        for token in ('id="header-tour-btn"', 'id="mobile-header-tour-btn"', 'id="audio-toggle-btn"', "lg:flex"):
            if token not in html:
                errors.append(f"[{tree_name}/{rel}] Missing header chrome token: {token}")

        # 2. Script load ordering invariants
        if "simple_cat.js" in html:
            if "simple_cat_data.js" not in html:
                errors.append(f"[{tree_name}/{rel}] Loads simple_cat.js without simple_cat_data.js")
            elif html.index("simple_cat_data.js") > html.index("simple_cat.js"):
                errors.append(f"[{tree_name}/{rel}] simple_cat_data.js must load before simple_cat.js")

        if rel == "labs.html":
            if "orbit_labs.js" not in html:
                errors.append(f"[{tree_name}/{rel}] Missing orbit_labs.js")
            elif html.index("orbit_radar.js") > html.index("orbit_labs.js"):
                errors.append(f"[{tree_name}/{rel}] orbit_radar.js must load before orbit_labs.js")

        if rel == "index.html":
            if "landing_ui.js" not in html:
                errors.append(f"[{tree_name}/{rel}] Missing landing_ui.js")
            elif html.index("orbit_radar.js") > html.index("landing_ui.js"):
                errors.append(f"[{tree_name}/{rel}] orbit_radar.js must load before landing_ui.js")

        # 3. Collect ?v= asset versions
        for asset in TRACKED_ASSETS:
            for ver in re.findall(rf"{re.escape(asset)}\?v=([A-Za-z0-9_.-]+)", html):
                asset_versions[asset].setdefault(ver, set()).add(rel)

        # 4. Legal footer link coverage (for pages with a <footer>)
        prefix = "../" if "/" in rel else ""
        if "<footer" in html:
            expected_legal = (
                ("disclaimer.html",)
                if rel == "portals/index.html"
                else ("privacy.html", "terms.html", "disclaimer.html")
            )
            if rel in ("index.html", "labs.html", "about.html"):
                expected_legal = (*expected_legal, "refunds.html")
            for legal in expected_legal:
                if f"{prefix}{legal}" not in html and legal not in html:
                    errors.append(f"[{tree_name}/{rel}] Missing legal link: {legal}")

    # Verify per-asset ?v= consistency across all shared pages in this tree
    for asset, ver_map in asset_versions.items():
        if len(ver_map) > 1:
            detail = ", ".join(f"{v} ({len(pages)} pages)" for v, pages in sorted(ver_map.items()))
            errors.append(f"[{tree_name}] Inconsistent ?v= for {asset}: {detail}")

    return errors


def main() -> int:
    all_errors: list[str] = []
    for tree in ("landing", "docs"):
        all_errors.extend(check_tree(tree))

    if all_errors:
        print(f"[FAIL] Shared chrome drift detected ({len(all_errors)} issue(s)):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("[✓] Shared header/footer chrome, script load order, and asset ?v= parity verified across all 8 pages in landing/ and docs/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
