#!/usr/bin/env python3
"""Orbit Security — Release gate.

One command that answers the only question that matters before a deploy:
"is the public surface true right now?"

Checks, in order:
  1. landing/ -> docs/ parity for shared files (source of truth is landing/)
  2. JSON-LD validity on every public page, with @id cross-page resolution
  3. Required public assets present on disk (og-image, logo, favicon, robots,
     sitemap, security.txt)
  4. Optional live HEAD sweep against the published site

Exit code 0 = release gate passed, 1 = gate failed.

Usage:
    .venv\\Scripts\\python.exe scripts\\verify_release.py
    .venv\\Scripts\\python.exe scripts\\verify_release.py --live
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"
LANDING = REPO_ROOT / "landing"

BASE = "https://cmfh009.github.io/Orbit-Security"

PUBLIC_PAGES = [
    "index.html",
    "about.html",
    "fleet.html",
    "signup.html",
    "ghostdns/index.html",
    "portals/index.html",
]

REQUIRED_ASSETS = [
    "assets/og-image.png",
    "assets/logo.png",
    "favicon.ico",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
]

LIVE_URLS = ["/"] + [f"/{p}" for p in PUBLIC_PAGES] + [
    "/robots.txt",
    "/sitemap.xml",
    "/llms.txt",
    "/assets/og-image.png",
    "/assets/logo.png",
    "/favicon.ico",
    "/.well-known/security.txt",
]

LD_BLOCK = re.compile(r'<script type="application/ld\+json">(.*?)</script>', re.S)
ID_REF = re.compile(r'"@id"\s*:\s*"([^"]+)"')


class Gate:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.notes: list[str] = []

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label}" + (f" - {detail}" if detail else ""))
        if not ok:
            self.failures.append(f"{label}{(' - ' + detail) if detail else ''}")
        return ok

    def note(self, text: str) -> None:
        self.notes.append(text)
        print(f"  [note] {text}")


def _hash(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def check_parity(gate: Gate) -> None:
    print("\n1. landing/ -> docs/ parity")
    shared_ok = True
    compared = 0
    for src in sorted(LANDING.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(LANDING)
        if rel.parts[0] in {"__pycache__"}:
            continue
        dst = DOCS / rel
        if not dst.exists():
            elsewhere = list(DOCS.rglob(src.name))
            if elsewhere:
                gate.note(f"path differs, same file present in docs/: {rel.as_posix()} -> "
                          f"{elsewhere[0].relative_to(DOCS).as_posix()}")
            else:
                gate.note(f"landing-only, not deployed: {rel.as_posix()}")
            continue
        compared += 1
        if _hash(src) != _hash(dst):
            shared_ok = False
            gate.failures.append(f"parity drift: {rel.as_posix()}")
            print(f"  [FAIL] drift: {rel.as_posix()}")
    gate.check(shared_ok, f"shared files identical ({compared} compared)")


def check_structured_data(gate: Gate) -> None:
    print("\n2. Structured data on public pages")
    all_ids: dict[str, str] = {}
    graphs: dict[str, list[dict]] = {}

    for page in PUBLIC_PAGES:
        path = DOCS / page
        if not path.exists():
            gate.check(False, f"{page} exists")
            continue
        html = path.read_text(encoding="utf-8")
        blocks = LD_BLOCK.findall(html)
        if not blocks:
            gate.check(False, f"{page} has JSON-LD")
            continue
        try:
            data = json.loads(blocks[0])
        except Exception as exc:
            gate.check(False, f"{page} JSON-LD parses", str(exc))
            continue
        nodes = data.get("@graph", [data])
        graphs[page] = nodes
        types = [n.get("@type") for n in nodes]
        gate.check(True, f"{page} JSON-LD parses", f"{len(nodes)} nodes: {', '.join(str(t) for t in types)}")
        for node in nodes:
            nid = node.get("@id")
            if nid:
                all_ids.setdefault(nid, page)

    # cross-page @id sharing
    shared = {}
    for page, nodes in graphs.items():
        for node in nodes:
            nid = node.get("@id")
            if nid:
                shared.setdefault(nid, []).append(page)
    multi = {k: v for k, v in shared.items() if len(v) > 1}
    if multi:
        gate.note("shared @id across pages: " + ", ".join(f"{k} -> {len(v)} pages" for k, v in multi.items()))
    gate.check(
        any(k.endswith("#organization") for k in multi),
        "organization @id shared across pages (entity merge)",
    )

    # unresolved intra-graph references
    unresolved = []
    for page, nodes in graphs.items():
        local_ids = {n.get("@id") for n in nodes if n.get("@id")}
        for node in nodes:
            for ref in re.findall(r'"@id"\s*:\s*"(https://cmfh009\.github\.io/Orbit-Security/[^"]+)"', json.dumps(node)):
                if ref not in local_ids and ref not in all_ids:
                    unresolved.append(f"{page}: {ref}")
    gate.check(not unresolved, "all @id references resolve", "; ".join(unresolved[:4]))


def check_assets(gate: Gate) -> None:
    print("\n3. Required public assets on disk")
    for asset in REQUIRED_ASSETS:
        p = DOCS / asset
        exists = p.exists() and p.stat().st_size > 0
        gate.check(exists, f"docs/{asset}", f"{p.stat().st_size} bytes" if exists else "missing")
        mirror = LANDING / asset
        if exists:
            gate.check(mirror.exists() and _hash(mirror) == _hash(p),
                       f"landing/{asset} mirrors docs/{asset}")


def check_live(gate: Gate) -> None:
    print("\n4. Live HEAD sweep")
    for path in LIVE_URLS:
        url = BASE + path
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Orbit-Release-Gate/1.0"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                gate.check(resp.status == 200, f"{path}", f"HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            gate.check(False, f"{path}", f"HTTP {exc.code}")
        except Exception as exc:
            gate.check(False, f"{path}", str(exc))


def main() -> int:
    parser = argparse.ArgumentParser(description="Orbit Security release gate")
    parser.add_argument("--live", action="store_true", help="also HEAD-check the published site")
    args = parser.parse_args()

    print("=" * 70)
    print(" ORBIT SECURITY - RELEASE GATE")
    print("=" * 70)

    gate = Gate()
    check_parity(gate)
    check_structured_data(gate)
    check_assets(gate)
    if args.live:
        check_live(gate)

    print("\n" + "=" * 70)
    if gate.failures:
        print(f" RELEASE GATE FAILED ({len(gate.failures)} problem(s))")
        for f in gate.failures:
            print(f"   - {f}")
        print("=" * 70)
        return 1
    print(" RELEASE GATE PASSED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
