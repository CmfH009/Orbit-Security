#!/usr/bin/env python3
"""Orbit Security - add JSON-LD entity graph + canonical to the remaining public pages.

Phase 0 gate: every public page carries valid Schema.org structured data and
shares the same Organization @id as the hub + About pages, so search engines and
AI crawlers can resolve one entity instead of eight disconnected documents.

Idempotent: re-running is a no-op for pages that already carry the block.

Usage:
    .venv\\Scripts\\python.exe scripts\\apply_page_schema.py
    .venv\\Scripts\\python.exe scripts\\apply_page_schema.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TREES = [REPO_ROOT / "docs", REPO_ROOT / "landing"]

BASE = "https://cmfh009.github.io/Orbit-Security"
ORG = f"{BASE}/#organization"
SITE = f"{BASE}/#website"

LASTMOD = "2026-10-22"

PAGES = {
    "fleet.html": {
        "canonical": f"{BASE}/fleet.html",
        "description": "Fleet Command Center - real-time multi-client attack surface sentinel and perimeter hygiene dashboard for web and Shopify agencies.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/fleet.html#webpage",
                "url": f"{BASE}/fleet.html",
                "name": "Fleet Command Center | Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/fleet.html#breadcrumb"},
            },
            {
                "@type": "WebApplication",
                "@id": f"{BASE}/fleet.html#app",
                "name": "Orbit Security Fleet Command Center",
                "applicationCategory": "SecurityApplication",
                "operatingSystem": "Any (browser)",
                "description": "Multi-client attack surface dashboard that tracks perimeter hygiene scores, remediation status and DNS drift across an agency client fleet.",
                "url": f"{BASE}/fleet.html",
                "publisher": {"@id": ORG},
                "isPartOf": {"@id": SITE},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/fleet.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Fleet Command Center", "item": f"{BASE}/fleet.html#webpage"},
                ],
            },
        ],
    },
    "signup.html": {
        "canonical": f"{BASE}/signup.html",
        "description": "White-label agency retainer onboarding and custom client portal initialization for Orbit Security.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/signup.html#webpage",
                "url": f"{BASE}/signup.html",
                "name": "Orbit Security - Agency Retainer Onboarding",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/signup.html#breadcrumb"},
            },
            {
                "@type": "Offer",
                "@id": f"{BASE}/signup.html#offer",
                "name": "Orbit Security agency retainer",
                "description": "Starter $29/mo, Growth $59/mo, Pro $99/mo agency retainers with white-label client portals.",
                "category": "subscription",
                "priceCurrency": "USD",
                "lowPrice": "29.00",
                "highPrice": "99.00",
                "url": f"{BASE}/signup.html",
                "seller": {"@id": ORG},
                "availability": "https://schema.org/InStock",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/signup.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Onboard", "item": f"{BASE}/signup.html#webpage"},
                ],
            },
        ],
    },
    "ghostdns/index.html": {
        "canonical": f"{BASE}/ghostdns/index.html",
        "description": "Dedicated 24/7 dangling CNAME sentinel and silent DNS drift protection for high-growth DTC brands and web agencies.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/ghostdns/index.html#webpage",
                "url": f"{BASE}/ghostdns/index.html",
                "name": "GhostDNS | Dangling CNAME & DNS Drift Sentinel for Shopify & Webflow",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/ghostdns/index.html#breadcrumb"},
            },
            {
                "@type": "SoftwareApplication",
                "@id": f"{BASE}/ghostdns/index.html#app",
                "name": "GhostDNS",
                "applicationCategory": "SecurityApplication",
                "operatingSystem": "Any",
                "description": "Dedicated sentinel for dangling CNAME takeover exposure and silent DNS drift across Shopify, Webflow and agency client estates.",
                "url": f"{BASE}/ghostdns/index.html",
                "publisher": {"@id": ORG},
                "isPartOf": {"@id": SITE},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/ghostdns/index.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "GhostDNS", "item": f"{BASE}/ghostdns/index.html#webpage"},
                ],
            },
        ],
    },
    "portals/index.html": {
        "canonical": f"{BASE}/portals/index.html",
        "description": "White-label agency partner portals for Orbit Security - co-branded client security dashboards delivered under an agency's own brand.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/index.html#webpage",
                "url": f"{BASE}/portals/index.html",
                "name": "Orbit Security | White-Label Agency Partner Portals",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/portals/index.html#breadcrumb"},
            },
            {
                "@type": "CollectionPage",
                "@id": f"{BASE}/portals/index.html#collection",
                "name": "White-Label Agency Partner Portals",
                "description": "Co-branded client security portals generated by Orbit Security for partner web and ecommerce agencies.",
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/index.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                ],
            },
        ],
    },
}


def build_block(spec: dict) -> str:
    graph = {"@context": "https://schema.org", "@graph": spec["nodes"]}
    body = json.dumps(graph, indent=2, ensure_ascii=False)
    return (
        "\n    <!-- Structured Data: Schema.org entity graph (shared Organization @id) -->\n"
        "    <script type=\"application/ld+json\">\n"
        + body
        + "\n    </script>\n"
    )


def apply(tree: Path, rel: str, spec: dict, check_only: bool) -> str:
    path = tree / rel
    text = path.read_text(encoding="utf-8")
    if "application/ld+json" in text:
        return f"skip (already has JSON-LD): {rel}"

    # canonical first
    if 'rel="canonical"' not in text:
        canon = f'    <link rel="canonical" href="{spec["canonical"]}">\n'
        if "</head>" in text:
            text = text.replace("</head>", canon + "</head>", 1)

    block = build_block(spec)
    if "</head>" in text:
        text = text.replace("</head>", block + "</head>", 1)
    else:
        raise RuntimeError(f"no </head> in {path}")

    if not check_only:
        path.write_text(text, encoding="utf-8", newline="")
    return f"{'would update' if check_only else 'updated'}: {rel}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report only, do not write")
    args = ap.parse_args()

    failures = []
    for rel, spec in PAGES.items():
        for tree in TREES:
            try:
                print(" ", apply(tree, rel, spec, args.check))
            except Exception as exc:
                failures.append(f"{rel}: {exc}")
                print(f"  ERROR {rel}: {exc}")

    # verify parity + parse
    for rel in PAGES:
        hashes = []
        for tree in TREES:
            p = tree / rel
            hashes.append(hashlib.md5(p.read_bytes()).hexdigest())
            blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', p.read_text(encoding="utf-8"), re.S)
            if not blocks:
                failures.append(f"{rel}: no JSON-LD found in {tree.name}")
                continue
            try:
                json.loads(blocks[0])
            except Exception as exc:
                failures.append(f"{rel} [{tree.name}]: JSON-LD parse error {exc}")
        if hashes[0] != hashes[1]:
            failures.append(f"{rel}: docs/landing drift")

    print("\n" + ("CHECK-ONLY: no files written" if args.check else "WRITE COMPLETE"))
    if failures:
        for f in failures:
            print("  FAIL", f)
        return 1
    print("  all pages carry valid JSON-LD and docs/landing are identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
