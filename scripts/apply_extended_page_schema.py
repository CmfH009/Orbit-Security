#!/usr/bin/env python3
"""Orbit Security - add JSON-LD entity graph + canonical to remaining 14 pages (T39).

Covers:
- 4 legal pages: privacy.html, terms.html, refunds.html, disclaimer.html
- 1 product page: stealthbridge/index.html
- 9 agency partner portals: wholegrain-digital.html, moove-agency.html, propeller.html,
  eastside-co.html, we-make-websites.html, swanky.html, barrel.html, charle.html,
  orbit-core.html

Idempotent: re-running is a no-op for pages that already carry the JSON-LD block.

Usage:
    .venv\\Scripts\\python.exe scripts\\apply_extended_page_schema.py
    .venv\\Scripts\\python.exe scripts\\apply_extended_page_schema.py --check
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
PORTALS = f"{BASE}/portals/index.html#collection"

LASTMOD = "2026-10-26"

EXTENDED_PAGES = {
    # 4 Legal Pages
    "privacy.html": {
        "canonical": f"{BASE}/privacy.html",
        "description": "Privacy policy, data retention rules, and telemetry handling guidelines for Orbit Security.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/privacy.html#webpage",
                "url": f"{BASE}/privacy.html",
                "name": "Orbit Security | Privacy Policy",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/privacy.html#breadcrumb"},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/privacy.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Privacy Policy", "item": f"{BASE}/privacy.html#webpage"},
                ],
            },
        ],
    },
    "terms.html": {
        "canonical": f"{BASE}/terms.html",
        "description": "Terms of service, subscription retainer conditions, and authorized scope limits for Orbit Security.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/terms.html#webpage",
                "url": f"{BASE}/terms.html",
                "name": "Orbit Security | Terms of Service",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/terms.html#breadcrumb"},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/terms.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Terms of Service", "item": f"{BASE}/terms.html#webpage"},
                ],
            },
        ],
    },
    "refunds.html": {
        "canonical": f"{BASE}/refunds.html",
        "description": "Refund policy, 14-day zero-risk trial terms, and subscription cancellation procedures for Orbit Security.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/refunds.html#webpage",
                "url": f"{BASE}/refunds.html",
                "name": "Orbit Security | Refund & Cancellation Policy",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/refunds.html#breadcrumb"},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/refunds.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Refund Policy", "item": f"{BASE}/refunds.html#webpage"},
                ],
            },
        ],
    },
    "disclaimer.html": {
        "canonical": f"{BASE}/disclaimer.html",
        "description": "Technical RFC compliance documentation, ethical safe harbor standards, and passive reconnaissance legal guidelines for Orbit Security.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/disclaimer.html#webpage",
                "url": f"{BASE}/disclaimer.html",
                "name": "RFC Passive Reconnaissance & Safe Harbor Disclaimer | Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/disclaimer.html#breadcrumb"},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/disclaimer.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Safe Harbor Disclaimer", "item": f"{BASE}/disclaimer.html#webpage"},
                ],
            },
        ],
    },
    # 1 Product / SDK Page
    "stealthbridge/index.html": {
        "canonical": f"{BASE}/stealthbridge/index.html",
        "description": "High-performance Python & TypeScript SDK for humanized browser automation, Cloudflare Turnstile bypass, and desktop session hooking.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/stealthbridge/index.html#webpage",
                "url": f"{BASE}/stealthbridge/index.html",
                "name": "StealthBridge SDK | Commercial Anti-Detection Browser Automation Library",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/stealthbridge/index.html#breadcrumb"},
            },
            {
                "@type": "SoftwareApplication",
                "@id": f"{BASE}/stealthbridge/index.html#app",
                "name": "StealthBridge SDK",
                "applicationCategory": "DeveloperApplication",
                "operatingSystem": "Windows, Linux, macOS",
                "description": "High-performance Python & TypeScript SDK for humanized browser automation, Cloudflare Turnstile bypass, and desktop session hooking.",
                "url": f"{BASE}/stealthbridge/index.html",
                "publisher": {"@id": ORG},
                "isPartOf": {"@id": SITE},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/stealthbridge/index.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "StealthBridge SDK", "item": f"{BASE}/stealthbridge/index.html#webpage"},
                ],
            },
        ],
    },
    # 9 Agency Partner Portals
    "portals/wholegrain-digital.html": {
        "canonical": f"{BASE}/portals/wholegrain-digital.html",
        "description": "Client security audit portal and attack surface sentinel for Wholegrain Digital client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/wholegrain-digital.html#webpage",
                "url": f"{BASE}/portals/wholegrain-digital.html",
                "name": "Wholegrain Digital | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/wholegrain-digital.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/wholegrain-digital.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/wholegrain-digital.html#agency",
                "name": "Wholegrain Digital",
                "url": "https://www.wholegraindigital.com",
                "description": "London's leading sustainable WordPress agency and Orbit Security verified partner.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/wholegrain-digital.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Wholegrain Digital", "item": f"{BASE}/portals/wholegrain-digital.html#webpage"},
                ],
            },
        ],
    },
    "portals/moove-agency.html": {
        "canonical": f"{BASE}/portals/moove-agency.html",
        "description": "Client security audit portal and attack surface sentinel for Moove Agency client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/moove-agency.html#webpage",
                "url": f"{BASE}/portals/moove-agency.html",
                "name": "Moove Agency | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/moove-agency.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/moove-agency.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/moove-agency.html#agency",
                "name": "Moove Agency",
                "url": "https://www.mooveagency.com",
                "description": "Enterprise WordPress web development agency and Orbit Security verified partner.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/moove-agency.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Moove Agency", "item": f"{BASE}/portals/moove-agency.html#webpage"},
                ],
            },
        ],
    },
    "portals/propeller.html": {
        "canonical": f"{BASE}/portals/propeller.html",
        "description": "Client security audit portal and attack surface sentinel for Propeller client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/propeller.html#webpage",
                "url": f"{BASE}/portals/propeller.html",
                "name": "Propeller | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/propeller.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/propeller.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/propeller.html#agency",
                "name": "Propeller",
                "url": "https://www.propeller.co.uk",
                "description": "Full-service digital agency for luxury, hospitality and lifestyle brands.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/propeller.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Propeller", "item": f"{BASE}/portals/propeller.html#webpage"},
                ],
            },
        ],
    },
    "portals/eastside-co.html": {
        "canonical": f"{BASE}/portals/eastside-co.html",
        "description": "Client security audit portal and attack surface sentinel for Eastside Co client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/eastside-co.html#webpage",
                "url": f"{BASE}/portals/eastside-co.html",
                "name": "Eastside Co | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/eastside-co.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/eastside-co.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/eastside-co.html#agency",
                "name": "Eastside Co",
                "url": "https://eastsideco.com",
                "description": "Award-winning Shopify Plus agency and Orbit Security verified partner.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/eastside-co.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Eastside Co", "item": f"{BASE}/portals/eastside-co.html#webpage"},
                ],
            },
        ],
    },
    "portals/we-make-websites.html": {
        "canonical": f"{BASE}/portals/we-make-websites.html",
        "description": "Client security audit portal and attack surface sentinel for We Make Websites client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/we-make-websites.html#webpage",
                "url": f"{BASE}/portals/we-make-websites.html",
                "name": "We Make Websites | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/we-make-websites.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/we-make-websites.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/we-make-websites.html#agency",
                "name": "We Make Websites",
                "url": "https://wemakewebsites.com",
                "description": "The Shopify Plus agency for international brands and Orbit Security partner.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/we-make-websites.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "We Make Websites", "item": f"{BASE}/portals/we-make-websites.html#webpage"},
                ],
            },
        ],
    },
    "portals/swanky.html": {
        "canonical": f"{BASE}/portals/swanky.html",
        "description": "Client security audit portal and attack surface sentinel for Swanky Agency client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/swanky.html#webpage",
                "url": f"{BASE}/portals/swanky.html",
                "name": "Swanky Agency | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/swanky.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/swanky.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/swanky.html#agency",
                "name": "Swanky Agency",
                "url": "https://swankyagency.com",
                "description": "Leading Shopify Plus ecommerce agency and Orbit Security partner.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/swanky.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Swanky Agency", "item": f"{BASE}/portals/swanky.html#webpage"},
                ],
            },
        ],
    },
    "portals/barrel.html": {
        "canonical": f"{BASE}/portals/barrel.html",
        "description": "Client security audit portal and attack surface sentinel for Barrel client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/barrel.html#webpage",
                "url": f"{BASE}/portals/barrel.html",
                "name": "Barrel | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/barrel.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/barrel.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/barrel.html#agency",
                "name": "Barrel",
                "url": "https://www.barrelny.com",
                "description": "Creative and digital marketing agency for DTC brands and Orbit Security partner.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/barrel.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Barrel", "item": f"{BASE}/portals/barrel.html#webpage"},
                ],
            },
        ],
    },
    "portals/charle.html": {
        "canonical": f"{BASE}/portals/charle.html",
        "description": "Client security audit portal and attack surface sentinel for Charle Agency client estates.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/charle.html#webpage",
                "url": f"{BASE}/portals/charle.html",
                "name": "Charle Agency | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": f"{BASE}/portals/charle.html#agency"},
                "breadcrumb": {"@id": f"{BASE}/portals/charle.html#breadcrumb"},
            },
            {
                "@type": "Organization",
                "@id": f"{BASE}/portals/charle.html#agency",
                "name": "Charle Agency",
                "url": "https://www.charle.co.uk",
                "description": "Bespoke Shopify Plus agency in London and Orbit Security partner.",
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/charle.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Charle Agency", "item": f"{BASE}/portals/charle.html#webpage"},
                ],
            },
        ],
    },
    "portals/orbit-core.html": {
        "canonical": f"{BASE}/portals/orbit-core.html",
        "description": "Client security audit portal and attack surface sentinel for Orbit Core flagship accounts.",
        "nodes": [
            {
                "@type": "WebPage",
                "@id": f"{BASE}/portals/orbit-core.html#webpage",
                "url": f"{BASE}/portals/orbit-core.html",
                "name": "Orbit Core | Client Security Audit Portal — Orbit Security",
                "datePublished": "2026-10-02",
                "dateModified": LASTMOD,
                "isPartOf": {"@id": SITE},
                "about": {"@id": ORG},
                "breadcrumb": {"@id": f"{BASE}/portals/orbit-core.html#breadcrumb"},
            },
            {
                "@type": "BreadcrumbList",
                "@id": f"{BASE}/portals/orbit-core.html#breadcrumb",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": SITE},
                    {"@type": "ListItem", "position": 2, "name": "Partner Portals", "item": f"{BASE}/portals/index.html#webpage"},
                    {"@type": "ListItem", "position": 3, "name": "Orbit Core", "item": f"{BASE}/portals/orbit-core.html#webpage"},
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
    if not path.exists():
        return f"skip (does not exist in {tree.name}): {rel}"
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
    for rel, spec in EXTENDED_PAGES.items():
        for tree in TREES:
            try:
                print(" ", apply(tree, rel, spec, args.check))
            except Exception as exc:
                failures.append(f"{rel}: {exc}")
                print(f"  ERROR {rel}: {exc}")

    # verify parity + parse
    for rel in EXTENDED_PAGES:
        hashes = []
        for tree in TREES:
            p = tree / rel
            if not p.exists():
                continue
            hashes.append(hashlib.md5(p.read_bytes()).hexdigest())
            blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', p.read_text(encoding="utf-8"), re.S)
            if not blocks:
                failures.append(f"{rel}: no JSON-LD found in {tree.name}")
                continue
            try:
                json.loads(blocks[0])
            except Exception as exc:
                failures.append(f"{rel} [{tree.name}]: JSON-LD parse error {exc}")
        if len(hashes) == 2 and hashes[0] != hashes[1]:
            failures.append(f"{rel}: docs/landing drift")

    print("\n" + ("CHECK-ONLY: no files written" if args.check else "WRITE COMPLETE"))
    if failures:
        for f in failures:
            print("  FAIL", f)
        return 1
    print("  all extended pages carry valid JSON-LD and docs/landing are identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
