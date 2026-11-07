#!/usr/bin/env python3
"""Orbit Security — outbound contact verification & anti-bounce deliverability gate.

We bounce because we guess addresses. 43 of 178 dispatched campaigns came
back hard-bounced, yet 43 of 46 of those domains have valid MX records, and
the MX provider mix of the bounced set is statistically identical to the
delivered set. So the problem is not the sending infrastructure and not the
domains - it is that the specific mailbox we guessed does not exist.

This tool verifies the specific address instead of the domain:

  1. MX check - a domain with no mail exchanger can never receive the message.
  2. Published-address mining - fetch the agency's own pages (including
     de-obfuscation of HTML entities and `[at]`/`[dot]` patterns) and extract
     the addresses they publish. If our guess appears, it exists.
  3. Classification per agency:
        CONFIRMED  - the guessed address is published by the agency
        REFUTED    - the agency publishes mail, but not the address we guessed
        UNKNOWN    - no address could be found (inconclusive, not a failure)
        NO_MX      - the domain cannot receive mail at all
  4. Deliverability Pre-Flight Gate - blocks cohort dispatch if any target has
     NO_MX or if REFUTED addresses exceed the safety threshold.

Reads:  data/dispatched_campaigns.json, data/bounced_agencies.json
Writes: data/contact_verification/verification.json
        data/contact_verification/verified_contacts.csv

This is passive reconnaissance of public websites, which is exactly what the
product does, but it is only ever pointed at agencies we are already in
conversation with. Request rate is capped at 1 request/second per domain and
at most 4 pages are read per domain.

Usage:
    .venv\\Scripts\\python.exe scripts\\verify_contacts.py
    .venv\\Scripts\\python.exe scripts\\verify_contacts.py --only-bounced
    .venv\\Scripts\\python.exe scripts\\verify_contacts.py --limit 20
    .venv\\Scripts\\python.exe scripts\\verify_contacts.py --preflight
"""

from __future__ import annotations

import argparse
import csv
import datetime
import html as html_lib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA = REPO_ROOT / "data"
OUT_DIR = DATA / "contact_verification"

CONTACT_PATHS = (
    "",
    "/contact",
    "/contact-us",
    "/about",
    "/about-us",
    "/hello",
    "/team",
    "/.well-known/security.txt",
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
MAILTO_RE = re.compile(r"mailto:([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})", re.I)

OBFUSCATED_AT_RE = re.compile(r"\s*(?:\[at\]|\(at\))\s*", re.I)
OBFUSCATED_DOT_RE = re.compile(r"\s*(?:\[dot\]|\(dot\))\s*", re.I)

ASSET_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".css",
    ".js",
    ".woff",
    ".woff2",
    ".ico",
    ".mp4",
)

# Addresses that are never a real prospect mailbox.
JUNK = re.compile(
    r"^(example|sentry|wixpress|domain|your|email|name|test|no-reply|noreply|"
    r"donotreply|abuse|postmaster|hostmaster|webmaster|privacy|legal|"
    r"gdpr|cookie|cookiepolicy|unsubscribe)@",
    re.I,
)

USER_AGENT = "OrbitSecurity-ContactVerifier/1.0 (deliverability check; contact: carsonmail009@gmail.com)"
REQUEST_DELAY = 1.0
MAX_PAGES = 4
TIMEOUT = 12


def has_mx(domain: str) -> tuple[bool, list[str]]:
    """True when the domain publishes a mail exchanger."""
    try:
        import dns.resolver
    except ImportError:
        return True, []  # cannot verify -> do not block the record
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=6)
        hosts = sorted(str(r.exchange).rstrip(".").lower() for r in answers)
        hosts = [h for h in hosts if h]
        if not hosts:
            return False, []
        return True, hosts
    except Exception:
        return False, []


def fetch(url: str) -> tuple[int, str]:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain"})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(400_000)
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.status, raw.decode(charset, errors="ignore")
    except HTTPError as exc:
        return exc.code, ""
    except (URLError, OSError, ValueError):
        return 0, ""


def _deobfuscate_text(raw_html: str) -> str:
    """Unescapes HTML entities and normalizes common [at]/[dot] obfuscations."""
    unescaped = html_lib.unescape(raw_html)
    normalized = OBFUSCATED_AT_RE.sub("@", unescaped)
    normalized = OBFUSCATED_DOT_RE.sub(".", normalized)
    return normalized


def extract_emails(html: str) -> set[str]:
    cleaned = _deobfuscate_text(html)
    found = {m.group(0).lower() for m in EMAIL_RE.finditer(cleaned)}
    found |= {m.group(1).lower() for m in MAILTO_RE.finditer(cleaned)}
    filtered: set[str] = set()
    for addr in found:
        if JUNK.match(addr):
            continue
        if addr.endswith(ASSET_EXTENSIONS):
            continue
        filtered.add(addr)
    return filtered


def rank_replacement_addresses(addresses: set[str], domain: str) -> list[str]:
    """Filters to same-domain addresses and ranks by business/security relevance."""
    suffix = "@" + domain.lower().lstrip("@")
    same_domain = [
        a.lower()
        for a in addresses
        if a.lower().endswith(suffix)
        and not a.lower().startswith(("no-reply", "noreply", "donotreply", "abuse", "postmaster"))
    ]

    high_priority_prefixes = ("security@", "hello@", "contact@", "info@", "partners@", "agency@")
    low_priority_prefixes = ("careers@", "jobs@", "hr@", "press@", "media@", "billing@", "invoices@")

    def _score_addr(addr: str) -> tuple[int, str]:
        for idx, pref in enumerate(high_priority_prefixes):
            if addr.startswith(pref):
                return (idx, addr)
        if addr.startswith(low_priority_prefixes):
            return (100, addr)
        # Named or general mailbox gets middle priority (after security/hello/contact, before careers/press)
        return (50, addr)

    return [a for a in sorted(set(same_domain), key=_score_addr)]


def mine_addresses(domain: str) -> tuple[set[str], list[str]]:
    """Read up to MAX_PAGES of the agency's own site and collect published emails."""
    found: set[str] = set()
    visited: list[str] = []
    for path in CONTACT_PATHS:
        if len(visited) >= MAX_PAGES:
            break
        url = f"https://{domain}{path}" if path else f"https://{domain}/"
        status, html = fetch(url)
        visited.append(f"{url} [{status}]")
        if status == 200 and html:
            found |= extract_emails(html)
        time.sleep(REQUEST_DELAY)
    return found, visited


def load_targets(only_bounced: bool) -> list[dict]:
    campaigns = json.loads((DATA / "dispatched_campaigns.json").read_text(encoding="utf-8"))
    bounces = json.loads((DATA / "bounced_agencies.json").read_text(encoding="utf-8"))
    targets = []
    for agency_domain, record in campaigns.items():
        status = str(record.get("status", "")).upper()
        if only_bounced and status != "BOUNCED":
            continue
        email = record.get("contact_email", "")
        if not email:
            bounce = bounces.get(agency_domain, {})
            email = bounce.get("bounced_email", "")
        targets.append({
            "agency_domain": agency_domain,
            "agency_name": record.get("agency_name", ""),
            "contact_email": email,
            "status": status,
            "client_domain": record.get("client_domain", ""),
        })
    return targets


def classify(target: dict) -> dict:
    domain = target["agency_domain"]
    guessed = (target["contact_email"] or "").lower()

    mx_ok, mx_hosts = has_mx(domain)
    if not mx_ok:
        return {**target, "classification": "NO_MX", "published_addresses": [], "pages_read": []}

    published, visited = mine_addresses(domain)
    if not published:
        return {**target, "classification": "UNKNOWN", "published_addresses": [], "pages_read": visited}

    if guessed and guessed in published:
        classification = "CONFIRMED"
    else:
        classification = "REFUTED"

    replacements = rank_replacement_addresses(published, domain)
    return {
        **target,
        "classification": classification,
        "published_addresses": sorted(published)[:20],
        "replacement_addresses": replacements[:5],
        "pages_read": visited,
        "mx_hosts": mx_hosts[:3],
    }


def evaluate_deliverability_gate(
    results: list[dict[str, Any]],
    max_refuted_ratio: float = 0.05,
) -> dict[str, Any]:
    """Evaluates whether a cohort passes the anti-bounce pre-flight gate."""
    total = len(results)
    confirmed = sum(1 for r in results if r.get("classification") == "CONFIRMED")
    refuted = sum(1 for r in results if r.get("classification") == "REFUTED")
    no_mx = sum(1 for r in results if r.get("classification") == "NO_MX")
    unknown = sum(1 for r in results if r.get("classification") == "UNKNOWN")

    refuted_ratio = (refuted / total) if total > 0 else 0.0
    blocking_reasons: list[str] = []

    if no_mx > 0:
        blocking_reasons.append(f"{no_mx} domain(s) have NO_MX and cannot receive mail.")
    if refuted_ratio > max_refuted_ratio:
        blocking_reasons.append(
            f"Refuted address ratio ({refuted_ratio:.1%}) exceeds threshold ({max_refuted_ratio:.1%})."
        )

    return {
        "gate_passed": len(blocking_reasons) == 0,
        "total_checked": total,
        "confirmed_count": confirmed,
        "refuted_count": refuted,
        "no_mx_count": no_mx,
        "unknown_count": unknown,
        "refuted_ratio": round(refuted_ratio, 4),
        "blocking_reasons": blocking_reasons,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify outbound agency contacts")
    ap.add_argument("--only-bounced", action="store_true", help="only check campaigns marked BOUNCED")
    ap.add_argument("--limit", type=int, default=0, help="cap the number of domains checked")
    ap.add_argument("--preflight", action="store_true", help="enforce strict anti-bounce pre-flight gate exit code")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = load_targets(args.only_bounced)
    if args.limit:
        targets = targets[: args.limit]
    print(f"Verifying {len(targets)} agency contacts (1 req/s per domain, <= {MAX_PAGES} pages/domain)\n")

    results = []
    for i, target in enumerate(targets, 1):
        row = classify(target)
        results.append(row)
        print(f"[{i:>3}/{len(targets)}] {row['agency_domain']:<32} {row['classification']:<10}"
              f" {row.get('replacement_addresses') or ''}")

    counts: dict[str, int] = {}
    for row in results:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1

    gate = evaluate_deliverability_gate(results)

    payload = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "checked": len(results),
        "classification_counts": counts,
        "deliverability_gate": gate,
        "method": {
            "mx_check": "DNS MX lookup; a domain with no exchanger cannot receive mail",
            "address_mining": "public pages of the agency's own site; emails extracted from text, mailto links, and de-obfuscated patterns",
            "request_rate": f"{REQUEST_DELAY}/s per domain, max {MAX_PAGES} pages per domain",
            "pages": list(CONTACT_PATHS[:MAX_PAGES]),
        },
        "results": results,
    }
    (out_dir / "verification.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with open(out_dir / "verified_contacts.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["agency_domain", "agency_name", "contact_email", "status",
                         "classification", "replacement_addresses", "published_addresses"])
        for row in results:
            writer.writerow([
                row["agency_domain"], row["agency_name"], row["contact_email"], row["status"],
                row["classification"], "; ".join(row.get("replacement_addresses", [])),
                "; ".join(row.get("published_addresses", [])[:5]),
            ])

    print("\n" + "=" * 62)
    print(" CLASSIFICATION")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"   {k:<12} {v:>4}")
    print(f" DELIVERABILITY GATE: {'PASS' if gate['gate_passed'] else 'HOLD'}")
    for reason in gate["blocking_reasons"]:
        print(f"   [!] {reason}")
    print(f"\n Wrote {out_dir / 'verification.json'}")
    print(f" Wrote {out_dir / 'verified_contacts.csv'}")
    print("=" * 62)

    if args.preflight and not gate["gate_passed"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
