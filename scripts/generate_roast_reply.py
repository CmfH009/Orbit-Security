#!/usr/bin/env python3
"""Orbit Security — Fast CLI Roast Reply Generator for X (@_arsoncode).

Accepts a domain, executes a rapid passive scan (use_crtsh=False, 5s timeout),
and outputs a ready-to-paste tweet reply strictly <= 280 characters.
"""

import argparse
import asyncio
from pathlib import Path
import re
import sys
from typing import Optional, Tuple
from urllib.parse import urlparse

# Ensure src/ is on sys.path for direct CLI execution
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from orbit_security.scanner import OrbitSecurityScanner
    from orbit_security.models import DomainAuditResult, Finding, Severity
except ImportError:
    # Fallback to direct import if package resolution differs
    from src.orbit_security.scanner import OrbitSecurityScanner
    from src.orbit_security.models import DomainAuditResult, Finding, Severity

ARCADE_DECODER_URL = "https://cmfh009.github.io/Orbit-Security/"


def clean_domain(raw_input: str) -> str:
    """Sanitizes user input down to a clean fully qualified domain name."""
    cleaned = raw_input.strip()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    # Strip paths, ports, or query parameters
    cleaned = cleaned.split("/")[0].split(":")[0].strip()
    return cleaned.lower()


def extract_dmarc_status(result: DomainAuditResult) -> Tuple[str, Optional[Finding]]:
    """Analyzes audit findings to classify DMARC posture in Simple Cat bouncer terms."""
    dmarc_finding = None
    for f in result.findings:
        if "dmarc" in f.title.lower() or (f.category == "Email Authentication" and "_dmarc" in f.target):
            dmarc_finding = f
            break

    if not dmarc_finding:
        return "Enforced (Bouncer active)", None

    title_lower = dmarc_finding.title.lower()
    if "p=none" in title_lower or "monitoring" in title_lower:
        return "Vulnerable (p=none bouncer)", dmarc_finding
    elif "missing" in title_lower or "lacks" in dmarc_finding.description.lower():
        return "Vulnerable (No DMARC bouncer)", dmarc_finding
    elif "timeout" in title_lower:
        return "Unverified (DNS timeout)", dmarc_finding
    else:
        return f"Vulnerable ({dmarc_finding.title})", dmarc_finding


def extract_key_finding(result: DomainAuditResult, dmarc_finding: Optional[Finding]) -> str:
    """Selects the single most salient technical finding to roast."""
    # Exclude the already highlighted DMARC finding
    other_findings = [f for f in result.findings if f is not dmarc_finding]

    if not other_findings:
        if dmarc_finding:
            return "Email spoofing unblocked (p=none policy)"
        return "Clean perimeter headers & DNS hygiene"

    # 1. Critical & High: Dangling CNAME takeover or SSL expirations
    for f in other_findings:
        if "takeover" in f.title.lower():
            return f"Dangling CNAME takeover on {f.target}"
        if "expired" in f.title.lower():
            return f"Expired SSL certificate on {f.target}"

    # 2. Application Security: Content Security Policy & Clickjacking
    has_csp = any("content security policy" in f.title.lower() or "csp" in f.title.lower() for f in other_findings)
    has_xfo = any("x-frame-options" in f.title.lower() or "clickjacking" in f.title.lower() for f in other_findings)
    if has_csp and has_xfo:
        return "Missing CSP & X-Frame-Options (Clickjacking)"
    if has_csp:
        return "Missing Content-Security-Policy (CSP)"
    if has_xfo:
        return "Missing X-Frame-Options (Clickjacking risk)"

    # 3. Transport Security: HSTS (non-INFO)
    for f in other_findings:
        if "hsts" in f.title.lower() and f.severity != Severity.INFO:
            return "Missing HSTS (SSL stripping risk)"

    # 4. Email & Web Transport: MTA-STS & Referrer-Policy
    has_mta = any("mta-sts" in f.title.lower() for f in other_findings)
    has_ref = any("referrer-policy" in f.title.lower() for f in other_findings)
    if has_mta and has_ref:
        return "Missing MTA-STS & Referrer-Policy"
    if has_mta:
        return "Missing MTA-STS Transport Security"
    if has_ref:
        return "Missing Referrer-Policy header"

    # 5. Brand Identity & Trust: BIMI
    if any("bimi" in f.title.lower() for f in other_findings):
        return "Missing BIMI brand trust indicator"

    # 6. Fallback to first non-DMARC finding title
    first_title = other_findings[0].title
    cleaned_title = re.sub(r"\(RFC \d+\)", "", first_title)
    cleaned_title = re.sub(r"\(HTTP Strict Transport Security\)", "", cleaned_title)
    return cleaned_title.strip()


def generate_roast_tweet(
    domain: str, score: int, grade: str, dmarc_status: str, key_finding: str
) -> str:
    """Builds the final tweet reply with strict <= 280 char enforcement."""
    base_template = (
        f"🛡️ Orbit Roast: {domain}\n\n"
        f"📊 Score: {score}/100 (Grade: {grade})\n"
        f"✉️ DMARC: {dmarc_status}\n"
        f"⚠️ Key finding: {key_finding}\n\n"
        f"Decode in our 16-bit arcade:\n"
        f"{ARCADE_DECODER_URL}"
    )

    if len(base_template) <= 280:
        return base_template

    # If exceeding 280, truncate key_finding safely
    overflow = len(base_template) - 280
    trimmed_len = max(10, len(key_finding) - overflow - 3)
    trimmed_finding = key_finding[:trimmed_len] + "..."

    shortened = (
        f"🛡️ Orbit Roast: {domain}\n\n"
        f"📊 Score: {score}/100 (Grade: {grade})\n"
        f"✉️ DMARC: {dmarc_status}\n"
        f"⚠️ Key finding: {trimmed_finding}\n\n"
        f"Decode in our 16-bit arcade:\n"
        f"{ARCADE_DECODER_URL}"
    )
    return shortened


async def scan_and_generate(domain: str) -> Tuple[str, DomainAuditResult]:
    """Runs OrbitSecurityScanner asynchronously and generates the roast tweet."""
    scanner = OrbitSecurityScanner(timeout=5.0)
    result = await scanner.scan_domain(domain, use_crtsh=False)

    dmarc_status, dmarc_finding = extract_dmarc_status(result)
    key_finding = extract_key_finding(result, dmarc_finding)
    tweet = generate_roast_tweet(
        domain=result.domain,
        score=result.score,
        grade=result.grade,
        dmarc_status=dmarc_status,
        key_finding=key_finding,
    )
    return tweet, result


def main():
    parser = argparse.ArgumentParser(
        description="Orbit Security: Rapid X Roast Reply Generator (Option 1 Inbound Magnet)"
    )
    parser.add_argument("domain", help="Target domain to scan and roast (e.g. targetbrand.com)")
    parser.add_argument(
        "--raw", action="store_true", help="Print only the ready-to-paste tweet text without framing"
    )
    parser.add_argument(
        "--video", action="store_true", help="Synthesize a 16-bit video roast MP4 with neural cat voiceover"
    )
    args = parser.parse_args()

    clean_target = clean_domain(args.domain)
    if not clean_target:
        print("Error: Invalid or empty domain provided.", file=sys.stderr)
        sys.exit(1)

    try:
        tweet, result = asyncio.run(scan_and_generate(clean_target))
    except Exception as e:
        print(f"Error executing Orbit Security scan for '{clean_target}': {e}", file=sys.stderr)
        sys.exit(1)

    char_count = len(tweet)
    is_valid = char_count <= 280

    video_path = None
    if args.video:
        try:
            from orbit_security.video_generator import VideoGenerator
            dmarc_status, dmarc_finding = extract_dmarc_status(result)
            key_finding = extract_key_finding(result, dmarc_finding)
            vg = VideoGenerator(project_root=REPO_ROOT)
            speech_script = (
                f"Orbit Security perimeter scan for {clean_target}. "
                f"Attack surface hygiene score is {result.score} out of 100, Grade {result.grade}. "
                f"DMARC status: {dmarc_status}. Key finding: {key_finding}."
            )
            print("🎥 Synthesizing astronaut cat video roast with neural DSP...")
            video_path = vg.generate_video_short(
                script_text=speech_script,
                title=f"roast_{clean_target.replace('.', '_')}",
            )
            print(f"🎬 Video Roast rendered: {video_path}")
        except Exception as ve:
            print(f"Video synthesis notice: {ve}", file=sys.stderr)

    if args.raw:
        print(tweet)
        return

    print("=" * 60)
    print("🕹️ ORBIT SECURITY: X ROAST REPLY GENERATOR")
    print(f"Target Domain: {clean_target}")
    print(f"Score: {result.score}/100 | Grade: {result.grade}")
    print(f"Character Count: {char_count}/280 [{'PASS' if is_valid else 'FAIL'}]")
    if video_path:
        print(f"Media Asset: {video_path.name} ({round(video_path.stat().st_size / 1024, 1)} KB)")
    print("=" * 60)
    print("\nREADY-TO-PASTE TWEET REPLY:\n")
    print(tweet)
    print("\n" + "=" * 60)

    if not is_valid:
        print(f"WARNING: Tweet exceeds 280 chars by {char_count - 280}!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
