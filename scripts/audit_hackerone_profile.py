#!/usr/bin/env python3
"""audit_hackerone_profile.py: Live HackerOne API Researcher Profile & Portfolio Auditor.

Reads authenticated HackerOne researcher telemetry via the Hacker REST API v1
(`/v1/hackers/me/reports`, `/v1/hackers/reports/{id}`, `/v1/hackers/payments/balance`),
scores profile readiness (name, bio, HTTPS website, location, professional avatar),
and outputs actionable guidance for updating https://hackerone.com/settings/profile/edit.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
import http.cookiejar
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import urllib.error
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"
HACKERONE_API_BASE = "https://api.hackerone.com"
HACKERONE_WEB_BASE = "https://hackerone.com"
HACKERONE_EDIT_PROFILE_URL = "https://hackerone.com/settings/profile/edit"
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

MIN_BIO_LENGTH = 40
INTRO_TRUNCATION_THRESHOLD = 895
TERMINAL_PUNCTUATION = (".", "!", "?", ")", "*", "`")
SOCIAL_HANDLE_FIELDS = (
    ("linkedin_handle", "LinkedIn"),
    ("github_handle", "GitHub"),
    ("twitter_handle", "X/Twitter"),
)
PLACEHOLDER_AVATAR_MARKERS = (
    "lakeday2022lil.jpg",
    "default-avatar",
    "default_avatar",
    "/assets/avatars/default",
    "ghost-avatar",
)


def _parse_env_file(env_path: Path) -> Dict[str, str]:
    """Parse key=value pairs from a dotenv file without external dependencies."""
    values: Dict[str, str] = {}
    if not env_path.exists():
        return values

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def load_hackerone_credentials(env_path: Optional[Path] = None) -> Tuple[str, str]:
    """Load HackerOne API username and token from os.environ or .env file."""
    username = os.environ.get("HACKERONE_API_USERNAME", "").strip()
    token = os.environ.get("HACKERONE_API_TOKEN", "").strip()

    if not username or not token:
        target_env = env_path or DEFAULT_ENV_PATH
        file_env = _parse_env_file(target_env)
        username = username or file_env.get("HACKERONE_API_USERNAME", "").strip()
        token = token or file_env.get("HACKERONE_API_TOKEN", "").strip()

    if not username or not token:
        raise RuntimeError(
            "Missing HACKERONE_API_USERNAME or HACKERONE_API_TOKEN in environment or .env."
        )
    return username, token


def _is_valid_https_url(value: Any) -> bool:
    """Return True if value is a well-formed HTTPS URL with a network host."""
    if not isinstance(value, str) or not value.strip():
        return False
    parsed = urlparse(value.strip())
    return parsed.scheme.lower() == "https" and bool(parsed.netloc)


def _inspect_avatar(profile_picture: Any) -> Tuple[bool, str]:
    """Verify that profile_picture is present and not a casual or default placeholder."""
    if isinstance(profile_picture, dict):
        urls = [str(v) for v in profile_picture.values() if v]
    elif isinstance(profile_picture, str) and profile_picture.strip():
        urls = [profile_picture.strip()]
    else:
        urls = []

    if not urls:
        return False, "No profile avatar configured."

    joined = " ".join(urls).lower()
    for marker in PLACEHOLDER_AVATAR_MARKERS:
        if marker in joined:
            return (
                False,
                f"Avatar uses non-branded/placeholder asset ({marker}); replace with a professional security avatar.",
            )
    return True, "Custom professional avatar configured."


def _is_intro_truncated(intro: str) -> bool:
    """Detect whether a HackerOne Markdown intro was clipped near the 900-char ceiling."""
    if not intro:
        return False
    return len(intro) >= INTRO_TRUNCATION_THRESHOLD or not intro.endswith(TERMINAL_PUNCTUATION)


def _evaluate_bio_or_intro(bio: str, intro: str) -> Tuple[bool, str, Optional[str]]:
    """Evaluate Researcher Bio or GraphQL Intro completeness and truncation hygiene."""
    if len(intro) >= MIN_BIO_LENGTH:
        if _is_intro_truncated(intro):
            tail = intro[-45:]
            return (
                False,
                f"Intro ({len(intro)} chars) appears truncated mid-sentence ('...{tail}').",
                "Intro appears truncated at HackerOne's 900-character limit; tighten under ~800 chars so the closing sentence is not clipped.",
            )
        return True, f"Markdown Intro configured cleanly ({len(intro)} chars).", None

    if len(bio) >= MIN_BIO_LENGTH:
        return True, f"Bio length is {len(bio)} chars (>= {MIN_BIO_LENGTH}).", None

    best_len = max(len(bio), len(intro))
    return (
        False,
        f"Bio / Intro is missing or too short ({best_len}/{MIN_BIO_LENGTH} chars minimum).",
        f"Add a technical researcher bio or intro (>= {MIN_BIO_LENGTH} chars) highlighting Orbit Security, DNS/CNAME takeovers, cloud exposure, and API research.",
    )


def _evaluate_location_or_socials(attrs: Dict[str, Any], location: str) -> Tuple[bool, str, Optional[str]]:
    """Evaluate researcher location or connected social handles (>= 2 handles)."""
    connected = [
        f"{label}: {str(attrs.get(field)).strip()}"
        for field, label in SOCIAL_HANDLE_FIELDS
        if str(attrs.get(field) or "").strip()
    ]
    if location:
        suffix = f" ({', '.join(connected)})" if connected else ""
        return True, f"Location set to '{location}'{suffix}.", None
    if len(connected) >= 2:
        return True, f"Verified social handles configured ({', '.join(connected)}).", None
    return (
        False,
        f"Location is empty ({len(connected)}/2 social handles connected).",
        "Set Location (e.g., 'United States') or connect at least 2 social handles (LinkedIn, GitHub, X/Twitter).",
    )


def evaluate_profile_completeness(reporter_attrs: Dict[str, Any]) -> Dict[str, Any]:
    """Score researcher profile readiness on a 0-100 scale and emit recommendations."""
    attrs = reporter_attrs or {}
    name = str(attrs.get("name") or "").strip()
    bio = str(attrs.get("bio") or "").strip()
    intro = str(attrs.get("intro") or "").strip()
    website = attrs.get("website")
    location = str(attrs.get("location") or "").strip()
    profile_picture = attrs.get("profile_picture")

    name_ok = bool(name)
    bio_ok, bio_detail, bio_rec = _evaluate_bio_or_intro(bio, intro)
    website_ok = _is_valid_https_url(website)
    location_ok, location_detail, location_rec = _evaluate_location_or_socials(attrs, location)
    avatar_ok, avatar_detail = _inspect_avatar(profile_picture)

    checks: Dict[str, Dict[str, Any]] = {
        "name": {
            "passed": name_ok,
            "points": 20 if name_ok else 0,
            "max_points": 20,
            "detail": f"Display name set to '{name}'." if name_ok else "Display name is empty.",
        },
        "bio": {
            "passed": bio_ok,
            "points": 30 if bio_ok else 0,
            "max_points": 30,
            "detail": bio_detail,
        },
        "website": {
            "passed": website_ok,
            "points": 20 if website_ok else 0,
            "max_points": 20,
            "detail": f"HTTPS website set to '{website}'."
            if website_ok
            else "Website is missing or not a valid HTTPS URL.",
        },
        "location": {
            "passed": location_ok,
            "points": 15 if location_ok else 0,
            "max_points": 15,
            "detail": location_detail,
        },
        "profile_picture": {
            "passed": avatar_ok,
            "points": 15 if avatar_ok else 0,
            "max_points": 15,
            "detail": avatar_detail,
        },
    }

    recommendations: List[str] = []
    if not name_ok:
        recommendations.append("Set your full professional display name.")
    if bio_rec:
        recommendations.append(bio_rec)
    if not website_ok:
        recommendations.append(
            "Set Website to https://cmfh009.github.io/Orbit-Security/ (HTTPS required)."
        )
    if location_rec:
        recommendations.append(location_rec)
    if not avatar_ok:
        recommendations.append(
            "Replace current profile avatar with a branded asset (e.g., landing/assets/orbit_x_avatar_2026.jpg)."
        )

    score = sum(item["points"] for item in checks.values())
    return {
        "score": score,
        "max_score": 100,
        "checks": checks,
        "recommendations": recommendations,
    }


def summarize_reports(reports_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize HackerOne reports by state and extract concise metadata."""
    state_counts: Counter[str] = Counter()
    summaries: List[Dict[str, Any]] = []

    for item in reports_data:
        attrs = item.get("attributes") or {}
        state = str(attrs.get("state") or "unknown")
        state_counts[state] += 1
        summaries.append(
            {
                "id": str(item.get("id") or ""),
                "title": str(attrs.get("title") or "Untitled Report"),
                "state": state,
                "created_at": attrs.get("created_at"),
            }
        )

    return {
        "total": len(summaries),
        "by_state": dict(state_counts),
        "reports": summaries,
    }


def _api_get_json(
    url: str,
    auth_header: str,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Execute an authenticated GET request against the HackerOne REST API."""
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": auth_header,
            "Accept": "application/json",
            "User-Agent": "OrbitSecurity-HackerOneProfileAudit/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_public_graphql_profile(username: str, timeout: int = 15) -> Dict[str, Any]:
    """Fetch public HackerOne profile fields (intro & social handles) via GraphQL."""
    if not username:
        return {}
    try:
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        profile_url = f"{HACKERONE_WEB_BASE}/{username}"
        page_req = urllib.request.Request(
            profile_url,
            headers={
                "User-Agent": BROWSER_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        with opener.open(page_req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        csrf_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
        csrf_token = csrf_match.group(1) if csrf_match else ""
        if not csrf_token:
            return {}

        gql_payload = {
            "query": """
            query($u: String!) {
              user(username: $u) {
                bio
                intro
                website
                location
                linkedin_handle
                github_handle
                twitter_handle
              }
            }
            """,
            "variables": {"u": username},
        }
        gql_req = urllib.request.Request(
            f"{HACKERONE_WEB_BASE}/graphql",
            data=json.dumps(gql_payload).encode("utf-8"),
            headers={
                "User-Agent": BROWSER_USER_AGENT,
                "Content-Type": "application/json",
                "X-Csrf-Token": csrf_token,
                "Origin": HACKERONE_WEB_BASE,
                "Referer": profile_url,
            },
        )
        with opener.open(gql_req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        user_node = (payload.get("data") or {}).get("user")
        return user_node if isinstance(user_node, dict) else {}
    except Exception:
        return {}


def fetch_hackerone_profile_snapshot(
    username: str,
    api_token: str,
    *,
    base_url: str = HACKERONE_API_BASE,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Fetch live profile, reports, and balance telemetry from the HackerOne REST API + GraphQL."""
    credentials = base64.b64encode(f"{username}:{api_token}".encode("utf-8")).decode("ascii")
    auth_header = f"Basic {credentials}"
    root = base_url.rstrip("/")

    reports_resp = _api_get_json(
        f"{root}/v1/hackers/me/reports?page[size]=25",
        auth_header,
        timeout=timeout,
    )
    reports_data = reports_resp.get("data") or []
    report_summary = summarize_reports(reports_data)

    reporter_id: Optional[str] = None
    reporter_attrs: Dict[str, Any] = {}
    if reports_data:
        first_id = reports_data[0].get("id")
        if first_id:
            detail_resp = _api_get_json(
                f"{root}/v1/hackers/reports/{first_id}",
                auth_header,
                timeout=timeout,
            )
            reporter_node = (
                (detail_resp.get("data") or {})
                .get("relationships", {})
                .get("reporter", {})
                .get("data", {})
            )
            reporter_id = reporter_node.get("id")
            reporter_attrs = dict(reporter_node.get("attributes") or {})

    effective_username = str(reporter_attrs.get("username") or username)
    graphql_attrs = fetch_public_graphql_profile(effective_username, timeout=timeout)
    for key, val in graphql_attrs.items():
        if val not in (None, ""):
            reporter_attrs[key] = val

    balance_data: Dict[str, Any] = {}
    try:
        balance_resp = _api_get_json(
            f"{root}/v1/hackers/payments/balance",
            auth_header,
            timeout=timeout,
        )
        balance_data = balance_resp.get("data") or {}
    except urllib.error.HTTPError as exc:
        balance_data = {"error": f"HTTP {exc.code}"}

    completeness = evaluate_profile_completeness(reporter_attrs)
    return {
        "username": effective_username,
        "user_id": reporter_id,
        "profile": reporter_attrs,
        "completeness": completeness,
        "reports": report_summary,
        "balance": balance_data,
        "edit_url": HACKERONE_EDIT_PROFILE_URL,
    }


def render_dashboard(snapshot: Dict[str, Any]) -> str:
    """Format a human-readable terminal audit report for a HackerOne researcher snapshot."""
    profile = snapshot.get("profile") or {}
    comp = snapshot.get("completeness") or {}
    reports = snapshot.get("reports") or {}
    balance = snapshot.get("balance") or {}

    intro = str(profile.get("intro") or "").strip()
    intro_preview = f"{len(intro)} chars" if intro else "(empty)"
    if intro and _is_intro_truncated(intro):
        intro_preview += f" [TRUNCATED at '...{intro[-32:]}']"

    lines: List[str] = [
        "==============================================================================",
        " ORBIT SECURITY :: HACKERONE LIVE PROFILE & PORTFOLIO AUDIT",
        "==============================================================================",
        f" Handle:       @{snapshot.get('username')} (User ID: {snapshot.get('user_id') or 'N/A'})",
        f" Name:         {profile.get('name') or '(empty)'}",
        f" Reputation:   {profile.get('reputation', 'N/A')}",
        f" Location:     {profile.get('location') or '(empty)'}",
        f" Website:      {profile.get('website') or '(empty)'}",
        f" Bio:          {profile.get('bio') or '(empty)'}",
        f" Intro:        {intro_preview}",
        f" LinkedIn:     {profile.get('linkedin_handle') or '(empty)'}",
        f" GitHub:       {profile.get('github_handle') or '(empty)'}",
        f" X / Twitter:  {profile.get('twitter_handle') or '(empty)'}",
        f" Balance:      {balance.get('balance', 'N/A')} {balance.get('currency', '')}".rstrip(),
        "------------------------------------------------------------------------------",
        f" Readiness Score: {comp.get('score', 0)}/{comp.get('max_score', 100)}",
        "------------------------------------------------------------------------------",
    ]

    for field, check in (comp.get("checks") or {}).items():
        status = "PASS" if check.get("passed") else "FAIL"
        lines.append(
            f" [{status}] {field:<16} ({check.get('points', 0):>2}/{check.get('max_points', 0):>2}) - {check.get('detail')}"
        )

    lines.extend(
        [
            "------------------------------------------------------------------------------",
            f" Active Reports ({reports.get('total', 0)}): {reports.get('by_state', {})}",
        ]
    )
    for rep in reports.get("reports") or []:
        lines.append(f"  - #{rep.get('id')} [{rep.get('state')}] {rep.get('title')}")

    recs = comp.get("recommendations") or []
    lines.append("------------------------------------------------------------------------------")
    if recs:
        lines.append(f" Action Items (Update at {snapshot.get('edit_url')}):")
        for idx, rec in enumerate(recs, start=1):
            lines.append(f"  {idx}. {rec}")
    else:
        lines.append(" Status: Profile meets 100/100 professional researcher standards.")
    lines.append("==============================================================================")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit live HackerOne researcher profile readiness via Hacker REST API v1."
    )
    parser.add_argument(
        "--env-path",
        type=Path,
        default=DEFAULT_ENV_PATH,
        help="Path to .env containing HACKERONE_API_USERNAME and HACKERONE_API_TOKEN.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    args = parser.parse_args(argv)

    try:
        username, token = load_hackerone_credentials(env_path=args.env_path)
        snapshot = fetch_hackerone_profile_snapshot(username, token)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(snapshot, indent=2))
    else:
        print(render_dashboard(snapshot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
