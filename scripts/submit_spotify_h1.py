#!/usr/bin/env python3
"""submit_spotify_h1.py: One-command HackerOne API dispatcher for Spotify's open GCS bucket (spaa-cdn).

Safe-by-default CLI (defaults to --dry-run) that verifies duplicate protection, optionally checks
live HTTP 200 status on both cdn.pdst.fm (Podsights Scope 95514) and cdn.byspotify.com (*.byspotify.com
Scope 637130), and submits via POST /v1/hackers/reports when --live is specified after Persona KYC.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from audit_hackerone_profile import DEFAULT_ENV_PATH, HACKERONE_API_BASE, load_hackerone_credentials

SPOTIFY_TEAM_HANDLE = "spotify"
SPOTIFY_PODSIGHTS_SCOPE_ID = 95514
SPOTIFY_WEAKNESS_CWE200_ID = 18
BUCKET_HOSTS = ("https://cdn.pdst.fm/", "https://cdn.byspotify.com/")
SAMPLE_OBJECT_PATH = "interviews/Podsights%20Seed%20-%20Interview%20Version.pdf"
DUPLICATE_MARKERS = ("byspotify.com", "pdst.fm", "spaa-cdn")


def build_spotify_report_payload() -> Dict[str, Any]:
    """Build the HackerOne API v1 report submission payload for bucket spaa-cdn."""
    vuln_info = (
        "## Summary\n"
        "During a non-destructive security posture assessment of in-scope assets under Spotify's Bug Bounty Program, "
        "an open public Google Cloud Storage bucket directory listing (`<Name>spaa-cdn</Name>`) was verified on both:\n"
        "- **`https://cdn.pdst.fm/`** — Explicitly listed in Spotify's **Podsights** scope "
        "(Scope ID `95514`, `eligible_for_bounty: true`, `max_severity: critical`)\n"
        "- **`https://cdn.byspotify.com/`** — In scope under `*.byspotify.com` "
        "(Scope ID `637130`, `eligible_for_bounty: true`)\n\n"
        "Both hostnames serve the identical 24,981-byte XML `<ListBucketResult>` index (`GET /`, `HTTP 200 OK`) "
        "for bucket `spaa-cdn`, allowing any unauthenticated internet actor to enumerate all stored object keys "
        "and download non-public Podsights internal documents, including:\n"
        "1. `interviews/Podsights Seed - Interview Version.pdf` (`2,153,328` bytes / 2.1 MB)\n"
        "2. `interviews/AP Q4-2020 Podcast Adv. Rept_4Ww1Disc.Mtg.pdf` (5.3 MB)\n"
        "3. `reports/benchmarks/test-q3-podsights-conversion-report.pdf`\n"
        "4. `advisor/advisor-onboarding-demo.mp4` (18.1 MB)\n\n"
        "## Steps to Reproduce\n"
        "1. Query the root XML bucket listing on both in-scope hosts:\n"
        "   ```bash\n"
        "   curl -i -s https://cdn.pdst.fm/\n"
        "   curl -i -s https://cdn.byspotify.com/\n"
        "   ```\n"
        "2. Observe `HTTP 200 OK` (`Content-Type: application/xml`) returning `<ListBucketResult><Name>spaa-cdn</Name>` "
        "with full object keys, sizes, and modification timestamps.\n"
        "3. Perform a non-destructive `HEAD` check against an exposed internal Podsights PDF:\n"
        "   ```bash\n"
        f'   curl -sI "https://cdn.pdst.fm/{SAMPLE_OBJECT_PATH}"\n'
        f'   curl -sI "https://cdn.byspotify.com/{SAMPLE_OBJECT_PATH}"\n'
        "   ```\n"
        "4. Observe `HTTP 200 OK`, `Content-Type: application/pdf`, `Content-Length: 2153328` without authentication.\n\n"
        "## Safe Harbor & Non-Destructive Testing Attestation\n"
        "Only public `GET /` directory enumeration and HTTP `HEAD` size/type checks were performed. "
        "No bulk files were exfiltrated or modified.\n\n"
        "## Suggested Remediation\n"
        "1. Remove public `storage.objects.list` / `s3:ListBucket` permissions for `allUsers` and "
        "`allAuthenticatedUsers` on bucket `spaa-cdn`.\n"
        "2. Restrict public read access strictly to intended public static assets and relocate internal pitch decks, "
        "partner advertising reports, and onboarding recordings to a private authenticated bucket.\n"
        "3. Enable GCS Public Access Prevention / uniform bucket-level access enforcement."
    )

    impact = (
        "Unauthenticated external actors can enumerate the entire XML bucket index "
        "(<ListBucketResult> for bucket 'spaa-cdn') on both cdn.pdst.fm and cdn.byspotify.com and "
        "directly download non-public Podsights acquisition/seed investor pitch decks, partner "
        "advertising reports, benchmark PDFs, and internal advisor onboarding videos."
    )

    return {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": SPOTIFY_TEAM_HANDLE,
                "title": (
                    "Open Public GCS Bucket (spaa-cdn) Directory Listing Exposing Internal "
                    "Podsights Pitch Decks & Partner Reports on cdn.pdst.fm and cdn.byspotify.com"
                ),
                "vulnerability_information": vuln_info,
                "impact": impact,
                "severity_rating": "medium",
                "weakness_id": SPOTIFY_WEAKNESS_CWE200_ID,
                "structured_scope_id": SPOTIFY_PODSIGHTS_SCOPE_ID,
            },
        }
    }


def has_existing_spotify_report(reports_data: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Return (True, report_id) if an existing report already covers cdn.pdst.fm / cdn.byspotify.com."""
    for item in reports_data:
        title = str((item.get("attributes") or {}).get("title") or "").lower()
        if any(marker in title for marker in DUPLICATE_MARKERS):
            return True, str(item.get("id") or "")
    return False, None


def verify_live_bucket(timeout: int = 15) -> Dict[str, Any]:
    """Perform read-only verification of spaa-cdn XML listing and PDF HEAD access."""
    endpoints: List[Dict[str, Any]] = []
    pdf_heads: List[Dict[str, Any]] = []
    headers = {"User-Agent": "OrbitSecurity-HackerOneVerify/1.0"}

    try:
        for base in BUCKET_HOSTS:
            req = urllib.request.Request(base, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                match = re.search(r"<Name>([^<]+)</Name>", body)
                bucket_name = match.group(1) if match else None
                endpoints.append(
                    {
                        "url": base,
                        "status": resp.status,
                        "bucket_name": bucket_name,
                        "has_list_bucket": "<ListBucketResult" in body,
                        "body_bytes": len(body),
                    }
                )

            head_url = f"{base}{SAMPLE_OBJECT_PATH}"
            head_req = urllib.request.Request(head_url, method="HEAD", headers=headers)
            with urllib.request.urlopen(head_req, timeout=timeout) as head_resp:
                pdf_heads.append(
                    {
                        "url": head_url,
                        "status": head_resp.status,
                        "content_length": head_resp.headers.get("Content-Length"),
                        "content_type": head_resp.headers.get("Content-Type"),
                    }
                )
    except Exception as exc:
        return {"ok": False, "error": str(exc), "endpoints": endpoints, "pdf_heads": pdf_heads}

    all_ok = (
        len(endpoints) == len(BUCKET_HOSTS)
        and all(ep["status"] == 200 and ep["has_list_bucket"] for ep in endpoints)
        and all(hd["status"] == 200 for hd in pdf_heads)
    )
    return {"ok": all_ok, "endpoints": endpoints, "pdf_heads": pdf_heads}


def _extract_error_detail(raw_body: str) -> Tuple[str, str]:
    """Extract parameter name and detail string from HackerOne JSON error payloads."""
    try:
        parsed = json.loads(raw_body)
        errors = parsed.get("errors") or []
        if errors:
            first = errors[0]
            param = str((first.get("source") or {}).get("parameter") or "")
            detail = str(first.get("detail") or first.get("title") or raw_body)
            return param, detail
    except Exception:
        pass
    return "", raw_body.strip()


def submit_spotify_report(
    username: str,
    api_token: str,
    *,
    dry_run: bool = True,
    verify_bucket: bool = False,
    base_url: str = HACKERONE_API_BASE,
    timeout: int = 20,
) -> Dict[str, Any]:
    """Validate duplicate state and submit (or dry-run) the Spotify report via HackerOne API v1."""
    credentials = base64.b64encode(f"{username}:{api_token}".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {credentials}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "OrbitSecurity-HackerOneDispatch/1.0",
    }
    root = base_url.rstrip("/")

    bucket_check: Optional[Dict[str, Any]] = None
    if verify_bucket:
        bucket_check = verify_live_bucket(timeout=timeout)
        if not bucket_check.get("ok"):
            return {
                "status": "LIVE_VERIFY_FAILED",
                "duplicate_found": False,
                "bucket_verification": bucket_check,
            }

    list_req = urllib.request.Request(f"{root}/v1/hackers/me/reports?page[size]=25", headers=headers)
    with urllib.request.urlopen(list_req, timeout=timeout) as resp:
        existing_reports = json.loads(resp.read().decode("utf-8")).get("data") or []

    dup_found, dup_id = has_existing_spotify_report(existing_reports)
    if dup_found:
        return {
            "status": "DUPLICATE_ABORTED",
            "duplicate_found": True,
            "existing_report_id": dup_id,
            "bucket_verification": bucket_check,
        }

    payload = build_spotify_report_payload()
    if dry_run:
        return {
            "status": "DRY_RUN_READY",
            "duplicate_found": False,
            "bucket_verification": bucket_check,
            "payload": payload,
        }

    post_req = urllib.request.Request(
        f"{root}/v1/hackers/reports",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(post_req, timeout=timeout) as resp:
            created = json.loads(resp.read().decode("utf-8")).get("data") or {}
            report_id = str(created.get("id") or "")
            attrs = created.get("attributes") or {}
            return {
                "status": "SUBMITTED",
                "http_status": resp.status,
                "duplicate_found": False,
                "report_id": report_id,
                "report_url": f"https://hackerone.com/reports/{report_id}" if report_id else None,
                "state": attrs.get("state"),
                "created_at": attrs.get("created_at"),
                "bucket_verification": bucket_check,
            }
    except urllib.error.HTTPError as exc:
        raw_err = exc.read().decode("utf-8", errors="ignore")
        param, detail = _extract_error_detail(raw_err)
        if exc.code == 400 and "id_verification" in f"{param} {detail}".lower():
            return {
                "status": "BLOCKED_KYC_ID_VERIFICATION",
                "http_status": exc.code,
                "duplicate_found": False,
                "error_detail": detail,
                "bucket_verification": bucket_check,
            }
        return {
            "status": "HTTP_ERROR",
            "http_status": exc.code,
            "duplicate_found": False,
            "error_detail": detail,
            "bucket_verification": bucket_check,
        }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Dispatch or dry-run Spotify spaa-cdn GCS bucket report via HackerOne API v1."
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Check duplicate state and build payload without POSTing (default).",
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        help="Submit the report live to POST /v1/hackers/reports.",
    )
    parser.add_argument(
        "--verify-bucket",
        action="store_true",
        help="Perform live read-only HTTP GET/HEAD verification on cdn.pdst.fm and cdn.byspotify.com.",
    )
    parser.add_argument(
        "--env-path",
        type=Path,
        default=DEFAULT_ENV_PATH,
        help="Path to .env containing HACKERONE_API_USERNAME and HACKERONE_API_TOKEN.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    args = parser.parse_args(argv)

    dry_run = not args.live
    try:
        username, token = load_hackerone_credentials(env_path=args.env_path)
        result = submit_spotify_report(
            username,
            token,
            dry_run=dry_run,
            verify_bucket=args.verify_bucket,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Status:          {result.get('status')}")
        print(f"Duplicate Found: {result.get('duplicate_found')}")
        if result.get("report_url"):
            print(f"Report URL:      {result.get('report_url')}")
        if result.get("error_detail"):
            print(f"Detail:          {result.get('error_detail')}")

    return 0 if result.get("status") in {"DRY_RUN_READY", "SUBMITTED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
