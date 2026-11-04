"""
triage_hackerone_staging.py
Sorts raw orbit-security disclosures into clean HackerOne triage tiers.
"""
import os
import glob
import shutil
import re
from pathlib import Path

def main():
    base_dir = Path(r"C:\AgyHut\projects\orbit-security\data")
    disc_dir = base_dir / "disclosures"
    staging_dir = base_dir / "hackerone_staging"

    ready_dir = staging_dir / "01_ready_for_submission"
    verify_dir = staging_dir / "02_needs_session_verification"
    archive_dir = staging_dir / "03_out_of_scope_archive"

    for d in [ready_dir, verify_dir, archive_dir]:
        d.mkdir(parents=True, exist_ok=True)

    md_files = list(disc_dir.glob("*.md"))
    print(f"Total markdown disclosures to triage: {len(md_files)}")

    categorized = {"ready": [], "verify": [], "archive": []}

    for md in md_files:
        content = md.read_text(encoding="utf-8")
        name = md.name
        zip_name = md.stem + "_bundle.zip"
        zip_path = disc_dir / zip_name

        if "Mail Spoofing" in content or "CWE-290" in content:
            dest = archive_dir
            reason = "Missing DMARC/SPF - universally excluded from HackerOne bounties"
            categorized["archive"].append((name, reason))
        elif "Graphql Introspection" in content or "CWE-200" in content:
            dest = archive_dir
            reason = "GraphQL schema introspection on public API - documented vendor behavior"
            categorized["archive"].append((name, reason))
        elif "Cloud Storage Takeover" in content:
            dest = archive_dir
            reason = "No dangling CNAME (Cloudflare/GCP proxy false positive)"
            categorized["archive"].append((name, reason))
        elif "Open Cloud Bucket" in content:
            dest = verify_dir
            reason = "Spotify CDN bucket listing - requires inspection for non-public assets"
            categorized["verify"].append((name, reason))
        elif "Cors Arbitrary Origin With Credentials" in content or "CWE-942" in content:
            dest = verify_dir
            reason = "CORS credentials reflected - requires authenticated endpoint check for private data"
            categorized["verify"].append((name, reason))
        else:
            dest = archive_dir
            reason = "Unclassified or informational finding"
            categorized["archive"].append((name, reason))

        shutil.copy2(md, dest / name)
        if zip_path.exists():
            shutil.copy2(zip_path, dest / zip_name)

    print(f"Archived (Out-of-Scope / Junk): {len(categorized['archive'])}")
    print(f"Needs Session Verification (CORS / Bucket): {len(categorized['verify'])}")
    print(f"Ready for Direct Submission: {len(categorized['ready'])}")

    # Write a triage manifest
    manifest_path = staging_dir / "TRIAGE_MANIFEST.md"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("# HackerOne Staging Triage Manifest\n\n")
        f.write(f"Generated on 2026-11-03.\n\n")
        f.write("## 1. High Potential Candidates (Needs Session/PII Verification)\n")
        f.write("These have confirmed CORS arbitrary origin reflection with `Access-Control-Allow-Credentials: true` or open storage listings. Before submitting to HackerOne, test an authenticated endpoint with real cookies to capture proof of user data exposure.\n\n")
        f.write("| File | Reason / Target |\n")
        f.write("| :--- | :--- |\n")
        for name, reason in categorized["verify"]:
            f.write(f"| `{name}` | {reason} |\n")

        f.write("\n## 2. Archived / Out of Scope (DO NOT SUBMIT)\n")
        f.write("Submitting these will result in immediate N/A closures and HackerOne reputation deductions (-7 reputation per N/A).\n\n")
        f.write("| File | Reason for Exclusion |\n")
        f.write("| :--- | :--- |\n")
        for name, reason in sorted(categorized["archive"]):
            f.write(f"| `{name}` | {reason} |\n")

    print(f"Wrote triage manifest to: {manifest_path}")

if __name__ == "__main__":
    main()
