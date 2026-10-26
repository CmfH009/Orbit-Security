#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/run_opencode_remediation.py: CLI Harness for OpenCode Autonomous Remediation
===================================================================================
Executes autonomous patch synthesis for security vulnerabilities, perimeters,
and configuration omissions discovered by Orbit Security.

Usage Examples:
    python scripts/run_opencode_remediation.py --domain example.com --title "Exposed .git directory" --severity CRITICAL
    python scripts/run_opencode_remediation.py --domain agency.com --title "Missing DMARC Policy" --severity HIGH --fallback-only
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.opencode_remediation import OpenCodeRemediationSynthesizer


def main():
    parser = argparse.ArgumentParser(description="Orbit OpenCode Autonomous Remediation Synthesizer")
    parser.add_argument("--domain", type=str, required=True, help="Target domain (e.g. client.com)")
    parser.add_argument("--id", type=str, default="VULN-001", help="Finding or vulnerability ID")
    parser.add_argument("--title", type=str, required=True, help="Finding title (e.g. 'Exposed .env file')")
    parser.add_argument("--severity", type=str, default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    parser.add_argument("--desc", type=str, default="", help="Description of finding")
    parser.add_argument("--evidence", type=str, default="", help="Observed evidence or HTTP response snippet")
    parser.add_argument("--fallback-only", action="store_true", help="Force deterministic rule fallback (skip CLI subprocess)")
    parser.add_argument("--json", action="store_true", help="Output JSON result only")

    args = parser.parse_args()

    synthesizer = OpenCodeRemediationSynthesizer()
    desc = args.desc or f"Vulnerability {args.title} discovered during Orbit Security perimeter audit on {args.domain}."

    artifact = synthesizer.synthesize_remediation(
        domain=args.domain,
        finding_id=args.id,
        finding_title=args.title,
        severity=args.severity,
        description=desc,
        evidence=args.evidence,
        force_fallback=args.fallback_only,
    )

    if args.json:
        print(json.dumps(artifact.to_dict(), indent=2))
    else:
        status_icon = "✓" if artifact.verification_passed else "❌"
        print(f"\n=======================================================")
        print(f" Orbit OpenCode Remediation Sentinel")
        print(f"=======================================================")
        print(f" Target Domain : {artifact.domain}")
        print(f" Finding       : {artifact.finding_title} [{artifact.severity}]")
        print(f" Target Layer  : {artifact.target_component.upper()}")
        print(f" Generator     : {artifact.generator}")
        print(f" Verification  : {status_icon} {artifact.verification_notes}")
        print(f" Patch File    : {artifact.file_path}")
        print(f" Commit Message: {artifact.commit_message}")
        print(f"\n--- [Synthesized Patch Preview] ---")
        preview = artifact.patch_content[:500] + ("..." if len(artifact.patch_content) > 500 else "")
        print(preview)
        print(f"-------------------------------------------------------\n")


if __name__ == "__main__":
    main()
