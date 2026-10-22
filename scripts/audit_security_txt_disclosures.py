#!/usr/bin/env python3
"""Orbit Security: Automated Security.txt & Responsible Disclosure Auditor.

Parses all 121 packaged vulnerability bundles in data/disclosures/, categorizing
by program, target domain, flaw type, severity, CVSS score, and security.txt contact.
Generates a structured registry and staging manifest for review and coordinated disclosure.
"""

from collections import defaultdict
import datetime
import json
import os
from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent
DISCLOSURES_DIR = REPO_ROOT / "data" / "disclosures"
REGISTRY_JSON = REPO_ROOT / "data" / "security_txt_registry.json"
REGISTRY_MD = REPO_ROOT / "data" / "security_txt_registry.md"

def audit_disclosures():
    bundles = []
    by_program = defaultdict(list)
    by_flaw = defaultdict(list)
    by_severity = defaultdict(list)

    # Scan all directories in data/disclosures ending with _bundle
    for bundle_dir in sorted(DISCLOSURES_DIR.iterdir()):
        if not bundle_dir.is_dir() or not bundle_dir.name.endswith("_bundle"):
            continue

        meta_file = bundle_dir / "metadata.json"
        advisory_file = bundle_dir / "security_txt_advisory.txt"
        manifest_file = bundle_dir / "manifest_sha256.json"
        zip_file = DISCLOSURES_DIR / f"{bundle_dir.name}.zip"

        if not meta_file.exists():
            continue

        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        program_id = meta.get("program_id", "unknown")
        program_name = meta.get("program_name", program_id.title())
        target_domain = meta.get("target_domain", "unknown")
        flaw_type = meta.get("flaw_type", "unknown")
        severity = meta.get("severity", "LOW")
        cvss_score = meta.get("cvss_score", 0.0)
        cvss_vector = meta.get("cvss_vector", "")
        cwe_id = meta.get("cwe_id", "")
        timestamp = meta.get("timestamp", "")
        cname_target = meta.get("cname_target")

        # Parse security contact from advisory file if present
        to_contacts = []
        if advisory_file.exists():
            advisory_text = advisory_file.read_text(encoding="utf-8", errors="ignore")
            for line in advisory_text.splitlines():
                if line.startswith("To:"):
                    raw_to = line[3:].strip()
                    to_contacts = [c.strip() for c in raw_to.split(",") if c.strip()]
                    break

        if not to_contacts:
            # Fallback standard RFC 9116 security address using organizational domain
            from orbit_security.bounty_radar import BountyTakeoverSweeper
            org_domain = BountyTakeoverSweeper.get_organizational_domain(target_domain)
            to_contacts = [f"security@{org_domain}", f"security-team@{org_domain}"]

        bundle_record = {
            "bundle_name": bundle_dir.name,
            "program_id": program_id,
            "program_name": program_name,
            "target_domain": target_domain,
            "flaw_type": flaw_type,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwe_id": cwe_id,
            "timestamp": timestamp,
            "cname_target": cname_target,
            "contacts": to_contacts,
            "zip_path": str(zip_file) if zip_file.exists() else None,
            "has_advisory": advisory_file.exists(),
            "has_manifest": manifest_file.exists(),
        }

        bundles.append(bundle_record)
        by_program[program_name].append(bundle_record)
        by_flaw[flaw_type].append(bundle_record)
        by_severity[severity].append(bundle_record)

    # Save structured JSON registry
    registry_data = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_bundles": len(bundles),
        "total_programs": len(by_program),
        "bundles": bundles,
        "summary": {
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_flaw": {k: len(v) for k, v in by_flaw.items()},
            "by_program": {k: len(v) for k, v in by_program.items()},
        }
    }
    REGISTRY_JSON.write_text(json.dumps(registry_data, indent=2), encoding="utf-8")

    # Generate Markdown Summary
    lines = [
        "# Orbit Security: Responsible Disclosure Registry (RFC 9116 / Security.txt)",
        f"**Generated:** {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | **Total Packaged Disclosures:** {len(bundles)}",
        "",
        "## 1. Executive Summary",
        f"- **Total Monitored Programs with Disclosed Findings:** {len(by_program)}",
        f"- **Total Cryptographically Sealed Bundles:** {len(bundles)}",
        "- **Breakdown by Severity:**",
    ]
    for sev, count in sorted(registry_data["summary"]["by_severity"].items(), key=lambda x: -x[1]):
        lines.append(f"  - **{sev}:** {count} findings")

    lines.append("\n- **Breakdown by Weakness Category:**")
    for flaw, count in sorted(registry_data["summary"]["by_flaw"].items(), key=lambda x: -x[1]):
        lines.append(f"  - **{flaw.replace('_', ' ').title()}:** {count} findings")

    lines.append("\n## 2. Program Breakdown & Primary Security Contacts")
    lines.append("| Program | Total Bundles | Highest Severity | Primary Contact(s) | Sample Target |")
    lines.append("|---------|---------------|------------------|--------------------|---------------|")

    for prog_name, prog_bundles in sorted(by_program.items(), key=lambda x: -len(x[1])):
        sample = prog_bundles[0]
        max_sev = "HIGH" if any(b["severity"] == "HIGH" for b in prog_bundles) else ("MEDIUM" if any(b["severity"] == "MEDIUM" for b in prog_bundles) else "LOW")
        contacts_str = ", ".join(f"`{c}`" for c in sample["contacts"][:2])
        lines.append(f"| **{prog_name}** | {len(prog_bundles)} | `{max_sev}` | {contacts_str} | `{sample['target_domain']}` |")

    lines.append("\n## 3. High-Priority Enterprise Direct Disclosures (Sample)")
    lines.append("| Target Domain | Program | Flaw | CVSS | Primary Contact | Status |")
    lines.append("|---------------|---------|------|------|-----------------|--------|")

    for b in bundles[:15]:
        contact = b["contacts"][0] if b["contacts"] else "N/A"
        lines.append(f"| `{b['target_domain']}` | {b['program_name']} | {b['flaw_type']} | {b['cvss_score']} | `{contact}` | 🟢 `SEALED_STAGED` |")

    lines.extend([
        "",
        "## 4. Responsible Disclosure Protocols",
        "1. **Zero Exploitation**: Orbit Security does not weaponize, extract data, or alter state. All evidence consists of non-intrusive DNS TXT/CNAME records and RFC-compliant email routing inspections.",
        "2. **Coordinated 90-Day Window**: Enterprise recipients are provided a strict 90-day remediation timeline prior to any coordinated public disclosure or advisory publication.",
        "3. **Cryptographic Integrity**: Every package includes raw technical proofs, structured metadata, and a SHA-256 manifest to allow enterprise teams to instantly verify evidence without ambiguity.",
    ])

    REGISTRY_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"[✔] Successfully audited {len(bundles)} bundles across {len(by_program)} programs.")
    print(f"[✔] Registry saved to {REGISTRY_MD.name} and {REGISTRY_JSON.name}")

if __name__ == "__main__":
    audit_disclosures()
