#!/usr/bin/env python3
"""
triage_and_verify_disclosures.py: Archives low-signal informational disclosures
(mail_spoofing on non-MX subdomains, unauthenticated cors_wildcard_origin) into
data/disclosures/archived_informational/ and runs live OperatorExploitSandbox
verification + HMAC-SHA256 receipt signing on all remaining high-signal candidates.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from orbit_security.exploit_sandbox import OperatorExploitSandbox


def main() -> int:
    disc_dir = ROOT / "data" / "disclosures"
    arch_dir = disc_dir / "archived_informational"
    mit_dir = disc_dir / "archived_mitigated"
    arch_dir.mkdir(parents=True, exist_ok=True)
    mit_dir.mkdir(parents=True, exist_ok=True)

    moved = 0
    for p in list(disc_dir.iterdir()):
        if p.is_file() and ("mail_spoofing" in p.name or "cors_wildcard_origin" in p.name):
            shutil.move(str(p), str(arch_dir / p.name))
            moved += 1

    remaining_md = sorted(disc_dir.glob("*.md"))
    print(f"Archived informational files: {moved}")
    print(f"Remaining high-signal .md disclosures: {len(remaining_md)}")

    receipts = []
    from dataclasses import asdict, is_dataclass
    for md in remaining_md:
        ver_obj = OperatorExploitSandbox.verify_vulnerability(md, timeout=6.0)
        ver = ver_obj.to_dict() if hasattr(ver_obj, "to_dict") else (asdict(ver_obj) if is_dataclass(ver_obj) else dict(ver_obj))
        diff_info = ver.get("diff", {}) if isinstance(ver.get("diff"), dict) else {}
        exec_info = ver.get("execution", {}) if isinstance(ver.get("execution"), dict) else {}
        is_conf = bool(diff_info.get("is_confirmed"))
        stdout_text = str(exec_info.get("stdout") or "")
        target_dom = str(ver.get("target_domain") or md.stem)
        flaw_t = str(ver.get("flaw_type") or "unknown")
        finding = {
            "target_domain": target_dom,
            "flaw_type": flaw_t,
            "evidence": stdout_text[:300],
            "mock_execution": {
                "exit_code": exec_info.get("exit_code", 0),
                "stdout": stdout_text,
                "stderr": str(exec_info.get("stderr") or ""),
                "duration_ms": float(exec_info.get("duration_ms") or 0.0),
                "status_code": exec_info.get("status_code") or (200 if is_conf else 404),
                "response_body_preview": stdout_text[:400],
            },
        }
        rec = OperatorExploitSandbox.generate_signed_verification_receipt(finding)
        rec["filename"] = md.name
        rec["live_confirmed"] = is_conf
        rec["live_verdict"] = "CONFIRMED_LIVE" if is_conf else "NOT_REPRODUCED_OR_MITIGATED"
        rec["live_stdout_snippet"] = stdout_text.strip()[:260]
        if not is_conf:
            shutil.move(str(md), str(mit_dir / md.name))
        receipts.append(rec)
        print(
            f"  [{rec['live_verdict']}] {md.name} -> target={target_dom} "
            f"flaw={flaw_t} status={exec_info.get('status_code')} receipt={rec['receipt_id']}"
        )

    confirmed_count = sum(1 for r in receipts if r["live_confirmed"])
    out_file = disc_dir / "live_verification_receipts.json"
    out_file.write_text(
        json.dumps(
            {
                "total_high_signal": len(receipts),
                "confirmed_live_count": confirmed_count,
                "archived_informational_count": moved,
                "receipts": receipts,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Saved {len(receipts)} verification receipts ({confirmed_count} confirmed live) -> {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
