"""tests/test_triage_bounties.py: Unit tests for scripts/triage_bounties.py helper."""

from __future__ import annotations

from pathlib import Path
import sys
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from triage_bounties import (
    copy_to_clipboard,
    load_all_disclosures,
    parse_disclosure_file,
)


SAMPLE_DISCLOSURE = """# [Subdomain Takeover] Unclaimed AWS S3 Resource via Dangling CNAME on assets.example.com

**Program:** Example Corp (Hackerone)  
**Program Policy:** [https://hackerone.com/example](https://hackerone.com/example)  
**Asset (In-Scope Target):** `assets.example.com`  
**Weakness:** `CWE-284: Improper Access Control`  
**Severity:** `HIGH` (CVSS 3.1: **7.5**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`  
**Bounty Viability Grade:** `HIGH_CONFIDENCE`  
**Date Discovered:** 2026-10-03T11:00:00.000000+00:00  

---

## 1. Summary
> [!TIP] **High-Value P1/P2 Bounty Finding**
Dangling CNAME matched AWS S3 NoSuchBucket.
"""


def test_parse_disclosure_file(tmp_path):
    report_file = tmp_path / "example_takeover.md"
    report_file.write_text(SAMPLE_DISCLOSURE, encoding="utf-8")

    parsed = parse_disclosure_file(report_file)
    assert parsed is not None
    assert parsed["target_domain"] == "assets.example.com"
    assert parsed["program"] == "Example Corp (Hackerone)"
    assert parsed["severity"] == "HIGH (CVSS 3.1: **7.5**)"
    assert parsed["viability"] == "HIGH_CONFIDENCE"
    assert "CWE-284" in parsed["weakness"]
    assert "2026-10-03" in parsed["date_discovered"]


def test_load_all_disclosures(tmp_path):
    f1 = tmp_path / "finding1.md"
    f1.write_text(SAMPLE_DISCLOSURE, encoding="utf-8")

    loaded = load_all_disclosures(disclosures_dir=tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["target_domain"] == "assets.example.com"


def test_copy_to_clipboard_mocked():
    with patch("subprocess.Popen") as mock_popen:
        mock_proc = mock_popen.return_value
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0

        success = copy_to_clipboard("test text")
        assert success is True
