"""Unit tests for the Turn-Key GitHub Action PR Security Gate & SARIF 2.1.0 Exporter."""

from __future__ import annotations

import json
from pathlib import Path
import yaml
import pytest

from scripts.github_action_entrypoint import (
    run_ci_security_gate,
    render_step_summary_markdown,
    build_sarif_report,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_action_yml_manifest_is_valid_and_backwards_compatible():
    action_path = REPO_ROOT / "action.yml"
    assert action_path.exists(), "action.yml must exist at repository root"

    data = yaml.safe_load(action_path.read_text(encoding="utf-8"))
    assert "Orbit Security" in data["name"]
    assert "description" in data
    assert data["runs"]["using"] == "composite"

    # CI/CD PR & Static AST Gate inputs
    assert "target-path" in data["inputs"]
    assert "scan-types" in data["inputs"]
    assert "fail-on-findings" in data["inputs"]
    assert "sarif-output" in data["inputs"]

    # Backwards-compatible Perimeter Sentinel inputs (used by orbit-perimeter-sentinel.yml)
    assert "target" in data["inputs"]
    assert "targets-file" in data["inputs"]
    assert "fail-on-critical" in data["inputs"]
    assert "markdown-summary" in data["inputs"]
    assert "export-markdown" in data["inputs"]

    assert "verdict" in data["outputs"]


def test_run_ci_security_gate_passes_on_clean_directory_and_writes_sarif(tmp_path: Path):
    src_dir = tmp_path / "clean_pkg"
    src_dir.mkdir()
    (src_dir / "app.py").write_text(
        "import json\n\ndef serialize(data: dict) -> str:\n    return json.dumps(data)\n",
        encoding="utf-8",
    )

    summary_file = tmp_path / "step_summary.md"
    output_file = tmp_path / "github_output.txt"
    sarif_file = tmp_path / "orbit.sarif"

    report = run_ci_security_gate(
        target_path=src_dir,
        scan_types=["ast", "secrets", "cisa-kev"],
        diff_text="feat(app): add clean json serializer",
        step_summary_path=summary_file,
        github_output_path=output_file,
        sarif_output_path=sarif_file,
    )

    assert report["passed"] is True
    assert report["verdict"] == "PASS"
    assert report["files_scanned"] == 1
    assert report["findings_count"] == 0
    assert summary_file.exists()
    assert "PASS" in summary_file.read_text(encoding="utf-8")
    assert "verdict=PASS" in output_file.read_text(encoding="utf-8")

    assert sarif_file.exists()
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif_data["runs"][0]["results"] == []


def test_run_ci_security_gate_detects_findings_and_emits_compliant_sarif(tmp_path: Path):
    bad_dir = tmp_path / "broken_pkg"
    bad_dir.mkdir()
    # Uses time.sleep without importing time + eval() sink
    (bad_dir / "worker.py").write_text(
        "def pause(expr: str):\n    eval(expr)\n    return time.sleep(1)\n",
        encoding="utf-8",
    )

    sarif_file = tmp_path / "findings.sarif"
    report = run_ci_security_gate(
        target_path=bad_dir,
        scan_types=["ast", "secrets", "cisa-kev"],
        diff_text="bump dependency with CVE-2021-44228",
        sarif_output_path=sarif_file,
    )

    assert report["passed"] is False
    assert report["verdict"] == "FAIL"
    assert report["findings_count"] >= 3
    assert "CVE-2021-44228" in report["cisa_kev_hits"]

    sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert "ORBIT-AST-001" in rule_ids
    assert "CWE-95" in rule_ids
    assert "ORBIT-KEV-001" in rule_ids

    results = run["results"]
    assert len(results) >= 3
    for res in results:
        assert len(res["locations"]) >= 1
        loc = res["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        assert "\\" not in uri, f"URI must be POSIX relative path without backslashes: {uri}"
        assert ":" not in uri, f"URI must not contain Windows drive letter: {uri}"
        assert loc["region"]["startLine"] >= 1


def test_render_step_summary_markdown_formats_table():
    sample_report = {
        "verdict": "PASS",
        "passed": True,
        "files_scanned": 12,
        "findings_count": 0,
        "ast_issues": [],
        "vuln_graph_findings": [],
        "cisa_kev_hits": [],
    }
    md = render_step_summary_markdown(sample_report)
    assert "## 🛡️ Orbit Security CI/CD Gate" in md
    assert "| Engine | Status | Details |" in md
    assert "12 Python files scanned" in md
