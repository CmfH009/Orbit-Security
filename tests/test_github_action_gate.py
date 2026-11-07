"""Unit tests for the Turn-Key GitHub Action PR Security Gate (Option 3)."""

from __future__ import annotations

from pathlib import Path
import yaml
import pytest

from scripts.github_action_entrypoint import (
    run_ci_security_gate,
    render_step_summary_markdown,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_action_yml_manifest_is_valid_composite_action():
    action_path = REPO_ROOT / "action.yml"
    assert action_path.exists(), "action.yml must exist at repository root"

    data = yaml.safe_load(action_path.read_text(encoding="utf-8"))
    assert data["name"] == "Orbit Security — CI/CD PR & Perimeter Gate"
    assert "description" in data
    assert data["runs"]["using"] == "composite"
    assert "target-path" in data["inputs"]
    assert "scan-types" in data["inputs"]
    assert "fail-on-findings" in data["inputs"]
    assert "verdict" in data["outputs"]


def test_run_ci_security_gate_passes_on_clean_directory(tmp_path: Path):
    src_dir = tmp_path / "clean_pkg"
    src_dir.mkdir()
    (src_dir / "app.py").write_text(
        "import json\n\ndef serialize(data: dict) -> str:\n    return json.dumps(data)\n",
        encoding="utf-8",
    )

    summary_file = tmp_path / "step_summary.md"
    output_file = tmp_path / "github_output.txt"

    report = run_ci_security_gate(
        target_path=src_dir,
        scan_types=["ast", "secrets", "cisa-kev"],
        diff_text="feat(app): add clean json serializer",
        step_summary_path=summary_file,
        github_output_path=output_file,
    )

    assert report["passed"] is True
    assert report["verdict"] == "PASS"
    assert report["files_scanned"] == 1
    assert report["findings_count"] == 0
    assert summary_file.exists()
    assert "PASS" in summary_file.read_text(encoding="utf-8")
    assert "verdict=PASS" in output_file.read_text(encoding="utf-8")


def test_run_ci_security_gate_detects_cisa_kev_and_missing_imports(tmp_path: Path):
    bad_dir = tmp_path / "broken_pkg"
    bad_dir.mkdir()
    # Uses time.sleep without importing time
    (bad_dir / "worker.py").write_text(
        "def pause():\n    return time.sleep(1)\n",
        encoding="utf-8",
    )

    report = run_ci_security_gate(
        target_path=bad_dir,
        scan_types=["ast", "cisa-kev"],
        diff_text="bump dependency with CVE-2021-44228",
    )

    assert report["passed"] is False
    assert report["verdict"] == "FAIL"
    assert report["findings_count"] >= 2
    assert "CVE-2021-44228" in report["cisa_kev_hits"]


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
