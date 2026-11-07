#!/usr/bin/env python3
"""Orbit Security — Composite GitHub Action Entrypoint.

Executes the Orbit Security CI/CD PR & Perimeter Gate across three engines:
  1. AST Code Sentinel (unresolved stdlib symbols & syntax verification)
  2. Static AST Vulnerability & Secret Graph (CWE-78, CWE-95, CWE-502, CWE-798)
  3. CISA KEV Pull Request & Dependency Auditor (actively exploited CVEs)

Emits GitHub Actions annotations (`::error`) and writes a rich Markdown report
to `$GITHUB_STEP_SUMMARY` and structured outputs to `$GITHUB_OUTPUT`.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path and SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.ast_sentinel import ASTCodeSentinel
from orbit_security.github_sentinel import GitHubPRAuditor


def _collect_git_diff(cwd: Path) -> str:
    """Collects the latest git commit diff if running inside a git repository."""
    try:
        res = subprocess.run(
            ["git", "diff", "HEAD~1..HEAD"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            return res.stdout
    except Exception:
        pass
    return ""


def render_step_summary_markdown(report: Dict[str, Any]) -> str:
    """Renders a GitHub Actions Step Summary Markdown table from the gate report."""
    verdict = report["verdict"]
    badge = "✅ **PASS**" if report["passed"] else "❌ **FAIL**"
    files_scanned = report["files_scanned"]
    ast_issues = report.get("ast_issues", [])
    vuln_findings = report.get("vuln_graph_findings", [])
    kev_hits = report.get("cisa_kev_hits", [])

    ast_status = "PASS" if not ast_issues else f"FAIL ({len(ast_issues)} issue(s))"
    vuln_status = "PASS" if not vuln_findings else f"FAIL ({len(vuln_findings)} finding(s))"
    kev_status = "PASS" if not kev_hits else f"FAIL ({len(kev_hits)} KEV hit(s))"

    lines = [
        f"## 🛡️ Orbit Security CI/CD Gate — {badge}",
        "",
        "| Engine | Status | Details |",
        "|---|---|---|",
        f"| **AST Code Sentinel** | `{ast_status}` | {files_scanned} Python files scanned |",
        f"| **Static Secret & Sink Graph** | `{vuln_status}` | CWE-78 / CWE-95 / CWE-502 / CWE-798 checks |",
        f"| **CISA KEV PR Auditor** | `{kev_status}` | {len(kev_hits)} Known Exploited Vulnerabilities matched |",
        "",
        f"**Overall Verdict:** `{verdict}` ({report['findings_count']} total finding(s))",
        "",
    ]
    return "\n".join(lines)


def run_ci_security_gate(
    target_path: Path,
    scan_types: List[str],
    diff_text: Optional[str] = None,
    step_summary_path: Optional[Path] = None,
    github_output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Executes enabled security engines on target_path and returns structured verdict."""
    normalized_types = {t.strip().lower() for t in scan_types if t.strip()}
    sentinel = ASTCodeSentinel()
    auditor = GitHubPRAuditor()

    files_scanned = 0
    ast_issues: List[Dict[str, Any]] = []
    vuln_graph_findings: List[Dict[str, Any]] = []
    cisa_kev_hits: List[str] = []

    if "ast" in normalized_types:
        if target_path.is_dir():
            ast_res = sentinel.inspect_directory(target_path)
            files_scanned = int(ast_res.get("files_scanned", 0))
            ast_issues = list(ast_res.get("issues", []))
        elif target_path.is_file():
            files_scanned = 1
            single_res = sentinel.inspect_file(target_path)
            if not single_res.get("ok"):
                ast_issues.append(single_res)

    if "secrets" in normalized_types and target_path.exists():
        scan_dir = target_path if target_path.is_dir() else target_path.parent
        graph_res = sentinel.build_security_vulnerability_matrix(scan_dir)
        if files_scanned == 0:
            files_scanned = int(graph_res.get("files_scanned", 0))
        vuln_graph_findings = list(graph_res.get("findings", []))

    if "cisa-kev" in normalized_types:
        effective_diff = diff_text if diff_text is not None else _collect_git_diff(
            target_path if target_path.is_dir() else target_path.parent
        )
        kev_res = auditor.audit_pr_against_cisa_kev(effective_diff)
        cisa_kev_hits = list(kev_res.get("matched_kev_cves", []))

    findings_count = len(ast_issues) + len(vuln_graph_findings) + len(cisa_kev_hits)
    passed = findings_count == 0
    verdict = "PASS" if passed else "FAIL"

    report: Dict[str, Any] = {
        "verdict": verdict,
        "passed": passed,
        "files_scanned": files_scanned,
        "findings_count": findings_count,
        "ast_issues": ast_issues,
        "vuln_graph_findings": vuln_graph_findings,
        "cisa_kev_hits": cisa_kev_hits,
    }

    summary_file = step_summary_path or (
        Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None
    )
    if summary_file:
        md = render_step_summary_markdown(report)
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")

    output_file = github_output_path or (
        Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None
    )
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"verdict={verdict}\n")
            fh.write(f"files_scanned={files_scanned}\n")
            fh.write(f"findings_count={findings_count}\n")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Orbit Security GitHub Action Gate")
    parser.add_argument("--target-path", default=".", help="Target directory or file to scan")
    parser.add_argument("--scan-types", default="ast,secrets,cisa-kev", help="Comma-separated scan types")
    parser.add_argument("--fail-on-findings", default="true", help="Exit non-zero if findings detected")
    args = parser.parse_args()

    target = Path(args.target_path).resolve()
    scan_types = [s.strip() for s in args.scan_types.split(",") if s.strip()]
    fail_on_findings = str(args.fail_on_findings).strip().lower() in ("true", "1", "yes")

    report = run_ci_security_gate(target_path=target, scan_types=scan_types)

    for issue in report["ast_issues"]:
        print(f"::error file={issue.get('file', '')}::AST Sentinel: {issue.get('error') or issue.get('missing_imports')}")
    for vuln in report["vuln_graph_findings"]:
        print(
            f"::error file={vuln.get('file', '')},line={vuln.get('lineno', 1)}::"
            f"[{vuln.get('cwe')}] {vuln.get('sink_type')} ({vuln.get('symbol')})"
        )
    for cve in report["cisa_kev_hits"]:
        print(f"::error ::CISA KEV Actively Exploited Vulnerability detected in PR diff: {cve}")

    print(
        f"[Orbit Security Gate] Verdict: {report['verdict']} | "
        f"Files Scanned: {report['files_scanned']} | Findings: {report['findings_count']}"
    )

    if fail_on_findings and not report["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
