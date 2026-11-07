#!/usr/bin/env python3
"""Orbit Security — Composite GitHub Action Entrypoint & SARIF 2.1.0 Exporter.

Executes the Orbit Security CI/CD PR & Perimeter Gate across three engines:
  1. AST Code Sentinel (unresolved stdlib symbols & syntax verification)
  2. Static AST Vulnerability & Secret Graph (CWE-78, CWE-95, CWE-502, CWE-798)
  3. CISA KEV Pull Request & Dependency Auditor (actively exploited CVEs)

Emits GitHub Actions annotations (`::error`), writes a rich Markdown report
to `$GITHUB_STEP_SUMMARY`, structured outputs to `$GITHUB_OUTPUT`, and optional
SARIF 2.1.0 reports (`--sarif-output`) compatible with `github/codeql-action/upload-sarif@v3`.
"""

from __future__ import annotations

import argparse
import json
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

SARIF_RULES: List[Dict[str, Any]] = [
    {
        "id": "ORBIT-AST-001",
        "name": "UnresolvedStdlibSymbol",
        "shortDescription": {
            "text": "Unresolved standard library symbol or syntax error detected by AST Sentinel."
        },
        "fullDescription": {
            "text": "Static AST analysis detected an unimported standard library module or Python syntax error that will fail at runtime."
        },
        "help": {
            "text": "Import the missing standard library module at the top of the file or fix the syntax error.",
            "markdown": "**Remediation:** Import the missing standard library module at the top of the module or resolve the syntax error.",
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "correctness", "ast"],
            "precision": "very-high",
            "security-severity": "6.5",
        },
    },
    {
        "id": "CWE-95",
        "name": "DangerousEvalExec",
        "shortDescription": {"text": "Dynamic code execution via eval() or exec() (CWE-95)."},
        "fullDescription": {
            "text": "Use of eval() or exec() allows arbitrary code execution if untrusted input reaches the sink."
        },
        "help": {
            "text": "Replace eval()/exec() with ast.literal_eval() or safe structured parsers.",
            "markdown": "**Remediation:** Avoid `eval()` and `exec()`. Use `ast.literal_eval()` or structured JSON/YAML safe loaders.",
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "external/cwe/cwe-95"],
            "precision": "high",
            "security-severity": "9.0",
        },
    },
    {
        "id": "CWE-78",
        "name": "SubprocessShellTrue",
        "shortDescription": {"text": "OS command execution with shell=True (CWE-78)."},
        "fullDescription": {
            "text": "Invoking subprocess with shell=True enables shell metacharacter injection when combined with dynamic arguments."
        },
        "help": {
            "text": "Pass command arguments as a list with shell=False.",
            "markdown": "**Remediation:** Pass argument arrays to `subprocess.run([...], shell=False)`.",
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "external/cwe/cwe-78"],
            "precision": "high",
            "security-severity": "8.5",
        },
    },
    {
        "id": "CWE-502",
        "name": "UnsafeDeserialization",
        "shortDescription": {"text": "Deserialization of untrusted data (CWE-502)."},
        "fullDescription": {
            "text": "Deserializing untrusted payloads via pickle, marshal, or unsafe YAML loaders can lead to arbitrary code execution."
        },
        "help": {
            "text": "Use json.loads() or yaml.safe_load().",
            "markdown": "**Remediation:** Replace `pickle.loads()` / `yaml.load()` with `json.loads()` or `yaml.safe_load()`.",
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "external/cwe/cwe-502"],
            "precision": "high",
            "security-severity": "9.0",
        },
    },
    {
        "id": "CWE-798",
        "name": "HardcodedSecretLiteral",
        "shortDescription": {"text": "Use of hard-coded credentials or secret tokens (CWE-798)."},
        "fullDescription": {
            "text": "Hardcoded API keys, tokens, or passwords in source code risk credential exposure in version control."
        },
        "help": {
            "text": "Load credentials from environment variables or a secret manager.",
            "markdown": "**Remediation:** Move secrets out of source code and load them via `os.environ` or CI secret stores.",
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "external/cwe/cwe-798"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
    {
        "id": "ORBIT-KEV-001",
        "name": "CisaKnownExploitedVulnerability",
        "shortDescription": {
            "text": "Reference or dependency matching a CISA Known Exploited Vulnerability (KEV)."
        },
        "fullDescription": {
            "text": "The pull request diff introduces or references a CVE present in the CISA Known Exploited Vulnerabilities catalog."
        },
        "help": {
            "text": "Upgrade the affected package to a patched release not listed in CISA KEV.",
            "markdown": "**Remediation:** Upgrade the dependency immediately to a patched version outside the CISA KEV catalog.",
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "cisa-kev", "supply-chain"],
            "precision": "very-high",
            "security-severity": "9.5",
        },
    },
]

RULE_INDEX_MAP: Dict[str, int] = {r["id"]: idx for idx, r in enumerate(SARIF_RULES)}


def _normalize_sarif_uri(raw_path: str, base_dir: Optional[Path] = None) -> str:
    """Converts a file path into a relative POSIX URI without drive letters or backslashes."""
    if not raw_path:
        return "pyproject.toml"
    p = Path(raw_path)
    for root_candidate in (base_dir, REPO_ROOT):
        if root_candidate is not None:
            try:
                rel = p.resolve().relative_to(root_candidate.resolve())
                uri = rel.as_posix().lstrip("./")
                if uri and ":" not in uri:
                    return uri
            except Exception:
                pass
    # Fallback: use filename or clean posix segments without drive letters
    posix_str = p.as_posix()
    if ":" in posix_str:
        posix_str = posix_str.split(":", 1)[-1]
    cleaned = posix_str.lstrip("/")
    return cleaned or p.name or "pyproject.toml"


def build_sarif_report(
    report: Dict[str, Any],
    base_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Builds a GitHub Code Scanning compliant SARIF 2.1.0 payload from a gate report."""
    results: List[Dict[str, Any]] = []

    for iss in report.get("ast_issues", []):
        uri = _normalize_sarif_uri(str(iss.get("file", "")), base_dir=base_dir)
        missing_list = iss.get("missing_imports", [])
        formatted_missing = [
            f"{m.get('symbol', m.get('module', ''))} (L{m.get('lineno', 1)})" if isinstance(m, dict) else str(m)
            for m in missing_list
        ]
        first_line = 1
        if missing_list and isinstance(missing_list[0], dict):
            first_line = max(1, int(missing_list[0].get("lineno", 1) or 1))
        detail = iss.get("error") or f"Missing stdlib imports: {', '.join(formatted_missing)}"
        results.append({
            "ruleId": "ORBIT-AST-001",
            "ruleIndex": RULE_INDEX_MAP["ORBIT-AST-001"],
            "level": "error",
            "message": {"text": f"AST Code Sentinel: {detail}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": first_line, "startColumn": 1},
                    }
                }
            ],
        })

    for vuln in report.get("vuln_graph_findings", []):
        cwe = str(vuln.get("cwe", "CWE-95")).upper()
        rule_id = cwe if cwe in RULE_INDEX_MAP else "CWE-95"
        uri = _normalize_sarif_uri(str(vuln.get("file", "")), base_dir=base_dir)
        start_line = max(1, int(vuln.get("lineno", 1) or 1))
        results.append({
            "ruleId": rule_id,
            "ruleIndex": RULE_INDEX_MAP[rule_id],
            "level": "error",
            "message": {
                "text": f"[{rule_id}] {vuln.get('sink_type', 'security_sink')} ({vuln.get('symbol', '')}) detected."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": start_line, "startColumn": 1},
                    }
                }
            ],
        })

    for cve in report.get("cisa_kev_hits", []):
        results.append({
            "ruleId": "ORBIT-KEV-001",
            "ruleIndex": RULE_INDEX_MAP["ORBIT-KEV-001"],
            "level": "error",
            "message": {
                "text": f"CISA KEV Actively Exploited Vulnerability detected in PR diff: {cve}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "pyproject.toml", "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Orbit Security CI/CD Gate",
                        "version": "0.1.0",
                        "informationUri": "https://cmfh009.github.io/Orbit-Security/",
                        "rules": SARIF_RULES,
                    }
                },
                "results": results,
            }
        ],
    }


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
    sarif_output_path: Optional[Path] = None,
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

    if sarif_output_path:
        base_dir = target_path if target_path.is_dir() else target_path.parent
        sarif_payload = build_sarif_report(report, base_dir=base_dir)
        sarif_output_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_output_path.write_text(json.dumps(sarif_payload, indent=2), encoding="utf-8")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Orbit Security GitHub Action Gate")
    parser.add_argument("--target-path", default=".", help="Target directory or file to scan")
    parser.add_argument("--scan-types", default="ast,secrets,cisa-kev", help="Comma-separated scan types")
    parser.add_argument("--fail-on-findings", default="true", help="Exit non-zero if findings detected")
    parser.add_argument("--sarif-output", default="", help="Optional file path to write SARIF 2.1.0 report")
    args = parser.parse_args()

    target = Path(args.target_path).resolve()
    scan_types = [s.strip() for s in args.scan_types.split(",") if s.strip()]
    fail_on_findings = str(args.fail_on_findings).strip().lower() in ("true", "1", "yes")
    sarif_path = Path(args.sarif_output) if args.sarif_output.strip() else None

    report = run_ci_security_gate(
        target_path=target,
        scan_types=scan_types,
        sarif_output_path=sarif_path,
    )

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
