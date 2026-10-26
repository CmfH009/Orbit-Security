# Orbit Security Project Guidelines (`A:\projects\orbit-security`)
====================================================================
This document governs development, audits, and autonomous remediation in Project ORBIT.

## 🛡️ Project Overview
Orbit Security is an autonomous attack surface sentinel and perimeter auditor built for web design, development, and digital marketing agencies.

## 🏗️ Core Architecture & Conventions
- **Source Root**: `src/orbit_security`
- **Tests**: `tests/` (Run with `pytest`)
- **Remediation Directory**: `data/remediation/` (patches, correction notes, and emails)
- **Blackboard Event Mesh**: Decoupled SQLite WAL bus in `src/orbit_security/blackboard.py`
- **Autonomous Remediation**: Driven by OpenCode in `src/orbit_security/opencode_remediation.py` and `scripts/run_opencode_remediation.py`
- **AST Code Sentinel**: Static symbol and import hygiene in `src/orbit_security/ast_sentinel.py` (with `--auto-fix`)

## ⚡ Execution Invariants
1. **DHH v2 Production Gate**: Must score >= 9.60/10.00. Zero superfluous dependencies.
2. **Empirical Verification**: Run `pytest tests/test_opencode_remediation.py tests/test_audit_scoring.py` before committing.
3. **Conventional Commits**: Format commit messages as `fix(security): ...`, `feat(recon): ...`, etc.
4. **Quota Preservation**: OpenCode is configured with free-tier and local models (`opencode/deepseek-v4.1-flash-free` or `ollama/orbit-coder:latest`) to preserve API quotas.
