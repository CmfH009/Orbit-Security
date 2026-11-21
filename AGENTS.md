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
- **Landing & GitHub Pages (`landing/` -> `docs/`)**: When editing any HTML, CSS, JS, or media in `landing/`:
  1. Edit `landing/` only (never `docs/` directly); rebuild Tailwind v4 CSS with `npm run build:css` (`landing/input.css` -> `landing/assets/styles.min.css`).
  2. Sync to `docs/` with `npm run sync:docs` (preserve `>=96` shared files; keep `landing/assets/orbit_cats_pounce.jpg` at `1024x1024` `>100KB` for X/Meta ad gates and OG images `>=1200x630`).
  3. Verify with `npm run check:landing` before committing.

## ⚡ Execution Invariants
1. **Landing & Parity Gate**: Run `npm run check:landing` after any `landing/` or `docs/` change.
2. **Backend Empirical Verification**: Run `pytest tests/test_opencode_remediation.py tests/test_audit_scoring.py` before committing backend changes.
3. **Conventional Commits**: Format commit messages as `fix(security): ...`, `feat(landing): ...`, `feat(recon): ...`, etc.
4. **Quota Preservation**: OpenCode is configured with free-tier and local models (`opencode/deepseek-v4.1-flash-free` or `ollama/orbit-coder:latest`) to preserve API quotas.

## 📚 Domain Docs (On-Demand)
- **Domain Vocabulary**: `GLOSSARY.md` (use exact terms in specs, code, and PRs)
- **Architecture Decisions**: `docs/adr/` (read before altering core seams; mint new ADRs on one-way choices)
- **Review-Only Standards**: `CODING_STANDARDS.md` (load during code review only, not routine implementation)
