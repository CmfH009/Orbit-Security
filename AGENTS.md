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
  2. Sync to `docs/` with `npm run sync:docs` (preserve `>=87` shared files; keep `landing/assets/orbit_cats_pounce.jpg` at `1024x1024` `>100KB` for X/Meta ad gates and OG images `>=1200x630`).
  3. Verify with `npm run check:landing` before committing.

## ⚡ Execution Invariants
1. **Landing & Parity Gate**: Run `npm run check:landing` after any `landing/` or `docs/` change.
2. **Backend Empirical Verification**: Run `pytest tests/test_opencode_remediation.py tests/test_audit_scoring.py` before committing backend changes.
3. **Conventional Commits**: Format commit messages as `fix(security): ...`, `feat(landing): ...`, `feat(recon): ...`, etc.
4. **Quota Preservation**: OpenCode is configured with free-tier and local models (`opencode/deepseek-v4.1-flash-free` or `ollama/orbit-coder:latest`) to preserve API quotas.
5. **Classifier-Safe Vault Inspection**: Inspect disclosure vaults via `python scripts/inspect_vault_safe.py --redact-domains` (enforced by `PreToolUse` `read_file` gate), use synthetic domains (`example.com`, `target.test`) for scanner/parser work, and route raw live-target analysis to local Ollama (`:11434`).
6. **External Bug Bounty Submission Gate (`TRAP-023`)**:
   - Load `bounty-submission-gate` (never rely solely on defensive-only `security-audit`) for any Bugcrowd, HackerOne, or external VDP work.
   - Run `bugcrowd-brief <slug> --check-target <asset> --vuln-class <class>` or `h1-read program <handle> --scopes --policy` BEFORE auditing.
   - Require live end-to-end reproduction (compiled/booted server or owned instance, real HTTP/browser sessions, before/after visual screenshots — zero `MockMvc`/`plugintest.API` mocks), concise `400–900` word reports, and adversarial triager critique.
   - **Hard Human-in-the-Loop Gate**: NEVER autonomously click Submit/`Report vulnerability` or `POST` external bounty reports; stage the verified draft/evidence and stop for human review and submission.

## 📚 Domain Docs (On-Demand)
- **Domain Vocabulary**: `GLOSSARY.md` (use exact terms in specs, code, and PRs)
- **Architecture Decisions**: `docs/adr/` (read before altering core seams; mint new ADRs on one-way choices)
- **Review-Only Standards**: `CODING_STANDARDS.md` (load during code review only, not routine implementation)
