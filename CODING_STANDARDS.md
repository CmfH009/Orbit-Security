# Orbit Security — Coding Standards (Review-Only)

> **Context Boundary**: Read during **code review** (not implementation). Mechanical syntax, formatting, and import hygiene belong in `ast_sentinel.py`, `ruff`/`black`, `pytest`, and `npm run check:landing` — not here.

## Architecture & State
- **Single-Writer SQLite Discipline**: Route cross-module state transitions through `Blackboard` (`src/orbit_security/blackboard.py`) rather than opening ad-hoc SQLite connections to the same database file.
- **One-Way Landing Sync**: Every marketing site edit lands in `landing/` first and flows into `docs/` strictly via `npm run build:css` + `npm run sync:docs`. Reject direct edits to `docs/` with no corresponding `landing/` source change.
- **No Silent Error Masking**: Never catch broad `Exception` blocks in scanners, audit scoring, or remediation pipelines to return fake-healthy defaults; surface structured failure records on the **Blackboard** or propagate.

## Remediation & Cost Safety
- **Quota-Safe Model Routing**: OpenCode remediation paths must default to free-tier or local Ollama models (`opencode/deepseek-v4.1-flash-free`, `ollama/orbit-coder:latest`); flag any hardcoded paid-tier cloud model fallback.
- **Safe Remediation Boundaries**: Keep generated **Remediation Artifacts** isolated under `data/remediation/` and never auto-send live external emails or apply destructive remote mutations without an explicit human approval gate.

## Test Seams
- Test audit scoring and remediation at public module seams (`tests/test_audit_scoring.py`, `tests/test_opencode_remediation.py`) using realistic payloads rather than asserting internal private helper call counts.

## Landing UI & Fixed Overlays
- **Fixed Overlays & Responsive Bounds**: For `landing/` changes adding fixed overlays, tour spotlights, or floating HUD bars, verify sticky-navbar clearance (`top >= 76px`) and `390×844` mobile viewport bounds visually; string-matching tests in `tests/test_simplecat_visuals_and_scroll.js` alone do not catch geometric clipping.
