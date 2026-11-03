# Orbit Security: Pre-Push Bughunt Handoff & Adversarial QA Dossier

**Target Workspace**: `A:/projects/orbit-security` (`C:\AgyHut\projects\orbit-security`)  
**Production URL**: `https://cmfh009.github.io/Orbit-Security/`  
**Current Git Baseline**: Commit `9cb15d5` on branch `main`  
**Release Gate Status**: `python scripts/verify_release.py` &rarr; **PASS (97 shared files identical, 20 JSON-LD schema graphs valid)**  

---

## 1. Executive Summary & Context

Across the last implementation cycle, four high-converting interactive systems and conversion engines were engineered for the Orbit Security landing page:

1. **Feature 1: Live Agency DoH Perimeter Scanner & On-the-Spot Briefing** (`c343819`)
2. **Feature 2: Visual Attack Tree / Takeover Simulator** (`c6944d0`)
3. **Feature 3: Interactive White-Label Portal Customizer Sandbox** (`957e9c5`)
4. **Feature 4: Astro-Cat Sentinel Gamification & Audio/Visual Arcade Polish** (`5731389`, `9cb15d5`)

Before deploying to `origin/main` and serving live production traffic from GitHub Pages, an **exhaustive, adversarial pre-push bughunt** is required to catch regressions, edge case crashes, DOM/SVG layout quirks, memory leaks, XSS vulnerabilities, and mobile touch quirks.

---

## 2. Master Verification Baseline

All 4 automated test suites are currently exiting 0:

| Test Runner | Command | Assertions | Focus |
|---|---|---|---|
| **Release Gate** | `python scripts/verify_release.py` | 97 shared files, 20 JSON-LD schemas | Parity between `landing/` and `docs/`, public asset hashes, JSON-LD @id links |
| **Audit & Radar Suite** | `node tests/test_radar_parity_suite.js` | 239 / 239 passed | DoH scanner, 100-pt scoring, PDF generation, Visual Attack Tree, Portal Customizer |
| **SimpleCat & Visual Suite** | `node tests/test_simplecat_visuals_and_scroll.js` | 53 / 53 passed | Sentinel showcase, Arcade Defense mode, audio lifecycle, touch controls, horizontal masks |
| **Telemetry & Score Suite** | `pytest tests/test_radar_score_delta.py tests/test_radar_telemetry.py -q` | 33 / 33 passed | Python telemetry collector payloads, scoring delta math |

---

## 3. High-Priority Adversarial Bug Hunting Targets

### Target 1: Live DoH Perimeter Scanner (`docs/assets/orbit_radar.js`)
- [ ] **Wildcard DNS Evasion**:
  - Test apex domains configured with wildcard DNS (`*.domain.com A 1.2.3.4`). Confirm the pre-probe `orbit-wc-check-[rand].[domain]` suppresses false-positive CNAME takeover warnings across the 16 subdomains.
- [ ] **Two-Prong Takeover Classification**:
  - Confirm Prong A (NXDOMAIN) triggers for decommissioned Azure/Beanstalk endpoints and forces overall Grade F.
  - Confirm Prong B (Multi-Tenant SaaS) flags AWS S3, GitHub Pages, and Shopify as `WARN // UNVERIFIED CLOUD ENDPOINT` without false NXDOMAIN assertions.
- [ ] **RFC 7505 Null-MX Inbound Route**:
  - Verify domains with `0 .` are awarded 15/15 pts without flagging RFC 5321 §5.1 missing MX fallback.
  - Verify active web servers with no MX records get flagged as `5/15 pts (WARN)`.
- [ ] **Client-Side PDF Generation (`generateInstantPdfForDomain`)**:
  - Verify PDF generation succeeds with both 5 and 6 categories.
  - Verify card spacing (`startY -= 42`, height 36) leaves clean breathing room above the Care Plan box (`y: 85`).
  - Verify custom agency name and primary brand color are cleanly applied.

### Target 2: Visual Attack Tree / Takeover Simulator (`docs/assets/orbit_radar.js`)
- [ ] **SVG Coordinate & Flow Geometry**:
  - Verify `p34` (Node 3 &rarr; Node 4) flows forward without backwards pulse flow.
  - Verify `p51` elevated arch (`y=10..24`) never collides with or slices through Node 2/3 headers.
- [ ] **Timer & Lifecycle Hygiene**:
  - Rapidly click between Step 1 &rarr; Step 5, toggle Play/Pause, and switch Presets. Confirm no runaway intervals or leaked animation loops.
- [ ] **Malicious Input & Entity Safety**:
  - Test custom subdomains containing quotes, ampersands, or long strings (>60 chars). Ensure `_safeTruncate` prevents XML parsing failures.

### Target 3: White-Label Portal Customizer Sandbox (`docs/assets/orbit_radar.js` & `docs/index.html`)
- [ ] **Color Picker & 3-Char Hex Shorthand**:
  - Test `#0ff`, `#fff`, `#000`, and invalid hex inputs. Ensure contrast calculation properly sets button text color (`#ffffff` vs `#020617`).
- [ ] **Logo Drag-and-Drop Robustness**:
  - Test oversized files (>2MB), non-image files (.exe, .pdf), and zero-byte images. Ensure graceful rejection and `reader.onerror` error handling.
- [ ] **LocalStorage Quota Boundaries**:
  - Check storage behavior when `localStorage` contains prior audit logs and a high-resolution logo is saved.
- [ ] **Target Portal Hydration (`docs/portals/orbit-core.html`)**:
  - Click "Launch Live Demo Portal". Confirm query parameter parsing and `localStorage` hydration accurately render custom agency name, brand color, and logo.

### Target 4: Astro-Cat Sentinel Gamification & Audio Polish (`docs/assets/simple_cat.js`)
- [ ] **Arcade Defense Victory Condition**:
  - Let 1–2 threats penetrate the shield (reducing HP to 75% or 50% > 0) while destroying the rest. Verify victory debrief fires cleanly when all 16 threats resolve.
- [ ] **Canvas Resize & Touch Controls**:
  - Rotate mobile device (portrait to landscape). Confirm `resizeDefenseCanvas` preserves circular shields without oval stretching or touch aiming offset.
  - Test dragging touch finger off `#defense-touch-left` / `#defense-touch-right`. Ensure `pointercancel` cleanly halts rotation.
- [ ] **Web Audio API Policy Unlock**:
  - Confirm `AudioContext` initializes and resumes to `running` on the first genuine user gesture without console autoplay warnings.
- [ ] **Sound Toggle UI Integrity**:
  - Confirm clicking sound toggle button in desktop navbar or mobile drawer updates icon without corrupting the mobile drawer's layout, descriptive text, or hotkey badge.

---

## 4. Hard Deployment Rules

1. **100% Parity Rule**: Any changes made in `docs/` must be mirrored in `landing/` (or vice-versa).
2. **Release Gate**: `python scripts/verify_release.py` must exit 0 before pushing.
3. **Commit Standard**: Conventional Commits (`fix(landing):`, `fix(docs):`, `test(radar):`).
