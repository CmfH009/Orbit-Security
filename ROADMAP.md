# Orbit Security — Engineering & Revenue Roadmap

> **Version:** `v1.2.0` | **Updated:** `2026-11-13` | **Owner Direction:** Option C (**Dual-Track Minimal**)
> **Baseline:** Commit `c857ef9` + sibling bridge commits (`439da0b`, `9eb36e4`, `b18b19a`, `2235534`) + v1.2.0 groundwork

---

## 0. Ground-Truth Baseline (Honest Accounting)

Earlier roadmap revisions (`v1.1.0`, `2026-11-06`) ran an outbound cold email experiment and accumulated high-volume passive recon scans. The empirical numbers below remain our anchor against vanity metrics:

### 0.3 Commercial Outreach Lesson (Permanent Guardrail)
- **Cold Email Result:** `178` sent, `43` hard bounces (`24.2%`), `0` conversations, `$0` revenue.
- **Policy Invariant:** `COMMERCIAL_OUTREACH_FROZEN: bool = True` in `src/orbit_security/private_alerting.py`. Unsolicited cold email / bulk domain prospecting remains permanently frozen unless explicitly re-authorized after Gate 2.

### Current Ground Truth (`scripts/orbit_readiness_audit.py`)
- **Paid Subscribers (`data/subscribers.json`):** `0`
- **Client Registry (`data/clients.json`):** `1` real entry (`client-velvetcraft-com`); synthetic test leaks (`c1`, `t.com`) purged and guarded via `src/orbit_security/_runtime_paths.py`.
- **Landing <-> Docs Parity (`scripts/sync_landing_to_docs.py --check`):** `96/96` shared files byte-identical (`0` drift).
- **Stripe Live Keys:** `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` not yet configured in runtime environment.
- **KYC / Payout Blocker:** `ORBIT_KYC_STATUS = PENDING_PHYSICAL_ID` — awaiting delivery of hard-copy government ID in the mail before Stripe payout activation and HackerOne/Bugcrowd KYC-gated payouts can clear.
- **Bounty Catalog (`data/bounty_programs.json`):** `45` unique programs (`0` duplicates, `44` cash-tier programs).
- **Disclosure Queue (`data/disclosures/`):** `26` high-signal `.md` reports + `26` cryptographic `.zip` evidence bundles staged; `311` legacy passive `mail_spoofing` / `cors_wildcard_origin` artifacts moved cleanly to `data/archive/legacy_passive_disclosures/`.

---

## 1. Strategic Focus: Option C (Dual-Track Minimal)

Until Orbit Security collects its first verified dollar, **100% of engineering cycles go strictly into two revenue paths and their reliability floor**:

### Track A — High-Signal Bug Bounty Hunting
- Only exploitable, payout-eligible flaw classes (`SUBMITTABLE_BOUNTY_FLAW_TYPES` in `src/orbit_security/bounty_radar.py`) generate disclosures, alerts, or submittable tallies via `is_bounty_submittable()`:
  - `subdomain_takeover`, `cloud_storage_takeover`, `client_subdomain_takeover`, `open_cloud_bucket`
  - `cors_arbitrary_origin_with_credentials`, `cors_null_origin_with_credentials`
  - `dom_xss_sink`, `sourcemap_exposure`, `graphql_introspection`
  - `http_request_smuggling_cl_te`, `http_request_smuggling_te_cl`, `http_request_smuggling_h2_downgrade`
  - `oauth_redirect_uri_hijack`, `rce`, `ssrf`, `idor`
- Passive hygiene observations (`mail_spoofing`, `missing_dmarc`, `spf`, `missing_hsts`, `expiring_certificate`, `cors_wildcard_origin`) are tracked separately under `total_advisory_observations` and **never** pollute disclosure queues.
- Pre-ID execution focuses on validating and tightening PoCs + `ReportCriticVerifier` cryptographic bundles on the staged `26` candidates so submissions go out immediately once physical ID arrives.

### Track B — Inbound Self-Serve Security Audit -> Stripe Checkout -> Fixpack / Portal Delivery
- Single crisp inbound funnel through `landing/` -> `docs/` (`https://purav...` / GitHub Pages), `stripe_checkout.py`, `stripe_webhook.py`, `agency_retainer.py`, and fixpack/portal delivery.
- Zero cold outreach; improvements focus on conversion clarity, checkout webhook reliability, and automated report/fixpack generation.

---

## 2. Sequenced Execution Gates (Phase 0 -> Phase 4 Re-baselined)

- **Gate 1 — Clean Technical & Data Floor (`DONE — 2026-11-13`)**
  - Hermetic test persistence isolation (`_runtime_paths.py`) preventing pytest from mutating `data/clients.json`, `data/bounty_programs.json`, or fleet registries.
  - Strict signal-over-noise disclosure gate (`is_bounty_submittable`) & archival of `311` passive noise artifacts.
  - Program catalog restored to `45` unique verified scopes (`0` duplicate IDs).
  - Read-only `scripts/orbit_readiness_audit.py` providing exact truth in one command.
- **Gate 2 — Physical ID Receipt, KYC Clearance & First `$` Validation (`CURRENT / BLOCKED ON MAIL`)**
  1. Receive hard-copy government ID (`ORBIT_KYC_STATUS -> VERIFIED`).
  2. Complete HackerOne / Bugcrowd KYC and Stripe identity + bank payout verification; configure `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`.
  3. While waiting on mail: manually & empirically validate the top staged findings in `data/disclosures/` (e.g., `cors_arbitrary_origin_with_credentials`, `graphql_introspection`) with reproducible PoC steps and zero false positives.
  4. Submit verified high-signal reports and validate one end-to-end test/live inbound Stripe Fixpack purchase.
  5. **Exit Criteria:** First real `$1+` earned (confirmed bounty triage/payout or inbound Stripe settlement).
- **Gate 3 — Disciplined Repeatable Revenue (`LOCKED UNTIL GATE 2 PASSES`)**
  - Scale scanning frequency and exploit verifiers on highest-converting Track A program scopes.
  - Automate post-checkout onboarding & recurring monitoring cadence for paying Track B customers.
- **Gate 4 — Selective Expansion (`LOCKED UNTIL GATE 3`)**
  - Only unfreeze peripheral features if clear customer pull or ROI exists.

---

## 3. What We Are Explicitly NOT Doing (Frozen Scope)

To stop splitting focus across non-revenue surfaces, the following remain **frozen** until Gate 2 clears real revenue:
1. **No Cold Email Blasting:** `COMMERCIAL_OUTREACH_FROZEN = True` remains locked.
2. **No Automated Podcast / Briefing Audio Production:** Daily/weekly briefing podcast synthesis (`hypernote_briefing.py` media workflows) is paused.
3. **No X / Twitter Auto-Roast or Social Daemons:** `social_daemon.py` outbound posting remains disabled.
4. **No Cross-Repo Telemetry / Game / Visualizer Bridges:** Non-revenue UI topologies (`gods_eye_bridge.py` expansions, unrelated sibling integrations, and cancelled `Aevum`/`Polyarch` Sprint 4 work) are out of scope.
5. **No New Speculative Scanners Without Payout Evidence:** Every check must map to an actionable bounty tier or a paid Fixpack deliverable.

---

## 4. Next 14 Days Action Plan (Pending Physical ID)

1. Run `.venv\Scripts\python.exe scripts/orbit_readiness_audit.py` before/after work sessions to verify clean state and blocker status.
2. Audit top `5–10` staged `.md` / `.zip` bundles in `data/disclosures/` (`cors_arbitrary_origin_with_credentials`, `graphql_introspection`) to verify live reproduction and impact statement quality.
3. Dry-run inbound Stripe webhook + checkout smoke flow locally with `STRIPE_WEBHOOK_SECRET` test keys so live key drop-in after ID delivery takes <5 minutes.
4. The day the physical ID arrives: complete HackerOne/Bugcrowd + Stripe KYC, flip `ORBIT_KYC_STATUS=VERIFIED`, submit top verified bounty packets, and publish/verify live checkout.

---

## 5. Archived Work: Closed Nov 9–13 Sprint (§ 9 Closure)

- **Landed & Retained (`main`):** Sibling bridge Sprints 1, 2, 3, and 5 (`439da0b`, `9eb36e4`, `b18b19a`, `2235534`) providing `Nova Brain` vitals fallback, `OdysseusBrowserVerifier` + `BrowserCompanionClient` zero-trust RoE gating, `MicrogravitySubdomainDispatcher` (`mg.exe` CT fan-out), and non-blocking topology hook.
- **Cancelled:** Sprint 4 (`Aevum` ramp-down checkpointing & `Polyarch` routing) was explicitly dropped per user direction to keep Orbit Security focused and decoupled from unrelated work.
- **Status:** Closed as of `v1.2.0` (`2026-11-13`). Future work follows Gates 1–4 above exclusively.
