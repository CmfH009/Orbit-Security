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
- **Landing <-> Docs Parity (`scripts/sync_landing_to_docs.py --check`):** `96/96` shared files byte-identical (`0` drift); `scripts/verify_landing_pages.py` passing (`audit.html`, `signup.html`, `fleet.html`, `portals/index.html` validated).
- **Stripe Live Keys:** `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` not yet configured in runtime environment.
- **KYC / Payout Blocker:** `ORBIT_KYC_STATUS = PENDING_PHYSICAL_ID` — awaiting delivery of hard-copy government ID in the mail before Stripe payout activation and HackerOne/Bugcrowd KYC-gated payouts can clear.
- **Bounty Catalog (`data/bounty_programs.json`):** `45` unique programs (`0` duplicates, `44` cash-tier programs), with `45/45` populated with `excluded_vulnerabilities` baseline out-of-scope categories.
- **Disclosure Queue (`data/disclosures/`):** `19` staged `.md` reports + `19` paired cryptographic `.zip` evidence bundles (`19/19` carrying deterministic `ev_<12-char-hex>` digests and valid SHA-256 manifests: `1` Tier-1 Spotify open bucket ready on KYC ID arrival + `18` Tier-2 `CONDITIONAL` CORS candidates); `7` Tier-3 false positives (+ duplicate `(1)` dir) archived to `data/archive/false_positive_disclosures/` alongside `311` legacy passive `mail_spoofing` / `cors_wildcard_origin` artifacts in `data/archive/legacy_passive_disclosures/` (`318` archived items total).
- **Track B Funnel Readiness (`ready=True`):** Hermetic E2E dry-run verified in `tests/test_stripe_trackb_e2e.py` (`audit.html` local Fixpack export & CTA prefill -> `signup.html` -> `stripe_checkout.py` -> signed `stripe_webhook.py` -> isolated SLA PDF, Fixpack ZIP, and hyphen/underscore `/portal/<agency_id>` delivery).
- **AST Sentinel & Suite Health:** `107/107` source modules passing `ast_sentinel.py --check` (`0` issues) and `ast_sentinel.py --check-egress` (`0` `ROE-EGRESS-001` violations); full-suite `pytest -q` healthy (`1,917 passed, 12 skipped, 0 failed` post-`conftest.py` `background_telemetry_scanner` daemon-thread isolation).

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
- Pre-ID execution focuses on `19` staged candidates (`1` Tier-1 Spotify open bucket ready upon KYC ID arrival + `18` Tier-2 `CONDITIONAL` CORS bundles requiring authenticated session/PII PoC verification), all grounded with `ev_<12-char-hex>` digests and SHA-256 `ReportCriticVerifier` manifests, while `7` Tier-3 false positives remain archived under `data/archive/false_positive_disclosures/`.

### Track B — Inbound Self-Serve Security Audit -> Stripe Checkout -> Fixpack / Portal Delivery
- Single crisp inbound funnel through `landing/` -> `docs/` (`96/96` byte-identical, `verify_landing_pages.py` passing), `audit.html` (DOM XSS-hardened with client-side Fixpack download & CTA prefill into `signup.html`), `stripe_checkout.py` (tier alias normalization, validation, `/portal/<agency_id>` multi-slug resolution), `stripe_webhook.py`, `agency_retainer.py`, `client_bundle_exporter.py`, and hermetic `scripts/run_stripe_webhook.py --test-event` / `tests/test_stripe_trackb_e2e.py` verification.
- Zero cold outreach; improvements focus on conversion clarity, checkout webhook reliability, and automated report/fixpack generation.

---

## 2. Sequenced Execution Gates (Phase 0 -> Phase 4 Re-baselined)

- **Gate 1 — Clean Technical & Data Floor (`DONE — 2026-11-13`)**
  - Hermetic test persistence isolation (`_runtime_paths.py`, `fleet.py`, `agency_retainer.py`, `bounty_radar.py`, `stripe_webhook.py`, `client_bundle_exporter.py`, `conftest.py` daemon-thread isolation) keeping live `data/` and `docs/` untouched during tests (`1,917 passed, 12 skipped, 0 failed`).
  - Strict signal-over-noise disclosure gate (`is_bounty_submittable`), `7` Tier-3 false-positive + `311` legacy passive archival, and `19/19` staged bundles upgraded with `ev_<12-char-hex>` digests + SHA-256 manifests.
  - Program catalog restored to `45` unique verified scopes (`0` duplicate IDs, `45/45` `excluded_vulnerabilities` populated).
  - Zero-Trust egress & AST hygiene verified (`107/107` modules passing `ast_sentinel.py --check` with `0` issues and `--check-egress` with `0` violations).
  - Track B E2E dry-run readiness (`ready=True`, `96/96` `landing/` <-> `docs/` parity), OpenRig `backlog_pump.py` / `deepcoder_orchestrator.py` Option C alignment, and read-only `scripts/orbit_readiness_audit.py` verification.
- **Gate 2 — Physical ID Receipt, KYC Clearance & First `$` Validation (`CURRENT / BLOCKED ON MAIL`)**
  1. Receive hard-copy government ID (`ORBIT_KYC_STATUS -> VERIFIED`).
  2. Complete HackerOne / Bugcrowd KYC and Stripe identity + bank payout verification; configure `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`.
  3. While waiting on mail: capture authenticated session/PII proof for Tier-2 `CONDITIONAL` CORS candidates before promotion; keep Tier-1 Spotify bundle submission-ready.
  4. Submit verified high-signal reports and validate live end-to-end inbound Stripe Fixpack purchase (<5 min key drop-in).
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

1. Run `.venv\Scripts\python.exe scripts/orbit_readiness_audit.py` before/after work sessions to verify clean state (`19/19` `ev_` coverage, `Track B ready=True`) and blocker status.
2. Collect authenticated session/PII proof for Tier-2 `CONDITIONAL` CORS candidates in `data/disclosures/` (never promoting unverified public-HTML CORS).
3. Keep Track B dry-run test suite (`tests/test_stripe_trackb_e2e.py`) and `sync_landing_to_docs.py --check` green so live Stripe key drop-in after ID delivery takes <5 minutes.
4. The day the physical ID arrives: complete HackerOne/Bugcrowd + Stripe KYC, flip `ORBIT_KYC_STATUS=VERIFIED`, submit Tier-1 Spotify + verified packets, and publish/verify live checkout.

---

## 5. Archived Work: Closed Nov 9–13 Sprint (§ 9 Closure)

- **Landed & Retained (`main`):** Sibling bridge Sprints 1, 2, 3, and 5 (`439da0b`, `9eb36e4`, `b18b19a`, `2235534`) providing `Nova Brain` vitals fallback, `OdysseusBrowserVerifier` + `BrowserCompanionClient` zero-trust RoE gating, `MicrogravitySubdomainDispatcher` (`mg.exe` CT fan-out), and non-blocking topology hook.
- **Cancelled:** Sprint 4 (`Aevum` ramp-down checkpointing & `Polyarch` routing) was explicitly dropped per user direction to keep Orbit Security focused and decoupled from unrelated work.
- **Status:** Closed as of `v1.2.0` (`2026-11-13`). Future work follows Gates 1–4 above exclusively.
