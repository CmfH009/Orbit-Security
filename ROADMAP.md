# 🗺️ Orbit Security — Delivery Roadmap

**Version:** 1.1.0 · **Date:** 2026-11-06 · **Owner:** Carson Haynes (Founder) · **Co-pilot:** Nova
**Scope:** Product integrity → Revenue loop → AI-search authority → Scale
**Companion:** [`SECURITY.md`](SECURITY.md) (Coordinated Vulnerability Disclosure & Safe Harbor policy)

---

## 0. Where we actually are

### 0.1 Phase status as of 2026-11-06 (`v1.1.0` Release — CI/CD Gate, SARIF 2.1.0, Vault & Deliverability)

| Phase | State | Evidence |
|---|---|---|
| **Phase 0 — Trust Surface** | ✅ **complete** | 7 declared 404s → 0; structured data on 20/20 public pages sharing one `Organization @id`; robots/sitemap (15 URLs)/security.txt/llms.txt/SECURITY.md live; release gate PASS with 14/14 live URLs 200; internal handoff docs purged from public `docs/` |
| **Phase 1 — Product Integrity** | ✅ **complete** | Scoring model rewritten (F now = exploit risk); 52 audits re-scored (18 failing → 5, 13 rescued, 0 newly failing, +28.1 avg); 1,668 tests green; composite GitHub Action (`CmfH009/Orbit-Security@v1`) with SARIF 2.1.0 exporter (`--sarif-output`) + Dependabot weekly supply-chain updates live |
| **Track A — SPF Tree & DNS Fix Pack** | ✅ **complete** | RFC 7208 SPF 10-lookup recursive tree counter & simulator, PermError evaluation (>=10 lookups, >2 void lookups, cycle detection preserving valid diamond DAGs), flattening engine (`v=spf1 ip4:... ip6:... -all`), 1-click DNS fixpack exporter (Terraform, BIND zone, security.txt, SHA-256 manifest) with atomic ZIP & SSRF/traversal guards, CLI `--export-fixpack` and portal integration; 1,769 tests green |
| **Phase 2 — Revenue Loop** | 🟡 **in progress** | Cohort 11 staged & calibrated (`scripts/stage_cohort_11.py`, mean 87.0, 100% ≥ C+, zero hygiene Fs, 35/35/30 split); White-Label Client Remediation & Export Bundle Generator (`src/orbit_security/client_bundle_exporter.py`) with atomic ZIP, NTFS mutex locking, XML escaping, underscore preservation, deal desk & Stripe webhook provisioning; Cohort 7–11 disposition reconciler (`scripts/reconcile_outreach_dispositions.py`, 0 undispositioned, 46 suppressed contacts hard-quarantined); anti-bounce contact deliverability gate (`scripts/verify_contacts.py --preflight`) shipped |
| **Phase 3 — AI-Search Authority** | 🟡 **in progress** | Benchmark published and cited from About page; dedicated OpenGraph & Twitter preview cards configured across all 7 public pages; dated methodology footnotes attached to all quantitative marketing claims (`< 12s scan latency`, `52 provider signatures`, `10,493% ROI benchmark`); 95/95 byte-identical docs parity confirmed |
| **Phase 4 — Scale & Harden** | 🟡 **in progress** | Fleet Command Center scoring parity & per-client score deltas (`old_score` → `new_score`, `score_change`, dynamic badges, drift events) shipped in `src/orbit_security/fleet.py` and `landing/fleet.html`; Full-Scope 27-Program Bounty Radar triage engine (`src/orbit_security/bounty_radar.py`) with takeover/RCE prioritization and atomic state persistence; social governor spacing ledger unified with operator manual posts to eliminate refusal loops; W4.3 voice narration pipeline hardened (`DegradedAudioError`, silent audio publish blocker in `video_generator.py` and `creative_engine.py`); 1,769 tests green |

**Operator actions this cycle produced, none of which can be done by an agent:** send the 13 correction emails, publish the roast thread, apply the suppression list and launch the 12 re-target cohort, register the Search Console property, publish to PyPI, and decide the public-repo lead-data question (T38).

---

### 0.2 Dimension snapshot

| Dimension | Reality on 2026-11-01 | Where it needs to be |
|---|---|---|
| Live surface | **0** declared 404s; 14/14 live URLs 200 on the release gate; all 6 `SENT` Fleet Pilot agency portals (`10up`, `alley_interactive`, `absolute_web`, `akqa`, `august_ash`, `astound_commerce`) provisioned in both `landing/portals/` and `docs/portals/` (95/95 shared files byte-identical); 15 adversarial fuzzing test files purged | 0 broken references ✅ |
| Structured data | **20 of 20** public pages (core product, legal, agency portals, and StealthBridge) carry JSON-LD on one shared `Organization @id` | every indexable page ✅ |
| AI-search readiness | robots.txt (AI-crawler allowlist), sitemap.xml (15 URLs), security.txt, llms.txt, SECURITY.md live; **Search Console property still unregistered** | indexed + AI-feature eligible |
| Audit credibility | F now means exploitable risk; 52 audits re-scored, 18 failing → 5; Cohort 11 staged at mean 87.0 (100% ≥ C+); 0 un-dispositioned records across Cohorts 7–11; 46 suppressed contacts quarantined | Cohort 11 at the new floor (mean ≥ 60) ✅ |
| Revenue | $0 balance, 0 retainers, 178 campaigns dispatched, 43 hard bounces (24.2 %); Stripe live tier links ($29, $59, $99) wired across all pages and `STRIPE_SECRET_KEY` unified | ≥ 3 active retainers |
| Delivery | 135 delivered, 43 hard-bounced, 12 verified recovery contacts wired into `KNOWN_LEADERSHIP_OSINT`; `verify_contacts.py --preflight` blocks unverified outreach; `--followup` strictly filters `SENT` leads with RFC 5322 `In-Reply-To`/`References` threading | ≥ 8 % reply rate, ≤ 3 % bounce |
| Automation | `orbit_daemon.py status` (`cmd_status`) live-probes TCP ports, process command lines, and `hut-daemon` services; `daily_briefing.py` reconciles CI failures against live GitHub `HEAD` | 16 of 16, no stale states |
| Engineering | **1,769 tests green**, hermetic test suite, composite GitHub Action (`v1.1.0`) with SARIF 2.1.0 export, RFC 7208 SPF Tree Analyzer & 1-Click DNS Fix Pack Exporter, W4.3 voice narration pipeline hardening, CI enforcing tests + `landing`/`docs` parity (95/95 byte-identical) + live-asset health + 371/371 AST Sentinel clean | green at any hour, CI-enforced ✅ |
| Install path | `pip install orbit-security` does not resolve on PyPI yet; `[project.optional-dependencies].dev` includes `pytest-asyncio>=0.23.0` so `pip install -e ".[dev]"` works cleanly | published on PyPI (T37) |

**The one-line diagnosis:** the machine is in good shape; the *claims* the machine makes about itself — to prospects, to search engines, and in its own audit output — are not yet true. This roadmap is mostly about making them true.

### 0.3 The two numbers that changed the plan

Measured on 2026-10-22 with `scripts/outreach_metrics.py` (new):

| Finding | Evidence | Consequence |
|---|---|---|
| **The F-grade bug is systemic, not a Cohort 10 accident.** Every cohort contains F grades, and two audits scored **0/100** and **5/100**. | cohort_8 min=0, cohort_7 min=5, cohort_10 F×4, cohort_9 F×1, cohort_7 F×2, cohort_8 F×2, cohort_6 F×1 | Agencies received audits scoring zero. The scoring fix (Phase 1) is therefore a **customer-facing remediation**, not a nicety — cohorts 7–10 must be re-scored and re-sent. |
| **The cold-email channel is not working.** 178 campaigns dispatched → **43 hard bounces (24.2 %)**, and of 34 tracked threads: **11 explicit rejections, 8 out-of-office, 5 ticket acks, 4 unclear, 3 newsletters, 3 bounces → 0 meaningful conversations, 0 high-intent.** | `data/dispatched_campaigns.json` (status `BOUNCED`), `data/bounced_agencies.json`, `data/leads_state.json` | The root cause is now measured, and it is **not** the sending infrastructure: **43 of the 46 bounced domains publish valid MX records**, and their mail-provider mix (Google 65 %, MS365 7 %) is statistically identical to the delivered set (Google 76 %, MS365 10 %). We were **guessing mailboxes that do not exist**. 11 rejections against 0 conversations means the pitch or the targeting is also wrong. **Cadence discipline cannot fix this — the channel needs triage.** |

---

## 1. Guiding principles

1. **Quality is the wedge.** A scanner that grades a clean estate F because it is missing a BIMI logo is worse than no scanner. Every phase below gates on "the claim is true", not "the feature shipped".
2. **Non-commodity beats volume.** We would rather publish one honest benchmark dataset and one real engagement write-up than 30 SEO pages. Google explicitly says AI visibility comes from first-hand, non-commodity content.
3. **One source of truth per artifact.** `landing/` is the source; `docs/` is the deploy mirror; a CI job proves they match. No more hand-editing both.
4. **Quota-aware by design.** X (2 posts/day, 8 h spacing), Drive (8 tx/s), the disclosure sweep window (02:00–05:00 MST) — every growth engine has a ceiling, so nothing may depend on a single quota.
5. **Human-in-the-loop publishing.** Anything public (X posts, cold email, disclosures) is generated by the machine, verified by the operator, published by the operator.
6. **Ship the boring work.** Robots.txt, sitemaps, favicons, CI, status reconciliation. These are the tasks that look like nothing and compound into everything.

---

## 2. Phase plan

### Phase 0 — Trust Surface · *Days 1–2* · "Make the machine-readable claims true"

**Why first:** every other phase depends on the site being credible to a crawler, a prospect's browser, and a shared link. We are currently shipping an About page whose own JSON-LD points at a 404 logo.

| Workstream | Deliverables | Owner | Exit gate |
|---|---|---|---|
| W0.1 Trust assets | `og-image.png` (1200×630), `logo.png` (512×512), `favicon.ico`; `robots.txt` with explicit AI-crawler allowlist; `sitemap.xml` (7 URLs); `/.well-known/security.txt` (RFC 9116); optional `llms.txt` | Agent 1 | Every asset HEAD → 200 |
| W0.2 About-page GEO | standalone `Person` entity, `jobTitle` consistency, meta description 181 → ~155 chars, `og:image` dims + `twitter:image`, `BreadcrumbList`, `speakable` on Key Facts, `areaServed`/`availableLanguage` | Agent 2 | JSON-LD parses; all `@id` refs resolve; visible copy == markup |
| W0.3 Hub structured data | `WebSite` + `Organization` (shared `@id` with About) + `SoftwareApplication`/`Offer` + `BreadcrumbList` on `index.html` | Agent 3 | One entity graph across `/` and `/about.html`; Rich Results Test 0 errors |
| W0.4 Publish hygiene | commit the 6 untracked operator scripts + 2 telemetry files; push; verify live 200s | Operator | `git status` clean; live re-HEAD |

**Exit gate:** zero non-200 references across the public surface; `sitemap.xml` submitted in Search Console; property eligible for generative AI features.

---

### Phase 1 — Product Integrity · *Days 2–7* · "Stop shipping false grades"

**Why second:** the roast campaign we are about to publish is only credible if the fix is real and shipped. We do not post about a fix that has not landed.

| Workstream | Deliverables | Owner | Exit gate |
|---|---|---|---|
| W1.1 Scoring model | separate *exploitable risk* from *hygiene checklist*; best-practice-only items → INFO; no CRITICAL/HIGH ⇒ grade ≥ C; diminishing returns per finding class; align `recon.calculate_score()` with `models.calculate_grade_and_score()` via a shared `scoring.py` | Agent 4 | New `tests/test_audit_scoring.py` green; 513 existing tests still green |
| W1.2 Evidence | `scripts/rescore_audit_evidence.py` re-scores every stored audit MD under old vs new model; before/after table | Agent 4 | Table shows no F-grade estate remaining on hygiene-only findings |
| W1.3 Test determinism | inject the clock into the disclose window logic so `test_disclose_dry_run_outside_window` is hour-independent | Agent 6 | Suite green at 00:00 and 04:00 MST |
| W1.4 CI gates | `.github/workflows/orbit-ci.yml`: pytest + JUnit artifact, `landing/`↔`docs/` parity check, public-asset HEAD sweep | Agent 6 | A divergent PR fails the build |
| W1.5 Quota hardening (done) | Drive: `--tpslimit 8 --tpslimit-burst 1 --max-backlog 10` on both rclone paths; 403/429 → `QUOTA_DEFERRED`; stale `RUNNING` → `STALE` reconcile (recovered 2 stale entries today) | Operator | No new `403 Quota exceeded`; backup board never lies |

**Exit gate:** the F grades are explained, fixed, measured, regression-tested, and enforced in CI. Only now does Phase 2 include publishing the story.

---

### Phase 2 — Revenue Loop · *Week 2–6* · "Turn audits into retainers"

**Why third:** credibility is worthless without cash conversion. 178 campaigns with $0 collected is the biggest gap in the business, not the product.

| Workstream | Deliverables | Owner | Exit gate |
|---|---|---|---|
| W2.1 Checkout loop | one verified end-to-end Stripe cycle: checkout → webhook → subscriber provisioning → agency portal generation; validate $59/mo and $299–$499 tier links; Client Bundle Exporter (`client_bundle_exporter.py`) white-label ZIP provisioning | Operator + Agent 4 | A live test client with a working portal + atomic ZIP export bundles ✅ |
| W2.1b **Audit remediation** | re-score Cohorts 7–10 under the new model; re-send corrected grades to every agency that received an F, D, 0/100 or 5/100 audit, with a short, non-apologetic note ("your score was wrong; here is the corrected report") | Sentinel + Operator | Every F/D recipient has a corrected audit |
| W2.2 Cohort quality | Cohort 11 with mean ≥ 60 and ≥ 7/10 at grade C+, under the fixed scorer | Sentinel | Cohort 11 matrix meets the floor (mean 87.0, 100% ≥ C+, zero hygiene Fs) ✅ |
| W2.3 Bump cadence | 24–36 h gestation honoured; the 46 suppressed addresses re-verified before any re-send; every agency carries a disposition (`scripts/reconcile_outreach_dispositions.py`) | Nova | 0 un-dispositioned agencies across Cohorts 7–11; 46 suppressed addresses quarantined ✅ |
| W2.4 **Channel triage (new)** | **Root cause measured: we guessed mailboxes.** `scripts/verify_contacts.py` checks the exact address (MX + the agency's own published contact page) instead of the domain. Result on the 43 bounced agencies: **16 REFUTED** (domain accepts mail, our address does not exist), **12 with a published replacement address found**, **3 NO_MX** (cannot receive mail at all), **3 CONFIRMED** (address is published; the bounce was mailbox-level). Next: review the 11 rejections for the real objection, and A/B the subject + opening line with a 30 % holdout across the next 3 cohorts. | Operator + Nova | Bounce ≤ 3 %, and a measured reply-rate lift or a documented pivot |
| W2.5 Deliverability | Postmaster Tools reputation ≥ 0.9 daily watch; cohort size cap 10; ≥ 24 h spacing; **pause sending until the bounce rate is under 10 %** | Nova | Hard bounce ≤ 3 % per cohort |
| W2.6 First case study | one real engagement documented end-to-end (with the agency's permission) — the first non-commodity, first-hand content asset the business owns | Operator | 1 published case study + 1 inbound reference |

**Exit gate:** ≥ 3 active retainers, ≥ 8 % reply rate on new cohorts, ≤ 3 % bounce rate, one written case study.

---

### Phase 3 — AI-Search Authority · *Week 3–8* · "Become the cited answer"

**Why:** the About page is a landing pad, not a moat. Authority comes from primary data and corroboration that AI systems can resolve.

| Workstream | Deliverables | Owner | Exit gate |
|---|---|---|---|
| W3.1 Own a benchmark | publish the takeover-signature accuracy + audit-latency benchmark as a reproducible dataset (`orbit-recon --benchmark`) with methodology, dates and sample size — the GEO paper's "statistics + citations" tactic, but real | Operator + Agent 4 | **DONE** — `docs/benchmark/` publishes measured latency, 52 provider signatures / 76 fingerprints / 69 hostname classes, the false-positive guard self-test and the scoring replay. Every number is bound to `benchmark_results.json` at build time; the limits are stated; the page audits our own claims and says where "< 12 s" does **not** hold. |
| W3.2 Prompt panel | weekly 12-query × 4-engine panel (ChatGPT / Perplexity / Gemini / Claude) logging mentions + citations to `data/geo_panels.jsonl`, surfaced in the daily briefing | Agent 5 + CI | ≥ 4/12 queries mention Orbit by week 8 |
| W3.2b Link the benchmark from the About page | the About page's "Key Facts" block and the hub CTA should point at the measured dataset, not at the assertion | Operator | `about.html` links `/benchmark/` with the median latency and signature count sourced from the benchmark |
| W3.3 Corroboration | publish the package to PyPI (T30), link it in the founder entity, complete HackerOne/Bugcrowd KYC, publish the founder story on LinkedIn | Operator | Package installable; 3+ independent profiles agree on the same facts |
| W3.4 Entity consolidation | one canonical entity across site, GitHub, PyPI, X, Stripe, and (Phase 4) a branded domain | Operator | Same `@id`/`sameAs` everywhere; custom domain live |
| W3.5 Claim hygiene | methodology footnotes for "< 12 s", "52 provider signatures", "10,493 % ROI" across all landing pages; dedicated OpenGraph & Twitter preview cards configured | Operator | Every published number has a footnote + date; 0 card fallbacks ✅ |

**Exit gate:** 8/8 pages indexed, ≥ 4/12 panel queries mention the brand, ≥ 25 % of mentions carry a citation, zero unsourced numbers.

---

### Phase 4 — Scale & Harden · *Week 6–12* · "Automate without losing the plot"

| Workstream | Deliverables | Owner | Exit gate |
|---|---|---|---|
| W4.1 Fleet parity | Fleet Command Center reflects the new scoring model; per-client score deltas (`record_score_delta()`, dynamic badges, drift events) | Guardian | Fleet shows the same grades as the CLI + dynamic deltas ✅ |
| W4.2 Radar coverage | every sweep iterates all 27 registered programs; severity triage prefers takeover/RCE class over LOW-CORS noise; atomic state persistence (`data/bounty_radar_state.json`) | Sentinel | `programs_scanned` ≥ 20 per sweep ✅ |
| W4.3 Voice pipeline | authorised or local TTS; degraded assets can never be published (`DegradedAudioError`, silent audio publish blocker in `video_generator.py` and `creative_engine.py`) | Sentinel | A narrated asset renders real speech; degradation raises a flag ✅ |
| W4.4 Repo hygiene | `landing/` is the only source; sync script + CI parity; stale published handoff docs moved out of `docs/` | Agent 6 + Operator | Drift = 0, enforced ✅ |
| W4.5 Brand surface | custom domain + HTTPS; per-page social cards (Core / Fleet / GhostDNS / Portals / Benchmark / About / Signup); favicon/brand kit everywhere | Operator | 0 preview regressions across 7 public pages ✅ |
| W4.6 X quota unification | operator posts recorded in the same ledger the governor reads (`check_social_spacing_governor`); the daemon idles instead of logging a refusal loop | Guardian | No "quota reached" refusal while a manual post is live ✅ |

**Exit gate:** 16/16 daemons green, 0 stale states, 0 broken references, radar full-scope, docs↔landing drift 0.

---

## 3. Execution model — how the team ran

This cycle was executed as **one coordinator + six parallel agents with exclusive file ownership**, so no two agents could ever collide on a file:

| Agent | Workstream | Exclusive files |
|---|---|---|
| 1 | Trust assets | `docs/`, `landing/` asset + policy files |
| 2 | About-page GEO | `docs/about.html`, `landing/about.html` |
| 3 | Hub structured data | `docs/index.html`, `landing/index.html` |
| 4 | Scoring model | `src/orbit_security/{models,recon,scoring}.py`, `tests/test_audit_scoring.py` |
| 5 | X roast harness | `scripts/post_x_roast_f_grades.py`, `scripts/validate_x_post_lengths.py` |
| 6 | CI + guardrails | `tests/test_disclose_unit.py`, `scripts/sync_landing_to_docs.py`, `.github/workflows/orbit-ci.yml` |
| Coordinator | Roadmap, system-level quota fixes, git hygiene, integration, verification | `ROADMAP.md`, `system/run_dual_backup.py`, `system/drive_watchdog.py`, git ops |

**Rules that made it work:** every agent got absolute paths, an explicit "do not touch" list, a verification command to run, and a required report format. No agent committed to git; the coordinator reviewed, ran the full suite, and committed once.

---

## 4. Operating cadence

| Rhythm | Activity | Owner | Output |
|---|---|---|---|
| Every 30 min | Supervisor health + canary probe | automated | cockpit board, no silent failures |
| Daily 09:00 | Daily briefing (revenue, pipeline, radar, daemon) | Nova | `daily_briefings/briefing_YYYY-MM-DD.md` |
| Daily 02:00–05:00 MST | Disclosure sweep window | Sentinel | sealed evidence bundles + state file |
| Weekly (Mon) | Cohort dispatch review: quality floor, bounce rate, reply rate | Carson + Nova | cohort matrix + go/no-go |
| Weekly (Fri) | GEO prompt panel + index coverage + CI review | CI | `data/geo_panels.jsonl`, scorecard delta |
| Monthly | Entity/claim hygiene audit; dependency + quota review; roadmap re-baseline | Carson | updated roadmap + scorecard |

**Escalation:** any CRITICAL finding on our own estate, any quarantine event (CAPTCHA / RATE_LIMIT / auth invalidation) on X, any Drive `QUOTA_DEFERRED` on two consecutive runs, or any test failure that is not hour-dependent ⇒ stop the line and page the operator.

---

## 5. Risk register

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|
| A wrong/embarrassing post reaches @_arsoncode (live account) | Medium | High | dry-run default; 8 h spacing ledger; length validator; held variants hard-blocked; operator publishes | Operator |
| Naming a third-party client in public copy | Low | High | third-party domain reconciliation check in the validator; held variant never publishable | Agent 5 |
| The scoring fix shifts grades on live client audits | Medium | Medium | run the before/after table over all stored audits first; re-score before any new dispatch; version the scoring change in the PDF footer | Agent 4 |
| `docs/` and `landing/` drift breaks a Pages deploy | Medium | Medium | sync script + CI parity gate | Agent 6 |
| Google indexes the site without AI-feature eligibility | Medium | Medium | register GSC property, submit sitemap, verify generative-AI inclusion | Operator |
| X account action (shadowban / lock) | Low | Critical | ≤ 2 posts/day, 8 h spacing, replies manual, circuit breaker on CAPTCHA, no engagement automation | Guardian |
| Backup quota exhaustion leaves stale coverage | Low | Medium | tpslimit + `QUOTA_DEFERRED` + stale reconcile (live today) | Operator |
| Cold-email sender reputation decay | Medium | High | 46-address suppression, cohort cap 10, Postmaster watch, one bounce = prune | Nova |

---

## 6. What we are deliberately NOT doing

- **No more feature work on the audit engine until Phase 1's exit gate passes.** The engine currently misgrades; adding detectors on top of a broken grader makes the product worse, not better.
- **No bulk "GEO content" farm.** Google has stated plainly that scaled content and keyword-stuffed variants are a spam-policy violation, and third-party "GEO" services are not a ranking strategy. We publish data and evidence instead.
- **No `llms.txt` as a strategy.** It ships as a convenience file only; Google ignores it and we will not pretend otherwise.
- **No automated replies, follows, or engagement.** Policy-blocked in the governor and it stays that way.
- **No fabricated social proof.** No invented ratings, no invented customer logos, no unsourced ROI numbers.
- **No publishing about a fix before the fix is merged, tested, and measured.**

---

## 7. Definition of Done (per work item)

A work item is done only when **all** of the following hold:

1. Implemented in the source of truth (`landing/`, `src/`, `scripts/`) — never only in the mirror.
2. Covered by a test (new behaviour) or explicitly documented as untestable with a reason.
3. Full suite green, including the hour-independent disclose test.
4. `landing/` ↔ `docs/` parity verified.
5. Live-surface re-verified by HTTP HEAD for anything web-facing (200 expected; no new 404).
6. Committed with a message that states the *why*, and pushed to `origin/main`.
7. Recorded in the handoff task register with a status flip and evidence.

---

## 8. Next 14 days at a glance

| Day | Milestone |
|---|---|
| 1 | Phase 0 complete: trust assets + About GEO + hub structured data live; sitemap submitted |
| 2 | Phase 1 complete: scoring model shipped, re-score table published, tests green, CI gate on |
| 3 | Roast thread published (4 posts) after operator review; first standalone post |
| 4–5 | Stripe end-to-end test; Cohorts 7–10 dispositions closed; Cohort 11 re-scored under the new model |
| 6–7 | Benchmark dataset v1 published; PyPI release; founder entity updated |
| 8–10 | Cohort 11 dispatched at the new quality floor; case study drafted with one agency |
| 11–14 | Custom domain + per-page social cards; GEO panel shows first panel deltas; roadmap re-baselined |

---

## 9. 4-Day Sovereign Autonomous Sprint (OpenRig & KaiExplains Architecture)

**Execution Window:** Nov 9–13, 2026 · **Execution Engine:** OpenRig Autonomous Daemon (`A:\system\deepcoder`) · **Cost:** $0.00 Cloud Tokens

### 9.1 Hardware & Concurrency Invariants (KaiExplains Architecture)
- **Memory-Bandwidth Roofline**: Governed by Tiger Lake UP3 sustained dual-channel UMA bandwidth (~28.5 GB/s).
- **Concurrency Floor**: Maximum 2 concurrent seats (`max_concurrent_seats = 2`). Parallel batching beyond 2 seats saturates memory bus and risks thermal throttling past 28W cTDP.
- **KV Cache Quantization**: All long-context tasks enforce quantized KV cache (`-ctk q8_0 -ctv q8_0`), saving 50% RAM and reducing decode bus traffic.
- **Quantization Standard**: IQ4_XS (Importance Matrix) at 4.0 bits/weight standard for 7B/9B models, cutting memory bandwidth requirements by ~19% compared to Q4_K_M.
- **Hardware Isolation**: Pinned to physical cores `[0, 2, 4, 6]` with `BELOW_NORMAL_PRIORITY_CLASS`. Peak thermal ceiling < 83°C (currently ~39–49°C).

### 9.2 Pipelined Assembly Line (OpenRig Topology)
Tasks flow across specialized, domain-isolated seats in persistent SQLite WAL storage (`deepcoder_rig.db`):
1. **Recon & Bounty Sweeps** (`rig-bounty-hunter` / `orbit-osint`): Continuous passive audits across 38 enrolled programs (Shopify, GitLab, Yahoo, Uber, PayPal, etc.).
2. **Safe Harbor CVD & PII Screening** (`rig-compliance-guard` / `orbit-guard`): Inline Llama-Guard-3 verification in <250ms ensuring zero PII leaks and RFC 9116 compliance.
3. **Infrastructure-as-Code Fixpacks** (`rig-coder-core` / `orbit-coder`): Compiles Terraform Cloudflare resources, BIND 9 zone lines, and Cloudflare API JSON for detected SPF PermErrors.
4. **B2B Executive Teardown Campaigns** (`rig-outreach-copywriter` / `orbit-copywriter`): Synthesizes high-urgency 3-sentence briefings staged in `data/staged_campaigns/` for operator 1-click review.
5. **Continuous Nuclei Template Synthesis** (`rig-bounty-hunter`): Automatically converts 52 SaaS takeover signatures into Nuclei v3 YAML templates in `data/nuclei_templates/`.
6. **Code Hygiene & Pre-Commit Sentinels** (`rig-maintenance-janitor` / `orbit-coder-fast`): AST linting, dirty tree recovery, and Conventional Commit hygiene.
7. **Strategic Revenue Loop Ideation** (`rig-brainstormer` / `orbit-brainstormer`): GraphRAG traversal for high-leverage monetization hypotheses.

---

*Roadmap maintained by the coordinator. Next revision: on completion of Phase 1 exit gate, or on any material change to the live site.*
