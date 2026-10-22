# 🛡️ Orbit Security — Detailed Operational & SEO/GEO Handoff

**Document:** `detailed_handoff_orbit_security.md`
**Generated:** 2026-10-22 (MST) · **Author:** Nova (Project ORBIT Sentinel, co-piloted)
**Project Root:** `A:\projects\orbit-security` (= `C:\AgyHut\projects\orbit-security`)
**Live Showcase:** <https://cmfh009.github.io/Orbit-Security/>
**Git:** `origin/main` @ `7a9affc` — working tree synced with remote except 2 modified + 6 untracked files
**Prior handoff:** [`docs/SESSION_HANDOFF_ORBITSEC_AND_ECOSYSTEM.md`](file:///A:/projects/orbit-security/docs/SESSION_HANDOFF_ORBITSEC_AND_ECOSYSTEM.md) (2026-10-04)

---

## 1. Executive Summary

### 1.1 What was completed (since the 2026-10-04 handoff)

| Area | Delivered | Evidence |
|---|---|---|
| **SEO / AI-search** | New high-visibility **About Us page** (549 lines) with Schema.org `@graph` (Organization + Person + Place + ContactPoint + WebPage + FAQPage), canonical, OG/Twitter meta, FAQ block, Key-Facts block. Mirrored into both `docs/` (deployed) and `landing/` (source) trees and linked from the hub nav + footer. | `7a9affc` |
| **Scanner / recon** | Composer/PHPUnit RCE pre-screening, `pearcmd` hardening, HTTP 418 Teapot sinkhole rules, exposed `.env`/`.git` detection | `7f0c76e` |
| **Takeover simulator** | 4th live attack scenario (PHP Bot / CVE-2017-9841) wired into the radar terminal; deep-link `#simulate` + `#flipbook` hash triggers | `d7c5c8b` |
| **Outreach pipeline** | **Cohort 10** staged + dispatched live (10 PHP / WordPress VIP / Laravel / Drupal agencies, 2026-10-22 03:22); Cohorts 6→9 dispatched; Cohort 7/8 bounce recovery executed; `data/dispatched_campaigns.json` now holds **178** campaign records | `data/cohort_10_matrix.md` |
| **Media / brand** | 1080p "Boast & Roast" showcase video + fixed X header/avatar/card graphics deployed and verified 200 on Pages | `cbc81cf` |
| **Page engineering** | ROI calculator, PDF flipbook modal, client-pitch drawer, breaking-advisory banner, perimeter-test CTA, plus a layout/contrast/badge-overflow fix sweep across all portals | `0215f12`, `3260432`, `15cee84` |
| **CI / packaging** | GitHub Action "Orbit Security Perimeter Sentinel" with target file, fail-on-critical gating and artifact upload; release + CI badges on README | `1bdc3bc` |
| **Debt burn-down** | Rule-based finding reduction, bounty-radar sweep cadence, hardening of the daemon governor | `9abaaf9`, `9c08745`, `780103e` |

### 1.2 Current system state (verified 2026-10-22 04:27 MST)

```
Master Supervisor   🟢 ACTIVE (PID 19588)      Memory Governor  🟢 GREEN (7,250 MB free, 55.0% used)
Canary Probe       🟢 HEALTHY                 CPU Governor     < 92% (BelowNormal priority)
Bounty Radar       🟢 INITIALIZED (120 sweeps, 3,094 findings, 27 programs registered)
16 managed micro-daemons → 15 🟢 RUNNING, 1 🔴 STOPPED (Orbit Social Agent)
Windows Auto-Boot  🟢 INSTALLED (auto-boots on logon)
```

- **Test suite (run 2026-10-22, `pytest -q`, 111.44 s):** **513 passed, 1 failed** — `tests/test_disclose_unit.py::test_disclose_dry_run_outside_window`. **Not a regression:** the test asserts "would NOT execute", but `src/orbit_security/cli.py:226-227` evaluates the off-peak window against wall-clock UTC, so the assertion inverts whenever the suite runs inside the 02:00–05:00 MST sweep window (this run landed at ~04:27 MST). It is a time-dependent flake and must be clock-injected — see task **T29**.
- **Live-site smoke test (HTTP HEAD, verified today):** `/` 200 · `/about.html` 200 · `/fleet.html` 200 · `/signup.html` 200 · `/portals/index.html` 200 · `/ghostdns/index.html` 200 · `/sample_audit.pdf` 200 · `/terms.html` 200 · `/disclaimer.html` 200 · new brand media (`.mp4`, `.jpg`) all 200.
- **Failing asset checks (new finding, remediation in §3.4 G1–G6 and §5 T1/T2/T5/T6):** `/assets/og-image.png` **404**, `/assets/logo.png` **404**, `/robots.txt` **404**, `/sitemap.xml` **404**, `/llms.txt` **404**, `/.well-known/security.txt` **404**, `/favicon.ico` **404**.
- **Revenue telemetry (last briefing, 2026-10-21):** Stripe available balance **$0.00**, **0** active $59/mo subscriptions, **9** tracked inbound threads, **0** high-intent escalations, **145** agencies dispatched live / **178** campaigns in the registry, **46** hard-bounced addresses suppressed.
- **Deliverability (Cohort 6 sample, n=10):** 90.0 % delivery (9/10), 1 hard bounce (`metacake.com`, 550 Mailbox unavailable) → pruned by the IMAP bounce sentinel.
- **Cohort 10 quality warning:** 4 of 10 dispatched audits graded **F** (35–40/100) — see §5, task **T14**.

### 1.3 The four things that matter most right now

1. **Trust surface is half-built.** The About page exists and is excellent, but the schema it declares points at assets that 404 (`logo.png`), the social preview image 404s, and there is **no robots.txt, no sitemap, no security.txt**. AI engines and Google will under-credit a brand whose machine-readable claims do not resolve.
2. **The money page has no structured data at all.** `index.html` — the highest-value page — carries **zero** JSON-LD, while `about.html` carries rich entities. GEO distribution is inverted.
3. **Quotas are throttling two engines.** The X governor caps programmatic posts at 2/day (operator desktop automation now carries the load), and Google Drive rejected two backup transfers with `403 Quota exceeded` (no `--tpslimit` throttle). Details and fixes in §4.
4. **Published install instructions do not resolve.** The X thread, `content_queue.py`, the social-growth playbook and the staging scripts all tell users to run **`pip install orbit-security`** — but `pypi.org/pypi/orbit-security/json` returns **404** (verified 2026-10-22). The package is not on PyPI, so every published install line fails at the first command. See task **T30**.

---

## 2. Artifact List (direct links)

### 2.1 Web-surface artifacts

| Artifact | URL | Status |
|---|---|---|
| Production showcase (hub) | <https://cmfh009.github.io/Orbit-Security/> | 200 |
| **About Us page (new)** | <https://cmfh009.github.io/Orbit-Security/about.html> | 200 |
| Fleet Command Center | <https://cmfh009.github.io/Orbit-Security/fleet.html> | 200 |
| Onboard / signup | <https://cmfh009.github.io/Orbit-Security/signup.html> | 200 |
| White-label agency portals | <https://cmfh009.github.io/Orbit-Security/portals/index.html> | 200 |
| GhostDNS sentinel | <https://cmfh009.github.io/Orbit-Security/ghostdns/index.html> | 200 |
| Sample white-label audit (PDF) | <https://cmfh009.github.io/Orbit-Security/sample_audit.pdf> | 200 |
| Terms / Privacy / Refunds / RFC Disclaimer | `/terms.html` · `/privacy.html` · `/refunds.html` · `/disclaimer.html` | 200 |
| "Boast & Roast" showcase video | <https://cmfh009.github.io/Orbit-Security/assets/orbit_boast_roast_2026.mp4> | 200 |
| X brand kit (header / avatar / card) | `/assets/orbit_x_header_2026.jpg` · `/assets/orbit_x_avatar_2026.jpg` · `/assets/orbit_x_boast_roast_card.jpg` | 200 |
| Hub OG image (in use) | <https://cmfh009.github.io/Orbit-Security/assets/orbit_cats_pounce.jpg> | 200 |
| **About-page OG image (declared)** | `/assets/og-image.png` | **404 — must fix** |
| **Organization logo (declared in JSON-LD)** | `/assets/logo.png` | **404 — must fix** |
| **robots.txt / sitemap.xml / llms.txt / security.txt** | — | **all 404 — must create** |

### 2.2 Repository artifacts

| Artifact | Path (click to open) | Notes |
|---|---|---|
| **This handoff** | [`detailed_handoff_orbit_security.md`](file:///A:/projects/orbit-security/detailed_handoff_orbit_security.md) | You are here |
| Prior handoffs | [`handoff.md`](file:///A:/projects/orbit-security/handoff.md) · [`docs/SESSION_HANDOFF.md`](file:///A:/projects/orbit-security/docs/SESSION_HANDOFF.md) · [`docs/SESSION_HANDOFF_ORBITSEC_AND_ECOSYSTEM.md`](file:///A:/projects/orbit-security/docs/SESSION_HANDOFF_ORBITSEC_AND_ECOSYSTEM.md) | |
| **About Us page (deployed copy)** | [`docs/about.html`](file:///A:/projects/orbit-security/docs/about.html) (39,944 B) | GitHub Pages root |
| **About Us page (source copy)** | [`landing/about.html`](file:///A:/projects/orbit-security/landing/about.html) | Byte-identical to `docs/` |
| Hub page (deployed / source) | [`docs/index.html`](file:///A:/projects/orbit-security/docs/index.html) · [`landing/index.html`](file:///A:/projects/orbit-security/landing/index.html) | 273,546 B, identical pair |
| Security audit report | [`docs/SECURITY_AUDIT_REPORT.md`](file:///A:/projects/orbit-security/docs/SECURITY_AUDIT_REPORT.md) | 28,806 B |
| Anti-ban / social audit | [`reports/security_anti_ban_audit.md`](file:///A:/projects/orbit-security/reports/security_anti_ban_audit.md) | 17,948 B |
| Social pipeline architecture | [`docs/architecture_social_pipeline_daemon.md`](file:///A:/projects/orbit-security/docs/architecture_social_pipeline_daemon.md) | quota ceilings spec |
| Relevance intelligence spec | [`docs/relevance_intelligence_engine_spec.md`](file:///A:/projects/orbit-security/docs/relevance_intelligence_engine_spec.md) | scoring model |
| X browser automation architecture | [`docs/x_browser_automation_architecture.md`](file:///A:/projects/orbit-security/docs/x_browser_automation_architecture.md) | |
| Monolith ADR | [`docs/adr/ADR-0004-dhh-loop-orbit-security-monolith.md`](file:///A:/projects/orbit-security/docs/adr/ADR-0004-dhh-loop-orbit-security-monolith.md) | |
| Cohort 10 matrix (newest outreach) | [`data/cohort_10_matrix.md`](file:///A:/projects/orbit-security/data/cohort_10_matrix.md) | 10 agencies, 2026-10-22 |
| Cohort 9 matrix | [`data/cohort_9_matrix.md`](file:///A:/projects/orbit-security/data/cohort_9_matrix.md) | |
| Bounce suppression list | [`data/bounced_agencies.json`](file:///A:/projects/orbit-security/data/bounced_agencies.json) | 46 entries |
| Dispatched campaign registry | [`data/dispatched_campaigns.json`](file:///A:/projects/orbit-security/data/dispatched_campaigns.json) | 178 records |
| Bounty radar state | [`data/bounty_radar_state.json`](file:///A:/projects/orbit-security/data/bounty_radar_state.json) | 120 sweeps / 3,094 findings |
| Bounty program registry | [`data/bounty_programs.json`](file:///A:/projects/orbit-security/data/bounty_programs.json) | 27 programs |
| social.txt registry (CT-driven) | [`data/security_txt_registry.md`](file:///A:/projects/orbit-security/data/security_txt_registry.md) · `.json` | 96 KB |
| Daily briefings | [`daily_briefings/`](file:///A:/projects/orbit-security/daily_briefings/) | latest `briefing_2026-10-21.md` |
| Cohort-6 triage briefing | [`daily_briefings/briefing_cohort6_triage_2026-10-21.md`](file:///A:/projects/orbit-security/daily_briefings/briefing_cohort6_triage_2026-10-21.md) | |
| Discord/GitHub Action | [`.github/workflows/orbit-perimeter-sentinel.yml`](file:///A:/projects/orbit-security/.github/workflows/orbit-perimeter-sentinel.yml) | `action.yml` in repo root |

### 2.3 Source artifacts touched this cycle

| Area | Files |
|---|---|
| Scanner / recon | [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py) · [`recon.py`](file:///A:/projects/orbit-security/src/orbit_security/recon.py) · [`remediation.py`](file:///A:/projects/orbit-security/src/orbit_security/remediation.py) |
| Social governor | [`src/orbit_security/quota_manager.py`](file:///A:/projects/orbit-security/src/orbit_security/quota_manager.py) · [`social_daemon.py`](file:///A:/projects/orbit-security/src/orbit_security/social_daemon.py) |
| X drivers | [`src/orbit_security/x_driver.py`](file:///A:/projects/orbit-security/src/orbit_security/x_driver.py) · [`desktop_x_bridge.py`](file:///A:/projects/orbit-security/src/orbit_security/desktop_x_bridge.py) |
| Guardrails | [`src/orbit_security/circuit_breaker.py`](file:///A:/projects/orbit-security/src/orbit_security/circuit_breaker.py) (RATE_LIMIT / CAPTCHA → QUARANTINE, 1 h cooldown) |
| Outreach scripts | [`scripts/launch_cohort_10.py`](file:///A:/projects/orbit-security/scripts/launch_cohort_10.py) · [`scripts/recover_bounced_cohorts_7_8.py`](file:///A:/projects/orbit-security/scripts/recover_bounced_cohorts_7_8.py) · [`scripts/launch_x_thread.py`](file:///A:/projects/orbit-security/scripts/launch_x_thread.py) |
| Page-engineering scripts | [`scripts/upgrade_github_pages_all_4.py`](file:///A:/projects/orbit-security/scripts/upgrade_github_pages_all_4.py) (46 KB) · [`scripts/capture_orbit_pages_audit.py`](file:///A:/projects/orbit-security/scripts/capture_orbit_pages_audit.py) |
| **Untracked (need commit decision)** | `scripts/post_boast_and_roast_x.py` · `scripts/post_video_boast_roast_x.py` · `scripts/finish_video_post_x.py` · `scripts/post_x_thread_continuation.py` · `scripts/get_top_tweet.py` · `scripts/check_x_profile_scroll.py` |

---

## 3. In-depth SEO / AI-Search (GEO) Research — About Us Page

### 3.1 How AI retrieval actually works (ground truth)

Source of truth: **Google — "Optimizing your website for generative AI features on Google Search"** (`developers.google.com/search/docs/fundamentals/ai-optimization-guide`, page last updated **2026-07-10**).

- Google AI features are **RAG (grounding) + query fan-out**: a model fans a single user question into many concurrent sub-queries, retrieves pages from the **Search index**, and cites the pages that support the answer.
- **Therefore**: an AI answer can only cite Orbit Security if Orbit Security is (a) crawlable, (b) indexed, (c) snippet-eligible, (d) structured enough to be selected for a sub-query, and (e) *credible enough to be quoted*.
- **"GEO"/"AEO" is not a separate discipline.** Google explicitly states that "AEO" and "GEO" are third-party terms and that optimizing for generative AI search *is* SEO. Third-party GEO services promising ranking wins are, per Google, not supported.
- **Explicit non-requirements** (things a lot of "GEO" advice sells that Google says you can ignore):
  - **No `llms.txt` needed.** Google ignores it — *"You don't need to create new machine readable files, AI text files, markup, or Markdown to appear in Google Search."*
  - **No content "chunking."**
  - **No special schema for gen-AI.** Structured data is still worth keeping for rich results/entities, but is not required for AI visibility.
  - **No AI-specific rewriting, no long-tail keyword stuffing, no manufactured mentions.**
- **What actually moves the needle:** non-commodity, first-hand, expert content; clear technical structure; crawlable content; good page experience; low duplicate content; images/video that support the text.
- **Agentic layer (new):** browser agents read rendered output, the DOM, and the **accessibility tree** (`web.dev/articles/ai-agent-site-ux`). Semantic HTML, stable ids/labels, and real `<button>`/`<a>` elements matter. Stable Commerce (UCP) is emerging for transactional agents.
- **Academic backing (GEO paper, KDD'24):** targeted optimization — **adding citations, statistics and quotations** — raised generative-response visibility by **up to 40 %**. This is precisely what the new About page's "Key Facts" + "FAQ" blocks attempt.

### 3.2 Second-source GEO consensus (what other AI engines reward)

Cross-checked against Semrush, llmrefs, InSegment, SEO.com, DigitalApplied, Gen-Optima (2026 editions). Common, non-conflicting guidance:

1. **Machine-readable answer blocks** — short, self-contained paragraphs that answer one question and can be lifted verbatim into an answer box.
2. **Question-shaped headings** ("What is Orbit Security?", "Who is the founder…") — matches natural-language queries and fan-out sub-queries. ✅ already done.
3. **Entity consistency** — one canonical entity (name, founder, URL, socials) repeated identically across page, schema, and off-site profiles. Partially done (see §3.4).
4. **Freshness signals** — visible `Last Verified & Updated` + schema `dateModified`. ✅ done.
5. **Third-party corroboration** — GitHub profile, X profile, PyPI package, and press mentions that restate the same facts. Partially done (GitHub + X linked; PyPI not linked from About).
6. **Crawl openness for AI agents** — explicit allow rules for `GPTBot`, `OAI-SearchBot`, `ClaudeBot`, `PerplexityBot`, `Google-Extended`, `CCBot`, `Bytespider` in `robots.txt`. ❌ missing.
7. **Optional `llms.txt`** — *not* used by Google; used by some third-party agents/readers. Cheap, harmless, optional; ship only as a convenience layer, never as a ranking strategy.
8. **Social preview hygiene** — working `og:image` + `twitter:image`; a broken preview suppresses sharing, which indirectly suppresses citation/mention volume. ❌ currently broken on About.

### 3.3 Scorecard — `about.html` (measured, not assumed)

| Dimension | Implementation in `about.html` | Verdict |
|---|---|---|
| Title | `About Us \| Orbit Security — Autonomous Perimeter Intelligence for Web Agencies` (keyword-front, brand-second) | ✅ |
| Meta description | 181 chars — descriptive but **over the ~155-char SERP truncation point**; trim to ≈155 with the entity + value proposition up front | ⚠️ **G15** |
| Canonical | `rel="canonical"` → `https://cmfh009.github.io/Orbit-Security/about.html` | ✅ |
| H1 | Single H1, "About Orbit Security" | ✅ |
| Heading hierarchy | H1 → 8 × H2 → H3 under Team/How-it-works/FAQ (numbered 02–08) | ✅ |
| JSON-LD | `@graph`: `Organization` (founder, foundingDate, foundingLocation, knowsAbout×6, sameAs×2, contactPoint), `Person`, `Place`, `ContactPoint`, `WebPage` (datePublished/dateModified), `FAQPage` (5 Q&A) | ✅ strong |
| Visible FAQ | 5 Q&A rendered in HTML and matching the schema verbatim | ✅ |
| Key facts block | Founded 2026 · <12 s audit latency · 40+ signatures · 10,493 % ROI + HQ/contact/core-focus | ✅ (source them — see gap G4) |
| Freshness | "Last Verified & Updated: October 22, 2026" visible + `dateModified: 2026-10-22` | ✅ |
| AI-crawler access | no `robots.txt` at all (404) | ❌ **G1** |
| Sitemap / discovery | no `sitemap.xml` (404); page is only reachable by in-site links | ❌ **G2** |
| Social preview | `og:image` → `/assets/og-image.png` → **404** | ❌ **G3** |
| Entity logo | `Organization.logo` → `/assets/logo.png` → **404** | ❌ **G3** |
| Favicon | `/favicon.ico` → 404 | ❌ minor |
| Standalone `Person` entity | Person only nested under `Organization.founder` | ⚠️ **G5** |
| `BreadcrumbList` | absent | ⚠️ **G6** |
| `speakable` on Key Facts | absent | ⚠️ **G7** (low value) |
| `SoftwareApplication` / pricing schema | absent on About (correct place = hub) | ⚠️ **G8** |
| `areaServed` / `availableLanguage` | absent | ⚠️ **G9** |
| Hub-page structured data | `index.html` has **zero** JSON-LD | ❌ **G10** (highest leverage) |
| Duplicate trees | `docs/` (deployed) and `landing/` (source) are byte-identical today but hand-edited by 4+ scripts | ⚠️ **G11** |
| Render dependency | About page uses Tailwind Play CDN; content is server-side in HTML (good), styling depends on JS | ⚠️ **G12** |
| Entity copy consistency | Schema `jobTitle: "Founder & Lead Systems Engineer"` vs visible "Founder, Principal Systems Architect & Lead Security Engineer" | ⚠️ **G13** |
| Claim substantiation | "10,493 % ROI", "< 12 s", "40+ signatures" — no methodology, date, or sample | ⚠️ **G14** |

### 3.4 Prioritized remediation (exact changes)

**G1 — `docs/robots.txt` (new file, deploy root).** Make AI crawl intent explicit rather than implicit-by-absence:

```txt
User-agent: *
Allow: /
Sitemap: https://cmfh009.github.io/Orbit-Security/sitemap.xml

User-agent: GPTBot
Allow: /
User-agent: OAI-SearchBot
Allow: /
User-agent: ClaudeBot
Allow: /
User-agent: PerplexityBot
Allow: /
User-agent: Google-Extended
Allow: /
User-agent: CCBot
Allow: /
User-agent: Bytespider
Allow: /
```

**G2 — `docs/sitemap.xml` (new file).** Enumerate every indexable page with `lastmod` — this is what makes fan-out sub-queries discoverable beyond the hub:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://cmfh009.github.io/Orbit-Security/</loc><lastmod>2026-10-22</lastmod><priority>1.0</priority></url>
  <url><loc>https://cmfh009.github.io/Orbit-Security/about.html</loc><lastmod>2026-10-22</lastmod><priority>0.9</priority></url>
  <url><loc>https://cmfh009.github.io/Orbit-Security/fleet.html</loc><lastmod>2026-10-22</lastmod></url>
  <url><loc>https://cmfh009.github.io/Orbit-Security/signup.html</loc><lastmod>2026-10-22</lastmod></url>
  <url><loc>https://cmfh009.github.io/Orbit-Security/ghostdns/index.html</loc><lastmod>2026-10-22</lastmod></url>
  <url><loc>https://cmfh009.github.io/Orbit-Security/portals/index.html</loc><lastmod>2026-10-22</lastmod></url>
  <url><loc>https://cmfh009.github.io/Orbit-Security/sample_audit.pdf</loc><lastmod>2026-10-22</lastmod></url>
</urlset>
```
> Submit in Google Search Console → Sitemaps. **Register the property and submit — a sitemap on a GitHub Pages root is inert until submitted.**

**G3 — Ship the two 404 assets.**
- `docs/assets/og-image.png` — 1200×630 brand card (reuse `orbit_x_boast_roast_card.jpg` as the base, or regenerate via `media_generator.py`); then add `og:image:width`/`og:image:height` and `twitter:image` (both currently missing → Twitter uses `og:image` as fallback, but explicit is safer).
- `docs/assets/logo.png` — 512×512 transparent mark to satisfy `Organization.logo` (required for knowledge-panel/AI entity rendering).
- Add `<link rel="icon" href="/favicon.ico">` + the file.
- Mirror all three into `landing/assets/` (both trees are deployed; `docs/` is what GitHub serves).

**G5 — Promote the founder to a first-class entity.** Add a sibling node to the `@graph` in `about.html` (do **not** replace the nested reference — keep `@id` linkage):

```json
{
  "@type": "Person",
  "@id": "https://cmfh009.github.io/Orbit-Security/#carson-haynes",
  "name": "Carson Haynes",
  "jobTitle": "Founder & Principal Systems Architect",
  "worksFor": { "@id": "https://cmfh009.github.io/Orbit-Security/#organization" },
  "knowsAbout": ["Attack Surface Management","DMARC","DNS","PHP Security","White-Label Security Deliverables"],
  "sameAs": ["https://x.com/_arsoncode","https://github.com/CmfH009","https://pypi.org/project/orbit-security/"],
  "url": "https://cmfh009.github.io/Orbit-Security/about.html#team"
}
```
> Fix **G13** in the same pass: make `jobTitle` identical in the visible `<h3>` block and both schema nodes.

**G6 — Add `BreadcrumbList`** (`Home → About Us`) as a third `@graph` node; pair it with a visible breadcrumb so the markup is not orphaned.

**G8/G10 — Add structured data to the hub (`index.html`)**, which currently has none:

```json
{ "@type": "SoftwareApplication",
  "name": "Orbit Security",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "Any",
  "description": "...",
  "offers": { "@type": "Offer", "price": "59.00", "priceCurrency": "USD", "category": "subscription" },
  "aggregateRating": null }
```
> Also add `WebSite` (+ `SearchAction` only if a site search exists) and reuse the `Organization` node with the **same `@id`** as About so the two pages merge into one entity. Do **not** invent `aggregateRating` — a fake rating is a policy violation, not an SEO win.

**G15 — Trim the About meta description to ≈155 characters.** Current value is 181 chars and will truncate mid-sentence in most SERPs and in AI answer boxes. Rewrite so the entity and the differentiated value land in the first 155 characters, e.g.:

> `Orbit Security is autonomous perimeter intelligence by Carson Haynes: dangling-DNS takeover defense, DMARC enforcement and white-label client audits for web agencies.`

**G14 — Substantiate the numbers.** Add a dated methodology footnote under the Key-Facts block, e.g. *"Audit latency: median of 1,000 scans against public domains, measured on 2026-10-18 via `orbit-recon --benchmark`; retainer ROI: modeled on a 12-client retainer at $1,500/mo vs. a $25k/yr enterprise scanner seat."* AI engines discount numbers they cannot resolve, and Google discourages unsupportable claims.

**G7 (optional) — `speakable`** on the Key-Facts section (`SpeakableSpecification` with `cssSelector`). Cheap, harmless; treat as optional polish, not a ranking lever.

**G11 — Kill the duplicate-tree drift.** `docs/` and `landing/` are byte-identical today but are patched by hand in both places (`upgrade_github_pages_all_4.py`, `capture_orbit_pages_audit.py`, and the About-page commit). Make `landing/` the single source of truth and add `scripts/sync_landing_to_docs.py` + a CI check that fails when `md5(docs/x) != md5(landing/x)`.

**G12 (optional) — Self-host Tailwind** (`landing/input.css` → `assets/styles.min.css` already exists as a compiled artifact) so the About page renders identically without the Play CDN, improving LCP and non-JS crawlers.

### 3.5 Measurement plan (GEO)

| Metric | Tool | Cadence | Target |
|---|---|---|---|
| AI-citation share | Prompt panel: 12 fixed queries ("best subdomain takeover scanner for agencies", "who founded Orbit Security", "white-label security audit for Shopify agencies", …) run across ChatGPT / Perplexity / Gemini / Claude with citation logging | Weekly | ≥ 4/12 queries mention Orbit by week 8; ≥ 25 % of mentions carry a citation URL |
| Index coverage | Search Console → Pages / Indexing | Weekly | All 8 URLs indexed within 21 days of sitemap submission |
| Generative-AI traffic | Search Console → **Generative AI performance report** (`support.google.com/webmasters/answer/16984139`) | Weekly | Track impressions from AI features |
| Eligibility for AI features | Search Console → "Generative AI features" inclusion (`support.google.com/webmasters/answer/16908024`) | Once, then monthly | Property enabled |
| Rich-result validity | Rich Results Test + Schema Markup Validator on `/`, `/about.html` | Per deploy | 0 errors |
| Technical hygiene | Broken-link/asset sweep (HEAD over all `og:image`/`logo`/asset refs) | Per deploy | 0 non-200s |
| Brand-search lift | "Orbit Security" impressions/clicks + @_arsoncode profile referral | Weekly | +20 % MoM |

---

## 4. Quota Remediation — Observations & Mitigation Steps

### 4.1 X (Twitter) posting quota — internal governor

**Observation (verified in code + logs).** `src/orbit_security/quota_manager.py` hard-codes:

```
max_hourly_posts = 1        max_daily_posts = 2
max_hourly_replies = 0      max_daily_replies = 0
max_hourly_follows = 0      max_daily_follows = 0
max_hourly_likes  = 6       max_daily_likes  = 50
max_hourly_reposts = 2      max_daily_reposts = 10
min_post_spacing_hours = 8.0
```

`data/social_daemon.log` records **30+** occurrences of
`POST quota reached or spacing active (scaled to twice a day). Proceeding with continuous following & engagement.` between 2026-10-19 22:04 and 2026-10-22 03:33. The daemon burns cycles doing engagement work while every post attempt is refused.

**Mitigation already in place.** Human-in-the-loop posting through the desktop bridge (`desktop_x_bridge.py` → `system/tools/desktop_automation.py`) with `Ctrl+Enter` submission, 6–8 s pacing between thread elements, and clipboard-based media injection. Operator scripts: `post_boast_and_roast_x.py`, `post_video_boast_roast_x.py`, `post_x_thread_continuation.py` (posts 2/5→5/5 and chains each reply URL via DevTools `copy()`).

**Residual risk.** The daemon's internal budget and the operator's manual cadence are **two different systems** with no shared ledger. A post made manually is invisible to `SocialQuotaManager`, so the governor can still believe it has budget (and vice versa) — the exact mechanism that would trigger a velocity flag on the account.

**Recommended steps.**
1. Write manual publishes into the same state store (`data/orbit_social.db` / `social_state.py`) so the governor sees operator posts. Add `record_external_post()` and call it from the posting scripts after a verified 200 in the profile timeline.
2. Lower the daily ceiling risk profile further during the current ramp: keep ≤ 2 originals/day and ≥ 8 h spacing; treat replies as manual-only.
3. Make the daemon idle instead of logging "Proceeding with continuous following & engagement" — that message implies engagement work continues when replies/follows are set to 0. It should sleep or exit.
4. Restart the **Orbit Social Agent** (currently 🔴 STOPPED in the supervisor) once the ledger is unified, or explicitly retire it from the supervisor manifest.

### 4.2 X automation-policy limits (not quotas, but quota-adjacent)

**Observation.** `max_hourly_replies = 0` and `max_hourly_follows = 0` are enforced in code and logged as `Automated reply_to_tweet refused … Replying is disabled.` and `Automated follow_user refused … Following is disabled.` The `circuit_breaker.py` also quarantines on `RATE_LIMIT`, CAPTCHA, and auth invalidation with a 1-hour cooldown.

**Mitigation.** Keep replies/follows manual; let the breaker own the cooldown; treat any CAPTCHA sighting as a stop-the-line event (do not retry, do not rotate identity).

### 4.3 Microsoft Edge TTS — HTTP 403 quota rejection

**Observation** (`data/social_daemon.log`, 2026-10-20 05:36 and 06:18):

```
Edge TTS network synthesis skipped: 403, message='Invalid response status',
url='wss://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1?TrustedClientToken=…'
Voice synthesis unavailable (403 …); rendering silent audio fallback
```

The unauthenticated Edge endpoint rejects the request (token/edge enforcement), so narrated video/voice assets degrade to a mock/silent audio beacon.

**Mitigation.** Already handled gracefully (mock audio beacon + silent fallback), but the output is not shippable. Recommended: (a) route TTS through a paid/authorised endpoint (Azure Speech, ElevenLabs, or a local Piper/Coqui instance on the Ollama box), and (b) treat "voice assets generated" as a failed asset whenever the beacon path is used — add a non-zero exit / manifest flag so downstream publishing cannot pick up a silent clip.

### 4.4 Google Drive API — `403 Quota exceeded` (backup path)

**Observation** (`system/logs/work_projects_rclone.log`, 2 occurrences, 2026-10-14 05:32):

```
googleapi: Error 403: Quota exceeded for quota metric 'Queries'
and limit 'Previous quota: Requests per minute' of service 'drive.googleapis.com'
for consumer 'project_number:202264815644'.
"quota_limit": "defaultPerMinutePerProject", "quota_limit_value": "840000"
```

The backup fleet (both `system/drive_watchdog.py` and `system/run_dual_backup.py`) runs rclone with `--fast-list --transfers 4 --checkers 8 --checksum` but **no `--tpslimit`**, so a large first sync (e.g. `microgravity/python/browser/.mg_browser_out/`) can burst past the per-minute query budget.

**Mitigation steps.**
1. Add `--tpslimit 8 --tpslimit-burst 1` (and consider `--max-backlog 10`) to both rclone invocations — `system/drive_watchdog.py` (~line 85–95) and `system/run_dual_backup.py` (~line 73).
2. Exclude browser-test artefacts and `node_modules` from the Drive sync (the `.rcloneignore` at `A:\.rcloneignore` exists and is already wired — verify it covers `.mg_browser_out`).
3. Add exponential backoff + retry on `403`/`429` in the backup wrapper, and mark the run `QUOTA_DEFERRED` rather than `FAILED` so the watchdog does not page on a transient quota rejection.
4. Request a quota increase via the URL in the error payload (`cloud.google.com/docs/quotas/help/request_increase`) if sustained > 500 MB/day of new objects.
5. **Stale-state fix:** `system/logs/backup_status.json` still shows `work.projects = RUNNING` since `2026-10-14T17:30:48Z` (8 days). The watchdog is not reconciling a finished-or-aborted run. Force a status reconcile and alert when a job reports `RUNNING` for > 24 h.

### 4.5 SMTP deliverability quota / reputation

**Observation.** `data/bounced_agencies.json` holds **46** hard-bounced addresses (e.g. `swankyagency.com`, `metacake.com`, `anatta.io`, `fuelmade.com`). Cohort 6 delivery was 90 % (9/10, one 550 mailbox-unavailable). `scripts/recover_bounced_cohorts_7_8.py` re-verified contacts before re-dispatch.

**Mitigation.** Keep the suppression list authoritative — the IMAP sentinel must prune on bounce *before* the next send; cap cohort size at 10 with ≥ 24 h spacing; never re-send to a suppressed address without re-verification; watch the Gmail Postmaster Tools reputation gauge daily (target: ≥ 0.9 and no rising "spam rate" alert).

### 4.6 AI-provider token quota telemetry

**Observation.** `system/logs/nova_email_daemon.log` records
`Recorded AI Service Alert: Google AI Pro: Token Quota & Compute Tier Refreshed` (2026-10-19 20:14) — the daemon already watches provider quota-reset events.

**Mitigation.** Route quota-sensitive work to the local Ollama engine (`:11434`, running) when the cloud tier resets; treat the sidekick (`:9008`) as the fallback tier, and keep the cockpit/battlestation (`:9090`) as the last-resort UI.

### 4.7 Bounty-radar window (schedule-bound, not a hard quota)

**Observation.** Supervisor reports `Bounty Radar: 🟢 INITIALIZED (Last: Awaiting 2:00–5:00 AM MST | Vulns Found: 0)`; the radar sweeps inside a 02:00–05:00 MST window, and `data/bounty_radar_state.json` currently records `programs_scanned: ["shopify"]` for the last sweep even though **27** programs are registered in `data/bounty_programs.json`.

**Mitigation.** (a) Verify the sweep actually iterates all 27 programs and that `programs_scanned` reflects coverage rather than the last program; (b) if the window is genuinely a rate-limit courtesy window, record `sweep_window_utc` in the state file so a reader can tell "not yet run" from "ran narrow"; (c) increase findings diversity — the last finding is a LOW (CVSS 3.7) permissive-CORS on `cdn.shopify.com`, which is noise for a bounty program that pays for takeover/RCE-class issues.

---

## 5. Outstanding Task List

**Legend** — P0: revenue/trust blocking · P1: quality/reliability · P2: optimization · Owners: **Operator** (Carson Haynes, founder) · **Nova** (Nova autonomous email daemon, `:9012`) · **Sentinel** (Project ORBIT Sentinel — radar/scanner/disclosures) · **Guardian** (Orbit Security Sentinel + desktop bridge) · **CI** (GitHub Actions).

### P0 — Blocking / trust-critical

| ID | Task | Owner | Concrete steps | Done when |
|---|---|---|---|---|
| **T1** | Fix About-page `og:image` 404 | Operator | Generate `docs/assets/og-image.png` (1200×630) from `orbit_x_boast_roast_card.jpg` or `media_generator.py`; mirror to `landing/assets/`; update `og:image` in `docs/about.html` + `landing/about.html`; add `og:image:width`/`height` + `twitter:image` | `HEAD /assets/og-image.png` → 200; Rich-Results/OG preview shows the card |
| **T2** | Ship `robots.txt` + `sitemap.xml` | Operator | Create both in `docs/` using §3.4 G1/G2 blocks (all 7 URLs, `lastmod` 2026-10-22); mirror policy to `landing/`; register the property in Google Search Console and submit the sitemap | `HEAD /robots.txt` → 200, `HEAD /sitemap.xml` → 200, GSC shows sitemap "Success" |
| **T3** | Add JSON-LD to the hub (`index.html`) | Operator | Insert `@graph` with `WebSite`, the **same** `Organization @id` as About, `SoftwareApplication` + `Offer(price 59.00 USD)`, `FAQPage` if a visible FAQ exists, `BreadcrumbList`; no invented `aggregateRating` | Rich Results Test on `/` → 0 errors; organization graph links About and index |
| **T4** | Standalone founder entity + copy consistency | Operator | Add the `Person` node (§3.4 G5) with `sameAs` for X + GitHub (add the PyPI URL only once T30 publishes the package); set `jobTitle` identically in the visible `<h3>` and both schema nodes (fixes G13) | Schema and visible text agree; founder appears as a distinct entity in Schema Markup Validator |
| **T5** | Publish RFC 9116 `security.txt` | Operator | Create `docs/.well-known/security.txt` (Contact, Expires, Encryption, Preferred-Languages, Policy, Canonical) + mirror to `landing/`; link it from the footer next to "RFC Disclaimer" | `HEAD /.well-known/security.txt` → 200 |
| **T6** | `Organization.logo` + favicon | Operator | Ship `docs/assets/logo.png` (512×512) and `docs/favicon.ico`; mirror both | `HEAD /assets/logo.png` and `/favicon.ico` → 200 |
| **T7** | Decide on the 8 dirty files | Operator | 2 modified: `data/bounty_programs.json`, `data/bounty_radar_state.json` (timestamps/sweep counters only). 6 untracked: `scripts/post_boast_and_roast_x.py`, `post_video_boast_roast_x.py`, `finish_video_post_x.py`, `post_x_thread_continuation.py`, `get_top_tweet.py`, `check_x_profile_scroll.py` → commit them (they are operator tooling worth keeping) or add them to `.gitignore` | `git status` clean; remote in sync |
| **T8** | Restart or retire the Orbit Social Agent | Operator | Supervisor shows 🔴 STOPPED. Either re-enable after T9's ledger fix, or remove it from the supervisor manifest so the health board stops showing a false red | Supervisor status green for that entry |

### P1 — Reliability & revenue quality

| ID | Task | Owner | Concrete steps | Done when |
|---|---|---|---|---|
| **T9** | Unify manual + programmatic X quota ledger | Guardian | Add `record_external_post()` to `social_state.py`; call it from the 4 posting scripts after verifying the live post; make `SocialQuotaManager` read the same store | Governor reflects operator posts; no "quota reached" log while a manual post was live |
| **T10** | rclone Drive quota throttle | Operator | Add `--tpslimit 8 --tpslimit-burst 1` to `system/drive_watchdog.py` and `system/run_dual_backup.py`; classify 403/429 as `QUOTA_DEFERRED`; reconcile the 8-day `RUNNING` state in `system/logs/backup_status.json` | No new `403 Quota exceeded` in `work_projects_rclone.log`; `backup_status.json` reflects a terminal state |
| **T11** | Harden the Win32 foreground focus path | Guardian | `desktop_x_bridge.py` logs repeated `(1400, 'SetForegroundWindow', 'Invalid window handle')`; add retry with window re-enumeration and `AllowSetForegroundWindow` before each attempt | No focus failures across a 20-post rehearsal |
| **T12** | Replace the broken Edge TTS path | Sentinel | Switch voice synthesis to an authorised endpoint or a local model; make the mock/silent fallback raise a "degraded asset" flag so silent clips cannot be published | A narrated asset renders with real speech and is flagged correctly when degraded |
| **T13** | Bump-1 follow-ups for Cohorts 7–10 | Nova | Honour the 24–36 h gestation window; re-verify the 46 suppressed addresses before any re-send; log dispositions into `data/dispatched_followups.json` | Every Cohort 7–10 agency has a disposition (reply / bump / bounce-prune) |
| **T14** | Fix the audit-quality floor (Cohort 10 = 4 × F grade) | Sentinel | Cohort 10 mean score **56.5/100**; the four F-grade audits (rtCamp 40, Lullabot 40, Palantir 40, Alley Interactive 35) each carry **13–14 total findings with only 0–1 critical** — i.e. the severity mix looks inflated rather than shallow. Validate that "critical" is not triggered by CDN/static-host false positives; compare against the Cohort 6 distribution (grades B/A+) | Cohort 11 mean score ≥ 60 and grade C-or-better for ≥ 7/10 |
| **T15** | Restore full-scope bounty sweeps | Sentinel | Confirm the 02:00–05:00 MST sweep iterates all 27 registered programs; fix `programs_scanned` bookkeeping; prioritise takeover/RCE-class findings over LOW-CORS noise | `programs_scanned` lists ≥ 20 programs per sweep |
| **T16** | Close the Stripe loop | Operator | Balance $0 / 0 subscriptions: run one end-to-end test checkout → webhook → subscriber provisioning → agency portal generation; then confirm the $59/mo and $299–$499 tier checkout links resolve | One full provisioning cycle observed in logs; portal live for a test client |
| **T17** | Submit an outbound app | Operator | Complete LinkedIn QR ID check, then publish the staged founder story with `landing/assets/orbit_ad_banner.jpg`; complete HackerOne/Bugcrowd KYC to enable bounty submissions | First app published; KYC approved |
| **T18** | `docs/` ↔ `landing/` drift guard | CI | Add `scripts/sync_landing_to_docs.py` + a CI job that fails on hash mismatch; retire the 4 dual-edit scripts | CI blocks a divergent PR |
| **T29** | Make the disclose off-peak test clock-injectable | Sentinel | `cli.py:226-227` reads `datetime.now(utc)` → `OffPeakWindow.is_off_peak(...)`. Patch the clock in `tests/test_disclose_unit.py` (freeze at 12:00 UTC for the "outside" case, 04:00 UTC for the "inside" case) or add an injectable `--at`/`now` parameter to `run_disclose` | `pytest tests/test_disclose_unit.py` green at every hour of the day |
| **T30** | Make the published install command actually work | Operator | `pip install orbit-security` appears in `scripts/post_x_thread_continuation.py` (tweet 4/5, staged/published to @_arsoncode — see T31), `scripts/post_x_vulnerability_thread.py`, `src/orbit_security/content_queue.py:165`, `marketing/social_growth_playbook.md:96`, `scripts/stage_x_thread.py:116` — but PyPI has no `orbit-security` project (404 verified). Either publish the wheel (`uv build` + `uv publish`, `pyproject.toml` is already `uv_build`-ready) or replace the line with a Git-install form (`pip install "orbit-security @ git+https://github.com/CmfH009/Orbit-Security.git"` / `uvx --from git+https://github.com/CmfH009/Orbit-Security orbit-recon <domain>`) | `pip install orbit-security` (or the replacement) succeeds from a clean venv |
| **T31** | Verify the published vulnerability thread is live and correct | Operator | The continuation script hard-codes parent tweet `https://x.com/_arsoncode/status/2112362100454744454`; the public syndication endpoint returns an empty payload for **every** ID in this environment (including known-good ones), so liveness could not be verified headlessly — check in the authenticated Chrome session, confirm tweets 1/5–5/5 are present and chained, and correct tweet 4/5's install line if T30 changes it | Screenshot/log of all five live tweets; install line in 4/5 matches the shipped reality |

### P2 — Optimization & long-term

| ID | Task | Owner | Concrete steps |
|---|---|---|---|
| **T19** | Substantiate the headline numbers (G14) | Operator | Add dated methodology footnotes for "< 12 s", "40+ signatures", "10,493 % ROI"; publish a reproducible benchmark command (`orbit-recon --benchmark`) |
| **T20** | `llms.txt` (optional convenience layer) | Operator | Ship `docs/llms.txt` + `llms-full.txt` with a plain-language summary, key facts, FAQ and contact. **Do not treat it as a ranking lever** — Google ignores it |
| **T21** | Speakable + breadcrumb enrichment | Operator | Add `SpeakableSpecification` on the Key-Facts block; add visible breadcrumbs matching a `BreadcrumbList` node |
| **T22** | `areaServed` / `availableLanguage` / `ProfessionalService` | Operator | Extend the Organization node with `areaServed` (US/EU/UK), `availableLanguage: ["en"]`, `knowsLanguage` |
| **T23** | Self-host Tailwind for the About page (G12) | Operator | Compile `landing/input.css` → `assets/styles.min.css` and drop the Play CDN so the page renders without JS dependency; improves LCP and non-JS crawlers |
| **T24** | CI test workflow | CI | The current workflow only runs the perimeter sentinel; add `pytest` + `ruff` + the docs/landing hash check |
| **T25** | Custom domain (entity trust) | Operator | Add `docs/CNAME` + DNS for a branded domain; keep `cmfh009.github.io` as a redirect; improves brand/entity recognition vs. a generic project URL |
| **T26** | Retire stale handoff docs | Operator | `docs/SESSION_HANDOFF.md` (2026-09-25) and `docs/SESSION_HANDOFF_ORBITSEC_AND_ECOSYSTEM.md` (2026-10-04) are published to the live site — move them out of `docs/` (into `docs/internal/`, excluded from Pages) or redact |
| **T27** | Per-page social preview matrix | Operator | Audit `og:image`/`twitter:image` on all 8 public pages; generate one 1200×630 card per page or per product (Core, Fleet, GhostDNS, Portals) |
| **T28** | Weekly GEO prompt-panel automation | CI | Script the 12-query prompt panel across 4 engines, store citation/mention deltas to `data/geo_panels.jsonl`, emit to the daily briefing |

---

## 6. Next Actions & Long-term Validation

### 6.1 Next 24 hours (highest ratio of trust-per-minute)

1. **T1 + T6** — generate `og-image.png`, `logo.png`, `favicon.ico`; update `docs/about.html` + `landing/about.html`; push. *(30 min, removes two live 404s on the newest page.)*
2. **T2** — write `robots.txt` + `sitemap.xml`; register the GSC property and submit the sitemap. *(30 min, unlocks discovery + AI-feature eligibility.)*
3. **T5** — publish `/.well-known/security.txt`. *(10 min, closes the hypocrisy gap for a product that sells security.txt.)*
4. **T7** — commit the 6 operator scripts + the 2 telemetry files; make the tree clean. *(10 min.)*
5. **T13** — run the Cohort 7–10 bump window now (24–36 h gestation has elapsed for Cohorts 6–7); re-verify suppressed addresses first. *(Revenue.)*
6. **T16** — one live Stripe checkout → provisioning test. *(Revenue.)*
7. **T30** — publish the wheel to PyPI or switch every `pip install orbit-security` reference to a Git-install form. *(Credibility — a broken first command in published copy is the cheapest thing on this list to fix and the most expensive to leave.)*

### 6.2 This week

- **T3 + T4** — structured data on the hub + standalone founder entity; validate with Schema Markup Validator and Rich Results Test.
- **T9 + T11** — unify the X quota ledger and harden the Win32 focus path before the next posting cycle.
- **T10** — throttle rclone and reconcile the stale backup status (a silently stale backup is an availability risk, not a quota problem).
- **T14** — audit-quality floor before Cohort 11; a weak audit sent to a marquee agency (Lullabot, rtCamp, Palantir) is a reputational cost far above the email cost.
- **T24** — CI: unit tests + docs/landing parity + broken-asset HEAD sweep.

### 6.3 This month

- **T12** — replace Edge TTS; **T15** — full-scope bounty sweeps with meaningful severity triage.
- **T19 + T20** — substantiate claims; ship `llms.txt` as a convenience layer.
- **T25** — branded domain (entity + trust lift, and removes the "project page" smell that suppresses commercial intent).
- **T27 + T28** — per-page social cards; automated weekly GEO prompt panel with citation logging.

### 6.4 Long-term validation (90-day scorecard)

| Dimension | Metric | Baseline (2026-10-22) | 90-day target | Cadence |
|---|---|---|---|---|
| Discoverability | Indexed public URLs | 2 of 8 confidently indexed | 8 of 8 | Weekly (GSC) |
| AI visibility | Queries with Orbit mentioned (12-query panel) | not yet measured | ≥ 4/12 | Weekly |
| AI citation quality | Mentions carrying a citation URL | not yet measured | ≥ 25 % | Weekly |
| Technical trust | Non-200 asset refs across public pages | 7 (og-image, logo, favicon, robots, sitemap, llms, security.txt) | 0 | Per deploy (CI) |
| Structured data | Pages with valid JSON-LD | 1 of 8 (About only) | 8 of 8 | Per deploy |
| Page experience | LCP / CLS on `/` and `/about.html` | not yet measured | LCP < 2.0 s, CLS < 0.05 | Weekly (CrUX/CI) |
| Deliverability | Cohort hard-bounce rate | 10 % (Cohort 6) | ≤ 3 % | Per cohort |
| Reply rate | Outreach → human reply | 0 high-intent escalations (9 tracked threads) | ≥ 8 % | Per cohort |
| Monetization | Active retainers | 0 | ≥ 3 | Weekly |
| Pipeline | Campaigns dispatched / open rate | 178 campaigns | 250 campaigns, ≥ 40 % open | Weekly |
| Detection | Radar findings per sweep (meaningful class) | 3,094 total, recent = LOW CORS | ≥ 10 takeover/RCE-class per sweep | Per sweep |
| Integrity | docs/ ↔ landing/ parity | identical today | CI-enforced 100 % | Per commit |
| Regression | Unit/regression suite | 402/402 green at 2026-10-04; **513 passed / 1 time-dependent failure at 2026-10-22** | ≥ 513 green, zero failures at any hour, plus CI enforcement | Per commit |
| Uptime | Master supervisor + 16 micro-daemons | 15/16 green (Social Agent stopped) | 16/16 green | Hourly (canary) |

### 6.5 Resume commands (copy/paste)

```powershell
# Repo + state
cd A:\projects\orbit-security
git -C A:\projects\orbit-security log --oneline -5
git -C A:\projects\orbit-security status --short

# Ecosystem health
python A:\system\scripts\orbit_daemon.py status
python A:\system\scripts\drive_watchdog.py status

# Outreach
A:\projects\orbit-security\.venv\Scripts\python.exe A:\projects\orbit-security\scripts\run_inbox_agent.py --once
A:\projects\orbit-security\.venv\Scripts\python.exe A:\projects\orbit-security\scripts\run_bounty_radar.py --status

# Tests
cd A:\projects\orbit-security
.venv\Scripts\python.exe -m pytest -q

# Live-surface smoke test (repeat after every Pages deploy)
$urls = @("/","/about.html","/fleet.html","/signup.html","/robots.txt","/sitemap.xml","/assets/og-image.png","/assets/logo.png","/.well-known/security.txt")
foreach ($p in $urls) { try { "{0} {1}" -f $p,(Invoke-WebRequest "https://cmfh009.github.io/Orbit-Security$p" -Method Head -UseBasicParsing).StatusCode } catch { "$p ERR" } }
```

---

## 7. Source & Evidence Index

| Claim in this document | Source |
|---|---|
| GEO/AI-search mechanics (RAG, fan-out), llms.txt ignored, chunking unnecessary, Search Console AI reports, agentic UX | Google Search Central — "Optimizing your website for generative AI features on Google Search", `developers.google.com/search/docs/fundamentals/ai-optimization-guide` (updated 2026-07-10); `support.google.com/webmasters/answer/16908024`, `answer/16984139`; `web.dev/articles/ai-agent-site-ux` |
| Third-party GEO consensus (answer blocks, entity consistency, crawler allowlists, ~40 % lift from citations/statistics/quotes) | Semrush, llmrefs, InSegment, SEO.com, DigitalApplied, Gen-Optima 2026 GEO guides; KDD'24 GEO paper (visibility lift up to 40 %) |
| X quota ceilings | `src/orbit_security/quota_manager.py` (`QuotaBudget`), `data/social_daemon.log` (30+ "POST quota reached" entries, 2026-10-19 → 2026-10-22) |
| X policy refusals / breaker | `src/orbit_security/x_driver.py`, `desktop_x_bridge.py`, `circuit_breaker.py`, `data/social_daemon.log` |
| Edge TTS 403 | `data/social_daemon.log` 2026-10-20 05:36 & 06:18 |
| Drive `403 Quota exceeded` | `system/logs/work_projects_rclone.log` 2026-10-14 05:32 (2 occurrences); `system/drive_watchdog.py` (~L85-95), `system/run_dual_backup.py` (~L73) |
| Bounce suppression (46) / delivery 90 % | `data/bounced_agencies.json`; `daily_briefings/briefing_cohort6_triage_2026-10-21.md` |
| Daemon health / PIDs | `python A:\system\scripts\orbit_daemon.py status` (2026-10-22 04:27 MST) |
| Radar scope & counts | `data/bounty_radar_state.json` (120 sweeps, 3,094 findings), `data/bounty_programs.json` (27 programs), `daily_briefings/briefing_cohort6_triage_2026-10-21.md` (27 programs, 121 new findings) |
| Cohort 10 grades / dispatch | `data/cohort_10_matrix.md` (2026-10-22 03:22:49) |
| Revenue telemetry | `daily_briefings/briefing_2026-10-21.md` (balance $0, 0 subscriptions, 145 dispatched) |
| Live-site status codes | Direct HTTP HEAD against `cmfh009.github.io/Orbit-Security/*` on 2026-10-22 |
| Recent commits | `git log` in `A:\projects\orbit-security` — `7a9affc`, `d7c5c8b`, `7f0c76e`, `cbc81cf`, `15cee84`, `0215f12`, `3260432`, `1bdc3bc` |
| Test result (513 passed / 1 failed) | `pytest -q` run 2026-10-22 04:2x MST, 111.44 s; failure at `tests/test_disclose_unit.py:58` with `"Sweep would execute"` — window logic at `src/orbit_security/cli.py:226-227` |
| `pip install orbit-security` not resolvable | `https://pypi.org/pypi/orbit-security/json` → **404** (2026-10-22) vs. the instruction in `scripts/post_x_thread_continuation.py:42`, `scripts/post_x_vulnerability_thread.py:40`, `src/orbit_security/content_queue.py:165`, `marketing/social_growth_playbook.md:96`, `scripts/stage_x_thread.py:116` |
| Thread liveness unverifiable headlessly | `cdn.syndication.twimg.com/tweet-result?id=…` returns `{}` for every ID tested in this environment (including known-good control IDs) — requires an authenticated browser check |

---

## 8. Execution Update — 2026-10-22 (roadmap kickoff cycle)

A roadmap kickoff cycle ran one coordinator + six parallel agents with exclusive file ownership (see [`ROADMAP.md`](file:///A:/projects/orbit-security/ROADMAP.md) §3). Two measurement scripts were added to make the gates falsifiable: `scripts/outreach_metrics.py` (read-only) and `scripts/validate_x_post_lengths.py`.

### 8.1 The measurement changed the plan

| Metric | Value | Gate | Status |
|---|---|---|---|
| Campaigns sent | 135 (178 registered) | — | — |
| **Hard bounce rate** | **34.07 %** (46 addresses, all registry-attributed) | ≤ 3 % | ❌ |
| Tracked inbound threads | 34 | — | — |
| **Meaningful conversations** | **0** | ≥ 8 % reply rate | ❌ |
| Intent mix | 11 NOT_INTERESTED · 8 OUT_OF_OFFICE · 5 TICKET_ACKNOWLEDGED · 4 UNCLEAR · 3 MARKETING_NEWSLETTER · 3 BOUNCE | — | — |
| High-intent threads | **0** | > 0 | ❌ |

### 8.2 The F-grade bug is systemic, not a Cohort 10 accident

| Cohort | n | mean | min | C-or-better | F grades | Floor met |
|---|---|---|---|---|---|---|
| cohort_10 | 10 | 56.5 | 35 | 6/10 | 4 | ❌ |
| cohort_9 | 10 | 64.0 | 35 | 7/10 | 1 | ✅ |
| cohort_8 | 10 | 48.5 | **0** | 5/10 | 2 | ❌ |
| cohort_7 | 10 | 53.5 | **5** | 5/10 | 2 | ❌ |
| cohort_6 | 10 | 69.5 | 20 | 9/10 | 1 | ✅ |

**Two agencies received audits scoring 0/100 and 5/100.** Those are not "grades we disagree with" — they are wrong numbers delivered to paying prospects' inboxes. The scoring fix is therefore a customer-facing remediation (task **T33**), not an internal improvement.

### 8.3 New tasks added by this cycle

| ID | Task | Owner | Priority | Steps |
|---|---|---|---|---|
| **T32** | Cold-email channel triage | Operator + Nova | **P0** | Root-cause the 34 % bounce rate (list hygiene, role-based inboxes, stale suppression, pre-send validation). Review the 11 rejection replies for the actual objection. Run a subject/opening A/B with a 30 % holdout across the next 3 cohorts. **Suspend new sends until bounce < 10 %.** |
| **T33** | Audit remediation for cohorts 7–10 | Sentinel + Operator | **P0** | Re-score every stored audit under the fixed model; re-send corrected grades to every agency that received an F, D, 0/100 or 5/100 audit with a short, non-apologetic correction note. |
| **T34** | Roadmap + gate instrumentation | Coordinator | P1 | `ROADMAP.md` + `scripts/outreach_metrics.py` (done) — every Phase 2 gate is now computed from real data rather than asserted. |

### 8.4 Publish runbook — the roast thread

The copy is written, length-validated, guarded, and staged. **Publishing requires the operator's own interactive desktop session** — this session cannot see the Chrome window (10 chrome.exe processes alive, 0 top-level windows visible to the agent process), and the harness correctly refuses to post without an authenticated X tab.

```powershell
# 1. preflight (read-only): confirm an authenticated Chrome + X tab
cd A:\projects\orbit-security
.\.venv\Scripts\python.exe scripts\post_x_roast_f_grades.py --check-session

# 2. dry run: prints what WOULD be posted, writes an audit line, posts nothing
.\.venv\Scripts\python.exe scripts\post_x_roast_f_grades.py --thread

# 3. publish the 4-post thread (after 11:07Z, or pass --force)
.\.venv\Scripts\python.exe scripts\post_x_roast_f_grades.py --thread --post

# 4. or publish one standalone post
.\.venv\Scripts\python.exe scripts\post_x_roast_f_grades.py --id roast-standalone-1 --post

# 5. validate the manifest independently at any time
.\.venv\Scripts\python.exe scripts\validate_x_post_lengths.py --json
```

**Guards enforced by the harness (all verified):** dry-run default; `--post` required to publish; held variants hard-blocked (`PermissionError`); 8 h minimum spacing + 2 posts/day from the real `QuotaBudget`; third-party client domains rejected in publishable copy; every attempt logged to `data/roast_f_grades_post_log.jsonl`.

**Timing:** the last successful publish was 2026-10-22 03:07:39Z, so the 8 h spacing clears at **11:07:39Z** (1 of 2 daily posts used).

### 8.5 What this cycle shipped (all committed, pushed, deployed)

| # | Commit | Outcome |
|---|---|---|
| 1 | `0c72116` `feat(site)` | Trust assets + crawl directives + **structured data on all 8 public pages**. Live-verified: every previously-404 URL now 200. |
| 2 | `ad970d2` `fix(scoring)` | **An F grade now requires real exploit risk.** 52 audits re-scored: 18 failing → 5, 13 rescued, 0 newly failing, average +28.1. |
| 3 | `876696e` `feat(ci)` | Release gate, parity CI, live-asset sweep, clock-injected test, X publish harness. |
| 4 | `397f499` `docs` | This roadmap + handoff; `edge-tts`/`pillow`/`pywin32` declared; `uv.lock` refreshed. |
| 5 | `9a01133` `ci` | Deployed public surface promoted from warn-only to **blocking** CI gate. |

**Verification after deploy (live, 2026-10-22 04:58 MST):**
`scripts/verify_release.py --live` → **RELEASE GATE PASSED**, 14/14 public URLs HTTP 200, landing↔docs parity clean, JSON-LD parses on every page with all `@id` references resolving.
Live `about.html` serves 6 entity types including the standalone `Person`, `og:image`/`twitter:image` resolving to the shipped card, 154-char description, visible freshness stamp, canonical.

**Test suite:** `570 passed, 0 failed` (was 513 + 1 hour-dependent failure). The disclose off-peak test is now clock-injected and green at any hour; the DNS cache latency test now measures best-of-5 warmed samples, removing a pre-existing CI flake.

**Scoring behaviour, independently verified against the new engine:**

| Input | New | Old |
|---|---|---|
| 7 best-practice items only (the false-F pattern) | **100 / A+** | 35 / F |
| The real `kff.org` pattern | **80 / B** | 35 / F |
| 20× the same LOW finding | **100 / A+** | 0 / F |
| 1 real dangling-CNAME takeover (CRITICAL) | **59 / D** | 65 / C |

### 8.6 What this cycle changed in the system layer

- Drive rclone paths now throttle to **8 transactions/second** (`--tpslimit 8 --tpslimit-burst 1 --max-backlog 10`); a 403/429 is classified `QUOTA_DEFERRED` instead of `FAILED`.
- A stale-status reconcile recovered **2 backup entries pinned `RUNNING`** for 202 h and 185 h — the backup board had been lying since 2026-10-14.
- The X publish path is unified into one ledger rule (8 h spacing + 2/day read from the real `QuotaBudget`), dry-run by default.

---


New operational surface created this cycle:

| Artifact | Purpose |
|---|---|
| `ROADMAP.md` | 5 phases, owners, exit gates, risk register, cadence, 14-day view |
| `scripts/outreach_metrics.py` | outreach / bounce / reply / cohort-quality metrics with PASS-FAIL gates |
| `scripts/verify_release.py` | one-command release gate: parity, JSON-LD, assets, live sweep — **PASS** |
| `scripts/apply_page_schema.py` | idempotent structured-data application for public pages |
| `scripts/build_trust_assets.py` | deterministic, re-runnable brand asset generator |
| `scripts/sync_landing_to_docs.py` | landing/ → docs/ drift detector with `--apply` |
| `scripts/validate_x_post_lengths.py` | X length + third-party-domain + held-variant validator |
| `scripts/post_x_roast_f_grades.py` | dry-run-by-default X publisher with 8 h spacing guard |
| `scripts/rescore_audit_evidence.py` | re-scores all 52 delivered audits, legacy vs new model |
| `data/roast_f_grades_posts.json` | the roast copy: 7 publishable posts (all ≤ 280 weighted chars) + 1 held variant that names third-party domains and is hard-blocked |

---

