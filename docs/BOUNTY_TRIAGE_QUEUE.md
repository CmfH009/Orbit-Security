# Orbit Security — Bug Bounty Triage Queue

**Last Updated:** 2026-11-26  
**Researcher Handle:** `arsoncarson` (ID verified on Bugcrowd & HackerOne)

---

## 1. Live Submissions (Awaiting Triage)

| Platform | Program / Target | Finding | Reference / ID | Status |
| :--- | :--- | :--- | :--- | :--- |
| **HackerOne** | `mondelez` | `shop.hukitchen.com` dangling CNAME to `unbouncepages.com` | `#4204025` | `New` (Mondelēz paused new submissions 2026-11-26 15:48 UTC; existing report awaiting triage; Signal-gates other H1 programs until resolved) |
| **Direct Private Email** (`security@omarchy.org`) | `omacom/omarchy` (`quattro` @ `f989b43`) | 3 verified security-boundary issues (`omarchy.clonedFrom` auth bypass, root ALPM `hyprland-reload-guard` hardening, WPA-Enterprise RADIUS TLS validation) + 3 clean patches | [omarchy-security-disclosure-bundle.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/7ac73744-8f67-4f1d-bb31-7871dcbca23f/omarchy-security-disclosure-bundle.md) | Dispatched 2026-11-26 02:40 UTC to `security@omarchy.org` (awaiting vendor reply) |

---

## 2. Ready Now (No Platform Queue / Signal Gate)

| Platform | Target | Finding Summary | Artifact | Next Action |
| :--- | :--- | :--- | :--- | :--- |
| **Bugcrowd** (`launchdarkly-mbb-og`) | `launchdarkly/ld-relay` | Unbounded inbound event payload & `gzip` decompression OOM on public client-side event routes | [backblaze_launchdarkly_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/4803c6f8-5ab3-447e-a610-8ea5d01da32a/backblaze_launchdarkly_audit.md) | Hold — verify DoS is in scope before submitting; Bugcrowd `1/1` slot is open |
| **Bugcrowd** (`aiven-mbb-og`) | `Aiven-Open/klaw` | Cross-user & cross-tenant active team modification IDOR (`POST /user/updateTeam`, CWE-639) + user/switch-team enumeration | [bugcrowd_aiven_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/c2e423cc-1735-4674-a0f6-93bcb0a62666/bugcrowd_aiven_audit.md) | Run standalone `curl`/JUnit PoC on a Java/Docker host to capture live output before submitting |

### Automated Paid Bounty Discovery Leads (`2026-11-26`)
- **`deriv`** (score `80` [fast-pay, gold-harbor]) — `URL, SOURCE_CODE, WILDCARD, OTHER` (`h1-read program deriv --scopes --paid-only`)
- **`matomo`** (score `70` [fast-pay]) — `SOURCE_CODE, URL` (`h1-read program matomo --scopes --paid-only`)
- **`faraday_inc`** (score `70` [fast-pay, gold-harbor]) — `URL, OTHER`
- **`mercadolibre`** (score `70` [fast-pay, gold-harbor]) — `URL, WILDCARD, GOOGLE_PLAY_APP_ID, OTHER, APPLE_STORE_APP_ID, HARDWARE`
- **`crypto`** (score `70` [fast-pay, gold-harbor]) — `WILDCARD, URL, APPLE_STORE_APP_ID, API, GOOGLE_PLAY_APP_ID, SMART_CONTRACT`

---

## 3. Staged Next (Blocked by Platform Queue or Signal Gate)

| Platform | Target | Finding Summary | Artifact | Blocker |
| :--- | :--- | :--- | :--- | :--- |
| **HackerOne** (`gitlab`) | `gitlab-org/gitaly` | SSRF via DNS rebinding bypass on `git://` URLs (`internal/git/gitcmd/command_resolve.go`) | [gitaly_ssrf_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/0f94c3e0-4031-48e6-9de3-d96872df8113/gitaly_ssrf_audit.md) | HackerOne Signal >= 1.0 gate (0 trial reports left) |
| **HackerOne** (`gitlab`) | `gitlab-org/gitlab-runner` | KMP partial-match drop in `masker.Write` leaks self-overlapping CI/CD secrets | [gitlab_runner_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/0f94c3e0-4031-48e6-9de3-d96872df8113/gitlab_runner_audit.md) | HackerOne Signal >= 1.0 gate (0 trial reports left) |

---

## 4. Closed / Clean / Archived Audits (Do Not Submit)

- `mattermost/mattermost-plugin-confluence` (`a67e736a-829c-4c61-a4af-c4d2d550888e`, [report](file:///C:/Users/purav/.gemini/antigravity-cli/brain/0f94c3e0-4031-48e6-9de3-d96872df8113/confluence_oauth_csrf_audit.md)) — Closed — Not Applicable by `hexghost_bugcrowd` (2026-11-26 14:07 UTC).
- `Aiven-Open/karapace` (`91f25f28`), `Aiven-Open/ai-gateway-cli` (`23b6e49a`), `Aiven-Open/myhoard` (`b7ec9ac6`) — Clean on audited auth/ACL/forwarding boundaries.

- `cloudflare/vinext` ([vinext-security-audit-report.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/3c9e83cd-386a-443d-b318-7d90fde0cd15/vinext-security-audit-report.md)) — Clean pass.
- `gitlab-org/gitlab-pages` ([gitlab-pages-security-audit-report.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/61686068-3087-49f4-93ae-dba925a03183/gitlab-pages-security-audit-report.md)) — `GetConfigForClient` placeholder not wired live.
- `google/osv-scanner` ([osv-scanner-security-audit-report.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/61686068-3087-49f4-93ae-dba925a03183/osv-scanner-security-audit-report.md)) — Clean on Google OSS VRP bar.
- `Backblaze/B2_Command_Line_Tool`, `Backblaze/b2-sdk-java`, `launchdarkly/go-server-sdk`, `launchdarkly/js-core` ([backblaze_launchdarkly_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/4803c6f8-5ab3-447e-a610-8ea5d01da32a/backblaze_launchdarkly_audit.md)) — Clean / hardened.
- `anthropics/*` (7 repos) ([anthropic_oss_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/1995ca6d-c81e-42a6-bc77-2df14f0eca5a/anthropic_oss_audit.md), [anthropic_deep_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/b6aa2310-d863-492f-9955-cd0f8195773c/anthropic_deep_audit.md)) — Clean code.
