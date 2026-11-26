# Orbit Security — Bug Bounty Triage Queue

**Last Updated:** 2026-11-26  
**Researcher Handle:** `arsoncarson` (ID verified on Bugcrowd & HackerOne)

---

## 1. Live Submissions (Awaiting Triage)

| Platform | Program / Target | Finding | Reference / ID | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Bugcrowd** | `mattermost-mbb-public` (`mattermost/mattermost-plugin-confluence`) | OAuth2 state not bound to authenticated user & missing single-use invalidation (CWE-352) | `a67e736a-829c-4c61-a4af-c4d2d550888e` ([report](file:///C:/Users/purav/.gemini/antigravity-cli/brain/0f94c3e0-4031-48e6-9de3-d96872df8113/confluence_oauth_csrf_audit.md)) | `New` (1/1 slot occupied; est. review `2026-12-06`) |
| **HackerOne** | `mondelez` | `shop.hukitchen.com` dangling CNAME to `unbouncepages.com` | `#4204025` | `New` (no triage reply yet; Signal-gates other H1 programs until resolved) |

---

## 2. Ready Now (No Platform Queue / Signal Gate)

| Channel | Target | Finding Summary | Artifact | Next Action |
| :--- | :--- | :--- | :--- | :--- |
| **Direct Private Email** (`security@omarchy.org`) | `omacom/omarchy` (`quattro` @ `f989b43`) | 3 verified security-boundary issues (`omarchy.clonedFrom` auth bypass, root ALPM `hyprland-reload-guard` hardening, WPA-Enterprise RADIUS TLS validation) + 3 clean patches | [omarchy-security-disclosure-bundle.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/7ac73744-8f67-4f1d-bb31-7871dcbca23f/omarchy-security-disclosure-bundle.md) | Send private disclosure email to `security@omarchy.org` |

---

## 3. Staged Next (Blocked by Platform Queue or Signal Gate)

| Platform | Target | Finding Summary | Artifact | Blocker |
| :--- | :--- | :--- | :--- | :--- |
| **Bugcrowd** (`launchdarkly-mbb-og`) | `launchdarkly/ld-relay` | Unbounded inbound event payload & `gzip` decompression OOM on public client-side event routes | [backblaze_launchdarkly_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/4803c6f8-5ab3-447e-a610-8ea5d01da32a/backblaze_launchdarkly_audit.md) | Waiting for Bugcrowd `1/1` slot to clear |
| **HackerOne** (`gitlab`) | `gitlab-org/gitaly` | SSRF via DNS rebinding bypass on `git://` URLs (`internal/git/gitcmd/command_resolve.go`) | [gitaly_ssrf_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/0f94c3e0-4031-48e6-9de3-d96872df8113/gitaly_ssrf_audit.md) | HackerOne Signal >= 1.0 gate (0 trial reports left) |
| **HackerOne** (`gitlab`) | `gitlab-org/gitlab-runner` | KMP partial-match drop in `masker.Write` leaks self-overlapping CI/CD secrets | [gitlab_runner_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/0f94c3e0-4031-48e6-9de3-d96872df8113/gitlab_runner_audit.md) | HackerOne Signal >= 1.0 gate (0 trial reports left) |

---

## 4. Clean / Archived Audits (Do Not Submit)

- `cloudflare/vinext` ([vinext-security-audit-report.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/3c9e83cd-386a-443d-b318-7d90fde0cd15/vinext-security-audit-report.md)) — Clean pass.
- `gitlab-org/gitlab-pages` ([gitlab-pages-security-audit-report.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/61686068-3087-49f4-93ae-dba925a03183/gitlab-pages-security-audit-report.md)) — `GetConfigForClient` placeholder not wired live.
- `google/osv-scanner` ([osv-scanner-security-audit-report.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/61686068-3087-49f4-93ae-dba925a03183/osv-scanner-security-audit-report.md)) — Clean on Google OSS VRP bar.
- `Backblaze/B2_Command_Line_Tool`, `Backblaze/b2-sdk-java`, `launchdarkly/go-server-sdk`, `launchdarkly/js-core` ([backblaze_launchdarkly_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/4803c6f8-5ab3-447e-a610-8ea5d01da32a/backblaze_launchdarkly_audit.md)) — Clean / hardened.
- `anthropics/*` (7 repos) ([anthropic_oss_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/1995ca6d-c81e-42a6-bc77-2df14f0eca5a/anthropic_oss_audit.md), [anthropic_deep_audit.md](file:///C:/Users/purav/.gemini/antigravity-cli/brain/b6aa2310-d863-492f-9955-cd0f8195773c/anthropic_deep_audit.md)) — Clean code.
