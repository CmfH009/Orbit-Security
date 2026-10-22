# 🛡️ Orbit Security: Attack Surface & Subdomain Hygiene Sentinel

[![Orbit Security Perimeter Sentinel](https://github.com/CmfH009/Orbit-Security/actions/workflows/orbit-perimeter-sentinel.yml/badge.svg)](https://github.com/CmfH009/Orbit-Security/actions/workflows/orbit-perimeter-sentinel.yml)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/CmfH009/Orbit-Security?color=cyan&label=release)](https://github.com/CmfH009/Orbit-Security/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Live Demo & Fleet Center](https://img.shields.io/badge/Fleet%20Center-Live%20Demo-10B981)](https://cmfh009.github.io/Orbit-Security/)

**Orbit Security** is an autonomous external perimeter auditor and attack surface sentinel built for web design, development, and digital marketing agencies. It monitors client domains for dangling CNAME takeovers, email spoofing risks (DMARC/SPF), exposed environment secrets (`.env`, `.git`), and expiring SSL certificates—automatically compiling co-branded, white-label monthly audit PDFs that agencies send to their clients to justify and elevate their recurring monthly maintenance retainers.

---

## 🎯 The Daily Micro-Revenue Model ($10 – $100/day)

Agencies charge 20–100+ clients between **$150 and $350/month** for "Website Maintenance & Care Plans". However, clients frequently ask: *"What are we paying you for if the site hasn't changed?"*

By delivering a co-branded, high-polish Security & Perimeter Audit on the 1st of every month:
1. **The agency protects and justifies their retainer revenue.**
2. **You charge the agency $29 – $99/month.**
3. **With just 15 to 25 agency accounts, you generate a reliable $50/day ($1,500/month) with near-zero marginal cost and virtually zero churn.**

---

## 🚀 Quickstart

### 1. Installation
```powershell
cd A:\projects\orbit-security
uv sync
```

### 2. Run a Live Audit
```powershell
uv run orbit-security scan example.com --agency-name "Apex Digital Studio" --output-pdf audit.pdf --output-md audit.md
```

### 3. Specify Target Subdomains
```powershell
uv run orbit-security scan myclient.com --subdomains "staging.myclient.com,promo.myclient.com,dev.myclient.com" --output-pdf client_audit.pdf
```

---

## 🔍 Core Security & Hygiene Checks

1. **Subdomain Takeovers (Dangling CNAMEs):**
   - Resolves subdomains against known vulnerable SaaS signatures (Unbounce, GitHub Pages, AWS S3, Heroku, Webflow, Shopify, Zendesk, Pantheon, Netlify, Surge).
   - Probes endpoints for unattached provider 404 error strings.
2. **Email Spoofing & Phishing Resistance:**
   - DMARC inspection (`_dmarc.<domain>`), distinguishing between active enforcement (`p=quarantine`/`p=reject`) and monitoring-only mode (`p=none`).
   - SPF inspection (`v=spf1`), alerting on missing or dangerously permissive (`+all`) rules.
3. **Exposed Critical Files:**
   - Detects publicly accessible `/.env`, `/.git/HEAD`, and `/wp-config.php.bak`.
4. **Transport & Application Headers:**
   - HSTS (`Strict-Transport-Security`), Content Security Policy (`Content-Security-Policy`), and Clickjacking mitigation (`X-Frame-Options`).
5. **SSL/TLS Certificate Validity:**
   - Validates socket TLS certificates, calculating exact days until expiration.

---

---

## ⚡ Autonomous CLI Scanner (`orbit-recon`)

`orbit-recon` is our standalone, zero-dependency external attack surface scanner:

```bash
# Scan a single domain
python tools/orbit-recon.py example.com

# Scan multiple domains with Markdown matrix export & CI/CD gate
python tools/orbit-recon.py --targets-file domains.txt --markdown fleet_matrix.md --fail-on-critical
```

---

## 🤖 CI/CD GitHub Action (`action.yml`)

Gate pull requests and deployments by verifying that no staging subdomains, broken CNAMEs, or exposed secrets slip into production:

```yaml
name: Orbit Security Perimeter Sentinel

on: [push, pull_request]

jobs:
  perimeter-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Audit External Perimeter
        uses: CmfH009/Orbit-Security@main
        with:
          target: 'myagency.com'
          # Or specify a list of client domains:
          # targets-file: '.orbit-targets.txt'
          fail-on-critical: 'true'
          markdown-summary: 'true'
```
*When `markdown-summary` is enabled, the formatted audit table is automatically rendered right inside the GitHub Actions run summary tab!*

### Native GitHub Actions Workflow (`.github/workflows/orbit-perimeter-sentinel.yml`)

The repository also ships a native GitHub Actions workflow that runs on every push/PR to `main` and `develop`. It reads targets from `.orbit-targets.txt` (RFC 2606 reserved domains by default — never third-party production sites), executes the composite action with `fail-on-critical: true`, and uploads the Markdown audit report as a workflow artifact:

```yaml
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
jobs:
  perimeter-audit:
    runs-on: ubuntu-latest
    continue-on-error: false
    steps:
      - uses: actions/checkout@v4
      - name: Read target domains
        id: targets
        run: |
          # Reads .orbit-targets.txt (comments + blanks stripped)
          # Falls back to repo's GitHub Pages domain or example.com
      - name: Run Orbit Security Perimeter Audit
        uses: ./
        with:
          targets-file: ${{ steps.targets.outputs.targets-file }}
          fail-on-critical: 'true'
          markdown-summary: 'true'
          export-markdown: 'orbit-perimeter-audit.md'
      - name: Upload audit report artifact
        uses: actions/upload-artifact@v4
        with:
          name: orbit-perimeter-audit
          path: orbit-perimeter-audit.md
```

---

## 🔔 Slack & Discord Webhooks

Send real-time alerts when client perimeters drift into dangerous states:

```bash
python scripts/scheduled_sentinel.py \
  --clients-file data/clients.json \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --discord-webhook "https://discord.com/api/webhooks/..."
```

---

## 🐛 Bug Bounty Disclose Pipeline (`disclose`)

Automated bug-bounty radar sweep → HackerOne-compliant disclosure generation pipeline. Ingests enrolled program scopes (HackerOne / Bugcrowd), sweeps for dangling CNAME takeovers and mail-spoofing vectors, generates structured disclosure reports, and dispatches `HIGH_CONFIDENCE` alerts via Discord/Slack webhooks.

```powershell
# Preview what would be swept (safe — no external probing)
uv run orbit-security disclose --dry-run

# Force a live sweep now (bypasses the 2:00–5:00 AM MST off-peak window)
uv run orbit-security disclose --program shopify --now

# Sweep a specific program with passive Certificate Transparency discovery
uv run orbit-security disclose --program shopify --now --passive-ct --max-targets 25

# Custom output directory and webhook alerts for HIGH_CONFIDENCE findings
uv run orbit-security disclose --now --output-dir data/disclosures `
  --webhook-discord "https://discord.com/api/webhooks/..." `
  --webhook-slack "https://hooks.slack.com/services/..."

# Triage existing disclosures (no sweep)
uv run orbit-security disclose --list
uv run orbit-security disclose --json
uv run orbit-security disclose --view cdn.shopify.com
uv run orbit-security disclose --copy cdn.shopify.com
uv run orbit-security disclose --grade HIGH_CONFIDENCE
```

**`--dry-run`** shows which programs would be swept, their in-scope pattern counts, and whether the off-peak window would block execution — without probing any external targets.

---

## 📬 Cohort Outreach Audit Generator (`run_cohort_outreach.py`)

Batch-generates co-branded perimeter-hygiene audit PDFs + Markdown reports from `data/new_prospects.json` for agency outreach. Each prospect's primary portfolio domain is scanned and a white-label report is emitted under `data/generated_audits/<agency-slug>/`.

```powershell
# Preview what would be generated (no scanning, no file writes)
.venv\Scripts\python.exe scripts\run_cohort_outreach.py --dry-run --limit 3

# Scan all 54 prospects
.venv\Scripts\python.exe scripts\run_cohort_outreach.py

# Limit to 10 prospects, custom output dir
.venv\Scripts\python.exe scripts\run_cohort_outreach.py --limit 10 --output-dir out/audits

# Only agencies whose name contains "Blue" (case-insensitive)
.venv\Scripts\python.exe scripts\run_cohort_outreach.py --agency "Blue"

# Combine filter + limit + dry-run
.venv\Scripts\python.exe scripts\run_cohort_outreach.py --agency "Blue" --limit 5 --dry-run
```

Each audit includes the agency's name, support email, and website in the report header — ready to attach to cold-email outreach.

---

## 🕵️ Passive OSINT Intelligence

Every `orbit-security scan` now cross-references the target against the curated public-apis catalog (`A:\reference\public-apis\db\resources.json`, 1,690+ APIs). The OSINT section in the terminal, Markdown, and PDF reports shows:

- **Catalog APIs indexed** and **security/OSINT endpoints** count
- **Domain matches**: catalog APIs whose name/domain/link mention the target
- **Pivot domains**: unique host domains across security/OSINT catalog entries for attack-surface expansion

This is purely passive (local file lookup, no network to the target) and gives agencies a ready-made list of recon tooling to recommend to clients.

---

## 🧪 Testing

Run the automated test suite (444 tests, 100% green):
```powershell
uv run pytest
```

---

## 🌐 Live Platform & Demos

- **Live Production App & Scanner:** [https://cmfh009.github.io/Orbit-Security/](https://cmfh009.github.io/Orbit-Security/)
- **Terms of Service:** [https://cmfh009.github.io/Orbit-Security/terms.html](https://cmfh009.github.io/Orbit-Security/terms.html)
- **Privacy Policy:** [https://cmfh009.github.io/Orbit-Security/privacy.html](https://cmfh009.github.io/Orbit-Security/privacy.html)
- **RFC Safe Harbor:** [https://cmfh009.github.io/Orbit-Security/disclaimer.html](https://cmfh009.github.io/Orbit-Security/disclaimer.html)

