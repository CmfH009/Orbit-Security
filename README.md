# 🛡️ Orbit Security: Attack Surface & Subdomain Hygiene Sentinel

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

## 🧪 Testing

Run the automated test suite (44/44 tests with 100% deterministic mocking):
```powershell
uv run pytest
```

---

## 🌐 Live Platform & Demos

- **Live Production App & Scanner:** [https://cmfh009.github.io/Orbit-Security/](https://cmfh009.github.io/Orbit-Security/)
- **Terms of Service:** [https://cmfh009.github.io/Orbit-Security/terms.html](https://cmfh009.github.io/Orbit-Security/terms.html)
- **Privacy Policy:** [https://cmfh009.github.io/Orbit-Security/privacy.html](https://cmfh009.github.io/Orbit-Security/privacy.html)
- **RFC Safe Harbor:** [https://cmfh009.github.io/Orbit-Security/disclaimer.html](https://cmfh009.github.io/Orbit-Security/disclaimer.html)

