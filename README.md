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

## 🧪 Testing

Run the automated test suite:
```powershell
uv run pytest
```
All tests run with 100% deterministic mocking for DNS and network requests.
