# Orbit Security: Custom Domain & DNS Setup Guide

This guide explains how to connect your custom brand domain (e.g., `orbitsecurity.ai` or `orbitsecurity.io`) to Orbit Security's live landing page.

---

### Step 1: Add DNS Records in Your Registrar / Cloudflare

Log in to your DNS provider (Cloudflare, Namecheap, GoDaddy, Google Domains, etc.) and add the following records:

#### Apex / Root Domain (`@` or `orbitsecurity.ai`)
Create four **A** records pointing to GitHub Pages' global CDN:

| Record Type | Host / Name | IP Address | TTL |
| :--- | :--- | :--- | :--- |
| **A** | `@` | `185.199.108.153` | Auto / 300s |
| **A** | `@` | `185.199.109.153` | Auto / 300s |
| **A** | `@` | `185.199.110.153` | Auto / 300s |
| **A** | `@` | `185.199.111.153` | Auto / 300s |

#### Subdomain (`www.orbitsecurity.ai`)
Create a **CNAME** record pointing to your GitHub Pages host:

| Record Type | Host / Name | Target / Value | TTL |
| :--- | :--- | :--- | :--- |
| **CNAME** | `www` | `cmfh009.github.io` | Auto / 300s |

---

### Step 2: Bind Domain via Automated Script

Once your DNS records are added, run the automated domain setup utility:

```powershell
cd A:\projects\orbit-security
uv run python scripts/setup_custom_domain.py <your-domain.com>
```

This utility will:
1. Generate `docs/CNAME` with your domain.
2. Verify DNS resolution and SSL readiness.
3. Automatically bind the domain to your repository via the GitHub REST API.

---

### Step 3: HTTPS & TLS Verification

GitHub automatically provisions a free, auto-renewing Let's Encrypt TLS certificate for your custom domain within 15–60 minutes of DNS propagation. "Enforce HTTPS" will be automatically enabled.
