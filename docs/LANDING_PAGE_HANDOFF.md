# Orbit Security: Landing Page Enhancement & Link Wiring Handoff

**Target Resource**: `landing/index.html` & `docs/index.html`  
**Live Production URL**: `https://cmfh009.github.io/Orbit-Security/`  
**Deployment Mechanism**: GitHub Pages deployed from the `/docs` branch root. (Changes in `landing/` must always be synced to `docs/` via `python scripts/deploy_landing.py` or direct copy before pushing).

---

## 1. Executive Summary & Objective

This handoff blueprint outlines all required updates to bring the live Orbit Security landing page to enterprise production standard. 

When visitors land on the site from Carson's Facebook feed, the cold email campaigns (Cohorts 1–3), or tomorrow's $10 Meta Ad campaign, every link must resolve cleanly, the founder persona must establish instant trust through verified social profiles (Facebook, LinkedIn, GitHub, Email), and the page must unfurl rich visual cards across all social platforms.

---

## 2. Master Link Wiring Matrix

| Section / Element | Current State | Required Update & Exact Destination |
| :--- | :--- | :--- |
| **Founder Profile Card** | Photo + bio, no social links | Add branded SVG buttons for **LinkedIn**, **Facebook**, **GitHub**, and **Email**. |
| **Founder Letter Signoff** | Plain email text link | Add social icon strip alongside direct email: `mailto:carsonmail009@gmail.com`. |
| **Page Footer** | Basic text, no social channels | Add a 4-icon social cluster: Facebook, LinkedIn, GitHub, and Email. |
| **LinkedIn Target** | Not linked | Link to Carson's verified LinkedIn profile. |
| **Facebook Target** | Not linked | Link to Carson Michael Haynes' Facebook profile / Orbit Security page. |
| **GitHub Repository** | Not linked | Link to `https://github.com/CmfH009/Orbit-Security` for open-source credibility. |
| **Direct Email Inquiries** | Raw mailto link | Structured mailto with subject: `mailto:carsonmail009@gmail.com?subject=Agency%20Security%20Audit%20Inquiry`. |
| **Growth Tier Checkout** | Active Stripe Link | Retain live checkout: `https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800` ($59/mo). |
| **Starter Tier Checkout** | Mailto link | Wire dedicated Stripe checkout or instant free trial modal. |
| **Pro / Agency Retainer** | Mailto link | Wire dedicated inquiry / booking link or higher-tier Stripe link ($99/mo or $199/mo). |

---

## 3. Social Media & SEO Meta Tag Specification (OpenGraph & Twitter)

Currently, the landing page `<head>` lacks OpenGraph and Twitter Card metadata. When the page URL is shared on Facebook, LinkedIn, Twitter, or Discord, it does not generate an image preview.

### Required `<head>` Injection:
```html
<!-- Primary Meta Tags -->
<title>Orbit Security | Attack Surface & Subdomain Hygiene for Web Agencies</title>
<meta name="title" content="Orbit Security | Attack Surface & Subdomain Hygiene for Web Agencies">
<meta name="description" content="Turn client DNS & perimeter hygiene into high-margin recurring retainers. Automated white-label security audits for Shopify & WordPress agencies.">
<meta name="author" content="Carson | Founder, Orbit Security">

<!-- Open Graph / Facebook / LinkedIn -->
<meta property="og:type" content="website">
<meta property="og:url" content="https://cmfh009.github.io/Orbit-Security/">
<meta property="og:title" content="Orbit Security | White-Label Perimeter Defense for Agencies">
<meta property="og:description" content="Automate client perimeter security, catch subdomain takeovers, and export co-branded monthly audit PDFs to justify $250/mo agency retainers.">
<meta property="og:image" content="https://cmfh009.github.io/Orbit-Security/assets/orbit_cats_pounce.jpg">
<meta property="og:image:width" content="1024">
<meta property="og:image:height" content="1024">

<!-- Twitter -->
<meta property="twitter:card" content="summary_large_image">
<meta property="twitter:url" content="https://cmfh009.github.io/Orbit-Security/">
<meta property="twitter:title" content="Orbit Security | Perimeter Sentinels for Web Agencies">
<meta property="twitter:description" content="Automated monthly white-label security audits for web and Shopify agencies.">
<meta property="twitter:image" content="https://cmfh009.github.io/Orbit-Security/assets/orbit_cats_pounce.jpg">
```

---

## 4. Visual Components & Creative Suite Integration

1. **Astro-Cat Sentinel Feature Grid**:
   - Feature 1: **Perimeter Interception** -> `assets/orbit_cats_pounce.jpg` (1:1 threat defense).
   - Feature 2: **Gateway Firewall Portal** -> `assets/orbit_cats_gatekeeper.jpg` (16:9 cosmic gatekeeper).
   - Feature 3: **Telemetry Sentinel** -> `assets/orbit_cats_radar.jpg` (1:1 radar surface scanner).
2. **Interactive Sample PDF Modal or Carousel**:
   - Provide an instant 1-click preview of `sample_audit.pdf` so visiting agency owners can inspect the exact co-branded deliverable their clients would receive.

---

## 5. Interactive Lead Capture Widget ("Run Instant Perimeter Check")

```html
<!-- Interactive Domain Audit Request Widget -->
<div class="mt-8 max-w-lg mx-auto bg-slate-900/90 border border-slate-700/80 p-2 rounded-2xl shadow-2xl flex flex-col sm:flex-row gap-2">
    <input 
        type="text" 
        id="targetDomainInput" 
        placeholder="Enter your agency or client domain (e.g. client.com)" 
        class="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
    />
    <button 
        onclick="requestAudit()" 
        class="px-6 py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm transition-all shadow-md shadow-emerald-500/20 whitespace-nowrap">
        Scan Perimeter
    </button>
</div>
```

---

## 6. Mobile Navigation & Accessibility Hardening

- **Mobile Hamburger Menu**: The current navigation links (`#features`, `#pricing`, etc.) are hidden on screens `< 768px` (`hidden md:flex`). Add a lightweight JavaScript toggle for mobile viewports.
- **Scroll Spy & Active States**: Add subtle highlight states for navigation links as the user scrolls past `#features`, `#pricing`, and `#founder`.

---

## 7. Execution Checklist for Tomorrow Morning

- [ ] **Step 1: Obtain / Confirm Exact Social URLs**:
  - Facebook Profile/Page URL.
  - LinkedIn Profile URL.
- [ ] **Step 2: Update `landing/index.html`**:
  - Inject OpenGraph & Twitter `<meta>` tags.
  - Add SVG social icon clusters (LinkedIn, Facebook, GitHub, Email) in the Founder section and Footer.
  - Insert the Interactive Domain Audit Request widget.
  - Add mobile hamburger navigation menu.
- [ ] **Step 3: Sync & Deploy to GitHub Pages**:
  - Run `python scripts/deploy_landing.py` (copies `landing/` -> `docs/`).
  - Verify working tree and push to `origin main`.
- [ ] **Step 4: Empirical Verification**:
  - Test live URL: `https://cmfh009.github.io/Orbit-Security/`.
  - Click every single link (Facebook, LinkedIn, GitHub, Email, Stripe) to verify HTTP 200 OK.
  - Run Facebook Sharing Debugger & LinkedIn Post Inspector on the live URL to verify that the Astro-Cat image preview renders cleanly.
- [ ] **Step 5: Launch $10 Meta Ad**:
  - Once NVIDIA stock funds clear, execute the ad launch following `meta_10_dollar_ad_blueprint.md`.
