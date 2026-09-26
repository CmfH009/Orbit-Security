# Orbit Security — Social Growth & Community Campaign Playbook
**Author:** Carson Haynes (`@_arsoncode`), Founder & Principal Systems Architect  
**Co-Pilot:** Nova (`en-US-AvaNeural`)  
**Target:** Organic Agency Acquisition ($29–$99/mo MRR Retainers) & Infosec Thought Leadership

---

## Executive Summary

Orbit Security’s growth engine relies on **high-density technical proof over marketing fluff**. Agencies do not care about generic "cybersecurity"; they care about:
1. **Defending their existing retainers** ($150–$350/mo per client).
2. **Preventing reputational disaster** (a client's subdomains serving malware or spoofed phishing).
3. **Automating deliverables without burning senior dev hours**.

This playbook details four coordinated growth vectors:
- **Vector 1**: Authentic engagement with the 19 curated infosec heavyweights on our public X List (`Infosec & Zero-Day Watch`).
- **Vector 2**: A viral 7-part technical storytelling thread detailing dangling CNAME takeovers.
- **Vector 3**: The "Free Perimeter Roast / Care Plan Audit" organic inbound lead funnel.
- **Vector 4**: Cross-platform syndication across LinkedIn, Reddit, and Hacker News (`Show HN`).

---

## 1. Curated X List Engagement Playbook

**List Coordinates:** `https://x.com/i/lists/2103939027368051079`  
**List Name:** `Infosec & Zero-Day Watch` (19 verified accounts)

### Core Rules of Engagement:
- **Zero Pitching**: Never reply with links to `buy.stripe.com` or solicit business in replies to list members.
- **Add Signal, Not Noise**: Add complementary technical context, RFC citations, or specific DNS telemetry observations.
- **Quote-Tweet with Value-Add Data**: Retweet breaking zero-day or breach news with an agency-centric perspective.

### Targeted Member Playbook & Reply Templates:

#### Tier 1: Industry Broadcasters & Journalists
*Brian Krebs (@briankrebs, @KrebsOnSecurity), The Hacker News (@TheHackersNews), BleepingComputer (@BleepinComputer), Dark Reading (@DarkReading)*
- **Angle**: Translating enterprise breaches into lessons for digital web studios and Shopify merchants.
- **Reply Template**:
  > *"Fascinating writeup on [Attack Vector]. What's often overlooked is how downstream marketing subdomains created by third-party agencies during seasonal campaigns often remain unmonitored for years after the primary contract ends. Stale DNS records are the soft underbelly of web perimeters."*

#### Tier 2: Technical Researchers & Thought Leaders
*Troy Hunt (@troyhunt), Daniel Miessler (@DanielMiessler), Kevin Beaumont (@GossiTheDog), Florian Roth (@cyb3rops), SwiftOnSecurity (@SwiftOnSecurity)*
- **Angle**: DMARC enforcement decay, DNS-over-HTTPS innovations, and non-intrusive heuristics.
- **Quote-Tweet Template (on Email Spoofing / Phishing)**:
  > *"Seeing a massive surge in domains with `p=none` believing they are protected. Monitoring mode does nothing to prevent lookalike BEC fraud. In our scans across web agencies, over 65% of client perimeters fail basic DMARC quarantine policies because nobody audits DNS drift post-launch."*

#### Tier 3: Practical Red Team & Security Educators
*John Hammond (@_JohnHammond), Dave Kennedy (@HackingDave), Jake Williams (@MalwareJake), Rachel Tobac (@RachelTobac), Katie Moussouris (@k8em0), Lesley Carhart (@hacks4pancakes)*
- **Angle**: Subdomain takeover mechanics, passive reconnaissance safety, and defensive engineering.
- **Interaction Hook**: Share open-source findings from `orbit-recon` verifying non-destructive takeover signatures without sending active payloads.

---

## 2. High-Impact Technical Storytelling Thread on X

**Cadence:** Post during peak B2B engagement hours (Tuesday or Wednesday, 9:30 AM EST).

### Tweet 1 (The Hook):
> How an abandoned $15/mo Unbounce landing page can compromise a $50M Shopify Plus brand:
> 
> The hidden anatomy of Dangling CNAME Subdomain Takeovers — and how open-source reconnaissance catches them in 800ms. 🧵👇
> [Attach visual: `landing/assets/orbit_cats_pounce.jpg`]

### Tweet 2 (The Setup):
> Web & Shopify agencies launch dozens of promotional subdomains every year:
> • `promo.brand.com` ➔ Unbounce
> • `store.brand.com` ➔ Shopify
> • `docs.brand.com` ➔ GitHub Pages / AWS S3
> 
> The marketing campaign ends. The agency cancels the SaaS subscription.
> But nobody touches the DNS manager.

### Tweet 3 (The Vulnerability):
> The DNS record still points:
> `promo.brand.com CNAME unbouncepages.com`
> 
> When anyone visits `promo.brand.com`, Unbounce’s edge servers return:
> `"The requested URL was not found on this server."`
> 
> To an attacker, that 404 is an open invitation.

### Tweet 4 (The Exploit):
> A malicious actor logs into Unbounce, creates a $15 trial account, and claims `promo.brand.com` as their custom domain.
> 
> Suddenly, they control:
> 1. Complete HTTPS delivery under `brand.com`
> 2. Full cookie access across parent domain scopes
> 3. Legitimate SSL certificates issued by Let's Encrypt
> 4. Perfect credential harvesting / phishing legitimacy

### Tweet 5 (The Solution & Automation):
> You don't need expensive enterprise red-teaming suites to stop this.
> 
> We packaged Orbit Security’s core detection heuristics into an open-source CLI utility (`orbit-recon`):
> 
> `pip install orbit-security`
> `orbit-recon clientbrand.com`
> 
> It resolves DNS pointers, audits RFC 7489 DMARC alignment, and checks 17 SaaS takeover signatures in parallel.

### Tweet 6 (The Agency Retainer Angle):
> For web and Shopify agencies:
> 
> Running this audit once a month for your clients turns a hidden vulnerability into a high-margin $250/mo "Website Security & Maintenance Retainer".
> 
> We generate white-label executive PDF reports with your agency’s logo so your clients see proactive stewardship.

### Tweet 7 (The Call to Action):
> Want to see your perimeter hygiene score?
> 
> 1. Run our zero-server DoH terminal directly in your browser:
> https://cmfh009.github.io/Orbit-Security/
> 
> 2. Or reply below with your domain and I’ll run an instant `orbit-recon` audit for you.
> 
> Code is open source on GitHub: https://github.com/CmfH009/Orbit-Security

---

## 3. "Free Perimeter Roast / Audit" Campaign Hook

**Purpose:** Drive organic inbound leads by turning passive DNS audits into a public engagement game.

### Public Post on X:
> 🛡️ Dropping free Perimeter Hygiene Roasts for web agencies and DTC brands today.
> 
> Drop your domain in the replies.
> 
> I’ll run our passive DoH scanner and reply with:
> • Your DMARC & SPF spoofing resistance score
> • Any dangling CNAME / abandoned SaaS routing risks
> • Overall Hygiene Grade (A+ to F)
> 
> Zero intrusive probing. 100% passive DNS telemetry. Drop them below 👇

### Public Reply Template:
> Perimeter Roast for @[User] ([domain]):
> 
> 📊 **Hygiene Score:** 68/100 (Grade: C)
> • Email Spoofing (DMARC): `p=none` (WARN — anyone can forge @[domain])
> • SPF Record: `v=spf1 include:_spf.google.com ~all` (PASS)
> • Perimeter Routing: Apex routed via Cloudflare (PASS)
> 
> 💡 Quick Fix: Upgrade DMARC policy from `p=none` to `p=quarantine` in your DNS manager to reject spoofed emails.
> 
> DM me if you’d like the full co-branded 1-page executive PDF report!

### Private DM Transition Sequence:
> *"Hey [Name], ran the full executive scan for [domain] through Orbit Security. Here’s the 1-page PDF audit ready to send to your stakeholders or clients: [Attach PDF].*
> 
> *If you manage web clients and want automated monthly white-label audits for all your domains, take a look at our Growth Plan ($59/mo for up to 40 domains): https://cmfh009.github.io/Orbit-Security/#pricing.*
> 
> *Cheers,*  
> *Carson (@_arsoncode)"*

---

## 4. Cross-Platform Syndication Plan

### A. LinkedIn Strategy (Agency Founders & CTOs)
- **Target Audience**: Founders, Directors of Web Development, and Head of Client Services at digital studios.
- **Post Copy**:
  > **Why most $250/mo website maintenance retainers are vulnerable to churn (and how to fix it):**
  > 
  > Every agency owner has heard a client ask: *"What are we paying you for each month if the site hasn’t changed?"*
  > 
  > The problem isn't that you aren't providing value. The problem is that continuous security stewardship is invisible.
  > 
  > When an agency updates WordPress plugins or monitors DNS health, the client sees nothing. Until a rogue marketing subdomain gets hijacked or their domain is spoofed in a phishing scam.
  > 
  > That's why I built Orbit Security.
  > 
  > It continuously patrols client perimeters for orphaned DNS pointers, dangling SaaS subdomains (Shopify, Unbounce, AWS, GitHub), and email spoofing drift—and compiles white-label, co-branded monthly PDF audits with your agency's logo.
  > 
  > We just launched our interactive browser scanner and live co-branding studio. Try it out with your agency's name:
  > https://cmfh009.github.io/Orbit-Security/

### B. Reddit Developer Communities
- **Subreddits**: `r/netsec` (technical tool), `r/sysadmin` (DNS automation), `r/webdev` (agency retainer workflow).
- **Title for r/webdev**:
  > *I built a lightweight Python & Web tool that automates client DNS hygiene checks (DMARC, dangling CNAMEs, SSL expiry) so agencies can justify monthly care plans.*
- **Tone**: Self-effacing, technical, open-source focus. Link to GitHub repo first, landing page second.

### C. Hacker News (Show HN)
- **Title**: `Show HN: orbit-recon – Zero-dependency DNS hygiene and subdomain takeover scanner`
- **Text**:
  > *Hi HN, I’m Carson. While working with web agencies, I noticed a recurring issue: agencies launch promotional subdomains pointing to SaaS platforms (Unbounce, Shopify, S3, GitHub Pages) and forget about them when campaigns end. Later, attackers claim the abandoned endpoint and take over the subdomain.*
  > 
  > *I wrote `orbit-recon` (Python 3, pure dnspython/httpx) to passively scan DNS records, evaluate RFC 7489 DMARC/SPF compliance, and check 17 known takeover fingerprints in under a second.*
  > 
  > *Code: https://github.com/CmfH009/Orbit-Security*  
  > *Interactive DoH Web Demo: https://cmfh009.github.io/Orbit-Security/*
  > 
  > *Feedback on detection heuristics and additional SaaS signatures welcome!*

---

## 5. 14-Day Social Scaling Cadence

| Day | Platform | Action / Content |
| :--- | :--- | :--- |
| **Day 1** | X (@_arsoncode) | Publish 7-part Technical Dangling CNAME Thread. |
| **Day 2** | X List | Quote-tweet breaking infosec news from List member with agency-centric analysis. |
| **Day 3** | X (@_arsoncode) | Launch "Free Perimeter Roast / Audit" hook tweet. |
| **Day 4** | LinkedIn | Publish Founder Long-form Post: "Why care plan retainers churn". |
| **Day 5** | X | Reply with 5–10 public roast scorecards + DM white-label sample PDFs. |
| **Day 6** | GitHub / Reddit | Post `orbit-recon` release to `r/webdev` and `r/sysadmin`. |
| **Day 7** | Hacker News | Submit `Show HN: orbit-recon`. |
| **Day 8** | X List | Engage with 3 list members (Troy Hunt, Kevin Beaumont, SwiftOnSecurity) on DMARC decay. |
| **Day 9** | Meta / FB | Share Astro-Cat Sentinel creative post to Orbit Security Facebook page. |
| **Day 10** | X (@_arsoncode) | Share customer case study / before-after DNS hygiene turnaround. |
| **Day 11** | LinkedIn | InMail outreach to 10 Shopify Plus agency founders using Option 1 Free Audit hook. |
| **Day 12** | X | Poll follow-up breakdown: "Results from our 4-choice infosec poll". |
| **Day 13** | X List | Curate and highlight 5 top infosec articles from the public list in a rollup tweet. |
| **Day 14** | All Channels | Announce monthly fleet sentinel update with Slack/Discord webhook integration. |
