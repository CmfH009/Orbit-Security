# Orbit Security — Agency Fleet Retainer Outreach Playbook

**Target**: Web, eCommerce (Shopify Plus/Magento), and WordPress Agencies & MSPs  
**Objective**: Convert agency founders & technical directors into White-Label Fleet Studio subscribers ($29–$99/mo)  
**Value Proposition**: Enable agencies to offer automated monthly perimeter hygiene & DNS drift audits to their client roster under their own brand, unlocking $150–$350/mo in recurring client care-plan revenue.

---

## 1. Why the Shift from Unsolicited "F-Grade" Audits?

The initial cold outreach sequence delivered unsolicited F-grade security reports to engineering leads. While technically accurate, this triggered defensive reactions:
- Recipients felt ambushed or targeted.
- CTOs viewed the unsolicited audit as aggressive vendor posturing.
- 135 delivered emails yielded 0 closed conversations.

### The New Partner-First Philosophy
Instead of telling an agency *"your client site has security flaws,"* we approach them as infrastructure allies:
> *"You maintain 20–50 client websites. When marketing teams add third-party tracking or abandon promotional subdomains, DNS drifts. We provide an automated White-Label Fleet Studio so you can deliver branded monthly security hygiene reports to your clients without burning senior developer hours."*

---

## 2. High-Converting Email Sequences

### Sequence A: Direct Founder/CTO Outreach (The Agency Retainer Angle)

**Subject**: White-label security audits for your client portfolio

**Body**:
```text
Hi {{first_name}},

Noticed {{company_name}} manages complex web builds across your client roster.

A recurring headache for digital studios is client DNS drift post-launch—marketing teams spin up unmonitored subdomains or third-party SaaS services that eventually expire into dangling records.

We built the Orbit Fleet Studio (https://cmfh009.github.io/Orbit-Security/fleet.html) specifically for agencies:
1. Multi-Client Perimeter Sentinel: Monitor your entire client fleet in one lightweight HUD.
2. 100% Passive DoH Telemetry: Zero active scans or intrusive probes against client infrastructure.
3. Branded Client PDFs: Export 1-click executive hygiene certificates under {{company_name}}'s brand to include in your monthly maintenance retainers.

Would you be open to testing a complimentary 10-domain agency dashboard for {{company_name}} to see if it fits your client care plans?

Best regards,

Carson Haynes
Founder & Systems Architect, Orbit Security
https://cmfh009.github.io/Orbit-Security/
```

---

### Sequence B: The Care-Plan Upsell (For Agency Account & Operations Leads)

**Subject**: Adding perimeter hygiene to {{company_name}} maintenance retainers

**Body**:
```text
Hi {{first_name}},

Most agencies charge $150–$500/mo for standard maintenance (hosting, CMS updates, uptime), but clients increasingly ask what proactive security measures are included.

Orbit Security provides a turnkey, white-label client audit suite:
- Automated perimeter & email spoofing (DMARC/SPF/DKIM) posture checks.
- Continuous dangling DNS & subdomain takeover detection.
- Co-branded executive PDFs that demonstrate tangible monthly care value.

Our agency fleet tier starts at $29/mo for up to 25 domains:
https://cmfh009.github.io/Orbit-Security/fleet.html

If you'd like a quick preview using a couple of {{company_name}} sample domains, let me know and I'll generate a white-labeled audit pack for your team.

Cheers,

Carson Haynes
Orbit Security
```

---

## 3. LinkedIn Warm Connection & Soft Inmail

**Connection Note**:
> *"Hi {{first_name}} — love {{company_name}}'s recent work. We built a lightweight multi-domain perimeter monitor for web agencies to automate client security reporting in monthly retainers. Would love to connect!"*

**Follow-up (after accept)**:
> *"Thanks for connecting, {{first_name}}! In case it's helpful for your operations team, we recently launched our White-Label Fleet Studio (https://cmfh009.github.io/Orbit-Security/fleet.html) to let digital studios monitor up to 50 client domains with 1-click branded PDF reports. Let me know if you'd ever like a test run for your maintenance clients."*

---

## 4. Key Objections & Clean Handling

| Objection | Agency Reality | Recommended Response |
| :--- | :--- | :--- |
| *"We already use Cloudflare/WAF."* | Cloudflare protects traffic, but doesn't monitor forgotten third-party SaaS CNAMEs on DNS providers. | *"Cloudflare is great for active traffic filtering. Orbit specializes in perimeter drift—identifying forgotten CNAMEs, expired SaaS endpoints, and DNSSEC/DMARC posture across your client fleet."* |
| *"Is this intrusive or will it trigger client alarms?"* | 100% client-side RFC 8484 DNS-over-HTTPS. | *"Zero active port scans or HTTP probes. Orbit operates purely through encrypted, passive DNS queries via Google and Cloudflare resolvers—completely invisible to client servers and zero intrusion risk."* |
| *"Can we put our agency logo on the reports?"* | Yes, built into `fleet.html`. | *"Yes, the Fleet Studio supports custom agency branding so you can export client-ready PDFs with your logo and agency certification."* |
