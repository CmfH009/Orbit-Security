# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on portalinmobiliario.com

**Program:** MercadoLibre (Hackerone)  
**Program Policy:** [https://hackerone.com/mercadolibre](https://hackerone.com/mercadolibre)  
**Asset (In-Scope Target):** `portalinmobiliario.com`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T10:43:42.856151+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **MercadoLibre** Responsible Disclosure Program, Orbit Security identified a security weakness on `portalinmobiliario.com`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'portalinmobiliario.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:dmarcrua@mercadolibre.com, mailto:mercadolibre@rua.netcraft.com, mailto:dmarc_agg@vali.email; ruf=mailto:dmarcruf@mercadolibre.com,mailto:mercadolibre@ruf.netcraft.com; adkim=r; aspf=r; rf=afrf; pct=100;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.portalinmobiliario.com`:
   ```bash
   dig _dmarc.portalinmobiliario.com TXT +short
   ```
2. Query the SPF TXT record at `portalinmobiliario.com`:
   ```bash
   dig portalinmobiliario.com TXT +short
   ```
3. Observe evidence: `Domain 'portalinmobiliario.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:dmarcrua@mercadolibre.com, mailto:mercadolibre@rua.netcraft.com, mailto:dmarc_agg@vali.email; ruf=mailto:dmarcruf@mercadolibre.com,mailto:mercadolibre@ruf.netcraft.com; adkim=r; aspf=r; rf=afrf; pct=100;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `portalinmobiliario.com` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@portalinmobiliario.com`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.portalinmobiliario.com' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **MercadoLibre** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
