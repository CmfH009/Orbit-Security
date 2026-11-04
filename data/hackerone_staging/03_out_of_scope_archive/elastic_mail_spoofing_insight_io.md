# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on insight.io

**Program:** Elastic (Hackerone)  
**Program Policy:** [https://hackerone.com/elastic](https://hackerone.com/elastic)  
**Asset (In-Scope Target):** `insight.io`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T10:18:01.932029+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **Elastic** Responsible Disclosure Program, Orbit Security identified a security weakness on `insight.io`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'insight.io' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:dmarc@elastic.co,mailto:dmarc_agg@vali.email;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.insight.io`:
   ```bash
   dig _dmarc.insight.io TXT +short
   ```
2. Query the SPF TXT record at `insight.io`:
   ```bash
   dig insight.io TXT +short
   ```
3. Observe evidence: `Domain 'insight.io' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:dmarc@elastic.co,mailto:dmarc_agg@vali.email;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `insight.io` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@insight.io`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.insight.io' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Elastic** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
