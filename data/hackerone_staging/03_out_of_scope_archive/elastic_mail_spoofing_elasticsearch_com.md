# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on elasticsearch.com

**Program:** Elastic (Hackerone)  
**Program Policy:** [https://hackerone.com/elastic](https://hackerone.com/elastic)  
**Asset (In-Scope Target):** `elasticsearch.com`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T08:54:59.052314+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **Elastic** Responsible Disclosure Program, Orbit Security identified a security weakness on `elasticsearch.com`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'elasticsearch.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:dmarc@elastic.co,mailto:dmarc_agg@vali.email;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.elasticsearch.com`:
   ```bash
   dig _dmarc.elasticsearch.com TXT +short
   ```
2. Query the SPF TXT record at `elasticsearch.com`:
   ```bash
   dig elasticsearch.com TXT +short
   ```
3. Observe evidence: `Domain 'elasticsearch.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:dmarc@elastic.co,mailto:dmarc_agg@vali.email;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `elasticsearch.com` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@elasticsearch.com`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.elasticsearch.com' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Elastic** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
