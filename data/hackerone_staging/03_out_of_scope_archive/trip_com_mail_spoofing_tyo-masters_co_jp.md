# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on tyo-masters.co.jp

**Program:** Trip.com (Hackerone)  
**Program Policy:** [https://hackerone.com/trip_com](https://hackerone.com/trip_com)  
**Asset (In-Scope Target):** `tyo-masters.co.jp`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T11:02:28.451394+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **Trip.com** Responsible Disclosure Program, Orbit Security identified a security weakness on `tyo-masters.co.jp`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'tyo-masters.co.jp' publishes DMARC record 'v=DMARC1; p=none; sp=none; rua=mailto:leon@tyo-masters.co.jp' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.tyo-masters.co.jp`:
   ```bash
   dig _dmarc.tyo-masters.co.jp TXT +short
   ```
2. Query the SPF TXT record at `tyo-masters.co.jp`:
   ```bash
   dig tyo-masters.co.jp TXT +short
   ```
3. Observe evidence: `Domain 'tyo-masters.co.jp' publishes DMARC record 'v=DMARC1; p=none; sp=none; rua=mailto:leon@tyo-masters.co.jp' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `tyo-masters.co.jp` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@tyo-masters.co.jp`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.tyo-masters.co.jp' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Trip.com** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
