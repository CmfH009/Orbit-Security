# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on ppb.com

**Program:** Flutter UK&I (Hackerone)  
**Program Policy:** [https://hackerone.com/flutteruki](https://hackerone.com/flutteruki)  
**Asset (In-Scope Target):** `ppb.com`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T10:06:02.519839+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **Flutter UK&I** Responsible Disclosure Program, Orbit Security identified a security weakness on `ppb.com`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'ppb.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:5a23cdd989f4495586147bb0e27cd1d2@dmarc-reports.cloudflare.net' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.ppb.com`:
   ```bash
   dig _dmarc.ppb.com TXT +short
   ```
2. Query the SPF TXT record at `ppb.com`:
   ```bash
   dig ppb.com TXT +short
   ```
3. Observe evidence: `Domain 'ppb.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:5a23cdd989f4495586147bb0e27cd1d2@dmarc-reports.cloudflare.net' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `ppb.com` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@ppb.com`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.ppb.com' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Flutter UK&I** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
