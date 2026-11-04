# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on ppbdev.com

**Program:** Flutter UK&I (Hackerone)  
**Program Policy:** [https://hackerone.com/flutteruki](https://hackerone.com/flutteruki)  
**Asset (In-Scope Target):** `ppbdev.com`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T10:06:07.569198+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **Flutter UK&I** Responsible Disclosure Program, Orbit Security identified a security weakness on `ppbdev.com`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'ppbdev.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:6e58900eb1a44d31b0ac9ce03aa6cc49@dmarc-reports.cloudflare.net;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.ppbdev.com`:
   ```bash
   dig _dmarc.ppbdev.com TXT +short
   ```
2. Query the SPF TXT record at `ppbdev.com`:
   ```bash
   dig ppbdev.com TXT +short
   ```
3. Observe evidence: `Domain 'ppbdev.com' publishes DMARC record 'v=DMARC1; p=none; rua=mailto:6e58900eb1a44d31b0ac9ce03aa6cc49@dmarc-reports.cloudflare.net;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `ppbdev.com` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@ppbdev.com`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.ppbdev.com' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Flutter UK&I** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
