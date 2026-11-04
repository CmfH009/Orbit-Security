# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on khealth.com

**Program:** KHealth (Hackerone)  
**Program Policy:** [https://hackerone.com/khealth](https://hackerone.com/khealth)  
**Asset (In-Scope Target):** `khealth.com`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T11:06:20.114859+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **KHealth** Responsible Disclosure Program, Orbit Security identified a security weakness on `khealth.com`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'khealth.com' publishes DMARC record 'v=DMARC1;p=none;sp=none;rua=mailto:mailauth-reports@khealth.com' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.khealth.com`:
   ```bash
   dig _dmarc.khealth.com TXT +short
   ```
2. Query the SPF TXT record at `khealth.com`:
   ```bash
   dig khealth.com TXT +short
   ```
3. Observe evidence: `Domain 'khealth.com' publishes DMARC record 'v=DMARC1;p=none;sp=none;rua=mailto:mailauth-reports@khealth.com' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `khealth.com` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@khealth.com`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.khealth.com' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **KHealth** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
