# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on hhc247.org

**Program:** KHealth (Hackerone)  
**Program Policy:** [https://hackerone.com/khealth](https://hackerone.com/khealth)  
**Asset (In-Scope Target):** `hhc247.org`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T08:56:28.603775+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **KHealth** Responsible Disclosure Program, Orbit Security identified a security weakness on `hhc247.org`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'hhc247.org' publishes DMARC record 'v=DMARC1; p=none;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.hhc247.org`:
   ```bash
   dig _dmarc.hhc247.org TXT +short
   ```
2. Query the SPF TXT record at `hhc247.org`:
   ```bash
   dig hhc247.org TXT +short
   ```
3. Observe evidence: `Domain 'hhc247.org' publishes DMARC record 'v=DMARC1; p=none;' with 'p=none' monitoring-only policy. Spoofed emails are delivered without rejection.`

---

## 3. Impact
Because `hhc247.org` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@hhc247.org`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.hhc247.org' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **KHealth** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
