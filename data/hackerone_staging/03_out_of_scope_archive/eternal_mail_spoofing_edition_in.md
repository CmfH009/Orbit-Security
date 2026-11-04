# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on edition.in

**Program:** Eternal (Hackerone)  
**Program Policy:** [https://hackerone.com/eternal](https://hackerone.com/eternal)  
**Asset (In-Scope Target):** `edition.in`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `HIGH` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T10:54:22.684980+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **Eternal** Responsible Disclosure Program, Orbit Security identified a security weakness on `edition.in`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'edition.in' has NO DMARC record published at _dmarc.edition.in. Anyone can spoof email headers with arbitrary envelope senders.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.edition.in`:
   ```bash
   dig _dmarc.edition.in TXT +short
   ```
2. Query the SPF TXT record at `edition.in`:
   ```bash
   dig edition.in TXT +short
   ```
3. Observe evidence: `Domain 'edition.in' has NO DMARC record published at _dmarc.edition.in. Anyone can spoof email headers with arbitrary envelope senders.`

---

## 3. Impact
Because `edition.in` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@edition.in`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.edition.in' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Eternal** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
