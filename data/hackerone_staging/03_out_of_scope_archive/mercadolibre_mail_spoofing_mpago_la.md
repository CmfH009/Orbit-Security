# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on mpago.la

**Program:** MercadoLibre (Hackerone)  
**Program Policy:** [https://hackerone.com/mercadolibre](https://hackerone.com/mercadolibre)  
**Asset (In-Scope Target):** `mpago.la`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `HIGH` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T10:43:17.540253+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **MercadoLibre** Responsible Disclosure Program, Orbit Security identified a security weakness on `mpago.la`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'mpago.la' has NO DMARC record published at _dmarc.mpago.la. Anyone can spoof email headers with arbitrary envelope senders.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.mpago.la`:
   ```bash
   dig _dmarc.mpago.la TXT +short
   ```
2. Query the SPF TXT record at `mpago.la`:
   ```bash
   dig mpago.la TXT +short
   ```
3. Observe evidence: `Domain 'mpago.la' has NO DMARC record published at _dmarc.mpago.la. Anyone can spoof email headers with arbitrary envelope senders.`

---

## 3. Impact
Because `mpago.la` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@mpago.la`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.mpago.la' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **MercadoLibre** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
