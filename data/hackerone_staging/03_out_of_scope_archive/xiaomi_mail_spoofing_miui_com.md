# [Email Spoofing] Missing DMARC Enforcement Enables Inbound Spoofing on miui.com

**Program:** Xiaomi (Hackerone)  
**Program Policy:** [https://hackerone.com/xiaomi](https://hackerone.com/xiaomi)  
**Asset (In-Scope Target):** `miui.com`  
**Weakness:** `CWE-290: Authentication Bypass by Spoofing`  
**Severity:** `HIGH` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**Bounty Viability Grade:** `CONDITIONAL`  
**Date Discovered:** 2026-10-29T09:41:26.852642+00:00  

---

## 1. Summary
During an external attack surface and DNS perimeter hygiene assessment under the **Xiaomi** Responsible Disclosure Program, Orbit Security identified a security weakness on `miui.com`.

- **Vulnerability Category:** `Mail Spoofing`
- **Affected Provider/Service:** `Email / DNS Infrastructure`
- **Observed Evidence:** Domain 'miui.com' has NO DMARC record published at _dmarc.miui.com. Anyone can spoof email headers with arbitrary envelope senders.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DMARC TXT record at `_dmarc.miui.com`:
   ```bash
   dig _dmarc.miui.com TXT +short
   ```
2. Query the SPF TXT record at `miui.com`:
   ```bash
   dig miui.com TXT +short
   ```
3. Observe evidence: `Domain 'miui.com' has NO DMARC record published at _dmarc.miui.com. Anyone can spoof email headers with arbitrary envelope senders.`

---

## 3. Impact
Because `miui.com` lacks strict DMARC rejection (`p=reject`), an adversary can forge email `From:` headers appearing to originate directly from `*@miui.com`. This enables highly convincing CEO fraud, invoice fraud, and employee credential harvesting that bypasses standard email security gateways.

---

## 4. Remediation & Recommended Solution
Publish a strict DMARC record at '_dmarc.miui.com' with 'v=DMARC1; p=reject; sp=reject;' and ensure valid SPF (~all or -all).

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Xiaomi** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
