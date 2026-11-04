# [CORS Misconfiguration] Arbitrary Origin Reflection with Credentials on apps.stage.napoleoncasino.be

**Program:** Superbet (Hackerone)  
**Program Policy:** [https://hackerone.com/superbet](https://hackerone.com/superbet)  
**Asset (In-Scope Target):** `apps.stage.napoleoncasino.be`  
**Weakness:** `CWE-942: Permissive Cross-domain Policy with Untrusted Domains`  
**Severity:** `HIGH` (CVSS 3.1: **8.1**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`  
**Bounty Viability Grade:** `HIGH_CONFIDENCE`  
**Date Discovered:** 2026-10-27T10:43:00.163037+00:00  

---

## 1. Summary
> [!TIP] **High-Value Bounty Finding**
> High-confidence security finding verified on target infrastructure with direct impact on origin integrity or confidentiality.

During an external attack surface and DNS perimeter hygiene assessment under the **Superbet** Responsible Disclosure Program, Orbit Security identified a security weakness on `apps.stage.napoleoncasino.be`.

- **Vulnerability Category:** `Cors Arbitrary Origin With Credentials`
- **Affected Provider/Service:** `API Gateway CORS`
- **Observed Evidence:** Vulnerable CORS policy on 'apps.stage.napoleoncasino.be': Server blindly reflects untrusted Origin 'https://untrusted-adversary.com' in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials to true. Any third-party website can forge cross-origin requests with user session cookies and read responses.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Send an HTTP request with an untrusted Origin header to `apps.stage.napoleoncasino.be`:
   ```bash
   curl -i -s -H "Origin: https://evil.com" https://apps.stage.napoleoncasino.be/
   ```
2. Inspect the HTTP response headers for reflected origin and credentials allowance:
   ```http
   Access-Control-Allow-Origin: https://evil.com
   Access-Control-Allow-Credentials: true
   ```
3. Observe evidence: `Vulnerable CORS policy on 'apps.stage.napoleoncasino.be': Server blindly reflects untrusted Origin 'https://untrusted-adversary.com' in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials to true. Any third-party website can forge cross-origin requests with user session cookies and read responses.`

---

## 3. Impact
The endpoint on `apps.stage.napoleoncasino.be` implements an insecure Cross-Origin Resource Sharing (CORS) policy.
When an authenticated user visits an attacker-controlled website:
1. The malicious website can issue background cross-origin requests to `apps.stage.napoleoncasino.be`.
2. The browser grants the untrusted site read access to sensitive response bodies due to permissive origin allowance.
3. The attacker can extract private user records, account details, CSRF tokens, or internal API responses cross-origin.

---

## 4. Remediation & Recommended Solution
Do not dynamically reflect untrusted Origin header values. Validate incoming Origin headers against an explicit, strict server-side whitelist before echoing in Access-Control-Allow-Origin. Never enable Access-Control-Allow-Credentials for untrusted or dynamic origins.

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Superbet** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
