# [Cloud Storage Takeover] Unclaimed Storage Bucket on cdn.khealth-test.com

**Program:** KHealth (Hackerone)  
**Program Policy:** [https://hackerone.com/khealth](https://hackerone.com/khealth)  
**Asset (In-Scope Target):** `cdn.khealth-test.com`  
**Weakness:** `CWE-284: Improper Access Control`  
**Severity:** `HIGH` (CVSS 3.1: **8.6**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`  
**Bounty Viability Grade:** `HIGH_CONFIDENCE`  
**Date Discovered:** 2026-10-29T11:04:35.837210+00:00  

---

## 1. Summary
> [!TIP] **High-Value Bounty Finding**
> High-confidence security finding verified on target infrastructure with direct impact on origin integrity or confidentiality.

During an external attack surface and DNS perimeter hygiene assessment under the **KHealth** Responsible Disclosure Program, Orbit Security identified a security weakness on `cdn.khealth-test.com`.

- **Vulnerability Category:** `Cloud Storage Takeover`
- **Affected Provider/Service:** `AWS S3`
- **Observed Evidence:** Dangling AWS S3 storage bucket detected on 'cdn.khealth-test.com'. Response body matches unallocated bucket signature: 'NoSuchBucket'.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DNS CNAME record for `cdn.khealth-test.com`:
   ```bash
   dig cdn.khealth-test.com CNAME +short
   # Output: None
   ```
2. Query the HTTP endpoint and observe the unallocated storage response (`NoSuchBucket` / `BlobNotFound`):
   ```bash
   curl -i -s https://cdn.khealth-test.com
   ```
3. Observe evidence: `Dangling AWS S3 storage bucket detected on 'cdn.khealth-test.com'. Response body matches unallocated bucket signature: 'NoSuchBucket'.`

---

## 3. Impact
The domain `cdn.khealth-test.com` points to an unallocated or deleted cloud storage bucket (`storage endpoint`) on AWS S3.
An adversary can claim the identical bucket name in their own cloud account and serve arbitrary malicious content under `cdn.khealth-test.com`, enabling stored XSS, session hijacking, and brand impersonation.

---

## 4. Remediation & Recommended Solution
Either create/claim the matching AWS S3 bucket name in your cloud account to prevent third-party registration, or remove the dangling DNS CNAME record.

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **KHealth** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
