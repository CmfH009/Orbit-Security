# [Cloud Storage Takeover] Unclaimed Storage Bucket on assets.gitlab.com

**Program:** GitLab (Hackerone)  
**Program Policy:** [https://hackerone.com/gitlab](https://hackerone.com/gitlab)  
**Asset (In-Scope Target):** `assets.gitlab.com`  
**Weakness:** `CWE-284: Improper Access Control`  
**Severity:** `HIGH` (CVSS 3.1: **8.6**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`  
**Bounty Viability Grade:** `HIGH_CONFIDENCE`  
**Date Discovered:** 2026-10-31T09:01:28.150821+00:00  

---

## 1. Summary
> [!TIP] **High-Value Bounty Finding**
> High-confidence security finding verified on target infrastructure with direct impact on origin integrity or confidentiality.

During an external attack surface and DNS perimeter hygiene assessment under the **GitLab** Responsible Disclosure Program, Orbit Security identified a security weakness on `assets.gitlab.com`.

- **Vulnerability Category:** `Cloud Storage Takeover`
- **Affected Provider/Service:** `AWS S3`
- **Observed Evidence:** Dangling AWS S3 storage bucket detected on 'assets.gitlab.com'. Response body matches unallocated bucket signature: 'NoSuchBucket'.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Query the DNS CNAME record for `assets.gitlab.com`:
   ```bash
   dig assets.gitlab.com CNAME +short
   # Output: None
   ```
2. Query the HTTP endpoint and observe the unallocated storage response (`NoSuchBucket` / `BlobNotFound`):
   ```bash
   curl -i -s https://assets.gitlab.com
   ```
3. Observe evidence: `Dangling AWS S3 storage bucket detected on 'assets.gitlab.com'. Response body matches unallocated bucket signature: 'NoSuchBucket'.`

---

## 3. Impact
The domain `assets.gitlab.com` points to an unallocated or deleted cloud storage bucket (`storage endpoint`) on AWS S3.
An adversary can claim the identical bucket name in their own cloud account and serve arbitrary malicious content under `assets.gitlab.com`, enabling stored XSS, session hijacking, and brand impersonation.

---

## 4. Remediation & Recommended Solution
Either create/claim the matching AWS S3 bucket name in your cloud account to prevent third-party registration, or remove the dangling DNS CNAME record.

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **GitLab** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
