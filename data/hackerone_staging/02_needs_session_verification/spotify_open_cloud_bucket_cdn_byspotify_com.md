# [Cloud Storage] Open Public Bucket Directory Listing on cdn.byspotify.com

**Program:** Spotify (Hackerone)  
**Program Policy:** [https://hackerone.com/spotify](https://hackerone.com/spotify)  
**Asset (In-Scope Target):** `cdn.byspotify.com`  
**Weakness:** `CWE-284: Improper Access Control`  
**Severity:** `HIGH` (CVSS 3.1: **7.5**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**Bounty Viability Grade:** `HIGH_CONFIDENCE`  
**Date Discovered:** 2026-10-29T11:07:13.912334+00:00  

---

## 1. Summary
> [!TIP] **High-Value Bounty Finding**
> High-confidence security finding verified on target infrastructure with direct impact on origin integrity or confidentiality.

During an external attack surface and DNS perimeter hygiene assessment under the **Spotify** Responsible Disclosure Program, Orbit Security identified a security weakness on `cdn.byspotify.com`.

- **Vulnerability Category:** `Open Cloud Bucket`
- **Affected Provider/Service:** `Cloud Storage`
- **Observed Evidence:** Public cloud storage bucket listing is exposed on 'cdn.byspotify.com'. Signature match: '<ListBucketResult'.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Issue an HTTP GET request to the bucket endpoint on `cdn.byspotify.com`:
   ```bash
   curl -i -s https://cdn.byspotify.com
   ```
2. Observe the XML storage index containing key names, sizes, and file metadata (`<ListBucketResult>` or `<EnumerationResults>`).
3. Observe evidence: `Public cloud storage bucket listing is exposed on 'cdn.byspotify.com'. Signature match: '<ListBucketResult'.`

---

## 3. Impact
The cloud storage bucket mapped to `cdn.byspotify.com` has open public READ permissions enabled.
Any unauthorized internet user can list and download stored assets, potentially exposing private customer documents, source backups, configuration archives, and sensitive media.

---

## 4. Remediation & Recommended Solution
Disable public READ permissions on the cloud storage bucket and remove 'AllUsers' / 'AllAuthenticatedUsers' ACL grants.

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Spotify** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.
