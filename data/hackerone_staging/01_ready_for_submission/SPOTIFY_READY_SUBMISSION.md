# HackerOne Submission Ready Dossier: Spotify

**Program:** Spotify  
**Program URL:** https://hackerone.com/spotify  
**Asset:** `cdn.byspotify.com` (In Scope via `*.byspotify.com`)  
**Vulnerability Type:** Information Disclosure / Sensitive Data Exposure  
**Weakness:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor  
**Severity:** Medium (CVSS 3.1: **5.3** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)  

---

### Title:
`[Information Disclosure] Open Public Storage Bucket Directory Listing Leaking Internal Acquisition Pitch Decks and Client Reports on cdn.byspotify.com`

---

### Summary:
During a security posture assessment of in-scope perimeter assets under Spotify's Vulnerability Disclosure Program, an open public Google Cloud Storage / S3 directory listing was identified on `cdn.byspotify.com`.

The storage bucket permits public `ListBucket` / directory enumeration requests (`GET /`). An unauthorized internet actor can enumerate and directly download all stored assets. Among the listed files are non-public business documents from Spotify's acquired Podsights entity, including:
1. Internal seed / investor pitch decks: `interviews/Podsights Seed - Interview Version.pdf` (2.1 MB)
2. Partner & client advertising meeting disclosures: `interviews/AP Q4-2020 Podcast Adv. Rept_4Ww1Disc.Mtg.pdf` (5.3 MB)
3. Internal conversion reports and historical benchmarks: `reports/benchmarks/test-q3-podsights-conversion-report.pdf`
4. Internal onboarding & demo recordings: `advisor/advisor-onboarding-demo.mp4` (18.1 MB)

---

### Steps to Reproduce (Proof of Concept):

1. Issue an HTTP GET request to the root endpoint of `cdn.byspotify.com`:
   ```bash
   curl -i -s https://cdn.byspotify.com/
   ```
2. Observe the HTTP 200 OK response containing the full XML directory index (`<ListBucketResult>`) enumerating object keys, file sizes, and modification timestamps.

3. Download one of the exposed internal meeting/pitch documents to confirm public read access:
   ```bash
   curl -i -s https://cdn.byspotify.com/interviews/Podsights%20Seed%20-%20Interview%20Version.pdf -o podsights_seed.pdf
   ```
4. Observe the HTTP 200 OK status code confirming that the file is served without authentication (`Content-Length: 2153328` bytes).

---

### Impact:
Public bucket directory listing allows unauthenticated external parties to index and exfiltrate internal business intelligence, historical partner advertising reports, proprietary pitch presentations, and internal demo material. While the CDN is intended for static delivery, granting public object enumeration exposes private operational archives that should not be visible to external search engines or threat actors.

---

### Remediation:
1. Disable public `s3:ListBucket` (AWS S3) or `storage.objects.list` (Google Cloud Storage) permissions for `allUsers` and `allAuthenticatedUsers`.
2. Ensure public access is restricted strictly to designated static asset keys (e.g. `ping.js`, public logo assets) rather than granting blanket bucket-wide enumeration.
3. Move sensitive historical archives (internal PDFs, advisor onboarding videos) to a segregated, private, authenticated storage bucket.
