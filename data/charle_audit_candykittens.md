# 🛡️ Client Security & Domain Health Audit
**Audited Target:** `candykittens.co.uk`  
**Prepared By:** Charle Agency (Managed Web & Security Operations)  
**Audit Date:** 2026-10-03 16:15:03 UTC  
**Executive Grade:** **C** (Score: 65/100)

---

## 1. Executive Summary
This perimeter hygiene audit analyzed domain records, transport security, email authentication, and publicly exposed server paths for **candykittens.co.uk**.

- **Security Score:** `65 / 100`
- **Overall Assessment:** `C`
- **Total Findings:** `10`
- **Subdomains Probed:** `9`

---

## 2. Findings & Recommended Actions

### 1. DMARC Policy in Inactive Monitoring Mode (p=none) (🟡 **MEDIUM**)
- **Category:** Email Authentication
- **Target / Endpoint:** `_dmarc.candykittens.co.uk`
- **Risk Description:** The DMARC policy is set to `p=none`. Spoofed emails from attackers are still delivered to recipient inboxes without rejection or quarantine.
- **Evidence Detected:** `v=DMARC1; p=none; rua=mailto:dmarc@candykittens.co.uk; ruf=mailto:dmarc@candykittens.co.uk; sp=none; pct=100`
- **Recommended Remediation:** Upgrade policy from `p=none` to `p=quarantine` or `p=reject` after reviewing authentication reports.

### 2. Missing BIMI Brand Indicator (RFC 8617) (🔵 **LOW**)
- **Category:** Email Authentication
- **Target / Endpoint:** `default._bimi.candykittens.co.uk`
- **Risk Description:** No BIMI record discovered at `default._bimi.candykittens.co.uk`. Implementing BIMI authenticates brand logos in supporting inboxes (Gmail, Apple Mail, Yahoo) and prevents visual brand spoofing.
- **Evidence Detected:** `No BIMI TXT record located.`
- **Recommended Remediation:** Configure a DNS TXT record at `default._bimi.candykittens.co.uk` with `v=BIMI1; l=https://candykittens.co.uk/logo.svg;`.

### 3. Missing MTA-STS Transport Security (RFC 8461) (🔵 **LOW**)
- **Category:** Email Authentication
- **Target / Endpoint:** `_mta-sts.candykittens.co.uk`
- **Risk Description:** Domain candykittens.co.uk has no MTA-STS DNS record. Inbound emails remain vulnerable to SMTP TLS downgrade attacks and eavesdropping.
- **Evidence Detected:** `No MTA-STS record located.`
- **Recommended Remediation:** Publish `_mta-sts.candykittens.co.uk` TXT record and establish mta-sts.txt policy endpoint.

### 4. Missing SMTP TLS Reporting (TLS-RPT RFC 8460) (⚪ **INFO**)
- **Category:** Email Authentication
- **Target / Endpoint:** `_smtp._tls.candykittens.co.uk`
- **Risk Description:** No TLS-RPT record found for candykittens.co.uk. Diagnostic telemetry on MTA transport security is unavailable.
- **Evidence Detected:** `No TLS-RPT record located.`
- **Recommended Remediation:** Publish `_smtp._tls.candykittens.co.uk` TXT record with `v=TLSRPTv1; rua=mailto:...`.

### 5. Missing DNS CAA Policy (RFC 8659) (🔵 **LOW**)
- **Category:** Transport Security
- **Target / Endpoint:** `candykittens.co.uk`
- **Risk Description:** Domain candykittens.co.uk has no DNS CAA policy configured. Any globally trusted CA can issue certificates for this domain without restriction.
- **Evidence Detected:** `No CAA records found in DNS zone (The DNS response does not contain an answer to the question: candykittens.co.uk. IN CAA).`
- **Recommended Remediation:** Publish a DNS CAA record for `candykittens.co.uk` restricting issuance to approved Certificate Authorities.

### 6. HSTS Header Incomplete (Subdomains or Preload) (⚪ **INFO**)
- **Category:** Transport Security
- **Target / Endpoint:** `https://candykittens.co.uk`
- **Risk Description:** HSTS header is active but does not declare `includeSubDomains` or `preload`. Subdomains may remain susceptible to SSL stripping.
- **Evidence Detected:** `Current HSTS: max-age=7889238`
- **Recommended Remediation:** Strengthen HSTS header to `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.

### 7. Missing Referrer-Policy Header (🔵 **LOW**)
- **Category:** Application Security
- **Target / Endpoint:** `https://candykittens.co.uk`
- **Risk Description:** No Referrer-Policy header is defined. Browsers may leak confidential URLs and query parameters in the Referer header to external destinations.
- **Evidence Detected:** `Header 'Referrer-Policy' not present.`
- **Recommended Remediation:** Set `Referrer-Policy: strict-origin-when-cross-origin`.

### 8. Missing Permissions-Policy Header (⚪ **INFO**)
- **Category:** Application Security
- **Target / Endpoint:** `https://candykittens.co.uk`
- **Risk Description:** Permissions-Policy is missing. Modern web applications should explicitly restrict unnecessary browser features (camera, microphone, geolocation, payment).
- **Evidence Detected:** `Header 'Permissions-Policy' not present.`
- **Recommended Remediation:** Configure `Permissions-Policy: camera=(), microphone=(), geolocation=()`.

### 9. Missing Cross-Origin-Opener-Policy (COOP) (⚪ **INFO**)
- **Category:** Application Security
- **Target / Endpoint:** `https://candykittens.co.uk`
- **Risk Description:** COOP header is not set. Isolating top-level browsing contexts prevents cross-origin Spectre and XS-Leak interactions.
- **Evidence Detected:** `Header 'Cross-Origin-Opener-Policy' not present.`
- **Recommended Remediation:** Configure `Cross-Origin-Opener-Policy: same-origin` or `same-origin-allow-popups`.

### 10. Missing RFC 9116 Security Disclosure (security.txt) (🔵 **LOW**)
- **Category:** Application Security
- **Target / Endpoint:** `https://candykittens.co.uk/.well-known/security.txt`
- **Risk Description:** Domain candykittens.co.uk does not publish a standardized vulnerability disclosure policy at `/.well-known/security.txt` per IETF RFC 9116. Ethical security researchers and bug bounty reporters lack a designated, confidential channel to report zero-day vulnerabilities.
- **Evidence Detected:** `No valid security.txt discovered with Contact: directive.`
- **Recommended Remediation:** Deploy a `security.txt` file at `https://candykittens.co.uk/.well-known/security.txt` declaring `Contact: mailto:security@candykittens.co.uk` and a valid `Expires:` date.

---

## 3. Retainer & Infrastructure Care Plan Recommendations
As part of your managed web operations with **Charle Agency**, we recommend the following ongoing safeguards:
- **Continuous Subdomain Sentinel:** Automated monitoring against dangling DNS takeovers as SaaS trials (Unbounce, Webflow, Shopify, Azure) expire.
- **Google & Yahoo Bulk Sender Protection:** Active enforcement of DMARC (`p=quarantine`/`p=reject`), SPF, and MTA-STS TLS encryption to preserve 100% primary inbox deliverability.
- **BIMI Verified Brand Logo:** Publishing BIMI (RFC 8617) to display authenticated client logos in Gmail and Apple Mail.
- **Zero-Exposure Secret Hygiene:** Automated surveillance preventing accidental public exposure of `.env`, `.git`, or database backups.

---

### Managed Service Contact
For automated remediation or questions regarding this audit, please contact **Charle Agency** at [hello@charleagency.com](mailto:hello@charleagency.com) or visit [https://charleagency.com](https://charleagency.com).