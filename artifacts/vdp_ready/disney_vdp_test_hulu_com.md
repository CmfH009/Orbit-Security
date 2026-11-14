# VDP Submission Draft: Dangling DNS CNAME to Unattached Fastly Endpoint on `test.hulu.com`

- **Target Program:** The Walt Disney Company VDP (`https://hackerone.com/disney`)
- **Disclosure Channel:** HackerOne VDP (`https://api.hackerone.com/v1/hackers/reports`)
- **Researcher:** Carson Haynes (`@arsoncarson`) | Founder, Orbit Security (`carsonmail009@gmail.com`)
- **Affected Asset:** `test.hulu.com`
- **CNAME Target:** `web.hulu.map.fastly.net.`
- **Weakness:** CWE-350 / Misconfigured Dangling DNS CNAME (Potential Subdomain Takeover Risk Exposure)
- **Proposed CVSSv3 Vector & Score:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` (`7.5` High)
- **Researcher Source IP:** `174.201.31.8`
- **Program Tracking Header:** `X-TWDC-VDP: HackerOne-arsoncarson`
- **Testing Client:** `Python requests / Cloudflare DoH, Windows 11 x64`
- **Live Verification Timestamp (UTC):** `2026-11-14T23:08:22+00:00`
- **Initial Evidence SHA-256:** `92679d6fdf4c1fe1799cf3dba5e407b12643374a9777a92150de3f6920077536`

---

## Summary

The subdomain `test.hulu.com` maintains an active DNS `CNAME` record pointing to `web.hulu.map.fastly.net.` (`TTL 300`), resolving to Fastly edge IP addresses (`151.101.2.252`, `151.101.66.252`, `151.101.130.252`, `151.101.194.252`). When queried over HTTP or HTTPS, Fastly responds with `HTTP/1.1 500 Domain Not Found` and the body `Fastly error: unknown domain: test.hulu.com. Please check that this domain has been added to a service.`

Per responsible disclosure boundaries, **no attempt was made to register, claim, or attach `test.hulu.com` to any Fastly service**, nor to modify or probe internal infrastructure beyond passive DNS resolution and single HTTP/HTTPS GET requests.

---

## Non-Destructive Proof of Concept & Reproduction Steps

### 1. Passive DNS Resolution (`CNAME` + `A` Chain)

```bash
dig +short CNAME test.hulu.com
dig A test.hulu.com
```

**Verified DNS Response (Cloudflare DoH `2026-11-14T20:09:06Z`):**
- `test.hulu.com. 300 IN CNAME web.hulu.map.fastly.net.` (`RCODE: 0 / NOERROR`)
- `web.hulu.map.fastly.net. 300 IN A 151.101.2.252`
- `web.hulu.map.fastly.net. 300 IN A 151.101.66.252`
- `web.hulu.map.fastly.net. 300 IN A 151.101.130.252`
- `web.hulu.map.fastly.net. 300 IN A 151.101.194.252`

### 2. Passive HTTP / HTTPS Signature Verification

```bash
curl -i -H "X-TWDC-VDP: HackerOne-arsoncarson" http://test.hulu.com/
curl -i -H "X-TWDC-VDP: HackerOne-arsoncarson" https://test.hulu.com/
```

**Observed Tagged HTTP Responses (`2026-11-14T23:08:22Z` from IP `174.201.31.8`):**
- `http://test.hulu.com/`: `HTTP/1.1 500 Domain Not Found` (`X-Served-By: cache-den-kden1300075-DEN`) — `Fastly error: unknown domain: test.hulu.com`
- `https://test.hulu.com/`: `HTTP/1.1 500 Domain Not Found` (`X-Served-By: cache-den-kden1300061-DEN`) — `Fastly error: unknown domain: test.hulu.com`

**Initial Passive Capture (`http://test.hulu.com/` at `Sat, 14 Nov 2026 20:09:09 GMT`):**
```http
HTTP/1.1 500 Domain Not Found
Connection: close
Content-Length: 270
Server: Varnish
Retry-After: 0
content-type: text/html
Cache-Control: private, no-cache
X-Served-By: cache-den-kden1300024-DEN
Accept-Ranges: bytes
Date: Sat, 14 Nov 2026 20:09:09 GMT
Via: 1.1 varnish

<html>
<head>
<title>Fastly error: unknown domain test.hulu.com</title>
</head>
<body>
<p>Fastly error: unknown domain: test.hulu.com. Please check that this domain has been added to a service.</p>
<p>Details: cache-den-kden1300024-DEN (151.101.2.252)</p></body></html>
```

**Observed HTTPS Response (`https://test.hulu.com/` at `Sat, 14 Nov 2026 20:09:09 GMT`):**
- Returns identical `HTTP/1.1 500 Domain Not Found` (`X-Served-By: cache-den-kden1300058-DEN`) with `Fastly error: unknown domain: test.hulu.com`.

---

## Impact Assessment

- **Dangling Infrastructure Hygiene Risk:** An active external DNS alias under a high-trust entertainment brand (`test.hulu.com`) points to a deprovisioned or unattached CDN service mapping on Fastly.
- **Conditional Takeover / Phishing Risk (Vendor-Dependent):** If Fastly account-level domain ownership verification is disabled, misconfigured, or bypassed on shared edge maps, an attacker able to attach `test.hulu.com` to a Fastly service could serve arbitrary HTML/JS on `test.hulu.com`, capture scoped cookies (`Domain=.hulu.com` if any), or abuse brand trust for phishing. Because non-destructive testing stopped at read-only fingerprinting, claimability is unexploited and reported as dangling DNS hygiene.

---

## Recommended Remediation

1. **Remove the Stale DNS Record:** If `test.hulu.com` is retired or no longer used, delete the `CNAME web.hulu.map.fastly.net.` record from authoritative DNS immediately.
2. **Re-Attach Domain & Enforce Ownership Controls:** If `test.hulu.com` is still intended for use, add it back to the authorized Disney/Hulu Fastly service and confirm Fastly domain-ownership/TLS pinning prevents cross-account registration.
