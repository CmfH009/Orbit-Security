# VDP Submission Dossier: Dangling DNS CNAME to Unattached Unbounce Endpoint on `try.yesware.com`

- **Target Program:** Vendasta VDP (`https://hackerone.com/vendasta`)
- **Disclosure Channel:** HackerOne VDP (`https://api.hackerone.com/v1/hackers/reports`)
- **Researcher:** Carson Haynes (`@arsoncarson`) | Founder, Orbit Security (`carsonmail009@gmail.com`)
- **Affected Asset:** `try.yesware.com` (Yesware — Vendasta subsidiary; Structured Scope ID `319888` `*.yesware.com`, `eligible_for_submission: true`)
- **CNAME Target:** `407cc70cc1f5474cb1ae28d67a395920.unbouncepages.com.`
- **Weakness:** `CWE-284` (`weakness_id: 26` — Improper Access Control - Generic; also mapped to `CWE-350` Reliance on Reverse DNS / Dangling DNS CNAME and `CWE-610` Externally Controlled Reference to a Resource in Another Sphere)
- **Severity Rating:** `high` (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N`, `7.5` High)
- **Program Compliance User-Agent:** `HackerOne-arsoncarson`
- **Live Verification Timestamp (UTC):** `2026-11-15T01:02:04.613220+00:00`
- **Response Body SHA-256:** `cd8b79123a843eee64985a23257e2fab80ef2c4c08427b688ea979671fc1c457`

---

> [!IMPORTANT]
> **Vendasta VDP Program Compliance:**
> All HTTP verification probes sent to `try.yesware.com` included `User-Agent: HackerOne-arsoncarson` in compliance with Vendasta's HackerOne program rules.
> Per Structured Scope `319888` (`*.yesware.com`), `www.yesware.com` (WordPress) and `help.yesware.com` (Zendesk) are excluded, and `t.yesware.com` (`741204`) is out of scope. `try.yesware.com` falls directly within in-scope wildcard `*.yesware.com`.

---

## Summary

The subdomain `try.yesware.com` resolves via an active DNS `CNAME` record (`TTL 300`) to an Unbounce SaaS landing-page endpoint (`407cc70cc1f5474cb1ae28d67a395920.unbouncepages.com.`), resolving to edge IPs `172.64.153.235` and `104.18.34.21`. Both `http://try.yesware.com/` and `https://try.yesware.com/` return `HTTP/1.1 404 Not Found` (`Server: cloudflare`) with the 47-byte plain-text body `The requested URL was not found on this server.`, matching the signature of an unattached or deprovisioned Unbounce custom domain.

Per safe-harbor rules, **no attempt was made to register or claim `try.yesware.com` inside Unbounce**, alter DNS/content, or perform intrusive scanning.

---

## Non-Destructive Proof of Concept & Reproduction Steps

### 1. Passive DNS Resolution (`CNAME` + `A` Chain)

```bash
dig +short CNAME try.yesware.com
dig A try.yesware.com
```

**Verified DNS Response (Cloudflare DoH `2026-11-15T01:02:04Z`):**
- `try.yesware.com. 300 IN CNAME 407cc70cc1f5474cb1ae28d67a395920.unbouncepages.com.`
- `407cc70cc1f5474cb1ae28d67a395920.unbouncepages.com. 300 IN A 172.64.153.235`
- `407cc70cc1f5474cb1ae28d67a395920.unbouncepages.com. 300 IN A 104.18.34.21`

### 2. Passive HTTP / HTTPS Signature Verification (With Compliance User-Agent)

```bash
curl -i -s -H "User-Agent: HackerOne-arsoncarson" http://try.yesware.com/
curl -i -s -H "User-Agent: HackerOne-arsoncarson" https://try.yesware.com/
```

**Observed HTTP Response (`http://try.yesware.com/` at `Sun, 15 Nov 2026 01:02:09 GMT`):**
```http
HTTP/1.1 404 Not Found
Date: Sun, 15 Nov 2026 01:02:09 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 47
Connection: close
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'
Referrer-Policy: no-referrer
cf-cache-status: DYNAMIC
Speculation-Rules: "/cdn-cgi/speculation"
Server: cloudflare
CF-RAY: a5aa542e59c6db4b-DEN
alt-svc: h3=":443"; ma=86400

The requested URL was not found on this server.
```

**Observed HTTPS Response (`https://try.yesware.com/` at `Sun, 15 Nov 2026 01:02:09 GMT`):**
```http
HTTP/1.1 404 Not Found
Date: Sun, 15 Nov 2026 01:02:09 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 47
Connection: close
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'
Referrer-Policy: no-referrer
cf-cache-status: DYNAMIC
Speculation-Rules: "/cdn-cgi/speculation"
Server: cloudflare
CF-RAY: a5aa542fcff659d4-DEN
alt-svc: h3=":443"; ma=86400

The requested URL was not found on this server.
```

---

## Impact

An external actor can create an Unbounce account and register `try.yesware.com` as a custom domain without performing DNS ownership verification beyond the already-published `CNAME` to `407cc70cc1f5474cb1ae28d67a395920.unbouncepages.com.`. Once claimed, the actor gains full control over HTTPS-served content on `https://try.yesware.com/`, enabling:
- **Credential Harvesting & Phishing:** Hosting spoofed Yesware trial/login pages on a trusted `*.yesware.com` domain (`try.yesware.com`), including OAuth/Google/Microsoft sign-in phishing flows targeting prospective Yesware customers.
- **Session & Cookie Scope Exposure:** Potential access to or manipulation of parent-domain cookies scoped to `.yesware.com` and cross-origin trust assumptions across `*.yesware.com`.
- **Brand & Reputation Damage:** Serving arbitrary malicious HTML, scripts, or malware downloads over valid TLS under Yesware's official domain.

---

## Recommended Remediation

1. **Remove the Dangling CNAME (Preferred if Unused):** Delete `try.yesware.com CNAME 407cc70cc1f5474cb1ae28d67a395920.unbouncepages.com.` from authoritative `yesware.com` DNS if this Unbounce landing page campaign has been retired.
2. **Re-Bind or Redirect Explicitly:** If `try.yesware.com` is still intended to resolve, either re-attach the custom domain inside Vendasta/Yesware's active Unbounce workspace or point it to an internally controlled reverse proxy/CDN (`301`/`302` redirect to `https://www.yesware.com/`).
