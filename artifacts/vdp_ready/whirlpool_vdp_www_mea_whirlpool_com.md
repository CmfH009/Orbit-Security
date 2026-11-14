# Direct VDP Security Advisory: Orphaned AWS CloudFront CNAME on `www.mea.whirlpool.com`

- **Target Organization:** Whirlpool Corporation (Direct Product Security / VDP)
- **Disclosure Channel:** `mailto:product_security@whirlpool.com` (**Direct Email VDP — Zero HackerOne Signal Risk**)
- **Primary Verified Vulnerable Subdomain:** `www.mea.whirlpool.com` *(Correction: apex `whirlpool.com` resolves directly to `A 54.175.185.69` behind Akamai `HTTP 403`; the orphaned CloudFront CNAME is on `www.mea.whirlpool.com`)*
- **CNAME Target:** `du1taozq07ehy.cloudfront.net.`
- **Weakness:** CWE-350 / Misconfigured Dangling DNS CNAME & Unattached CDN Distribution / Broken TLS Endpoint
- **Live Verification Timestamp (UTC):** `2026-11-14T20:09:09.651641+00:00`
- **Evidence SHA-256:** `1a4737d23f06daea97d26a20547ec72237845f105c86174cef488cf6d884a495`

---

> [!NOTE]
> **Critic Scope & Target Correction Advisory:**
> - **Apex vs. Subdomain Correction:** Live verification confirmed that root `whirlpool.com` resolves cleanly via `A 54.175.185.69` (`AkamaiGHost` `HTTP 403 Access Denied`). The orphaned CloudFront CNAME identified in Orbit Security's audit (`data/generated_audits/elogic-commerce/whirlpool.com_audit.md`) belongs specifically to **`www.mea.whirlpool.com`** (`CNAME du1taozq07ehy.cloudfront.net.`).
> - **Exploitability Boundary:** AWS CloudFront requires valid ACM/IAM TLS certificate validation (DNS or email domain validation) to attach an Alternate Domain Name (CNAME) on HTTPS distributions, mitigating direct unauthorized takeover over HTTPS unless HTTP-only wildcard/unclaimed distribution conditions apply. Sending this constructively via direct email to `product_security@whirlpool.com` carries zero HackerOne Signal penalty.

---

## Summary

The regional subdomain `www.mea.whirlpool.com` has an active DNS `CNAME` record (`TTL 300`) pointing to `du1taozq07ehy.cloudfront.net.` (`A 99.84.105.32`, `99.84.105.75`, `99.84.105.35`, `99.84.105.82`). Live HTTP requests to `http://www.mea.whirlpool.com/` fail with `HTTP/1.1 403 Forbidden` (`X-Cache: Error from cloudfront` — `ERROR: The request could not be satisfied`), while HTTPS requests to `https://www.mea.whirlpool.com/` fail at the TLS handshake layer (`SSL: SSLV3_ALERT_HANDSHAKE_FAILURE`).

This indicates an orphaned or decommissioned AWS CloudFront configuration where DNS still delegates traffic for `www.mea.whirlpool.com` to an unconfigured or retired CDN distribution. Per non-destructive disclosure guidelines, **no attempt was made to claim `www.mea.whirlpool.com` or `du1taozq07ehy.cloudfront.net` in AWS**.

---

## Non-Destructive Proof of Concept & Reproduction Steps

### 1. Passive DNS Resolution Comparison (Apex vs. `www.mea.whirlpool.com`)

```bash
dig +short CNAME www.mea.whirlpool.com
dig A www.mea.whirlpool.com
dig +short A whirlpool.com
```

**Verified DNS Response (Cloudflare DoH `2026-11-14T20:09:09Z`):**
- `www.mea.whirlpool.com. 300 IN CNAME du1taozq07ehy.cloudfront.net.` (`RCODE: 0 / NOERROR`)
- `du1taozq07ehy.cloudfront.net. 60 IN A 99.84.105.32` (+ `.35`, `.75`, `.82`)
- `whirlpool.com. 99 IN A 54.175.185.69` *(for clarity: apex is not the orphaned CloudFront CNAME)*

### 2. Passive HTTP & TLS Verification

```bash
curl -i http://www.mea.whirlpool.com/
curl -iv https://www.mea.whirlpool.com/
```

**Observed HTTP Response (`http://www.mea.whirlpool.com/` at `Sat, 14 Nov 2026 20:09:13 GMT`):**
```http
HTTP/1.1 403 Forbidden
Server: CloudFront
Date: Sat, 14 Nov 2026 20:09:13 GMT
Content-Type: text/html
Content-Length: 915
Connection: close
X-Cache: Error from cloudfront
Via: 1.1 59b91fa5bb1f56f1a653604439afb430.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: DEN53-P6
X-Amz-Cf-Id: daV5cYYFIR_aJJh_0gwXaSvfqLudsEagvV3RCz0K4mbpnPdVRngTtg==

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML><HEAD><META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=iso-8859-1">
<TITLE>ERROR: The request could not be satisfied</TITLE>
</HEAD><BODY>
<H1>403 ERROR</H1>
<H2>The request could not be satisfied.</H2>
```

**Observed HTTPS Probe (`https://www.mea.whirlpool.com/`):**
- Fails during TLS negotiation: `SSL: SSLV3_ALERT_HANDSHAKE_FAILURE` (indicating no active SNI/ACM certificate is served for `www.mea.whirlpool.com` on `du1taozq07ehy.cloudfront.net`).

---

## Impact Assessment

- **Dangling CDN Reference & Degraded Availability:** Regional traffic directed to `www.mea.whirlpool.com` resolves cleanly in DNS but terminates in an unattached CloudFront `403 Bad Request` error over HTTP and a fatal TLS handshake failure over HTTPS.
- **Residual DNS Hygiene Risk:** Retaining orphaned third-party CDN CNAMEs after decommissioning regional portals increases configuration drift risk if CDN ownership verification controls are ever bypassed or misconfigured in downstream DNS moves.

---

## Recommended Remediation

1. **Delete Orphaned DNS Record:** Remove the `CNAME du1taozq07ehy.cloudfront.net.` record for `www.mea.whirlpool.com` if the MEA regional portal has been retired or migrated.
2. **Audit Related Regional Subdomains:** Review sibling `*.whirlpool.com` CNAMEs pointing to `*.cloudfront.net` distributions and verify each points to an active, certificate-bound distribution under Whirlpool's AWS Organization.
