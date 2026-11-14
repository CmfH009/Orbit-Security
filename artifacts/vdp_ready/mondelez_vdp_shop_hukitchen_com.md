# VDP Submission Draft: Dangling DNS CNAME to Unattached Unbounce Endpoint on `shop.hukitchen.com`

- **Target Program:** Mondelēz International VDP (`https://hackerone.com/mondelez`)
- **Disclosure Channel:** HackerOne VDP (**STAGED ONLY — DO NOT AUTO-SUBMIT**)
- **Affected Asset:** `shop.hukitchen.com` (Hu Kitchen — Mondelēz International subsidiary)
- **CNAME Target:** `5c35d9eda65344a590aea0ebb93fb0b6.unbouncepages.com.`
- **Weakness:** CWE-350 / Dangling DNS CNAME to Unattached SaaS Landing Page Host (Unbounce)
- **Live Verification Timestamp (UTC):** `2026-11-14T20:09:06.930204+00:00`
- **Evidence SHA-256:** `4d639214ddc495a87d37b7e316fd30be0e526924e77e2ddd03014e0837f3af13`

---

> [!IMPORTANT]
> **Required Mondelēz Program Compliance Metadata:**
> Any active verification HTTP traffic sent to Mondelēz-owned targets during reproduction MUST include your HackerOne identification header:
> `X-Mondelez-VDP: HackerOne-<username>`
> Replace `<username>` with your actual HackerOne handle before running any manual verification commands or pasting into HackerOne.

> [!WARNING]
> **Critic & HackerOne Signal-Protection Advisory (Read Before Submitting):**
> Passive DNS and HTTP checks confirm `shop.hukitchen.com` points to `5c35d9eda65344a590aea0ebb93fb0b6.unbouncepages.com.` and returns `HTTP 404 Not Found` (`The requested URL was not found on this server.`). Note two risks before submitting to HackerOne:
> 1. Confirm `shop.hukitchen.com` / `hukitchen.com` is covered under Mondelēz VDP scope and check whether Unbounce's account-specific subdomain hash (`5c35d9ed...`) restricts claiming `shop.hukitchen.com` from an unrelated Unbounce tenant.
> 2. If third-party registration is blocked by Unbounce's custom-domain binding check, HackerOne triagers may classify an unverified dangling CNAME as *Informative*, which affects HackerOne Signal.

---

## Summary

The subdomain `shop.hukitchen.com` resolves via an active DNS `CNAME` record (`TTL 3600`) to an Unbounce SaaS landing-page endpoint (`5c35d9eda65344a590aea0ebb93fb0b6.unbouncepages.com.`), resolving to edge IPs `104.18.34.21` and `172.64.153.235`. Both `http://shop.hukitchen.com/` and `https://shop.hukitchen.com/` return `HTTP/1.1 404 Not Found` with the plain-text response body `The requested URL was not found on this server.`, matching the signature of an unattached or deprovisioned Unbounce custom domain.

Per VDP safe-harbor rules, **no attempt was made to claim `shop.hukitchen.com` inside Unbounce**, alter DNS/content, or perform intrusive scanning.

---

## Non-Destructive Proof of Concept & Reproduction Steps

### 1. Passive DNS Resolution (`CNAME` + `A` Chain)

```bash
dig +short CNAME shop.hukitchen.com
dig A shop.hukitchen.com
```

**Verified DNS Response (Cloudflare DoH `2026-11-14T20:09:06Z`):**
- `shop.hukitchen.com. 3600 IN CNAME 5c35d9eda65344a590aea0ebb93fb0b6.unbouncepages.com.` (`RCODE: 0 / NOERROR`)
- `5c35d9eda65344a590aea0ebb93fb0b6.unbouncepages.com. 300 IN A 104.18.34.21`
- `5c35d9eda65344a590aea0ebb93fb0b6.unbouncepages.com. 300 IN A 172.64.153.235`

### 2. Passive HTTP / HTTPS Signature Verification (With Required Compliance Header)

```bash
curl -i -H "X-Mondelez-VDP: HackerOne-<username>" http://shop.hukitchen.com/
curl -i -H "X-Mondelez-VDP: HackerOne-<username>" https://shop.hukitchen.com/
```

**Observed HTTP Response (`http://shop.hukitchen.com/` at `Sat, 14 Nov 2026 20:09:10 GMT`):**
```http
HTTP/1.1 404 Not Found
Date: Sat, 14 Nov 2026 20:09:10 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 47
Connection: close
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'
Referrer-Policy: no-referrer
cf-cache-status: DYNAMIC
Server: cloudflare
CF-RAY: a5a8a702cb65e661-DEN

The requested URL was not found on this server.
```

**Observed HTTPS Response (`https://shop.hukitchen.com/` at `Sat, 14 Nov 2026 20:09:11 GMT`):**
```http
HTTP/1.1 404 Not Found
Date: Sat, 14 Nov 2026 20:09:11 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 47
CF-RAY: a5a8a7043f18638c-DEN

The requested URL was not found on this server.
```

---

## Impact Assessment

- **Brand Trust & Deprovisioned SaaS Exposure:** Leaving a `shop.*` commercial subdomain mapped to an inactive/unattached landing-page endpoint (`*.unbouncepages.com`) creates ongoing subdomain takeover exposure if the Unbounce customer workspace `5c35d9eda65344a590aea0ebb93fb0b6` is deleted, or if cross-tenant domain binding in Unbounce is permitted when that hostname is unclaimed.
- **Potential Downstream Risk:** Should an attacker claim `shop.hukitchen.com` on the SaaS provider, they could serve deceptive e-commerce/checkout pages under a legitimate `hukitchen.com` subdomain and potentially harvest credentials or payment details via phishing.

---

## Recommended Remediation

1. **Remove Dangling CNAME (Preferred if Unused):** Delete `shop.hukitchen.com CNAME 5c35d9eda65344a590aea0ebb93fb0b6.unbouncepages.com.` from authoritative DNS if the landing page campaign has ended.
2. **Re-Bind or Redirect Explicitly:** If `shop.hukitchen.com` is intentionally reserved, point it to a Mondelēz-controlled reverse proxy/CDN (`301`/`302` redirect to the active store) rather than an unattached third-party SaaS edge.
