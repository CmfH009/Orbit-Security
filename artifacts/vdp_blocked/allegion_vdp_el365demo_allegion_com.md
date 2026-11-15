# VDP Submission Dossier: Dangling DNS CNAME to Unattached Microsoft Azure Endpoint on el365demo.allegion.com

- **Target Program:** Allegion (`https://hackerone.com/allegion`)
- **Disclosure Channel:** HackerOne VDP API
- **Researcher:** Carson Haynes (`@arsoncarson`) | Orbit Security
- **Affected Asset:** `el365demo.allegion.com` (Structured Scope ID: `88832`)
- **CNAME Target:** `elalle365demo.centralus.cloudapp.azure.com`
- **Resolved A Records:** `None`
- **Severity:** `medium`
- **Weakness ID:** `130`
- **Captured UTC:** `2026-11-15T02:59:46.358704+00:00`
- **User-Agent:** `OrbitSecurity-VDP/1.0 (HackerOne:@arsoncarson)`

## Summary

Non-destructive reconnaissance against in-scope asset `el365demo.allegion.com` identified `dangling_cname` (NXDOMAIN (Dangling Service Endpoint)). Only passive DNS queries and single bounded HTTP GET requests were performed; no service claiming, modification, or bulk data retrieval occurred.

## Steps to Reproduce

```bash
dig +short CNAME el365demo.allegion.com
dig A elalle365demo.centralus.cloudapp.azure.com
```

## Observed Evidence

- **DNS Status:** `NXDOMAIN (Status: 3)` on `elalle365demo.centralus.cloudapp.azure.com`
- **Matched Signature / Output:**
```text
NXDOMAIN (Dangling Service Endpoint)
```

## Suggested Remediation

Ensure custom domain is attached to an active Azure App Service / Traffic Manager or remove the DNS record.
