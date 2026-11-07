# Security Policy

## Supported Versions

Orbit Security actively maintains and publishes security updates for the latest `main` branch and `1.1.x` release line:

| Version | Supported |
|---|---|
| `1.1.x` (`main`) | :white_check_mark: Yes |
| `< 1.1.0` | :x: No |

---

## Reporting a Vulnerability

We welcome coordinated vulnerability reports from security researchers and developers.

- **Primary Security Contact:** [`carsonmail009@gmail.com`](mailto:carsonmail009@gmail.com)
- **GitHub Private Vulnerability Reporting:** [Report a vulnerability privately on GitHub](https://github.com/CmfH009/Orbit-Security/security/advisories/new)
- **Canonical `security.txt` (RFC 9116):** [`https://cmfh009.github.io/Orbit-Security/.well-known/security.txt`](https://cmfh009.github.io/Orbit-Security/.well-known/security.txt)
- **Full Legal & Safe Harbor Policy:** [`https://cmfh009.github.io/Orbit-Security/disclaimer.html`](https://cmfh009.github.io/Orbit-Security/disclaimer.html)
- **Preferred Languages:** `en`

Please include:
1. The affected file path, module, or public URL (`https://cmfh009.github.io/Orbit-Security/`).
2. Minimal, non-destructive steps to reproduce the issue.
3. Expected vs. observed behavior and estimated security impact (CWE / CVSS v3.1 if applicable).

---

## Coordinated Disclosure & Safe Harbor

- **Response SLA:** Initial acknowledgment within **48 hours**; triage and remediation plan within **7 days**.
- **Disclosure Window:** We observe a standard **90-day coordinated disclosure window**.
- **Good-Faith Safe Harbor:** Security research conducted in good faith against our repository or public web properties—without data destruction, service disruption, or third-party privacy violations—is authorized and protected under the U.S. Department of Justice Revised CFAA Charging Policy (18 U.S.C. § 1030).
- **Reward Policy:** Orbit Security is a defensive engineering project and does not currently operate a paid cash bounty program; verified reporters are credited in release notes and security advisories upon remediation.

---

## Scope & Rules of Engagement

### In Scope
- `CmfH009/Orbit-Security` source code, CLI (`orbit-security`, `orbit-recon`), and composite GitHub Action (`action.yml`).
- Public web surface at `https://cmfh009.github.io/Orbit-Security/`.

### Out of Scope
- Denial of Service (DoS) or volumetric traffic flooding.
- Social engineering, phishing, or physical security testing.
- Claiming or registering third-party subdomains without explicit written authorization.

---

## Domain Exclusion / Opt-Out Requests

Administrative contacts wishing to exclude their domains from Orbit Security passive reconnaissance telemetry may email [`carsonmail009@gmail.com`](mailto:carsonmail009@gmail.com) with the subject line `"Domain Exclusion Request"`. Verified requests are processed and permanently added to the exclusion list within 24 hours.
