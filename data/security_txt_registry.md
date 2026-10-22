# Orbit Security: Responsible Disclosure Registry (RFC 9116 / Security.txt)
**Generated:** 2026-10-22 02:43:35 UTC | **Total Packaged Disclosures:** 121

## 1. Executive Summary
- **Total Monitored Programs with Disclosed Findings:** 14
- **Total Cryptographically Sealed Bundles:** 121
- **Breakdown by Severity:**
  - **LOW:** 78 findings
  - **MEDIUM:** 25 findings
  - **HIGH:** 18 findings

- **Breakdown by Weakness Category:**
  - **Mail Spoofing:** 121 findings

## 2. Program Breakdown & Primary Security Contacts
| Program | Total Bundles | Highest Severity | Primary Contact(s) | Sample Target |
|---------|---------------|------------------|--------------------|---------------|
| **Xiaomi** | 32 | `HIGH` | `security@airstar-finance.com`, `security-team@airstar-finance.com` | `airstar-finance.com` |
| **MercadoLibre** | 23 | `HIGH` | `security@adminml.com`, `security-team@adminml.com` | `adminml.com` |
| **Elastic** | 17 | `MEDIUM` | `security@ela.st`, `security-team@ela.st` | `ela.st` |
| **Eternal** | 8 | `HIGH` | `security@edition.in`, `security-team@edition.in` | `edition.in` |
| **Expedia Group Bug Bounty** | 8 | `HIGH` | `security@bookabach.co.nz`, `security-team@bookabach.co.nz` | `bookabach.co.nz` |
| **Flutter UK&I** | 8 | `HIGH` | `security@betsharedservices.io`, `security-team@betsharedservices.io` | `betsharedservices.io` |
| **Superbet** | 7 | `MEDIUM` | `security@happening.dev`, `security-team@happening.dev` | `happening.dev` |
| **KHealth** | 5 | `MEDIUM` | `security@hhc247.org`, `security-team@hhc247.org` | `hhc247.org` |
| **U.S. Dept of Defense** | 4 | `LOW` | `security@assets.mil`, `security-team@assets.mil` | `assets.mil` |
| **Playtika** | 3 | `HIGH` | `security@bestfiends.com`, `security-team@bestfiends.com` | `bestfiends.com` |
| **Spotify** | 2 | `LOW` | `security@byspotify.com`, `security-team@byspotify.com` | `byspotify.com` |
| **Trip.com** | 2 | `MEDIUM` | `security@travix.io`, `security-team@travix.io` | `travix.io` |
| **Slack** | 1 | `LOW` | `security@slack-core.com`, `security-team@slack-core.com` | `slack-core.com` |
| **Starbucks** | 1 | `LOW` | `security@starbucksreserve.com`, `security-team@starbucksreserve.com` | `starbucksreserve.com` |

## 3. High-Priority Enterprise Direct Disclosures (Sample)
| Target Domain | Program | Flaw | CVSS | Primary Contact | Status |
|---------------|---------|------|------|-----------------|--------|
| `assets.mil` | U.S. Dept of Defense | mail_spoofing | 4.3 | `security@assets.mil` | 🟢 `SEALED_STAGED` |
| `cdn1.mil` | U.S. Dept of Defense | mail_spoofing | 4.3 | `security@cdn1.mil` | 🟢 `SEALED_STAGED` |
| `cdn2.mil` | U.S. Dept of Defense | mail_spoofing | 4.3 | `security@cdn2.mil` | 🟢 `SEALED_STAGED` |
| `static.mil` | U.S. Dept of Defense | mail_spoofing | 4.3 | `security@static.mil` | 🟢 `SEALED_STAGED` |
| `ela.st` | Elastic | mail_spoofing | 4.3 | `security@ela.st` | 🟢 `SEALED_STAGED` |
| `elastic.dev` | Elastic | mail_spoofing | 4.3 | `security@elastic.dev` | 🟢 `SEALED_STAGED` |
| `elasticacademy.com` | Elastic | mail_spoofing | 5.3 | `security@elasticacademy.com` | 🟢 `SEALED_STAGED` |
| `elasticapm.co` | Elastic | mail_spoofing | 4.3 | `security@elasticapm.co` | 🟢 `SEALED_STAGED` |
| `elasticpartneracademy.com` | Elastic | mail_spoofing | 4.3 | `security@elasticpartneracademy.com` | 🟢 `SEALED_STAGED` |
| `elasticps.co` | Elastic | mail_spoofing | 5.3 | `security@elasticps.co` | 🟢 `SEALED_STAGED` |
| `elasticsearch.com` | Elastic | mail_spoofing | 5.3 | `security@elasticsearch.com` | 🟢 `SEALED_STAGED` |
| `elasticsearch.fr` | Elastic | mail_spoofing | 4.3 | `security@elasticsearch.fr` | 🟢 `SEALED_STAGED` |
| `elasticsearch.org` | Elastic | mail_spoofing | 5.3 | `security@elasticsearch.org` | 🟢 `SEALED_STAGED` |
| `elstc.co` | Elastic | mail_spoofing | 4.3 | `security@elstc.co` | 🟢 `SEALED_STAGED` |
| `eops.nl` | Elastic | mail_spoofing | 4.3 | `security@eops.nl` | 🟢 `SEALED_STAGED` |

## 4. Responsible Disclosure Protocols
1. **Zero Exploitation**: Orbit Security does not weaponize, extract data, or alter state. All evidence consists of non-intrusive DNS TXT/CNAME records and RFC-compliant email routing inspections.
2. **Coordinated 90-Day Window**: Enterprise recipients are provided a strict 90-day remediation timeline prior to any coordinated public disclosure or advisory publication.
3. **Cryptographic Integrity**: Every package includes raw technical proofs, structured metadata, and a SHA-256 manifest to allow enterprise teams to instantly verify evidence without ambiguity.