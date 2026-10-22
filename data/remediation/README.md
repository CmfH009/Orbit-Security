# Orbit Security - Audit Remediation Pack

## What this pack is

Between 2026-10-20 and 2026-10-22 Orbit Security dispatched five outreach cohorts (6, 7, 8, 9, 10) to web / ecommerce agencies. Each email carried a PDF "client security audit" for that agency's client domain, scored by a flat-penalty model (CRITICAL 35 / HIGH 20 / MEDIUM 10 / LOW 5) with no finding-class awareness, no exploitability floor and no cap on repeated classes.

Re-scoring the same evidence with the corrected engine (`src/orbit_security/scoring.py`) moves 18 failing audits down to 5. 13 of those were published in error - in several cases to domains whose scan returned no critical and no high finding at all, only best-practice gaps (missing BIMI, MTA-STS, TLS-RPT, CAA, CSP, X-Frame-Options, X-Content-Type-Options) and a DMARC policy still in `p=none` monitoring mode.

This directory holds the customer-facing remediation:

| Path | What it is |
|------|------------|
| `remediation_manifest.json` | Machine-readable record of every audit: old and new score/grade, delta, severity counts, classification, PDF delivery status, join status and the paths of the artefacts. |
| `correction_notes/` | One ready-to-send correction note per **rescued** audit (subject line, body, and a factual "What changed" section). |
| `correction_emails/` | One RFC 5322 `.eml` per **rescued** audit - same body, ready to open and send from a desktop mail client. |
| `summary.md` | Operator summary: counts by cohort, affected table, send list. |

## Scope

- `rescued` (13) - the published grade was wrong. A correction note and a staged `.eml` are written for each.
- `still_failing` (5) - **no correction note.** Those grades are correct: the scan found genuine exploit risk (dangling CNAME / subdomain takeover, SSL/TLS certificate failures, missing DMARC). They get a normal follow-up instead.
- `unjoinable` (2) - audits on disk with no cohort 6-10 record. Their agency identity and contact address were recovered from the co-branding footer of the audit itself (2 of 2 recovered, 0 still without an address). They are flagged in `summary.md` and the manifest; never silently dropped.
- `unparseable` (0) - audits whose findings or grade could not be parsed. No score is invented for them and no note is written.

## How to regenerate

```powershell
.venv\Scripts\python.exe scripts\build_audit_remediation.py
```

The script is idempotent: it re-reads the on-disk evidence, rewrites the manifest, the notes, the `.eml` files, `summary.md` and this README from scratch every run. **This is the command that stages the correction e-mails as `.eml` files** in `data/remediation/correction_emails/` - there is no separate staging step and no send step. It writes only inside `data/remediation/`. It never touches the delivered audits, the cohort manifests or `outbound_campaigns/`, it never regenerates a PDF and it never sends mail.

Options:

| Flag | Effect |
|------|--------|
| `--date ISO8601` | Pin the generation timestamp and the `Date` header of every staged e-mail (useful for a reproducible pack). |
| `--verify-only` | Re-run the verification pass against the existing pack without rewriting it. |
| `--audits-dir PATH` | Point at a different audit tree (read-only). |

## Operator send procedure

1. **Regenerate** the pack so it matches the current evidence:

```powershell
.venv\Scripts\python.exe scripts\build_audit_remediation.py
```

2. **Review** every note in `data/remediation/correction_notes/`. Each file is
   a self-contained note: a `Subject:` line, a 120-220 word body and a factual
   "What changed" section listing the rule change.

3. **Check the staged e-mail** in `data/remediation/correction_emails/`. It carries the same body with `To`, `From`, `Subject`, `Reply-To` and `Date` headers, and it opens natively in Outlook / Mail / Thunderbird. Open it, read it once end to end, then send it.

4. **Send** the e-mail. Dispatch is manual on purpose - this pack stages, it does not send. Never point a mail client at `outbound_campaigns/` for this batch; the correction e-mails live in `data/remediation/correction_emails/`.

5. **Leave the `still_failing` audits out of the correction batch.** There is no note and no e-mail for them, by design. Their published grade was not wrong - the scan found real exploit risk - so a "we mis-scored this" note would be untrue. Send them the standard perimeter follow-up instead, leading with the specific exploitable finding rather than the headline score.

6. **Do not use this pack for the flagged audits.** The `unjoinable` audits sit outside cohorts 6-10 (an earlier dispatch). Their contact address was recovered from the audit footer, but they published a passing grade, so no correction is due - handle them as a normal outreach decision.

## Notes on the correction notes

- They state that the published grade was miscalculated. They never claim the estate is secure, and they never re-sell the product inside a correction.
- They name only the agency's own client domain - the domain that agency already received - and no third-party domain.
- The two or three finding classes named in each note are derived from that audit's own parsed findings and the legacy penalty they carried; the full attribution lives in `remediation_manifest.json` under `cause_classes`.
- The PDF that was attached to the original email still shows the old grade. It is not regenerated here. Reply-to-the-note re-issue is the operator's call.

## Files in this pack

```
data/remediation/
  README.md                          # this file
  summary.md                         # operator summary
  remediation_manifest.json          # machine-readable record
  correction_notes/<slug>_<domain>_correction.md
  correction_emails/<slug>_<domain>_correction.eml
```
