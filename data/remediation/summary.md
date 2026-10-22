# Orbit Security - Audit Remediation Pack Summary

**Generated:** 2026-10-22T12:08:46.583131+00:00 | **Source:** `data/generated_audits/*/*_audit.md` (read-only evidence) | **Regenerate:** `scripts/build_audit_remediation.py`

Between 2026-10-20 and 2026-10-22 five outreach cohorts shipped 52 client security audits. The published grades came from a flat-penalty scoring model that treated best-practice items as vulnerabilities. This pack holds the corrected numbers, the correction notes for the agencies whose grade was wrong, and the staged e-mails.

## Headline counts

| Metric | Count |
|--------|-------|
| Audits re-scored | 52 |
| Audits joined to a cohort record | 50 |
| **Affected (published D/F)** | **18** |
| **Rescued (grade was wrong - correction note ready)** | **13** |
| **Still failing (genuine exploit risk - no correction note)** | **5** |
| Audits that could not be joined to a cohort | 2 |
| ...of those, contact address recovered from the audit body | 2 |
| Audits that could not be parsed | 0 |
| Unaffected audits (published grade C or better) | 34 |
| **Correction notes ready to send** | **13** |
| **Staged correction e-mails (.eml)** | **13** |

## Counts by cohort

| Cohort | Audits | Affected (D/F) | Rescued | Still failing | Correction notes |
|--------|--------|-----------------|---------|---------------|-----------------|
| 6 | 10 | 1 | 0 | 1 | 0 |
| 7 | 10 | 5 | 4 | 1 | 4 |
| 8 | 10 | 5 | 2 | 3 | 2 |
| 9 | 10 | 3 | 3 | 0 | 3 |
| 10 | 10 | 4 | 4 | 0 | 4 |
| not in cohort 6-10 | 2 | 0 | 0 | 0 | 0 |

## Affected audits (published grade D or F)

| Agency | Client domain | Contact email | Cohort | Old | New | Delta | Classification |
|--------|---------------|---------------|--------|-----|-----|-------|----------------|
| Aligent | `theathletesfoot.com.au` | `contact@aligent.com.au` | 9 | 45/100 D | 85/100 B | +40 | `rescued` |
| Alley Interactive | `kff.org` | `info@alley.com` | 10 | 35/100 F | 75/100 B | +40 | `rescued` |
| Astound Commerce | `underarmour.com` | `privacy@astounddigital.com` | 7 | 35/100 F | 70/100 C | +35 | `rescued` |
| Blue Thirst | `bathstore.com` | `info@bluethirst.co.uk` | 6 | 20/100 F | 40/100 F | +20 | `still_failing` |
| Elogic Commerce | `whirlpool.com` | `office@elogic.co` | 8 | 45/100 D | 59/100 D | +14 | `still_failing` |
| Grebban | `bjornborg.com` | `hello@grebban.com` | 9 | 35/100 F | 75/100 B | +40 | `rescued` |
| Kensium | `backcountry.com` | `info@kensium.com` | 8 | 0/100 F | 40/100 F | +40 | `still_failing` |
| Latori | `sennheiser.com` | `info@latori.com` | 8 | 50/100 D | 85/100 B | +35 | `rescued` |
| Lullabot | `grammy.com` | `hello@lullabot.com` | 10 | 40/100 F | 80/100 B | +40 | `rescued` |
| Palantir.net | `uchicago.edu` | `info@palantir.net` | 10 | 40/100 F | 80/100 B | +40 | `rescued` |
| Pixafy | `yamaha.com` | `info@pixafy.com` | 7 | 50/100 D | 90/100 A | +40 | `rescued` |
| Process Creative | `bondisands.com.au` | `enquiries@processcreative.com.au` | 9 | 55/100 D | 90/100 A | +35 | `rescued` |
| Redstage | `citgo.com` | `info@redstage.com` | 7 | 45/100 D | 60/100 C | +15 | `rescued` |
| rtCamp | `aljazeera.com` | `hello@rtcamp.com` | 10 | 40/100 F | 80/100 B | +40 | `rescued` |
| Scandiweb | `puma.com` | `info@scandiweb.com` | 7 | 50/100 D | 85/100 B | +35 | `rescued` |
| Series Eight | `oatly.com` | `info@serieseight.com` | 8 | 50/100 D | 85/100 B | +35 | `rescued` |
| The Stable | `ring.com` | `info@thestable.com` | 7 | 5/100 F | 55/100 D | +50 | `still_failing` |
| Ziffity | `bergdorfgoodman.com` | `contactus@ziffity.com` | 8 | 0/100 F | 40/100 F | +40 | `still_failing` |

## Correction notes ready to send

13 note(s) are written to `data/remediation/correction_notes/` and the matching staged e-mails to `data/remediation/correction_emails/`.

- `data/remediation/correction_notes/aligent_theathletesfoot.com.au_correction.md` - Aligent / `theathletesfoot.com.au` - D (45) -> B (85)
- `data/remediation/correction_notes/alley-interactive_kff.org_correction.md` - Alley Interactive / `kff.org` - F (35) -> B (75)
- `data/remediation/correction_notes/astound-commerce_underarmour.com_correction.md` - Astound Commerce / `underarmour.com` - F (35) -> C (70)
- `data/remediation/correction_notes/grebban_bjornborg.com_correction.md` - Grebban / `bjornborg.com` - F (35) -> B (75)
- `data/remediation/correction_notes/latori_sennheiser.com_correction.md` - Latori / `sennheiser.com` - D (50) -> B (85)
- `data/remediation/correction_notes/lullabot_grammy.com_correction.md` - Lullabot / `grammy.com` - F (40) -> B (80)
- `data/remediation/correction_notes/palantir-net_uchicago.edu_correction.md` - Palantir.net / `uchicago.edu` - F (40) -> B (80)
- `data/remediation/correction_notes/pixafy_yamaha.com_correction.md` - Pixafy / `yamaha.com` - D (50) -> A (90)
- `data/remediation/correction_notes/process-creative_bondisands.com.au_correction.md` - Process Creative / `bondisands.com.au` - D (55) -> A (90)
- `data/remediation/correction_notes/redstage_citgo.com_correction.md` - Redstage / `citgo.com` - D (45) -> C (60)
- `data/remediation/correction_notes/rtcamp_aljazeera.com_correction.md` - rtCamp / `aljazeera.com` - F (40) -> B (80)
- `data/remediation/correction_notes/scandiweb_puma.com_correction.md` - Scandiweb / `puma.com` - D (50) -> B (85)
- `data/remediation/correction_notes/series-eight_oatly.com_correction.md` - Series Eight / `oatly.com` - D (50) -> B (85)

## Still-failing audits - recommendation

**Do not send a correction note to these agencies.** Their published grade was not wrong: after re-scoring with the corrected model they still fail, because the scanner found genuinely exploitable risk (dangling CNAME / subdomain takeover, SSL/TLS certificate failures, missing DMARC). Sending a correction there would be both inaccurate and damaging.

Treat them as a normal engagement follow-up instead: send the standard perimeter follow-up, attach the same co-branded audit, and lead with the specific exploitable finding rather than the headline score. If the operator wants to publish the revised score alongside it, use the corrected score from the manifest - do not restate the old grade.

- Blue Thirst / `bathstore.com` - F (20) -> F (40) - still-scored findings: Missing DMARC Email Protection [HIGH], SSL/TLS Certificate Verification Failure [HIGH], SSL/TLS Connection Failure [HIGH]
- Elogic Commerce / `whirlpool.com` - D (45) -> D (59) - still-scored findings: Dangling CNAME / Subdomain Takeover Risk (AWS CloudFront) [CRITICAL]
- Kensium / `backcountry.com` - F (0) -> F (40) - still-scored findings: Missing HSTS Header (HTTP Strict Transport Security) [MEDIUM], Dangling CNAME / Subdomain Takeover Risk (AWS CloudFront) [CRITICAL]
- The Stable / `ring.com` - F (5) -> D (55) - still-scored findings: Server / Tech Stack Version Disclosure [LOW], Dangling CNAME / Subdomain Takeover Risk (AWS CloudFront) [CRITICAL]
- Ziffity / `bergdorfgoodman.com` - F (0) -> F (40) - still-scored findings: Missing HSTS Header (HTTP Strict Transport Security) [MEDIUM], Dangling CNAME / Subdomain Takeover Risk (AWS CloudFront) [CRITICAL]

## Flagged - audits that could not be joined to a cohort record

These audits exist on disk but have no matching cohort 6-10 record. They are **not** silently dropped - they are listed here and in `remediation_manifest.json` under `unjoinable`. The agency identity and contact address were recovered from the co-branding footer of the audit itself; the dispatch status comes from `data/dispatched_campaigns.json`.

| Client domain | Audit file | Agency (recovered) | Contact (recovered) | Dispatch | Published | Corrected | Affected |
|---------------|------------|---------------------|----------------------|----------|-----------|-----------|----------|
| `goruck.com` | `data/generated_audits/blue-stout/goruck.com_audit.md` | Blue Stout (`bluestout.com`) | `hello@bluestout.com` | SENT (2026-10-04 14:54:09) | B (75) | A+ (100) | no |
| `untuckit.com` | `data/generated_audits/bva-agency/untuckit.com_audit.md` | BVA Agency (`bva.com`) | `info@bva.com` | BOUNCED (2026-10-04 14:54:23) | B (80) | A+ (100) | no |

## Send procedure

1. Review each note in `data/remediation/correction_notes/` - one per rescued audit.
2. Review the staged e-mail in `data/remediation/correction_emails/` - same body, ready to open in any desktop mail client.
3. Send. Nothing is auto-sent by this pack; the operator drives dispatch.
4. Leave `still_failing` audits out of the correction batch - follow up normally.

See `data/remediation/README.md` for the full procedure.
