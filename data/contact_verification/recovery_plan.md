# Orbit Security - Deliverability Recovery Plan

**Generated:** 2026-10-22T12:22:55.596497+00:00 | **Source:** `data\contact_verification\verification.json`

## What this is

43 of 178 dispatched campaigns hard-bounced. The domains were fine - 43 of the 46 bounced
have valid MX records, and their mail providers are statistically identical to the
delivered set. The problem was the specific mailbox: we guessed role addresses that
often do not exist. This plan verifies the mailbox instead of the domain.

## Actions

| Action | Count | Meaning |
|---|---|---|
| RETARGET | 12 | a published address exists on their own site - re-target this one |
| SUPPRESS_NO_MX | 3 | the domain cannot receive mail at all - drop permanently |
| SUPPRESS_REFUTED | 4 | domain accepts mail, but not the address we guessed |
| NO_ACTION | 3 | guessed address is published; the bounce was mailbox-level |
| UNKNOWN | 21 | no published address found - inconclusive, needs manual review |

## Re-target list

| Agency | Domain | We guessed | Use instead |
|---|---|---|---|
| Swanky | `swankyagency.com` | `hello@swankyagency.com` | **`cat@swankyagency.com`** |
| Avex Designs | `avexdesigns.com` | `hello@avexdesigns.com` | **`newbusiness@avexdesigns.com`** |
| Ask Phill | `askphill.com` | `hello@askphill.com` | **`sales@askphill.com`** |
| Chromatic | `chromatichq.com` | `hello@chromatichq.com` | **`info@chromatichq.com`** |
| Digitas | `digitas.com` | `info@digitas.com` | **`amsterdam@digitas.com`** |
| R/GA | `rga.com` | `info@rga.com` | **`argentina@rga.com`** |
| Work & Co | `work.co` | `hello@work.co` | **`newbiz@work.co`** |
| BASIC/DEPT | `basicagency.com` | `hello@basicagency.com` | **`biz@basicagency.com`** |
| Major Tom | `majortom.com` | `info@majortom.com` | **`hello@majortom.com`** |
| Immersive Garden | `immersive-g.com` | `contact@immersive-g.com` | **`inquiries@immersive-g.com`** |
| B-Reel | `b-reel.com` | `hello@b-reel.com` | **`newbiz@b-reel.com`** |
| Goodface Agency | `goodface.agency` | `hello@goodface.agency` | **`hi@goodface.agency`** |

## Suppress list

| Agency | Domain | We guessed | Reason |
|---|---|---|---|
| Guidance | `guidance.com` | `info@guidance.com` | agency publishes mail, but not the address we guessed |
| Fuel Made | `fuelmade.com` | `hello@fuelmade.com` | agency publishes mail, but not the address we guessed |
| FFW Agency | `ffw.com` | `hello@ffw.com` | agency publishes mail, but not the address we guessed |
| VML Commerce | `vml.com` | `contact@vml.com` | agency publishes mail, but not the address we guessed |
| Heco Studio | `heco.design` | `hello@heco.design` | domain publishes no mail exchanger |
| Juno E-Commerce | `juno-ecommerce.co.uk` | `hello@juno-ecommerce.co.uk` | domain publishes no mail exchanger |
| The Dylan Agency | `thedylanagency.com` | `hello@thedylanagency.com` | domain publishes no mail exchanger |

## Operator procedure

1. Apply the suppress list to `data/bounced_agencies.json` (add the guessed address, keep
   the replacement out of the suppression list so it can be used).
2. Re-stage the re-target list as a fresh cohort using the published address.
3. Run `scripts/verify_contacts.py` over every new cohort **before** dispatch. A REFUTED
   or NO_MX agency should never enter a send queue.
4. Re-measure with `scripts/outreach_metrics.py` after the next cohort lands.

## Structural fix

Stop guessing. `scripts/verify_contacts.py` reads the agency's own published contact page
and checks the exact address before it enters a send queue. Wire it into the cohort
launcher as a pre-flight gate and the bounce rate becomes a function of target quality,
not of guessing.
