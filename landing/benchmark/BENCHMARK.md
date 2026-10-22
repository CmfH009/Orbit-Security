# Orbit Security Audit Benchmark

<!-- Source note: every "bind" marker in this file ties a published number to the measurement it came from. scripts/build_benchmark_page.py verifies each one against docs/benchmark/benchmark_results.json and refuses to build the page if any of them drifts. -->

*Published 2026-10-22<!--bind:generated_date date--> (UTC) - every number on this page comes from a single run of a single command, and the raw output is published beside it as `benchmark_results.json`.*

## Why this page exists

Most security marketing is asserted rather than measured. The Orbit Security [About page](../about.html) claims a per-domain turnaround time and a takeover signature count, and until now neither claim carried a date, a sample size or a method.

This page fixes that. It publishes four things:

1. **What is measured** and why.
2. **The exact command** that produced the numbers, so you can run it yourself.
3. **The numbers**, as measured, on a stated date.
4. **The limits** - what the sample size, the date and the network conditions do and do not allow these numbers to prove.

The harness is the same code path that produces a client audit: it calls `orbit_security.recon.resolve_dns()`, `orbit_security.recon.check_headers_and_exposures()`, `orbit_security.recon.calculate_score()` and `orbit_security.recon.calculate_grade()`. If a measurement cannot be taken, the harness writes `null` together with the reason. Nothing on this page is estimated, extrapolated or copied from a marketing claim.

## What is measured

| Measurement | Question it answers |
| --- | --- |
| Per-domain audit latency | How long does one full Orbit audit of one domain take? |
| Takeover signature coverage | How many providers, fingerprints and dangling hostname classes can the scanner recognise? |
| False-positive guards | How does Orbit avoid flagging static hosts, parked pages and reserved domains? |
| Scoring stability | Does the grader give the same verdict on the same input, and does it separate exploitable risk from hygiene? |

One thing this benchmark deliberately does **not** measure is the retainer ROI figure printed on the About page. That is a business-model projection rather than a technical measurement, and mixing it into a measurement page would be dishonest.

## Reproduce it

The harness and this page both live in the public repository:

```bash
git clone https://github.com/CmfH009/Orbit-Security.git
cd Orbit-Security
.venv\Scripts\python.exe scripts\run_benchmark.py --repeat 5<!--bind:repeat int--> --out docs\benchmark\benchmark_results.json
```

On macOS or Linux, use `python3` in place of `.venv\Scripts\python.exe`. The command that produced *this* page was:

```bash
A:\projects\orbit-security\.venv\Scripts\python.exe scripts/run_benchmark.py --repeat 5 --out docs\benchmark\benchmark_results.json<!--bind:command_line raw-->
```

The harness is deterministic and read-only with respect to the scanner source, the tests and the stored audits. It only writes the JSON file, and it writes `null` plus a reason for anything it could not measure. To benchmark a client estate you are authorised to scan, pass a target file - one domain per line, `#` comments allowed:

```bash
.venv\Scripts\python.exe scripts\run_benchmark.py --targets my_clients.txt --repeat 3
```

## Results

### 1. Per-domain audit latency

One "audit" is the complete per-domain sequence the `orbit-recon` CLI runs: DNS resolution (CNAME, A, MX, DMARC, BIMI, MTA-STS, CAA), HTTP header inspection plus the exposed-file probes, then scoring and grading.

Two numbers are reported for every audit:

- **Wall clock** - what an operator waits, with the 1 request/second politeness limit enforced. The limit is not optional in the harness: it cannot be configured below 1.0 seconds.
- **Active time** - the same audit with the deliberate throttle sleeps removed. This is the scanner plus network cost, and it is the number to compare against a per-domain turnaround claim.

| Statistic | Wall clock (1 req/s enforced) | Active time (throttle sleeps removed) |
| --- | --- | --- |
| Minimum | 18,227 ms<!--bind:wall_min ms0--> | 1,470 ms<!--bind:active_min ms0--> |
| Median (p50) | 19,194 ms<!--bind:wall_p50 ms0--> | 4,063 ms<!--bind:active_p50 ms0--> |
| p90 | 20,477 ms<!--bind:wall_p90 ms0--> | 5,693 ms<!--bind:active_p90 ms0--> |
| p95 | 20,531 ms<!--bind:wall_p95 ms0--> | 5,907 ms<!--bind:active_p95 ms0--> |
| p99 | 20,566 ms<!--bind:wall_p99 ms0--> | 6,189 ms<!--bind:active_p99 ms0--> |
| Maximum | 20,566 ms<!--bind:wall_max ms0--> | 6,189 ms<!--bind:active_max ms0--> |
| Mean | 19,393 ms<!--bind:wall_mean ms0--> | 3,802 ms<!--bind:active_mean ms0--> |

Sample: 25<!--bind:sample_count int--> audits of 5<!--bind:target_count int--> domains (example.com, github.com, python.org, wikipedia.org, mozilla.org<!--bind:targets raw-->), repeated 5<!--bind:repeat int--> times each - 275<!--bind:total_http_requests int--> HTTP requests and 310<!--bind:total_dns_operations int--> DNS operations in total. Percentiles use the nearest-rank method with no interpolation, so every reported percentile is an observed value.

**Per-domain breakdown**

| Domain | Grade(s) observed | Score(s) | Median active time | Fastest | Slowest | DNS queries | OS resolver lookups | HTTP requests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `example.com` | A | 90 | 1,996 ms | 1,470 ms | 5,090 ms | 7 | 3 | 11 |
| `github.com` | A+ | 100 | 4,063 ms | 3,243 ms | 5,513 ms | 7 | 3 | 11 |
| `python.org` | A+ | 100 | 5,672 ms | 4,466 ms | 6,189 ms | 7 | 14 | 11 |
| `wikipedia.org` | A | 90 | 2,071 ms | 1,942 ms | 2,396 ms | 7 | 3 | 11 |
| `mozilla.org` | A+ | 100 | 4,381 ms | 3,788 ms | 5,907 ms | 7 | 4 | 11 |

**Where the time goes** (median per audit, wall clock - these phase figures include the politeness sleeps)

| Phase | Median wall clock |
| --- | --- |
| DNS resolution and mail-record checks | 7,001 ms<!--bind:phase_dns_p50 ms0--> |
| HTTP header inspection and exposed-file probes | 12,108 ms<!--bind:phase_http_p50 ms0--> |
| Scoring and grading | 0.1 ms<!--bind:phase_scoring_p50 ms1--> |

Of the 19,194 ms<!--bind:wall_p50 ms0--> median wall clock, 15,375 ms<!--bind:throttle_p50 ms0--> was spent deliberately sleeping to respect the 1 request/second limit. The real work - the network time above minus those sleeps - was 4,063 ms<!--bind:active_p50 ms0--> in the median. Scoring and grading is effectively free at 0.1 ms<!--bind:phase_scoring_p50 ms1-->: all of the time is spent on the network, not on the model. (Phase figures and the throttle figure are independent medians of the same sample, so they are not expected to sum exactly.)

**Cold versus warm DNS cache**

Orbit ships a local DNS cache daemon, and it was running on this machine during the run, so the first repeat of each domain paid the cache-fill cost and later repeats were answered from cache. Both passes are reported rather than blended:

| Pass | Samples | Median DNS phase | Median active time |
| --- | --- | --- | --- |
| Repeat 1 (cold cache) | 5<!--bind:cold_samples int--> | 7,003 ms<!--bind:cold_dns_p50 ms0--> | 4,184 ms<!--bind:cold_active_p50 ms0--> |
| Repeats 2+ (warm cache) | 20<!--bind:warm_samples int--> | 7,001 ms<!--bind:warm_dns_p50 ms0--> | 3,794 ms<!--bind:warm_active_p50 ms0--> |

The difference between the two passes is small, and the reason matters: the DNS phase is bounded by the 1 request/second politeness limit, not by cache misses. A warm cache saves milliseconds of real work and seconds of waiting.

### 1a. How this compares with the published claim

The About page advertises "< 12 seconds per domain audit". The honest comparison has to name which number is being compared, so here it is in full:

| Reading of "< 12 seconds per domain audit" | Measured | Verdict |
| --- | --- | --- |
| Scanner plus network work per domain, throttle sleeps removed (median) | 4,063 ms<!--bind:active_p50 ms0--> | holds |
| Worst observed audit on this run, throttle sleeps removed (p95) | 5,907 ms<!--bind:active_p95 ms0--> | holds |
| Wall clock per domain while the harness caps itself at 1 request/second | 19,194 ms<!--bind:wall_p50 ms0--> | does not hold |

The third row is not a defect: an audit issues 11<!--bind:http_requests_per_audit int--> HTTP requests and about 10<!--bind:dns_ops_per_audit int--> DNS operations to a handful of hosts, so a hard 1 request/second cap makes a sub-12-second wall clock arithmetically impossible. The claim is defensible for the scanner's own cost and indefensible for a throttled wall clock, and this page states which one it is. The original marketing copy does not make that distinction, which is exactly the gap this benchmark exists to close.

### 2. Takeover signature coverage

Counted directly from the live signature table the scanner uses, not from a hand-maintained list on this page.

| Metric | Measured |
| --- | --- |
| Provider signatures | 52<!--bind:provider_signatures int--> |
| Fingerprint entries (one provider can carry several) | 80<!--bind:fingerprint_entries int--> |
| Distinct provider fingerprints | 76<!--bind:distinct_fingerprints int--> |
| Distinct dangling hostname classes (CNAME targets) | 69<!--bind:hostname_classes int--> |
| Providers that additionally verify NXDOMAIN | 3<!--bind:nxdomain_providers int--> |

The About page advertises "40+ takeover signatures". The measured value is 52<!--bind:provider_signatures int--> provider signatures carrying 76<!--bind:distinct_fingerprints int--> distinct provider fingerprints and 69<!--bind:hostname_classes int--> distinct dangling hostname classes, so the marketing floor is met and then some.

A provider is only reported as a takeover when its CNAME pattern matches **and** the provider fingerprint (or an NXDOMAIN response) is confirmed. A CNAME alone is never treated as a finding.

### 3. False-positive guards

| Guard | What it prevents | Measured |
| --- | --- | --- |
| Static hosting / CDN suffixes | Header findings on hosts whose edge owns the headers | 13<!--bind:static_suffixes int--> guarded suffixes plus the bare `github.io` host |
| Parked-page fingerprints | Scoring a parked domain as a broken deployment | 8<!--bind:parked_fingerprints int--> HTML fingerprints |
| RFC 2606 reserved domains | Auditing `example.com` or a `.test` host as a client | 6<!--bind:reserved_domains int--> reserved names and 4 reserved TLDs |
| SSRF block | Auditing loopback, private or cloud-metadata addresses | Enforced on every resolution and every HTTP probe |

The benchmark exercises these guards with a self-test of 21<!--bind:guard_cases int--> cases; 21<!--bind:guard_passed int--> of them behaved exactly as the code specifies. The full case list is in the `guard_self_test` block of the raw JSON.

### 4. Scoring stability

The current grading engine (`orbit_security.scoring.score_findings`) was replayed over every stored client audit in the repository - 52<!--bind:audits_parsed int--> delivered audits containing 514<!--bind:findings_parsed int--> findings. The audit files were read only; nothing was rewritten.

**Grade distribution**

| Grade | Legacy flat-penalty model | Current exploitability-aware engine |
| --- | --- | --- |
| A+ | 1 | 22<!--bind:grade_Aplus int--> |
| A | 0 | 12<!--bind:grade_A int--> |
| B | 16 | 11<!--bind:grade_B int--> |
| C | 17 | 2<!--bind:grade_C int--> |
| D | 8 | 2<!--bind:grade_D int--> |
| F | 10 | 3<!--bind:grade_F int--> |

Under the current engine 18<!--bind:legacy_failing int--> audits used to fail (D or F) and 5<!--bind:new_failing int--> do; 13<!--bind:rescued_from_df int--> were rescued and 0<!--bind:newly_failing int--> newly failed. 47<!--bind:grade_changed int--> of 52<!--bind:audits_parsed int--> grades changed, with a mean score change of 28.1<!--bind:mean_score_delta num1--> points.

The reason is visible in the findings themselves:

| Finding class | Count |
| --- | --- |
| Scored as risk (CRITICAL / HIGH / MEDIUM / LOW) | 67<!--bind:findings_scored_as_risk int--> |
| Reported as hygiene - never scored (missing BIMI, MTA-STS, CAA, CSP, X-Frame-Options, ...) | 447<!--bind:findings_reported_as_hygiene int--> |
| Audits containing at least one CRITICAL or HIGH finding | 8<!--bind:audits_with_critical_or_high int--> |
| Audits with no CRITICAL and no HIGH finding | 44<!--bind:audits_without_critical_or_high int--> |

The parser that reads the delivered audits was also validated against the legacy model: it reproduces the score printed in every one of the 52<!--bind:audits_parsed int--> documents, so the comparison above is a comparison of two scoring models and not of two parsers.

**Run-to-run stability**: each of the 5<!--bind:target_count int--> domains was audited 5<!--bind:repeat int--> times. The grade was identical across every repeat for 5<!--bind:grade_stable_domains int--> of 5<!--bind:target_count int--> domains (100%<!--bind:grade_stability_rate pct0-->).

## Limits - what these numbers do not claim

This section is the point of the page. If you only read one part, read this one.

- **Sample size.** 25<!--bind:sample_count int--> audits of 5<!--bind:target_count int--> domains from one workstation on one day. That is enough to show the scanner's order of magnitude and to prove the numbers are reproducible. It is not a statistical study of the global Internet.
- **One date, one machine, one network.** The run happened on 2026-10-22<!--bind:generated_date date--> on Windows<!--bind:os_name raw--> / Python 3.13.13<!--bind:python_version raw--> (8<!--bind:cpu_count int--> logical CPUs). Latency depends on the network path to the target and on the machine. A different day, a different machine or a different upstream resolver will produce different numbers.
- **The wall-clock figure is dominated by politeness, not by the scanner.** The harness caps every host at 1 request per second, so an audit that issues 11<!--bind:http_requests_per_audit int--> HTTP requests cannot finish faster than about 11<!--bind:http_requests_per_audit int--> seconds. The wall-clock column measures the politeness policy; the active column measures the scanner. Both are published because quoting only one of them would be misleading.
- **The active time is dominated by the OS resolver, not by Orbit's own logic.** Every audit runs the SSRF guard, which resolves the target through the operating system resolver before any request is allowed. In this run that produced between 3<!--bind:min_os_dns_lookups int--> and 14<!--bind:max_os_dns_lookups int--> OS lookups per audit, and the target with the most lookups was also the slowest one. That is a real cost of a real guard, and it is the largest single component of the active time.
- **The phase figures include the politeness sleeps.** The per-phase medians above are wall clock, so the DNS and HTTP rows are dominated by the rate limiter rather than by work. Only the "active time" column excludes it.
- **Small percentiles on a small sample.** With 25<!--bind:sample_count int--> samples the nearest-rank p95 and p99 land on or next to the maximum observation. Read them as "the slowest audit we saw", not as a tail estimate.
- **DNS cache effects.** Orbit's local DNS cache daemon was running during this run (yes<!--bind:local_dns_cache_running yesno-->), so repeats reuse cached answers. The cold and warm passes are reported separately for that reason.
- **The target set is not a typical client estate.** The five public domains used here are large, mature, well-run organisations. A small agency client on shared hosting will produce different findings, different grades and different latencies. These numbers describe the scanner, not the targets.
- **Coverage is not accuracy.** This benchmark measures how many signatures the scanner knows, how the guards behave and how the grader is consistent. It does **not** measure a true-positive rate against a ground truth, because no such ground truth was available for this run. Treat "we can recognise N provider fingerprints" as exactly that and not as "we detect N takeovers".
- **The grader was not validated against human reviewers.** The comparison here is between the previous flat-penalty model and the current exploitability-aware model on the same documents. That shows the model changed deliberately and reproducibly; it does not prove the new grades are the correct ones.
- **The ROI figure is not covered.** The retainer ROI number on the About page is a business projection and is not part of this dataset.
- **Single run, single operator.** One execution on one machine. It has not been repeated across a fleet of vantage points.

## How to challenge this

The point of publishing the raw JSON is that you do not have to trust the prose.

1. **Re-run it.** The command above reproduces the whole dataset from scratch in a few minutes. Compare your `benchmark_results.json` against ours.
2. **Disagree with a number?** Open an issue with your JSON attached. If the median active latency on your network is 3x ours, the page should say so.
3. **Found a missing signature?** The signature table lives in `src/orbit_security/signatures.py`. A pull request with the provider, the CNAME pattern and the fingerprint is a direct contribution to the table these numbers count.
4. **Think the limits section is too generous - or too harsh?** Tell us which limit you think is wrong. We would rather publish a smaller claim than a bigger one we cannot defend.
5. **Found a measurement that looks wrong?** The harness records `null` and a reason for anything it could not measure. If you can make it produce a number we could not, that is a bug in the harness and we want it.

## Frequently asked questions

### How long does one Orbit Security domain audit actually take?

The median audit on this run took 4,063 ms<!--bind:active_p50 ms0--> of active time - scanner plus network, with the artificial throttle sleeps removed - and 19,194 ms<!--bind:wall_p50 ms0--> of wall clock while the harness deliberately limited itself to 1 request per second per host. The audit covers DNS resolution and mail-record checks, HTTP header inspection, ten exposed-file probes and the scoring pass. The 1 request/second limit is the harness's own politeness rule, not a technical limit of the scanner.

### How many takeover signatures can Orbit Security detect?

52<!--bind:provider_signatures int--> provider signatures, carrying 76<!--bind:distinct_fingerprints int--> distinct provider fingerprints and 69<!--bind:hostname_classes int--> distinct dangling hostname classes, with 3<!--bind:nxdomain_providers int--> providers verified by NXDOMAIN as well. A takeover is only reported when the CNAME pattern matches and the provider fingerprint is confirmed, so the count is of recognised provider responses rather than of URLs we flag.

### How does Orbit Security avoid false positives?

With deterministic guards rather than heuristics: 13<!--bind:static_suffixes int--> static hosting and CDN suffixes plus the bare `github.io` host are recognised so that headers owned by a provider edge are never scored against the client, 8<!--bind:parked_fingerprints int--> parked-page fingerprints keep parked domains out of the estate, RFC 2606 reserved names are skipped, and every resolution and HTTP probe passes through an SSRF block for loopback, private and cloud-metadata addresses. The benchmark exercises all of them with a 21<!--bind:guard_cases int-->-case self-test, of which 21<!--bind:guard_passed int--> passed.

### Is the security grading stable?

Yes, in the two senses that can be measured. Re-running the current engine over the 52<!--bind:audits_parsed int--> stored client audits reproduces every published grade deterministically, and the parser that reads those documents reproduces the score printed in every one of them. Across the live runs, the grade was identical on every repeat for 5<!--bind:grade_stable_domains int--> of 5<!--bind:target_count int--> domains. What this does not prove is that the grades are correct in an absolute sense - that would need a human-graded ground truth, which this dataset does not contain.

### Can I reproduce this benchmark on my own infrastructure?

Yes. Clone the repository, install the dependencies and run `scripts/run_benchmark.py`. Point it at your own target file to audit an estate you are authorised to scan. The harness enforces a 1 request/second per host limit that cannot be configured lower, writes the same JSON structure, and writes `null` with a reason for any measurement it could not take, so your output is directly comparable with ours.

### Does this benchmark prove Orbit Security finds every vulnerability?

No, and no benchmark of this shape could. It measures what the scanner knows (the signature table), how its guards behave, and how consistently its grader scores the same evidence. It does not measure detection accuracy against a ground truth, it does not claim the scanned domains were free of vulnerabilities, and it does not cover the retainer ROI figure. The honest summary is: this is a reproducible measurement of the scanner's speed, coverage and consistency - not a certification of its completeness.

## Structured data

The block below is injected verbatim into this page as `<script type="application/ld+json">` and describes the benchmark as a machine-readable dataset.

```json
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html#webpage",
      "url": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html",
      "name": "Orbit Security Audit Benchmark | Reproducible Latency, Signature Coverage & Scoring Data",
      "datePublished": "2026-10-22<!--bind:generated_date date-->",
      "dateModified": "2026-10-22<!--bind:generated_date date-->",
      "inLanguage": "en",
      "isPartOf": { "@id": "https://cmfh009.github.io/Orbit-Security/#website" },
      "about": { "@id": "https://cmfh009.github.io/Orbit-Security/#organization" },
      "mainEntity": { "@id": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html#dataset" }
    },
    {
      "@type": "Dataset",
      "@id": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html#dataset",
      "name": "Orbit Security Perimeter Audit Benchmark",
      "description": "Reproducible measurements of the Orbit Security perimeter scanner: per-domain audit latency, takeover signature coverage, false-positive guard behaviour and the grade distribution of the exploitability-aware scoring engine across stored client audits.",
      "creator": { "@id": "https://cmfh009.github.io/Orbit-Security/#organization" },
      "publisher": { "@id": "https://cmfh009.github.io/Orbit-Security/#organization" },
      "datePublished": "2026-10-22<!--bind:generated_date date-->",
      "dateModified": "2026-10-22<!--bind:generated_date date-->",
      "temporalCoverage": "2026-10-22<!--bind:generated_date date-->/2026-10-22<!--bind:generated_date date-->",
      "distribution": {
        "@type": "DataDownload",
        "encodingFormat": "application/json",
        "contentUrl": "https://cmfh009.github.io/Orbit-Security/benchmark/benchmark_results.json"
      },
      "license": "https://github.com/CmfH009/Orbit-Security/blob/main/LICENSE",
      "isAccessibleForFree": true,
      "variableMeasured": [
        "Per-domain audit latency in milliseconds (wall clock and active)",
        "Number of takeover provider signatures",
        "Number of distinct provider fingerprints",
        "Number of distinct dangling hostname classes",
        "Number of static hosting and CDN false-positive guard suffixes",
        "Number of parked-page fingerprints",
        "Security grade distribution across stored client audits",
        "Number of findings scored as risk versus reported as hygiene"
      ],
      "measurementTechnique": "In-process wall-clock instrumentation of orbit_security.recon (dnspython + httpx) with a hard 1 request per second per host politeness limit; nearest-rank percentiles; scoring engine replayed over stored audit deliverables.",
      "sampleSize": "25<!--bind:sample_count int--> audits across 5<!--bind:target_count int--> public domains and 52<!--bind:audits_parsed int--> stored client audits",
      "version": "1.0.0",
      "keywords": [
        "security benchmark",
        "audit latency",
        "subdomain takeover signatures",
        "false positive prevention",
        "security grading",
        "DNS hygiene"
      ]
    },
    {
      "@type": "FAQPage",
      "@id": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html#faq",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "How long does one Orbit Security domain audit actually take?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "The median audit on the published run took 4,063 ms<!--bind:active_p50 ms0--> of active time - scanner plus network, with the artificial throttle sleeps removed - and 19,194 ms<!--bind:wall_p50 ms0--> of wall clock while the harness limited itself to 1 request per second per host. The audit covers DNS and mail-record resolution, HTTP header inspection, ten exposed-file probes and the scoring pass."
          }
        },
        {
          "@type": "Question",
          "name": "How many takeover signatures can Orbit Security detect?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "52<!--bind:provider_signatures int--> provider signatures carrying 76<!--bind:distinct_fingerprints int--> distinct provider fingerprints and 69<!--bind:hostname_classes int--> distinct dangling hostname classes, with 3<!--bind:nxdomain_providers int--> providers additionally verified by NXDOMAIN. A takeover is only reported when the CNAME pattern matches and the provider fingerprint is confirmed."
          }
        },
        {
          "@type": "Question",
          "name": "How does Orbit Security avoid false positives?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "With deterministic guards: 13<!--bind:static_suffixes int--> static hosting and CDN suffixes plus the bare github.io host are recognised so provider-owned headers are never scored against the client, 8<!--bind:parked_fingerprints int--> parked-page fingerprints keep parked domains out of the estate, RFC 2606 reserved names are skipped, and every resolution and HTTP probe passes through an SSRF block for loopback, private and cloud-metadata addresses. The benchmark exercises all of them with a 21<!--bind:guard_cases int-->-case self-test of which 21<!--bind:guard_passed int--> passed."
          }
        },
        {
          "@type": "Question",
          "name": "Is the security grading stable?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Re-running the current grading engine over the 52<!--bind:audits_parsed int--> stored client audits reproduces every published grade deterministically, and the parser reproduces the score printed in every delivered document. Across the live runs the grade was identical on every repeat for 5<!--bind:grade_stable_domains int--> of 5<!--bind:target_count int--> domains. Absolute correctness of the grades was not tested, because this dataset contains no human-graded ground truth."
          }
        },
        {
          "@type": "Question",
          "name": "Can I reproduce this benchmark on my own infrastructure?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Yes. Clone the repository, install the dependencies and run scripts/run_benchmark.py. Point it at a target file to audit an estate you are authorised to scan. The harness enforces a 1 request per second per host limit that cannot be configured lower, writes the same JSON structure, and writes null with a reason for any measurement it could not take."
          }
        },
        {
          "@type": "Question",
          "name": "Does this benchmark prove Orbit Security finds every vulnerability?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "No. It measures what the scanner knows, how its false-positive guards behave and how consistently its grader scores the same evidence. It does not measure a true-positive rate against a ground truth, it does not claim the scanned domains were vulnerability-free, and it does not cover the retainer ROI figure."
          }
        }
      ]
    },
    {
      "@type": "BreadcrumbList",
      "@id": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html#breadcrumb",
      "itemListElement": [
        {
          "@type": "ListItem",
          "position": 1,
          "name": "Home",
          "item": { "@id": "https://cmfh009.github.io/Orbit-Security/#website" }
        },
        {
          "@type": "ListItem",
          "position": 2,
          "name": "Benchmark",
          "item": { "@id": "https://cmfh009.github.io/Orbit-Security/benchmark/index.html#webpage" }
        }
      ]
    }
  ]
}
```
