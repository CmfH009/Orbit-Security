Subject: Correction: revised audit score for sennheiser.com - grade B (85/100)

Hi Latori team,

We sent you a client security audit for sennheiser.com with a published grade of D (50/100). That grade was wrong. Our scoring model at the time penalised every finding flatly and counted best-practice configuration items as vulnerabilities. Re-scoring the same scan under the corrected model gives B (85/100).

Three finding classes drove the wrong grade: the missing HSTS header (HTTP Strict Transport Security), the missing HTTP response hardening headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP) and the missing mail security records (BIMI, MTA-STS, TLS-RPT).

That scan returned no critical or high finding, so the published failure did not describe exploit risk.

The rule now: best-practice items are reported but never scored, a scan with no critical or high finding cannot score below 60, and repeated findings of the same class are charged at a reduced rate under a per-class cap.

Next step: reply to this note and we will re-issue the sennheiser.com audit with the corrected grade and score. No change to the client's configuration is required to correct the score.

Best regards,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/

---

What changed
- Best-practice items (BIMI, MTA-STS, TLS-RPT, CAA, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP) are still detected and still reported, but they are no longer scored as vulnerabilities.
- A scan with no critical and no high finding cannot score below 60 (grade C), so a failing grade always means exploitable risk.
- Repeated findings of the same class are charged at a reduced rate and each class is capped, so a large estate is not punished for being large.
- Grade bands are unchanged: A+ 95, A 88, B 75, C 60, D 45, F below 45.
