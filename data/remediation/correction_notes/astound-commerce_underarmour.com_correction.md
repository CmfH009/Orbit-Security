Subject: Correction: revised audit score for underarmour.com - grade C (70/100)

Hi Astound Commerce team,

We sent you a client security audit for underarmour.com with a published grade of F (35/100). That grade was wrong. Our scoring model at the time penalised every finding flatly and counted best-practice configuration items as vulnerabilities. Re-scoring the same scan under the corrected model gives C (70/100).

Three finding classes drove the wrong grade: the SSL/TLS certificate expiring soon, the missing HTTP response hardening headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP) and the DMARC policy in inactive monitoring mode (p=none).

One critical or high finding in that report is unaffected by this correction and still needs attention.

The rule now: best-practice items are reported but never scored, a scan with no critical or high finding cannot score below 60, and repeated findings of the same class are charged at a reduced rate under a per-class cap.

Next step: reply to this note and we will re-issue the underarmour.com audit with the corrected grade and score. No change to the client's configuration is required to correct the score.

Best regards,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/

---

What changed
- Best-practice items (BIMI, MTA-STS, TLS-RPT, incomplete HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, security.txt) are still detected and still reported, but they are no longer scored as vulnerabilities.
- A scan with no critical and no high finding cannot score below 60 (grade C), so a failing grade always means exploitable risk.
- Repeated findings of the same class are charged at a reduced rate and each class is capped, so a large estate is not punished for being large.
- Grade bands are unchanged: A+ 95, A 88, B 75, C 60, D 45, F below 45.
