Subject: Correction: revised audit score for citgo.com - grade C (60/100)

Hi Redstage team,

We sent you a client security audit for citgo.com with a published grade of D (45/100). That grade was wrong. Our scoring model at the time penalised every finding flatly and counted best-practice configuration items as vulnerabilities. Re-scoring the same scan under the corrected model gives C (60/100).

Three finding classes drove the wrong grade: the SSL/TLS certificate verification failure, the SSL/TLS connection failure and the missing DNS and disclosure records (CAA, security.txt).

Two critical or high findings in that report are unaffected by this correction and still need attention.

The rule now: best-practice items are reported but never scored, a scan with no critical or high finding cannot score below 60, and repeated findings of the same class are charged at a reduced rate under a per-class cap.

Next step: reply to this note and we will re-issue the citgo.com audit with the corrected grade and score. No change to the client's configuration is required to correct the score.

Best regards,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/

---

What changed
- Best-practice items (MTA-STS, TLS-RPT, CAA, security.txt) are still detected and still reported, but they are no longer scored as vulnerabilities.
- A scan with no critical and no high finding cannot score below 60 (grade C), so a failing grade always means exploitable risk.
- Repeated findings of the same class are charged at a reduced rate and each class is capped, so a large estate is not punished for being large.
- Grade bands are unchanged: A+ 95, A 88, B 75, C 60, D 45, F below 45.
