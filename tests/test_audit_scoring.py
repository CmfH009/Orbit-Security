"""Tests for the exploitability-aware audit scoring model.

Covers the 2026-10-22 scoring rewrite that replaced the flat
"penalty per finding" model which produced false "F" grades for domains with
zero CRITICAL and zero HIGH findings.

Rules under test (see ``orbit_security.scoring`` for the full spec):

R1. Best-practice-only items (BIMI, MTA-STS, TLS-RPT, CAA, missing CSP /
    X-Frame-Options / X-Content-Type-Options, incomplete HSTS, missing
    security.txt, ...) are reported but never scored.
R2. Zero CRITICAL + zero HIGH findings never scores below 60 (grade C).
R3. Repeats of the same finding class are discounted and capped.
R4. Genuinely dangerous findings keep their CRITICAL/HIGH/MEDIUM meaning.
R5. Grade bands are unchanged and a clean domain still scores 100 / A+.
"""

from __future__ import annotations

import pytest

from orbit_security.models import DomainAuditResult, Finding, Severity
from orbit_security.recon import calculate_score as recon_calculate_score
from orbit_security.scoring import (
    CLASS_PENALTY_CAP,
    EXPLOITABILITY_CEILING_SCORE,
    EXPLOITABILITY_FLOOR_SCORE,
    REPEAT_PENALTY,
    SEVERITY_PENALTY,
    ScoreItem,
    finding_class,
    grade_from_score,
    hygiene_class,
    is_hygiene_title,
    score_findings,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

#: The 13 best-practice-only items that produced the false "F / 40" grade for
#: aljazeera.com (Cohort 10, 2026-10-22).
BEST_PRACTICE_ONLY_FINDINGS = [
    ("Missing BIMI Brand Indicator (RFC 8617)", Severity.LOW),
    ("Missing MTA-STS Transport Security (RFC 8461)", Severity.LOW),
    ("Missing SMTP TLS Reporting (TLS-RPT RFC 8460)", Severity.INFO),
    ("Missing DNS CAA Policy (RFC 8659)", Severity.LOW),
    ("HSTS Header Incomplete (Subdomains or Preload)", Severity.INFO),
    ("Missing Content Security Policy (CSP)", Severity.LOW),
    ("Missing X-Frame-Options (Clickjacking Protection)", Severity.LOW),
    ("Missing X-Content-Type-Options (MIME Sniffing Defense)", Severity.LOW),
    ("Missing Referrer-Policy Header", Severity.LOW),
    ("Missing Permissions-Policy Header", Severity.INFO),
    ("Missing Cross-Origin-Opener-Policy (COOP)", Severity.INFO),
    ("Missing RFC 9116 Security Disclosure (security.txt)", Severity.LOW),
]


def make_finding(title: str, severity: Severity, target: str = "example.com") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category="Test",
        description=f"description for {title}",
        remediation="fix it",
        target=target,
        evidence="evidence",
    )


def make_audit(findings) -> DomainAuditResult:
    audit = DomainAuditResult(domain="example.com")
    for finding in findings:
        audit.findings.append(finding)
    return audit


# --------------------------------------------------------------------------- #
# R1 - hygiene vs. exploitable risk
# --------------------------------------------------------------------------- #


def test_best_practice_only_findings_never_grade_f():
    """13 hygiene-only findings must not produce an F grade.

    Regression test for the Cohort 10 false grade: aljazeera.com was graded
    "F (40/100)" with 13 findings and zero CRITICAL/HIGH findings.
    """
    findings = [make_finding(title, sev) for title, sev in BEST_PRACTICE_ONLY_FINDINGS]
    audit = make_audit(findings)
    grade, score = audit.calculate_grade_and_score()

    assert len(audit.findings) == 12
    assert grade != "F"
    assert grade in ("A+", "A", "B", "C")
    assert score >= 60


def test_thirteen_best_practice_only_findings_hold_the_c_floor():
    """A 13 item hygiene checklist (plus one LOW) stays at or above C / 60."""
    findings = [make_finding(title, sev) for title, sev in BEST_PRACTICE_ONLY_FINDINGS]
    findings.append(make_finding("Server / Tech Stack Version Disclosure", Severity.LOW))
    audit = make_audit(findings)
    grade, score = audit.calculate_grade_and_score()

    assert len(audit.findings) == 13
    assert grade != "F"
    assert grade in ("A+", "A", "B", "C")
    assert score >= 60


@pytest.mark.parametrize(
    "title",
    [
        "Missing BIMI Brand Indicator (RFC 8617)",
        "Missing MTA-STS Transport Security (RFC 8461)",
        "Missing SMTP TLS Reporting (TLS-RPT RFC 8460)",
        "Missing DNS CAA Policy (RFC 8659)",
        "Missing Content Security Policy (CSP)",
        "Missing X-Frame-Options (Clickjacking Protection)",
        "Missing X-Content-Type-Options (MIME Sniffing Defense)",
        "Missing Referrer-Policy Header",
        "Missing Permissions-Policy Header",
        "Missing Cross-Origin-Opener-Policy (COOP)",
        "HSTS Header Incomplete (Subdomains or Preload)",
        "Missing RFC 9116 Security Disclosure (security.txt)",
    ],
)
def test_hygiene_titles_are_classified_as_best_practice(title):
    assert is_hygiene_title(title) is True
    assert hygiene_class(title) is not None


def test_hygiene_findings_are_still_reported_in_the_deliverable():
    """Reclassification must not remove findings from the deliverable."""
    from orbit_security.reporter import ReportGenerator

    findings = [make_finding(title, sev) for title, sev in BEST_PRACTICE_ONLY_FINDINGS]
    audit = make_audit(findings)
    audit.calculate_grade_and_score()
    markdown = ReportGenerator.generate_markdown(audit)

    assert "Total Findings:** `12`" in markdown
    for title, _sev in BEST_PRACTICE_ONLY_FINDINGS:
        assert title in markdown


def test_missing_hsts_is_not_hygiene():
    """A completely missing HSTS header is a real downgrade risk (MEDIUM)."""
    assert is_hygiene_title("Missing HSTS Header (HTTP Strict Transport Security)") is False


# --------------------------------------------------------------------------- #
# R2 - exploitability floor
# --------------------------------------------------------------------------- #


def test_single_critical_is_graded_f_or_d():
    """One CRITICAL finding must still be able to fail the audit."""
    audit = make_audit(
        [make_finding("Dangling CNAME / Subdomain Takeover Risk (Unbounce)", Severity.CRITICAL)]
    )
    grade, score = audit.calculate_grade_and_score()

    assert grade in ("D", "F")
    assert score < 60


def test_zero_critical_high_never_falls_below_c():
    """R2: no CRITICAL and no HIGH -> grade >= C, whatever else was found."""
    findings = [
        make_finding(f"Missing Security Control {i}", Severity.MEDIUM) for i in range(12)
    ]
    audit = make_audit(findings)
    grade, score = audit.calculate_grade_and_score()

    assert grade in ("C", "B", "A", "A+")
    assert score >= EXPLOITABILITY_FLOOR_SCORE
    assert score >= 60


def test_exploitability_floor_is_not_applied_when_high_findings_exist():
    """A HIGH finding is a real risk, so the floor must not rescue the score."""
    audit = make_audit([make_finding("Missing DMARC Email Protection", Severity.HIGH)])
    grade, score = audit.calculate_grade_and_score()

    assert score == 80
    assert grade == "B"


def test_floor_does_not_rescue_a_critical():
    """A CRITICAL finding is capped at grade D - never C or better."""
    audit = make_audit(
        [make_finding("Exposed Environment Secrets (.env)", Severity.CRITICAL)]
    )
    grade, score = audit.calculate_grade_and_score()

    assert score == 59
    assert grade == "D"


def test_score_findings_reports_floor_application():
    result = score_findings(
        [ScoreItem(title=f"Missing Control {i}", severity=Severity.MEDIUM) for i in range(12)]
    )
    assert result.floor_applied is True
    assert result.score == EXPLOITABILITY_FLOOR_SCORE
    assert result.grade == "C"


# --------------------------------------------------------------------------- #
# R3 - diminishing returns
# --------------------------------------------------------------------------- #


def test_twenty_identical_findings_do_not_compound():
    """20 identical findings must not cost 20x a single finding.

    A finding class is capped at ``CLASS_PENALTY_CAP`` (~1.5x a single
    instance), so 20 identical LOW findings cost at most 8 points.
    """
    single = score_findings([ScoreItem(title="Some LOW issue", severity=Severity.LOW)])
    twenty = score_findings(
        [ScoreItem(title="Some LOW issue", severity=Severity.LOW) for _ in range(20)]
    )

    assert single.score == 95
    assert twenty.score == 92
    # Never worse than the documented per-class cap.
    assert single.score - twenty.score <= CLASS_PENALTY_CAP[Severity.LOW]


def test_twenty_identical_critical_findings_are_capped():
    """Even 20 identical CRITICALs of one class stay capped."""
    twenty = score_findings(
        [ScoreItem(title="Dangling CNAME / Subdomain Takeover Risk", severity=Severity.CRITICAL)
         for _ in range(20)]
    )

    assert twenty.penalty == CLASS_PENALTY_CAP[Severity.CRITICAL]
    assert twenty.score == 100 - CLASS_PENALTY_CAP[Severity.CRITICAL]


def test_repeat_findings_are_cheaper_than_distinct_ones():
    """The 20th identical finding must cost less than a 20th distinct one."""
    repeats = score_findings(
        [ScoreItem(title="Exposed Asset", severity=Severity.HIGH) for _ in range(20)]
    )
    distinct = score_findings(
        [ScoreItem(title=f"Exposed Asset {i}", severity=Severity.HIGH) for i in range(20)]
    )

    assert repeats.penalty < distinct.penalty
    assert repeats.score > distinct.score


def test_repeat_penalty_is_a_small_fraction_of_the_base_penalty():
    """Documented contract: a repeat is worth a fraction of the first hit."""
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        base = SEVERITY_PENALTY[severity]
        repeat = REPEAT_PENALTY[severity]
        assert repeat < base / 2


def test_finding_class_groups_the_same_issue_across_subdomains():
    """Same class, different hosts/paths -> one class key."""
    a = ScoreItem(title="Dangling CNAME / Subdomain Takeover Risk (Unbounce)", severity=Severity.CRITICAL)
    b = ScoreItem(title="Dangling CNAME / Subdomain Takeover Risk (NXDOMAIN Unbounce)", severity=Severity.CRITICAL)
    c = ScoreItem(title="Dangling CNAME / Subdomain Takeover Risk (Shopify)", severity=Severity.CRITICAL)

    assert finding_class(a) == finding_class(b) == finding_class(c)

    d = ScoreItem(title="Exposed Environment Secrets (.env)", severity=Severity.CRITICAL)
    assert finding_class(a) != finding_class(d)


# --------------------------------------------------------------------------- #
# R4 - honest severity semantics
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "title,severity",
    [
        ("Dangling CNAME / Subdomain Takeover Risk (Unbounce)", Severity.CRITICAL),
        ("Exposed Environment Secrets (.env)", Severity.CRITICAL),
        ("Exposed Git Repository Metadata (/.git)", Severity.CRITICAL),
        (
            "Exposed PHPUnit RCE Gadget (CVE-2017-9841 / eval-stdin.php)",
            Severity.CRITICAL,
        ),
        (
            "Exposed PHP Composer Dependency Tree (/vendor/composer/installed.json)",
            Severity.CRITICAL,
        ),
        ("Missing DMARC Email Protection", Severity.HIGH),
        ("SSL/TLS Certificate Expiring Soon (12 days left)", Severity.HIGH),
        ("SSL/TLS Certificate Expired", Severity.CRITICAL),
    ],
)
def test_dangerous_findings_keep_their_severity_and_weight(title, severity):
    """R4: dangerous items keep their real severity and still cost score."""
    assert is_hygiene_title(title) is False

    result = score_findings([ScoreItem(title=title, severity=severity)])
    assert result.penalty == SEVERITY_PENALTY[severity]
    if severity is Severity.CRITICAL:
        # A CRITICAL is capped at grade D (never C or better).
        assert result.score == EXPLOITABILITY_CEILING_SCORE
        assert result.grade == "D"
    else:
        assert result.score == 100 - SEVERITY_PENALTY[severity]


def test_missing_dmarc_is_at_least_medium():
    """Requirement: missing DMARC must remain at least MEDIUM."""
    assert SEVERITY_PENALTY[Severity.HIGH] >= SEVERITY_PENALTY[Severity.MEDIUM] > 0


# --------------------------------------------------------------------------- #
# R5 - stable bands
# --------------------------------------------------------------------------- #


def test_clean_domain_scores_100_and_a_plus():
    audit = make_audit([])
    grade, score = audit.calculate_grade_and_score()

    assert score == 100
    assert grade == "A+"


def test_info_only_findings_score_100():
    findings = [make_finding(title, sev) for title, sev in BEST_PRACTICE_ONLY_FINDINGS]
    audit = make_audit(findings)
    grade, score = audit.calculate_grade_and_score()

    assert score == 100
    assert grade == "A+"


@pytest.mark.parametrize(
    "score,expected",
    [
        (100, "A+"),
        (95, "A+"),
        (94, "A"),
        (88, "A"),
        (87, "B"),
        (75, "B"),
        (74, "C"),
        (60, "C"),
        (59, "D"),
        (45, "D"),
        (44, "F"),
        (0, "F"),
    ],
)
def test_grade_bands_are_unchanged(score, expected):
    assert grade_from_score(score) == expected


# --------------------------------------------------------------------------- #
# Two scoring paths must agree
# --------------------------------------------------------------------------- #


def test_recon_path_matches_the_audit_path():
    """`recon.calculate_score` and the deliverable share one model."""
    audit = make_audit([make_finding("Missing DMARC Email Protection", Severity.HIGH)])
    grade, score = audit.calculate_grade_and_score()

    recon_score = recon_calculate_score(
        {"dangling_risk": False, "mx_records": ["mail.example.com"]},
        {"missing_headers": [], "exposures": []},
    )
    # A clean recon posture is a clean audit posture.
    assert recon_score == 100
    assert score == 80 and grade == "B"


def test_recon_path_does_not_penalise_missing_best_practice_headers():
    """Missing hygiene headers must not drag the Recon score down either."""
    score = recon_calculate_score(
        {"dangling_risk": False, "mx_records": ["mail.example.com"]},
        {
            "missing_headers": [
                {"header": "Content-Security-Policy"},
                {"header": "X-Frame-Options"},
                {"header": "X-Content-Type-Options"},
                {"header": "Referrer-Policy"},
                {"header": "Permissions-Policy"},
                {"header": "Cross-Origin-Opener-Policy"},
            ],
            "exposures": [],
        },
    )
    assert score == 100


def test_recon_path_still_fails_on_dangerous_posture():
    score = recon_calculate_score(
        {"dangling_risk": True, "mx_records": []},
        {"missing_headers": [], "exposures": [{"path": "/.env"}]},
    )
    assert score < 60


def test_recon_path_scores_missing_hsts_as_medium():
    score = recon_calculate_score(
        {"dangling_risk": False, "mx_records": []},
        {"missing_headers": [{"header": "Strict-Transport-Security"}], "exposures": []},
    )
    assert score == 90
