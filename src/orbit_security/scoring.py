"""Shared, exploitability-aware scoring engine for Orbit Security audits.

This module is the single source of truth for:

* **Severity semantics** - what actually counts as a vulnerability.
* **Finding-class penalties with diminishing returns** - a large estate is not
  punished for being large.
* **The "no actively exploitable finding" score floor** - an F grade means
  *actively exploitable*, not "missed a few best-practice items".
* **The grade band ladder** - A+ / A / B / C / D / F.

Two independent code paths consume this engine so that the CLI, the cohort
scripts and the PDF/markdown deliverables can never disagree:

* ``orbit_security.models.DomainAuditResult.calculate_grade_and_score()``
  -> the client-facing audit deliverable.
* ``orbit_security.recon.calculate_score()``
  -> the Orbit Recon CLI / fleet perimeter matrix.

--------------------------------------------------------------------------
THE SCORING RULES (2026-10-22 rewrite)
--------------------------------------------------------------------------
R1. SEPARATE EXPLOITABLE RISK FROM HYGIENE CHECKLIST
    Best-practice-only items (BIMI, MTA-STS, TLS-RPT, CAA, missing
    CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy /
    Permissions-Policy / COOP, incomplete HSTS, missing security.txt) are
    *never* scored as vulnerabilities. They are still detected and still
    rendered into the deliverable - they are simply reported as INFO.
    See ``HYGIENE_CLASS_PATTERNS``.

R2. EXPLOITABILITY FLOOR *AND* CEILING
    A domain with **zero CRITICAL and zero HIGH** findings can never score
    below 60 (grade C). "F means actively exploitable." This is an explicit
    rule (``EXPLOITABILITY_FLOOR_SCORE``), not an accident of arithmetic.
    Symmetrically, a domain with **at least one CRITICAL** finding can never
    score above 59 (grade D at best) - an actively exploitable issue must
    never be presented as an "acceptable" (C or better) posture
    (``EXPLOITABILITY_CEILING_SCORE``).

R3. DIMINISHING RETURNS PER FINDING CLASS
    The first finding of a class costs the full severity weight. Additional
    findings of the *same* class cost a much smaller amount
    (``REPEAT_PENALTY``), and no class may ever cost more than
    ``CLASS_PENALTY_CAP`` (~1.5x a single instance).

R4. HONEST SEVERITY SEMANTICS
    Dangling CNAME / takeover, exposed ``.env`` / ``.git``, the PHPUnit
    eval-stdin RCE gadget (CVE-2017-9841), Composer dependency exposure,
    missing DMARC and SSL/TLS expiry keep real CRITICAL/HIGH/MEDIUM weight.

R5. STABLE BANDS
    A+ >= 95, A >= 88, B >= 75, C >= 60, D >= 45, F < 45.
    A clean domain still scores 100 / A+.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# --------------------------------------------------------------------------- #
# Severity ladder
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    """Severity ladder shared by the audit deliverable and the Recon CLI."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# --------------------------------------------------------------------------- #
# R1 - hygiene (best-practice-only) classes
# --------------------------------------------------------------------------- #

#: Canonical class keys for findings that are *hygiene*, not vulnerabilities.
#: These are detected and reported, but they never move the score.
HYGIENE_CLASS_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("bimi", re.compile(r"\bbimi\b")),
    ("mta-sts", re.compile(r"\bmta[\s\-_]?sts\b")),
    ("tls-rpt", re.compile(r"\btls[\s\-_]?rpt\b|tls reporting")),
    ("caa", re.compile(r"\bcaa\b")),
    ("content-security-policy", re.compile(r"content[\s\-_]?security[\s\-_]?policy|\bcsp\b")),
    ("x-frame-options", re.compile(r"x[\s\-_]?frame[\s\-_]?options")),
    ("x-content-type-options", re.compile(r"x[\s\-_]?content[\s\-_]?type[\s\-_]?options")),
    ("referrer-policy", re.compile(r"referrer[\s\-_]?policy")),
    ("permissions-policy", re.compile(r"permissions[\s\-_]?policy")),
    ("cross-origin-opener-policy", re.compile(r"cross[\s\-_]?origin[\s\-_]?opener[\s\-_]?policy|\bcoop\b")),
    ("hsts-incomplete", re.compile(r"hsts header incomplete")),
    ("security-txt", re.compile(r"security\.txt|security disclosure")),
)

#: Hosts where HTTP security headers / mail records are managed by the
#: provider edge and therefore cannot be fixed by the domain owner.
STATIC_HOST_SUFFIXES: Tuple[str, ...] = (
    ".github.io",
    ".pages.dev",
    ".vercel.app",
    ".netlify.app",
    ".gitlab.io",
    ".azurewebsites.net",
    ".render.com",
    ".onrender.com",
    ".fly.dev",
    ".webflow.io",
    ".surge.sh",
    ".firebaseapp.com",
    ".web.app",
)


def is_static_hosting_domain(domain: str) -> bool:
    """True when *domain* is served by a static host whose edge owns the headers."""
    clean = (domain or "").strip().lower()
    return clean == "github.io" or any(clean.endswith(s) for s in STATIC_HOST_SUFFIXES)


# --------------------------------------------------------------------------- #
# R3 - weights, repeats and per-class caps
# --------------------------------------------------------------------------- #

#: Penalty for the *first* finding of a class. These are the weights the
#: legacy flat model used, so genuinely dangerous findings keep their
#: historic impact on the score.
SEVERITY_PENALTY: Dict[Severity, int] = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

#: Penalty added by the 2nd..nth finding of the *same* class (R3).
REPEAT_PENALTY: Dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

#: Hard ceiling for a single finding class (R3). A class can never cost more
#: than ~1.5x a single instance, no matter how many hosts it was found on.
CLASS_PENALTY_CAP: Dict[Severity, int] = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 30,
    Severity.MEDIUM: 15,
    Severity.LOW: 8,
    Severity.INFO: 0,
}

#: R2 - score floor applied when nothing is actively exploitable.
EXPLOITABILITY_FLOOR_SCORE = 60

#: R2 - score ceiling applied when something *is* actively exploitable. One
#: CRITICAL finding must never leave the audit looking "acceptable" (C or
#: better), but a single finding also never produces an F - F is reserved for
#: a compounded / aggravated posture.
EXPLOITABILITY_CEILING_SCORE = 59

#: R5 - grade bands (unchanged from the legacy ladder).
GRADE_BANDS: Tuple[Tuple[str, int], ...] = (
    ("A+", 95),
    ("A", 88),
    ("B", 75),
    ("C", 60),
    ("D", 45),
    ("F", 0),
)


def grade_from_score(score: int) -> str:
    """Map a 0-100 score onto the A+/A/B/C/D/F ladder (R5)."""
    for band, floor in GRADE_BANDS:
        if score >= floor:
            return band
    return "F"


# --------------------------------------------------------------------------- #
# Finding classification helpers
# --------------------------------------------------------------------------- #

_PARENTHETICAL_RE = re.compile(r"\([^)]*\)")
_NON_KEY_RE = re.compile(r"[^a-z0-9/ ]+")


def normalize_class_key(title: str) -> str:
    """Collapse a finding title into a stable, repeatable class key.

    Parentheticals (RFC numbers, provider names, paths, day counts) are
    dropped so that the *same* class found on 20 subdomains shares one key,
    while genuinely different findings keep different keys.
    """
    text = (title or "").strip().lower()
    text = _PARENTHETICAL_RE.sub(" ", text)
    text = _NON_KEY_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text or "unknown"


def hygiene_class(title: str) -> Optional[str]:
    """Return the canonical hygiene class key for *title* (R1), else ``None``."""
    text = (title or "").lower()
    for key, pattern in HYGIENE_CLASS_PATTERNS:
        if pattern.search(text):
            return key
    return None


def is_hygiene_title(title: str) -> bool:
    """True when the title describes a best-practice-only item (R1)."""
    return hygiene_class(title) is not None


def coerce_severity(value: Any) -> Severity:
    """Coerce enum/str/None into a :class:`Severity` (unknown -> INFO)."""
    if isinstance(value, Severity):
        return value
    raw = getattr(value, "value", value)
    try:
        return Severity(str(raw).strip().upper())
    except (ValueError, AttributeError):
        return Severity.INFO


def item_weight(item: Any) -> int:
    """Scoring weight of a single finding.

    Returns ``0`` for hygiene / best-practice-only items, so they can never
    push a score down (R1), and for INFO findings.
    """
    if getattr(item, "hygiene", False):
        return 0
    title = str(getattr(item, "title", "") or "")
    if is_hygiene_title(title):
        return 0
    return SEVERITY_PENALTY.get(coerce_severity(getattr(item, "severity", None)), 0)


def finding_class(item: Any) -> str:
    """Canonical class key for a finding-like object (R3).

    An explicit ``class_key`` attribute wins (the Recon path supplies one for
    raw exposure paths); otherwise the key is derived from the title.
    """
    explicit = getattr(item, "class_key", None)
    if explicit:
        return str(explicit)
    title = str(getattr(item, "title", "") or "")
    hygiene = hygiene_class(title)
    if hygiene:
        return f"hygiene:{hygiene}"
    return normalize_class_key(title)


# --------------------------------------------------------------------------- #
# Score item / result containers
# --------------------------------------------------------------------------- #


@dataclass
class ScoreItem:
    """Lightweight, duck-typed finding used by the non-pydantic call sites."""

    title: str
    severity: Severity = Severity.INFO
    category: str = ""
    target: str = ""
    class_key: Optional[str] = None
    hygiene: bool = False


@dataclass
class AuditScore:
    """Result of scoring a set of findings."""

    score: int
    grade: str
    penalty: int
    has_critical: bool
    has_high: bool
    floor_applied: bool
    class_breakdown: Dict[str, int] = field(default_factory=dict)
    scored_findings: int = 0
    ignored_findings: int = 0


# --------------------------------------------------------------------------- #
# The engine
# --------------------------------------------------------------------------- #


def score_findings(findings: Iterable[Any]) -> AuditScore:
    """Score a collection of findings with the exploitability-aware model.

    * Hygiene / INFO findings contribute nothing (R1).
    * Each finding class is charged once at full weight; repeats of the same
      class are heavily discounted and the class total is capped (R3).
    * Zero CRITICAL + zero HIGH findings forces a floor of 60 / grade C (R2).
    """
    groups: Dict[str, List[Severity]] = {}
    has_critical = False
    has_high = False
    scored = 0
    ignored = 0

    for finding in findings or []:
        severity = coerce_severity(getattr(finding, "severity", None))
        if severity is Severity.CRITICAL:
            has_critical = True
        elif severity is Severity.HIGH:
            has_high = True

        if item_weight(finding) == 0:
            ignored += 1
            continue

        scored += 1
        groups.setdefault(finding_class(finding), []).append(severity)

    penalty = 0
    breakdown: Dict[str, int] = {}
    for key, severities in groups.items():
        # The most severe instance of the class sets the price for the class.
        severities.sort(key=lambda s: SEVERITY_PENALTY.get(s, 0), reverse=True)
        base_severity = severities[0]
        base = SEVERITY_PENALTY.get(base_severity, 0)
        repeat_cost = sum(REPEAT_PENALTY.get(base_severity, 0) for _ in severities[1:])
        contribution = min(base + repeat_cost, CLASS_PENALTY_CAP.get(base_severity, base))
        breakdown[key] = contribution
        penalty += contribution

    score = max(0, min(100, 100 - penalty))

    # R2 - explicit exploitability floor and ceiling.
    floor_applied = False
    if not has_critical and not has_high:
        if score < EXPLOITABILITY_FLOOR_SCORE:
            score = EXPLOITABILITY_FLOOR_SCORE
            floor_applied = True
    if has_critical and score > EXPLOITABILITY_CEILING_SCORE:
        score = EXPLOITABILITY_CEILING_SCORE

    return AuditScore(
        score=score,
        grade=grade_from_score(score),
        penalty=penalty,
        has_critical=has_critical,
        has_high=has_high,
        floor_applied=floor_applied,
        class_breakdown=breakdown,
        scored_findings=scored,
        ignored_findings=ignored,
    )


def calculate_score_and_grade(findings: Iterable[Any]) -> Tuple[str, int]:
    """Convenience wrapper returning ``(grade, score)`` like the legacy API."""
    result = score_findings(findings)
    return result.grade, result.score


# --------------------------------------------------------------------------- #
# Shared posture vocabulary (used by both the scanner and the Recon CLI)
# --------------------------------------------------------------------------- #

#: Canonical titles for missing HTTP security headers. Using the same title in
#: both paths guarantees the same class key, and therefore the same score.
MISSING_HEADER_TITLES: Dict[str, str] = {
    "Strict-Transport-Security": "Missing HSTS Header (HTTP Strict Transport Security)",
    "Content-Security-Policy": "Missing Content Security Policy (CSP)",
    "X-Frame-Options": "Missing X-Frame-Options (Clickjacking Protection)",
    "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME Sniffing Defense)",
    "Referrer-Policy": "Missing Referrer-Policy Header",
    "Permissions-Policy": "Missing Permissions-Policy Header",
    "Cross-Origin-Opener-Policy": "Missing Cross-Origin-Opener-Policy (COOP)",
}

#: Missing HSTS entirely is a genuine transport risk (MEDIUM). Every other
#: missing header is hygiene (INFO) and never costs score (R1).
MISSING_HEADER_SEVERITY: Dict[str, Severity] = {
    "Strict-Transport-Security": Severity.MEDIUM,
}

#: Publicly reachable secret files keep their true severity (R4).
EXPOSURE_SEVERITY: Dict[str, Severity] = {
    "/.env": Severity.CRITICAL,
    "/.env.local": Severity.CRITICAL,
    "/.git/HEAD": Severity.CRITICAL,
    "/.git/config": Severity.CRITICAL,
    "/.git/index": Severity.CRITICAL,
    "/wp-config.php.bak": Severity.CRITICAL,
    "/wp-config.php.old": Severity.CRITICAL,
    "/vendor/composer/installed.json": Severity.CRITICAL,
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": Severity.CRITICAL,
    "/docker-compose.yml": Severity.HIGH,
    "/phpinfo.php": Severity.HIGH,
    "/.DS_Store": Severity.LOW,
}

#: Anything not in the table above is treated as an unknown exposure -> CRITICAL.
DEFAULT_EXPOSURE_SEVERITY = Severity.CRITICAL

#: Canonical title for a dangling CNAME (subdomain takeover) - the single most
#: dangerous class we detect.
TAKEOVER_TITLE = "Dangling CNAME / Subdomain Takeover Risk"

#: Class key used for every takeover finding, regardless of the provider
#: suffix that the scanner adds to the title.
TAKEOVER_CLASS_KEY = "dangling-cname-takeover"


def missing_header_severity(header: str, domain: str = "") -> Severity:
    """Severity for a missing HTTP security header.

    Missing HSTS is MEDIUM (a real downgrade risk) unless the domain is served
    by a static host whose edge owns HSTS. Everything else is hygiene/INFO.
    """
    if is_static_hosting_domain(domain):
        return Severity.INFO
    return MISSING_HEADER_SEVERITY.get(header, Severity.INFO)


def exposure_severity(path: str) -> Severity:
    """Severity for a publicly reachable sensitive path (R4)."""
    return EXPOSURE_SEVERITY.get(path, DEFAULT_EXPOSURE_SEVERITY)


def evaluate_zero_knowledge_fleet_scorecard(
    domains_payload: Sequence[Dict[str, Any]],
    agency_name: str = "Agency Partner",
) -> Dict[str, Any]:
    """Evaluates a multi-domain agency portfolio in-memory under R1-R5 rules (Project #9).

    Zero-Knowledge Guarantee:
    - Operates purely on in-memory domain/finding payloads.
    - Writes zero state, logs, or PII to disk.
    - Returns a deterministic SHA-256 verification digest over the normalized scorecard.
    """
    import hashlib
    import json

    clean_agency = (agency_name or "Agency Partner").strip()
    domain_results: List[Dict[str, Any]] = []

    for entry in domains_payload or []:
        dom = str(entry.get("domain", "") or "").strip().lower()
        if not dom:
            continue
        raw_findings = entry.get("findings") or []
        score_items: List[ScoreItem] = []
        for f in raw_findings:
            if isinstance(f, ScoreItem):
                score_items.append(f)
            elif isinstance(f, dict):
                score_items.append(
                    ScoreItem(
                        title=str(f.get("title", "")),
                        severity=coerce_severity(f.get("severity", "INFO")),
                        category=str(f.get("category", "")),
                        target=str(f.get("target", dom)),
                        class_key=f.get("class_key"),
                        hygiene=bool(f.get("hygiene", False)),
                    )
                )
            else:
                score_items.append(
                    ScoreItem(
                        title=str(getattr(f, "title", "")),
                        severity=coerce_severity(getattr(f, "severity", "INFO")),
                        category=str(getattr(f, "category", "")),
                        target=str(getattr(f, "target", dom)),
                        class_key=getattr(f, "class_key", None),
                        hygiene=bool(getattr(f, "hygiene", False)),
                    )
                )

        audit_score = score_findings(score_items)
        domain_results.append(
            {
                "domain": dom,
                "score": audit_score.score,
                "grade": audit_score.grade,
                "penalty": audit_score.penalty,
                "has_critical": audit_score.has_critical,
                "has_high": audit_score.has_high,
                "floor_applied": audit_score.floor_applied,
                "scored_findings": audit_score.scored_findings,
                "hygiene_only_findings": audit_score.ignored_findings,
            }
        )

    total_domains = len(domain_results)
    avg_score = int(round(sum(d["score"] for d in domain_results) / total_domains)) if total_domains else 100
    fleet_grade = grade_from_score(avg_score)
    at_risk_domains = sum(
        1 for d in domain_results if d["has_critical"] or d["has_high"] or d["score"] < 75
    )

    canonical_digest_payload = json.dumps(
        {
            "agency_name": clean_agency,
            "total_domains": total_domains,
            "fleet_score": avg_score,
            "fleet_grade": fleet_grade,
            "domains": [
                {
                    "domain": d["domain"],
                    "score": d["score"],
                    "grade": d["grade"],
                    "scored_findings": d["scored_findings"],
                }
                for d in domain_results
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    zk_hash = hashlib.sha256(canonical_digest_payload.encode("utf-8")).hexdigest()

    return {
        "agency_name": clean_agency,
        "zero_knowledge_mode": True,
        "server_storage_persisted": False,
        "total_domains": total_domains,
        "fleet_score": avg_score,
        "fleet_grade": fleet_grade,
        "at_risk_domains": at_risk_domains,
        "domain_results": domain_results,
        "zk_verification_sha256": zk_hash,
    }


__all__: Sequence[str] = (
    "AuditScore",
    "CLASS_PENALTY_CAP",
    "DEFAULT_EXPOSURE_SEVERITY",
    "EXPOSURE_SEVERITY",
    "EXPLOITABILITY_CEILING_SCORE",
    "EXPLOITABILITY_FLOOR_SCORE",
    "GRADE_BANDS",
    "HYGIENE_CLASS_PATTERNS",
    "MISSING_HEADER_SEVERITY",
    "MISSING_HEADER_TITLES",
    "REPEAT_PENALTY",
    "SEVERITY_PENALTY",
    "STATIC_HOST_SUFFIXES",
    "ScoreItem",
    "Severity",
    "TAKEOVER_CLASS_KEY",
    "TAKEOVER_TITLE",
    "calculate_score_and_grade",
    "coerce_severity",
    "evaluate_zero_knowledge_fleet_scorecard",
    "exposure_severity",
    "finding_class",
    "grade_from_score",
    "hygiene_class",
    "is_hygiene_title",
    "is_static_hosting_domain",
    "item_weight",
    "missing_header_severity",
    "normalize_class_key",
    "score_findings",
)
