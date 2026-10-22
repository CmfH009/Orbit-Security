#!/usr/bin/env python3
"""Build the customer-facing audit remediation pack for agencies that received a wrong score.

Between 2026-10-20 and 2026-10-22 five outreach cohorts (6-10) shipped 52 client
security audits.  The scoring model that produced those grades penalised every
finding flatly (CRITICAL 35 / HIGH 20 / MEDIUM 10 / LOW 5) with no notion of
finding class, no exploitability floor and no cap on repeated classes, so 18 of
the 52 audits shipped a failing D/F grade - several of them with zero critical
or high findings.

This script rebuilds the remediation pack from the on-disk evidence:

* reads every ``data/generated_audits/*/*_audit.md`` (READ ONLY),
* re-scores each one with the legacy model *and* with the current
  ``orbit_security.scoring`` engine,
* joins each audit to its cohort record (``client_domain`` + ``agency_domain``)
  so the contact address, agency name and cohort number are known,
* classifies every affected (published D/F) audit as ``rescued`` or
  ``still_failing``,
* writes a ready-to-send correction note and a staged ``.eml`` for every
  **rescued** audit only, plus a manifest, an operator summary and a README.

Nothing outside ``data/remediation/`` is written.  No mail is sent and no PDF is
regenerated.

Usage:
    .venv\\Scripts\\python.exe scripts\\build_audit_remediation.py
    .venv\\Scripts\\python.exe scripts\\build_audit_remediation.py --date 2026-10-22T15:00:00+00:00
    .venv\\Scripts\\python.exe scripts\\build_audit_remediation.py --verify-only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:  # namespace-package import (repo root on sys.path)
    from scripts.rescore_audit_evidence import (  # noqa: E402
        AUDIT_ROOT,
        LEGACY_PENALTY,
        parse_audit,
        rescore,
    )
except ImportError:  # pragma: no cover - fallback for a direct-script invocation
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from rescore_audit_evidence import (  # noqa: E402
        AUDIT_ROOT,
        LEGACY_PENALTY,
        parse_audit,
        rescore,
    )

from orbit_security.scoring import (  # noqa: E402
    ScoreItem,
    Severity,
    finding_class,
    hygiene_class,
)


# --------------------------------------------------------------------------- #
# Paths & constants
# --------------------------------------------------------------------------- #

DATA_DIR = REPO_ROOT / "data"
REMEDIATION_DIR = DATA_DIR / "remediation"
NOTES_DIR = REMEDIATION_DIR / "correction_notes"
EMAILS_DIR = REMEDIATION_DIR / "correction_emails"
MANIFEST_PATH = REMEDIATION_DIR / "remediation_manifest.json"
SUMMARY_PATH = REMEDIATION_DIR / "summary.md"
README_PATH = REMEDIATION_DIR / "README.md"

COHORTS: Tuple[int, ...] = (6, 7, 8, 9, 10)

FAILING_GRADES = ("D", "F")

#: House sender identity - matches the From/Reply-To of every staged campaign email.
SENDER_NAME = '"Carson | Founder", Orbit Security'
SENDER_EMAIL = "carsonmail009@gmail.com"
SENDER_SIGNATURE = (
    "Best regards,\n"
    "Carson Haynes\n"
    "Founder, Orbit Security\n"
    "carsonmail009@gmail.com\n"
    "https://cmfh009.github.io/Orbit-Security/"
)

#: Readable short names for the engine's canonical hygiene classes.
HYGIENE_SHORT: Dict[str, str] = {
    "bimi": "BIMI",
    "mta-sts": "MTA-STS",
    "tls-rpt": "TLS-RPT",
    "caa": "CAA",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "hsts-incomplete": "incomplete HSTS",
    "security-txt": "security.txt",
}

#: Hygiene classes are grouped into three readable buckets for the correction note.
HYGIENE_GROUP: Dict[str, str] = {
    "bimi": "mail-records",
    "mta-sts": "mail-records",
    "tls-rpt": "mail-records",
    "caa": "dns-disclosure",
    "hsts-incomplete": "dns-disclosure",
    "security-txt": "dns-disclosure",
    "content-security-policy": "http-headers",
    "x-frame-options": "http-headers",
    "x-content-type-options": "http-headers",
    "referrer-policy": "http-headers",
    "permissions-policy": "http-headers",
    "cross-origin-opener-policy": "http-headers",
}

HYGIENE_GROUP_LABEL: Dict[str, str] = {
    "mail-records": "missing mail security records",
    "dns-disclosure": "missing DNS and disclosure records",
    "http-headers": "missing HTTP response hardening headers",
}

#: RFC references and countdowns are stripped from titles used inside prose.
_RFC_PAREN = re.compile(r"\([^()]*\bRFC\s*\d+[^()]*\)")
_COUNTDOWN_PAREN = re.compile(r"\(\s*\d+\s*days?\s+left\s*\)")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def rel_to_repo(path) -> str:
    """Return *path* relative to the repo root, POSIX style."""
    path = Path(path)
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def clean_title(title: str) -> str:
    """Strip RFC references / day countdowns from a finding title."""
    text = _RFC_PAREN.sub("", title or "")
    text = _COUNTDOWN_PAREN.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text.strip(" -")


def sentence_case(text: str) -> str:
    """Lower-case the first character only when it is not an acronym."""
    if not text:
        return text
    if len(text) > 1 and text[1].islower():
        return text[0].lower() + text[1:]
    return text


def prose_title(title: str) -> str:
    """Render a finding title for use inside prose.

    Acronyms (SSL/TLS, HSTS, DMARC) keep their capitals; everything else in the
    head of the title is lower-cased. A trailing parenthetical is kept verbatim.
    """
    text = clean_title(title)
    head, sep, tail = text.partition(" (")
    words = head.split(" ")
    out: List[str] = []
    for word in words:
        core = word.strip("(),.;:")
        if core.isupper() and len(core) > 1:
            out.append(word)
        elif out:
            out.append(word.lower())
        else:
            out.append(word[:1].lower() + word[1:] if word else word)
    return " ".join(out) + ((" (" + tail) if sep else "")


def count_words(text: str) -> int:
    return len([w for w in re.split(r"\s+", text.strip()) if w])


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Cohort records
# --------------------------------------------------------------------------- #


def load_cohort_records() -> List[dict]:
    """Load every cohort 6-10 staged manifest and tag it with its cohort number."""
    records: List[dict] = []
    for cohort in COHORTS:
        path = DATA_DIR / f"cohort_{cohort}_staged.json"
        if not path.exists():
            print(f"[!] cohort manifest not found: {path}")
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        for rec in raw:
            item = dict(rec)
            item["cohort"] = cohort
            records.append(item)
    return records


def index_cohort_records(records: Sequence[dict]) -> Dict[str, dict]:
    """Index cohort records by lower-cased client domain (verified unique)."""
    index: Dict[str, dict] = {}
    for rec in records:
        key = str(rec.get("client_domain", "")).strip().lower()
        if not key:
            continue
        if key in index:
            raise SystemExit(
                f"Duplicate client_domain across cohort manifests: {key} "
                f"(cohorts {index[key]['cohort']} and {rec['cohort']})"
            )
        index[key] = rec
    return index


PREPARED_BY_RE = re.compile(
    r"\*\*Prepared By:\*\*\s*(?P<name>[^(]+?)\s*(?:\(Managed Web[^)]*\))?\s*$",
    re.MULTILINE,
)
CONTACT_RE = re.compile(
    r"please contact\s+\*\*(?P<name>[^*]+)\*\*\s+at\s+\[(?P<email>[^\]]+)\]"
    r"\(mailto:(?P<email2>[^\)]+)\)",
    re.IGNORECASE,
)
VISIT_RE = re.compile(r"or visit \[https?://(?P<domain>[^\]\s]+)\]", re.IGNORECASE)


def extract_audit_identity(text: str) -> Dict[str, Optional[str]]:
    """Recover the agency identity from an audit body.

    The delivered audit carries its own co-branding footer, so an audit that is
    not in a cohort manifest is not necessarily contact-less.
    """
    identity: Dict[str, Optional[str]] = {
        "agency_name": None,
        "agency_domain": None,
        "contact_email": None,
    }

    prepared = PREPARED_BY_RE.search(text or "")
    if prepared:
        identity["agency_name"] = prepared.group("name").strip()

    contact = CONTACT_RE.search(text or "")
    if contact:
        identity["contact_email"] = contact.group("email2").strip()

    visit = VISIT_RE.search(text or "")
    if visit:
        identity["agency_domain"] = visit.group("domain").strip().lower()

    return identity


def lookup_dispatched(client_domain: str, agency_domain: Optional[str] = None) -> Optional[dict]:
    """Best-effort lookup of an audit in data/dispatched_campaigns.json.

    Used only to give the operator context for audits that cannot be joined to
    a cohort 6-10 manifest.
    """
    path = DATA_DIR / "dispatched_campaigns.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None

    needle = client_domain.strip().lower()
    if agency_domain:
        rec = data.get(agency_domain.strip().lower())
        if isinstance(rec, dict):
            out = dict(rec)
            out["agency_domain"] = agency_domain
            out.setdefault("client_domain", client_domain)
            return out

    for key, rec in data.items():
        if not isinstance(rec, dict):
            continue
        if str(rec.get("client_domain", "")).strip().lower() == needle:
            out = dict(rec)
            out["agency_domain"] = key
            return out
    return None


# --------------------------------------------------------------------------- #
# Finding-class attribution (which classes caused the wrong grade?)
# --------------------------------------------------------------------------- #


def build_buckets(findings) -> List[dict]:
    """Group findings into scoring classes and attribute legacy penalty points.

    * Hygiene findings collapse into three readable buckets (mail records, HTTP
      response hardening headers, DNS / disclosure records).
    * Everything else is grouped by the engine's own ``finding_class`` key.
    """
    buckets: Dict[str, dict] = {}
    order: List[str] = []

    for index, finding in enumerate(findings):
        item = ScoreItem(title=finding.title, severity=Severity(finding.severity))
        legacy_points = LEGACY_PENALTY.get(finding.severity, 0)
        hygiene_key = hygiene_class(finding.title)

        if hygiene_key:
            group = HYGIENE_GROUP.get(hygiene_key, "other")
            key = f"hygiene:{group}"
            label = HYGIENE_GROUP_LABEL.get(group, "missing best-practice configuration")
            member = HYGIENE_SHORT.get(hygiene_key, hygiene_key)
            members = [member]
        else:
            key = f"finding:{finding_class(item)}"
            label = clean_title(finding.title)
            members = [label]

        if key not in buckets:
            buckets[key] = {
                "key": key,
                "label": label,
                "hygiene": bool(hygiene_key),
                "legacy_points": 0,
                "members": [],
                "first_index": index,
                "titles": [],
                "severities": [],
            }
            order.append(key)

        bucket = buckets[key]
        bucket["legacy_points"] += legacy_points
        for member in members:
            if member not in bucket["members"]:
                bucket["members"].append(member)
        bucket["titles"].append(finding.title)
        bucket["severities"].append(finding.severity)

    result = [buckets[key] for key in order]

    # Label a non-hygiene class with the title of its most severe member.
    for bucket in result:
        if bucket["hygiene"]:
            continue
        best = max(
            zip(bucket["titles"], bucket["severities"]),
            key=lambda pair: LEGACY_PENALTY.get(pair[1], 0),
        )
        bucket["label"] = clean_title(best[0])

    return result


def select_causes(buckets: Sequence[dict], limit: int = 3) -> List[dict]:
    """Pick the 2-3 finding classes that drove the wrong published grade.

    The highest-scoring *genuine* (non-hygiene) class is always included; the
    remaining slots go to the classes that carried the most legacy penalty.
    """
    if not buckets:
        return []

    genuine = [b for b in buckets if not b["hygiene"]]
    primary: Optional[dict] = None
    if genuine:
        primary = sorted(
            genuine, key=lambda b: (-b["legacy_points"], b["first_index"])
        )[0]

    ranked = sorted(buckets, key=lambda b: (-b["legacy_points"], b["first_index"]))
    selected: List[dict] = []
    if primary is not None:
        selected.append(primary)
    for bucket in ranked:
        if len(selected) >= limit:
            break
        if primary is not None and bucket["key"] == primary["key"]:
            continue
        selected.append(bucket)

    return selected


def clause_for(bucket: dict) -> str:
    """Render one finding class as a prose clause."""
    label = bucket["label"]
    if bucket["hygiene"]:
        members = ", ".join(bucket["members"])
        return f"the {sentence_case(label)} ({members})"
    return f"the {prose_title(label)}"


def join_clauses(clauses: Sequence[str]) -> str:
    if not clauses:
        return ""
    if len(clauses) == 1:
        return clauses[0]
    return ", ".join(clauses[:-1]) + " and " + clauses[-1]


# --------------------------------------------------------------------------- #
# Correction note / e-mail rendering
# --------------------------------------------------------------------------- #


def build_what_changed(hygiene_present: Sequence[str]) -> List[str]:
    """The factual rule-change bullets attached to every correction note."""
    if hygiene_present:
        listed = ", ".join(hygiene_present)
        hygiene_line = (
            f"Best-practice items ({listed}) are still detected and still reported, "
            "but they are no longer scored as vulnerabilities."
        )
    else:
        hygiene_line = (
            "Best-practice items are still detected and still reported, but they are "
            "no longer scored as vulnerabilities."
        )
    return [
        hygiene_line,
        "A scan with no critical and no high finding cannot score below 60 (grade C), "
        "so a failing grade always means exploitable risk.",
        "Repeated findings of the same class are charged at a reduced rate and each "
        "class is capped, so a large estate is not punished for being large.",
        "Grade bands are unchanged: A+ 95, A 88, B 75, C 60, D 45, F below 45.",
    ]


def render_note_body(record: dict) -> Tuple[str, str]:
    """Return ``(subject, body)`` for a rescued audit's correction note."""
    agency_name = record["agency_name"]
    client_domain = record["client_domain"]
    old_grade = record["old_grade"]
    old_score = record["old_score"]
    new_grade = record["new_grade"]
    new_score = record["new_score"]

    causes = record["cause_classes"]
    clauses = [clause_for(bucket) for bucket in causes]
    count_word = {1: "One", 2: "Two", 3: "Three"}.get(len(clauses), str(len(clauses)))
    cause_sentence = (
        f"{count_word} finding class{'es' if len(clauses) != 1 else ''} drove the wrong "
        f"grade: {join_clauses(clauses)}."
    )

    # Integrity clause: the correction is to the score, not to the findings.
    critical_high = record["findings_by_severity"].get("CRITICAL", 0) + record[
        "findings_by_severity"
    ].get("HIGH", 0)
    if critical_high:
        spelled = {
            1: "One",
            2: "Two",
            3: "Three",
            4: "Four",
            5: "Five",
            6: "Six",
            7: "Seven",
            8: "Eight",
            9: "Nine",
            10: "Ten",
        }.get(critical_high, str(critical_high))
        if critical_high == 1:
            integrity_sentence = (
                f"{spelled} critical or high finding in that report is unaffected by this "
                "correction and still needs attention."
            )
        else:
            integrity_sentence = (
                f"{spelled} critical or high findings in that report are unaffected by "
                "this correction and still need attention."
            )
    else:
        integrity_sentence = (
            "That scan returned no critical or high finding, so the published failure did "
            "not describe exploit risk."
        )

    subject = (
        f"Correction: revised audit score for {client_domain} - "
        f"grade {new_grade} ({new_score}/100)"
    )

    paragraphs = [
        f"Hi {agency_name} team,",
        "",
        f"We sent you a client security audit for {client_domain} with a published grade "
        f"of {old_grade} ({old_score}/100). That grade was wrong. Our scoring model "
        f"at the time penalised every finding flatly and counted best-practice "
        f"configuration items as vulnerabilities. Re-scoring the same scan under the "
        f"corrected model gives {new_grade} ({new_score}/100).",
        "",
        cause_sentence,
        "",
        integrity_sentence,
        "",
        "The rule now: best-practice items are reported but never scored, a scan with no "
        "critical or high finding cannot score below 60, and repeated findings of the "
        "same class are charged at a reduced rate under a per-class cap.",
        "",
        f"Next step: reply to this note and we will re-issue the {client_domain} audit "
        f"with the corrected grade and score. No change to the client's configuration is "
        f"required to correct the score.",
        "",
        SENDER_SIGNATURE,
    ]

    body = "\n".join(paragraphs).rstrip() + "\n"
    return subject, body


def render_eml_body(body: str, what_changed: Sequence[str]) -> str:
    """Plain-text e-mail body: the note prose plus the factual rule-change list."""
    lines = [body.rstrip(), "", "What changed:", ""]
    lines.extend(f"- {bullet}" for bullet in what_changed)
    return "\n".join(lines).rstrip() + "\n"


def build_eml(recipient: str, subject: str, body: str, when: datetime, msgid: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Reply-To"] = SENDER_EMAIL
    msg["Date"] = format_datetime(when)
    msg["Message-ID"] = msgid
    msg.set_content(body)
    return msg.as_bytes()


def deterministic_msgid(agency_slug: str, client_domain: str) -> str:
    """A stable, reproducible Message-ID (Python's hash() is salted per run)."""
    digest = hashlib.sha1(
        f"{agency_slug}|{client_domain}".encode("utf-8")
    ).hexdigest()[:16]
    return f"<orbit-correction.{agency_slug}.{digest}@cmfh009.github.io>"


# --------------------------------------------------------------------------- #
# Pack assembly
# --------------------------------------------------------------------------- #


def collect_audits(cohort_index: Dict[str, dict], audits_root: Path) -> List[dict]:
    """Parse + re-score every stored audit and join it to its cohort record."""
    rows: List[dict] = []
    files = sorted(audits_root.glob("*/*_audit.md"))
    for path in files:
        agency_slug = path.parent.name
        client_domain = path.name[: -len("_audit.md")]
        parsed = parse_audit(path)
        scored = rescore(parsed)

        text = path.read_text(encoding="utf-8")
        cohort_rec = cohort_index.get(client_domain.lower())

        severities = [f.severity for f in parsed.findings]
        counts = {sev: severities.count(sev) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

        buckets = build_buckets(parsed.findings)
        hygiene_present: List[str] = []
        for finding in parsed.findings:
            key = hygiene_class(finding.title)
            if key:
                short = HYGIENE_SHORT.get(key, key)
                if short not in hygiene_present:
                    hygiene_present.append(short)

        join_status = "joined"
        join_note = ""
        identity = extract_audit_identity(text)
        if cohort_rec is None:
            join_status = "unjoinable"
            join_note = (
                f"no cohort 6-10 manifest contains client_domain {client_domain!r}"
            )
        else:
            agency_domain = str(cohort_rec.get("agency_domain", "")).lower()
            if agency_domain and agency_domain not in text.lower():
                join_status = "unjoinable"
                join_note = (
                    f"agency_domain {agency_domain!r} from cohort {cohort_rec['cohort']} "
                    "does not appear in the audit body"
                )

        unparseable = (
            parsed.header_grade is None
            or parsed.header_score is None
            or not parsed.findings
        )
        if unparseable and join_status == "joined":
            join_note = join_note or "audit could not be parsed into findings/grade"

        # Legacy model must reproduce the published header, otherwise the audit
        # was not produced by the model we are correcting.
        legacy_matches_header = (
            parsed.header_score is not None and parsed.header_score == scored["old_score"]
        )

        row = {
            "agency_slug": agency_slug,
            "client_domain": client_domain,
            "audit_file": rel_to_repo(path),
            "audit_path": str(path),
            "cohort": cohort_rec.get("cohort") if cohort_rec else None,
            "agency_name": (
                cohort_rec.get("agency_name")
                if cohort_rec
                else identity["agency_name"]
            ),
            "agency_domain": (
                cohort_rec.get("agency_domain")
                if cohort_rec
                else identity["agency_domain"]
            ),
            "contact_email": (
                cohort_rec.get("contact_email")
                if cohort_rec
                else identity["contact_email"]
            ),
            "identity_recovered_from_audit": cohort_rec is None,
            "published_score": parsed.header_score,
            "published_grade": parsed.header_grade,
            "old_score": scored["old_score"],
            "old_grade": scored["old_grade"],
            "new_score": scored["new_score"],
            "new_grade": scored["new_grade"],
            "delta": scored["delta"],
            "floor_applied": scored["floor_applied"],
            "findings_total": scored["findings"],
            "findings_by_severity": counts,
            "findings_hygiene": sum(
                1 for f in parsed.findings if hygiene_class(f.title)
            ),
            "legacy_matches_published_header": legacy_matches_header,
            "join_status": join_status,
            "join_note": join_note,
            "unparseable": unparseable,
            "buckets": buckets,
            "hygiene_present": hygiene_present,
            "cohort_record": cohort_rec,
            "audit_text": text,
        }
        rows.append(row)
    return rows


def classify(row: dict) -> Optional[str]:
    """``rescued`` / ``still_failing`` for an affected audit, else ``None``."""
    if row["unparseable"]:
        return None
    if row["old_grade"] not in FAILING_GRADES:
        return None
    if not row["contact_email"]:
        # Affected but with no address on file - cannot be corrected, only flagged.
        return None
    if row["new_grade"] in FAILING_GRADES:
        return "still_failing"
    return "rescued"


def resolve_pdf(row: dict, audits_root: Path) -> Tuple[bool, Optional[str], Optional[str]]:
    """Was the PDF actually delivered? Check the recorded path, then the repo copy."""
    cohort_rec = row["cohort_record"]
    if not cohort_rec:
        return False, None, None
    recorded = cohort_rec.get("pdf_path")
    recorded_exists = bool(recorded) and Path(recorded).exists()
    fallback = audits_root / row["agency_slug"] / f"{row['client_domain']}_audit.pdf"
    fallback_exists = fallback.exists()
    delivered = recorded_exists or fallback_exists
    used = None
    if recorded_exists:
        used = str(recorded)
    elif fallback_exists:
        used = str(fallback)
    return delivered, used, rel_to_repo(fallback) if fallback_exists else None


def build_pack(when: datetime, audits_root: Path = AUDIT_ROOT) -> dict:
    cohort_records = load_cohort_records()
    cohort_index = index_cohort_records(cohort_records)
    rows = collect_audits(cohort_index, audits_root)

    affected: List[dict] = []
    unaffected: List[dict] = []
    unjoinable: List[dict] = []
    unparseable: List[dict] = []

    notes_written: List[str] = []
    emails_written: List[str] = []

    for row in rows:
        row["classification"] = classify(row)
        delivered, pdf_used, pdf_rel = resolve_pdf(row, audits_root)
        row["pdf_delivered"] = delivered
        row["pdf_path_recorded"] = row["cohort_record"].get("pdf_path") if row["cohort_record"] else None
        row["pdf_path_used"] = pdf_used
        row["pdf_path_repo_relative"] = pdf_rel
        eml_path = row["cohort_record"].get("eml_path") if row["cohort_record"] else None
        row["original_eml_path"] = eml_path
        row["original_eml_exists"] = bool(eml_path) and Path(eml_path).exists()

        if row["unparseable"]:
            unparseable.append(row)
            continue
        if row["join_status"] != "joined":
            row["dispatched_context"] = lookup_dispatched(
                row["client_domain"], row["agency_domain"]
            )
            unjoinable.append(row)
        if row["old_grade"] in FAILING_GRADES and row["classification"]:
            affected.append(row)
        else:
            unaffected.append(row)

    # ---- write the correction notes + staged e-mails (rescued only) -------
    for row in affected:
        if row["classification"] != "rescued":
            row["correction_note_path"] = None
            row["correction_email_path"] = None
            continue

        causes = select_causes(row["buckets"], limit=3)
        row["cause_classes"] = [
            {
                "key": bucket["key"],
                "label": bucket["label"],
                "hygiene": bucket["hygiene"],
                "members": bucket["members"],
                "legacy_points": bucket["legacy_points"],
            }
            for bucket in causes
        ]
        subject, body = render_note_body(row)
        what_changed = build_what_changed(row["hygiene_present"])
        row["correction_subject"] = subject
        row["correction_word_count"] = count_words(body)

        note_name = f"{row['agency_slug']}_{row['client_domain']}_correction.md"
        eml_name = f"{row['agency_slug']}_{row['client_domain']}_correction.eml"
        note_path = NOTES_DIR / note_name
        eml_path = EMAILS_DIR / eml_name

        note_text = (
            f"Subject: {subject}\n\n"
            f"{body}\n"
            "---\n\n"
            "What changed\n"
            + "\n".join(f"- {bullet}" for bullet in what_changed)
            + "\n"
        )
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_text(note_text, encoding="utf-8")

        eml_body = render_eml_body(body, what_changed)
        eml_bytes = build_eml(
            recipient=row["contact_email"],
            subject=subject,
            body=eml_body,
            when=when,
            msgid=deterministic_msgid(row["agency_slug"], row["client_domain"]),
        )
        eml_path.parent.mkdir(parents=True, exist_ok=True)
        eml_path.write_bytes(eml_bytes)

        row["correction_note_path"] = rel_to_repo(note_path)
        row["correction_email_path"] = rel_to_repo(eml_path)
        notes_written.append(rel_to_repo(note_path))
        emails_written.append(rel_to_repo(eml_path))

    for row in unaffected:
        row["cause_classes"] = []
        row["correction_note_path"] = None
        row["correction_email_path"] = None

    # ---- manifest ---------------------------------------------------------
    def affected_view(row: dict) -> dict:
        return {
            "agency_name": row["agency_name"],
            "agency_slug": row["agency_slug"],
            "agency_domain": row["agency_domain"],
            "contact_email": row["contact_email"],
            "client_domain": row["client_domain"],
            "cohort": row["cohort"],
            "audit_file": row["audit_file"],
            "published": {"score": row["old_score"], "grade": row["old_grade"]},
            "corrected": {"score": row["new_score"], "grade": row["new_grade"]},
            "delta": row["delta"],
            "findings_total": row["findings_total"],
            "findings_by_severity": row["findings_by_severity"],
            "findings_hygiene": row["findings_hygiene"],
            "classification": row["classification"],
            "pdf_delivered": row["pdf_delivered"],
            "pdf_path": row["pdf_path_recorded"],
            "pdf_path_repo_relative": row["pdf_path_repo_relative"],
            "original_eml_path": row["original_eml_path"],
            "original_eml_exists": row["original_eml_exists"],
            "correction_note_path": row.get("correction_note_path"),
            "correction_email_path": row.get("correction_email_path"),
            "correction_subject": row.get("correction_subject"),
            "correction_word_count": row.get("correction_word_count"),
            "cause_classes": row.get("cause_classes", []),
        }

    def flagged_view(row: dict) -> dict:
        view = {
            "agency_name": row["agency_name"],
            "agency_slug": row["agency_slug"],
            "agency_domain": row["agency_domain"],
            "contact_email": row["contact_email"],
            "identity_recovered_from_audit": row["identity_recovered_from_audit"],
            "client_domain": row["client_domain"],
            "audit_file": row["audit_file"],
            "published": {"score": row["old_score"], "grade": row["old_grade"]},
            "corrected": {"score": row["new_score"], "grade": row["new_grade"]},
            "delta": row["delta"],
            "findings_total": row["findings_total"],
            "findings_by_severity": row["findings_by_severity"],
            "reason": row["join_note"] or "audit could not be parsed",
            "affected": row["old_grade"] in FAILING_GRADES,
            "classification": row.get("classification"),
            "correction_note_path": None,
            "correction_email_path": None,
        }
        if row.get("dispatched_context"):
            ctx = row["dispatched_context"]
            view["dispatched_context"] = {
                "agency_name": ctx.get("agency_name"),
                "agency_domain": ctx.get("agency_domain"),
                "contact_email": ctx.get("contact_email"),
                "dispatched_at": ctx.get("dispatched_at"),
                "status": ctx.get("status"),
            }
        return view

    manifest = {
        "generated_at": iso(when),
        "generator": "scripts/build_audit_remediation.py",
        "source_audits_root": rel_to_repo(audits_root),
        "cohorts": list(COHORTS),
        "scoring_model": {
            "legacy": dict(LEGACY_PENALTY),
            "current": "orbit_security.scoring (2026-10-22 rewrite: R1 hygiene split, "
            "R2 exploitability floor/ceiling, R3 per-class caps, R5 grade bands)",
        },
        "counts": {
            "total_audits": len(rows),
            "parsed_audits": len(rows) - len(unparseable),
            "unparseable_audits": len(unparseable),
            "joined_audits": len(rows) - len(unjoinable) - len(unparseable),
            "unjoinable_audits": len(unjoinable),
            "unjoinable_contact_recovered": sum(
                1 for r in unjoinable if r["contact_email"]
            ),
            "unjoinable_without_contact": sum(
                1 for r in unjoinable if not r["contact_email"]
            ),
            "affected_audits": len(affected),
            "rescued_audits": sum(1 for r in affected if r["classification"] == "rescued"),
            "still_failing_audits": sum(
                1 for r in affected if r["classification"] == "still_failing"
            ),
            "unaffected_audits": len(unaffected),
            "correction_notes_written": len(notes_written),
            "correction_emails_written": len(emails_written),
        },
        "by_cohort": cohort_breakdown(rows, affected, unjoinable, unparseable),
        "affected": [affected_view(r) for r in affected],
        "unjoinable": [flagged_view(r) for r in unjoinable],
        "unparseable": [flagged_view(r) for r in unparseable],
    }

    REMEDIATION_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # ---- summary ----------------------------------------------------------
    SUMMARY_PATH.write_text(
        render_summary(manifest, affected, unjoinable, unparseable), encoding="utf-8"
    )

    # ---- readme -----------------------------------------------------------
    README_PATH.write_text(render_readme(manifest), encoding="utf-8")

    manifest["_rows"] = rows
    manifest["_notes_written"] = notes_written
    manifest["_emails_written"] = emails_written
    return manifest


def cohort_breakdown(rows, affected, unjoinable, unparseable) -> List[dict]:
    """Per-cohort audit / affected / rescued / still-failing counts."""
    out: List[dict] = []
    for cohort in COHORTS:
        cohort_rows = [r for r in rows if r["cohort"] == cohort]
        cohort_affected = [r for r in affected if r["cohort"] == cohort]
        out.append(
            {
                "cohort": cohort,
                "audits": len(cohort_rows),
                "affected": len(cohort_affected),
                "rescued": sum(
                    1 for r in cohort_affected if r["classification"] == "rescued"
                ),
                "still_failing": sum(
                    1 for r in cohort_affected if r["classification"] == "still_failing"
                ),
                "correction_notes": sum(
                    1 for r in cohort_affected if r["classification"] == "rescued"
                ),
            }
        )
    out.append(
        {
            "cohort": "not in cohort 6-10",
            "audits": len(unjoinable) + len(unparseable),
            "affected": 0,
            "rescued": 0,
            "still_failing": 0,
            "correction_notes": 0,
        }
    )
    return out


def render_summary(manifest: dict, affected, unjoinable, unparseable) -> str:
    counts = manifest["counts"]
    lines: List[str] = []
    lines.append("# Orbit Security - Audit Remediation Pack Summary")
    lines.append("")
    lines.append(
        f"**Generated:** {manifest['generated_at']} | "
        f"**Source:** `data/generated_audits/*/*_audit.md` (read-only evidence) | "
        f"**Regenerate:** `scripts/build_audit_remediation.py`"
    )
    lines.append("")
    lines.append(
        "Between 2026-10-20 and 2026-10-22 five outreach cohorts shipped 52 client security "
        "audits. The published grades came from a flat-penalty scoring model that treated "
        "best-practice items as vulnerabilities. This pack holds the corrected numbers, the "
        "correction notes for the agencies whose grade was wrong, and the staged e-mails."
    )
    lines.append("")

    lines.append("## Headline counts")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Audits re-scored | {counts['total_audits']} |")
    lines.append(f"| Audits joined to a cohort record | {counts['joined_audits']} |")
    lines.append(f"| **Affected (published D/F)** | **{counts['affected_audits']}** |")
    lines.append(f"| **Rescued (grade was wrong - correction note ready)** | **{counts['rescued_audits']}** |")
    lines.append(f"| **Still failing (genuine exploit risk - no correction note)** | **{counts['still_failing_audits']}** |")
    lines.append(f"| Audits that could not be joined to a cohort | {counts['unjoinable_audits']} |")
    lines.append(
        f"| ...of those, contact address recovered from the audit body | "
        f"{counts['unjoinable_contact_recovered']} |"
    )
    lines.append(f"| Audits that could not be parsed | {counts['unparseable_audits']} |")
    lines.append(f"| Unaffected audits (published grade C or better) | {counts['unaffected_audits']} |")
    lines.append(f"| **Correction notes ready to send** | **{counts['correction_notes_written']}** |")
    lines.append(f"| **Staged correction e-mails (.eml)** | **{counts['correction_emails_written']}** |")
    lines.append("")

    lines.append("## Counts by cohort")
    lines.append("")
    lines.append("| Cohort | Audits | Affected (D/F) | Rescued | Still failing | Correction notes |")
    lines.append("|--------|--------|-----------------|---------|---------------|-----------------|")
    for row in manifest["by_cohort"]:
        lines.append(
            f"| {row['cohort']} | {row['audits']} | {row['affected']} | {row['rescued']} | "
            f"{row['still_failing']} | {row['correction_notes']} |"
        )
    lines.append("")

    lines.append("## Affected audits (published grade D or F)")
    lines.append("")
    lines.append("| Agency | Client domain | Contact email | Cohort | Old | New | Delta | Classification |")
    lines.append("|--------|---------------|---------------|--------|-----|-----|-------|----------------|")
    for row in affected:
        lines.append(
            f"| {row['agency_name']} | `{row['client_domain']}` | `{row['contact_email']}` | "
            f"{row['cohort']} | {row['old_score']}/100 {row['old_grade']} | "
            f"{row['new_score']}/100 {row['new_grade']} | {row['delta']:+d} | "
            f"`{row['classification']}` |"
        )
    lines.append("")

    lines.append("## Correction notes ready to send")
    lines.append("")
    lines.append(
        f"{counts['correction_notes_written']} note(s) are written to "
        "`data/remediation/correction_notes/` and the matching staged e-mails to "
        "`data/remediation/correction_emails/`."
    )
    lines.append("")
    for row in affected:
        if row["classification"] != "rescued":
            continue
        lines.append(
            f"- `{row.get('correction_note_path')}` - {row['agency_name']} / "
            f"`{row['client_domain']}` - {row['old_grade']} ({row['old_score']}) -> "
            f"{row['new_grade']} ({row['new_score']})"
        )
    lines.append("")

    lines.append("## Still-failing audits - recommendation")
    lines.append("")
    lines.append(
        "**Do not send a correction note to these agencies.** Their published grade was not "
        "wrong: after re-scoring with the corrected model they still fail, because the "
        "scanner found genuinely exploitable risk (dangling CNAME / subdomain takeover, "
        "SSL/TLS certificate failures, missing DMARC). Sending a correction there would be "
        "both inaccurate and damaging."
    )
    lines.append("")
    lines.append(
        "Treat them as a normal engagement follow-up instead: send the standard perimeter "
        "follow-up, attach the same co-branded audit, and lead with the specific exploitable "
        "finding rather than the headline score. If the operator wants to publish the revised "
        "score alongside it, use the corrected score from the manifest - do not restate the "
        "old grade."
    )
    lines.append("")
    for row in affected:
        if row["classification"] != "still_failing":
            continue
        drivers = ", ".join(
            f"{bucket['label']} [{max(bucket['severities'], key=lambda s: LEGACY_PENALTY.get(s, 0))}]"
            for bucket in row["buckets"]
            if not bucket["hygiene"]
        ) or "n/a"
        lines.append(
            f"- {row['agency_name']} / `{row['client_domain']}` - "
            f"{row['old_grade']} ({row['old_score']}) -> {row['new_grade']} "
            f"({row['new_score']}) - still-scored findings: {drivers}"
        )
    lines.append("")

    lines.append("## Flagged - audits that could not be joined to a cohort record")
    lines.append("")
    if not unjoinable and not unparseable:
        lines.append("None.")
    else:
        lines.append(
            "These audits exist on disk but have no matching cohort 6-10 record. They are "
            "**not** silently dropped - they are listed here and in "
            "`remediation_manifest.json` under `unjoinable`. The agency identity and "
            "contact address were recovered from the co-branding footer of the audit "
            "itself; the dispatch status comes from `data/dispatched_campaigns.json`."
        )
        lines.append("")
        lines.append(
            "| Client domain | Audit file | Agency (recovered) | Contact (recovered) | "
            "Dispatch | Published | Corrected | Affected |"
        )
        lines.append(
            "|---------------|------------|---------------------|----------------------|"
            "----------|-----------|-----------|----------|"
        )
        for row in unjoinable + unparseable:
            ctx = row.get("dispatched_context") or {}
            dispatch = (
                f"{ctx.get('status', '?')} ({ctx.get('dispatched_at', '?')})"
                if ctx
                else "not found"
            )
            lines.append(
                f"| `{row['client_domain']}` | `{rel_to_repo(row['audit_path'])}` | "
                f"{row['agency_name'] or '?'} (`{row['agency_domain'] or '?'}`) | "
                f"`{row['contact_email'] or '?'}` | {dispatch} | "
                f"{row['old_grade']} ({row['old_score']}) | {row['new_grade']} "
                f"({row['new_score']}) | {'yes' if row['old_grade'] in FAILING_GRADES else 'no'} |"
            )
    lines.append("")

    lines.append("## Send procedure")
    lines.append("")
    lines.append(
        "1. Review each note in `data/remediation/correction_notes/` - one per rescued audit."
    )
    lines.append(
        "2. Review the staged e-mail in `data/remediation/correction_emails/` - same body, "
        "ready to open in any desktop mail client."
    )
    lines.append(
        "3. Send. Nothing is auto-sent by this pack; the operator drives dispatch."
    )
    lines.append(
        "4. Leave `still_failing` audits out of the correction batch - follow up normally."
    )
    lines.append("")
    lines.append("See `data/remediation/README.md` for the full procedure.")
    lines.append("")
    return "\n".join(lines)


def render_readme(manifest: dict) -> str:
    counts = manifest["counts"]
    lines: List[str] = []
    lines.append("# Orbit Security - Audit Remediation Pack")
    lines.append("")
    lines.append("## What this pack is")
    lines.append("")
    lines.append(
        "Between 2026-10-20 and 2026-10-22 Orbit Security dispatched five outreach cohorts "
        "(6, 7, 8, 9, 10) to web / ecommerce agencies. Each email carried a PDF \"client "
        "security audit\" for that agency's client domain, scored by a flat-penalty model "
        "(CRITICAL 35 / HIGH 20 / MEDIUM 10 / LOW 5) with no finding-class awareness, no "
        "exploitability floor and no cap on repeated classes."
    )
    lines.append("")
    lines.append(
        f"Re-scoring the same evidence with the corrected engine "
        f"(`src/orbit_security/scoring.py`) moves {counts['affected_audits']} failing audits "
        f"down to {counts['still_failing_audits']}. {counts['rescued_audits']} of those were "
        f"published in error - in several cases to domains whose scan returned no critical "
        f"and no high finding at all, only best-practice gaps (missing BIMI, MTA-STS, "
        f"TLS-RPT, CAA, CSP, X-Frame-Options, X-Content-Type-Options) and a DMARC policy "
        f"still in `p=none` monitoring mode."
    )
    lines.append("")
    lines.append("This directory holds the customer-facing remediation:")
    lines.append("")
    lines.append("| Path | What it is |")
    lines.append("|------|------------|")
    lines.append(
        "| `remediation_manifest.json` | Machine-readable record of every audit: old and new "
        "score/grade, delta, severity counts, classification, PDF delivery status, join "
        "status and the paths of the artefacts. |"
    )
    lines.append(
        "| `correction_notes/` | One ready-to-send correction note per **rescued** audit "
        "(subject line, body, and a factual \"What changed\" section). |"
    )
    lines.append(
        "| `correction_emails/` | One RFC 5322 `.eml` per **rescued** audit - same body, "
        "ready to open and send from a desktop mail client. |"
    )
    lines.append("| `summary.md` | Operator summary: counts by cohort, affected table, send list. |")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(
        f"- `rescued` ({counts['rescued_audits']}) - the published grade was wrong. A "
        f"correction note and a staged `.eml` are written for each."
    )
    lines.append(
        f"- `still_failing` ({counts['still_failing_audits']}) - **no correction note.** "
        f"Those grades are correct: the scan found genuine exploit risk (dangling CNAME / "
        f"subdomain takeover, SSL/TLS certificate failures, missing DMARC). They get a normal "
        f"follow-up instead."
    )
    lines.append(
        f"- `unjoinable` ({counts['unjoinable_audits']}) - audits on disk with no cohort "
        f"6-10 record. Their agency identity and contact address were recovered from the "
        f"co-branding footer of the audit itself "
        f"({counts['unjoinable_contact_recovered']} of {counts['unjoinable_audits']} "
        f"recovered, {counts['unjoinable_without_contact']} still without an address). "
        f"They are flagged in `summary.md` and the manifest; never silently dropped."
    )
    lines.append(
        f"- `unparseable` ({counts['unparseable_audits']}) - audits whose findings or grade "
        f"could not be parsed. No score is invented for them and no note is written."
    )
    lines.append("")

    lines.append("## How to regenerate")
    lines.append("")
    lines.append("```powershell")
    lines.append(".venv\\Scripts\\python.exe scripts\\build_audit_remediation.py")
    lines.append("```")
    lines.append("")
    lines.append(
        "The script is idempotent: it re-reads the on-disk evidence, rewrites the manifest, "
        "the notes, the `.eml` files, `summary.md` and this README from scratch every run. "
        "**This is the command that stages the correction e-mails as `.eml` files** in "
        "`data/remediation/correction_emails/` - there is no separate staging step and no "
        "send step. It writes only inside `data/remediation/`. It never touches the "
        "delivered audits, the cohort manifests or `outbound_campaigns/`, it never "
        "regenerates a PDF and it never sends mail."
    )
    lines.append("")
    lines.append("Options:")
    lines.append("")
    lines.append("| Flag | Effect |")
    lines.append("|------|--------|")
    lines.append(
        "| `--date ISO8601` | Pin the generation timestamp and the `Date` header of every "
        "staged e-mail (useful for a reproducible pack). |"
    )
    lines.append("| `--verify-only` | Re-run the verification pass against the existing pack without rewriting it. |")
    lines.append("| `--audits-dir PATH` | Point at a different audit tree (read-only). |")
    lines.append("")

    lines.append("## Operator send procedure")
    lines.append("")
    lines.append(
        "1. **Regenerate** the pack so it matches the current evidence:"
    )
    lines.append("")
    lines.append("```powershell")
    lines.append(".venv\\Scripts\\python.exe scripts\\build_audit_remediation.py")
    lines.append("```")
    lines.append("")
    lines.append("2. **Review** every note in `data/remediation/correction_notes/`. Each file is")
    lines.append(
        "   a self-contained note: a `Subject:` line, a 120-220 word body and a factual"
    )
    lines.append("   \"What changed\" section listing the rule change.")
    lines.append("")
    lines.append(
        "3. **Check the staged e-mail** in `data/remediation/correction_emails/`. It carries "
        "the same body with `To`, `From`, `Subject`, `Reply-To` and `Date` headers, and it "
        "opens natively in Outlook / Mail / Thunderbird. Open it, read it once end to end, "
        "then send it."
    )
    lines.append("")
    lines.append(
        "4. **Send** the e-mail. Dispatch is manual on purpose - this pack stages, it does not "
        "send. Never point a mail client at `outbound_campaigns/` for this batch; the "
        "correction e-mails live in `data/remediation/correction_emails/`."
    )
    lines.append("")
    lines.append(
        f"5. **Leave the `still_failing` audits out of the correction batch.** There is no "
        f"note and no e-mail for them, by design. Their published grade was not wrong - the "
        f"scan found real exploit risk - so a \"we mis-scored this\" note would be untrue. "
        f"Send them the standard perimeter follow-up instead, leading with the specific "
        f"exploitable finding rather than the headline score."
    )
    lines.append("")
    lines.append(
        "6. **Do not use this pack for the flagged audits.** The `unjoinable` audits sit "
        "outside cohorts 6-10 (an earlier dispatch). Their contact address was recovered "
        "from the audit footer, but they published a passing grade, so no correction is "
        "due - handle them as a normal outreach decision."
    )
    lines.append("")

    lines.append("## Notes on the correction notes")
    lines.append("")
    lines.append(
        "- They state that the published grade was miscalculated. They never claim the "
        "estate is secure, and they never re-sell the product inside a correction."
    )
    lines.append(
        "- They name only the agency's own client domain - the domain that agency already "
        "received - and no third-party domain."
    )
    lines.append(
        "- The two or three finding classes named in each note are derived from that "
        "audit's own parsed findings and the legacy penalty they carried; the full "
        "attribution lives in `remediation_manifest.json` under `cause_classes`."
    )
    lines.append(
        "- The PDF that was attached to the original email still shows the old grade. It is "
        "not regenerated here. Reply-to-the-note re-issue is the operator's call."
    )
    lines.append("")

    lines.append("## Files in this pack")
    lines.append("")
    lines.append("```")
    lines.append("data/remediation/")
    lines.append("  README.md                          # this file")
    lines.append("  summary.md                         # operator summary")
    lines.append("  remediation_manifest.json          # machine-readable record")
    lines.append("  correction_notes/<slug>_<domain>_correction.md")
    lines.append("  correction_emails/<slug>_<domain>_correction.eml")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def verify() -> int:
    """Assert every published number and every staged artefact."""
    failures: List[str] = []
    checks = 0

    def check(condition: bool, message: str) -> None:
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(message)

    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    counts = data["counts"]

    # --- counts reproduce from the rows -----------------------------------
    affected_rows = data["affected"]
    check(
        counts["affected_audits"] == len(affected_rows),
        "manifest counts.affected_audits does not match len(affected)",
    )
    rescued = [r for r in affected_rows if r["classification"] == "rescued"]
    still = [r for r in affected_rows if r["classification"] == "still_failing"]
    check(len(rescued) == counts["rescued_audits"], "rescued count mismatch")
    check(len(still) == counts["still_failing_audits"], "still_failing count mismatch")
    check(
        counts["rescued_audits"] + counts["still_failing_audits"]
        == counts["affected_audits"],
        "rescued + still_failing != affected",
    )
    check(
        counts["correction_notes_written"] == len(rescued),
        "correction note count != rescued count",
    )
    check(
        counts["correction_emails_written"] == len(rescued),
        "correction email count != rescued count",
    )
    check(
        counts["total_audits"]
        == counts["joined_audits"] + counts["unjoinable_audits"] + counts["unparseable_audits"],
        "total audits != joined + unjoinable + unparseable",
    )

    # --- every rescued audit has a note + an eml; no still_failing has one --
    for row in affected_rows:
        if row["classification"] == "rescued":
            check(row["correction_note_path"] is not None, f"missing note path for {row['client_domain']}")
            check(row["correction_email_path"] is not None, f"missing eml path for {row['client_domain']}")
            check(
                row["corrected"]["grade"] not in FAILING_GRADES,
                f"{row['client_domain']} classified rescued but still fails",
            )
        else:
            check(
                row["correction_note_path"] is None,
                f"still_failing {row['client_domain']} must not have a correction note",
            )
            check(
                row["correction_email_path"] is None,
                f"still_failing {row['client_domain']} must not have a correction email",
            )
            check(
                row["corrected"]["grade"] in FAILING_GRADES,
                f"still_failing {row['client_domain']} does not actually fail",
            )

    # --- notes on disk: subject, word count, no third-party domain ---------
    note_files = sorted(NOTES_DIR.glob("*_correction.md"))
    eml_files = sorted(EMAILS_DIR.glob("*_correction.eml"))
    check(len(note_files) == counts["correction_notes_written"], "note file count mismatch")
    check(len(eml_files) == counts["correction_emails_written"], "eml file count mismatch")

    # Every client / agency domain that exists in the cohort manifests. A note
    # may only ever name its own agency's client domain and its own domain.
    known_client_domains = set()
    known_agency_domains = set()
    for cohort in COHORTS:
        path = DATA_DIR / f"cohort_{cohort}_staged.json"
        if not path.exists():
            continue
        for rec in json.loads(path.read_text(encoding="utf-8")):
            known_client_domains.add(str(rec.get("client_domain", "")).lower())
            known_agency_domains.add(str(rec.get("agency_domain", "")).lower())
    by_client = {row["client_domain"].lower(): row for row in affected_rows}

    #: Tokens that look like a domain but are a file name, not a hostname.
    NON_DOMAIN_TOKENS = {"security.txt"}
    SENDER_DOMAINS = {"gmail.com", "cmfh009.github.io", "github.io"}

    for path in note_files:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        check(bool(lines) and lines[0].startswith("Subject: "), f"{path.name}: no Subject: line")
        check("What changed" in text, f"{path.name}: no 'What changed' section")
        body = text.split("\n---\n", 1)[0]
        body = body.split("\n", 1)[1] if body.startswith("Subject: ") else body
        words = count_words(body)
        check(
            120 <= words <= 220,
            f"{path.name}: body word count {words} outside 120-220",
        )
        # The only domains that may appear are the agency's own client domain
        # and the agency's own domain. No third party's client domain.
        client_domain = path.name[: -len("_correction.md")].split("_", 1)[1]
        own = by_client.get(client_domain.lower(), {})
        allowed = {
            client_domain.lower(),
            str(own.get("agency_domain", "")).lower(),
            str(own.get("agency_name", "")).lower(),
        } | SENDER_DOMAINS
        found = {
            d.lower()
            for d in re.findall(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", body)
        }
        extra = sorted(
            d
            for d in found
            if d not in allowed and d not in NON_DOMAIN_TOKENS
        )
        check(
            not extra,
            f"{path.name}: body names unrelated domain(s): {extra}",
        )
        third_party = sorted(
            d for d in found if d in known_client_domains and d != client_domain.lower()
        )
        check(
            not third_party,
            f"{path.name}: body names a third-party client domain: {third_party}",
        )

    # --- emls parse and carry the required headers -------------------------
    import email as _email
    from email import policy as _policy

    for path in eml_files:
        with open(path, "rb") as handle:
            msg = _email.message_from_binary_file(handle, policy=_policy.default)
        check(msg["To"] is not None, f"{path.name}: no To header")
        check(msg["From"] is not None, f"{path.name}: no From header")
        check(msg["Subject"] is not None, f"{path.name}: no Subject header")
        check(msg["Date"] is not None, f"{path.name}: no Date header")
        body = msg.get_body(preferencelist=("plain",))
        check(body is not None, f"{path.name}: no plain-text body")
        if body is not None:
            content = body.get_content()
            check(len(content.strip()) > 0, f"{path.name}: empty body")

    # --- summary.md numbers reproduce from the manifest --------------------
    summary = SUMMARY_PATH.read_text(encoding="utf-8")
    summary_needles = [
        (f"| Audits re-scored | {counts['total_audits']} |", "total audits row"),
        (f"| **Affected (published D/F)** | **{counts['affected_audits']}** |", "affected row"),
        (f"| **Rescued (grade was wrong - correction note ready)** | **{counts['rescued_audits']}** |", "rescued row"),
        (f"| **Still failing (genuine exploit risk - no correction note)** | **{counts['still_failing_audits']}** |", "still failing row"),
        (f"| Audits that could not be joined to a cohort | {counts['unjoinable_audits']} |", "unjoinable row"),
        (f"| ...of those, contact address recovered from the audit body | {counts['unjoinable_contact_recovered']} |", "unjoinable recovered row"),
        (f"| Audits that could not be parsed | {counts['unparseable_audits']} |", "unparseable row"),
        (f"| **Correction notes ready to send** | **{counts['correction_notes_written']}** |", "notes row"),
        (f"| **Staged correction e-mails (.eml)** | **{counts['correction_emails_written']}** |", "emails row"),
    ]
    for needle, label in summary_needles:
        check(needle in summary, f"summary.md: missing {label}")

    for row in affected_rows:
        needle = (
            f"| {row['agency_name']} | `{row['client_domain']}` | `{row['contact_email']}` | "
            f"{row['cohort']} | {row['published']['score']}/100 {row['published']['grade']} | "
            f"{row['corrected']['score']}/100 {row['corrected']['grade']} | "
            f"{row['delta']:+d} | `{row['classification']}` |"
        )
        check(needle in summary, f"summary.md: missing affected row for {row['client_domain']}")

    for row in data["by_cohort"]:
        needle = (
            f"| {row['cohort']} | {row['audits']} | {row['affected']} | {row['rescued']} | "
            f"{row['still_failing']} | {row['correction_notes']} |"
        )
        check(needle in summary, f"summary.md: missing cohort row {row['cohort']}")

    # --- report -----------------------------------------------------------
    print("VERIFICATION")
    print(f"  assertions run ............ {checks}")
    print(f"  failures ................. {len(failures)}")
    for failure in failures:
        print(f"    - {failure}")
    print()
    print("  counts:")
    for key in (
        "total_audits",
        "joined_audits",
        "unjoinable_audits",
        "unparseable_audits",
        "affected_audits",
        "rescued_audits",
        "still_failing_audits",
        "correction_notes_written",
        "correction_emails_written",
    ):
        print(f"    {key:<26} {counts[key]}")
    print()
    print("  affected audits:")
    for row in affected_rows:
        print(
            f"    {row['agency_name']:<24} {row['client_domain']:<24} "
            f"{row['published']['grade']} {row['published']['score']:>3}/100 -> "
            f"{row['corrected']['grade']} {row['corrected']['score']:>3}/100  "
            f"[{row['classification']}]"
        )
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the customer-facing audit remediation pack (staging only, never sends)."
    )
    parser.add_argument(
        "--audits-dir",
        default=str(AUDIT_ROOT),
        help="Directory containing the generated audit markdown (read-only).",
    )
    parser.add_argument(
        "--date",
        default=None,
        help="Pin the generation timestamp / e-mail Date header (ISO 8601).",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify the existing pack without rewriting it.",
    )
    args = parser.parse_args()

    audits_root = Path(args.audits_dir)

    if args.date:
        when = datetime.fromisoformat(args.date)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
    else:
        when = datetime.now(timezone.utc)

    if not args.verify_only:
        print("=" * 70)
        print("ORBIT SECURITY: AUDIT REMEDIATION PACK BUILD")
        print("=" * 70)
        manifest = build_pack(when, audits_root)
        counts = manifest["counts"]
        print(f"  audits re-scored ............ {counts['total_audits']}")
        print(f"  joined to a cohort .......... {counts['joined_audits']}")
        print(f"  unjoinable .................. {counts['unjoinable_audits']}")
        print(f"  unparseable ................ {counts['unparseable_audits']}")
        print(f"  affected (published D/F) .... {counts['affected_audits']}")
        print(f"  rescued ..................... {counts['rescued_audits']}")
        print(f"  still failing ............... {counts['still_failing_audits']}")
        print(f"  correction notes written .... {counts['correction_notes_written']}")
        print(f"  correction e-mails staged ... {counts['correction_emails_written']}")
        print()
        print(f"  manifest -> {rel_to_repo(MANIFEST_PATH)}")
        print(f"  summary  -> {rel_to_repo(SUMMARY_PATH)}")
        print(f"  readme   -> {rel_to_repo(README_PATH)}")
        print()
        print("  (staging only - nothing was sent)")
        print()

    return verify()


if __name__ == "__main__":
    raise SystemExit(main())
