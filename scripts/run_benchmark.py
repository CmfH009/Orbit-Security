#!/usr/bin/env python3
"""Orbit Security reproducible benchmark harness.

Measures four things about the Orbit Security engine and writes them to a
machine-readable JSON file that the published methodology page is generated
from:

1. ``audit_latency``      - wall-clock time of one real per-domain audit
                            (DNS + HTTP + scoring) across a target list,
                            with p50/p90/p95/p99 plus min/max/mean.
2. ``signature_coverage`` - how many provider fingerprints and dangling
                            hostname classes the scanner can actually detect,
                            counted from the live signature table.
3. ``false_positive_guards`` - the deterministic static-host / parked-page /
                            reserved-domain guards and their observable
                            behaviour (including a self-test).
4. ``scoring_stability``  - the grade distribution produced by the current
                            scoring engine when it is replayed over every
                            stored client audit.

Everything reported here is measured at run time. A measurement that could
not be taken (no network, missing tool, DNS blocked) is written as ``null``
together with a human readable reason - never as an estimate.

Usage
-----
    .venv\\Scripts\\python.exe scripts\\run_benchmark.py
    .venv\\Scripts\\python.exe scripts\\run_benchmark.py --repeat 3
    .venv\\Scripts\\python.exe scripts\\run_benchmark.py --targets my_targets.txt
    .venv\\Scripts\\python.exe scripts\\run_benchmark.py --no-network

Safety
------
* Only domains from the built-in default list, or from an operator supplied
  ``--targets`` file, are ever contacted.
* Outbound traffic is rate limited to at most 1 request per second per host
  (HTTP: per target host, DNS: across the whole resolver fleet). The limit
  can be raised but never lowered below 1.0 s.
* The harness is read-only with respect to ``src/``, ``tests/``, ``data/``
  and every existing page. It only writes the JSON output file.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(SRC_DIR), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dns.resolver  # noqa: E402
import dns.version  # noqa: E402
import httpx  # noqa: E402

from orbit_security import recon  # noqa: E402
from orbit_security.scanner import (  # noqa: E402
    PARKED_HTML_FINGERPRINTS,
    RESERVED_TLDS,
    RFC_2606_RESERVED_DOMAINS,
    is_reserved_domain,
)
from orbit_security.scoring import (  # noqa: E402
    STATIC_HOST_SUFFIXES,
    ScoreItem,
    Severity,
    is_static_hosting_domain,
    missing_header_severity,
    score_findings,
)
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES  # noqa: E402

import rescore_audit_evidence  # noqa: E402  (read-only parsing helpers)

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

#: Small, well-known, publicly operated sites. They are used by IANA, the
#: Python Software Foundation, the Wikimedia Foundation, Mozilla and GitHub
#: as documentation / primary sites, and are safe to contact at a trivial
#: request rate.
DEFAULT_TARGETS: Tuple[str, ...] = (
    "example.com",
    "github.com",
    "python.org",
    "wikipedia.org",
    "mozilla.org",
)

DEFAULT_OUT = REPO_ROOT / "docs" / "benchmark" / "benchmark_results.json"
DEFAULT_AUDITS_DIR = REPO_ROOT / "data" / "generated_audits"

#: The marketing claim on the About page is "< 12 seconds per domain audit".
#: The benchmark records the real number; it never asserts this one.
MARKETING_CLAIM_SECONDS = 12.0

#: Hard floor for the per-host request interval. The harness will not go
#: faster than one request per second per host, whatever the operator asks
#: for, so a published benchmark run cannot hammer a third party.
MIN_REQUEST_INTERVAL_S = 1.0


# --------------------------------------------------------------------------- #
# Rate limiting + instrumentation
# --------------------------------------------------------------------------- #


class HostRateLimiter:
    """Enforces a minimum interval between consecutive requests to a host.

    The limiter *reserves* the next slot before sleeping so that two
    consecutive callers are always at least ``min_interval`` apart, even when
    the sleep happens outside the lock.
    """

    def __init__(self, min_interval: float) -> None:
        self.min_interval = float(min_interval)
        self._last: Dict[str, float] = {}
        self.total_sleep_s = 0.0
        self.sleep_events = 0
        self.waits = 0

    def wait(self, host: str) -> float:
        """Block until *host* may be contacted again. Returns seconds slept."""
        self.waits += 1
        if self.min_interval <= 0:
            return 0.0
        now = time.monotonic()
        earliest = self._last.get(host, 0.0) + self.min_interval
        self._last[host] = max(now, earliest)
        delay = earliest - now
        if delay <= 0:
            return 0.0
        time.sleep(delay)
        self.total_sleep_s += delay
        self.sleep_events += 1
        return delay

    def stats(self) -> Dict[str, Any]:
        return {
            "min_interval_s": self.min_interval,
            "requests_through_limiter": self.waits,
            "throttle_sleep_events": self.sleep_events,
            "throttle_sleep_total_s": round(self.total_sleep_s, 3),
        }


@dataclass
class _Instrumentation:
    """Mutable counters shared by the patched httpx / dns call sites."""

    http_limiter: Optional[HostRateLimiter] = None
    dns_limiter: Optional[HostRateLimiter] = None
    dns_sleep_s: float = 0.0
    http_sleep_s: float = 0.0
    dns_queries: int = 0
    os_dns_lookups: int = 0
    http_requests: int = 0

    def reset(self) -> None:
        self.dns_sleep_s = 0.0
        self.http_sleep_s = 0.0
        self.dns_queries = 0
        self.os_dns_lookups = 0
        self.http_requests = 0


_CTX = _Instrumentation()
_PATCHED = False
_ORIG_HTTPX_SEND = httpx.Client.send
_ORIG_DNS_RESOLVE = dns.resolver.Resolver.resolve
_ORIG_GETADDRINFO = socket.getaddrinfo


def _dns_host_key(qname: Any) -> str:
    """Group DNS queries by the domain they are about (not by resolver)."""
    try:
        text = str(getattr(qname, "to_text", lambda: qname)())
    except Exception:
        text = str(qname)
    text = text.strip().rstrip(".").lower()
    labels = [l for l in text.split(".") if l]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return text or "dns"


def _install_instrumentation() -> None:
    """Patch httpx + dnspython so every outbound request is rate limited."""
    global _PATCHED
    if _PATCHED:
        return

    def throttled_send(self, request, *args, **kwargs):  # type: ignore[no-untyped-def]
        if _CTX.http_limiter is not None:
            _CTX.http_sleep_s += _CTX.http_limiter.wait(request.url.host)
        _CTX.http_requests += 1
        return _ORIG_HTTPX_SEND(self, request, *args, **kwargs)

    def throttled_resolve(self, qname, *args, **kwargs):  # type: ignore[no-untyped-def]
        if _CTX.dns_limiter is not None:
            # One shared bucket for the whole resolver fleet: at most one DNS
            # query per second leaves this process, whichever resolver it is
            # finally sent to.
            _CTX.dns_sleep_s += _CTX.dns_limiter.wait("dns-fleet")
        _CTX.dns_queries += 1
        return _ORIG_DNS_RESOLVE(self, qname, *args, **kwargs)

    def throttled_getaddrinfo(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        # The SSRF guard and httpx' connection setup both resolve through the
        # OS resolver. Route those lookups through the same fleet bucket so
        # "one request per second per host" covers every DNS operation.
        if _CTX.dns_limiter is not None:
            _CTX.dns_sleep_s += _CTX.dns_limiter.wait("dns-fleet")
        _CTX.os_dns_lookups += 1
        return _ORIG_GETADDRINFO(host, port, *args, **kwargs)

    httpx.Client.send = throttled_send  # type: ignore[assignment]
    dns.resolver.Resolver.resolve = throttled_resolve  # type: ignore[assignment]
    socket.getaddrinfo = throttled_getaddrinfo  # type: ignore[assignment]
    _PATCHED = True


# --------------------------------------------------------------------------- #
# Statistics helpers
# --------------------------------------------------------------------------- #


def percentile(sorted_values: Sequence[float], pct: float) -> Optional[float]:
    """Nearest-rank percentile.

    ``index = ceil(pct/100 * n) - 1`` on the ascending sample. No
    interpolation, so every reported percentile is an observed measurement.
    """
    if not sorted_values:
        return None
    n = len(sorted_values)
    idx = max(0, min(n - 1, math.ceil((pct / 100.0) * n) - 1))
    return sorted_values[idx]


def summarize(values: Sequence[float]) -> Dict[str, Any]:
    """min / p50 / p90 / p95 / p99 / max / mean for a sample of numbers."""
    clean = [float(v) for v in values if v is not None]
    if not clean:
        return {
            "count": 0,
            "min": None,
            "p50": None,
            "p90": None,
            "p95": None,
            "p99": None,
            "max": None,
            "mean": None,
        }
    s = sorted(clean)
    return {
        "count": len(s),
        "min": round(s[0], 2),
        "p50": round(percentile(s, 50), 2),
        "p90": round(percentile(s, 90), 2),
        "p95": round(percentile(s, 95), 2),
        "p99": round(percentile(s, 99), 2),
        "max": round(s[-1], 2),
        "mean": round(sum(s) / len(s), 2),
    }


# --------------------------------------------------------------------------- #
# Measurement 1 - per-domain audit latency
# --------------------------------------------------------------------------- #


def audit_domain(domain: str) -> Dict[str, Any]:
    """Run one real Orbit Recon domain audit and time every phase.

    This is exactly the call sequence ``orbit_security.recon.run_recon()``
    performs: DNS resolution, HTTP header/exposure inspection, then scoring.
    """
    _CTX.reset()

    domain = normalize_domain(domain)

    t0 = time.perf_counter()
    dns_res = recon.resolve_dns(domain)
    t1 = time.perf_counter()
    web_res = recon.check_headers_and_exposures(domain)
    t2 = time.perf_counter()
    score = recon.calculate_score(dns_res, web_res, domain=domain)
    grade = recon.calculate_grade(dns_res, web_res, domain=domain)
    t3 = time.perf_counter()

    dns_ms = (t1 - t0) * 1000.0
    http_ms = (t2 - t1) * 1000.0
    scoring_ms = (t3 - t2) * 1000.0
    wall_ms = (t3 - t0) * 1000.0
    throttle_ms = (_CTX.dns_sleep_s + _CTX.http_sleep_s) * 1000.0
    active_ms = max(0.0, wall_ms - throttle_ms)

    issues: List[str] = []
    dns_evidence = bool(
        dns_res.get("cname")
        or dns_res.get("a_records")
        or dns_res.get("mx_records")
        or dns_res.get("caa_records")
        or dns_res.get("dmarc_record")
    )
    if not dns_evidence:
        issues.append("no DNS answer of any type was returned - DNS appears blocked")
    if web_res.get("error"):
        issues.append(f"HTTP probe failed: {web_res['error']}")
    if web_res.get("status_code") is None:
        issues.append("no HTTP status code was obtained")

    status = "ok"
    if issues:
        status = "failed" if not dns_evidence else "partial"

    missing_headers = web_res.get("missing_headers") or []
    exposures = web_res.get("exposures") or []

    return {
        "domain": domain,
        "wall_ms": round(wall_ms, 2),
        "active_ms": round(active_ms, 2),
        "dns_ms": round(dns_ms, 2),
        "http_ms": round(http_ms, 2),
        "scoring_ms": round(scoring_ms, 2),
        "throttle_sleep_ms": round(throttle_ms, 2),
        "dns_queries": _CTX.dns_queries,
        "os_dns_lookups": _CTX.os_dns_lookups,
        "http_requests": _CTX.http_requests,
        "score": score,
        "grade": grade,
        "status": status,
        "issues": issues,
        "dns": {
            "cname": dns_res.get("cname"),
            "matched_service": dns_res.get("matched_service"),
            "dangling_risk": bool(dns_res.get("dangling_risk")),
            "dmarc_present": bool(dns_res.get("dmarc_record")),
            "mx_records": len(dns_res.get("mx_records") or []),
            "caa_records": len(dns_res.get("caa_records") or []),
        },
        "web": {
            "status_code": web_res.get("status_code"),
            "headers_found": len(web_res.get("headers_found") or {}),
            "missing_headers": len(missing_headers),
            "exposures": len(exposures),
            "static_host_guard_applied": is_static_hosting_domain(domain),
            "reserved_domain_guard_applied": is_reserved_domain(domain),
            "error": web_res.get("error"),
        },
    }


def measure_latency(
    targets: Sequence[str], repeat: int, interval_s: float
) -> Dict[str, Any]:
    """Measure per-domain audit latency across *targets*, repeated *repeat* times."""
    http_limiter = HostRateLimiter(interval_s)
    dns_limiter = HostRateLimiter(interval_s)
    _CTX.http_limiter = http_limiter
    _CTX.dns_limiter = dns_limiter

    samples: List[Dict[str, Any]] = []
    try:
        for rep in range(1, repeat + 1):
            for domain in targets:
                try:
                    record = audit_domain(domain)
                except Exception as exc:  # pragma: no cover - defensive
                    record = {
                        "domain": domain,
                        "wall_ms": None,
                        "active_ms": None,
                        "dns_ms": None,
                        "http_ms": None,
                        "scoring_ms": None,
                        "throttle_sleep_ms": None,
                        "dns_queries": 0,
                        "os_dns_lookups": 0,
                        "http_requests": 0,
                        "score": None,
                        "grade": None,
                        "status": "failed",
                        "issues": [f"unhandled exception during audit: {exc!r}"],
                        "dns": {},
                        "web": {},
                    }
                record["repeat"] = rep
                samples.append(record)
    finally:
        _CTX.http_limiter = None
        _CTX.dns_limiter = None

    usable = [s for s in samples if s["status"] != "failed" and s["wall_ms"] is not None]
    wall = [s["wall_ms"] for s in usable]
    active = [s["active_ms"] for s in usable]

    per_domain: Dict[str, Dict[str, Any]] = {}
    for domain in targets:
        rows = [s for s in samples if s["domain"] == domain]
        grades = sorted({r["grade"] for r in rows if r.get("grade")})
        per_domain[domain] = {
            "domain": domain,
            "samples": len(rows),
            "ok_samples": len([r for r in rows if r["status"] != "failed"]),
            "grades_observed": grades,
            "grade_stable": len(grades) == 1 and len(rows) > 1,
            "scores_observed": sorted({r["score"] for r in rows if r.get("score") is not None}),
            "wall_ms": summarize([r["wall_ms"] for r in rows]),
            "active_ms": summarize([r["active_ms"] for r in rows]),
            "dns_ms": summarize([r["dns_ms"] for r in rows]),
            "http_ms": summarize([r["http_ms"] for r in rows]),
            "scoring_ms": summarize([r["scoring_ms"] for r in rows]),
            "dns_queries": rows[0]["dns_queries"] if rows else None,
            "http_requests": rows[0]["http_requests"] if rows else None,
            "dangling_risk_observed": any(r["dns"]["dangling_risk"] for r in rows),
            "exposures_observed": sum(r["web"]["exposures"] for r in rows),
            "status": "ok" if rows and all(r["status"] == "ok" for r in rows) else "degraded",
        }

    stable_domains = [d for d, v in per_domain.items() if v["grade_stable"]]
    phase = {
        "dns_ms": summarize([s["dns_ms"] for s in usable]),
        "http_ms": summarize([s["http_ms"] for s in usable]),
        "scoring_ms": summarize([s["scoring_ms"] for s in usable]),
        "throttle_sleep_ms": summarize([s["throttle_sleep_ms"] for s in usable]),
    }

    cold = [s for s in usable if s.get("repeat") == 1]
    warm = [s for s in usable if s.get("repeat", 1) > 1]
    cache_split = {
        "note": (
            "Repeat 1 populates Orbit's DNS cache; repeats 2+ are answered "
            "from cache. Both are reported so the cold-cache number is never "
            "hidden behind the warm one."
        ),
        "cold_repeat_1": {
            "samples": len(cold),
            "active_ms": summarize([s["active_ms"] for s in cold]),
            "dns_ms": summarize([s["dns_ms"] for s in cold]),
            "wall_ms": summarize([s["wall_ms"] for s in cold]),
        },
        "warm_repeats_2_plus": {
            "samples": len(warm),
            "active_ms": summarize([s["active_ms"] for s in warm]),
            "dns_ms": summarize([s["dns_ms"] for s in warm]),
            "wall_ms": summarize([s["wall_ms"] for s in warm]),
        },
    }

    return {
        "status": "measured" if usable else "not_measured",
        "not_measured_reason": None
        if usable
        else "Every audited domain failed: no DNS answers and no HTTP responses were obtained.",
        "unit": "milliseconds",
        "targets": list(targets),
        "repeat": repeat,
        "samples_total": len(samples),
        "samples_usable": len(usable),
        "samples_failed": len(samples) - len(usable),
        "wall_ms": summarize(wall),
        "active_ms": summarize(active),
        "active_ms_definition": (
            "wall-clock time of the audit minus the time deliberately spent "
            "sleeping to respect the 1 request/second per host limit. It is the "
            "scanner plus network cost of one domain audit."
        ),
        "wall_ms_definition": (
            "wall-clock time of one domain audit as an operator experiences it "
            "while the 1 request/second politeness limit is enforced."
        ),
        "percentile_method": "nearest-rank (index = ceil(p/100 * n) - 1), no interpolation",
        "phase_breakdown": phase,
        "dns_cache_split": cache_split,
        "grade_stability": {
            "domains_compared": len(per_domain),
            "domains_with_identical_grade_across_repeats": len(stable_domains),
            "grade_stability_rate": (
                round(len(stable_domains) / len(per_domain), 4) if per_domain else None
            ),
        },
        "per_domain": per_domain,
        "samples": samples,
        "throttle": {
            "http": http_limiter.stats(),
            "dns": dns_limiter.stats(),
        },
    }


# --------------------------------------------------------------------------- #
# Measurement 2 - takeover signature coverage
# --------------------------------------------------------------------------- #


def measure_signature_coverage() -> Dict[str, Any]:
    """Count what the scanner can actually detect, straight from the code."""
    providers = list(SAAS_TAKEOVER_SIGNATURES)
    fingerprints = [fp for sig in providers for fp in sig.fingerprints]
    cname_classes = [c for sig in providers for c in sig.cname_patterns]

    return {
        "status": "measured",
        "source_module": "orbit_security.signatures.SAAS_TAKEOVER_SIGNATURES",
        "provider_signatures": len(providers),
        "fingerprint_entries": len(fingerprints),
        "distinct_provider_fingerprints": len(set(fingerprints)),
        "cname_pattern_entries": len(cname_classes),
        "distinct_dangling_hostname_classes": len(set(cname_classes)),
        "providers_using_nxdomain_verification": len([s for s in providers if s.nxdomain]),
        "providers_with_remediation_guidance": len([s for s in providers if s.remediation]),
        "note": (
            "A provider is only reported as a takeover when its CNAME pattern "
            "matches AND the provider fingerprint (or NXDOMAIN) is confirmed. "
            "The fingerprint count is therefore the number of distinct "
            "provider-specific 'this resource is unclaimed' responses Orbit "
            "knows how to recognise."
        ),
        "providers": [s.name for s in providers],
    }


# --------------------------------------------------------------------------- #
# Measurement 3 - false positive guards
# --------------------------------------------------------------------------- #


def measure_false_positive_guards(measured_domains: Sequence[str]) -> Dict[str, Any]:
    """Exercise the deterministic false-positive guards and report behaviour."""
    cases: List[Dict[str, Any]] = []

    static_cases = [
        ("project.github.io", True),
        ("site.pages.dev", True),
        ("app.vercel.app", True),
        ("site.netlify.app", True),
        ("site.webflow.io", True),
        ("site.surge.sh", True),
        ("app.firebaseapp.com", True),
        ("site.web.app", True),
        ("repo.gitlab.io", True),
        ("example.com", False),
        ("notgithub.io.example.com", False),
        # A shared provider apex is not a customer host: only the bare
        # `github.io` gets the exact-host exemption.
        ("gitlab.io", False),
    ]
    for domain, expected in static_cases:
        actual = is_static_hosting_domain(domain)
        cases.append(
            {
                "guard": "static_hosting_domain",
                "case": domain,
                "expected": expected,
                "actual": actual,
                "pass": actual == expected,
            }
        )

    hsts_cases = [
        ("Strict-Transport-Security", "client-agency.com", Severity.MEDIUM),
        ("Strict-Transport-Security", "client.github.io", Severity.INFO),
        ("Content-Security-Policy", "client-agency.com", Severity.INFO),
        ("X-Frame-Options", "client-agency.com", Severity.INFO),
    ]
    for header, domain, expected in hsts_cases:
        actual = missing_header_severity(header, domain)
        cases.append(
            {
                "guard": "missing_header_severity",
                "case": f"{header} @ {domain}",
                "expected": expected.value,
                "actual": actual.value,
                "pass": actual == expected,
            }
        )

    reserved_cases = [
        ("example.com", True),
        ("example.org", True),
        ("client.test", True),
        ("client.invalid", True),
        ("client-agency.com", False),
    ]
    for domain, expected in reserved_cases:
        actual = is_reserved_domain(domain)
        cases.append(
            {
                "guard": "reserved_domain_rfc2606",
                "case": domain,
                "expected": expected,
                "actual": actual,
                "pass": actual == expected,
            }
        )

    return {
        "status": "measured",
        "static_host_suffixes_guarded": len(STATIC_HOST_SUFFIXES),
        "static_host_suffixes": list(STATIC_HOST_SUFFIXES),
        "static_host_guard_extra_exact_hosts": ["github.io"],
        "parked_page_fingerprints": len(PARKED_HTML_FINGERPRINTS),
        "rfc2606_reserved_domains": len(RFC_2606_RESERVED_DOMAINS),
        "rfc2606_reserved_tlds": len(RESERVED_TLDS),
        "guard_self_test": {
            "cases": len(cases),
            "passed": len([c for c in cases if c["pass"]]),
            "failed": len([c for c in cases if not c["pass"]]),
            "all_passed": all(c["pass"] for c in cases),
            "details": cases,
        },
        "static_guard_applied_to_measured_domains": sorted(
            d for d in measured_domains if is_static_hosting_domain(d)
        ),
    }


# --------------------------------------------------------------------------- #
# Measurement 4 - scoring stability over the stored audits
# --------------------------------------------------------------------------- #


def measure_scoring_stability(audits_dir: Path) -> Dict[str, Any]:
    """Replay the current scoring engine over every stored client audit."""
    files = sorted(audits_dir.glob("*/*_audit.md"))
    if not files:
        return {
            "status": "not_measured",
            "not_measured_reason": f"No audit deliverables found under {audits_dir}.",
            "audits_parsed": 0,
        }

    rows: List[Dict[str, Any]] = []
    mismatches: List[str] = []
    severity_counts: Dict[str, int] = {}
    scored_total = 0
    ignored_total = 0
    audits_with_exploitable = 0
    for path in files:
        parsed = rescore_audit_evidence.parse_audit(path)
        row = rescore_audit_evidence.rescore(parsed)
        rows.append(row)
        if parsed.header_score is not None and parsed.header_score != row["old_score"]:
            mismatches.append(
                f"{row['file']}: published header score {parsed.header_score} != "
                f"recomputed legacy score {row['old_score']}"
            )
        for finding in parsed.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        items = [
            ScoreItem(title=f.title, severity=Severity(f.severity), category="")
            for f in parsed.findings
        ]
        engine = score_findings(items)
        scored_total += engine.scored_findings
        ignored_total += engine.ignored_findings
        if engine.has_critical or engine.has_high:
            audits_with_exploitable += 1

    new_grades: Dict[str, int] = {}
    old_grades: Dict[str, int] = {}
    for row in rows:
        new_grades[row["new_grade"]] = new_grades.get(row["new_grade"], 0) + 1
        old_grades[row["old_grade"]] = old_grades.get(row["old_grade"], 0) + 1

    order = ["A+", "A", "B", "C", "D", "F"]
    deltas = [int(r["delta"]) for r in rows]
    old_fail = [r for r in rows if r["old_grade"] in ("D", "F")]
    new_fail = [r for r in rows if r["new_grade"] in ("D", "F")]
    rescued = [r for r in rows if r["old_grade"] in ("D", "F") and r["new_grade"] not in ("D", "F")]
    worsened = [r for r in rows if r["old_grade"] not in ("D", "F") and r["new_grade"] in ("D", "F")]

    return {
        "status": "measured",
        "source": str(audits_dir.relative_to(REPO_ROOT)).replace("\\", "/"),
        "audits_parsed": len(rows),
        "findings_parsed": sum(int(r["findings"]) for r in rows),
        "findings_by_severity": {
            sev: severity_counts.get(sev, 0)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "findings_scored_as_risk": scored_total,
        "findings_reported_as_hygiene": ignored_total,
        "audits_with_critical_or_high": audits_with_exploitable,
        "audits_without_critical_or_high": len(rows) - audits_with_exploitable,
        "scoring_engine": "orbit_security.scoring.score_findings",
        "grade_distribution": {g: new_grades.get(g, 0) for g in order if g in new_grades},
        "legacy_grade_distribution": {g: old_grades.get(g, 0) for g in order if g in old_grades},
        "audits_whose_grade_changed": len([r for r in rows if r["old_grade"] != r["new_grade"]]),
        "failing_before_d_or_f": len(old_fail),
        "failing_after_d_or_f": len(new_fail),
        "rescued_from_d_or_f": len(rescued),
        "newly_failing": len(worsened),
        "exploitability_floor_applied": len([r for r in rows if r["floor_applied"]]),
        "mean_score_delta": round(sum(deltas) / len(deltas), 2) if deltas else None,
        "min_score_delta": min(deltas) if deltas else None,
        "max_score_delta": max(deltas) if deltas else None,
        "parser_fidelity_mismatches": mismatches,
        "parser_fidelity_ok": not mismatches,
        "parser_fidelity_note": (
            "The legacy flat-penalty model is replayed against every audit and "
            "compared with the score printed in the delivered document. A "
            "mismatch would mean the parser no longer understands the "
            "deliverable format."
        ),
    }


# --------------------------------------------------------------------------- #
# Environment + output
# --------------------------------------------------------------------------- #


def git_commit() -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except Exception:
        pass
    return None


def build_environment() -> Dict[str, Any]:
    from orbit_security.dns_cache import DEFAULT_DNS_HOST, DEFAULT_DNS_PORT, is_dns_cache_running

    local_cache = is_dns_cache_running(DEFAULT_DNS_HOST, DEFAULT_DNS_PORT)
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "httpx_version": getattr(httpx, "__version__", None),
        "dnspython_version": getattr(dns.version, "version", None),
        "dns_resolvers": ["1.1.1.1", "1.0.0.0", "8.8.8.8", "8.8.4.4"],
        "local_dns_cache_daemon_running": local_cache,
        "local_dns_cache_endpoint": f"{DEFAULT_DNS_HOST}:{DEFAULT_DNS_PORT}" if local_cache else None,
        "dns_resolver_note": (
            "Orbit resolves through orbit_security.dns_cache. When the local "
            "cache daemon is running, its 127.0.0.1:53 socket is queried "
            "first and the public recursive resolvers are only used by that "
            "daemon on a cache miss. Repeat audits of the same domain "
            "therefore reuse cached answers - see the cold/warm split in the "
            "latency measurement."
        ),
    }


def normalize_domain(raw: str) -> str:
    """Turn a targets-file line into a bare hostname."""
    text = (raw or "").strip().lstrip("\ufeff").strip()
    text = text.split("#", 1)[0].strip()
    for scheme in ("http://", "https://"):
        if text.lower().startswith(scheme):
            text = text[len(scheme) :]
            break
    text = text.split("/", 1)[0].strip()
    text = text.rstrip(".").strip().lower()
    if text.startswith("*."):
        text = text[2:]
    return text


def parse_targets_file(path: Path) -> List[str]:
    domains: List[str] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domain = normalize_domain(line)
        if domain:
            domains.append(domain)
    return domains


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_benchmark.py",
        description="Reproducible Orbit Security benchmark (latency, signature coverage, guards, scoring).",
    )
    parser.add_argument(
        "--targets",
        type=Path,
        default=None,
        help="File with one domain per line ('#' comments allowed). Defaults to a small public set.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="How many times to audit every target (default: 1).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"JSON output path (default: {DEFAULT_OUT.relative_to(REPO_ROOT)}).",
    )
    parser.add_argument(
        "--min-interval",
        type=float,
        default=1.0,
        help="Minimum seconds between requests to the same host (floor: 1.0s).",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Skip every outbound request; measure only the offline metrics.",
    )
    parser.add_argument(
        "--audits-dir",
        type=Path,
        default=DEFAULT_AUDITS_DIR,
        help="Directory holding the stored audit deliverables (read-only).",
    )
    parser.add_argument("--quiet", action="store_true", help="Only print the summary.")
    args = parser.parse_args(argv)

    if args.repeat < 1:
        parser.error("--repeat must be >= 1")

    interval = max(MIN_REQUEST_INTERVAL_S, float(args.min_interval))
    if interval != float(args.min_interval):
        print(
            f"[!] --min-interval raised to {interval}s: the benchmark never sends "
            f"more than 1 request per second to a host.",
            file=sys.stderr,
        )

    if args.targets:
        if not args.targets.is_file():
            print(f"ERROR: targets file not found: {args.targets}", file=sys.stderr)
            return 2
        targets = parse_targets_file(args.targets)
        target_source = str(args.targets)
    else:
        targets = list(DEFAULT_TARGETS)
        target_source = "built-in default public set"

    if not args.quiet:
        print("Orbit Security benchmark")
        print(f"  targets      : {len(targets)} ({target_source})")
        print(f"  repeat       : {args.repeat}")
        print(f"  rate limit   : {interval}s minimum between requests to the same host")

    _install_instrumentation()

    started_utc = datetime.now(timezone.utc)
    t_start = time.perf_counter()

    if args.no_network:
        latency: Dict[str, Any] = {
            "status": "not_measured",
            "not_measured_reason": "--no-network was passed: no outbound request was made.",
            "unit": "milliseconds",
            "targets": targets,
            "repeat": args.repeat,
            "samples_total": 0,
            "samples_usable": 0,
            "wall_ms": summarize([]),
            "active_ms": summarize([]),
            "phase_breakdown": {
                "dns_ms": summarize([]),
                "http_ms": summarize([]),
                "scoring_ms": summarize([]),
                "throttle_sleep_ms": summarize([]),
            },
            "dns_cache_split": {
                "note": "not measured - no outbound request was made.",
                "cold_repeat_1": {"samples": 0, "active_ms": summarize([]), "dns_ms": summarize([]), "wall_ms": summarize([])},
                "warm_repeats_2_plus": {"samples": 0, "active_ms": summarize([]), "dns_ms": summarize([]), "wall_ms": summarize([])},
            },
            "grade_stability": {
                "domains_compared": 0,
                "domains_with_identical_grade_across_repeats": 0,
                "grade_stability_rate": None,
            },
            "per_domain": {},
            "samples": [],
        }
    else:
        if not args.quiet:
            print("  measuring per-domain audit latency ...")
        latency = measure_latency(targets, args.repeat, interval)

    signature_coverage = measure_signature_coverage()
    guards = measure_false_positive_guards(targets)
    scoring = measure_scoring_stability(args.audits_dir)

    duration_s = time.perf_counter() - t_start
    generated_utc = datetime.now(timezone.utc)

    argv_list = list(sys.argv if argv is None else argv)
    command_line = " ".join([sys.executable, "scripts/run_benchmark.py", *argv_list[1:]])

    results: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "benchmark": "Orbit Security perimeter audit benchmark",
        "generated_utc": generated_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "started_utc": started_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "duration_s": round(duration_s, 2),
        "command_line": command_line,
        "argv": argv_list,
        "repo_commit": git_commit(),
        "methodology": {
            "audit_definition": (
                "One domain audit = orbit_security.recon.resolve_dns() + "
                "orbit_security.recon.check_headers_and_exposures() + "
                "orbit_security.recon.calculate_score() + "
                "orbit_security.recon.calculate_grade() - the exact sequence "
                "the orbit-recon CLI runs for a single target."
            ),
            "clock": "time.perf_counter() (monotonic, highest available resolution)",
            "percentile_method": "nearest-rank, no interpolation",
            "rate_limit_per_host_per_second": 1.0 / interval,
            "rate_limit_enforcement": (
                "httpx.Client.send and dns.resolver.Resolver.resolve are "
                "wrapped in-process; every outbound request sleeps so that no "
                "host receives more than one request per second."
            ),
            "targets": targets,
            "target_source": target_source,
            "repeat": args.repeat,
            "network_enabled": not args.no_network,
            "claims_under_test": {
                "< 12 seconds per domain audit": MARKETING_CLAIM_SECONDS,
                "40+ takeover signatures": 40,
            },
            "claims_note": (
                "The claim values are recorded only so the published page can "
                "compare a real measurement against them. They are never used "
                "as, or mixed into, a measured number."
            ),
        },
        "environment": build_environment(),
        "measurements": {
            "audit_latency": latency,
            "signature_coverage": signature_coverage,
            "false_positive_guards": guards,
            "scoring_stability": scoring,
        },
    }

    out_path = args.out if args.out.is_absolute() else REPO_ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, sort_keys=False) + "\n", encoding="utf-8", newline="\n")

    if not args.quiet:
        print()
        print(f"  wrote {out_path.relative_to(REPO_ROOT)}")
        wall = latency.get("wall_ms") or {}
        active = latency.get("active_ms") or {}
        if latency.get("status") == "measured":
            print(
                "  audit latency  wall p50/p95 = "
                f"{wall.get('p50')} ms / {wall.get('p95')} ms   "
                f"active p50/p95 = {active.get('p50')} ms / {active.get('p95')} ms"
            )
        else:
            print(f"  audit latency  NOT MEASURED: {latency.get('not_measured_reason')}")
        sig = signature_coverage
        print(
            f"  signatures     {sig['provider_signatures']} providers / "
            f"{sig['distinct_provider_fingerprints']} fingerprints / "
            f"{sig['distinct_dangling_hostname_classes']} hostname classes"
        )
        print(
            f"  guards         {guards['guard_self_test']['passed']}/"
            f"{guards['guard_self_test']['cases']} self-test cases pass"
        )
        print(
            f"  scoring        {scoring.get('audits_parsed')} audits -> "
            f"{scoring.get('grade_distribution')}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
