"""GhostDNS: Dedicated Dangling CNAME & DNS Drift Sentinel (ghost_dns.py).

Commercial micro-SaaS module ($29/mo Store Sentinel, $199/mo Agency Fleet).
Provides:
  1. Headless attack surface and dangling CNAME scanner.
  2. DNS drift detection sentinel (detects unexpected CNAME/A/MX record changes against saved baselines).
  3. JSON API responses for headless integrations and webhook alerts.
  4. Multi-tenant target tracking and automated hygiene grade calculations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import difflib
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.resolver

from orbit_security.dns_cache import get_orbit_sync_resolver
from orbit_security.models import Severity
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES, SaasSignature

logger = logging.getLogger("orbit_security.ghost_dns")

DEFAULT_GHOSTDNS_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "ghostdns_targets.json"
DEFAULT_GHOSTDNS_BASELINES_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "ghostdns_baselines.json"


@dataclass
class DnsRecordSnapshot:
    record_type: str  # CNAME, A, AAAA, MX, TXT, NS
    values: List[str] = field(default_factory=list)
    ttl: int = 300


@dataclass
class DnsBaseline:
    domain: str
    records: Dict[str, List[str]] = field(default_factory=dict)  # {"CNAME": ["..."], "A": ["1.2.3.4"]}
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    last_verified: Optional[str] = None


@dataclass
class DriftAnomaly:
    domain: str
    record_type: str
    previous_values: List[str]
    current_values: List[str]
    severity: Severity
    description: str
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@dataclass
class GhostDNSTarget:
    target_id: str
    domain: str
    client_name: str
    plan: str = "Store"  # "Store" ($29/mo), "Agency" ($199/mo)
    monitored_subdomains: List[str] = field(default_factory=list)
    status: str = "active"  # "active", "paused"
    baseline_id: Optional[str] = None
    last_audit_score: int = 100
    last_audit_grade: str = "A+"
    drift_anomalies_count: int = 0
    dangling_cname_count: int = 0
    last_scanned: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@dataclass
class GhostDNSAuditReport:
    domain: str
    plan: str
    score: int
    grade: str
    is_vulnerable: bool
    dangling_cnames: List[Dict[str, Any]] = field(default_factory=list)
    drift_anomalies: List[Dict[str, Any]] = field(default_factory=list)
    records_probed: Dict[str, List[str]] = field(default_factory=dict)
    summary: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GhostDNSManager:
    """Manages GhostDNS client targets and baseline snapshots."""

    def __init__(
        self,
        targets_file: Optional[Path] = None,
        baselines_file: Optional[Path] = None,
        resolver: Optional[dns.resolver.Resolver] = None,
    ):
        self.targets_file = Path(targets_file or DEFAULT_GHOSTDNS_DATA_PATH)
        self.baselines_file = Path(baselines_file or DEFAULT_GHOSTDNS_BASELINES_PATH)
        self.resolver = resolver or get_orbit_sync_resolver()
        self.targets: Dict[str, GhostDNSTarget] = {}
        self.baselines: Dict[str, DnsBaseline] = {}
        self.load()

    def load(self):
        """Loads targets and baselines from disk."""
        if self.targets_file.exists():
            try:
                with open(self.targets_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.targets = {
                        item["target_id"]: GhostDNSTarget(**item)
                        for item in data.get("targets", [])
                    }
            except Exception as e:
                logger.warning(f"Error loading GhostDNS targets: {e}")
                self.targets = {}
        else:
            self._populate_seed_targets()
            self.save()

        if self.baselines_file.exists():
            try:
                with open(self.baselines_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.baselines = {
                        k: DnsBaseline(**v) for k, v in data.get("baselines", {}).items()
                    }
            except Exception as e:
                logger.warning(f"Error loading GhostDNS baselines: {e}")
                self.baselines = {}

    def save(self):
        """Persists targets and baselines to disk."""
        self.targets_file.parent.mkdir(parents=True, exist_ok=True)
        self.baselines_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.targets_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": "1.0",
                    "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "targets": [asdict(t) for t in self.targets.values()],
                },
                f,
                indent=2,
            )

        with open(self.baselines_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": "1.0",
                    "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "baselines": {k: asdict(v) for k, v in self.baselines.items()},
                },
                f,
                indent=2,
            )

    def _populate_seed_targets(self):
        """Default seed stores enrolled in GhostDNS."""
        seeds = [
            GhostDNSTarget(
                target_id="store-candykittens",
                domain="candykittens.co.uk",
                client_name="Candy Kittens UK",
                plan="Store",
                monitored_subdomains=["shop.candykittens.co.uk", "cdn.candykittens.co.uk"],
                last_audit_score=95,
                last_audit_grade="A",
            ),
            GhostDNSTarget(
                target_id="agency-eastside",
                domain="eastsideco.com",
                client_name="Eastside Co Agency Fleet",
                plan="Agency",
                monitored_subdomains=[
                    "wildfang.com",
                    "trolli.com",
                    "loop-earplugs.com",
                ],
                last_audit_score=90,
                last_audit_grade="A",
            ),
        ]
        self.targets = {t.target_id: t for t in seeds}

    def register_target(
        self,
        domain: str,
        client_name: str,
        plan: str = "Store",
        subdomains: Optional[List[str]] = None,
    ) -> GhostDNSTarget:
        """Enrolls a new domain into GhostDNS monitoring."""
        clean_domain = domain.strip().lower()
        target_id = re.sub(r"[^a-zA-Z0-9_-]", "-", clean_domain)
        target = GhostDNSTarget(
            target_id=target_id,
            domain=clean_domain,
            client_name=client_name,
            plan=plan,
            monitored_subdomains=[s.strip().lower() for s in (subdomains or [])],
        )
        self.targets[target_id] = target
        self.save()
        return target

    def capture_baseline(
        self, domain: str, mock_records: Optional[Dict[str, List[str]]] = None
    ) -> DnsBaseline:
        """Captures and stores authoritative DNS snapshot for drift comparison."""
        clean = domain.strip().lower()
        records: Dict[str, List[str]] = {}

        if mock_records is not None:
            records = mock_records
        else:
            for rtype in ("CNAME", "A", "AAAA", "MX", "TXT"):
                try:
                    answers = self.resolver.resolve(clean, rtype)
                    vals = []
                    for rdata in answers:
                        val = str(rdata).rstrip(".")
                        vals.append(val)
                    if vals:
                        records[rtype] = sorted(vals)
                except Exception:
                    continue

        baseline = DnsBaseline(
            domain=clean,
            records=records,
            last_verified=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        self.baselines[clean] = baseline
        self.save()
        return baseline

    def check_dns_drift(
        self,
        domain: str,
        current_records: Optional[Dict[str, List[str]]] = None,
    ) -> List[DriftAnomaly]:
        """Compares current DNS state against baseline and returns any detected drift anomalies."""
        clean = domain.strip().lower()
        baseline = self.baselines.get(clean)
        if not baseline:
            # No baseline to compare against; capture now
            self.capture_baseline(clean, mock_records=current_records)
            return []

        anomalies: List[DriftAnomaly] = []
        now_records = current_records

        if now_records is None:
            now_records = {}
            for rtype in ("CNAME", "A", "AAAA", "MX", "TXT"):
                try:
                    answers = self.resolver.resolve(clean, rtype)
                    vals = [str(rdata).rstrip(".") for rdata in answers]
                    if vals:
                        now_records[rtype] = sorted(vals)
                except Exception:
                    continue

        base_recs = baseline.records
        all_types = set(base_recs.keys()) | set(now_records.keys())

        for rtype in all_types:
            prev = sorted(base_recs.get(rtype, []))
            curr = sorted(now_records.get(rtype, []))

            if prev != curr:
                sev = Severity.HIGH if rtype in ("CNAME", "MX") else Severity.MEDIUM
                desc = f"DNS record drift detected for {rtype} on {clean}: previous={prev}, current={curr}"
                anomalies.append(
                    DriftAnomaly(
                        domain=clean,
                        record_type=rtype,
                        previous_values=prev,
                        current_values=curr,
                        severity=sev,
                        description=desc,
                    )
                )

        baseline.last_verified = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.save()
        return anomalies

    def scan_for_dangling_cname(
        self,
        domain: str,
        mock_cname: Optional[str] = None,
        mock_body: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Lightweight headless check for dangling CNAME takeovers."""
        clean = domain.strip().lower()
        cname = mock_cname

        if cname is None:
            try:
                answers = self.resolver.resolve(clean, "CNAME")
                for rdata in answers:
                    cname = str(rdata.target).rstrip(".")
                    break
            except Exception:
                cname = None

        if not cname:
            return None

        for sig in SAAS_TAKEOVER_SIGNATURES:
            if any(p in cname for p in sig.cname_patterns):
                body = mock_body
                if body is None:
                    # In headless mode probe body
                    import urllib.request
                    try:
                        req = urllib.request.Request(
                            f"https://{clean}",
                            headers={"User-Agent": "GhostDNS/1.0 (Dangling Sentinel)"},
                        )
                        with urllib.request.urlopen(req, timeout=2.5) as r:
                            body = r.read(4096).decode("utf-8", errors="ignore")
                    except Exception as e:
                        body = str(e)

                for fp in sig.fingerprints:
                    if fp.lower() in (body or "").lower():
                        return {
                            "provider": sig.name,
                            "cname_target": cname,
                            "fingerprint_matched": fp,
                            "remediation": sig.remediation,
                            "severity": Severity.CRITICAL.value,
                        }

        return None

    def execute_audit(
        self,
        domain: str,
        plan: str = "Store",
        mock_records: Optional[Dict[str, List[str]]] = None,
        mock_cname: Optional[str] = None,
        mock_body: Optional[str] = None,
    ) -> GhostDNSAuditReport:
        """Executes full GhostDNS audit combining takeover scan and drift detection."""
        clean = domain.strip().lower()

        # Check takeover
        takeover = self.scan_for_dangling_cname(clean, mock_cname=mock_cname, mock_body=mock_body)
        dangling_list = [takeover] if takeover else []

        # Check drift
        drift = self.check_dns_drift(clean, current_records=mock_records)
        drift_list = [asdict(d) for d in drift]

        penalty = (len(dangling_list) * 40) + (len(drift_list) * 15)
        score = max(0, 100 - penalty)
        grade = "A+" if score >= 95 else ("A" if score >= 88 else ("B" if score >= 75 else "F"))
        is_vuln = bool(dangling_list or drift_list)

        summary = (
            f"GhostDNS audit for {clean}: {len(dangling_list)} dangling CNAME(s), "
            f"{len(drift_list)} record drift anomaly(s). Grade: {grade} ({score}/100)."
        )

        report = GhostDNSAuditReport(
            domain=clean,
            plan=plan,
            score=score,
            grade=grade,
            is_vulnerable=is_vuln,
            dangling_cnames=dangling_list,
            drift_anomalies=drift_list,
            records_probed=mock_records or {},
            summary=summary,
        )

        # Update target state if registered
        target_id = re.sub(r"[^a-zA-Z0-9_-]", "-", clean)
        if target_id in self.targets:
            t = self.targets[target_id]
            t.last_audit_score = score
            t.last_audit_grade = grade
            t.dangling_cname_count = len(dangling_list)
            t.drift_anomalies_count = len(drift_list)
            t.last_scanned = report.timestamp
            self.save()

        return report
