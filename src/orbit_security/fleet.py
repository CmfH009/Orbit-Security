"""Orbit Security Fleet Management & Multi-Client Retainer Registry (fleet.py).

Provides persistent client target management, scheduled continuous surveillance,
score drift detection, and automated monthly executive PDF generation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from orbit_security.blackboard import TOPIC_TELEMETRY, Blackboard, get_blackboard
from orbit_security.models import AgencyBranding, DomainAuditResult, Finding, Severity
from orbit_security.reporter import ReportGenerator
from orbit_security.scanner import OrbitSecurityScanner
from orbit_security.scoring import coerce_severity, score_findings

DEFAULT_FLEET_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "clients.json"


@dataclass
class ClientTarget:
    client_id: str
    client_name: str
    apex_domain: str
    subdomains: List[str] = field(default_factory=list)
    contact_email: Optional[str] = None
    agency_id: str = "orbit-core"
    retainer_plan: str = "Growth"  # Growth ($59/mo), Scale ($149/mo), Enterprise ($399/mo)
    status: str = "active"  # active, paused, archived
    last_scanned: Optional[str] = None
    last_score: Optional[int] = None
    last_grade: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


class FleetRegistry:
    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = Path(data_path or DEFAULT_FLEET_DATA_PATH)
        self.clients: Dict[str, ClientTarget] = {}
        self.load()

    def load(self):
        """Loads client registry from disk."""
        if not self.data_path.exists():
            self.clients = {}
            return

        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.clients = {
                    item["client_id"]: ClientTarget(**item) for item in data.get("clients", [])
                }
        except Exception:
            self.clients = {}

    def save(self):
        """Persists client registry to disk atomically."""
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": "1.0",
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "clients": [asdict(client) for client in self.clients.values()],
        }
        temp_path = self.data_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_path.replace(self.data_path)

    def add_client(self, client: ClientTarget) -> ClientTarget:
        self.clients[client.client_id] = client
        self.save()
        return client

    def get_client(self, client_id: str) -> Optional[ClientTarget]:
        return self.clients.get(client_id)

    def list_active(self) -> List[ClientTarget]:
        return [c for c in self.clients.values() if c.status == "active"]

    def update_scan_metrics(self, client_id: str, score: int, grade: str):
        if client_id in self.clients:
            client = self.clients[client_id]
            client.last_score = score
            client.last_grade = grade
            client.last_scanned = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.save()


@dataclass
class DriftEvent:
    client_id: str
    client_name: str
    domain: str
    old_score: Optional[int]
    new_score: int
    score_change: int
    critical_findings: int
    high_findings: int
    findings: List[Finding] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


class FleetSentinel:
    def __init__(
        self,
        registry: Optional[FleetRegistry] = None,
        scanner: Optional[OrbitSecurityScanner] = None,
        blackboard: Optional[Blackboard] = None,
    ):
        self.registry = registry or FleetRegistry()
        self.scanner = scanner or OrbitSecurityScanner()
        self.blackboard = blackboard

    def record_score_delta(
        self,
        client_id: str,
        findings: Iterable[Any],
        broadcast: bool = True,
        override_score: Optional[int] = None,
        override_grade: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Calculates scoring parity delta via score_findings, updates client metrics,
        and broadcasts 'fleet_score_delta' event to blackboard.
        """
        client = self.registry.get_client(client_id)
        if not client:
            raise ValueError(f"Client '{client_id}' not found in registry")

        old_score = client.last_score
        audit_score = score_findings(findings)
        new_score = override_score if override_score is not None else audit_score.score
        grade = override_grade if override_grade is not None else audit_score.grade

        critical_findings = sum(
            1 for f in findings if coerce_severity(getattr(f, "severity", None)) == Severity.CRITICAL
        )
        high_findings = sum(
            1 for f in findings if coerce_severity(getattr(f, "severity", None)) == Severity.HIGH
        )

        score_change = (new_score - old_score) if old_score is not None else 0

        self.registry.update_scan_metrics(client_id, new_score, grade)

        delta_record = {
            "client_id": client_id,
            "client_name": client.client_name,
            "domain": client.apex_domain,
            "old_score": old_score,
            "new_score": new_score,
            "score_change": score_change,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "grade": grade,
        }

        if broadcast:
            try:
                bb = self.blackboard or get_blackboard()
                bb.publish(
                    event_type="fleet_score_delta",
                    payload=delta_record,
                    source="FleetSentinel",
                    topic=TOPIC_TELEMETRY,
                )
            except Exception:
                pass

        return {
            "client_id": client_id,
            "client_name": client.client_name,
            "domain": client.apex_domain,
            "old_score": old_score,
            "new_score": new_score,
            "score_change": score_change,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "grade": grade,
        }

    async def scan_client(
        self, client: ClientTarget, agency_branding: Optional[AgencyBranding] = None
    ) -> DomainAuditResult:
        branding = agency_branding or AgencyBranding(
            agency_name=f"{client.client_name} Perimeter Security",
            support_email=client.contact_email or "security@orbitsecurity.io",
        )
        result = await self.scanner.scan_domain(
            domain=client.apex_domain,
            subdomains=client.subdomains,
            agency_branding=branding,
        )
        return result

    async def run_daily_drift_sweep(
        self, agency_branding: Optional[AgencyBranding] = None
    ) -> List[DriftEvent]:
        """Runs automated perimeter hygiene scan across all active fleet clients,
        identifying posture regressions and critical findings.
        """
        active_clients = self.registry.list_active()
        drift_events: List[DriftEvent] = []

        for client in active_clients:
            audit_result = await self.scan_client(client, agency_branding)

            override_score = None
            override_grade = None
            if hasattr(audit_result, "score") and hasattr(audit_result, "findings"):
                computed = score_findings(audit_result.findings)
                if audit_result.score != computed.score and audit_result.score != 100:
                    override_score = audit_result.score
                    override_grade = audit_result.grade

            delta = self.record_score_delta(
                client.client_id,
                audit_result.findings,
                broadcast=True,
                override_score=override_score,
                override_grade=override_grade,
            )

            if delta["score_change"] < -5 or delta["critical_findings"] > 0:
                drift_events.append(
                    DriftEvent(
                        client_id=client.client_id,
                        client_name=client.client_name,
                        domain=client.apex_domain,
                        old_score=delta["old_score"],
                        new_score=delta["new_score"],
                        score_change=delta["score_change"],
                        critical_findings=delta["critical_findings"],
                        high_findings=delta["high_findings"],
                        findings=audit_result.findings,
                    )
                )

        return drift_events

    async def run_monthly_report_batch(
        self,
        output_dir: Path,
        agency_branding: Optional[AgencyBranding] = None,
    ) -> List[Path]:
        """Generates executive co-branded PDF audits for all active fleet clients."""
        output_dir.mkdir(parents=True, exist_ok=True)
        generated_reports: List[Path] = []
        month_stamp = datetime.datetime.now().strftime("%Y-%m")

        for client in self.registry.list_active():
            audit_result = await self.scan_client(client, agency_branding)
            self.registry.update_scan_metrics(
                client.client_id, audit_result.score, audit_result.grade
            )

            report_filename = f"{client.client_id}_{month_stamp}_audit.pdf"
            pdf_path = output_dir / report_filename

            ReportGenerator.generate_pdf(audit_result, str(pdf_path))
            generated_reports.append(pdf_path)

        return generated_reports
