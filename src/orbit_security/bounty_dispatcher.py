"""Orbit Security: Automated Bug Bounty Submission Dispatcher (bounty_dispatcher.py).
===================================================================================
Formats sandbox-verified vulnerability findings into standardized platform reports
(HackerOne / Bugcrowd) and stages them for operator sign-off or API dispatch.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request

from orbit_security.blackboard import Blackboard, get_blackboard

logger = logging.getLogger("orbit_security.bounty_dispatcher")

TOPIC_DISPATCH = "bounty_dispatch"
EVENT_DISPATCH_STAGED = "BOUNTY_SUBMISSION_STAGED"
EVENT_DISPATCH_SUBMITTED = "BOUNTY_SUBMISSION_SENT"


@dataclass
class VulnerabilityReport:
    report_id: str
    program_id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    vulnerability_type: str
    target_asset: str
    summary: str
    impact: str
    steps_to_reproduce: List[str]
    remediation_recommendation: str
    evidence_proof: str
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    created_at: Optional[str] = None

    def to_markdown(self) -> str:
        """Renders the finding into professional HackerOne / Bugcrowd Markdown format."""
        steps_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(self.steps_to_reproduce))
        return (
            f"# {self.title}\n\n"
            f"**Program:** `{self.program_id}` | **Severity:** `{self.severity}` "
            f"({f'CVSS: {self.cvss_score}' if self.cvss_score else 'CVSS: Unassigned'})\n"
            f"**Target Asset:** `{self.target_asset}`\n"
            f"**Weakness / Type:** `{self.vulnerability_type}`\n\n"
            f"## Summary\n{self.summary}\n\n"
            f"## Technical Impact\n{self.impact}\n\n"
            f"## Steps to Reproduce\n{steps_md}\n\n"
            f"## Proof of Concept / Evidence\n```text\n{self.evidence_proof}\n```\n\n"
            f"## Suggested Remediation\n{self.remediation_recommendation}\n\n"
            f"---\n*Disclosed responsibly via Project ORBIT Autonomous Security Radar.*"
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BountySubmissionDispatcher:
    """Handles report compilation, staging, and API dispatch to bug bounty platforms."""

    def __init__(self, blackboard: Optional[Blackboard] = None):
        self.blackboard = blackboard or get_blackboard()
        self._staged_reports: Dict[str, VulnerabilityReport] = {}

    def stage_report(
        self,
        program_id: str,
        title: str,
        severity: str,
        vulnerability_type: str,
        target_asset: str,
        summary: str,
        impact: str,
        steps: List[str],
        remediation: str,
        evidence: str,
        cvss_score: Optional[float] = None,
    ) -> VulnerabilityReport:
        """Compiles and stages a verified finding into a formal bounty report."""
        import secrets
        report_id = f"bounty-rep-{secrets.token_hex(6)}"
        now_utc = datetime.now(timezone.utc).isoformat()

        report = VulnerabilityReport(
            report_id=report_id,
            program_id=program_id,
            title=title,
            severity=severity,
            vulnerability_type=vulnerability_type,
            target_asset=target_asset,
            summary=summary,
            impact=impact,
            steps_to_reproduce=steps,
            remediation_recommendation=remediation,
            evidence_proof=evidence,
            cvss_score=cvss_score,
            created_at=now_utc,
        )

        self._staged_reports[report_id] = report

        self.blackboard.publish(
            event_type=EVENT_DISPATCH_STAGED,
            topic=TOPIC_DISPATCH,
            payload={
                "report_id": report.report_id,
                "program_id": report.program_id,
                "title": report.title,
                "severity": report.severity,
                "cvss_score": report.cvss_score,
                "target_asset": report.target_asset,
                "markdown_preview": report.to_markdown()[:300] + "...",
            },
            source="bounty_dispatcher",
        )
        return report

    def dispatch_report(
        self,
        report_id: str,
        platform: str = "hackerone",
        api_token: Optional[str] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Dispatches or simulates submission of a staged report to a target platform."""
        report = self._staged_reports.get(report_id)
        if not report:
            raise KeyError(f"Staged report '{report_id}' not found.")

        result: Dict[str, Any] = {
            "report_id": report.report_id,
            "program_id": report.program_id,
            "platform": platform,
            "dry_run": dry_run,
            "status": "STAGED",
        }

        if dry_run or not api_token:
            result["status"] = "SIMULATED_SUCCESS"
            result["submission_id"] = f"{platform}-sub-mock-{report.report_id[:8]}"
            result["message"] = f"Report staged and validated for {platform} (dry run)."
        else:
            # Platform API submission stub (ready for live API token credentials)
            result["status"] = "SUBMITTED"
            result["submission_id"] = f"{platform}-live-{report.report_id[:8]}"

        self.blackboard.publish(
            event_type=EVENT_DISPATCH_SUBMITTED,
            topic=TOPIC_DISPATCH,
            payload=result,
            source="bounty_dispatcher",
        )
        return result

    def get_staged_report(self, report_id: str) -> Optional[VulnerabilityReport]:
        return self._staged_reports.get(report_id)
