"""Unit and regression tests for Fleet Command Center Scoring Parity & Per-Client Score Deltas (Milestone M5).

Covers:
- record_score_delta() calculation (old_score, new_score, score_change, critical_findings, high_findings, grade)
- Exploitability floor and ceiling invariants via score_findings
- Blackboard broadcasting with event_type="fleet_score_delta" to TOPIC_TELEMETRY
- Drift detection in run_daily_drift_sweep() for regressions > 5 points or CRITICAL findings > 0
- Unknown client handling (ValueError)
- Initial scan handling (old_score is None -> score_change = 0)
- broadcast=False flag
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest

from orbit_security.blackboard import Blackboard, TOPIC_TELEMETRY
from orbit_security.fleet import ClientTarget, DriftEvent, FleetRegistry, FleetSentinel
from orbit_security.models import DomainAuditResult, Finding, Severity
from orbit_security.scoring import score_findings


@pytest.fixture
def temp_registry(tmp_path: Path) -> FleetRegistry:
    data_file = tmp_path / "clients.json"
    return FleetRegistry(data_path=data_file)


@pytest.fixture
def temp_blackboard(tmp_path: Path) -> Blackboard:
    db_file = tmp_path / "test_blackboard.db"
    return Blackboard(db_path=db_file)


def test_record_score_delta_increases_score(temp_registry: FleetRegistry, temp_blackboard: Blackboard):
    client = ClientTarget(
        client_id="client-up",
        client_name="Improving Agency Client",
        apex_domain="improving.example.com",
        last_score=70,
        last_grade="C",
    )
    temp_registry.add_client(client)

    sentinel = FleetSentinel(registry=temp_registry, blackboard=temp_blackboard)

    # Empty findings list corresponds to a clean 100 A+ audit
    delta = sentinel.record_score_delta(client_id="client-up", findings=[], broadcast=True)

    assert delta["client_id"] == "client-up"
    assert delta["old_score"] == 70
    assert delta["new_score"] == 100
    assert delta["score_change"] == 30
    assert delta["critical_findings"] == 0
    assert delta["high_findings"] == 0
    assert delta["grade"] == "A+"

    # Verify registry was updated
    updated = temp_registry.get_client("client-up")
    assert updated is not None
    assert updated.last_score == 100
    assert updated.last_grade == "A+"


def test_record_score_delta_decreases_score(temp_registry: FleetRegistry, temp_blackboard: Blackboard):
    client = ClientTarget(
        client_id="client-down",
        client_name="Degrading Agency Client",
        apex_domain="degrading.example.com",
        last_score=95,
        last_grade="A+",
    )
    temp_registry.add_client(client)

    sentinel = FleetSentinel(registry=temp_registry, blackboard=temp_blackboard)

    crit_finding = Finding(
        title="Dangling CNAME / Subdomain Takeover",
        severity=Severity.CRITICAL,
        category="Subdomain & DNS",
        description="Unclaimed cloud resource",
        remediation="Remove CNAME",
        target="degrading.example.com",
    )

    delta = sentinel.record_score_delta(client_id="client-down", findings=[crit_finding], broadcast=True)

    assert delta["client_id"] == "client-down"
    assert delta["old_score"] == 95
    assert delta["critical_findings"] == 1
    assert delta["high_findings"] == 0
    # CRITICAL finding forces ceiling <= 59
    assert delta["new_score"] <= 59
    assert delta["score_change"] <= -36
    assert delta["grade"] in ("D", "F")

    # Verify registry persisted updated score
    updated = temp_registry.get_client("client-down")
    assert updated is not None
    assert updated.last_score == delta["new_score"]
    assert updated.last_grade == delta["grade"]


def test_record_score_delta_initial_scan_none_old_score(temp_registry: FleetRegistry, temp_blackboard: Blackboard):
    client = ClientTarget(
        client_id="client-fresh",
        client_name="Fresh Onboarded Client",
        apex_domain="fresh.example.com",
        last_score=None,
        last_grade=None,
    )
    temp_registry.add_client(client)

    sentinel = FleetSentinel(registry=temp_registry, blackboard=temp_blackboard)

    delta = sentinel.record_score_delta(client_id="client-fresh", findings=[], broadcast=True)

    assert delta["old_score"] is None
    assert delta["new_score"] == 100
    assert delta["score_change"] == 0
    assert delta["grade"] == "A+"


def test_record_score_delta_unknown_client_raises(temp_registry: FleetRegistry):
    sentinel = FleetSentinel(registry=temp_registry)

    with pytest.raises(ValueError, match="Client 'unknown-id' not found in registry"):
        sentinel.record_score_delta(client_id="unknown-id", findings=[])


def test_record_score_delta_blackboard_broadcast(temp_registry: FleetRegistry, temp_blackboard: Blackboard):
    client = ClientTarget(
        client_id="client-broadcast",
        client_name="Broadcast Target",
        apex_domain="broadcast.example.com",
        last_score=80,
        last_grade="B",
    )
    temp_registry.add_client(client)

    sentinel = FleetSentinel(registry=temp_registry, blackboard=temp_blackboard)

    delta = sentinel.record_score_delta(client_id="client-broadcast", findings=[], broadcast=True)

    # Check blackboard events
    events = temp_blackboard.get_recent(limit=10, event_type="fleet_score_delta")
    assert len(events) >= 1
    latest = events[0]

    assert latest["topic"] == TOPIC_TELEMETRY
    assert latest["event_type"] == "fleet_score_delta"
    assert latest["source"] == "FleetSentinel"

    payload = latest["payload"]
    assert payload["client_id"] == "client-broadcast"
    assert payload["client_name"] == "Broadcast Target"
    assert payload["domain"] == "broadcast.example.com"
    assert payload["old_score"] == 80
    assert payload["new_score"] == 100
    assert payload["score_change"] == 20
    assert payload["critical_findings"] == 0
    assert payload["high_findings"] == 0
    assert payload["grade"] == "A+"


def test_record_score_delta_broadcast_disabled(temp_registry: FleetRegistry, temp_blackboard: Blackboard):
    client = ClientTarget(
        client_id="client-nobroadcast",
        client_name="Silent Target",
        apex_domain="silent.example.com",
        last_score=85,
        last_grade="B+",
    )
    temp_registry.add_client(client)

    sentinel = FleetSentinel(registry=temp_registry, blackboard=temp_blackboard)

    delta = sentinel.record_score_delta(client_id="client-nobroadcast", findings=[], broadcast=False)
    assert delta["score_change"] == 15

    events = temp_blackboard.get_recent(limit=10, event_type="fleet_score_delta")
    matching = [e for e in events if e.get("payload", {}).get("client_id") == "client-nobroadcast"]
    assert len(matching) == 0


def test_record_score_delta_exploitability_invariants(temp_registry: FleetRegistry):
    sentinel = FleetSentinel(registry=temp_registry)

    # 1. Zero CRITICAL and zero HIGH findings never falls below 60 (exploitability floor)
    client_floor = ClientTarget(
        client_id="client-floor",
        client_name="Floor Target",
        apex_domain="floor.example.com",
        last_score=90,
    )
    temp_registry.add_client(client_floor)

    # Many MEDIUM findings
    many_medium = [
        Finding(
            title=f"Medium Issue {i}",
            severity=Severity.MEDIUM,
            category=f"Category {i}",
            description="Medium risk issue",
            remediation="Fix it",
            target=f"sub{i}.example.com",
        )
        for i in range(10)
    ]
    delta_floor = sentinel.record_score_delta(client_id="client-floor", findings=many_medium, broadcast=False)
    assert delta_floor["critical_findings"] == 0
    assert delta_floor["high_findings"] == 0
    assert delta_floor["new_score"] >= 60
    assert delta_floor["grade"] in ("A+", "A", "B", "C")

    # 2. Hygiene findings (e.g. INFO, missing CSP, BIMI) incur zero score penalty
    client_hygiene = ClientTarget(
        client_id="client-hygiene",
        client_name="Hygiene Target",
        apex_domain="hygiene.example.com",
        last_score=100,
    )
    temp_registry.add_client(client_hygiene)

    hygiene_findings = [
        Finding(
            title="Missing Content Security Policy (CSP)",
            severity=Severity.LOW,
            category="Security Headers",
            description="No CSP header found",
            remediation="Add Content-Security-Policy",
            target="hygiene.example.com",
        ),
        Finding(
            title="Missing BIMI Record",
            severity=Severity.INFO,
            category="Email Authentication",
            description="BIMI not published",
            remediation="Publish BIMI",
            target="hygiene.example.com",
        ),
    ]
    delta_hygiene = sentinel.record_score_delta(client_id="client-hygiene", findings=hygiene_findings, broadcast=False)
    assert delta_hygiene["new_score"] == 100
    assert delta_hygiene["score_change"] == 0
    assert delta_hygiene["grade"] == "A+"

    # 3. >= 1 CRITICAL finding forces ceiling <= 59
    client_crit = ClientTarget(
        client_id="client-crit",
        client_name="Critical Target",
        apex_domain="crit.example.com",
        last_score=100,
    )
    temp_registry.add_client(client_crit)

    crit_findings = [
        Finding(
            title="Dangling CNAME / Takeover Risk",
            severity=Severity.CRITICAL,
            category="Subdomain & DNS",
            description="Dangling pointer",
            remediation="Delete record",
            target="crit.example.com",
        )
    ]
    delta_crit = sentinel.record_score_delta(client_id="client-crit", findings=crit_findings, broadcast=False)
    assert delta_crit["critical_findings"] == 1
    assert delta_crit["new_score"] <= 59


@pytest.mark.asyncio
async def test_run_daily_drift_sweep_integration(temp_registry: FleetRegistry, temp_blackboard: Blackboard):
    """Verifies that run_daily_drift_sweep() records score deltas, triggers DriftEvent

    for regressions > 5 points or CRITICAL findings > 0, and broadcasts events.
    """
    # Setup 3 clients:
    # 1. Regressed client (> 5 points drift)
    # 2. Critical client (has critical finding)
    # 3. Stable / improving client (score improves)
    client_regressed = ClientTarget(
        client_id="c-regressed",
        client_name="Regressed Client",
        apex_domain="regressed.com",
        last_score=90,
        last_grade="A",
    )
    client_critical = ClientTarget(
        client_id="c-critical",
        client_name="Critical Client",
        apex_domain="critical.com",
        last_score=58,
        last_grade="D",
    )
    client_stable = ClientTarget(
        client_id="c-stable",
        client_name="Stable Client",
        apex_domain="stable.com",
        last_score=85,
        last_grade="B+",
    )

    temp_registry.add_client(client_regressed)
    temp_registry.add_client(client_critical)
    temp_registry.add_client(client_stable)

    sentinel = FleetSentinel(registry=temp_registry, blackboard=temp_blackboard)

    # Mock scan results
    finding_high = Finding(
        title="Wildcard DNS Misconfiguration",
        severity=Severity.HIGH,
        category="DNS",
        description="High risk DNS misconfiguration",
        remediation="Restrict wildcards",
        target="regressed.com",
    )
    finding_crit = Finding(
        title="Dangling AWS S3 Bucket CNAME",
        severity=Severity.CRITICAL,
        category="DNS",
        description="Unclaimed S3 bucket",
        remediation="Remove CNAME",
        target="critical.com",
    )

    audit_regressed = DomainAuditResult(domain="regressed.com", findings=[finding_high])
    audit_critical = DomainAuditResult(domain="critical.com", findings=[finding_crit])
    audit_stable = DomainAuditResult(domain="stable.com", findings=[])

    async def fake_scan(client: ClientTarget, branding=None):
        if client.client_id == "c-regressed":
            return audit_regressed
        elif client.client_id == "c-critical":
            return audit_critical
        else:
            return audit_stable

    with patch.object(sentinel, "scan_client", side_effect=fake_scan):
        drift_events = await sentinel.run_daily_drift_sweep()

        # Both regressed and critical should produce DriftEvents
        drift_ids = [e.client_id for e in drift_events]
        assert "c-regressed" in drift_ids
        assert "c-critical" in drift_ids
        assert "c-stable" not in drift_ids

        regressed_ev = next(e for e in drift_events if e.client_id == "c-regressed")
        assert regressed_ev.old_score == 90
        # High finding penalty is 25 -> new score 75 -> score change -15 (< -5)
        assert regressed_ev.score_change <= -5
        assert regressed_ev.high_findings == 1

        crit_ev = next(e for e in drift_events if e.client_id == "c-critical")
        assert crit_ev.critical_findings == 1
        assert crit_ev.new_score <= 59

        # Check blackboard received telemetry events for all 3 clients
        recent_bb_events = temp_blackboard.get_recent(limit=10, event_type="fleet_score_delta")
        bb_client_ids = [e["payload"]["client_id"] for e in recent_bb_events]
        assert "c-regressed" in bb_client_ids
        assert "c-critical" in bb_client_ids
        assert "c-stable" in bb_client_ids
