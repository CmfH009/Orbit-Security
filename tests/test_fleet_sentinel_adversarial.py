"""Adversarial stress harness and empirical challenge suite for Milestone M5.

Targets:
- FleetSentinel.record_score_delta()
- Exploitability model boundary conditions (R1-R5) under load
- Blackboard failure recovery & fault isolation
- High-volume stress (500+ and 1,000+ findings)
- Duplicate class penalty capping under repeat barrage
- Unexpected severities and duck-typed finding inputs
- Rapid sequential score deltas and telemetry chaining
- Concurrent async execution safety
"""

import asyncio
from pathlib import Path
import time
from typing import List
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.blackboard import Blackboard, TOPIC_TELEMETRY
from orbit_security.fleet import ClientTarget, FleetRegistry, FleetSentinel
from orbit_security.models import Finding, Severity
from orbit_security.scoring import (
    CLASS_PENALTY_CAP,
    EXPLOITABILITY_CEILING_SCORE,
    EXPLOITABILITY_FLOOR_SCORE,
    ScoreItem,
)


@pytest.fixture
def adversarial_registry(tmp_path: Path) -> FleetRegistry:
    data_file = tmp_path / "adversarial_clients.json"
    return FleetRegistry(data_path=data_file)


@pytest.fixture
def adversarial_blackboard(tmp_path: Path) -> Blackboard:
    db_file = tmp_path / "adversarial_bb.db"
    return Blackboard(db_path=db_file)


# =========================================================================== #
# 1. Extreme Finding Volumes (500+ and 1,000+ findings)
# =========================================================================== #


def test_extreme_volume_1000_findings_performance(adversarial_registry: FleetRegistry):
    """Stress tests record_score_delta with 1,000 findings, verifying sub-second

    execution and arithmetic clamping at 0 / Grade F.
    """
    client = ClientTarget(
        client_id="stress-vol-1",
        client_name="Volume Target",
        apex_domain="volume.example.com",
        last_score=100,
        last_grade="A+",
    )
    adversarial_registry.add_client(client)
    sentinel = FleetSentinel(registry=adversarial_registry)

    # 250 CRITICAL, 250 HIGH, 250 MEDIUM, 250 LOW
    findings: List[Finding] = []
    for i in range(250):
        findings.append(Finding(title=f"Critical Issue {i}", severity=Severity.CRITICAL, description="c", remediation="r"))
        findings.append(Finding(title=f"High Issue {i}", severity=Severity.HIGH, description="h", remediation="r"))
        findings.append(Finding(title=f"Medium Issue {i}", severity=Severity.MEDIUM, description="m", remediation="r"))
        findings.append(Finding(title=f"Low Issue {i}", severity=Severity.LOW, description="l", remediation="r"))

    t0 = time.perf_counter()
    delta = sentinel.record_score_delta(client_id="stress-vol-1", findings=findings, broadcast=False)
    elapsed = time.perf_counter() - t0

    # Execution must be fast (< 250ms)
    assert elapsed < 0.25, f"1,000 findings took {elapsed:.4f}s (> 0.25s)"
    assert delta["client_id"] == "stress-vol-1"
    assert delta["old_score"] == 100
    assert delta["new_score"] == 0
    assert delta["score_change"] == -100
    assert delta["critical_findings"] == 250
    assert delta["high_findings"] == 250
    assert delta["grade"] == "F"

    # Verify registry persisted
    updated = adversarial_registry.get_client("stress-vol-1")
    assert updated is not None
    assert updated.last_score == 0
    assert updated.last_grade == "F"


# =========================================================================== #
# 2. Repeat Duplicates & Diminishing Returns (Class Penalty Capping)
# =========================================================================== #


def test_repeat_duplicates_class_penalty_cap(adversarial_registry: FleetRegistry):
    """Verifies that 1,000 duplicate findings belonging to the same finding class

    do not drive score to 0, but strictly obey the CLASS_PENALTY_CAP (R3 rule).
    """
    client = ClientTarget(
        client_id="stress-dup-1",
        client_name="Duplicate Target",
        apex_domain="dup.example.com",
        last_score=100,
        last_grade="A+",
    )
    adversarial_registry.add_client(client)
    sentinel = FleetSentinel(registry=adversarial_registry)

    # 1,000 findings with identical class: "Dangling CNAME / Subdomain Takeover"
    findings = [
        Finding(
            title="Dangling CNAME / Subdomain Takeover Risk",
            severity=Severity.CRITICAL,
            description="Takeover",
            remediation="Delete DNS record",
            target=f"sub{i}.dup.example.com",
        )
        for i in range(1000)
    ]

    delta = sentinel.record_score_delta(client_id="stress-dup-1", findings=findings, broadcast=False)

    # Under R3: CLASS_PENALTY_CAP for CRITICAL is 50
    # Score must be 100 - 50 = 50, Grade D
    assert delta["critical_findings"] == 1000
    assert delta["high_findings"] == 0
    assert delta["new_score"] == (100 - CLASS_PENALTY_CAP[Severity.CRITICAL])
    assert delta["new_score"] == 50
    assert delta["score_change"] == -50
    assert delta["grade"] == "D"


# =========================================================================== #
# 3. Unexpected & Adversarial Severities Fuzzing
# =========================================================================== #


def test_unexpected_severities_and_duck_typed_findings(adversarial_registry: FleetRegistry):
    """Verifies that malformed, unexpected, or non-enum severity values are

    coerced safely without throwing exceptions or corrupting score deltas.
    """
    client = ClientTarget(
        client_id="stress-fuzz-1",
        client_name="Fuzz Target",
        apex_domain="fuzz.example.com",
        last_score=100,
        last_grade="A+",
    )
    adversarial_registry.add_client(client)
    sentinel = FleetSentinel(registry=adversarial_registry)

    # Duck-typed findings with unconventional severity formats
    fuzz_findings = [
        ScoreItem(title="Unknown Severity String", severity="UNKNOWN_SEV"),
        ScoreItem(title="None Severity", severity=None),
        ScoreItem(title="Empty String Severity", severity=""),
        ScoreItem(title="Integer Severity", severity=999),
        ScoreItem(title="Mixed-Case Critical", severity="critical"),  # should coerce to CRITICAL
        ScoreItem(title="Mixed-Case High", severity="High"),          # should coerce to HIGH
    ]

    delta = sentinel.record_score_delta(client_id="stress-fuzz-1", findings=fuzz_findings, broadcast=False)

    # "critical" -> CRITICAL (1), "High" -> HIGH (1), others -> INFO
    assert delta["critical_findings"] == 1
    assert delta["high_findings"] == 1
    # Since 1 CRITICAL is present, exploitability ceiling <= 59 applies
    assert delta["new_score"] <= EXPLOITABILITY_CEILING_SCORE
    assert delta["grade"] in ("D", "F")


# =========================================================================== #
# 4. Rapid Sequential Score Deltas (50 Iterations)
# =========================================================================== #


def test_rapid_sequential_deltas_chaining(adversarial_registry: FleetRegistry):
    """Verifies that 50 rapid sequential updates maintain strict old_score ->

    new_score chaining and delta arithmetic across multiple oscillations.
    """
    client = ClientTarget(
        client_id="stress-seq-1",
        client_name="Sequential Target",
        apex_domain="seq.example.com",
        last_score=100,
        last_grade="A+",
    )
    adversarial_registry.add_client(client)
    sentinel = FleetSentinel(registry=adversarial_registry)

    crit_finding = Finding(title="Takeover", severity=Severity.CRITICAL, description="c", remediation="r")
    high_finding = Finding(title="Exposed Git", severity=Severity.HIGH, description="h", remediation="r")

    expected_old_score = 100

    for iteration in range(50):
        # Alternate between 3 states:
        # A: clean (score 100)
        # B: high finding (score 80)
        # C: crit finding (score 59)
        phase = iteration % 3
        if phase == 0:
            test_findings = []
            expected_new_score = 100
        elif phase == 1:
            test_findings = [high_finding]
            expected_new_score = 80
        else:
            test_findings = [crit_finding]
            expected_new_score = 59

        delta = sentinel.record_score_delta(client_id="stress-seq-1", findings=test_findings, broadcast=False)

        assert delta["old_score"] == expected_old_score, f"Iter {iteration}: old_score mismatch"
        assert delta["new_score"] == expected_new_score, f"Iter {iteration}: new_score mismatch"
        assert delta["score_change"] == (expected_new_score - expected_old_score), f"Iter {iteration}: delta mismatch"

        expected_old_score = expected_new_score

    # Check final persisted state
    persisted = adversarial_registry.get_client("stress-seq-1")
    assert persisted is not None
    assert persisted.last_score == expected_new_score


# =========================================================================== #
# 5. Blackboard Failure Recovery & Fault Isolation
# =========================================================================== #


def test_blackboard_publish_exception_isolation(adversarial_registry: FleetRegistry):
    """Verifies that if Blackboard.publish raises RuntimeError or OperationalError,

    record_score_delta catches the exception, updates the registry, and returns the delta.
    """
    client = ClientTarget(
        client_id="stress-bb-1",
        client_name="BB Fail Target",
        apex_domain="bbfail.example.com",
        last_score=90,
        last_grade="A",
    )
    adversarial_registry.add_client(client)

    mock_bb = MagicMock()
    mock_bb.publish.side_effect = RuntimeError("Simulated SQLite WAL lock contention")

    sentinel = FleetSentinel(registry=adversarial_registry, blackboard=mock_bb)

    # Should not raise RuntimeError
    delta = sentinel.record_score_delta(client_id="stress-bb-1", findings=[], broadcast=True)

    assert delta["client_id"] == "stress-bb-1"
    assert delta["new_score"] == 100
    assert delta["score_change"] == 10

    # Verify registry was nonetheless updated
    updated = adversarial_registry.get_client("stress-bb-1")
    assert updated is not None
    assert updated.last_score == 100


def test_blackboard_get_blackboard_exception_isolation(adversarial_registry: FleetRegistry):
    """Verifies that if get_blackboard() raises an unhandled error when blackboard

    is None, record_score_delta isolates the failure and completes safely.
    """
    client = ClientTarget(
        client_id="stress-bb-2",
        client_name="BB Uninit Target",
        apex_domain="bbuninit.example.com",
        last_score=85,
    )
    adversarial_registry.add_client(client)

    sentinel = FleetSentinel(registry=adversarial_registry, blackboard=None)

    with patch("orbit_security.fleet.get_blackboard", side_effect=Exception("Database missing")):
        delta = sentinel.record_score_delta(client_id="stress-bb-2", findings=[], broadcast=True)

    assert delta["new_score"] == 100
    assert delta["score_change"] == 15


# =========================================================================== #
# 6. Concurrent Async Execution Safety (asyncio.gather)
# =========================================================================== #


@pytest.mark.asyncio
async def test_concurrent_async_score_deltas(adversarial_registry: FleetRegistry, adversarial_blackboard: Blackboard):
    """Verifies that multiple client score deltas processed concurrently via

    asyncio.gather execute safely and broadcast all events to the blackboard.
    """
    client_ids = [f"client-conc-{i}" for i in range(25)]
    for cid in client_ids:
        adversarial_registry.add_client(
            ClientTarget(
                client_id=cid,
                client_name=f"Name {cid}",
                apex_domain=f"{cid}.example.com",
                last_score=70,
            )
        )

    sentinel = FleetSentinel(registry=adversarial_registry, blackboard=adversarial_blackboard)

    async def run_delta(cid: str, idx: int):
        await asyncio.sleep(0.001)
        findings = [Finding(title="Exposed .git", severity=Severity.HIGH, description="h", remediation="r")] if idx % 2 == 0 else []
        return sentinel.record_score_delta(cid, findings=findings, broadcast=True)

    results = await asyncio.gather(*(run_delta(cid, i) for i, cid in enumerate(client_ids)))

    assert len(results) == 25
    # Verify blackboard received all 25 events
    events = adversarial_blackboard.get_recent(limit=50, event_type="fleet_score_delta")
    recorded_cids = {e["payload"]["client_id"] for e in events}
    for cid in client_ids:
        assert cid in recorded_cids


# =========================================================================== #
# 7. Exploitability Invariants Under Massive Findings Load
# =========================================================================== #


def test_exploitability_invariants_under_massive_load(adversarial_registry: FleetRegistry):
    """Stress tests R2 exploitability floor (>= 60 for 0 crit/high) and ceiling

    (<= 59 for >= 1 crit) under 500 findings of varying categories.
    """
    client = ClientTarget(
        client_id="stress-inv-1",
        client_name="Invariant Target",
        apex_domain="inv.example.com",
        last_score=100,
    )
    adversarial_registry.add_client(client)
    sentinel = FleetSentinel(registry=adversarial_registry)

    # 1. 500 MEDIUM/LOW findings -> floor >= 60 MUST hold
    medium_barrage = [
        Finding(
            title=f"Medium Issue {i}",
            severity=Severity.MEDIUM,
            description="med",
            remediation="fix",
            target=f"sub{i}.inv.example.com",
        )
        for i in range(500)
    ]
    delta_floor = sentinel.record_score_delta(client_id="stress-inv-1", findings=medium_barrage, broadcast=False)
    assert delta_floor["critical_findings"] == 0
    assert delta_floor["high_findings"] == 0
    assert delta_floor["new_score"] >= EXPLOITABILITY_FLOOR_SCORE
    assert delta_floor["grade"] in ("A+", "A", "B", "C")

    # 2. 1 CRITICAL finding added to 500 LOW findings -> ceiling <= 59 MUST hold
    mixed_barrage = [
        Finding(title="Dangling Takeover", severity=Severity.CRITICAL, description="c", remediation="r")
    ] + [
        Finding(title=f"Low Issue {i}", severity=Severity.LOW, description="l", remediation="r")
        for i in range(500)
    ]
    delta_ceiling = sentinel.record_score_delta(client_id="stress-inv-1", findings=mixed_barrage, broadcast=False)
    assert delta_ceiling["critical_findings"] == 1
    assert delta_ceiling["new_score"] <= EXPLOITABILITY_CEILING_SCORE
    assert delta_ceiling["grade"] in ("D", "F")


# =========================================================================== #
# 8. Override Scores & Extreme Values
# =========================================================================== #


def test_override_score_and_grade_parameters(adversarial_registry: FleetRegistry):
    """Verifies that override_score and override_grade take precedence when

    supplied, allowing callers to handle legacy or external calibration.
    """
    client = ClientTarget(
        client_id="stress-override-1",
        client_name="Override Target",
        apex_domain="override.example.com",
        last_score=75,
        last_grade="B",
    )
    adversarial_registry.add_client(client)
    sentinel = FleetSentinel(registry=adversarial_registry)

    # Even with empty findings (which would score 100 A+), overrides should prevail
    delta = sentinel.record_score_delta(
        client_id="stress-override-1",
        findings=[],
        broadcast=False,
        override_score=42,
        override_grade="F",
    )

    assert delta["new_score"] == 42
    assert delta["grade"] == "F"
    assert delta["score_change"] == -33

    updated = adversarial_registry.get_client("stress-override-1")
    assert updated is not None
    assert updated.last_score == 42
    assert updated.last_grade == "F"
