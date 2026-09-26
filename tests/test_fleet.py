from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest

from orbit_security.fleet import ClientTarget, DriftEvent, FleetRegistry, FleetSentinel
from orbit_security.models import DomainAuditResult, Finding, Severity


def test_fleet_registry_crud(tmp_path: Path):
    data_file = tmp_path / "clients.json"
    registry = FleetRegistry(data_path=data_file)
    assert len(registry.list_active()) == 0

    client1 = ClientTarget(
        client_id="client-1",
        client_name="Test Store",
        apex_domain="teststore.com",
        subdomains=["shop.teststore.com"],
        retainer_plan="Growth",
    )
    registry.add_client(client1)
    assert len(registry.list_active()) == 1

    loaded = registry.get_client("client-1")
    assert loaded is not None
    assert loaded.client_name == "Test Store"

    # Reload from disk
    registry2 = FleetRegistry(data_path=data_file)
    assert len(registry2.list_active()) == 1
    assert registry2.get_client("client-1").apex_domain == "teststore.com"

    # Test metric updates
    registry2.update_scan_metrics("client-1", score=88, grade="B+")
    updated = registry2.get_client("client-1")
    assert updated.last_score == 88
    assert updated.last_grade == "B+"
    assert updated.last_scanned is not None


@pytest.mark.asyncio
async def test_fleet_drift_detection(tmp_path: Path):
    data_file = tmp_path / "clients.json"
    registry = FleetRegistry(data_path=data_file)

    client = ClientTarget(
        client_id="client-drift",
        client_name="Drifting Agency Client",
        apex_domain="drift.example.com",
        last_score=95,
        last_grade="A",
    )
    registry.add_client(client)

    sentinel = FleetSentinel(registry=registry)

    # Mock scan result returning a degraded score and critical finding
    mock_audit = DomainAuditResult(domain="drift.example.com")
    mock_audit.score = 65
    mock_audit.grade = "C"
    mock_audit.findings.append(
        Finding(
            title="Dangling CNAME / Takeover Risk",
            severity=Severity.CRITICAL,
            category="Subdomain & DNS",
            description="Exposed endpoint",
            remediation="Delete CNAME",
            target="drift.example.com",
        )
    )

    with patch.object(sentinel, "scan_client", new_callable=AsyncMock, return_value=mock_audit):
        drift_events = await sentinel.run_daily_drift_sweep()
        assert len(drift_events) == 1
        event = drift_events[0]
        assert event.client_id == "client-drift"
        assert event.new_score == 65
        assert event.score_change == -30
        assert event.critical_findings == 1


@pytest.mark.asyncio
async def test_fleet_monthly_batch_pdf(tmp_path: Path):
    data_file = tmp_path / "clients.json"
    registry = FleetRegistry(data_path=data_file)

    client = ClientTarget(
        client_id="client-pdf",
        client_name="PDF Test Client",
        apex_domain="pdfclient.com",
    )
    registry.add_client(client)

    sentinel = FleetSentinel(registry=registry)

    mock_audit = DomainAuditResult(domain="pdfclient.com")
    mock_audit.score = 100
    mock_audit.grade = "A+"

    output_dir = tmp_path / "reports"

    with patch.object(sentinel, "scan_client", new_callable=AsyncMock, return_value=mock_audit):
        reports = await sentinel.run_monthly_report_batch(output_dir)
        assert len(reports) == 1
        pdf_path = reports[0]
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0
        assert "client-pdf" in pdf_path.name
