"""Tests verifying pytest execution never mutates production data/ JSON state."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_security.agency_retainer import AgencyRetainerManager, DEFAULT_RETAINERS_DATA_PATH
from orbit_security.bounty_radar import BountyProgram, BountyScopeIngester, DEFAULT_BOUNTY_DATA_PATH
from orbit_security.fleet import ClientTarget, DEFAULT_FLEET_DATA_PATH, FleetRegistry


REPO_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class TestRuntimePathIsolation:
    def test_fleet_registry_default_path_isolated_under_pytest(self):
        before = DEFAULT_FLEET_DATA_PATH.read_text(encoding="utf-8") if DEFAULT_FLEET_DATA_PATH.exists() else None
        reg = FleetRegistry()
        assert reg.data_path != DEFAULT_FLEET_DATA_PATH
        reg.add_client(
            ClientTarget(
                client_id="isolated-test-id",
                client_name="Isolated Test",
                apex_domain="isolated-test.example",
            )
        )
        after = DEFAULT_FLEET_DATA_PATH.read_text(encoding="utf-8") if DEFAULT_FLEET_DATA_PATH.exists() else None
        assert after == before

    def test_agency_retainer_default_path_isolated_under_pytest(self):
        before = DEFAULT_RETAINERS_DATA_PATH.read_text(encoding="utf-8") if DEFAULT_RETAINERS_DATA_PATH.exists() else None
        mgr = AgencyRetainerManager()
        assert mgr.data_path != DEFAULT_RETAINERS_DATA_PATH
        mgr.add_client_domain("eastside-co", "isolated.example", client_name="Iso")
        after = DEFAULT_RETAINERS_DATA_PATH.read_text(encoding="utf-8") if DEFAULT_RETAINERS_DATA_PATH.exists() else None
        assert after == before

    def test_bounty_ingester_default_path_seeds_catalog_without_mutating_repo_file(self):
        before = DEFAULT_BOUNTY_DATA_PATH.read_text(encoding="utf-8") if DEFAULT_BOUNTY_DATA_PATH.exists() else None
        ingester = BountyScopeIngester()
        assert ingester.data_path != DEFAULT_BOUNTY_DATA_PATH
        assert len(ingester.list_programs()) >= 27
        ingester.programs["temp-test-prog"] = BountyProgram(
            program_id="temp-test-prog",
            name="Temp Test",
            in_scope=["*.temp-test.example"],
        )
        ingester.save()
        after = DEFAULT_BOUNTY_DATA_PATH.read_text(encoding="utf-8") if DEFAULT_BOUNTY_DATA_PATH.exists() else None
        assert after == before
        ingester.programs.pop("temp-test-prog", None)
        ingester.save()

    def test_clients_json_contains_no_test_fixture_records(self):
        clients_path = REPO_DATA_DIR / "clients.json"
        if clients_path.exists():
            payload = json.loads(clients_path.read_text(encoding="utf-8"))
            ids = {c.get("client_id") for c in payload.get("clients", [])}
            domains = {c.get("apex_domain") for c in payload.get("clients", [])}
            assert "c1" not in ids
            assert "t.com" not in domains
