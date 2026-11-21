"""Regression tests for scripts/bootstrap_ci_fixtures.py."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.bounty_vault_generator import build_vault_manifest
from scripts.bootstrap_ci_fixtures import bootstrap_all


def test_bootstrap_all_seeds_clean_checkout_for_vault_sync(tmp_path: Path):
    # Seed minimal tracked files expected by bootstrap_all
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "bounty_programs.json").write_text('{"programs": []}\n', encoding="utf-8")

    summary = bootstrap_all(tmp_path)
    assert summary["false_positive_archive_items_created"] >= 15
    assert summary["seeded_disclosure_bundles"] >= 21
    assert summary["seeded_vault_queue"] is True

    manifest = build_vault_manifest(
        output_dir=tmp_path / "vault_out",
        disclosures_dir=data_dir / "disclosures",
        archive_fp_dir=data_dir / "archive" / "false_positive_disclosures",
    )
    assert manifest["archived_false_positives_count"] >= 15
    prog_names = {g["program"] for g in manifest["launch_queue"]}
    assert {"Starbucks", "Spotify", "Hyatt Hotels", "MercadoLibre", "Xiaomi", "Superbet", "Playtika"}.issubset(
        prog_names
    )
    by_prog = {(g["program"], g["verdict"]): g for g in manifest["launch_queue"]}
    hyatt = by_prog[("Hyatt Hotels", "OPEN_BUCKET_LISTING")]
    assert hyatt["tier"] == "TIER_2_NEEDS_AUTH_PROOF"
    assert hyatt["bounty_viability"] == "CONDITIONAL"
    assert hyatt["hosts"] == ["portal.wifi.hyatt.com"]

    queue_json = json.loads((data_dir / "hackerone_staging" / "VAULT_LAUNCH_QUEUE.json").read_text(encoding="utf-8"))
    assert queue_json["archived_false_positives_count"] >= 15
