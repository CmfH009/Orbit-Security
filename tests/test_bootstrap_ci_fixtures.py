"""Regression tests for scripts/bootstrap_ci_fixtures.py."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.bootstrap_ci_fixtures import bootstrap_all


def test_bootstrap_all_seeds_clean_checkout_for_vault_sync(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    summary = bootstrap_all(tmp_path)
    assert summary["false_positive_archive_items_created"] >= 15
    assert summary["portal_audit_pdfs_created"] >= 3
    assert summary["seeded_vault_queue"] is False
