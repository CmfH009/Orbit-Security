from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import inspect_vault_safe as ivs


def _make_bundle(
    disclosures_dir: Path,
    stem: str,
    meta: dict,
    *,
    as_zip: bool = False,
    narrative: str = "NARRATIVE_SECRET_BODY_SHOULD_NEVER_APPEAR",
) -> None:
    if as_zip:
        zp = disclosures_dir / f"{stem}_bundle.zip"
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr("metadata.json", json.dumps(meta))
            z.writestr("technical_evidence.txt", narrative)
    else:
        bdir = disclosures_dir / f"{stem}_bundle"
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
        (bdir / "technical_evidence.txt").write_text(narrative, encoding="utf-8")

    (disclosures_dir / f"{stem}.md").write_text(narrative, encoding="utf-8")


def test_reads_structured_metadata_from_dir_and_zip_without_narrative(tmp_path: Path) -> None:
    disc = tmp_path / "disclosures"
    stag = tmp_path / "staging"
    disc.mkdir()
    stag.mkdir()

    _make_bundle(
        disc,
        "acme_cors_api_vendor_com",
        {
            "program_id": "acme",
            "program_name": "Acme",
            "target_domain": "api.vendor.com",
            "flaw_type": "cors_arbitrary_origin_with_credentials",
            "severity": "MEDIUM",
            "cvss_score": 5.4,
            "bounty_viability": "CONDITIONAL",
            "evidence_artifact_id": "ev_111111111111",
            "timestamp": "2026-11-25T16:00:00+00:00",
        },
        as_zip=False,
    )
    _make_bundle(
        disc,
        "beta_bucket_cdn_partner_org",
        {
            "program_id": "beta",
            "program_name": "Beta",
            "target_domain": "cdn.partner.org",
            "flaw_type": "open_cloud_bucket",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "bounty_viability": "HIGH_CONFIDENCE",
            "evidence_artifact_id": "ev_222222222222",
            "timestamp": "2026-11-25T16:05:00+00:00",
        },
        as_zip=True,
    )

    queue = {
        "launch_queue": [
            {
                "program_id": "acme",
                "bundles": [
                    {
                        "host": "api.vendor.com",
                        "evidence_artifact_id": "ev_000000000000",
                    }
                ],
            }
        ]
    }
    (stag / "VAULT_LAUNCH_QUEUE.json").write_text(json.dumps(queue), encoding="utf-8")

    records = ivs.collect_vault_records(disc, stag)
    assert len(records) == 2
    acme_rec = [r for r in records if r["program_id"] == "acme"][0]
    assert acme_rec["evidence_artifact_id"] == "ev_111111111111"
    assert acme_rec["staging_digest"] == "ev_000000000000"
    assert acme_rec["staging_drift"] is True

    rendered = json.dumps(records)
    assert "NARRATIVE_SECRET_BODY_SHOULD_NEVER_APPEAR" not in rendered


def test_program_filter_and_deterministic_domain_redaction(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    disc = tmp_path / "disclosures"
    stag = tmp_path / "staging"
    disc.mkdir()
    stag.mkdir()

    _make_bundle(
        disc,
        "acme_1",
        {
            "program_id": "acme",
            "program_name": "Acme",
            "target_domain": "api.vendor.com",
            "flaw_type": "cors_arbitrary_origin_with_credentials",
            "severity": "MEDIUM",
            "cvss_score": 5.4,
            "bounty_viability": "CONDITIONAL",
            "evidence_artifact_id": "ev_aaaaaaaaaaaa",
            "timestamp": "2026-11-25T16:00:00+00:00",
        },
        as_zip=True,
    )
    _make_bundle(
        disc,
        "acme_2",
        {
            "program_id": "acme",
            "program_name": "Acme",
            "target_domain": "portal.vendor.com",
            "flaw_type": "cors_arbitrary_origin_with_credentials",
            "severity": "MEDIUM",
            "cvss_score": 5.4,
            "bounty_viability": "CONDITIONAL",
            "evidence_artifact_id": "ev_bbbbbbbbbbbb",
            "timestamp": "2026-11-25T16:01:00+00:00",
        },
        as_zip=True,
    )
    _make_bundle(
        disc,
        "other_1",
        {
            "program_id": "other",
            "program_name": "Other",
            "target_domain": "shop.other.net",
            "flaw_type": "open_cloud_bucket",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "bounty_viability": "HIGH_CONFIDENCE",
            "evidence_artifact_id": "ev_cccccccccccc",
            "timestamp": "2026-11-25T16:02:00+00:00",
        },
        as_zip=True,
    )
    (stag / "VAULT_LAUNCH_QUEUE.json").write_text(
        json.dumps(
            {
                "launch_queue": [
                    {
                        "program_id": "acme",
                        "bundles": [
                            {"host": "api.vendor.com", "evidence_artifact_id": "ev_aaaaaaaaaaaa"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rc = ivs.main(
        [
            "--disclosures-dir",
            str(disc),
            "--staging-dir",
            str(stag),
            "--program",
            "acme",
            "--redact-domains",
            "--json",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "api.vendor.com" not in out
    assert "portal.vendor.com" not in out
    assert "shop.other.net" not in out
    assert "NARRATIVE_SECRET_BODY_SHOULD_NEVER_APPEAR" not in out

    parsed = json.loads(out)
    assert len(parsed) == 2
    assert {r["host"] for r in parsed} == {"host-01.example.test", "host-02.example.test"}
