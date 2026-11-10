"""Unit tests for DnsFixpackOptimizer (Pathway 3)."""

from __future__ import annotations

import json
from pathlib import Path
from orbit_security.dns_fixpack_optimizer import DnsFixpackOptimizer, DnsFixpackBundle


def test_flatten_spf_record():
    opt = DnsFixpackOptimizer()
    ips = ["198.51.100.1", "203.0.113.5", "198.51.100.1"]  # includes duplicate
    flattened = opt.flatten_spf_record(ips, qualifier="-all")
    assert flattened == "v=spf1 ip4:198.51.100.1 ip4:203.0.113.5 -all"


def test_generate_fixpack_bundle():
    opt = DnsFixpackOptimizer()
    bundle = opt.generate_fixpack(
        domain="10up.com",
        original_spf="v=spf1 include:_spf.google.com include:servers.mcsv.net include:mail.zendesk.com -all",
        flattened_ips=["192.0.2.1", "198.51.100.5"],
        original_lookups=12,
    )

    assert bundle.domain == "10up.com"
    assert bundle.total_original_lookups == 12
    assert bundle.optimized_lookups == 0
    assert "192.0.2.1" in bundle.flattened_spf
    assert 'resource "cloudflare_record"' in bundle.terraform_snippet
    assert "IN    TXT" in bundle.bind_zone_snippet
    assert bundle.cloudflare_api_json["type"] == "TXT"
    assert len(bundle.sha256_hash) == 64


def test_export_fixpack_files(tmp_path: Path):
    opt = DnsFixpackOptimizer()
    bundle = opt.generate_fixpack(
        domain="alley.com",
        original_spf="v=spf1 include:_spf.nested.com -all",
        flattened_ips=["203.0.113.10"],
        original_lookups=11,
    )
    files = opt.export_fixpack_files(bundle, tmp_path / "fixpack_export")

    assert files["terraform"].exists()
    assert files["bind"].exists()
    assert files["cloudflare_api"].exists()
    assert files["manifest"].exists()

    manifest_data = json.loads(files["manifest"].read_text(encoding="utf-8"))
    assert manifest_data["domain"] == "alley.com"
    assert manifest_data["total_original_lookups"] == 11
