"""Unit tests for NucleiTemplateGenerator (Pathway 1)."""

from __future__ import annotations

import yaml
from pathlib import Path
from orbit_security.nuclei_generator import NucleiTemplateGenerator
from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES, SaasSignature


def test_generate_takeover_template_structure():
    gen = NucleiTemplateGenerator()
    sig = SaasSignature(
        name="GitHub Pages",
        cname_patterns=["github.io"],
        fingerprints=["There isn't a GitHub Pages site here"],
        remediation="Remove the CNAME pointing to github.io.",
        status_code=404,
    )
    tpl = gen.generate_takeover_template(sig)

    assert tpl["id"] == "orbit-takeover-github-pages"
    assert tpl["info"]["severity"] == "high"
    assert "github.io" in tpl["info"]["metadata"]["cname-patterns"]
    assert len(tpl["http"]) == 1
    assert tpl["http"][0]["matchers"][0]["words"] == ["There isn't a GitHub Pages site here"]
    assert tpl["http"][0]["matchers"][1]["status"] == [404]

    # Verify YAML serialization roundtrip
    yaml_str = gen.to_yaml(tpl)
    parsed = yaml.safe_load(yaml_str)
    assert parsed["id"] == tpl["id"]


def test_generate_spf_permerror_template():
    gen = NucleiTemplateGenerator()
    tpl = gen.generate_spf_permerror_template("10up.com")

    assert tpl["id"] == "orbit-dns-spf-permerror-10up-com"
    assert tpl["info"]["severity"] == "medium"
    assert len(tpl["dns"]) == 1
    assert tpl["dns"][0]["name"] == "10up.com"
    assert tpl["dns"][0]["type"] == "TXT"


def test_generate_security_txt_template():
    gen = NucleiTemplateGenerator()
    tpl = gen.generate_security_txt_template("example.org")

    assert tpl["id"] == "orbit-rfc9116-security-txt-example-org"
    assert tpl["info"]["severity"] == "info"
    assert len(tpl["http"]) == 1
    assert "{{BaseURL}}/.well-known/security.txt" in tpl["http"][0]["path"]


def test_export_all_takeover_templates(tmp_path: Path):
    gen = NucleiTemplateGenerator()
    out_dir = tmp_path / "nuclei_templates"
    exported = gen.export_all_takeover_templates(out_dir)

    assert len(exported) == len(SAAS_TAKEOVER_SIGNATURES)
    for p in exported:
        assert p.exists()
        content = p.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        assert "id" in data
        assert "info" in data
