"""Unit tests for the upgraded Contact Verification & Anti-Bounce Deliverability Gate."""

from __future__ import annotations

import pytest

from scripts.verify_contacts import (
    extract_emails,
    rank_replacement_addresses,
    evaluate_deliverability_gate,
    classify,
)


def test_extract_emails_handles_html_entities_and_obfuscated_patterns():
    html = """
    <html>
      <body>
        <a href="mailto:hello&#64;agency.io">Email Us</a>
        <p>Security Contact: security [at] agency [dot] io</p>
        <p>Support: partner(at)agency(dot)io</p>
        <img src="hero-banner@2x.png" />
        <img src="icon@3x.webp" />
        <p>Ignore noreply@agency.io and sentry@agency.io</p>
      </body>
    </html>
    """
    extracted = extract_emails(html)
    assert "hello@agency.io" in extracted
    assert "security@agency.io" in extracted
    assert "partner@agency.io" in extracted
    assert "hero-banner@2x.png" not in extracted
    assert "icon@3x.webp" not in extracted
    assert "noreply@agency.io" not in extracted
    assert "sentry@agency.io" not in extracted


def test_rank_replacement_addresses_prioritizes_security_and_hello_over_careers():
    candidates = {
        "careers@acme.com",
        "press@acme.com",
        "hello@acme.com",
        "security@acme.com",
        "other@external.org",
    }
    ranked = rank_replacement_addresses(candidates, "acme.com")
    assert "other@external.org" not in ranked
    assert ranked[0] == "security@acme.com"
    assert ranked[1] == "hello@acme.com"
    assert ranked[-1] in ("careers@acme.com", "press@acme.com")


def test_evaluate_deliverability_gate_blocks_on_no_mx_or_high_refuted():
    unsafe_cohort = [
        {"agency_domain": "a.com", "classification": "CONFIRMED"},
        {"agency_domain": "b.com", "classification": "NO_MX"},
        {"agency_domain": "c.com", "classification": "REFUTED", "replacement_addresses": ["hello@c.com"]},
    ]
    gate = evaluate_deliverability_gate(unsafe_cohort)
    assert gate["gate_passed"] is False
    assert gate["no_mx_count"] == 1
    assert gate["refuted_count"] == 1
    assert len(gate["blocking_reasons"]) >= 1

    clean_cohort = [
        {"agency_domain": "a.com", "classification": "CONFIRMED"},
        {"agency_domain": "d.com", "classification": "CONFIRMED"},
    ]
    clean_gate = evaluate_deliverability_gate(clean_cohort)
    assert clean_gate["gate_passed"] is True
    assert clean_gate["blocking_reasons"] == []


def test_classify_uses_ranked_replacements(monkeypatch):
    monkeypatch.setattr("scripts.verify_contacts.has_mx", lambda domain: (True, ["mx1.acme.com"]))
    monkeypatch.setattr(
        "scripts.verify_contacts.mine_addresses",
        lambda domain: ({"careers@acme.com", "security@acme.com", "hello@acme.com"}, ["https://acme.com/ [200]"]),
    )

    target = {
        "agency_domain": "acme.com",
        "agency_name": "Acme Digital",
        "contact_email": "guessed_ceo@acme.com",
        "status": "BOUNCED",
        "client_domain": "shop.acme.com",
    }
    res = classify(target)
    assert res["classification"] == "REFUTED"
    assert res["replacement_addresses"][0] == "security@acme.com"
    assert res["replacement_addresses"][1] == "hello@acme.com"
