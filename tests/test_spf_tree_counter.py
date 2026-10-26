"""Unit tests for the recursive RFC 7208 SPF lookup-tree expander.

Contract under test (``EmailAuthPolicyAnalyzer.expand_spf_tree``):
- Recursively follows ``include:`` and ``redirect=`` through a resolver callback.
- Counts every DNS-lookup mechanism (include/redirect/a/mx/ptr/exists).
- Flags cycles instead of recursing forever.
- Flags ``exceeds_limit`` once total lookups exceed the RFC 7208 limit of 10.
- Deduplicates ``ip4:`` / ``ip6:`` CIDRs into a flattened record preview.
"""

from __future__ import annotations

from orbit_security.cloud_sentinels import EmailAuthPolicyAnalyzer


def _resolver(records):
    return lambda name: records.get((name or "").lower().rstrip("."))


def test_nested_include_tree_expansion_counts_all_lookups():
    records = {
        "example.com": "v=spf1 include:_spf.nested1.com include:_spf.nested2.com -all",
        "_spf.nested1.com": "v=spf1 include:_spf.child.com -all",
        "_spf.nested2.com": "v=spf1 ip4:198.51.100.1 ~all",
        "_spf.child.com": "v=spf1 ip4:203.0.113.5 ~all",
    }

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="example.com",
        spf_record=records["example.com"],
        lookup_fn=_resolver(records),
    )

    assert result["total_lookups"] == 3
    assert result["exceeds_limit"] is False
    assert result["has_loop"] is False
    assert result["void_lookups"] == 0
    assert "198.51.100.1" in result["flattened_ips"]
    assert "203.0.113.5" in result["flattened_ips"]


def test_redirect_chain_is_followed():
    records = {
        "redirected.com": "v=spf1 redirect=_spf.provider.com",
        "_spf.provider.com": "v=spf1 include:_spf.child.com -all",
        "_spf.child.com": "v=spf1 ip4:192.0.2.10 -all",
    }

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="redirected.com",
        spf_record=records["redirected.com"],
        lookup_fn=_resolver(records),
    )

    assert result["total_lookups"] == 2
    assert result["has_loop"] is False
    assert result["flattened_ips"] == ["192.0.2.10"]


def test_circular_includes_are_detected_without_infinite_recursion():
    records = {
        "loop.com": "v=spf1 include:loop2.com -all",
        "loop2.com": "v=spf1 include:loop.com -all",
    }

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="loop.com",
        spf_record=records["loop.com"],
        lookup_fn=_resolver(records),
    )

    assert result["has_loop"] is True
    assert result["total_lookups"] == 2


def test_exceeds_limit_when_lookups_exceed_ten():
    includes = " ".join(f"include:_spf.p{i}.example.net" for i in range(11))
    record = f"v=spf1 {includes} -all"

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="overlimit.com",
        spf_record=record,
        lookup_fn=lambda _name: None,
        max_lookups=10,
    )

    assert result["total_lookups"] == 11
    assert result["exceeds_limit"] is True


def test_exactly_ten_lookups_does_not_exceed_limit():
    includes = " ".join(f"include:_spf.p{i}.example.net" for i in range(10))
    record = f"v=spf1 {includes} -all"

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="atlimit.com",
        spf_record=record,
        lookup_fn=lambda _name: None,
    )

    assert result["total_lookups"] == 10
    assert result["exceeds_limit"] is False


def test_ipv4_and_ipv6_cidrs_are_deduplicated_and_flattened():
    records = {
        "dedupe.com": (
            "v=spf1 ip4:192.0.2.1 ip4:192.0.2.1 ip6:2001:db8::1 "
            "include:_spf.extra.com -all"
        ),
        "_spf.extra.com": "v=spf1 ip4:192.0.2.2 ip6:2001:db8::1 ~all",
    }

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="dedupe.com",
        spf_record=records["dedupe.com"],
        lookup_fn=_resolver(records),
    )

    assert result["flattened_ips"] == ["192.0.2.1", "192.0.2.2", "2001:db8::1"]
    assert result["flattened_record"] == (
        "v=spf1 ip4:192.0.2.1 ip4:192.0.2.2 ip6:2001:db8::1 -all"
    )


def test_non_recursive_lookup_mechanisms_are_counted():
    record = "v=spf1 a mx ptr a:mail.example.com mx:mx.example.com exists:%{i}._spf.example.com -all"

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="mechanisms.com",
        spf_record=record,
        lookup_fn=lambda _name: None,
    )

    assert result["total_lookups"] == 6
    assert result["flattened_ips"] == []


def test_missing_include_targets_are_counted_as_void_lookups():
    record = "v=spf1 include:void1.example.net include:void2.example.net -all"

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="voids.com",
        spf_record=record,
        lookup_fn=lambda _name: None,
    )

    assert result["total_lookups"] == 2
    assert result["void_lookups"] == 2


def test_resolver_exceptions_do_not_break_tree_walk():
    def exploding_lookup(_name):
        raise RuntimeError("DoH timeout")

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="resilient.com",
        spf_record="v=spf1 include:_spf.flaky.com -all",
        lookup_fn=exploding_lookup,
    )

    assert result["total_lookups"] == 1
    assert result["void_lookups"] == 1
    assert result["has_loop"] is False


def test_resolver_can_return_txt_record_list():
    records = {"_spf.multi.com": ["v=spf1 ip4:198.51.100.7 -all"]}

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="multi.com",
        spf_record="v=spf1 include:_spf.multi.com -all",
        lookup_fn=_resolver(records),
    )

    assert result["total_lookups"] == 1
    assert result["flattened_ips"] == ["198.51.100.7"]


def test_qualifiers_and_case_are_normalized():
    records = {
        "qualified.com": "v=spf1 +include:_SPF.Child.COM -all",
        "_spf.child.com": "v=spf1 IP4:203.0.113.9 -all",
    }

    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="qualified.com",
        spf_record=records["qualified.com"],
        lookup_fn=_resolver(records),
    )

    assert result["total_lookups"] == 1
    assert result["flattened_ips"] == ["203.0.113.9"]
