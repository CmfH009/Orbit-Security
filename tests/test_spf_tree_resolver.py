"""Unit and regression tests for RFC 7208 Recursive SPF Tree Resolver & Flattening Simulator.

Covers:
- Recursive include: and redirect= tree expansion up to RFC 7208 10-lookup threshold.
- Mechanism counting rules (include, redirect, a, mx, ptr, exists count; ip4, ip6, all, exp= do not).
- Status tiers: SAFE (<8), WARNING (8-9), CRITICAL / SPF PermError (>=10).
- Void lookup tracking (<=2 allowed; >2 triggers CRITICAL PermError).
- Loop and circular reference detection without infinite recursion.
- CIDR harvesting and flattening simulator (overhead reduced to 1).
- Large payload size warnings (>450 bytes UDP limit).
- Structured tree node hierarchy and backwards-compatible dictionary access.
"""

from __future__ import annotations

import pytest
from typing import Dict, List, Optional, Union

from orbit_security.cloud_sentinels import (
    EmailAuthPolicyAnalyzer,
    SPFLookupStatus,
    SPFNode,
    SPFTreeResolver,
    SPFTreeResult,
)


def _mock_resolver(records: Dict[str, Union[str, List[str]]]):
    """Returns a lookup_fn for hermetic DNS resolution testing."""
    return lambda name: records.get((name or "").lower().rstrip("."))


def test_spf_tree_resolver_safe_status():
    """Under 8 lookups must be categorized as SAFE."""
    records = {
        "example.com": "v=spf1 include:_spf.nested1.com a mx -all",
        "_spf.nested1.com": "v=spf1 ip4:198.51.100.1 -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("example.com", records["example.com"])

    # 1 include + 1 a + 1 mx = 3 lookups
    assert result.total_lookups == 3
    assert result.status == SPFLookupStatus.SAFE
    assert result.status == "SAFE"
    assert result.exceeds_limit is False
    assert result.is_permerror is False
    assert result.has_loop is False
    assert result.void_lookups == 0


def test_spf_tree_resolver_warning_at_eight_lookups():
    """8 lookups must be categorized as WARNING (approaching 10-lookup limit)."""
    includes = " ".join(f"include:_spf.p{i}.example.net" for i in range(8))
    record = f"v=spf1 {includes} -all"

    # Resolvers returning simple ip4 records so lookups don't increase further
    records = {f"_spf.p{i}.example.net": f"v=spf1 ip4:10.0.{i}.1 -all" for i in range(8)}
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("warn8.com", record)

    assert result.total_lookups == 8
    assert result.status == SPFLookupStatus.WARNING
    assert result.status == "WARNING"
    assert result.exceeds_limit is False
    assert result.is_permerror is False
    assert any("warning threshold" in w.lower() for w in result.warnings)


def test_spf_tree_resolver_warning_at_nine_lookups():
    """9 lookups must be categorized as WARNING (danger zone)."""
    includes = " ".join(f"include:_spf.p{i}.example.net" for i in range(9))
    record = f"v=spf1 {includes} -all"

    records = {f"_spf.p{i}.example.net": f"v=spf1 ip4:10.0.{i}.1 -all" for i in range(9)}
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("warn9.com", record)

    assert result.total_lookups == 9
    assert result.status == SPFLookupStatus.WARNING
    assert result.exceeds_limit is False
    assert result.is_permerror is False


def test_spf_tree_resolver_critical_at_ten_lookups():
    """Exactly 10 lookups reaches RFC 7208 ceiling: CRITICAL status, is_permerror True, exceeds_limit False."""
    includes = " ".join(f"include:_spf.p{i}.example.net" for i in range(10))
    record = f"v=spf1 {includes} -all"

    records = {f"_spf.p{i}.example.net": f"v=spf1 ip4:10.0.{i}.1 -all" for i in range(10)}
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("crit10.com", record)

    assert result.total_lookups == 10
    assert result.status == SPFLookupStatus.CRITICAL
    assert result.status == "CRITICAL"
    # RFC 7208 strictly permits at most 10, so >10 is false, but ceiling is reached
    assert result.exceeds_limit is False
    assert result.is_permerror is True
    assert any("ceiling" in e.lower() or "limit" in e.lower() for e in result.errors)


def test_spf_tree_resolver_critical_exceeded_above_ten():
    """11 lookups strictly violates RFC 7208: CRITICAL status, exceeds_limit True, is_permerror True."""
    includes = " ".join(f"include:_spf.p{i}.example.net" for i in range(11))
    record = f"v=spf1 {includes} -all"

    records = {f"_spf.p{i}.example.net": f"v=spf1 ip4:10.0.{i}.1 -all" for i in range(11)}
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("crit11.com", record)

    assert result.total_lookups == 11
    assert result.status == SPFLookupStatus.CRITICAL
    assert result.exceeds_limit is True
    assert result.is_permerror is True


def test_spf_tree_resolver_all_mechanisms_counted():
    """include, redirect, a, mx, ptr, exists mechanisms must each count as 1 lookup."""
    record = (
        "v=spf1 include:_spf.srv.com redirect=_spf.redir.com a a:mail.com/24 "
        "mx mx:mail.com/28 ptr ptr:host.com exists:%{i}._spf.example.com -all"
    )
    records = {
        "_spf.srv.com": "v=spf1 ip4:192.0.2.1 -all",
        "_spf.redir.com": "v=spf1 ip4:192.0.2.2 -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("mechanisms.com", record)

    # 1 include + 1 redirect + 1 bare a + 1 prefixed a + 1 bare mx + 1 prefixed mx + 1 bare ptr + 1 prefixed ptr + 1 exists = 9 lookups
    assert result.total_lookups == 9
    assert result.status == SPFLookupStatus.WARNING


def test_spf_tree_resolver_non_counting_mechanisms_ignored():
    """ip4, ip6, all qualifiers (+,-,~,?), and exp= must not count as lookups."""
    record = (
        "v=spf1 ip4:192.0.2.1 ip4:198.51.100.0/24 ip6:2001:db8::1 ip6:2001:db8::/32 "
        "exp=explain.example.com +all"
    )
    resolver = SPFTreeResolver()
    result = resolver.expand_tree("noncounting.com", record)

    assert result.total_lookups == 0
    assert result.status == SPFLookupStatus.SAFE
    assert result.exceeds_limit is False
    assert result.is_permerror is False


def test_spf_tree_resolver_direct_self_loop():
    """Domain directly including itself must trigger has_loop and CRITICAL status without hanging."""
    records = {
        "loop.com": "v=spf1 include:loop.com -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("loop.com", records["loop.com"])

    assert result.has_loop is True
    assert result.total_lookups == 1
    assert result.status == SPFLookupStatus.CRITICAL
    assert result.is_permerror is True
    assert any("circular" in err.lower() for err in result.errors)


def test_spf_tree_resolver_indirect_cycle():
    """Circular chain A -> B -> C -> A must be halted and flagged as CRITICAL."""
    records = {
        "a.com": "v=spf1 include:b.com -all",
        "b.com": "v=spf1 include:c.com -all",
        "c.com": "v=spf1 include:a.com -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("a.com", records["a.com"])

    assert result.has_loop is True
    assert result.total_lookups == 3
    assert result.status == SPFLookupStatus.CRITICAL
    assert result.is_permerror is True


def test_spf_tree_resolver_void_lookups_under_limit():
    """Up to 2 void lookups (NXDOMAIN/empty answer) are tolerated by RFC 7208."""
    records = {
        "apex.com": "v=spf1 include:void1.example.net include:void2.example.net -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("apex.com", records["apex.com"])

    assert result.total_lookups == 2
    assert result.void_lookups == 2
    assert result.has_void_error is False
    assert result.status == SPFLookupStatus.SAFE
    assert result.is_permerror is False


def test_spf_tree_resolver_void_lookups_over_limit():
    """More than 2 void lookups violates RFC 7208 (DoS mitigation), escalating to CRITICAL."""
    records = {
        "apex.com": "v=spf1 include:void1.net include:void2.net include:void3.net -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("apex.com", records["apex.com"])

    assert result.total_lookups == 3
    assert result.void_lookups == 3
    assert result.has_void_error is True
    assert result.status == SPFLookupStatus.CRITICAL
    assert result.is_permerror is True
    assert any("void" in err.lower() for err in result.errors)


def test_spf_tree_resolver_flattening_simulator():
    """Nested includes with duplicate IPs/CIDRs must be deduplicated and flattened with 0 lookup mechanisms."""
    records = {
        "corp.com": (
            "v=spf1 include:_spf.google.com include:_spf.sendgrid.net "
            "ip4:192.0.2.1 ~all"
        ),
        "_spf.google.com": (
            "v=spf1 ip4:192.0.2.1 ip4:198.51.100.0/24 ip6:2001:db8::1 ~all"
        ),
        "_spf.sendgrid.net": (
            "v=spf1 ip4:203.0.113.50 ip6:2001:db8::1 -all"
        ),
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("corp.com", records["corp.com"])

    assert result.total_lookups == 2
    assert "192.0.2.1" in result.flattened_ips
    assert "198.51.100.0/24" in result.flattened_ips
    assert "203.0.113.50" in result.flattened_ips
    assert "2001:db8::1" in result.flattened_ips

    # Flattened record must contain only ip4/ip6 and terminal -all
    flat = result.flattened_record
    assert flat.startswith("v=spf1 ")
    assert flat.endswith(" -all")
    assert "include:" not in flat
    assert "redirect=" not in flat
    assert "ip4:192.0.2.1" in flat
    assert "ip4:198.51.100.0/24" in flat
    assert "ip4:203.0.113.50" in flat
    assert "ip6:2001:db8::1" in flat

    # Evaluating the flattened record itself must yield 0 mechanism lookups
    flat_result = resolver.expand_tree("corp.com", flat)
    assert flat_result.total_lookups == 0
    assert flat_result.status == SPFLookupStatus.SAFE


def test_spf_tree_resolver_flatten_record_custom_qualifier():
    """flatten_record helper should accept custom terminal qualifiers."""
    records = {
        "corp.com": "v=spf1 include:_spf.child.com -all",
        "_spf.child.com": "v=spf1 ip4:1.2.3.4 ~all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    preview = resolver.flatten_record("corp.com", records["corp.com"], qualifier="~all")
    assert preview == "v=spf1 ip4:1.2.3.4 ~all"


def test_spf_tree_resolver_redirect_modifier():
    """redirect= modifier replaces evaluation and traverses child SPF record."""
    records = {
        "redirected.com": "v=spf1 redirect=_spf.target.com",
        "_spf.target.com": "v=spf1 ip4:192.0.2.99 -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("redirected.com", records["redirected.com"])

    assert result.total_lookups == 1
    assert result.flattened_ips == ["192.0.2.99"]
    assert result.has_loop is False


def test_spf_tree_resolver_exception_resilience():
    """Exceptions raised during lookup_fn must be safely trapped and counted as void lookups."""
    def exploding_lookup(name: str):
        if "flaky" in name:
            raise ConnectionResetError("DNS connection dropped")
        return None

    resolver = SPFTreeResolver(lookup_fn=exploding_lookup)
    result = resolver.expand_tree("resilient.com", "v=spf1 include:flaky.example.com -all")

    assert result.total_lookups == 1
    assert result.void_lookups == 1
    assert result.has_loop is False
    assert result.tree_root is not None
    assert len(result.tree_root.children) == 1
    assert "connection dropped" in (result.tree_root.children[0].error or "").lower()


def test_spf_tree_resolver_multi_chunk_txt():
    """Resolver returning a list of strings (multi-chunk TXT) should be joined seamlessly."""
    records = {
        "multi.com": "v=spf1 include:chunks.example.com -all",
        "chunks.example.com": ["v=spf1 ip4:198.51.100.1 ", "ip4:198.51.100.2 -all"],
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("multi.com", records["multi.com"])

    assert result.total_lookups == 1
    assert "198.51.100.1" in result.flattened_ips
    assert "198.51.100.2" in result.flattened_ips


def test_spf_tree_resolver_payload_warning_over_450_bytes():
    """Flattened records exceeding 450 bytes must emit a UDP size warning."""
    # Generate 30 distinct IPv4 CIDRs to exceed 450 bytes
    ips = [f"ip4:198.51.{i}.0/24" for i in range(30)]
    record = f"v=spf1 {' '.join(ips)} -all"

    resolver = SPFTreeResolver()
    result = resolver.expand_tree("huge.com", record)

    assert len(result.flattened_record.encode("utf-8")) > 450
    assert any("450-byte" in w or "udp" in w.lower() for w in result.warnings)


def test_spf_tree_resolver_tree_node_hierarchy():
    """SPFNode tree hierarchy should correctly capture parent/child relationships."""
    records = {
        "root.com": "v=spf1 include:sub1.com include:sub2.com -all",
        "sub1.com": "v=spf1 ip4:10.0.0.1 -all",
        "sub2.com": "v=spf1 include:sub3.com -all",
        "sub3.com": "v=spf1 ip4:10.0.0.2 -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("root.com", records["root.com"])

    root = result.tree_root
    assert root is not None
    assert root.domain == "root.com"
    assert len(root.children) == 2

    sub1 = root.children[0]
    assert sub1.domain == "sub1.com"
    assert sub1.ips == ["10.0.0.1"]
    assert len(sub1.children) == 0

    sub2 = root.children[1]
    assert sub2.domain == "sub2.com"
    assert len(sub2.children) == 1

    sub3 = sub2.children[0]
    assert sub3.domain == "sub3.com"
    assert sub3.ips == ["10.0.0.2"]

    # Verify dictionary serialization
    tree_dict = result.tree
    assert tree_dict["domain"] == "root.com"
    assert len(tree_dict["children"]) == 2


def test_spf_tree_resolver_dict_access_compatibility():
    """SPFTreeResult should support dictionary subscripting and get()."""
    record = "v=spf1 ip4:1.2.3.4 -all"
    resolver = SPFTreeResolver()
    result = resolver.expand_tree("dict.com", record)

    assert result["total_lookups"] == 0
    assert result["status"] == "SAFE"
    assert result["is_permerror"] is False
    assert result.get("non_existent", 42) == 42
    assert "flattened_record" in result


def test_email_auth_policy_analyzer_backwards_compatibility():
    """EmailAuthPolicyAnalyzer.expand_spf_tree must forward to SPFTreeResolver and return a Dict."""
    records = {
        "legacy.com": "v=spf1 include:child.com -all",
        "child.com": "v=spf1 ip4:192.0.2.1 ~all",
    }
    result = EmailAuthPolicyAnalyzer.expand_spf_tree(
        domain="legacy.com",
        spf_record=records["legacy.com"],
        lookup_fn=_mock_resolver(records),
    )

    assert isinstance(result, dict)
    assert result["domain"] == "legacy.com"
    assert result["total_lookups"] == 1
    assert result["void_lookups"] == 0
    assert result["exceeds_limit"] is False
    assert result["has_loop"] is False
    assert result["flattened_ips"] == ["192.0.2.1"]
    assert "v=spf1 ip4:192.0.2.1 -all" in result["flattened_record"]


def test_email_auth_policy_analyzer_warning_and_critical_findings():
    """EmailAuthPolicyAnalyzer.analyze_email_security_posture evaluates warning and critical SPF lookups."""
    # Test WARNING (8 lookups)
    spf_8 = "v=spf1 " + " ".join(f"include:srv{i}.com" for i in range(8)) + " -all"
    res_8 = EmailAuthPolicyAnalyzer.analyze_email_security_posture(
        domain="warn.com",
        spf_record=spf_8,
        dmarc_record="v=DMARC1; p=reject",
    )
    codes_8 = {f["code"] for f in res_8["findings"]}
    assert "SPF_LOOKUP_LIMIT_WARNING" in codes_8

    # Test CRITICAL (11 lookups)
    spf_11 = "v=spf1 " + " ".join(f"include:srv{i}.com" for i in range(11)) + " -all"
    res_11 = EmailAuthPolicyAnalyzer.analyze_email_security_posture(
        domain="crit.com",
        spf_record=spf_11,
        dmarc_record="v=DMARC1; p=reject",
    )
    codes_11 = {f["code"] for f in res_11["findings"]}
    assert "SPF_LOOKUP_LIMIT_EXCEEDED" in codes_11
    finding = next(f for f in res_11["findings"] if f["code"] == "SPF_LOOKUP_LIMIT_EXCEEDED")
    assert finding["severity"] == "CRITICAL"


def test_spf_tree_resolver_dag_diamond_dependency_not_flagged_as_loop():
    """Directed Acyclic Graph (DAG) diamond dependency must not be flagged as a circular loop.

    Verifies that when two distinct include branches reference a common shared vendor SPF record
    (e.g., Root -> Sub1 -> Shared and Root -> Sub2 -> Shared), active recursion path tracking
    correctly identifies the graph as acyclic:
    - has_loop is False
    - status is SAFE (< 8 lookups)
    - is_permerror is False
    - shared IPs are properly collected and deduplicated
    - zero false-positive circular reference errors are emitted
    - EmailAuthPolicyAnalyzer does NOT emit SPF_CIRCULAR_REFERENCE finding
    """
    records = {
        "enterprise.com": "v=spf1 include:marketing.enterprise.com include:support.enterprise.com -all",
        "marketing.enterprise.com": "v=spf1 include:_spf.sharedprovider.net ip4:198.51.100.10 -all",
        "support.enterprise.com": "v=spf1 include:_spf.sharedprovider.net ip4:198.51.100.20 -all",
        "_spf.sharedprovider.net": "v=spf1 ip4:203.0.113.1 -all",
    }
    resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
    result = resolver.expand_tree("enterprise.com", records["enterprise.com"])

    assert result.has_loop is False
    assert result.status == SPFLookupStatus.SAFE
    assert result.is_permerror is False
    assert result.exceeds_limit is False
    assert result.total_lookups == 4
    assert result.void_lookups == 0
    assert "203.0.113.1" in result.flattened_ips
    assert "198.51.100.10" in result.flattened_ips
    assert "198.51.100.20" in result.flattened_ips
    assert not any("circular" in err.lower() for err in result.errors)

    # Verify EmailAuthPolicyAnalyzer integration has zero SPF_CIRCULAR_REFERENCE false positives
    policy_res = EmailAuthPolicyAnalyzer.analyze_email_security_posture(
        domain="enterprise.com",
        spf_record=records["enterprise.com"],
        dmarc_record="v=DMARC1; p=reject",
        lookup_fn=_mock_resolver(records),
    )
    codes = {f["code"] for f in policy_res["findings"]}
    assert "SPF_CIRCULAR_REFERENCE" not in codes

