"""Empirical Adversarial Stress Test Suite for RFC 7208 SPF Tree Resolver & Flattening Simulator.

Authored by: teamwork_challenger_1 (Critic & Specialist)
Target: src/orbit_security/cloud_sentinels.py (SPFTreeResolver, SPFTreeResult, SPFNode)

Test Matrix:
1. Deep recursion chains (depths 1 to 20) and stack limit resilience.
2. Multi-hop circular references (self-loop, 2-hop, 3-hop, 5-hop, deep-nested loop, mixed redirect/include loop).
3. DAG diamond dependency stress test (verifying whether shared includes across branches trigger false-positive loops).
4. Exact mechanism boundary testing (6, 7, 8, 9, 10, 11 lookups) using all RFC 7208 counting mechanisms.
5. High-volume non-counting mechanism floods (ip4, ip6, exp=, all qualifiers) verifying zero lookup pollution.
6. Void lookup flooding (0, 1, 2, 3, 10 voids, plus deeply nested voids).
7. Flattening simulator verification (0 mechanism lookups, valid syntax, IP/CIDR preservation, 450-byte UDP warning).
8. Malformed tokens, empty targets, and hostile DNS resolver behavior.
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
    """Returns a deterministic lookup_fn for hermetic DNS resolution testing."""
    return lambda name: records.get((name or "").lower().rstrip("."))


class TestSPFTreeStressChallenger:
    """Adversarial challenge test suite for SPFTreeResolver."""

    # =========================================================================
    # 1. Deep Recursion Chains
    # =========================================================================

    def test_deep_recursion_chain_15_levels(self):
        """15-deep include chain: must not crash, must count all 15 lookups, exceed 10 limit, and harvest all IPs."""
        records = {}
        for i in range(15):
            records[f"hop{i}.example.com"] = f"v=spf1 include:hop{i+1}.example.com ip4:10.0.{i}.1 -all"
        records["hop15.example.com"] = "v=spf1 ip4:10.0.15.1 -all"

        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("hop0.example.com", records["hop0.example.com"])

        assert result.total_lookups == 15
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.exceeds_limit is True
        assert result.is_permerror is True
        assert result.has_loop is False
        assert len(result.flattened_ips) == 16
        for i in range(16):
            assert f"10.0.{i}.1" in result.flattened_ips

    def test_deep_recursion_depth_cutoff_boundary(self):
        """Recursion beyond depth 20 must gracefully truncate without RecursionError."""
        records = {}
        for i in range(25):
            records[f"deep{i}.com"] = f"v=spf1 include:deep{i+1}.com ip4:10.1.{i}.1 -all"
        records["deep25.com"] = "v=spf1 ip4:10.1.25.1 -all"

        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        # Should not raise RecursionError
        result = resolver.expand_tree("deep0.com", records["deep0.com"])

        assert result.total_lookups >= 20
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.exceeds_limit is True
        assert result.has_loop is False

    # =========================================================================
    # 2. Multi-Hop Circular References
    # =========================================================================

    def test_circular_self_loop(self):
        """1-hop direct self-include."""
        records = {"self.com": "v=spf1 include:self.com -all"}
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("self.com", records["self.com"])

        assert result.has_loop is True
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.is_permerror is True
        assert result.total_lookups == 1

    def test_circular_2_hop_loop(self):
        """2-hop loop: A -> B -> A."""
        records = {
            "a2.com": "v=spf1 include:b2.com -all",
            "b2.com": "v=spf1 include:a2.com -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("a2.com", records["a2.com"])

        assert result.has_loop is True
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.is_permerror is True
        assert result.total_lookups == 2

    def test_circular_3_hop_loop(self):
        """3-hop loop: A -> B -> C -> A."""
        records = {
            "a3.com": "v=spf1 include:b3.com -all",
            "b3.com": "v=spf1 include:c3.com -all",
            "c3.com": "v=spf1 include:a3.com -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("a3.com", records["a3.com"])

        assert result.has_loop is True
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.is_permerror is True
        assert result.total_lookups == 3

    def test_circular_5_hop_loop(self):
        """5-hop loop: A -> B -> C -> D -> E -> A."""
        records = {
            "a5.com": "v=spf1 include:b5.com -all",
            "b5.com": "v=spf1 include:c5.com -all",
            "c5.com": "v=spf1 include:d5.com -all",
            "d5.com": "v=spf1 include:e5.com -all",
            "e5.com": "v=spf1 include:a5.com -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("a5.com", records["a5.com"])

        assert result.has_loop is True
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.is_permerror is True
        assert result.total_lookups == 5

    def test_circular_deep_nested_loop(self):
        """Cycle nested deep in a valid prefix: Root -> Sub -> LoopA -> LoopB -> LoopA."""
        records = {
            "root.com": "v=spf1 include:sub.com -all",
            "sub.com": "v=spf1 include:loopa.com -all",
            "loopa.com": "v=spf1 include:loopb.com -all",
            "loopb.com": "v=spf1 include:loopa.com -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("root.com", records["root.com"])

        assert result.has_loop is True
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.is_permerror is True
        assert result.total_lookups == 4
        assert any("loopa.com" in e for e in result.errors)

    def test_circular_mixed_include_and_redirect_loop(self):
        """Mixed include and redirect cycle: A -> redirect=B -> include:C -> redirect=A."""
        records = {
            "mix_a.com": "v=spf1 redirect=mix_b.com",
            "mix_b.com": "v=spf1 include:mix_c.com -all",
            "mix_c.com": "v=spf1 redirect=mix_a.com",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("mix_a.com", records["mix_a.com"])

        assert result.has_loop is True
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.is_permerror is True
        assert result.total_lookups == 3

    # =========================================================================
    # 3. DAG / Diamond Dependency (Adversarial Challenge Finding)
    # =========================================================================

    def test_dag_diamond_dependency_structural_behavior(self):
        """Stress-test diamond dependency: Root -> Sub1, Root -> Sub2; Sub1 -> Shared, Sub2 -> Shared.
        
        NOTE: In graph theory, a DAG is acyclic. In RFC 7208, two distinct includes referencing
        a common third-party provider (e.g. Google Workspace, Zendesk) is valid and normal.
        This test documents the empirical behavior of SPFTreeResolver on diamond dependencies.
        """
        records = {
            "apex.com": "v=spf1 include:sub1.com include:sub2.com -all",
            "sub1.com": "v=spf1 include:shared.com -all",
            "sub2.com": "v=spf1 include:shared.com -all",
            "shared.com": "v=spf1 ip4:192.0.2.1 -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("apex.com", records["apex.com"])

        # Empirical observation: global visited set flags shared.com when re-encountered
        # Document whether has_loop is triggered:
        has_visited_loop_finding = result.has_loop
        # IPs must still be collected
        assert "192.0.2.1" in result.flattened_ips
        assert result.total_lookups == 4

        # If has_visited_loop_finding is True, this demonstrates the DAG false-positive phenomenon:
        if has_visited_loop_finding:
            assert any("shared.com" in err for err in result.errors)

    def test_dag_diamond_dependency_must_not_flag_circular_loop(self):
        """RFC 7208 / Graph Invariant: A Directed Acyclic Graph (DAG) with diamond dependencies
        (e.g. two subdomains including _spf.google.com) must NOT be flagged as has_loop=True.
        """
        records = {
            "apex.com": "v=spf1 include:sub1.com include:sub2.com -all",
            "sub1.com": "v=spf1 include:shared.com -all",
            "sub2.com": "v=spf1 include:shared.com -all",
            "shared.com": "v=spf1 ip4:192.0.2.1 -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("apex.com", records["apex.com"])

        # Expected correct behavior: No cycle exists in this graph!
        assert result.has_loop is False, f"DAG diamond dependency falsely flagged as circular loop: {result.errors}"
        assert result.status != SPFLookupStatus.CRITICAL

    # =========================================================================
    # 4. Exact Mechanism Boundary Testing (6, 7, 8, 9, 10, 11 Lookups)
    # =========================================================================

    @pytest.mark.parametrize(
        "target_lookups,expected_status,expected_exceeds,expected_permerror",
        [
            (6, SPFLookupStatus.SAFE, False, False),
            (7, SPFLookupStatus.SAFE, False, False),
            (8, SPFLookupStatus.WARNING, False, False),
            (9, SPFLookupStatus.WARNING, False, False),
            (10, SPFLookupStatus.CRITICAL, False, True),
            (11, SPFLookupStatus.CRITICAL, True, True),
        ],
    )
    def test_exact_lookup_boundaries_with_diverse_mechanisms(
        self,
        target_lookups: int,
        expected_status: SPFLookupStatus,
        expected_exceeds: bool,
        expected_permerror: bool,
    ):
        """Construct exact lookup counts using a diverse mix of RFC 7208 counting mechanisms:
        include:, a, mx, ptr, exists:, a:host/24, mx:host/28, ptr:host, redirect=.
        """
        pool = [
            "a",
            "mx",
            "ptr",
            "exists:%{i}._spf.example.com",
            "a:host1.example.com/24",
            "mx:mail.example.com/28",
            "ptr:host2.example.com",
            "a/24",
            "mx/28",
            "include:inc1.example.com",
            "redirect=redir.example.com",
        ]
        chosen = pool[:target_lookups]
        record = f"v=spf1 {' '.join(chosen)} -all"

        records = {
            "inc1.example.com": "v=spf1 ip4:10.0.1.1 -all",
            "redir.example.com": "v=spf1 ip4:10.0.2.1 -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("boundary.com", record)

        assert result.total_lookups == target_lookups
        assert result.status == expected_status
        assert result.exceeds_limit is expected_exceeds
        assert result.is_permerror is expected_permerror

    # =========================================================================
    # 5. Non-Counting Mechanism Floods
    # =========================================================================

    def test_non_counting_mechanism_flood_zero_lookup_impact(self):
        """50 IPv4s, 20 IPv6s, CIDR notations, mixed qualifiers (+,-,~,?), and exp=
        must add 0 DNS mechanism lookups and preserve all 70 IPs.
        """
        tokens = []
        expected_ips = []
        for i in range(50):
            cidr = f"198.51.{i}.0/24"
            qualifier = ["+", "-", "~", ""][i % 4]
            tokens.append(f"{qualifier}ip4:{cidr}")
            expected_ips.append(cidr)

        for i in range(20):
            v6_cidr = f"2001:db8:{i}::/48"
            qualifier = ["+", "~", ""][i % 3]
            tokens.append(f"{qualifier}ip6:{v6_cidr}")
            expected_ips.append(v6_cidr)

        tokens.append("exp=explain.example.com")
        tokens.append("~all")

        # Add 3 legitimate counting mechanisms
        record = f"v=spf1 a mx include:child.example.com {' '.join(tokens)}"
        records = {"child.example.com": "v=spf1 ip4:10.254.254.1 -all"}
        expected_ips.append("10.254.254.1")

        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("flood.com", record)

        # Lookups must strictly reflect the 3 counting mechanisms (a, mx, include:)
        assert result.total_lookups == 3
        assert result.status == SPFLookupStatus.SAFE
        assert result.exceeds_limit is False
        assert result.is_permerror is False

        # Verify all IPs/CIDRs were collected
        assert len(result.flattened_ips) == len(expected_ips)
        for ip in expected_ips:
            assert ip in result.flattened_ips

    # =========================================================================
    # 6. Void Lookup Flooding & Tolerance Boundaries
    # =========================================================================

    @pytest.mark.parametrize(
        "void_count,expected_status,expected_void_error,expected_permerror",
        [
            (0, SPFLookupStatus.SAFE, False, False),
            (1, SPFLookupStatus.SAFE, False, False),
            (2, SPFLookupStatus.SAFE, False, False),  # RFC 7208 allows up to 2
            (3, SPFLookupStatus.CRITICAL, True, True),  # > 2 void triggers PermError
            (10, SPFLookupStatus.CRITICAL, True, True),  # 10 void flood
        ],
    )
    def test_void_lookup_flooding_boundaries(
        self,
        void_count: int,
        expected_status: SPFLookupStatus,
        expected_void_error: bool,
        expected_permerror: bool,
    ):
        """RFC 7208 limits void lookups to at most 2. Flooding >2 void lookups escalates to CRITICAL PermError."""
        includes = " ".join(f"include:nxdomain{i}.example.com" for i in range(void_count))
        record = f"v=spf1 {includes} -all" if void_count > 0 else "v=spf1 -all"

        # Empty dictionary means all lookups return None (void / NXDOMAIN)
        records = {}
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("voidtest.com", record)

        assert result.void_lookups == void_count
        assert result.has_void_error is expected_void_error
        assert result.status == expected_status
        assert result.is_permerror is expected_permerror
        if expected_void_error:
            assert any("void" in err.lower() for err in result.errors)

    def test_nested_void_lookups_bubble_up_to_root(self):
        """Void lookups 3 levels deep in include hierarchy must properly bubble up and trigger PermError."""
        records = {
            "root.com": "v=spf1 include:level1.com -all",
            "level1.com": "v=spf1 include:level2.com -all",
            "level2.com": "v=spf1 include:void1.com include:void2.com include:void3.com -all",
        }
        # void1, void2, void3 are missing from records (NXDOMAIN)
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("root.com", records["root.com"])

        # 2 valid includes (level1, level2) + 3 void includes = 5 total lookups
        assert result.total_lookups == 5
        assert result.void_lookups == 3
        assert result.has_void_error is True
        assert result.status == SPFLookupStatus.CRITICAL
        assert result.is_permerror is True

    # =========================================================================
    # 7. Flattening Simulation Verification
    # =========================================================================

    def test_flattening_simulation_exactness_and_zero_lookups(self):
        """Flattened record must have valid syntax, 0 lookup mechanisms, and preserve all CIDRs."""
        records = {
            "apex.com": "v=spf1 include:corp.com include:cloud.com ip4:192.0.2.1 -all",
            "corp.com": "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::1 -all",
            "cloud.com": "v=spf1 ip4:203.0.113.50 ip4:192.0.2.1 ip6:2001:db8::1 ~all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("apex.com", records["apex.com"])

        flattened = result.flattened_record
        assert flattened.startswith("v=spf1 ")
        assert flattened.endswith(" -all")
        for forbidden in ["include:", "redirect=", "a", "mx", "ptr", "exists:"]:
            # Check individual mechanism tokens
            tokens = flattened.split()
            assert not any(t.startswith(forbidden) or t == forbidden for t in tokens)

        # Feed flattened record back into resolver: must have exactly 0 lookups
        re_eval = resolver.expand_tree("apex.com", flattened)
        assert re_eval.total_lookups == 0
        assert re_eval.status == SPFLookupStatus.SAFE
        assert re_eval.exceeds_limit is False
        assert re_eval.is_permerror is False

        # Verify sorted and deduplicated IPs
        assert re_eval.flattened_ips == [
            "192.0.2.1",
            "198.51.100.0/24",
            "2001:db8::1",
            "203.0.113.50",
        ]

    def test_flattening_record_helper_custom_qualifiers(self):
        """flatten_record helper must support ~all, ?all, +all, and -all."""
        records = {
            "apex.com": "v=spf1 include:sub.com -all",
            "sub.com": "v=spf1 ip4:10.0.0.1 -all",
        }
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))

        assert resolver.flatten_record("apex.com", records["apex.com"], qualifier="~all") == "v=spf1 ip4:10.0.0.1 ~all"
        assert resolver.flatten_record("apex.com", records["apex.com"], qualifier="?all") == "v=spf1 ip4:10.0.0.1 ?all"
        assert resolver.flatten_record("apex.com", records["apex.com"], qualifier="-all") == "v=spf1 ip4:10.0.0.1 -all"
        assert resolver.flatten_record("apex.com", records["apex.com"], qualifier="all") == "v=spf1 ip4:10.0.0.1 -all"

    def test_flattening_udp_payload_size_warning_boundary(self):
        """Flattened SPF record exceeding 450 bytes must emit UDP warning."""
        # 35 CIDRs will generate a record around 600+ bytes
        ips = [f"ip4:192.168.{i}.0/24" for i in range(35)]
        record = f"v=spf1 {' '.join(ips)} -all"

        resolver = SPFTreeResolver()
        result = resolver.expand_tree("large.com", record)

        assert len(result.flattened_record.encode("utf-8")) > 450
        assert any("450-byte" in w or "udp" in w.lower() for w in result.warnings)

    # =========================================================================
    # 8. Malformed Tokens and Hostile Resiliency
    # =========================================================================

    def test_empty_include_and_redirect_targets(self):
        """Empty targets (e.g. 'include:' or 'redirect=') must be counted as void lookups without crashing."""
        record = "v=spf1 include: redirect= a -all"
        resolver = SPFTreeResolver()
        result = resolver.expand_tree("empty_mechs.com", record)

        # 1 include + 1 redirect + 1 a = 3 lookups
        assert result.total_lookups == 3
        assert result.void_lookups == 2  # empty include and empty redirect
        assert result.has_void_error is False  # 2 is tolerated
        assert result.status == SPFLookupStatus.SAFE

    def test_dns_resolver_exploding_exceptions(self):
        """Hostile DNS exceptions (e.g. timeouts, broken pipes) must be caught and recorded."""
        def broken_dns(name: str):
            if "fail" in name:
                raise OSError("DNS socket timeout: 504")
            return "v=spf1 ip4:10.0.0.1 -all"

        record = "v=spf1 include:fail.com include:ok.com -all"
        resolver = SPFTreeResolver(lookup_fn=broken_dns)
        result = resolver.expand_tree("resilience.com", record)

        assert result.total_lookups == 2
        assert result.void_lookups == 1
        assert "10.0.0.1" in result.flattened_ips
        assert result.has_loop is False
        assert any("socket timeout" in (c.error or "").lower() for c in result.tree_root.children)

    def test_whitespace_and_tabs_normalization(self):
        """Records with irregular whitespace, tabs, and newlines must parse correctly."""
        record = "v=spf1 \t  include:sub.com \n\r   ip4:10.5.5.5   \t  -all"
        records = {"sub.com": "v=spf1  \t ip4:10.6.6.6   -all"}
        resolver = SPFTreeResolver(lookup_fn=_mock_resolver(records))
        result = resolver.expand_tree("whitespace.com", record)

        assert result.total_lookups == 1
        assert "10.5.5.5" in result.flattened_ips
        assert "10.6.6.6" in result.flattened_ips
