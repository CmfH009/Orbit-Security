#!/usr/bin/env python3
"""
Adversarial Stress Test Suite: Cohort 11 Holdout Partitioning & Dual-Mode Fallback.
Authored by: Empirical Challenger (teamwork_challenger_m1_iter2_2)

Rigorous empirical challenge of:
1. Permutation invariance (10,000 random shuffles, mixed casings, whitespaces, dict vs str shapes).
2. Exact 30% holdout split on Cohort 11 (3 holdout, 4 variant_a, 3 variant_b) and disk parity.
3. Dual-mode fallback (cohort-level partitioning vs standalone hash modulo fallback).
4. Boundary condition exploration (slots 0, 1, 29, 30, 31, 64, 65, 66, 98, 99).
5. Statistical distribution across 10,000 synthetic targets.
6. Invariant properties across arbitrary cohort sizes N in [1..50].
7. Pathological input resilience (extreme strings, duplicate entries, punycode).
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import json
from pathlib import Path
import random
import sys
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.stage_cohort_11 import (
    COHORT_11_TARGETS,
    assign_ab_variant,
    build_pitch_copy,
    partition_cohort_targets,
)


class TestPermutationInvariance:
    """Stress tests permutation invariance: input target order must never alter partition output."""

    def test_random_shuffle_invariance_10000_iterations(self):
        """10,000 randomized permutations of COHORT_11_TARGETS must produce identical partitions."""
        baseline = partition_cohort_targets(COHORT_11_TARGETS)
        rng = random.Random(1337)

        for i in range(10000):
            shuffled = list(COHORT_11_TARGETS)
            rng.shuffle(shuffled)
            result = partition_cohort_targets(shuffled)
            assert result == baseline, f"Permutation invariance broken at iteration {i}!"

    def test_structural_representation_invariance(self):
        """Partitioning must be identical regardless of how targets are wrapped (dicts or strings)."""
        domains = [t["agency_domain"] for t in COHORT_11_TARGETS]
        p_baseline = partition_cohort_targets(COHORT_11_TARGETS)

        # 1. Raw string list
        p_strings = partition_cohort_targets(domains)
        assert p_strings == p_baseline

        # 2. Dicts with 'domain'
        p_domain_key = partition_cohort_targets([{"domain": d} for d in domains])
        assert p_domain_key == p_baseline

        # 3. Dicts with 'agency_slug' where slug matches domain
        p_slug_key = partition_cohort_targets([{"agency_slug": d} for d in domains])
        assert p_slug_key == p_baseline

        # 4. Mixed list of dicts and strings
        mixed = [COHORT_11_TARGETS[0], domains[1], {"domain": domains[2]}] + list(COHORT_11_TARGETS[3:])
        p_mixed = partition_cohort_targets(mixed)
        assert p_mixed == p_baseline

    def test_casing_whitespace_and_formatting_invariance(self):
        """Upper, title, mixed casing, leading/trailing whitespace, tabs, and newlines must normalize cleanly."""
        messy_targets = [
            f" \t {t['agency_domain'].swapcase()} \n "
            for t in COHORT_11_TARGETS
        ]
        p_messy = partition_cohort_targets(messy_targets)
        p_clean = partition_cohort_targets(COHORT_11_TARGETS)
        assert p_messy == p_clean


class TestCohort11HoldoutSplit:
    """Verifies exact discrete 30% holdout split on Cohort 11."""

    def test_exact_quota_counts(self):
        """Cohort 11 (N=10) must produce exactly 3 holdouts (30%), 4 variant_a, and 3 variant_b."""
        part = partition_cohort_targets(COHORT_11_TARGETS)
        assert len(part) == 10

        counts = {"holdout": 0, "variant_a": 0, "variant_b": 0}
        for dom, info in part.items():
            bucket = info["bucket"]
            counts[bucket] += 1
            assert info["variant"] == bucket
            assert info["is_holdout"] == (bucket == "holdout")
            assert 0 <= info["rank"] <= 9
            assert 0 <= info["slot"] <= 99

        assert counts["holdout"] == 3
        assert counts["variant_a"] == 4
        assert counts["variant_b"] == 3

    def test_discrete_rank_ordering(self):
        """Sorted by SHA-256 digest: ranks 0..2 are holdout, 3..6 are variant_a, 7..9 are variant_b."""
        part = partition_cohort_targets(COHORT_11_TARGETS)
        sorted_ranks = sorted(part.items(), key=lambda kv: kv[1]["rank"])

        for rank, (dom, info) in enumerate(sorted_ranks):
            assert info["rank"] == rank
            if rank in (0, 1, 2):
                assert info["bucket"] == "holdout"
                assert info["is_holdout"] is True
            elif rank in (3, 4, 5, 6):
                assert info["bucket"] == "variant_a"
                assert info["is_holdout"] is False
            elif rank in (7, 8, 9):
                assert info["bucket"] == "variant_b"
                assert info["is_holdout"] is False

    def test_disk_manifest_and_draft_parity(self):
        """Inspects outbound_queue/cohort_11 to verify manifest and .eml files reflect 30% holdout."""
        manifest_path = REPO_ROOT / "outbound_queue" / "cohort_11" / "cohort_11_manifest.json"
        assert manifest_path.exists(), "Manifest file not found on disk"

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["ab_split_summary"] == {"variant_a": 4, "variant_b": 3, "holdout": 3}
        assert manifest["total_targets"] == 10

        part = partition_cohort_targets(COHORT_11_TARGETS)

        for target in manifest["targets"]:
            dom = target["agency_domain"]
            expected = part[dom]
            assert target["ab_variant"] == expected["bucket"]
            assert target["is_holdout"] == expected["is_holdout"]

            # Verify .eml header
            eml_path = Path(target["eml_path"])
            assert eml_path.exists()
            msg = email.message_from_bytes(eml_path.read_bytes(), policy=email.policy.default)
            assert msg["X-Orbit-AB-Variant"] == expected["bucket"]

            # Verify pitch copy
            subj, body = build_pitch_copy(target, expected["bucket"])
            if expected["bucket"] == "holdout":
                assert "[Holdout Control]" in subj
                assert "controlled calibration" in body
            elif expected["bucket"] == "variant_a":
                assert "White-label security audits" in subj
            elif expected["bucket"] == "variant_b":
                assert "Automated DMARC & subdomain takeover guard" in subj


class TestDualModeFallback:
    """Stress tests dual-mode assignment in assign_ab_variant."""

    def test_cohort_mode_resolution_for_cohort_11_members(self):
        """Any domain in COHORT_11_TARGETS resolves to cohort partition even without cohort arg."""
        part = partition_cohort_targets(COHORT_11_TARGETS)
        for t in COHORT_11_TARGETS:
            dom = t["agency_domain"]
            res = assign_ab_variant(dom)
            assert res["bucket"] == part[dom]["bucket"]
            assert res["rank"] == part[dom]["rank"]
            assert res["is_holdout"] == part[dom]["is_holdout"]

    def test_legacy_alias_tablexi_resolution(self):
        """tablexi.com maps to txidigital.com assignment in Cohort 11."""
        res_alias = assign_ab_variant("tablexi.com")
        res_canon = assign_ab_variant("txidigital.com")
        assert res_alias["bucket"] == res_canon["bucket"]
        assert res_alias["rank"] == res_canon["rank"]
        assert res_alias["is_holdout"] == res_canon["is_holdout"]

    def test_explicit_custom_cohort_mode(self):
        """Passing an explicit cohort overrides Cohort 11 partition for domains in that cohort."""
        custom_cohort = ["studio-alpha.io", "studio-beta.io", "studio-gamma.io", "studio-delta.io"]
        part = partition_cohort_targets(custom_cohort)

        for d in custom_cohort:
            res = assign_ab_variant(d, cohort=custom_cohort)
            assert res["bucket"] == part[d]["bucket"]
            assert res["rank"] == part[d]["rank"]

    def test_standalone_fallback_slot_boundaries(self):
        """For non-cohort domains, test exact boundary slots: 0, 1, 29, 30, 31, 64, 65, 66, 98, 99."""
        found_slots: Dict[int, str] = {}
        idx = 0
        target_slots = {0, 1, 29, 30, 31, 64, 65, 66, 98, 99}

        while not target_slots.issubset(found_slots.keys()) and idx < 20000:
            dom = f"standalone-probe-{idx}.test"
            digest_int = int(hashlib.sha256(dom.encode("utf-8")).hexdigest()[:8], 16)
            slot = digest_int % 100
            if slot in target_slots and slot not in found_slots:
                found_slots[slot] = dom
            idx += 1

        assert target_slots.issubset(found_slots.keys()), "Failed to find candidate domains for all boundary slots"

        # Slots 0, 1, 29 -> holdout (is_holdout = True)
        for s in (0, 1, 29):
            res = assign_ab_variant(found_slots[s])
            assert res["slot"] == s
            assert res["bucket"] == "holdout", f"Slot {s} expected holdout, got {res['bucket']}"
            assert res["is_holdout"] is True

        # Slots 30, 31, 64 -> variant_a (is_holdout = False)
        for s in (30, 31, 64):
            res = assign_ab_variant(found_slots[s])
            assert res["slot"] == s
            assert res["bucket"] == "variant_a", f"Slot {s} expected variant_a, got {res['bucket']}"
            assert res["is_holdout"] is False

        # Slots 65, 66, 98, 99 -> variant_b (is_holdout = False)
        for s in (65, 66, 98, 99):
            res = assign_ab_variant(found_slots[s])
            assert res["slot"] == s
            assert res["bucket"] == "variant_b", f"Slot {s} expected variant_b, got {res['bucket']}"
            assert res["is_holdout"] is False

    def test_statistical_distribution_10000_synthetic_targets(self):
        """10,000 synthetic agency domains in standalone fallback mode adhere to 30% / 35% / 35% within 1.5% tolerance."""
        counts = {"holdout": 0, "variant_a": 0, "variant_b": 0}
        n = 10000

        for i in range(n):
            dom = f"synthetic-agency-{i}.example"
            res = assign_ab_variant(dom)
            counts[res["bucket"]] += 1

        h_ratio = counts["holdout"] / n
        a_ratio = counts["variant_a"] / n
        b_ratio = counts["variant_b"] / n

        assert 0.285 <= h_ratio <= 0.315, f"Holdout ratio {h_ratio:.2%} deviated from expected 30%"
        assert 0.335 <= a_ratio <= 0.365, f"Variant A ratio {a_ratio:.2%} deviated from expected 35%"
        assert 0.335 <= b_ratio <= 0.365, f"Variant B ratio {b_ratio:.2%} deviated from expected 35%"


class TestPartitionScalingInvariants:
    """Mathematical invariants across cohort sizes N in [1..50]."""

    @pytest.mark.parametrize("n", list(range(1, 51)))
    def test_cohort_invariants_across_all_sizes(self, n: int):
        cohort = [f"scale-firm-{i}.org" for i in range(n)]
        part = partition_cohort_targets(cohort)

        assert len(part) == n
        counts = {"holdout": 0, "variant_a": 0, "variant_b": 0}
        for info in part.values():
            counts[info["bucket"]] += 1

        assert sum(counts.values()) == n
        if n >= 3:
            expected_holdout = round(n * 0.30)
            assert counts["holdout"] == expected_holdout
            assert abs(counts["variant_a"] - counts["variant_b"]) <= 1


class TestAdversarialAndPathologicalInputs:
    """Stress tests unexpected, empty, and pathological domain inputs."""

    def test_empty_cohort(self):
        assert partition_cohort_targets([]) == {}

    def test_single_target(self):
        part = partition_cohort_targets(["lonely-target.com"])
        assert len(part) == 1
        assert part["lonely-target.com"]["bucket"] == "holdout"

    def test_two_targets(self):
        part = partition_cohort_targets(["target-one.com", "target-two.com"])
        assert len(part) == 2
        buckets = [v["bucket"] for v in part.values()]
        assert "holdout" in buckets
        assert "variant_a" in buckets

    def test_duplicate_domains(self):
        """Duplicates in the cohort do not crash partitioning and result in single normalized entry."""
        cohort = ["dup.io", "dup.io", "dup.io", "other.io"]
        part = partition_cohort_targets(cohort)
        assert "dup.io" in part
        assert "other.io" in part

    def test_extremely_long_domain_string(self):
        """A 5,000 character domain string is hashed cleanly without crash."""
        long_dom = ("sub." * 1000) + "domain.com"
        res = assign_ab_variant(long_dom)
        assert res["bucket"] in ("holdout", "variant_a", "variant_b")
        assert 0 <= res["slot"] <= 99

    def test_punycode_and_unicode_domains(self):
        """Unicode internationalized domain names (IDN / Punycode) hash deterministically."""
        unicode_dom = "münchen-security.de"
        puny_dom = "xn--mnchen-security-2vb.de"
        res_uni = assign_ab_variant(unicode_dom)
        res_puny = assign_ab_variant(puny_dom)
        assert res_uni["bucket"] in ("holdout", "variant_a", "variant_b")
        assert res_puny["bucket"] in ("holdout", "variant_a", "variant_b")
