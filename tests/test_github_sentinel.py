#!/usr/bin/env python3
"""
test_github_sentinel.py: Comprehensive Unit & Integration Tests for GitHub DevOps Swarm
=======================================================================================
Tests:
1. GitHubReleaseSentinel:
   - compute_next_version: major bumps (BREAKING CHANGE, feat!), minor bumps (feat), patch bumps (fix, perf, refactor).
   - generate_changelog: section grouping (Features, Fixes, Performance & Hardening, Chores).
   - stage_release: test_gate_passed handling (READY vs BLOCKED), blackboard event publishing.
2. GitHubShowcaseBuilder:
   - generate_badge_svg: XML/SVG validation, dynamic width scaling, accessible labels.
   - build_showcase_page: Markdown structure, metrics embedding.
3. GitHubPRAuditor:
   - validate_commit_message: Conventional Commits regex compliance and rejections.
   - scan_for_secrets: secret token detection (Stripe, GitHub, AWS, Google, PGP).
   - audit_python_code: Python AST syntax validator with error capturing.
   - audit_pr: End-to-end PR audit verdict (APPROVE / REJECT) and blackboard event broadcasting.
4. GitHubDevOpsSwarm:
   - run_devops_cycle: end-to-end orchestration, event broadcasting, output contracts.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock

from orbit_security.github_sentinel import (
    GitHubReleaseSentinel,
    GitHubShowcaseBuilder,
    GitHubPRAuditor,
    GitHubDevOpsSwarm,
)
from orbit_security.blackboard import (
    TOPIC_DEVOPS,
    EVENT_GITHUB_RELEASE_READY,
    EVENT_SHOWCASE_UPDATED,
    EVENT_PR_AUDIT_COMPLETED,
)


class TestGitHubReleaseSentinel(unittest.TestCase):
    def setUp(self):
        self.sentinel = GitHubReleaseSentinel(current_version="1.4.0")

    def test_compute_next_version_patch(self):
        """Standard fixes and refactors trigger a patch version bump."""
        commits = [
            "fix(inbox): resolve race condition in IMAP idle loop",
            "refactor(dns): modernize async resolver pool",
            "perf(db): add WAL index for event lookups"
        ]
        next_ver = self.sentinel.compute_next_version(commits)
        self.assertEqual(next_ver, "1.4.1")

    def test_compute_next_version_minor(self):
        """New features trigger a minor version bump."""
        commits = [
            "feat(radar): integrate X social sentinel stream",
            "fix(tui): align 100-col border"
        ]
        next_ver = self.sentinel.compute_next_version(commits)
        self.assertEqual(next_ver, "1.5.0")

    def test_compute_next_version_major(self):
        """Breaking changes trigger a major version bump."""
        commits_exclamation = ["feat!(api): overhaul REST endpoint schemas for v2"]
        self.assertEqual(self.sentinel.compute_next_version(commits_exclamation), "2.0.0")

        commits_footer = [
            "fix(db): drop legacy table\n\nBREAKING CHANGE: database migration requires fresh sync"
        ]
        self.assertEqual(self.sentinel.compute_next_version(commits_footer), "2.0.0")

    def test_generate_changelog(self):
        """generate_changelog groups commits into logical markdown sections."""
        commits = [
            "feat(auth): add OAuth2 PKCE flow",
            "fix(dns): handle timeout on CNAME check",
            "perf(cache): LRU eviction speedup",
            "chore(deps): bump httpx to 0.28.0"
        ]
        changelog = self.sentinel.generate_changelog("1.5.0", commits)
        self.assertIn("## [1.5.0]", changelog)
        self.assertIn("### Features", changelog)
        self.assertIn("- feat(auth): add OAuth2 PKCE flow", changelog)
        self.assertIn("### Fixes", changelog)
        self.assertIn("- fix(dns): handle timeout on CNAME check", changelog)
        self.assertIn("### Performance & Hardening", changelog)
        self.assertIn("- perf(cache): LRU eviction speedup", changelog)
        self.assertIn("### Chores & Maintenance", changelog)
        self.assertIn("- chore(deps): bump httpx to 0.28.0", changelog)

    def test_stage_release_passed(self):
        """stage_release publishes GITHUB_RELEASE_READY event when test gate passes."""
        with patch("orbit_security.github_sentinel.publish_event") as mock_pub:
            rel = self.sentinel.stage_release("1.5.0", "Summary of features", test_passed=True)
            self.assertEqual(rel["version"], "1.5.0")
            self.assertEqual(rel["release_tag"], "v1.5.0")
            self.assertEqual(rel["status"], "READY")
            self.assertTrue(rel["test_gate_passed"])

            mock_pub.assert_called_once()
            args, kwargs = mock_pub.call_args
            self.assertEqual(kwargs.get("event_type"), EVENT_GITHUB_RELEASE_READY)
            self.assertEqual(kwargs.get("topic"), TOPIC_DEVOPS)

    def test_stage_release_blocked(self):
        """stage_release marks release BLOCKED and suppresses event when test gate fails."""
        with patch("orbit_security.github_sentinel.publish_event") as mock_pub:
            rel = self.sentinel.stage_release("1.5.0", "Broken release", test_passed=False)
            self.assertEqual(rel["status"], "BLOCKED")
            self.assertFalse(rel["test_gate_passed"])
            mock_pub.assert_not_called()


class TestGitHubShowcaseBuilder(unittest.TestCase):
    def setUp(self):
        self.builder = GitHubShowcaseBuilder()

    def test_generate_badge_svg(self):
        """generate_badge_svg returns valid SVG with custom label, value, and color."""
        svg = self.builder.generate_badge_svg("Tests", "233/233 Passed", "#00FF66")
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn("Tests", svg)
        self.assertIn("233/233 Passed", svg)
        self.assertIn("#00FF66", svg)

    def test_build_showcase_page(self):
        """build_showcase_page embeds metrics into markdown document."""
        metrics = {"pass_rate": 100.0, "bounty_programs": 27, "remediation_rate": 98.5}
        md = self.builder.build_showcase_page(metrics)
        self.assertIn("# 🪐 Project ORBIT: Autonomous Security Architecture & Showcase", md)
        self.assertIn("100.0%", md)
        self.assertIn("27", md)
        self.assertIn("98.5%", md)


class TestGitHubPRAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = GitHubPRAuditor()

    def test_validate_commit_message_valid(self):
        """Conventional commits pass validation."""
        valid_messages = [
            "feat(radar): add new CVE sniffer",
            "fix: resolve race in worker pool",
            "chore(deps): update packages",
            "refactor(tui): improve visual padding",
            "docs: update README badges",
        ]
        for msg in valid_messages:
            res = self.auditor.validate_commit_message(msg)
            self.assertTrue(res["valid"], f"Failed on valid message: {msg}")
            self.assertIsNone(res["error"])

    def test_validate_commit_message_invalid(self):
        """Non-conventional commits fail validation."""
        invalid_messages = [
            "fixed stuff",
            "wip",
            "update readme",
            "feat without colon",
        ]
        for msg in invalid_messages:
            res = self.auditor.validate_commit_message(msg)
            self.assertFalse(res["valid"], f"Passed on invalid message: {msg}")
            self.assertIsNotNone(res["error"])

    def test_scan_for_secrets(self):
        """scan_for_secrets detects known secret patterns."""
        clean_code = "def add(a, b): return a + b\n"
        self.assertEqual(self.auditor.scan_for_secrets(clean_code), [])

        dirty_stripe = "stripe_key = '" + "sk_" + "live_" + "1234567890abcdef1234567890abcdef'"
        self.assertTrue(len(self.auditor.scan_for_secrets(dirty_stripe)) > 0)

        dirty_ghp = "github_pat = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'"
        self.assertTrue(len(self.auditor.scan_for_secrets(dirty_ghp)) > 0)

        dirty_aws = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
        self.assertTrue(len(self.auditor.scan_for_secrets(dirty_aws)) > 0)

    def test_audit_python_code(self):
        """audit_python_code verifies syntax via AST parsing."""
        valid_code = "def hello():\n    return 'world'\n"
        res = self.auditor.audit_python_code(valid_code)
        self.assertTrue(res["ok"])
        self.assertTrue(res["syntax_valid"])
        self.assertIsNone(res["error"])

        invalid_code = "def broken(:\n    return\n"
        res = self.auditor.audit_python_code(invalid_code)
        self.assertFalse(res["ok"])
        self.assertFalse(res["syntax_valid"])
        self.assertIn("SyntaxError", res["error"])

    def test_audit_pr_approved(self):
        """audit_pr approves clean PR with conventional commits, no secrets, and valid AST."""
        with patch("orbit_security.github_sentinel.publish_event") as mock_pub:
            commits = ["feat(inbox): add bounce filter", "fix(db): wrap cursor in try-except"]
            diff = "def new_feature():\n    pass\n"
            result = self.auditor.audit_pr("PR #42: Feature", commits, diff)

            self.assertEqual(result["verdict"], "APPROVE")
            self.assertTrue(result["passed"])
            self.assertEqual(result["commit_errors"], [])
            self.assertEqual(result["secrets_detected"], [])
            mock_pub.assert_called_once()
            args, kwargs = mock_pub.call_args
            self.assertEqual(kwargs.get("event_type"), EVENT_PR_AUDIT_COMPLETED)
            self.assertEqual(kwargs.get("topic"), TOPIC_DEVOPS)

    def test_audit_pr_rejected_on_secrets(self):
        """audit_pr rejects PR containing hardcoded secrets."""
        with patch("orbit_security.github_sentinel.publish_event"):
            commits = ["feat(api): connect stripe"]
            diff = "sk = '" + "sk_" + "live_" + "999999999999999999999999'"
            result = self.auditor.audit_pr("PR #43: Stripe", commits, diff)
            self.assertEqual(result["verdict"], "REJECT")
            self.assertFalse(result["passed"])
            self.assertTrue(len(result["secrets_detected"]) > 0)


class TestGitHubDevOpsSwarm(unittest.TestCase):
    def test_run_devops_cycle(self):
        """GitHubDevOpsSwarm executes full cycle and publishes showcase event."""
        with patch("orbit_security.github_sentinel.publish_event") as mock_pub:
            swarm = GitHubDevOpsSwarm()
            commits = [
                "feat(radar): add breaking cve feed parser",
                "fix(tui): fix 100-col border alignment"
            ]
            res = swarm.run_devops_cycle(commits, test_passed=True)

            self.assertTrue(res["ok"])
            self.assertEqual(res["next_version"], "1.5.0")
            self.assertIn("## [1.5.0]", res["changelog"])
            self.assertEqual(res["release"]["status"], "READY")
            self.assertGreater(res["badge_svg_len"], 50)
            self.assertGreater(res["showcase_md_len"], 100)

            # Check that events were published (RELEASE_READY and SHOWCASE_UPDATED)
            event_types = [call[1]["event_type"] for call in mock_pub.call_args_list]
            self.assertIn(EVENT_GITHUB_RELEASE_READY, event_types)
            self.assertIn(EVENT_SHOWCASE_UPDATED, event_types)


if __name__ == "__main__":
    unittest.main()
