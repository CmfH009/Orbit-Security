"""Tests for OpenCode Autonomous Remediation PR Engine."""

import unittest
from unittest.mock import MagicMock, patch
from orbit_security.opencode_remediation import (
    OpenCodeRemediationSynthesizer,
    RemediationPatchArtifact,
)


class TestOpenCodeRemediationPR(unittest.TestCase):
    def setUp(self):
        self.mock_blackboard = MagicMock()
        self.synthesizer = OpenCodeRemediationSynthesizer(blackboard=self.mock_blackboard)

    def test_create_remediation_pull_request_dry_run(self):
        artifact = RemediationPatchArtifact(
            domain="brand.com",
            finding_id="dangling_s3_takeover_12345",
            finding_title="Dangling S3 Takeover",
            severity="HIGH",
            target_component="dns",
            patch_content="DELETE CNAME assets.brand.com",
            commit_message="fix(security): remove dangling CNAME",
            verification_passed=True,
            verification_notes="Syntax structure valid",
            created_at="2026-10-26T00:00:00Z",
            generator="opencode",
            file_path="/tmp/remediation_brand_dns.patch",
        )

        res = self.synthesizer.create_remediation_pull_request(
            artifact=artifact,
            repo_target="acme-corp/infrastructure",
            dry_run=True,
        )

        self.assertTrue(res["success"])
        self.assertTrue(res["dry_run"])
        self.assertEqual(res["repo"], "acme-corp/infrastructure")
        self.assertEqual(res["branch"], "fix/orbit-dns-dangling")
        self.assertIn("mock-orbit", res["pr_url"])
        self.assertIn("gh pr create", res["command"])

    @patch("subprocess.run")
    def test_create_remediation_pull_request_live(self, mock_subprocess):
        # 1st call for gh --version, 2nd call for gh pr create
        mock_subprocess.side_effect = [
            MagicMock(returncode=0, stdout="gh version 2.50.0"),
            MagicMock(returncode=0, stdout="https://github.com/acme-corp/infra/pull/42\n", stderr=""),
        ]

        artifact = RemediationPatchArtifact(
            domain="brand.com",
            finding_id="cors_reflection_9876",
            finding_title="Permissive CORS Reflection",
            severity="MEDIUM",
            target_component="nginx",
            patch_content="add_header Access-Control-Allow-Origin 'https://brand.com';",
            commit_message="fix(security): restrict CORS origin",
            verification_passed=True,
            verification_notes="Valid Nginx block",
            created_at="2026-10-26T00:00:00Z",
            generator="opencode",
            file_path="/tmp/remediation_brand_nginx.patch",
        )

        res = self.synthesizer.create_remediation_pull_request(
            artifact=artifact,
            repo_target="acme-corp/infra",
            dry_run=False,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["pr_url"], "https://github.com/acme-corp/infra/pull/42")


if __name__ == "__main__":
    unittest.main()
