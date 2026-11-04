"""tests/test_cert_transparency_bounty_bridge.py
=============================================
Verification test suite for Track 2: Certificate Transparency Stream Bridge.
Tests passive CT subdomain discovery, third-party domain filtering,
wildcard normalization/deduplication, sweeper expansion, and daemon integration.
"""

from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.bounty_active_prober import BountyRollingWorker
from orbit_security.bounty_radar import (
    BountyProgram,
    BountyTakeoverSweeper,
    discover_subdomains_from_ct,
)
from orbit_security.bounty_rolling_daemon import BountyRollingDaemon
from orbit_security.cert_transparency import (
    CertificateEntry,
    CtStreamDaemon,
    fetch_certificates,
)


def _make_mock_cert(cert_id: int, common_name: str, san_domains: List[str]) -> CertificateEntry:
    return CertificateEntry(
        cert_id=cert_id,
        common_name=common_name,
        issuer="C=US, O=Let's Encrypt, CN=R3",
        logged_at="2026-10-25T12:00:00",
        not_before="2026-10-25T00:00:00",
        not_after="2027-01-25T23:59:59",
        san_domains=san_domains,
        serial_number=f"0{cert_id}abcdef",
    )


class TestCertTransparencyBountyBridge:
    """Test suite verifying Certificate Transparency discovery integration into bounty radar."""

    def test_discover_subdomains_from_ct_basic(self):
        """Verify discover_subdomains_from_ct returns clean subdomains from mock CT certs."""
        mock_certs = [
            _make_mock_cert(
                101,
                "mocktarget.com",
                ["mocktarget.com", "api.mocktarget.com", "staging.mocktarget.com"],
            ),
            _make_mock_cert(
                102,
                "portal.mocktarget.com",
                ["portal.mocktarget.com", "auth.mocktarget.com"],
            ),
        ]

        with patch("orbit_security.bounty_radar.fetch_certificates", return_value=mock_certs):
            subs = discover_subdomains_from_ct("mocktarget.com")

        expected = {
            "mocktarget.com",
            "api.mocktarget.com",
            "staging.mocktarget.com",
            "portal.mocktarget.com",
            "auth.mocktarget.com",
        }
        assert subs == expected

    def test_discover_subdomains_filters_third_party_and_mismatched_domains(self):
        """Verify strict filtering out of third-party domains or spoofed apex suffixes."""
        mock_certs = [
            _make_mock_cert(
                201,
                "evil.com",
                [
                    "valid.targetcorp.com",
                    "evil.com",
                    "targetcorp.com.attacker.com",
                    "fake-targetcorp.com",
                    "other-domain.org",
                ],
            )
        ]

        with patch("orbit_security.bounty_radar.fetch_certificates", return_value=mock_certs):
            subs = discover_subdomains_from_ct("targetcorp.com")

        assert "valid.targetcorp.com" in subs
        assert "evil.com" not in subs
        assert "targetcorp.com.attacker.com" not in subs
        assert "fake-targetcorp.com" not in subs
        assert "other-domain.org" not in subs
        assert subs == {"valid.targetcorp.com"}

    def test_discover_subdomains_normalizes_wildcards_and_deduplicates(self):
        """Verify leading '*.', duplicate SANs, and case sensitivity are normalized and deduplicated."""
        mock_certs = [
            _make_mock_cert(
                301,
                "*.API.targetcorp.com",
                [
                    "*.api.targetcorp.com",
                    "api.targetcorp.com",
                    "*.internal.targetcorp.com",
                    "internal.targetcorp.com",
                    "portal.targetcorp.com",
                ],
            ),
            _make_mock_cert(
                302,
                "portal.targetcorp.com",
                [
                    "portal.targetcorp.com",
                    "PORTAL.targetcorp.com",
                ],
            ),
        ]

        with patch("orbit_security.bounty_radar.fetch_certificates", return_value=mock_certs):
            subs = discover_subdomains_from_ct("*.targetcorp.com")

        expected = {
            "api.targetcorp.com",
            "internal.targetcorp.com",
            "portal.targetcorp.com",
        }
        assert subs == expected

    def test_sweeper_discover_subdomains_method_delegates_to_ct_daemon(self):
        """Verify BountyTakeoverSweeper.discover_subdomains_from_ct uses provided CtStreamDaemon."""
        mock_daemon = MagicMock()
        mock_daemon.monitor.fetch_certificates.return_value = [
            _make_mock_cert(401, "daemon-found.targetcorp.com", ["daemon-found.targetcorp.com"])
        ]

        sweeper = BountyTakeoverSweeper(ct_daemon=mock_daemon)
        discovered = sweeper.discover_subdomains_from_ct("targetcorp.com")

        assert "daemon-found.targetcorp.com" in discovered
        mock_daemon.monitor.fetch_certificates.assert_called_once_with("targetcorp.com")

    def test_expand_wildcards_includes_ct_discoveries_and_static_prefixes(self):
        """Verify wildcard expansion includes CT discovered subdomains alongside static prefixes."""
        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets", "cdn", "api"])
        mock_ct_subs = {"ct-legacy.acme.com", "ct-staging.acme.com"}

        with patch.object(sweeper, "discover_subdomains_from_ct", return_value=mock_ct_subs):
            candidates = sweeper.expand_wildcards(
                in_scope=["*.acme.com"],
                out_of_scope=["cdn.acme.com"],
                max_per_wildcard=5,
                use_passive_ct=True,
            )

        # Apex
        assert "acme.com" in candidates
        # Discovered via CT
        assert "ct-legacy.acme.com" in candidates
        assert "ct-staging.acme.com" in candidates
        # Static prefixes
        assert "assets.acme.com" in candidates
        assert "api.acme.com" in candidates
        # Filtered out_of_scope
        assert "cdn.acme.com" not in candidates
        # Ensure no duplicates
        assert len(candidates) == len(set(candidates))

    def test_expand_wildcards_respects_out_of_scope_for_ct_subdomains(self):
        """Verify CT-discovered subdomains matching out_of_scope patterns are suppressed."""
        sweeper = BountyTakeoverSweeper(custom_prefixes=["assets"])
        mock_ct_subs = {
            "dev.acme.com",
            "secret-admin.acme.com",
            "out-of-scope-wildcard.restricted.acme.com",
        }

        with patch.object(sweeper, "discover_subdomains_from_ct", return_value=mock_ct_subs):
            candidates = sweeper.expand_wildcards(
                in_scope=["*.acme.com"],
                out_of_scope=["secret-admin.acme.com", "*.restricted.acme.com"],
                max_per_wildcard=5,
                use_passive_ct=True,
            )

        assert "dev.acme.com" in candidates
        assert "secret-admin.acme.com" not in candidates
        assert "out-of-scope-wildcard.restricted.acme.com" not in candidates

    def test_bounty_rolling_daemon_round_robin_queries_ct_when_enabled(self, tmp_path):
        """Verify BountyRollingDaemon queries CtStreamDaemon during round-robin sweeps when enable_ct=True."""
        programs_file = tmp_path / "programs.json"
        programs_file.write_text(
            """{
                "programs": [
                    {
                        "program_id": "test_corp",
                        "name": "Test Corp",
                        "platform": "hackerone",
                        "policy_url": "https://hackerone.com/test",
                        "in_scope": ["*.testcorp.com"],
                        "out_of_scope": [],
                        "bounty_tier": "cash",
                        "max_bounty": 10000
                    }
                ]
            }""",
            encoding="utf-8",
        )
        mock_ct = MagicMock(spec=CtStreamDaemon)
        mock_ct.poll_domains.return_value = [
            {
                "domain": "testcorp.com",
                "total_certificates": 1,
                "new_certificates": 1,
                "total_subdomains": 2,
                "new_subdomains": ["api.testcorp.com"],
                "takeover_findings": [],
                "subdomains": ["testcorp.com", "api.testcorp.com"],
            }
        ]

        daemon = BountyRollingDaemon(
            programs_path=programs_file,
            offline=True,
            enable_ct=True,
            ct_daemon=mock_ct,
        )

        res = daemon.sweep_one_cycle()
        assert res is not None
        assert "ct_discovery" in res
        assert res["ct_discovery"]["program_id"] == "test_corp"
        assert "api.testcorp.com" in res["ct_discovery"]["new_subdomains"]
        mock_ct.poll_domains.assert_called_once()

    def test_bounty_rolling_daemon_skips_ct_when_disabled(self, tmp_path):
        """Verify BountyRollingDaemon skips CtStreamDaemon during sweeps when enable_ct=False."""
        programs_file = tmp_path / "programs.json"
        programs_file.write_text(
            """{
                "programs": [
                    {
                        "program_id": "test_corp",
                        "name": "Test Corp",
                        "platform": "hackerone",
                        "policy_url": "https://hackerone.com/test",
                        "in_scope": ["*.testcorp.com"],
                        "out_of_scope": [],
                        "bounty_tier": "cash",
                        "max_bounty": 10000
                    }
                ]
            }""",
            encoding="utf-8",
        )
        mock_ct = MagicMock(spec=CtStreamDaemon)

        daemon = BountyRollingDaemon(
            programs_path=programs_file,
            offline=True,
            enable_ct=False,
            ct_daemon=mock_ct,
        )

        res = daemon.sweep_one_cycle()
        assert res is not None
        assert "ct_discovery" not in res
        mock_ct.poll_domains.assert_not_called()

    def test_bounty_rolling_worker_queries_ct_round_robin(self, tmp_path):
        """Verify BountyRollingWorker queries CtStreamDaemon directly during run_one_cycle when enable_ct=True."""
        programs_file = tmp_path / "programs.json"
        programs_file.write_text(
            """{
                "programs": [
                    {
                        "program_id": "test_worker_corp",
                        "name": "Test Worker Corp",
                        "platform": "hackerone",
                        "policy_url": "https://hackerone.com/test",
                        "in_scope": ["*.workercorp.com"],
                        "out_of_scope": [],
                        "bounty_tier": "cash",
                        "max_bounty": 5000
                    }
                ]
            }""",
            encoding="utf-8",
        )
        mock_ct = MagicMock(spec=CtStreamDaemon)
        mock_ct.poll_domains.return_value = [
            {
                "domain": "workercorp.com",
                "total_certificates": 1,
                "new_certificates": 1,
                "total_subdomains": 1,
                "new_subdomains": ["admin.workercorp.com"],
                "takeover_findings": [],
                "subdomains": ["admin.workercorp.com"],
            }
        ]

        worker = BountyRollingWorker(
            programs_path=programs_file,
            enable_ct=True,
            ct_daemon=mock_ct,
        )

        cycle_res = worker.run_one_cycle(offline=True)
        assert cycle_res is not None
        assert "ct_discovery" in cycle_res
        mock_ct.poll_domains.assert_called_once_with(["*.workercorp.com"])
