"""tests/test_hackerone_vdp_hunter_interface.py: Deep-module interface tests for HackerOneVdpHunter.

Exercises target discovery, deduplication, non-destructive screening, quality gating,
dossier rendering, and live/dry-run dispatch strictly through the deepened
`HackerOneVdpHunter` interface using deterministic in-memory fake transport adapters
and `tmp_path` (zero urllib monkeypatching, zero network I/O).
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import pytest

from orbit_security.ast_sentinel import audit_egress_guard_compliance
from orbit_security.hackerone_vdp_hunter import (
    HTML_LOOKALIKE_RE,
    SENSITIVE_BUCKET_KEY_RE,
    STATIC_PUBLIC_ASSET_EXTS,
    STATIC_PUBLIC_FILENAMES,
    HackerOneVdpHunter,
    VdpFinding,
    VdpHuntConfig,
    VdpProgram,
)
from orbit_security import vdp_high_signal_detectors as det_mod


class FakeHttpTransport:
    """In-memory HTTP adapter matching the HttpTransport protocol."""

    def __init__(
        self,
        handler: Callable[[str, Dict[str, str], int, int], Tuple[int, Dict[str, str], str]],
    ) -> None:
        self._handler = handler
        self.requests: List[Tuple[str, Dict[str, str]]] = []

    def fetch(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        max_bytes: int = 8192,
        timeout: int = 5,
    ) -> Tuple[int, Dict[str, str], str]:
        hdrs = dict(headers or {})
        self.requests.append((url, hdrs))
        return self._handler(url, hdrs, max_bytes, timeout)


class FakeDnsTransport:
    """In-memory DNS adapter matching the DnsTransport protocol."""

    def __init__(self, records: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None) -> None:
        self._records: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for (host, rtype), payload in (records or {}).items():
            self._records[(host.strip().lower().rstrip("."), rtype.upper())] = payload
        self.queries: List[Tuple[str, str]] = []

    def resolve(
        self,
        host: str,
        record_type: str = "CNAME",
        timeout: int = 5,
    ) -> Dict[str, Any]:
        key = (host.strip().lower().rstrip("."), record_type.upper())
        self.queries.append(key)
        return self._records.get(key, {"Status": 0, "Answer": []})


class FakeDiscoveryTransport:
    """In-memory passive subdomain discovery adapter matching SubdomainDiscoveryTransport."""

    def __init__(self, subdomains_by_root: Optional[Dict[str, Set[str]]] = None) -> None:
        self._subdomains = {k.lower(): set(v) for k, v in (subdomains_by_root or {}).items()}
        self.called_roots: List[str] = []

    def discover(
        self,
        root: str,
        *,
        use_crtsh: bool = False,
        use_subfinder: bool = False,
        timeout: int = 10,
    ) -> Set[str]:
        clean = root.strip().lower().lstrip("*.").rstrip(".")
        self.called_roots.append(clean)
        return set(self._subdomains.get(clean, set()))


class FakeHackerOneTransport:
    """In-memory HackerOne API + GraphQL adapter matching HackerOneTransport."""

    def __init__(
        self,
        *,
        raw_programs: Optional[List[Dict[str, Any]]] = None,
        program_details: Optional[Dict[str, Dict[str, Any]]] = None,
        program_scopes: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        program_weaknesses: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        existing_reports: Optional[List[Dict[str, Any]]] = None,
        kyc_flags: Optional[Dict[str, Optional[bool]]] = None,
        graphql_gates: Optional[Dict[str, Dict[str, Any]]] = None,
        post_response: Tuple[int, Dict[str, Any], str] = (
            201,
            {"data": {"id": "9000123", "attributes": {"state": "new"}}},
            "",
        ),
    ) -> None:
        self._raw_programs = list(raw_programs or [])
        self._details = dict(program_details or {})
        self._scopes = dict(program_scopes or {})
        self._weaknesses = dict(program_weaknesses or {})
        self._existing_reports = list(existing_reports or [])
        self._kyc_flags = dict(kyc_flags or {})
        self._graphql_gates = dict(graphql_gates or {})
        self._post_response = post_response
        self.posted_payloads: List[Dict[str, Any]] = []

    def fetch_paginated(
        self,
        path_or_url: str,
        auth_header: str,
        *,
        base_url: str = "",
        max_items: int = 200,
        timeout: int = 15,
    ) -> List[Dict[str, Any]]:
        if "/me/reports" in path_or_url:
            return self._existing_reports[:max_items]
        if "/structured_scopes" in path_or_url:
            handle = path_or_url.split("/programs/")[1].split("/")[0]
            return self._scopes.get(handle, [])[:max_items]
        if "/weaknesses" in path_or_url:
            handle = path_or_url.split("/programs/")[1].split("/")[0]
            return self._weaknesses.get(handle, [])[:max_items]
        return self._raw_programs[:max_items]

    def fetch_program_detail(
        self,
        handle: str,
        auth_header: str,
        *,
        base_url: str = "",
        timeout: int = 15,
    ) -> Dict[str, Any]:
        return self._details.get(handle, {})

    def fetch_program_kyc_status(self, handle: str, *, timeout: int = 12) -> Optional[bool]:
        return self._kyc_flags.get(handle, False)

    def fetch_program_graphql_gates(self, handle: str, *, timeout: int = 10) -> Dict[str, Any]:
        return self._graphql_gates.get(handle, {})

    def post_report(
        self,
        payload: Dict[str, Any],
        auth_header: str,
        *,
        base_url: str = "",
        timeout: int = 20,
    ) -> Tuple[int, Dict[str, Any], str]:
        self.posted_payloads.append(payload)
        return self._post_response


def _make_program(
    *,
    handle: str = "acme-vdp",
    policy: str = "Include header X-Acme-VDP: HackerOne-arsoncarson",
    target_signal: Optional[float] = None,
    offers_bounties: bool = False,
    kyc_required: bool = False,
    submission_state: str = "open",
) -> VdpProgram:
    return VdpProgram(
        handle=handle,
        name="Acme Corp VDP",
        offers_bounties=offers_bounties,
        submission_state=submission_state,
        i_must_verify_identity_to_submit=kyc_required,
        policy=policy,
        structured_scopes=[
            {
                "id": "555",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "*.acme.example",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "556",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "https://portal.acme.example/login",
                    "eligible_for_submission": True,
                },
            },
            {
                "id": "557",
                "attributes": {
                    "asset_type": "DOMAIN",
                    "asset_identifier": "excluded.acme.example",
                    "eligible_for_submission": False,
                },
            },
        ],
        weaknesses=[
            {"id": "18", "attributes": {"external_id": "cwe-200", "name": "Information Exposure"}},
            {"id": "22", "attributes": {"external_id": "cwe-538", "name": "Sensitive File Exposure"}},
            {"id": "33", "attributes": {"external_id": "cwe-798", "name": "Use of Hard-coded Credentials"}},
            {"id": "44", "attributes": {"external_id": "cwe-942", "name": "Overly Permissive CORS Policy"}},
            {"id": "55", "attributes": {"external_id": "cwe-284", "name": "Improper Access Control"}},
        ],
        compliance_headers={"X-Acme-VDP": "HackerOne-arsoncarson"},
        target_signal=target_signal,
    )


def test_inverted_module_graph_has_zero_duplication_and_clean_egress_compliance() -> None:
    """Confirm single source of truth constants, deleted pass-through, and clean AST egress."""
    repo_root = Path(__file__).resolve().parent.parent
    src_file = repo_root / "src" / "orbit_security" / "hackerone_vdp_hunter.py"
    cli_file = repo_root / "scripts" / "hunt_hackerone_vdps.py"
    removed_passthrough = repo_root / "scripts" / "hackerone_vdp_hunter.py"

    assert not removed_passthrough.exists(), "Pass-through scripts/hackerone_vdp_hunter.py must be removed"
    src_text = src_file.read_text(encoding="utf-8")
    cli_text = cli_file.read_text(encoding="utf-8")

    # Inverted graph: library never imports from scripts or mutates sys.path
    assert "from hunt_hackerone_vdps" not in src_text
    assert "sys.path.insert" not in src_text
    assert "audit_hackerone_profile" not in src_text
    assert "sys.path.insert" not in cli_text
    assert "from orbit_security.hackerone_vdp_hunter import" in cli_text
    assert len(cli_text.splitlines()) < 180

    # Single source of truth for detector regexes & asset filters
    assert HTML_LOOKALIKE_RE is det_mod.HTML_LOOKALIKE_RE
    assert SENSITIVE_BUCKET_KEY_RE is det_mod.SENSITIVE_BUCKET_KEY_RE
    assert STATIC_PUBLIC_ASSET_EXTS is det_mod.STATIC_PUBLIC_ASSET_EXTS
    assert STATIC_PUBLIC_FILENAMES is det_mod.STATIC_PUBLIC_FILENAMES

    # AST Sentinel egress compliance passes with zero violations
    violations = audit_egress_guard_compliance([src_file])
    assert violations == []


def test_discover_targets_deduplicates_reports_staged_dossiers_and_persists_ct_cache(tmp_path: Path) -> None:
    ready_dir = tmp_path / "vdp_ready"
    ready_dir.mkdir()
    (ready_dir / "acme-vdp_vdp_staged_acme_example.md").write_text("# staged", encoding="utf-8")

    cache_path = tmp_path / "vdp_ct_cache.json"
    discovery = FakeDiscoveryTransport(
        {
            "acme.example": {
                "try.acme.example",
                "reported.acme.example",
                "staged.acme.example",
                "excluded.acme.example",
                "api.acme.example",
            }
        }
    )
    hunter = HackerOneVdpHunter(discovery=discovery)
    prog = _make_program()

    existing_reports = [
        {"id": "101", "attributes": {"title": "Exposed /.git/config on reported.acme.example", "state": "new"}}
    ]

    plan = hunter.discover_targets(
        prog,
        existing_reports=existing_reports,
        vdp_ready_dir=ready_dir,
        covered_domains=set(),
        cache_path=cache_path,
        max_subdomains=10,
    )

    assert plan.wildcards_scanned == ["acme-vdp:*.acme.example"]
    assert "portal.acme.example" in plan.hosts_to_screen
    assert "try.acme.example" in plan.hosts_to_screen
    assert "api.acme.example" in plan.hosts_to_screen
    # Duplicates and out-of-scope hosts are excluded
    assert "reported.acme.example" not in plan.hosts_to_screen
    assert "staged.acme.example" not in plan.hosts_to_screen
    assert "excluded.acme.example" not in plan.hosts_to_screen

    # Second call hits non-empty CT cache without re-invoking discovery adapter
    assert discovery.called_roots == ["acme.example"]
    plan_cached = hunter.discover_targets(
        prog,
        existing_reports=existing_reports,
        vdp_ready_dir=ready_dir,
        covered_domains=set(),
        cache_path=cache_path,
        max_subdomains=10,
    )
    assert discovery.called_roots == ["acme.example"]
    assert plan_cached.hosts_to_screen == plan.hosts_to_screen


def test_screen_gate_render_and_live_dispatch_end_to_end_with_fake_adapters(tmp_path: Path) -> None:
    git_config = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        '[remote "origin"]\n'
        "\turl = https://ci_bot:TopSecret99@github.com/acme/backend.git\n"
    )

    def _http_handler(url: str, headers: Dict[str, str], max_bytes: int, timeout: int):
        path = urlparse(url).path or "/"
        if path == "/":
            return (200, {"Content-Type": "text/html"}, "<html><body>App</body></html>")
        if path == "/.git/config":
            return (200, {"Content-Type": "text/plain"}, git_config)
        return (404, {}, "Not Found")

    http = FakeHttpTransport(_http_handler)
    dns = FakeDnsTransport({("app.acme.example", "A"): {"Status": 0, "Answer": [{"type": 1, "data": "203.0.113.10"}]}})
    h1 = FakeHackerOneTransport()
    hunter = HackerOneVdpHunter(http=http, dns=dns, h1=h1, sleep_fn=lambda _: None)
    prog = _make_program()

    finding = hunter.screen_target(prog, "app.acme.example")
    assert finding is not None
    assert finding.finding_type == "exposed_git"
    assert finding.weakness_id == "22"
    assert "TopSecret99" not in finding.evidence_snippet
    assert "<REDACTED>" in finding.evidence_snippet

    gate = hunter.evaluate_quality_gate(
        prog,
        finding,
        reverify_runs=2,
        critic_runs=3,
        reverify_sleep_seconds=0.0,
    )
    assert gate.passed is True
    assert gate.verdict == "APPROVED"
    assert gate.reverification_passes == 2
    assert gate.critic_passes == 3

    dossier_md, digest = hunter.render_dossier(prog, finding)
    assert "app.acme.example" in dossier_md
    assert "X-Acme-VDP: HackerOne-arsoncarson" in dossier_md
    assert "TopSecret99" not in dossier_md
    assert len(digest) == 64

    ready_dir = tmp_path / "vdp_ready"
    manifest_path = ready_dir / "vdp_verification_manifest.json"
    res = hunter.dispatch_finding(
        prog,
        finding,
        "researcher",
        "token",
        dry_run=False,
        existing_reports=[],
        vdp_ready_dir=ready_dir,
        manifest_path=manifest_path,
        reverify_runs=2,
        critic_runs=3,
        reverify_sleep_seconds=0.0,
    )
    assert res["status"] == "SUBMITTED"
    assert res["report_id"] == "9000123"
    assert len(h1.posted_payloads) == 1
    assert h1.posted_payloads[0]["data"]["attributes"]["team_handle"] == "acme-vdp"
    assert (ready_dir / "acme-vdp_vdp_app_acme_example.md").exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "app.acme.example" in manifest["vdp_hunter_dispatches"]

    # Immediate re-dispatch is blocked by staged dossier deduplication
    dup = hunter.dispatch_finding(
        prog,
        finding,
        "researcher",
        "token",
        dry_run=False,
        existing_reports=[],
        vdp_ready_dir=ready_dir,
        manifest_path=manifest_path,
    )
    assert dup["status"] == "DUPLICATE_ABORTED"
    assert len(h1.posted_payloads) == 1


def test_quality_gate_blocks_reverify_drift_and_403_stages_to_blocked_dir(tmp_path: Path) -> None:
    calls = {"count": 0}

    def _drifting_http(url: str, headers: Dict[str, str], max_bytes: int, timeout: int):
        calls["count"] += 1
        # First probe during live re-verify returns 404 (drifted from 200)
        return (404, {}, "Gone")

    prog = _make_program()
    finding = VdpFinding(
        program_handle="acme-vdp",
        program_name="Acme Corp VDP",
        host="app.acme.example",
        finding_type="exposed_git",
        title="Exposed /.git/config Sensitive Configuration File on app.acme.example",
        severity="medium",
        weakness_id="22",
        structured_scope_id="555",
        cname_target=None,
        a_records=["203.0.113.10"],
        http_status=200,
        http_url="https://app.acme.example/.git/config",
        evidence_snippet="[core]\nrepositoryformatversion = 0",
        remediation="Block /.git/config.",
        captured_utc="2026-11-21T00:00:00+00:00",
    )

    hunter_drift = HackerOneVdpHunter(
        http=FakeHttpTransport(_drifting_http),
        dns=FakeDnsTransport(),
        sleep_fn=lambda _: None,
    )
    gate = hunter_drift.evaluate_quality_gate(
        prog, finding, reverify_runs=2, critic_runs=3, reverify_sleep_seconds=0.0
    )
    assert gate.passed is False
    assert gate.reverification_passes == 0
    assert calls["count"] == 2

    # 403 Forbidden moves dossier into vdp_blocked and never pollutes vdp_ready
    h1_403 = FakeHackerOneTransport(post_response=(403, {}, '{"errors":[{"status":403}]}'))
    hunter_403 = HackerOneVdpHunter(h1=h1_403, sleep_fn=lambda _: None)
    ready_dir = tmp_path / "vdp_ready"
    res = hunter_403.dispatch_finding(
        prog,
        finding,
        "researcher",
        "token",
        dry_run=False,
        existing_reports=[],
        vdp_ready_dir=ready_dir,
        manifest_path=tmp_path / "manifest.json",
        skip_live_reverify=True,
    )
    assert res["status"] == "BLOCKED_PROGRAM_FORBIDDEN"
    assert not (ready_dir / "acme-vdp_vdp_app_acme_example.md").exists()
    assert (tmp_path / "vdp_blocked" / "acme-vdp_vdp_app_acme_example.md").exists()


def test_run_hunt_full_orchestration_through_fake_adapters(tmp_path: Path) -> None:
    raw_programs = [
        {"id": "1", "attributes": {"handle": "high-sig-vdp", "offers_bounties": False, "submission_state": "open"}},
        {"id": "2", "attributes": {"handle": "open-vdp", "offers_bounties": False, "submission_state": "open"}},
        {"id": "3", "attributes": {"handle": "paid-bbp", "offers_bounties": True, "submission_state": "open"}},
    ]
    details = {
        "high-sig-vdp": {
            "attributes": {
                "handle": "high-sig-vdp",
                "name": "High Signal VDP",
                "offers_bounties": False,
                "submission_state": "open",
            }
        },
        "open-vdp": {
            "attributes": {
                "handle": "open-vdp",
                "name": "Open VDP",
                "offers_bounties": False,
                "submission_state": "open",
                "policy": "Use header X-Open-VDP when testing.",
            }
        },
    }
    scopes = {
        "high-sig-vdp": [
            {
                "id": "10",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "*.highsig.example",
                    "eligible_for_submission": True,
                },
            }
        ],
        "open-vdp": [
            {
                "id": "20",
                "attributes": {
                    "asset_type": "WILDCARD",
                    "asset_identifier": "*.openvdp.example",
                    "eligible_for_submission": True,
                },
            }
        ],
    }
    weaknesses = {
        "open-vdp": [
            {"id": "44", "attributes": {"external_id": "cwe-942", "name": "Overly Permissive CORS Policy"}},
        ]
    }
    existing_reports = [
        {"id": "99", "attributes": {"state": "informative", "title": "old.other.example"}}
    ]
    h1 = FakeHackerOneTransport(
        raw_programs=raw_programs,
        program_details=details,
        program_scopes=scopes,
        program_weaknesses=weaknesses,
        existing_reports=existing_reports,
        graphql_gates={
            "high-sig-vdp": {"target_signal": 1.0},
            "open-vdp": {"target_signal": 0.0},
        },
    )
    discovery = FakeDiscoveryTransport(
        {
            "highsig.example": {"api.highsig.example"},
            "openvdp.example": {"api.openvdp.example"},
        }
    )

    def _cors_http(url: str, headers: Dict[str, str], max_bytes: int, timeout: int):
        if url == "https://api.openvdp.example/":
            origin = headers.get("Origin")
            if origin:
                return (
                    200,
                    {
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                        "Content-Type": "application/json",
                    },
                    '{"account_id": 7, "role": "admin"}',
                )
            return (200, {"Content-Type": "application/json"}, '{"account_id": 7, "role": "admin"}')
        return (404, {}, "Not Found")

    log_buf = io.StringIO()
    hunter = HackerOneVdpHunter(
        http=FakeHttpTransport(_cors_http),
        dns=FakeDnsTransport(),
        h1=h1,
        discovery=discovery,
        credentials_loader=lambda _env: ("researcher", "tok"),
        sleep_fn=lambda _: None,
        log_stream=log_buf,
    )

    # Seed an empty cache entry to confirm purge_empty_cache works in the same run
    cache_path = tmp_path / "ct_cache.json"
    cache_path.write_text(
        json.dumps({"empty-stale.example": {"timestamp": 1.0, "subdomains": []}}),
        encoding="utf-8",
    )

    summary = hunter.run_hunt(
        VdpHuntConfig(
            max_programs=5,
            workers=1,
            submit_vdp=True,
            purge_empty_cache=True,
            cache_path=cache_path,
            vdp_ready_dir=tmp_path / "vdp_ready",
            manifest_path=tmp_path / "vdp_ready" / "manifest.json",
            reverify_runs=2,
            critic_runs=3,
            reverify_sleep_seconds=0.0,
        ),
        covered_domains=set(),
    )

    assert summary["purged_empty_cache_count"] == 1
    assert summary["total_programs_fetched"] == 3
    assert summary["open_vdp_candidates"] == 2
    assert summary["programs_skipped_signal_gate"] == 1
    assert summary["programs_with_uncovered_wildcards_scanned"] == 1
    assert summary["findings_count"] == 1
    assert summary["findings"][0]["finding_type"] == "cors_credentialed_reflection"
    assert summary["submissions"][0]["status"] == "SUBMITTED"
    assert len(h1.posted_payloads) == 1
    assert discovery.called_roots == ["openvdp.example"]
    assert "[VDP-HUNT] Skipping high-sig-vdp" in log_buf.getvalue()
    assert "[VDP-HUNT] DISPATCH [open-vdp] api.openvdp.example -> SUBMITTED" in log_buf.getvalue()
