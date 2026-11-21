"""Typed domain models and collector adapter seam for the Briefing & Cockpit Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class EmailCollectRequest:
    """Typed request passed to the IMAP/email collector adapter (eliminates inspect.signature probes)."""

    max_retries: int = 0
    retry_interval_sec: float = 300.0
    target_date: Optional[datetime.date] = None


@dataclass(frozen=True)
class BriefingConfig:
    """Configuration for a two-phase briefing run (Phase 1 collection + Phase 2 synthesis)."""

    now: Optional[datetime.datetime] = None
    schedule_mode: str = "default"
    dry_run: bool = False
    max_retries: Optional[int] = None
    retry_interval_sec: float = 300.0
    repo_root: Optional[Path] = None
    workspace_root: Optional[Path] = None
    state_dir: Optional[Path] = None
    persist_state: bool = False
    previous_date: Optional[str] = None
    previous_snapshot: Optional[Dict[str, Any]] = None
    delta_override: Optional[Dict[str, Any]] = None
    ci_reconciled_override: Optional[Dict[str, Any]] = None
    critic_override: Optional[Dict[str, Any]] = None
    agenda_override: Optional[List[str]] = None

    def effective_now(self) -> datetime.datetime:
        return self.now if self.now is not None else datetime.datetime.now()

    def effective_retries(self) -> int:
        if self.max_retries is not None:
            return int(self.max_retries)
        return 0 if self.dry_run else 3


@dataclass(frozen=True)
class TelemetrySnapshot:
    """Single typed snapshot produced by Phase 1 collection and consumed purely in-process by Phase 2."""

    generated_at: str = ""
    date_key: str = ""
    schedule_mode: str = "default"
    stripe: Dict[str, Any] = field(default_factory=dict)
    daemon: Dict[str, Any] = field(default_factory=dict)
    inbox: Dict[str, Any] = field(default_factory=dict)
    campaigns: Dict[str, Any] = field(default_factory=dict)
    option_c: Dict[str, Any] = field(default_factory=dict)
    email_data: Dict[str, Any] = field(default_factory=dict)
    email_hygiene: Dict[str, Any] = field(default_factory=dict)
    live_ci: Dict[str, Any] = field(default_factory=dict)
    archived_ci_count: int = 0
    geo_panel: Dict[str, Any] = field(default_factory=dict)
    system_telemetry: Dict[str, Any] = field(default_factory=dict)
    projects_radar: Dict[str, Any] = field(default_factory=dict)
    calendar_tasks: Dict[str, Any] = field(default_factory=dict)
    intel_news: Dict[str, Any] = field(default_factory=dict)
    commits_24h: int = 0
    # Pre-collected local/remote critic evidence so Phase 2 runs purely in-process
    multi_repo_ci: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    repo_git_states: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    go_mod_files: Dict[str, str] = field(default_factory=dict)

    @property
    def master_briefing(self) -> Dict[str, Any]:
        hyg_mb = self.email_hygiene.get("master_briefing") if isinstance(self.email_hygiene, dict) else None
        if isinstance(hyg_mb, dict) and hyg_mb:
            return hyg_mb
        nested_hyg = self.email_data.get("email_hygiene") if isinstance(self.email_data, dict) else None
        if isinstance(nested_hyg, dict) and isinstance(nested_hyg.get("master_briefing"), dict):
            return nested_hyg["master_briefing"]
        direct_mb = self.email_data.get("master_briefing") if isinstance(self.email_data, dict) else None
        return direct_mb if isinstance(direct_mb, dict) else {}

    @property
    def post_briefing_delta(self) -> Dict[str, Any]:
        val = self.email_data.get("post_briefing_delta") if isinstance(self.email_data, dict) else None
        return val if isinstance(val, dict) else {}

    def delta_metrics(self) -> Dict[str, Any]:
        """Extracts canonical scalar metrics used for 24h day-over-day delta reconciliation."""
        drives = self.system_telemetry.get("drives", {}) if isinstance(self.system_telemetry, dict) else {}
        primary_drive = (
            drives.get("A:\\")
            or drives.get("C:\\")
            or (next(iter(drives.values())) if drives else {})
        )
        geo_latest = self.geo_panel.get("latest") if isinstance(self.geo_panel, dict) else None
        geo_latest = geo_latest if isinstance(geo_latest, dict) else {}
        return {
            "disk_free_gb": float(primary_drive.get("free_gb", 0.0) or 0.0),
            "commits_24h": int(self.commits_24h or 0),
            "unread_count": int(self.email_data.get("unread", 0) or 0),
            "urgent_count": int(self.email_data.get("urgent", 0) or 0),
            "tier1_ready": len(self.option_c.get("tier_1_items", []) or []),
            "tier2_queued": len(self.option_c.get("tier_2_items", []) or []),
            "geo_citation_share_pct": float(geo_latest.get("citation_rate_pct", 0.0) or 0.0),
            "kyc_gate": str(self.option_c.get("kyc_payout_status") or "PENDING_PHYSICAL_ID"),
        }


@dataclass(frozen=True)
class BriefingResult:
    """Pure output of Phase 2 synthesis over a TelemetrySnapshot."""

    snapshot: TelemetrySnapshot
    markdown: str
    spoken_summary: str
    ci_reconciled: Dict[str, Any]
    critic: Dict[str, Any]
    deltas: Dict[str, Any]
    agenda_items: List[str]
    top3_actions: List[str]
    date_key: str
    generated_at: str
    schedule_mode: str = "default"


def _empty_dict(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
    return {}


def _zero_int(*_args: Any, **_kwargs: Any) -> int:
    return 0


def _empty_critic_probe(
    _ci_candidates: List[Dict[str, str]],
    _mb_blob: str,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    return {}, {}


@dataclass(frozen=True)
class CollectorAdapters:
    """Injected Phase 1 collector adapters across hardware, IMAP/email, GitHub CI, Stripe, and workspace/news."""

    # Hardware / Ports & Local Daemons
    system_telemetry: Callable[[], Dict[str, Any]] = _empty_dict
    daemon_health: Callable[[], Dict[str, Any]] = _empty_dict
    # IMAP / Email & Calendar
    email_telemetry: Callable[[EmailCollectRequest], Dict[str, Any]] = _empty_dict
    email_hygiene: Optional[Callable[[], Dict[str, Any]]] = None
    calendar_tasks: Callable[[], Dict[str, Any]] = _empty_dict
    archive_ci_alerts: Callable[[Dict[str, Any]], int] = _zero_int
    # GitHub CI
    github_ci: Callable[[str, str], Dict[str, Any]] = _empty_dict
    # Stripe & Revenue Operations
    stripe_telemetry: Callable[[], Dict[str, Any]] = _empty_dict
    option_c_readiness: Callable[[], Dict[str, Any]] = _empty_dict
    inbox_pipeline: Callable[[], Dict[str, Any]] = _empty_dict
    campaign_outreach: Callable[[], Dict[str, Any]] = _empty_dict
    geo_panel: Callable[[], Dict[str, Any]] = _empty_dict
    # Workspace & News
    projects_radar: Callable[[], Dict[str, Any]] = _empty_dict
    intel_news: Callable[[], Dict[str, Any]] = _empty_dict
    commits_24h: Callable[[Dict[str, Any], datetime.datetime], int] = _zero_int
    workspace_critic_probe: Callable[
        [List[Dict[str, str]], str],
        Tuple[Dict[str, Dict[str, Any]], Dict[str, str]],
    ] = _empty_critic_probe

    @classmethod
    def in_memory(
        cls,
        *,
        system_telemetry: Optional[Dict[str, Any]] = None,
        daemon_health: Optional[Dict[str, Any]] = None,
        email_telemetry: Optional[Dict[str, Any]] = None,
        email_hygiene: Optional[Dict[str, Any]] = None,
        calendar_tasks: Optional[Dict[str, Any]] = None,
        github_ci: Optional[Dict[str, Any]] = None,
        multi_repo_ci: Optional[Dict[str, Dict[str, Any]]] = None,
        stripe_telemetry: Optional[Dict[str, Any]] = None,
        option_c_readiness: Optional[Dict[str, Any]] = None,
        inbox_pipeline: Optional[Dict[str, Any]] = None,
        campaign_outreach: Optional[Dict[str, Any]] = None,
        geo_panel: Optional[Dict[str, Any]] = None,
        projects_radar: Optional[Dict[str, Any]] = None,
        intel_news: Optional[Dict[str, Any]] = None,
        commits_24h: int = 0,
        archived_ci_count: int = 0,
        repo_git_states: Optional[Dict[str, Dict[str, Any]]] = None,
        go_mod_files: Optional[Dict[str, str]] = None,
    ) -> "CollectorAdapters":
        """Builds a deterministic, zero-I/O in-memory adapter bundle for pipeline testing."""
        primary_ci = dict(github_ci or {})
        extra_ci = {k.lower(): dict(v) for k, v in (multi_repo_ci or {}).items()}
        git_states = {k.lower(): dict(v) for k, v in (repo_git_states or {}).items()}
        go_mods = dict(go_mod_files or {})

        def _ci_lookup(repo: str = "CmfH009/Orbit-Security", branch: str = "main") -> Dict[str, Any]:
            key = f"{repo.lower()}@{branch.lower()}"
            if key in extra_ci:
                return dict(extra_ci[key])
            if repo.lower() in extra_ci:
                return dict(extra_ci[repo.lower()])
            return dict(primary_ci)

        return cls(
            system_telemetry=lambda: dict(system_telemetry or {}),
            daemon_health=lambda: dict(daemon_health or {}),
            email_telemetry=lambda _req: dict(email_telemetry or {}),
            email_hygiene=(lambda: dict(email_hygiene)) if email_hygiene is not None else None,
            calendar_tasks=lambda: dict(calendar_tasks or {}),
            archive_ci_alerts=lambda _live_ci: int(archived_ci_count),
            github_ci=_ci_lookup,
            stripe_telemetry=lambda: dict(stripe_telemetry or {}),
            option_c_readiness=lambda: dict(option_c_readiness or {}),
            inbox_pipeline=lambda: dict(inbox_pipeline or {}),
            campaign_outreach=lambda: dict(campaign_outreach or {}),
            geo_panel=lambda: dict(geo_panel or {}),
            projects_radar=lambda: dict(projects_radar or {}),
            intel_news=lambda: dict(intel_news or {}),
            commits_24h=lambda _radar, _now: int(commits_24h),
            workspace_critic_probe=lambda _cands, _blob: (dict(git_states), dict(go_mods)),
        )
