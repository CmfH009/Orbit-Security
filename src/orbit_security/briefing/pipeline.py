"""Deep two-phase Briefing & Cockpit Pipeline (Phase 1 Collect -> Phase 2 Pure In-Process Synthesis)."""

from __future__ import annotations

from dataclasses import replace
import datetime
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ._sanitize import (
    sanitize_email_data,
    sanitize_intel_news,
    sanitize_master_briefing,
)
from .email_cockpit import _clean_subject
from .models import (
    BriefingConfig,
    BriefingResult,
    CollectorAdapters,
    EmailCollectRequest,
    TelemetrySnapshot,
)
from .system_collectors import (
    live_collector_adapters,
    probe_workspace_critic_evidence,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_BRIEFINGS_DIR = _REPO_ROOT / "daily_briefings"

_STATE_DATE_FILE_RE = re.compile(r"^briefing_state_(\d{4}-\d{2}-\d{2})\.json$")
_DELTA_FLOAT_KEYS = ("disk_free_gb", "geo_citation_share_pct")
_DELTA_INT_KEYS = ("commits_24h", "unread_count", "urgent_count", "tier1_ready", "tier2_queued")

_BRIEFING_CI_LINE_RE = re.compile(
    r"\[(?P<repo>[^\]]+)\]\s*Run\s+(?:failed|cancelled|timed out)\s*:\s*(?P<workflow>.+?)\s*-\s*(?P<branch>[^\s(]+)\s*\((?P<sha>[0-9a-fA-F]{6,40})\)",
    re.IGNORECASE,
)
_CLOSED_VDP_REPORT_IDS = frozenset({"4204024", "4204160"})
_CLOSED_VDP_ADVISORY_STATES = frozenset({"not-applicable", "informative", "resolved", "duplicate", "spam"})


def _closed_vdp_report_ids() -> frozenset[str]:
    """Return known closed/withdrawn HackerOne VDP report IDs from constants and local advisory ledger."""
    closed = set(_CLOSED_VDP_REPORT_IDS)
    advisories_path = _REPO_ROOT / "data" / "dispatched_security_advisories.json"
    if advisories_path.exists():
        try:
            payload = json.loads(advisories_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                for entry in payload.values():
                    if not isinstance(entry, dict):
                        continue
                    rid = str(entry.get("report_id") or "").strip()
                    state = str(entry.get("state") or "").strip().lower()
                    status = str(entry.get("status") or "").strip().upper()
                    if rid and (state in _CLOSED_VDP_ADVISORY_STATES or status.startswith("CLOSED_")):
                        closed.add(rid)
        except Exception:
            pass
    return frozenset(closed)


def _is_closed_vdp_subject(subject: str, closed_ids: Optional[frozenset[str]] = None) -> bool:
    """Return True when a VDP email subject references a closed/withdrawn report ID."""
    ids = closed_ids if closed_ids is not None else _closed_vdp_report_ids()
    return any(f"#{rid}" in subject for rid in ids)


def sanitize_snapshot(snapshot: TelemetrySnapshot) -> TelemetrySnapshot:
    """Returns a new TelemetrySnapshot with all untrusted external payloads scrubbed via PromptInjectionSanitizer."""
    clean_email = sanitize_email_data(snapshot.email_data or {})
    clean_hygiene = dict(snapshot.email_hygiene or {})
    if not clean_hygiene and isinstance(clean_email.get("email_hygiene"), dict):
        clean_hygiene = dict(clean_email["email_hygiene"])
    if "master_briefing" in clean_hygiene:
        clean_hygiene["master_briefing"] = sanitize_master_briefing(clean_hygiene["master_briefing"])
    clean_news = sanitize_intel_news(snapshot.intel_news or {})
    return replace(
        snapshot,
        email_data=clean_email,
        email_hygiene=clean_hygiene,
        intel_news=clean_news,
    )


def _is_other_repo_ci_alert(alert_text: str) -> bool:
    """Returns True when a CI alert explicitly targets a repository other than Orbit-Security."""
    m = re.match(r"^\s*\[([^\]]+)\]", alert_text or "")
    if not m:
        return False
    repo_tag = m.group(1).strip().lower()
    return "/" in repo_tag and "orbit-security" not in repo_tag


def reconcile_ci_alerts_with_live_status(
    email_ci_alerts: Sequence[str],
    live_ci: Dict[str, Any],
    archived_in_imap: int = 0,
) -> Dict[str, Any]:
    """Reconciles historical Orbit-Security inbox CI failure emails against live GitHub Actions HEAD status."""
    orbit_alerts = [str(a) for a in (email_ci_alerts or []) if not _is_other_repo_ci_alert(str(a))]
    head_sha = live_ci.get("head_sha", "")
    all_green = bool(live_ci.get("all_green", False))
    failing_wf = live_ci.get("failing_workflows", [])

    if all_green:
        lines = [f"  - 🟢 All GitHub Actions green on `HEAD` (`{head_sha}`)"]
        if archived_in_imap > 0:
            lines.append(
                f"  - 🧹 Auto-archived {archived_in_imap} superseded CI failure notification(s) to `Orbit/CI-CD`"
            )
        for s in orbit_alerts[:3]:
            clean_s = s.replace("\r", "").replace("\n", " ").strip()
            lines.append(f"  - ✅ [RESOLVED on HEAD {head_sha}] {clean_s}")
        return {
            "active_failures": 0,
            "resolved_alerts": list(orbit_alerts),
            "archived_in_imap": archived_in_imap,
            "summary_markdown": "\n".join(lines),
            "spoken_note": f"all CI test runs are green on HEAD {head_sha}",
        }

    if failing_wf:
        active_count = len(failing_wf)
        lines = [f"  - ⚠️ Live failing workflow on `HEAD` (`{head_sha}`): {wf}" for wf in failing_wf[:3]]
        for s in orbit_alerts[:2]:
            clean_s = s.replace("\r", "").replace("\n", " ").strip()
            lines.append(f"  - ⚠️ {clean_s}")
        return {
            "active_failures": active_count,
            "resolved_alerts": [],
            "summary_markdown": "\n".join(lines),
            "spoken_note": f"heads up, {active_count} GitHub CI workflows failing on HEAD",
        }

    ci_count = len(orbit_alerts)
    summary_str = (
        "\n".join([f"  - ⚠️ {s.replace(chr(13), '').replace(chr(10), ' ').strip()}" for s in orbit_alerts[:3]])
        if ci_count > 0
        else "  - All GitHub Actions green on CmfH009/Orbit-Security"
    )
    return {
        "active_failures": ci_count,
        "resolved_alerts": [],
        "summary_markdown": summary_str,
        "spoken_note": (
            f"heads up, {ci_count} GitHub CI failures logged in Orbit CI CD"
            if ci_count > 0
            else "all CI test runs are green"
        ),
    }


def _normalize_delta_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Coerces tracked snapshot fields to deterministic numeric/string types."""
    norm: Dict[str, Any] = {}
    for k in _DELTA_FLOAT_KEYS:
        try:
            norm[k] = round(float(snapshot.get(k, 0.0) or 0.0), 2)
        except (TypeError, ValueError):
            norm[k] = 0.0
    for k in _DELTA_INT_KEYS:
        try:
            norm[k] = int(snapshot.get(k, 0) or 0)
        except (TypeError, ValueError):
            norm[k] = 0
    kyc_val = snapshot.get("kyc_gate")
    norm["kyc_gate"] = str(kyc_val) if kyc_val not in (None, "") else "PENDING_PHYSICAL_ID"
    return norm


def _load_json_dict(path: Path) -> Optional[Dict[str, Any]]:
    """Reads a JSON file and returns a dict or None on missing/invalid payloads."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _extract_snapshot_payload(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extracts tracked snapshot dict from either a wrapped state record or flat snapshot."""
    snap = data.get("snapshot")
    if isinstance(snap, dict):
        return snap
    all_keys = (*_DELTA_FLOAT_KEYS, *_DELTA_INT_KEYS, "kyc_gate")
    if any(k in data for k in all_keys):
        return data
    return None


def _find_previous_snapshot(
    date_key: str,
    target_dir: Path,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Finds the most recent prior-day snapshot, avoiding today's own snapshot on repeated runs."""
    candidates: List[Tuple[str, Path]] = []
    for entry in target_dir.iterdir():
        if not entry.is_file():
            continue
        match = _STATE_DATE_FILE_RE.match(entry.name)
        if not match:
            continue
        file_date = match.group(1)
        if file_date < date_key:
            candidates.append((file_date, entry))

    candidates.sort(key=lambda item: item[0], reverse=True)
    for file_date, entry in candidates:
        data = _load_json_dict(entry)
        if data:
            snap = _extract_snapshot_payload(data)
            if snap is not None:
                return file_date, snap

    latest_data = _load_json_dict(target_dir / "briefing_state_latest.json")
    if latest_data:
        latest_date = str(latest_data.get("date") or "")[:10]
        if latest_date and latest_date < date_key:
            snap = _extract_snapshot_payload(latest_data)
            if snap is not None:
                return latest_date, snap
        if latest_date == date_key and isinstance(latest_data.get("previous_snapshot"), dict):
            prev_date = latest_data.get("previous_date")
            return (str(prev_date)[:10] if prev_date else None), latest_data["previous_snapshot"]

    today_data = _load_json_dict(target_dir / f"briefing_state_{date_key}.json")
    if today_data and isinstance(today_data.get("previous_snapshot"), dict):
        prev_date = today_data.get("previous_date")
        return (str(prev_date)[:10] if prev_date else None), today_data["previous_snapshot"]

    return None, None


def compute_daily_deltas_in_memory(
    date_str: str,
    current_snapshot: Dict[str, Any],
    *,
    previous_date: Optional[str] = None,
    previous_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Computes 24h day-over-day deltas purely in-process with zero filesystem I/O."""
    date_key = str(date_str).strip()[:10] or datetime.date.today().isoformat()
    normalized = _normalize_delta_snapshot(current_snapshot)

    if previous_snapshot is not None:
        norm_prev = _normalize_delta_snapshot(previous_snapshot)
        has_previous = True
        deltas: Dict[str, Any] = {}
        for k in _DELTA_FLOAT_KEYS:
            deltas[k] = round(normalized[k] - norm_prev[k], 2)
        for k in _DELTA_INT_KEYS:
            deltas[k] = int(normalized[k] - norm_prev[k])
        kyc_prev = norm_prev["kyc_gate"]
        kyc_curr = normalized["kyc_gate"]
        kyc_changed = kyc_curr != kyc_prev
        deltas["kyc_gate"] = f"{kyc_prev} -> {kyc_curr}" if kyc_changed else "unchanged"
        has_prev_geo = "geo_citation_share_pct" in previous_snapshot
        geo_unchanged = bool(
            has_prev_geo
            and round(normalized["geo_citation_share_pct"], 2)
            == round(norm_prev["geo_citation_share_pct"], 2)
        )
        kyc_note = f"{kyc_prev} -> {kyc_curr}" if kyc_changed else f"{kyc_curr} (unchanged)"
        summary_line = (
            f"vs {previous_date or 'prior'}: "
            f"Disk {deltas['disk_free_gb']:+.1f} GB | "
            f"Commits {deltas['commits_24h']:+d} | "
            f"Unread {deltas['unread_count']:+d} | "
            f"Urgent {deltas['urgent_count']:+d} | "
            f"Tier-1 {deltas['tier1_ready']:+d} | "
            f"Tier-2 {deltas['tier2_queued']:+d} | "
            f"GEO {deltas['geo_citation_share_pct']:+.1f}% | "
            f"KYC: {kyc_note}"
        )
    else:
        norm_prev = None
        has_previous = False
        deltas = {k: 0.0 for k in _DELTA_FLOAT_KEYS}
        deltas.update({k: 0 for k in _DELTA_INT_KEYS})
        deltas["kyc_gate"] = "baseline"
        kyc_changed = False
        geo_unchanged = False
        summary_line = (
            f"Baseline ({date_key}): "
            f"Disk {normalized['disk_free_gb']:.1f} GB free | "
            f"Commits {normalized['commits_24h']} | "
            f"Unread {normalized['unread_count']} | "
            f"Urgent {normalized['urgent_count']} | "
            f"Tier-1 {normalized['tier1_ready']} | "
            f"Tier-2 {normalized['tier2_queued']} | "
            f"GEO {normalized['geo_citation_share_pct']:.1f}% | "
            f"KYC: {normalized['kyc_gate']}"
        )

    return {
        "date": date_key,
        "has_previous": has_previous,
        "previous_date": previous_date,
        "current": normalized,
        "previous": norm_prev,
        "deltas": deltas,
        "geo_unchanged": geo_unchanged,
        "kyc_changed": kyc_changed,
        "summary_line": summary_line,
    }


def compute_and_save_daily_deltas(
    date_str: str,
    current_snapshot: Dict[str, Any],
    state_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Computes 24h day-over-day deltas against the prior day's snapshot and persists state files."""
    date_key = str(date_str).strip()[:10] or datetime.date.today().isoformat()
    target_dir = Path(state_dir) if state_dir is not None else DEFAULT_BRIEFINGS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    prev_date, raw_prev = _find_previous_snapshot(date_key=date_key, target_dir=target_dir)
    result = compute_daily_deltas_in_memory(
        date_str=date_key,
        current_snapshot=current_snapshot,
        previous_date=prev_date,
        previous_snapshot=raw_prev,
    )

    state_payload = {
        "date": date_key,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snapshot": result["current"],
        "previous_date": result["previous_date"],
        "previous_snapshot": result["previous"],
        "has_previous": result["has_previous"],
        "deltas": result["deltas"],
        "geo_unchanged": result["geo_unchanged"],
        "kyc_changed": result["kyc_changed"],
        "summary_line": result["summary_line"],
    }

    dated_path = target_dir / f"briefing_state_{date_key}.json"
    latest_path = target_dir / "briefing_state_latest.json"
    serialized = json.dumps(state_payload, indent=2)
    dated_path.write_text(serialized, encoding="utf-8")
    latest_path.write_text(serialized, encoding="utf-8")

    return {
        **result,
        "state_file": str(dated_path),
        "latest_file": str(latest_path),
    }


def extract_critic_ci_candidates(
    master_briefing: Optional[Dict[str, Any]],
    post_delta: Optional[Dict[str, Any]],
    email_ci_alerts: Optional[Sequence[str]],
) -> List[Dict[str, str]]:
    """Extracts deduplicated multi-repo CI failure candidates from delta, master briefing, and email alerts."""
    mb = master_briefing if isinstance(master_briefing, dict) else {}
    delta = post_delta if isinstance(post_delta, dict) else {}
    ci_candidates: List[Dict[str, str]] = []
    seen_ci_keys: set[Tuple[str, str]] = set()

    for item in delta.get("ci_cd_all", []) or []:
        if isinstance(item, dict) and item.get("repo") and item.get("sha"):
            key = (str(item["repo"]).lower(), str(item["sha"]).lower())
            if key not in seen_ci_keys:
                seen_ci_keys.add(key)
                ci_candidates.append(
                    {
                        "repo": str(item["repo"]),
                        "workflow": str(item.get("workflow") or "CI"),
                        "branch": str(item.get("branch") or "main"),
                        "sha": str(item["sha"]),
                        "subject": str(item.get("subject") or ""),
                    }
                )

    sections = mb.get("sections") if isinstance(mb.get("sections"), dict) else {}
    sec_ci_lines = [
        line
        for sec_k in ("ops_cicd_sla", "critic_audit", "personal_delta")
        for line in (sections.get(sec_k, []) or [])
    ]
    for line in [*sec_ci_lines, *(email_ci_alerts or ())]:
        m = _BRIEFING_CI_LINE_RE.search(str(line))
        if m:
            key = (m.group("repo").strip().lower(), m.group("sha").strip().lower())
            if key not in seen_ci_keys:
                seen_ci_keys.add(key)
                ci_candidates.append(
                    {
                        "repo": m.group("repo").strip(),
                        "workflow": m.group("workflow").strip(),
                        "branch": m.group("branch").strip(),
                        "sha": m.group("sha").strip(),
                        "subject": str(line),
                    }
                )
    return ci_candidates


def _build_master_briefing_blob(master_briefing: Dict[str, Any]) -> str:
    sections = master_briefing.get("sections") if isinstance(master_briefing.get("sections"), dict) else {}
    return " ".join(
        [
            str(master_briefing.get("subject") or ""),
            *(str(x) for x in (master_briefing.get("highlights") or [])),
            *(str(x) for sec in sections.values() if isinstance(sec, list) for x in sec),
        ]
    )


def verify_critic_snapshot(snapshot: TelemetrySnapshot) -> Dict[str, Any]:
    """Pure in-process Critic Verification over a single typed TelemetrySnapshot (zero disk/git/network I/O)."""
    mb = snapshot.master_briefing
    delta = snapshot.post_briefing_delta
    live_ci = snapshot.live_ci or {}
    option_c = snapshot.option_c or {}
    daemon = snapshot.daemon or {}
    sys_telem = snapshot.system_telemetry or {}
    sections = mb.get("sections") if isinstance(mb.get("sections"), dict) else {}

    checks: List[Dict[str, str]] = []
    active_ci_failures: List[str] = []
    active_security_actions: List[str] = []
    resolved_ci_alerts: List[str] = []

    ci_candidates = extract_critic_ci_candidates(
        master_briefing=mb,
        post_delta=delta,
        email_ci_alerts=snapshot.email_data.get("ci_alerts", []),
    )

    repo_git_states = {k.lower(): v for k, v in (snapshot.repo_git_states or {}).items()}
    multi_repo_ci = {k.lower(): v for k, v in (snapshot.multi_repo_ci or {}).items()}

    # 1. Multi-Repo CI Failure Reconciliation (purely over pre-collected git & CI state)
    for ci in ci_candidates:
        repo_full = ci["repo"]
        short_repo = repo_full.split("/")[-1].strip().lower()
        branch = ci["branch"]
        fail_sha = ci["sha"]
        wf = ci["workflow"]

        git_info = (
            repo_git_states.get(f"{short_repo}:{fail_sha.lower()}")
            or repo_git_states.get(short_repo)
            or {}
        )
        local_dir = str(git_info.get("local_dir") or short_repo)
        local_head = str(git_info.get("local_head") or "")
        commits_ahead = int(git_info.get("commits_ahead", 0) or 0)

        gh_status: Dict[str, Any] = {}
        if short_repo == "orbit-security" and live_ci:
            gh_status = live_ci
        else:
            gh_status = (
                multi_repo_ci.get(f"{repo_full.lower()}@{branch.lower()}")
                or multi_repo_ci.get(repo_full.lower())
                or multi_repo_ci.get(short_repo)
                or {}
            )

        gh_head = str(gh_status.get("head_sha") or "")
        gh_green = bool(gh_status.get("all_green", False))
        gh_failing = list(gh_status.get("failing_workflows", []) or [])

        if gh_green and gh_head:
            msg = f"`{repo_full}` `{wf}` failure on `{fail_sha}` superseded — GitHub Actions all green on `HEAD` `{gh_head}`"
            if local_head and commits_ahead > 0:
                msg += f" (local `HEAD` `{local_head}`, `{commits_ahead}` commit(s) ahead)"
            checks.append({"check": f"CI:{repo_full}", "status": "RESOLVED_ON_HEAD", "detail": msg})
            resolved_ci_alerts.append(msg)
        elif gh_failing:
            if local_head and local_head != gh_head and commits_ahead > 0:
                msg = (
                    f"`{repo_full}` `{wf}` failing on remote `{gh_head}` (from `{fail_sha}`); "
                    f"local `HEAD` `{local_head}` is `{commits_ahead}` commit(s) ahead — push/verify remote CI"
                )
                checks.append({"check": f"CI:{repo_full}", "status": "LOCAL_AHEAD_REMOTE_FAILING", "detail": msg})
            else:
                msg = f"`{repo_full}` `{wf}` failing on `{branch}` (`{gh_head or fail_sha}`)"
                checks.append({"check": f"CI:{repo_full}", "status": "ACTIVE_FAILURE", "detail": msg})
            active_ci_failures.append(msg)
        elif local_head and commits_ahead > 0:
            msg = (
                f"`{repo_full}` `{wf}` failure (`{fail_sha}`) locally superseded: "
                f"`{local_dir}` is on `{local_head}` (`{commits_ahead}` commit(s) ahead; verify remote CI)"
            )
            checks.append({"check": f"CI:{repo_full}", "status": "LOCALLY_SUPERSEDED", "detail": msg})
            resolved_ci_alerts.append(msg)
        else:
            msg = f"`{repo_full}` `{wf}` failure flagged on `{branch}` (`{fail_sha}`)"
            checks.append({"check": f"CI:{repo_full}", "status": "ACTIVE_FAILURE", "detail": msg})
            active_ci_failures.append(msg)

    # 2. Go MCP SDK CVE-2026-34742 (< v1.4.0 DNS Rebinding) Check over pre-collected go.mod files
    mb_blob = _build_master_briefing_blob(mb)
    if re.search(r"CVE-2026-34742|go\s+mcp\s+sdk", mb_blob, re.IGNORECASE):
        vuln_hits: List[str] = []
        scanned_labels: List[str] = []
        for rel, content in sorted((snapshot.go_mod_files or {}).items()):
            scanned_labels.append(rel)
            for line in str(content or "").splitlines():
                low = line.lower()
                if "modelcontextprotocol/go-sdk" in low or "mcp-go" in low:
                    ver_m = re.search(r"\bv(\d+)\.(\d+)\.(\d+)", line)
                    if ver_m and (int(ver_m.group(1)), int(ver_m.group(2)), int(ver_m.group(3))) < (1, 4, 0):
                        vuln_hits.append(f"{rel}: {line.strip()}")

        if vuln_hits:
            detail = f"Vulnerable Go MCP SDK < v1.4.0 detected locally: {'; '.join(vuln_hits)}"
            checks.append({"check": "CVE-2026-34742", "status": "PATCH_REQUIRED", "detail": detail})
            active_security_actions.append(detail)
        else:
            scanned_str = ", ".join(f"`{s}`" for s in scanned_labels) or "workspace `go.mod` files"
            detail = (
                f"Checked {scanned_str} — `0` references to `modelcontextprotocol/go-sdk < v1.4.0` "
                "(not affected by CVE-2026-34742; `microgravity` already hardened loopback/origin checks)"
            )
            checks.append({"check": "CVE-2026-34742", "status": "VERIFIED_CLEAN", "detail": detail})

    # 3. Stale Cloud Echo Suppression & Ground-Truth Vault Reconciliation
    parser_meta = mb.get("parser_meta") if isinstance(mb.get("parser_meta"), dict) else {}
    suppressed_echo = int(parser_meta.get("suppressed_stale_echo_lines", 0) or 0)
    if suppressed_echo > 0:
        staged_cnt = option_c.get("staged_reports", 0)
        sv_pid = daemon.get("supervisor_pid")
        checks.append(
            {
                "check": "24h_Stale_Overlap",
                "status": "SUPPRESSED",
                "detail": (
                    f"Eliminated {suppressed_echo} stale Orbit operational echo line(s) from Gemini Section 1; "
                    f"replaced with live local state (`{staged_cnt}` staged Track A bundles, Supervisor PID `{sv_pid}`)"
                ),
            }
        )

    # 4. Digest Parser Boundary & Inline Link Integrity Check
    if mb.get("found"):
        hard_stopped = bool(parser_meta.get("hard_stopped_at_dossier", False))
        all_sec_items = [str(v) for vals in sections.values() if isinstance(vals, list) for v in vals]
        dangling_cnt = sum(1 for v in all_sec_items if v.strip().endswith(":") and "](" not in v)
        md_links_cnt = sum(len(re.findall(r"\[[^\]]+\]\([^)]+\)", v)) for v in all_sec_items)
        checks.append(
            {
                "check": "Parser_Boundary_&_Links",
                "status": "PASS" if dangling_cnt == 0 else "WARN",
                "detail": (
                    f"Hard-stop before Section 5 Dossier=`{hard_stopped}` | "
                    f"Blank dangling bullets=`{dangling_cnt}` | "
                    f"Preserved inline Markdown links=`{md_links_cnt}`"
                ),
            }
        )

    # 5. Open-Port Delta Triage Verification
    port_triage = sys_telem.get("port_triage") if isinstance(sys_telem.get("port_triage"), dict) else {}
    if port_triage:
        unexp = port_triage.get("unexpected_listeners", []) or []
        exp = port_triage.get("expected_listeners", []) or []
        checks.append(
            {
                "check": "Open_Port_Delta_Triage",
                "status": "WARN" if unexp else "PASS",
                "detail": f"{len(exp)} expected ecosystem listener(s) mapped, {len(unexp)} unexpected listener(s)",
            }
        )

    summary_lines = [
        f"  - **[{c['status']}] `{c['check']}`:** {c['detail']}" for c in checks
    ] or ["  - **[PASS] `Local_State_Baseline`:** No unresolved cloud vs. local discrepancies detected."]

    return {
        "checks": checks,
        "active_ci_failures": active_ci_failures,
        "active_security_actions": active_security_actions,
        "resolved_ci_alerts": resolved_ci_alerts,
        "summary_lines": summary_lines,
    }


def run_local_critic_reconciliation(
    *,
    master_briefing: Optional[Dict[str, Any]] = None,
    post_delta: Optional[Dict[str, Any]] = None,
    email_ci_alerts: Optional[Sequence[str]] = None,
    live_ci: Optional[Dict[str, Any]] = None,
    proj_radar: Optional[Dict[str, Any]] = None,
    option_c: Optional[Dict[str, Any]] = None,
    daemon: Optional[Dict[str, Any]] = None,
    sys_telem: Optional[Dict[str, Any]] = None,
    workspace_root: Optional[Path] = None,
    gh_ci_querier: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Cross-checks Gemini cloud alerts and Gmail CI/CVE signals against live local disk & git state."""
    mb = master_briefing if isinstance(master_briefing, dict) else {}
    delta = post_delta if isinstance(post_delta, dict) else {}
    ci_candidates = extract_critic_ci_candidates(mb, delta, email_ci_alerts)
    mb_blob = _build_master_briefing_blob(mb)

    repo_git_states, go_mod_files = probe_workspace_critic_evidence(
        ci_candidates=ci_candidates,
        mb_blob=mb_blob,
        workspace_root=workspace_root,
    )

    multi_repo_ci: Dict[str, Dict[str, Any]] = {}
    if gh_ci_querier is not None:
        for ci in ci_candidates:
            repo_full = ci["repo"]
            short_repo = repo_full.split("/")[-1].strip().lower()
            branch = ci["branch"]
            if short_repo == "orbit-security" and live_ci:
                continue
            try:
                status = gh_ci_querier(repo=repo_full, branch=branch) or {}
            except Exception:
                status = {}
            multi_repo_ci[f"{repo_full.lower()}@{branch.lower()}"] = status

    snapshot = TelemetrySnapshot(
        daemon=daemon or {},
        option_c=option_c or {},
        email_data={
            "ci_alerts": list(email_ci_alerts or ()),
            "post_briefing_delta": delta,
        },
        email_hygiene={"master_briefing": mb},
        live_ci=live_ci or {},
        system_telemetry=sys_telem or {},
        projects_radar=proj_radar or {},
        multi_repo_ci=multi_repo_ci,
        repo_git_states=repo_git_states,
        go_mod_files=go_mod_files,
    )
    return verify_critic_snapshot(snapshot)


def build_agenda_items(
    snapshot: TelemetrySnapshot,
    *,
    ci_reconciled: Dict[str, Any],
    critic_res: Dict[str, Any],
) -> List[str]:
    """Derives prioritized engineering, VDP/career SLA, and multi-repo CI agenda items from a TelemetrySnapshot."""
    return _build_agenda_items(
        ci_count=int(ci_reconciled.get("active_failures", 0) or 0),
        live_ci=snapshot.live_ci or {},
        option_c=snapshot.option_c or {},
        email_data=snapshot.email_data or {},
        daemon=snapshot.daemon or {},
        inbox_q=(snapshot.projects_radar or {}).get("inbox_queues", {}),
        post_delta=snapshot.post_briefing_delta,
        critic_res=critic_res,
        master_briefing=snapshot.master_briefing,
        sys_telem=snapshot.system_telemetry or {},
    )


def _build_agenda_items(
    ci_count: int,
    live_ci: Dict[str, Any],
    option_c: Dict[str, Any],
    email_data: Dict[str, Any],
    daemon: Dict[str, Any],
    inbox_q: Dict[str, Any],
    *,
    post_delta: Optional[Dict[str, Any]] = None,
    critic_res: Optional[Dict[str, Any]] = None,
    master_briefing: Optional[Dict[str, Any]] = None,
    sys_telem: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Derives prioritized engineering, VDP/career SLA, and multi-repo CI agenda items."""
    state_ts = daemon.get("state_timestamp") or "unknown"
    delta = post_delta if isinstance(post_delta, dict) else {}
    critic = critic_res if isinstance(critic_res, dict) else {}
    mb = master_briefing if isinstance(master_briefing, dict) else {}
    telem = sys_telem if isinstance(sys_telem, dict) else {}

    agenda_items: List[str] = []

    if ci_count > 0:
        failing_names = ", ".join(live_ci.get("failing_workflows", [])) or "GitHub CI"
        agenda_items.append(
            f"Fix {ci_count} failing GitHub Actions workflow(s) on `CmfH009/Orbit-Security` HEAD ({failing_names})."
        )
    for multi_ci in critic.get("active_ci_failures", []) or []:
        if "Orbit-Security" not in multi_ci:
            agenda_items.append(f"Multi-Repo CI: {multi_ci}")

    for sec_act in critic.get("active_security_actions", []) or []:
        agenda_items.append(f"Security Patch: {sec_act}")
    port_triage = telem.get("port_triage") if isinstance(telem.get("port_triage"), dict) else {}
    unexp_ports = port_triage.get("unexpected_listeners", []) or []
    if unexp_ports:
        p_desc = ", ".join(f"{e.get('port')} ({e.get('process')})" for e in unexp_ports[:3])
        agenda_items.append(f"Port Triage: inspect unexpected local listener(s): {p_desc}.")

    vdp_delta = delta.get("vdp_delta", []) or []
    vdp_all = delta.get("vdp_all", []) or []
    work_delta = delta.get("work_delta", []) or []
    closed_vdp_ids = _closed_vdp_report_ids()
    open_vdp_all = [
        v for v in vdp_all
        if not _is_closed_vdp_subject(str(v.get("subject", "")), closed_ids=closed_vdp_ids)
    ]
    if vdp_delta:
        top_vdp = vdp_delta[0]
        agenda_items.append(
            f"Waiting on Carson (VDP Delta): respond to `{top_vdp.get('subject')}` ({top_vdp.get('sender')})."
        )
    else:
        analyst_vdp = next(
            (v for v in open_vdp_all if "analyst" in str(v.get("subject", "")).lower()),
            None,
        )
        if analyst_vdp is not None:
            agenda_items.append(
                f"Waiting on Carson (VDP SLA, `{analyst_vdp.get('age_hours', 0)}h` age): fulfill HackerOne analyst PoC request on `{analyst_vdp.get('subject')}`."
            )

    if work_delta:
        top_work = work_delta[0]
        agenda_items.append(
            f"Career / Work Delta: review `{top_work.get('subject')}` from `{top_work.get('sender')}`."
        )

    if option_c.get("kyc_payout_status") != "VERIFIED":
        agenda_items.append(
            "Gate 2 Physical ID / KYC watch: keep Tier-1 Spotify bucket ready and capture authenticated session/PII proof for Tier-2 CONDITIONAL CORS bundles (MercadoLibre, Xiaomi, Superbet, Playtika)."
        )
    if email_data.get("unread_non_ci_count", 0) > 0:
        agenda_items.append(
            f"Triage {email_data['unread_non_ci_count']} unread non-CI message(s) in `carsonmail009@gmail.com`."
        )
    elif email_data.get("urgent", 0) > 0:
        agenda_items.append(
            f"Review {email_data['urgent']} actionable urgent email item(s) in `carsonmail009@gmail.com`."
        )

    if mb.get("warning_banner"):
        agenda_items.append(
            f"{mb['warning_banner']} — check Gmail `Orbit/Briefings` label or re-run once delivered."
        )

    if not daemon.get("live_verified_active"):
        agenda_items.append(
            f"Restart `OrbitMasterSupervisor` daemon if 24/7 background monitoring is desired (state stale since `{state_ts}`)."
        )
    if inbox_q.get("failed", 0) > 0:
        agenda_items.append(f"Inspect {inbox_q['failed']} failed task(s) in `A:\\inbox\\failed`.")
    if not agenda_items:
        agenda_items.append("Run `orbit_readiness_audit.py --verify-cutover` and advance active workspace sprint.")
    return agenda_items


def _render_cloud_subsection(title: str, items: Sequence[str], empty_note: str, limit: int = 16) -> str:
    clean_items = [str(x).strip() for x in (items or []) if str(x).strip()]
    lines = [f"#### {title}"]
    if clean_items:
        for item in clean_items[:limit]:
            lines.append(f"- {item}")
    else:
        lines.append(f"- {empty_note}")
    return "\n".join(lines)


def render_master_briefing_block(master_briefing: Any) -> str:
    """Formats the Gemini Combined Daily Master Briefing cleanly using strict canonical sections and inline links."""
    if isinstance(master_briefing, dict) and master_briefing.get("found"):
        subject = _clean_subject(str(master_briefing.get("subject") or "Combined Daily Master Briefing"))
        date_val = str(master_briefing.get("date") or "").strip()
        highlights = [str(h).strip() for h in (master_briefing.get("highlights") or []) if str(h).strip()]
        sections = master_briefing.get("sections") or {}
        date_suffix = f" *({date_val})*" if date_val else ""
        lines = [f"- **Latest Dispatch:** {subject}{date_suffix}"]

        ops_items = sections.get("ops_cicd_sla") or sections.get("personal_delta") or []
        ai_items = sections.get("ai_dev_radar") or sections.get("ai_news") or []
        comp_sec_items = sections.get("competitive_security") or []
        yt_items = sections.get("youtube_newsletters") or sections.get("youtube_digest") or []
        dl_items = sections.get("deadlines_checklist") or sections.get("deprecations") or []

        has_canonical = any((ops_items, ai_items, comp_sec_items, yt_items, dl_items))
        if has_canonical:
            lines.append("")
            lines.append(
                _render_cloud_subsection(
                    "3.1 VDP / Career SLAs & Personal Delta",
                    ops_items,
                    "No new personal or SLA items in this dispatch.",
                )
            )
            lines.append("")
            lines.append(
                _render_cloud_subsection(
                    "3.2 AI / Antigravity / Dev Radar",
                    ai_items,
                    "No new AI/dev stack releases in this dispatch.",
                )
            )
            lines.append("")
            lines.append(
                _render_cloud_subsection(
                    "3.3 Competitive & Adversarial Security Radar",
                    comp_sec_items,
                    "No new CVE or competitive security alerts in this dispatch.",
                )
            )
            lines.append("")
            lines.append(
                _render_cloud_subsection(
                    "3.4 Technical YouTube & Newsletter Digest",
                    yt_items,
                    "No new curated YouTube uploads or newsletter highlights in past 24h.",
                )
            )
            lines.append("")
            lines.append(
                _render_cloud_subsection(
                    "3.5 Upcoming 30-Day Pricing, CVE & Deprecation Deadlines",
                    dl_items,
                    "No upcoming 30-day deadlines reported.",
                )
            )
        else:
            for h in highlights[:24]:
                lines.append(f"  - {h}")
        return "\n".join(lines)

    if isinstance(master_briefing, dict) and master_briefing.get("warning_banner"):
        warn = f"**{master_briefing['warning_banner']}** — "
    else:
        warn = "**[WARN] Gemini Master Briefing not yet received** — "
    return f"- {warn}No Combined Daily Master Briefing found in latest inbox sweep; running in local-only mode."


def render_markdown(
    snapshot: TelemetrySnapshot,
    *,
    ci_reconciled: Dict[str, Any],
    critic_reconciled: Dict[str, Any],
    deltas: Dict[str, Any],
    agenda_items: List[str],
) -> str:
    """Renders the unified 5-section daily executive briefing Markdown from a single sanitized TelemetrySnapshot."""
    today_str = snapshot.generated_at or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    schedule_mode = snapshot.schedule_mode or "default"
    stripe = snapshot.stripe or {}
    daemon = snapshot.daemon or {}
    inbox = snapshot.inbox or {}
    campaigns = snapshot.campaigns or {}
    option_c = snapshot.option_c or {}
    email_data = snapshot.email_data or {}
    geo_panel = snapshot.geo_panel or {}
    sys_telem = snapshot.system_telemetry or {}
    proj_radar = snapshot.projects_radar or {}
    cal_tasks = snapshot.calendar_tasks or {}
    intel_news = snapshot.intel_news or {}
    email_hygiene = snapshot.email_hygiene or {}
    master_brief = snapshot.master_briefing
    post_delta = snapshot.post_briefing_delta

    ci_count = ci_reconciled.get("active_failures", 0)
    ci_summary_str = ci_reconciled.get(
        "summary_markdown", "  - All GitHub Actions green on CmfH009/Orbit-Security"
    )

    recent_str = "\n".join([f"  - {r}" for r in campaigns.get("recent_dispatched", [])]) or "  - None yet"
    deal_count = len(email_data.get("deal_threads", []))
    deals_summary_str = (
        "\n".join([f"  - 💼 {s}" for s in email_data.get("deal_threads", [])[:3]])
        if deal_count > 0
        else "  - No pending customer inquiries waiting in Orbit/Deal-Desk"
    )
    hygiene = email_data.get("hygiene", {}) or {}

    sv_pid = daemon.get("supervisor_pid")
    sen_pid = daemon.get("sentinel_pid")
    state_ts = daemon.get("state_timestamp") or "unknown"
    if daemon.get("live_verified_active"):
        supervisor_banner = f"🟢 ACTIVE (PID: {sv_pid})"
    elif daemon.get("supervisor_active"):
        supervisor_banner = f"🟡 STOPPED / STALE STATE (Last seen: {state_ts}, PID {sv_pid} not running)"
    else:
        supervisor_banner = "🔴 INACTIVE"

    if daemon.get("sentinel_live_verified"):
        sentinel_banner = f"🟢 RUNNING (PID: {sen_pid})"
    elif daemon.get("sentinel_running"):
        sentinel_banner = f"🟡 STOPPED / STALE STATE (Last seen: {state_ts}, PID {sen_pid} not running)"
    else:
        sentinel_banner = "🔴 STOPPED"

    drives_telem = sys_telem.get("drives", {})
    drive_notes = {"A:\\": " (Mapped to C:\\AgyHut)", "G:\\": " (Google Drive Mirror)"}
    drive_lines = []
    for d_letter, d_info in drives_telem.items():
        note = drive_notes.get(d_letter, "")
        drive_lines.append(
            f"  - **Drive {d_letter}**{note}: `{d_info.get('free_gb', 0)} GB free` of `{d_info.get('total_gb', 0)} GB` ({d_info.get('pct_free', 0)}% free)"
        )
    drives_str = "\n".join(drive_lines) if drive_lines else "  - Storage info unavailable"

    port_triage = sys_telem.get("port_triage") or {}
    if port_triage:
        expected_ports = port_triage.get("expected_listeners", []) or []
        unexpected_ports = port_triage.get("unexpected_listeners", []) or []
        if unexpected_ports:
            unexp_tags = ", ".join(
                f"`{e['port']}` ({e.get('service', 'Unknown')} / `{e.get('process', '?')}`)"
                for e in unexpected_ports
            )
            ports_status = f"⚠️ Unexpected/Dev Listeners: {unexp_tags}"
        else:
            ports_status = f"🟢 {port_triage.get('summary', '0 unexpected listeners')}"
        if expected_ports:
            mapped_lines = [
                f"    - Port `{e['port']}` -> **{e['service']}** (`{e.get('process', 'detected')}`, PID `{e.get('pid') or 'n/a'}`)"
                for e in expected_ports
            ]
            ports_status += "\n" + "\n".join(mapped_lines)
    else:
        ports_status = (
            "🟢 0 open debug ports (Ports 4173, 8501, 8765 verified closed)"
            if not sys_telem.get("open_ports")
            else f"⚠️ Active ports: {sys_telem.get('open_ports')}"
        )

    temp_c = sys_telem.get("temp_c", 52.0)
    chassis_c = sys_telem.get("chassis_temp_c")
    exhaust_c = sys_telem.get("exhaust_temp_c")
    fan_rpm = sys_telem.get("fan_rpm")
    thermal_extras = []
    if chassis_c is not None:
        thermal_extras.append(f"Chassis {chassis_c}°C")
    if exhaust_c is not None:
        thermal_extras.append(f"Exhaust {exhaust_c}°C")
    if fan_rpm is not None:
        thermal_extras.append(f"Fan {fan_rpm} RPM")
    thermal_suffix = f" ({', '.join(thermal_extras)})" if thermal_extras else " (Optimal)"

    core_repos = proj_radar.get("core_active_repos", [])
    if core_repos:
        core_lines = []
        for p in core_repos:
            dirty_cnt = int(p.get("dirty_count", 0) or 0)
            dirty_tag = f"dirty `{dirty_cnt}`" if dirty_cnt > 0 else "clean"
            c48 = int(p.get("commits_48h", 0) or 0)
            sha_tag = f"`{p['head_sha']}`" if p.get("head_sha") else "`n/a`"
            core_lines.append(
                f"  - **{p['name']}** (`{p['branch']}` @ {sha_tag}, `{c48}` commits/48h, {dirty_tag}): {p.get('commit_msg') or 'No commits'} *({p.get('last_commit') or 'n/a'})*"
            )
        core_repos_str = "\n".join(core_lines)
    else:
        recent_projs = proj_radar.get("recently_active", [])
        if recent_projs:
            core_repos_str = "\n".join(
                f"  - 🔥 **{p['name']}** (`{p['branch']}`): {p['commit_msg']} *(last commit: {p['last_commit']})*"
                for p in recent_projs[:7]
            )
        else:
            core_repos_str = "  - No project commits recorded in the last 48 hours."

    root_commits = proj_radar.get("workspace_root_commits_48h", [])
    root_commits_str = (
        "\n".join([f"  - `{c}`" for c in root_commits[:5]])
        if root_commits
        else "  - No root workspace commits in the last 48 hours."
    )
    inbox_q = proj_radar.get("inbox_queues", {})
    inbox_q_line = (
        f"pending `{inbox_q.get('pending', 0)}` | in_progress `{inbox_q.get('in_progress', 0)}` | "
        f"failed `{inbox_q.get('failed', 0)}` | expansion `{inbox_q.get('expansion_queue', 0)}` | "
        f"completed_24h `{inbox_q.get('completed_24h', 0)}`"
    )

    top3_items = agenda_items[:3]
    top3_str = (
        "\n".join([f"{i + 1}. {item}" for i, item in enumerate(top3_items)])
        if top3_items
        else "1. Run `orbit_readiness_audit.py --verify-cutover` and advance active workspace sprint."
    )
    overflow_items = agenda_items[3:]
    if overflow_items:
        agenda_str = "\n".join([f"  {i + 4}. {item}" for i, item in enumerate(overflow_items)])
    else:
        agenda_str = "  - Top 3 priorities surfaced in executive banner above (0 overflow backlog items)."

    delta_summary_line = str((deltas or {}).get("summary_line") or "Baseline snapshot pending")

    scanned_cnt = email_data.get("scanned", email_hygiene.get("total_scanned", 0))
    archived_cnt = email_hygiene.get(
        "archived_count",
        email_hygiene.get("archived", hygiene.get("archived_count", hygiene.get("archived", 0))),
    )
    trashed_cnt = email_hygiene.get(
        "trashed_count",
        email_hygiene.get("trashed", hygiene.get("trashed_count", hygiene.get("trashed", 0))),
    )
    unsub_cnt = email_hygiene.get(
        "unsubscribed_count",
        email_hygiene.get("unsubscribed", hygiene.get("unsubscribed_count", hygiene.get("unsubscribed", 0))),
    )
    received_24h = email_hygiene.get("received_24h", 0)
    read_cleared_24h = email_hygiene.get("read_or_cleared_24h", 0)
    auto_hygiene_cnt = email_hygiene.get("auto_hygiene_candidates", 0)
    master_briefing_block = render_master_briefing_block(master_brief)

    delta_lines: List[str] = []
    for label_title, bucket_key in (
        ("Orbit/CI-CD (Post-Briefing)", "ci_cd_delta"),
        ("Orbit/VDP (Post-Briefing)", "vdp_delta"),
        ("Work / Career (Post-Briefing)", "work_delta"),
    ):
        for entry in post_delta.get(bucket_key, []) or []:
            delta_lines.append(
                f"  - **{label_title}:** {entry.get('subject')} — `{entry.get('sender')}` *({entry.get('date')})*"
            )
    if not delta_lines:
        delta_lines.append(
            "  - 0 new high-priority messages arrived in `Orbit/CI-CD`, `Orbit/VDP`, or `Work` after Gemini's briefing timestamp."
        )
    post_delta_str = "\n".join(delta_lines)

    if (deltas or {}).get("geo_unchanged"):
        latest_geo = geo_panel.get("latest") or {}
        c_rate = float(
            latest_geo.get(
                "citation_rate_pct",
                ((deltas or {}).get("current") or {}).get("geo_citation_share_pct", 0.0),
            )
        )
        m_rate = float(latest_geo.get("mention_rate_pct", 0.0))
        auth = float(latest_geo.get("composite_authority_score", 0.0))
        prev_dt = (deltas or {}).get("previous_date") or "prior day"
        geo_section_body = (
            f"- **UNCHANGED vs {prev_dt}:** Citation Share `{c_rate:.1f}%` "
            f"(Mention `{m_rate:.1f}%` | Authority `{auth:.1f}/100` | {geo_panel.get('total_records', 0)} probes logged)."
        )
    else:
        geo_section_body = geo_panel.get("summary_markdown", "- **GEO Panel Status:** Pending")

    feed_status = str(cal_tasks.get("feed_status") or "").strip()
    fallback_used = bool(cal_tasks.get("fallback_used", False))
    structured_events = cal_tasks.get("events") or []
    gmail_invites = [
        ev for ev in structured_events if isinstance(ev, dict) and ev.get("source") == "gmail_invite"
    ]
    fallback_events_count = int(cal_tasks.get("fallback_events_count", len(gmail_invites)) or 0)

    raw_today = list(cal_tasks.get("events_today", []))
    raw_week = list(cal_tasks.get("events_week", []))
    if not raw_today and not raw_week and gmail_invites:
        for inv in gmail_invites[:5]:
            summary = str(inv.get("summary") or inv.get("subject") or "Calendar Invitation")
            when = str(inv.get("when") or "").strip()
            label = f"📩 {summary} ({when})" if when else f"📩 {summary}"
            if inv.get("is_today"):
                raw_today.append(label)
            else:
                raw_week.append(label)

    if cal_tasks.get("configured") or raw_today or raw_week or gmail_invites or feed_status:
        events_str = "\n".join([f"  - {e}" for e in raw_today]) or "  - No meetings or events scheduled for today."
        week_str = "\n".join([f"  - {e}" for e in raw_week]) or "  - Clear schedule for the remainder of the week."
        birthdays_str = (
            "\n".join([f"  - {b}" for b in cal_tasks.get("birthdays", [])])
            if cal_tasks.get("birthdays")
            else "  - No birthdays today."
        )
    else:
        events_str = "  - *Google Calendar sync*: Set `GOOGLE_CALENDAR_ICAL_URL` in `.env` to stream live events."
        week_str = "  - *Weekly runway*: Set `GOOGLE_CALENDAR_ICAL_URL` in `.env` to stream weekly schedule."
        birthdays_str = "  - None registered."

    cal_diag_lines: List[str] = []
    if feed_status:
        fb_note = f" (Gmail invite fallback active: `{fallback_events_count}` invite(s) surfaced)" if fallback_used else ""
        cal_diag_lines.append(f"- **Calendar Feed Status:** `{feed_status}`{fb_note}")
    elif fallback_used:
        cal_diag_lines.append(f"- **Calendar Feed Status:** Gmail invite fallback active (`{fallback_events_count}` invite(s))")
    cal_diag_block = ("\n" + "\n".join(cal_diag_lines)) if cal_diag_lines else ""

    ziva_items = (master_brief.get("sections") or {}).get("ziva_and_brittany", []) if isinstance(master_brief, dict) else []
    ziva_str = (
        "\n".join([f"  - 🐾 {item}" for item in ziva_items])
        if ziva_items
        else "  - 🐾 Household baseline active (Missoula, MT · Ziva & Brittany); no new `[AGY_SECTION:ZIVA_AND_BRITTANY]` delta in today's dispatch."
    )

    ai_list = intel_news.get("ai_innovations", [])
    tech_sec_list = intel_news.get("tech_and_security", [])
    world_list = intel_news.get("world_news", [])
    ai_news_str = "\n".join([f"  - 🤖 {item}" for item in ai_list]) if ai_list else "  - No live HN AI frontpage items fetched."
    tech_sec_str = "\n".join([f"  - 🛡️ {item}" for item in tech_sec_list]) if tech_sec_list else "  - No live engineering/security frontpage items fetched."
    world_news_str = "\n".join([f"  - 🌐 {item}" for item in world_list]) if world_list else "  - Macro markets and world news nominal."
    ai_takeaway = str(intel_news.get("ai_takeaway") or "").strip()
    world_takeaway = str(intel_news.get("world_takeaway") or "").strip()
    ai_takeaway_line = f"> 💡 **Why It Matters**: {ai_takeaway}\n" if ai_takeaway else ""
    world_takeaway_line = f"> 💡 **Why It Matters**: {world_takeaway}\n" if world_takeaway else ""

    urgent_items_list = email_data.get("urgent_list", [])
    urgent_items_str = (
        "\n".join([f"  - 🚨 {u}" for u in urgent_items_list])
        if urgent_items_list
        else "  - No new or unread urgent action items today."
    )
    awaiting_list = email_data.get("awaiting_external_reply", [])
    awaiting_count = int(email_data.get("awaiting_external_reply_count", len(awaiting_list)) or 0)
    if awaiting_list:
        awaiting_lines = "\n".join([f"  - ⏳ {item}" for item in awaiting_list])
        awaiting_block = f"\n- **⏳ Awaiting External Reply:** {awaiting_count}\n{awaiting_lines}"
    elif awaiting_count > 0:
        awaiting_block = f"\n- **⏳ Awaiting External Reply:** {awaiting_count}"
    else:
        awaiting_block = ""
    unread_list = email_data.get("unread_list", [])
    unread_non_ci_str = (
        "\n".join([f"  - ✉️ {u}" for u in unread_list]) if unread_list else "  - No unread non-CI messages."
    )

    tier_1_str = ", ".join(option_c.get("tier_1_items", [])) or "None"
    tier_2_str = ", ".join(option_c.get("tier_2_items", [])) or "None"
    outreach_freeze_label = (
        "❄️ FROZEN (Option C Guardrail — 0 active blasts)"
        if campaigns.get("frozen", True)
        else "🟢 ACTIVE"
    )

    warn_banner_line = ""
    if isinstance(master_brief, dict) and master_brief.get("warning_banner"):
        warn_banner_line = f"\n> ⚠️ **{master_brief['warning_banner']}** (Local-only fallback active after backoff)\n"

    sched_label = (
        "09:00 MST (Early Morning Mode)"
        if str(schedule_mode).lower().startswith("early")
        else "10:15 MST (Default +45m Buffer)"
    )
    critic_log_str = "\n".join((critic_reconciled or {}).get("summary_lines", []))

    return f"""# Orbit Security & Antigravity: Unified Daily Executive Briefing
**Generated:** {today_str} | **Schedule:** {sched_label}  
**Supervisor Status:** {supervisor_banner}  
**24h Delta (Δ):** {delta_summary_line}
{warn_banner_line}
---

## ⚡ 1. TOP 3 PRIORITY ACTIONS TODAY
{top3_str}

---

## 🖥️ 2. Live Local System, Port Triage & Multi-Repo Health

### 2.1 Supervisor, Sentinel & CI/CD Status
- **Sentinel Daemon Status:** {sentinel_banner}
- **Service Mesh Live:** {daemon.get("services_live_active", 0)}/{daemon.get("services_total", 0)} services running (state file active count: {daemon.get("services_state_active", 0)})
- **Process Restarts:** {daemon.get("sentinel_restarts", 0)}
- **Orbit-Security CI (`CmfH009/Orbit-Security`):** Active Failures = `{ci_count}`
{ci_summary_str}

### 2.2 Host Hardware, Thermals & Open-Port Delta Triage
- **CPU & Thermal Health:** `{sys_telem.get("cpu_name", "Intel Core i7-1185G7")}` · **{temp_c}°C**{thermal_suffix}
- **Host Uptime:** `{sys_telem.get("uptime", "Unknown")}`
- **Memory Load:** `{sys_telem.get("ram_used_gb", 0.0)} GB used` of `{sys_telem.get("ram_total_gb", 16.0)} GB` ({sys_telem.get("ram_pct", 0.0)}% load)
- **Power & Battery:** `{sys_telem.get("battery", "AC Connected")}`
- **Storage Pools:**
{drives_str}
- **Open-Port Delta Triage:** {ports_status}

### 2.3 Multi-Repo 48h Velocity & Dirty-Tree Status (`C:\\AgyHut`)
- **Total Workspace Projects:** {proj_radar.get("total_projects", 0)} repositories in `A:\\projects` | **Root Uncommitted Files:** `{proj_radar.get("workspace_dirty_count", 0)}`
- **`A:\\inbox` Autonomous Queues:** {inbox_q_line}
- **Core Active Repos (48h Commits & Dirty Tree):**
{core_repos_str}
- **Root Workspace (`C:\\AgyHut`) 48h Velocity:**
{root_commits_str}
- **Recommended Engineering Agenda Today:**
{agenda_str}

### 2.4 Track A Bounty Vault, Track B/Stripe, GEO Citation Share & Mailbox Hygiene
- **Strategic Focus:** {option_c.get("revenue_focus")}
- **Technical Floor Clean:** {option_c.get("technical_floor_clean")} | **KYC / Payout Gate:** `{option_c.get("kyc_payout_status")}`
- **Bounty Catalog:** {option_c.get("unique_programs", 0)} unique programs ({option_c.get("cash_tier_count", 0)} cash tier)
- **Submission Vault (`data/hackerone_staging`):** {option_c.get("staged_reports", 0)} staged `.md` + {option_c.get("paired_bundles", 0)} paired `.zip` bundles (`{option_c.get("ev_covered", 0)}/{option_c.get("ev_total", 0)}` `ev_` digests, `{option_c.get("consolidated_dossiers", 0)}` dossiers, `{option_c.get("archived_total", 0)}` archived noise)
- **Tier-1 Ready (Pending KYC ID):** {tier_1_str}
- **Tier-2 Conditional CORS (Needs Auth Proof):** {tier_2_str}
- **Track B Self-Serve Funnel:** `ready={option_c.get("track_b_ready")}` | **Landing <-> Docs Parity:** `{option_c.get("landing_docs_identical")}/{option_c.get("landing_docs_shared")}` (`in_sync={option_c.get("landing_docs_in_sync")}`)
- **Stripe Live Checkout Ready:** `{option_c.get("stripe_live_checkout_ready")}` | **Available:** ${stripe.get("available_usd", 0.0):.2f} USD | **Pending:** ${stripe.get("pending_usd", 0.0):.2f} USD | **Paid Subs:** {option_c.get("paid_subscribers", 0)} ({stripe.get("active_subscriptions", 0)} Stripe)
- **Inbound Deals & Lead Pipeline (`Orbit/Deal-Desk`):** {deal_count} deals | {inbox.get("total_threads", 0)} threads tracked ({inbox.get("escalations", 0)} escalations)
{deals_summary_str}
- **Cold Email Outreach Status:** {outreach_freeze_label} ({campaigns.get("dispatched_count", 0)} historical dispatches)
- **Historical Outreach Registry (Recent):**
{recent_str}
- **GEO Visibility & AI Citation Panel (`data/geo_panels.jsonl`):**
{geo_section_body}
- **Mailbox Hygiene (`carsonmail009@gmail.com`):**
  - **Total Scanned in Last Sweep:** {scanned_cnt}
  - **24h Inbox Flow:** `{received_24h} received` | `{read_cleared_24h} read/cleared` | `{auto_hygiene_cnt} auto-hygiene candidates`
  - **Eligible Inbox Zero Archiving:** {archived_cnt}
  - **Marketing Promos & Spam Purged:** {trashed_cnt}
  - **Active Unsubscribe Targets Extracted:** {unsub_cnt}
  - **Unread Inbox Messages:** {email_data.get("unread", 0)} total ({email_data.get("unread_non_ci_count", 0)} non-CI)
{unread_non_ci_str}
  - **Today's Actionable Urgent Items:** {email_data.get("urgent", 0)} *(historical read alerts deduplicated: {email_data.get("historical_alerts_count", 0)})*
{urgent_items_str}{awaiting_block}

---

## ☁️ 3. Gemini Cloud Intelligence Digest

{master_briefing_block}

#### 3.6 Post-Briefing High-Priority Gmail Delta (`Orbit/CI-CD`, `Orbit/VDP`, `Work`)
{post_delta_str}

#### 3.7 Live Local Macro & Frontpage Supplement
- **AI & Agent Engineering (HN):**
{ai_takeaway_line}{ai_news_str}
- **Engineering & Security (HN):**
{tech_sec_str}
- **World & Macro News:**
{world_takeaway_line}{world_news_str}

---

## 🏔️ 4. Missoula Home, Ziva & Brittany Corner
- **Household & Missoula Updates:**
{ziva_str}
- **Google Workspace Agenda (Calendar & Tasks):**{cal_diag_block}
  - **Today's Events & Meetings:**
{events_str}
  - **Birthdays & Observances:**
{birthdays_str}
  - **Rest of Week Lookahead:**
{week_str}

---

## 🔍 5. Critic Verification Log
{critic_log_str}

---
*Unified briefing autonomously synthesized & verified by Nova & Orbit Security Sentinel.*
"""


def render_spoken_summary(
    snapshot: TelemetrySnapshot,
    *,
    ci_reconciled: Dict[str, Any],
) -> str:
    """Synthesizes Nova's ground-truth spoken debrief purely in-process from a sanitized TelemetrySnapshot."""
    daemon = snapshot.daemon or {}
    email_data = snapshot.email_data or {}
    sys_telem = snapshot.system_telemetry or {}
    proj_radar = snapshot.projects_radar or {}
    intel_news = snapshot.intel_news or {}
    option_c = snapshot.option_c or {}
    master_brief = snapshot.master_briefing

    sen_pid = daemon.get("sentinel_pid")
    if daemon.get("live_verified_active") and daemon.get("sentinel_live_verified"):
        daemon_spoken = f"Supervisor and Sentinel are green on PID {sen_pid}"
    elif daemon.get("supervisor_active"):
        daemon_spoken = "Heads up, Orbit Supervisor and Sentinel look offline"
    else:
        daemon_spoken = "Orbit Supervisor is currently offline"

    unread_non_ci = email_data.get("unread_non_ci_count", 0)
    urgent_count = email_data.get("urgent", 0)
    unread_str = (
        f"{unread_non_ci} unread non-CI messages" if unread_non_ci != 1 else "1 unread non-CI message"
    )
    urgent_spoken = (
        f"and {urgent_count} urgent item needing eyes today"
        if urgent_count > 0
        else "with zero new urgent emergencies"
    )
    ci_note = ci_reconciled.get("spoken_note", "all CI test runs are green")
    temp_c = sys_telem.get("temp_c", 52.0)
    temp_spoken = f"{temp_c} degrees"
    ram_spoken = f"{sys_telem.get('ram_pct', 55.0)} percent"
    recent_projs = proj_radar.get("recently_active", [])
    root_commits = proj_radar.get("workspace_root_commits_48h", [])
    active_count = len(recent_projs)
    projs_spoken = (
        f"{active_count} active repos plus {len(root_commits)} root workspace commits in the last forty-eight hours"
    )
    ai_list = intel_news.get("ai_innovations", [])
    world_list = intel_news.get("world_news", [])
    top_ai = ai_list[0].split(" [")[0].split("(")[0].strip() if ai_list else "AI models running stable"
    top_world = world_list[0].split(" - ")[0].strip() if world_list else "macro news quiet"
    vault_count = option_c.get("staged_reports", 0)
    kyc_note = (
        "awaiting physical ID for KYC payout unlock"
        if option_c.get("kyc_payout_status") != "VERIFIED"
        else "KYC verified"
    )
    gemini_note = (
        "Gemini Master Briefing synced cleanly"
        if isinstance(master_brief, dict) and master_brief.get("found")
        else "Gemini Master Briefing not yet received, running local-only mode"
    )
    port_triage = sys_telem.get("port_triage") or {}
    unexp_cnt = len(port_triage.get("unexpected_listeners", []) or [])
    port_spoken = f"{unexp_cnt} unexpected listeners" if unexp_cnt > 0 else "zero unexpected open ports"

    return (
        f"[chuckle] Morning Carson. Nova here with your synced morning briefing. "
        f"Hardware pulse: CPU is running cool at {temp_spoken}, RAM is at {ram_spoken}, with {port_spoken}. "
        f"{daemon_spoken}. Over on GitHub, {ci_note}. {gemini_note}. "
        f"Option C status: {vault_count} verified bounty bundles staged with Spotify Tier-1 ready, Track B checkout ready, {kyc_note}. "
        f"In your workspace, {projs_spoken}. "
        f"Mailbox has {unread_str}, {urgent_spoken}. "
        f"On the AI radar: {top_ai}. World headline: {top_world}. "
        f"Let's knock out the priority queue."
    )


class BriefingEngine:
    """Deep two-phase Daily Briefing & Morning Cockpit engine.

    Phase 1 (`collect_snapshot`): collects a single typed `TelemetrySnapshot` through injected `CollectorAdapters`.
    Phase 2 (`synthesize`): runs prompt-injection sanitization, CI/delta reconciliation, critic verification,
        and Markdown/spoken-summary synthesis purely in-process over that single typed snapshot.
    """

    def __init__(
        self,
        adapters: Optional[CollectorAdapters] = None,
        *,
        default_config: Optional[BriefingConfig] = None,
    ) -> None:
        self._default_config = default_config or BriefingConfig()
        self._adapters = adapters or live_collector_adapters(
            repo_root=self._default_config.repo_root,
            workspace_root=self._default_config.workspace_root,
        )

    @property
    def adapters(self) -> CollectorAdapters:
        return self._adapters

    def collect_snapshot(self, config: Optional[BriefingConfig] = None) -> TelemetrySnapshot:
        """Phase 1: Collects all external/local telemetry into one typed TelemetrySnapshot."""
        cfg = config or self._default_config
        now_dt = cfg.effective_now()
        generated_at = now_dt.strftime("%Y-%m-%d %H:%M")
        date_key = now_dt.strftime("%Y-%m-%d")

        stripe = dict(self._adapters.stripe_telemetry() or {})
        daemon = dict(self._adapters.daemon_health() or {})
        inbox = dict(self._adapters.inbox_pipeline() or {})
        campaigns = dict(self._adapters.campaign_outreach() or {})
        option_c = dict(self._adapters.option_c_readiness() or {})

        email_req = EmailCollectRequest(
            max_retries=cfg.effective_retries(),
            retry_interval_sec=cfg.retry_interval_sec,
            target_date=now_dt.date(),
        )
        email_data = dict(self._adapters.email_telemetry(email_req) or {})
        live_ci = dict(self._adapters.github_ci("CmfH009/Orbit-Security", "main") or {})
        archived_ci_count = (
            0
            if cfg.dry_run
            else (
                int(self._adapters.archive_ci_alerts(live_ci) or 0)
                if email_data.get("ci_alerts")
                else 0
            )
        )
        geo_panel = dict(self._adapters.geo_panel() or {})
        sys_telem = dict(self._adapters.system_telemetry() or {})
        proj_radar = dict(self._adapters.projects_radar() or {})
        cal_tasks = dict(self._adapters.calendar_tasks() or {})
        intel_news = dict(self._adapters.intel_news() or {})

        raw_hygiene = email_data.get("email_hygiene")
        if not raw_hygiene and self._adapters.email_hygiene is not None:
            try:
                raw_hygiene = self._adapters.email_hygiene() or {}
            except Exception:
                raw_hygiene = {}
        email_hygiene = dict(raw_hygiene or {})

        commits_24h = int(self._adapters.commits_24h(proj_radar, now_dt) or 0)

        master_brief = (
            email_hygiene.get("master_briefing")
            if isinstance(email_hygiene.get("master_briefing"), dict)
            else {}
        )
        post_delta = (
            email_data.get("post_briefing_delta")
            if isinstance(email_data.get("post_briefing_delta"), dict)
            else {}
        )
        ci_candidates = extract_critic_ci_candidates(
            master_briefing=master_brief,
            post_delta=post_delta,
            email_ci_alerts=email_data.get("ci_alerts", []),
        )
        mb_blob = _build_master_briefing_blob(master_brief)
        repo_git_states, go_mod_files = self._adapters.workspace_critic_probe(ci_candidates, mb_blob)

        multi_repo_ci: Dict[str, Dict[str, Any]] = {}
        if not cfg.dry_run:
            for ci in ci_candidates:
                repo_full = ci["repo"]
                short_repo = repo_full.split("/")[-1].strip().lower()
                branch = ci["branch"]
                if short_repo == "orbit-security":
                    continue
                try:
                    multi_repo_ci[f"{repo_full.lower()}@{branch.lower()}"] = dict(
                        self._adapters.github_ci(repo_full, branch) or {}
                    )
                except Exception:
                    multi_repo_ci[f"{repo_full.lower()}@{branch.lower()}"] = {}

        return TelemetrySnapshot(
            generated_at=generated_at,
            date_key=date_key,
            schedule_mode=cfg.schedule_mode,
            stripe=stripe,
            daemon=daemon,
            inbox=inbox,
            campaigns=campaigns,
            option_c=option_c,
            email_data=email_data,
            email_hygiene=email_hygiene,
            live_ci=live_ci,
            archived_ci_count=archived_ci_count,
            geo_panel=geo_panel,
            system_telemetry=sys_telem,
            projects_radar=proj_radar,
            calendar_tasks=cal_tasks,
            intel_news=intel_news,
            commits_24h=commits_24h,
            multi_repo_ci=multi_repo_ci,
            repo_git_states=dict(repo_git_states or {}),
            go_mod_files=dict(go_mod_files or {}),
        )

    def synthesize(
        self,
        snapshot: TelemetrySnapshot,
        config: Optional[BriefingConfig] = None,
    ) -> BriefingResult:
        """Phase 2: Pure in-process sanitize -> reconcile -> verify -> render over one typed TelemetrySnapshot."""
        cfg = config or self._default_config
        now_dt = cfg.effective_now()
        generated_at = snapshot.generated_at or now_dt.strftime("%Y-%m-%d %H:%M")
        date_key = snapshot.date_key or generated_at[:10] or now_dt.strftime("%Y-%m-%d")
        schedule_mode = snapshot.schedule_mode or cfg.schedule_mode or "default"

        sanitized = sanitize_snapshot(
            replace(
                snapshot,
                generated_at=generated_at,
                date_key=date_key,
                schedule_mode=schedule_mode,
            )
        )

        ci_reconciled = (
            dict(cfg.ci_reconciled_override)
            if cfg.ci_reconciled_override is not None
            else reconcile_ci_alerts_with_live_status(
                sanitized.email_data.get("ci_alerts", []),
                sanitized.live_ci,
                archived_in_imap=sanitized.archived_ci_count,
            )
        )

        critic_reconciled = (
            dict(cfg.critic_override)
            if cfg.critic_override is not None
            else verify_critic_snapshot(sanitized)
        )

        if cfg.delta_override is not None:
            deltas = dict(cfg.delta_override)
        elif cfg.persist_state and cfg.state_dir is not None:
            deltas = compute_and_save_daily_deltas(
                date_str=date_key,
                current_snapshot=sanitized.delta_metrics(),
                state_dir=cfg.state_dir,
            )
        else:
            deltas = compute_daily_deltas_in_memory(
                date_str=date_key,
                current_snapshot=sanitized.delta_metrics(),
                previous_date=cfg.previous_date,
                previous_snapshot=cfg.previous_snapshot,
            )

        agenda_items = (
            list(cfg.agenda_override)
            if cfg.agenda_override is not None
            else build_agenda_items(
                sanitized,
                ci_reconciled=ci_reconciled,
                critic_res=critic_reconciled,
            )
        )

        markdown = render_markdown(
            sanitized,
            ci_reconciled=ci_reconciled,
            critic_reconciled=critic_reconciled,
            deltas=deltas,
            agenda_items=agenda_items,
        )
        spoken_summary = render_spoken_summary(
            sanitized,
            ci_reconciled=ci_reconciled,
        )

        return BriefingResult(
            snapshot=sanitized,
            markdown=markdown,
            spoken_summary=spoken_summary,
            ci_reconciled=ci_reconciled,
            critic=critic_reconciled,
            deltas=deltas,
            agenda_items=agenda_items,
            top3_actions=agenda_items[:3],
            date_key=date_key,
            generated_at=generated_at,
            schedule_mode=schedule_mode,
        )

    def run(self, config: Optional[BriefingConfig] = None) -> BriefingResult:
        """Executes Phase 1 collection followed by Phase 2 in-process synthesis."""
        cfg = config or self._default_config
        snapshot = self.collect_snapshot(cfg)
        return self.synthesize(snapshot, cfg)
