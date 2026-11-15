"""Authorized Executive & Brand Handle OSINT runner via local Sherlock v0.16.2 CLI."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Iterable, Optional

HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SITE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$")

DEFAULT_SHERLOCK_PATHS = (
    Path(r"C:\AgyHut\system\tools\sherlock\.venv\Scripts\sherlock.exe"),
    Path(r"C:\AgyHut\bin\sherlock.cmd"),
)


@dataclass(slots=True)
class SherlockMatch:
    """Single discovered public profile from Sherlock OSINT."""

    username: str
    site: str
    url_user: str
    url_main: str = ""
    http_status: Optional[int] = None
    status: str = "Claimed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "site": self.site,
            "url_user": self.url_user,
            "url_main": self.url_main,
            "http_status": self.http_status,
            "status": self.status,
        }


@dataclass(slots=True)
class SherlockSweepResult:
    """Structured result of an authorized Sherlock OSINT sweep."""

    available: bool
    executable: Optional[str]
    usernames: list[str]
    sites_filter: list[str]
    findings: list[SherlockMatch] = field(default_factory=list)
    elapsed_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "executable": self.executable,
            "usernames": self.usernames,
            "sites_filter": self.sites_filter,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "elapsed_ms": round(self.elapsed_ms, 2),
            "errors": self.errors,
        }


def resolve_sherlock_executable() -> Optional[str]:
    """Locate the local Sherlock CLI executable without invoking any browser."""
    on_path = shutil.which("sherlock")
    if on_path:
        return on_path
    for candidate in DEFAULT_SHERLOCK_PATHS:
        if candidate.is_file():
            return str(candidate)
    return None


def _validate_handles(usernames: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for raw in usernames:
        handle = str(raw).strip().lstrip("@")
        if not handle:
            continue
        if not HANDLE_RE.match(handle):
            raise ValueError(f"Invalid handle for Sherlock OSINT: {raw!r}")
        if handle not in cleaned:
            cleaned.append(handle)
    if not cleaned:
        raise ValueError("At least one valid username/handle is required.")
    return cleaned


def _validate_sites(sites: Optional[Iterable[str]]) -> list[str]:
    if not sites:
        return []
    cleaned: list[str] = []
    for raw in sites:
        site = str(raw).strip()
        if not site:
            continue
        if not SITE_RE.match(site):
            raise ValueError(f"Invalid site filter for Sherlock OSINT: {raw!r}")
        if site not in cleaned:
            cleaned.append(site)
    return cleaned


def _parse_sherlock_json(username: str, payload: Any) -> list[SherlockMatch]:
    """Parse Sherlock --json output dictionary into normalized SherlockMatch objects."""
    if not isinstance(payload, dict):
        return []
    matches: list[SherlockMatch] = []
    for site_name, record in payload.items():
        if not isinstance(record, dict):
            continue
        status_raw = record.get("status")
        if isinstance(status_raw, dict):
            status_val = str(status_raw.get("status", "")).strip()
        else:
            status_val = str(status_raw or "").strip()
        url_user = str(record.get("url_user", "")).strip()
        if not status_val or status_val.lower() != "claimed":
            continue
        if not url_user:
            continue
        http_status = record.get("http_status")
        try:
            http_status_int = int(http_status) if http_status is not None else None
        except (TypeError, ValueError):
            http_status_int = None
        matches.append(
            SherlockMatch(
                username=username,
                site=str(site_name),
                url_user=url_user,
                url_main=str(record.get("url_main", "")).strip(),
                http_status=http_status_int,
                status=status_val or "Claimed",
            )
        )
    return matches


def run_sherlock_osint(
    usernames: Iterable[str],
    *,
    sites: Optional[Iterable[str]] = None,
    timeout: int = 15,
    local_only: bool = False,
    output_dir: Optional[Path] = None,
    subprocess_timeout: int = 90,
    executable: Optional[str] = None,
) -> SherlockSweepResult:
    """Run authorized Sherlock OSINT handle discovery with JSON export and strict timeouts."""
    t0 = time.perf_counter()
    handles = _validate_handles(usernames)
    site_list = _validate_sites(sites)
    exe = executable or resolve_sherlock_executable()

    if not exe:
        return SherlockSweepResult(
            available=False,
            executable=None,
            usernames=handles,
            sites_filter=site_list,
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            errors=["Sherlock CLI executable not found on PATH or C:\\AgyHut\\system\\tools\\sherlock"],
        )

    all_findings: list[SherlockMatch] = []
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="orbit_sherlock_") as tmp_dir_str:
        work_dir = Path(output_dir) if output_dir else Path(tmp_dir_str)
        work_dir.mkdir(parents=True, exist_ok=True)

        for handle in handles:
            json_path = work_dir / f"{handle}.sherlock.json"
            cmd = [
                exe,
                handle,
                "--print-found",
                "--timeout",
                str(max(1, int(timeout))),
                "--json",
                str(json_path),
            ]
            if local_only:
                cmd.append("--local")
            for site in site_list:
                cmd.extend(["--site", site])

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=subprocess_timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{handle}: Sherlock timed out after {subprocess_timeout}s")
                continue
            except OSError as exc:
                errors.append(f"{handle}: Failed to invoke Sherlock: {exc}")
                continue

            if proc.returncode != 0 and not json_path.is_file():
                stderr_preview = (proc.stderr or proc.stdout or "").strip()[:300]
                errors.append(f"{handle}: Sherlock exited {proc.returncode}: {stderr_preview}")
                continue

            if json_path.is_file():
                try:
                    data = json.loads(json_path.read_text(encoding="utf-8"))
                    all_findings.extend(_parse_sherlock_json(handle, data))
                except Exception as exc:
                    errors.append(f"{handle}: Failed to parse Sherlock JSON output: {exc}")

    return SherlockSweepResult(
        available=True,
        executable=exe,
        usernames=handles,
        sites_filter=site_list,
        findings=all_findings,
        elapsed_ms=(time.perf_counter() - t0) * 1000.0,
        errors=errors,
    )


def verify_executive_handles(
    handles: Iterable[str],
    *,
    sites: Optional[Iterable[str]] = ("GitHub", "GitLab", "Twitter", "LinkedIn", "Reddit"),
    timeout: int = 12,
    local_only: bool = True,
) -> dict[str, Any]:
    """Convenience wrapper for Orbit Security executive/brand handle footprint checks."""
    res = run_sherlock_osint(
        handles,
        sites=sites,
        timeout=timeout,
        local_only=local_only,
    )
    return res.to_dict()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Orbit Security — Authorized Sherlock OSINT Runner")
    parser.add_argument("usernames", nargs="+", help="Authorized handle(s) or brand name(s) to check")
    parser.add_argument("--site", action="append", dest="sites", default=[], help="Restrict scan to site(s)")
    parser.add_argument("--timeout", type=int, default=15, help="Per-request socket timeout (seconds)")
    parser.add_argument("--local", action="store_true", help="Use bundled Sherlock manifest without remote fetch")
    parser.add_argument("--out-dir", type=Path, default=None, help="Directory to retain per-handle JSON exports")
    args = parser.parse_args(argv)

    result = run_sherlock_osint(
        args.usernames,
        sites=args.sites or None,
        timeout=args.timeout,
        local_only=args.local,
        output_dir=args.out_dir,
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.available else 1


if __name__ == "__main__":
    raise SystemExit(main())
