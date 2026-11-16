"""Unit tests for orbit_security.sherlock_osint."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from orbit_security import sherlock_osint as so


def test_resolve_sherlock_executable_finds_local_install() -> None:
    exe = so.resolve_sherlock_executable()
    if exe is None:
        pytest.skip("Sherlock executable is not installed in this environment")
    assert exe is not None
    assert Path(exe).exists()


def test_validate_handles_and_sites_reject_injection() -> None:
    assert so._validate_handles(["@alice_dev", "bob-sec"]) == ["alice_dev", "bob-sec"]
    with pytest.raises(ValueError):
        so._validate_handles(["--browse"])
    with pytest.raises(ValueError):
        so._validate_handles(["   "])
    with pytest.raises(ValueError):
        so._validate_sites(["GitHub;rm -rf /"])


def test_run_sherlock_osint_parses_json_and_never_passes_browse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured_cmds: list[list[str]] = []

    def _fake_run(cmd, **kwargs):
        captured_cmds.append(list(cmd))
        json_idx = cmd.index("--json") + 1
        out_path = Path(cmd[json_idx])
        out_path.write_text(
            json.dumps(
                {
                    "GitHub": {
                        "url_main": "https://github.com/",
                        "url_user": "https://github.com/orbit_exec",
                        "status": {"status": "Claimed"},
                        "http_status": 200,
                    },
                    "GitLab": {
                        "url_main": "https://gitlab.com/",
                        "url_user": "https://gitlab.com/orbit_exec",
                        "status": {"status": "Available"},
                        "http_status": 404,
                    },
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(so.subprocess, "run", _fake_run)

    res = so.run_sherlock_osint(
        ["@orbit_exec"],
        sites=["GitHub", "GitLab"],
        timeout=10,
        local_only=True,
        output_dir=tmp_path,
        executable="sherlock.exe",
    )
    assert res.available is True
    assert res.errors == []
    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "--browse" not in cmd
    assert "--print-found" in cmd
    assert "--local" in cmd
    assert cmd[cmd.index("--timeout") + 1] == "10"

    assert len(res.findings) == 1
    assert res.findings[0].site == "GitHub"
    assert res.findings[0].url_user == "https://github.com/orbit_exec"
    assert res.findings[0].http_status == 200


def test_run_sherlock_osint_handles_timeout_and_missing_exe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _timeout_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="sherlock", timeout=5)

    monkeypatch.setattr(so.subprocess, "run", _timeout_run)
    res_timeout = so.run_sherlock_osint(["alice"], subprocess_timeout=5, executable="sherlock.exe")
    assert res_timeout.available is True
    assert res_timeout.findings == []
    assert any("timed out" in err for err in res_timeout.errors)

    monkeypatch.setattr(so, "resolve_sherlock_executable", lambda: None)
    res_missing = so.run_sherlock_osint(["alice"])
    assert res_missing.available is False
    assert res_missing.findings == []
    assert any("not found" in err for err in res_missing.errors)
