"""tests/test_ast_sentinel_egress.py: Unit tests for AST Sentinel RoE Egress Rule ROE-EGRESS-001."""

from __future__ import annotations

from pathlib import Path
import pytest

from orbit_security.ast_sentinel import (
    EgressViolation,
    check_file_egress_compliance,
    audit_egress_guard_compliance,
    ASTCodeSentinel,
)


def test_flags_direct_requests_and_httpx_calls(tmp_path: Path) -> None:
    source = """
import requests
import httpx
import socket

def sync_recon():
    r = requests.get("https://example.com/api")
    client = httpx.Client()
    s = socket.socket()
"""
    test_file = tmp_path / "recon_worker.py"
    violations = check_file_egress_compliance(test_file, source)
    symbols = [v.symbol for v in violations]

    assert "requests.get" in symbols
    assert "httpx.Client" in symbols
    assert "socket.socket" in symbols
    assert all(v.rule_id == "ROE-EGRESS-001" for v in violations)


def test_flags_aliased_modules_and_from_imports(tmp_path: Path) -> None:
    source = """
import requests as req
from httpx import AsyncClient, get as hget
from urllib.request import urlopen

async def fetch():
    r1 = req.post("https://target.com/login")
    async with AsyncClient() as client:
        pass
    hget("https://target.com/status")
    res = urlopen("https://target.com/data")
"""
    test_file = tmp_path / "aliased_recon.py"
    violations = check_file_egress_compliance(test_file, source)
    symbols = [v.symbol for v in violations]

    assert "requests.post" in symbols
    assert "httpx.AsyncClient" in symbols
    assert "httpx.get" in symbols
    assert "urllib.request.urlopen" in symbols


def test_allows_centralized_egress_guard_factories(tmp_path: Path) -> None:
    source = """
from orbit_security.egress_guard import (
    create_guarded_httpx_client,
    create_guarded_async_httpx_client,
    create_guarded_requests_session,
)

def run_guarded():
    client = create_guarded_httpx_client(roe_engine=None)
    session = create_guarded_requests_session(roe_engine=None)
"""
    test_file = tmp_path / "safe_consumer.py"
    violations = check_file_egress_compliance(test_file, source)
    assert len(violations) == 0


def test_exempts_egress_guard_module_itself(tmp_path: Path) -> None:
    source = """
import httpx
import requests

def build_raw():
    c = httpx.Client()
    s = requests.Session()
"""
    # Specifically named egress_guard.py is exempt
    exempt_file = tmp_path / "egress_guard.py"
    violations = check_file_egress_compliance(exempt_file, source)
    assert len(violations) == 0


def test_inline_roe_exempt_pragma_only_exempts_annotated_line(tmp_path: Path) -> None:
    source = """
import socket
import requests

def local_probe():
    # Only this local socket is allowed to bypass
    s = socket.socket()  # roe-exempt: local unix domain socket IPC
    # But this requests call lacks the pragma and must be caught
    requests.get("https://out-of-scope.com")
"""
    test_file = tmp_path / "mixed_exemptions.py"
    violations = check_file_egress_compliance(test_file, source)
    assert len(violations) == 1
    assert violations[0].symbol == "requests.get"
    assert violations[0].line == 9


def test_audit_egress_guard_compliance_scans_directory_tree(tmp_path: Path) -> None:
    sub = tmp_path / "subpkg"
    sub.mkdir()

    f1 = sub / "clean.py"
    f1.write_text("x = 1 + 2\n", encoding="utf-8")

    f2 = sub / "dirty.py"
    f2.write_text("import requests\nrequests.get('https://example.com')\n", encoding="utf-8")

    f3 = sub / "egress_guard.py"
    f3.write_text("import requests\nrequests.Session()\n", encoding="utf-8")

    all_violations = audit_egress_guard_compliance(tmp_path.rglob("*.py"))
    assert len(all_violations) == 1
    assert all_violations[0].symbol == "requests.get"
    assert "dirty.py" in all_violations[0].file_path


def test_ast_sentinel_inspect_file_includes_egress_violations(tmp_path: Path) -> None:
    sentinel = ASTCodeSentinel()
    dirty = tmp_path / "dirty.py"
    dirty.write_text("import requests\nrequests.get('https://bad.com')\n", encoding="utf-8")

    res = sentinel.inspect_file(dirty)
    assert "egress_violations" in res
    assert len(res["egress_violations"]) == 1
    assert res["egress_violations"][0].symbol == "requests.get"
