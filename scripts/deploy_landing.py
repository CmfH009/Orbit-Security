#!/usr/bin/env python3
"""Deploy Orbit Security landing page bundle to AppDeploy MCP endpoint."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.egress_guard import create_guarded_httpx_client  # noqa: E402
from orbit_security.scanner import PublicHostOnlyRoE  # noqa: E402

ENDPOINT = "https://api-v2.appdeploy.ai/mcp"
HTML_PATH = PROJECT_ROOT / "docs" / "index.html"


def _resolve_appdeploy_api_key(project_root: Optional[Path] = None) -> Optional[str]:
    """Resolve APPDEPLOY_API_KEY from environment first, falling back to .env."""
    env_val = (os.environ.get("APPDEPLOY_API_KEY") or "").strip()
    if env_val:
        return env_val

    base_dir = Path(project_root) if project_root is not None else PROJECT_ROOT
    env_file = base_dir / ".env"
    if not env_file.is_file():
        return None

    try:
        content = env_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        if key.strip() != "APPDEPLOY_API_KEY":
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1].strip()
        else:
            val = re.sub(r"\s+#.*$", "", val).strip()
        return val or None

    return None


def deploy(roe_engine: Optional[Any] = None, timeout: float = 60.0) -> dict[str, Any]:
    """Deploy docs/index.html to AppDeploy via RoE-guarded httpx client."""
    api_key = _resolve_appdeploy_api_key()
    if not api_key:
        raise RuntimeError("APPDEPLOY_API_KEY is not configured in environment or .env")

    html_content = HTML_PATH.read_text(encoding="utf-8") if HTML_PATH.is_file() else ""

    tests_json = json.dumps([
        {
            "name": "Landing Page Renders Hero",
            "sanity": True,
            "viewport": "desktop",
            "covers": ["hero_rendering"],
            "description": "Verify headline and hero section load properly",
            "steps": ["Open page", "Check Orbit Security title", "Verify CTA button is visible"],
            "expected": "Hero section is displayed with heading and CTA buttons",
        },
        {
            "name": "Pricing Section Loads",
            "viewport": "mobile",
            "covers": ["pricing_tiers"],
            "description": "Verify $59 Growth plan and Stripe link are visible",
            "steps": ["Scroll to pricing", "Verify $59/mo plan is present", "Check subscribe link"],
            "expected": "Growth plan with Stripe checkout link is clickable",
        },
        {
            "name": "Legal Footer Visible",
            "viewport": "desktop",
            "covers": ["compliance_footer"],
            "description": "Verify operator email and terms are displayed",
            "steps": ["Scroll to footer", "Locate carsonmail009@gmail.com", "Verify copyright"],
            "expected": "Footer shows contact email and legal policies",
        },
    ], indent=2)

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "deploy_app",
            "arguments": {
                "app_id": None,
                "app_type": "frontend-only",
                "app_name": "OrbitSecurity",
                "description": (
                    "Autonomous external perimeter hygiene, subdomain takeover sentinel, "
                    "and white-label client security auditing for web & Shopify agencies."
                ),
                "frontend_template": "html-static",
                "model": "gemini-2.5-pro",
                "intent": "initial app deploy",
                "files": [
                    {
                        "path": "index.html",
                        "content": html_content,
                    },
                    {
                        "path": "tests/tests.json",
                        "content": tests_json,
                    },
                ],
            },
        },
    }

    request_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    roe = roe_engine if roe_engine is not None else PublicHostOnlyRoE()

    print("[*] Deploying Orbit Security landing page to AppDeploy...")
    with create_guarded_httpx_client(roe_engine=roe, timeout=timeout) as client:
        response = client.post(ENDPOINT, headers=request_headers, json=payload)
    print(f"[*] Response status: {response.status_code}")
    res = response.json()
    print(json.dumps(res, indent=2))
    return res


if __name__ == "__main__":
    deploy()
