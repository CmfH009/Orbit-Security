import json
import os
import httpx

APPDEPLOY_API_KEY = "ak_548cd73451c0b6ccdf5da82244ddcd2815b0412321a627a1ccf7ef8fc1ea2ca2"
ENDPOINT = "https://api-v2.appdeploy.ai/mcp"

HTML_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "index.html")
if os.path.exists(HTML_PATH):
    with open(HTML_PATH, "r", encoding="utf-8") as f:
        HTML_CONTENT = f.read()
else:
    HTML_CONTENT = ""

headers = {
    "Authorization": f"Bearer {APPDEPLOY_API_KEY}",
    "Content-Type": "application/json"
}


def deploy():
    TESTS_JSON = json.dumps([
        {
            "name": "Landing Page Renders Hero",
            "sanity": True,
            "viewport": "desktop",
            "covers": ["hero_rendering"],
            "description": "Verify headline and hero section load properly",
            "steps": ["Open page", "Check Orbit Security title", "Verify CTA button is visible"],
            "expected": "Hero section is displayed with heading and CTA buttons"
        },
        {
            "name": "Pricing Section Loads",
            "viewport": "mobile",
            "covers": ["pricing_tiers"],
            "description": "Verify $59 Growth plan and Stripe link are visible",
            "steps": ["Scroll to pricing", "Verify $59/mo plan is present", "Check subscribe link"],
            "expected": "Growth plan with Stripe checkout link is clickable"
        },
        {
            "name": "Legal Footer Visible",
            "viewport": "desktop",
            "covers": ["compliance_footer"],
            "description": "Verify operator email and terms are displayed",
            "steps": ["Scroll to footer", "Locate carsonmail009@gmail.com", "Verify copyright"],
            "expected": "Footer shows contact email and legal policies"
        }
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
                "description": "Autonomous external perimeter hygiene, subdomain takeover sentinel, and white-label client security auditing for web & Shopify agencies.",
                "frontend_template": "html-static",
                "model": "gemini-2.5-pro",
                "intent": "initial app deploy",
                "files": [
                    {
                        "path": "index.html",
                        "content": HTML_CONTENT
                    },
                    {
                        "path": "tests/tests.json",
                        "content": TESTS_JSON
                    }
                ]
            }
        }
    }

    print("[*] Deploying Orbit Security landing page to AppDeploy...")
    r = httpx.post(ENDPOINT, headers=headers, json=payload, timeout=60.0)
    print(f"[*] Response status: {r.status_code}")
    res = r.json()
    print(json.dumps(res, indent=2))
    return res


if __name__ == "__main__":
    deploy()
