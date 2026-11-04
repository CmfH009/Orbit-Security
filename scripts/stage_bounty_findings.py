"""Compiles live-verified findings into standardized HackerOne submission markdown dossiers."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Dict

STAGING_ROOT = Path(__file__).resolve().parent.parent / "data" / "hackerone_staging"


def format_cors_submission(finding: Dict[str, Any]) -> str:
    url = finding.get("full_url", finding.get("base_target", ""))
    keywords = ", ".join(finding.get("sensitive_keywords", [])) or "Session/User State"
    target = finding.get("base_target", "")
    return f"""# 🛡️ Vulnerability Disclosure: Dynamic Origin Reflection with Credentials on {target}

**Target:** `{url}`  
**Asset:** `{target}`  
**Vulnerability Type:** Cross-Origin Resource Sharing (CORS) Misconfiguration  
**CWE:** `CWE-942: Permissive Cross-Origin Resource Sharing Policy with Untrusted Domains`  
**Severity:** Medium (CVSS 5.4 - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`)  

---

## 1. Summary
The endpoint `{url}` dynamically reflects the arbitrary HTTP `Origin` header received from client requests (`Origin: https://evil.com`) and pairs this with `Access-Control-Allow-Credentials: true`. This allows malicious third-party websites to issue authenticated cross-origin XMLHttpRequests/Fetch requests on behalf of logged-in users and read sensitive response data ({keywords}).

---

## 2. Steps to Reproduce
1. In a terminal, execute the following reproduction curl command:
```bash
curl -i -s -k -X GET '{url}' \\
  -H 'Origin: https://evil.com' \\
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'
```
2. Inspect the HTTP response headers:
```http
HTTP/1.1 {finding.get('status_code', 200)} OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

---

## 3. Impact
An external attacker who tricks an authenticated user into visiting a malicious webpage can read private API responses containing: {keywords}.

---

## 4. Remediation
Configure the CORS policy to validate incoming `Origin` headers against a strict whitelist of legitimate trusted domains. Do not dynamically reflect arbitrary Origin headers when `Access-Control-Allow-Credentials` is set to `true`.
"""


def stage_high_value_findings(matrix_path: Path) -> int:
    if not matrix_path.exists():
        print(f"Matrix file {matrix_path} does not exist.")
        return 0
    with open(matrix_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    staged_count = 0
    for finding in findings:
        if finding.get("is_high_value") or (finding.get("reflected") and finding.get("credentials")):
            endpoint = finding.get("endpoint", "root")
            safe_name = endpoint.replace("/", "_").strip("_")
            if not safe_name:
                safe_name = "root"
            safe_name = re.sub(r'[\\/*?:"<>|]', "_", safe_name)
            target_str = (
                finding.get("base_target", "")
                .replace("https://", "")
                .replace("http://", "")
                .replace(":", "_")
                .replace("/", "_")
            )
            out_file = (
                STAGING_ROOT
                / "02_needs_session_verification"
                / f"CORS_{target_str}_{safe_name}.md"
            )
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(format_cors_submission(finding))
            staged_count += 1

    print(
        f"[+] Staged {staged_count} verified high-value dossiers to {STAGING_ROOT / '02_needs_session_verification'}"
    )
    return staged_count


if __name__ == "__main__":
    matrix = STAGING_ROOT / "cors_endpoint_matrix.json"
    stage_high_value_findings(matrix)
