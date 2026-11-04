"""
verify_bounty_impact.py
Active verification and ranking tool for candidate CORS and Bucket endpoints.
Tests CORS origin reflection, credentials allowance, and response body characteristics.
"""
import requests
import json
from pathlib import Path
from typing import Dict, Any

CANDIDATES = [
    {"program": "MercadoLibre", "host": "buyingflow.mercadolibre.com.co", "proto": "https"},
    {"program": "MercadoLibre", "host": "buyingflow.mercadolibre.com.mx", "proto": "https"},
    {"program": "MercadoLibre", "host": "buyingflow.mercadolibre.com.pe", "proto": "https"},
    {"program": "MercadoLibre", "host": "images.mercadolibre.com.co", "proto": "https"},
    {"program": "MercadoLibre", "host": "lhstage.mercadolibre.com.ar", "proto": "https"},
    {"program": "MercadoLibre", "host": "realtime-test.mercadolibre.com.mx", "proto": "https"},
    {"program": "MercadoLibre", "host": "test-vendedores.mercadolibre.cl", "proto": "https"},
    {"program": "MercadoLibre", "host": "test-vendedores.mercadolibre.com.co", "proto": "https"},
    {"program": "MercadoLibre", "host": "tucarro.com.co", "proto": "https"},
    {"program": "Playtika", "host": "slotomania.com", "proto": "https"},
    {"program": "Spotify", "host": "cdn.byspotify.com", "proto": "https"},
    {"program": "Superbet", "host": "apps.stage.napoleoncasino.be", "proto": "https"},
    {"program": "Superbet", "host": "apps.stage.napoleonsports.be", "proto": "https"},
    {"program": "Uber", "host": "fpbi8c1t.ubereats.com", "proto": "https"},
    {"program": "Uber", "host": "fpfcpn2u.ubereats.com", "proto": "https"},
    {"program": "Xiaomi", "host": "airstarfinance.net", "proto": "https"},
    {"program": "Xiaomi", "host": "www.airstarfinance.net", "proto": "https"},
    {"program": "Xiaomi", "host": "mijiayoupin.com", "proto": "https"},
    {"program": "Xiaomi", "host": "xiaomiyoupin.com", "proto": "https"},
    {"program": "Xiaomi", "host": "youpin.cn", "proto": "https"},
    {"program": "Xiaomi", "host": "wali.com", "proto": "https"},
]

def probe_target(item: Dict[str, str]) -> Dict[str, Any]:
    url = f"{item['proto']}://{item['host']}/"
    headers = {
        "Origin": "https://evil.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
    }
    result = {
        "program": item["program"],
        "host": item["host"],
        "url": url,
        "status": "ERROR",
        "code": None,
        "cors_origin": None,
        "cors_credentials": None,
        "reflected": False,
        "body_len": 0,
        "content_type": None,
        "verdict": "FAIL",
        "score": 0,
        "notes": "",
    }
    try:
        r = requests.get(url, headers=headers, timeout=8, verify=False)
        result["code"] = r.status_code
        result["cors_origin"] = r.headers.get("Access-Control-Allow-Origin")
        result["cors_credentials"] = r.headers.get("Access-Control-Allow-Credentials")
        result["content_type"] = r.headers.get("Content-Type", "")
        result["body_len"] = len(r.content)

        reflected = result["cors_origin"] in ["https://evil.com", "*"]
        creds = str(result["cors_credentials"]).lower() == "true"
        result["reflected"] = reflected

        if item["host"] == "cdn.byspotify.com":
            if "<ListBucketResult" in r.text or "<Contents>" in r.text:
                result["verdict"] = "OPEN_BUCKET_LISTING"
                result["score"] = 6
                result["notes"] = "S3/GCS bucket directory listing open. Needs sensitive key check."
            else:
                result["verdict"] = "BUCKET_PROTECTED"
                result["score"] = 1
        elif reflected and creds:
            if result["body_len"] == 0:
                result["verdict"] = "REFLECTED_EMPTY_BODY"
                result["score"] = 4
                result["notes"] = "CORS reflected with creds, but root body is empty (telemetry/bot probe). Low bounty odds."
            elif "text/html" in result["content_type"]:
                result["verdict"] = "REFLECTED_PUBLIC_HTML"
                result["score"] = 5
                result["notes"] = "CORS reflected with creds on public HTML. Needs authenticated API endpoint for high bounty."
            elif "application/json" in result["content_type"]:
                result["verdict"] = "REFLECTED_JSON_API"
                result["score"] = 9
                result["notes"] = "CRITICAL/HIGH: CORS reflected with credentials on JSON API! Prime bounty target."
            else:
                result["verdict"] = "REFLECTED_WITH_CREDS"
                result["score"] = 6
                result["notes"] = f"CORS reflected with creds ({result['content_type']})."
        elif reflected and not creds:
            result["verdict"] = "REFLECTED_NO_CREDS"
            result["score"] = 3
            result["notes"] = "Reflects origin but credentials not allowed."
        else:
            result["verdict"] = "NO_CORS_REFLECT"
            result["score"] = 1
            result["notes"] = f"ACAC={result['cors_credentials']}, ACAO={result['cors_origin']}"
            
        result["status"] = "OK"
    except Exception as e:
        result["notes"] = f"Request error: {str(e)[:80]}"

    return result

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("=" * 80)
    print("PROBING 21 HACKERONE CANDIDATE TARGETS FOR EMPIRICAL CORS / BUCKET EXPOSURE")
    print("=" * 80)

    results = []
    for item in CANDIDATES:
        res = probe_target(item)
        results.append(res)
        tag = f"[{res['score']}/10]"
        print(f"{tag:<8} | {res['program']:<12} | {res['host']:<35} | {res['verdict']:<22} | {res['notes']}")

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)

    out_file = Path(r"C:\AgyHut\projects\orbit-security\data\hackerone_staging\live_verification_matrix.json")
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote full matrix to {out_file}")

if __name__ == "__main__":
    main()
