import pytest
from scripts.mine_cors_endpoints import (
    extract_script_urls,
    extract_api_endpoints,
    evaluate_cors_response,
)

def test_extract_script_urls():
    html = """
    <html>
      <head>
        <script src="/static/js/main.abc1234.js"></script>
        <script src="https://cdn.example.com/assets/vendor.js"></script>
      </head>
      <body>
        <script src="relative/bundle.js"></script>
      </body>
    </html>
    """
    base_url = "https://buyingflow.mercadolibre.com.mx"
    urls = extract_script_urls(html, base_url)
    assert "https://buyingflow.mercadolibre.com.mx/static/js/main.abc1234.js" in urls
    assert "https://cdn.example.com/assets/vendor.js" in urls
    assert "https://buyingflow.mercadolibre.com.mx/relative/bundle.js" in urls

def test_extract_api_endpoints():
    js_code = """
    const userApi = "/api/v1/users/profile";
    const checkoutUrl = "/checkout/cart/summary";
    function fetchBilling() { return axios.get("/v2/billing/invoices?page=1"); }
    const ignored = "https://evil.com/not/relative";
    const invalidPath = "/";
    const staticImg = "/images/logo.png";
    """
    routes = extract_api_endpoints(js_code)
    assert "/api/v1/users/profile" in routes
    assert "/checkout/cart/summary" in routes
    assert "/v2/billing/invoices" in routes
    assert "/images/logo.png" not in routes

def test_evaluate_cors_response():
    headers_vulnerable = {
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json"
    }
    result = evaluate_cors_response(status_code=200, headers=headers_vulnerable, body='{"user_id": 12345, "email": "test@example.com"}')
    assert result["reflected"] is True
    assert result["credentials"] is True
    assert result["sensitive_keywords"] == ["email", "user_id"]
    assert result["is_high_value"] is True

    headers_safe = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "text/html"
    }
    result_safe = evaluate_cors_response(status_code=200, headers=headers_safe, body="<html>Public Page</html>")
    assert result_safe["reflected"] is False
    assert result_safe["credentials"] is False
    assert result_safe["is_high_value"] is False
