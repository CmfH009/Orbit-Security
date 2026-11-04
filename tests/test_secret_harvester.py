# C:\AgyHut\projects\orbit-security\tests\test_secret_harvester.py
import pytest
from orbit_security.tools.secret_harvester import SecretHarvester, SecretMatch

def test_detect_aws_access_key():
    text = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";'
    harvester = SecretHarvester()
    matches = harvester.scan_text(text)
    aws_matches = [m for m in matches if m.pattern_name == "AWS Access Key ID"]
    assert len(aws_matches) == 1
    assert aws_matches[0].matched_value == "AKIAIOSFODNN7EXAMPLE"
    assert aws_matches[0].redacted_value.startswith("AKIA")
    assert aws_matches[0].redacted_value.endswith("MPLE")

def test_detect_stripe_live_key():
    text = 'var stripe = Stripe("sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz1234");'
    harvester = SecretHarvester()
    matches = harvester.scan_text(text)
    stripe_matches = [m for m in matches if m.pattern_name == "Stripe Live Secret Key"]
    assert len(stripe_matches) == 1
    assert "sk_live_" in stripe_matches[0].matched_value

def test_detect_google_cloud_api_key():
    text = 'const gmapKey = "AIzaSyD-1234567890abcdefghijklmnopqrstuv";'
    harvester = SecretHarvester()
    matches = harvester.scan_text(text)
    gcp_matches = [m for m in matches if m.pattern_name == "Google Cloud API Key"]
    assert len(gcp_matches) == 1
    assert gcp_matches[0].matched_value.startswith("AIzaSy")

def test_detect_slack_webhook():
    text = 'fetch("https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")'
    harvester = SecretHarvester()
    matches = harvester.scan_text(text)
    slack_matches = [m for m in matches if m.pattern_name == "Slack Webhook URL"]
    assert len(slack_matches) == 1
    assert "hooks.slack.com/services" in slack_matches[0].matched_value

def test_detect_jwt_token():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f'const authToken = "{jwt}";'
    harvester = SecretHarvester()
    matches = harvester.scan_text(text)
    jwt_matches = [m for m in matches if m.pattern_name == "JSON Web Token (JWT)"]
    assert len(jwt_matches) == 1
    assert jwt_matches[0].confidence == "Medium"

def test_detect_cloud_storage_bucket():
    text = 'const backupStorage = "s3://spotify-client-archive-internal";'
    harvester = SecretHarvester()
    matches = harvester.scan_text(text)
    s3_matches = [m for m in matches if m.pattern_name == "Cloud Storage URI"]
    assert len(s3_matches) == 1
    assert s3_matches[0].matched_value == "s3://spotify-client-archive-internal"

def test_empty_and_benign_text():
    harvester = SecretHarvester()
    assert harvester.scan_text("") == []
    assert harvester.scan_text("function add(a, b) { return a + b; }") == []
