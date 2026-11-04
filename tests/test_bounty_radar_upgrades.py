import pytest
from orbit_security.bounty_radar import (
    BucketListingEvaluator,
    SensitiveExposureScanner,
    BountyTakeoverSweeper,
    BountyProgram,
)

def test_bucket_listing_evaluator_sensitive_keywords():
    xml_with_sensitive = """
    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Name>spotify-media</Name>
      <Contents>
        <Key>pitch/Podsights_Seed_Interview.pdf</Key>
        <Size>2145320</Size>
      </Contents>
      <Contents>
        <Key>db/users_backup.sql.gz</Key>
        <Size>9814421</Size>
      </Contents>
      <Contents>
        <Key>images/icon.png</Key>
        <Size>1230</Size>
      </Contents>
    </ListBucketResult>
    """
    evaluator = BucketListingEvaluator()
    result = evaluator.inspect_xml_keys(xml_with_sensitive)
    assert result["is_sensitive"] is True
    assert "pitch/Podsights_Seed_Interview.pdf" in result["matched_files"]
    assert "db/users_backup.sql.gz" in result["matched_files"]
    assert "images/icon.png" not in result["matched_files"]
    assert result["severity"] == "High"

def test_bucket_listing_evaluator_public_assets_only():
    xml_public = """
    <ListBucketResult>
      <Contents><Key>styles/main.css</Key></Contents>
      <Contents><Key>scripts/app.js</Key></Contents>
    </ListBucketResult>
    """
    evaluator = BucketListingEvaluator()
    result = evaluator.inspect_xml_keys(xml_public)
    assert result["is_sensitive"] is False
    assert len(result["matched_files"]) == 0

def test_sensitive_exposure_signature_verification():
    scanner = SensitiveExposureScanner()

    # Valid .git/HEAD
    assert scanner.verify_git_head("ref: refs/heads/main\n") is True
    assert scanner.verify_git_head("c3b4a5d6e7f809123456789abcdef0123456789a\n") is True
    # SPA 200 OK catch-all should fail
    assert scanner.verify_git_head("<!DOCTYPE html><html><body>404 Not Found</body></html>") is False

    # Valid /actuator/env
    actuator_json = '{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment"}]}'
    assert scanner.verify_actuator_env(actuator_json) is True
    assert scanner.verify_actuator_env("<html>SPA Fallback</html>") is False

    # Valid .env
    dotenv_text = "DATABASE_URL=postgres://user:pass@db.local:5432/main\nSECRET_KEY=s3cr3t"
    assert scanner.verify_dotenv(dotenv_text) is True
    assert scanner.verify_dotenv("<html>Not An Env</html>") is False

def test_dmarc_disabled_by_default():
    prog = BountyProgram(
        program_id="test_prog",
        name="Test",
        platform="hackerone",
        policy_url="https://hackerone.com/test",
        in_scope=["*.test.com"],
        out_of_scope=[],
        excluded_vulnerabilities=[],
        bounty_tier="cash",
    )
    sweeper = BountyTakeoverSweeper(program=prog, enable_mail_spoofing=False)
    assert sweeper.enable_mail_spoofing is False
