import os
import sys
from pathlib import Path
import pytest
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.stage_x_ad_campaign import (
    X_CAMPAIGN_CONFIG,
    X_AD_VARIANTS,
    X_TARGETING_CONFIG,
    X_CREATIVE_ASSET_PATH,
    verify_x_campaign,
    format_x_ad_copy,
)


def test_creative_asset_for_x():
    assert X_CREATIVE_ASSET_PATH.exists(), f"Asset missing at {X_CREATIVE_ASSET_PATH}"
    assert X_CREATIVE_ASSET_PATH.stat().st_size > 100_000, "Asset size too small"
    with Image.open(X_CREATIVE_ASSET_PATH) as img:
        w, h = img.size
        assert w == 1024 and h == 1024


def test_x_campaign_budget_and_objective():
    total = X_CAMPAIGN_CONFIG["total_budget_usd"]
    daily = X_CAMPAIGN_CONFIG["daily_budget_usd"]
    days = X_CAMPAIGN_CONFIG["duration_days"]

    assert total == 10.00
    assert daily == 2.50
    assert days == 4
    assert round(daily * days, 2) == total
    assert X_CAMPAIGN_CONFIG["objective"] == "Website Traffic"
    assert X_CAMPAIGN_CONFIG["pacing"] == "Standard"


def test_x_targeting_mesh():
    handles = X_TARGETING_CONFIG["follower_lookalikes"]
    assert "@ShopifyDevs" in handles
    assert "@troyhunt" in handles
    assert "@dhh" in handles

    keywords = X_TARGETING_CONFIG["keywords"]
    assert "Shopify Plus" in keywords
    assert "DMARC" in keywords
    assert "subdomain takeover" in keywords

    locations = X_TARGETING_CONFIG["locations"]
    assert "United States" in locations
    assert "United Kingdom" in locations
    assert "Canada" in locations


def test_x_ad_variants_length_and_utms():
    assert "variant_1" in X_AD_VARIANTS
    assert "variant_2" in X_AD_VARIANTS

    for key, v in X_AD_VARIANTS.items():
        assert "utm_source=x" in v["url"]
        assert "utm_medium=promoted_tweet" in v["url"]
        assert len(v["tweet_text"]) <= 280, f"{key} tweet text exceeds 280 chars ({len(v['tweet_text'])})"


def test_verify_x_campaign():
    assert verify_x_campaign() is True


def test_format_x_ad_copy():
    copy_v1 = format_x_ad_copy("variant_1")
    assert "Shopify Plus" in copy_v1
    assert "cmfh009.github.io/Orbit-Security" in copy_v1
