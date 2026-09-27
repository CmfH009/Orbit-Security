import os
import sys
from pathlib import Path
import pytest
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.stage_meta_ad_campaign import (
    CAMPAIGN_CONFIG,
    AD_VARIANTS,
    TARGETING_CONFIG,
    CREATIVE_ASSET_PATH,
    verify_campaign,
    format_ad_copy,
)


def test_creative_asset_properties():
    assert CREATIVE_ASSET_PATH.exists(), f"Creative asset missing at {CREATIVE_ASSET_PATH}"
    assert CREATIVE_ASSET_PATH.stat().st_size > 100_000, "Asset size abnormally small"
    with Image.open(CREATIVE_ASSET_PATH) as img:
        width, height = img.size
        assert width == 1024
        assert height == 1024
        assert img.format in ("JPEG", "JPG")


def test_campaign_budget_and_pacing():
    total_budget = CAMPAIGN_CONFIG["total_budget_usd"]
    daily_budget = CAMPAIGN_CONFIG["daily_budget_usd"]
    duration_days = CAMPAIGN_CONFIG["duration_days"]

    assert total_budget == 10.00
    assert daily_budget == 2.50
    assert duration_days == 4
    assert round(daily_budget * duration_days, 2) == total_budget
    assert CAMPAIGN_CONFIG["objective"] == "Traffic"
    assert CAMPAIGN_CONFIG["optimization_goal"] == "Landing Page Views"


def test_targeting_mesh_parameters():
    locations = TARGETING_CONFIG["locations"]
    assert "United States" in locations
    assert "United Kingdom" in locations
    assert "Canada" in locations

    interests = TARGETING_CONFIG["interests"]
    assert "Shopify Plus" in interests
    assert "Cybersecurity" in interests

    job_titles = TARGETING_CONFIG["job_titles"]
    assert "Founder" in job_titles
    assert "Chief Technology Officer" in job_titles
    assert "Agency Owner" in job_titles

    placements = TARGETING_CONFIG["placements"]
    assert "Facebook Feed" in placements
    assert "Instagram Feed" in placements
    assert len(placements) == 2  # Exclusive feed placements


def test_ad_variants_structure_and_utms():
    assert "variant_1" in AD_VARIANTS
    assert "variant_2" in AD_VARIANTS

    v1 = AD_VARIANTS["variant_1"]
    assert "utm_source=meta" in v1["url"]
    assert "utm_campaign=retainer_multiplier" in v1["url"]
    assert "utm_content=astro_pounce" in v1["url"]
    assert len(v1["headline"]) <= 40
    assert len(v1["description"]) <= 45

    v2 = AD_VARIANTS["variant_2"]
    assert "utm_source=meta" in v2["url"]
    assert "utm_campaign=sentinel_guardian" in v2["url"]
    assert "utm_content=astro_pounce" in v2["url"]
    assert len(v2["headline"]) <= 40
    assert len(v2["description"]) <= 45


def test_verify_campaign():
    assert verify_campaign() is True


def test_format_ad_copy():
    formatted_v1 = format_ad_copy("variant_1")
    assert "How do top Shopify Plus" in formatted_v1
    assert "Headline: Automate Agency Security Retainers" in formatted_v1

    formatted_v2 = format_ad_copy("variant_2")
    assert "Meet the perimetric sentinels" in formatted_v2
    assert "Headline: Perimeter Defense for Web Agencies" in formatted_v2
