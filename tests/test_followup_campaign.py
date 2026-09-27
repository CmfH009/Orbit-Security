import os
import sys
from datetime import datetime, timedelta
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.run_followup_campaign import (
    generate_bump_copy,
    get_client_domain_for_agency,
    get_eligible_followups,
    EXCLUDED_BOUNCE_DOMAINS,
)


def test_generate_bump_copy():
    copy = generate_bump_copy("Acme Agency", "clientbrand.com")
    assert "Re: Co-branded perimeter hygiene audit for clientbrand.com" == copy["subject"]
    assert "Acme Agency team" in copy["body"]
    assert "fleet.html" in copy["body"]
    assert "Carson Haynes" in copy["body"]


def test_get_client_domain_for_agency():
    prospects = [
        {"agency_domain": "testagency.com", "portfolio_domains": ["clientbrand.com", "alt.com"]},
        {"agency_domain": "nodomains.com", "portfolio_domains": []},
    ]
    assert get_client_domain_for_agency("testagency.com", prospects) == "clientbrand.com"
    assert get_client_domain_for_agency("nodomains.com", prospects) == "your client builds"
    assert get_client_domain_for_agency("unknown.com", prospects) == "your client builds"


def test_get_eligible_followups_filtering():
    now = datetime.now()
    two_days_ago = (now - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")
    five_hours_ago = (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S")

    dispatched = {
        "old_agency.com": {
            "agency_name": "Old Agency",
            "contact_email": "team@oldagency.com",
            "dispatched_at": two_days_ago,
        },
        "recent_agency.com": {
            "agency_name": "Recent Agency",
            "contact_email": "team@recentagency.com",
            "dispatched_at": five_hours_ago,
        },
        "anatta.io": {
            "agency_name": "Anatta",
            "contact_email": "hello@anatta.io",
            "dispatched_at": two_days_ago,
        },
    }

    prospects = [
        {"agency_domain": "old_agency.com", "portfolio_domains": ["oldclient.com"]},
        {"agency_domain": "recent_agency.com", "portfolio_domains": ["recentclient.com"]},
        {"agency_domain": "anatta.io", "portfolio_domains": ["rothys.com"]},
    ]

    followups_log = {}

    eligible = get_eligible_followups(
        dispatched=dispatched,
        prospects=prospects,
        followups_log=followups_log,
        min_hours=36.0,
    )

    # old_agency is > 36h and not bounced -> eligible
    # recent_agency is < 36h -> filtered
    # anatta.io is in EXCLUDED_BOUNCE_DOMAINS -> filtered
    assert len(eligible) == 1
    assert eligible[0]["agency_domain"] == "old_agency.com"
    assert eligible[0]["client_domain"] == "oldclient.com"
