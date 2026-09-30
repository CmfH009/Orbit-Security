import pytest
from orbit_security.relevance_engine import (
    CURATED_INFOSEC_ACCOUNTS,
    LIVE_SEARCH_QUERIES,
    ActionDecision,
    ActionType,
    DiscoveredPost,
    DiscoveryVector,
    RelevanceEngine,
)


@pytest.fixture
def engine():
    return RelevanceEngine()


def test_curated_infosec_accounts_registry():
    """Verifies that all 19 curated accounts from the playbook exist in the registry."""
    assert len(CURATED_INFOSEC_ACCOUNTS) == 19

    # Tier 1 Broadcasters
    assert "briankrebs" in CURATED_INFOSEC_ACCOUNTS
    assert "krebsonsecurity" in CURATED_INFOSEC_ACCOUNTS
    assert "thehackersnews" in CURATED_INFOSEC_ACCOUNTS
    assert "bleepincomputer" in CURATED_INFOSEC_ACCOUNTS
    assert "darkreading" in CURATED_INFOSEC_ACCOUNTS

    # Tier 2 Researchers
    assert "troyhunt" in CURATED_INFOSEC_ACCOUNTS
    assert "danielmiessler" in CURATED_INFOSEC_ACCOUNTS
    assert "gossithedog" in CURATED_INFOSEC_ACCOUNTS
    assert "cyb3rops" in CURATED_INFOSEC_ACCOUNTS
    assert "swiftonsecurity" in CURATED_INFOSEC_ACCOUNTS

    # Tier 3 Educators
    assert "_johnhammond" in CURATED_INFOSEC_ACCOUNTS
    assert "hackingdave" in CURATED_INFOSEC_ACCOUNTS
    assert "malwarejake" in CURATED_INFOSEC_ACCOUNTS
    assert "racheltobac" in CURATED_INFOSEC_ACCOUNTS
    assert "k8em0" in CURATED_INFOSEC_ACCOUNTS
    assert "hacks4pancakes" in CURATED_INFOSEC_ACCOUNTS

    # Supplementary Watchdogs
    assert "campuscodi" in CURATED_INFOSEC_ACCOUNTS
    assert "vxunderground" in CURATED_INFOSEC_ACCOUNTS
    assert "malwrhunterteam" in CURATED_INFOSEC_ACCOUNTS


def test_live_search_queries_coverage():
    """Verifies that required search keywords are captured in LIVE_SEARCH_QUERIES."""
    query_texts = " ".join([q["query"] for q in LIVE_SEARCH_QUERIES])
    assert "dangling CNAME" in query_texts
    assert "subdomain takeover" in query_texts
    assert "DMARC p=none" in query_texts
    assert "SPF fail" in query_texts
    assert "website maintenance retainer" in query_texts
    assert "WordPress maintenance care plan" in query_texts
    assert "Shopify Plus DNS" in query_texts
    assert "expired SSL certificate" in query_texts


def test_domain_extraction(engine):
    """Tests URL stripping, cleaning, denylist filtering, and portfolio prioritization."""
    text = (
        "Check out our new launch at https://candykittens.co.uk/store! "
        "Also see https://github.com/orbit-security and node.js docs at bit.ly/test. "
        "Another site is staging.appdev.io:8080."
    )
    domains = engine.extract_domains(text)

    # candykittens.co.uk is a known agency portfolio target in prospects.json
    assert "candykittens.co.uk" in domains
    assert domains[0] == "candykittens.co.uk"  # Priority sorted

    # Denylisted/false-positives should NOT appear
    assert "github.com" not in domains
    assert "node.js" not in domains
    assert "bit.ly" not in domains

    # staging.appdev.io should be extracted
    assert "staging.appdev.io" in domains


def test_spam_hard_filter_drops(engine):
    """Tests instant drops on crypto, airdrops, follow trains, and tag flooding."""
    # Crypto airdrop
    post_airdrop = DiscoveredPost(
        tweet_id="101",
        author_handle="crypto_bot99",
        text="Massive airdrop happening now! Claim $SOL whitelist at pump.fun/xyz",
    )
    score = engine.calculate_score(post_airdrop)
    assert score.is_hard_dropped
    assert score.total_score == 0
    decision = engine.classify_action(post_airdrop, score)
    assert decision.action == ActionType.DROP

    # Follow train
    post_f4f = DiscoveredPost(
        tweet_id="102",
        author_handle="growth_hacker",
        text="F4F follow for follow instant follow back! Gain 10k today!",
    )
    score = engine.calculate_score(post_f4f)
    assert score.is_hard_dropped
    assert decision.action == ActionType.DROP

    # Tag flood
    post_tag_flood = DiscoveredPost(
        tweet_id="103",
        author_handle="spammer",
        text="Check this @user1 @user2 @user3 @user4 @user5 @user6",
    )
    score = engine.calculate_score(post_tag_flood)
    assert score.is_hard_dropped


def test_scoring_agency_target_client(engine):
    """Target agency discussing retainer with a client domain yields high score."""
    post = DiscoveredPost(
        tweet_id="201",
        author_handle="charleagency",  # Target agency
        text="Managing our monthly website maintenance retainer for candykittens.co.uk — DNS hygiene is critical.",
        like_count=12,
        reply_count=2,
    )
    score = engine.calculate_score(post)
    assert score.keyword_score >= 30
    assert score.author_score == 30
    assert score.domain_score == 25  # candykittens.co.uk is recognized client domain
    assert score.total_score >= 85

    decision = engine.classify_action(post, score)
    assert decision.action == ActionType.REPLY
    assert decision.target_domain == "candykittens.co.uk"
    assert decision.scan_recommended is True


def test_scoring_inbound_roast_request(engine):
    """User asking for roast with domain yields automated scan recommendation."""
    post = DiscoveredPost(
        tweet_id="202",
        author_handle="coolfounder",
        text="Hey @_arsoncode, roast my domain please! acmebrand.com",
    )
    score = engine.calculate_score(post)
    assert score.author_score >= 25
    assert score.domain_score >= 25
    assert score.total_score >= 75

    decision = engine.classify_action(post, score)
    assert decision.action == ActionType.REPLY
    assert decision.target_domain == "acmebrand.com"
    assert decision.scan_recommended is True


def test_scoring_curated_list_breaking_news(engine):
    """Tier 1 Broadcaster posting breaking zero-day leads to REPOST."""
    post = DiscoveredPost(
        tweet_id="301",
        author_handle="BleepinComputer",
        text="Critical zero-day vulnerability in DNS edge routing allows remote subdomain takeover.",
        like_count=120,
        retweet_count=45,
    )
    score = engine.calculate_score(post)
    assert score.author_score == 25
    assert score.keyword_score >= 35
    assert score.total_score >= 75

    decision = engine.classify_action(post, score)
    assert decision.action == ActionType.REPOST


def test_scoring_curated_list_researcher_insight(engine):
    """Tier 2 Researcher discussing DMARC leads to QUOTE."""
    post = DiscoveredPost(
        tweet_id="302",
        author_handle="troyhunt",
        text="Fascinating how many enterprises still run DMARC p=none and think they're safe from spoofing.",
        like_count=85,
        retweet_count=20,
    )
    score = engine.calculate_score(post)
    assert score.author_score == 25
    assert score.keyword_score >= 35
    assert score.total_score >= 75

    decision = engine.classify_action(post, score)
    assert decision.action == ActionType.QUOTE


def test_scoring_moderate_alignment_likes(engine):
    """Moderate alignment (score 50-74) leads to LIKE."""
    post = DiscoveredPost(
        tweet_id="401",
        author_handle="web_dev_daily",
        text="Always make sure to check your expired SSL certificate warnings before rolling out to production.",
        like_count=5,
    )
    score = engine.calculate_score(post)
    assert 50 <= score.total_score < 75

    decision = engine.classify_action(post, score)
    assert decision.action == ActionType.LIKE
