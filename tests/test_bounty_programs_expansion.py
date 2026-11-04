from pathlib import Path
import json

def test_bounty_programs_expansion_count():
    path = Path(__file__).resolve().parent.parent / "data" / "bounty_programs.json"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    programs = data.get("programs", [])
    assert len(programs) >= 45, f"Expected at least 45 programs, found {len(programs)}"

    prog_map = {p["program_id"]: p for p in programs}
    required_programs = [
        "valve",
        "coinbase",
        "uber",
        "automattic",
        "epicgames",
        "hyatt",
        "paypal",
        "slack",
        "atlassian",
        "dropbox",
        "yahoo",
        "twitter",
        "github",
        "airbnb",
        "tiktok",
        "roblox",
        "nintendo",
        "sony",
        "yelp",
        "reddit",
        "square",
    ]
    for req in required_programs:
        assert req in prog_map, f"Missing required program: {req}"
        prog = prog_map[req]
        assert prog["bounty_tier"] == "cash"
        assert prog["max_bounty"] > 0
        assert len(prog["in_scope"]) > 0
        assert any("*" in scope for scope in prog["in_scope"]), f"Program {req} must include wildcard scopes"
