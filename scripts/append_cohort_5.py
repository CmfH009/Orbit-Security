import json
from pathlib import Path

PROSPECTS_FILE = Path(__file__).resolve().parent.parent / "data" / "prospects.json"

cohort_5 = [
    {
        "agency_name": "Verbal+Visual",
        "agency_domain": "verbalplusvisual.com",
        "contact_email": "hello@verbalplusvisual.com",
        "portfolio_domains": ["carawayhome.com", "mackweldon.com"],
        "personalization_hook": "We've long admired Verbal+Visual's craftsmanship as a B Corp Shopify Plus partner, especially the clean performance engineering behind Caraway Home's D2C flagship."
    },
    {
        "agency_name": "Anatta",
        "agency_domain": "anatta.io",
        "contact_email": "hello@anatta.io",
        "portfolio_domains": ["rothys.com", "molekule.com"],
        "personalization_hook": "We have huge respect for Anatta's data-driven eCommerce engineering and continuous optimization work powering global scale for Rothy's."
    },
    {
        "agency_name": "Fostr",
        "agency_domain": "fostr.online",
        "contact_email": "hello@fostr.online",
        "portfolio_domains": ["victoriabeckham.com", "tataharperskincare.com"],
        "personalization_hook": "We admire Fostr's immaculate technical execution and luxury eCommerce systems for global icons like Victoria Beckham."
    },
    {
        "agency_name": "Growth Spark",
        "agency_domain": "growthspark.com",
        "contact_email": "hello@growthspark.com",
        "portfolio_domains": ["johnnycupcakes.com", "boseaccessories.com"],
        "personalization_hook": "We've followed Growth Spark's focus on scalable Shopify Plus architecture and conversion optimization for cult brands like Johnny Cupcakes."
    },
    {
        "agency_name": "Guidance",
        "agency_domain": "guidance.com",
        "contact_email": "info@guidance.com",
        "portfolio_domains": ["burlington.com", "footlocker.com"],
        "personalization_hook": "We have deep respect for Guidance's decades of enterprise omnichannel commerce engineering and high-availability architecture."
    },
    {
        "agency_name": "Lounge Lizard",
        "agency_domain": "loungelizard.com",
        "contact_email": "sales@loungelizard.com",
        "portfolio_domains": ["broadway.com", "honeywell.com"],
        "personalization_hook": "We've long appreciated Lounge Lizard's blend of high-impact visual design and rock-solid web architecture for premier platforms like Broadway.com."
    },
    {
        "agency_name": "Taoti Creative",
        "agency_domain": "taoti.com",
        "contact_email": "hello@taoti.com",
        "portfolio_domains": ["nationalgeographic.org", "usaid.gov"],
        "personalization_hook": "We admire Taoti Creative's purposeful digital architecture and complex multi-stakeholder web solutions for world-changing organizations like National Geographic."
    },
    {
        "agency_name": "Northern Commerce",
        "agency_domain": "northern.co",
        "contact_email": "info@northern.co",
        "portfolio_domains": ["rexall.ca", "westlandinsurance.ca"],
        "personalization_hook": "We respect Northern's massive enterprise commerce and health compliance implementations for trusted institutions like Rexall."
    },
    {
        "agency_name": "Zeek Interactive",
        "agency_domain": "zeekinteractive.com",
        "contact_email": "info@zeekinteractive.com",
        "portfolio_domains": ["zeek.com", "ocregister.com"],
        "personalization_hook": "We have high regard for Zeek's deep architectural engineering in WordPress core, enterprise integrations, and high-scale publisher systems."
    },
    {
        "agency_name": "WebFX",
        "agency_domain": "webfx.com",
        "contact_email": "info@webfx.com",
        "portfolio_domains": ["reynoldsam.com", "webfx.com"],
        "personalization_hook": "We've tracked WebFX's proprietary tech stack and relentless focus on measurable ROI and technical performance for mid-market leaders like Reynolds."
    }
]

def main():
    if not PROSPECTS_FILE.exists():
        prospects = []
    else:
        with open(PROSPECTS_FILE, "r", encoding="utf-8") as f:
            prospects = json.load(f)

    existing_domains = {p["agency_domain"] for p in prospects}
    added = 0
    for p in cohort_5:
        if p["agency_domain"] not in existing_domains:
            prospects.append(p)
            added += 1

    with open(PROSPECTS_FILE, "w", encoding="utf-8") as f:
        json.dump(prospects, f, indent=2)

    print(f"Added {added} new prospects to {PROSPECTS_FILE}. Total: {len(prospects)}")

if __name__ == "__main__":
    main()
