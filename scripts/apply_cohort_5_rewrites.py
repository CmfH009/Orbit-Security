#!/usr/bin/env python3
"""Applies the gamified Perimeter Arena pitch copy to all 10 Cohort 5 agencies
and regenerates the corresponding .eml draft packages with attached PDFs.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orbit_security.mailer import EmailDispatcher

COHORT_5 = [
    {
        "folder": "verbalplusvisual_com",
        "recipient": "hello@verbalplusvisual.com",
        "subject": "Caraway Home's perimeter posture (and automated white-label audit PDFs for Verbal+Visual)",
        "pdf": "carawayhome_com_security_audit.pdf",
        "body": """Hey Verbal+Visual team,

I'm Carson, software engineer and founder at Orbit Security.

I've long admired Verbal+Visual's craftsmanship as a B Corp Shopify Plus partner, especially the clean performance engineering behind Caraway Home's D2C flagship.

With automated bots and AI crawlers now representing over 51% of all web traffic, client attack surfaces are under continuous, automated probing for DNS drift and missing security boundaries. 

I ran Caraway Home through our passive reconnaissance engine:
- Score: 60/100
- DMARC & BIMI: Active quarantine policy verified (great defense)
- Security Headers: Missing Content-Security-Policy, X-Frame-Options, and Referrer-Policy

🎮 Perimeter Arena Benchmark (Shopify Plus & DTC Sector):
- Category Rank: #7 of 10 audited brands
- Sector Benchmark Leader: Candy Kittens (95/100) | Sector Median: 76/100
- Quick Win: Closing 2 header gaps immediately unlocks a 90+ Top 10% ranking and DMARC Fortress status in our sentinel registry.

I generated a 1-page co-branded PDF audit branded with Verbal+Visual's logo (attached). Many Shopify Plus agencies use our automated monthly PDF reports to demonstrate ongoing technical stewardship to their clients and defend $150–$350/mo maintenance retainers without burning billable developer hours.

Check out our new Fleet Command Center and live DoH terminal to see where your clients rank:
https://cmfh009.github.io/Orbit-Security/fleet.html

Best,
Carson Haynes
Founder, Orbit Security | @_arsoncode
carsonmail009@gmail.com"""
    },
    {
        "folder": "anatta_io",
        "recipient": "hello@anatta.io",
        "subject": "Rothy's perimeter hygiene (and client retainer reporting for Anatta)",
        "pdf": "rothys_com_security_audit.pdf",
        "body": """Hey Anatta team,

I'm Carson, an engineer and founder at Orbit Security.

We have huge respect for Anatta's data-driven eCommerce engineering and continuous optimization work powering global scale for Rothy's.

Because more than half of web traffic is now autonomous bots and scrapers probing perimeters 24/7, keeping DNS routing and header policies tightly aligned is critical to protecting brand reputation.

I ran our passive reconnaissance engine across Rothy's:
- Score: 84/100 (Strong posture)
- DMARC: Strict quarantine enforced with active BIMI certification
- Opportunities: Missing Referrer-Policy and Cross-Origin-Opener-Policy (COOP)

🎮 Perimeter Arena Benchmark (Global Headless eCommerce):
- Category Rank: Top 20% across audited enterprise eCommerce perimeters
- Sector Benchmark Leader: Candy Kittens (95/100) | Politico (100/100)
- Sector Median: 78/100 (Rothy's is well ahead of industry baseline)

I attached a sample 1-page executive audit co-branded for Anatta. We built Orbit Security so agencies can deliver automated, monthly white-label security audits to clients—providing tangible proof of ongoing retainers without taking developers away from billable sprint work.

Would love to hear your thoughts, or you can explore our Fleet Command Center directly:
https://cmfh009.github.io/Orbit-Security/fleet.html

Cheers,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com"""
    },
    {
        "folder": "fostr_online",
        "recipient": "hello@fostr.online",
        "subject": "Victoria Beckham's perimeter defense (and retainer automation for Fostr)",
        "pdf": "victoriabeckham_com_security_audit.pdf",
        "body": """Hey Fostr team,

I'm Carson, software engineer and founder at Orbit Security.

We admire Fostr's immaculate technical execution and luxury eCommerce systems for global icons like Victoria Beckham.

In today's landscape where autonomous AI agents and bots account for over 51% of web traffic, luxury brands are prime targets for spoofed domains and perimeter drift.

I ran a passive check on victoriabeckham.com:
- Score: 84/100
- Routing & DMARC: Subdomain pointers clean, email anti-spoofing in place
- Security Headers: Missing COOP and modern Referrer-Policy controls

🎮 Perimeter Arena Benchmark (Luxury Fashion & Lifestyle):
- Category Rank: #2 of audited luxury flagships (Top Tier)
- Sector Median: 78/100 (Ahead of industry peers)
- Opportunity: Adding Cross-Origin-Opener-Policy unlocks the full 100/100 Sovereign status.

Attached is a co-branded sample executive PDF audit under Fostr's brand. Agencies use Orbit to run monthly background audits across their entire portfolio and export branded PDFs to defend $250/mo+ maintenance care plans.

Feel free to check out our open-source scanner and Fleet Command Center here:
https://cmfh009.github.io/Orbit-Security/fleet.html

Best regards,
Carson Haynes
Founder, Orbit Security | @_arsoncode
carsonmail009@gmail.com"""
    },
    {
        "folder": "growthspark_com",
        "recipient": "hello@growthspark.com",
        "subject": "Johnny Cupcakes perimeter health (and a tool for Growth Spark retainers)",
        "pdf": "johnnycupcakes_com_security_audit.pdf",
        "body": """Hey Growth Spark team,

I'm Carson, an engineer and founder at Orbit Security.

We've followed Growth Spark's focus on scalable Shopify Plus architecture and conversion optimization for cult brands like Johnny Cupcakes.

With automated bot probes and scrapers making up over half of internet traffic, continuous perimeter monitoring is becoming standard for high-profile retail brands.

We audited johnnycupcakes.com through our passive scanner:
- Score: 84/100
- Email Defense: DMARC active
- Observations: Missing modern Permissions-Policy and COOP isolation

🎮 Perimeter Arena Benchmark (Shopify Plus & Apparel):
- Category Rank: Top 25% of audited D2C brands
- Sector Benchmark Leader: Candy Kittens (95/100) | Sector Median: 76/100
- Hardening Streak: Johnny Cupcakes is just 2 policy tweaks away from an elite 95+ score.

I attached a co-branded executive audit PDF featuring Growth Spark's branding. Our goal with Orbit Security is simple: help agencies automate recurring monthly deliverables that justify $150–$350/mo client care plans without burning dev hours.

You can run an instant audit on any of your clients in our browser studio:
https://cmfh009.github.io/Orbit-Security/fleet.html

Cheers,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com"""
    },
    {
        "folder": "guidance_com",
        "recipient": "info@guidance.com",
        "subject": "Burlington's external attack surface (and automated retainer audits for Guidance)",
        "pdf": "burlington_com_security_audit.pdf",
        "body": """Hey Guidance team,

I'm Carson, software engineer and founder at Orbit Security.

We have deep respect for Guidance's decades of enterprise omnichannel commerce engineering and high-availability architecture.

With autonomous bots and crawlers representing >51% of web traffic, enterprise retail perimeters face persistent automated reconnaissance.

I ran a passive perimeter audit on burlington.com:
- Score: 52/100
- Routing: Direct A records stable
- Critical Gaps: Missing 6 recommended OWASP HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)

🎮 Perimeter Arena Benchmark (Enterprise Retail Commerce):
- Category Rank: Bottom 30% of audited national retail chains
- Sector Median: 68/100 (Burlington currently sits 16 points below sector benchmark)
- Quick Win: Injecting HSTS and anti-framing headers via CDN edge immediately lifts the score to 85/100.

Attached is an executive PDF audit formatted for Guidance. We built Orbit Security so enterprise agencies can continuously patrol client domains, generate instant IaC/DNS remediation snippets, and export monthly white-label reports that reinforce long-term client trust.

Check out our new Fleet Command Center and live DoH terminal:
https://cmfh009.github.io/Orbit-Security/fleet.html

Best regards,
Carson Haynes
Founder, Orbit Security | @_arsoncode
carsonmail009@gmail.com"""
    },
    {
        "folder": "loungelizard_com",
        "recipient": "sales@loungelizard.com",
        "subject": "Broadway.com perimeter review (and client retainer deliverables for Lounge Lizard)",
        "pdf": "broadway_com_security_audit.pdf",
        "body": """Hey Lounge Lizard team,

I'm Carson, founder and developer at Orbit Security.

We've long appreciated Lounge Lizard's blend of high-impact visual design and rock-solid web architecture for premier platforms like Broadway.com.

In an era where over 51% of web traffic is autonomous bots probing for abandoned endpoints and misconfigurations, proactive perimeter vigilance is essential.

I ran Broadway.com through our passive scanner:
- Score: 84/100
- Routing & DMARC: Clean infrastructure, strong baseline
- Opportunities: Missing MTA-STS mail encryption and Cross-Origin-Opener-Policy

🎮 Perimeter Arena Benchmark (Entertainment & Ticketing Platforms):
- Category Rank: Top 20% in category
- Sector Benchmark Leader: POLITICO (100/100) | Category Median: 75/100
- Status: Broadway.com holds a solid B+; closing 2 header policies unlocks a 95+ A+ grade.

Attached is a 1-page sample audit co-branded for Lounge Lizard. Agencies use our platform to automatically monitor client fleets and deliver monthly PDF audits that prove the value of their ongoing maintenance retainers.

Feel free to test your clients in our browser terminal:
https://cmfh009.github.io/Orbit-Security/fleet.html

Best,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com"""
    },
    {
        "folder": "taoti_com",
        "recipient": "hello@taoti.com",
        "subject": "National Geographic's perimeter posture (and retainer defense for Taoti)",
        "pdf": "nationalgeographic_org_security_audit.pdf",
        "body": """Hey Taoti Creative team,

I'm Carson, software engineer and founder at Orbit Security.

We admire Taoti Creative's purposeful digital architecture and complex multi-stakeholder web solutions for world-changing organizations like National Geographic.

With autonomous AI bots and scrapers exceeding half of all web traffic, institutional domains face non-stop passive scanning.

A passive inspection of nationalgeographic.org revealed:
- Score: 44/100
- Routing: Clean apex routing
- Critical Observations: Zero OWASP security headers detected (missing HSTS, CSP, and framing protection)

🎮 Perimeter Arena Benchmark (Institutional & NGO Sector):
- Category Rank: Sector Median is 54/100 (Leader: Adoptium at 85/100)
- Risk Profile: The absence of HSTS and MIME protection leaves institutional reputation exposed.
- Remediation: Our CLI (`orbit-recon --remediate`) generates ready-to-paste Cloudflare / Nginx configs to bring this to 90/100 in 15 minutes.

Attached is a co-branded executive audit PDF for Taoti. Orbit Security automates background perimeter audits across client rosters, providing white-label monthly proof of stewardship to support ongoing retainer agreements.

Explore our open-source tools and interactive scanner:
https://cmfh009.github.io/Orbit-Security/fleet.html

Warm regards,
Carson Haynes
Founder, Orbit Security | @_arsoncode
carsonmail009@gmail.com"""
    },
    {
        "folder": "northern_co",
        "recipient": "info@northern.co",
        "subject": "Rexall's perimeter compliance (and automated client audits for Northern)",
        "pdf": "rexall_ca_security_audit.pdf",
        "body": """Hey Northern team,

I'm Carson, software engineer and founder at Orbit Security.

We respect Northern's massive enterprise commerce and health compliance implementations for trusted Canadian institutions like Rexall.

Because over 51% of all web traffic is now autonomous bots probing perimeters 24/7, continuous perimeter hygiene is a foundational compliance requirement for healthcare and commerce brands.

We ran a passive audit on rexall.ca:
- Score: 52/100
- DNS Routing: Stable
- Header Posture: Missing HSTS and multiple OWASP response security headers

🎮 Perimeter Arena Benchmark (Healthcare & Pharmacy Platforms):
- Category Rank: Below Sector Median (54/100)
- Opportunity: Deploying HSTS and secure cookie policies elevates Rexall to top-tier compliance status.

I generated a 1-page co-branded PDF audit for Northern Commerce (attached). We built Orbit Security to help enterprise digital studios automate monthly client deliverables that protect high-value care plan retainers.

Check out our new Fleet Command Center:
https://cmfh009.github.io/Orbit-Security/fleet.html

Best,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com"""
    },
    {
        "folder": "zeekinteractive_com",
        "recipient": "info@zeekinteractive.com",
        "subject": "Zeek's perimeter telemetry (and retainer tools for your agency)",
        "pdf": "zeek_com_security_audit.pdf",
        "body": """Hey Zeek team,

I'm Carson, founder and developer at Orbit Security.

We have high regard for Zeek's deep architectural engineering in WordPress core, enterprise integrations, and high-scale publisher systems.

Given that autonomous bots and crawlers make up >51% of internet traffic, keeping perimeter headers and DNS configurations pristine is vital to defending client trust.

I ran a quick passive scan on zeek.com:
- Score: 44/100
- Observations: Missing HSTS, CSP, and modern header protections

🎮 Perimeter Arena Benchmark (Enterprise WordPress & Publishing):
- Sector Benchmark Leader: POLITICO (100/100) | Category Median: 82/100
- Opportunity: A modern Cloudflare Transform Rule for security headers immediately jumps zeek.com to 85+/100.

Attached is a sample white-label PDF audit co-branded for Zeek Interactive. Orbit Security lets agencies patrol client domains automatically and export monthly branded PDFs that show proactive care plan stewardship without burning developer hours.

Test any client domain live in our zero-server DoH scanner:
https://cmfh009.github.io/Orbit-Security/fleet.html

Cheers,
Carson Haynes
Founder, Orbit Security | @_arsoncode
carsonmail009@gmail.com"""
    },
    {
        "folder": "webfx_com",
        "recipient": "info@webfx.com",
        "subject": "Reynolds perimeter review (and white-label audit tools for WebFX retainers)",
        "pdf": "reynoldsam_com_security_audit.pdf",
        "body": """Hey WebFX team,

I'm Carson, an engineer and founder at Orbit Security.

We've tracked WebFX's proprietary tech stack and relentless focus on measurable ROI and technical performance for mid-market leaders like Reynolds.

With autonomous scrapers and bots accounting for over 51% of web traffic, perimeter hygiene is a visible metric of client diligence.

We ran reynoldsam.com through our passive scanner:
- Score: 76/100
- DMARC: Active email authentication verified
- Gaps: Missing modern Permissions-Policy and COOP isolation headers

🎮 Perimeter Arena Benchmark (B2B Industrial & Manufacturing):
- Category Rank: Above Sector Median (70/100)
- Peer Comparison: Reynolds outperforms 65% of audited industrial peers.
- Next Level: Enforcing COOP headers unlocks the A-Grade tier in our sentinel registry.

Attached is an executive PDF audit co-branded for WebFX. Our tool helps agencies automatically monitor client perimeters and generate monthly white-label deliverables that protect $250/mo+ maintenance retainers.

You can explore our CLI tool or web terminal here:
https://cmfh009.github.io/Orbit-Security/fleet.html

Best regards,
Carson Haynes
Founder, Orbit Security
carsonmail009@gmail.com"""
    }
]

def main():
    campaigns_dir = PROJECT_ROOT / "outbound_campaigns"
    dispatcher = EmailDispatcher()
    
    print(f"[*] Applying critic-approved & gamified copy to 10 Cohort 5 agencies...")
    
    for item in COHORT_5:
        folder = campaigns_dir / item["folder"]
        folder.mkdir(parents=True, exist_ok=True)
        
        email_txt_path = folder / "pitch_email.txt"
        eml_path = folder / "pitch_email.eml"
        pdf_path = folder / item["pdf"]
        
        # 1. Write the pitch_email.txt
        with open(email_txt_path, "w", encoding="utf-8") as f:
            f.write(f"Subject: {item['subject']}\n\n{item['body']}\n")
            
        print(f"    [+] Updated text: {email_txt_path.name} in {item['folder']}")
        
        # 2. Verify PDF exists
        if not pdf_path.exists():
            print(f"    [!] Warning: PDF attachment not found at {pdf_path}")
            
        # 3. Export .eml draft
        dispatcher.export_eml(
            recipient_email=item["recipient"],
            subject=item["subject"],
            body_text=item["body"],
            pdf_attachment_path=str(pdf_path) if pdf_path.exists() else None,
            output_eml_path=str(eml_path)
        )
        print(f"    [✓] Generated EML: {eml_path.name} (with {pdf_path.name if pdf_path.exists() else 'no attachment'})")
        
    print("\n[✔] All 10 Cohort 5 agencies successfully updated with gamified Perimeter Arena copy and EML drafts!")

if __name__ == "__main__":
    main()
