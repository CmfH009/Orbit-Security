#!/usr/bin/env python3
"""Applies the critic-approved peer-to-peer email copy to all 11 Cohort 4 agencies
and regenerates the corresponding .eml draft packages with attached PDFs.
"""

import os
from orbit_security.mailer import EmailDispatcher

EMAILS = [
    {
        "folder": "10up_com",
        "recipient": "sales@10up.com",
        "subject": "Politico's clean perimeter / white-label retainer audits for 10up",
        "pdf": "politico_com_security_audit.pdf",
        "body": """Hi 10up team,

Ran a baseline perimeter audit across Politico Europe's stack recently—clean 100/100 across TLS, DNSSEC, and security headers. Given 10up's architecture on WordPress VIP, that clean sheet wasn't surprising.

The friction I hear constantly from enterprise agency directors is that non-technical client stakeholders take this baseline for granted. When retainer renewals come up, clients struggle to visualize the continuous infrastructure oversight you provide behind the scenes.

I built Orbit Security to solve that retainer defense problem. It runs automated monthly perimeter and hygiene audits across your client portfolio and generates co-branded, white-label executive PDFs. Agencies drop them directly into their monthly invoicing packages to justify $200–$500/mo maintenance retainers without pulling a senior engineer away from billable sprint work.

Open to seeing what a co-branded 10up sample audit looks like for your client rosters?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "humanmade_com",
        "recipient": "hello@humanmade.com",
        "subject": "RecipeTin Eats audit / client-facing retainer reports",
        "pdf": "recipetineats_com_security_audit.pdf",
        "body": """Hi Human Made team,

Loved the decoupled WordPress build you engineered for RecipeTin Eats—sustaining massive traffic surges with a 25% speed bump is serious engineering.

I ran an automated hygiene scan on recipetineats.com: 90/100 baseline. Only loose end on the perimeter was DMARC remaining on p=none (reporting mode), which leaves room for brand spoofing if their newsletter or transactional volume is scaling.

We built Orbit Security for high-caliber WordPress agencies managing ongoing client retainers. It runs recurring monthly audits across headers, DNS authentication, and perimeter hygiene, packaging the results into white-label, agency-branded PDFs. Your account leads can bundle them into monthly maintenance reports to tangibly anchor $250–$400/mo client care plans without consuming engineer billable hours.

Would you be opposed to checking out a white-label sample report formatted for Human Made?

Cheers,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "kota_co_uk",
        "recipient": "hello@kota.co.uk",
        "subject": "nutopia.com perimeter check + defending monthly web retainers",
        "pdf": "nutopia_com_security_audit.pdf",
        "body": """Hi KOTA team,

Nutopia's interactive motion portfolio is stunning—rare to see documentary production work presented with that level of sleek editorial finesse.

I ran a quick technical hygiene scan against nutopia.com: scored 80/100. The primary missing directive is HTTP Strict Transport Security (HSTS), which leaves browsers open to protocol downgrade attacks on initial load. A 2-minute Nginx/Cloudflare header rule resolves it.

We built Orbit Security specifically so design and digital agencies can productize technical care without eating up dev hours. Orbit automatically tracks your client sites and generates clean, white-label monthly audit PDFs that prove ongoing maintenance and security posture—giving clients tangible proof of work to justify £150–£350/mo retainers.

Could I send over a quick 1-page sample audit branded for KOTA to see if it fits your current client maintenance workflow?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "illustrate_digital",
        "recipient": "hello@illustrate.digital",
        "subject": "Foot Anstey perimeter / white-label compliance reports for retainers",
        "pdf": "footanstey_com_security_audit.pdf",
        "body": """Hi Illustrate team,

Clocking Foot Anstey as the fastest law firm site in the UK was a masterclass in enterprise WordPress performance optimization.

I ran an infrastructure scan on footanstey.com: 90/100. Performance and SSL hygiene are dialed in; the one item legal clients typically scrutinize is email domain protection—DMARC is still at p=none, meaning spoofed inbound emails aren't yet rejected at the gateway.

For law firms and corporate accounts on your digital growth retainers, security perception is paramount. Orbit Security automates monthly perimeter, header, and DNS audits, outputting white-label co-branded PDFs that demonstrate active compliance and maintenance oversight. It gives your team a tangible monthly deliverable that protects £200–£400/mo retainer margins without developer overhead.

Would you be open to seeing a sample white-label PDF audit to see if it adds value to your monthly client reporting?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "ctidigital_com",
        "recipient": "hello@ctidigital.com",
        "subject": "Donkey Sanctuary hosting hygiene / automating support retainer deliverables",
        "pdf": "thedonkeysanctuary_org_uk_security_audit.pdf",
        "body": """Hi CTI team,

Tracking your Drupal 10 architecture and managed hosting work for The Donkey Sanctuary—handling non-profit donation scaling on enterprise Drupal is solid engineering.

Ran an automated perimeter scan across thedonkeysanctuary.org.uk: 85/100. Clean stack, but HSTS (Strict-Transport-Security) is currently absent in the response headers. For a high-traffic charity processing donations, enforcing transport layer security at the header level prevents man-in-the-middle downgrades.

For managed hosting and support retainers, clients often struggle to understand what "ongoing infrastructure maintenance" means month-to-month. Orbit Security monitors your portfolio and generates white-label, co-branded security and hygiene reports automatically. It provides your account managers with an executive deliverable that validates your ongoing retainers without taking dev time.

Open to checking out a sample audit PDF formatted with CTI Digital's branding?

Regards,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "propeller_co_uk",
        "recipient": "info@propeller.co.uk",
        "subject": "Cotswolds Distillery D2C perimeter / defending Shopify retainer margins",
        "pdf": "cotswoldsdistillery_com_security_audit.pdf",
        "body": """Hi Propeller team,

The Shopify D2C build and tour booking integration you rolled out for Cotswolds Distillery is top-tier commerce work.

Ran a quick perimeter check on cotswoldsdistillery.com: scored 90/100. The storefront configuration is tight; the one gap is that DMARC remains on p=none. With customer accounts, order receipts, and tour confirmations going out, moving toward p=quarantine protects their domain reputation from phishing lookalikes.

Most e-commerce agencies we work with find that Shopify clients question maintenance retainers because "Shopify handles hosting." Orbit automates monthly perimeter, DNS, and header sweeps, packaging them into white-label monthly security and health PDFs. It gives your team tangible proof of work to anchor £150–£300/mo retainer tiers with zero dev drain.

Would you be opposed to seeing a co-branded sample report to see how other Shopify agencies use it?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "neverbland_com",
        "recipient": "hello@neverbland.com",
        "subject": "MOTH Drinks digital health / white-label retainers for NEVERBLAND",
        "pdf": "mothdrinks_com_security_audit.pdf",
        "body": """Hi NEVERBLAND team,

The brand identity and e-commerce design system you built for MOTH Drinks is easily one of the freshest D2C executions in the UK beverage space.

Ran a baseline security and health scan on mothdrinks.com: 90/100. Frontend performance and assets are pristine. The only notable perimeter item is DMARC remaining set to p=none, which leaves a fast-growing brand susceptible to brand impersonation over email.

Design and product studios often get dragged into retainer scope creep or have clients drop maintenance plans once a launch settles. We built Orbit Security to automatically monitor client perimeters and generate sleek, white-label monthly audit PDFs. It gives your accounts team a recurring, branded deliverable that protects £150–£300/mo client care retainers without burdening your engineers.

Worth sending over a sample PDF styled with NEVERBLAND branding to see if it fits your post-launch workflow?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "alley_com",
        "recipient": "info@alley.com",
        "subject": "Chicago Sun-Times publishing hygiene / publisher retainer reports",
        "pdf": "suntimes_com_security_audit.pdf",
        "body": """Hi Alley team,

Long-time admirer of Alley's high-throughput publishing engineering—your work keeping the Chicago Sun-Times resilient under heavy newsroom cycles is premier CMS work.

Ran an automated infrastructure hygiene sweep across suntimes.com: 80/100. While the news delivery infrastructure is resilient, their primary domain DMARC record is still in monitoring mode (p=none). For an authoritative metro news organization, an unprotected email domain is a prime target for journalist impersonation and phishing.

For publishing agencies managing ongoing SLA and retainers, newsroom boards frequently scrutinize recurring tech spend. Orbit Security automates monthly perimeter, DNS, and header audits, outputting white-label executive summary PDFs. It equips your client leads with continuous evidence of infrastructure oversight, defending $250–$500/mo retainers without taking dev hours off product roadmaps.

Could I send you a 1-page sample audit co-branded for Alley to see if it would streamline your publisher client reporting?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "tri_be",
        "recipient": "hello@tri.be",
        "subject": "littleleague.org infrastructure / automated retainer audits for Modern Tribe",
        "pdf": "littleleague_org_security_audit.pdf",
        "body": """Hi Modern Tribe team,

Centralizing the digital ecosystem for Little League was a massive undertaking—managing multi-tier navigation and community event hubs across that footprint requires serious architectural discipline.

I ran an automated perimeter scan across littleleague.org: scored 80/100. Core CDN and server infrastructure look solid, but the HSTS header is missing on responses. Given the youth sports registrations and parent traffic flowing through that ecosystem, enforcing strict HTTPS at the browser level via HSTS is a recommended hardening step.

I built Orbit Security to help enterprise WordPress and digital agencies defend their ongoing maintenance retainers ($200–$500/mo). Orbit continuously runs hygiene sweeps and compiles white-label, agency-branded monthly audit reports. Your client partners get a tangible, boardroom-ready deliverable that proves ongoing site health without dev teams writing manual reports.

Would you be open to reviewing a sample white-label PDF audit to see if it aligns with your client support retainers?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "rtcamp_com",
        "recipient": "sales@rtcamp.com",
        "subject": "Ready Logistics VIP stack / white-label retainer deliverables for rtCamp",
        "pdf": "readylogistics_com_security_audit.pdf",
        "body": """Hi rtCamp team,

Consolidating 8 Cox Automotive brands onto WordPress VIP and wiring Gravity Forms into Salesforce for Ready Logistics (+49% lead velocity) was a clinic in enterprise WordPress integration.

Ran an infrastructure perimeter audit across readylogistics.com: 80/100. VIP hosting performance is spotless; the primary item flagged was the absence of the HSTS response header. On a high-value B2B logistics site capturing enterprise automotive leads, HSTS eliminates the window for protocol downgrade attacks.

Enterprise clients on ongoing maintenance retainers often question monthly bills if there are no new feature requests. Orbit Security generates automated, white-label monthly PDF audits covering security headers, SSL, and DNS hygiene under rtCamp's branding. It gives your accounts team a tangible monthly deliverable justifying $250–$500/mo enterprise care plans without consuming engineer hours.

Open to taking a look at a sample co-branded audit formatted for rtCamp?

Cheers,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "impressiondigital_com",
        "recipient": "hello@impressiondigital.com",
        "subject": "Abigail Ahern digital health / client retention deliverables for Impression",
        "pdf": "abigailahern_com_security_audit.pdf",
        "body": """Hi Impression team,

Driving +179% revenue growth for Abigail Ahern was exceptional work—bridging technical SEO and high-intent paid media at that level of luxury e-commerce scale is tough to pull off.

I ran a quick digital hygiene scan on abigailahern.com: 90/100. Core vitals and security baseline are strong; the only item flagged was DMARC set to p=none. For an e-commerce brand generating substantial transactional revenue, tightening email authentication prevents bad actors from phishing their luxury customer base.

Growth and digital agencies frequently tell us that retaining clients on monthly technical retainers requires constant proof of vigilance beyond standard Google Analytics screenshots. Orbit Security generates monthly white-label security and technical health PDFs under Impression's brand. It gives your strategists a concrete monthly asset to protect £150–£350/mo retainers with zero engineering overhead.

Would it be worth sending over a sample co-branded audit PDF to see how it looks?

Best,
Carson
Founder & Software Engineer, Orbit Security
https://cmfh009.github.io/Orbit-Security/"""
    }
]

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "outbound_campaigns"))
    dispatcher = EmailDispatcher()

    print("[*] Applying critic-approved rewrites and regenerating EML draft packages...")
    for item in EMAILS:
        out_dir = os.path.join(root, item["folder"])
        os.makedirs(out_dir, exist_ok=True)

        txt_path = os.path.join(out_dir, "pitch_email.txt")
        eml_path = os.path.join(out_dir, "pitch_email.eml")
        pdf_path = os.path.join(out_dir, item["pdf"])

        full_txt = f"Subject: {item['subject']}\n\n{item['body']}\n"
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(full_txt)

        if not os.path.exists(pdf_path):
            print(f"[!] Warning: PDF not found: {pdf_path}")

        dispatcher.export_eml(
            recipient_email=item["recipient"],
            subject=item["subject"],
            body_text=item["body"],
            pdf_attachment_path=pdf_path if os.path.exists(pdf_path) else None,
            output_eml_path=eml_path
        )
        print(f"[✓] Updated {item['folder']}: {item['subject']}")

    print("\n[✔] All 11 Cohort 4 agencies successfully refreshed with peer-to-peer copy!")

if __name__ == "__main__":
    main()
