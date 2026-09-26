#!/usr/bin/env python3
"""Orbit Security: Autonomous Reconnect & Genuine Founder Follow-Up Engine.

Follows up with Cohorts 1-3 (the 15 agencies dispatched yesterday) with:
1. Radical candor: Carson stepping in personally as founder/engineer.
2. Macro shift: >50% of web traffic is autonomous AI bots probing perimeters 24/7.
3. Retainer defense: Co-branded white-label PDFs justifying $150-$350/mo care plans.
4. Direct founder access: Personal contact and low-friction 10-minute Zoom.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Dict, List

from orbit_security.mailer import EmailDispatcher

RECONNECT_EMAILS = [
    {
        "folder": "charleagency_com",
        "recipient": "hello@charleagency.com",
        "agency_name": "Charle Agency",
        "subject": "candykittens.co.uk & yesterday’s automated note",
        "body": """Hi Nic and the Charle team,

I’m stepping in directly because yesterday’s automated note sent from my system was way too stiff and template-heavy. That’s on me—I’m a software engineer and founder, not a professional cold outreach guy.

I’ve admired Charle’s bespoke Shopify Plus builds for a long time, especially the clean, high-conversion frontend work you did for Candy Kittens.

The reason I reached out isn't because Candy Kittens is broken—their core Shopify setup is pristine. It’s because the web landscape has shifted drastically over the past year: autonomous bots and AI scrapers now account for over 50% of all web traffic. These automated crawlers probe peripheral DNS records, third-party marketing tags, and dangling staging CNAMEs around the clock. If an orphaned promotional subdomain or email record drifts, malicious scanners catch it in seconds, and clients immediately question their agency’s oversight.

I built Orbit Security specifically to help agencies defend their $150–$350/mo maintenance retainers. It continuously monitors client perimeters and automatically generates white-label, co-branded security health PDFs that your account managers can send straight to clients—proving your ongoing vigilance without pulling senior developers away from billable design and build sprints.

Would you be open to seeing a sample white-label report run against one of your stores, or jumping on a quick 10-minute Zoom this week? Either way, keep up the fantastic work on Candy Kittens.

Best,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "commandc_com",
        "recipient": "info@commandc.com",
        "agency_name": "Command C",
        "subject": "Command C / edenbrothers.com (stepping in personally)",
        "body": """Hi team at Command C,

Dropping in directly to apologize for the note yesterday. It went out through an automated sequence and read like a generic SDR pitch—which is entirely on me. I’m a developer and founder, and I hate robotic cold emails as much as you do.

I’ve followed Command C’s work managing complex, high-SKU e-commerce architectures like Eden Brothers. When you manage thousands of plant and seed varieties with heavy seasonal traffic, the back-office integrations, search plugins, and third-party tools inevitably cause DNS sprawl.

Here’s the reality we’re seeing right now: autonomous bots and AI agents now drive more than half of all web traffic. They aren’t browsing—they’re running 24/7 automated scans sniffing out dangling CNAMEs, expired third-party pointers, and DNS drift. When an edge breaks or an orphaned record is exploited, the agency gets the frantic Sunday morning call.

I built Orbit Security to solve this for dev agencies without burning billable dev hours. Orbit passively tracks perimeter and DNS hygiene and produces clean, white-label co-branded monthly PDFs. It gives your clients tangible proof of proactive perimeter defense every month, justifying ongoing maintenance retainers ($150–$350/mo) without your engineers lifting a finger.

Could I send over a quick 2-page co-branded sample report for Eden Brothers, or grab 10 minutes on Zoom to show you how other dev agencies automate this?

Cheers,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "blubolt_com",
        "recipient": "hello@blubolt.com",
        "agency_name": "blubolt",
        "subject": "blubolt + snowdoniacheese.co.uk (a quick note from Carson)",
        "body": """Hi Leigh and the blubolt crew,

I wanted to follow up personally because yesterday's email felt like a standard automated marketing sequence. That was my mistake—I'm an engineer and founder building security tools for agencies, not an outreach bot.

blubolt’s work on Snowdonia Cheese Company is a textbook example of heritage DTC done right. For premium food and luxury gift brands, client trust and transactional integrity are everything.

With autonomous bots and automated scrapers now making up over 50% of all internet traffic, client perimeters face non-stop machine scrutiny. Bots probe mail records (SPF/DKIM/DMARC) and unlinked subdomains continuously. If an orphaned marketing CNAME or email vector is weaponized, the client’s reputation takes a hit, and retainers come under scrutiny.

We built Orbit Security to give Shopify Plus agencies an effortless way to protect client retainers. Orbit automates continuous perimeter surveillance and generates white-label, co-branded monthly audit reports. Your team can drop these directly into your monthly client reporting to justify $150–$350/mo retainers with zero developer time required.

Open to taking a look at a sample report for Snowdonia Cheese, or having a quick 10-minute chat this week?

Best regards,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "underwaterpistol_com",
        "recipient": "info@underwaterpistol.com",
        "agency_name": "Underwaterpistol",
        "subject": "brewteacompany.co.uk / yesterday's robotic note",
        "body": """Hi team Underwaterpistol,

I’m reaching out directly because yesterday’s automated note came across way too stiff and corporate. That’s my fault—I’m a software engineer and founder, and our automated sequence stripped out the genuine developer-to-agency context.

I’m a huge fan of UWP’s creative design ethos, especially the clean, punchy execution on Brew Tea Co.

For high-retention DTC brands like Brew Tea, domain hygiene and email deliverability are mission-critical. Right now, automated bot traffic accounts for more than 50% of the entire internet. AI scrapers and botnets continuously probe peripheral DNS entries, forgotten landing page subdomains, and mail configurations looking for vulnerabilities. When an orphaned record is flagged or spoofed, it threatens email open rates and client confidence.

Orbit Security monitors client perimeters silently in the background and generates agency-branded, white-label monthly audit PDFs. It gives your account managers concrete, visible proof of ongoing store protection to bundle into your monthly maintenance retainers ($150–$350/mo), without pulling your frontend developers off active design and CRO sprints.

Could I send you a 1-minute video breakdown or a sample white-label PDF for Brew Tea Co? Happy to jump on a quick 10-minute Zoom if you’re curious.

Best,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "matchboxdesigngroup_com",
        "recipient": "info@matchboxdesigngroup.com",
        "agency_name": "Matchbox Design Group",
        "subject": "blueprintcoffee.com & Matchbox care plans (direct from Carson)",
        "body": """Hi Cullen and the Matchbox team,

I’m writing to you personally to clear the air after yesterday’s automated note. It read like a canned sales pitch sent through a mailer tool, which is my mistake. I’m a software developer and founder, and I’d rather talk straight engineer-to-agency.

I love Matchbox’s digital work, especially the balance of e-commerce, roasting subscriptions, and cafe operations you built for Blueprint Coffee.

For regional hospitality and retail leaders, web stacks often juggle third-party POS connectors, subscription plugins, and marketing integrations. Today, over 50% of all internet traffic consists of autonomous bots and vulnerability scanners. These automated agents probe DNS records, stale staging subdomains, and drifting mail records 24 hours a day. When an unmonitored subdomain gets flagged, clients immediately question their monthly care plans.

Orbit Security was created to eliminate this headache. It runs continuous perimeter scans and automatically generates white-label, co-branded monthly PDF reports that Matchbox can drop straight into your $150–$350/mo client care plans. Your clients get documented proof that their perimeter is secured, and your developers don't have to spend unbillable hours running manual audits.

Would you be open to checking out a sample co-branded report for Blueprint Coffee, or grabbing a quick 10-minute call to see how it works?

Best,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "wholegraindigital_com",
        "recipient": "eat@wholegraindigital.com",
        "agency_name": "Wholegrain Digital",
        "subject": "climbingtrees.com / yesterday's automated email (stepping in personally)",
        "body": """Hi Tom and the Wholegrain team,

I wanted to step in personally following yesterday’s automated note. It was generated via a template that felt impersonal and overly corporate—the opposite of how I like to communicate. That’s on me; I’m a software engineer and founder, not a cold marketer.

I have immense respect for Wholegrain’s pioneering leadership in low-carbon web design, your B-Corp ethos, and your work on platforms like Climbing Trees.

There’s an angle to web sustainability that doesn’t get talked about enough: today, over 50% of global web traffic comes from autonomous bots and automated scrapers. Beyond the obvious security hazards (probing for DNS drift, dangling CNAMEs, and spoofable records), these relentless automated probes waste substantial server compute, inflate cloud energy consumption, and drive up carbon footprints across client infrastructures.

I built Orbit Security to monitor client perimeters continuously and efficiently. It auto-generates lightweight, white-label co-branded monthly security and perimeter reports. It allows ethical agencies like Wholegrain to reinforce your ongoing website care retainers ($150–$350/mo) with hard proof of perimeter defense, without consuming unnecessary developer hours or server resources.

Could I share a sample white-label PDF generated for Climbing Trees, or jump on a brief 10-minute Zoom call with you this week?

Warmly,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "mooveagency_com",
        "recipient": "info@mooveagency.com",
        "agency_name": "Moove Agency",
        "subject": "charityjob.co.uk & enterprise perimeter defense (from Carson)",
        "body": """Hi Ilona and the Moove leadership team,

Following up directly to apologize for yesterday’s automated email. It was dispatched via a system template that came across as stiff and robotic. As a developer and founder, I value direct, transparent peer conversations, so I wanted to reach out personally.

Moove’s engineering work on high-traffic, mission-critical platforms like CharityJob is top-tier. Powering the UK’s premier charity job platform requires serious scale, rock-solid data governance, and ironclad uptime.

With automated bot traffic now exceeding 50% of all internet activity, enterprise platforms face relentless probing. Automated scanners map subdomains, scan for DNS drift, and seek out dangling service records in seconds. On platforms handling sensitive CVs and applicant data, any perimeter vulnerability or spoofed domain reputation risks severe client trust and compliance fallout.

We built Orbit Security to help enterprise WordPress agencies safeguard their high-value client retainers. Orbit automates continuous edge and perimeter monitoring, generating white-label, co-branded monthly verification PDFs. Your client service directors can present these directly to non-profit boards and enterprise clients to prove active security hygiene, preserving your $200–$500/mo+ maintenance margins with zero dev overhead.

Would you be open to reviewing a co-branded sample report for CharityJob, or connecting on a quick 10-minute call this week?

Best regards,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "steadfastcollective_com",
        "recipient": "hello@steadfastcollective.com",
        "agency_name": "Steadfast Collective",
        "subject": "adoptium.net / apologies for yesterday's robotic note",
        "body": """Hi Pete and the Steadfast team,

I’m jumping in directly because yesterday’s automated note felt like a generic sales pitch. That’s on me—I’m an engineer and founder, and our outbound pipeline sent a template that didn't reflect who I am or how I operate.

I’ve followed Steadfast’s work building community applications and open-source infrastructure for years. Your contribution to Eclipse Adoptium is serious engineering—delivering high-performance OpenJDK binaries requires absolute infrastructure integrity.

When you operate in the developer tooling and open-source space, perimeter defense is non-negotiable. Autonomous bots and scrapers now represent over 50% of all internet traffic. They continuously scan mirrors, package infrastructure, DNS pointers, and mail records for unlinked CNAMEs or spoofable headers. If an open-source client suffers domain drift or hijacking, community trust evaporates overnight.

I developed Orbit Security to automate perimeter and DNS hygiene without draining engineering time. Orbit passively tracks perimeters and auto-generates white-label, co-branded monthly PDFs. It provides tangible, automated proof of maintenance for your retainers ($150–$350/mo) so your senior engineers stay focused on building software rather than running manual domain audits.

Can I send over a quick sample report run for Adoptium, or jump on a 10-minute Zoom call to share the architecture?

Cheers,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "tinyfrog_com",
        "recipient": "info@tinyfrog.com",
        "agency_name": "Tiny Frog Technologies",
        "subject": "definefinancial.com & Tiny Frog care plans (direct from Carson)",
        "body": """Hi Mikel and the Tiny Frog team,

Reaching out directly to apologize for yesterday's outreach. It went out through an automated template that sounded like a canned SDR script. That was my mistake—I’m a software engineer and founder, and I believe in honest, direct conversations.

Tiny Frog is renowned for having one of the most mature, disciplined WordPress Maintenance & Care Plan operations in the country. Your work with compliance-sensitive clients like Define Financial requires an exceptional level of diligence.

For wealth management firms and RIAs, regulatory scrutiny (SEC/FINRA) and client trust are paramount. Today, autonomous bots and automated scrapers account for more than 50% of all internet traffic. They scan 24/7 for DNS drift, email spoofing vulnerabilities (DMARC/SPF/DKIM), and orphaned subdomains. If a financial client's domain is exploited for phishing or suffers an unmonitored record breach, their practice—and the agency's care plan—faces immediate scrutiny.

Orbit Security was engineered specifically to augment agency care plans. It automatically monitors client perimeters and produces white-label, co-branded monthly security health PDFs. It provides concrete, client-facing evidence that validates your $150–$350/mo care plans, keeping financial clients confident without consuming your developers' billable hours.

Could I send over a sample white-label PDF formatted for Define Financial, or jump on a brief 10-minute Zoom with you this week?

Best regards,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "electriceye_io",
        "recipient": "info@electriceye.io",
        "agency_name": "Electric Eye",
        "subject": "giordanos.com & yesterday's automated email (Carson here)",
        "body": """Hey Chase and the Electric Eye crew,

I'm stepping in personally because yesterday’s automated note was way too stiff and felt like typical cold-outreach spam. That’s on me—I’m a developer and founder, and our sequence didn't represent how I communicate.

I listen to Honest Ecommerce and love Electric Eye's no-BS approach to scaled Shopify Plus brands. Managing the nationwide frozen shipping operation and DTC storefront for an institution like Giordano’s is serious business.

With omnichannel and high-order food brands, third-party logistics, marketing pixels, and campaign subdomains constantly expand. Meanwhile, autonomous bots and AI scrapers now generate over 50% of total web traffic. These automated scanners probe store infrastructure 24/7 for dangling CNAMEs, DNS drift, and spoofable email settings. When an unmonitored subdomain gets exploited or mail deliverability falters, clients immediately look to their agency.

I built Orbit Security so agencies don't have to waste expensive developer hours on manual security checks. Orbit runs continuous perimeter scans and outputs white-label, co-branded monthly PDFs. You can bundle them straight into your ongoing monthly retainers ($150–$350/mo) to show clients tangible proof of proactive store protection while your developers stay locked into revenue-generating CRO sprints.

Open to seeing a sample report for Giordano's, or hopping on a quick 10-minute Zoom this week?

Best,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "wemakewebsites_com",
        "recipient": "hello@wemakewebsites.com",
        "agency_name": "We Make Websites",
        "subject": "pangaia.com & yesterday's outreach note (direct from Carson)",
        "body": """Hi Alex and the WMW team,

I’m following up directly to apologize for yesterday’s automated note. It went out via an outbound template that sounded like a canned SDR pitch, which was a mistake on my part. As an engineer and founder, I value direct peer-to-peer technical conversations.

We Make Websites sets the gold standard for enterprise Shopify Plus builds, and PANGAIA’s global multi-currency, multi-region architecture is a prime example of your team's technical caliber.

When managing international flagships with sprawling CDNs, localized domains, and third-party SaaS integrations, perimeter creep is inevitable. Crucially, autonomous bots and AI crawlers now make up over 50% of all internet traffic. They scan global edge networks and DNS records around the clock, seeking out orphaned marketing subdomains, dangling CNAMEs, and mail configuration drift. In enterprise DTC, a compromised subdomain or spoofed domain reputation damages brand equity immediately.

Orbit Security was designed to give enterprise Shopify agencies automated perimeter governance. It monitors client domains continuously and generates sleek, white-label co-branded monthly PDF reports. Your account leads can present these during monthly and quarterly client reviews to justify high-tier maintenance retainers ($250–$500/mo+) without pulling senior developers off core build sprints.

Would you be open to taking a look at a sample report generated for PANGAIA, or jumping on a concise 10-minute Zoom this week?

Best,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "barrelny_com",
        "recipient": "info@barrelny.com",
        "agency_name": "Barrel",
        "subject": "hukitchen.com / yesterday's automated note (stepping in personally)",
        "body": """Hi Peter, Sei-Wook, and the Barrel team,

I wanted to step in personally because yesterday’s automated note came across like a generic sales pitch. That’s on me—I’m a software engineer and founder, and the automation didn't reflect the genuine respect I have for Barrel’s work.

Barrel’s reputation for scaling DTC brands through thoughtful retention and subscription design is unmatched, and your work on Hu Kitchen is a masterclass in CPG e-commerce.

For high-volume subscription brands, customer communication and email deliverability are the lifeblood of recurring revenue. Today, autonomous bots and scrapers drive over 50% of all web traffic, constantly probing for dangling marketing CNAMEs, DNS drift, and DMARC/SPF misconfigurations. When an abandoned promotional subdomain drifts or email spoofing occurs, customer trust takes a hit and retainers get questioned.

I built Orbit Security to help agencies safeguard recurring retainers ($150–$350/mo) with zero friction. Orbit monitors perimeters continuously and delivers white-label, co-branded monthly PDF reports that your retention leads can share directly with clients. It gives clients visual proof of security and DNS health without burning a single billable developer hour.

Could I send over a sample white-label PDF run for Hu Kitchen, or hop on a quick 10-minute Zoom call?

Best,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "eastsideco_com",
        "recipient": "info@eastsideco.com",
        "agency_name": "Eastside Co",
        "subject": "themillionroses.com & support retainers (from Carson)",
        "body": """Hi Jason and the Eastside Co team,

Reaching out directly to apologize for yesterday's outreach note. It was sent via an automated template that came across as robotic and impersonal. That’s my fault—I’m a software developer and founder, not a cold outreach marketer.

Eastside Co’s reputation as an elite Shopify Plus powerhouse is well earned, and the luxury gifting experience you built for The Million Roses is stunning.

In luxury e-commerce, brand protection is everything. High-ticket stores are prime targets for automated botnets, which now make up over 50% of all global web traffic. These automated scanners probe around the clock for DNS drift, abandoned third-party subdomains, and mail authentication gaps. If an unmonitored subdomain is hijacked for spoofing, the luxury brand’s reputation suffers immediate damage.

We built Orbit Security to fortify agency support and maintenance retainers. Orbit silently audits client perimeters 24/7 and generates co-branded, white-label monthly security reports. Your account managers can attach these directly to your monthly client invoices to reinforce $150–$350/mo+ care plans—proving proactive oversight with zero developer effort.

Would you be open to seeing a sample white-label report for The Million Roses, or chatting for 10 minutes on Zoom this week?

Cheers,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "swankyagency_com",
        "recipient": "hello@swankyagency.com",
        "agency_name": "Swanky",
        "subject": "wilkinson-sword.co.uk & enterprise governance (a note from Carson)",
        "body": """Hi Dan and the Swanky leadership team,

I’m stepping in personally following yesterday’s automated note. It went out through a generic system sequence that lacked the technical depth I prefer to bring to peer conversations. That’s on me, and I wanted to reach out directly as a software engineer and founder.

Swanky’s international enterprise work is stellar, and managing a household FMCG brand like Wilkinson Sword with recurring blade subscriptions requires rigorous technical standards.

When dealing with legacy global conglomerates, IT security governance is notoriously intense. Today, over 50% of all web traffic originates from autonomous bots and automated scrapers. These bots continuously probe regional subdomains, third-party tracking scripts, and DNS configurations. If an orphaned CNAME or email authentication record drifts on an affiliated domain, corporate IT raises alarms, putting agency retainers in jeopardy.

Orbit Security was engineered to solve this without bogging down your development team. It continuously monitors client perimeters and automatically generates white-label, co-branded monthly PDF reports. Your account directors can present these directly to corporate brand managers to substantiate monthly maintenance retainers ($150–$350/mo), proving ongoing vigilance without spending billable hours on manual audits.

Can I send over a sample white-label PDF generated for Wilkinson Sword, or grab 10 minutes on Zoom to walk through it?

Best regards,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    },
    {
        "folder": "domaineworldwide_com",
        "recipient": "hello@domaineworldwide.com",
        "agency_name": "Domaine",
        "subject": "rembeauty.com & headless edge security (direct from Carson)",
        "body": """Hi team Domaine,

I'm reaching out directly to apologize for yesterday’s outreach email. It was dispatched via an automated template that sounded like a canned SDR pitch. As a software engineer and founder, I prefer speaking straight developer-to-agency, so that mistake is entirely on me.

Domaine’s work at the intersection of high fashion, celebrity brands, and headless Shopify Plus architectures is unmatched. Handling the explosive, viral drop traffic for a brand like r.e.m. beauty demands serious edge engineering.

Headless architectures naturally decouple the frontend (Vercel/Cloudflare) from backend APIs (Shopify Plus, Sanity, Klaviyo), multiplying edge DNS records and third-party microservices. Meanwhile, autonomous bots and AI scrapers now account for over 50% of all web traffic—surging even higher during limited product drops. Automated bots probe decoupled endpoints and DNS perimeters continuously for dangling CNAMEs, cache drift, and spoofing vectors.

I created Orbit Security to give digital agencies effortless perimeter governance. Orbit runs continuous, passive monitoring across client perimeters and outputs elegant, white-label co-branded monthly PDF reports. Your team can drop these directly into your monthly client retainers ($200–$500/mo) to give executive stakeholders concrete peace of mind, without pulling your senior engineers off headless feature development.

Would you be open to reviewing a sample white-label audit for r.e.m. beauty, or jumping on a quick 10-minute Zoom this week?

Best,
Carson
Software Engineer & Founder, Orbit Security
carsonmail009@gmail.com
https://cmfh009.github.io/Orbit-Security/"""
    }
]


async def run_reconnect(send_live: bool = False):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "outbound_campaigns"))
    dispatcher = EmailDispatcher()

    print(f"[*] Staging Reconnect Follow-Up Packages for {len(RECONNECT_EMAILS)} agencies...")
    print(f"[*] Live Dispatch Enabled: {send_live}")

    for item in RECONNECT_EMAILS:
        out_dir = os.path.join(root, item["folder"])
        os.makedirs(out_dir, exist_ok=True)

        txt_path = os.path.join(out_dir, "reconnect_email.txt")
        eml_path = os.path.join(out_dir, "reconnect_email.eml")

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"Subject: {item['subject']}\n\n{item['body']}\n")

        dispatcher.export_eml(
            recipient_email=item["recipient"],
            subject=item["subject"],
            body_text=item["body"],
            pdf_attachment_path=None,
            output_eml_path=eml_path
        )
        print(f"  [✓] Staged Reconnect: {item['agency_name']} ({item['recipient']})")

        if send_live:
            if dispatcher.is_configured():
                dispatcher.send_email(
                    recipient_email=item["recipient"],
                    subject=item["subject"],
                    body_text=item["body"],
                    pdf_attachment_path=None
                )
                print(f"    [✔] Live email dispatched via Gmail SMTP to {item['recipient']}!")
                await asyncio.sleep(4.0)
            else:
                print(f"    [!] SMTP not configured in .env. Draft saved to {eml_path}.")

    print("\n[✔] Reconnect staging complete!")


def main():
    parser = argparse.ArgumentParser(description="Orbit Security Reconnect Campaign Dispatcher")
    parser.add_argument("--send", action="store_true", help="Send live emails via SMTP")
    args = parser.parse_args()
    asyncio.run(run_reconnect(send_live=args.send))


if __name__ == "__main__":
    main()
