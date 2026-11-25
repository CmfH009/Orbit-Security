/**
 * Simple Cat Static Data Module (Dictionary, Contextual Quips, Guided Tour Routes, Arcade Threat Specs)
 * Extracted from simple_cat.js; must be loaded before simple_cat.js.
 */
(function () {
    'use strict';

    const DICTIONARY = {
        dmarc: {
            title: "DMARC: The VIP Bouncer",
            tag: "EMAIL SPOOFING SHIELD",
            acronym: "Domain-based Message Authentication, Reporting, and Conformance",
            acronymBreakdown: [
                { term: "Domain-based", meaning: "Tied directly to your actual web address (e.g. youragency.com)." },
                { term: "Message Authentication", meaning: "Proving an email really came from you, not an imposter sitting in a basement." },
                { term: "Reporting", meaning: "Sending you daily secret notes about anyone on earth who tried to send fake mail with your name." },
                { term: "Conformance", meaning: "Giving strict orders to Gmail and Outlook: 'If an email fails our test, throw it in the trash!'" }
            ],
            analogy: "Imagine you own a high-end luxury nightclub. Anyone can buy a $2 nametag that says 'STAFF: YOUR COMPANY' and try to walk through the front door. Without DMARC, Gmail and Apple Mail let them right inside to talk to your clients! With DMARC configured to 'p=reject', you have an 8-foot-tall bouncer at the door who checks their ID against your official guest list. If they're fake, the bouncer tackles them and throws them in the alley.",
            walletRisk: "Without DMARC, scammers can send fake billing invoices or wire requests directly from 'ceo@yourdomain.com'. When a client wires $50,000 to a criminal because the email looked 100% genuine, your agency takes the blame and loses the client forever.",
            howToFix: "It takes 2 minutes: Add a single TXT record to your domain registrar (GoDaddy, Cloudflare, Namecheap) with 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'. Orbit scans this daily to make sure your bouncer never falls asleep."
        },
        spf: {
            title: "SPF: The VIP Guest List",
            tag: "MAIL SENDER VERIFICATION",
            acronym: "Sender Policy Framework",
            acronymBreakdown: [
                { term: "Sender", meaning: "The person or company sending the email." },
                { term: "Policy", meaning: "Your official house rules on who is authorized." },
                { term: "Framework", meaning: "The universal agreement that all mail servers worldwide follow." }
            ],
            analogy: "Think of SPF as the official VIP guest list posted outside your venue. You tell Google, Microsoft, and Yahoo: 'Only these 3 computer servers (e.g. Google Workspace, Mailchimp, and our website server) are allowed to speak for us.' When an email arrives at a client's inbox, their server checks your public guest list. If the sending computer isn't on the list, the email gets tossed into the spam dumpster.",
            walletRisk: "If your SPF is missing or has a typo, Google and Yahoo will mark even your REAL client proposals and invoice emails as spam. Your emails vanish into junk folders, deals stall, and clients wonder why you stopped replying.",
            howToFix: "Add a simple TXT record to your DNS: 'v=spf1 include:_spf.google.com ~all'. Orbit inspects your SPF records across all client domains to ensure your guest list never breaks."
        },
        dkim: {
            title: "DKIM: The Royal Wax Seal",
            tag: "CRYPTOGRAPHIC SEAL",
            acronym: "DomainKeys Identified Mail",
            acronymBreakdown: [
                { term: "DomainKeys", meaning: "A unique digital cryptographic key registered to your domain." },
                { term: "Identified Mail", meaning: "Proof that the email wasn't opened, changed, or forged on its journey." }
            ],
            analogy: "Back in medieval times, kings stamped hot red wax with their signet ring onto every envelope. If an enemy spy intercepted the messenger and altered the king's orders, the wax seal would shatter! DKIM is a digital wax seal. When your server sends an email, it stamps it with a secret mathematical code. The recipient's mail provider checks the seal. If anyone tampered with a single word or link in transit, the seal breaks and the email is rejected.",
            walletRisk: "Along with SPF and DMARC, DKIM is the third leg of the email deliverability stool. Missing DKIM means failing Google's 2024+ bulk sender authentication rules, leading to spam-folder placement or rejected mail across major consumer inboxes.",
            howToFix: "Click 'Generate DKIM' inside Google Workspace or Microsoft 365, then paste the generated CNAME record into your DNS provider."
        },
        cname: {
            title: "Dangling CNAME: The Abandoned Locker",
            tag: "SUBDOMAIN TAKEOVER",
            acronym: "Canonical Name (CNAME) Pointer",
            acronymBreakdown: [
                { term: "Canonical Name (CNAME)", meaning: "A forwarding address in the internet's phonebook (e.g., 'shop.mybrand.com points to stores.shopify.com')." },
                { term: "Dangling", meaning: "The forwarding address points to an old account or service that was deleted or cancelled." },
                { term: "Takeover", meaning: "A bad guy claims that empty slot and takes complete control of your official website address." }
            ],
            analogy: "Imagine you rented Locker #42 at the train station and put a forwarding notice: 'All my packages should go to Locker #42.' Later, you stop paying for the locker and walk away, but forget to remove the forwarding notice! A teenage hacker walks by, pays $5 to rent Locker #42, and now all your incoming packages and secret letters go straight into their hands. On the web, if your DNS points 'promo.yourclient.com' to an old cancelled Shopify or Unbounce page, a hacker can register that exact name in 30 seconds and control your client's official domain!",
            walletRisk: "Attackers use hijacked subdomains to put up fake credit card checkout forms, spread malware, or post illicit content on your client's trusted domain. It can trigger Google Safe Browsing blacklists and destroy an agency's retainer relationship overnight.",
            howToFix: "Regularly audit all DNS records. If a SaaS service (Unbounce, Webflow, Shopify, GitHub) is no longer active, immediately delete the CNAME pointer from DNS. Orbit checks 52 provider signatures across 76 CNAME fingerprints to flag dangling pointers automatically."
        },
        hsts: {
            title: "HSTS: The Armored Truck",
            tag: "ENCRYPTED TRANSPORT",
            acronym: "HTTP Strict Transport Security",
            acronymBreakdown: [
                { term: "HTTP", meaning: "The old, unencrypted way websites communicated (plain text in the clear)." },
                { term: "Strict", meaning: "Zero exceptions allowed—no falling back to unsafe connections." },
                { term: "Transport Security", meaning: "Locking down the entire road between the visitor and the web server." }
            ],
            analogy: "Normal websites without HSTS are like driving in an open convertible car. If you log into your account while sitting on public airport or coffee shop WiFi, anyone with a laptop and free software can peek into the car and snatch your passwords and cookies! HSTS tells every browser: 'Never, ever use old unencrypted HTTP. Always put all visitors into a bulletproof armored truck with tinted windows (HTTPS).' Even if someone types http://, the browser forces encrypted https:// before sending a single byte.",
            walletRisk: "Without HSTS, visitors on public WiFi are vulnerable to 'SSL Strip' attacks where attackers steal session cookies, hijack client accounts, and scrape customer checkout data.",
            howToFix: "Add a single header to your web server or Cloudflare configuration: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. Orbit audits your HSTS age and preload status automatically."
        },
        doh: {
            title: "DoH: The Secret Envelope",
            tag: "ENCRYPTED RESOLUTION",
            acronym: "DNS-over-HTTPS (RFC 8484)",
            acronymBreakdown: [
                { term: "DNS (Domain Name System)", meaning: "The internet's phonebook that translates names like 'google.com' into numeric computer IP addresses." },
                { term: "over-HTTPS", meaning: "Sending phonebook lookups inside an encrypted, tamper-proof envelope." }
            ],
            analogy: "Standard DNS is like standing in the middle of a crowded mall and shouting: 'Hey operator, what is the address for my secret doctor?!' Everyone in the mall hears who you are looking for—including your Internet Service Provider (ISP), coffee shop snoopers, and government censors. DoH writes your query on a card, seals it in an armored lockbox, and hands it directly to a trusted provider like Cloudflare. Orbit runs DoH 100% inside your browser so you can scan client domains without our servers ever logging your lookups.",
            walletRisk: "Plaintext DNS allows rogue WiFi routers or malicious ISPs to redirect your visitors to clone phishing sites without anyone noticing.",
            howToFix: "Modern browsers (Chrome, Firefox, Safari) support DoH natively. Orbit uses RFC 8484 DoH endpoints to conduct passive, zero-server perimeter reconnaissance with zero privacy leakage."
        },
        headers: {
            title: "OWASP Headers: The Digital Deadbolts",
            tag: "SECURITY DIRECTIVES",
            acronym: "Open Web Application Security Project (OWASP) HTTP Headers",
            acronymBreakdown: [
                { term: "OWASP", meaning: "The worldwide non-profit cybersecurity organization that defines the gold standard for web safety." },
                { term: "HTTP Headers", meaning: "Invisible instructions your web server whispers to the browser before showing the page." }
            ],
            analogy: "When someone visits your website, your server whispers a checklist of safety rules to their browser. For example: 'Never allow our site to be placed inside an invisible glass iframe on another site' (stops clickjacking), or 'Don't let sneaky files pretend to be pictures when they are actually executable viruses' (nosniff). Think of OWASP headers as the deadbolts, window latches, and peepholes on your front door. Without them, your house looks fine from the curb, but the windows are unlocked.",
            walletRisk: "Missing headers leave ecommerce sites open to clickjacking (stealing clicks to buy products without user knowledge), cross-site scripting (XSS), and content sniffing.",
            howToFix: "Configure your CDN (Cloudflare Rules) or web server (Nginx/Apache) to return the 7 core OWASP headers: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Content-Security-Policy, and Cross-Origin policies."
        },
        drift: {
            title: "Perimeter Drift: The Forgotten Promo",
            tag: "ATTACK SURFACE DECAY",
            acronym: "DNS & Attack Surface Drift",
            acronymBreakdown: [
                { term: "Perimeter", meaning: "The outer fence of all subdomains, servers, and services your agency manages." },
                { term: "Drift", meaning: "The gradual, unnoticed decay over time as settings age and people forget what was created." }
            ],
            analogy: "Remember that landing page your marketing team spun up two Black Fridays ago for a seasonal contest? The developer created 'blackfriday.client.com'. The holiday ended, the marketing manager switched jobs, and the credit card expired. But the DNS record is STILL pointing out there! Over months and years, your client's web perimeter drifts like an abandoned boat with a loose anchor. Attackers rarely try to kick down the reinforced front door; they find the forgotten basement window.",
            walletRisk: "Forgotten, unmonitored subdomains and legacy staging servers are one of the most common ways attackers bypass hardened main sites. When one gets hacked, the agency is held responsible.",
            howToFix: "Schedule automated monthly perimeter scans with Orbit Fleet Sentinel. We continuously catalog every subdomain and alert you the second an unmaintained record appears."
        },
        csp: {
            title: "CSP: The House Rules for Code",
            tag: "SCRIPT WHITELISTING",
            acronym: "Content Security Policy",
            acronymBreakdown: [
                { term: "Content", meaning: "All scripts, images, styling sheets, and fonts loaded on your site." },
                { term: "Security Policy", meaning: "The strict whitelist of approved external services allowed to execute code." }
            ],
            analogy: "Imagine hosting a VIP gala and telling the security guards: 'Only people wearing a blue badge and carrying an official card from Google Analytics or Stripe are allowed to enter the kitchen.' That is CSP. If a sneaky cyber thief manages to inject a malicious credit-card skimming script into your comments or checkout page, the browser immediately blocks it because it isn't on your approved list of invited services.",
            walletRisk: "Without CSP, ecommerce stores are vulnerable to 'Magecart' attacks where invisible scripts siphon credit card numbers directly from checkout fields.",
            howToFix: "Define a Content-Security-Policy header listing your trusted script sources (e.g. 'script-src 'self' https://js.stripe.com'). Orbit tests your CSP coverage automatically."
        },
        bimi: {
            title: "BIMI: The Verified Checkmark",
            tag: "INBOX TRUST BADGE",
            acronym: "Brand Indicators for Message Identification",
            acronymBreakdown: [
                { term: "Brand Indicators", meaning: "Your official, verified vector company logo (SVG)." },
                { term: "Message Identification", meaning: "Proof that your brand genuinely sent the email." }
            ],
            analogy: "Ever notice how official emails from CNN, Apple, or Chase have their crisp company logo displayed right next to the subject line in Gmail and Apple Mail? That's BIMI! It's like Twitter's blue checkmark, but for your client's email inbox. To earn it, you must have 100% perfect DMARC and SPF policies.",
            walletRisk: "Without BIMI, emails show a generic grey circle letter. With BIMI, your verified brand logo appears beside your messages, reinforcing trust when sending proposals and invoices.",
            howToFix: "First, enforce DMARC with 'p=quarantine' or 'p=reject'. Next, host an SVG tiny-P/S logo and add a DNS TXT record for 'default._bimi.yourdomain.com'."
        },
        mta_sts: {
            title: "MTA-STS: The Tunnel Shield",
            tag: "ENCRYPTED ROUTE",
            acronym: "Mail Transfer Agent Strict Transport Security (RFC 8461)",
            acronymBreakdown: [
                { term: "Mail Transfer Agent (MTA)", meaning: "The big server computers that pass emails across the internet." },
                { term: "Strict Transport Security", meaning: "Forcing bulletproof encryption between mail providers." }
            ],
            analogy: "When an email leaves your Google server to travel to your client's Microsoft Outlook server, it passes through internet routers. Without MTA-STS, a rogue actor could trick the servers into downgrading to unencrypted text (STARTTLS stripping) and eavesdrop on private contracts. MTA-STS guarantees that the entire tunnel between Google and Microsoft is shielded with unbreakable encryption.",
            walletRisk: "Protects sensitive client contracts, non-disclosure agreements, and wire instructions from intermediate wiretapping.",
            howToFix: "Host an mta-sts.txt policy file over HTTPS and add a TXT DNS record for '_mta-sts.yourdomain.com'. Orbit verifies your mail route security automatically."
        },
        audit: {
            title: "Retainer Audit: The Monthly Passport",
            tag: "EXECUTIVE CLIENT PROOF",
            acronym: "White-Label Perimeter Security Stewardship",
            acronymBreakdown: [
                { term: "White-Label", meaning: "Branded with your agency's logo and color palette with zero mention of Orbit Security." },
                { term: "Executive Audit", meaning: "A clean, jargon-free 1-page report translating technical DNS health into business security." },
                { term: "Stewardship", meaning: "Proving your agency actively guards the client's perimeter 24/7 without pulling senior devs off billable sprints." }
            ],
            analogy: "When an architect builds a skyscraper, the building owner can't see the steel rebar deep inside the concrete. If the architect never sends an inspection report, the owner eventually asks: 'Why do we need building maintenance?' A monthly executive audit is like a certified structural safety certificate delivered to your client's desk on the 1st of every month. It proves their perimeter is locked tight, making your $250/mo retainer the easiest invoice they approve all year.",
            walletRisk: "Without tangible monthly deliverables, non-technical clients forget about invisible backend maintenance. When renewal time comes, they cut maintenance contracts because they don't see what they're paying for.",
            howToFix: "Activate Orbit Security, enter your agency name, and let automated executive PDF audits generate on the 1st of every month ready to deliver to your clients."
        },
        dnssec: {
            title: "DNSSEC: The Certified Notary",
            tag: "TAMPER-PROOF DNS ROUTING",
            acronym: "Domain Name System Security Extensions",
            acronymBreakdown: [
                { term: "Domain Name System (DNS)", meaning: "The global internet phonebook mapping domain names into computer IP numbers." },
                { term: "Security", meaning: "Cryptographic mathematical proof that lookup records were not forged or altered." },
                { term: "Extensions", meaning: "Modern upgrade layers added to legacy 1980s internet routing protocols." }
            ],
            analogy: "Imagine an impostor sneaks into the telephone company and replaces the phone number of Chase Bank with their own burner phone. When you dial Chase, the impostor answers and asks for your PIN! That is 'DNS Cache Poisoning'. Standard DNS lookups have zero signatures. DNSSEC is like having a licensed government notary stamp an embossed holographic seal onto every page of the phonebook. If a hacker tries to reroute your visitors to a clone website, the browser spots the missing seal and instantly refuses to load.",
            walletRisk: "Attackers poison DNS caches at coffee shops or ISPs to redirect your client's ecommerce checkout traffic to a replica phishing site. Customers enter credit cards, funds vanish, and your client faces severe fraud chargebacks, credential theft, and lasting brand damage.",
            howToFix: "It takes 2 minutes: Log into your domain registrar (Cloudflare, GoDaddy, Namecheap) and click 'Enable DNSSEC'. The registrar generates a DS record that links with your parent registry (.com / .io). Orbit scans your DS record status and cryptographic validation daily."
        },
        mx: {
            title: "MX Records: The Official Post Office Box",
            tag: "MAIL ROUTING ARCHITECTURE",
            acronym: "Mail Exchange (MX) DNS Resource Record",
            acronymBreakdown: [
                { term: "Mail", meaning: "All incoming client messages, contract proposals, invoices, and password reset codes." },
                { term: "Exchange", meaning: "The physical or cloud server designated to accept and process incoming mail." },
                { term: "Record", meaning: "The verified priority entry in your domain's public DNS database." }
            ],
            analogy: "Think of your domain as a company headquarters. An MX record is the official sign in the front lobby telling the postman: 'Deliver all incoming mail to Mailroom #3 (Google Workspace) on the 4th floor.' If your MX record has a typo, the postman dumps all your mail on the street or returns it to sender. Worse, if an old abandoned MX record from a cancelled email provider lingers in your DNS, malicious actors can hijack that abandoned inbox and read your private client emails!",
            walletRisk: "Misconfigured or dangling MX records cause 100% of incoming client leads, contracts, and urgent support tickets to bounce. Even worse, dangling mail servers allow attackers to receive password reset links for agency admin accounts.",
            howToFix: "Ensure your DNS has exactly one authoritative mail provider configured (e.g. priority '10 aspmx.l.google.com' or Microsoft 365) and delete all orphaned legacy mail server pointers. If the domain sends NO mail, configure an RFC 7505 Null-MX record ('. 0') to permanently prevent mail routing misuse. Orbit audits MX priority and dangling endpoints automatically."
        },
        subdomain: {
            title: "Subdomain Hijacking: The Guest House Squatter",
            tag: "UNAUTHORIZED DOMAIN ANNEXATION",
            acronym: "Subdomain Takeover via Orphaned DNS Delegation",
            acronymBreakdown: [
                { term: "Subdomain", meaning: "A prefix off your main domain (e.g., 'vip.yourclient.com' or 'beta.agency.com')." },
                { term: "Hijacking", meaning: "An unauthorized party seizing complete operational control of that address." },
                { term: "Takeover", meaning: "Serving malicious code, cookies, or forms directly under your client's trusted SSL padlock." }
            ],
            analogy: "Imagine you built a luxury guest house on your property, put a key under the mat, and rented it to a tenant on Airbnb. Six months later, the tenant moves out, but you never change the locks or take down the listing! A squatter moves into your guest house, throws wild parties, sells counterfeit goods on your lawn, and tells the neighbors they are your business partner. Because the guest house sits on your official land, everyone trusts them! In web security, if an old DNS record points to a deleted Webflow, AWS S3 bucket, Shopify store, or GitHub Page, an attacker can claim that bucket for $0 and host phishing attacks directly under your client's URL.",
            walletRisk: "Because hijacked subdomains inherit root domain cookies and carry the client's trusted SSL certificate, attackers steal authentication tokens, bypass Single Sign-On (SSO), and launch spear-phishing campaigns that bypass all corporate spam filters. Incident response, breach disclosure, and domain cleanup can quickly turn into a costly agency crisis.",
            howToFix: "Audit all DNS records quarterly or use continuous automated monitoring. When tearing down a landing page, marketing campaign, or staging site on AWS/Webflow/Shopify, delete the DNS CNAME record FIRST before deleting the cloud account. Orbit checks 52 provider signatures across 76 CNAME fingerprints on automated sweeps and alerts your team when an orphaned pointer appears."
        }
    };


    const PAGE_QUIPS = {
        index: [
            "Drop any domain into the DoH terminal—100% client-side, zero server logs! 🛰️",
            "Want the 60-second nickel tour? Hit 🗺️ Tour down on the Space Station dock!"
        ],
        labs: [
            "Welcome to Security Labs! 1,750+ CISA KEVs and 52 takeover signatures loaded locally. 🧪",
            "Click any node in the Subdomain Takeover tree to trace the exact DNS hijack path! 🎯"
        ],
        fleet: [
            "Multi-domain fleet audits export with WebCrypto SHA-256 integrity hashes! 🔐"
        ],
        audit: [
            "Every DNS check here resolves directly via RFC 8484 DoH—no proxy middleman! 🛡️"
        ],
        benchmark: [
            "All latency & coverage numbers here come straight from reproducible local runs! ⚡"
        ],
        portals: [
            "Agency sample portals show how co-branded white-label deliverables look for clients! 💼"
        ],
        about: [
            "Built sovereign and local-first from Missoula, MT—zero cloud bloat! 🚀"
        ]
    };

    const SECTION_QUIPS = {
        "audit-terminal": "Enter any domain above—DoH queries resolve right inside your browser tab! 🛰️",
        "sentinels": "Each sentinel watches a different perimeter layer: DNS, dangling CNAMEs, DMARC, and MX. 🛡️",
        "security-labs": "The Security Labs page packs KEV+EPSS radar, takeover PoCs, and batch fleet scoring! 🧪",
        "open-source-proof": "Plug Orbit-Security@v1 into GitHub Actions to stream SARIF 2.1.0 alerts straight to Code Scanning! ⚙️",
        "simple-cat": "Pick any acronym card below for a plain-English analogy clients actually get! 📖",
        "pricing": "Self-serve browser audits stay free—optional fleet tiers scale when agencies want automation. 💎",
        "kev-epss-radar": "CISA KEV + 30-day FIRST EPSS scores pre-joined for sub-5ms client-side search! 📡",
        "takeover-poc-playground": "52 cloud providers across 76 CNAME fingerprints—plus 1-click DNS cleanup commands! 🎯",
        "fleet-sentinel-cockpit": "Audit a whole client roster in one batch and sign the JSON export with WebCrypto SHA-256! 🔐"
    };


    const TOUR_STEPS = [
        {
            targetId: "audit-terminal",
            focusSelector: "#audit-terminal",
            align: "center",
            icon: "🛰️",
            label: "PASSIVE DOH RADAR",
            title: "1/7 🛰️ PASSIVE DOH RADAR",
            text: "RFC 8484 DNS-over-HTTPS audits run 100% inside your browser—zero backend storage, deterministic DMARC/SPF/CNAME grading, and instant co-branded PDFs.",
            btnText: "Next: 72s Video ➔"
        },
        {
            targetId: "product-walkthrough",
            focusSelector: "#explainer-player-card",
            align: "top",
            icon: "🎬",
            label: "72-SECOND WALKTHROUGH",
            title: "2/7 🎬 72-SECOND WALKTHROUGH",
            text: "Watch the studio briefing or jump straight to any chapter—browser DoH audits, co-branded PDFs, KEV + EPSS radar, takeover trees, and GitHub SARIF.",
            btnText: "Next: Sentinels ➔"
        },
        {
            targetId: "sentinels",
            focusSelector: "#sentinels > div",
            align: "top",
            icon: "🛡️",
            label: "AUTONOMOUS SENTINELS",
            title: "3/7 🛡️ AUTONOMOUS SENTINELS",
            text: "Passive sentinels continuously inspect DNS records, dangling CNAMEs, SPF deliverability, and DMARC spoofing before attackers strike.",
            btnText: "Next: Security Labs ➔"
        },
        {
            targetId: "security-labs",
            focusSelector: "#security-labs > div",
            align: "top",
            icon: "🧪",
            label: "INTERACTIVE SECURITY LABS",
            title: "4/7 🧪 INTERACTIVE SECURITY LABS",
            text: "Jump into client-side sandboxes for CISA KEV + EPSS prioritization, 52-provider Subdomain Takeover PoCs, and multi-domain Fleet scoring.",
            btnText: "Next: Simple Cat ➔"
        },
        {
            targetId: "simple-cat",
            focusSelector: "#simple-cat > div",
            align: "top",
            icon: "🐱",
            label: "SIMPLE CAT JARGON DECODER",
            title: "5/7 🐱 SIMPLE CAT JARGON DECODER",
            text: "Translates DMARC, DNSSEC, HSTS, and takeover risks into plain-English analogies that non-technical clients immediately understand.",
            btnText: "Next: CI/CD Proof ➔"
        },
        {
            targetId: "open-source-proof",
            focusSelector: "#open-source-proof > div",
            align: "top",
            icon: "⚙️",
            label: "OPEN-SOURCE & CI/CD PROOF",
            title: "6/7 ⚙️ OPEN-SOURCE & CI/CD PROOF",
            text: "Add CmfH009/Orbit-Security@v1 to GitHub Actions to emit SARIF 2.1.0 findings straight into GitHub Code Scanning, backed by reproducible benchmarks.",
            btnText: "Next: Pricing ➔"
        },
        {
            targetId: "pricing",
            focusSelector: "#pricing > div",
            align: "top",
            icon: "💎",
            label: "TRANSPARENT AGENCY PRICING",
            title: "7/7 💎 TRANSPARENT AGENCY PRICING",
            text: "Self-serve browser audits stay free forever—with straightforward optional fleet tiers when agencies want automated monitoring and white-label portals.",
            btnText: "🎉 Finish Tour!",
            actionLabel: "Continue Tour in Security Labs →",
            actionHref: "labs.html?tour=1"
        }
    ];

    const TOUR_ROUTES = {
        index: TOUR_STEPS,
        labs: [
            {
                targetId: "kev-epss-radar",
                focusSelector: "#kev-epss-radar > div",
                align: "top",
                icon: "📡",
                label: "CISA KEV + EPSS RADAR",
                title: "1/3 📡 CISA KEV + EPSS RADAR",
                text: "1,750+ Known Exploited Vulnerabilities pre-joined with FIRST 30-day EPSS weaponization scores—searchable in <5ms completely offline in-browser.",
                btnText: "Next: Takeover Lab ➔"
            },
            {
                targetId: "takeover-poc-playground",
                focusSelector: "#takeover-poc-playground",
                align: "top",
                icon: "🎯",
                label: "SUBDOMAIN TAKEOVER LAB",
                title: "2/3 🎯 SUBDOMAIN TAKEOVER LAB",
                text: "Simulate 52 cloud provider signatures across 76 CNAME fingerprints with an animated 5-node attack tree and copy-paste DNS remediation.",
                btnText: "Next: Fleet Portal ➔"
            },
            {
                targetId: "fleet-sentinel-cockpit",
                focusSelector: "#fleet-sentinel-cockpit",
                align: "top",
                icon: "🛰️",
                label: "ZERO-KNOWLEDGE FLEET",
                title: "3/3 🛰️ ZERO-KNOWLEDGE FLEET",
                text: "Audit multiple domains in one batch with WebCrypto SHA-256 signed JSON exports—zero domain lists ever leave your browser.",
                btnText: "🎉 Finish Labs Tour!",
                actionLabel: "Back to Main Radar →",
                actionHref: "index.html"
            }
        ]
    };


    const DEFENSE_THREAT_SPECS = [
        {
            type: 'cname',
            name: 'Dangling CNAME',
            payload: 'orphaned-promo.s3.aws',
            color: '#ef4444',
            symbol: '💀',
            speed: 1.15,
            hp: 1,
            pts: 100,
            radius: 18
        },
        {
            type: 'mx',
            name: 'Spoofed MX',
            payload: 'mail.fake-spoof.io',
            color: '#a855f7',
            symbol: '👾',
            speed: 1.25,
            hp: 1,
            pts: 120,
            radius: 18
        },
        {
            type: 'spf',
            name: 'SPF PermError',
            payload: 'spf.permerror.fail',
            color: '#f59e0b',
            symbol: '⚠️',
            speed: 1.05,
            hp: 1,
            pts: 90,
            radius: 18
        },
        {
            type: 's3',
            name: 'Abandoned S3 Bucket',
            payload: 's3.orphaned-leak.aws',
            color: '#06b6d4',
            symbol: '📡',
            speed: 1.20,
            hp: 1,
            pts: 110,
            radius: 18
        }
    ];


    window.OrbitSimpleCatData = {
        DICTIONARY,
        PAGE_QUIPS,
        SECTION_QUIPS,
        TOUR_STEPS,
        TOUR_ROUTES,
        DEFENSE_THREAT_SPECS,
    };
})();
