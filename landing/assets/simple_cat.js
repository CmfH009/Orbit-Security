/**
 * Simple Cat (simple_cat.js)
 * 16-Bit Retro Arcade Companion, Plain-English Decoder & Cyber Background Engine
 * Created for Orbit Security (Founder: Carson Haynes @_arsoncode)
 */

(function () {
    // =========================================================================
    // 1. IN-DEPTH LAYMAN DICTIONARY & ACRONYM DECODER
    // =========================================================================
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
            walletRisk: "Along with SPF and DMARC, DKIM is the third leg of the email deliverability stool. Missing DKIM means failing Google's 2024+ bulk sender authentication rules, cutting your deliverability by up to 40%.",
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
            howToFix: "Regularly audit all DNS records. If a SaaS service (Unbounce, Webflow, Shopify, GitHub) is no longer active, immediately delete the CNAME pointer from DNS. Orbit scans 20+ SaaS platforms 24/7 to catch dangling pointers instantly."
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
            walletRisk: "Over 80% of security breaches happen on forgotten, unmonitored subdomains and legacy staging servers. When one gets hacked, the agency is held responsible.",
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
            walletRisk: "Without BIMI, emails show a generic grey circle letter. With BIMI, emails get up to 39% higher open rates and instill immediate confidence when sending proposals and invoices.",
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
        }
    };

    // =========================================================================
    // 2. RETRO 8-BIT WEB AUDIO SYNTHESIZER
    // =========================================================================
    let audioCtx = null;
    let soundEnabled = true;

    function getAudioContext() {
        if (!audioCtx) {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (AudioContext) {
                audioCtx = new AudioContext();
            }
        }
        if (audioCtx && audioCtx.state === 'suspended') {
            audioCtx.resume();
        }
        return audioCtx;
    }

    function playTone(freq, type, duration, delay = 0) {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = type;
            osc.frequency.setValueAtTime(freq, ctx.currentTime + delay);
            gain.gain.setValueAtTime(0.08, ctx.currentTime + delay);
            gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + delay + duration);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(ctx.currentTime + delay);
            osc.stop(ctx.currentTime + delay + duration);
        } catch (e) {
            // Audio blocked or not supported
        }
    }

    function playBlip() {
        playTone(587.33, 'square', 0.08); // D5
    }

    function playChirp() {
        playTone(659.25, 'square', 0.06); // E5
        playTone(880.00, 'square', 0.09, 0.05); // A5
    }

    function playPowerUp() {
        playTone(440.00, 'triangle', 0.08, 0.00); // A4
        playTone(554.37, 'triangle', 0.08, 0.07); // C#5
        playTone(659.25, 'triangle', 0.08, 0.14); // E5
        playTone(880.00, 'triangle', 0.18, 0.21); // A5
    }

    function playMeow() {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(440, now);
            osc.frequency.exponentialRampToValueAtTime(880, now + 0.12);
            osc.frequency.exponentialRampToValueAtTime(620, now + 0.32);

            gain.gain.setValueAtTime(0.001, now);
            gain.gain.linearRampToValueAtTime(0.12, now + 0.08);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.32);

            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.33);
        } catch (e) {}
    }

    function playPurr() {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;
            const carrier = ctx.createOscillator();
            const modulator = ctx.createOscillator();
            const modGain = ctx.createGain();
            const masterGain = ctx.createGain();

            modulator.frequency.value = 24;
            modGain.gain.value = 25;

            carrier.frequency.value = 75;
            carrier.type = 'triangle';

            modulator.connect(modGain);
            modGain.connect(carrier.frequency);

            masterGain.gain.setValueAtTime(0.001, now);
            masterGain.gain.linearRampToValueAtTime(0.08, now + 0.1);
            masterGain.gain.linearRampToValueAtTime(0.08, now + 0.5);
            masterGain.gain.exponentialRampToValueAtTime(0.0001, now + 0.7);

            carrier.connect(masterGain);
            masterGain.connect(ctx.destination);

            modulator.start(now);
            carrier.start(now);
            modulator.stop(now + 0.71);
            carrier.stop(now + 0.71);
        } catch (e) {}
    }

    function playLaser() {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(1200, now);
            osc.frequency.exponentialRampToValueAtTime(140, now + 0.12);

            gain.gain.setValueAtTime(0.09, now);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.12);

            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.13);
        } catch (e) {}
    }

    function playBoing() {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(240, now);
            osc.frequency.exponentialRampToValueAtTime(560, now + 0.08);
            osc.frequency.exponentialRampToValueAtTime(320, now + 0.18);

            gain.gain.setValueAtTime(0.08, now);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.18);

            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.19);
        } catch (e) {}
    }

    function playCoin() {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            playTone(987.77, 'square', 0.08, 0.00); // B5
            playTone(1318.51, 'square', 0.22, 0.08); // E6
        } catch (e) {}
    }

    function playHoverTick() {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(2400, now);
            gain.gain.setValueAtTime(0.015, now);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.012);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.015);
        } catch (e) {}
    }

    function playThruster() {
        if (!soundEnabled) return;
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;
            const bufferSize = Math.floor(ctx.sampleRate * 0.15);
            const buffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate);
            const data = buffer.getChannelData(0);
            for (let i = 0; i < bufferSize; i++) {
                data[i] = Math.random() * 2 - 1;
            }
            const noise = ctx.createBufferSource();
            noise.buffer = buffer;
            const filter = ctx.createBiquadFilter();
            filter.type = 'bandpass';
            filter.frequency.setValueAtTime(340, now);
            filter.frequency.linearRampToValueAtTime(180, now + 0.15);
            filter.Q.value = 3.0;

            const gain = ctx.createGain();
            gain.gain.setValueAtTime(0.035, now);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.15);

            noise.connect(filter);
            filter.connect(gain);
            gain.connect(ctx.destination);
            noise.start(now);
        } catch (e) {}
    }

    // =========================================================================
    // 3. PIXEL CAT & ASTRONAUT CAT SVG GENERATORS
    // =========================================================================
    function getPixelCatSVG(size = 40) {
        return `
        <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="image-rendering: pixelated; filter: drop-shadow(0 0 8px rgba(16,185,129,0.5));">
            <!-- Ears -->
            <path d="M4 3H7V6H4V3ZM17 3H20V6H17V3Z" fill="#10b981"/>
            <path d="M5 4H6V5H5V4ZM18 4H19V5H18V4Z" fill="#ec4899"/>
            <!-- Head -->
            <rect x="4" y="6" width="16" height="11" fill="#0f172a"/>
            <rect x="5" y="6" width="14" height="11" fill="#1e293b"/>
            <!-- Cyber Visor / Shades -->
            <rect x="5" y="9" width="14" height="3" fill="#06b6d4"/>
            <rect x="7" y="10" width="10" height="1" fill="#67e8f9"/>
            <!-- Cute Nose & Mouth -->
            <rect x="11" y="13" width="2" height="1" fill="#f43f5e"/>
            <rect x="10" y="14" width="1" height="1" fill="#cbd5e1"/>
            <rect x="13" y="14" width="1" height="1" fill="#cbd5e1"/>
            <rect x="11" y="15" width="2" height="1" fill="#cbd5e1"/>
            <!-- Whiskers -->
            <rect x="2" y="12" width="2" height="1" fill="#94a3b8"/>
            <rect x="20" y="12" width="2" height="1" fill="#94a3b8"/>
            <rect x="1" y="14" width="3" height="1" fill="#94a3b8"/>
            <rect x="20" y="14" width="3" height="1" fill="#94a3b8"/>
            <!-- Collar / Scarf -->
            <rect x="6" y="17" width="12" height="2" fill="#10b981"/>
            <rect x="11" y="18" width="2" height="2" fill="#fbbf24"/>
        </svg>`;
    }

    function getAstroCatSVG(size = 56) {
        return `
        <svg width="${size}" height="${size}" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" class="astro-cat-svg" style="filter: drop-shadow(0 0 12px rgba(16,185,129,0.5));">
            <!-- Jetpack Thruster Flames -->
            <g class="thruster-flames">
                <path class="flame-left" d="M19 50 Q21 62 23 50" fill="url(#flameGrad)" />
                <path class="flame-right" d="M41 50 Q43 62 45 50" fill="url(#flameGrad)" />
            </g>

            <!-- Jetpack Backpack -->
            <rect x="15" y="32" width="10" height="20" rx="3" fill="#0f172a" stroke="#10b981" stroke-width="1.5" />
            <rect x="39" y="32" width="10" height="20" rx="3" fill="#0f172a" stroke="#10b981" stroke-width="1.5" />
            <rect x="23" y="36" width="18" height="12" rx="2" fill="#1e293b" stroke="#334155" stroke-width="1" />
            <!-- Thruster Nozzles -->
            <polygon points="17,50 25,50 24,54 18,54" fill="#64748b" />
            <polygon points="39,50 47,50 46,54 40,54" fill="#64748b" />

            <!-- Space Suit Body -->
            <ellipse cx="32" cy="42" rx="13" ry="12" fill="#1e293b" stroke="#10b981" stroke-width="2" />
            <!-- Chest Mission Patch -->
            <rect x="28" y="37" width="8" height="5" rx="1" fill="#064e3b" stroke="#34d399" stroke-width="0.8" />
            <circle cx="32" cy="39.5" r="1.5" fill="#38bdf8" />
            <!-- Suit Paws -->
            <circle cx="21" cy="45" r="3.5" fill="#334155" stroke="#10b981" stroke-width="1.5" />
            <circle cx="43" cy="45" r="3.5" fill="#334155" stroke="#10b981" stroke-width="1.5" />

            <!-- Helmet Base Collar -->
            <ellipse cx="32" cy="31" rx="16" ry="5" fill="#0f172a" stroke="#10b981" stroke-width="2" />

            <!-- Helmet Ear Pods -->
            <path d="M17 18 L22 7 L27 15 Z" fill="#0f172a" stroke="#10b981" stroke-width="1.5" />
            <path d="M19 16 L22 10 L25 15 Z" fill="#ec4899" opacity="0.8" />
            <path d="M47 18 L42 7 L37 15 Z" fill="#0f172a" stroke="#10b981" stroke-width="1.5" />
            <path d="M45 16 L42 10 L39 15 Z" fill="#ec4899" opacity="0.8" />

            <!-- Glass Bubble Helmet -->
            <circle cx="32" cy="22" r="17" fill="url(#helmetGlass)" stroke="#38bdf8" stroke-width="2" />

            <!-- Cat Head Inside Helmet -->
            <ellipse cx="32" cy="23" rx="12" ry="10" fill="#090d16" />

            <!-- Cute Eyes -->
            <g class="cat-eyes">
                <ellipse cx="27" cy="22" rx="2.5" ry="3.5" fill="#10b981" />
                <circle cx="28" cy="21" r="1" fill="#ffffff" />
                <ellipse cx="37" cy="22" rx="2.5" ry="3.5" fill="#10b981" />
                <circle cx="38" cy="21" r="1" fill="#ffffff" />
            </g>

            <!-- Nose and Mouth -->
            <polygon points="31,25 33,25 32,26.5" fill="#f43f5e" />
            <path d="M30 27 Q32 28.5 34 27" stroke="#cbd5e1" stroke-width="0.8" fill="none" />

            <!-- Whiskers -->
            <line x1="22" y1="24" x2="17" y2="23" stroke="#94a3b8" stroke-width="0.8" opacity="0.8" />
            <line x1="22" y1="26" x2="17" y2="27" stroke="#94a3b8" stroke-width="0.8" opacity="0.8" />
            <line x1="42" y1="24" x2="47" y2="23" stroke="#94a3b8" stroke-width="0.8" opacity="0.8" />
            <line x1="42" y1="26" x2="47" y2="27" stroke="#94a3b8" stroke-width="0.8" opacity="0.8" />

            <!-- Glass Specular Highlight Curve -->
            <path d="M20 13 A15 15 0 0 1 41 12" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.65" />
            <circle cx="21" cy="15" r="1" fill="#ffffff" opacity="0.8" />

            <!-- Gradients -->
            <defs>
                <radialGradient id="helmetGlass" cx="30%" cy="30%" r="70%">
                    <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.35"/>
                    <stop offset="60%" stop-color="#0f172a" stop-opacity="0.6"/>
                    <stop offset="100%" stop-color="#020617" stop-opacity="0.9"/>
                </radialGradient>
                <linearGradient id="flameGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#38bdf8"/>
                    <stop offset="50%" stop-color="#f59e0b"/>
                    <stop offset="100%" stop-color="#ef4444" stop-opacity="0"/>
                </linearGradient>
            </defs>
        </svg>`;
    }

    // =========================================================================
    // 4. MULTI-TAB IN-DEPTH DIALOGUE MODAL
    // =========================================================================
    let currentActiveTab = 'story';
    let currentTermKey = 'dmarc';

    function buildModalHtml() {
        return `
        <div id="simple-cat-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 999999; align-items: center; justify-content: center; background-color: rgba(2, 6, 23, 0.88); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); padding: 1rem; box-sizing: border-box;">
            <div class="relative bg-slate-900 border-2 border-emerald-500 max-w-2xl w-full p-6 shadow-[0_0_50px_rgba(16,185,129,0.35)] rounded-2xl max-h-[90vh] flex flex-col" style="box-shadow: 6px 6px 0px #064e3b; margin: auto;">
                
                <!-- Close button -->
                <button id="cat-close-btn" class="absolute top-4 right-4 text-slate-400 hover:text-emerald-400 font-mono text-xl px-2.5 py-1 border border-slate-700 hover:border-emerald-500 rounded bg-slate-950 transition-colors cursor-pointer" title="Close (Esc)">✕</button>

                <!-- Header with pixel cat avatar and quick term switcher -->
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                    <div class="flex items-center gap-3.5">
                        <div id="cat-avatar-box" class="p-2 bg-slate-950 border border-emerald-500/40 rounded-xl animate-bounce flex-shrink-0" style="animation-duration: 2.2s;">
                            ${getPixelCatSVG(48)}
                        </div>
                        <div>
                            <div class="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[10px] font-bold uppercase tracking-wider mb-1">
                                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                <span id="cat-badge-tag">SIMPLE CAT // LEVEL 99 DECODER</span>
                            </div>
                            <h3 id="cat-dialog-title" class="text-xl font-extrabold text-white font-mono tracking-tight">Security Term</h3>
                        </div>
                    </div>

                    <!-- Quick Switcher Dropdown -->
                    <div class="flex items-center gap-2 self-stretch sm:self-auto">
                        <label for="cat-term-select" class="text-[10px] font-mono text-slate-400 uppercase">Topic:</label>
                        <select id="cat-term-select" class="bg-slate-950 border border-emerald-500/40 text-emerald-300 font-mono text-xs rounded px-2 py-1.5 focus:outline-none focus:border-emerald-400 cursor-pointer">
                            <option value="dmarc">DMARC (The Bouncer)</option>
                            <option value="spf">SPF (The Guest List)</option>
                            <option value="dkim">DKIM (The Wax Seal)</option>
                            <option value="cname">CNAME Takeover (The Locker)</option>
                            <option value="hsts">HSTS (The Armored Truck)</option>
                            <option value="doh">DoH (The Secret Envelope)</option>
                            <option value="headers">OWASP Headers (Deadbolts)</option>
                            <option value="drift">Perimeter Drift (Forgotten Promo)</option>
                            <option value="csp">CSP (The House Rules)</option>
                            <option value="bimi">BIMI (The Verified Badge)</option>
                            <option value="mta_sts">MTA-STS (The Tunnel Shield)</option>
                            <option value="audit">Retainer Audit (Monthly Proof)</option>
                        </select>
                    </div>
                </div>

                <!-- Navigation Tabs -->
                <div class="flex items-center gap-1.5 pt-4 pb-2 border-b border-slate-800 overflow-x-auto text-xs font-mono">
                    <button type="button" id="cat-tab-story" onclick="SimpleCat.switchTab('story')" class="px-3 py-1.5 rounded-t-lg border-b-2 font-bold transition-all cursor-pointer border-emerald-400 text-emerald-300 bg-emerald-500/10">
                        🐱 1. Layman Story
                    </button>
                    <button type="button" id="cat-tab-acronym" onclick="SimpleCat.switchTab('acronym')" class="px-3 py-1.5 rounded-t-lg border-b-2 font-bold transition-all cursor-pointer border-transparent text-slate-400 hover:text-white">
                        🔤 2. Letters Decoded
                    </button>
                    <button type="button" id="cat-tab-risk" onclick="SimpleCat.switchTab('risk')" class="px-3 py-1.5 rounded-t-lg border-b-2 font-bold transition-all cursor-pointer border-transparent text-slate-400 hover:text-white">
                        💥 3. Wallet Risk
                    </button>
                    <button type="button" id="cat-tab-fix" onclick="SimpleCat.switchTab('fix')" class="px-3 py-1.5 rounded-t-lg border-b-2 font-bold transition-all cursor-pointer border-transparent text-slate-400 hover:text-white">
                        🛠️ 4. The 2-Min Fix
                    </button>
                </div>

                <!-- Scrollable Tab Content Container -->
                <div class="py-4 overflow-y-auto flex-1 text-sm text-slate-300 leading-relaxed font-sans pr-1">
                    
                    <!-- Tab 1: Layman Story -->
                    <div id="pane-story" class="space-y-3">
                        <div class="p-3.5 bg-slate-950/80 rounded-xl border border-emerald-500/20">
                            <div class="text-xs font-mono text-emerald-400 uppercase tracking-widest mb-1.5 font-bold">
                                📖 The 5-Year-Old Explanation:
                            </div>
                            <p id="cat-dialog-analogy" class="text-slate-200 leading-relaxed"></p>
                        </div>
                    </div>

                    <!-- Tab 2: Letters Decoded -->
                    <div id="pane-acronym" class="space-y-3" style="display: none;">
                        <div class="p-3 bg-slate-950/80 rounded-xl border border-cyan-500/20">
                            <div class="text-xs font-mono text-cyan-400 uppercase tracking-widest mb-1 font-bold">
                                🔤 What the Crazy Acronym Stands For:
                            </div>
                            <div id="cat-dialog-full-acronym" class="text-base font-bold text-white font-mono mb-2"></div>
                            <div id="cat-dialog-acronym-list" class="space-y-2 mt-3 font-mono text-xs"></div>
                        </div>
                    </div>

                    <!-- Tab 3: Wallet Risk -->
                    <div id="pane-risk" class="space-y-3" style="display: none;">
                        <div class="p-3.5 bg-slate-950/80 rounded-xl border border-red-500/30">
                            <div class="text-xs font-mono text-red-400 uppercase tracking-widest mb-1.5 font-bold flex items-center gap-1.5">
                                <span>⚠️ Real-World Danger & Financial Loss:</span>
                            </div>
                            <p id="cat-dialog-risk" class="text-slate-200 leading-relaxed"></p>
                        </div>
                    </div>

                    <!-- Tab 4: Fix -->
                    <div id="pane-fix" class="space-y-3" style="display: none;">
                        <div class="p-3.5 bg-slate-950/80 rounded-xl border border-emerald-500/30">
                            <div class="text-xs font-mono text-emerald-400 uppercase tracking-widest mb-1.5 font-bold flex items-center gap-1.5">
                                <span>⚡ How It Gets Fixed in 2 Minutes:</span>
                            </div>
                            <p id="cat-dialog-fix" class="text-slate-200 leading-relaxed"></p>
                        </div>
                    </div>

                </div>

                <!-- Footer Controls -->
                <div class="pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
                    <span class="text-[11px] text-slate-500 hidden sm:inline">"Security explained so your creative clients actually get it."</span>
                    <button id="cat-got-it-btn" class="px-5 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs transition-all shadow-[0_0_15px_rgba(16,185,129,0.3)] cursor-pointer">
                        Got it! (Close)
                    </button>
                </div>

            </div>
        </div>
        `;
    }

    function renderActiveTab() {
        const tabs = ['story', 'acronym', 'risk', 'fix'];
        tabs.forEach(tab => {
            const btn = document.getElementById(`cat-tab-${tab}`);
            const pane = document.getElementById(`pane-${tab}`);
            if (!btn || !pane) return;

            if (tab === currentActiveTab) {
                btn.className = "px-3 py-1.5 rounded-t-lg border-b-2 font-bold transition-all cursor-pointer border-emerald-400 text-emerald-300 bg-emerald-500/10";
                pane.style.display = 'block';
            } else {
                btn.className = "px-3 py-1.5 rounded-t-lg border-b-2 font-bold transition-all cursor-pointer border-transparent text-slate-400 hover:text-white";
                pane.style.display = 'none';
            }
        });
    }

    function populateModalContent(termKey) {
        currentTermKey = termKey.toLowerCase();
        const data = DICTIONARY[currentTermKey] || DICTIONARY['dmarc'];

        document.getElementById("cat-badge-tag").innerText = `SIMPLE CAT // ${data.tag}`;
        document.getElementById("cat-dialog-title").innerText = data.title;
        document.getElementById("cat-dialog-analogy").innerText = data.analogy;
        document.getElementById("cat-dialog-full-acronym").innerText = data.acronym;
        document.getElementById("cat-dialog-risk").innerText = data.walletRisk;
        document.getElementById("cat-dialog-fix").innerText = data.howToFix;

        // Render acronym breakdown list
        const listEl = document.getElementById("cat-dialog-acronym-list");
        if (listEl) {
            listEl.innerHTML = data.acronymBreakdown.map(item => `
                <div class="p-2 rounded bg-slate-900 border border-slate-800">
                    <span class="text-emerald-400 font-bold">${item.term}:</span>
                    <span class="text-slate-300 ml-1 font-sans">${item.meaning}</span>
                </div>
            `).join("");
        }

        const selector = document.getElementById("cat-term-select");
        if (selector && selector.value !== currentTermKey) {
            selector.value = currentTermKey;
        }

        renderActiveTab();
    }

    function showSimpleCatDialog(termKey = 'dmarc') {
        playChirp();
        let modal = document.getElementById("simple-cat-modal");
        if (!modal) {
            document.body.insertAdjacentHTML('beforeend', buildModalHtml());
            modal = document.getElementById("simple-cat-modal");

            document.getElementById("cat-close-btn").addEventListener("click", hideSimpleCatDialog);
            document.getElementById("cat-got-it-btn").addEventListener("click", hideSimpleCatDialog);
            document.getElementById("cat-term-select").addEventListener("change", (e) => {
                playBlip();
                populateModalContent(e.target.value);
            });

            modal.addEventListener("click", (e) => {
                if (e.target === modal) {
                    hideSimpleCatDialog();
                }
            });

            window.addEventListener("keydown", (e) => {
                if (e.key === "Escape" && modal.style.display === "flex") {
                    hideSimpleCatDialog();
                }
            });
        }

        populateModalContent(termKey);
        modal.style.display = 'flex';
        modal.classList.add('cat-modal-open');
        modal.classList.remove('hidden');
    }

    function hideSimpleCatDialog() {
        playBlip();
        const modal = document.getElementById("simple-cat-modal");
        if (modal) {
            modal.style.display = 'none';
            modal.classList.remove('cat-modal-open');
            modal.classList.add('hidden');
        }
    }

    function switchTab(tabName) {
        playBlip();
        currentActiveTab = tabName;
        renderActiveTab();
    }

    // =========================================================================
    // 5. 16-BIT CYBER ARCADE BACKGROUND CANVAS & STARFIELD ENGINE
    // =========================================================================
    function initArcadeBackground() {
        if (document.getElementById("retro-arcade-canvas")) return;

        // Create canvas
        const canvas = document.createElement("canvas");
        canvas.id = "retro-arcade-canvas";
        canvas.className = "fixed inset-0 pointer-events-none";
        canvas.style.cssText = "position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none;";
        document.body.prepend(canvas);

        // Create scanlines overlay
        const scanlines = document.createElement("div");
        scanlines.id = "retro-scanlines";
        scanlines.className = "fixed inset-0 pointer-events-none";
        scanlines.style.cssText = "position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; pointer-events: none; opacity: 0.12; background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.45) 50%); background-size: 100% 4px;";
        document.body.prepend(scanlines);

        const ctx = canvas.getContext("2d");
        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;

        let bgGlowCanvas = null;
        function updateBgGlow() {
            bgGlowCanvas = document.createElement('canvas');
            bgGlowCanvas.width = width;
            bgGlowCanvas.height = height;
            const bCtx = bgGlowCanvas.getContext('2d');
            bCtx.fillStyle = '#060a16';
            bCtx.fillRect(0, 0, width, height);

            const grad1 = bCtx.createRadialGradient(width * 0.2, height * 0.25, 0, width * 0.2, height * 0.25, width * 0.5);
            grad1.addColorStop(0, 'rgba(16, 185, 129, 0.16)');
            grad1.addColorStop(1, 'transparent');
            bCtx.fillStyle = grad1;
            bCtx.fillRect(0, 0, width, height);

            const grad2 = bCtx.createRadialGradient(width * 0.8, height * 0.4, 0, width * 0.8, height * 0.4, width * 0.55);
            grad2.addColorStop(0, 'rgba(6, 182, 212, 0.16)');
            grad2.addColorStop(1, 'transparent');
            bCtx.fillStyle = grad2;
            bCtx.fillRect(0, 0, width, height);

            const grad3 = bCtx.createRadialGradient(width * 0.5, height * 0.8, 0, width * 0.5, height * 0.8, width * 0.65);
            grad3.addColorStop(0, 'rgba(168, 85, 247, 0.14)');
            grad3.addColorStop(1, 'transparent');
            bCtx.fillStyle = grad3;
            bCtx.fillRect(0, 0, width, height);
        }

        window.addEventListener("resize", () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
            initStars();
            updateBgGlow();
        });

        // Pixel Stars
        const starColors = ['#10b981', '#06b6d4', '#ec4899', '#fbbf24', '#ffffff'];
        let stars = [];

        function initStars() {
            stars = [];
            const starCount = Math.floor((width * height) / 8000);
            for (let i = 0; i < starCount; i++) {
                stars.push({
                    x: Math.random() * width,
                    y: Math.random() * height,
                    size: Math.random() < 0.15 ? 4 : (Math.random() < 0.45 ? 3 : 2),
                    isCross: Math.random() < 0.25,
                    color: starColors[Math.floor(Math.random() * starColors.length)],
                    speed: 0.2 + Math.random() * 0.6,
                    opacity: 0.4 + Math.random() * 0.6,
                    twinkleSpeed: 0.02 + Math.random() * 0.04
                });
            }
        }
        initStars();
        updateBgGlow();

        // Floating Cyber Data Glyphs
        let glyphs = [];
        const glyphChars = ['▲', '◆', '■', '01', 'CR:99', '1P', 'SEC', '★'];
        for (let g = 0; g < 16; g++) {
            glyphs.push({
                x: Math.random() * width,
                y: Math.random() * height,
                char: glyphChars[g % glyphChars.length],
                color: starColors[g % starColors.length],
                speed: 0.3 + Math.random() * 0.5,
                opacity: 0.25 + Math.random() * 0.4
            });
        }

        // Cyber Horizon Grid State
        let gridOffset = 0;

        function drawArcadeFrame() {
            if (document.hidden) {
                requestAnimationFrame(drawArcadeFrame);
                return;
            }

            // 1. Draw cached ambient space background (Zero per-frame gradient allocation!)
            if (bgGlowCanvas) {
                ctx.drawImage(bgGlowCanvas, 0, 0);
            } else {
                ctx.fillStyle = '#060a16';
                ctx.fillRect(0, 0, width, height);
            }

            // 2. Render Twinkling 16-Bit Pixel Stars (Optimized: Zero per-star shadowBlur)
            ctx.shadowBlur = 0;
            stars.forEach(star => {
                star.y += star.speed;
                if (star.y > height) {
                    star.y = 0;
                    star.x = Math.random() * width;
                }

                star.opacity += Math.sin(Date.now() * star.twinkleSpeed) * 0.015;
                const currentOpacity = Math.max(0.25, Math.min(1.0, star.opacity));

                ctx.fillStyle = star.color;
                ctx.globalAlpha = currentOpacity;

                const sx = Math.floor(star.x);
                const sy = Math.floor(star.y);

                if (star.isCross && star.size >= 3) {
                    ctx.fillRect(sx, sy, star.size, star.size);
                    ctx.fillRect(sx - 1, sy + 1, 1, 1);
                    ctx.fillRect(sx + star.size, sy + 1, 1, 1);
                    ctx.fillRect(sx + 1, sy - 1, 1, 1);
                    ctx.fillRect(sx + 1, sy + star.size, 1, 1);
                } else {
                    ctx.fillRect(sx, sy, star.size, star.size);
                }
            });

            // 3. Render Floating Cyber Data Glyphs
            ctx.font = '10px "Press Start 2P", monospace';
            glyphs.forEach(gl => {
                gl.y -= gl.speed;
                if (gl.y < -20) {
                    gl.y = height + 20;
                    gl.x = Math.random() * width;
                }
                ctx.fillStyle = gl.color;
                ctx.globalAlpha = gl.opacity;
                ctx.fillText(gl.char, Math.floor(gl.x), Math.floor(gl.y));
            });

            // 4. Render 3D Perspective Retro Cyber Grid Horizon (Stabilized - Zero Optical Illusion)
            ctx.globalAlpha = 1.0;
            const horizonY = height * 0.78;
            const vanishingX = Math.floor((document.documentElement.clientWidth || width) * 0.5);

            // Horizon Glow Beam with gentle ambient pulse
            const beamAlpha = 0.5 + Math.sin(Date.now() * 0.0015) * 0.2;
            ctx.strokeStyle = `rgba(16, 185, 129, ${beamAlpha})`;
            ctx.shadowBlur = 10;
            ctx.shadowColor = '#10b981';
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.moveTo(0, horizonY);
            ctx.lineTo(width, horizonY);
            ctx.stroke();

            // Perspective Vanishing Lines (Soft Cyan laser rays)
            ctx.strokeStyle = 'rgba(6, 182, 212, 0.20)';
            ctx.shadowBlur = 3;
            ctx.shadowColor = '#06b6d4';
            ctx.lineWidth = 1;
            const lineCount = 14;
            for (let i = -lineCount; i <= lineCount; i++) {
                const targetX = vanishingX + (i * (width / (lineCount * 0.9)));
                ctx.beginPath();
                ctx.moveTo(vanishingX, horizonY);
                ctx.lineTo(targetX, height);
                ctx.stroke();
            }

            // Moving Horizontal Depth Laser Lines (Forward Synthwave Motion)
            gridOffset = (gridOffset + 0.0035) % 1.0;
            const depthLines = 9;
            for (let d = 0; d <= depthLines; d++) {
                const progress = (d + gridOffset) / depthLines;
                if (progress <= 0.02 || progress > 1.0) continue;
                const lineY = horizonY + Math.pow(progress, 2.2) * (height - horizonY);
                if (lineY <= height) {
                    const lineAlpha = 0.06 + Math.pow(progress, 1.4) * 0.35;
                    ctx.strokeStyle = `rgba(16, 185, 129, ${lineAlpha})`;
                    ctx.shadowColor = '#10b981';
                    ctx.shadowBlur = 3 + progress * 6;
                    ctx.lineWidth = 1 + progress * 1.5;
                    ctx.beginPath();
                    ctx.moveTo(0, lineY);
                    ctx.lineTo(width, lineY);
                    ctx.stroke();
                }
            }

            // Reset shadows for next frame
            ctx.shadowBlur = 0;
            requestAnimationFrame(drawArcadeFrame);
        }

        requestAnimationFrame(drawArcadeFrame);
    }

    // =========================================================================
    // =========================================================================
    // 6. ASTRO-CAT ZERO-G COPILOT & INTERACTIVE PLAYGROUND
    // =========================================================================
    const QUIPS = [
        "Purr-fect! 0 dangling CNAMEs on my radar! 🐾",
        "DMARC p=reject is my personal blast shield! 🛡️",
        "Zero-G maneuver complete! Toss me again! 🚀",
        "80% of leaks hide in old Black Friday subdomains! ⚠️",
        "Click 🎯 LASER below to test my orbital thrusters!",
        "Click 👾 PATROL to zap rogue DNS threats!",
        "Monthly PDF audits make client retainers invincible! 💼",
        "HSTS forces armored HTTPS trucks for all visitors! 🚚",
        "DNS over HTTPS keeps your lookups 100% secret! 🔒"
    ];

    const copilot = {
        state: 'docked', // 'docked' | 'floating' | 'laser' | 'patrol'
        x: window.innerWidth - 180,
        y: window.innerHeight - 140,
        vx: 0,
        vy: 0,
        rot: 0,
        bobAngle: 0,
        isDragging: false,
        dragStartX: 0,
        dragStartY: 0,
        lastX: 0,
        lastY: 0,
        dragVx: 0,
        dragVy: 0,
        mouseX: window.innerWidth / 2,
        mouseY: window.innerHeight / 2,
        laserActive: false,
        patrolActive: false,
        patrolThreats: [],
        patrolScore: 0,
        speechTimer: null,
        sparks: []
    };

    let copilotEl = null;
    let dockEl = null;
    let laserDotEl = null;
    let fxCanvas = null;
    let fxCtx = null;

    function createAstroCatCopilot() {
        if (document.getElementById("astro-cat-copilot")) return;

        // 1. Effects Canvas for thruster sparks, lasers, and score popups
        fxCanvas = document.createElement("canvas");
        fxCanvas.id = "astro-fx-canvas";
        fxCanvas.style.cssText = "position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; pointer-events: none; z-index: 99980;";
        document.body.appendChild(fxCanvas);
        resizeFxCanvas();
        window.addEventListener("resize", resizeFxCanvas);

        // 2. Laser Target Reticle
        laserDotEl = document.createElement("div");
        laserDotEl.id = "astro-laser-dot";
        laserDotEl.className = "hidden";
        laserDotEl.innerHTML = `
            <div class="laser-ring"></div>
            <div class="laser-core"></div>
            <div class="laser-hint-pill">CLICK / ESC TO STOP</div>
        `;
        document.body.appendChild(laserDotEl);

        // 2b. 60fps Video Recorder Banner for X Clips
        const recBannerEl = document.createElement("div");
        recBannerEl.id = "orbit-rec-banner";
        recBannerEl.className = "fixed top-20 left-1/2 -translate-x-1/2 z-50 px-4 py-2 rounded-full bg-rose-950/95 border-2 border-rose-500 text-rose-200 font-mono text-xs flex items-center gap-3 shadow-[0_0_30px_rgba(244,63,94,0.6)] backdrop-blur-md hidden";
        recBannerEl.innerHTML = `
            <span class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span>
                <span class="font-bold text-rose-300">REC FOR X</span>
                <span id="orbit-rec-timer" class="px-1.5 py-0.5 rounded bg-black/60 text-white font-bold text-[10px]">00:00</span>
            </span>
            <button type="button" id="orbit-rec-finish-btn" class="px-3 py-1 rounded-full bg-rose-500 hover:bg-rose-400 text-slate-950 font-bold text-[10px] transition-all cursor-pointer shadow-sm">
                ⏹️ Save Clip
            </button>
        `;
        document.body.appendChild(recBannerEl);

        // 3. Independent Fixed Viewport Speech Bubble (Never tilts with cat, never clips off-screen)
        const bubbleEl = document.createElement("div");
        bubbleEl.id = "astro-speech-bubble";
        bubbleEl.className = "astro-bubble hidden";
        bubbleEl.innerHTML = `
            <div id="astro-bubble-tail" class="astro-bubble-tail-down"></div>
            <div class="astro-bubble-header">
                <span class="astro-bubble-title">ASTRO-CAT // COMMS</span>
                <button id="astro-bubble-close" class="astro-bubble-close" title="Dismiss">✕</button>
            </div>
            <div id="astro-bubble-text" class="astro-bubble-text">Mission ready! Toss me into zero-G! 🐾</div>
        `;
        document.body.appendChild(bubbleEl);

        // 4. Floating Zero-G Astro-Cat Element
        copilotEl = document.createElement("div");
        copilotEl.id = "astro-cat-copilot";
        copilotEl.className = "astro-cat-wrapper hidden";
        copilotEl.innerHTML = `
            <!-- Cat Figure Body (handles zero-G tilt & backflip) -->
            <div id="astro-cat-body" class="astro-cat-body" title="Click to Pet • Drag to Toss!">
                ${getAstroCatSVG(64)}
            </div>

            <!-- Floating Action HUD Menu (stays upright and readable) -->
            <div id="astro-cat-hud" class="astro-hud">
                <button type="button" id="hud-pet-btn" class="astro-hud-btn" title="Pet Astro-Cat">🐾 Pet</button>
                <button type="button" id="hud-laser-btn" class="astro-hud-btn" title="Laser Chase Mode">🎯 Laser</button>
                <button type="button" id="hud-patrol-btn" class="astro-hud-btn" title="Threat Patrol Mini-Game">👾 Patrol</button>
                <button type="button" id="hud-decode-btn" class="astro-hud-btn" title="Security Dictionary">📖 Decode</button>
                <button type="button" id="hud-dock-btn" class="astro-hud-btn" title="Park into Corner Dock">⚓ Dock</button>
            </div>
        `;
        document.body.appendChild(copilotEl);

        // 5. Corner Docking Station
        dockEl = document.createElement("div");
        dockEl.id = "simple-cat-dock";
        dockEl.className = "fixed bottom-5 right-5 sm:bottom-6 sm:right-6 z-50 flex items-center gap-2";
        dockEl.innerHTML = `
            <div class="px-3 py-2 bg-slate-900/95 border-2 border-emerald-500 rounded-xl shadow-[0_0_25px_rgba(16,185,129,0.35)] hover:border-emerald-400 transition-all flex items-center gap-2.5 backdrop-blur-md" style="box-shadow: 4px 4px 0px #064e3b;">
                <div class="relative flex-shrink-0 cursor-pointer" id="dock-avatar-btn">
                    ${getPixelCatSVG(32)}
                    <span class="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full animate-ping"></span>
                    <span class="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full border border-slate-900"></span>
                </div>
                <div class="flex flex-col text-left pr-0.5">
                    <div class="flex items-center gap-1.5">
                        <span class="text-[9px] font-arcade text-emerald-400 tracking-wider">ASTRO-CAT</span>
                        <span class="text-[8px] font-mono px-1 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">ONLINE</span>
                    </div>
                    <div class="flex items-center gap-2 mt-0.5 flex-wrap">
                        <button type="button" id="dock-launch-btn" class="text-[10px] font-mono font-bold text-emerald-400 hover:text-emerald-300 hover:underline flex items-center gap-0.5 cursor-pointer">
                            <span>🚀 Fly Zero-G</span>
                        </button>
                        <span class="text-slate-600 text-[10px]">•</span>
                        <button type="button" id="dock-decode-btn" class="text-[10px] font-mono text-slate-300 hover:text-white hover:underline cursor-pointer">
                            <span>📖 Jargon</span>
                        </button>
                        <span class="text-slate-600 text-[10px]">•</span>
                        <button type="button" id="dock-rec-btn" class="text-[10px] font-mono font-bold text-cyan-400 hover:text-cyan-300 hover:underline cursor-pointer flex items-center gap-1" title="Record 60fps gameplay clip directly for X (Twitter)">
                            <span>📹 Clip for X</span>
                        </button>
                        <button type="button" id="dock-laser-stop-btn" class="hidden text-[10px] font-mono font-bold text-rose-400 hover:text-rose-300 hover:underline cursor-pointer animate-pulse ml-0.5">
                            <span>🛑 Stop Laser</span>
                        </button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(dockEl);

        bindCopilotEvents();
        requestAnimationFrame(updateCopilotLoop);
    }

    function resizeFxCanvas() {
        if (!fxCanvas) return;
        fxCanvas.width = window.innerWidth;
        fxCanvas.height = window.innerHeight;
        fxCtx = fxCanvas.getContext('2d');
    }

    function bindCopilotEvents() {
        // Dock buttons
        document.getElementById("dock-launch-btn").addEventListener("click", () => {
            launchAstroCatIntoZeroG();
        });
        document.getElementById("dock-avatar-btn").addEventListener("click", () => {
            launchAstroCatIntoZeroG();
        });
        document.getElementById("dock-decode-btn").addEventListener("click", () => {
            showSimpleCatDialog("dmarc");
        });

        // Copilot HUD buttons
        const hudPet = document.getElementById("hud-pet-btn");
        if (hudPet) {
            hudPet.addEventListener("click", (e) => {
                e.stopPropagation();
                petAstroCat();
            });
        }
        const hudLaser = document.getElementById("hud-laser-btn");
        if (hudLaser) {
            hudLaser.addEventListener("click", (e) => {
                e.stopPropagation();
                toggleLaserChase();
            });
        }
        const hudPatrol = document.getElementById("hud-patrol-btn");
        if (hudPatrol) {
            hudPatrol.addEventListener("click", (e) => {
                e.stopPropagation();
                startSpacePatrol();
            });
        }
        const hudDecode = document.getElementById("hud-decode-btn");
        if (hudDecode) {
            hudDecode.addEventListener("click", (e) => {
                e.stopPropagation();
                showSimpleCatDialog("dmarc");
            });
        }
        const hudDock = document.getElementById("hud-dock-btn");
        if (hudDock) {
            hudDock.addEventListener("click", (e) => {
                e.stopPropagation();
                dockAstroCat();
            });
        }
        const bubbleClose = document.getElementById("astro-bubble-close");
        if (bubbleClose) {
            bubbleClose.addEventListener("click", (e) => {
                e.stopPropagation();
                hideSpeechBubble();
            });
        }

        const bubbleEl = document.getElementById("astro-speech-bubble");
        if (bubbleEl) {
            bubbleEl.addEventListener("mouseenter", () => {
                clearTimeout(copilot.speechTimer);
            });
            bubbleEl.addEventListener("mouseleave", () => {
                clearTimeout(copilot.speechTimer);
                copilot.speechTimer = setTimeout(() => {
                    hideSpeechBubble();
                }, 3500);
            });
        }

        // Rec Clip for X button
        const dockRecBtn = document.getElementById("dock-rec-btn");
        if (dockRecBtn) {
            dockRecBtn.addEventListener("click", () => {
                toggleScreenRecording();
            });
        }

        // Dock Stop Laser button
        const dockLaserStopBtn = document.getElementById("dock-laser-stop-btn");
        if (dockLaserStopBtn) {
            dockLaserStopBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                stopLaserChase();
            });
        }

        // Finish recording button on banner
        const recFinishBtn = document.getElementById("orbit-rec-finish-btn");
        if (recFinishBtn) {
            recFinishBtn.addEventListener("click", () => {
                stopScreenRecording();
            });
        }

        // Click ANYWHERE to disengage laser chase easily!
        window.addEventListener("pointerdown", (e) => {
            if (copilot.laserActive) {
                // If user clicks anywhere on the screen (except clicking the start laser button itself)
                if (!e.target.closest('#hud-laser-btn') && !e.target.closest('#dock-laser-stop-btn') && !e.target.closest('#simple-cat-modal')) {
                    stopLaserChase();
                }
            }
        }, true);

        // Escape or L key stops laser
        window.addEventListener("keydown", (e) => {
            if (e.key === "Escape" || e.key === "l" || e.key === "L") {
                if (copilot.laserActive) {
                    stopLaserChase();
                }
            }
        });

        // Pointer Drag & Toss Controls
        const catBody = document.getElementById("astro-cat-body");

        catBody.addEventListener("pointerdown", (e) => {
            if (copilot.state === 'docked') return;
            copilot.isDragging = true;
            catBody.setPointerCapture(e.pointerId);
            copilot.dragStartX = e.clientX;
            copilot.dragStartY = e.clientY;
            copilot.lastX = e.clientX;
            copilot.lastY = e.clientY;
            copilot.dragVx = 0;
            copilot.dragVy = 0;
            copilot.vx = 0;
            copilot.vy = 0;
            copilotEl.classList.add("grabbing");
            playThruster();
        });

        window.addEventListener("pointermove", (e) => {
            copilot.mouseX = e.clientX;
            copilot.mouseY = e.clientY;

            // Move Laser Reticle if active
            if (copilot.laserActive && laserDotEl) {
                laserDotEl.style.transform = `translate(${e.clientX - 12}px, ${e.clientY - 12}px)`;
            }

            if (!copilot.isDragging) return;

            const dx = e.clientX - copilot.lastX;
            const dy = e.clientY - copilot.lastY;
            copilot.dragVx = dx;
            copilot.dragVy = dy;
            copilot.x += dx;
            copilot.y += dy;
            copilot.lastX = e.clientX;
            copilot.lastY = e.clientY;

            // Emit dragging spark particles
            spawnSparks(copilot.x + 32, copilot.y + 54, 1, '#38bdf8');
        });

        const endDrag = (e) => {
            if (!copilot.isDragging) return;
            copilot.isDragging = false;
            copilotEl.classList.remove("grabbing");

            const totalDragDist = Math.hypot(e.clientX - copilot.dragStartX, e.clientY - copilot.dragStartY);

            if (totalDragDist < 5) {
                // Treated as click / pet!
                petAstroCat();
            } else {
                // Toss with momentum!
                copilot.vx = Math.max(-18, Math.min(18, copilot.dragVx * 0.9));
                copilot.vy = Math.max(-18, Math.min(18, copilot.dragVy * 0.9));
                copilot.rot += (copilot.dragVx * 3);
                playThruster();
                spawnSparks(copilot.x + 32, copilot.y + 54, 8, '#f59e0b');
            }
        };

        window.addEventListener("pointerup", endDrag);
        window.addEventListener("pointercancel", endDrag);
    }

    function launchAstroCatIntoZeroG() {
        copilot.state = 'floating';
        dockEl.classList.add("opacity-50", "hover:opacity-100");
        copilotEl.classList.remove("hidden");
        
        // Spawn smoothly above dock
        copilot.x = window.innerWidth - 180;
        copilot.y = window.innerHeight - 240;
        copilot.vx = -4.5;
        copilot.vy = -3.5;
        copilot.rot = -10;

        playPowerUp();
        playThruster();
        spawnSparks(copilot.x + 32, copilot.y + 54, 12, '#38bdf8');
        showSpeechBubble("Thrusters engaged! Drag & toss me around the screen! 🐾");
    }

    function dockAstroCat() {
        copilot.state = 'docked';
        copilot.laserActive = false;
        copilot.patrolActive = false;
        clearTimeout(copilot.laserAutoStopTimer);
        const dockLaserStop = document.getElementById("dock-laser-stop-btn");
        if (dockLaserStop) dockLaserStop.classList.add("hidden");
        const laserHudBtn = document.getElementById("hud-laser-btn");
        if (laserHudBtn) laserHudBtn.classList.remove("astro-hud-btn-active");
        if (laserDotEl) laserDotEl.classList.add("hidden");
        clearPatrolThreats();
        hideSpeechBubble();

        playBoing();
        copilotEl.classList.add("hidden");
        dockEl.classList.remove("opacity-50");
    }

    function petAstroCat() {
        const catBody = document.getElementById("astro-cat-body");
        if (catBody) {
            catBody.classList.remove("astro-flip");
            void catBody.offsetWidth; // Trigger reflow
            catBody.classList.add("astro-flip");
        }

        const isMeow = Math.random() > 0.4;
        if (isMeow) {
            playMeow();
        } else {
            playPurr();
        }

        spawnSparks(copilot.x + 32, copilot.y + 20, 6, '#34d399');
        const randomQuip = QUIPS[Math.floor(Math.random() * QUIPS.length)];
        showSpeechBubble(randomQuip);
    }

    function toggleLaserChase() {
        if (copilot.laserActive) {
            stopLaserChase();
            return;
        }

        copilot.laserActive = true;
        copilot.state = 'laser';
        const btn = document.getElementById("hud-laser-btn");
        if (btn) btn.classList.add("astro-hud-btn-active");
        const dockLaserStop = document.getElementById("dock-laser-stop-btn");
        if (dockLaserStop) dockLaserStop.classList.remove("hidden");

        if (laserDotEl) {
            laserDotEl.classList.remove("hidden");
            laserDotEl.style.transform = `translate(${copilot.mouseX - 12}px, ${copilot.mouseY - 12}px)`;
        }
        playPowerUp();
        showSpeechBubble("Laser locked! Click anywhere, press ESC, or I'll catch my breath in 15s! 🎯");

        // Auto-stop after 15 seconds so cat doesn't exhaust itself or trap the user
        clearTimeout(copilot.laserAutoStopTimer);
        copilot.laserAutoStopTimer = setTimeout(() => {
            if (copilot.laserActive) {
                stopLaserChase("Whew! Astro-Cat caught his breath. Good chase! 🐾");
            }
        }, 15000);
    }

    function stopLaserChase(customMsg) {
        if (!copilot.laserActive) return;
        copilot.laserActive = false;
        clearTimeout(copilot.laserAutoStopTimer);
        copilot.state = 'floating';

        const btn = document.getElementById("hud-laser-btn");
        if (btn) btn.classList.remove("astro-hud-btn-active");
        const dockLaserStop = document.getElementById("dock-laser-stop-btn");
        if (dockLaserStop) dockLaserStop.classList.add("hidden");

        if (laserDotEl) laserDotEl.classList.add("hidden");
        playPurr();
        showSpeechBubble(customMsg || "Laser disengaged! Floating smooth in zero-g. 😸");
    }

    // =========================================================================
    // 6b. ULTRA-LIGHTWEIGHT IN-BROWSER SCREEN RECORDER ("CLIP FOR X")
    // =========================================================================
    let mediaRecorder = null;
    let recordedChunks = [];
    let recTimerInterval = null;
    let recSeconds = 0;
    let recStream = null;

    async function toggleScreenRecording() {
        if (mediaRecorder && mediaRecorder.state === "recording") {
            stopScreenRecording();
            return;
        }
        startScreenRecording();
    }

    async function startScreenRecording() {
        try {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
                alert("In-browser recording requires displayMedia support. On Windows, you can also press Win+Shift+R!");
                return;
            }

            // Target 720p / 1080p @ 30fps: Recommended Twitter/X specs.
            // Drastically slashes CPU & RAM overhead by 80%+ compared to uncapped 60fps VP9!
            recStream = await navigator.mediaDevices.getDisplayMedia({
                video: {
                    displaySurface: "browser",
                    width: { ideal: 1280, max: 1920 },
                    height: { ideal: 720, max: 1080 },
                    frameRate: { ideal: 30, max: 30 }
                },
                audio: true
            });

            recordedChunks = [];

            // Prioritize GPU Hardware-Accelerated Codecs:
            // 1. MP4 (H.264 / AVC) -> GPU Hardware NVENC/Intel QuickSync (virtually 0% CPU)
            // 2. WebM with H.264
            // 3. WebM with VP8 (lightweight hardware acceleration)
            // 4. WebM default
            let chosenMime = "";
            let fileExt = "webm";
            const candidates = [
                { mime: "video/mp4;codecs=avc1.42E01E,mp4a.40.2", ext: "mp4" },
                { mime: "video/mp4;codecs=avc1", ext: "mp4" },
                { mime: "video/mp4", ext: "mp4" },
                { mime: "video/webm;codecs=h264,opus", ext: "webm" },
                { mime: "video/webm;codecs=vp8,opus", ext: "webm" },
                { mime: "video/webm;codecs=vp8", ext: "webm" },
                { mime: "video/webm", ext: "webm" }
            ];

            for (const c of candidates) {
                if (typeof MediaRecorder !== "undefined" && MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(c.mime)) {
                    chosenMime = c.mime;
                    fileExt = c.ext;
                    break;
                }
            }

            // Cap bitrate to 2.5 Mbps: standard for Twitter/X video clips.
            // Prevents runaway RAM buffers and stops CPU encoder saturation.
            const recorderOptions = {
                videoBitsPerSecond: 2500000
            };
            if (chosenMime) recorderOptions.mimeType = chosenMime;

            mediaRecorder = new MediaRecorder(recStream, recorderOptions);

            mediaRecorder.ondataavailable = (e) => {
                if (e.data && e.data.size > 0) {
                    recordedChunks.push(e.data);
                }
            };

            mediaRecorder.onstop = () => {
                clearInterval(recTimerInterval);
                const banner = document.getElementById("orbit-rec-banner");
                if (banner) banner.classList.add("hidden");
                const dockRecBtn = document.getElementById("dock-rec-btn");
                if (dockRecBtn) dockRecBtn.innerHTML = '<span>📹 Clip for X</span>';

                // Release all capture tracks immediately
                if (recStream) {
                    recStream.getTracks().forEach(track => track.stop());
                    recStream = null;
                }

                if (recordedChunks.length === 0) return;

                const blob = new Blob(recordedChunks, { type: mediaRecorder.mimeType || (fileExt === "mp4" ? "video/mp4" : "video/webm") });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.style.display = "none";
                a.href = url;
                const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
                a.download = `orbit-security-astro-cat-${timestamp}.${fileExt}`;
                document.body.appendChild(a);
                a.click();
                setTimeout(() => {
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                    recordedChunks = [];
                }, 100);

                playCoin();
                showSpeechBubble("🎬 Clip saved! Ready to post on X (Twitter)! 🚀");
            };

            recStream.getVideoTracks()[0].onended = () => {
                if (mediaRecorder && mediaRecorder.state === "recording") {
                    mediaRecorder.stop();
                }
            };

            // Collect 1000ms (1-second) chunks instead of 250ms -> reduces memory allocations by 75%
            mediaRecorder.start(1000);
            recSeconds = 0;
            const banner = document.getElementById("orbit-rec-banner");
            const timerEl = document.getElementById("orbit-rec-timer");
            if (banner) banner.classList.remove("hidden");
            if (timerEl) timerEl.textContent = "00:00";

            recTimerInterval = setInterval(() => {
                recSeconds++;
                const mins = String(Math.floor(recSeconds / 60)).padStart(2, "0");
                const secs = String(recSeconds % 60).padStart(2, "0");
                if (timerEl) timerEl.textContent = `${mins}:${secs}`;

                // Auto-stop at 60 seconds max to prevent runaway RAM consumption
                if (recSeconds >= 60) {
                    stopScreenRecording();
                }
            }, 1000);

            const dockRecBtn = document.getElementById("dock-rec-btn");
            if (dockRecBtn) dockRecBtn.innerHTML = '<span class="text-rose-400 animate-pulse">⏹️ Stop Rec</span>';

            playPowerUp();
            showSpeechBubble("🎥 Recording clip (GPU optimized)! Flips & tricks ready! 🐾");
        } catch (err) {
            console.warn("Screen recording cancelled or failed:", err);
            if (recStream) {
                recStream.getTracks().forEach(track => track.stop());
                recStream = null;
            }
        }
    }

    function stopScreenRecording() {
        if (mediaRecorder && mediaRecorder.state === "recording") {
            mediaRecorder.stop();
        }
    }

    function startSpacePatrol() {
        if (copilot.patrolActive) return;
        copilot.patrolActive = true;
        copilot.state = 'patrol';
        copilot.patrolScore = 0;

        const patrolBtn = document.getElementById("hud-patrol-btn");
        if (patrolBtn) patrolBtn.classList.add("astro-hud-btn-active");

        playPowerUp();
        showSpeechBubble("🚨 Threat Alert! 3 rogue DNS anomalies detected! Intercepting...");

        // Spawn 3 Threat Bugs across the viewport
        const threats = [
            { id: 1, name: "DANGLING CNAME", color: "#ef4444", x: window.innerWidth * 0.25, y: window.innerHeight * 0.3 },
            { id: 2, name: "EXPIRED SSL", color: "#f59e0b", x: window.innerWidth * 0.70, y: window.innerHeight * 0.35 },
            { id: 3, name: "SPOOF DRIFT", color: "#a855f7", x: window.innerWidth * 0.45, y: window.innerHeight * 0.65 }
        ];

        copilot.patrolThreats = threats.map(t => {
            const el = document.createElement("div");
            el.className = "astro-threat-chip";
            el.style.cssText = `position: fixed; left: ${t.x}px; top: ${t.y}px; z-index: 99985; border-color: ${t.color}; box-shadow: 0 0 15px ${t.color};`;
            el.innerHTML = `
                <span class="threat-dot" style="background-color: ${t.color};"></span>
                <span>👾 ${t.name}</span>
            `;
            document.body.appendChild(el);
            return { ...t, el, alive: true };
        });
    }

    function clearPatrolThreats() {
        copilot.patrolThreats.forEach(t => {
            if (t.el && t.el.parentElement) {
                t.el.parentElement.removeChild(t.el);
            }
        });
        copilot.patrolThreats = [];
        copilot.patrolActive = false;
        const patrolBtn = document.getElementById("hud-patrol-btn");
        if (patrolBtn) patrolBtn.classList.remove("astro-hud-btn-active");
    }

    function showSpeechBubble(text, duration = 7500) {
        const bubble = document.getElementById("astro-speech-bubble");
        const bubbleText = document.getElementById("astro-bubble-text");
        if (!bubble || !bubbleText) return;

        bubbleText.innerText = text;
        bubble.classList.remove("hidden");

        clearTimeout(copilot.speechTimer);
        if (duration > 0 && isFinite(duration)) {
            copilot.speechTimer = setTimeout(() => {
                hideSpeechBubble();
            }, duration);
        }
    }

    function hideSpeechBubble() {
        const bubble = document.getElementById("astro-speech-bubble");
        if (bubble) bubble.classList.add("hidden");
    }

    function spawnSparks(x, y, count = 4, color = '#38bdf8') {
        for (let i = 0; i < count; i++) {
            const angle = Math.random() * Math.PI * 2;
            const speed = Math.random() * 3 + 1;
            copilot.sparks.push({
                x: x,
                y: y,
                vx: Math.cos(angle) * speed,
                vy: Math.sin(angle) * speed,
                size: Math.random() * 3 + 1.5,
                alpha: 1.0,
                color: color
            });
        }
    }

    // Main 60fps Physics & Render Loop
    function updateCopilotLoop() {
        if (copilot.state !== 'docked') {
            copilot.bobAngle += 0.05;

            // Physics states
            if (copilot.state === 'laser') {
                const tx = copilot.mouseX - 32;
                const ty = copilot.mouseY - 32;
                const dx = tx - copilot.x;
                const dy = ty - copilot.y;
                const dist = Math.hypot(dx, dy);

                if (dist > 35) {
                    copilot.vx += (dx / dist) * 0.7;
                    copilot.vy += (dy / dist) * 0.7;
                    copilot.vx *= 0.94;
                    copilot.vy *= 0.94;
                    copilot.rot = Math.atan2(copilot.vy, copilot.vx) * (180 / Math.PI) * 0.3;
                    if (Math.random() > 0.4) spawnSparks(copilot.x + 32, copilot.y + 54, 1, '#38bdf8');
                } else {
                    copilot.vx *= 0.8;
                    copilot.vy *= 0.8;
                    if (Math.random() > 0.92) {
                        playPurr();
                        spawnSparks(copilot.x + 32, copilot.y + 20, 2, '#34d399');
                    }
                }
                copilot.x += copilot.vx;
                copilot.y += copilot.vy;

            } else if (copilot.state === 'patrol') {
                const target = copilot.patrolThreats.find(t => t.alive);
                if (target) {
                    const tx = target.x - 20;
                    const ty = target.y - 20;
                    const dx = tx - copilot.x;
                    const dy = ty - copilot.y;
                    const dist = Math.hypot(dx, dy);

                    if (dist > 60) {
                        copilot.vx += (dx / dist) * 0.85;
                        copilot.vy += (dy / dist) * 0.85;
                        copilot.vx *= 0.93;
                        copilot.vy *= 0.93;
                        copilot.rot = Math.atan2(copilot.vy, copilot.vx) * (180 / Math.PI) * 0.3;
                        if (Math.random() > 0.5) spawnSparks(copilot.x + 32, copilot.y + 54, 1, '#f59e0b');
                    } else {
                        // In firing range! Zap the threat!
                        target.alive = false;
                        playLaser();
                        playCoin();
                        spawnSparks(target.x + 40, target.y + 12, 18, target.color);
                        if (target.el && target.el.parentElement) {
                            target.el.parentElement.removeChild(target.el);
                        }
                        copilot.patrolScore += 100;

                        // Check if all cleared
                        const remaining = copilot.patrolThreats.filter(t => t.alive).length;
                        if (remaining === 0) {
                            playPowerUp();
                            showSpeechBubble(`🏆 ALL 3 THREATS PURGED! +300 PTS! Retainer secured!`);
                            setTimeout(() => {
                                copilot.state = 'floating';
                                copilot.patrolActive = false;
                                const pBtn = document.getElementById("hud-patrol-btn");
                                if (pBtn) pBtn.classList.remove("astro-hud-btn-active");
                            }, 2500);
                        }
                    }
                }
                copilot.x += copilot.vx;
                copilot.y += copilot.vy;

            } else if (!copilot.isDragging) {
                // Free Float Mode
                copilot.x += copilot.vx;
                copilot.y += copilot.vy;
                copilot.vx *= 0.985;
                copilot.vy *= 0.985;

                // Ambient cosmic drift
                if (Math.hypot(copilot.vx, copilot.vy) < 0.25) {
                    copilot.vx = Math.sin(copilot.bobAngle * 0.4) * 0.3;
                    copilot.vy = Math.cos(copilot.bobAngle * 0.5) * 0.25;
                }

                copilot.rot += (copilot.vx * 1.5 - copilot.rot) * 0.08;

                // Screen edge bounce
                const minX = 15;
                const maxX = window.innerWidth - 85;
                const minY = 65;
                const maxY = window.innerHeight - 95;

                if (copilot.x < minX) {
                    copilot.x = minX;
                    copilot.vx = Math.abs(copilot.vx) * 0.85;
                    playBoing();
                    spawnSparks(copilot.x, copilot.y + 32, 4, '#38bdf8');
                } else if (copilot.x > maxX) {
                    copilot.x = maxX;
                    copilot.vx = -Math.abs(copilot.vx) * 0.85;
                    playBoing();
                    spawnSparks(copilot.x + 64, copilot.y + 32, 4, '#38bdf8');
                }

                if (copilot.y < minY) {
                    copilot.y = minY;
                    copilot.vy = Math.abs(copilot.vy) * 0.85;
                    playBoing();
                    spawnSparks(copilot.x + 32, copilot.y, 4, '#38bdf8');
                } else if (copilot.y > maxY) {
                    copilot.y = maxY;
                    copilot.vy = -Math.abs(copilot.vy) * 0.85;
                    playBoing();
                    spawnSparks(copilot.x + 32, copilot.y + 64, 4, '#38bdf8');
                }
            }

            // Render DOM Position (Astro-Cat wrapper stays upright for HUD stability)
            const visualY = copilot.y + Math.sin(copilot.bobAngle) * 4;
            if (copilotEl) {
                copilotEl.style.transform = `translate3d(${copilot.x}px, ${visualY}px, 0px)`;
                const catBody = document.getElementById("astro-cat-body");
                if (catBody && !catBody.classList.contains("astro-flip")) {
                    catBody.style.transform = `rotate(${copilot.rot}deg)`;
                }
            }

            // Render Independent Fixed Speech Bubble (Never tilts, clamped to screen)
            const bubble = document.getElementById("astro-speech-bubble");
            if (bubble && !bubble.classList.contains("hidden")) {
                const bubbleW = bubble.offsetWidth || 230;
                const bubbleH = bubble.offsetHeight || 75;
                let bubbleX = (copilot.x + 32) - (bubbleW / 2);
                bubbleX = Math.max(12, Math.min(window.innerWidth - bubbleW - 12, bubbleX));

                let bubbleY;
                const tail = document.getElementById("astro-bubble-tail");
                if (visualY > 120) {
                    // Position bubble above the cat
                    bubbleY = visualY - bubbleH - 12;
                    if (tail) {
                        tail.className = "astro-bubble-tail-down";
                        const tailLeft = Math.max(16, Math.min(bubbleW - 16, (copilot.x + 32) - bubbleX));
                        tail.style.left = `${tailLeft}px`;
                    }
                } else {
                    // Position bubble below the cat (if cat is near top edge)
                    bubbleY = visualY + 74;
                    if (tail) {
                        tail.className = "astro-bubble-tail-up";
                        const tailLeft = Math.max(16, Math.min(bubbleW - 16, (copilot.x + 32) - bubbleX));
                        tail.style.left = `${tailLeft}px`;
                    }
                }
                bubble.style.transform = `translate3d(${bubbleX}px, ${bubbleY}px, 0px)`;
            }
        }

        // Render Particle Canvas & Active Lasers (Optimized: skips work when idle)
        if (fxCtx && fxCanvas) {
            const hasSparks = copilot.sparks.length > 0;
            const hasLaser = copilot.laserActive && copilot.state !== 'docked';
            const hasPatrol = copilot.patrolActive && copilot.state !== 'docked';

            if (!hasSparks && !hasLaser && !hasPatrol) {
                if (!fxCanvas._isClean) {
                    fxCtx.clearRect(0, 0, fxCanvas.width, fxCanvas.height);
                    fxCanvas._isClean = true;
                }
            } else {
                fxCanvas._isClean = false;
                fxCtx.clearRect(0, 0, fxCanvas.width, fxCanvas.height);

                const visualY = copilot.y + Math.sin(copilot.bobAngle) * 4;
                const catVisorX = copilot.x + 32;
                const catVisorY = visualY + 22;

                // 1. Laser Chase Mode - Active Laser Targeting Line
                if (copilot.laserActive && copilot.state !== 'docked') {
                    fxCtx.save();
                    fxCtx.beginPath();
                    fxCtx.moveTo(catVisorX, catVisorY);
                    fxCtx.lineTo(copilot.mouseX, copilot.mouseY);
                    fxCtx.strokeStyle = 'rgba(6, 182, 212, 0.6)';
                    fxCtx.lineWidth = 2;
                    fxCtx.setLineDash([6, 4]);
                    fxCtx.shadowColor = '#06b6d4';
                    fxCtx.shadowBlur = 8;
                    fxCtx.stroke();
                    fxCtx.restore();
                }

                // 2. Threat Patrol Mini-Game - Dynamic Targeting Line & Firing Laser Beam
                if (copilot.patrolActive && copilot.state !== 'docked') {
                    const target = copilot.patrolThreats.find(t => t.alive);
                    if (target) {
                        const targetX = target.x + 40;
                        const targetY = target.y + 14;
                        const dist = Math.hypot(targetX - catVisorX, targetY - catVisorY);

                        fxCtx.save();
                        if (dist < 110) {
                            fxCtx.beginPath();
                            fxCtx.moveTo(catVisorX, catVisorY);
                            fxCtx.lineTo(targetX, targetY);
                            fxCtx.strokeStyle = '#ef4444';
                            fxCtx.lineWidth = 3;
                            fxCtx.shadowColor = '#f43f5e';
                            fxCtx.shadowBlur = 10;
                            fxCtx.stroke();

                            fxCtx.beginPath();
                            fxCtx.moveTo(catVisorX, catVisorY);
                            fxCtx.lineTo(targetX, targetY);
                            fxCtx.strokeStyle = '#ffffff';
                            fxCtx.lineWidth = 1;
                            fxCtx.stroke();
                        } else {
                            fxCtx.beginPath();
                            fxCtx.moveTo(catVisorX, catVisorY);
                            fxCtx.lineTo(targetX, targetY);
                            fxCtx.strokeStyle = 'rgba(245, 158, 11, 0.45)';
                            fxCtx.lineWidth = 1.5;
                            fxCtx.setLineDash([5, 5]);
                            fxCtx.stroke();
                        }
                        fxCtx.restore();
                    }
                }

                // 3. Render Sparks & Debris (Optimized: Zero per-particle save/restore)
                for (let i = copilot.sparks.length - 1; i >= 0; i--) {
                    const p = copilot.sparks[i];
                    p.x += p.vx;
                    p.y += p.vy;
                    p.alpha -= 0.035;
                    if (p.alpha <= 0) {
                        copilot.sparks.splice(i, 1);
                        continue;
                    }
                    fxCtx.globalAlpha = p.alpha;
                    fxCtx.fillStyle = p.color;
                    fxCtx.fillRect(p.x, p.y, p.size, p.size);
                }
                fxCtx.globalAlpha = 1.0;
            }
        }

        requestAnimationFrame(updateCopilotLoop);
    }

    // =========================================================================
    // 7. AUDIO TOGGLE BUTTON (WITH PERSISTENCE)
    // =========================================================================
    function createSoundToggle() {
        if (document.getElementById("audio-toggle-btn")) return;
        
        // Load saved sound preference
        const saved = localStorage.getItem("orbit_sound_enabled");
        if (saved !== null) {
            soundEnabled = (saved === "true");
        }

        const btn = document.createElement("button");
        btn.id = "audio-toggle-btn";
        btn.className = "text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors flex items-center gap-1.5 cursor-pointer";
        btn.innerHTML = soundEnabled ? `<span>🔊</span> <span>AUDIO: ON</span>` : `<span>🔇</span> <span>AUDIO: OFF</span>`;
        btn.title = "Toggle 8-Bit Retro Audio SFX";

        btn.addEventListener("click", () => {
            soundEnabled = !soundEnabled;
            localStorage.setItem("orbit_sound_enabled", soundEnabled.toString());
            btn.innerHTML = soundEnabled ? `<span>🔊</span> <span>AUDIO: ON</span>` : `<span>🔇</span> <span>AUDIO: OFF</span>`;
            if (soundEnabled) {
                playBlip();
            }
        });

        const navActions = document.querySelector("header .max-w-7xl .sm\\:flex") || document.querySelector("header .max-w-6xl .sm\\:flex") || document.querySelector("header nav");
        if (navActions) {
            navActions.prepend(btn);
        }
    }

    // =========================================================================
    // 8. TACTILE AUDIO & SPECULAR CARD SPOTLIGHT
    // =========================================================================
    function bindTactileInteractions() {
        // Subtle micro-click audio on hoverable cards & primary buttons
        document.querySelectorAll("a, button, .pixel-btn, [data-cat-term]").forEach(el => {
            el.addEventListener("mouseenter", () => {
                playHoverTick();
            });
        });

        // Specular mouse cursor spotlight on glass cards
        const glassCards = document.querySelectorAll(".card-glass, .card-glass-emerald, .card-glass-cyan, .pricing-grid > div");
        glassCards.forEach(card => {
            card.addEventListener("mousemove", (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                card.style.setProperty("--mouse-x", `${x}px`);
                card.style.setProperty("--mouse-y", `${y}px`);
            });
        });

        // Helper Chips
        document.querySelectorAll("[data-cat-term]").forEach(el => {
            if (el.dataset.catBound) return;
            el.dataset.catBound = "true";
            el.style.cursor = "pointer";

            if (!el.querySelector(".cat-chip")) {
                const chip = document.createElement("span");
                chip.className = "cat-chip ml-1.5 inline-flex items-center text-[10px] font-mono text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 px-1.5 py-0.5 rounded transition-all";
                chip.innerHTML = `🐱 explain`;
                el.appendChild(chip);
            }

            el.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                showSimpleCatDialog(el.dataset.catTerm);
            });
        });
    }

    // =========================================================================
    // 9. INJECT STYLE GUARANTEES
    // =========================================================================
    function injectStyleGuarantees() {
        if (document.getElementById("simple-cat-injected-styles")) return;
        const style = document.createElement("style");
        style.id = "simple-cat-injected-styles";
        style.innerHTML = `
            #simple-cat-modal.hidden, #astro-cat-copilot.hidden, #astro-speech-bubble.hidden, #astro-laser-dot.hidden, #orbit-rec-banner.hidden, #dock-laser-stop-btn.hidden {
                display: none !important;
            }
            #retro-arcade-canvas {
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100% !important;
                height: 100% !important;
                z-index: 0 !important;
                pointer-events: none !important;
            }
            #retro-scanlines {
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100% !important;
                height: 100% !important;
                z-index: 1 !important;
                pointer-events: none !important;
            }
            #simple-cat-modal {
                display: none;
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                right: 0 !important;
                bottom: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                z-index: 999999 !important;
                background-color: rgba(2, 6, 23, 0.88) !important;
                backdrop-filter: blur(8px) !important;
                -webkit-backdrop-filter: blur(8px) !important;
                align-items: center !important;
                justify-content: center !important;
                padding: 1rem !important;
                box-sizing: border-box !important;
            }
            #simple-cat-modal.cat-modal-open {
                display: flex !important;
            }

            /* Specular Mouse-Tracking Spotlight on Cards */
            .card-glass, .card-glass-emerald, .card-glass-cyan, .pricing-grid > div {
                position: relative !important;
                overflow: hidden !important;
            }
            .card-glass::after, .card-glass-emerald::after, .card-glass-cyan::after, .pricing-grid > div::after {
                content: '';
                position: absolute;
                inset: 0;
                border-radius: inherit;
                background: radial-gradient(400px circle at var(--mouse-x, -500px) var(--mouse-y, -500px), rgba(16, 185, 129, 0.09), transparent 40%);
                pointer-events: none;
                z-index: 1;
                transition: opacity 0.3s;
            }

            /* Astro-Cat Floating Copilot Wrapper */
            .astro-cat-wrapper {
                position: fixed !important;
                top: 0;
                left: 0;
                width: 64px;
                height: 64px;
                z-index: 99990 !important;
                cursor: grab;
                user-select: none;
                -webkit-user-select: none;
                touch-action: none;
                transform-origin: center center;
            }
            .astro-cat-wrapper.grabbing {
                cursor: grabbing !important;
            }

            .astro-cat-body {
                position: relative;
                width: 64px;
                height: 64px;
                transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            }
            .astro-cat-body:hover {
                transform: scale(1.1);
            }
            .astro-flip {
                animation: astroBackflip 0.65s cubic-bezier(0.34, 1.56, 0.64, 1) forwards !important;
            }
            @keyframes astroBackflip {
                0% { transform: scale(1) rotate(0deg); }
                50% { transform: scale(1.3) rotate(180deg); }
                100% { transform: scale(1) rotate(360deg); }
            }

            /* Thruster Flame Flicker */
            .flame-left, .flame-right {
                animation: flameFlicker 0.12s infinite alternate ease-in-out;
                transform-origin: 50% 50px;
            }
            @keyframes flameFlicker {
                0% { transform: scaleY(0.85) scaleX(0.9); opacity: 0.8; }
                100% { transform: scaleY(1.3) scaleX(1.1); opacity: 1; }
            }

            /* Speech Bubble (Fixed Viewport Coordinates - Never tilts or flips) */
            .astro-bubble {
                position: fixed !important;
                top: 0;
                left: 0;
                width: 230px;
                background-color: rgba(15, 23, 42, 0.96);
                border: 2px solid #10b981;
                border-radius: 12px;
                padding: 10px 12px;
                box-shadow: 0 0 25px rgba(16, 185, 129, 0.35), 4px 4px 0px #064e3b;
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                z-index: 99995 !important;
                pointer-events: auto;
                transition: opacity 0.2s;
            }
            .astro-bubble-tail-down {
                position: absolute;
                bottom: -8px;
                width: 0;
                height: 0;
                border-left: 8px solid transparent;
                border-right: 8px solid transparent;
                border-top: 8px solid #10b981;
                transform: translateX(-50%);
            }
            .astro-bubble-tail-up {
                position: absolute;
                top: -8px;
                width: 0;
                height: 0;
                border-left: 8px solid transparent;
                border-right: 8px solid transparent;
                border-bottom: 8px solid #10b981;
                transform: translateX(-50%);
            }
            .astro-bubble-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 4px;
                border-bottom: 1px solid rgba(16, 185, 129, 0.25);
                padding-bottom: 3px;
            }
            .astro-bubble-title {
                font-family: monospace;
                font-size: 8px;
                font-weight: bold;
                color: #34d399;
                letter-spacing: 0.05em;
            }
            .astro-bubble-close {
                background: none;
                border: none;
                color: #94a3b8;
                font-size: 11px;
                cursor: pointer;
                padding: 0 3px;
                line-height: 1;
            }
            .astro-bubble-close:hover {
                color: #ffffff;
            }
            .astro-bubble-text {
                font-family: sans-serif;
                font-size: 11px;
                color: #f1f5f9;
                line-height: 1.4;
            }

            /* Floating HUD Action Toolbar (Arcade Pill) */
            .astro-hud {
                position: absolute;
                top: 70px;
                left: 50%;
                transform: translateX(-50%);
                display: flex;
                align-items: center;
                gap: 5px;
                background-color: rgba(15, 23, 42, 0.95);
                border: 1.5px solid rgba(16, 185, 129, 0.5);
                border-radius: 9999px;
                padding: 4px 8px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6), 0 0 12px rgba(16, 185, 129, 0.25);
                opacity: 0.85;
                transition: opacity 0.2s, transform 0.2s;
                white-space: nowrap;
                z-index: 99995;
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
            }
            .astro-cat-wrapper:hover .astro-hud {
                opacity: 1;
                transform: translateX(-50%) scale(1.04);
            }
            .astro-hud-btn {
                background: rgba(30, 41, 59, 0.9);
                border: 1px solid rgba(16, 185, 129, 0.25);
                color: #cbd5e1;
                font-family: monospace;
                font-size: 9px;
                padding: 3px 7px;
                border-radius: 9999px;
                cursor: pointer;
                transition: all 0.15s;
                user-select: none;
            }
            .astro-hud-btn:hover {
                background: #10b981;
                color: #020617;
                font-weight: bold;
                box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
            }
            .astro-hud-btn-active {
                background: #06b6d4 !important;
                color: #020617 !important;
                font-weight: bold;
                border-color: #38bdf8 !important;
                box-shadow: 0 0 12px rgba(6, 182, 212, 0.6) !important;
            }

            /* Laser Target Reticle */
            #astro-laser-dot {
                position: fixed;
                top: 0;
                left: 0;
                width: 24px;
                height: 24px;
                pointer-events: none;
                z-index: 99999;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .laser-ring {
                position: absolute;
                width: 22px;
                height: 22px;
                border: 2px dashed #06b6d4;
                border-radius: 50%;
                animation: spinLaser 3s linear infinite;
                box-shadow: 0 0 12px #06b6d4;
            }
            .laser-core {
                width: 6px;
                height: 6px;
                background-color: #ef4444;
                border-radius: 50%;
                box-shadow: 0 0 8px #ef4444, 0 0 16px #ef4444;
            }
            @keyframes spinLaser {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            .laser-hint-pill {
                position: absolute;
                top: 26px;
                left: 50%;
                transform: translateX(-50%);
                background-color: rgba(15, 23, 42, 0.94);
                border: 1px solid #06b6d4;
                color: #67e8f9;
                font-family: monospace;
                font-size: 8px;
                font-weight: bold;
                padding: 2px 7px;
                border-radius: 9999px;
                white-space: nowrap;
                pointer-events: none;
                box-shadow: 0 0 10px rgba(6, 182, 212, 0.4);
                letter-spacing: 0.05em;
            }

            /* Threat Bug Chips for Patrol Mini-Game */
            .astro-threat-chip {
                padding: 6px 10px;
                border-radius: 8px;
                background-color: rgba(15, 23, 42, 0.95);
                border: 2px solid;
                font-family: monospace;
                font-size: 10px;
                font-weight: bold;
                color: #ffffff;
                display: flex;
                align-items: center;
                gap: 6px;
                animation: threatFloat 1.8s ease-in-out infinite alternate;
                pointer-events: none;
            }
            .threat-dot {
                width: 6px;
                height: 6px;
                border-radius: 50%;
                animation: pulse 1s infinite;
            }
            @keyframes threatFloat {
                0% { transform: translateY(-5px); }
                100% { transform: translateY(5px); }
            }
        `;
        document.head.appendChild(style);
    }

    // =========================================================================
    // 10. PUBLIC API & LIFECYCLE
    // =========================================================================
    window.SimpleCat = {
        explain: showSimpleCatDialog,
        hide: hideSimpleCatDialog,
        switchTab: switchTab,
        playBlip: playBlip,
        playChirp: playChirp,
        playPowerUp: playPowerUp,
        playPowerup: playPowerUp,
        playMeow: playMeow,
        playPurr: playPurr,
        playLaser: playLaser,
        playBoing: playBoing,
        playCoin: playCoin,
        playHoverTick: playHoverTick,
        playThruster: playThruster,
        launchZeroG: launchAstroCatIntoZeroG,
        dock: dockAstroCat,
        laserChase: toggleLaserChase,
        stopLaser: stopLaserChase,
        recordClip: toggleScreenRecording,
        stopRecording: stopScreenRecording,
        patrol: startSpacePatrol,
        pet: petAstroCat,
        say: showSpeechBubble,
        hideBubble: hideSpeechBubble,
        getPixelCatSVG: getPixelCatSVG,
        getAstroCatSVG: getAstroCatSVG,
        bindHelperChips: bindTactileInteractions,
        initBackground: initArcadeBackground
    };

    function initAll() {
        injectStyleGuarantees();
        initArcadeBackground();
        createAstroCatCopilot();
        createSoundToggle();
        bindTactileInteractions();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initAll);
    } else {
        initAll();
    }
})();

