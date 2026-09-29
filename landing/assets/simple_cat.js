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

    // =========================================================================
    // 3. PIXEL CAT SVG GENERATOR
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

        window.addEventListener("resize", () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
            initStars();
        });

        // Pixel Stars
        const starColors = ['#10b981', '#06b6d4', '#ec4899', '#fbbf24', '#ffffff'];
        let stars = [];

        function initStars() {
            stars = [];
            const starCount = Math.floor((width * height) / 7000); // denser starfield
            for (let i = 0; i < starCount; i++) {
                stars.push({
                    x: Math.random() * width,
                    y: Math.random() * height,
                    size: Math.random() < 0.15 ? 4 : (Math.random() < 0.45 ? 3 : 2),
                    isCross: Math.random() < 0.25, // 16-bit arcade sparkling star shape
                    color: starColors[Math.floor(Math.random() * starColors.length)],
                    speed: 0.2 + Math.random() * 0.6,
                    opacity: 0.4 + Math.random() * 0.6,
                    twinkleSpeed: 0.02 + Math.random() * 0.04
                });
            }
        }
        initStars();

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

            // Fill space background
            ctx.fillStyle = '#060a16';
            ctx.fillRect(0, 0, width, height);

            // 1. Ambient Cyber Nebulae
            ctx.shadowBlur = 0;
            const grad1 = ctx.createRadialGradient(width * 0.2, height * 0.25, 0, width * 0.2, height * 0.25, width * 0.5);
            grad1.addColorStop(0, 'rgba(16, 185, 129, 0.16)');
            grad1.addColorStop(1, 'transparent');
            ctx.fillStyle = grad1;
            ctx.fillRect(0, 0, width, height);

            const grad2 = ctx.createRadialGradient(width * 0.8, height * 0.4, 0, width * 0.8, height * 0.4, width * 0.55);
            grad2.addColorStop(0, 'rgba(6, 182, 212, 0.16)');
            grad2.addColorStop(1, 'transparent');
            ctx.fillStyle = grad2;
            ctx.fillRect(0, 0, width, height);

            const grad3 = ctx.createRadialGradient(width * 0.5, height * 0.8, 0, width * 0.5, height * 0.8, width * 0.65);
            grad3.addColorStop(0, 'rgba(168, 85, 247, 0.14)');
            grad3.addColorStop(1, 'transparent');
            ctx.fillStyle = grad3;
            ctx.fillRect(0, 0, width, height);

            // 2. Render Twinkling 16-Bit Pixel Stars with Glow
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
                ctx.shadowBlur = 8;
                ctx.shadowColor = star.color;

                const sx = Math.floor(star.x);
                const sy = Math.floor(star.y);

                if (star.isCross && star.size >= 3) {
                    // 16-Bit Cross Star: central box + 4 tiny 1px pips
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
            ctx.shadowBlur = 6;
            ctx.font = '10px "Press Start 2P", monospace';
            glyphs.forEach(gl => {
                gl.y -= gl.speed;
                if (gl.y < -20) {
                    gl.y = height + 20;
                    gl.x = Math.random() * width;
                }
                ctx.fillStyle = gl.color;
                ctx.globalAlpha = gl.opacity;
                ctx.shadowColor = gl.color;
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

            // Stationary Depth Grid Lines (Zero downward motion = No optical barber-pole shift)
            ctx.strokeStyle = 'rgba(16, 185, 129, 0.22)';
            ctx.shadowColor = '#10b981';
            ctx.shadowBlur = 4;
            ctx.lineWidth = 1;
            for (let d = 1; d <= 8; d++) {
                const progress = d / 8;
                const lineY = horizonY + Math.pow(progress, 2.0) * (height - horizonY);
                if (lineY <= height) {
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
    // 6. FLOATING SIMPLE CAT COMPANION WIDGET
    // =========================================================================
    function createFloatingWidget() {
        if (document.getElementById("simple-cat-floating")) return;

        const widget = document.createElement("div");
        widget.id = "simple-cat-floating";
        widget.className = "fixed bottom-5 left-5 z-40 flex items-center gap-2 group cursor-pointer";
        widget.innerHTML = `
            <div class="p-2.5 bg-slate-900 border-2 border-emerald-500 rounded-xl shadow-[0_0_25px_rgba(16,185,129,0.3)] hover:scale-110 hover:shadow-[0_0_35px_rgba(16,185,129,0.5)] transition-all flex items-center gap-2" style="box-shadow: 4px 4px 0px #064e3b;">
                <div class="relative">
                    ${getPixelCatSVG(34)}
                    <span class="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full animate-ping"></span>
                    <span class="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full border border-slate-900"></span>
                </div>
                <div class="hidden sm:block text-left pr-1">
                    <div class="text-[9px] font-mono font-bold text-emerald-400 tracking-wider">GUIDE</div>
                    <div class="text-xs font-bold text-white font-mono">Simple Cat</div>
                </div>
            </div>
            <div class="opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity bg-slate-900 border border-slate-700 text-slate-300 text-xs px-3 py-1.5 rounded-lg shadow-lg font-mono whitespace-nowrap">
                Click me to explain confusing security words!
            </div>
        `;

        widget.addEventListener("click", () => {
            showSimpleCatDialog("dmarc");
        });

        document.body.appendChild(widget);
    }

    // =========================================================================
    // 7. AUDIO TOGGLE BUTTON
    // =========================================================================
    function createSoundToggle() {
        if (document.getElementById("audio-toggle-btn")) return;
        const btn = document.createElement("button");
        btn.id = "audio-toggle-btn";
        btn.className = "text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors flex items-center gap-1.5 cursor-pointer";
        btn.innerHTML = `<span>🔊</span> <span>AUDIO: ON</span>`;
        btn.addEventListener("click", () => {
            soundEnabled = !soundEnabled;
            btn.innerHTML = soundEnabled ? `<span>🔊</span> <span>AUDIO: ON</span>` : `<span>🔇</span> <span>AUDIO: OFF</span>`;
            if (soundEnabled) playBlip();
        });

        const navRight = document.querySelector("header .max-w-6xl > div:last-child") || document.querySelector("header .max-w-7xl > div:last-child");
        if (navRight) {
            navRight.prepend(btn);
        }
    }

    // =========================================================================
    // 8. AUTO-BIND ALL HELPER CHIPS AND LINKS
    // =========================================================================
    function bindHelperChips() {
        document.querySelectorAll("[data-cat-term]").forEach(el => {
            if (el.dataset.catBound) return;
            el.dataset.catBound = "true";
            el.style.cursor = "pointer";

            // Add retro question badge if not already customized
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

    // Inject CSS helper guarantees (such as .hidden)
    function injectStyleGuarantees() {
        if (document.getElementById("simple-cat-injected-styles")) return;
        const style = document.createElement("style");
        style.id = "simple-cat-injected-styles";
        style.innerHTML = `
            .hidden { display: none !important; }
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
            #simple-cat-modal.hidden {
                display: none !important;
            }
        `;
        document.head.appendChild(style);
    }

    // =========================================================================
    // 9. PUBLIC API & LIFECYCLE
    // =========================================================================
    window.SimpleCat = {
        explain: showSimpleCatDialog,
        hide: hideSimpleCatDialog,
        switchTab: switchTab,
        playBlip: playBlip,
        playChirp: playChirp,
        playPowerUp: playPowerUp,
        getPixelCatSVG: getPixelCatSVG,
        bindHelperChips: bindHelperChips,
        initBackground: initArcadeBackground
    };

    function initAll() {
        injectStyleGuarantees();
        initArcadeBackground();
        createFloatingWidget();
        createSoundToggle();
        bindHelperChips();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initAll);
    } else {
        initAll();
    }
})();
