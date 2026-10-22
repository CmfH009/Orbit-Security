# -*- coding: utf-8 -*-
"""
Upgrades docs/index.html and landing/index.html with all 4 high-converting agency features:
1. Interactive "Attack Simulator" Mode in the Radar Terminal
2. In-Browser White-Label PDF Flipbook Preview Modal + Trigger Button
3. "Steal Our Client Pitch" Copy-Paste Email Script Drawer (Synced with Agency Name)
4. Interactive Agency Retainer ROI Calculator with Dynamic Tier Routing
"""

with open("A:/projects/orbit-security/docs/index.html", "r", encoding="utf-8") as f:
    raw_html = f.read()

has_crlf = "\r\n" in raw_html
html = raw_html.replace("\r\n", "\n")

# ==============================================================================
# 1. ADD ATTACK SIMULATOR CHIP IN RADAR TERMINAL
# ==============================================================================
target_quick_tests = """                        <button type="button" onclick="if(window.SimpleCat) SimpleCat.playBlip(); setScanTarget('10up.com')" class="min-h-[48px] px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 hover:text-emerald-400 transition-colors pixel-btn flex items-center justify-center">10up.com</button>
                    </div>"""

replacement_quick_tests = """                        <button type="button" onclick="if(window.SimpleCat) SimpleCat.playBlip(); setScanTarget('10up.com')" class="min-h-[48px] px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 hover:text-emerald-400 transition-colors pixel-btn flex items-center justify-center">10up.com</button>
                        <button type="button" onclick="simulateTakeoverAttack()" class="min-h-[48px] px-4 py-2.5 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/50 text-xs text-red-300 hover:text-red-200 font-bold transition-all pixel-btn flex items-center justify-center gap-1.5 shadow-sm shadow-red-500/10 cursor-pointer">
                            <span class="w-2 h-2 rounded-full bg-red-400 animate-ping"></span>
                            <span>⚡ Simulate Takeover Attack</span>
                        </button>
                    </div>"""

assert target_quick_tests in html, "Could not find target_quick_tests"
html = html.replace(target_quick_tests, replacement_quick_tests, 1)

# ==============================================================================
# 2. ADD IN-BROWSER PDF FLIPBOOK BUTTON & "STEAL OUR CLIENT PITCH" DRAWER
# ==============================================================================
target_audit_footer = """                    <!-- Footer Callout -->
                    <div class="mt-6 bg-slate-950/60 rounded-xl p-4 border border-slate-800 text-xs text-slate-400 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                        <span>💡 Co-Branding Guarantee: Your clients never see Orbit Security. All reports feature your logo, brand colors, and contact info.</span>
                        <a href="sample_audit.pdf" target="_blank" rel="noopener noreferrer" class="text-emerald-400 hover:text-emerald-300 font-semibold flex items-center gap-1 whitespace-nowrap">
                            Download Sample PDF Audit &rarr;
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </section>"""

replacement_audit_footer = """                    <!-- Footer Callout -->
                    <div class="mt-6 bg-slate-950/60 rounded-xl p-4 border border-slate-800 text-xs text-slate-400 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                        <span>💡 Co-Branding Guarantee: Your clients never see Orbit Security. All reports feature your logo, brand colors, and contact info.</span>
                        <div class="flex flex-wrap items-center gap-3">
                            <button type="button" onclick="openPdfFlipbookModal()" class="min-h-[42px] px-3.5 py-2 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-emerald-300 font-mono text-xs font-bold flex items-center gap-1.5 transition-all pixel-btn cursor-pointer">
                                <span>📖 Inspect Interactive PDF Flipbook</span>
                            </button>
                            <a href="sample_audit.pdf" target="_blank" rel="noopener noreferrer" class="text-slate-300 hover:text-emerald-300 font-semibold flex items-center gap-1 whitespace-nowrap underline decoration-dotted">
                                Raw PDF &rarr;
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Feature 3 Enhancement: "Steal Our Client Pitch" Copy-Paste Email Drawer -->
            <div id="client-pitch-drawer" class="mt-8 bg-slate-900/90 rounded-2xl border-2 border-cyan-500/40 shadow-2xl overflow-hidden card-glass-cyan">
                <div class="px-5 sm:px-6 py-4 bg-slate-950/90 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                        <div class="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-arcade text-[9px] uppercase tracking-wider mb-1">
                            <span>✉️ STEAL OUR CLIENT PITCH // 1-CLICK RETAINER TEMPLATES</span>
                        </div>
                        <h3 class="text-lg sm:text-xl font-bold text-white">Ready-to-Send Client Upgrade Emails</h3>
                        <p class="text-xs text-slate-400 mt-0.5">Send one of these plain-English emails to your client roster today to close $250/mo security care retainers.</p>
                    </div>
                    <div class="flex items-center gap-2 overflow-x-auto pb-1 md:pb-0 no-scrollbar">
                        <button type="button" onclick="switchPitchTemplate('cve')" id="pitchTab-cve" class="pitch-tab-btn min-h-[42px] px-3.5 py-2 rounded-xl text-xs font-bold bg-red-500/20 text-red-300 border border-red-500/40 cursor-pointer whitespace-nowrap">🚨 Breaking CVE Alert</button>
                        <button type="button" onclick="switchPitchTemplate('quarterly')" id="pitchTab-quarterly" class="pitch-tab-btn min-h-[42px] px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 text-slate-300 hover:text-white border border-slate-700 cursor-pointer whitespace-nowrap">🛡️ Quarterly Checkup</button>
                        <button type="button" onclick="switchPitchTemplate('handover')" id="pitchTab-handover" class="pitch-tab-btn min-h-[42px] px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 text-slate-300 hover:text-white border border-slate-700 cursor-pointer whitespace-nowrap">🚀 Post-Launch Care</button>
                    </div>
                </div>
                <div class="p-5 sm:p-6">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
                        <div class="text-xs font-mono text-slate-400">
                            Subject: <span id="pitchSubjectDisplay" class="text-white font-bold">[Action Recommended] Protecting your domain against the October DNS takeover wave</span>
                        </div>
                        <button type="button" id="copyPitchBtn" onclick="copyClientPitch()" class="min-h-[44px] px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-bold text-xs uppercase font-sans tracking-wide transition-all shadow-lg shadow-cyan-500/20 pixel-btn flex items-center justify-center gap-2 cursor-pointer flex-shrink-0">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                            <span id="copyPitchBtnText">Copy Email Pitch</span>
                        </button>
                    </div>
                    <pre id="pitchBodyDisplay" class="p-4 rounded-xl bg-slate-950/90 border border-slate-800 font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed select-all overflow-x-auto">Hi [Client Name],

With the wave of DNS and subdomain takeover vulnerabilities disclosed this week, our engineering team at Apex Digital Studio ran a passive external check on your domain perimeter.

When marketing campaigns or third-party tools (like old landing pages, Shopify apps, or email senders) are disconnected, they often leave behind "dangling" DNS records. Attackers are currently scanning for these unattached records to hijack brand subdomains and send spoofed invoices.

To make sure your brand is completely locked down, we are rolling out continuous 24/7 Attack Surface & DMARC Monitoring across our care plans for $250/mo. On the 1st of every month, you'll receive an executive security scorecard verifying that your subdomains, SSL certificates, and email spoofing defenses are 100% airtight.

Reply "LOCK IT DOWN" and we will activate your domain sentinel and send over your baseline Executive Audit PDF today.

Best regards,
Apex Digital Studio</pre>
                </div>
            </div>
        </div>
    </section>"""

assert target_audit_footer in html, "Could not find target_audit_footer"
html = html.replace(target_audit_footer, replacement_audit_footer, 1)

# ==============================================================================
# 3. ADD INTERACTIVE RETAINER ROI CALCULATOR IN PRICING SECTION
# ==============================================================================
target_roi_spot = """                        <!-- Highlights Banner -->
                        <div class="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-300">
                            <div class="flex items-center gap-2">
                                <span class="text-emerald-400 font-bold font-arcade text-[10px]">★ ROI SUMMARY:</span>
                                <span class="text-[11px] text-slate-300 font-mono">1 client covers the stack &bull; 5 clients net $1,191/mo profit &bull; 100% automated</span>
                            </div>
                            <a href="signup.html" class="min-h-[48px] px-4 py-2.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 font-mono text-xs font-bold transition-colors whitespace-nowrap flex items-center justify-center gap-1.5">
                                <span>Get Retainer Vault</span>
                                <span>&rarr;</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>"""

replacement_roi_spot = """                        <!-- Highlights Banner -->
                        <div class="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-300">
                            <div class="flex items-center gap-2">
                                <span class="text-emerald-400 font-bold font-arcade text-[10px]">★ ROI SUMMARY:</span>
                                <span class="text-[11px] text-slate-300 font-mono">1 client covers the stack &bull; 5 clients net $1,191/mo profit &bull; 100% automated</span>
                            </div>
                            <a href="signup.html" class="min-h-[48px] px-4 py-2.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 font-mono text-xs font-bold transition-colors whitespace-nowrap flex items-center justify-center gap-1.5">
                                <span>Get Retainer Vault</span>
                                <span>&rarr;</span>
                            </a>
                        </div>
                    </div>
                </div>

                <!-- Interactive Agency Retainer ROI Calculator -->
                <div class="mt-6 pt-6 border-t border-slate-800/90 relative z-10">
                    <div class="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-4">
                        <div class="flex items-center gap-2">
                            <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-arcade text-[9px] border border-emerald-500/40">INTERACTIVE SIMULATOR</span>
                            <h4 class="text-base sm:text-lg font-bold text-white">Calculate Your Agency's Exact Retainer Profit</h4>
                        </div>
                        <span class="text-xs font-mono text-slate-400">Drag sliders to model your monthly recurring margin</span>
                    </div>

                    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center bg-slate-950/90 p-5 rounded-xl border border-emerald-500/30">
                        <!-- Sliders Column -->
                        <div class="lg:col-span-7 space-y-5">
                            <div>
                                <div class="flex items-center justify-between text-xs font-mono mb-2">
                                    <label for="roiClientCount" class="text-slate-300">Active Client Domains on Care Plan:</label>
                                    <span id="roiClientCountVal" class="px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-sm border border-emerald-500/40">25 Clients</span>
                                </div>
                                <input type="range" id="roiClientCount" min="1" max="100" value="25" oninput="updateRoiCalculator()" class="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-emerald-400" />
                                <div class="flex justify-between text-[10px] font-mono text-slate-500 mt-1">
                                    <span>1 Client</span>
                                    <span>15 (Starter)</span>
                                    <span>40 (Growth)</span>
                                    <span>100 (Pro Fleet)</span>
                                </div>
                            </div>

                            <div>
                                <div class="flex items-center justify-between text-xs font-mono mb-2">
                                    <label for="roiRetainerFee" class="text-slate-300">Monthly Security Retainer Charged per Client:</label>
                                    <span id="roiRetainerFeeVal" class="px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-sm border border-cyan-500/40">$250 / mo</span>
                                </div>
                                <input type="range" id="roiRetainerFee" min="100" max="500" step="25" value="250" oninput="updateRoiCalculator()" class="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400" />
                                <div class="flex justify-between text-[10px] font-mono text-slate-500 mt-1">
                                    <span>$100/mo (Add-on)</span>
                                    <span>$250/mo (Standard)</span>
                                    <span>$500/mo (Enterprise)</span>
                                </div>
                            </div>
                        </div>

                        <!-- Live Profit Readout Column -->
                        <div class="lg:col-span-5 p-4 rounded-xl bg-gradient-to-br from-slate-900 via-slate-900 to-emerald-950/40 border border-emerald-500/40 flex flex-col justify-between space-y-3">
                            <div class="flex items-center justify-between border-b border-slate-800 pb-2.5">
                                <div>
                                    <div class="text-[10px] font-mono text-slate-400 uppercase">Gross Monthly Retainer MRR</div>
                                    <div id="roiMonthlyGross" class="text-2xl font-extrabold text-white font-sans">$6,250<span class="text-xs font-normal text-slate-400">/mo</span></div>
                                </div>
                                <div class="text-right">
                                    <div class="text-[10px] font-mono text-slate-400 uppercase">Orbit Stack Cost</div>
                                    <div id="roiOrbitCost" class="text-sm font-bold text-emerald-400 font-mono">$59/mo (Growth)</div>
                                </div>
                            </div>

                            <div class="flex items-center justify-between">
                                <div>
                                    <div class="text-[10px] font-arcade text-emerald-400 uppercase">NET ANNUAL AGENCY PROFIT</div>
                                    <div id="roiAnnualNet" class="text-2xl sm:text-3xl font-extrabold text-emerald-400 font-sans">+$74,292<span class="text-xs font-normal text-slate-300">/yr</span></div>
                                </div>
                                <div class="text-right">
                                    <span id="roiMultiplierBadge" class="px-2.5 py-1 rounded-lg bg-emerald-500 text-slate-950 font-arcade text-[10px] font-bold shadow-sm">10,493% ROI</span>
                                </div>
                            </div>

                            <a id="roiRecommendedCta" href="https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800" class="w-full min-h-[44px] py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-400 hover:from-emerald-400 hover:to-teal-300 text-slate-950 font-bold text-xs uppercase font-sans tracking-wide text-center transition-all shadow-md shadow-emerald-500/20 pixel-btn flex items-center justify-center gap-1.5">
                                <span id="roiRecommendedCtaText">Deploy Recommended Growth Plan ($59/mo)</span>
                                <span>&rarr;</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>"""

assert target_roi_spot in html, "Could not find target_roi_spot"
html = html.replace(target_roi_spot, replacement_roi_spot, 1)

# ==============================================================================
# 4. ADD IN-BROWSER PDF FLIPBOOK MODAL & INTERACTIVE SCRIPTS BEFORE </body>
# ==============================================================================
target_body_end = """            <div class="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between">
                <span>DHH Majestic Ergonomics // Sub-millisecond dispatch</span>
                <span class="text-emerald-400 font-arcade">CR: 99</span>
            </div>
        </div>
    </div>
</body>"""

replacement_body_end = """            <div class="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between">
                <span>DHH Majestic Ergonomics // Sub-millisecond dispatch</span>
                <span class="text-emerald-400 font-arcade">CR: 99</span>
            </div>
        </div>
    </div>

    <!-- In-Browser White-Label PDF Flipbook Preview Modal -->
    <div id="pdfFlipbookModal"
         class="fixed inset-0 hidden items-center justify-center p-3 sm:p-6 transition-all"
         style="z-index: 999999 !important; background-color: rgba(4, 8, 18, 0.92); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);"
         aria-modal="true"
         role="dialog"
         aria-labelledby="flipbookTitle">
        <div class="rounded-2xl max-w-4xl w-full relative text-left overflow-hidden flex flex-col max-h-[90dvh]"
             style="background: #0b1329; border: 2px solid rgba(16, 185, 129, 0.7); box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.95), 0 0 40px rgba(16, 185, 129, 0.25);">
            <!-- Modal Header -->
            <div class="px-5 py-4 bg-slate-950 border-b border-emerald-500/30 flex items-center justify-between gap-3">
                <div class="flex items-center gap-2.5">
                    <span class="text-xl">📖</span>
                    <div>
                        <h3 id="flipbookTitle" class="font-pixel text-emerald-400 text-xs sm:text-sm tracking-wide">WHITE-LABEL EXECUTIVE AUDIT PREVIEW</h3>
                        <p class="text-[11px] text-slate-400 font-mono">100% Co-Branded Deliverable • Zero Orbit Security Watermarks</p>
                    </div>
                </div>
                <div class="flex items-center gap-2">
                    <button type="button" onclick="setFlipbookPage(1)" id="flipBtn-1" class="flip-page-btn px-3 py-1.5 rounded bg-emerald-500 text-slate-950 font-mono text-xs font-bold cursor-pointer">Page 1: Executive Scorecard</button>
                    <button type="button" onclick="setFlipbookPage(2)" id="flipBtn-2" class="flip-page-btn px-3 py-1.5 rounded bg-slate-900 text-slate-300 border border-slate-700 hover:border-emerald-400 font-mono text-xs cursor-pointer">Page 2: Takeover Matrix</button>
                    <button type="button" onclick="setFlipbookPage(3)" id="flipBtn-3" class="flip-page-btn px-3 py-1.5 rounded bg-slate-900 text-slate-300 border border-slate-700 hover:border-emerald-400 font-mono text-xs cursor-pointer">Page 3: DMARC & Remediation</button>
                    <button type="button" onclick="closePdfFlipbookModal()" class="text-slate-400 hover:text-white font-arcade text-xs min-w-[40px] min-h-[40px] px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 cursor-pointer">✕</button>
                </div>
            </div>

            <!-- Simulated High-Craft White Paper Document Body -->
            <div class="p-5 sm:p-8 overflow-y-auto space-y-6 bg-slate-900/90 flex-1">
                <!-- Page 1: Executive Scorecard -->
                <div id="flipPage-1" class="flip-page bg-white text-slate-900 rounded-xl p-6 sm:p-8 shadow-2xl border-t-8 border-emerald-500">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-5 mb-6">
                        <div>
                            <div class="text-[10px] font-mono uppercase tracking-widest text-emerald-700 font-bold">MONTHLY PERIMETER SECURITY & HYGIENE AUDIT</div>
                            <h4 class="text-2xl font-extrabold text-slate-900 mt-1">Prepared for: <span class="text-emerald-600 font-mono">clientbrand.com</span></h4>
                            <p class="text-xs text-slate-500 mt-0.5">Audited & Certified by <strong class="flipbook-agency-name text-slate-800">Apex Digital Studio</strong> • Autonomous Care Plan</p>
                        </div>
                        <div class="px-5 py-3 rounded-xl bg-emerald-50 border border-emerald-200 text-center">
                            <div class="text-[10px] font-mono uppercase text-emerald-800 font-bold">OVERALL POSTURE</div>
                            <div class="text-3xl font-black text-emerald-600">GRADE A</div>
                            <div class="text-[11px] font-mono text-emerald-700">Score: 94 / 100</div>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                        <div class="p-4 rounded-lg bg-slate-50 border border-slate-200">
                            <div class="text-xs font-bold text-slate-700">Subdomain Routing</div>
                            <div class="text-lg font-extrabold text-emerald-600 mt-1">17 / 17 Verified</div>
                            <p class="text-[11px] text-slate-500 mt-1">Zero abandoned CNAMEs or vulnerable cloud buckets detected.</p>
                        </div>
                        <div class="p-4 rounded-lg bg-slate-50 border border-slate-200">
                            <div class="text-xs font-bold text-slate-700">Email Anti-Spoofing</div>
                            <div class="text-lg font-extrabold text-emerald-600 mt-1">p=reject Active</div>
                            <p class="text-[11px] text-slate-500 mt-1">Strict DMARC & SPF enforcement blocking unauthorized senders.</p>
                        </div>
                        <div class="p-4 rounded-lg bg-slate-50 border border-slate-200">
                            <div class="text-xs font-bold text-slate-700">SSL & Transport</div>
                            <div class="text-lg font-extrabold text-emerald-600 mt-1">TLS 1.3 + HSTS</div>
                            <p class="text-[11px] text-slate-500 mt-1">Certificate valid for 78 days. Strict transport headers enforced.</p>
                        </div>
                    </div>
                    <div class="p-4 rounded-lg bg-emerald-50/70 border border-emerald-200 text-xs text-slate-700 leading-relaxed">
                        <strong>Executive Summary for Stakeholders:</strong> During this billing cycle, <span class="flipbook-agency-name font-bold">Apex Digital Studio</span> executed 30 automated passive perimeter inspections across your root domain and marketing subdomains. All DNS pointers, Shopify storefront aliases, and executive email policies remain locked against external hijacking.
                    </div>
                </div>

                <!-- Page 2: Subdomain Takeover Matrix -->
                <div id="flipPage-2" class="flip-page hidden bg-white text-slate-900 rounded-xl p-6 sm:p-8 shadow-2xl border-t-8 border-cyan-500">
                    <div class="flex items-center justify-between border-b border-slate-200 pb-4 mb-5">
                        <div>
                            <div class="text-[10px] font-mono uppercase tracking-widest text-cyan-700 font-bold">SECTION 02 // DNS & SUBDOMAIN TOPOLOGY</div>
                            <h4 class="text-xl font-extrabold text-slate-900 mt-0.5">External Attack Surface & CNAME Verification</h4>
                        </div>
                        <span class="px-3 py-1 rounded bg-slate-100 text-slate-700 font-mono text-xs font-bold">Page 2 of 3</span>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr class="border-b-2 border-slate-200 text-slate-600 font-mono uppercase text-[10px]">
                                    <th class="py-2.5 px-3">Subdomain</th>
                                    <th class="py-2.5 px-3">Record / Target</th>
                                    <th class="py-2.5 px-3">SaaS Fingerprint</th>
                                    <th class="py-2.5 px-3">Takeover Status</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-200 font-mono">
                                <tr>
                                    <td class="py-3 px-3 font-bold text-slate-900">clientbrand.com</td>
                                    <td class="py-3 px-3 text-slate-600">A &rarr; 104.21.45.12</td>
                                    <td class="py-3 px-3 text-slate-600">Cloudflare Edge</td>
                                    <td class="py-3 px-3"><span class="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-bold">PROTECTED</span></td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold text-slate-900">shop.clientbrand.com</td>
                                    <td class="py-3 px-3 text-slate-600">CNAME &rarr; shops.myshopify.com</td>
                                    <td class="py-3 px-3 text-slate-600">Shopify Plus</td>
                                    <td class="py-3 px-3"><span class="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-bold">VERIFIED STORE</span></td>
                                </tr>
                                <tr class="bg-red-50/70">
                                    <td class="py-3 px-3 font-bold text-red-900">promo.clientbrand.com</td>
                                    <td class="py-3 px-3 text-red-700">CNAME &rarr; unbouncepages.com</td>
                                    <td class="py-3 px-3 text-red-700">Unbounce (Orphaned)</td>
                                    <td class="py-3 px-3"><span class="px-2 py-0.5 rounded bg-red-200 text-red-900 font-bold">REMEDIATED BY AGENCY</span></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Page 3: DMARC & Remediation -->
                <div id="flipPage-3" class="flip-page hidden bg-white text-slate-900 rounded-xl p-6 sm:p-8 shadow-2xl border-t-8 border-purple-500">
                    <div class="flex items-center justify-between border-b border-slate-200 pb-4 mb-5">
                        <div>
                            <div class="text-[10px] font-mono uppercase tracking-widest text-purple-700 font-bold">SECTION 03 // CRYPTOGRAPHIC EMAIL & HEADER HYGIENE</div>
                            <h4 class="text-xl font-extrabold text-slate-900 mt-0.5">Executive Anti-Phishing & Compliance</h4>
                        </div>
                        <span class="px-3 py-1 rounded bg-slate-100 text-slate-700 font-mono text-xs font-bold">Page 3 of 3</span>
                    </div>
                    <div class="space-y-4 text-xs text-slate-700">
                        <div class="p-4 rounded-lg bg-slate-50 border border-slate-200">
                            <div class="font-bold text-slate-900 mb-1">1. DMARC Enforcement Record (_dmarc.clientbrand.com)</div>
                            <code class="block p-2 rounded bg-slate-900 text-emerald-400 font-mono mb-2">v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s;</code>
                            <p>Plain-English Impact: Unauthorized third parties attempting to spoof executive emails or send fake wire-transfer invoices using your domain are rejected outright by Gmail and Office 365.</p>
                        </div>
                        <div class="p-4 rounded-lg bg-slate-50 border border-slate-200">
                            <div class="font-bold text-slate-900 mb-1">2. Exposed Environment & Git Secrets Check</div>
                            <p>Probed <code class="font-mono text-slate-900">/.env</code>, <code class="font-mono text-slate-900">/.git/HEAD</code>, and <code class="font-mono text-slate-900">/wp-config.php.bak</code>. All sensitive paths properly return HTTP 403/404 with zero credential leakage.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Modal Footer -->
            <div class="px-5 py-3.5 bg-slate-950 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
                <span class="text-xs text-slate-400 font-mono">💡 Customize the agency name in the Audit Studio to see it reflected live in this preview!</span>
                <div class="flex items-center gap-2.5">
                    <a href="sample_audit.pdf" target="_blank" rel="noopener noreferrer" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-bold transition-colors">Download Full PDF File</a>
                    <button type="button" onclick="closePdfFlipbookModal(); generateInstantPdf();" class="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold uppercase tracking-wide cursor-pointer pixel-btn">Export Custom Branded PDF</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Interactive Growth Engine Controllers (Attack Simulator, Pitch Drawer, ROI Calculator, PDF Flipbook) -->
    <script>
        // 1. Interactive Attack Simulator in Radar Terminal
        function simulateTakeoverAttack() {
            if (window.SimpleCat && SimpleCat.playPowerUp) SimpleCat.playPowerUp();
            const hud = document.getElementById('auditHUD');
            const input = document.getElementById('targetDomain');
            if (input) input.value = 'promo.clientbrand.com';
            if (!hud) return;

            hud.classList.remove('hidden');
            hud.innerHTML = `
                <div class="p-4 sm:p-5 rounded-xl bg-red-950/40 border-2 border-red-500/60 space-y-4 font-mono text-xs">
                    <div class="flex items-center justify-between border-b border-red-500/30 pb-3">
                        <div class="flex items-center gap-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping"></span>
                            <span class="font-arcade text-[10px] text-red-300 uppercase">LIVE EXPLOIT SIMULATION // CNAME HIJACK SEQUENCE</span>
                        </div>
                        <span class="px-2 py-0.5 rounded bg-red-500/20 text-red-300 text-[10px] font-bold border border-red-500/40">CRITICAL RISK</span>
                    </div>
                    <div class="space-y-2.5 text-slate-200">
                        <div class="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 flex items-start gap-2.5">
                            <span class="text-emerald-400 font-bold">[T+0.0s]</span>
                            <span>RFC-8484 DoH Query: <strong class="text-white">promo.clientbrand.com</strong> resolves to <code class="text-amber-300">CNAME unbouncepages.com</code>.</span>
                        </div>
                        <div class="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/40 flex items-start gap-2.5">
                            <span class="text-red-400 font-bold">[T+0.4s]</span>
                            <span>Fingerprint Match: Target SaaS endpoint returns <code class="text-red-300">HTTP 404: The requested URL was not found on this server</code> (Abandoned campaign).</span>
                        </div>
                        <div class="p-2.5 rounded-lg bg-red-950/60 border border-red-500/50 flex items-start gap-2.5">
                            <span class="text-red-300 font-bold">[T+0.8s]</span>
                            <span><strong>Hostile Takeover Path:</strong> Threat actor registers <code class="text-white">promo.clientbrand.com</code> on Unbounce in 45 seconds, inherits parent <code class="text-red-300">.clientbrand.com</code> cookies, and launches a fake customer checkout under your client's genuine SSL padlock.</span>
                        </div>
                        <div class="p-3 rounded-lg bg-emerald-950/70 border border-emerald-500/50 flex items-start gap-2.5">
                            <span class="text-emerald-400 font-bold">[ORBIT SHIELD]</span>
                            <span><strong>Autonomous Interception:</strong> Orbit Sentinel-01 detects the dangling pointer within 60 seconds of campaign expiration, fires an urgent Slack/Email alert to your agency, and generates a client remediation ticket worth <strong class="text-emerald-300">$250/mo in retainer value</strong>.</span>
                        </div>
                    </div>
                    <div class="pt-2 flex flex-wrap items-center justify-between gap-2">
                        <button type="button" onclick="if(window.SimpleCat) SimpleCat.explain('cname')" class="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-emerald-500/40 text-emerald-300 font-pixel text-[11px] cursor-pointer">
                            🐱 Ask Simple Cat to Decode This Attack
                        </button>
                        <button type="button" onclick="setScanTarget('shopify.com'); document.getElementById('scanBtn')?.click();" class="px-3.5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-sans font-bold text-xs uppercase cursor-pointer">
                            Run Real DoH Scan Now &rarr;
                        </button>
                    </div>
                </div>
            `;
            hud.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        // 2. "Steal Our Client Pitch" Copy-Paste Email Drawer
        let currentPitchKey = 'cve';
        const pitchTemplates = {
            cve: {
                subject: '[Action Recommended] Protecting your domain against the October DNS takeover wave',
                body: `Hi [Client Name],\n\nWith the wave of DNS and subdomain takeover vulnerabilities disclosed this week, our engineering team at {{AGENCY}} ran a passive external check on your domain perimeter.\n\nWhen marketing campaigns or third-party tools (like old landing pages, Shopify apps, or email senders) are disconnected, they often leave behind "dangling" DNS records. Attackers are currently scanning for these unattached records to hijack brand subdomains and send spoofed invoices.\n\nTo make sure your brand is completely locked down, we are rolling out continuous 24/7 Attack Surface & DMARC Monitoring across our care plans for $250/mo. On the 1st of every month, you'll receive an executive security scorecard verifying that your subdomains, SSL certificates, and email spoofing defenses are 100% airtight.\n\nReply "LOCK IT DOWN" and we will activate your domain sentinel and send over your baseline Executive Audit PDF today.\n\nBest regards,\n{{AGENCY}}`
            },
            quarterly: {
                subject: 'Quarterly Perimeter Security & Email Deliverability Audit for [Client Domain]',
                body: `Hi [Client Name],\n\nAs part of our proactive stewardship at {{AGENCY}}, we just completed a non-intrusive external perimeter review of your domain and email authentication records (SPF, DKIM, and DMARC).\n\nWhile your primary storefront is performing great, Gmail and Microsoft 365 have tightened their sender enforcement rules—meaning any drift in your DNS records can cause customer order confirmations to land in spam or leave your domain open to spoofing.\n\nWe've packaged continuous 24/7 DNS drift surveillance and a monthly white-label Executive Security Audit PDF into our $250/mo Perimeter Care Plan. Would you like us to attach your initial baseline report and enable monthly protection?\n\nBest regards,\n{{AGENCY}}`
            },
            handover: {
                subject: 'Launch Complete! Next Step: Protecting Your New Site Perimeter',
                body: `Hi [Client Name],\n\nCongratulations again on the launch! Now that your new site is live, protecting your domain reputation, SSL transport layer, and subdomain routing is critical.\n\nAt {{AGENCY}}, we include our Autonomous Perimeter & Subdomain Hygiene Sentinel in our $250/mo Website Care Retainer. Every month on the 1st, you receive a certified Executive Security Audit PDF proving that your DNS records, Shopify/SaaS integrations, and executive email policies are secure against hijacking.\n\nLet us know if you'd like us to activate your 24/7 perimeter sentinel as part of your post-launch care plan.\n\nBest regards,\n{{AGENCY}}`
            }
        };

        function getActiveAgencyName() {
            const input = document.getElementById('customAgencyName');
            return (input && input.value.trim()) ? input.value.trim() : 'Apex Digital Studio';
        }

        function switchPitchTemplate(key) {
            currentPitchKey = key;
            if (window.SimpleCat && SimpleCat.playBlip) SimpleCat.playBlip();
            const agency = getActiveAgencyName();
            const tpl = pitchTemplates[key] || pitchTemplates.cve;

            const subjEl = document.getElementById('pitchSubjectDisplay');
            const bodyEl = document.getElementById('pitchBodyDisplay');
            if (subjEl) subjEl.textContent = tpl.subject;
            if (bodyEl) bodyEl.textContent = tpl.body.replace(/\{\{AGENCY\}\}/g, agency);

            ['cve', 'quarterly', 'handover'].forEach(k => {
                const btn = document.getElementById('pitchTab-' + k);
                if (!btn) return;
                if (k === key) {
                    btn.className = 'pitch-tab-btn min-h-[42px] px-3.5 py-2 rounded-xl text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 cursor-pointer whitespace-nowrap';
                } else {
                    btn.className = 'pitch-tab-btn min-h-[42px] px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 text-slate-300 hover:text-white border border-slate-700 cursor-pointer whitespace-nowrap';
                }
            });
        }

        function copyClientPitch() {
            const subj = document.getElementById('pitchSubjectDisplay')?.textContent || '';
            const body = document.getElementById('pitchBodyDisplay')?.textContent || '';
            const fullText = `Subject: ${subj}\n\n${body}`;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(fullText);
            }
            if (window.SimpleCat && SimpleCat.playPowerUp) SimpleCat.playPowerUp();
            const btnText = document.getElementById('copyPitchBtnText');
            if (btnText) {
                const orig = btnText.textContent;
                btnText.textContent = '✓ Copied to Clipboard!';
                setTimeout(() => { btnText.textContent = orig; }, 2200);
            }
        }

        // Sync Agency Name changes across Pitch Drawer & PDF Flipbook
        document.addEventListener('DOMContentLoaded', () => {
            const agencyInput = document.getElementById('customAgencyName');
            if (agencyInput) {
                agencyInput.addEventListener('input', () => {
                    switchPitchTemplate(currentPitchKey);
                    document.querySelectorAll('.flipbook-agency-name').forEach(el => {
                        el.textContent = getActiveAgencyName();
                    });
                });
            }
        });

        // 3. Interactive Agency Retainer ROI Calculator
        function updateRoiCalculator() {
            const clients = parseInt(document.getElementById('roiClientCount')?.value || '25', 10);
            const fee = parseInt(document.getElementById('roiRetainerFee')?.value || '250', 10);

            const countEl = document.getElementById('roiClientCountVal');
            const feeEl = document.getElementById('roiRetainerFeeVal');
            if (countEl) countEl.textContent = clients + (clients === 1 ? ' Client' : ' Clients');
            if (feeEl) feeEl.textContent = '$' + fee + ' / mo';

            let orbitCost = 59;
            let tierName = 'Growth';
            let checkoutUrl = 'https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800';
            if (clients <= 15) {
                orbitCost = 29;
                tierName = 'Starter';
                checkoutUrl = 'https://buy.stripe.com/8x29ASgAk3V15X2el6cs801';
            } else if (clients > 40) {
                orbitCost = 99;
                tierName = 'Pro';
                checkoutUrl = 'https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802';
            }

            const grossMonthly = clients * fee;
            const netMonthly = grossMonthly - orbitCost;
            const netAnnual = netMonthly * 12;
            const roiPct = Math.round((netMonthly / orbitCost) * 100);

            const grossEl = document.getElementById('roiMonthlyGross');
            const costEl = document.getElementById('roiOrbitCost');
            const annualEl = document.getElementById('roiAnnualNet');
            const badgeEl = document.getElementById('roiMultiplierBadge');
            const ctaEl = document.getElementById('roiRecommendedCta');
            const ctaTextEl = document.getElementById('roiRecommendedCtaText');

            if (grossEl) grossEl.innerHTML = '$' + grossMonthly.toLocaleString() + '<span class="text-xs font-normal text-slate-400">/mo</span>';
            if (costEl) costEl.textContent = '$' + orbitCost + '/mo (' + tierName + ')';
            if (annualEl) annualEl.innerHTML = '+$' + netAnnual.toLocaleString() + '<span class="text-xs font-normal text-slate-300">/yr</span>';
            if (badgeEl) badgeEl.textContent = roiPct.toLocaleString() + '% ROI';
            if (ctaEl) ctaEl.href = checkoutUrl;
            if (ctaTextEl) ctaTextEl.textContent = 'Deploy Recommended ' + tierName + ' Plan ($' + orbitCost + '/mo)';
        }

        // 4. In-Browser PDF Flipbook Modal
        function openPdfFlipbookModal() {
            if (window.SimpleCat && SimpleCat.playBlip) SimpleCat.playBlip();
            const modal = document.getElementById('pdfFlipbookModal');
            if (!modal) return;
            document.querySelectorAll('.flipbook-agency-name').forEach(el => {
                el.textContent = getActiveAgencyName();
            });
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            setFlipbookPage(1);
        }

        function closePdfFlipbookModal() {
            const modal = document.getElementById('pdfFlipbookModal');
            if (!modal) return;
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }

        function setFlipbookPage(pageNum) {
            if (window.SimpleCat && SimpleCat.playBlip) SimpleCat.playBlip();
            [1, 2, 3].forEach(n => {
                const page = document.getElementById('flipPage-' + n);
                const btn = document.getElementById('flipBtn-' + n);
                if (page) {
                    if (n === pageNum) page.classList.remove('hidden');
                    else page.classList.add('hidden');
                }
                if (btn) {
                    if (n === pageNum) {
                        btn.className = 'flip-page-btn px-3 py-1.5 rounded bg-emerald-500 text-slate-950 font-mono text-xs font-bold cursor-pointer';
                    } else {
                        btn.className = 'flip-page-btn px-3 py-1.5 rounded bg-slate-900 text-slate-300 border border-slate-700 hover:border-emerald-400 font-mono text-xs cursor-pointer';
                    }
                }
            });
        }
    </script>
</body>"""

assert target_body_end in html, "Could not find target_body_end"
html = html.replace(target_body_end, replacement_body_end, 1)

if has_crlf:
    html = html.replace("\n", "\r\n")

for out_path in ["A:/projects/orbit-security/docs/index.html", "A:/projects/orbit-security/landing/index.html"]:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"SUCCESS: Wrote all 4 upgrades to {out_path}")
