# -*- coding: utf-8 -*-
"""
Script to inject the breaking security advisory banner into docs/index.html and landing/index.html
"""

target = """        <div class="max-w-5xl mx-auto px-4 sm:px-6 text-center relative z-10">
            <!-- High-Impact Eyebrow Badge (CRO & Value Proposition) -->"""

advisory = """        <div class="max-w-5xl mx-auto px-4 sm:px-6 text-center relative z-10">
            <!-- Breaking Vulnerability & Perimeter Advisory Banner (October 2026 Wave) -->
            <div class="mb-6 p-4 sm:p-5 rounded-2xl bg-gradient-to-r from-red-950/85 via-slate-900/95 to-slate-900/90 border border-red-500/50 shadow-2xl shadow-red-950/40 backdrop-blur-md text-left relative overflow-hidden group">
                <div class="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-red-500 via-amber-400 to-emerald-400 animate-pulse"></div>
                <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                    <div class="flex items-start gap-3.5">
                        <div class="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center flex-shrink-0 text-red-400 font-bold text-lg shadow-inner">
                            🚨
                        </div>
                        <div>
                            <div class="flex items-center gap-2 flex-wrap mb-1">
                                <span class="px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-arcade text-[9px] uppercase tracking-wide border border-red-500/40">SECURITY ADVISORY</span>
                                <span class="text-xs font-mono text-slate-200 font-bold">OCTOBER 2026 MASS PERIMETER CVEs ACTIVE</span>
                                <span class="hidden sm:inline-block w-1.5 h-1.5 rounded-full bg-red-400 animate-ping"></span>
                            </div>
                            <p class="text-xs sm:text-sm text-slate-300 font-sans leading-relaxed">
                                <strong class="text-white">Active CNAME & DNS Hijacking Surge:</strong> Stale CDN pointers, unattached SaaS subdomains, and permissive DMARC/SPF policies are currently exposing client domains to zero-click subdomain takeovers and spoofed phishing. Test client perimeter exposure in real time with our zero-packet DoH radar.
                            </p>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 w-full md:w-auto flex-shrink-0">
                        <button type="button" onclick="if(window.setScanTarget){setScanTarget('shopify.com');} const el=document.getElementById('audit-terminal'); if(el){el.scrollIntoView({behavior:'smooth',block:'center'});} const btn=document.getElementById('scanBtn'); if(btn){setTimeout(function(){btn.click();},350);}" class="w-full md:w-auto px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-500 to-amber-500 hover:from-red-400 hover:to-amber-400 text-slate-950 font-bold text-xs uppercase font-sans tracking-wide transition-all shadow-lg shadow-red-500/25 pixel-btn flex items-center justify-center gap-2 cursor-pointer">
                            <span>Scan Live Perimeter</span>
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/></svg>
                        </button>
                    </div>
                </div>
            </div>

            <!-- High-Impact Eyebrow Badge (CRO & Value Proposition) -->"""

for path in ['A:/projects/orbit-security/docs/index.html', 'A:/projects/orbit-security/landing/index.html']:
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Normalize CRLF for matching if necessary
    norm_content = content.replace('\r\n', '\n')
    norm_target = target.replace('\r\n', '\n')
    norm_advisory = advisory.replace('\r\n', '\n')

    if norm_target in norm_content:
        updated = norm_content.replace(norm_target, norm_advisory, 1)
        # Restore CRLF if original had CRLF
        if '\r\n' in content:
            updated = updated.replace('\n', '\r\n')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(updated)
        print(f"SUCCESS: Updated {path}")
    else:
        print(f"ERROR: Target not found in {path}")
