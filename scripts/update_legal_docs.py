import os
import shutil

DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "docs")
LANDING_DIR = os.path.join(os.path.dirname(__file__), "..", "landing")

# 1. Update disclaimer.html
disclaimer_path = os.path.join(DOCS_DIR, "disclaimer.html")
with open(disclaimer_path, "r", encoding="utf-8") as f:
    disclaimer_content = f.read()

regulatory_section = """
            <!-- Section 4: Industry & Regulatory Compliance Alignment -->
            <section class="space-y-4">
                <h2 class="text-lg font-bold text-white flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                    4. Regulatory Standards & Compliance Alignment
                </h2>
                <p class="text-xs text-slate-300 leading-relaxed">
                    Orbit Security's automated heuristics are explicitly mapped to recognized web security and email deliverability frameworks:
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                    <div class="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                        <span class="text-emerald-400 font-bold block mb-1 font-pixel">Google & Yahoo 2024 Sender Mandates</span>
                        <p class="text-slate-400 font-sans text-xs leading-relaxed">
                            Automates mandatory verification of SPF alignment, DKIM signatures, and strict DMARC (<code class="text-emerald-300">p=quarantine</code> or <code class="text-emerald-300">p=reject</code>) to prevent bulk email rejection.
                        </p>
                    </div>
                    <div class="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                        <span class="text-cyan-400 font-bold block mb-1 font-pixel">PCI-DSS v4.0 Requirement 6.4.3 & 11.6.1</span>
                        <p class="text-slate-400 font-sans text-xs leading-relaxed">
                            Assists ecommerce agencies in confirming Content-Security-Policy (CSP) script authorization and HTTP header tampering shields across checkout perimeters.
                        </p>
                    </div>
                    <div class="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                        <span class="text-purple-400 font-bold block mb-1 font-pixel">OWASP Top 10 A05: Security Misconfiguration</span>
                        <p class="text-slate-400 font-sans text-xs leading-relaxed">
                            Continuously tracks dangling DNS pointers to decommissioned cloud assets (AWS S3, Shopify, Unbounce) to eliminate hostile subdomain takeovers.
                        </p>
                    </div>
                    <div class="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                        <span class="text-amber-400 font-bold block mb-1 font-pixel">FTC Safeguards & Cyber Insurance Hygiene</span>
                        <p class="text-slate-400 font-sans text-xs leading-relaxed">
                            Provides objective third-party monthly PDF audit documentation required by cyber insurance underwriters to substantiate proactive perimeter care.
                        </p>
                    </div>
                </div>
            </section>

            <!-- Section 5: Agency Client Safe Harbor Contract Rider -->
            <section class="space-y-4 pt-4 border-t border-slate-800">
                <div class="flex items-center justify-between">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                        5. Agency-Client Safe Harbor Contract Rider (Copy-Paste for Agency MSAs)
                    </h2>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">AGENCY SHIELD</span>
                </div>
                <p class="text-xs text-slate-400">
                    Agencies subscribing to Orbit Security may incorporate the following standard provision into their client Master Services Agreements (MSAs), Web Care Plans, or Maintenance SOWs to establish clear contractual authority:
                </p>
                <div class="p-4 rounded-xl bg-slate-900/90 border border-emerald-500/30 font-mono text-xs text-slate-300 relative group">
                    <pre class="whitespace-pre-wrap leading-relaxed select-all">"Client authorizes Agency and its automated security telemetry partners (including Orbit Security) to conduct continuous, non-intrusive external perimeter reconnaissance, DNS authentication analysis (SPF/DKIM/DMARC), subdomain routing checks, and public HTTP header verification across Client's digital domains and staging properties. Client acknowledges that all surveillance is conducted passively or via standard RFC-compliant HTTP queries without payload execution or access-control bypasses, and serves solely to maintain attack surface hygiene."</pre>
                </div>
            </section>
"""

if "<!-- Section 4: Domain Exclusion -->" in disclaimer_content:
    disclaimer_content = disclaimer_content.replace(
        "<!-- Section 4: Domain Exclusion -->",
        regulatory_section + "\n            <!-- Section 6: Domain Exclusion -->"
    ).replace("4. Domain Exclusion & Opt-Out Request", "6. Domain Exclusion & Opt-Out Request")
    with open(disclaimer_path, "w", encoding="utf-8") as f:
        f.write(disclaimer_content)
    print("[✓] disclaimer.html updated")

# 2. Update privacy.html
privacy_path = os.path.join(DOCS_DIR, "privacy.html")
with open(privacy_path, "r", encoding="utf-8") as f:
    privacy_content = f.read()

zero_server_section = """
            <!-- Section 2: Information Architecture & Zero-Server Logging Guarantee -->
            <section class="space-y-3">
                <h2 class="text-lg font-bold text-white flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                    2. Information We Collect & Zero-Server Scanning Architecture
                </h2>
                <div class="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 mb-3 space-y-1">
                    <div class="font-bold uppercase tracking-wider flex items-center gap-1.5">
                        <span>🛡️ Zero-Server Logging Guarantee for Browser Scans:</span>
                    </div>
                    <p class="text-slate-200">
                        When you enter a domain into the Orbit Radar Terminal on our landing page or Fleet Command Center, the lookup is performed <strong>100% within your client browser</strong> using RFC 8484 DNS-over-HTTPS. Orbit Security's web servers never receive, store, or log the target domains you analyze.
                    </p>
                </div>
                <ul class="list-disc pl-6 space-y-2 text-slate-300 text-xs">
                    <li><strong>Account & Contact Information:</strong> Your agency name, contact email address, and billing details provided when you voluntarily register, email our founder, or subscribe via Stripe.</li>
                    <li><strong>Financial & Transaction Data:</strong> All payments are processed directly by Stripe (PCI-DSS Service Provider Level 1). Orbit Security never accesses, processes, or stores your credit card numbers, CVVs, or bank account credentials.</li>
                    <li><strong>Third-Party DNS Resolvers:</strong> Browser-based DoH lookups query public resolvers provided by Google Public DNS (Google Privacy Policy) and Cloudflare (Cloudflare 1.1.1.1 Privacy Policy, which guarantees 24-hour log purges and zero IP-to-query correlation).</li>
                    <li><strong>Static Hosting Telemetry:</strong> Standard web server connection logs (IP address, browser user-agent) generated transiently by GitHub Pages infrastructure.</li>
                </ul>
            </section>
"""

cookie_localstorage_section = """
            <!-- Section 4: Cookies, LocalStorage & Tracking -->
            <section class="space-y-3">
                <h2 class="text-lg font-bold text-white flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                    4. Cookies, Browser LocalStorage & Third-Party Trackers
                </h2>
                <p>
                    Orbit Security adheres to strict privacy-first standards:
                </p>
                <ul class="list-disc pl-6 space-y-2 text-slate-300 text-xs">
                    <li><strong>Zero Advertising Tracking Cookies:</strong> We do not deploy third-party advertising cookies, conversion tracking pixels (e.g., Meta Pixel, Google Ads), or invasive behavioral session recording software (e.g., Hotjar, FullStory).</li>
                    <li><strong>HTML5 LocalStorage Usage:</strong> Our multi-domain Fleet Command Center (<code class="text-emerald-400">fleet.html</code>) utilizes browser <code class="text-emerald-400">window.localStorage</code> under the key <code class="text-emerald-400">orbit_fleet_registry_v2</code> solely to persist your client domain registry locally on your device between browser sessions. This data is never synchronized to Orbit Security servers. You can permanently delete this local data at any time by clearing your browser cache or clicking "Clear Fleet" in the application.</li>
                    <li><strong>Client-Side PDF Compilation:</strong> All executive PDF deliverables generated via the "Export Branded PDF" feature are compiled purely in client RAM using <code class="text-emerald-400">pdf-lib</code>. No client logos, audit scores, or corporate identities are uploaded to third-party rendering clouds.</li>
                </ul>
            </section>
"""

# Replace sections if present
if "<!-- Section 2: Information We Collect -->" in privacy_content:
    # Find start and end of Section 2
    sec2_start = privacy_content.find("<!-- Section 2: Information We Collect -->")
    sec3_start = privacy_content.find("<!-- Section 3: How We Use Your Information -->")
    if sec2_start != -1 and sec3_start != -1:
        privacy_content = privacy_content[:sec2_start] + zero_server_section.strip() + "\n\n            " + privacy_content[sec3_start:]

if "<!-- Section 4: Cookies & Tracking -->" in privacy_content:
    sec4_start = privacy_content.find("<!-- Section 4: Cookies & Tracking -->")
    sec5_start = privacy_content.find("<!-- Section 5: Data Storage & Security -->")
    if sec4_start != -1 and sec5_start != -1:
        privacy_content = privacy_content[:sec4_start] + cookie_localstorage_section.strip() + "\n\n            " + privacy_content[sec5_start:]

with open(privacy_path, "w", encoding="utf-8") as f:
    f.write(privacy_content)
print("[✓] privacy.html updated")

# 3. Update terms.html
terms_path = os.path.join(DOCS_DIR, "terms.html")
with open(terms_path, "r", encoding="utf-8") as f:
    terms_content = f.read()

white_label_license = """
            <!-- Section 4: White-Label Commercial License & Agency Deliverables -->
            <section class="space-y-3">
                <h2 class="text-lg font-bold text-white flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                    4. White-Label Commercial License & Agency Deliverables
                </h2>
                <p>
                    Subscribers to active Orbit Security plans (Starter, Growth, Pro) are granted a perpetual, royalty-free, worldwide commercial license to generate, co-brand (incorporating the agency's exclusive logo, typography, and color schemes), package, and distribute monthly perimeter audit deliverables to direct agency clients as part of paid website maintenance retainers or security stewardship plans.
                </p>
                <p class="text-xs text-slate-400">
                    Orbit Security claims zero intellectual property or copyright over custom-generated client audit PDFs and grants agencies full authorization to market these audits under their proprietary agency care plan branding.
                </p>
            </section>
"""

if "<!-- Section 4: Acceptable Use -->" in terms_content:
    terms_content = terms_content.replace(
        "<!-- Section 4: Acceptable Use -->",
        white_label_license.strip() + "\n\n            <!-- Section 5: Acceptable Use -->"
    ).replace("4. Acceptable Use Policy", "5. Acceptable Use Policy")
    # Bump other sections
    terms_content = terms_content.replace("5. Subscription, Billing & Cancellation", "6. Subscription, Billing & Cancellation")
    terms_content = terms_content.replace("6. Disclaimer of Warranties", "7. Disclaimer of Warranties & Downstream Client Limitation")
    terms_content = terms_content.replace("7. Limitation of Liability", "8. Limitation of Liability")
    terms_content = terms_content.replace("8. Governing Law", "9. Governing Law")
    terms_content = terms_content.replace("9. Modifications to Terms", "10. Modifications to Terms")

    with open(terms_path, "w", encoding="utf-8") as f:
        f.write(terms_content)
    print("[✓] terms.html updated")

# 4. Update refunds.html
refunds_path = os.path.join(DOCS_DIR, "refunds.html")
with open(refunds_path, "r", encoding="utf-8") as f:
    refunds_content = f.read()

if "Within 24 Hours of Request" not in refunds_content:
    refunds_content = refunds_content.replace(
        "Refunds are processed within 1-2 business days",
        "Refunds are processed within 24 hours of request (guaranteed 24h SLA)"
    )
    with open(refunds_path, "w", encoding="utf-8") as f:
        f.write(refunds_content)
    print("[✓] refunds.html updated")

# Sync all legal files from docs/ to landing/
for fname in ["disclaimer.html", "privacy.html", "terms.html", "refunds.html"]:
    src = os.path.join(DOCS_DIR, fname)
    dst = os.path.join(LANDING_DIR, fname)
    shutil.copy2(src, dst)
    print(f"[✓] Synced {fname} to landing/")

print("[*] All legal documents upgraded and synchronized successfully!")
