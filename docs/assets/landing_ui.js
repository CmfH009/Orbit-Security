/* Orbit Security — Landing Page UI Controllers (Extracted from landing/index.html) */

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function playOrbitExplainer() {
    const vid = document.getElementById('orbit-explainer-video');
    if (!vid) return;
    if (vid.ended || vid.currentTime >= (vid.duration || 71.9) - 0.3) {
        vid.currentTime = 0;
    }
    vid.muted = false;
    vid.play().catch(() => {});
    if (window.SimpleCat && SimpleCat.playBlip) SimpleCat.playBlip();
}

function seekOrbitExplainer(seconds) {
    const vid = document.getElementById('orbit-explainer-video');
    if (!vid) return;
    const target = Number(seconds) || 0;
    vid.currentTime = target;
    updateExplainerChapterHighlight(target);
    vid.muted = false;
    vid.play().catch(() => {});
    if (window.SimpleCat && SimpleCat.playBlip) SimpleCat.playBlip();
}

let lastActiveChapterIndex = 0;

function formatExplainerTime(seconds) {
    const s = Math.max(0, Math.floor(Number(seconds) || 0));
    const mins = Math.floor(s / 60);
    const rem = s % 60;
    return `${mins}:${rem < 10 ? '0' : ''}${rem}`;
}

function updateExplainerChapterHighlight(currentTime) {
    const btns = Array.from(document.querySelectorAll('.explainer-chapter-btn'));
    if (!btns.length) return;
    const cur = Math.max(0, Number(currentTime) || 0);
    let activeIdx = 0;
    btns.forEach((btn, idx) => {
        const t = parseFloat(btn.getAttribute('data-chapter-time') || '0');
        if (cur + 0.25 >= t) {
            activeIdx = idx;
        }
    });
    const activeBtn = btns[activeIdx];
    for (const btn of btns) {
        const isActive = btn === activeBtn;
        btn.classList.toggle('bg-emerald-500/20', isActive);
        btn.classList.toggle('border-emerald-500/50', isActive);
        btn.classList.toggle('text-emerald-300', isActive);
        btn.classList.toggle('font-bold', isActive);
        btn.classList.toggle('bg-slate-900', !isActive);
        btn.classList.toggle('border-slate-700/80', !isActive);
        btn.classList.toggle('text-slate-300', !isActive);
        btn.classList.toggle('font-semibold', !isActive);
        if (isActive) {
            btn.setAttribute('aria-current', 'true');
        } else {
            btn.removeAttribute('aria-current');
        }
    }
    if (activeIdx !== lastActiveChapterIndex) {
        lastActiveChapterIndex = activeIdx;
        if (activeBtn && typeof activeBtn.scrollIntoView === 'function') {
            try {
                activeBtn.scrollIntoView({ behavior: 'smooth', inline: 'nearest', block: 'nearest' });
            } catch (_) {}
        }
    }
    const badgeEl = document.getElementById('explainerActiveChapterBadge');
    if (badgeEl && activeBtn) {
        const rawLabel = activeBtn.textContent.trim().replace(/^\d+:\d+\s*/, '');
        badgeEl.textContent = `CH ${activeIdx + 1}/${btns.length} · ${rawLabel}`;
    }
    const vid = document.getElementById('orbit-explainer-video');
    const totalDur = (vid && Number.isFinite(vid.duration) && vid.duration > 0) ? vid.duration : 72;
    const timeEl = document.getElementById('explainerTimeReadout');
    if (timeEl) {
        timeEl.textContent = `${formatExplainerTime(cur)} / ${formatExplainerTime(totalDur)}`;
    }
    const barEl = document.getElementById('explainerProgressBar');
    if (barEl) {
        const pct = Math.max(0, Math.min(100, (cur / totalDur) * 100));
        barEl.style.width = `${pct.toFixed(1)}%`;
    }
}
window.updateExplainerChapterHighlight = updateExplainerChapterHighlight;

// 1. Interactive 4-Scenario Attack Simulator in Radar Terminal
const SIMULATOR_SCENARIOS = {
    cname: {
        domain: 'promo.clientbrand.com',
        headerTitle: 'LIVE EXPLOIT SIMULATION // CNAME HIJACK SEQUENCE',
        badge: 'CRITICAL RISK',
        steps: [
            { t: '[T+0.0s]', color: 'text-emerald-400', border: 'border-slate-800', bg: 'bg-slate-950/80', html: 'RFC-8484 DoH Query: <strong class="text-white">promo.clientbrand.com</strong> resolves to <code class="text-amber-300">CNAME unbouncepages.com</code>.' },
            { t: '[T+0.4s]', color: 'text-red-400', border: 'border-red-500/40', bg: 'bg-slate-950/80', html: 'Fingerprint Match: Target SaaS endpoint returns <code class="text-red-300">HTTP 404: The requested URL was not found on this server</code> (Abandoned campaign).' },
            { t: '[T+0.8s]', color: 'text-red-300', border: 'border-red-500/50', bg: 'bg-red-950/60', html: '<strong>Hostile Takeover Path:</strong> Threat actor registers <code class="text-white">promo.clientbrand.com</code> on Unbounce in 45 seconds, inherits parent <code class="text-red-300">.clientbrand.com</code> cookies, and launches a fake customer checkout under your client\'s genuine SSL padlock.' },
            { t: '[ORBIT SHIELD]', color: 'text-emerald-400', border: 'border-emerald-500/50', bg: 'bg-emerald-950/70', html: '<strong>Autonomous Interception:</strong> Orbit Sentinel-01 detects the dangling pointer on its automated perimeter sweep, fires an urgent Slack/Email alert to your agency, and generates a client remediation ticket worth <strong class="text-emerald-300">$250/mo in retainer value</strong>.' }
        ],
        snippetTitle: 'Cloudflare / Route53 Remediation Command',
        snippetCode: '# Delete dangling CNAME immediately or reclaim SaaS endpoint:\norbit-recon promo.clientbrand.com --remediate'
    },
    dmarc: {
        domain: 'clientbrand.com',
        headerTitle: 'LIVE EXPLOIT SIMULATION // DMARC p=none EXECUTIVE SPOOFING',
        badge: 'HIGH SPOOF RISK',
        steps: [
            { t: '[T+0.0s]', color: 'text-emerald-400', border: 'border-slate-800', bg: 'bg-slate-950/80', html: 'RFC-8484 TXT Lookup: <strong class="text-white">_dmarc.clientbrand.com</strong> returns <code class="text-amber-300">v=DMARC1; p=none;</code> (Monitoring only — zero enforcement).' },
            { t: '[T+0.3s]', color: 'text-red-400', border: 'border-red-500/40', bg: 'bg-slate-950/80', html: 'SPF Evaluation: Softfail <code class="text-red-300">~all</code> detected without strict DKIM alignment (<code class="text-amber-300">adkim=r</code>).' },
            { t: '[T+0.7s]', color: 'text-red-300', border: 'border-red-500/50', bg: 'bg-red-950/60', html: '<strong>Invoice Wire Fraud Path:</strong> Attacker dispatches spoofed wire-transfer instructions from <code class="text-white">ceo@clientbrand.com</code>. Because <code class="text-red-300">p=none</code> instructs Gmail/M365 to deliver unauthenticated mail, the fake invoice lands directly in the VIP inbox.' },
            { t: '[ORBIT SHIELD]', color: 'text-emerald-400', border: 'border-emerald-500/50', bg: 'bg-emerald-950/70', html: '<strong>Autonomous Interception:</strong> Orbit generates copy-paste Cloudflare & Route53 TXT records upgrading the domain to <code class="text-emerald-300">p=reject; sp=reject; adkim=s; aspf=s;</code> + MTA-STS TLS enforcement.' }
        ],
        snippetTitle: 'Hardened DMARC TXT Record',
        snippetCode: '_dmarc.clientbrand.com. 300 IN TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@clientbrand.com;"'
    },
    dotenv: {
        domain: 'shop.clientbrand.com',
        headerTitle: 'LIVE EXPLOIT SIMULATION // EXPOSED .ENV & .GIT SECRETS HARVEST',
        badge: 'CRITICAL LEAK',
        steps: [
            { t: '[T+0.0s]', color: 'text-emerald-400', border: 'border-slate-800', bg: 'bg-slate-950/80', html: 'Perimeter Probe: <strong class="text-white">https://shop.clientbrand.com/.env</strong> and <strong class="text-white">/.git/config</strong>.' },
            { t: '[T+0.4s]', color: 'text-red-400', border: 'border-red-500/40', bg: 'bg-slate-950/80', html: 'Misconfigured Web Root: Server returns <code class="text-red-300">HTTP 200 OK (text/plain)</code> instead of <code class="text-emerald-300">403/404</code>, leaking <code class="text-amber-300">STRIPE_LIVE_SECRET_KEY</code> and <code class="text-amber-300">AWS_SECRET_ACCESS_KEY</code>.' },
            { t: '[T+0.9s]', color: 'text-red-300', border: 'border-red-500/50', bg: 'bg-red-950/60', html: '<strong>Automated Secret Exploitation:</strong> Botnet exfiltrates production database credentials and Stripe API keys within 90 seconds of an agency staging deployment.' },
            { t: '[ORBIT SHIELD]', color: 'text-emerald-400', border: 'border-emerald-500/50', bg: 'bg-emerald-950/70', html: '<strong>Autonomous Interception:</strong> Orbit\'s SPA-aware stream scanner verifies dotfile and backup (<code class="text-emerald-300">wp-config.php.bak</code>) isolation after every deploy with zero false positives.' }
        ],
        snippetTitle: 'Nginx Dotfile & Backup Lockdown',
        snippetCode: 'location ~ /\\.(?!well-known).* { deny all; access_log off; log_not_found off; }'
    },
    php418: {
        domain: 'cms.clientbrand.com',
        headerTitle: 'LIVE EXPLOIT SIMULATION // PHP BOT RCE vs. HTTP 418 TEAPOT SHIELD',
        badge: 'CVE-2017-9841 + PEARCMD',
        steps: [
            { t: '[T+0.0s]', color: 'text-red-400', border: 'border-red-500/40', bg: 'bg-slate-950/80', html: 'Bot Scanner (<code class="text-amber-300">103.46.186.148</code>) sweeps <code class="text-white">/api</code>, <code class="text-white">/cms</code>, <code class="text-white">/workspace/drupal</code>, and <code class="text-white">/app</code> for <code class="text-red-300">/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php</code>.' },
            { t: '[T+0.4s]', color: 'text-red-400', border: 'border-red-500/40', bg: 'bg-slate-950/80', html: 'ThinkPHP & PEAR LFI Chain: Bot fires <code class="text-amber-300">?s=/index/\\think\\app/invokefunction</code> followed by <code class="text-red-300">?lang=../../../../usr/local/lib/php/pearcmd&+config-create+/&lt;?echo(md5("hi"));?&gt;+/tmp/index1.php</code>.' },
            { t: '[T+0.8s]', color: 'text-emerald-400', border: 'border-emerald-500/50', bg: 'bg-emerald-950/70', html: '<strong>HTTP 418 Teapot Sinkhole Active:</strong> Hardened perimeter drops all 16 exploit probes with <code class="text-emerald-300">HTTP/1.1 418 I\'m a teapot (194 bytes)</code> while <code class="text-emerald-300">register_argc_argv = Off</code> neutralizes <code class="text-white">pearcmd.php</code> CLI injection.' },
            { t: '[ORBIT SHIELD]', color: 'text-cyan-300', border: 'border-cyan-500/50', bg: 'bg-slate-900/90', html: '<strong>Pre-Exploit Agency Audit:</strong> Orbit pre-screens client domains for exposed <code class="text-white">/vendor/composer/installed.json</code>, <code class="text-white">eval-stdin.php</code>, and <code class="text-white">X-Powered-By: PHP</code> banners, and exports the ready-to-deploy Nginx <code class="text-emerald-300">return 418;</code> sinkhole block below.' }
        ],
        snippetTitle: 'Nginx HTTP 418 ("I\'m a teapot") PHP Bot Sinkhole + php.ini Shield',
        snippetCode: `location ~* (?:/vendor/|eval-stdin\\.php|/\\.(?:env|git|DS_Store)|wp-config\\.php\\.(?:bak|old)|phpinfo\\.php) {
    return 418; # HTTP 418 I'm a teapot sinkhole
}
if ($query_string ~* "(?:invokefunction|call_user_func_array|pearcmd|\\+config-create\\+|\\.\\./\\.\\./)") {
    return 418;
}
# php.ini: expose_php = Off | register_argc_argv = Off`
    }
};

function copySimSnippet(key) {
    const sc = SIMULATOR_SCENARIOS[key] || SIMULATOR_SCENARIOS.cname;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(sc.snippetCode);
    }
    const btn = document.getElementById('copySimSnippetBtn');
    if (btn) {
        const orig = btn.textContent;
        btn.textContent = '✓ Copied Shield Config!';
        setTimeout(() => { btn.textContent = orig; }, 2000);
    }
}

function simulateTakeoverAttack(scenarioKey = 'cname', customDomain = null, customCname = null) {
    if (window.OrbitAttackTree && typeof OrbitAttackTree.simulateTakeoverAttack === 'function') {
        return OrbitAttackTree.simulateTakeoverAttack(scenarioKey, customDomain, customCname);
    }
    if (window.SimpleCat && typeof SimpleCat.playPowerUp === 'function') SimpleCat.playPowerUp();
    const hud = document.getElementById('auditHUD');
    const domain = customDomain || document.getElementById('targetDomain')?.value || 'media.client-store.com';
    let key = scenarioKey;
    if (key === 'cname') key = 'aws_s3';

    if (window.OrbitAttackTree && typeof OrbitAttackTree.renderInHud === 'function') {
        OrbitAttackTree.renderInHud('auditHUD', key, domain, customCname);
    }
    if (hud) {
        hud.classList.remove('hidden');
        const targetEl = document.getElementById('audit-terminal') || hud;
        if (targetEl && typeof targetEl.scrollIntoView === 'function') {
            targetEl.scrollIntoView({ behavior: 'instant', block: 'start' });
        }
    }
}
window.simulateTakeoverAttack = simulateTakeoverAttack;

// 2. "Steal Our Client Pitch" Copy-Paste Email Drawer
let currentPitchKey = 'cve';
const pitchTemplates = {
    cve: {
        subject: '[Action Recommended] Protecting your domain against the November NGINX, OpenSSL & DNS exposure wave',
        body: `Hi [Client Name],

With the wave of NGINX (nginx2root), OpenSSL (CVE-2026-121481), and dangling DNS exposures disclosed this week, our engineering team at {{AGENCY}} ran a passive external check on your domain perimeter.

When marketing campaigns or third-party tools (like old landing pages, Shopify apps, or email senders) are disconnected, they often leave behind "dangling" DNS records. Attackers are currently scanning for these unattached records to hijack brand subdomains and send spoofed invoices.

To make sure your brand is completely locked down, we are rolling out continuous 24/7 Attack Surface & DMARC Monitoring across our care plans for $250/mo. On the 1st of every month, you'll receive an executive security scorecard verifying that your subdomains, SSL certificates, and email spoofing defenses are 100% airtight.

Reply "LOCK IT DOWN" and we will activate your domain sentinel and send over your baseline Executive Audit PDF today.

Best regards,
{{AGENCY}}`
    },
    quarterly: {
        subject: 'Quarterly Perimeter Security & Email Deliverability Audit for [Client Domain]',
        body: `Hi [Client Name],

As part of our proactive stewardship at {{AGENCY}}, we just completed a non-intrusive external perimeter review of your domain and email authentication records (SPF, DKIM, and DMARC).

While your primary storefront is performing great, Gmail and Microsoft 365 have tightened their sender enforcement rules, so any drift in your DNS records can cause customer order confirmations to land in spam or leave your domain open to spoofing.

We've packaged continuous 24/7 DNS drift surveillance and a monthly white-label Executive Security Audit PDF into our $250/mo Perimeter Care Plan. Would you like us to attach your initial baseline report and enable monthly protection?

Best regards,
{{AGENCY}}`
    },
    handover: {
        subject: 'Launch Complete! Next Step: Protecting Your New Site Perimeter',
        body: `Hi [Client Name],

Congratulations again on the launch! Now that your new site is live, protecting your domain reputation, SSL transport layer, and subdomain routing is critical.

At {{AGENCY}}, we include our Autonomous Perimeter & Subdomain Hygiene Sentinel in our $250/mo Website Care Retainer. Every month on the 1st, you receive a certified Executive Security Audit PDF proving that your DNS records, Shopify/SaaS integrations, and executive email policies are secure against hijacking.

Let us know if you'd like us to activate your 24/7 perimeter sentinel as part of your post-launch care plan.

Best regards,
{{AGENCY}}`
    }
};

function getActiveAgencyName() {
    const radar = document.getElementById('radarAgencyName');
    const custom = document.getElementById('customAgencyName');
    const portal = document.getElementById('portalAgencyNameInput');
    return (radar && radar.value.trim()) || (custom && custom.value.trim()) || (portal && portal.value.trim()) || localStorage.getItem('orbit_agency_name') || 'Apex Digital Studio';
}

let activeAttributionAgency = '';
let agencyExplicitlyCleared = false;

function getEnteredAgencyName() {
    const radar = document.getElementById('radarAgencyName');
    const custom = document.getElementById('customAgencyName');
    const portal = document.getElementById('portalAgencyNameInput');
    let saved = '';
    try {
        saved = (typeof localStorage !== 'undefined' && localStorage.getItem('orbit_agency_name')) || '';
    } catch (e) {}
    return ((radar && radar.value && radar.value.trim())
        || (custom && custom.value && custom.value.trim())
        || (portal && portal.value && portal.value.trim())
        || saved.trim());
}

function updateHrefQueryParam(rawHref, key, encodedValue) {
    const hashIdx = rawHref.indexOf('#');
    const hash = hashIdx >= 0 ? rawHref.slice(hashIdx) : '';
    const withoutHash = hashIdx >= 0 ? rawHref.slice(0, hashIdx) : rawHref;
    const qIdx = withoutHash.indexOf('?');
    const base = qIdx >= 0 ? withoutHash.slice(0, qIdx) : withoutHash;
    const queryStr = qIdx >= 0 ? withoutHash.slice(qIdx + 1) : '';
    const kept = queryStr
        ? queryStr.split('&').filter(part => {
            if (!part) return false;
            const eqIdx = part.indexOf('=');
            const paramKey = eqIdx >= 0 ? part.slice(0, eqIdx) : part;
            return paramKey !== key;
        })
        : [];
    if (encodedValue !== null && encodedValue !== '') {
        kept.push(`${key}=${encodedValue}`);
    }
    return kept.length > 0 ? `${base}?${kept.join('&')}${hash}` : `${base}${hash}`;
}

function decorateStripeAndSignupLinks(agencyName) {
    const trimmed = String(agencyName || '').trim();
    activeAttributionAgency = trimmed;
    if (trimmed.length > 0) {
        agencyExplicitlyCleared = false;
    }
    const agencySlug = trimmed
        ? (trimmed.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'agency').slice(0, 64)
        : '';
    const encodedSlug = agencySlug ? encodeURIComponent(agencySlug) : null;
    const encodedAgency = trimmed ? encodeURIComponent(trimmed) : null;
    if (typeof document === 'undefined' || typeof document.querySelectorAll !== 'function') return;

    document.querySelectorAll('a[href^="https://buy.stripe.com/"]').forEach(link => {
        const rawHref = (typeof link.getAttribute === 'function' ? link.getAttribute('href') : '') || link.href || '';
        if (!rawHref) return;
        const nextHref = updateHrefQueryParam(rawHref, 'client_reference_id', encodedSlug);
        if (typeof link.setAttribute === 'function') link.setAttribute('href', nextHref);
        link.href = nextHref;
    });

    document.querySelectorAll('a[href^="signup.html"]').forEach(link => {
        const rawHref = (typeof link.getAttribute === 'function' ? link.getAttribute('href') : '') || link.href || '';
        if (!rawHref) return;
        const nextHref = updateHrefQueryParam(rawHref, 'agency', encodedAgency);
        if (typeof link.setAttribute === 'function') link.setAttribute('href', nextHref);
        link.href = nextHref;
    });

    document.querySelectorAll('a[href^="audit.html"]').forEach(link => {
        const rawHref = (typeof link.getAttribute === 'function' ? link.getAttribute('href') : '') || link.href || '';
        if (!rawHref) return;
        const nextHref = updateHrefQueryParam(rawHref, 'agency', encodedAgency);
        if (typeof link.setAttribute === 'function') link.setAttribute('href', nextHref);
        link.href = nextHref;
    });
}

function syncAgencyName(sourceValue) {
    const name = (sourceValue || '').trim();
    const radar = document.getElementById('radarAgencyName');
    const custom = document.getElementById('customAgencyName');
    const portal = document.getElementById('portalAgencyNameInput');
    const display = document.getElementById('brandNameDisplay');
    const mockupAgency = document.getElementById('portalMockupAgencyName');
    const mockupUrl = document.getElementById('portalMockupUrlDisplay');
    if (radar && radar.value !== sourceValue) radar.value = sourceValue;
    if (custom && custom.value !== sourceValue) custom.value = sourceValue;
    if (portal && portal.value !== sourceValue) portal.value = sourceValue;
    if (display) display.textContent = name || 'Your Agency';
    if (mockupAgency) mockupAgency.textContent = name || 'Apex Digital Studio';
    if (mockupUrl) {
        const slug = (name || 'apex').toLowerCase().replace(/[^a-z0-9]/g, '');
        mockupUrl.textContent = `security.${slug || 'apex'}.example.com`;
    }
    if (name) {
        agencyExplicitlyCleared = false;
        try {
            localStorage.setItem('orbit_agency_name', name);
        } catch (e) {}
    } else {
        agencyExplicitlyCleared = true;
    }
    decorateStripeAndSignupLinks(name);
    switchPitchTemplate(currentPitchKey);
    document.querySelectorAll('.flipbook-agency-name').forEach(el => {
        el.textContent = name || 'Apex Digital Studio';
    });
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

function copyNovThreatAlert() {
    const agency = getActiveAgencyName();
    const liveAlerts = Array.isArray(window.__orbitLiveWireAlerts) ? window.__orbitLiveWireAlerts.slice(0, 3) : [];
    const topLines = liveAlerts.length > 0
        ? liveAlerts.map((item) => {
            const sev = item.badge || 'CRITICAL';
            const title = item.label || item.id || 'Critical CVE';
            const detail = item.detail ? ` — ${item.detail}` : '';
            return `• [${sev}] ${title}${detail}${item.date ? ` (${item.date})` : ''}`;
        })
        : [
            '• [CVSS 9.2] NGINX nginx2root (5 HTTP/2 & HTTP/3 CVEs; patch to 1.30.7/1.31.9)',
            '• [CVSS 9.8] OpenSSL EVP_EncodeBlock() CVE-2026-121481'
        ];
    const leadSubject = liveAlerts.length > 0
        ? `${liveAlerts[0].label || liveAlerts[0].id} & Active KEV Perimeter Check`
        : 'NGINX (nginx2root) & OpenSSL CVE-2026-121481 Check';
    const alertText = [
        `Subject: [Urgent Perimeter Advisory] ${leadSubject}`,
        '',
        'Hi [Client Name],',
        '',
        'Critical infrastructure advisories are actively circulating on our threat wire:',
        ...topLines,
        '',
        `Our team at ${agency} is running a passive external perimeter & DNS hygiene sweep across client domains to confirm SSL/TLS exposure, DMARC enforcement, and zero dangling CNAMEs.`,
        '',
        'Reply "RUN CHECK" if you want us to send over your executive perimeter scorecard PDF today.',
        '',
        `Best,\n${agency}`
    ].join('\n');
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(alertText).catch(() => {});
    }
    if (window.SimpleCat && SimpleCat.playPowerUp) SimpleCat.playPowerUp();
    const btn = document.getElementById('copyThreatAlertBtn');
    if (btn) {
        const orig = btn.textContent;
        btn.textContent = '✓ Copied Alert!';
        setTimeout(() => { btn.textContent = orig; }, 2200);
    }
}
window.copyNovThreatAlert = copyNovThreatAlert;

function copyOrbitActionYaml() {
    const yamlEl = document.getElementById('orbitActionYamlSnippet');
    const yamlText = yamlEl ? yamlEl.textContent : '- uses: CmfH009/Orbit-Security@v1';
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(yamlText).catch(() => {});
    }
    if (window.SimpleCat && SimpleCat.playCoin) SimpleCat.playCoin();
    const btn = document.getElementById('copyActionYamlBtn');
    if (btn) {
        const orig = btn.textContent;
        btn.textContent = '✓ Copied YAML!';
        setTimeout(() => { btn.textContent = orig; }, 2200);
    }
}
window.copyOrbitActionYaml = copyOrbitActionYaml;

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

// Bi-directional Agency Name Sync across Hero, Audit Studio, Pitch Drawer & PDF Flipbook
document.addEventListener('DOMContentLoaded', () => {
    const savedAgency = localStorage.getItem('orbit_agency_name');
    if (savedAgency) {
        syncAgencyName(savedAgency);
    }
    const agencyInput = document.getElementById('customAgencyName');
    const radarAgencyInput = document.getElementById('radarAgencyName');
    const portalAgencyInput = document.getElementById('portalAgencyNameInput');
    if (agencyInput) {
        agencyInput.addEventListener('input', (e) => {
            syncAgencyName(e.target.value);
        });
    }
    if (radarAgencyInput) {
        radarAgencyInput.addEventListener('input', (e) => {
            syncAgencyName(e.target.value);
        });
    }
    if (portalAgencyInput) {
        portalAgencyInput.addEventListener('input', (e) => {
            syncAgencyName(e.target.value);
        });
    }
});

// 3. Interactive Agency Retainer ROI Calculator
function applyRoiPreset(clients, fee, laborMins = 0) {
    const cEl = document.getElementById('roiClientCount');
    const fEl = document.getElementById('roiRetainerFee');
    const lEl = document.getElementById('roiLaborMins');
    if (cEl) cEl.value = String(clients);
    if (fEl) fEl.value = String(fee);
    if (lEl) lEl.value = String(laborMins);
    updateRoiCalculator();
    if (window.SimpleCat && SimpleCat.playBlip) SimpleCat.playBlip();
}
window.applyRoiPreset = applyRoiPreset;

function updateRoiCalculator() {
    const clients = parseInt(document.getElementById('roiClientCount')?.value || '25', 10);
    const fee = parseInt(document.getElementById('roiRetainerFee')?.value || '250', 10);
    const laborMins = parseInt(document.getElementById('roiLaborMins')?.value || '0', 10);

    const countEl = document.getElementById('roiClientCountVal');
    const feeEl = document.getElementById('roiRetainerFeeVal');
    const laborEl = document.getElementById('roiLaborMinsVal');
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

    const laborCostMonthly = Math.round(clients * (laborMins / 60) * 75);
    if (laborEl) laborEl.textContent = `${laborMins} min ($${laborCostMonthly.toLocaleString()}/mo)`;

    const grossMonthly = clients * fee;
    const netMonthly = grossMonthly - orbitCost - laborCostMonthly;
    const netAnnual = netMonthly * 12;
    const netFeePerClient = Math.max(1, fee - Math.round((laborMins / 60) * 75));
    const breakEvenClients = Math.max(1, Math.ceil(orbitCost / netFeePerClient));
    const coverageLabel = breakEvenClients === 1
        ? '1 client covers stack'
        : breakEvenClients + ' clients break even';
    const marginPct = grossMonthly > 0 ? Math.max(0, Math.min(100, (netMonthly / grossMonthly) * 100)) : 0;
    const costPerDomain = clients > 0 ? (orbitCost / clients).toFixed(2) : orbitCost.toFixed(2);

    const grossEl = document.getElementById('roiMonthlyGross');
    const costEl = document.getElementById('roiOrbitCost');
    const annualEl = document.getElementById('roiAnnualNet');
    const badgeEl = document.getElementById('roiMultiplierBadge');
    const ctaEl = document.getElementById('roiRecommendedCta');
    const ctaTextEl = document.getElementById('roiRecommendedCtaText');
    const netMonthlyEl = document.getElementById('roiNetMonthlyVal');
    const costPerDomainEl = document.getElementById('roiCostPerDomainVal');
    const breakEvenEl = document.getElementById('roiBreakEvenVal');
    const marginPctEl = document.getElementById('roiMarginPctVal');
    const marginBarEl = document.getElementById('roiMarginBar');

    if (grossEl) grossEl.innerHTML = '$' + grossMonthly.toLocaleString() + '<span class="text-xs font-normal text-slate-400">/mo</span>';
    if (costEl) costEl.textContent = '$' + orbitCost + '/mo (' + tierName + ')';
    const annualPrefix = netAnnual >= 0 ? '+$' : '-$';
    if (annualEl) annualEl.innerHTML = annualPrefix + Math.abs(netAnnual).toLocaleString() + '<span class="text-xs font-normal text-slate-300">/yr</span>';
    if (badgeEl) badgeEl.textContent = coverageLabel;
    if (netMonthlyEl) netMonthlyEl.textContent = `${netMonthly >= 0 ? '+$' : '-$'}${Math.abs(netMonthly).toLocaleString()}/mo`;
    if (costPerDomainEl) costPerDomainEl.textContent = `$${costPerDomain}/site`;
    if (breakEvenEl) breakEvenEl.textContent = `${breakEvenClients} ${breakEvenClients === 1 ? 'client' : 'clients'}`;
    if (marginPctEl) marginPctEl.textContent = `${marginPct.toFixed(1)}%`;
    if (marginBarEl) marginBarEl.style.width = `${marginPct.toFixed(1)}%`;
    if (ctaEl) {
        ctaEl.href = checkoutUrl;
        if (typeof ctaEl.setAttribute === 'function') ctaEl.setAttribute('href', checkoutUrl);
    }
    if (ctaTextEl) ctaTextEl.textContent = 'Deploy Recommended ' + tierName + ' Plan ($' + orbitCost + '/mo)';
    const agencyForLinks = agencyExplicitlyCleared ? '' : (getEnteredAgencyName() || activeAttributionAgency);
    decorateStripeAndSignupLinks(agencyForLinks);
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
    document.body.classList.add('modal-open');
    if (window.SimpleCat && SimpleCat.initScrollIndicators) {
        setTimeout(SimpleCat.initScrollIndicators, 40);
    }
    setFlipbookPage(1);
}

function closePdfFlipbookModal() {
    const modal = document.getElementById('pdfFlipbookModal');
    if (!modal) return;
    modal.classList.add('hidden');
    modal.classList.remove('flex');
    document.body.classList.remove('modal-open');
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

// Deep-link hash triggers for #simulate and #flipbook
function handleHashTriggers() {
    const h = window.location.hash;
    if (h === '#simulate') {
        closePdfFlipbookModal();
        simulateTakeoverAttack('cname');
    } else if (h === '#simulate-php418' || h === '#teapot') {
        closePdfFlipbookModal();
        simulateTakeoverAttack('php418');
    } else if (h === '#flipbook') {
        openPdfFlipbookModal();
    } else if (h === '#arcadeDefenseMode' || h === '#arcadeDefense') {
        closePdfFlipbookModal();
        if (window.SimpleCat && typeof SimpleCat.startDefense === 'function') {
            SimpleCat.startDefense();
        }
    } else if (h === '#roi-calculator' || h === '#pricing') {
        closePdfFlipbookModal();
        const el = document.getElementById(h.substring(1));
        if (el) {
            setTimeout(() => el.scrollIntoView({ behavior: 'instant', block: 'start' }), 150);
            setTimeout(() => el.scrollIntoView({ behavior: 'instant', block: 'start' }), 800);
        }
    } else {
        closePdfFlipbookModal();
    }
}
window.addEventListener('hashchange', handleHashTriggers);
window.addEventListener('DOMContentLoaded', () => {
    setTimeout(handleHashTriggers, 150);
    if (document.getElementById('visualAttackTreeContainer') && window.OrbitAttackTree && typeof OrbitAttackTree.init === 'function') {
        OrbitAttackTree.init('visualAttackTreeContainer', { scenarioKey: 'aws_s3' });
    }
    if (window.SimpleCat && SimpleCat.initScrollIndicators) {
        setTimeout(SimpleCat.initScrollIndicators, 200);
    }
    const explainerVideo = document.getElementById('orbit-explainer-video');
    const explainerOverlay = document.getElementById('explainerPlayOverlay');
    const explainerOverlayText = document.getElementById('explainerPlayOverlayText');
    if (explainerVideo) {
        explainerVideo.addEventListener('play', () => {
            if (explainerOverlay) explainerOverlay.classList.add('hidden');
        });
        explainerVideo.addEventListener('ended', () => {
            if (explainerOverlayText) explainerOverlayText.textContent = 'Replay 72s Walkthrough';
            if (explainerOverlay) explainerOverlay.classList.remove('hidden');
        });
        const syncChapter = () => updateExplainerChapterHighlight(explainerVideo.currentTime);
        explainerVideo.addEventListener('timeupdate', syncChapter);
        explainerVideo.addEventListener('seeked', syncChapter);
        explainerVideo.addEventListener('loadedmetadata', () => {
            const tParam = parseFloat(new URLSearchParams(window.location.search).get('t') || '');
            if (Number.isFinite(tParam) && tParam >= 0 && tParam <= (explainerVideo.duration || 72)) {
                explainerVideo.currentTime = tParam;
            }
            syncChapter();
        });
    }

    // Hydrate Live Threat Wire ticker from assets/kev_epss_radar.json + live GitHub Security Advisories
    const _liveWireById = new Map([
        ['NGINX-HTTP2-3', {
            id: 'NGINX-HTTP2-3',
            vendor: 'NGINX',
            product: 'HTTP/2 & HTTP/3',
            label: 'NGINX nginx2root HTTP/2-3',
            badge: 'CVSS 9.2',
            tone: 'rose',
            detail: 'HTTP/2-3',
            date: '2026-11-20',
            due_date: 'BOD 26-04',
            is_cisa_kev: true,
            cvss: 9.2,
            epss: 0.91,
            percentile: 0.996,
            summary: 'Critical NGINX HTTP/2 & HTTP/3 request handling vulnerabilities (nginx2root) allowing remote code execution or privilege escalation on unpatched edge proxies.',
            action_required: 'Upgrade NGINX edge instances to 1.30.7 or 1.31.9+ and verify TLS/HTTP3 edge configuration.',
            source: 'CISA KEV + EPSS',
            external_url: '',
            labs_href: 'labs.html?cve=NGINX-HTTP2-3#kev-epss-radar',
        }],
        ['CVE-2026-121481', {
            id: 'CVE-2026-121481',
            vendor: 'OpenSSL',
            product: 'EVP_EncodeBlock()',
            label: 'OpenSSL CVE-2026-121481',
            badge: 'CVSS 9.8',
            tone: 'amber',
            detail: 'EVP_EncodeBlock',
            date: '2026-11-18',
            due_date: 'BOD 26-04',
            is_cisa_kev: false,
            cvss: 9.8,
            epss: 0.87,
            percentile: 0.992,
            summary: 'Critical OpenSSL EVP_EncodeBlock() buffer boundary vulnerability affecting TLS termination and cryptographic encoding pipelines.',
            action_required: 'Patch OpenSSL libraries on web & mail gateways and audit external TLS endpoints.',
            source: 'Live Wire Advisory',
            external_url: '',
            labs_href: 'labs.html?cve=CVE-2026-121481#kev-epss-radar',
        }],
    ]);
    let _activeDrawerAlert = null;

    function mergeLiveThreatAdvisories(localFeed, ghsaItems) {
        const byKey = new Map();
        const pushItem = (entry) => {
            if (!entry || !entry.id) return;
            const key = String(entry.id).trim().toUpperCase();
            const prev = byKey.get(key);
            if (!prev) {
                byKey.set(key, entry);
                return;
            }
            byKey.set(key, {
                ...prev,
                ...entry,
                is_cisa_kev: Boolean(prev.is_cisa_kev || entry.is_cisa_kev),
                cvss: Math.max(Number(prev.cvss || 0), Number(entry.cvss || 0)),
                epss: Math.max(Number(prev.epss || 0), Number(entry.epss || 0)),
                badge: (prev.is_cisa_kev || entry.is_cisa_kev) ? 'CISA KEV' : (entry.badge || prev.badge),
                tone: (prev.is_cisa_kev || entry.is_cisa_kev) ? 'rose' : (entry.tone || prev.tone),
            });
        };

        const localVulns = Array.isArray(localFeed?.vulnerabilities) ? localFeed.vulnerabilities.slice() : [];
        localVulns.sort((a, b) => {
            const da = String(a?.date_added || '');
            const db = String(b?.date_added || '');
            if (db !== da) return db.localeCompare(da);
            return Number(b?.epss || 0) - Number(a?.epss || 0);
        });
        for (const v of localVulns.slice(0, 14)) {
            const cveId = String(v?.cve || '').trim().toUpperCase();
            if (!cveId) continue;
            const vendor = String(v?.vendor || '').trim();
            const product = String(v?.product || '').trim();
            const label = vendor && product && !product.toLowerCase().includes(vendor.toLowerCase())
                ? `${vendor} ${product} (${cveId})`
                : `${vendor || product || cveId} (${cveId})`;
            const isKev = Boolean(v?.is_cisa_kev);
            const epssPct = Number(v?.epss || 0) > 0 ? `EPSS ${Math.round(Number(v.epss) * 100)}%` : '';
            pushItem({
                id: cveId,
                vendor: vendor || 'Infrastructure',
                product: product || 'Component',
                label: label.slice(0, 56),
                badge: isKev ? 'CISA KEV' : 'CRITICAL',
                tone: isKev ? 'rose' : 'amber',
                detail: epssPct || String(v?.vulnerability_name || v?.short_description || '').slice(0, 44),
                date: String(v?.date_added || '').slice(0, 10),
                due_date: String(v?.due_date || '').slice(0, 10),
                is_cisa_kev: isKev,
                cvss: isKev ? 9.5 : 9.2,
                epss: Number(v?.epss || 0),
                percentile: Number(v?.percentile || 0),
                summary: String(v?.short_description || v?.vulnerability_name || 'Active perimeter threat tracked in CISA KEV + EPSS.'),
                action_required: String(v?.action_required || 'Apply vendor security mitigations immediately.'),
                source: 'CISA KEV + EPSS',
                external_url: '',
                labs_href: `labs.html?cve=${encodeURIComponent(cveId)}#kev-epss-radar`,
            });
        }

        const liveArr = Array.isArray(ghsaItems) ? ghsaItems : [];
        for (const adv of liveArr) {
            const cveId = String(adv?.cve_id || adv?.ghsa_id || '').trim().toUpperCase();
            if (!cveId) continue;
            const cvssScore = Number(adv?.cvss?.score || 0);
            const pkgName = String(adv?.vulnerabilities?.[0]?.package?.name || '').trim();
            const summary = String(adv?.summary || adv?.description || '').trim();
            const rawUrl = String(adv?.html_url || '');
            const safeExternal = rawUrl.startsWith('https://github.com/advisories/');
            pushItem({
                id: cveId,
                vendor: pkgName || 'GitHub Advisory',
                product: adv?.vulnerabilities?.[0]?.package?.ecosystem || 'Package',
                label: pkgName ? `${pkgName} (${cveId})`.slice(0, 56) : cveId,
                badge: cvssScore > 0 ? `CVSS ${cvssScore.toFixed(1)}` : 'CRITICAL',
                tone: cvssScore >= 9.5 ? 'rose' : 'amber',
                detail: summary.slice(0, 44),
                date: String(adv?.published_at || '').slice(0, 10),
                due_date: '',
                is_cisa_kev: false,
                cvss: cvssScore || 9.0,
                epss: 0,
                percentile: 0,
                summary: summary || 'Critical GitHub Security Advisory actively monitored on the live wire.',
                action_required: 'Upgrade affected package to patched version and verify external perimeter exposure.',
                source: 'GitHub Security Advisory',
                external_url: safeExternal ? rawUrl : '',
                labs_href: `labs.html?cve=${encodeURIComponent(cveId)}#kev-epss-radar`,
            });
        }

        return Array.from(byKey.values())
            .sort((a, b) => {
                const da = String(a.date || '');
                const db = String(b.date || '');
                if (db !== da) return db.localeCompare(da);
                const pa = (a.is_cisa_kev || a.cvss >= 9.0) ? 1 : 0;
                const pb = (b.is_cisa_kev || b.cvss >= 9.0) ? 1 : 0;
                if (pb !== pa) return pb - pa;
                return Number(b.cvss || 0) - Number(a.cvss || 0);
            })
            .slice(0, 8);
    }
    window.mergeLiveThreatAdvisories = mergeLiveThreatAdvisories;

    function openThreatWireDrawer(cveId) {
        const key = String(cveId || '').trim().toUpperCase();
        const item = _liveWireById.get(key)
            || (Array.isArray(window.__orbitLiveWireAlerts) ? window.__orbitLiveWireAlerts.find((x) => String(x.id).toUpperCase() === key) : null)
            || _liveWireById.values().next().value;
        if (!item) return;
        _activeDrawerAlert = item;

        const drawer = document.getElementById('threatWireDrawer');
        if (!drawer) return;

        const badgeEl = document.getElementById('threatDrawerBadge');
        const cveEl = document.getElementById('threatDrawerCveId');
        const srcEl = document.getElementById('threatDrawerSource');
        const stackEl = document.getElementById('threatDrawerStack');
        const dateEl = document.getElementById('threatDrawerDate');
        const dueEl = document.getElementById('threatDrawerDue');
        const epssWrap = document.getElementById('threatDrawerEpssWrap');
        const epssVal = document.getElementById('threatDrawerEpssVal');
        const epssBar = document.getElementById('threatDrawerEpssBar');
        const sumEl = document.getElementById('threatDrawerSummary');
        const actEl = document.getElementById('threatDrawerAction');
        const labsLink = document.getElementById('threatDrawerLabsLink');
        const extLink = document.getElementById('threatDrawerExternalLink');
        const domInput = document.getElementById('threatDrawerDomainInput');

        if (badgeEl) {
            badgeEl.textContent = item.badge || 'CRITICAL';
            badgeEl.className = item.tone === 'rose'
                ? 'px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-300 font-arcade text-[9px] uppercase whitespace-nowrap'
                : 'px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-300 font-arcade text-[9px] uppercase whitespace-nowrap';
        }
        if (cveEl) cveEl.textContent = item.id;
        if (srcEl) srcEl.textContent = item.source || 'Live Threat Wire';
        if (stackEl) stackEl.textContent = `${item.vendor || 'Infrastructure'} — ${item.product || 'Component'}`;
        if (dateEl) dateEl.textContent = item.date ? `Added: ${item.date}` : '';
        if (dueEl) dueEl.textContent = item.due_date ? `Due: ${item.due_date}` : '';
        if (epssWrap) {
            if (Number(item.epss || 0) > 0) {
                epssWrap.classList.remove('hidden');
                const pct = (Number(item.epss) * 100).toFixed(1);
                if (epssVal) epssVal.textContent = `${pct}% (${(Number(item.percentile || 0) * 100).toFixed(1)}th %ile)`;
                if (epssBar) epssBar.style.width = `${Math.max(4, Math.min(100, Number(pct)))}%`;
            } else {
                epssWrap.classList.add('hidden');
            }
        }
        if (sumEl) sumEl.textContent = item.summary || item.detail || item.label;
        if (actEl) actEl.textContent = item.action_required || 'Apply vendor patch and audit external perimeter exposure.';
        if (labsLink) labsLink.href = item.labs_href || `labs.html?cve=${encodeURIComponent(item.id)}#kev-epss-radar`;
        if (extLink) {
            if (item.external_url && item.external_url.startsWith('https://github.com/advisories/')) {
                extLink.href = item.external_url;
                extLink.classList.remove('hidden');
            } else {
                extLink.classList.add('hidden');
            }
        }
        if (domInput && !domInput.value) {
            const heroDom = document.getElementById('targetDomain')?.value?.trim();
            if (heroDom) domInput.value = heroDom;
        }

        drawer.classList.remove('hidden');
        document.body.classList.add('drawer-open');
        if (window.SimpleCat && SimpleCat.playBlip) SimpleCat.playBlip();
    }

    function closeThreatWireDrawer() {
        const drawer = document.getElementById('threatWireDrawer');
        if (drawer) drawer.classList.add('hidden');
        document.body.classList.remove('drawer-open');
    }

    function copyDrawerCveAdvisory() {
        const item = _activeDrawerAlert;
        if (!item) return;
        const agency = getActiveAgencyName();
        const epssLine = Number(item.epss || 0) > 0
            ? `30-day EPSS exploitation probability: ${(Number(item.epss) * 100).toFixed(1)}%\n`
            : '';
        const text = [
            `Subject: [Security Advisory] ${item.id} (${item.vendor} ${item.product}) Perimeter Verification`,
            '',
            'Hi [Client Name],',
            '',
            `Our security sentinel at ${agency} is tracking ${item.id} (${item.badge || 'CRITICAL'}) affecting ${item.vendor} ${item.product}.`,
            epssLine + `Summary: ${item.summary || item.label}`,
            `Recommended Action: ${item.action_required || 'Apply vendor patch immediately.'}`,
            '',
            'We are verifying your external domain perimeter, SSL/TLS endpoints, and DNS records to confirm zero exposure.',
            '',
            `Best regards,\n${agency}`,
        ].join('\n');
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).catch(() => {});
        }
        const btn = document.getElementById('threatDrawerCopyBtn');
        if (btn) {
            const orig = btn.textContent;
            btn.textContent = `✓ Copied ${item.id} Advisory!`;
            setTimeout(() => { btn.textContent = orig; }, 2200);
        }
        if (window.SimpleCat && SimpleCat.playPowerUp) SimpleCat.playPowerUp();
    }

    function scanDomainFromThreatDrawer() {
        const domInput = document.getElementById('threatDrawerDomainInput');
        const heroInput = document.getElementById('targetDomain');
        const domainVal = (domInput?.value || heroInput?.value || 'clientbrand.com').trim();
        closeThreatWireDrawer();
        if (heroInput) {
            heroInput.value = domainVal;
        }
        const term = document.getElementById('audit-terminal');
        if (term) term.scrollIntoView({ behavior: 'smooth', block: 'center' });
        if (typeof window.handleAuditRequest === 'function') {
            window.handleAuditRequest({ preventDefault() {} });
        }
    }

    window.openThreatWireDrawer = openThreatWireDrawer;
    window.closeThreatWireDrawer = closeThreatWireDrawer;
    window.copyDrawerCveAdvisory = copyDrawerCveAdvisory;
    window.scanDomainFromThreatDrawer = scanDomainFromThreatDrawer;

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const drawer = document.getElementById('threatWireDrawer');
            if (drawer && !drawer.classList.contains('hidden')) {
                closeThreatWireDrawer();
            }
        }
    });

    function renderLiveWireTicker(items) {
        const primary = document.getElementById('livewirePrimaryGroup');
        const dup = document.getElementById('livewireDupGroup');
        const track = document.getElementById('livewireMarqueeTrack');
        if (!primary || !Array.isArray(items) || items.length === 0) return;

        primary.textContent = '';
        items.forEach((item, idx) => {
            _liveWireById.set(String(item.id).toUpperCase(), item);
            const a = document.createElement('a');
            if (idx === 0) a.id = 'heroThreatChip1';
            if (idx === 1) a.id = 'heroThreatChip2';
            a.href = item.labs_href || `labs.html?cve=${encodeURIComponent(item.id)}#kev-epss-radar`;
            a.dataset.cveId = item.id;
            const isRose = item.tone === 'rose';
            a.className = isRose
                ? 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/90 hover:bg-rose-500/20 border border-rose-500/40 text-[11px] font-mono text-rose-200 transition-colors whitespace-nowrap cursor-pointer'
                : 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/90 hover:bg-amber-500/20 border border-amber-500/40 text-[11px] font-mono text-amber-200 transition-colors whitespace-nowrap cursor-pointer';

            const badge = document.createElement('span');
            badge.className = isRose
                ? 'px-1 py-0.2 rounded bg-rose-500/20 text-rose-300 text-[9px] font-bold'
                : 'px-1 py-0.2 rounded bg-amber-500/20 text-amber-300 text-[9px] font-bold';
            badge.textContent = item.badge || 'CRITICAL';
            a.appendChild(badge);

            const strong = document.createElement('strong');
            strong.className = 'text-white';
            strong.textContent = item.label || item.id;
            a.appendChild(strong);

            if (item.detail || item.date) {
                const meta = document.createElement('span');
                meta.className = 'text-slate-400';
                meta.textContent = item.detail || item.date;
                a.appendChild(meta);
            }
            primary.appendChild(a);
        });

        if (dup) {
            dup.textContent = '';
            Array.from(primary.children).forEach((node) => {
                const clone = node.cloneNode(true);
                if (clone.id) clone.removeAttribute('id');
                clone.setAttribute('tabindex', '-1');
                clone.setAttribute('aria-hidden', 'true');
                dup.appendChild(clone);
            });
        }
        if (track) {
            track.style.animationDuration = `${Math.max(32, items.length * 5.5)}s`;
        }
    }

    (function initHeroThreatRibbon() {
        const ribbon = document.getElementById('heroThreatRibbon');
        if (!ribbon) return;
        ribbon.addEventListener('click', (e) => {
            const pill = e.target && e.target.closest ? e.target.closest('a[data-cve-id]') : null;
            if (!pill) return;
            if (!e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey) {
                e.preventDefault();
                openThreatWireDrawer(pill.dataset.cveId);
            }
        });
        try {
            if (sessionStorage.getItem('orbit_threat_ribbon_dismissed') === '1') {
                ribbon.classList.add('hidden');
                return;
            }
        } catch (e) {}

        let localFeedData = null;
        let liveGhsaData = null;
        const applyRender = () => {
            const merged = mergeLiveThreatAdvisories(localFeedData, liveGhsaData);
            if (merged.length > 0) {
                window.__orbitLiveWireAlerts = merged;
                renderLiveWireTicker(merged);
            }
            const badgeEl = document.getElementById('heroThreatBadge');
            const summaryEl = document.getElementById('heroThreatSummary');
            if (badgeEl) {
                if (Array.isArray(liveGhsaData) && liveGhsaData.length > 0) {
                    badgeEl.textContent = 'LIVE · CISA KEV + GHSA';
                } else if (localFeedData && localFeedData.generated_at) {
                    badgeEl.textContent = `LIVE WIRE · ${String(localFeedData.generated_at).replace(/\./g, '-')}`;
                }
            }
            if (summaryEl && localFeedData) {
                const kevCount = localFeedData.cisa_kev_count || localFeedData.total_tracked || 1750;
                summaryEl.textContent = `${kevCount}+ KEVs · ${merged.length} breaking`;
            }
        };

        fetch('assets/kev_epss_radar.json', { cache: 'no-cache' })
            .then((res) => (res.ok ? res.json() : null))
            .then((data) => {
                if (data && Array.isArray(data.vulnerabilities)) {
                    localFeedData = data;
                    applyRender();
                }
            })
            .catch(() => {});

        try {
            const cachedRaw = sessionStorage.getItem('orbit_livewire_ghsa_v1');
            if (cachedRaw) {
                const parsed = JSON.parse(cachedRaw);
                if (parsed && Array.isArray(parsed.items) && (Date.now() - Number(parsed.ts || 0)) < 900000) {
                    liveGhsaData = parsed.items;
                    applyRender();
                    return;
                }
            }
        } catch (e) {}

        const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
        const timer = ctrl ? setTimeout(() => ctrl.abort(), 4500) : null;
        fetch('https://api.github.com/advisories?severity=critical&type=reviewed&per_page=8', {
            headers: { 'Accept': 'application/vnd.github+json' },
            signal: ctrl ? ctrl.signal : undefined,
        })
            .then((res) => (res.ok ? res.json() : null))
            .then((items) => {
                if (Array.isArray(items) && items.length > 0) {
                    liveGhsaData = items;
                    try {
                        sessionStorage.setItem('orbit_livewire_ghsa_v1', JSON.stringify({ ts: Date.now(), items }));
                    } catch (e) {}
                    applyRender();
                }
            })
            .catch(() => {})
            .finally(() => {
                if (timer) clearTimeout(timer);
            });
    })();
});
