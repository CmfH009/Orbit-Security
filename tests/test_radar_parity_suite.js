/**
 * Multi-Domain Audit Engine & PDF Parity Verification Suite
 * Tests all 5 major domain archetypes + button bar responsive layout.
 */

const fs = require('fs');
const vm = require('vm');
const path = require('path');

// 1. Mock Browser Environment
const elements = {};
function createMockElement(id, tagName = 'div') {
    return {
        id,
        tagName,
        value: '',
        innerText: '',
        textContent: '',
        innerHTML: '',
        classList: {
            contains: (cls) => false,
            add: () => {},
            remove: () => {},
            toggle: () => {}
        },
        style: {},
        disabled: false,
        appendChild: () => {},
        removeChild: () => {},
        click: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        querySelector: () => null,
        querySelectorAll: () => []
    };
}

const mockDoc = {
    getElementById: (id) => {
        if (!elements[id]) {
            elements[id] = createMockElement(id);
        }
        return elements[id];
    },
    createElement: (tag) => createMockElement(`dyn-${tag}`, tag),
    body: createMockElement('body'),
    addEventListener: () => {},
    removeEventListener: () => {},
    querySelector: () => null,
    querySelectorAll: () => []
};

let lastPdfArgs = null;
const mockPdfLib = {
    PDFDocument: {
        create: async () => ({
            addPage: () => ({
                getSize: () => ({ width: 595.28, height: 841.89 }),
                drawRectangle: () => {},
                drawText: (text, options) => {
                    if (text.includes('/ 100')) {
                        lastPdfArgs.renderedScore = text;
                    }
                    if (text.startsWith('GRADE:')) {
                        lastPdfArgs.renderedGrade = text;
                    }
                }
            }),
            embedFont: async () => ({}),
            save: async () => new Uint8Array([37, 80, 68, 70])
        })
    },
    rgb: (r, g, b) => ({ r, g, b }),
    StandardFonts: { Helvetica: 'Helvetica', HelveticaBold: 'Helvetica-Bold' },
    PageSizes: { A4: [595.28, 841.89] }
};

let clipboardText = '';
const mockNav = {
    clipboard: {
        writeText: async (t) => { clipboardText = t; }
    }
};

const mockStorage = {};
const sandbox = {
    window: {},
    document: mockDoc,
    navigator: mockNav,
    localStorage: {
        getItem: (k) => mockStorage[k] || null,
        setItem: (k, v) => { mockStorage[k] = String(v); },
        removeItem: (k) => { delete mockStorage[k]; }
    },
    location: { search: '', pathname: '/' },
    history: { replaceState: () => {} },
    addEventListener: () => {},
    setTimeout: (fn) => setTimeout(fn, 0),
    clearTimeout: (id) => clearTimeout(id),
    setInterval: () => 1,
    clearInterval: () => {},
    alert: (msg) => {},
    prompt: () => {},
    open: () => {},
    URL: { createObjectURL: () => 'blob:mock-pdf', revokeObjectURL: () => {} },
    Blob,
    console: { log: () => {}, warn: () => {}, error: console.error },
    Uint8Array,
    Array,
    Object,
    String,
    Number,
    Boolean,
    Math,
    Date,
    Promise,
    RegExp,
    JSON,
    parseInt,
    isNaN,
    URLSearchParams
};

sandbox.window = sandbox;
sandbox.window.PDFLib = mockPdfLib;

const code = fs.readFileSync(path.join(__dirname, '../docs/assets/orbit_radar.js'), 'utf-8');
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const performClientDohAudit = sandbox.window.performClientDohAudit;
const generateInstantPdfForDomain = sandbox.window.generateInstantPdfForDomain;
const copyShareableBadge = sandbox.window.copyShareableBadge;
const handleAuditRequest = sandbox.window.handleAuditRequest;
const DoHService = sandbox.window.DoHService;

async function runTests() {
    console.log('--- STARTING ORBIT PARITY VERIFICATION SUITE ---');
    let passed = 0;
    let total = 0;

    function assert(cond, msg) {
        total++;
        if (!cond) {
            console.error(`FAILED [${total}]: ${msg}`);
            process.exit(1);
        } else {
            passed++;
            console.log(`✓ [${total}] ${msg}`);
        }
    }

    // =========================================================================
    // Scenario 1: monstersamonguspodcast.com (Missing DMARC & SPF, Grade F / 40)
    // =========================================================================
    console.log('\nTesting Scenario 1: monstersamonguspodcast.com');
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) return { success: true, status: 0, answer: [] };
        if (type === 16) return { success: true, status: 0, answer: [] }; // No SPF
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mail.example.com' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '192.0.2.1' }] };
        return { success: true, status: 0, answer: [] }; // Clean CNAMEs
    };

    const audit1 = await performClientDohAudit('monstersamonguspodcast.com');
    assert(audit1.score === 40, `monstersamonguspodcast.com score is 40 (got ${audit1.score})`);
    assert(audit1.grade === 'F', `monstersamonguspodcast.com grade is F (got ${audit1.grade})`);
    assert(audit1.dmarcStatus === 'missing', `DMARC status is missing`);
    assert(audit1.spfStatus === 'missing', `SPF status is missing`);
    assert(audit1.findings[0].category === 'SUBDOMAIN TAKEOVER SENTINEL' && audit1.findings[0].status === 'PASS', 'Finding 1 is Subdomain Takeover PASS');
    assert(audit1.findings[1].category === 'EMAIL SPOOFING PROTECTION (DMARC)' && audit1.findings[1].status === 'FAIL', 'Finding 2 is DMARC FAIL');
    assert(audit1.findings[2].category === 'SENDER POLICY FRAMEWORK (SPF)' && audit1.findings[2].status === 'FAIL', 'Finding 3 is SPF FAIL');
    assert(audit1.findings[3].category === 'MAIL INBOUND ROUTING (MX)' && audit1.findings[3].status === 'PASS', 'Finding 4 is Mail Routing PASS');

    // Test PDF generation for Scenario 1
    lastPdfArgs = {};
    await generateInstantPdfForDomain('monstersamonguspodcast.com', audit1.score, audit1.grade, null, audit1.findings);
    assert(lastPdfArgs.renderedScore === '40 / 100', `PDF rendered score is 40 / 100 (got ${lastPdfArgs.renderedScore})`);
    assert(lastPdfArgs.renderedGrade === 'GRADE: F', `PDF rendered grade is GRADE: F (got ${lastPdfArgs.renderedGrade})`);

    // Test Shareable Badge for Scenario 1
    copyShareableBadge('monstersamonguspodcast.com', audit1.score, audit1.grade, audit1.dmarcStatus, audit1.spfStatus);
    assert(clipboardText.includes('Security Score: 40/100 (Grade F)'), 'Clipboard badge contains correct score 40/100 Grade F');
    assert(clipboardText.includes('DMARC Spoofing Guard: MISSING'), 'Clipboard badge has DMARC MISSING');
    assert(clipboardText.includes('SPF Deliverability Guard: MISSING'), 'Clipboard badge has SPF MISSING');

    // =========================================================================
    // Scenario 2: uchicago.edu (Strict Enterprise Apex, Grade A+ / 100)
    // =========================================================================
    console.log('\nTesting Scenario 2: uchicago.edu (Strict Apex)');
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@uchicago.edu"' }] };
        }
        if (type === 16) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 include:_spf.uchicago.edu -all"' }] };
        }
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.uchicago.edu' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '128.135.164.124' }] };
        return { success: true, status: 0, answer: [] };
    };

    const audit2 = await performClientDohAudit('uchicago.edu');
    assert(audit2.score === 100, `uchicago.edu score is 100 (got ${audit2.score})`);
    assert(audit2.grade === 'A+', `uchicago.edu grade is A+ (got ${audit2.grade})`);
    assert(audit2.dmarcStatus === 'pass', 'DMARC status is pass');
    assert(audit2.spfStatus === 'pass', 'SPF status is pass');
    assert(audit2.findings[1].status === 'PASS', 'DMARC finding is PASS');
    assert(audit2.findings[2].status === 'PASS', 'SPF finding is PASS');

    lastPdfArgs = {};
    await generateInstantPdfForDomain('uchicago.edu', audit2.score, audit2.grade, null, audit2.findings);
    assert(lastPdfArgs.renderedScore === '100 / 100', `PDF rendered score is 100 / 100`);
    assert(lastPdfArgs.renderedGrade === 'GRADE: A+', `PDF rendered grade is GRADE: A+`);

    // =========================================================================
    // Scenario 3: Monitoring-Only Domain (p=none with -all, Grade B / 80)
    // =========================================================================
    console.log('\nTesting Scenario 3: Monitoring-Only Domain (p=none with -all)');
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=none;"' }] };
        }
        if (type === 16) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 mx -all"' }] };
        }
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mail.client.com' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '203.0.113.1' }] };
        return { success: true, status: 0, answer: [] };
    };

    const audit3 = await performClientDohAudit('client-monitored.com');
    assert(audit3.score === 80, `client-monitored.com score is 80 (got ${audit3.score})`);
    assert(audit3.grade === 'B', `client-monitored.com grade is B (got ${audit3.grade})`);
    assert(audit3.dmarcStatus === 'warn', 'DMARC status is warn');
    assert(audit3.findings[1].status === 'WARN', 'Finding DMARC is WARN');

    lastPdfArgs = {};
    await generateInstantPdfForDomain('client-monitored.com', audit3.score, audit3.grade, null, audit3.findings);
    assert(lastPdfArgs.renderedScore === '80 / 100', `PDF rendered score is 80 / 100`);
    assert(lastPdfArgs.renderedGrade === 'GRADE: B', `PDF rendered grade is GRADE: B`);

    // =========================================================================
    // Scenario 4: Subdomain Tree-Walk Inheritance (store.brand.com)
    // =========================================================================
    console.log('\nTesting Scenario 4: Subdomain Tree-Walk Inheritance');
    DoHService.query = async (name, type) => {
        // Direct subdomain queries have no DMARC or SPF
        if (name === '_dmarc.store.brand.com') return { success: true, status: 0, answer: [] };
        if (name === 'store.brand.com' && type === 16) return { success: true, status: 0, answer: [] };
        // Apex organization queries provide policy
        if (name === '_dmarc.brand.com') {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject; sp=quarantine;"' }] };
        }
        if (name === 'brand.com' && type === 16) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        }
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.brand.com' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '203.0.113.5' }] };
        return { success: true, status: 0, answer: [] };
    };

    const audit4 = await performClientDohAudit('store.brand.com');
    assert(audit4.isSubdomain === true, 'Identified as subdomain');
    assert(audit4.dmarcInherited === true, 'DMARC inherited from brand.com');
    assert(audit4.dmarcScore === 25, `DMARC score inherited sp=quarantine (25 pts) (got ${audit4.dmarcScore})`);
    assert(audit4.spfInherited === true, 'SPF inherited from brand.com (30 pts)');
    assert(audit4.score === 95, `Total score is 95 (got ${audit4.score})`);
    assert(audit4.grade === 'A+', `Grade is A+ (got ${audit4.grade})`);

    // =========================================================================
    // Scenario 5: Dangling CNAME Subdomain Takeover Detection (Prong A NXDOMAIN)
    // =========================================================================
    console.log('\nTesting Scenario 5: Dangling CNAME Takeover (Prong A NXDOMAIN)');
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        }
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.brand.com' }] };
        if (type === 1) {
            // Target CNAME resolution for dangling Azure target returns NXDOMAIN (status 3)
            if (name === 'orphaned.azurewebsites.net') {
                return { success: true, status: 3, answer: [] };
            }
            return { success: true, status: 0, answer: [{ type: 1, data: '203.0.113.1' }] };
        }
        // Dangling CNAME on dev subdomain (in 16-subdomain grid)
        if (name === 'dev.takeover-risk.com' && type === 5) {
            return { success: true, status: 0, answer: [{ type: 5, data: 'orphaned.azurewebsites.net' }] };
        }
        return { success: true, status: 0, answer: [] };
    };

    const audit5 = await performClientDohAudit('takeover-risk.com');
    assert(audit5.cnameStatus === 'critical', 'CNAME status is critical');
    assert(audit5.cnameScore === 0, 'CNAME score is 0 due to dangling pointer');
    assert(audit5.findings[0].category === 'SUBDOMAIN TAKEOVER SENTINEL' && audit5.findings[0].status === 'FAIL', 'Subdomain takeover finding is FAIL');
    assert(audit5.score === 75, `Total score is 75 (got ${audit5.score})`);
    assert(audit5.grade === 'F', `Grade is forced to F due to confirmed dangling CNAME (got ${audit5.grade})`);

    // =========================================================================
    // Scenario 5B: Multi-Tenant Cloud SaaS Unverified Route (Prong B)
    // =========================================================================
    console.log('\nTesting Scenario 5B: Multi-Tenant Cloud SaaS (Prong B)');
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        }
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.brand.com' }] };
        if (type === 1) {
            // Target CNAME resolves to active multi-tenant edge
            return { success: true, status: 0, answer: [{ type: 1, data: '23.227.38.65' }] };
        }
        // Subdomain shop points to Shopify multi-tenant edge
        if (name === 'shop.saas-brand.com' && type === 5) {
            return { success: true, status: 0, answer: [{ type: 5, data: 'custom.myshopify.com' }] };
        }
        return { success: true, status: 0, answer: [] };
    };

    const audit5B = await performClientDohAudit('saas-brand.com');
    assert(audit5B.cnameStatus === 'warn', 'CNAME status is warn for multi-tenant route');
    assert(audit5B.cnameScore === 15, `CNAME score is 15 for unverified multi-tenant route (got ${audit5B.cnameScore})`);
    assert(audit5B.findings[0].status === 'WARN', 'Finding 1 is WARN for unverified route');
    assert(audit5B.score === 90, `Total score is 90 (got ${audit5B.score})`);
    assert(audit5B.grade === 'A+', `Grade is A+ (got ${audit5B.grade})`);

    // =========================================================================
    // Scenario 5C: RFC 7505 Null-MX Non-Sending Perimeter
    // =========================================================================
    console.log('\nTesting Scenario 5C: RFC 7505 Null-MX');
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        }
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        // RFC 7505 Null-MX: 0 .
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '0 .' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '203.0.113.1' }] };
        return { success: true, status: 0, answer: [] };
    };

    const audit5C = await performClientDohAudit('non-sending-brand.com');
    assert(audit5C.isNullMx === true, 'Null-MX detected');
    assert(audit5C.hasValidMx === false, 'hasValidMx is false for Null-MX');
    assert(audit5C.mxScore === 15, `Null-MX awards 15 pts (got ${audit5C.mxScore})`);
    assert(audit5C.mxStatus === 'pass', 'Null-MX status is pass');
    assert(audit5C.score === 100, `Total score is 100 (got ${audit5C.score})`);
    assert(audit5C.grade === 'A+', `Grade is A+ (got ${audit5C.grade})`);

    // =========================================================================
    // Scenario 5D: RFC 5321 §5.1 Missing MX Fallback
    // =========================================================================
    console.log('\nTesting Scenario 5D: RFC 5321 §5.1 Missing MX Fallback');
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) {
            return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        }
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [] }; // Missing MX
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '203.0.113.1' }] }; // Active A host
        return { success: true, status: 0, answer: [] };
    };

    const audit5D = await performClientDohAudit('active-nomx.com');
    assert(audit5D.isNullMx === false, 'Not Null-MX');
    assert(audit5D.hasValidMx === false, 'Not valid MX');
    assert(audit5D.mxScore === 5, `Missing MX on A host awards 5 pts fallback (got ${audit5D.mxScore})`);
    assert(audit5D.mxStatus === 'warn', 'Status is warn');

    // =========================================================================
    // Scenario 6: UI Header & Action Bar Briefing Presentation
    // =========================================================================
    console.log('\nTesting Scenario 6: UI Header & Action Bar Briefing Presentation');
    // Set target input and trigger handleAuditRequest
    mockDoc.getElementById('targetDomain').value = 'monstersamonguspodcast.com';
    const fakeEvent = { preventDefault: () => {} };
    await handleAuditRequest(fakeEvent);

    const hudHtml = mockDoc.getElementById('auditHUD').innerHTML;
    assert(hudHtml.includes('flex flex-col xl:flex-row items-start xl:items-center justify-between gap-4'), 'HUD header wrapper has flex-col xl:flex-row responsive breakpoint');
    assert(hudHtml.includes('w-full xl:w-auto flex flex-wrap items-center') && hudHtml.includes('min-w-0'), 'Button group has flex-wrap to prevent clipping');
    assert(hudHtml.includes('📋 Copy Pitch Email'), 'Action Bar includes Copy Pitch Email button');
    assert(hudHtml.includes('Co-Branded PDF'), 'Action Bar includes Co-Branded PDF button');
    assert(hudHtml.includes('⚡ Simulate Exploit'), 'Action Bar includes Simulate Exploit button');
    assert(hudHtml.includes('⚡ Fix Pack'), 'Action Bar includes Fix Pack button');
    assert(hudHtml.includes('whitespace-nowrap'), 'Buttons enforce whitespace-nowrap');
    assert(!hudHtml.includes('overflow-hidden') || hudHtml.includes('min-w-0'), 'Card prevents button clipping');

    // Test copyClientBriefingEmail
    const copyClientBriefingEmail = sandbox.window.copyClientBriefingEmail;
    assert(typeof copyClientBriefingEmail === 'function', 'copyClientBriefingEmail is exposed on window');
    copyClientBriefingEmail('monstersamonguspodcast.com', 40, 'F');
    assert(clipboardText.includes('[Perimeter Security Audit] monstersamonguspodcast.com'), 'Pitch email subject has clean domain');
    assert(clipboardText.includes('Current Perimeter Hygiene Score: 40/100 (Grade: F)'), 'Pitch email body has score and grade');
    assert(clipboardText.includes('Key Findings Identified:'), 'Pitch email body has Key Findings');

    // =========================================================================
    // Scenario 7: Real-Time Radar Telemetry & Inbound Probe Observer
    // =========================================================================
    console.log('\nTesting Scenario 7: Real-Time Radar Telemetry & Probe Ingestion');
    assert(typeof sandbox.window.OrbitRadarTelemetry === 'object', 'window.OrbitRadarTelemetry is exposed');
    assert(typeof sandbox.window.dispatchRadarTelemetry === 'function', 'window.dispatchRadarTelemetry is exposed');

    // Test explicit telemetry dispatch
    const telemEvent = sandbox.window.dispatchRadarTelemetry('shopify.com', 'test_chip', {
        score: 85,
        grade: 'B',
        riskLabel: 'LOW RISK',
        dmarcStatus: 'pass',
        spfStatus: 'pass'
    });
    assert(telemEvent && telemEvent.event === 'RADAR_DOMAIN_ENTERED', 'Telemetry event type is RADAR_DOMAIN_ENTERED');
    assert(telemEvent.domain === 'shopify.com', 'Telemetry domain is shopify.com');
    assert(telemEvent.audit_result && telemEvent.audit_result.score === 85, 'Telemetry audit score is 85');
    assert(telemEvent.audit_result.grade === 'B', 'Telemetry audit grade is B');

    // Test local probe history retrieval
    const recentProbes = sandbox.window.OrbitRadarTelemetry.getRecentProbes();
    assert(Array.isArray(recentProbes) && recentProbes.length > 0, 'getRecentProbes returns array of probe records');
    assert(recentProbes[0].domain === 'shopify.com', 'Latest probe in storage is shopify.com');

    // Test endpoint discovery and multi-collector fallbacks
    const endpoints = sandbox.window.OrbitRadarTelemetry.getEndpoints();
    assert(Array.isArray(endpoints) && endpoints.length >= 2, 'getEndpoints returns list of collectors');
    assert(endpoints.includes('http://127.0.0.1:9090/api/orbit/radar/telemetry'), 'Endpoints includes port 9090 Cockpit collector');
    assert(endpoints.includes('http://127.0.0.1:9095/api/orbit/radar/telemetry'), 'Endpoints includes port 9095 Standalone CLI receiver');

    // Test dynamic endpoint and webhook setters
    sandbox.window.OrbitRadarTelemetry.setEndpoint('https://collector.example.com/api/telemetry');
    assert(sandbox.window.OrbitRadarTelemetry.getEndpoints().includes('https://collector.example.com/api/telemetry'), 'setEndpoint updates active endpoints');
    sandbox.window.OrbitRadarTelemetry.setWebhook('https://discord.com/api/webhooks/test/123');
    assert(sandbox.window.OrbitRadarTelemetry.getEndpoints().includes('https://discord.com/api/webhooks/test/123'), 'setWebhook updates active endpoints');

    // Test setScanTarget triggers telemetry dispatch
    sandbox.window.setScanTarget('cmfh009.github.io');
    const updatedProbes = sandbox.window.OrbitRadarTelemetry.getRecentProbes();
    assert(updatedProbes[0].domain === 'cmfh009.github.io', 'setScanTarget dispatched probe telemetry for cmfh009.github.io');

    // Test GDPR/CCPA & Global Privacy Control opt-out / opt-in API
    assert(sandbox.window.OrbitRadarTelemetry.isOptedOut() === false, 'Telemetry is opted-in by default');
    sandbox.window.OrbitRadarTelemetry.optOut();
    assert(sandbox.window.OrbitRadarTelemetry.isOptedOut() === true, 'optOut() enables telemetry opt-out');
    const optedOutEvent = sandbox.window.dispatchRadarTelemetry('privacy-first.org', 'optout_test');
    assert(optedOutEvent.network_dispatched === false, 'Opted-out probe suppresses external network dispatch');
    sandbox.window.OrbitRadarTelemetry.optIn();
    assert(sandbox.window.OrbitRadarTelemetry.isOptedOut() === false, 'optIn() restores telemetry dispatch');

    // =========================================================================
    // Scenario 8: Universal Free Tool Social Share Engine & Mobile Clip Recorder
    // =========================================================================
    console.log('\nTesting Scenario 8: Universal Free Tool Social Share & Mobile Clip Recorder');
    assert(typeof sandbox.window.shareOrbitTool === 'function', 'window.shareOrbitTool is exposed');
    assert(typeof sandbox.window.buildOrbitToolSharePayload === 'function', 'window.buildOrbitToolSharePayload is exposed');

    const toolKeys = [
        'radar', 'audit-studio', 'pitch-drawer', 'kev-radar', 'zk-scorecard',
        'takeover-poc', 'epss-horizon', 'simple-cat', 'legal-rider', 'roi-calculator'
    ];
    for (const tk of toolKeys) {
        const xUrl = sandbox.window.shareOrbitTool(tk, 'x', { domain: 'shopify.com' });
        assert(typeof xUrl === 'string' && xUrl.startsWith('https://x.com/intent/tweet?text='), `shareOrbitTool('${tk}', 'x') builds valid X intent URL`);
    }
    const liUrl = sandbox.window.shareOrbitTool('radar', 'linkedin');
    assert(liUrl.startsWith('https://www.linkedin.com/sharing/share-offsite/'), 'shareOrbitTool linkedin builds valid LinkedIn share URL');
    const rdUrl = sandbox.window.shareOrbitTool('radar', 'reddit');
    assert(rdUrl.startsWith('https://www.reddit.com/submit?url='), 'shareOrbitTool reddit builds valid Reddit submit URL');

    // Verify dynamic #auditHUD includes social share & mobile clip buttons
    assert(hudHtml.includes("shareOrbitTool('radar', 'x')"), 'Dynamic #auditHUD includes X share button');
    assert(hudHtml.includes("shareOrbitTool('radar', 'linkedin')"), 'Dynamic #auditHUD includes LinkedIn share button');
    assert(hudHtml.includes("SimpleCat.recordClip()"), 'Dynamic #auditHUD includes Record Clip for X button');

    // Verify simple_cat.js contains mobile phone canvas stream fallback & native file sharing
    const simpleCatJs = fs.readFileSync(path.join(__dirname, '..', 'landing', 'assets', 'simple_cat.js'), 'utf8');
    assert(simpleCatJs.includes('function createMobileCanvasStream()'), 'simple_cat.js defines createMobileCanvasStream() for mobile phones');
    assert(simpleCatJs.includes('function isMobileOrTouchDevice()'), 'simple_cat.js defines isMobileOrTouchDevice()');
    assert(simpleCatJs.includes('function showClipSavedShareBanner('), 'simple_cat.js defines showClipSavedShareBanner() with native phone share');

    // Verify landing/index.html and landing/ghostdns/index.html have share buttons across all free tools
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'landing', 'index.html'), 'utf8');
    for (const tk of toolKeys) {
        assert(indexHtml.includes(`shareOrbitTool('${tk}'`), `landing/index.html includes social share button for '${tk}'`);
    }
    const ghostDnsHtml = fs.readFileSync(path.join(__dirname, '..', 'landing', 'ghostdns', 'index.html'), 'utf8');
    assert(ghostDnsHtml.includes("shareGhostDnsTool('x')"), 'landing/ghostdns/index.html includes X share button');
    assert(ghostDnsHtml.includes("shareGhostDnsTool('native')"), 'landing/ghostdns/index.html includes Native share button');

    console.log(`\n========================================`);
    console.log(`ALL ${passed}/${total} AUDIT ENGINE & PDF PARITY TESTS PASSED!`);
    console.log(`========================================`);
    process.exit(0);
}

runTests().catch(err => {
    console.error('Test runner failure:', err);
    process.exit(1);
});
