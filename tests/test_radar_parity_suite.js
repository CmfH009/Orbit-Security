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
    const classListSet = new Set();
    const styleProps = {};
    return {
        id,
        tagName,
        value: '',
        innerText: '',
        textContent: '',
        innerHTML: '',
        classList: {
            contains: (cls) => classListSet.has(cls),
            add: (...classes) => classes.forEach(c => classListSet.add(c)),
            remove: (...classes) => classes.forEach(c => classListSet.delete(c)),
            toggle: (c) => classListSet.has(c) ? (classListSet.delete(c), false) : (classListSet.add(c), true)
        },
        style: new Proxy(styleProps, {
            get(target, prop) {
                if (prop === 'setProperty') {
                    return (k, v) => { target[k] = v; };
                }
                if (prop === 'getPropertyValue') {
                    return (k) => target[k] || '';
                }
                return target[prop] || '';
            },
            set(target, prop, value) {
                target[prop] = value;
                return true;
            }
        }),
        disabled: false,
        appendChild: () => {},
        removeChild: () => {},
        click: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        querySelector: () => null,
        querySelectorAll: () => [],
        scrollIntoView: () => {}
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

let lastPdfArgs = {};
const mockPdfLib = {
    PDFDocument: {
        create: async () => ({
            addPage: () => ({
                getSize: () => ({ width: 595.28, height: 841.89 }),
                drawRectangle: (options) => {
                    if (!lastPdfArgs.rectangles) lastPdfArgs.rectangles = [];
                    lastPdfArgs.rectangles.push(options);
                    if (options && options.y && options.height === 8) {
                        lastPdfArgs.renderedColor = options.color;
                    }
                },
                drawText: (text, options) => {
                    if (!lastPdfArgs.texts) lastPdfArgs.texts = [];
                    lastPdfArgs.texts.push({ text, options });
                    if (text && text.includes('\n') && (!options || !options.lineHeight)) {
                        throw new Error('The drawText method requires a lineHeight option when drawing text with newlines.');
                    }
                    if (text && text.includes('/ 100')) {
                        lastPdfArgs.renderedScore = text;
                    }
                    if (text && text.startsWith('GRADE:')) {
                        lastPdfArgs.renderedGrade = text;
                    }
                    if (options && options.size >= 12 && options.color && !text.includes('/ 100')) {
                        lastPdfArgs.renderedAgency = text;
                        lastPdfArgs.agencyColor = options.color;
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

class MockFileReader {
    constructor() {
        this.onload = null;
        this.onerror = null;
        this.result = null;
    }
    readAsDataURL(file) {
        if (file && file.__failRead) {
            setTimeout(() => {
                if (typeof this.onerror === 'function') {
                    this.onerror(new Error('Mock read failure'));
                }
            }, 0);
            return;
        }
        setTimeout(() => {
            this.result = `data:${file.type || 'image/png'};base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==`;
            if (typeof this.onload === 'function') {
                this.onload({ target: { result: this.result } });
            }
        }, 0);
    }
}

const mockStorage = {};
const sandbox = {
    window: {},
    document: mockDoc,
    navigator: mockNav,
    FileReader: MockFileReader,
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

    // =========================================================================
    // Scenario 9: Interactive Visual Attack Tree & Takeover Simulator
    // =========================================================================
    console.log('\nTesting Scenario 9: Interactive Visual Attack Tree & Takeover Simulator');
    assert(typeof sandbox.window.OrbitAttackTree === 'object', 'window.OrbitAttackTree is exposed');
    assert(typeof sandbox.window.OrbitAttackTree.init === 'function', 'OrbitAttackTree.init is exposed');
    assert(typeof sandbox.window.OrbitAttackTree.setStep === 'function', 'OrbitAttackTree.setStep is exposed');
    assert(typeof sandbox.window.OrbitAttackTree.togglePlay === 'function', 'OrbitAttackTree.togglePlay is exposed');
    assert(typeof sandbox.window.OrbitAttackTree.reset === 'function', 'OrbitAttackTree.reset is exposed');
    assert(typeof sandbox.window.OrbitAttackTree.loadScenario === 'function', 'OrbitAttackTree.loadScenario is exposed');

    // Verify Provider Presets (AWS S3, GitHub Pages, Azure App Service NXDOMAIN, Vercel, Shopify)
    const scenarios = sandbox.window.OrbitAttackTree.scenarios;
    assert(scenarios.aws_s3 && scenarios.aws_s3.provider === 'AWS S3', 'Provider preset AWS S3 is present');
    assert(scenarios.github_pages && scenarios.github_pages.provider === 'GitHub Pages', 'Provider preset GitHub Pages is present');
    assert(scenarios.azure_nxdomain && scenarios.azure_nxdomain.provider === 'Microsoft Azure', 'Provider preset Azure App Service NXDOMAIN is present');
    assert(scenarios.vercel && scenarios.vercel.provider === 'Vercel', 'Provider preset Vercel is present');
    assert(scenarios.shopify && scenarios.shopify.provider === 'Shopify', 'Provider preset Shopify is present');

    // Verify Backwards-Compatible Presets & Aliases
    assert(scenarios.cname && scenarios.cname.id === 'aws_s3', 'Preset alias cname maps to aws_s3');
    assert(scenarios.dmarc && scenarios.dmarc.id === 'azure_nxdomain', 'Preset alias dmarc maps to azure_nxdomain');
    assert(scenarios.dotenv && scenarios.dotenv.id === 'github_pages', 'Preset alias dotenv maps to github_pages');
    assert(scenarios.php418 && scenarios.php418.id === 'vercel', 'Preset alias php418 maps to vercel');

    // Test 5-Step Progression
    sandbox.window.OrbitAttackTree.init('visualAttackTreeContainer', { scenarioKey: 'aws_s3' });
    const inst = sandbox.window.OrbitAttackTree.getInstance('visualAttackTreeContainer');
    assert(inst.activeStep === 1, 'Initial attack tree step is Step 1 (Victim Browser)');

    sandbox.window.OrbitAttackTree.setStep(2, 'visualAttackTreeContainer');
    assert(inst.activeStep === 2, 'Stepper advances to Step 2 (Authoritative DNS CNAME)');

    sandbox.window.OrbitAttackTree.setStep(3, 'visualAttackTreeContainer');
    assert(inst.activeStep === 3, 'Stepper advances to Step 3 (Abandoned Cloud Endpoint)');

    sandbox.window.OrbitAttackTree.setStep(4, 'visualAttackTreeContainer');
    assert(inst.activeStep === 4, 'Stepper advances to Step 4 (Threat Actor Re-Registration)');

    sandbox.window.OrbitAttackTree.setStep(5, 'visualAttackTreeContainer');
    assert(inst.activeStep === 5, 'Stepper advances to Step 5 (Weaponized Execution)');

    // Test prevStep and nextStep Controls & Boundary Clamping
    sandbox.window.OrbitAttackTree.prevStep('visualAttackTreeContainer');
    assert(inst.activeStep === 4, 'prevStep moves from Step 5 to Step 4');
    sandbox.window.OrbitAttackTree.nextStep('visualAttackTreeContainer');
    assert(inst.activeStep === 5, 'nextStep moves from Step 4 to Step 5');
    sandbox.window.OrbitAttackTree.nextStep('visualAttackTreeContainer');
    assert(inst.activeStep === 5, 'nextStep clamps at Step 5 when not auto-playing');

    // Test Auto-Play and Pause Controls
    sandbox.window.OrbitAttackTree.togglePlay('visualAttackTreeContainer');
    assert(inst.isPlaying === true, 'togglePlay starts auto-play');
    sandbox.window.OrbitAttackTree.togglePlay('visualAttackTreeContainer');
    assert(inst.isPlaying === false, 'togglePlay pauses auto-play');

    // Test Reset Control
    sandbox.window.OrbitAttackTree.reset('visualAttackTreeContainer');
    assert(inst.activeStep === 1, 'Reset returns attack tree to Step 1');
    assert(inst.isPlaying === false, 'Reset stops auto-play');
    sandbox.window.OrbitAttackTree.prevStep('visualAttackTreeContainer');
    assert(inst.activeStep === 1, 'prevStep clamps at Step 1');

    // Test Provider Preset Toggling
    sandbox.window.OrbitAttackTree.loadScenario('azure_nxdomain', 'visualAttackTreeContainer');
    assert(inst.scenarioKey === 'azure_nxdomain', 'loadScenario switches active preset to azure_nxdomain');
    assert(inst.provider === 'Microsoft Azure', 'loadScenario updates active cloud provider');
    assert(inst.cnameTarget === 'retired-app-prod.azurewebsites.net', 'loadScenario updates CNAME target to Azure host');
    assert(inst.activeStep === 1, 'loadScenario resets step to 1');

    // Test Init with ScenarioKey Synchronizes Default Subdomain and CNAME
    sandbox.window.OrbitAttackTree.init('freshAttackContainer', { scenarioKey: 'github_pages' });
    const freshInst = sandbox.window.OrbitAttackTree.getInstance('freshAttackContainer');
    assert(freshInst.provider === 'GitHub Pages', 'Fresh init sets provider to GitHub Pages');
    assert(freshInst.subdomain === 'docs.agency-client.io', 'Fresh init sets subdomain to GitHub Pages default');
    assert(freshInst.cnameTarget === 'legacy-org.github.io', 'Fresh init sets CNAME target to GitHub Pages default');

    // Test Deep Integration: simulateTakeoverAttack preloads domain & renders into container
    assert(typeof sandbox.window.simulateTakeoverAttack === 'function', 'simulateTakeoverAttack is exposed on window');
    sandbox.window.simulateTakeoverAttack('aws_s3', 'media.client-store.com', 'orphaned-client-media.s3.amazonaws.com');
    const hudSimHtml = mockDoc.getElementById('auditHUD').innerHTML;
    assert(hudSimHtml.includes('svg') && hudSimHtml.includes('attack-tree-node'), 'simulateTakeoverAttack renders visual SVG attack tree into #auditHUD');
    assert(hudSimHtml.includes('1. VICTIM CLIENT') || hudSimHtml.includes('visitor.browser'), 'Rendered attack tree includes Node 1: Victim / Visitor');
    assert(hudSimHtml.includes('2. AUTHORITATIVE DNS'), 'Rendered attack tree includes Node 2: Authoritative DNS / CNAME');
    assert(hudSimHtml.includes('3. ABANDONED TENANT'), 'Rendered attack tree includes Node 3: Decommissioned Cloud Endpoint');
    assert(hudSimHtml.includes('4. THREAT ACTOR'), 'Rendered attack tree includes Node 4: Threat Actor');
    assert(hudSimHtml.includes('5. WEAPONIZED EXEC'), 'Rendered attack tree includes Node 5: Weaponized Execution');
    assert(hudSimHtml.includes('animateMotion'), 'SVG includes animated packet/pulse flow paths');

    // Test Smart Provider-Specific CNAME Target Fallback in simulateTakeoverAttack
    sandbox.window.simulateTakeoverAttack('azure_nxdomain', 'portal.corp-client.com');
    const hudAzureInst = sandbox.window.OrbitAttackTree.getInstance('auditHUD');
    assert(hudAzureInst.cnameTarget.includes('azurewebsites.net'), 'simulateTakeoverAttack generates azurewebsites.net target for Azure scenario');
    assert(!hudAzureInst.cnameTarget.includes('s3.amazonaws.com'), 'simulateTakeoverAttack does not force S3 target on Azure');

    // Test Calling simulateTakeoverAttack with No Arguments
    sandbox.window.simulateTakeoverAttack();
    const hudDefInst = sandbox.window.OrbitAttackTree.getInstance('auditHUD');
    assert(hudDefInst.subdomain.length > 0, 'simulateTakeoverAttack with 0 args sets valid default subdomain');

    // Test preloadCustom with Azure Signature Synchronizes scenarioKey
    sandbox.window.OrbitAttackTree.preloadCustom('sso.test.net', 'old-api.azurewebsites.net', 'Microsoft Azure', 'NXDOMAIN', 'visualAttackTreeContainer');
    assert(inst.scenarioKey === 'azure_nxdomain', 'preloadCustom with Azure CNAME updates scenarioKey to azure_nxdomain');

    // Test Extreme String Input Does Not Crash or Overflow
    const longDomain = 'very-long-subdomain-name-exceeding-sixty-characters-for-stress-testing.agency-client.com';
    sandbox.window.OrbitAttackTree.preloadCustom(longDomain, 'cname.target.com', 'Custom Cloud', '404 Not Found', 'visualAttackTreeContainer');
    const longHtml = mockDoc.getElementById('visualAttackTreeContainer').innerHTML;
    assert(longHtml.includes('..'), 'Long subdomain is safely truncated with ellipsis');

    // Verify Takeover Playground HTML in landing/index.html includes the visual attack tree elements & noscript
    assert(indexHtml.includes('visualAttackTreeContainer'), 'landing/index.html includes visual attack tree container');
    assert(indexHtml.includes('OrbitAttackTree'), 'landing/index.html integrates OrbitAttackTree engine');
    assert(indexHtml.includes('<noscript>') && indexHtml.includes('Visual Attack Tree // Subdomain Takeover Sequence'), 'landing/index.html includes accessible noscript attack tree fallback');

    // ==========================================
    // Testing Scenario 10: Interactive White-Label Portal Customizer Sandbox
    // ==========================================
    console.log('\nTesting Scenario 10: Interactive White-Label Portal Customizer Sandbox');

    // 1. Verify Sandbox Controls in landing/index.html
    assert(indexHtml.includes('id="portals"'), 'landing/index.html includes #portals section');
    assert(indexHtml.includes('id="portalAgencyNameInput"'), 'landing/index.html includes #portalAgencyNameInput');
    assert(indexHtml.includes('id="portalSwatch-emerald"'), 'landing/index.html includes Orbit Emerald swatch');
    assert(indexHtml.includes('id="portalSwatch-cyan"'), 'landing/index.html includes Cyber Cyan swatch');
    assert(indexHtml.includes('id="portalSwatch-indigo"'), 'landing/index.html includes Indigo swatch');
    assert(indexHtml.includes('id="portalSwatch-violet"'), 'landing/index.html includes Electric Violet swatch');
    assert(indexHtml.includes('id="portalSwatch-amber"'), 'landing/index.html includes Amber Gold swatch');
    assert(indexHtml.includes('id="portalSwatch-crimson"'), 'landing/index.html includes Crimson swatch');
    assert(indexHtml.includes('id="portalColorPicker"'), 'landing/index.html includes custom hex color picker');
    assert(indexHtml.includes('id="portalColorHexInput"'), 'landing/index.html includes custom hex text input');
    assert(indexHtml.includes('id="portalLogoDropzone"'), 'landing/index.html includes logo drag-and-drop zone');
    assert(indexHtml.includes('id="portalLogoInput"'), 'landing/index.html includes hidden logo file input');
    assert(indexHtml.includes('id="portalResetLogoBtn"'), 'landing/index.html includes 1-click Reset Logo button');
    assert(indexHtml.includes('id="portalMockupCard"'), 'landing/index.html includes Live Portal Mockup card');
    assert(indexHtml.includes('id="portalMockupAgencyName"'), 'landing/index.html includes mockup agency name header');
    assert(indexHtml.includes('id="portalMockupLogoImg"'), 'landing/index.html includes mockup custom logo image');
    assert(indexHtml.includes('id="portalMockupDefaultMark"'), 'landing/index.html includes mockup default shield brand mark');
    assert(indexHtml.includes('id="portalMockupTierBadge"'), 'landing/index.html includes mockup tier badge');
    assert(indexHtml.includes('id="portalMockupScoreVal"'), 'landing/index.html includes mockup score ring value');
    assert(indexHtml.includes('id="portalMockupScoreRingCircle"'), 'landing/index.html includes mockup SVG circular score ring');
    assert(indexHtml.includes('id="portalMockupGradeBadge"'), 'landing/index.html includes mockup health grade badge');
    assert(indexHtml.includes('id="portalMockupLaunchBtn"'), 'landing/index.html includes Launch Live Demo Portal button');
    assert(indexHtml.includes('id="portalMockupInviteBtn"'), 'landing/index.html includes Copy Client Invite Link button');
    assert(indexHtml.includes('id="portalMockupResetBtn"'), 'landing/index.html includes Reset Branding button');

    // 2. Verify Exposed Customizer API on window
    assert(typeof sandbox.window.applyPortalBrandColor === 'function', 'applyPortalBrandColor is exposed on window');
    assert(typeof sandbox.window.applyPortalAgencyName === 'function', 'applyPortalAgencyName is exposed on window');
    assert(typeof sandbox.window.handlePortalLogoFile === 'function', 'handlePortalLogoFile is exposed on window');
    assert(typeof sandbox.window.applyPortalLogo === 'function', 'applyPortalLogo is exposed on window');
    assert(typeof sandbox.window.resetPortalLogo === 'function', 'resetPortalLogo is exposed on window');
    assert(typeof sandbox.window.resetPortalBranding === 'function', 'resetPortalBranding is exposed on window');
    assert(typeof sandbox.window.copyClientInviteLink === 'function', 'copyClientInviteLink is exposed on window');

    // 3. Agency Name Synchronization & Persistence
    sandbox.window.applyPortalAgencyName('Vanguard Digital Partners', true);
    assert(mockDoc.getElementById('portalMockupAgencyName').textContent === 'Vanguard Digital Partners', 'Mockup displays updated agency name');
    assert(mockDoc.getElementById('radarAgencyName').value === 'Vanguard Digital Partners', 'radarAgencyName input synchronized');
    assert(mockDoc.getElementById('customAgencyName').value === 'Vanguard Digital Partners', 'customAgencyName input synchronized');
    assert(mockDoc.getElementById('portalAgencyNameInput').value === 'Vanguard Digital Partners', 'portalAgencyNameInput synchronized');
    assert(mockStorage['orbit_agency_name'] === 'Vanguard Digital Partners', 'Agency name persisted in localStorage');
    assert(mockDoc.getElementById('portalMockupUrlDisplay').textContent.includes('vanguarddigitalpartners'), 'Mockup URL display updated with sanitized domain slug');

    // 4. Brand Accent Color Swatches, Score Rings & Custom Hex Picker
    sandbox.window.applyPortalBrandColor('#06b6d4', 'cyan');
    assert(mockStorage['orbit_brand_color'] === '#06b6d4', 'Cyber Cyan persisted in localStorage');
    assert(mockDoc.getElementById('portalActiveColorLabel').textContent === '#06b6d4', 'Active color label reflects Cyber Cyan');
    assert(mockDoc.getElementById('portalColorPicker').value === '#06b6d4', 'Color picker value synchronized');
    assert(mockDoc.getElementById('portalMockupScoreRingCircle').style.stroke === '#06b6d4', 'Mockup SVG score ring stroke reflects Cyber Cyan');

    sandbox.window.applyPortalBrandColor('#8b5cf6', 'violet');
    assert(mockStorage['orbit_brand_color'] === '#8b5cf6', 'Electric Violet persisted in localStorage');
    assert(mockDoc.getElementById('portalMockupTierBadge').style.color === '#8b5cf6', 'Mockup tier badge reflects Electric Violet');
    assert(mockDoc.getElementById('portalMockupScoreRingCircle').style.stroke === '#8b5cf6', 'Mockup SVG score ring stroke reflects Electric Violet');

    sandbox.window.applyPortalBrandColor('#f59e0b', 'amber');
    assert(mockStorage['orbit_brand_color'] === '#f59e0b', 'Amber Gold persisted in localStorage');

    sandbox.window.applyPortalBrandColor('#f43f5e', 'crimson');
    assert(mockStorage['orbit_brand_color'] === '#f43f5e', 'Crimson persisted in localStorage');

    sandbox.window.applyPortalBrandColor('#3b82f6', 'custom');
    assert(mockStorage['orbit_brand_color'] === '#3b82f6', 'Custom hex code persisted in localStorage');
    assert(mockDoc.getElementById('portalMockupScoreVal').style.color === '#3b82f6', 'Mockup score value reflects custom hex');
    assert(mockDoc.getElementById('portalMockupScoreRingCircle').style.stroke === '#3b82f6', 'Mockup SVG score ring reflects custom hex');

    // Test 3-character hex shorthand normalization (#0ff -> #00ffff)
    sandbox.window.applyPortalBrandColor('#0ff', 'custom');
    assert(mockStorage['orbit_brand_color'] === '#00ffff', '3-character hex shorthand #0ff normalizes to 6-digit #00ffff');
    assert(mockDoc.getElementById('portalActiveColorLabel').textContent === '#00ffff', 'Active label reflects normalized 6-digit hex');

    // Test custom hex persistence across session load (no regression to emerald)
    sandbox.AuditStore.saveBranding('Apex Elite', '#ff00aa', 'custom');
    const loadedBrand = sandbox.AuditStore.loadBranding();
    assert(loadedBrand && loadedBrand.color === '#ff00aa', 'loadBranding accurately restores custom hex color without wiping');
    sandbox.window.applyPortalBrandColor(loadedBrand.color, loadedBrand.colorName);
    assert(mockStorage['orbit_brand_color'] === '#ff00aa', 'applyPortalBrandColor retains custom hex #ff00aa without falling back to emerald');

    // 5. Logo File Validation & FileReader Upload
    const invalidFile = { name: 'malware.exe', type: 'application/x-msdownload', size: 1024 };
    const invalidRes = sandbox.window.handlePortalLogoFile(invalidFile);
    assert(invalidRes === false, 'handlePortalLogoFile rejects non-image executable file');

    const oversizeFile = { name: 'huge_logo.png', type: 'image/png', size: 5 * 1024 * 1024 };
    const oversizeRes = sandbox.window.handlePortalLogoFile(oversizeFile);
    assert(oversizeRes === false, 'handlePortalLogoFile rejects file exceeding 2MB');

    const validFile = { name: 'agency_logo.png', type: 'image/png', size: 10240 };
    const validRes = sandbox.window.handlePortalLogoFile(validFile);
    assert(validRes === true, 'handlePortalLogoFile accepts valid PNG image');

    // Test error handling in FileReader
    const errorFile = { name: 'broken.png', type: 'image/png', size: 1024, __failRead: true };
    const errorRes = sandbox.window.handlePortalLogoFile(errorFile);
    assert(errorRes === true, 'handlePortalLogoFile attempts read on valid format');

    // Test applyPortalLogo directly
    const testDataUrl = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    sandbox.window.applyPortalLogo(testDataUrl, 'agency_logo.png');
    assert(mockDoc.getElementById('portalMockupLogoImg').src === testDataUrl, 'Mockup logo img src set to data URL');
    assert(mockStorage['orbit_agency_logo'] === testDataUrl, 'Logo data URL persisted in localStorage');

    // 6. 1-Click Reset to Default Orbit Logo
    sandbox.window.resetPortalLogo();
    assert(mockDoc.getElementById('portalMockupLogoImg').src === '', 'Mockup logo img cleared on reset');
    assert(mockStorage['orbit_agency_logo'] === undefined || mockStorage['orbit_agency_logo'] === null, 'Logo removed from localStorage');

    // 7. Copy Client Invite Link
    const inviteUrl = sandbox.window.copyClientInviteLink();
    assert(inviteUrl.includes('orbit-core.html') && inviteUrl.includes('agency='), 'copyClientInviteLink generates valid portal URL with agency query');
    assert(clipboardText.includes('orbit-core.html'), 'Invite URL copied to clipboard');

    // 8. 1-Click Reset All Branding
    sandbox.window.resetPortalBranding();
    assert(mockDoc.getElementById('portalMockupAgencyName').textContent === 'Apex Digital Studio', 'Reset branding restores default agency name');
    assert(mockStorage['orbit_brand_color'] === '#10b981', 'Reset branding restores Orbit Emerald');

    // 9. Multi-Tab Broadcast Synchronization
    sandbox.window.applyPortalAgencyName('Original Agency', true);
    sandbox.window.applyPortalBrandColor('#10b981', 'emerald');
    // Simulate incoming broadcast from sibling tab
    sandbox.window.applyPortalAgencyName('Sibling Tab Security', true);
    sandbox.window.applyPortalBrandColor('#6366f1', 'indigo');
    sandbox.window.applyPortalLogo(testDataUrl, 'remote-logo.png');
    assert(mockDoc.getElementById('portalAgencyNameInput').value === 'Sibling Tab Security', 'Remote tab sync updates portalAgencyNameInput');
    assert(mockDoc.getElementById('portalMockupAgencyName').textContent === 'Sibling Tab Security', 'Remote tab sync updates portalMockupAgencyName');
    assert(mockStorage['orbit_brand_color'] === '#6366f1', 'Remote tab sync updates brand color to Indigo');
    assert(mockDoc.getElementById('portalMockupLogoImg').src === testDataUrl, 'Remote tab sync updates mockup logo');

    // 10. Synergy with PDF Generation
    lastPdfArgs = {};
    sandbox.window.applyPortalAgencyName('Custom Enterprise Agency', true);
    sandbox.window.applyPortalBrandColor('#6366f1', 'indigo');
    await sandbox.window.generateInstantPdfForDomain('client-test.com', 92, 'A+');
    assert(lastPdfArgs.renderedScore === '92 / 100', 'PDF generation successfully renders score with custom branding');
    assert(lastPdfArgs.renderedAgency === 'CUSTOM ENTERPRISE AGENCY', 'PDF generation renders custom agency name in header banner');
    assert(lastPdfArgs.renderedColor && Math.abs(lastPdfArgs.renderedColor.r - 99/255) < 0.02, 'PDF top accent bar renders Indigo primaryColor');

    // Test generateInstantPdf() resolves from portal customizer input
    lastPdfArgs = {};
    sandbox.window.applyPortalAgencyName('Global Threat Sentinels', true);
    await sandbox.window.generateInstantPdf();
    assert(lastPdfArgs.renderedAgency === 'GLOBAL THREAT SENTINELS', 'generateInstantPdf() uses agency name from portal customizer');

    // =========================================================================
    // Scenario 11: Adversarial Bughunt Stress & Edge Case Verification Suite
    // =========================================================================
    console.log('\nTesting Scenario 11: Adversarial Bughunt Stress & Edge Case Suite');

    // 1. Apex Wildcard DNS Evasion (Wildcard A Record)
    DoHService.query = async (name, type) => {
        if (name.startsWith('orbit-wc-check-')) {
            if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '198.51.100.1' }] };
            return { success: true, status: 0, answer: [] };
        }
        if (name.startsWith('_dmarc.')) return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.wildcard-a.com' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '198.51.100.1' }] };
        return { success: true, status: 0, answer: [] };
    };
    const auditWcA = await performClientDohAudit('wildcard-a.com');
    assert(auditWcA.hasWildcardDns === true, 'Wildcard A probe detects wildcard DNS presence');
    assert(auditWcA.cnameStatus === 'pass', 'Wildcard A does not trigger false CNAME takeover');
    assert(auditWcA.findings[0].status === 'PASS', 'Subdomain takeover finding is PASS on Wildcard A');

    // 2. Apex Wildcard DNS Evasion (Wildcard CNAME Record)
    DoHService.query = async (name, type) => {
        if (name.startsWith('orbit-wc-check-')) {
            if (type === 5) return { success: true, status: 0, answer: [{ type: 5, data: 'wildcard.cdn.net.' }] };
            if (type === 1) return { success: true, status: 0, answer: [{ type: 5, data: 'wildcard.cdn.net.' }, { type: 1, data: '198.51.100.2' }] };
            return { success: true, status: 0, answer: [] };
        }
        if (name.startsWith('_dmarc.')) return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.wildcard-cname.com' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '198.51.100.2' }] };
        // 16 subdomains all return the apex wildcard CNAME
        if (type === 5) return { success: true, status: 0, answer: [{ type: 5, data: '"wildcard.cdn.net."' }] };
        return { success: true, status: 0, answer: [] };
    };
    const auditWcCname = await performClientDohAudit('wildcard-cname.com');
    assert(auditWcCname.hasWildcardDns === true, 'Wildcard CNAME probe detects wildcard DNS');
    assert(auditWcCname.cnameStatus === 'pass', 'Wildcard CNAME suppresses false-positive takeover across all 16 subdomains');
    assert(auditWcCname.findings[0].status === 'PASS', 'Subdomain takeover finding is PASS despite wildcard CNAME');

    // 3. Two-Prong Takeover: Active Azure App Service (Status 0 -> PASS)
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.azure-active.com' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '20.119.8.1' }] }; // Active IP
        if (name === 'app.azure-active.com' && type === 5) {
            return { success: true, status: 0, answer: [{ type: 5, data: 'active-app.azurewebsites.net' }] };
        }
        return { success: true, status: 0, answer: [] };
    };
    const auditAzureActive = await performClientDohAudit('azure-active.com');
    assert(auditAzureActive.cnameStatus === 'pass', 'Active Azure app service target does not trigger takeover');
    assert(auditAzureActive.cnameScore === 25, 'Active Azure app awards 25/25 pts');
    assert(auditAzureActive.grade === 'A+', 'Active Azure app preserves Grade A+');

    // 4. Two-Prong Takeover: AWS Elastic Beanstalk NXDOMAIN (Status 3 -> Prong A Grade F)
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '10 mx.beanstalk-risk.com' }] };
        if (type === 1) {
            if (name === 'dangling-env.elasticbeanstalk.com') return { success: true, status: 3, answer: [] };
            return { success: true, status: 0, answer: [{ type: 1, data: '203.0.113.1' }] };
        }
        if (name === 'api.beanstalk-risk.com' && type === 5) {
            return { success: true, status: 0, answer: [{ type: 5, data: 'dangling-env.elasticbeanstalk.com' }] };
        }
        return { success: true, status: 0, answer: [] };
    };
    const auditBeanstalk = await performClientDohAudit('beanstalk-risk.com');
    assert(auditBeanstalk.cnameStatus === 'critical', 'Dangling Elastic Beanstalk triggers critical CNAME status');
    assert(auditBeanstalk.cnameScore === 0, 'Dangling Beanstalk sets cnameScore to 0');
    assert(auditBeanstalk.grade === 'F', 'Dangling Beanstalk forces overall Grade F');

    // 5. Quoted RFC 7505 Null-MX ("0 .")
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [{ type: 15, data: '"0 ."' }] };
        if (type === 1) return { success: true, status: 0, answer: [{ type: 1, data: '203.0.113.1' }] };
        return { success: true, status: 0, answer: [] };
    };
    const auditQuotedNullMx = await performClientDohAudit('quoted-nullmx.com');
    assert(auditQuotedNullMx.isNullMx === true, 'Quoted "0 ." correctly recognized as Null-MX');
    assert(auditQuotedNullMx.mxScore === 15, 'Quoted Null-MX awards 15 pts');
    assert(auditQuotedNullMx.mxStatus === 'pass', 'Quoted Null-MX status is pass');

    // 6. Missing MX with Unresolvable Apex A (Status 0 pts, fail)
    DoHService.query = async (name, type) => {
        if (name.startsWith('_dmarc.')) return { success: true, status: 0, answer: [{ type: 16, data: '"v=DMARC1; p=reject;"' }] };
        if (type === 16) return { success: true, status: 0, answer: [{ type: 16, data: '"v=spf1 -all"' }] };
        if (type === 15) return { success: true, status: 0, answer: [] };
        if (type === 1) return { success: true, status: 0, answer: [] }; // No apex A
        return { success: true, status: 0, answer: [] };
    };
    const auditNoMxNoA = await performClientDohAudit('nomx-noa.com');
    assert(auditNoMxNoA.mxScore === 0, 'Missing MX with unresolvable apex A awards 0 pts');
    assert(auditNoMxNoA.mxStatus === 'fail', 'Missing MX with unresolvable apex A status is fail');

    // 7. Client-side PDF Generation with 5 Categories and Vertical Spacing
    lastPdfArgs = {};
    const fiveCategories = [
        { category: 'SUBDOMAIN TAKEOVER SENTINEL', desc: 'Zero dangling pointers.', status: 'PASS' },
        { category: 'EMAIL SPOOFING PROTECTION (DMARC)', desc: 'Strict reject policy verified.', status: 'PASS' },
        { category: 'SENDER POLICY FRAMEWORK (SPF)', desc: 'Strict SPF policy enforced.', status: 'PASS' },
        { category: 'MAIL INBOUND ROUTING (MX)', desc: 'Valid MX route active.', status: 'PASS' },
        { category: 'TLS / SSL CERTIFICATE EXPIRY', desc: 'Valid cert active.', status: 'PASS' }
    ];
    await generateInstantPdfForDomain('five-cat.com', 95, 'A+', null, fiveCategories);
    assert(lastPdfArgs.renderedScore === '95 / 100', 'PDF generated with 5 categories renders score');
    const findingRects5 = (lastPdfArgs.rectangles || []).filter(r => r.width === 595.28 - 80 && r.height === 36);
    assert(findingRects5.length === 5, 'PDF generated with 5 categories renders exactly 5 finding cards');
    const lowestBoxY5 = Math.min(...findingRects5.map(r => r.y));
    assert(lowestBoxY5 > 140, `Lowest finding box y (${lowestBoxY5}) is well above Care Plan box (y=85, top=140)`);

    // 8. Client-side PDF Generation with 6 Categories and Vertical Spacing
    lastPdfArgs = {};
    const sixCategories = [
        ...fiveCategories,
        { category: 'SENSITIVE EXPOSURE SENTINEL', desc: 'Passive DoH audit complete.', status: 'N/A' }
    ];
    await generateInstantPdfForDomain('six-cat.com', 95, 'A+', null, sixCategories);
    const findingRects6 = (lastPdfArgs.rectangles || []).filter(r => r.width === 595.28 - 80 && r.height === 36);
    assert(findingRects6.length === 6, 'PDF generated with 6 categories renders exactly 6 finding cards');
    const lowestBoxY6 = Math.min(...findingRects6.map(r => r.y));
    assert(lowestBoxY6 > 140, `Lowest finding box y for 6 items (${lowestBoxY6}) leaves breathing room above Care Plan box (y=85)`);

    // 9. Client-side PDF Generation with Newlines in Description (No pdf-lib Crash)
    lastPdfArgs = {};
    const multilineDesc = [
        { category: 'EMAIL SPOOFING PROTECTION (DMARC)', desc: 'Line 1 of DMARC policy\nLine 2 with extra info\r\nLine 3', status: 'PASS' },
        { category: 'SENDER POLICY FRAMEWORK (SPF)', desc: 'v=spf1\ninclude:_spf.google.com\n-all', status: 'PASS' },
        { category: 'SUBDOMAIN TAKEOVER SENTINEL', desc: 'No\ndangling\nCNAME', status: 'PASS' },
        { category: 'MAIL INBOUND ROUTING (MX)', desc: 'RFC 7505\nNull-MX', status: 'PASS' }
    ];
    await generateInstantPdfForDomain('multiline.com', 90, 'A', null, multilineDesc);
    assert(lastPdfArgs.renderedScore === '90 / 100', 'PDF generator strips newlines and succeeds without throw');

    // 10. Attack Tree Stepper Boundary Clamping
    sandbox.window.OrbitAttackTree.init('boundaryAttackTree', { activeStep: 1 });
    const bInst = sandbox.window.OrbitAttackTree.getInstance('boundaryAttackTree');
    assert(bInst.activeStep === 1, 'Initial step is 1');
    sandbox.window.OrbitAttackTree.prevStep('boundaryAttackTree');
    assert(bInst.activeStep === 1, 'prevStep clamps at 1');
    sandbox.window.OrbitAttackTree.setStep(5, 'boundaryAttackTree');
    assert(bInst.activeStep === 5, 'setStep reaches 5');
    sandbox.window.OrbitAttackTree.nextStep('boundaryAttackTree');
    assert(bInst.activeStep === 5, 'nextStep clamps at 5');

    // 11. Attack Tree Timer Hygiene
    sandbox.window.OrbitAttackTree.togglePlay('boundaryAttackTree');
    const firstTimer = bInst.timer;
    assert(bInst.isPlaying === true, 'Attack tree isPlaying is true');
    assert(firstTimer !== null, 'Timer is active');
    sandbox.window.OrbitAttackTree.togglePlay('boundaryAttackTree');
    assert(bInst.isPlaying === false, 'Attack tree paused');
    assert(bInst.timer === null, 'Timer is cleared on pause');
    sandbox.window.OrbitAttackTree.togglePlay('boundaryAttackTree');
    assert(bInst.isPlaying === true, 'Attack tree resumed');
    sandbox.window.OrbitAttackTree.reset('boundaryAttackTree');
    assert(bInst.isPlaying === false, 'Reset halts playback');
    assert(bInst.timer === null, 'Reset clears timer');

    // 12. Attack Tree SVG Path Geometry & Malicious Special Characters
    const xssDomain = 'adversary-subdomain-overflowing-sixty-characters-with-symbols<script>"\'&.client.com';
    sandbox.window.OrbitAttackTree.preloadCustom(xssDomain, 'cname.target.com', 'Custom Cloud', 'Fingerprint', 'boundaryAttackTree');
    const xssHtml = mockDoc.getElementById('boundaryAttackTree').innerHTML;
    assert(!xssHtml.includes('<script>'), 'Unescaped script tags blocked in SVG');
    assert(xssHtml.includes('&lt;script&gt;') || xssHtml.includes('..'), 'Special characters are safely escaped or truncated with ellipsis');
    assert(xssHtml.includes('p34') || xssHtml.includes('C 515 180, 540 215, 590 215'), 'SVG contains valid p34 path geometry');
    assert(xssHtml.includes('p51') || xssHtml.includes('M 885 95 L 885 24 Q 885 10, 870 10 L 130 10 Q 115 10, 115 24 L 115 95'), 'SVG contains elevated return arch p51 clearing Node 2/3 headers');

    // 13. Portal Customizer 3-Char Shorthand & Contrast
    sandbox.window.applyPortalBrandColor('#ffffff', 'custom');
    assert(mockStorage['orbit_brand_color'] === '#ffffff', 'Custom hex #ffffff saved');
    const launchWhiteBtn = mockDoc.getElementById('portalMockupLaunchBtn');
    assert(launchWhiteBtn.style.color === '#020617', 'White brand color sets dark text #020617 for contrast');

    sandbox.window.applyPortalBrandColor('#020617', 'custom');
    assert(mockStorage['orbit_brand_color'] === '#020617', 'Custom hex #020617 saved');
    const launchDarkBtn = mockDoc.getElementById('portalMockupLaunchBtn');
    assert(launchDarkBtn.style.color === '#ffffff', 'Dark brand color sets white text #ffffff for contrast');

    // 14. Portal Customizer Logo Rejections
    const exeFile = { name: 'exploit.exe', type: 'application/octet-stream', size: 1024 };
    assert(sandbox.window.handlePortalLogoFile(exeFile) === false, 'Rejects non-image executable file');
    const hugeFile = { name: 'banner.png', type: 'image/png', size: 3 * 1024 * 1024 };
    assert(sandbox.window.handlePortalLogoFile(hugeFile) === false, 'Rejects oversized >2MB image file');

    // 15. orbit-core.html Client Hydration Verification
    const orbitCoreHtml = fs.readFileSync(path.join(__dirname, '..', 'docs', 'portals', 'orbit-core.html'), 'utf8');
    assert(orbitCoreHtml.includes("params.get('agency')"), 'orbit-core.html parses agency query parameter');
    assert(orbitCoreHtml.includes("params.get('color')"), 'orbit-core.html parses color query parameter');
    assert(orbitCoreHtml.includes('/^#[0-9a-f]{3}$/i'), 'orbit-core.html normalizes 3-character hex shorthand');
    assert(orbitCoreHtml.includes('0.299 * r + 0.587 * g + 0.114 * b'), 'orbit-core.html calculates luminance for button text');
    assert(orbitCoreHtml.includes("document.createElement('img')"), 'orbit-core.html creates logo img via DOM node to prevent XSS');

    console.log(`\n========================================`);
    console.log(`ALL ${passed}/${total} AUDIT ENGINE & PDF PARITY TESTS PASSED!`);
    console.log(`========================================`);
    process.exit(0);
}

runTests().catch(err => {
    console.error('Test runner failure:', err);
    process.exit(1);
});
