/**
 * Orbit Security - SimpleCat Visuals & Horizontal Scroll Verification Suite
 * Empirically tests:
 * 1. Horizontal scroll mask classes & responsive indicators
 * 2. SimpleCat floating dock (#simple-cat-dock) z-index, safe-area insets, and modal suppression
 * 3. SimpleCat modal layout, mobile collision protection, and touch scrolling
 * 4. Astro-Cat copilot HUD flip and speech bubble viewport boundary clamping
 * 5. 100% byte-for-byte SHA-256 parity between docs/ and landing/
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');

console.log('--- STARTING SIMPLECAT VISUALS & HORIZONTAL SCROLL TEST SUITE ---');

// Helper to compute sha256
function sha256(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

const docsIndexPath = path.join(__dirname, '..', 'docs', 'index.html');
const landingIndexPath = path.join(__dirname, '..', 'landing', 'index.html');
const docsCatPath = path.join(__dirname, '..', 'docs', 'assets', 'simple_cat.js');
const landingCatPath = path.join(__dirname, '..', 'landing', 'assets', 'simple_cat.js');
const docsRadarPath = path.join(__dirname, '..', 'docs', 'assets', 'orbit_radar.js');
const landingRadarPath = path.join(__dirname, '..', 'landing', 'assets', 'orbit_radar.js');

const docsIndexHtml = fs.readFileSync(docsIndexPath, 'utf8');
const docsCatJs = fs.readFileSync(docsCatPath, 'utf8');
const docsRadarJs = fs.readFileSync(docsRadarPath, 'utf8');

let testCount = 0;
function test(name, fn) {
    testCount++;
    try {
        fn();
        console.log(`✓ [${testCount}] ${name}`);
    } catch (e) {
        console.error(`✗ [${testCount}] FAILED: ${name}`);
        console.error(e);
        process.exit(1);
    }
}

// 1. HORIZONTAL SCROLL MASK UTILITIES
test('Universal horizontal scroll mask utilities present in index.html', () => {
    assert(docsIndexHtml.includes('.scroll-indicate-x'), 'Missing .scroll-indicate-x in index.html');
    assert(docsIndexHtml.includes('.scroll-fade-r'), 'Missing .scroll-fade-r in index.html');
    assert(docsIndexHtml.includes('.scroll-fade-l'), 'Missing .scroll-fade-l in index.html');
    assert(docsIndexHtml.includes('.scroll-fade-both'), 'Missing .scroll-fade-both in index.html');
    assert(docsIndexHtml.includes('.scroll-cyber-x'), 'Missing .scroll-cyber-x in index.html');
});

test('Universal horizontal scroll mask utilities injected by simple_cat.js', () => {
    assert(docsCatJs.includes('.scroll-indicate-x'), 'Missing .scroll-indicate-x in simple_cat.js');
    assert(docsCatJs.includes('.scroll-fade-r'), 'Missing .scroll-fade-r in simple_cat.js');
    assert(docsCatJs.includes('.scroll-fade-l'), 'Missing .scroll-fade-l in simple_cat.js');
    assert(docsCatJs.includes('.scroll-fade-both'), 'Missing .scroll-fade-both in simple_cat.js');
    assert(docsCatJs.includes('.scroll-cyber-x'), 'Missing .scroll-cyber-x in simple_cat.js');
});

// 2. HORIZONTAL SCROLL CONTAINERS HOOKED UP
test('SimpleCat quick-jump chips have horizontal scroll mask & cyber scrollbar', () => {
    assert(docsCatJs.includes('id="cat-quick-chips" class="flex items-center gap-1.5 py-2.5 overflow-x-auto border-b border-slate-800 text-[10px] font-mono no-scrollbar scroll-indicate-x scroll-fade-r scroll-cyber-x"'), 'Quick chips missing scroll classes');
});

test('SimpleCat modal tabs have horizontal scroll mask & cyber scrollbar', () => {
    assert(docsCatJs.includes('overflow-x-auto text-xs font-mono no-scrollbar scroll-indicate-x scroll-fade-r scroll-cyber-x"'), 'Modal tabs missing scroll classes');
});

test('Audit HUD tabs in orbit_radar.js have horizontal scroll mask & cyber scrollbar', () => {
    assert(docsRadarJs.includes('overflow-x-auto pb-1.5 -mx-1 px-1 no-scrollbar scroll-indicate-x scroll-fade-r scroll-cyber-x'), 'Audit HUD tabs missing scroll classes');
});

test('Scenario Simulator Report Views have horizontal scroll mask & cyber scrollbar', () => {
    assert(docsIndexHtml.includes('overflow-x-auto pb-2 lg:pb-0 -mx-2 px-2 no-scrollbar scroll-indicate-x scroll-fade-r scroll-cyber-x'), 'Report views missing scroll classes');
});

test('Steal Our Pitch drawer tabs have horizontal scroll mask & cyber scrollbar', () => {
    assert(docsIndexHtml.includes('overflow-x-auto pb-1 md:pb-0 no-scrollbar scroll-indicate-x scroll-fade-r scroll-cyber-x'), 'Pitch tabs missing scroll classes');
});

test('Flipbook Page 2 Subdomain Matrix table has horizontal scroll mask & cyber scrollbar', () => {
    assert(docsIndexHtml.includes('overflow-x-auto scroll-indicate-x scroll-fade-r scroll-cyber-x'), 'Flipbook table missing scroll classes');
});

// 3. SIMPLECAT FLOATING DOCK & MODAL COLLISION ISOLATION
test('#simple-cat-dock uses z-45 to avoid colliding with z-50 modals & navigation', () => {
    assert(docsCatJs.includes('dockEl.className = "fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-45 flex items-center gap-2";'), 'Dock should use z-45');
    assert(docsIndexHtml.includes('#simple-cat-dock {'), 'index.html style must target #simple-cat-dock');
    assert(!docsIndexHtml.includes('#simple-cat-floating {'), 'Stale #simple-cat-floating selector should be removed');
});

test('#simple-cat-dock includes safe-area-inset padding for mobile home indicator bars', () => {
    assert(docsIndexHtml.includes('bottom: max(16px, env(safe-area-inset-bottom, 16px))'), 'Missing safe-area-inset-bottom on dock');
    assert(docsIndexHtml.includes('right: max(16px, env(safe-area-inset-right, 16px))'), 'Missing safe-area-inset-right on dock');
});

test('body.modal-open and body.drawer-open cleanly suppress #simple-cat-dock', () => {
    assert(docsIndexHtml.includes('body.drawer-open #simple-cat-dock'), 'Drawer open rule missing');
    assert(docsIndexHtml.includes('body.modal-open #simple-cat-dock'), 'Modal open rule missing');
    assert(docsCatJs.includes('body.modal-open #simple-cat-dock'), 'Modal open rule in simple_cat.js missing');
});

test('showSimpleCatDialog and hideSimpleCatDialog toggle body.modal-open', () => {
    assert(docsCatJs.includes("document.body.classList.add('modal-open');"), 'showSimpleCatDialog should add modal-open');
    assert(docsCatJs.includes("document.body.classList.remove('modal-open');"), 'hideSimpleCatDialog should remove modal-open');
});

test('openPdfFlipbookModal and closePdfFlipbookModal toggle body.modal-open', () => {
    assert(docsIndexHtml.includes("document.body.classList.add('modal-open');"), 'openPdfFlipbookModal should add modal-open');
    assert(docsIndexHtml.includes("document.body.classList.remove('modal-open');"), 'closePdfFlipbookModal should remove modal-open');
});

test('showKeyboardHud and hideKeyboardHud toggle body.modal-open', () => {
    assert(docsRadarJs.includes("document.body.classList.add('modal-open');"), 'showKeyboardHud should add modal-open');
    assert(docsRadarJs.includes("document.body.classList.remove('modal-open');"), 'hideKeyboardHud should remove modal-open');
});

// 4. SIMPLECAT MODAL LAYOUT & MOBILE COLLISION PREVENTION
test('SimpleCat dialog modal header has pr-12 to prevent title overlap with close button on mobile', () => {
    assert(docsCatJs.includes('<div class="flex items-center gap-3 pr-12 sm:pr-0">'), 'Modal header missing pr-12 collision protection');
});

test('SimpleCat dialog scrollable content container includes -webkit-overflow-scrolling: touch', () => {
    assert(docsCatJs.includes('-webkit-overflow-scrolling: touch;'), 'Modal tab content missing touch momentum scroll');
});

// 5. ASTRO-CAT COPILOT HUD & SPEECH BUBBLE VIEWPORT BOUNDARY CLAMPING
test('Astro-Cat Copilot HUD dynamically flips above cat when near bottom edge', () => {
    assert(docsCatJs.includes('visualY > window.innerHeight - 130'), 'Missing HUD flip threshold check');
    assert(docsCatJs.includes('hud.classList.add("astro-hud-above")'), 'Missing astro-hud-above class addition');
    assert(docsCatJs.includes('.astro-hud.astro-hud-above'), 'Missing .astro-hud.astro-hud-above style');
});

test('Astro-Cat Copilot HUD clamps horizontal offset to prevent off-screen clipping', () => {
    assert(docsCatJs.includes('catCenterX - hudHalfWidth < 12'), 'Missing left edge HUD clamping');
    assert(docsCatJs.includes('catCenterX + hudHalfWidth > window.innerWidth - 12'), 'Missing right edge HUD clamping');
});

test('Astro-Cat Speech Bubble strictly clamps bubbleY within viewport boundaries', () => {
    assert(docsCatJs.includes('bubbleY = Math.max(12, Math.min(window.innerHeight - bubbleH - 12, bubbleY));'), 'Speech bubble missing Y viewport clamping');
});

// 6. PUBLIC API & SCROLL OBSERVER EXPORTS
test('SimpleCat public API exports initScrollIndicators and updateScrollMask', () => {
    assert(docsCatJs.includes('initScrollIndicators: initAllScrollIndicators'), 'Missing initScrollIndicators export');
    assert(docsCatJs.includes('updateScrollMask: updateScrollMask'), 'Missing updateScrollMask export');
});

// 7. WHITE-LABEL FLIPBOOK RESPONSIVE HEADER REFACTORING
test('Flipbook modal header separates title and close button on mobile with dedicated scrollbar', () => {
    assert(docsIndexHtml.includes('class="sm:hidden text-slate-400 hover:text-white font-arcade text-xs min-w-[40px] min-h-[40px] px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 cursor-pointer flex items-center justify-center">✕</button>'), 'Flipbook modal missing mobile close button');
    assert(docsIndexHtml.includes('class="hidden sm:inline-flex text-slate-400 hover:text-white font-arcade text-xs min-w-[38px] min-h-[38px] px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 cursor-pointer items-center justify-center">✕</button>'), 'Flipbook modal missing desktop close button');
});

test('Flipbook modal footer clean Tailwind classes without malformed inline styles', () => {
    assert(!docsIndexHtml.includes('sm:flex-direction:row'), 'Malformed inline style sm:flex-direction:row must be removed');
});

// 7b. SIMPLECAT CLOSE BUTTON & ARCADE STYLING
test('SimpleCat dialog close button (#cat-close-btn) matches flipbook 38x38px arcade styling', () => {
    assert(docsCatJs.includes('id="cat-close-btn"'), 'Missing #cat-close-btn');
    assert(docsCatJs.includes('min-w-[38px] min-h-[38px]'), 'cat-close-btn must be 38x38px');
    assert(docsCatJs.includes('font-arcade text-xs'), 'cat-close-btn must use font-arcade text-xs');
});

// 7c. RETRO 16-BIT ORBITAL SPACE STATION DOCK
test('Space Station Dock (#space-station-pod) contains observation dome and solar wings', () => {
    assert(docsCatJs.includes('id="space-station-pod"'), 'Missing #space-station-pod');
    assert(docsCatJs.includes('getSpaceStationSVG'), 'Missing getSpaceStationSVG helper');
    assert(docsCatJs.includes('station-cat-pilot'), 'Missing station-cat-pilot in space station SVG');
    assert(docsCatJs.includes('solar-wing-left'), 'Missing solar wings in space station SVG');
    assert(docsCatJs.includes('station-beacon'), 'Missing antenna beacon in space station SVG');
});

// 7d. MOBILE TOUCHSCREEN ACTION DRAWER (>=44PX TOUCH TARGETS)
test('Mobile touchscreen action drawer (#station-touch-drawer) provides ergonomic >=44px touch targets', () => {
    assert(docsCatJs.includes('station-touch-drawer'), 'Missing #station-touch-drawer');
    assert(docsCatJs.includes('id="touch-launch-btn"'), 'Missing #touch-launch-btn');
    assert(docsCatJs.includes('id="touch-tour-btn"'), 'Missing #touch-tour-btn');
    assert(docsCatJs.includes('id="touch-treats-btn"'), 'Missing #touch-treats-btn');
    assert(docsCatJs.includes('id="touch-pet-btn"'), 'Missing #touch-pet-btn');
    assert(docsCatJs.includes('id="touch-patrol-btn"'), 'Missing #touch-patrol-btn');
    assert(docsCatJs.includes('id="touch-decode-btn"'), 'Missing #touch-decode-btn');
    assert(docsCatJs.includes('min-h-[46px]'), 'Touch drawer buttons must enforce ergonomic >=44px touch targets');
});

// 7e. ASTRO-CAT GUIDED SITE TOUR
test('Astro-Cat guided site tour (startTour) defined with 4 conversion landmarks and bubble controls', () => {
    assert(docsCatJs.includes('startSiteTour'), 'Missing startSiteTour');
    assert(docsCatJs.includes('TOUR_STEPS'), 'Missing TOUR_STEPS definition');
    assert(docsCatJs.includes('audit-terminal'), 'Tour must visit audit-terminal');
    assert(docsCatJs.includes('sentinels'), 'Tour must visit sentinels');
    assert(docsCatJs.includes('pricing'), 'Tour must visit pricing');
    assert(docsCatJs.includes('simple-cat'), 'Tour must visit simple-cat');
    assert(docsCatJs.includes('id="astro-tour-controls"'), 'Missing astro-tour-controls in speech bubble');
    assert(docsCatJs.includes('id="tour-next-btn"'), 'Missing tour-next-btn');
    assert(docsCatJs.includes('id="tour-exit-btn"'), 'Missing tour-exit-btn');
});

// 7f. COSMIC TREATS MINI-GAME & TOUCH-SCREEN PETTING
test('Cosmic treats mini-game (startTreats) enables tap-to-feed interaction with score tracking', () => {
    assert(docsCatJs.includes('startTreatsGame'), 'Missing startTreatsGame');
    assert(docsCatJs.includes('dropCosmicTreat'), 'Missing dropCosmicTreat');
    assert(docsCatJs.includes('showFloatingScore'), 'Missing showFloatingScore');
    assert(docsCatJs.includes('spawnHearts'), 'Missing spawnHearts');
    assert(docsCatJs.includes('petStationCat'), 'Missing petStationCat');
    assert(docsCatJs.includes('astro-cosmic-treat'), 'Missing astro-cosmic-treat styling');
    assert(docsCatJs.includes('astro-floating-score'), 'Missing astro-floating-score styling');
});

// 7g. PUBLIC API EXPORTS
test('SimpleCat public API exports startTour, startTreats, petStation, and getSpaceStationSVG', () => {
    assert(docsCatJs.includes('startTour: startSiteTour'), 'Missing startTour export');
    assert(docsCatJs.includes('startTreats: startTreatsGame'), 'Missing startTreats export');
    assert(docsCatJs.includes('petStation: petStationCat'), 'Missing petStation export');
    assert(docsCatJs.includes('getSpaceStationSVG: getSpaceStationSVG'), 'Missing getSpaceStationSVG export');
});

// 7h. SCREEN RECORDER FOR X TABS & SURFACE CONSTRAINTS
test('Screen recorder (startScreenRecording) includes preferCurrentTab and selfBrowserSurface: include for Chrome tabs', () => {
    assert(docsCatJs.includes('preferCurrentTab: true'), 'Missing preferCurrentTab in getDisplayMedia');
    assert(docsCatJs.includes('selfBrowserSurface: "include"'), 'Missing selfBrowserSurface in getDisplayMedia');
    assert(docsCatJs.includes('surfaceSwitching: "include"'), 'Missing surfaceSwitching in getDisplayMedia');
});

// 7i. MINI-GAME MUTUAL EXCLUSIVITY & ACTIVE CLASS HYGIENE
test('Mini-game mutual exclusivity: clearActiveGameModes cleanly strips active states and elements', () => {
    assert(docsCatJs.includes('clearActiveGameModes'), 'Missing clearActiveGameModes function');
    assert(docsCatJs.includes('clearActiveModes: clearActiveGameModes'), 'clearActiveModes must be exported in SimpleCat API');
    assert(docsCatJs.includes('laserHudBtn.classList.remove("astro-hud-btn-active")'), 'Laser button active state must be cleared');
    assert(docsCatJs.includes('treatsHudBtn.classList.remove("astro-hud-btn-active")'), 'Treats button active state must be cleared');
    assert(docsCatJs.includes('patrolHudBtn.classList.remove("astro-hud-btn-active")'), 'Patrol button active state must be cleared');
    assert(docsCatJs.includes('tourHudBtn.classList.remove("astro-hud-btn-active")'), 'Tour button active state must be cleared');
});

// 7j. DYNAMIC SPEECH BUBBLE TITLE RESOLUTION & STALE HEADER PREVENTION
test('Dynamic Speech Bubble Title Updates: showSpeechBubble assigns contextual titles to prevent stale headers', () => {
    assert(docsCatJs.includes('showSpeechBubble(text, duration = 7500, isTour = false, customTitle = null)'), 'showSpeechBubble must accept customTitle');
    assert(docsCatJs.includes('ASTRO-CAT // TREATS'), 'Treat mode must set title to ASTRO-CAT // TREATS');
    assert(docsCatJs.includes('ASTRO-CAT // THREAT PATROL'), 'Patrol mode must set title to ASTRO-CAT // THREAT PATROL');
    assert(docsCatJs.includes('ASTRO-CAT // LASER CHASE'), 'Laser mode must set title to ASTRO-CAT // LASER CHASE');
    assert(docsCatJs.includes('ASTRO-CAT // COMMS'), 'Default floating mode must set title to ASTRO-CAT // COMMS');
});

// 7k. VIEWPORT SAFE-BOUNDARY CLAMPING & TREAT CHOMP COLLISION
test('Viewport safe-boundary clamping for dropped treats and responsive chomp collision distance', () => {
    assert(docsCatJs.includes('const safeX = Math.max(50, Math.min(window.innerWidth - 70, x))'), 'Treats must be clamped to safe X viewport');
    assert(docsCatJs.includes('const safeY = Math.max(90, Math.min(window.innerHeight - 100, y))'), 'Treats must be clamped to safe Y viewport');
    assert(docsCatJs.includes('if (dist > 46)'), 'Treat chomp collision distance must be >= 46px');
    assert(docsCatJs.includes('minX = 15') && docsCatJs.includes('maxX = window.innerWidth - 85'), 'Universal screen edge bounce must clamp X');
    assert(docsCatJs.includes('minY = 65') && docsCatJs.includes('maxY = window.innerHeight - 95'), 'Universal screen edge bounce must clamp Y');
});

// 7l. COORDINATED HUD AND SPEECH BUBBLE OVERLAP PREVENTION
test('Coordinated HUD and Speech Bubble layout prevents occlusion in high viewport positions', () => {
    assert(docsCatJs.includes('forceHudAbove = (visualY > window.innerHeight - 130) || (bubbleVisible && visualY < bubbleH + 32)'), 'forceHudAbove must coordinate bubble and HUD geometry');
    assert(docsCatJs.includes('targetY = window.innerWidth > 640 ? 190 : 210'), 'Tour step targetY must provide >=190px top clearance');
});

// 7m. GLOBAL ASTRO-CAT DOCK PERSISTENCE ACROSS ALL PAGES
test('Space Station Dock & SimpleCat persistence across about.html and signup.html', () => {
    const aboutHtml = fs.readFileSync(path.join(__dirname, '..', 'docs', 'about.html'), 'utf8');
    const signupHtml = fs.readFileSync(path.join(__dirname, '..', 'docs', 'signup.html'), 'utf8');
    assert(aboutHtml.includes('assets/simple_cat.js'), 'docs/about.html must include assets/simple_cat.js');
    assert(signupHtml.includes('assets/simple_cat.js'), 'docs/signup.html must include assets/simple_cat.js');
});

// 8. STRICT 100% BYTE-FOR-BYTE SHA-256 PARITY BETWEEN DOCS/ AND LANDING/
test('docs/index.html and landing/index.html have 100% SHA-256 parity', () => {
    const hDocs = sha256(docsIndexPath);
    const hLanding = sha256(landingIndexPath);
    assert.strictEqual(hDocs, hLanding, `index.html drift: docs=${hDocs} landing=${hLanding}`);
});

test('docs/about.html and landing/about.html have 100% SHA-256 parity', () => {
    const hDocs = sha256(path.join(__dirname, '..', 'docs', 'about.html'));
    const hLanding = sha256(path.join(__dirname, '..', 'landing', 'about.html'));
    assert.strictEqual(hDocs, hLanding, `about.html drift: docs=${hDocs} landing=${hLanding}`);
});

test('docs/signup.html and landing/signup.html have 100% SHA-256 parity', () => {
    const hDocs = sha256(path.join(__dirname, '..', 'docs', 'signup.html'));
    const hLanding = sha256(path.join(__dirname, '..', 'landing', 'signup.html'));
    assert.strictEqual(hDocs, hLanding, `signup.html drift: docs=${hDocs} landing=${hLanding}`);
});

test('docs/assets/simple_cat.js and landing/assets/simple_cat.js have 100% SHA-256 parity', () => {
    const hDocs = sha256(docsCatPath);
    const hLanding = sha256(landingCatPath);
    assert.strictEqual(hDocs, hLanding, `simple_cat.js drift: docs=${hDocs} landing=${hLanding}`);
});

test('docs/assets/orbit_radar.js and landing/assets/orbit_radar.js have 100% SHA-256 parity', () => {
    const hDocs = sha256(docsRadarPath);
    const hLanding = sha256(landingRadarPath);
    assert.strictEqual(hDocs, hLanding, `orbit_radar.js drift: docs=${hDocs} landing=${hLanding}`);
});

console.log('========================================');
console.log(`ALL ${testCount}/${testCount} SIMPLECAT VISUAL & SCROLL TESTS PASSED!`);
console.log('========================================');
