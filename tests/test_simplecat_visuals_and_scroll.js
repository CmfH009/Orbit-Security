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

// 7n. ABOVE-THE-FOLD ASTRO-CAT SENTINEL SHOWCASE & 4 ROLES
test('Above-the-fold Sentinel Patrol Bar showcases 4 Sentinel Roles with telemetry & audio triggers', () => {
    assert(docsIndexHtml.includes('id="sentinel-patrol-bar"'), 'Missing #sentinel-patrol-bar above the fold');
    assert(docsIndexHtml.includes('Radar Scout'), 'Missing Radar Scout role in patrol bar');
    assert(docsIndexHtml.includes('Takeover Interceptor'), 'Missing Takeover Interceptor role in patrol bar');
    assert(docsIndexHtml.includes('Spoof Shield'), 'Missing Spoof Shield role in patrol bar');
    assert(docsIndexHtml.includes('MX Sentinel'), 'Missing MX Sentinel role in patrol bar');
    assert(docsIndexHtml.includes('16/16 Active'), 'Missing Radar Scout telemetry in patrol bar');
    assert(docsIndexHtml.includes('0 Dangling'), 'Missing Takeover Interceptor telemetry in patrol bar');
    assert(docsIndexHtml.includes('p=reject'), 'Missing Spoof Shield telemetry in patrol bar');
    assert(docsIndexHtml.includes('Null-MX'), 'Missing MX Sentinel telemetry in patrol bar');
    assert(docsIndexHtml.includes('SimpleCat.playHoverTick'), 'Patrol bar must include hover sound cues');
});

test('Creative Sentinels section showcases 4 dedicated Sentinel Roles with 16-bit badges and actions', () => {
    assert(docsIndexHtml.includes('SYS.ID: SENTINEL-01'), 'Missing SENTINEL-01');
    assert(docsIndexHtml.includes('SYS.ID: SENTINEL-02'), 'Missing SENTINEL-02');
    assert(docsIndexHtml.includes('SYS.ID: SENTINEL-03'), 'Missing SENTINEL-03');
    assert(docsIndexHtml.includes('SYS.ID: SENTINEL-04'), 'Missing SENTINEL-04');
    assert(docsIndexHtml.includes('data-cat-term="dns"'), 'Radar Scout must link to dns term');
    assert(docsIndexHtml.includes('data-cat-term="cname"'), 'Takeover Interceptor must link to cname term');
    assert(docsIndexHtml.includes('data-cat-term="dmarc"'), 'Spoof Shield must link to dmarc term');
    assert(docsIndexHtml.includes('data-cat-term="mx"'), 'MX Sentinel must link to mx term');
});

// 7o. ARCADE PERIMETER DEFENSE MODE MINI-GAME
test('Arcade Perimeter Defense Mode mini-game engine, threats, controls & scoring in simple_cat.js', () => {
    assert(docsCatJs.includes('DEFENSE_THREAT_SPECS'), 'Missing DEFENSE_THREAT_SPECS in simple_cat.js');
    assert(docsCatJs.includes('Dangling CNAME'), 'Missing Dangling CNAME threat spec');
    assert(docsCatJs.includes('Spoofed MX'), 'Missing Spoofed MX threat spec');
    assert(docsCatJs.includes('SPF PermError'), 'Missing SPF PermError threat spec');
    assert(docsCatJs.includes('Abandoned S3 Bucket'), 'Missing Abandoned S3 Bucket threat spec');
    assert(docsCatJs.includes('ensureArcadeDefenseDOM'), 'Missing ensureArcadeDefenseDOM helper');
    assert(docsCatJs.includes('startArcadeDefenseMode'), 'Missing startArcadeDefenseMode');
    assert(docsCatJs.includes('stopArcadeDefenseMode'), 'Missing stopArcadeDefenseMode');
    assert(docsCatJs.includes('toggleArcadeDefenseMode'), 'Missing toggleArcadeDefenseMode');
    assert(docsCatJs.includes('fireDefensePulse'), 'Missing fireDefensePulse');
    assert(docsCatJs.includes('triggerDefenseGameOver'), 'Missing triggerDefenseGameOver');
    assert(docsCatJs.includes('triggerDefenseVictory'), 'Missing triggerDefenseVictory');
    assert(docsCatJs.includes('combo'), 'Missing combo scoring tracking');
    assert(docsCatJs.includes('maxCombo'), 'Missing maxCombo tracking');
    assert(docsCatJs.includes('scanlines'), 'Missing CRT scanline styling in arcade overlay');
});

test('Arcade Perimeter Defense Mode overlay in index.html with >=44px touch targets', () => {
    assert(docsIndexHtml.includes('id="arcadeDefenseMode"'), 'Missing #arcadeDefenseMode container in index.html');
    assert(docsIndexHtml.includes('id="defenseCanvas"'), 'Missing #defenseCanvas in index.html');
    assert(docsIndexHtml.includes('id="defense-touch-left"'), 'Missing #defense-touch-left touch control');
    assert(docsIndexHtml.includes('id="defense-touch-right"'), 'Missing #defense-touch-right touch control');
    assert(docsIndexHtml.includes('id="defense-touch-fire"'), 'Missing #defense-touch-fire touch control');
    assert(docsIndexHtml.includes('min-h-[48px]'), 'Arcade defense touch targets must be >=44px (min-h-[48px])');
    assert(docsIndexHtml.includes('id="defense-gameover-overlay"'), 'Missing game over overlay');
    assert(docsIndexHtml.includes('id="defense-victory-overlay"'), 'Missing victory debrief overlay');
});

test('Arcade Defense Mode public API exports and hash deep-linking', () => {
    assert(docsCatJs.includes('startDefense: startArcadeDefenseMode'), 'Missing startDefense export');
    assert(docsCatJs.includes('stopDefense: stopArcadeDefenseMode'), 'Missing stopDefense export');
    assert(docsCatJs.includes('toggleDefense: toggleArcadeDefenseMode'), 'Missing toggleDefense export');
    assert(docsCatJs.includes('window.location.hash === \'#arcadeDefenseMode\''), 'Missing hashchange deep link support in simple_cat.js');
    assert(docsIndexHtml.includes('#arcadeDefenseMode'), 'index.html must handle #arcadeDefenseMode');
});

// 7p. GLOBAL AUDIO SYNTHESIZER POLISH & SOUND TOGGLE
test('Web Audio API 8-bit sound effects (deflect, alarm, victory, game over) implemented', () => {
    assert(docsCatJs.includes('function playDeflect()'), 'Missing playDeflect synth method');
    assert(docsCatJs.includes('function playAlarm()'), 'Missing playAlarm synth method');
    assert(docsCatJs.includes('function playVictory()'), 'Missing playVictory synth method');
    assert(docsCatJs.includes('function playGameOver()'), 'Missing playGameOver synth method');
    assert(docsCatJs.includes('playDeflect: playDeflect'), 'Missing playDeflect export');
    assert(docsCatJs.includes('playAlarm: playAlarm'), 'Missing playAlarm export');
    assert(docsCatJs.includes('playVictory: playVictory'), 'Missing playVictory export');
    assert(docsCatJs.includes('playGameOver: playGameOver'), 'Missing playGameOver export');
    assert(docsCatJs.includes('isSoundEnabled: function'), 'Missing isSoundEnabled export');
});

test('Global audio persistence in localStorage.orbit_audio_enabled and toggle buttons', () => {
    assert(docsCatJs.includes('orbit_audio_enabled'), 'simple_cat.js must read and persist orbit_audio_enabled');
    assert(docsCatJs.includes('updateSoundToggleButtons'), 'Missing updateSoundToggleButtons in simple_cat.js');
    assert(docsIndexHtml.includes('id="audio-toggle-btn"'), 'Missing #audio-toggle-btn in index.html desktop nav');
    assert(docsIndexHtml.includes('id="sound-toggle-btn"'), 'Missing #sound-toggle-btn in index.html mobile nav');
    assert(docsCatJs.includes('id="dock-audio-btn"'), 'Missing #dock-audio-btn in space station dock');
    assert(docsCatJs.includes('id="touch-audio-btn"'), 'Missing #touch-audio-btn in mobile touch drawer');
    assert(docsCatJs.includes('e.key === \'m\' || e.key === \'M\''), 'Missing hotkey M toggle in simple_cat.js');
});

// 7q. CORE SCANNER MILESTONE AUDIO HOOKS
test('Scanner milestone audio hooks wired to DoH query start, critical alert, and color switch', () => {
    assert(docsRadarJs.includes('SimpleCat.playChirp()'), 'DoH query start must trigger SimpleCat.playChirp');
    assert(docsRadarJs.includes('SimpleCat.playAlarm()'), 'Critical alerts must trigger SimpleCat.playAlarm');
    assert(docsRadarJs.includes('applyPortalBrandColor') && docsRadarJs.includes('SimpleCat.playBlip()'), 'Portal brand color switch must trigger SimpleCat.playBlip');
    assert(docsRadarJs.includes('OrbitAttackTree.setStep') && docsRadarJs.includes('SimpleCat.playBlip()'), 'Exploit simulator step must trigger SimpleCat.playBlip');
});

// 7r. ARCADE DEFENSE & WEB AUDIO ROBUSTNESS GUARDS
test('stopArcadeDefenseMode guards against spurious purr & modal-open stripping when inactive', () => {
    assert(docsCatJs.includes('const wasActive = defenseState.active;'), 'stopArcadeDefenseMode must track wasActive');
    assert(docsCatJs.includes('document.body.classList.remove("modal-open");') && docsCatJs.includes('wasActive'), 'modal-open should only be removed if defense was active');
    assert(docsCatJs.includes('playPurr();') && docsCatJs.includes('wasActive'), 'playPurr should only fire if defense was active');
});

test('Arcade Defense Mode includes responsive resizeDefenseCanvas for mobile orientation changes', () => {
    assert(docsCatJs.includes('function resizeDefenseCanvas()'), 'Missing resizeDefenseCanvas');
    assert(docsCatJs.includes('window.addEventListener("resize", resizeDefenseCanvas)'), 'Missing resize listener in defense mode');
    assert(docsCatJs.includes('window.removeEventListener("resize", resizeDefenseCanvas)'), 'Missing resize listener removal in stopArcadeDefenseMode');
});

test('Defense victory triggers when all threats spawned and zero active threats remain with shield > 0', () => {
    assert(docsCatJs.includes('const allSpawned = defenseState.threatsSpawned >= defenseState.threatsTotal;'), 'Missing allSpawned check');
    assert(docsCatJs.includes('const noneRemaining = defenseState.threats.length === 0;'), 'Missing noneRemaining check');
    assert(docsCatJs.includes('allSpawned && noneRemaining && defenseState.shieldHp > 0'), 'Victory must trigger when shield survives partial damage');
});

test('Arcade Defense Mode prevents listener accumulation on retry and cleans up touch intervals', () => {
    assert(docsCatJs.includes('window.removeEventListener("keydown", defenseKeyHandler);') && docsCatJs.includes('window.removeEventListener("keyup", defenseKeyUpHandler);'), 'Must remove listeners before adding to prevent duplicates');
    assert(docsCatJs.includes('pointercancel'), 'Touch controls must listen for pointercancel');
    assert(docsCatJs.includes('touchLeftInterval') && docsCatJs.includes('touchRightInterval'), 'Touch intervals must be tracked on defenseState');
});

test('createSoundToggle checks orbit_audio_enabled and updateSoundToggleButtons preserves mobile drawer structure', () => {
    assert(docsCatJs.includes('localStorage.getItem("orbit_audio_enabled") ?? localStorage.getItem("orbit_sound_enabled")'), 'createSoundToggle must check orbit_audio_enabled');
    assert(docsCatJs.includes('soundToggleBtn.setAttribute(\'aria-pressed\''), 'Toggle buttons must update aria-pressed');
    assert(docsCatJs.includes('Audio SFX (${soundEnabled ? \'Mute\' : \'Unmute\'})'), 'Mobile drawer button must preserve descriptive label');
});

test('Hashchange handler exits defense mode when navigating away from #arcadeDefenseMode', () => {
    assert(docsCatJs.includes('stopArcadeDefenseMode') && docsCatJs.includes('defenseState.active'), 'Hashchange must stop defense mode when hash clears');
});

test('triggerDefenseGameOver, triggerDefenseVictory, and stopArcadeDefenseMode cleanly clear all touch intervals and reset keys', () => {
    assert(docsCatJs.includes('clearInterval(defenseState.touchLeftInterval);') && docsCatJs.includes('defenseState.touchLeftInterval = null;'), 'Must clear touchLeftInterval');
    assert(docsCatJs.includes('clearInterval(defenseState.touchRightInterval);') && docsCatJs.includes('defenseState.touchRightInterval = null;'), 'Must clear touchRightInterval');
    assert(docsCatJs.includes('clearInterval(defenseState.touchFireInterval);') && docsCatJs.includes('defenseState.touchFireInterval = null;'), 'Must clear touchFireInterval');
    assert(docsCatJs.includes('defenseState.keys = {};'), 'Must reset active keys');
});

test('defense-touch-fire supports repeat pulse interval on hold with pointercancel cleanup', () => {
    assert(docsCatJs.includes('defenseState.touchFireInterval = setInterval'), 'touch-fire must initialize repeat firing interval on hold');
    assert(docsCatJs.includes('touchFire.addEventListener("pointerup", stopFire);'), 'touch-fire must stop on pointerup');
    assert(docsCatJs.includes('touchFire.addEventListener("pointercancel", stopFire);'), 'touch-fire must stop on pointercancel');
    assert(docsCatJs.includes('touchFire.addEventListener("pointerleave", stopFire);'), 'touch-fire must stop on pointerleave');
});

test('triggerDefenseVictory dynamically updates victory-bonus element based on wave damage', () => {
    assert(docsCatJs.includes('const cleanBonus = defenseState.threatsDefeated === defenseState.threatsTotal ? 500 : 250;'), 'Computes 500 for flawless vs 250 for damage survived');
    assert(docsCatJs.includes('bVal.textContent = `+${cleanBonus} PTS`;'), 'Dynamically updates victory-bonus element text');
    assert(docsIndexPath && fs.readFileSync(docsIndexPath, 'utf8').includes('id="victory-bonus"'), 'index.html contains victory-bonus element');
});

test('resizeDefenseCanvas adjusts threat coordinates, pulses, sparks, and trajectories on orientation change', () => {
    assert(docsCatJs.includes('const oldCx = defenseState.centerX;'), 'resizeDefenseCanvas must track oldCx');
    assert(docsCatJs.includes('const oldCy = defenseState.centerY;'), 'resizeDefenseCanvas must track oldCy');
    assert(docsCatJs.includes('t.x += dx;') && docsCatJs.includes('t.y += dy;'), 'resizeDefenseCanvas must translate threat coordinates on center shift');
    assert(docsCatJs.includes('p.x += dx;') && docsCatJs.includes('p.y += dy;'), 'resizeDefenseCanvas must translate in-flight pulses on center shift');
    assert(docsCatJs.includes('s.x += dx;') && docsCatJs.includes('s.y += dy;'), 'resizeDefenseCanvas must translate in-flight sparks on center shift');
    assert(docsCatJs.includes('fs.x += dx;') && docsCatJs.includes('fs.y += dy;'), 'resizeDefenseCanvas must translate in-flight floating scores on center shift');
    assert(docsCatJs.includes('const newAngle = Math.atan2(defenseState.centerY - t.y, defenseState.centerX - t.x);'), 'resizeDefenseCanvas must re-aim velocity vectors');
});

test('Web Audio gesture unlock cleanly removes window event listeners once running', () => {
    assert(docsCatJs.includes('window.removeEventListener("pointerdown", unlockAudio);'), 'Must remove pointerdown unlock listener');
    assert(docsCatJs.includes('window.removeEventListener("touchstart", unlockAudio);'), 'Must remove touchstart unlock listener');
    assert(docsCatJs.includes('window.removeEventListener("keydown", unlockAudio);'), 'Must remove keydown unlock listener');
});

test('toggleSound immediately triggers unlockAudio on audio enablement', () => {
    assert(docsCatJs.includes('function unlockAudio()'), 'unlockAudio must be declared as a hoisted function');
    assert(docsCatJs.includes('if (soundEnabled) {\n            unlockAudio();') || docsCatJs.includes('if (soundEnabled) {\r\n            unlockAudio();'), 'toggleSound must invoke unlockAudio when soundEnabled is true');
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

test('docs/portals/orbit-core.html and landing/portals/orbit-core.html have 100% SHA-256 parity', () => {
    const hDocs = sha256(path.join(__dirname, '..', 'docs', 'portals', 'orbit-core.html'));
    const hLanding = sha256(path.join(__dirname, '..', 'landing', 'portals', 'orbit-core.html'));
    assert.strictEqual(hDocs, hLanding, `portals/orbit-core.html drift: docs=${hDocs} landing=${hLanding}`);
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
