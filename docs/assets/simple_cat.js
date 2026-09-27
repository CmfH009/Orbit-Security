/**
 * Simple Cat (simple_cat.js)
 * 16-Bit Retro Companion & Plain-English Decoder for Orbit Security
 * Created for Orbit Security (Founder: Carson Haynes @_arsoncode)
 */

(function () {
    // 1. Simple Cat Layman Definitions
    const DICTIONARY = {
        dmarc: {
            title: "DMARC (Email Anti-Spoofing)",
            tag: "THE BOUNCER",
            explanation: "Think of DMARC as a strict VIP bouncer. Without it, scammers can send fake phishing emails wearing your company's name tag and your clients will think it's really you. With 'p=reject', the bouncer tackles them at the door."
        },
        spf: {
            title: "SPF (Sender Policy Framework)",
            tag: "THE GUEST LIST",
            explanation: "A public VIP guest list for your mail servers. It tells Google and Outlook exactly which computers are allowed to send email for your domain. If someone's server isn't on the list, their email gets tossed into the spam dumpster."
        },
        cname: {
            title: "Dangling CNAME / Subdomain Takeover",
            tag: "THE ABANDONED LOCKER",
            explanation: "Imagine you moved out of an old apartment, but left your mailbox forwarding to that address. A bad guy moves in, claims that mailbox, and starts reading all your letters. That's a dangling CNAME takeover—and it takes an attacker 30 seconds to pull off."
        },
        hsts: {
            title: "HSTS (HTTPS Strict Transport Security)",
            tag: "THE ARMORED TRUCK",
            explanation: "Forces your browser to only travel in armored, encrypted HTTPS trucks. It bans old unencrypted HTTP completely so shady coffee shop WiFi hackers can't peek into your client's passwords or cookies."
        },
        doh: {
            title: "DNS-over-HTTPS (DoH)",
            tag: "THE SECRET ENVELOPE",
            explanation: "Instead of shouting 'Hey, what is the IP address for google.com?' across a crowded room, DoH seals your address lookup in an encrypted envelope. Orbit runs this 100% inside your browser with zero server logging."
        },
        csp: {
            title: "Content Security Policy (CSP)",
            tag: "THE PARTY SECURITY",
            explanation: "Strict house rules for your website. It tells the browser: 'Only load scripts from people we personally invited.' This stops sneaky hackers from injecting malicious scripts or fake checkout buttons into your pages."
        },
        drift: {
            title: "Perimeter & DNS Drift",
            tag: "THE FORGOTTEN PROMO",
            explanation: "That marketing subdomain your team spun up two Black Fridays ago for a seasonal landing page and then forgot about. Over time, settings rot, subscriptions lapse, and the perimeter 'drifts' into danger."
        },
        bimi: {
            title: "BIMI (Brand Logo Trust)",
            tag: "THE VERIFIED CHECKMARK",
            explanation: "Puts your verified company logo right next to your emails in Gmail and Apple Mail inboxes. It proves to customers that your email is 100% genuine before they even open it."
        },
        mta_sts: {
            title: "MTA-STS (Encrypted Mail Route)",
            tag: "THE TUNNEL SHIELD",
            explanation: "Guarantees that when other mail servers talk to your mail servers, the tunnel between them is encrypted with modern TLS. Prevents wiretapping between email providers."
        },
        headers: {
            title: "OWASP Security Headers",
            tag: "THE DIGITAL DEADBOLTS",
            explanation: "Invisible security instructions your web server sends with every webpage. They lock down iframes (preventing clickjacking), stop MIME confusion attacks, and tell browsers how to behave safely."
        }
    };

    // 2. Retro 8-Bit Web Audio Synthesizer
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
            // Audio not supported or blocked
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

    // 3. Pixel Cat SVG Generator
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

    // 4. Modal and Dialogue UI
    function showSimpleCatDialog(termKey, triggerElement = null) {
        playChirp();
        const data = DICTIONARY[termKey.toLowerCase()] || {
            title: termKey.toUpperCase(),
            tag: "SECURITY CONCEPT",
            explanation: "Simple Cat is still analyzing this perimeter metric. Stay tuned!"
        };

        let modal = document.getElementById("simple-cat-modal");
        if (!modal) {
            modal = document.createElement("div");
            modal.id = "simple-cat-modal";
            modal.className = "fixed inset-0 z-[100] bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 transition-all duration-200";
            modal.innerHTML = `
                <div class="relative bg-slate-900 border-2 border-emerald-500 max-w-lg w-full p-6 shadow-[0_0_40px_rgba(16,185,129,0.3)] rounded-xl" style="box-shadow: 6px 6px 0px #064e3b;">
                    <!-- Close button -->
                    <button id="cat-close-btn" class="absolute top-3 right-3 text-slate-400 hover:text-emerald-400 font-mono text-xl px-2 py-0.5 border border-slate-700 hover:border-emerald-500 rounded bg-slate-950">✕</button>
                    
                    <!-- Header with pixel cat -->
                    <div class="flex items-center gap-4 mb-4 pb-3 border-b border-slate-800">
                        <div id="cat-avatar-box" class="p-2 bg-slate-950 border border-emerald-500/40 rounded-lg animate-bounce" style="animation-duration: 2s;">
                            ${getPixelCatSVG(48)}
                        </div>
                        <div>
                            <div class="inline-flex items-center gap-2 px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px] uppercase font-bold tracking-wider mb-1">
                                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                <span id="cat-badge-tag">SIMPLE CAT // LEVEL 99 GUIDE</span>
                            </div>
                            <h3 id="cat-dialog-title" class="text-lg font-extrabold text-white font-mono tracking-tight">Security Term</h3>
                        </div>
                    </div>

                    <!-- Explanation Bubble -->
                    <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 mb-4 relative">
                        <div class="text-xs font-mono text-emerald-400 uppercase tracking-widest mb-1.5 flex items-center gap-1.5">
                            <span>🐱 Simple Cat's Layman Translation:</span>
                        </div>
                        <p id="cat-dialog-text" class="text-sm text-slate-200 leading-relaxed font-sans"></p>
                    </div>

                    <!-- Footer Controls -->
                    <div class="flex items-center justify-between text-xs font-mono text-slate-400">
                        <span class="text-[11px] text-slate-500">"Security so simple your non-tech clients get it."</span>
                        <button id="cat-got-it-btn" class="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded text-xs transition-all shadow-[0_0_15px_rgba(16,185,129,0.3)]">
                            Got it! (Close)
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);

            document.getElementById("cat-close-btn").addEventListener("click", () => {
                modal.classList.add("hidden");
                playBlip();
            });
            document.getElementById("cat-got-it-btn").addEventListener("click", () => {
                modal.classList.add("hidden");
                playBlip();
            });
            modal.addEventListener("click", (e) => {
                if (e.target === modal) {
                    modal.classList.add("hidden");
                    playBlip();
                }
            });
        }

        document.getElementById("cat-badge-tag").innerText = `SIMPLE CAT // ${data.tag}`;
        document.getElementById("cat-dialog-title").innerText = data.title;
        document.getElementById("cat-dialog-text").innerText = data.explanation;
        modal.classList.remove("hidden");
    }

    // 5. Build Floating Simple Cat Widget
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

    // 6. Audio Toggle Button
    function createSoundToggle() {
        if (document.getElementById("audio-toggle-btn")) return;
        const btn = document.createElement("button");
        btn.id = "audio-toggle-btn";
        btn.className = "text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-emerald-400 hover:border-emerald-500/40 transition-colors flex items-center gap-1.5";
        btn.innerHTML = `<span>🔊</span> <span>AUDIO: ON</span>`;
        btn.addEventListener("click", () => {
            soundEnabled = !soundEnabled;
            btn.innerHTML = soundEnabled ? `<span>🔊</span> <span>AUDIO: ON</span>` : `<span>🔇</span> <span>AUDIO: OFF</span>`;
            if (soundEnabled) playBlip();
        });

        const navRight = document.querySelector("header .max-w-7xl > div:last-child");
        if (navRight) {
            navRight.prepend(btn);
        }
    }

    // 7. Auto-Bind All Plain-English Chips
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
                showSimpleCatDialog(el.dataset.catTerm, el);
            });
        });
    }

    // Expose Global Helper
    window.SimpleCat = {
        explain: showSimpleCatDialog,
        playBlip,
        playChirp,
        playPowerUp,
        getPixelCatSVG,
        bindHelperChips
    };

    // Initialize on DOM Ready
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => {
            createFloatingWidget();
            createSoundToggle();
            bindHelperChips();
        });
    } else {
        createFloatingWidget();
        createSoundToggle();
        bindHelperChips();
    }
})();
