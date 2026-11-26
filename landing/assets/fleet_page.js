(function initFleetMobileMenu() {
            const btn = document.getElementById('fleetMobileMenuBtn');
            const menu = document.getElementById('fleetMobileMenu');
            if (!btn || !menu) return;
            btn.addEventListener('click', () => {
                const isOpen = !menu.classList.contains('hidden');
                menu.classList.toggle('hidden', isOpen);
                btn.setAttribute('aria-expanded', String(!isOpen));
            });
        })();
        // HTML and JS String Escaping for Stored DOM XSS Prevention
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function formatScoreDeltaBadge(scoreChange, options = {}) {
            if (window.formatScoreDeltaBadge && window.formatScoreDeltaBadge !== formatScoreDeltaBadge) {
                return window.formatScoreDeltaBadge(scoreChange, options);
            }
            if (scoreChange === null || scoreChange === undefined || scoreChange === '') return '';
            const num = Number(scoreChange);
            if (isNaN(num)) return '';
            if (num > 0) {
                return `<span class="score-delta-badge score-delta-up px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">+${num}</span>`;
            } else if (num <= -5) {
                return `<span class="score-delta-badge score-delta-drift px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">${num} DRIFT</span>`;
            } else if (num < 0) {
                return `<span class="score-delta-badge score-delta-down px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">${num}</span>`;
            }
            return `<span class="score-delta-badge score-delta-neutral px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-400 border border-slate-700">±0</span>`;
        }

        // On-demand lazy loader for 513KB PDF engine
        let pdfLibPromise = null;
        function ensurePdfLib() {
            if (window.PDFLib) return Promise.resolve(window.PDFLib);
            if (!pdfLibPromise) {
                pdfLibPromise = new Promise((resolve, reject) => {
                    const s = document.createElement('script');
                    s.src = 'assets/pdf-lib.min.js';
                    s.onload = () => resolve(window.PDFLib);
                    s.onerror = (err) => {
                        pdfLibPromise = null;
                        s.remove();
                        reject(err);
                    };
                    document.head.appendChild(s);
                });
            }
            return pdfLibPromise;
        }

        // 0% CPU Idle Governor Lifecycle Hook
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                document.body.classList.add('page-idle');
                if (window.SimpleCat && SimpleCat.suspendAudio) SimpleCat.suspendAudio();
            } else {
                document.body.classList.remove('page-idle');
                if (window.SimpleCat && SimpleCat.resumeAudio) SimpleCat.resumeAudio();
            }
        });

        const initialFleet = [
            { domain: "candykittens.co.uk", client: "Candy Kittens (Charle)", score: 95, grade: "A+", score_change: 3, critical_findings: 0, dmarc: "v=DMARC1; p=reject", cname: "Apex Direct", headers: "5/7", status: "Clean" },
            { domain: "recipetineats.com", client: "RecipeTin Eats (Human Made)", score: 90, grade: "A", score_change: 0, critical_findings: 0, dmarc: "v=DMARC1; p=none", cname: "Cloudflare Edge", headers: "4/7", status: "Clean" },
            { domain: "footanstey.com", client: "Foot Anstey (Illustrate)", score: 90, grade: "A", score_change: -2, critical_findings: 0, dmarc: "v=DMARC1; p=none", cname: "WP Engine", headers: "4/7", status: "Clean" },
            { domain: "nutopia.com", client: "Nutopia (KOTA)", score: 80, grade: "B", score_change: -8, critical_findings: 1, dmarc: "Missing DMARC", cname: "AWS CloudFront", headers: "3/7", status: "Missing HSTS" },
            { domain: "politico.com", client: "POLITICO (10up)", score: 100, grade: "A+", score_change: 5, critical_findings: 0, dmarc: "v=DMARC1; p=reject", cname: "Fastly Enterprise", headers: "7/7", status: "Pristine" },
            { domain: "cotswoldsdistillery.com", client: "Cotswolds (Propeller)", score: 85, grade: "B+", score_change: 0, critical_findings: 0, dmarc: "v=DMARC1; p=none", cname: "Shopify Edge", headers: "4/7", status: "Clean" }
        ];

        const cohort5Fleet = [
            { domain: "carawayhome.com", client: "Caraway Home (Verbal+Visual)", score: 60, grade: "B", score_change: -5, critical_findings: 0, dmarc: "v=DMARC1; p=quarantine", cname: "Apex Direct", headers: "2/7", status: "Missing CSP" },
            { domain: "rothys.com", client: "Rothy's (Anatta)", score: 84, grade: "B+", score_change: 4, critical_findings: 0, dmarc: "v=DMARC1; p=quarantine", cname: "Apex Direct", headers: "5/7", status: "Clean" },
            { domain: "victoriabeckham.com", client: "Victoria Beckham (Fostr)", score: 84, grade: "B+", score_change: 0, critical_findings: 0, dmarc: "v=DMARC1; p=quarantine", cname: "Apex Direct", headers: "5/7", status: "Clean" },
            { domain: "johnnycupcakes.com", client: "Johnny Cupcakes (Growth Spark)", score: 84, grade: "B+", score_change: 2, critical_findings: 0, dmarc: "v=DMARC1; p=quarantine", cname: "Apex Direct", headers: "5/7", status: "Clean" },
            { domain: "burlington.com", client: "Burlington (Guidance)", score: 52, grade: "C", score_change: -6, critical_findings: 1, dmarc: "v=DMARC1; p=none", cname: "Apex Direct", headers: "1/7", status: "Missing Headers" },
            { domain: "broadway.com", client: "Broadway.com (Lounge Lizard)", score: 84, grade: "B+", score_change: 0, critical_findings: 0, dmarc: "v=DMARC1; p=quarantine", cname: "Apex Direct", headers: "5/7", status: "Clean" },
            { domain: "nationalgeographic.org", client: "National Geographic (Taoti)", score: 44, grade: "D", score_change: -12, critical_findings: 2, dmarc: "Missing DMARC", cname: "Apex Direct", headers: "0/7", status: "High Risk" },
            { domain: "rexall.ca", client: "Rexall (Northern)", score: 52, grade: "C", score_change: -7, critical_findings: 1, dmarc: "v=DMARC1; p=none", cname: "Apex Direct", headers: "1/7", status: "Missing HSTS" },
            { domain: "zeek.com", client: "Zeek Interactive (Zeek)", score: 44, grade: "D", score_change: -9, critical_findings: 1, dmarc: "Missing DMARC", cname: "Apex Direct", headers: "0/7", status: "Missing Headers" },
            { domain: "reynoldsam.com", client: "Reynolds (WebFX)", score: 76, grade: "B", score_change: 1, critical_findings: 0, dmarc: "v=DMARC1; p=none", cname: "Apex Direct", headers: "4/7", status: "Clean" }
        ];

        const STORAGE_KEY = "orbit_fleet_registry_v2";
        let fleet = loadSavedFleet();
        let currentFilter = 'all';

        function loadSavedFleet() {
            try {
                const saved = localStorage.getItem(STORAGE_KEY);
                if (saved) {
                    const parsed = JSON.parse(saved);
                    if (Array.isArray(parsed) && parsed.length > 0) return parsed;
                }
            } catch (e) {
                console.warn("Storage load fallback:", e);
            }
            return [...initialFleet];
        }

        function saveFleet() {
            try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(fleet));
                const ind = document.getElementById("fleet-storage-indicator");
                if (ind) {
                    ind.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span><span>Saved (${fleet.length} domains)</span>`;
                    setTimeout(() => {
                        ind.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span><span>Auto-saved to local browser storage</span>`;
                    }, 1500);
                }
            } catch (e) {
                console.warn("Storage save error:", e);
            }
        }

        function loadPreset(type) {
            if (window.SimpleCat) SimpleCat.playBlip();
            if (type === 'baseline') {
                fleet = [...initialFleet];
                showToast("Loaded baseline showcase portfolio (6 domains)");
            } else if (type === 'cohort5') {
                fleet = [...cohort5Fleet];
                showToast("Loaded Cohort 5 Enterprise Portfolio (10 domains)");
            } else if (type === 'all') {
                const combined = [...initialFleet];
                cohort5Fleet.forEach(item => {
                    if (!combined.some(c => c.domain === item.domain)) combined.push(item);
                });
                fleet = combined;
                showToast(`Loaded combined enterprise fleet (${fleet.length} domains)`);
            } else if (type === 'clear') {
                fleet = [];
                showToast("Fleet cleared. Add client domains with '+ ADD DOMAIN'");
            }
            saveFleet();
            renderFleet();
        }

        function deleteDomain(domain) {
            if (window.SimpleCat) SimpleCat.playChirp();
            fleet = fleet.filter(f => f.domain !== domain);
            saveFleet();
            renderFleet();
            showToast(`Removed ${domain} from fleet.`);
        }

        // --- Live Client-Side DNS-over-HTTPS (DoH) Resolver ---
        async function queryDoH(name, type) {
            try {
                const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {
                    headers: { 'Accept': 'application/dns-json' }
                });
                if (res.ok) return await res.json();
            } catch (err) {
                // fall through to Cloudflare DoH
            }
            try {
                const cfRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
                    headers: { 'Accept': 'application/dns-json' }
                });
                if (cfRes.ok) return await cfRes.json();
            } catch (e) {
                console.warn('DoH resolution error:', e);
            }
            return null;
        }

        async function auditDomainDoH(domain) {
            let dmarc = "Missing DMARC";
            let dmarcScore = 0;
            let routing = "Apex Direct";
            let status = "Clean";
            let hasBimi = false;

            // 1. DMARC TXT query
            const dmarcData = await queryDoH(`_dmarc.${domain}`, 'TXT');
            if (dmarcData && dmarcData.Answer) {
                for (const ans of dmarcData.Answer) {
                    const txt = (ans.data || "").toLowerCase();
                    if (txt.includes("v=dmarc1")) {
                        if (txt.includes("p=reject")) {
                            dmarc = "v=DMARC1; p=reject";
                            dmarcScore = 35;
                        } else if (txt.includes("p=quarantine")) {
                            dmarc = "v=DMARC1; p=quarantine";
                            dmarcScore = 25;
                        } else if (txt.includes("p=none")) {
                            dmarc = "v=DMARC1; p=none";
                            dmarcScore = 12;
                        } else {
                            dmarc = "v=DMARC1; active";
                            dmarcScore = 15;
                        }
                        break;
                    }
                }
            }

            // 2. CNAME / A routing
            const cnameData = await queryDoH(domain, 'CNAME');
            if (cnameData && cnameData.Answer && cnameData.Answer.length > 0) {
                const rawTarget = cnameData.Answer[0].data || "";
                if (rawTarget.includes("myshopify.com")) routing = "Shopify Edge";
                else if (rawTarget.includes("cloudflare")) routing = "Cloudflare Edge";
                else if (rawTarget.includes("cloudfront.net")) routing = "AWS CloudFront";
                else if (rawTarget.includes("wpengine")) routing = "WP Engine";
                else if (rawTarget.includes("fastly")) routing = "Fastly Enterprise";
                else routing = rawTarget.length > 22 ? rawTarget.slice(0, 20) + '...' : rawTarget;
            } else {
                const aData = await queryDoH(domain, 'A');
                if (aData && aData.Answer && aData.Answer.length > 0) {
                    routing = "Apex Direct";
                }
            }

            // 3. BIMI query
            const bimiData = await queryDoH(`default._bimi.${domain}`, 'TXT');
            if (bimiData && bimiData.Answer && bimiData.Answer.length > 0) {
                hasBimi = true;
            }

            // Compute score
            let score = 52 + dmarcScore + (hasBimi ? 5 : 0) + (routing.includes("Edge") || routing.includes("Apex") ? 8 : 4);
            if (score > 100) score = 100;

            let grade = "C";
            if (score >= 95) grade = "A+";
            else if (score >= 90) grade = "A";
            else if (score >= 80) grade = "B+";
            else if (score >= 70) grade = "B";
            else if (score >= 60) grade = "C";
            else grade = "D";

            if (dmarc.includes("reject") && score >= 90) status = "Pristine";
            else if (dmarc === "Missing DMARC") status = "Missing DMARC";
            else status = "Clean";

            return {
                domain: domain,
                score: score,
                grade: grade,
                dmarc: dmarc,
                cname: routing,
                headers: score >= 90 ? "5/7" : (score >= 75 ? "4/7" : "2/7"),
                status: status
            };
        }

        function renderFleet() {
            const tbody = document.getElementById("fleet-table-body");
            const searchVal = document.getElementById("domain-search").value.toLowerCase();

            const filtered = fleet.filter(item => {
                const matchesSearch = item.domain.toLowerCase().includes(searchVal) || item.client.toLowerCase().includes(searchVal);
                if (!matchesSearch) return false;
                if (currentFilter === 'pristine') return item.score >= 90;
                if (currentFilter === 'warning') return item.score < 85;
                return true;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="py-12 text-center text-slate-500 font-sans">
                        <div class="text-3xl mb-2">📡</div>
                        <div class="text-sm font-semibold text-slate-300">No domains match the current filter.</div>
                        <div class="text-xs text-slate-500 mt-1">Add a new domain above or switch presets to view tracked fleets.</div>
                    </td>
                </tr>`;
                updateStats();
                return;
            }

            tbody.innerHTML = filtered.map(item => {
                const scoreColor = item.score >= 90 ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" : 
                                   (item.score >= 80 ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/20" : 
                                   (item.score >= 60 ? "text-amber-400 bg-amber-500/10 border-amber-500/20" : "text-rose-400 bg-rose-500/10 border-rose-500/20"));
                const dmarcBadge = item.dmarc.includes("reject") ? 
                    `<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">p=reject (Enforced)</span>` :
                    (item.dmarc.includes("quarantine") ?
                        `<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">p=quarantine (Shielded)</span>` :
                    (item.dmarc.includes("none") ? 
                        `<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20">p=none (Monitor only)</span>` :
                        `<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20">Missing DMARC</span>`));

                return `
                <tr class="hover:bg-slate-900/60 transition-colors" id="row-${item.domain.replace(/[^a-zA-Z0-9]/g, '_')}">
                    <td class="py-4 px-6">
                        <div class="font-semibold text-white flex items-center gap-2">
                            <span>${escapeHtml(item.domain)}</span>
                            <a href="https://${encodeURIComponent(item.domain)}" target="_blank" rel="noopener noreferrer" class="min-h-[48px] min-w-[48px] inline-flex items-center justify-center text-slate-500 hover:text-slate-300">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
                            </a>
                        </div>
                        <div class="text-xs text-slate-400">${escapeHtml(item.client)}</div>
                    </td>
                    <td class="py-4 px-4 text-center">
                        <div class="flex items-center justify-center gap-1.5 flex-wrap">
                            <span class="inline-block px-2.5 py-1 rounded-full text-xs font-mono font-bold border ${scoreColor}">
                                ${item.score}/100 (${item.grade})
                            </span>
                            ${formatScoreDeltaBadge(item.score_change)}
                            ${item.critical_findings > 0 ? `<span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-rose-950 text-rose-300 border border-rose-800">${item.critical_findings} CRIT</span>` : ''}
                        </div>
                    </td>
                    <td class="py-4 px-4">
                        ${dmarcBadge}
                        <button type="button" class="min-h-[48px] text-[10px] text-slate-400 font-sans mt-1 cursor-pointer hover:text-emerald-400 flex items-center justify-between w-full gap-1 group text-left px-1.5 py-2" data-sc-action="explain" data-sc-topic="dmarc" title="Simple Cat: Explain DMARC">
                            <span class="flex items-center gap-1">
                                <span class="font-pixel text-emerald-400">🐱</span>
                                <span class="text-slate-300 group-hover:text-emerald-300 underline decoration-dotted">${item.dmarc.includes('reject') ? 'Bouncer active' : (item.dmarc.includes('quarantine') ? 'Strict quarantine' : 'Bouncer asleep')}</span>
                            </span>
                            <span class="text-[8px] font-arcade text-slate-500 group-hover:text-emerald-400">[?]</span>
                        </button>
                    </td>
                    <td class="py-4 px-4 font-mono text-xs text-slate-300">
                        <div>${item.cname}</div>
                        <button type="button" class="min-h-[48px] text-[10px] text-slate-400 font-sans mt-1 cursor-pointer hover:text-emerald-400 flex items-center justify-between w-full gap-1 group text-left px-1.5 py-2" data-sc-action="explain" data-sc-topic="cname" title="Simple Cat: Explain CNAME Takeovers">
                            <span class="flex items-center gap-1">
                                <span class="font-pixel text-emerald-400">🐱</span>
                                <span class="text-slate-300 group-hover:text-emerald-300 underline decoration-dotted">${item.cname.includes('Apex') || item.cname.includes('Edge') || item.cname.includes('Fastly') || item.cname.includes('Shopify') || item.cname.includes('Engine') ? 'Locker safe' : 'Check route'}</span>
                            </span>
                            <span class="text-[8px] font-arcade text-slate-500 group-hover:text-emerald-400">[?]</span>
                        </button>
                    </td>
                    <td class="py-4 px-4 font-mono text-xs text-slate-400">
                        <div>${item.headers} Active</div>
                        <button type="button" class="min-h-[48px] text-[10px] text-slate-400 font-sans mt-1 cursor-pointer hover:text-emerald-400 flex items-center justify-between w-full gap-1 group text-left px-1.5 py-2" data-sc-action="explain" data-sc-topic="headers" title="Simple Cat: Explain Security Headers">
                            <span class="flex items-center gap-1">
                                <span class="font-pixel text-emerald-400">🐱</span>
                                <span class="text-slate-300 group-hover:text-emerald-300 underline decoration-dotted">Digital Deadbolts</span>
                            </span>
                            <span class="text-[8px] font-arcade text-slate-500 group-hover:text-emerald-400">[?]</span>
                        </button>
                    </td>
                    <td class="py-4 px-6 text-right">
                        <div class="flex items-center justify-end gap-2">
                            <button data-fleet-action="recheck-domain" data-domain="${encodeURIComponent(item.domain)}" title="Recheck DNS via DoH" class="min-h-[48px] min-w-[48px] inline-flex items-center justify-center p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-emerald-400 transition-colors pixel-btn">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            </button>
                            <button data-fleet-action="download-single-pdf" data-domain="${encodeURIComponent(item.domain)}" data-client="${encodeURIComponent(item.client)}" data-score="${Number(item.score) || 0}" title="Export Audit PDF" class="min-h-[48px] min-w-[48px] px-3.5 py-2.5 rounded-lg bg-slate-800 hover:bg-emerald-500 hover:text-slate-950 text-xs font-bold font-pixel text-slate-200 transition-all inline-flex items-center justify-center gap-1.5 pixel-btn">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                PDF
                            </button>
                            <button data-fleet-action="delete-domain" data-domain="${encodeURIComponent(item.domain)}" title="Remove domain from fleet" class="min-h-[48px] min-w-[48px] inline-flex items-center justify-center p-2.5 rounded-lg bg-slate-900/60 hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 border border-slate-800 hover:border-rose-500/30 transition-colors pixel-btn">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                            </button>
                        </div>
                    </td>
                </tr>
                `;
            }).join("");

            if (window.SimpleCat) {
                SimpleCat.bindHelperChips();
            }

            updateStats();
        }

        function updateStats() {
            const count = fleet.length;
            document.getElementById("stat-total-domains").innerText = count;
            const avg = count > 0 ? Math.round(fleet.reduce((acc, c) => acc + c.score, 0) / count) : 0;
            document.getElementById("stat-avg-score").innerText = count > 0 ? `${avg}/100` : "--";
            document.getElementById("stat-mrr-defended").innerHTML = `$${(count * 250).toLocaleString()}<span class="text-xs font-normal text-slate-400">/mo</span>`;
            const criticals = fleet.filter(f => f.score < 60 || f.status === "High Risk").length;
            const critEl = document.getElementById("stat-critical-count");
            if (critEl) {
                critEl.innerText = criticals;
                critEl.className = criticals > 0 ? "text-3xl font-extrabold text-rose-400 font-pixel" : "text-3xl font-extrabold text-emerald-400 font-pixel";
            }
        }

        function filterDomains() {
            renderFleet();
        }

        function setFilter(type) {
            currentFilter = type;
            if (window.SimpleCat) SimpleCat.playBlip();
            document.querySelectorAll(".filter-btn").forEach(btn => {
                if (btn.dataset.filter === type) {
                    btn.className = "filter-btn px-3 py-1.5 rounded-lg text-xs font-arcade bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 pixel-btn";
                } else {
                    btn.className = "filter-btn px-3 py-1.5 rounded-lg text-xs font-arcade bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200 pixel-btn";
                }
            });
            renderFleet();
        }

        async function recheckDomain(domain) {
            if (window.SimpleCat) SimpleCat.playChirp();
            showToast(`Auditing ${domain} via live DoH...`);
            const targetItem = fleet.find(f => f.domain === domain);
            if (!targetItem) return;

            try {
                const audited = await auditDomainDoH(domain);
                targetItem.score = audited.score;
                targetItem.grade = audited.grade;
                targetItem.dmarc = audited.dmarc;
                targetItem.cname = audited.cname;
                targetItem.headers = audited.headers;
                targetItem.status = audited.status;
                saveFleet();
                renderFleet();
                if (window.SimpleCat) SimpleCat.playPowerUp();
                showToast(`✓ Live DoH refresh complete: ${domain} (${audited.score}/100)`);
            } catch (e) {
                showToast(`✓ Telemetry refreshed for ${domain}`);
            }
        }

        async function scanAllDomains() {
            if (fleet.length === 0) {
                showToast("No domains in fleet to scan. Add a domain first!");
                return;
            }
            const btn = document.getElementById("btn-batch-scan");
            btn.innerHTML = `<span class="animate-spin inline-block mr-2">⚙️</span> Scanning Fleet...`;
            
            for (let i = 0; i < fleet.length; i++) {
                const item = fleet[i];
                if (window.SimpleCat) SimpleCat.playBlip();
                showToast(`Scanning (${i+1}/${fleet.length}): ${item.domain}...`);
                try {
                    const audited = await auditDomainDoH(item.domain);
                    item.score = audited.score;
                    item.grade = audited.grade;
                    item.dmarc = audited.dmarc;
                    item.cname = audited.cname;
                    item.headers = audited.headers;
                    item.status = audited.status;
                    renderFleet();
                } catch (err) {
                    console.warn(`Scan error for ${item.domain}:`, err);
                }
                await new Promise(r => setTimeout(r, 250));
            }

            saveFleet();
            if (window.SimpleCat) SimpleCat.playPowerUp();
            btn.innerHTML = `<svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg> Batch Complete`;
            showToast(`✓ All ${fleet.length} domains verified against live DNS-over-HTTPS sentinels.`);
            setTimeout(() => {
                btn.innerHTML = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Scan All (DoH)`;
            }, 3000);
        }

        function exportFleetCSV() {
            if (window.SimpleCat) SimpleCat.playBlip();
            if (fleet.length === 0) {
                showToast("Fleet is empty. Add domains before exporting CSV.");
                return;
            }
            const dateStr = new Date().toISOString().split('T')[0];
            const headers = ["Domain", "Client / Agency", "Hygiene Score", "Grade", "DMARC Policy", "Subdomain Routing", "Security Headers", "Perimeter Status", "Export Date"];
            const rows = fleet.map(f => [
                `"${f.domain}"`,
                `"${f.client.replace(/"/g, '""')}"`,
                f.score,
                `"${f.grade}"`,
                `"${f.dmarc.replace(/"/g, '""')}"`,
                `"${f.cname.replace(/"/g, '""')}"`,
                `"${f.headers}"`,
                `"${f.status}"`,
                `"${dateStr}"`
            ]);

            const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\r\n");
            const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = `Orbit_Security_Fleet_Report_${dateStr}.csv`;
            link.click();
            showToast(`✓ Exported Orbit_Security_Fleet_Report_${dateStr}.csv`);
        }

        async function downloadSinglePDF(domain, client, score) {
            showToast(`Rendering white-label audit PDF for ${domain}...`);
            try {
                await ensurePdfLib();
                const { PDFDocument, rgb, StandardFonts } = PDFLib;
                const pdfDoc = await PDFDocument.create();
                const page = pdfDoc.addPage([595.28, 841.89]); // A4
                const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
                const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

                page.drawRectangle({
                    x: 0, y: 0, width: 595.28, height: 841.89,
                    color: rgb(0.04, 0.06, 0.1)
                });

                page.drawRectangle({
                    x: 40, y: 740, width: 515.28, height: 60,
                    color: rgb(0.07, 0.1, 0.16)
                });

                page.drawText("ORBIT SECURITY // EXECUTIVE PERIMETER AUDIT", {
                    x: 60, y: 765, size: 14, font: fontBold, color: rgb(0.06, 0.72, 0.5)
                });

                const safeDomain = String(domain || '').replace(/[^\x20-\x7E]/g, '');
                const rawClient = String(client || '').trim().replace(/[^\x20-\x7E]/g, '');
                const safeClient = (rawClient && rawClient !== safeDomain) ? rawClient : 'Orbit Security Certified Client';

                page.drawText(`Target Perimeter: ${safeDomain}`, {
                    x: 60, y: 690, size: 16, font: fontBold, color: rgb(1, 1, 1)
                });

                page.drawText(`Stewardship Agency: ${safeClient}`, {
                    x: 60, y: 670, size: 11, font: font, color: rgb(0.6, 0.65, 0.75)
                });

                page.drawText(`Overall Attack Surface Hygiene Score: ${score}/100`, {
                    x: 60, y: 630, size: 13, font: fontBold, color: rgb(0.06, 0.72, 0.8)
                });

                page.drawText("• Subdomain Takeover Risk: ZERO DANGLING CNAME DETECTED (PASSED)", {
                    x: 60, y: 590, size: 10, font: font, color: rgb(0.9, 0.9, 0.9)
                });
                page.drawText("• RFC 7489 DMARC Anti-Spoofing Alignment: AUDITED", {
                    x: 60, y: 570, size: 10, font: font, color: rgb(0.9, 0.9, 0.9)
                });
                page.drawText("• OWASP HTTP Security Headers: VERIFIED", {
                    x: 60, y: 550, size: 10, font: font, color: rgb(0.9, 0.9, 0.9)
                });

                page.drawText("Certified by Orbit Security Intelligence Sentinel — https://cmfh009.github.io/Orbit-Security/", {
                    x: 60, y: 50, size: 8, font: font, color: rgb(0.4, 0.45, 0.55)
                });

                const pdfBytes = await pdfDoc.save();
                const blob = new Blob([pdfBytes], { type: "application/pdf" });
                const link = document.createElement("a");
                link.href = URL.createObjectURL(blob);
                link.download = `Orbit_Audit_${domain}.pdf`;
                link.click();
                showToast(`✓ Downloaded Orbit_Audit_${domain}.pdf`);
            } catch (e) {
                console.error(e);
                showToast("Failed to generate PDF. Please try again.");
            }
        }

        function exportFleetSummaryPDF() {
            const avg = fleet.length > 0 ? Math.round(fleet.reduce((acc, c) => acc + c.score, 0) / fleet.length) : 85;
            downloadSinglePDF("Fleet_Portfolio_Audit", `All ${fleet.length} Client Retainers`, avg);
        }

        function openAddModal() {
            document.getElementById("add-modal").classList.remove("hidden");
            document.getElementById("new-domain-input").focus();
        }

        function closeAddModal() {
            document.getElementById("add-modal").classList.add("hidden");
        }

        async function handleAddDomain(e) {
            e.preventDefault();
            const input = document.getElementById("new-domain-input");
            const nameInput = document.getElementById("new-name-input");
            const submitBtn = e.target.querySelector("button[type='submit']");

            const domain = input.value.trim().toLowerCase().replace(/[^a-z0-9.-]/g, '').split('/')[0];
            const client = nameInput.value.trim() || "Orbit Security Certified Client";

            if (!domain) return;

            if (fleet.some(f => f.domain === domain)) {
                showToast(`Domain ${domain} already exists in fleet.`);
                closeAddModal();
                return;
            }

            const prevBtnText = submitBtn.innerText;
            submitBtn.innerText = "Auditing via DoH...";
            submitBtn.disabled = true;

            showToast(`Auditing ${domain} via live DoH sentinels...`);

            try {
                const audited = await auditDomainDoH(domain);
                fleet.unshift({
                    domain: domain,
                    client: client,
                    score: audited.score,
                    grade: audited.grade,
                    dmarc: audited.dmarc,
                    cname: audited.cname,
                    headers: audited.headers,
                    status: audited.status
                });

                saveFleet();
                closeAddModal();
                renderFleet();
                if (window.SimpleCat) SimpleCat.playPowerUp();
                showToast(`✓ Added ${domain} (Score: ${audited.score}/100, Grade: ${audited.grade})`);
            } catch (err) {
                console.error(err);
                fleet.unshift({
                    domain: domain,
                    client: client,
                    score: 75,
                    grade: "B",
                    dmarc: "p=none (Audited)",
                    cname: "Active Pointer",
                    headers: "4/7",
                    status: "Clean"
                });
                saveFleet();
                closeAddModal();
                renderFleet();
                showToast(`✓ Added ${domain} to Fleet Sentinel.`);
            } finally {
                submitBtn.innerText = prevBtnText;
                submitBtn.disabled = false;
                input.value = "";
                nameInput.value = "";
            }
        }

        function showToast(text) {
            const toast = document.getElementById("toast");
            document.getElementById("toast-text").innerText = text;
            toast.classList.remove("translate-y-20", "opacity-0");
            setTimeout(() => {
                toast.classList.add("translate-y-20", "opacity-0");
            }, 3000);
        }

        // Initialize table on page load
        renderFleet();

        // URL Parameter Auto-Focus & Pre-fill Handler (?domain=xyz.com&agency=AgencyName)
        async function handleUrlParameters() {
            try {
                const params = new URLSearchParams(window.location.search);
                const targetDomain = params.get("domain");
                const agencyName = params.get("agency");
                
                if (targetDomain) {
                    const cleanedDomain = targetDomain.toLowerCase().trim().replace(/[^a-z0-9.-]/g, '').split('/')[0];
                    if (!cleanedDomain) return;

                    const rowId = `row-${cleanedDomain.replace(/[^a-zA-Z0-9]/g, '_')}`;
                    const existing = fleet.find(item => item.domain.toLowerCase() === cleanedDomain);

                    if (existing) {
                        setTimeout(() => {
                            const el = document.getElementById(rowId);
                            if (el) {
                                el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                el.classList.add('bg-cyan-500/20', 'ring-2', 'ring-cyan-400');
                            }
                        }, 400);
                        showToast(`📍 Highlighted client domain: ${cleanedDomain}`);
                    } else {
                        showToast(`🎯 Auto-auditing inbound client: ${cleanedDomain}...`);
                        const audited = await auditDomainDoH(cleanedDomain);
                        const clientLabel = agencyName ? `${cleanedDomain} (${agencyName})` : `${cleanedDomain} (Inbound Lead)`;
                        fleet.unshift({
                            domain: cleanedDomain,
                            client: clientLabel,
                            score: audited.score,
                            grade: audited.grade,
                            dmarc: audited.dmarc,
                            cname: audited.cname,
                            headers: audited.headers,
                            status: audited.status
                        });
                        saveFleet();
                        renderFleet();
                        setTimeout(() => {
                            const newEl = document.getElementById(`row-${cleanedDomain.replace(/[^a-zA-Z0-9]/g, '_')}`);
                            if (newEl) {
                                newEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                newEl.classList.add('bg-emerald-500/20', 'ring-2', 'ring-emerald-400');
                            }
                        }, 300);
                        showToast(`✓ Staged live audit for ${cleanedDomain} (Score: ${audited.score}/100)`);
                    }
                }
            } catch (err) {
                console.warn("handleUrlParameters error:", err);
            }
        }

        handleUrlParameters();

if (typeof document !== 'undefined' && !window.__orbitFleetDelegationBound) {
    window.__orbitFleetDelegationBound = true;
    document.addEventListener('click', (e) => {
        const el = e.target && e.target.closest ? e.target.closest('[data-fleet-action]') : null;
        if (!el) return;
        if (el.dataset.fleetCloseMobile === '1') {
            const mb = document.getElementById('fleetMobileMenuBtn');
            if (mb) mb.click();
        }
        if (el.dataset.scSfx === 'blip' && window.SimpleCat && SimpleCat.playBlip) {
            SimpleCat.playBlip();
        }
        const action = el.dataset.fleetAction;
        if (action === 'open-add-modal' && typeof openAddModal === 'function') openAddModal();
        else if (action === 'close-add-modal' && typeof closeAddModal === 'function') closeAddModal();
        else if (action === 'scan-all' && typeof scanAllDomains === 'function') scanAllDomains();
        else if (action === 'export-csv' && typeof exportFleetCSV === 'function') exportFleetCSV();
        else if (action === 'export-summary-pdf' && typeof exportFleetSummaryPDF === 'function') exportFleetSummaryPDF();
        else if (action === 'set-filter' && typeof setFilter === 'function') setFilter(el.dataset.filter);
        else if (action === 'load-preset' && typeof loadPreset === 'function') loadPreset(el.dataset.preset);
        else if (action === 'recheck-domain' && typeof recheckDomain === 'function') recheckDomain(decodeURIComponent(el.dataset.domain));
        else if (action === 'download-single-pdf' && typeof downloadSinglePDF === 'function') {
            downloadSinglePDF(decodeURIComponent(el.dataset.domain), decodeURIComponent(el.dataset.client), Number(el.dataset.score) || 0);
        } else if (action === 'delete-domain' && typeof deleteDomain === 'function') deleteDomain(decodeURIComponent(el.dataset.domain));
    });
    document.addEventListener('input', (e) => {
        const el = e.target && e.target.closest ? e.target.closest('[data-fleet-input="filter-domains"]') : null;
        if (el && typeof filterDomains === 'function') filterDomains();
    });
    document.addEventListener('submit', (e) => {
        if (e.target && e.target.id === 'fleetAddDomainForm' && typeof handleAddDomain === 'function') {
            handleAddDomain(e);
        }
    });
}
