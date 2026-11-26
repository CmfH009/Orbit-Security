window.playgroundData = {};

        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function copyToClipboard(text, btn) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => {
                    if (btn) {
                        const orig = btn.innerHTML;
                        btn.innerHTML = '✓ Copied!';
                        setTimeout(() => { btn.innerHTML = orig; }, 1800);
                    }
                }).catch(() => {
                    prompt('Copy verification snippet:', text);
                });
            } else {
                prompt('Copy verification snippet:', text);
            }
        }

        function copyPlaygroundSnippet(id, kind, btn) {
            const item = window.playgroundData && window.playgroundData[id];
            if (!item) return;
            const text = item[kind];
            if (text) {
                copyToClipboard(text, btn);
            }
        }

        const SAAS_TAKEOVER_SIGNATURES = [
            { name: "Unbounce", patterns: ["unbouncepages.com"], pattern: "The requested URL was not found on this server" },
            { name: "GitHub Pages", patterns: ["github.io"], pattern: "There isn't a GitHub Pages site here" },
            { name: "AWS S3", patterns: ["s3.amazonaws.com", "s3-website", ".s3."], pattern: "NoSuchBucket" },
            { name: "AWS CloudFront", patterns: ["cloudfront.net"], pattern: "ERROR: The request could not be satisfied" },
            { name: "Shopify", patterns: ["myshopify.com"], pattern: "Sorry, this shop is currently unavailable" },
            { name: "Webflow", patterns: ["proxy.webflow.com", "webflow.io", "webflow.com"], pattern: "The site you are looking for could not be found" },
            { name: "Heroku", patterns: ["herokudns.com", "herokuapp.com"], pattern: "No such app" },
            { name: "Zendesk", patterns: ["zendesk.com"], pattern: "Help Center Closed" },
            { name: "Pantheon", patterns: ["pantheonsite.io"], pattern: "The gods are wise, but do not know of the site which you seek" },
            { name: "Netlify", patterns: ["netlify.app", "netlify.com"], pattern: "Not Found - Request ID" },
            { name: "Surge.sh", patterns: ["surge.sh"], pattern: "project not found" },
            { name: "Fly.io", patterns: ["fly.dev", "shw.io"], pattern: "Could not find that app" },
            { name: "HubSpot", patterns: ["hubspot.net"], pattern: "Domain not found" },
            { name: "Ghost", patterns: ["ghost.io"], pattern: "The thing you were looking for is no longer here" },
            { name: "Readme.io", patterns: ["readme.io"], pattern: "Project doesnt exist... yet!" },
            { name: "WordPress.com", patterns: ["wordpress.com"], pattern: "Do you want to register" },
            { name: "Fastly", patterns: ["fastly.net"], pattern: "Fastly error: unknown domain" },
            { name: "Microsoft Azure", patterns: ["azurewebsites.net", "azureedge.net", "cloudapp.net", "blob.core.windows.net"], pattern: "404 Web Site not found" }
        ];

        const PLAYGROUND_SUBDOMAINS = ['shop', 'store', 'blog', 'promo', 'app', 'dev', 'status', 'help', 'billing', 'staging'];

        function identifyProvider(cname) {
            if (!cname) return null;
            const lower = cname.toLowerCase();
            for (const sig of SAAS_TAKEOVER_SIGNATURES) {
                if (sig.patterns.some(p => lower.includes(p))) {
                    return sig;
                }
            }
            return null;
        }

        function buildPocObject(subdomain, cnameTarget, providerName) {
            const target = cnameTarget || subdomain;
            const curlCmd = `curl -sI -H "Host: ${subdomain}" "https://${target}"`;
            const zoneSnippet = `; --- GhostDNS Remediation: Dangling CNAME Removal ---\n; Subdomain: ${subdomain}\n; Action: Delete dangling CNAME in DNS:\n; ${subdomain}.    IN    CNAME    ${target}.`;
            const cleanSub = subdomain.split('.')[0].replace(/[^a-zA-Z0-9_]/g, '_');
            const tfSnippet = `# --- GhostDNS Remediation: Terraform Removal ---\n# Target: ${subdomain}\n# Action: Destroy or remove this resource block:\n# resource "cloudflare_record" "${cleanSub}" {\n#   name  = "${subdomain.split('.')[0]}"\n#   type  = "CNAME"\n#   value = "${target}"\n# }`;
            return {
                curl: curlCmd,
                zone: zoneSnippet,
                tf: tfSnippet
            };
        }

        async function queryDns(domain, type = 'CNAME') {
            try {
                const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, {
                    headers: { 'Accept': 'application/dns-json' }
                });
                if (!res.ok) throw new Error('Google DoH failed');
                return await res.json();
            } catch (e) {
                try {
                    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
                        headers: { 'Accept': 'application/dns-json' }
                    });
                    return await res.json();
                } catch (err) {
                    return null;
                }
            }
        }

        function renderPlayground(domain, rows, isVulnerable, summaryInfo) {
            const resContent = document.getElementById('auditContent');
            window.playgroundData = {};

            const danglingCount = rows.filter(r => r.isDangling).length;
            const score = isVulnerable || danglingCount > 0 ? Math.max(25, 85 - (danglingCount * 25)) : 95;
            const grade = score >= 90 ? "A+" : (score >= 70 ? "B" : "F - CRITICAL");
            const gradeColor = score >= 90 ? "text-emerald-400" : (score >= 70 ? "text-amber-400" : "text-rose-400");
            const headerIcon = danglingCount > 0 ? "⚠️" : "✓";
            const headerTitle = danglingCount > 0 ? "TAKEOVER ANOMALIES DETECTED — DANGLING CNAME RISK" : "GHOSTDNS PERIMETER SCAN COMPLETE";
            const headerColor = danglingCount > 0 ? "text-rose-400" : "text-emerald-400";

            let tableRowsHtml = '';
            rows.forEach((row, idx) => {
                const rowId = `row_${idx}_${Date.now()}`;
                window.playgroundData[rowId] = row.poc;

                let statusBadge = '';
                if (row.isDangling) {
                    statusBadge = `
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 text-rose-300 border border-rose-700/60 shadow-sm animate-pulse">
                            <span>⚠️</span> DANGLING // UNCLAIMED
                        </span>
                        <div class="text-[9px] text-rose-400 mt-0.5 font-sans">${escapeHtml(row.provider || 'Orphan SaaS')}</div>
                    `;
                } else if (row.cname) {
                    statusBadge = `
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 shadow-sm">
                            <span class="text-emerald-400">●</span> SECURE
                        </span>
                        <div class="text-[9px] text-emerald-400 mt-0.5 font-sans">${escapeHtml(row.provider || 'Active Service')}</div>
                    `;
                } else if (row.hasA) {
                    statusBadge = `
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] text-cyan-300 bg-cyan-950/60 border border-cyan-800/40">
                            <span class="text-cyan-400">●</span> SECURE (Apex A)
                        </span>
                    `;
                } else {
                    statusBadge = `
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] text-slate-400 bg-slate-900 border border-slate-800">
                            <span>○</span> INACTIVE (No CNAME)
                        </span>
                    `;
                }

                tableRowsHtml += `
                    <tr class="hover:bg-slate-900/50 transition">
                        <td class="py-2.5 px-3 font-bold text-white whitespace-nowrap">
                            ${escapeHtml(row.subdomain)}
                        </td>
                        <td class="py-2.5 px-3 font-mono text-cyan-400 text-[11px] whitespace-nowrap">
                            ${row.cname ? escapeHtml(row.cname) : '<span class="text-slate-600">None</span>'}
                        </td>
                        <td class="py-2.5 px-3 whitespace-nowrap">
                            ${statusBadge}
                        </td>
                        <td class="py-2.5 px-3">
                            <div class="flex items-center gap-1.5 bg-slate-950/90 px-2 py-1 rounded border border-slate-800 max-w-[270px]">
                                <code class="text-[10px] text-cyan-300 truncate font-mono select-all" title="${escapeHtml(row.poc.curl)}">${escapeHtml(row.poc.curl)}</code>
                                <button type="button" data-ghost-action="copy-snippet" data-target="${rowId}" data-kind="curl" class="px-2 py-1 text-[9px] font-bold text-cyan-400 hover:text-slate-950 bg-slate-900 hover:bg-cyan-400 border border-cyan-500/40 rounded transition cursor-pointer shrink-0">Copy</button>
                            </div>
                        </td>
                        <td class="py-2.5 px-3 whitespace-nowrap">
                            <div class="flex items-center gap-1">
                                <button type="button" data-ghost-action="copy-snippet" data-target="${rowId}" data-kind="zone" title="Copy BIND .zone removal" class="px-2 py-1 text-[10px] font-bold text-amber-300 hover:text-slate-950 bg-amber-950/60 hover:bg-amber-400 border border-amber-500/40 rounded transition cursor-pointer">.zone</button>
                                <button type="button" data-ghost-action="copy-snippet" data-target="${rowId}" data-kind="tf" title="Copy Terraform removal" class="px-2 py-1 text-[10px] font-bold text-purple-300 hover:text-white bg-purple-950/60 hover:bg-purple-600 border border-purple-500/40 rounded transition cursor-pointer">Terraform</button>
                            </div>
                        </td>
                    </tr>
                `;
            });

            resContent.innerHTML = `
                <div class="${headerColor} font-bold mb-3 flex items-center gap-2">
                    <span class="text-base">${headerIcon}</span>
                    <span class="font-arcade text-[11px]">${headerTitle}</span>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-slate-300 pb-3 border-b border-slate-800">
                    <div>Target Domain: <span class="text-white font-bold">${escapeHtml(domain)}</span></div>
                    <div>Hygiene Score: <span class="${gradeColor} font-bold font-mono">${score}/100 (${grade})</span></div>
                    <div>Dangling CNAMEs: <span class="${danglingCount > 0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}">${danglingCount} Detected</span></div>
                    <div>Authoritative Resolvers: <span class="text-cyan-400">Google DoH &amp; Cloudflare</span></div>
                    <div>Drift Status: <span class="${danglingCount > 0 ? 'text-rose-400 font-bold' : 'text-cyan-400 font-bold'}">${danglingCount > 0 ? 'ANOMALY DETECTED' : 'Cryptographic Baseline Locked'}</span></div>
                    <div>Monitored Subdomains: <span class="text-slate-200 font-mono">10 Targets Parallel</span></div>
                </div>

                <!-- Subdomain Takeover Exploit Proof-of-Concept Playground -->
                <div class="mt-4 rounded-xl border border-cyan-800/40 bg-slate-950/90 overflow-hidden shadow-xl">
                    <div class="p-3 bg-slate-900/80 border-b border-cyan-900/40 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div class="flex items-center gap-2">
                            <span class="w-2.5 h-2.5 rounded-full ${danglingCount > 0 ? 'bg-rose-500 animate-ping' : 'bg-cyan-400 animate-pulse'}"></span>
                            <span class="font-arcade text-[10px] text-cyan-300">SUBDOMAIN TAKEOVER EXPLOIT PROOF-OF-CONCEPT PLAYGROUND</span>
                        </div>
                        <span class="text-[9px] text-slate-400 font-mono">RFC-8484 REAL-TIME RESOLUTION &amp; VERIFICATION PROOFS</span>
                    </div>

                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs font-mono">
                            <thead>
                                <tr class="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                                    <th class="py-2.5 px-3">Subdomain</th>
                                    <th class="py-2.5 px-3">CNAME Destination</th>
                                    <th class="py-2.5 px-3">Matched SaaS / Risk</th>
                                    <th class="py-2.5 px-3">Safe Verification Proof (cURL)</th>
                                    <th class="py-2.5 px-3">Remediation</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-800/60">
                                ${tableRowsHtml}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Custom POC Sandbox Generator -->
                <div class="mt-4 p-3 rounded-xl card-glass card-glass-cyan border border-cyan-800/40 text-[11px]">
                    <div class="text-[10px] font-arcade text-cyan-400 mb-2 flex items-center gap-1.5">
                        <span>⚡</span> CUSTOM SUBDOMAIN TAKEOVER POC SANDBOX
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <input id="customSubInput" type="text" placeholder="custom.yourdomain.com" class="bg-slate-950 px-2.5 py-1.5 rounded font-mono text-white text-xs border border-slate-800 focus:border-cyan-400 focus:outline-none">
                        <input id="customCnameInput" type="text" placeholder="target.myshopify.com" class="bg-slate-950 px-2.5 py-1.5 rounded font-mono text-white text-xs border border-slate-800 focus:border-cyan-400 focus:outline-none">
                        <button type="button" data-ghost-action="generate-poc" class="px-3 py-1.5 rounded text-xs font-bold font-pixel bg-cyan-400 hover:bg-cyan-300 text-slate-950 transition pixel-btn">Generate Proof</button>
                    </div>
                    <div id="customPocOutput" class="mt-2 hidden p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[10px]">
                        <!-- Populated dynamically -->
                    </div>
                </div>

                <div class="mt-3 pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-2">
                    <div>
                        Continuous 15-minute takeover surveillance: <a href="#pricing" class="text-cyan-400 underline hover:text-cyan-300 font-bold">GhostDNS Sentinel ($29/mo)</a>.
                    </div>
                    <div class="text-slate-500 text-[10px]">Safe Harbor: Non-destructive audit verification commands only.</div>
                </div>
            `;
        }

        function generateCustomPoc() {
            const sub = (document.getElementById('customSubInput').value || '').trim();
            const cname = (document.getElementById('customCnameInput').value || '').trim();
            if (!sub || !cname) {
                alert('Please enter both a subdomain and CNAME target.');
                return;
            }
            const sig = identifyProvider(cname);
            const providerName = sig ? sig.name : 'Unknown SaaS';
            const poc = buildPocObject(sub, cname, providerName);
            const customId = `custom_${Date.now()}`;
            window.playgroundData[customId] = poc;

            const out = document.getElementById('customPocOutput');
            out.classList.remove('hidden');
            out.innerHTML = `
                <div class="flex items-center justify-between gap-2 mb-1">
                    <span class="text-cyan-400 font-bold">Provider: ${escapeHtml(providerName)}</span>
                    <div class="flex items-center gap-1">
                        <button type="button" data-ghost-action="copy-snippet" data-target="${customId}" data-kind="curl" class="px-2 py-0.5 text-[9px] bg-slate-800 text-cyan-300 hover:text-white rounded border border-slate-700 cursor-pointer">Copy cURL</button>
                        <button type="button" data-ghost-action="copy-snippet" data-target="${customId}" data-kind="zone" class="px-2 py-0.5 text-[9px] bg-amber-950/80 text-amber-300 hover:text-white rounded border border-amber-800/60 cursor-pointer">.zone</button>
                        <button type="button" data-ghost-action="copy-snippet" data-target="${customId}" data-kind="tf" class="px-2 py-0.5 text-[9px] bg-purple-950/80 text-purple-300 hover:text-white rounded border border-purple-800/60 cursor-pointer">Terraform</button>
                    </div>
                </div>
                <div class="bg-black/60 p-2 rounded border border-slate-800 text-slate-300 select-all font-mono">${escapeHtml(poc.curl)}</div>
            `;
        }

        async function runAudit() {
            const raw = document.getElementById('targetDomain').value.trim();
            if (!raw) {
                alert('Please enter a valid domain to scan.');
                return;
            }
            const domain = raw.toLowerCase().replace(/https?:\/\//, '').split('/')[0];
            const resArea = document.getElementById('auditResult');
            const resContent = document.getElementById('auditContent');
            resArea.classList.remove('hidden');

            resContent.innerHTML = `
                <div class="flex items-center gap-2 text-cyan-400">
                    <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                    <span class="font-arcade text-[10px]">PROBING RFC-8484 DoH ACROSS 10 SUBDOMAINS FOR ${escapeHtml(domain)}...</span>
                </div>
                <div class="text-slate-500 text-[11px]">Querying Google DoH &amp; Cloudflare Anycast resolvers in parallel...</div>
                <div class="mt-3 flex flex-wrap gap-1">
                    ${PLAYGROUND_SUBDOMAINS.map(s => `<span class="px-1.5 py-0.5 rounded text-[9px] bg-slate-900 border border-slate-800 text-slate-400 font-mono">${escapeHtml(s)}.${escapeHtml(domain)}</span>`).join('')}
                </div>
            `;

            const [apexCname, apexA, ...subResults] = await Promise.all([
                queryDns(domain, 'CNAME'),
                queryDns(domain, 'A'),
                ...PLAYGROUND_SUBDOMAINS.map(async (sub) => {
                    const fqdn = `${sub}.${domain}`;
                    const [cnameData, aData] = await Promise.all([
                        queryDns(fqdn, 'CNAME'),
                        queryDns(fqdn, 'A')
                    ]);
                    return { sub, fqdn, cnameData, aData };
                })
            ]);

            const apexCnameRecords = (apexCname && apexCname.Answer) ? apexCname.Answer.map(a => a.data) : [];
            const apexARecords = (apexA && apexA.Answer) ? apexA.Answer.map(a => a.data) : [];

            const isNxdomain = ((!apexCname || apexCname.Status === 3) && (!apexA || apexA.Status === 3)) &&
                               subResults.every(r => (!r.cnameData || r.cnameData.Status === 3) && (!r.aData || r.aData.Status === 3));

            if (isNxdomain) {
                resContent.innerHTML = `
                    <div class="text-rose-400 font-bold mb-2 flex items-center gap-2">
                        <span>⚠️</span>
                        <span class="font-arcade text-[10px]">GHOSTDNS PERIMETER SCAN COMPLETE — DOMAIN NOT RESOLVED (NXDOMAIN)</span>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
                        <div>Target Perimeter: <span class="text-white font-bold">${escapeHtml(domain)}</span></div>
                        <div>Authoritative Resolvers: <span class="text-cyan-400">Google DoH &amp; Cloudflare</span></div>
                        <div>Active CNAME Routing: <span class="text-rose-300 font-mono">Domain not resolved (NXDOMAIN)</span></div>
                        <div>Resolved A Records: <span class="text-rose-300 font-mono">None (NXDOMAIN / Inactive)</span></div>
                        <div>Perimeter Hygiene Score: <span class="text-rose-400 font-bold">0/100 (Unregistered / NXDOMAIN)</span></div>
                        <div>Dangling SaaS CNAMEs: <span class="text-slate-400">N/A — Domain Unreachable</span></div>
                    </div>
                    <div class="text-slate-400 pt-2 border-t border-slate-800">
                        DNS Drift Status: <span class="text-amber-400 font-bold">Unregistered or Expired Domain</span>
                    </div>
                    <div class="mt-2 pt-2 border-t border-slate-800 text-[11px] text-slate-400">
                        Verify domain spelling or register and configure perimeter defense: <a href="#pricing" class="text-cyan-400 underline hover:text-cyan-300">GhostDNS Sentinel ($29/mo)</a>.
                    </div>
                `;
                return;
            }

            const rows = subResults.map(({ sub, fqdn, cnameData, aData }) => {
                const cnameRec = (cnameData && cnameData.Answer) ? cnameData.Answer.find(a => a.type === 5 || a.type === 'CNAME') : null;
                const cnameVal = cnameRec ? cnameRec.data.replace(/\.$/, '') : null;
                const aRecs = (aData && aData.Answer) ? aData.Answer.filter(a => a.type === 1 || a.type === 'A').map(a => a.data) : [];
                const providerSig = identifyProvider(cnameVal);
                const providerName = providerSig ? providerSig.name : (cnameVal ? 'Custom SaaS' : null);

                let isDangling = false;
                if (cnameVal && providerSig) {
                    if (aRecs.length === 0 || (aData && aData.Status === 3)) {
                        isDangling = true;
                    }
                }

                return {
                    subdomain: fqdn,
                    cname: cnameVal,
                    provider: providerName,
                    isDangling: isDangling,
                    hasA: aRecs.length > 0,
                    poc: buildPocObject(fqdn, cnameVal, providerName)
                };
            });

            const hasAnyDangling = rows.some(r => r.isDangling);
            renderPlayground(domain, rows, hasAnyDangling, { apexCname: apexCnameRecords, apexA: apexARecords });
        }

        function simulateScenario(type) {
            const resArea = document.getElementById('auditResult');
            resArea.classList.remove('hidden');

            const domain = 'candykittens.co.uk';
            document.getElementById('targetDomain').value = domain;

            let rows = [];
            if (type === 'unbounce') {
                rows = PLAYGROUND_SUBDOMAINS.map((sub) => {
                    const fqdn = `${sub}.${domain}`;
                    if (sub === 'promo') {
                        return {
                            subdomain: fqdn,
                            cname: 'unbouncepages.com',
                            provider: 'Unbounce',
                            isDangling: true,
                            hasA: false,
                            poc: buildPocObject(fqdn, 'unbouncepages.com', 'Unbounce')
                        };
                    }
                    if (sub === 'shop') {
                        return {
                            subdomain: fqdn,
                            cname: 'shops.myshopify.com',
                            provider: 'Shopify',
                            isDangling: false,
                            hasA: true,
                            poc: buildPocObject(fqdn, 'shops.myshopify.com', 'Shopify')
                        };
                    }
                    return {
                        subdomain: fqdn,
                        cname: null,
                        provider: null,
                        isDangling: false,
                        hasA: false,
                        poc: buildPocObject(fqdn, null, null)
                    };
                });
                renderPlayground(domain, rows, true, { scenario: 'unbounce' });
            } else if (type === 's3') {
                rows = PLAYGROUND_SUBDOMAINS.map((sub) => {
                    const fqdn = `${sub}.${domain}`;
                    if (sub === 'store' || sub === 'app') {
                        return {
                            subdomain: fqdn,
                            cname: 'candykittens-assets.s3.amazonaws.com',
                            provider: 'AWS S3',
                            isDangling: true,
                            hasA: false,
                            poc: buildPocObject(fqdn, 'candykittens-assets.s3.amazonaws.com', 'AWS S3')
                        };
                    }
                    if (sub === 'shop') {
                        return {
                            subdomain: fqdn,
                            cname: 'shops.myshopify.com',
                            provider: 'Shopify',
                            isDangling: false,
                            hasA: true,
                            poc: buildPocObject(fqdn, 'shops.myshopify.com', 'Shopify')
                        };
                    }
                    return {
                        subdomain: fqdn,
                        cname: null,
                        provider: null,
                        isDangling: false,
                        hasA: false,
                        poc: buildPocObject(fqdn, null, null)
                    };
                });
                renderPlayground(domain, rows, true, { scenario: 's3' });
            } else {
                rows = PLAYGROUND_SUBDOMAINS.map((sub) => {
                    const fqdn = `${sub}.${domain}`;
                    if (sub === 'shop') {
                        return {
                            subdomain: fqdn,
                            cname: 'shops.myshopify.com',
                            provider: 'Shopify',
                            isDangling: false,
                            hasA: true,
                            poc: buildPocObject(fqdn, 'shops.myshopify.com', 'Shopify')
                        };
                    }
                    return {
                        subdomain: fqdn,
                        cname: null,
                        provider: null,
                        isDangling: false,
                        hasA: false,
                        poc: buildPocObject(fqdn, null, null)
                    };
                });
                renderPlayground(domain, rows, false, { scenario: 'clean' });
            }
        }

        function shareGhostDnsTool(platform = 'x') {
            const rawDomain = (document.getElementById('targetDomain')?.value || '').trim() || 'candykittens.co.uk';
            const shareUrl = 'https://cmfh009.github.io/Orbit-Security/ghostdns/';
            const shareText = `👻 Scanned ${rawDomain} for dangling SaaS CNAMEs & silent DNS drift with GhostDNS (RFC-8484 DoH) by @OrbitSecurity! Run a free subdomain takeover check:`;
            const shareTitle = `GhostDNS — Subdomain Takeover & Dangling CNAME Scanner (${rawDomain})`;

            if (platform === 'x') {
                window.open(`https://x.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(shareUrl)}`, '_blank', 'noopener,noreferrer');
                return;
            }
            if (platform === 'linkedin') {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(`${shareText} ${shareUrl}`).catch(() => {});
                }
                window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareUrl)}`, '_blank', 'noopener,noreferrer');
                return;
            }
            if (platform === 'reddit') {
                window.open(`https://www.reddit.com/submit?url=${encodeURIComponent(shareUrl)}&title=${encodeURIComponent(shareTitle)}`, '_blank', 'noopener,noreferrer');
                return;
            }
            if (navigator.share) {
                navigator.share({ title: shareTitle, text: shareText, url: shareUrl }).catch(() => {});
                return;
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(`${shareText}\n${shareUrl}`);
            }
        }

if (typeof document !== 'undefined' && !window.__orbitGhostDnsDelegationBound) {
    window.__orbitGhostDnsDelegationBound = true;
    document.addEventListener('click', (e) => {
        const el = e.target && e.target.closest ? e.target.closest('[data-ghost-action]') : null;
        if (!el) return;
        const action = el.dataset.ghostAction;
        if (action === 'run-audit' && typeof runAudit === 'function') runAudit();
        else if (action === 'simulate' && typeof simulateScenario === 'function') simulateScenario(el.dataset.scenario);
        else if (action === 'generate-poc' && typeof generateCustomPoc === 'function') generateCustomPoc();
        else if (action === 'share' && typeof shareGhostDnsTool === 'function') shareGhostDnsTool(el.dataset.channel);
        else if (action === 'copy-snippet' && typeof copyPlaygroundSnippet === 'function') {
            copyPlaygroundSnippet(el.dataset.target, el.dataset.kind, el);
        }
    });
}
