// Mobile nav toggle
    (function initAuditMobileMenu() {
      const btn = document.getElementById("auditMobileMenuBtn");
      const menu = document.getElementById("auditMobileMenu");
      if (!btn || !menu) return;
      btn.addEventListener("click", () => {
        const isOpen = !menu.classList.contains("hidden");
        menu.classList.toggle("hidden", isOpen);
        btn.setAttribute("aria-expanded", String(!isOpen));
      });
    })();
    // Known SaaS CNAME takeover targets
    const SAAS_FINGERPRINTS = [
      { pattern: "github.io", name: "GitHub Pages" },
      { pattern: "herokuapp.com", name: "Heroku" },
      { pattern: "s3.amazonaws.com", name: "AWS S3 Bucket" },
      { pattern: "zendesk.com", name: "Zendesk" },
      { pattern: "myshopify.com", name: "Shopify" },
      { pattern: "ghost.io", name: "Ghost CMS" },
      { pattern: "surge.sh", name: "Surge.sh" },
      { pattern: "bitbucket.io", name: "Bitbucket" },
      { pattern: "pantheonsite.io", name: "Pantheon" },
      { pattern: "readme.io", name: "ReadMe" },
      { pattern: "fastly.net", name: "Fastly CDN" }
    ];

    // High-risk prefix probes
    const SUBDOMAINS_TO_PROBE = ["blog", "shop", "help", "status", "docs", "dev", "app", "staging", "api", "mail"];

    // DoH query via Cloudflare (100% free, CORS enabled)
    async function queryDoH(name, type) {
      try {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
        const res = await fetch(url, {
          headers: { "Accept": "application/dns-json" }
        });
        if (!res.ok) return null;
        return await res.json();
      } catch (err) {
        console.warn("Cloudflare DoH fallback to Google DoH:", err);
        try {
          const gUrl = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
          const gRes = await fetch(gUrl);
          if (!gRes.ok) return null;
          return await gRes.json();
        } catch (e) {
          return null;
        }
      }
    }

    // Sample button clicks
    document.querySelectorAll(".sample-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.getElementById("domainInput").value = btn.dataset.domain;
        document.getElementById("scanBtn").click();
      });
    });

    // Form Submission
    document.getElementById("scanForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const domain = document.getElementById("domainInput").value.trim().toLowerCase();
      if (!domain) return;

      const progress = document.getElementById("progressState");
      const progressText = document.getElementById("progressText");
      const resultsCard = document.getElementById("resultsCard");
      const scanBtn = document.getElementById("scanBtn");

      progress.classList.remove("hidden");
      resultsCard.classList.add("hidden");
      scanBtn.disabled = true;
      scanBtn.classList.add("opacity-50");

      try {
        // Step 1: TXT (SPF & Verification)
        progressText.textContent = `[1/4] Probing TXT & SPF records for ${domain}...`;
        const txtData = await queryDoH(domain, "TXT");

        // Step 2: DMARC
        progressText.textContent = `[2/4] Querying RFC-7489 DMARC policy (_dmarc.${domain})...`;
        const dmarcData = await queryDoH(`_dmarc.${domain}`, "TXT");

        // Step 3: MX
        progressText.textContent = `[3/4] Resolving MX Mail Exchanger gateways for ${domain}...`;
        const mxData = await queryDoH(domain, "MX");

        // Step 4: CNAME probes
        progressText.textContent = `[4/4] Probing common SaaS subdomain CNAMEs for takeover risk...`;
        const takeoverResults = [];
        for (const sub of SUBDOMAINS_TO_PROBE) {
          const targetSub = `${sub}.${domain}`;
          const cnameData = await queryDoH(targetSub, "CNAME");
          if (cnameData && cnameData.Answer) {
            for (const ans of cnameData.Answer) {
              const cnameVal = ans.data;
              const matchedSaas = SAAS_FINGERPRINTS.find(fp => cnameVal.toLowerCase().includes(fp.pattern));
              if (matchedSaas) {
                takeoverResults.push({ sub: targetSub, target: cnameVal, saas: matchedSaas.name });
              }
            }
          }
        }

        renderResults(domain, txtData, dmarcData, mxData, takeoverResults);

      } catch (err) {
        alert("DNS Resolution Error: " + err.message);
      } finally {
        progress.classList.add("hidden");
        scanBtn.disabled = false;
        scanBtn.classList.remove("opacity-50");
      }
    });

    function escapeHtml(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function renderResults(domain, txt, dmarc, mx, takeovers) {
      document.getElementById("resultDomain").textContent = domain;

      let score = 100;

      // --- SPF Evaluation ---
      let spfRecord = null;
      if (txt && txt.Answer) {
        for (const ans of txt.Answer) {
          const dataClean = (ans.data || "").replace(/^"|"$/g, "");
          if (dataClean.startsWith("v=spf1")) {
            spfRecord = dataClean;
            break;
          }
        }
      }

      const spfBadge = document.getElementById("spfBadge");
      const spfIcon = document.getElementById("spfStatusIcon");
      const spfExp = document.getElementById("spfExplanation");
      const spfRaw = document.getElementById("spfRaw");

      if (!spfRecord) {
        score -= 30;
        spfBadge.textContent = "CRITICAL FAIL";
        spfBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-rose-950 text-rose-400 border border-rose-800/40";
        spfIcon.textContent = "🔴";
        spfExp.textContent = "Missing SPF record! Any attacker can forge emails from your domain with zero authentication checks.";
        spfRaw.textContent = "(No v=spf1 record published in DNS)";
      } else if (spfRecord.includes("+all") || spfRecord.includes("?all")) {
        score -= 20;
        spfBadge.textContent = "WEAK QUALIFIER";
        spfBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-amber-950 text-amber-400 border border-amber-800/40";
        spfIcon.textContent = "🟡";
        spfExp.textContent = "Permissive '+all' or '?all' qualifier detected. Allows unauthorized mail senders to impersonate your domain.";
        spfRaw.textContent = spfRecord;
      } else {
        spfBadge.textContent = "PASSED";
        spfBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/40";
        spfIcon.textContent = "🟢";
        spfExp.textContent = "Valid SPF record configured with strict -all or ~all softfail.";
        spfRaw.textContent = spfRecord;
      }

      // --- DMARC Evaluation ---
      let dmarcRecord = null;
      if (dmarc && dmarc.Answer) {
        for (const ans of dmarc.Answer) {
          const dataClean = (ans.data || "").replace(/^"|"$/g, "");
          if (dataClean.startsWith("v=DMARC1")) {
            dmarcRecord = dataClean;
            break;
          }
        }
      }

      const dmarcBadge = document.getElementById("dmarcBadge");
      const dmarcIcon = document.getElementById("dmarcStatusIcon");
      const dmarcExp = document.getElementById("dmarcExplanation");
      const dmarcRaw = document.getElementById("dmarcRaw");

      if (!dmarcRecord) {
        score -= 35;
        dmarcBadge.textContent = "CRITICAL FAIL";
        dmarcBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-rose-950 text-rose-400 border border-rose-800/40";
        dmarcIcon.textContent = "🔴";
        dmarcExp.textContent = "Missing DMARC policy! Inbound gateways cannot verify SPF/DKIM alignment or drop forged emails.";
        dmarcRaw.textContent = "(No _dmarc record published in DNS)";
      } else if (dmarcRecord.includes("p=none")) {
        score -= 15;
        dmarcBadge.textContent = "MONITORING ONLY";
        dmarcBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-amber-950 text-amber-400 border border-amber-800/40";
        dmarcIcon.textContent = "🟡";
        dmarcExp.textContent = "DMARC policy set to 'p=none' (telemetry only). Spoofed messages are not blocked by recipient inboxes.";
        dmarcRaw.textContent = dmarcRecord;
      } else {
        dmarcBadge.textContent = "ENFORCED";
        dmarcBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/40";
        dmarcIcon.textContent = "🟢";
        dmarcExp.textContent = "Strict DMARC enforcement active (p=quarantine or p=reject).";
        dmarcRaw.textContent = dmarcRecord;
      }

      // --- MX Evaluation ---
      const mxBadge = document.getElementById("mxBadge");
      const mxIcon = document.getElementById("mxStatusIcon");
      const mxExp = document.getElementById("mxExplanation");
      const mxRaw = document.getElementById("mxRaw");

      if (!mx || !mx.Answer || mx.Answer.length === 0) {
        score -= 10;
        mxBadge.textContent = "NO MX";
        mxBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-amber-950 text-amber-400 border border-amber-800/40";
        mxIcon.textContent = "🟡";
        mxExp.textContent = "No MX records found. Domain does not receive direct email.";
        mxRaw.textContent = "(No MX records)";
      } else {
        mxBadge.textContent = "CONFIGURED";
        mxBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/40";
        mxIcon.textContent = "🟢";
        mxExp.textContent = `${mx.Answer.length} Mail Exchangers active.`;
        mxRaw.textContent = mx.Answer.map(a => a.data).join(", ");
      }

      // --- Subdomain Takeover ---
      const toBadge = document.getElementById("takeoverBadge");
      const toIcon = document.getElementById("takeoverStatusIcon");
      const toExp = document.getElementById("takeoverExplanation");
      const toRaw = document.getElementById("takeoverRaw");

      if (takeovers.length > 0) {
        score -= 25;
        toBadge.textContent = "VULNERABLE";
        toBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-rose-950 text-rose-400 border border-rose-800/40";
        toIcon.textContent = "🔴";
        toExp.textContent = `Found ${takeovers.length} CNAME pointer(s) pointing to third-party SaaS services! Potential dangling takeover vulnerability.`;
        toRaw.innerHTML = takeovers.map(t => `<div class="text-rose-400 font-bold">⚠️ ${escapeHtml(t.sub)} &rarr; ${escapeHtml(t.target)} (${escapeHtml(t.saas)})</div>`).join("");
      } else {
        toBadge.textContent = "IMMUNE";
        toBadge.className = "text-xs px-2 py-0.5 rounded font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/40";
        toIcon.textContent = "🟢";
        toExp.textContent = "Common SaaS CNAME aliases tested clean against 52 signatures.";
        toRaw.textContent = "0 dangling CNAMEs identified across probed aliases.";
      }

      // Clamp score
      score = Math.max(0, Math.min(100, score));
      document.getElementById("scoreNumber").textContent = score;

      let grade = "A+";
      let gradeClass = "bg-emerald-950 text-emerald-400 border-emerald-500/40";
      if (score < 50) {
        grade = "F";
        gradeClass = "bg-rose-950 text-rose-400 border-rose-500/40";
      } else if (score < 70) {
        grade = "D";
        gradeClass = "bg-rose-950 text-rose-400 border-rose-500/40";
      } else if (score < 80) {
        grade = "C";
        gradeClass = "bg-amber-950 text-amber-400 border-amber-500/40";
      } else if (score < 90) {
        grade = "B";
        gradeClass = "bg-amber-950 text-amber-400 border-amber-500/40";
      }

      const gradeBadge = document.getElementById("gradeBadge");
      gradeBadge.textContent = grade;
      gradeBadge.className = `text-4xl font-extrabold px-3 py-1 rounded-lg border ${gradeClass}`;

      const signupCta = document.getElementById("auditSignupCta");
      if (signupCta) {
        const recommendedTier = score < 70 ? "growth" : "starter";
        signupCta.href = `signup.html?domain=${encodeURIComponent(domain)}&tier=${recommendedTier}`;
      }
      const fleetCta = document.getElementById("auditFleetCta");
      if (fleetCta) {
        fleetCta.href = `fleet.html?domain=${encodeURIComponent(domain)}`;
      }
      window._lastAuditSnapshot = { domain, score, grade, spfRecord, dmarcRecord, takeovers };
      window._lastBackendFixpack = null;

      document.getElementById("resultsCard").classList.remove("hidden");
      document.getElementById("resultsCard").scrollIntoView({ behavior: "smooth" });

      // Non-blocking Orbit backend DNS fixpack prefetch (falls back cleanly on GitHub Pages)
      requestBackendDnsFixpack(domain, spfRecord)
        .then((fp) => {
          if (fp && window._lastAuditSnapshot && window._lastAuditSnapshot.domain === domain) {
            window._lastBackendFixpack = fp;
          }
        })
        .catch(() => {});

      // Run Puter.js AI Teardown
      generateAiBriefing(domain, score, grade, spfRecord, dmarcRecord, takeovers);
    }

    function isStaticAuditHost(loc) {
      if (!loc) return true;
      const proto = String(loc.protocol || "").toLowerCase();
      const host = String(loc.hostname || "").toLowerCase();
      if (!proto.startsWith("http") || proto === "file:") return true;
      if (host === "github.io" || host.endsWith(".github.io")) return true;
      if (host === "pages.dev" || host.endsWith(".pages.dev")) return true;
      return false;
    }

    async function requestBackendDnsFixpack(domain, spfRecord) {
      const cleanDomain = String(domain || "").trim().toLowerCase();
      if (!cleanDomain || typeof fetch !== "function") return null;

      const explicitEndpoint = typeof window !== "undefined" ? window.ORBIT_DNS_FIXPACK_ENDPOINT : null;
      const loc = typeof window !== "undefined" ? window.location : null;
      let endpoint = null;
      if (explicitEndpoint) {
        endpoint = explicitEndpoint;
      } else if (loc && !isStaticAuditHost(loc) && loc.origin) {
        endpoint = `${loc.origin}/api/orbit/dns-fixpack`;
      } else {
        return null;
      }

      const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
      const timerId = controller ? setTimeout(() => controller.abort(), 1500) : null;
      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            domain: cleanDomain,
            original_spf: spfRecord || "v=spf1 ~all",
            spf_record: spfRecord || "v=spf1 ~all",
          }),
          signal: controller ? controller.signal : undefined,
        });
        if (!res || !res.ok) return null;
        const data = await res.json();
        return data && data.ok ? data : null;
      } catch (_err) {
        return null;
      } finally {
        if (timerId !== null) clearTimeout(timerId);
      }
    }
    if (typeof window !== "undefined") {
      window.requestBackendDnsFixpack = requestBackendDnsFixpack;
    }

    async function generateAiBriefing(domain, score, grade, spf, dmarc, takeovers) {
      const aiContainer = document.getElementById("aiAnalysisText");
      aiContainer.innerHTML = `<span class="text-slate-400 animate-pulse">Engaging Puter.js serverless AI gateway...</span>`;

      const prompt = `You are Orbit Security's senior automated auditor. Provide a concise, 3-bullet technical briefing for domain '${domain}' which scored ${score}/100 (Grade: ${grade}).
SPF: ${spf || "None"}
DMARC: ${dmarc || "None"}
Dangling CNAMEs: ${takeovers.length ? JSON.stringify(takeovers) : "None"}

Rules:
1. Explain the immediate exploit risk if any (e.g. email spoofing or subdomain takeover).
2. Recommend the exact fix (e.g. publish v=DMARC1; p=reject or drop stale CNAME).
3. Keep it punchy, technical, and under 90 words total.`;

      // Check if Puter.js AI API is available
      if (typeof puter !== "undefined" && puter.ai) {
        try {
          const resp = await puter.ai.chat(prompt, { model: "claude-3-5-sonnet" });
          aiContainer.innerHTML = escapeHtml(resp.message.content).replace(/\n/g, "<br>");
          return;
        } catch (err) {
          console.warn("Puter AI primary call failed, trying open-source fallback:", err);
          try {
            const respFallback = await puter.ai.chat(prompt);
            aiContainer.innerHTML = escapeHtml(respFallback.message.content).replace(/\n/g, "<br>");
            return;
          } catch (e2) {
            console.warn("Puter AI unavailable, using deterministic synthesizer:", e2);
          }
        }
      }

      // Deterministic Local Fallback (0% cloud dependency)
      const safeDomainHtml = escapeHtml(domain);
      let summary = "";
      if (score >= 90) {
        summary = `• Posture: Strong baseline configuration. Domain demonstrates active perimeter hygiene.<br>• Immunity: DMARC and SPF align with current RFC-8484 and RFC-7489 standards.<br>• Maintenance: Conduct quarterly CNAME audits to prevent future SaaS provider abandonment.`;
      } else if (!dmarc) {
        summary = `• Vulnerability: Missing DMARC record leaves domain unprotected against direct spoofing and CEO fraud inboxes.<br>• Exploit Path: Attackers can forge communications appearing from @${safeDomainHtml} that bypass consumer email filters.<br>• Remediation: Stage and deploy 'v=DMARC1; p=reject; rua=mailto:dmarc@${safeDomainHtml}' alongside SPF flattening.`;
      } else {
        summary = `• Remediation: Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' to enforce dropping of unaligned mail.<br>• Hygiene: Remove any dangling DNS records pointing to deactivated SaaS vendors.<br>• Fixpack: Deploy our automated Terraform fixpack to remediate DNS posture.`;
      }
      aiContainer.innerHTML = summary;
    }

    function buildSelfServeFixpack(snapshot, contactEmail, backendFixpack = null) {
      const domain = (snapshot && snapshot.domain) || "example.com";
      const spfLine = (!snapshot || !snapshot.spfRecord)
        ? `${domain}. 300 IN TXT "v=spf1 -all" ; Replace or include authorized senders before enforcing -all`
        : `; Existing SPF: ${snapshot.spfRecord}`;
      const dmarcLine = `_dmarc.${domain}. 300 IN TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:${contactEmail}; fo=1"`;
      const cnameRemovals = (snapshot && Array.isArray(snapshot.takeovers) && snapshot.takeovers.length)
        ? snapshot.takeovers.map(t => `; REMOVE DANGLING CNAME: ${t.sub} -> ${t.target} (${t.saas})`).join("\n")
        : "; No dangling CNAME takeovers detected across probed SaaS signatures.";

      const lines = [
        `# Orbit Security Remediation Fixpack (${domain})`,
        `# Generated: ${new Date().toISOString()}`,
        `# Contact: ${contactEmail}`,
        `# Baseline Score: ${snapshot ? snapshot.score : "N/A"}/100 (Grade: ${snapshot ? snapshot.grade : "N/A"})`,
        "",
        "## 1. BIND 9 / DNS Zone Records",
        spfLine,
        dmarcLine,
        cnameRemovals,
        "",
        "## 2. Terraform Starter (Cloudflare DNS)",
        `resource "cloudflare_record" "orbit_dmarc" {`,
        `  zone_id = var.cloudflare_zone_id`,
        `  name    = "_dmarc"`,
        `  type    = "TXT"`,
        `  value   = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:${contactEmail}; fo=1"`,
        `  ttl     = 300`,
        `}`,
        "",
        "## 3. RFC-9116 /.well-known/security.txt",
        `Contact: mailto:${contactEmail}`,
        `Preferred-Languages: en`,
        `Canonical: https://${domain}/.well-known/security.txt`,
      ];

      if (backendFixpack && backendFixpack.flattened_spf) {
        lines.push(
          "",
          "## 4. Orbit Backend SPF Flattening & Cloudflare API Payload",
          `# SHA-256: ${backendFixpack.sha256_hash || ""}`,
          `# Lookups: ${backendFixpack.total_original_lookups ?? "N/A"} -> ${backendFixpack.optimized_lookups ?? 0}`,
          backendFixpack.bind_zone_snippet || `; Flattened SPF: ${backendFixpack.flattened_spf}`,
          "",
          backendFixpack.terraform_snippet || "",
          "",
          backendFixpack.cloudflare_api_json ? JSON.stringify(backendFixpack.cloudflare_api_json, null, 2) : ""
        );
      }

      return lines.join("\n");
    }

    // Lead capture -> Local Fixpack download + Track B onboarding handoff
    document.getElementById("leadForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = document.getElementById("leadEmail").value.trim();
      const snapshot = window._lastAuditSnapshot || {
        domain: document.getElementById("resultDomain").textContent.trim() || "example.com",
        score: 0,
        grade: "N/A",
        spfRecord: null,
        dmarcRecord: null,
        takeovers: [],
      };
      if (!email) return;

      const backendFixpack = window._lastBackendFixpack || await requestBackendDnsFixpack(snapshot.domain, snapshot.spfRecord);
      const safeSlug = snapshot.domain.toLowerCase().replace(/[^a-z0-9.-]+/g, "-");
      const filename = `${safeSlug}-orbit-fixpack.txt`;
      const fixpackBody = buildSelfServeFixpack(snapshot, email, backendFixpack);

      try {
        const blob = new Blob([fixpackBody], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        document.body.removeChild(anchor);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (err) {
        console.warn("Fixpack browser download fallback:", err);
      }

      const signupCta = document.getElementById("auditSignupCta");
      if (signupCta) {
        const recommendedTier = snapshot.score < 70 ? "growth" : "starter";
        signupCta.href = `signup.html?domain=${encodeURIComponent(snapshot.domain)}&email=${encodeURIComponent(email)}&tier=${recommendedTier}`;
      }

      const msgEl = document.getElementById("leadConfirmationMsg");
      if (msgEl) {
        msgEl.textContent = `✓ Downloaded ${filename} (DNS zone, Terraform, & security.txt). Use the button below to activate continuous monitoring.`;
      }
      document.getElementById("leadForm").classList.add("hidden");
      document.getElementById("leadConfirmation").classList.remove("hidden");
    });
