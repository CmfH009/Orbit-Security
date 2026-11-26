const STRIPE_LINKS = {
            'Starter': 'https://buy.stripe.com/8x29ASgAk3V15X2el6cs801',
            'Growth': 'https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800',
            'Scale': 'https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800',
            'Pro': 'https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802',
            'Enterprise': 'https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802'
        };

        const STRIPE_LINKS_NORMALIZED = {
            'starter': STRIPE_LINKS.Starter,
            'growth': STRIPE_LINKS.Growth,
            'scale': STRIPE_LINKS.Scale,
            'pro': STRIPE_LINKS.Pro,
            'enterprise': STRIPE_LINKS.Enterprise
        };

        let selectedTierValue = 'Scale';

        function resolveStripePaymentLink(tierName) {
            const key = String(tierName || '').trim().toLowerCase();
            return STRIPE_LINKS_NORMALIZED[key] || STRIPE_LINKS.Scale;
        }

        function getSelectedTierValue() {
            if (typeof document !== 'undefined') {
                const checked = document.querySelector('input[name="tier"]:checked');
                if (checked && checked.value) {
                    selectedTierValue = checked.value;
                    return checked.value;
                }
            }
            return selectedTierValue || 'Scale';
        }

        function buildStripePaymentLinkUrl(tierName, clientRefId, email) {
            const url = new URL(resolveStripePaymentLink(tierName));
            const cleanEmail = String(email || '').trim();
            const cleanRef = String(clientRefId || '').trim();
            if (cleanEmail) {
                url.searchParams.set('prefilled_email', cleanEmail);
            }
            if (cleanRef) {
                url.searchParams.set('client_reference_id', cleanRef);
            }
            return url.toString();
        }

        function isStaticHostEnvironment(loc) {
            const target = loc || (typeof window !== 'undefined' ? window.location : null);
            if (!target) return true;
            const proto = String(target.protocol || '').toLowerCase();
            const host = String(target.hostname || '').toLowerCase();
            if (proto === 'file:') return true;
            if (host === 'github.io' || host.endsWith('.github.io')) return true;
            if (host === 'pages.dev' || host.endsWith('.pages.dev')) return true;
            return false;
        }

        function selectTier(tierName, index) {
            selectedTierValue = tierName;
            const tiles = document.querySelectorAll('.tier-tile');
            const radios = document.querySelectorAll('input[name="tier"]');
            tiles.forEach((t, i) => {
                t.classList.remove('selected', 'border-emerald-500');
                if (i === index) {
                    t.classList.add('selected', 'border-emerald-500');
                }
            });
            radios.forEach((r, i) => {
                r.checked = i === index;
            });
        }

        // URL Query Parameter Tier Selection & Self-Serve Prefill
        (function checkUrlTier() {
            try {
                const params = new URLSearchParams(window.location.search);
                const tierParam = (params.get('tier') || '').toLowerCase();
                if (tierParam === 'starter') {
                    selectTier('Starter', 0);
                } else if (tierParam === 'growth' || tierParam === 'scale') {
                    selectTier('Scale', 1);
                } else if (tierParam === 'pro' || tierParam === 'enterprise') {
                    selectTier('Enterprise', 2);
                }

                const emailParam = (params.get('email') || '').trim();
                if (emailParam) {
                    const emailEl = document.getElementById('contact_email');
                    const supportEl = document.getElementById('support_email');
                    if (emailEl) emailEl.value = emailParam;
                    if (supportEl && !supportEl.value) {
                        supportEl.value = emailParam;
                    }
                }

                const domainRaw = (params.get('domain') || '').trim();
                const agencyParam = (params.get('agency') || '').trim();
                const cleanDomain = domainRaw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
                if (cleanDomain) {
                    const siteEl = document.getElementById('website');
                    const customDomainEl = document.getElementById('custom_domain');
                    if (siteEl) siteEl.value = `https://${cleanDomain}`;
                    if (customDomainEl && !customDomainEl.value) {
                        customDomainEl.value = `security.${cleanDomain}`;
                    }
                    const derivedSlug = cleanDomain.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
                    const idEl = document.getElementById('agency_id');
                    const nameEl = document.getElementById('agency_name');
                    if (idEl && !idEl.value && derivedSlug) {
                        idEl.value = derivedSlug;
                    }
                    if (nameEl && !nameEl.value && !agencyParam) {
                        nameEl.value = cleanDomain;
                    }
                }
                if (agencyParam) {
                    const nameEl = document.getElementById('agency_name');
                    const idEl = document.getElementById('agency_id');
                    const derivedSlug = agencyParam.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
                    if (nameEl) nameEl.value = agencyParam;
                    if (idEl && !idEl.value && derivedSlug) {
                        idEl.value = derivedSlug;
                    }
                }
            } catch (err) {}
        })();

        // Dual-mode gateway handler
        const isStaticHost = isStaticHostEnvironment(typeof window !== 'undefined' ? window.location : null);
        if (isStaticHost && typeof document !== 'undefined') {
            const notice = document.getElementById('envNotice');
            if (notice) notice.classList.remove('hidden');
        }

        async function computeClientReferenceId(agencySlug, email) {
            const cleanSlug = (agencySlug || '')
                .toLowerCase()
                .replace(/[^a-z0-9_-]/g, '-')
                .replace(/^[-_]+|[-_]+$/g, '')
                .slice(0, 40) || 'agency';
            const seed = `${cleanSlug}:${(email || '').trim().toLowerCase()}`;
            try {
                if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle && typeof TextEncoder !== 'undefined') {
                    const buf = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(seed));
                    const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
                    return `${cleanSlug}-${hex.slice(0, 8)}`;
                }
            } catch (_) {}
            let h = 2166136261;
            for (let i = 0; i < seed.length; i++) {
                h ^= seed.charCodeAt(i);
                h = Math.imul(h, 16777619);
            }
            return `${cleanSlug}-${(h >>> 0).toString(16).padStart(8, '0')}`;
        }

        function getOnboardingEndpoints() {
            const endpoints = [];
            if (typeof window !== 'undefined' && window.ORBIT_ONBOARDING_ENDPOINT) {
                endpoints.push(window.ORBIT_ONBOARDING_ENDPOINT);
            }
            if (typeof window !== 'undefined' && window.location && window.location.protocol && window.location.protocol.startsWith('http') && !isStaticHostEnvironment(window.location)) {
                endpoints.push(`${window.location.origin}/api/orbit/onboarding`);
            }
            endpoints.push(
                'https://orbit-security-api-911438991206.us-central1.run.app/api/orbit/onboarding',
                'https://orbit-security-api-911438991206.us-central1.run.app/api/orbit/radar/telemetry',
                'http://127.0.0.1:9090/api/orbit/onboarding',
                'http://127.0.0.1:9095/api/orbit/onboarding'
            );
            return endpoints;
        }

        async function dispatchAgencyOnboarding(formData, opts) {
            if (opts && opts.skipTelemetry) return;
            const jsonStr = JSON.stringify(formData);
            const endpoints = getOnboardingEndpoints();
            const requests = endpoints.map(url => {
                try {
                    if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
                        try {
                            const blob = new Blob([jsonStr], { type: 'application/json' });
                            navigator.sendBeacon(url, blob);
                        } catch (_) {}
                    }
                    if (typeof fetch === 'function') {
                        return fetch(url, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonStr,
                            mode: 'cors',
                            keepalive: true
                        }).catch(() => null);
                    }
                } catch (_) {}
                return Promise.resolve(null);
            });
            await Promise.race([
                Promise.allSettled(requests),
                new Promise(resolve => setTimeout(resolve, 650))
            ]);
        }

        function navigateToCheckout(url, navigatorFn) {
            if (typeof navigatorFn === 'function') {
                return navigatorFn(url);
            }
            if (typeof window !== 'undefined' && typeof window.__orbitNavigate === 'function') {
                return window.__orbitNavigate(url);
            }
            window.location.href = url;
            return url;
        }

        function buildFormEncodedPayload(form, formData) {
            const params = new URLSearchParams();
            if (form && typeof FormData !== 'undefined') {
                try {
                    const raw = new FormData(form);
                    for (const [k, v] of raw.entries()) {
                        params.set(k, String(v));
                    }
                } catch (_) {}
            }
            if (formData) {
                const fields = [
                    'client_reference_id',
                    'agency_id',
                    'agency_name',
                    'contact_email',
                    'website',
                    'tier',
                    'custom_domain',
                    'support_email',
                    'tagline',
                    'primary_color',
                    'accent_color'
                ];
                fields.forEach(key => {
                    if (formData[key] !== undefined && formData[key] !== null) {
                        params.set(key, String(formData[key]));
                    }
                });
            }
            return params.toString();
        }

        function isFallbackCheckoutStatus(res) {
            if (!res) return true;
            if (res.type === 'error') return true;
            return res.status === 404 || res.status === 405 || res.status === 501;
        }

        async function submitSignupCheckout(e, options) {
            if (e && typeof e.preventDefault === 'function') {
                e.preventDefault();
            }
            const opts = options || {};
            const form = opts.form || (typeof document !== 'undefined' ? document.getElementById('signupForm') : null);
            const readField = (id, fallback) => {
                if (opts.formValues && Object.prototype.hasOwnProperty.call(opts.formValues, id)) {
                    return String(opts.formValues[id] || '').trim();
                }
                if (typeof document !== 'undefined') {
                    const el = document.getElementById(id);
                    if (el && typeof el.value === 'string') return el.value.trim();
                }
                return fallback || '';
            };

            const agencySlug = readField('agency_id', '');
            const email = readField('contact_email', '');
            const activeTier = (opts.formValues && opts.formValues.tier) || getSelectedTierValue();
            const clientRefId = await computeClientReferenceId(agencySlug, email);

            if (typeof document !== 'undefined') {
                const refInput = document.getElementById('client_reference_id');
                if (refInput) refInput.value = clientRefId;
            }

            const formData = {
                event: 'AGENCY_ONBOARDING',
                client_reference_id: clientRefId,
                agency_id: agencySlug,
                agency_name: readField('agency_name', ''),
                contact_email: email,
                website: readField('website', ''),
                tier: activeTier,
                custom_domain: readField('custom_domain', ''),
                support_email: readField('support_email', ''),
                tagline: readField('tagline', ''),
                primary_color: readField('primary_color', '#0B132B'),
                accent_color: readField('accent_color', '#10B981'),
                saved_at: new Date().toISOString()
            };

            try {
                if (typeof localStorage !== 'undefined' && localStorage.setItem) {
                    localStorage.setItem('orbit_agency_onboarding', JSON.stringify(formData));
                }
            } catch (err) {}

            const submitBtn = typeof document !== 'undefined' ? document.getElementById('submitBtn') : null;
            const submitLabel = typeof document !== 'undefined' ? document.getElementById('submitBtnLabel') : null;
            const origLabel = submitLabel ? submitLabel.textContent : '';
            if (submitBtn) submitBtn.disabled = true;
            if (submitLabel) submitLabel.textContent = 'Connecting to Stripe Checkout...';

            const resetButton = () => {
                if (submitBtn) submitBtn.disabled = false;
                if (submitLabel && origLabel) submitLabel.textContent = origLabel;
            };

            const revealStaticNotice = () => {
                if (typeof document !== 'undefined') {
                    const notice = document.getElementById('envNotice');
                    if (notice) notice.classList.remove('hidden');
                }
            };

            const loc = opts.location || (typeof window !== 'undefined' ? window.location : null);
            const forceApiProbe = Boolean(opts.forceApiProbe);
            if (!forceApiProbe && isStaticHostEnvironment(loc)) {
                try {
                    revealStaticNotice();
                    await dispatchAgencyOnboarding(formData, opts);
                    const targetUrl = buildStripePaymentLinkUrl(activeTier, clientRefId, email);
                    navigateToCheckout(targetUrl, opts.navigate);
                    return {
                        mode: 'payment_link_static',
                        url: targetUrl,
                        client_reference_id: clientRefId,
                        tier: activeTier
                    };
                } finally {
                    resetButton();
                }
            }

            const fetchFn = opts.fetchFn || (typeof fetch === 'function' ? fetch : null);
            const checkoutAction = (form && typeof form.getAttribute === 'function' && form.getAttribute('action')) || '/create-checkout-session';

            if (!fetchFn) {
                try {
                    revealStaticNotice();
                    await dispatchAgencyOnboarding(formData, opts);
                    const targetUrl = buildStripePaymentLinkUrl(activeTier, clientRefId, email);
                    navigateToCheckout(targetUrl, opts.navigate);
                    return {
                        mode: 'payment_link_static',
                        url: targetUrl,
                        client_reference_id: clientRefId,
                        tier: activeTier
                    };
                } finally {
                    resetButton();
                }
            }

            const onboardingPromise = dispatchAgencyOnboarding(formData, opts);
            let timerId = null;
            try {
                const fetchInit = {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: buildFormEncodedPayload(form, formData),
                    redirect: 'manual'
                };
                if (typeof AbortController !== 'undefined') {
                    const controller = new AbortController();
                    fetchInit.signal = controller.signal;
                    timerId = setTimeout(() => controller.abort(), 5000);
                }
                const res = await fetchFn(checkoutAction, fetchInit);
                if (timerId) clearTimeout(timerId);

                if (isFallbackCheckoutStatus(res)) {
                    await onboardingPromise;
                    revealStaticNotice();
                    const targetUrl = buildStripePaymentLinkUrl(activeTier, clientRefId, email);
                    navigateToCheckout(targetUrl, opts.navigate);
                    resetButton();
                    return {
                        mode: 'payment_link_fallback',
                        status: res ? res.status : 0,
                        url: targetUrl,
                        client_reference_id: clientRefId,
                        tier: activeTier
                    };
                }

                const redirectLoc = res.headers && typeof res.headers.get === 'function' ? res.headers.get('Location') : null;
                if (redirectLoc && ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect')) {
                    await onboardingPromise;
                    navigateToCheckout(redirectLoc, opts.navigate);
                    resetButton();
                    return {
                        mode: 'api_redirect',
                        status: res.status,
                        url: redirectLoc,
                        client_reference_id: clientRefId,
                        tier: activeTier
                    };
                }

                if (res.ok) {
                    const ct = (res.headers && typeof res.headers.get === 'function' ? res.headers.get('content-type') : '') || '';
                    if (ct.toLowerCase().includes('application/json') && typeof res.json === 'function') {
                        const payload = await res.json();
                        const apiUrl = payload && (payload.url || payload.checkout_url);
                        if (apiUrl) {
                            await onboardingPromise;
                            navigateToCheckout(apiUrl, opts.navigate);
                            resetButton();
                            return {
                                mode: 'api_json',
                                status: res.status,
                                url: apiUrl,
                                client_reference_id: clientRefId,
                                tier: activeTier
                            };
                        }
                    }
                    if (res.url && /^https:\/\/(?:checkout|buy)\.stripe\.com\//i.test(res.url)) {
                        await onboardingPromise;
                        navigateToCheckout(res.url, opts.navigate);
                        resetButton();
                        return {
                            mode: 'api_redirect',
                            status: res.status,
                            url: res.url,
                            client_reference_id: clientRefId,
                            tier: activeTier
                        };
                    }
                }

                // Live backend API returned opaqueredirect (302 without JS-readable Location), 400 validation, or 502 error:
                // preserve native API checkout submission behavior.
                await onboardingPromise;
                if (typeof opts.nativeSubmit === 'function') {
                    opts.nativeSubmit(form);
                } else if (form && typeof HTMLFormElement !== 'undefined' && HTMLFormElement.prototype && typeof HTMLFormElement.prototype.submit === 'function') {
                    HTMLFormElement.prototype.submit.call(form);
                } else if (form && typeof form.submit === 'function') {
                    form.submit();
                }
                resetButton();
                return {
                    mode: 'api_native_submit',
                    status: res.status,
                    opaqueredirect: res.type === 'opaqueredirect',
                    client_reference_id: clientRefId,
                    tier: activeTier
                };
            } catch (err) {
                if (timerId) clearTimeout(timerId);
                await onboardingPromise;
                revealStaticNotice();
                const targetUrl = buildStripePaymentLinkUrl(activeTier, clientRefId, email);
                navigateToCheckout(targetUrl, opts.navigate);
                resetButton();
                return {
                    mode: 'payment_link_network_fallback',
                    error: err && err.message ? err.message : 'network_error',
                    url: targetUrl,
                    client_reference_id: clientRefId,
                    tier: activeTier
                };
            }
        }

        if (typeof document !== 'undefined') {
            const signupFormEl = document.getElementById('signupForm');
            if (signupFormEl) {
                signupFormEl.addEventListener('submit', submitSignupCheckout);
            }
            const mBtn = document.getElementById('signupMobileMenuBtn');
            const mMenu = document.getElementById('signupMobileMenu');
            if (mBtn && mMenu) {
                mBtn.addEventListener('click', () => {
                    const isHidden = mMenu.classList.toggle('hidden');
                    mBtn.setAttribute('aria-expanded', isHidden ? 'false' : 'true');
                });
            }
        }

        if (typeof window !== 'undefined') {
            window.OrbitSignupCheckout = {
                STRIPE_LINKS,
                resolveStripePaymentLink,
                getSelectedTierValue,
                buildStripePaymentLinkUrl,
                isStaticHostEnvironment,
                isFallbackCheckoutStatus,
                computeClientReferenceId,
                submitSignupCheckout
            };
        }

        if (typeof document !== 'undefined' && typeof document.addEventListener === 'function' && !window.__orbitSignupDelegationBound) {
            window.__orbitSignupDelegationBound = true;
            document.addEventListener('click', (e) => {
                const el = e.target && e.target.closest ? e.target.closest('[data-signup-action="select-tier"]') : null;
                if (el && typeof selectTier === 'function') {
                    selectTier(el.dataset.tier, parseInt(el.dataset.idx, 10));
                }
            });
        }
