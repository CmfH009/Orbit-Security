#!/usr/bin/env python3
"""orbit_security.radar_lead_enricher: Background OSINT & Lead Enrichment Engine.
=================================================================================
Automatically enriches domains probed in the ORBIT // PERIMETER RADAR TERMINAL by:
1. Running `orbit.recon.public_apis_osint` (`PublicApisOsintBridge` / `PublicAPIsIntelHarvester`)
   to correlate the target against 1,400+ public APIs and security/OSINT endpoints.
2. Fingerprinting the target's Tech Stack (Shopify, Cloudflare, WordPress, Next.js,
   Vercel, Webflow, AWS, Stripe, etc.) via DNS TXT/CNAME/NS records and HTTP headers.
3. Identifying Domain Registrar & Nameserver infrastructure via RDAP (`rdap.org`)
   and authoritative NS inspection.
4. Resolving Company Profile (`company_name`, page `<title>`, meta description,
   MX mail provider, and executive leadership via `ExecutiveOSINTVerifier`).
5. Computing server-side passive DMARC/SPF hygiene score & grade when client
   beacons arrive from pre-scan `radar_submit` triggers.
"""

from __future__ import annotations

import datetime
import html as html_mod
import json
import logging
from pathlib import Path
import re
import threading
from typing import Any, Dict, List, Optional, Set
import urllib.parse
import urllib.request

from orbit_security.osint_verifier import ExecutiveOSINTVerifier
from orbit_security.recon_harvester import PublicAPIsIntelHarvester
from orbit_security.scanner import is_safe_host

logger = logging.getLogger("orbit_security.radar_lead_enricher")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"
DEFAULT_ENRICHED_LEADS_FILE = DATA_DIR / "radar_enriched_leads.json"


def _humanize_domain_brand(domain: str) -> str:
    """Derives a clean company/brand name from an apex domain (e.g. smartmouseco.com -> Smart Mouse Co)."""
    stem = (domain or "").strip().lower().split(".")[0]
    stem = re.sub(r"[-_]+", " ", stem)
    # Split common suffixes like 'co', 'inc', 'labs', 'tech', 'agency', 'studio', 'shop', 'mouse', 'smart'
    stem = re.sub(
        r"(smart|mouse|agency|studio|labs|tech|digital|media|cloud|cyber|security|web|shop|store|co|inc|hq|group)$",
        r" \1",
        stem,
    )
    stem = re.sub(
        r"^(smart|mouse|cyber|orbit|apex|global|prime|next|bright|blue|red|green)(?=[a-z]{3,})",
        r"\1 ",
        stem,
    )
    words = [w.capitalize() for w in stem.split() if w]
    return " ".join(words) if words else domain


class RadarLeadEnricher:
    """Passive OSINT and infrastructure enrichment engine for inbound radar probes."""

    def __init__(
        self,
        leads_file: Optional[Path] = None,
        db_path: Optional[Path] = None,
        timeout: float = 3.5,
    ):
        self.leads_file = Path(leads_file) if leads_file else DEFAULT_ENRICHED_LEADS_FILE
        self.leads_file.parent.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self._lock = threading.Lock()
        self.osint_harvester = PublicAPIsIntelHarvester(db_path=db_path)
        self.leadership_verifier = ExecutiveOSINTVerifier()

    def _query_doh_txt_or_ns(self, name: str, record_type: str = "TXT") -> List[str]:
        """Queries Google DNS-over-HTTPS (RFC 8484) for fast non-blocking DNS record inspection."""
        url = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={record_type}"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": "OrbitRadarEnricher/1.0"},
        )
        records: List[str] = []
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for ans in data.get("Answer") or []:
                        raw = str(ans.get("data") or "").strip().strip('"')
                        if raw:
                            records.append(raw)
        except Exception as ex:
            logger.debug("DoH query (%s %s) skipped: %s", name, record_type, ex)
        return records

    def _lookup_rdap_registrar(self, domain: str, nameservers: List[str]) -> str:
        """Queries RDAP for domain registrar with nameserver-based heuristic fallback."""
        rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
        req = urllib.request.Request(
            rdap_url,
            headers={"Accept": "application/rdap+json", "User-Agent": "OrbitRadarEnricher/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for entity in data.get("entities") or []:
                        roles = [str(r).lower() for r in (entity.get("roles") or [])]
                        if "registrar" in roles:
                            vcard = entity.get("vcardArray")
                            if isinstance(vcard, list) and len(vcard) > 1:
                                for item in vcard[1]:
                                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                                        fn_val = str(item[3]).strip()
                                        if fn_val:
                                            return fn_val
        except Exception as ex:
            logger.debug("RDAP lookup skipped for %s: %s", domain, ex)

        # Fallback: infer from nameservers
        ns_joined = " ".join(nameservers).lower()
        if "cloudflare.com" in ns_joined:
            return "Cloudflare, Inc. (inferred via NS)"
        if "awsdns" in ns_joined:
            return "Amazon Registrar / AWS Route 53"
        if "domaincontrol.com" in ns_joined:
            return "GoDaddy.com, LLC"
        if "registrar-servers.com" in ns_joined:
            return "Namecheap, Inc."
        if "googledomains.com" in ns_joined or "googledns.com" in ns_joined:
            return "Google Domains / Cloud DNS"
        if "squarespacedns.com" in ns_joined:
            return "Squarespace Domains LLC"
        if "wixdns.net" in ns_joined:
            return "Wix.com Ltd."
        if "digitalocean.com" in ns_joined:
            return "DigitalOcean DNS"
        return "Unlisted / Private WHOIS"

    @staticmethod
    def _infer_dns_provider(nameservers: List[str]) -> str:
        ns_joined = " ".join(nameservers).lower()
        if "cloudflare.com" in ns_joined:
            return "Cloudflare"
        if "awsdns" in ns_joined:
            return "AWS Route 53"
        if "domaincontrol.com" in ns_joined:
            return "GoDaddy DNS"
        if "registrar-servers.com" in ns_joined:
            return "Namecheap DNS"
        if "googledomains.com" in ns_joined or "ns-cloud" in ns_joined:
            return "Google Cloud DNS"
        if "digitalocean.com" in ns_joined:
            return "DigitalOcean"
        if "squarespacedns.com" in ns_joined:
            return "Squarespace DNS"
        if "azure-dns" in ns_joined:
            return "Azure DNS"
        return nameservers[0] if nameservers else "Standard Authoritative DNS"

    @staticmethod
    def _infer_mx_provider(mx_records: List[str]) -> str:
        mx_joined = " ".join(mx_records).lower()
        if "google.com" in mx_joined or "googlemail.com" in mx_joined or "aspmx.l.google.com" in mx_joined:
            return "Google Workspace"
        if "outlook.com" in mx_joined or "protection.outlook.com" in mx_joined:
            return "Microsoft 365"
        if "protonmail.ch" in mx_joined or "proton.ch" in mx_joined:
            return "ProtonMail"
        if "mimecast.com" in mx_joined:
            return "Mimecast"
        if "pphosted.com" in mx_joined:
            return "Proofpoint"
        if "zoho.com" in mx_joined:
            return "Zoho Mail"
        if "secureserver.net" in mx_joined:
            return "GoDaddy Workspace Mail"
        if "cloudflare.net" in mx_joined:
            return "Cloudflare Email Routing"
        return mx_records[0] if mx_records else "No MX Configured"

    def _probe_http_profile_and_stack(self, domain: str) -> Dict[str, Any]:
        """Fetches homepage headers and meta tags (SSRF-guarded) to fingerprint tech stack and company profile."""
        info: Dict[str, Any] = {
            "tech_signals": [],
            "title": "",
            "site_name": "",
            "description": "",
            "http_server": "",
        }
        if not is_safe_host(domain):
            return info

        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity-OSINT/1.0",
                    "Accept": "text/html,application/xhtml+xml",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    raw_html = resp.read(65536).decode("utf-8", errors="ignore")

                    stack: Set[str] = set()
                    server = headers.get("server", "")
                    info["http_server"] = server
                    powered = headers.get("x-powered-by", "")

                    if "cloudflare" in server.lower() or "cf-ray" in headers:
                        stack.add("Cloudflare")
                    if "x-shopify-stage" in headers or "myshopify.com" in raw_html.lower() or "cdn.shopify.com" in raw_html.lower():
                        stack.add("Shopify")
                    if "x-vercel-id" in headers or "vercel" in server.lower():
                        stack.add("Vercel")
                    if "x-nf-request-id" in headers or "netlify" in server.lower():
                        stack.add("Netlify")
                    if "wp-content" in raw_html.lower() or "wordpress" in powered.lower():
                        stack.add("WordPress")
                    if "webflow" in raw_html.lower():
                        stack.add("Webflow")
                    if "squarespace" in raw_html.lower() or "squarespace" in server.lower():
                        stack.add("Squarespace")
                    if "_next/static" in raw_html.lower() or "nextjs" in powered.lower():
                        stack.add("Next.js")
                    if "klaviyo" in raw_html.lower():
                        stack.add("Klaviyo")
                    if "js.stripe.com" in raw_html.lower():
                        stack.add("Stripe")
                    if "googletagmanager.com" in raw_html.lower():
                        stack.add("Google Tag Manager")
                    if "nginx" in server.lower():
                        stack.add("Nginx")
                    if "amazonaws.com" in raw_html.lower() or "cloudfront" in headers.get("via", "").lower():
                        stack.add("AWS CloudFront")

                    info["tech_signals"] = sorted(stack)

                    title_m = re.search(r"<title[^>]*>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
                    if title_m:
                        clean_title = re.sub(r"\s+", " ", html_mod.unescape(title_m.group(1))).strip()
                        info["title"] = clean_title[:140]

                    og_m = re.search(
                        r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)["\']',
                        raw_html,
                        re.IGNORECASE,
                    )
                    if og_m:
                        info["site_name"] = html_mod.unescape(og_m.group(1)).strip()[:80]

                    desc_m = re.search(
                        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
                        raw_html,
                        re.IGNORECASE,
                    )
                    if desc_m:
                        info["description"] = re.sub(r"\s+", " ", html_mod.unescape(desc_m.group(1))).strip()[:220]
                    break
            except Exception:
                continue

        return info

    def enrich_domain(self, domain: str, network_probe: bool = True) -> Dict[str, Any]:
        """Runs full OSINT & infrastructure enrichment on a probed domain."""
        clean_domain = (domain or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].rstrip(".")

        # 1. Public APIs OSINT Catalog Correlation (`orbit/recon/public_apis_osint.py`)
        osint_catalog = self.osint_harvester.harvest_public_api_intel(clean_domain, limit=15)
        sample_osint_tools = [
            {"name": ep.get("name"), "category": ep.get("category"), "link": ep.get("link")}
            for ep in (osint_catalog.get("security_osint_endpoints") or [])[:5]
        ]

        # 2. Executive Leadership & Email Pattern OSINT
        leadership = self.leadership_verifier.resolve_leadership(clean_domain)

        nameservers: List[str] = []
        mx_records: List[str] = []
        txt_records: List[str] = []
        dmarc_txt_records: List[str] = []
        http_info: Dict[str, Any] = {}
        registrar = "Cloudflare / Standard Registrar"

        if network_probe:
            mx_res = self.leadership_verifier.verify_domain_mx(clean_domain)
            mx_records = mx_res.get("mx_records") or []
            nameservers = [ns.rstrip(".").lower() for ns in self._query_doh_txt_or_ns(clean_domain, "NS")]
            txt_records = self._query_doh_txt_or_ns(clean_domain, "TXT")
            dmarc_txt_records = self._query_doh_txt_or_ns(f"_dmarc.{clean_domain}", "TXT")
            registrar = self._lookup_rdap_registrar(clean_domain, nameservers)
            http_info = self._probe_http_profile_and_stack(clean_domain)

        # 3. Evaluate DMARC & SPF hygiene
        dmarc_raw = next((t for t in dmarc_txt_records if t.lower().startswith("v=dmarc1")), "")
        if not dmarc_raw:
            dmarc_status = "missing"
        elif "p=reject" in dmarc_raw.lower() or "p=quarantine" in dmarc_raw.lower():
            dmarc_status = "pass"
        else:
            dmarc_status = "warn"

        spf_raw = next((t for t in txt_records if t.lower().startswith("v=spf1")), "")
        if not spf_raw:
            spf_status = "missing"
        elif "-all" in spf_raw.lower() or "~all" in spf_raw.lower() or "redirect=" in spf_raw.lower():
            spf_status = "pass"
        else:
            spf_status = "warn"

        # Compute deterministic hygiene score & grade when network_probe is active
        score = 92
        if dmarc_status == "missing":
            score -= 20
        elif dmarc_status == "warn":
            score -= 10
        if spf_status == "missing":
            score -= 18
        elif spf_status == "warn":
            score -= 8
        score = max(35, min(98, score))
        grade = (
            "A+" if score >= 95
            else ("A" if score >= 88
            else ("B" if score >= 75
            else ("C" if score >= 60
            else ("D" if score >= 45 else "F"))))
        )

        # 4. Aggregate Tech Stack Signals
        tech_stack_set: Set[str] = set(http_info.get("tech_signals") or [])
        dns_provider = self._infer_dns_provider(nameservers)
        if dns_provider and "Standard" not in dns_provider:
            tech_stack_set.add(dns_provider)
        mx_provider = self._infer_mx_provider(mx_records)
        if mx_provider and "No MX" not in mx_provider:
            tech_stack_set.add(mx_provider)

        txt_joined = " ".join(txt_records).lower()
        if "shopify" in txt_joined:
            tech_stack_set.add("Shopify")
        if "google-site-verification" in txt_joined:
            tech_stack_set.add("Google Search Console")
        if "stripe" in txt_joined:
            tech_stack_set.add("Stripe")
        if "hubspot" in txt_joined:
            tech_stack_set.add("HubSpot")
        if "atlassian" in txt_joined:
            tech_stack_set.add("Atlassian")
        if not tech_stack_set:
            tech_stack_set.add("HTTPS / Standard Web Stack")

        # 5. Company Profile Synthesis
        brand_guess = _humanize_domain_brand(clean_domain)
        company_name = (
            leadership.get("agency_name")
            or http_info.get("site_name")
            or (http_info.get("title", "").split("|")[0].split("—")[0].split("-")[0].strip() if http_info.get("title") else "")
            or brand_guess
        )

        enrichment_record: Dict[str, Any] = {
            "domain": clean_domain,
            "enriched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "company_profile": {
                "company_name": company_name,
                "title": http_info.get("title") or f"{company_name} ({clean_domain})",
                "description": http_info.get("description") or f"External attack surface and DNS perimeter profile for {clean_domain}.",
                "website_url": f"https://{clean_domain}",
            },
            "registrar": registrar,
            "dns_provider": dns_provider,
            "nameservers": nameservers,
            "mx_provider": mx_provider,
            "mx_records": mx_records,
            "tech_stack": sorted(tech_stack_set),
            "dmarc_status": dmarc_status,
            "dmarc_record": dmarc_raw,
            "spf_status": spf_status,
            "spf_record": spf_raw,
            "computed_score": score,
            "computed_grade": grade,
            "leadership": leadership,
            "public_apis_osint": {
                "bridge_available": osint_catalog.get("bridge_available", False),
                "total_catalog_apis": osint_catalog.get("total_catalog_apis", 0),
                "security_osint_count": osint_catalog.get("security_osint_count", 0),
                "domain_matches": osint_catalog.get("domain_matches", []),
                "sample_osint_tools": sample_osint_tools,
                "pivot_domains": (osint_catalog.get("pivot_domains") or [])[:25],
            },
        }

        self._save_enriched_lead(clean_domain, enrichment_record)
        self._publish_blackboard_event(enrichment_record)
        return enrichment_record

    def _save_enriched_lead(self, domain: str, record: Dict[str, Any]) -> None:
        with self._lock:
            data: Dict[str, Any] = {}
            if self.leads_file.exists():
                try:
                    raw = self.leads_file.read_text(encoding="utf-8").strip()
                    if raw:
                        loaded = json.loads(raw)
                        if isinstance(loaded, dict):
                            data = loaded
                except Exception as ex:
                    logger.warning("Failed to read enriched leads file %s: %s", self.leads_file, ex)

            data[domain] = record
            tmp = self.leads_file.with_suffix(".tmp")
            try:
                tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                tmp.replace(self.leads_file)
            except Exception as ex:
                if tmp.exists():
                    tmp.unlink()
                logger.warning("Failed to write enriched lead for %s: %s", domain, ex)

    def get_enriched_lead(self, domain: str) -> Optional[Dict[str, Any]]:
        clean = (domain or "").strip().lower()
        if not self.leads_file.exists():
            return None
        try:
            data = json.loads(self.leads_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data.get(clean)
        except Exception:
            pass
        return None

    def get_all_enriched_leads(self) -> Dict[str, Dict[str, Any]]:
        """Returns all enriched domain profiles keyed by domain."""
        if not self.leads_file.exists():
            return {}
        try:
            data = json.loads(self.leads_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    def _publish_blackboard_event(self, enrichment_record: Dict[str, Any]) -> None:
        try:
            from orbit_security.blackboard import (
                EVENT_RADAR_LEAD_ENRICHED,
                TOPIC_TELEMETRY,
                publish_event,
            )

            publish_event(
                event_type=EVENT_RADAR_LEAD_ENRICHED,
                payload={
                    "domain": enrichment_record.get("domain"),
                    "company_name": enrichment_record.get("company_profile", {}).get("company_name"),
                    "registrar": enrichment_record.get("registrar"),
                    "tech_stack": enrichment_record.get("tech_stack"),
                    "mx_provider": enrichment_record.get("mx_provider"),
                    "computed_score": enrichment_record.get("computed_score"),
                    "computed_grade": enrichment_record.get("computed_grade"),
                },
                source="radar_lead_enricher",
                topic=TOPIC_TELEMETRY,
            )
        except Exception as ex:
            logger.debug("Blackboard publish skipped for lead enrichment: %s", ex)
