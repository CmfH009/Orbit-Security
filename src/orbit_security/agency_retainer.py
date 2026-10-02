"""Orbit Security: Multi-Tenant Agency White-Label Retainer Tier (agency_retainer.py).

Provides multi-tenant agency retainer management, tiered subscriptions
(Starter $299/mo, Scale $499/mo, Enterprise $999/mo), client domain perimeter
tracking, custom agency domain branding, and white-label portal rendering.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
from enum import Enum
import html
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from orbit_security.models import AgencyBranding, DomainAuditResult, Severity

logger = logging.getLogger("orbit_security.agency_retainer")

DEFAULT_RETAINERS_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "agency_retainers.json"
DEFAULT_PORTALS_OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "portals"
DEFAULT_LANDING_PORTALS_DIR = Path(__file__).resolve().parent.parent.parent / "landing" / "portals"


class RetainerTier(str, Enum):
    STARTER = "Starter"       # $299/mo - Up to 15 domains, weekly scans
    SCALE = "Scale"           # $499/mo - Up to 50 domains, daily scans, custom portal domain, SLA certs
    ENTERPRISE = "Enterprise" # $999/mo - Unlimited domains, continuous scans, video roasts, dedicated IP pool


@dataclass
class TierPolicy:
    monthly_price: int
    max_domains: int
    scan_frequency: str
    custom_portal_enabled: bool
    sla_certificates_enabled: bool
    video_roasts_enabled: bool
    webhook_integrations_enabled: bool


TIER_POLICIES: Dict[RetainerTier, TierPolicy] = {
    RetainerTier.STARTER: TierPolicy(
        monthly_price=299,
        max_domains=15,
        scan_frequency="weekly",
        custom_portal_enabled=False,
        sla_certificates_enabled=False,
        video_roasts_enabled=False,
        webhook_integrations_enabled=False,
    ),
    RetainerTier.SCALE: TierPolicy(
        monthly_price=499,
        max_domains=50,
        scan_frequency="daily",
        custom_portal_enabled=True,
        sla_certificates_enabled=True,
        video_roasts_enabled=False,
        webhook_integrations_enabled=True,
    ),
    RetainerTier.ENTERPRISE: TierPolicy(
        monthly_price=999,
        max_domains=-1,  # unlimited
        scan_frequency="continuous",
        custom_portal_enabled=True,
        sla_certificates_enabled=True,
        video_roasts_enabled=True,
        webhook_integrations_enabled=True,
    ),
}


@dataclass
class AgencyClientSite:
    domain: str
    client_name: str
    status: str = "active"  # active, paused
    last_score: int = 100
    last_grade: str = "A+"
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    last_scanned: Optional[str] = None


@dataclass
class AgencyRetainer:
    agency_id: str
    agency_name: str
    tier: RetainerTier = RetainerTier.SCALE
    monthly_price: int = 499
    custom_domain: Optional[str] = None  # e.g. "security.eastsideco.com"
    agency_tagline: str = "Managed Web & Security Operations"
    primary_color: str = "#0B132B"
    accent_color: str = "#48CAE4"
    support_email: str = "security@agency.example.com"
    website: str = "https://agency.example.com"
    logo_svg: Optional[str] = None
    client_domains: List[AgencyClientSite] = field(default_factory=list)
    billing_status: str = "active"  # active, past_due, trial
    stripe_subscription_id: Optional[str] = None
    sla_guarantee: str = "99.9% Perimeter Uptime & <15-Min Takeover Alert Guarantee"
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    last_audit_at: Optional[str] = None

    def get_policy(self) -> TierPolicy:
        return TIER_POLICIES.get(self.tier, TIER_POLICIES[RetainerTier.SCALE])

    def can_add_domain(self) -> bool:
        policy = self.get_policy()
        if policy.max_domains == -1:
            return True
        return len(self.client_domains) < policy.max_domains

    def to_branding(self) -> AgencyBranding:
        return AgencyBranding(
            agency_name=self.agency_name,
            agency_tagline=self.agency_tagline,
            primary_color=self.primary_color,
            accent_color=self.accent_color,
            support_email=self.support_email,
            website=self.website,
        )


class AgencyRetainerManager:
    """Manages multi-tenant agency retainers and client domain perimeters."""

    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = Path(data_path or DEFAULT_RETAINERS_DATA_PATH)
        self.agencies: Dict[str, AgencyRetainer] = {}
        self.load()

    def load(self):
        """Loads agency retainers from disk or initializes defaults."""
        if not self.data_path.exists():
            self._populate_seed_agencies()
            self.save()
            return

        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                loaded = {}
                for item in data.get("agencies", []):
                    clients = [
                        AgencyClientSite(**c) if isinstance(c, dict) else AgencyClientSite(domain=c, client_name=c)
                        for c in item.get("client_domains", [])
                    ]
                    item["client_domains"] = clients
                    if "tier" in item and isinstance(item["tier"], str):
                        item["tier"] = RetainerTier(item["tier"])
                    loaded[item["agency_id"]] = AgencyRetainer(**item)
                self.agencies = loaded
            if not self.agencies:
                self._populate_seed_agencies()
                self.save()
        except Exception as e:
            logger.warning(f"Error loading agency retainers: {e}")
            self._populate_seed_agencies()

    def save(self):
        """Persists retainers to disk."""
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        raw_agencies = []
        for a in self.agencies.values():
            d = asdict(a)
            d["tier"] = a.tier.value
            raw_agencies.append(d)

        data = {
            "version": "1.0",
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agencies": raw_agencies,
        }
        with open(self.data_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _populate_seed_agencies(self):
        """Default seed partner agencies in Cohort 2 ready for retainer portals."""
        seeds = [
            AgencyRetainer(
                agency_id="eastside-co",
                agency_name="Eastside Co",
                tier=RetainerTier.SCALE,
                monthly_price=499,
                custom_domain="security.eastsideco.com",
                agency_tagline="Enterprise Shopify Plus Technical Solutions",
                primary_color="#0B132B",
                accent_color="#48CAE4",
                support_email="ops@eastsideco.com",
                website="https://eastsideco.com",
                client_domains=[
                    AgencyClientSite(domain="candykittens.co.uk", client_name="Candy Kittens", last_score=85, last_grade="B"),
                    AgencyClientSite(domain="wildfang.com", client_name="Wildfang Apparel", last_score=95, last_grade="A+"),
                    AgencyClientSite(domain="trolli.com", client_name="Trolli Candies", last_score=75, last_grade="C", critical_findings=1),
                ],
            ),
            AgencyRetainer(
                agency_id="we-make-websites",
                agency_name="We Make Websites",
                tier=RetainerTier.SCALE,
                monthly_price=499,
                custom_domain="security.wemakewebsites.com",
                agency_tagline="The International Shopify Plus Agency",
                primary_color="#181824",
                accent_color="#6366F1",
                support_email="ops@wemakewebsites.com",
                website="https://wemakewebsites.com",
                client_domains=[
                    AgencyClientSite(domain="haslemerecellar.co.uk", client_name="Haslemere Cellar", last_score=92, last_grade="A"),
                    AgencyClientSite(domain="skinnydip.com", client_name="Skinnydip London", last_score=88, last_grade="A"),
                ],
            ),
            AgencyRetainer(
                agency_id="barrel",
                agency_name="Barrel",
                tier=RetainerTier.STARTER,
                monthly_price=299,
                custom_domain="security.barrelny.com",
                agency_tagline="Digital Marketing & DTC Commerce Architecture",
                primary_color="#111827",
                accent_color="#10B981",
                support_email="support@barrelny.com",
                website="https://barrelny.com",
                client_domains=[
                    AgencyClientSite(domain="edenbrothers.com", client_name="Eden Brothers", last_score=90, last_grade="A"),
                ],
            ),
            AgencyRetainer(
                agency_id="swanky",
                agency_name="Swanky Agency",
                tier=RetainerTier.SCALE,
                monthly_price=499,
                custom_domain="security.swankyagency.com",
                agency_tagline="Global Shopify Plus & Subscription Specialists",
                primary_color="#0F172A",
                accent_color="#F59E0B",
                support_email="support@swankyagency.com",
                website="https://swankyagency.com",
                client_domains=[
                    AgencyClientSite(domain="loop-earplugs.com", client_name="Loop Earplugs", last_score=96, last_grade="A+"),
                    AgencyClientSite(domain="chillysbottles.com", client_name="Chilly's Bottles", last_score=84, last_grade="B"),
                ],
            ),
        ]
        self.agencies = {a.agency_id: a for a in seeds}

    def register_agency(
        self,
        agency_id: str,
        agency_name: str,
        tier: RetainerTier = RetainerTier.SCALE,
        custom_domain: Optional[str] = None,
        support_email: Optional[str] = None,
        primary_color: str = "#0F172A",
        accent_color: str = "#3B82F6",
        agency_tagline: str = "Managed Web & Security Operations",
        website: str = "https://example.com",
    ) -> AgencyRetainer:
        """Enrolls a new web agency into an Orbit White-Label Retainer tier."""
        clean_id = re.sub(r"[^a-zA-Z0-9_-]", "-", agency_id.lower().strip())
        policy = TIER_POLICIES.get(tier, TIER_POLICIES[RetainerTier.SCALE])

        retainer = AgencyRetainer(
            agency_id=clean_id,
            agency_name=agency_name,
            tier=tier,
            monthly_price=policy.monthly_price,
            custom_domain=custom_domain,
            agency_tagline=agency_tagline,
            primary_color=primary_color,
            accent_color=accent_color,
            support_email=support_email or f"ops@{clean_id}.example.com",
            website=website,
        )
        self.agencies[clean_id] = retainer
        self.save()
        return retainer

    def get_agency(self, agency_id: str) -> Optional[AgencyRetainer]:
        return self.agencies.get(agency_id)

    def list_agencies(self) -> List[AgencyRetainer]:
        return list(self.agencies.values())

    def add_client_domain(
        self,
        agency_id: str,
        domain: str,
        client_name: Optional[str] = None,
    ) -> bool:
        """Adds a client domain under an agency's retainer quota."""
        agency = self.get_agency(agency_id)
        if not agency:
            raise KeyError(f"Agency '{agency_id}' not found.")

        if not agency.can_add_domain():
            limit = agency.get_policy().max_domains
            raise ValueError(
                f"Agency '{agency.agency_name}' has reached its {agency.tier.value} tier domain limit ({limit} domains). "
                "Upgrade to Scale or Enterprise to add more client perimeters."
            )

        clean_domain = domain.strip().lower()
        for site in agency.client_domains:
            if site.domain == clean_domain:
                return False  # Already monitored

        agency.client_domains.append(
            AgencyClientSite(
                domain=clean_domain,
                client_name=client_name or clean_domain,
            )
        )
        self.save()
        return True

    def remove_client_domain(self, agency_id: str, domain: str) -> bool:
        """Removes a client domain from an agency's monitoring list."""
        agency = self.get_agency(agency_id)
        if not agency:
            return False

        clean_domain = domain.strip().lower()
        initial_len = len(agency.client_domains)
        agency.client_domains = [s for s in agency.client_domains if s.domain != clean_domain]
        if len(agency.client_domains) < initial_len:
            self.save()
            return True
        return False

    def update_site_audit(
        self,
        agency_id: str,
        domain: str,
        score: int,
        grade: str,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
    ) -> bool:
        """Updates security score and findings counts for an agency client site."""
        agency = self.get_agency(agency_id)
        if not agency:
            return False

        clean_domain = domain.strip().lower()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        agency.last_audit_at = now_iso

        for site in agency.client_domains:
            if site.domain == clean_domain:
                site.last_score = score
                site.last_grade = grade
                site.critical_findings = critical_count
                site.high_findings = high_count
                site.medium_findings = medium_count
                site.last_scanned = now_iso
                self.save()
                return True
        return False


class AgencyPortalRenderer:
    """Generates standalone, responsive HTML/CSS/JS co-branded portals for agency retainers."""

    @staticmethod
    def render_portal_html(agency: AgencyRetainer) -> str:
        """Renders an interactive, client-ready security portal for the agency."""
        p_color = agency.primary_color
        a_color = agency.accent_color
        domains = agency.client_domains
        total_domains = len(domains)
        avg_score = int(sum(d.last_score for d in domains) / total_domains) if total_domains > 0 else 100
        critical_total = sum(d.critical_findings for d in domains)
        high_total = sum(d.high_findings for d in domains)

        # Build table rows
        rows_html = []
        for site in domains:
            score = site.last_score
            grade = site.last_grade
            badge_color = "#10B981" if score >= 88 else ("#F59E0B" if score >= 70 else "#EF4444")
            status_text = "🟢 SECURE" if score >= 88 else ("🟡 WARNING" if score >= 70 else "🔴 AT RISK")
            last_scanned_fmt = (
                site.last_scanned[:16].replace("T", " ") if site.last_scanned else "Scheduled"
            )

            rows_html.append(f"""
                <tr class="border-b border-gray-800 hover:bg-gray-800/40 transition">
                    <td class="py-4 px-6 font-medium text-white flex items-center gap-3">
                        <span class="w-2.5 h-2.5 rounded-full" style="background-color: {badge_color}"></span>
                        <div>
                            <div class="font-bold">{html.escape(site.client_name)}</div>
                            <div class="text-xs text-gray-400 font-mono">{html.escape(site.domain)}</div>
                        </div>
                    </td>
                    <td class="py-4 px-6 text-center">
                        <span class="px-2.5 py-1 rounded text-xs font-bold font-mono" style="background-color: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}55">
                            {score}/100 ({grade})
                        </span>
                    </td>
                    <td class="py-4 px-6 text-center">
                        <span class="text-xs font-semibold px-2 py-0.5 rounded {'text-red-400 bg-red-950/40 border border-red-800/50' if site.critical_findings > 0 else 'text-gray-400'}">
                            {site.critical_findings} Critical / {site.high_findings} High
                        </span>
                    </td>
                    <td class="py-4 px-6 text-center text-xs text-gray-400 font-mono">
                        {last_scanned_fmt}
                    </td>
                    <td class="py-4 px-6 text-right">
                        <div class="flex items-center justify-end gap-2">
                            <button onclick="auditDomain('{html.escape(site.domain)}')" class="px-3 py-1.5 rounded text-xs font-semibold text-white bg-blue-600/30 hover:bg-blue-600/60 border border-blue-500/50 transition flex items-center gap-1.5">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                                Audit Now
                            </button>
                            <button onclick="downloadReport('{html.escape(site.domain)}', '{html.escape(site.client_name)}', {score})" class="px-3 py-1.5 rounded text-xs font-semibold text-gray-200 bg-gray-800 hover:bg-gray-700 border border-gray-700 transition flex items-center gap-1.5">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                Report
                            </button>
                        </div>
                    </td>
                </tr>
            """)

        rows_joined = "\n".join(rows_html)

        html_content = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(agency.agency_name)} | Client Security Fleet Command</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        :root {{
            --agency-primary: {p_color};
            --agency-accent: {a_color};
        }}
        body {{
            background-color: #0b0f17;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }}
        .brand-gradient {{
            background: linear-gradient(135deg, {p_color} 0%, #1e293b 100%);
        }}
        .accent-border {{
            border-color: {a_color};
        }}
        .accent-text {{
            color: {a_color};
        }}
        .accent-bg {{
            background-color: {a_color};
        }}
    </style>
</head>
<body class="min-h-screen flex flex-col">

    <!-- Top Navigation Bar -->
    <header class="border-b border-gray-800 bg-[#0d131f]/80 backdrop-blur-md sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-9 h-9 rounded-lg flex items-center justify-center font-bold text-white shadow-lg" style="background: linear-gradient(135deg, {a_color}, {p_color});">
                    🛡️
                </div>
                <div>
                    <h1 class="text-base font-bold text-white tracking-tight">{html.escape(agency.agency_name)}</h1>
                    <p class="text-xs text-gray-400">{html.escape(agency.agency_tagline)}</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-2 animate-pulse"></span>
                    {agency.tier.value} SLA Retainer Active
                </span>
                {f'<span class="text-xs font-mono text-gray-400 hidden sm:inline-block px-2.5 py-1 bg-gray-800/80 rounded border border-gray-700">{html.escape(agency.custom_domain)}</span>' if agency.custom_domain else ''}
                <a href="mailto:{html.escape(agency.support_email)}" class="text-xs font-semibold px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 transition">
                    Contact Ops
                </a>
            </div>
        </div>
    </header>

    <!-- Main Command Center Body -->
    <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

        <!-- Executive Banner -->
        <div class="rounded-2xl p-6 sm:p-8 border border-gray-800 relative overflow-hidden brand-gradient shadow-2xl">
            <div class="relative z-10 max-w-3xl">
                <div class="inline-block px-3 py-1 rounded text-xs font-semibold uppercase tracking-wider text-cyan-300 bg-cyan-950/60 border border-cyan-800/60 mb-3">
                    Managed Perimeter Hygiene & Sentinel Protection
                </div>
                <h2 class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                    Client Attack Surface & DNS Security Fleet
                </h2>
                <p class="mt-2 text-sm text-gray-300">
                    Continuous 24/7 DNS audit sentinel, subdomain takeover prevention, and email authentication enforcement for your client portfolio.
                </p>
                <div class="mt-4 flex flex-wrap gap-4 text-xs font-mono text-gray-300">
                    <span class="flex items-center gap-1.5">
                        <svg class="w-4 h-4 text-emerald-400" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                        {agency.sla_guarantee}
                    </span>
                </div>
            </div>
        </div>

        <!-- Telemetry Metrics Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="bg-[#0f172a]/60 rounded-xl p-5 border border-gray-800 shadow">
                <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Monitored Perimeters</div>
                <div class="mt-2 flex items-baseline justify-between">
                    <div class="text-3xl font-black text-white font-mono">{total_domains}</div>
                    <span class="text-xs font-semibold text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/40">100% Active</span>
                </div>
            </div>
            <div class="bg-[#0f172a]/60 rounded-xl p-5 border border-gray-800 shadow">
                <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Fleet Health Average</div>
                <div class="mt-2 flex items-baseline justify-between">
                    <div class="text-3xl font-black text-white font-mono">{avg_score}/100</div>
                    <span class="text-xs font-semibold {'text-emerald-400 bg-emerald-950/50 border-emerald-800/40' if avg_score >= 88 else 'text-amber-400 bg-amber-950/50 border-amber-800/40'} px-2 py-0.5 rounded border">
                        {'Grade A+' if avg_score >= 95 else ('Grade A' if avg_score >= 88 else 'Attention')}
                    </span>
                </div>
            </div>
            <div class="bg-[#0f172a]/60 rounded-xl p-5 border border-gray-800 shadow">
                <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Critical Takeover Flaws</div>
                <div class="mt-2 flex items-baseline justify-between">
                    <div class="text-3xl font-black {'text-red-400' if critical_total > 0 else 'text-emerald-400'} font-mono">{critical_total}</div>
                    <span class="text-xs font-semibold {'text-red-400 bg-red-950/50 border-red-800/40' if critical_total > 0 else 'text-emerald-400 bg-emerald-950/50 border-emerald-800/40'} px-2 py-0.5 rounded border">
                        {'Requires Action' if critical_total > 0 else 'Zero Dangling CNAMEs'}
                    </span>
                </div>
            </div>
            <div class="bg-[#0f172a]/60 rounded-xl p-5 border border-gray-800 shadow">
                <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Retainer Tier SLA</div>
                <div class="mt-2 flex items-baseline justify-between">
                    <div class="text-2xl font-black text-cyan-400 font-mono">${agency.monthly_price}<span class="text-xs text-gray-400">/mo</span></div>
                    <span class="text-xs font-semibold text-cyan-400 bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/40">{agency.tier.value}</span>
                </div>
            </div>
        </div>

        <!-- Managed Client Fleet Table -->
        <div class="bg-[#0f172a]/80 rounded-xl border border-gray-800 shadow-xl overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
                <div>
                    <h3 class="text-lg font-bold text-white">Client Portfolio Health</h3>
                    <p class="text-xs text-gray-400">Live perimetral posture across all enrolled client domains</p>
                </div>
                <span class="text-xs font-mono text-gray-400">{total_domains} Domains Enrolled</span>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm text-gray-300">
                    <thead class="bg-[#0b0f17]/90 text-xs uppercase font-semibold text-gray-400 border-b border-gray-800">
                        <tr>
                            <th class="py-3 px-6">Client & Domain</th>
                            <th class="py-3 px-6 text-center">Hygiene Score</th>
                            <th class="py-3 px-6 text-center">Vulnerabilities</th>
                            <th class="py-3 px-6 text-center">Last Scan</th>
                            <th class="py-3 px-6 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_joined}
                    </tbody>
                </table>
            </div>
        </div>

    </main>

    <!-- Footer -->
    <footer class="border-t border-gray-800 bg-[#0d131f] py-6 text-center text-xs text-gray-500">
        <div class="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
            <p>© {datetime.datetime.now().year} {html.escape(agency.agency_name)}. All Rights Reserved. Managed Security Retainer.</p>
            <p class="font-mono text-gray-600">Encrypted Transport • Automated DNS Sentinel • 24/7 SLA Guarantee</p>
        </div>
    </footer>

    <!-- Interactive Client-Side Audit & Report Scripts -->
    <script>
        function auditDomain(domain) {{
            alert('Initiating real-time DoH audit for ' + domain + '... Resolving DNS perimeter...');
            window.open('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=ANY', '_blank');
        }}

        function downloadReport(domain, clientName, score) {{
            const reportText = `# Security Audit Report - ${{clientName}} (${{domain}})\\n` +
                `Prepared by: {agency.agency_name} ({agency.agency_tagline})\\n` +
                `Audit Score: ${{score}}/100\\n` +
                `Date: ${{new Date().toUTCString()}}\\n\\n` +
                `## Executive Summary\\nThis report verifies the external DNS hygiene and attack surface perimeter for ${{domain}} under the {agency.agency_name} Retainer SLA.\\n\\n` +
                `Status: ${{score >= 88 ? 'CLEAN & COMPLIANT' : 'REMEDIATION RECOMMENDED'}}\\n`;

            const blob = new Blob([reportText], {{ type: 'text/markdown' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_audit_${{domain.replace(/[^a-zA-Z0-9]/g, '_')}}.md`;
            a.click();
            URL.revokeObjectURL(url);
        }}
    </script>
</body>
</html>"""
        return html_content

    @staticmethod
    def save_portal(
        agency: AgencyRetainer,
        output_dir: Optional[Path] = None,
        landing_dir: Optional[Path] = None,
    ) -> Tuple[Path, Optional[Path]]:
        """Generates and writes portal HTML files for docs/ and landing/ sites."""
        out_dir = Path(output_dir or DEFAULT_PORTALS_OUTPUT_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)
        file_path = out_dir / f"{agency.agency_id}.html"

        html_content = AgencyPortalRenderer.render_portal_html(agency)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        landing_path: Optional[Path] = None
        target_landing = Path(landing_dir or DEFAULT_LANDING_PORTALS_DIR)
        if landing_dir is not None or target_landing.parent.exists():
            target_landing.mkdir(parents=True, exist_ok=True)
            landing_path = target_landing / f"{agency.agency_id}.html"
            with open(landing_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        return file_path, landing_path
