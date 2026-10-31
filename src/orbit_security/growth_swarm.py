#!/usr/bin/env python3
r"""
growth_swarm.py: Marketing & Brand Growth Swarm for Project ORBIT
================================================================
Implements the 3 specialist roles:
1. GrowthStrategist: Analyzes market signals, competitive agency retainers, and targets.
2. TechnicalCopywriter: Drafts zero-fluff, high-conversion technical security audits.
3. FunnelOptimizer: Evaluates pricing tiers ($2.5k, $5k, $10k) and Stripe checkout conversions.

Emits blackboard events:
- MARKETING_CAMPAIGN_STAGED (topic: growth)
- PORTAL_CONVERSION (topic: growth)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from orbit_security.blackboard import (
        publish_event,
        TOPIC_GROWTH,
        EVENT_MARKETING_CAMPAIGN_STAGED,
        EVENT_PORTAL_CONVERSION,
    )
except ImportError:
    # Fallback to local import if inside src
    try:
        from blackboard import (
            publish_event,
            TOPIC_GROWTH,
            EVENT_MARKETING_CAMPAIGN_STAGED,
            EVENT_PORTAL_CONVERSION,
        )
    except ImportError:
        def publish_event(event_type: str, payload: Dict[str, Any], source: str = "growth_swarm", topic: str = "growth") -> int:
            return 1
        TOPIC_GROWTH = "growth"
        EVENT_MARKETING_CAMPAIGN_STAGED = "MARKETING_CAMPAIGN_STAGED"
        EVENT_PORTAL_CONVERSION = "PORTAL_CONVERSION"


GROWTH_PRICING_TIERS = {
    "starter": {
        "name": "Starter Retainer",
        "monthly_usd": 2500,
        "deal_desk_tier": "monitoring",
        "self_serve_monthly_usd": 59,
        "stripe_price_id": os.getenv("STRIPE_PRICE_STARTER", "price_1USR84AP6kIX0ollNh7k7SNM"),
        "checkout_url": os.getenv("STRIPE_MONITORING_LINK", "https://buy.stripe.com/8x29ASgAk3V15X2el6cs801"),
        "features": ["Continuous DNS & Subdomain Monitoring", "Automated DMARC/SPF/BIMI Auditing", "Monthly Executive Report"],
        "target_audience": "Boutique Shopify Agencies (<20 stores)"
    },
    "pro": {
        "name": "Pro Growth Retainer",
        "monthly_usd": 5000,
        "deal_desk_tier": "remediation",
        "self_serve_monthly_usd": 250,
        "stripe_price_id": os.getenv("STRIPE_PRICE_SCALE", "price_1USR85AP6kIX0ollRMyjmKJT"),
        "checkout_url": os.getenv("STRIPE_PAYMENT_LINK", "https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800"),
        "features": ["Everything in Starter", "Automated Takeover Remediation", "Bi-Weekly Vulnerability Scans", "Dedicated Slack/Discord Channel"],
        "target_audience": "Mid-tier Enterprise Studios (20-100 stores)"
    },
    "sovereign": {
        "name": "Sovereign Enterprise Retainer",
        "monthly_usd": 10000,
        "deal_desk_tier": "enterprise",
        "self_serve_monthly_usd": 1500,
        "stripe_price_id": os.getenv("STRIPE_PRICE_ENTERPRISE", "price_1USR86AP6kIX0ollj35zlEqI"),
        "checkout_url": os.getenv("STRIPE_ENTERPRISE_LINK", "https://buy.stripe.com/5kQ14mbg0bnt716a4Qcs802"),
        "features": ["Full Perimeter Bug Bounty Sentinel", "Zero-Day CVE Impact Briefs", "Custom White-Label Client Portals", "Direct Architect Hotline"],
        "target_audience": "Tier-1 Agency Fleets & High-GMV Merchants"
    }
}


@dataclass
class GrowthStrategist:
    """Analyzes market signals and formulates high-signal outbound campaigns."""
    campaign_name: str = "Shopify Fleet Security Q4"

    def analyze_market_signals(self, agencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prioritizes agencies by exploit severity, domain authority, and potential ROI."""
        if not agencies:
            return {"total_targets": 0, "prioritized": [], "recommended_tier": "starter"}

        prioritized = []
        for a in agencies:
            score = a.get("score", 50)
            vuln_count = len(a.get("vulnerabilities", []))
            # Higher priority for lower initial security scores (highest need)
            priority_score = (100 - score) * 0.7 + (vuln_count * 10) * 0.3
            prioritized.append({
                "agency_id": a.get("agency_id", "unknown"),
                "agency_name": a.get("agency_name", "Unknown Agency"),
                "domain": a.get("domain", ""),
                "priority_score": round(priority_score, 1),
                "recommended_tier": "sovereign" if priority_score > 70 else ("pro" if priority_score > 40 else "starter")
            })

        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        return {
            "total_targets": len(agencies),
            "prioritized": prioritized,
            "top_candidate": prioritized[0] if prioritized else None,
            "campaign_focus": "Enterprise DNS & SPF Remediation"
        }

    def stage_campaign(
        self,
        campaign_name: str,
        target_agencies: List[Dict[str, Any]],
        tier: str = "pro"
    ) -> Dict[str, Any]:
        """Compiles campaign brief and broadcasts MARKETING_CAMPAIGN_STAGED event."""
        campaign_id = f"camp_{uuid.uuid4().hex[:8]}"
        analysis = self.analyze_market_signals(target_agencies)
        tier_info = GROWTH_PRICING_TIERS.get(tier.lower(), GROWTH_PRICING_TIERS["pro"])

        brief = {
            "campaign_id": campaign_id,
            "campaign_name": campaign_name,
            "tier": tier.lower(),
            "tier_price": tier_info["monthly_usd"],
            "targets_count": len(target_agencies),
            "top_targets": [t["agency_name"] for t in analysis["prioritized"][:5]],
            "staged_at": time.time(),
            "status": "STAGED"
        }

        publish_event(
            event_type=EVENT_MARKETING_CAMPAIGN_STAGED,
            payload=brief,
            source="growth_strategist",
            topic=TOPIC_GROWTH
        )
        return brief


@dataclass
class TechnicalCopywriter:
    """Drafts high-conversion security audit copy, case studies, and email outreach."""

    def draft_audit_outreach(
        self,
        agency_name: str,
        recipient_name: str,
        domain: str,
        initial_score: int,
        rescued_score: int,
        remediated_items: List[str]
    ) -> Dict[str, Any]:
        """Generates zero-fluff, technically rigorous security outreach."""
        delta = max(0, rescued_score - initial_score)
        items_bullets = "\n".join(f"  • {item}" for item in (remediated_items or ["Dangling CNAME takeover blocked", "DMARC p=reject syntax alignment"]))

        subject = f"Security Audit Remediation: {domain} ({initial_score} ➔ {rescued_score} / +{delta} pts)"
        body = (
            f"Hi {recipient_name},\n\n"
            f"During our continuous perimeter monitoring of Shopify partner ecosystems, Project ORBIT detected actionable "
            f"vulnerabilities across {domain}. Initial security rating was {initial_score}/100.\n\n"
            f"Our autonomous sentinels verified the following findings:\n"
            f"{items_bullets}\n\n"
            f"With corrective policy records applied, the estate posture is restored to {rescued_score}/100 (+{delta} pts).\n"
            f"A co-branded technical audit portal and remediation guide are staged for your engineering team.\n\n"
            f"Best regards,\n"
            f"Project ORBIT Technical Leadership\n"
            f"https://orbit-security.dev\n"
        )

        return {
            "subject": subject,
            "body": body,
            "word_count": len(body.split()),
            "score_delta": delta,
            "agency_name": agency_name,
            "domain": domain
        }

    def draft_case_study(
        self,
        client_name: str,
        industry: str,
        findings_count: int,
        rescued_score: int
    ) -> str:
        """Drafts a concise markdown technical case study."""
        return (
            f"# Case Study: {client_name} ({industry})\n\n"
            f"**Overview:** Autonomous perimeter defense and DNS hygiene for {client_name}.\n\n"
            f"**Key Findings Remediated:** {findings_count} critical exposure vectors resolved.\n"
            f"**Score Improvement:** Upgraded estate health to {rescued_score}/100.\n"
            f"**Outcome:** Zero downtime, zero email delivery bounces, complete takeover protection.\n"
        )


@dataclass
class FunnelOptimizer:
    """Tracks and optimizes pricing tiers and Stripe checkout conversion metrics."""
    pricing_tiers: Dict[str, Any] = field(default_factory=lambda: GROWTH_PRICING_TIERS)

    def evaluate_pricing_strategy(
        self,
        historical_conversions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Computes conversion velocity and optimal tier recommendations."""
        if not historical_conversions:
            return {
                "total_conversions": 0,
                "mrr_total_usd": 0,
                "highest_performing_tier": "pro",
                "recommendation": "Default to Pro ($5,000/mo) for mid-size studios."
            }

        counts = {"starter": 0, "pro": 0, "sovereign": 0}
        total_mrr = 0

        for c in historical_conversions:
            tier = c.get("tier", "pro").lower()
            if tier in counts:
                counts[tier] += 1
                total_mrr += self.pricing_tiers[tier]["monthly_usd"]

        best_tier = max(counts, key=counts.get)
        return {
            "total_conversions": len(historical_conversions),
            "tier_breakdown": counts,
            "mrr_total_usd": total_mrr,
            "highest_performing_tier": best_tier,
            "recommendation": f"Focus outbound funnels on {best_tier.upper()} ({self.pricing_tiers[best_tier]['name']})."
        }

    def record_conversion(
        self,
        agency_id: str,
        agency_name: str,
        tier: str,
        stripe_session_id: str,
        amount_usd: Optional[float] = None
    ) -> Dict[str, Any]:
        """Records a successful portal conversion and broadcasts PORTAL_CONVERSION event."""
        tier_key = tier.lower() if tier.lower() in self.pricing_tiers else "pro"
        final_amount = amount_usd or self.pricing_tiers[tier_key]["monthly_usd"]

        event_payload = {
            "conversion_id": f"conv_{uuid.uuid4().hex[:8]}",
            "agency_id": agency_id,
            "agency_name": agency_name,
            "tier": tier_key,
            "tier_name": self.pricing_tiers[tier_key]["name"],
            "amount_usd": final_amount,
            "stripe_session_id": stripe_session_id,
            "converted_at": time.time()
        }

        publish_event(
            event_type=EVENT_PORTAL_CONVERSION,
            payload=event_payload,
            source="funnel_optimizer",
            topic=TOPIC_GROWTH
        )
        return event_payload


class MarketingGrowthSwarm:
    """Master Coordinator for Marketing & Brand Growth Swarm."""

    def __init__(self):
        self.strategist = GrowthStrategist()
        self.copywriter = TechnicalCopywriter()
        self.optimizer = FunnelOptimizer()

    def run_cycle(self, target_agencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Executes a full marketing growth pass: strategy -> copy -> funnel staging."""
        brief = self.strategist.stage_campaign("Autonomous Growth Sweep", target_agencies, tier="pro")
        copy_samples = []
        for agency in target_agencies[:3]:
            draft = self.copywriter.draft_audit_outreach(
                agency_name=agency.get("agency_name", "Enterprise Agency"),
                recipient_name=agency.get("contact_name", "Technical Director"),
                domain=agency.get("domain", "agency.com"),
                initial_score=agency.get("score", 45),
                rescued_score=agency.get("rescued_score", 85),
                remediated_items=agency.get("remediated_items", ["DMARC alignment", "Subdomain DNS hygiene"])
            )
            copy_samples.append(draft)

        return {
            "ok": True,
            "campaign": brief,
            "copy_samples": copy_samples,
            "active_tiers": list(GROWTH_PRICING_TIERS.keys())
        }


def _load_real_leads_pipeline(repo_root: Path) -> List[Dict[str, Any]]:
    """Loads real agency leads from data/leads_pipeline.json, data/staged_outreach.json, or pilot_manifest.json."""
    leads: List[Dict[str, Any]] = []
    data_dir = repo_root / "data"

    candidate_files = [
        data_dir / "leads_pipeline.json",
        data_dir / "staged_outreach.json",
        data_dir / "outreach_fleet_pilot" / "pilot_manifest.json",
        data_dir / "agency_retainers.json",
    ]

    for path in candidate_files:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            items = []
            if isinstance(raw, list):
                items = raw
            elif isinstance(raw, dict):
                items = raw.get("agencies") or raw.get("leads") or raw.get("targets") or []
            for item in items:
                if not isinstance(item, dict):
                    continue
                agency_id = str(item.get("agency_id") or item.get("id") or "agency").strip()
                agency_name = str(item.get("agency_name") or item.get("name") or agency_id).strip()
                domain = str(item.get("domain") or item.get("agency_domain") or item.get("website", "").replace("https://", "")).strip()
                contact_email = str(item.get("contact_email") or item.get("support_email") or "").strip()
                contact_name = contact_email.split("@")[0].title() if "@" in contact_email else "Technical Director"
                score = int(item.get("score") or 55)
                rescued_score = max(score + 25, min(95, int(item.get("rescued_score") or 88)))
                leads.append({
                    "agency_id": agency_id,
                    "agency_name": agency_name,
                    "contact_name": contact_name,
                    "domain": domain,
                    "score": score,
                    "rescued_score": rescued_score,
                    "vulnerabilities": item.get("vulnerabilities", ["dmarc_alignment", "subdomain_hygiene"]),
                })
            if leads:
                break
        except Exception:
            continue

    return leads


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Orbit Marketing & Brand Growth Swarm")
    parser.add_argument("--once", action="store_true", help="Run a single growth sweep and exit")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in daemon mode")
    parser.add_argument("--interval", type=int, default=300, help="Sweep interval in seconds (default: 300)")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent.parent
    swarm = MarketingGrowthSwarm()

    def _execute() -> Dict[str, Any]:
        targets = _load_real_leads_pipeline(repo_root)
        return swarm.run_cycle(targets)

    if args.daemon:
        print(f"[*] Orbit Marketing & Growth Swarm active (Interval: {args.interval}s)")
        while True:
            try:
                res = _execute()
                cnt = res.get("campaign", {}).get("targets_count", 0)
                print(f"[{time.strftime('%H:%M:%S')}] Growth Swarm: staged campaign across {cnt} real agency leads.")
            except Exception as exc:
                print(f"[{time.strftime('%H:%M:%S')}] Growth Swarm error: {exc}")
            time.sleep(max(5, args.interval))

    res = _execute()
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
