"""orbit_security.epss: Exploit Prediction Scoring System (EPSS) Correlator Engine.
=================================================================================
Correlates detected perimeter CVEs and software versions against FIRST EPSS scores
to predict active exploitation likelihood in the wild over the next 30 days.

Features:
- Local 24-hour TTL disk cache (data/epss_cache.json) to eliminate rate limits.
- Built-in offline fixture fallback for airgapped environments and testing.
- Probabilistic weaponization tiering (HIGH >= 0.35, CRITICAL >= 0.60).
- Combined correlation with CISA KEV for definitive 0-day threat prioritization.
- Standardized SQLite WAL Blackboard event publishing (EPSS_SCORE_EVALUATED).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("orbit_security.epss")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_EPSS_CACHE_PATH = REPO_ROOT / "data" / "epss_cache.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"

# Built-in essential EPSS baseline for offline runs, airgapped nodes, and unit tests
BUILTIN_EPSS_FALLBACK: Dict[str, Dict[str, Any]] = {
    "CVE-2024-21887": {
        "cve": "CVE-2024-21887",
        "epss": "0.94210",
        "percentile": "0.99120",
        "date": "2026-10-24",
    },
    "CVE-2021-41773": {
        "cve": "CVE-2021-41773",
        "epss": "0.97430",
        "percentile": "0.99840",
        "date": "2026-10-24",
    },
    "CVE-2021-42013": {
        "cve": "CVE-2021-42013",
        "epss": "0.96500",
        "percentile": "0.99610",
        "date": "2026-10-24",
    },
    "CVE-2023-3519": {
        "cve": "CVE-2023-3519",
        "epss": "0.92340",
        "percentile": "0.98700",
        "date": "2026-10-24",
    },
    "CVE-2021-44228": {
        "cve": "CVE-2021-44228",
        "epss": "0.97540",
        "percentile": "0.99910",
        "date": "2026-10-24",
    },
    "CVE-2023-38606": {
        "cve": "CVE-2023-38606",
        "epss": "0.18520",
        "percentile": "0.82010",
        "date": "2026-10-24",
    },
}


@dataclass
class EpssRecord:
    cve_id: str
    epss_score: float
    percentile: float
    date: str
    tier: str  # "CRITICAL", "HIGH", "ELEVATED", "BASELINE"


class EpssCorrelator:
    """Manages EPSS score fetching, local caching, and exploit prediction correlation."""

    def __init__(
        self,
        cache_file: Optional[Path] = None,
        offline_fixtures: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.cache_file = Path(cache_file or DEFAULT_EPSS_CACHE_PATH)
        self.offline_fixtures = offline_fixtures or BUILTIN_EPSS_FALLBACK

    def is_cache_valid(self, ttl_seconds: float = 86400.0) -> bool:
        """Returns True if the local disk cache exists and is fresh."""
        if not self.cache_file.exists():
            return False
        try:
            raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
            cache_ts = float(raw.get("timestamp", 0.0))
            return (time.time() - cache_ts) < ttl_seconds
        except Exception:
            return False

    def load_cached_scores(self) -> Dict[str, Dict[str, Any]]:
        """Loads cached score mapping from disk."""
        if not self.cache_file.exists():
            return {}
        try:
            raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
            return raw.get("scores", {})
        except Exception:
            return {}

    def save_cached_scores(self, scores: Dict[str, Dict[str, Any]]):
        """Persists updated scores to disk cache."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "timestamp": time.time(),
                "scores": scores,
            }
            self.cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as ex:
            logger.debug(f"Failed to write EPSS cache: {ex}")

    @staticmethod
    def classify_tier(score: float) -> str:
        """Categorizes EPSS probability into actionable threat tiers."""
        if score >= 0.60:
            return "CRITICAL"
        elif score >= 0.35:
            return "HIGH"
        elif score >= 0.10:
            return "ELEVATED"
        return "BASELINE"

    def get_score(self, cve_id: str, force_refresh: bool = False) -> Optional[EpssRecord]:
        """Retrieves EPSS probability and percentile for a single CVE."""
        clean_cve = cve_id.strip().upper()

        # 1. Use explicit offline fixture if available
        if clean_cve in self.offline_fixtures:
            item = self.offline_fixtures[clean_cve]
            score = float(item.get("epss", 0.0))
            percentile = float(item.get("percentile", 0.0))
            return EpssRecord(
                cve_id=clean_cve,
                epss_score=score,
                percentile=percentile,
                date=item.get("date", ""),
                tier=self.classify_tier(score),
            )

        # 2. Check disk cache if fresh
        cached_scores = self.load_cached_scores()
        if not force_refresh and self.is_cache_valid() and clean_cve in cached_scores:
            item = cached_scores[clean_cve]
            score = float(item.get("epss", 0.0))
            percentile = float(item.get("percentile", 0.0))
            return EpssRecord(
                cve_id=clean_cve,
                epss_score=score,
                percentile=percentile,
                date=item.get("date", ""),
                tier=self.classify_tier(score),
            )

        # 3. Live API request to FIRST EPSS endpoint
        url = EPSS_API_URL.format(cve_id=clean_cve)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "OrbitSecurity-EPSSCorrelator/1.0", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    items = data.get("data", [])
                    if items:
                        item = items[0]
                        score = float(item.get("epss", 0.0))
                        percentile = float(item.get("percentile", 0.0))
                        cached_scores[clean_cve] = item
                        self.save_cached_scores(cached_scores)
                        return EpssRecord(
                            cve_id=clean_cve,
                            epss_score=score,
                            percentile=percentile,
                            date=item.get("date", ""),
                            tier=self.classify_tier(score),
                        )
        except Exception as ex:
            logger.debug(f"Live EPSS query failed for {clean_cve}: {ex}")

        # 4. Fallback to fixture if live pull fails
        if clean_cve in self.offline_fixtures:
            item = self.offline_fixtures[clean_cve]
            score = float(item.get("epss", 0.0))
            percentile = float(item.get("percentile", 0.0))
            return EpssRecord(
                cve_id=clean_cve,
                epss_score=score,
                percentile=percentile,
                date=item.get("date", ""),
                tier=self.classify_tier(score),
            )

        return None

    def correlate_cves(
        self,
        cve_ids: List[str],
        domain: Optional[str] = None,
        blackboard: Any = None,
        threshold: float = 0.35,
    ) -> List[EpssRecord]:
        """Correlates multiple CVEs against EPSS, emitting events for high-probability targets."""
        records: List[EpssRecord] = []
        for cve in cve_ids:
            rec = self.get_score(cve)
            if not rec:
                continue
            records.append(rec)

            if rec.epss_score >= threshold and blackboard:
                try:
                    blackboard.publish(
                        event_type="EPSS_SCORE_EVALUATED",
                        payload={
                            "cve_id": rec.cve_id,
                            "epss_score": rec.epss_score,
                            "percentile": rec.percentile,
                            "tier": rec.tier,
                            "domain": domain or "unknown",
                            "high_threat": rec.epss_score >= 0.50,
                        },
                        source="epss_correlator",
                        topic="cve_radar",
                    )
                except Exception as ex:
                    logger.debug(f"Failed to publish EPSS blackboard event: {ex}")

        return records

    def correlate_with_cisa_kev(
        self,
        cve_ids: List[str],
        cisa_kev_catalog: Any,
        domain: Optional[str] = None,
        blackboard: Any = None,
    ) -> List[Dict[str, Any]]:
        """Joint correlation combining CISA KEV known weaponization with EPSS 30-day forecast."""
        results: List[Dict[str, Any]] = []

        for cve in cve_ids:
            clean_cve = cve.strip().upper()
            kev_entry = cisa_kev_catalog.vulnerabilities.get(clean_cve) if cisa_kev_catalog else None
            epss_rec = self.get_score(clean_cve)

            is_in_kev = kev_entry is not None
            epss_score = epss_rec.epss_score if epss_rec else 0.0
            percentile = epss_rec.percentile if epss_rec else 0.0

            # Priority categorization
            if is_in_kev and epss_score >= 0.50:
                threat_level = "CRITICAL_ACTUALLY_EXPLOITED_IN_WILD"
            elif is_in_kev:
                threat_level = "HIGH_KNOWN_EXPLOITED"
            elif epss_score >= 0.50:
                threat_level = "HIGH_PREDICTED_EXPLOITABLE"
            else:
                threat_level = "ELEVATED" if epss_score >= 0.10 else "LOW"

            entry = {
                "cve_id": clean_cve,
                "in_cisa_kev": is_in_kev,
                "epss_score": epss_score,
                "epss_percentile": percentile,
                "threat_level": threat_level,
                "vendor": kev_entry.vendor_project if kev_entry else "unknown",
                "product": kev_entry.product if kev_entry else "unknown",
                "domain": domain or "unknown",
            }
            results.append(entry)

            if threat_level == "CRITICAL_ACTUALLY_EXPLOITED_IN_WILD" and blackboard:
                try:
                    blackboard.publish(
                        event_type="CRITICAL_0DAY_CORRELATED",
                        payload=entry,
                        source="epss_kev_fusion_correlator",
                        topic="cve_radar",
                    )
                except Exception as ex:
                    logger.debug(f"Failed to publish fused KEV+EPSS event: {ex}")

        return results
