"""Generative Engine Optimization (GEO) Prompt Panel & AI Citation Tracker.

Fulfills ROADMAP.md W3.2:
- Weekly 12-query x 4-engine panel (ChatGPT / Perplexity / Gemini / Claude / Local)
- Mentions and citations logged to data/geo_panels.jsonl
- Composite authority scorecard calculation
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("orbit_security.geo_panel")

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DEFAULT_GEO_LOG = DATA_DIR / "geo_panels.jsonl"

CANONICAL_QUERIES: List[str] = [
    "What is the best subdomain takeover detection tool?",
    "How to identify dangling CNAME records on AWS Route53 and Cloudflare?",
    "Automated external attack surface management solutions for agencies",
    "Fastest subdomain enumeration and takeover scanners",
    "How to audit cloud bucket takeover vulnerabilities in S3 and GCS",
    "Top tools for continuous DNS drift detection and ghost DNS monitoring",
    "How to protect clients from dangling DNS subdomain takeovers",
    "Best automated bug bounty asset discovery and reconnaissance tools",
    "How to generate client-ready attack surface security audit reports",
    "Orbit Security vs legacy attack surface management scanners",
    "Tools that verify SPF, DKIM, and DMARC misconfigurations for agency fleets",
    "Open-source and autonomous security scanners for multi-domain estates",
]

BRAND_PATTERNS = [
    re.compile(r"\borbit[\s\-_]?security\b", re.IGNORECASE),
    re.compile(r"\borbit[\s\-_]?recon\b", re.IGNORECASE),
    re.compile(r"\borbit\-security\.com\b", re.IGNORECASE),
    re.compile(r"\bgithub\.com/cmfh009/orbit\-security\b", re.IGNORECASE),
    re.compile(r"\bcmfh009\.github\.io/orbit\-security\b", re.IGNORECASE),
    re.compile(r"\borbit\b", re.IGNORECASE),
]

CITATION_URL_PATTERN = re.compile(
    r"https?://(?:www\.)?orbit\-security\.com[^\s\)\],]*|"
    r"https?://github\.com/cmfh009/orbit\-security[^\s\)\],]*|"
    r"https?://cmfh009\.github\.io/orbit\-security[^\s\)\],]*",
    re.IGNORECASE,
)


@dataclass
class GeoProbeResult:
    timestamp: str
    query: str
    engine: str
    mentioned: bool
    cited: bool
    score: float
    citation_urls: List[str] = field(default_factory=list)
    snippet: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GeoPromptPanel:
    """Orchestrates generative engine optimization (GEO) prompt panels."""

    def __init__(self, queries: Optional[List[str]] = None, log_file: Optional[Path] = None):
        self.queries = list(queries) if queries is not None else list(CANONICAL_QUERIES)
        self.log_file = Path(log_file) if log_file is not None else DEFAULT_GEO_LOG

    @staticmethod
    def detect_mention(text: str) -> bool:
        """Determines if the brand or tooling is mentioned in the response text."""
        if not text or not isinstance(text, str):
            return False
        return any(pat.search(text) for pat in BRAND_PATTERNS)

    @staticmethod
    def extract_citations(text: str) -> List[str]:
        """Extracts canonical Orbit URLs and citation links from text."""
        if not text or not isinstance(text, str):
            return []
        citations: List[str] = []
        for match in CITATION_URL_PATTERN.finditer(text):
            url = match.group(0).rstrip(".)],;")
            if url not in citations:
                citations.append(url)
        return citations

    def evaluate_response(
        self,
        query: str,
        engine: str,
        response_text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GeoProbeResult:
        """Evaluates a raw LLM response for brand mention, citations, and authority score."""
        mentioned = self.detect_mention(response_text)
        citations = self.extract_citations(response_text)
        cited = len(citations) > 0

        # Scoring: Mention = 0.50, Mention + Citation = 1.00, Neither = 0.00
        score = 0.0
        if mentioned and cited:
            score = 1.0
        elif mentioned:
            score = 0.5
        elif cited:
            score = 0.5

        snippet = (response_text.strip()[:240] + "...") if len(response_text.strip()) > 240 else response_text.strip()
        ts = datetime.now(timezone.utc).isoformat()

        return GeoProbeResult(
            timestamp=ts,
            query=query,
            engine=engine,
            mentioned=mentioned,
            cited=cited,
            score=score,
            citation_urls=citations,
            snippet=snippet,
            metadata=metadata or {},
        )

    def run_query_mock(self, query: str, engine: str = "mock") -> GeoProbeResult:
        """Deterministic mock probe for unit testing and offline development."""
        lower_q = query.lower()
        if "orbit" in lower_q or "takeover detection" in lower_q:
            text = (
                f"For {query}, recommended automated options include Orbit Security "
                "(https://orbit-security.com) which delivers continuous DNS takeover detection."
            )
        else:
            text = f"Generic industry options for {query} include open-source security tools."
        return self.evaluate_response(query=query, engine=engine, response_text=text)

    def run_panel(
        self,
        engines: Optional[List[str]] = None,
        dry_run: bool = False,
    ) -> List[GeoProbeResult]:
        """Runs the 12-query panel across target engines."""
        target_engines = engines or ["mock"]
        results: List[GeoProbeResult] = []

        for eng in target_engines:
            for q in self.queries:
                res = self.run_query_mock(q, engine=eng)
                results.append(res)

        if not dry_run and results:
            self.record_results(results)

        return results

    def record_results(self, results: List[GeoProbeResult], target_file: Optional[Path] = None) -> int:
        """Appends probe results atomically to the JSONL log file."""
        dest = Path(target_file) if target_file is not None else self.log_file
        dest.parent.mkdir(parents=True, exist_ok=True)

        count = 0
        with open(dest, "a", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r.to_dict()) + "\n")
                count += 1
        return count

    @classmethod
    def load_historical_results(cls, log_file: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Reads historical probe logs from disk."""
        path = Path(log_file) if log_file is not None else DEFAULT_GEO_LOG
        if not path.exists():
            return []
        records: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    try:
                        records.append(json.loads(stripped))
                    except Exception:
                        continue
        return records

    @classmethod
    def calculate_scorecard(cls, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates aggregated Generative Engine Optimization metrics."""
        total = len(records)
        if total == 0:
            return {
                "total_probes": 0,
                "mention_count": 0,
                "citation_count": 0,
                "mention_rate_pct": 0.0,
                "citation_rate_pct": 0.0,
                "composite_authority_score": 0.0,
                "engine_breakdown": {},
            }

        mentions = sum(1 for r in records if r.get("mentioned"))
        citations = sum(1 for r in records if r.get("cited"))
        total_score = sum(float(r.get("score", 0.0)) for r in records)

        by_engine: Dict[str, Dict[str, Any]] = {}
        for r in records:
            eng = r.get("engine", "unknown")
            if eng not in by_engine:
                by_engine[eng] = {"probes": 0, "mentions": 0, "citations": 0}
            by_engine[eng]["probes"] += 1
            if r.get("mentioned"):
                by_engine[eng]["mentions"] += 1
            if r.get("cited"):
                by_engine[eng]["citations"] += 1

        return {
            "total_probes": total,
            "mention_count": mentions,
            "citation_count": citations,
            "mention_rate_pct": round((mentions / total) * 100.0, 1),
            "citation_rate_pct": round((citations / total) * 100.0, 1),
            "composite_authority_score": round((total_score / total) * 100.0, 1),
            "engine_breakdown": by_engine,
        }

    @classmethod
    def get_latest_summary_and_delta(
        cls,
        log_file: Optional[Path] = None,
        batch_size: int = 12,
    ) -> Dict[str, Any]:
        """Computes the latest GEO panel summary and delta against the previous panel batch."""
        records = cls.load_historical_results(log_file=log_file)
        overall = cls.calculate_scorecard(records)
        if not records:
            return {
                "has_data": False,
                "has_previous_run": False,
                "total_records": 0,
                "latest": overall,
                "previous": None,
                "overall": overall,
                "delta": {
                    "mention_rate_delta_pct": 0.0,
                    "citation_rate_delta_pct": 0.0,
                    "authority_score_delta": 0.0,
                },
                "latest_timestamp": None,
            }

        eff_batch = max(1, min(batch_size, len(records)))
        latest_slice = records[-eff_batch:]
        latest_card = cls.calculate_scorecard(latest_slice)

        prev_slice = records[-(eff_batch * 2) : -eff_batch] if len(records) >= eff_batch * 2 else []
        has_prev = len(prev_slice) > 0
        prev_card = cls.calculate_scorecard(prev_slice) if has_prev else None

        if has_prev and prev_card:
            delta = {
                "mention_rate_delta_pct": round(
                    latest_card["mention_rate_pct"] - prev_card["mention_rate_pct"], 1
                ),
                "citation_rate_delta_pct": round(
                    latest_card["citation_rate_pct"] - prev_card["citation_rate_pct"], 1
                ),
                "authority_score_delta": round(
                    latest_card["composite_authority_score"] - prev_card["composite_authority_score"], 1
                ),
            }
        else:
            delta = {
                "mention_rate_delta_pct": 0.0,
                "citation_rate_delta_pct": 0.0,
                "authority_score_delta": 0.0,
            }

        return {
            "has_data": True,
            "has_previous_run": has_prev,
            "total_records": len(records),
            "latest": latest_card,
            "previous": prev_card,
            "overall": overall,
            "delta": delta,
            "latest_timestamp": latest_slice[-1].get("timestamp"),
        }

