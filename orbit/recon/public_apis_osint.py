"""Orbit Security: Public APIs OSINT Bridge.
Pure Python standard library implementation adhering to Majestic Monolith standards.
Connects A:\\reference\\public-apis to Orbit Security reconnaissance pipelines.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

DEFAULT_RESOURCES_PATH = Path(r"A:\reference\public-apis\db\resources.json")

# Core categories in public-apis relevant to OSINT, network recon, and perimeter intelligence
SECURITY_OSINT_CATEGORIES = frozenset([
    "Anti-Malware",
    "Authentication & Authorization",
    "Data Validation",
    "Email",
    "Geocoding",
    "Security",
    "Tracking",
    "URL Shorteners",
    "Open Data",
])


@dataclass(frozen=True)
class ApiEndpoint:
    name: str
    description: str
    auth: str
    cors: str
    link: str
    category: str
    domain: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApiEndpoint":
        link = data.get("Link", "")
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        if ":" in domain:
            domain = domain.split(":")[0]
        return cls(
            name=data.get("API", "").strip(),
            description=data.get("Description", "").strip(),
            auth=data.get("Auth", "").strip(),
            cors=data.get("Cors", "").strip(),
            link=link.strip(),
            category=data.get("Category", "").strip(),
            domain=domain,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PublicApisOsintBridge:
    """In-memory indexing and search engine for public API resources."""

    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_RESOURCES_PATH
        self._endpoints: List[ApiEndpoint] = []
        self._category_map: Dict[str, List[ApiEndpoint]] = {}
        self._loaded: bool = False
        if self.db_path.exists():
            self.load()

    def load(self) -> None:
        """Loads and indexes resources.json."""
        with open(self.db_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        entries = raw.get("entries", [])
        self._endpoints = [ApiEndpoint.from_dict(item) for item in entries]
        self._category_map.clear()
        for ep in self._endpoints:
            cat_key = ep.category.lower()
            self._category_map.setdefault(cat_key, []).append(ep)
        self._loaded = True

    @property
    def total_count(self) -> int:
        return len(self._endpoints)

    def get_categories(self) -> List[str]:
        """Returns sorted list of distinct original category names."""
        cats: Set[str] = {ep.category for ep in self._endpoints}
        return sorted(cats)

    def filter_by_category(self, category: str) -> List[ApiEndpoint]:
        """Filters endpoints by exact or case-insensitive category."""
        return self._category_map.get(category.lower(), [])

    def filter_security_and_osint(self, custom_categories: Optional[Iterable[str]] = None) -> List[ApiEndpoint]:
        """Filters endpoints belonging to security, anti-malware, verification, and OSINT-aligned categories."""
        allowed = {c.lower() for c in (custom_categories or SECURITY_OSINT_CATEGORIES)}
        return [ep for ep in self._endpoints if ep.category.lower() in allowed]

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        auth_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[ApiEndpoint]:
        """Sub-millisecond keyword search across API name, description, and link."""
        q = query.strip().lower()
        cat_lower = category.lower() if category else None
        auth_lower = auth_type.lower() if auth_type else None

        results: List[ApiEndpoint] = []
        candidates = self.filter_by_category(category) if cat_lower else self._endpoints

        for ep in candidates:
            if auth_lower and ep.auth.lower() != auth_lower:
                continue
            if not q or (q in ep.name.lower() or q in ep.description.lower() or q in ep.domain):
                results.append(ep)
                if len(results) >= limit:
                    break

        return results

    def extract_domains(self, endpoints: Optional[List[ApiEndpoint]] = None) -> Set[str]:
        """Extracts unique host domains for attack-surface pivoting or safe-host inspection."""
        source = endpoints if endpoints is not None else self._endpoints
        return {ep.domain for ep in source if ep.domain}
