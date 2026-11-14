"""orbit_security.cert_transparency: Certificate Transparency (CT) Log Sentinel.
=============================================================================
Passively monitors public Certificate Transparency log streams (e.g. crt.sh)
for newly minted SSL/TLS certificates and uncataloged subdomains across target assets.

Features:
- Passive discovery without active port scanning or DNS brute-forcing.
- 24-hour TTL disk cache (data/ct_cache.json) to respect upstream rate limits.
- Built-in offline fixture fallback for airgapped environments and testing.
- Subdomain extraction, wildcard normalization, and anomaly filtering.
- Standardized SQLite WAL Blackboard event publishing (CT_LOG_CERTIFICATE_DISCOVERED,
  CT_LOG_NEW_SUBDOMAIN).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("orbit_security.cert_transparency")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CT_CACHE_PATH = REPO_ROOT / "data" / "ct_cache.json"
DEFAULT_CT_WATERMARK_PATH = REPO_ROOT / "data" / "ct_watermark.json"
CRTSH_BASE_URL = "https://crt.sh/?q=%.{domain}&output=json"

BUILTIN_CT_FALLBACK: Dict[str, List[Dict[str, Any]]] = {
    "example.com": [
        {
            "id": 10001,
            "logged_at": "2026-10-20T08:00:00",
            "not_before": "2026-10-20T00:00:00",
            "not_after": "2027-01-18T23:59:59",
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com\napi.example.com\nstaging.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "serial_number": "03a1b2c3d4e5f67890",
        },
        {
            "id": 10002,
            "logged_at": "2026-10-22T14:30:00",
            "not_before": "2026-10-22T00:00:00",
            "not_after": "2027-01-20T23:59:59",
            "common_name": "*.assets.example.com",
            "name_value": "*.assets.example.com\nassets.example.com",
            "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global G2",
            "serial_number": "04b2c3d4e5f6789012",
        },
    ]
}


@dataclass
class CertificateEntry:
    cert_id: int
    common_name: str
    issuer: str
    logged_at: str
    not_before: str
    not_after: str
    san_domains: List[str]
    serial_number: str = ""


class CertificateTransparencyMonitor:
    """Monitors CT log feeds and correlates new perimeter subdomains."""

    def __init__(
        self,
        cache_file: Optional[Path] = None,
        offline_fixtures: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        offline: bool = False,
    ):
        self.cache_file = Path(cache_file or DEFAULT_CT_CACHE_PATH)
        self.offline_fixtures = offline_fixtures or BUILTIN_CT_FALLBACK
        self.offline = offline
        self.known_subdomains: Dict[str, Set[str]] = {}

    def is_cache_valid(self, domain: str, ttl_seconds: float = 86400.0) -> bool:
        """Checks if cached CT query for domain is fresh."""
        if not self.cache_file.exists():
            return False
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            domain_cache = data.get(domain.lower(), {})
            ts = float(domain_cache.get("timestamp", 0.0))
            return (time.time() - ts) < ttl_seconds
        except Exception:
            return False

    def load_from_cache(self, domain: str) -> Optional[List[Dict[str, Any]]]:
        """Loads cached CT query results for domain."""
        if not self.cache_file.exists():
            return None
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            domain_cache = data.get(domain.lower(), {})
            return domain_cache.get("records")
        except Exception:
            return None

    def save_to_cache(self, domain: str, records: List[Dict[str, Any]]):
        """Saves CT query results for domain atomically to disk cache."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            existing = {}
            if self.cache_file.exists():
                try:
                    existing = json.loads(self.cache_file.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}

            existing[domain.lower()] = {
                "timestamp": time.time(),
                "records": records,
            }
            tmp_cache = self.cache_file.with_suffix(".tmp")
            tmp_cache.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            tmp_cache.replace(self.cache_file)
        except Exception as ex:
            logger.debug(f"Failed to save CT cache: {ex}")

    def fetch_certificates(
        self,
        domain: str,
        force_refresh: bool = False,
        offline: Optional[bool] = None,
    ) -> List[CertificateEntry]:
        """Fetches certificates for domain from cache, live API, or fallback fixture."""
        clean_domain = domain.strip().lower()
        records: Optional[List[Dict[str, Any]]] = None
        effective_offline = self.offline if offline is None else offline

        # 1. Use explicit test fixture if defined
        if clean_domain in self.offline_fixtures:
            records = self.offline_fixtures[clean_domain]

        # 2. Use disk cache if fresh
        elif not force_refresh and self.is_cache_valid(clean_domain):
            records = self.load_from_cache(clean_domain)

        # 3. Live network pull if no cache or fixture and NOT in offline mode
        if records is None:
            if effective_offline:
                logger.debug("Offline mode: skipping live CT network pull for %s", clean_domain)
                records = self.offline_fixtures.get(clean_domain, [])
            else:
                domain_regex = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
                if not domain_regex.match(clean_domain):
                    logger.warning(f"Invalid domain rejected for CT scan: {clean_domain}")
                    records = []
                else:
                    encoded_domain = urllib.parse.quote(clean_domain)
                    url = f"https://crt.sh/?q=%.{encoded_domain}&output=json"
                    req = urllib.request.Request(
                        url,
                        headers={"User-Agent": "OrbitSecurity-CTMonitor/1.0", "Accept": "application/json"},
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=6.0) as resp:
                            if resp.status == 200:
                                records = json.loads(resp.read().decode("utf-8"))
                                self.save_to_cache(clean_domain, records)
                    except urllib.error.HTTPError as he:
                        if he.code == 429:
                            logger.warning(f"Live CT pull rate limited (429) for {clean_domain}; using fallback")
                        else:
                            logger.warning(f"Live CT pull HTTP {he.code} for {clean_domain}: {he}")
                    except Exception as ex:
                        logger.warning(f"Live CT pull failed for {clean_domain}: {ex}; checking fallback")

        # 4. Fallback if network failed or rate limited
        if records is None:
            records = self.offline_fixtures.get(clean_domain, [])

        results: List[CertificateEntry] = []
        for r in records:
            name_val = r.get("name_value", "")
            cn = str(r.get("common_name", "")).strip()
            # Split SANs by whitespace or newline
            sans: List[str] = []
            candidates = list(re.split(r"[\s\r\n]+", name_val))
            if cn:
                candidates.append(cn)

            for item in candidates:
                clean_item = item.strip().lower()
                if clean_item.startswith("*."):
                    clean_item = clean_item[2:]
                elif clean_item.startswith("."):
                    clean_item = clean_item.lstrip(".")

                # Strict boundary check: must be the apex domain or end with dot-apex
                if clean_item and (clean_item == clean_domain or clean_item.endswith(f".{clean_domain}")):
                    if clean_item not in sans:
                        sans.append(clean_item)

            entry = CertificateEntry(
                cert_id=int(r.get("id") or 0),
                common_name=str(r.get("common_name", "")),
                issuer=str(r.get("issuer_name", "")),
                logged_at=str(r.get("entry_timestamp", r.get("logged_at", ""))),
                not_before=str(r.get("not_before", "")),
                not_after=str(r.get("not_after", "")),
                san_domains=sans,
                serial_number=str(r.get("serial_number", "")),
            )
            results.append(entry)

        return results

    def discover_subdomains(
        self,
        domain: str,
        known_baselines: Optional[Set[str]] = None,
        blackboard: Any = None,
    ) -> Dict[str, Any]:
        """Extracts unique subdomains and publishes newly discovered perimeter assets to Blackboard."""
        clean_domain = domain.strip().lower()
        certs = self.fetch_certificates(clean_domain)

        all_subdomains: Set[str] = set()
        for cert in certs:
            for san in cert.san_domains:
                all_subdomains.add(san)

        baseline = set(known_baselines or self.known_subdomains.get(clean_domain, set()))
        new_discoveries = sorted(list(all_subdomains - baseline))

        # Update known state
        if clean_domain not in self.known_subdomains:
            self.known_subdomains[clean_domain] = set()
        self.known_subdomains[clean_domain].update(all_subdomains)

        # Publish events to SQLite WAL Blackboard if connected
        if blackboard and new_discoveries:
            for sub in new_discoveries:
                try:
                    blackboard.publish(
                        event_type="CT_LOG_NEW_SUBDOMAIN",
                        payload={
                            "subdomain": sub,
                            "apex_domain": clean_domain,
                            "source_feed": "certificate_transparency",
                            "discovered_at": time.time(),
                        },
                        source="cert_transparency_monitor",
                        topic="threat_intel",
                    )
                except Exception as ex:
                    logger.debug(f"Failed to publish CT subdomain event: {ex}")

        return {
            "domain": clean_domain,
            "total_certificates": len(certs),
            "total_subdomains": len(all_subdomains),
            "new_subdomains": new_discoveries,
            "subdomains": sorted(list(all_subdomains)),
        }


class CtStreamDaemon:
    """Continuous Certificate Transparency log daemon with persistent watermark state and CNAME takeover chaining."""

    def __init__(
        self,
        watermark_file: Optional[Path] = None,
        cache_file: Optional[Path] = None,
        blackboard: Any = None,
        takeover_detector: Any = None,
        cname_probe_map: Optional[Dict[str, Dict[str, Any]]] = None,
        offline_fixtures: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        offline: bool = False,
    ):
        self.watermark_file = Path(watermark_file or DEFAULT_CT_WATERMARK_PATH)
        self.offline = offline
        self.monitor = CertificateTransparencyMonitor(
            cache_file=cache_file,
            offline_fixtures=offline_fixtures,
            offline=self.offline,
        )
        self.blackboard = blackboard
        if takeover_detector is None:
            from orbit_security.cname_takeover import PassiveTakeoverDetector
            self.takeover_detector = PassiveTakeoverDetector()
        else:
            self.takeover_detector = takeover_detector

        self.cname_probe_map = cname_probe_map or {}
        self.seen_cert_ids: Dict[str, Set[int]] = {}
        self.known_subdomains: Dict[str, Set[str]] = {}
        self._state_lock = threading.Lock()
        self.load_watermark()

    def load_watermark(self):
        """Loads persistent CT certificate ID and subdomain watermarks from disk."""
        if not self.watermark_file.exists():
            return
        try:
            raw = json.loads(self.watermark_file.read_text(encoding="utf-8"))
            domains_data = raw.get("domains", {})
            for dom, state in domains_data.items():
                self.seen_cert_ids[dom] = {int(cid) for cid in state.get("seen_cert_ids", [])}
                self.known_subdomains[dom] = {str(s).lower() for s in state.get("known_subdomains", [])}
                self.monitor.known_subdomains[dom] = set(self.known_subdomains[dom])
        except Exception as ex:
            logger.debug(f"Failed to load CT watermark from {self.watermark_file}: {ex}")

    def save_watermark(self):
        """Persists CT certificate ID and subdomain watermarks atomically to disk."""
        try:
            self.watermark_file.parent.mkdir(parents=True, exist_ok=True)
            domains_payload: Dict[str, Any] = {}
            all_domains = set(self.seen_cert_ids.keys()) | set(self.known_subdomains.keys())
            for dom in sorted(all_domains):
                domains_payload[dom] = {
                    "seen_cert_ids": sorted(list(self.seen_cert_ids.get(dom, set()))),
                    "known_subdomains": sorted(list(self.known_subdomains.get(dom, set()))),
                    "updated_at": time.time(),
                }
            tmp_path = self.watermark_file.with_suffix(".tmp")
            tmp_path.write_text(json.dumps({"domains": domains_payload}, indent=2), encoding="utf-8")
            tmp_path.replace(self.watermark_file)
        except Exception as ex:
            logger.debug(f"Failed to save CT watermark to {self.watermark_file}: {ex}")

    def poll_domain(
        self,
        domain: str,
        force_refresh: bool = False,
        program: Optional[Any] = None,
        batch_size: int = 100,
    ) -> Dict[str, Any]:
        """Polls CT log feed for domain, computes delta against persistent watermark, and chains takeover checks."""
        from orbit_security.bounty_radar import RulesOfEngagementEngine

        clean_domain = domain.strip().lower().lstrip("*.")
        certs = self.monitor.fetch_certificates(clean_domain, force_refresh=force_refresh, offline=self.offline)

        new_certs: List[CertificateEntry] = []
        all_subdomains: Set[str] = set()
        pending_events: List[Dict[str, Any]] = []

        with self._state_lock:
            seen_certs = self.seen_cert_ids.setdefault(clean_domain, set())
            known_subs = self.known_subdomains.setdefault(clean_domain, set())

            for cert in certs:
                if cert.cert_id and cert.cert_id not in seen_certs:
                    new_certs.append(cert)
                    seen_certs.add(cert.cert_id)
                    if self.blackboard:
                        pending_events.append({
                            "event_type": "CT_LOG_CERTIFICATE_DISCOVERED",
                            "payload": {
                                "cert_id": cert.cert_id,
                                "common_name": cert.common_name,
                                "issuer": cert.issuer,
                                "san_domains": cert.san_domains,
                                "apex_domain": clean_domain,
                            },
                            "source": "ct_stream_daemon",
                            "topic": "threat_intel",
                        })
                for san in cert.san_domains:
                    all_subdomains.add(san)

            raw_new_subdomains = sorted(list(all_subdomains - known_subs))
            known_subs.update(all_subdomains)
            self.monitor.known_subdomains[clean_domain] = set(known_subs)

        if program is not None:
            new_subdomains = [
                sub for sub in raw_new_subdomains
                if RulesOfEngagementEngine.is_permitted(program, sub)
            ]
        else:
            new_subdomains = raw_new_subdomains

        takeover_findings: List[Dict[str, Any]] = []
        now_ts = time.time()
        for sub in new_subdomains:
            if self.blackboard:
                pending_events.append({
                    "event_type": "CT_LOG_NEW_SUBDOMAIN",
                    "payload": {
                        "subdomain": sub,
                        "apex_domain": clean_domain,
                        "source_feed": "certificate_transparency",
                        "discovered_at": now_ts,
                    },
                    "source": "ct_stream_daemon",
                    "topic": "threat_intel",
                })

            # Automatic CNAME takeover evaluation chain
            probe_info = self.cname_probe_map.get(sub)
            if probe_info and self.takeover_detector:
                cname_target = probe_info.get("cname") or probe_info.get("cname_target") or ""
                body_snippet = probe_info.get("body_snippet", "")
                is_nxdomain = bool(probe_info.get("is_nxdomain", False))
                if cname_target:
                    finding = self.takeover_detector.evaluate_cname(
                        domain=sub,
                        cname_target=cname_target,
                        body_snippet=body_snippet,
                        is_nxdomain=is_nxdomain,
                        blackboard=self.blackboard,
                    )
                    if finding:
                        takeover_findings.append(asdict(finding))

        if self.blackboard and pending_events:
            chunked_publish_events(
                self.blackboard,
                pending_events,
                chunk_size=batch_size,
                default_source="ct_stream_daemon",
                default_topic="threat_intel",
            )

        with self._state_lock:
            self.save_watermark()

        permitted_all = (
            [s for s in sorted(list(all_subdomains)) if RulesOfEngagementEngine.is_permitted(program, s)]
            if program is not None
            else sorted(list(all_subdomains))
        )

        return {
            "domain": clean_domain,
            "total_certificates": len(certs),
            "new_certificates": len(new_certs),
            "total_subdomains": len(permitted_all),
            "new_subdomains": new_subdomains,
            "takeover_findings": takeover_findings,
            "subdomains": permitted_all,
        }

    def poll_domains(
        self,
        domains: List[str],
        force_refresh: bool = False,
        program: Optional[Any] = None,
        max_workers: int = 1,
        batch_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """Polls a list of apex domains and returns CT delta results."""
        clean_domains: List[str] = []
        seen_apex: Set[str] = set()
        for d in domains:
            clean = d.strip().lower().lstrip("*.")
            if not clean or clean in seen_apex:
                continue
            seen_apex.add(clean)
            clean_domains.append(clean)

        if max_workers > 1 and len(clean_domains) > 1:
            workers = min(int(max_workers), len(clean_domains))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [
                    pool.submit(
                        self.poll_domain,
                        dom,
                        force_refresh=force_refresh,
                        program=program,
                        batch_size=batch_size,
                    )
                    for dom in clean_domains
                ]
                return [fut.result() for fut in futures]

        return [
            self.poll_domain(
                dom,
                force_refresh=force_refresh,
                program=program,
                batch_size=batch_size,
            )
            for dom in clean_domains
        ]


def chunked_publish_events(
    blackboard: Any,
    events: List[Dict[str, Any]],
    chunk_size: int = 100,
    default_source: str = "ct_stream_daemon",
    default_topic: str = "threat_intel",
) -> List[int]:
    """Publishes blackboard events in bounded chunks via publish_batch to curb SQLite WAL lock pressure."""
    if blackboard is None or not events:
        return []
    size = max(1, int(chunk_size))
    inserted_ids: List[int] = []
    if hasattr(blackboard, "publish_batch"):
        for start in range(0, len(events), size):
            chunk = events[start:start + size]
            try:
                batch_ids = blackboard.publish_batch(
                    chunk,
                    default_source=default_source,
                    default_topic=default_topic,
                )
                if isinstance(batch_ids, list):
                    inserted_ids.extend(batch_ids)
            except Exception as exc:
                logger.debug("Chunked publish_batch failed cleanly: %s", exc)
        return inserted_ids

    if hasattr(blackboard, "publish"):
        for ev in events:
            try:
                ev_id = blackboard.publish(
                    event_type=str(ev.get("event_type") or "EVENT"),
                    payload=ev.get("payload") or {},
                    source=str(ev.get("source") or default_source),
                    topic=str(ev.get("topic") or default_topic),
                )
                inserted_ids.append(ev_id)
            except Exception as exc:
                logger.debug("Fallback publish failed cleanly: %s", exc)
    return inserted_ids


class MicrogravitySubdomainDispatcher:
    """RoE-filtered parallel CT and passive subdomain fan-out coordinator across enrolled programs.

    Note: Sibling `microgravity/mg.exe` exposes an AI coding CLI (`agent`, `audit`, `chat`, `run`, `swarm`)
    and does not provide a DNS/CT enumeration subcommand. Unless an external worker callable is supplied,
    fan-out runs natively in pure Python with ThreadPoolExecutor concurrency and chunked WAL batch commits.
    """

    def __init__(
        self,
        ct_daemon: Optional[CtStreamDaemon] = None,
        blackboard: Any = None,
        max_workers: int = 4,
        batch_size: int = 100,
        external_worker: Optional[Callable[[Any], List[str]]] = None,
    ):
        self.blackboard = blackboard
        self.ct_daemon = ct_daemon or CtStreamDaemon(blackboard=blackboard)
        if blackboard is not None and self.ct_daemon.blackboard is None:
            self.ct_daemon.blackboard = blackboard
        self.max_workers = max(1, int(max_workers))
        self.batch_size = max(1, int(batch_size))
        self.external_worker = external_worker

    def _scan_single_program(self, program: Any, force_refresh: bool = False) -> Dict[str, Any]:
        from orbit_security.bounty_radar import RulesOfEngagementEngine

        poll_results = self.ct_daemon.poll_domains(
            list(getattr(program, "in_scope", []) or []),
            force_refresh=force_refresh,
            program=program,
            max_workers=self.max_workers,
            batch_size=self.batch_size,
        )

        program_subs: List[str] = []
        seen_local: Set[str] = set()
        for res in poll_results:
            for sub in res.get("new_subdomains", []):
                if sub not in seen_local and RulesOfEngagementEngine.is_permitted(program, sub):
                    seen_local.add(sub)
                    program_subs.append(sub)

        if self.external_worker is not None:
            extra_events: List[Dict[str, Any]] = []
            for cand in self.external_worker(program) or []:
                norm = str(cand).strip().lower().lstrip("*.")
                if norm and norm not in seen_local and RulesOfEngagementEngine.is_permitted(program, norm):
                    seen_local.add(norm)
                    program_subs.append(norm)
                    if self.blackboard is not None:
                        extra_events.append({
                            "event_type": "CT_LOG_NEW_SUBDOMAIN",
                            "payload": {
                                "subdomain": norm,
                                "program_id": getattr(program, "program_id", ""),
                                "source_feed": "external_worker",
                                "discovered_at": time.time(),
                            },
                            "source": "microgravity_dispatcher",
                            "topic": "threat_intel",
                        })
            if extra_events and self.blackboard is not None:
                chunked_publish_events(
                    self.blackboard,
                    extra_events,
                    chunk_size=self.batch_size,
                    default_source="microgravity_dispatcher",
                    default_topic="threat_intel",
                )

        return {
            "program_id": getattr(program, "program_id", ""),
            "domains_polled": len(poll_results),
            "subdomains": program_subs,
        }

    def fan_out_programs(
        self,
        programs: List[Any],
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Concurrently sweeps multiple bounty programs through RoE-filtered batched CT discovery."""
        if not programs:
            return {
                "programs_scanned": 0,
                "mg_cli_active": self.external_worker is not None,
                "discovered_subdomains": [],
                "program_results": [],
            }

        results: List[Dict[str, Any]] = []
        if self.max_workers > 1 and len(programs) > 1:
            workers = min(self.max_workers, len(programs))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [
                    pool.submit(self._scan_single_program, prog, force_refresh=force_refresh)
                    for prog in programs
                ]
                results = [fut.result() for fut in futures]
        else:
            results = [self._scan_single_program(prog, force_refresh=force_refresh) for prog in programs]

        deduped: List[str] = []
        seen_global: Set[str] = set()
        for item in results:
            for sub in item.get("subdomains", []):
                if sub not in seen_global:
                    seen_global.add(sub)
                    deduped.append(sub)

        return {
            "programs_scanned": len(results),
            "mg_cli_active": self.external_worker is not None,
            "discovered_subdomains": deduped,
            "program_results": results,
        }


def fetch_certificates(
    domain: str,
    force_refresh: bool = False,
    cache_file: Optional[Path] = None,
    offline_fixtures: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> List[CertificateEntry]:
    """Fetches certificates for domain using a CertificateTransparencyMonitor instance."""
    monitor = CertificateTransparencyMonitor(
        cache_file=cache_file,
        offline_fixtures=offline_fixtures,
    )
    return monitor.fetch_certificates(domain, force_refresh=force_refresh)


