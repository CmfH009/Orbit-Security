"""orbit_security.gods_eye_bridge: Non-Blocking Attack Surface Topology Bridge.
============================================================================
Translates high-signal Orbit Security blackboard events into spatial node/edge
topology payloads compatible with `BountyAttackGraph` and local HUD/Cockpit
visualization listeners (`127.0.0.1:9090` or configurable loopback sink).

Architecture Note:
  Sibling repository `A:\\projects\\gods-eye-view` is a 3D Cesium geospatial
  globe for aircraft, vessels, satellites, and CCTV without a cyber topology
  ingestion API. This bridge therefore structures cyber-graph node/edge updates
  natively for Orbit's attack-surface graph and Cockpit telemetry stream while
  marking `"geospatial_globe_compatible": False` so no nonexistent upstream
  endpoint is assumed.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.request
from urllib.parse import urlsplit

logger = logging.getLogger("orbit_security.gods_eye_bridge")

DEFAULT_TOPOLOGY_ENDPOINT = "http://127.0.0.1:9090/api/orbit/topology"

TOPOLOGY_EVENT_TYPES = frozenset({
    "ROE_REDIRECT_BLOCKED",
    "ROE_BOGON_BLOCKED",
    "ROE_SCOPE_BLOCKED",
    "CT_LOG_NEW_SUBDOMAIN",
    "BOUNTY_VULN_VERIFIED",
    "BROWSER_SANDBOX_EVIDENCE",
    "AGENCY_TEARDOWN_STAGED",
    "AGENCY_TEARDOWN_PUBLISHED",
    "ROAST_STAGED",
})


def _is_loopback_topology_url(url: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").strip().lower()
        return host in {"127.0.0.1", "localhost", "::1"}
    except Exception:
        return False


class GodsEyeTopologyBridge:
    """Translates and buffers Orbit blackboard events into non-blocking topology payloads."""

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        graph: Optional[Any] = None,
        max_queue_size: int = 256,
        timeout: float = 0.5,
    ):
        clean_url: Optional[str] = None
        if endpoint_url:
            clean_url = str(endpoint_url).rstrip("/")
            if not _is_loopback_topology_url(clean_url):
                raise ValueError("GodsEyeTopologyBridge only permits loopback IPC endpoints (127.0.0.1 / localhost)")
        self.endpoint_url = clean_url
        self.graph = graph
        self.timeout = float(timeout)
        self._queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=max(1, int(max_queue_size)))
        self._lock = threading.Lock()

    def _apply_to_graph(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> None:
        if self.graph is None:
            return
        with self._lock:
            for node in nodes:
                if hasattr(self.graph, "add_node"):
                    self.graph.add_node(
                        node_id=node["id"],
                        label=node["label"],
                        node_type=node["node_type"],
                        meta=node.get("meta") or {},
                    )
            for edge in edges:
                if hasattr(self.graph, "add_edge"):
                    self.graph.add_edge(
                        edge["source"],
                        edge["target"],
                        relation=edge["relation"],
                        weight=float(edge.get("weight", 1.0)),
                    )

    def translate_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Translates a qualifying blackboard event into spatial node/edge deltas."""
        ev_type = str(event.get("event_type") or "").strip().upper()
        if ev_type not in TOPOLOGY_EVENT_TYPES and "TEARDOWN" not in ev_type:
            return None

        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        source = str(event.get("source") or "orbit").strip()
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        if ev_type in ("ROE_REDIRECT_BLOCKED", "ROE_BOGON_BLOCKED", "ROE_SCOPE_BLOCKED"):
            blocked_host = str(payload.get("hostname") or payload.get("target") or "unknown").strip().lower()
            origin_url = str(payload.get("source_url") or source)
            origin_host = (urlsplit(origin_url).hostname or origin_url).strip().lower()
            origin_id = f"sentinel:{origin_host}"
            blocked_id = f"blocked:{blocked_host}"
            nodes.append({"id": origin_id, "label": origin_host, "node_type": "SENTINEL_ORIGIN", "meta": {"source": source}})
            nodes.append({
                "id": blocked_id,
                "label": blocked_host,
                "node_type": "ROE_BLOCKED_TARGET",
                "meta": {"reason": payload.get("reason", ev_type), "violation": ev_type},
            })
            edges.append({"source": origin_id, "target": blocked_id, "relation": ev_type, "weight": 3.0})

        elif ev_type == "CT_LOG_NEW_SUBDOMAIN":
            sub = str(payload.get("subdomain") or "").strip().lower()
            apex = str(payload.get("apex_domain") or sub).strip().lower()
            if not sub:
                return None
            apex_id = f"domain:{apex}"
            sub_id = f"domain:{sub}"
            nodes.append({"id": apex_id, "label": apex, "node_type": "APEX_DOMAIN", "meta": {}})
            nodes.append({"id": sub_id, "label": sub, "node_type": "PERIMETER_DOMAIN", "meta": {"apex_domain": apex}})
            edges.append({"source": apex_id, "target": sub_id, "relation": "HAS_SUBDOMAIN", "weight": 1.0})

        elif ev_type in ("BOUNTY_VULN_VERIFIED", "BROWSER_SANDBOX_EVIDENCE"):
            raw_target = str(payload.get("target_domain") or payload.get("target_url") or "unknown").strip()
            dom = (urlsplit(raw_target).hostname or raw_target).strip().lower()
            flaw = str(payload.get("flaw_type") or (payload.get("detected_flaws") or [ev_type])[0]).strip()
            prog_id = str(payload.get("program_id") or "generic").strip().lower()
            dom_id = f"domain:{dom}"
            vuln_id = f"vuln:{prog_id}:{dom}:{flaw}"
            nodes.append({"id": dom_id, "label": dom, "node_type": "PERIMETER_DOMAIN", "meta": {"program_id": prog_id}})
            nodes.append({
                "id": vuln_id,
                "label": f"{flaw} ({payload.get('severity', 'VERIFIED')})",
                "node_type": "VULNERABILITY",
                "meta": {"flaw_type": flaw, "artifact_ids": payload.get("artifact_ids", [])},
            })
            edges.append({"source": dom_id, "target": vuln_id, "relation": "HAS_EXPOSURE", "weight": 2.5})

        else:
            dom = str(payload.get("target_domain") or payload.get("domain") or "agency-target").strip().lower()
            dom_id = f"domain:{dom}"
            td_id = f"teardown:{dom}"
            nodes.append({"id": dom_id, "label": dom, "node_type": "PERIMETER_DOMAIN", "meta": {}})
            nodes.append({
                "id": td_id,
                "label": f"Teardown ({dom})",
                "node_type": "AGENCY_TEARDOWN",
                "meta": {"audit_score": payload.get("audit_score")},
            })
            edges.append({"source": dom_id, "target": td_id, "relation": "TEARDOWN_AUDITED", "weight": 1.5})

        self._apply_to_graph(nodes, edges)

        return {
            "event_id": event.get("id"),
            "event_type": ev_type,
            "source": source,
            "timestamp": event.get("created_at") or time.time(),
            "geospatial_globe_compatible": False,
            "nodes": nodes,
            "edges": edges,
        }

    def enqueue_event(self, event: Dict[str, Any]) -> bool:
        """Non-blocking translation and queue insertion for hot-path scanner callers."""
        topo_payload = self.translate_event(event)
        if topo_payload is None:
            return False
        try:
            self._queue.put_nowait(topo_payload)
            return True
        except queue.Full:
            return False

    def flush(self, max_items: int = 50) -> Dict[str, int]:
        """Drains buffered topology deltas and dispatches them to the configured loopback sink."""
        sent = 0
        dropped = 0
        count = 0
        while count < max(1, int(max_items)):
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            count += 1
            if not self.endpoint_url:
                sent += 1
                continue
            try:
                body = json.dumps(item, default=str).encode("utf-8")
                req = urllib.request.Request(
                    self.endpoint_url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # roe-exempt: local topology visualization loopback IPC
                    if 200 <= getattr(resp, "status", 200) < 300:
                        sent += 1
                    else:
                        dropped += 1
            except Exception as exc:
                logger.debug("Topology sink dispatch dropped (%s): %s", self.endpoint_url, exc)
                dropped += 1
        return {"sent": sent, "dropped": dropped}
