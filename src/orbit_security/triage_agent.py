"""orbit_security.triage_agent: Local Quantized LLM Triage Sentinel.
=======================================================================
Pipes high-severity Blackboard security events (CISA KEV, takeover findings)
into a local quantized model via Ollama (http://127.0.0.1:11434/api/chat).

Features:
- Schema-constrained JSON extraction using Pydantic (TriageRemediationSpec).
- Strict low-temperature inference (temperature=0.1) for deterministic analysis.
- Controlled memory lifecycle: sets keep_alive="5m" (or "0" on completion) so
  Ollama automatically unloads model weights from RAM, keeping workstation memory free.
- Offline deterministic fallback when local Ollama runtime is offline or testing.
- Publishes structured TRIAGE_COMPLETED events back to the SQLite WAL Blackboard.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("orbit_security.triage_agent")

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
DEFAULT_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"


class TriageRemediationSpec(BaseModel):
    """Schema-constrained vulnerability triage and remediation specification."""
    cve_id: str = Field(description="Target CVE identifier or Vulnerability Token")
    threat_level: str = Field(description="Triaged threat level: CRITICAL, HIGH, MEDIUM, LOW")
    cvss_score: float = Field(ge=0.0, le=10.0, description="Calculated CVSS v3.1 base score")
    attack_vector: str = Field(description="Primary attack vector: NETWORK, ADJACENT, LOCAL, PHYSICAL")
    remediation_patch: str = Field(description="Actionable configuration change or code patch to mitigate")
    executive_summary: str = Field(description="Concise 1-2 sentence executive briefing for operators")


class LocalTriageAgent:
    """Manages offline, schema-constrained LLM triage via Ollama."""

    def __init__(
        self,
        ollama_url: Optional[str] = None,
        model_name: Optional[str] = None,
        blackboard: Any = None,
    ):
        self.ollama_url = ollama_url or os.environ.get("ORBIT_OLLAMA_URL", DEFAULT_OLLAMA_URL)
        self.model_name = model_name or os.environ.get("ORBIT_TRIAGE_MODEL", DEFAULT_MODEL)
        if blackboard is None:
            from orbit_security.blackboard import get_blackboard
            self.bb = get_blackboard()
        else:
            self.bb = blackboard

    def is_ollama_available(self, timeout: float = 1.0) -> bool:
        """Checks if local Ollama daemon is reachable."""
        try:
            req = urllib.request.Request("http://127.0.0.1:11434/api/tags", headers={"User-Agent": "Orbit-Triage/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def triage_vulnerability(
        self,
        event_type: str,
        payload: Dict[str, Any],
        unload_after: bool = True,
    ) -> TriageRemediationSpec:
        """Analyzes vulnerability event and returns schema-constrained triage spec."""
        target = payload.get("domain") or payload.get("target") or "target.system"
        cve_id = payload.get("cve_id") or payload.get("service") or "VULN-UNKNOWN"

        prompt = (
            f"You are Orbit Security's autonomous triage agent. Analyze this security discovery:\n"
            f"Event Type: {event_type}\n"
            f"Target: {target}\n"
            f"CVE/Component: {cve_id}\n"
            f"Raw Details: {json.dumps(payload)}\n\n"
            f"Provide a definitive CVSS v3.1 score, threat rating, concrete remediation patch, "
            f"and executive summary."
        )

        keep_alive = "0" if unload_after else "5m"
        req_payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "format": TriageRemediationSpec.model_json_schema(),
            "options": {"temperature": 0.1},
            "keep_alive": keep_alive,
            "stream": False,
        }

        # Attempt live Ollama inference
        if self.is_ollama_available():
            try:
                body_bytes = json.dumps(req_payload).encode("utf-8")
                req = urllib.request.Request(
                    self.ollama_url,
                    data=body_bytes,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    if resp.status == 200:
                        res_data = json.loads(resp.read().decode("utf-8"))
                        msg_content = res_data.get("message", {}).get("content", "{}")
                        parsed_spec = json.loads(msg_content)
                        spec = TriageRemediationSpec(**parsed_spec)
                        self._publish_triage_complete(spec, target, event_type)
                        return spec
            except Exception as ex:
                logger.warning(f"Ollama inference failed ({ex}); using deterministic fallback")

        # Deterministic offline fallback (airgapped or testing mode)
        spec = self._deterministic_fallback(event_type, payload)
        self._publish_triage_complete(spec, target, event_type)
        return spec

    def _deterministic_fallback(self, event_type: str, payload: Dict[str, Any]) -> TriageRemediationSpec:
        """Generates deterministic remediation spec when Ollama runtime is offline."""
        cve = payload.get("cve_id") or payload.get("service") or "CVE-GENERIC"
        if event_type == "CISA_KEV_MATCH_DETECTED":
            return TriageRemediationSpec(
                cve_id=cve,
                threat_level="CRITICAL",
                cvss_score=9.8,
                attack_vector="NETWORK",
                remediation_patch="Upgrade server package to latest vendor security release or isolate network endpoint.",
                executive_summary=f"CISA KEV matched active weaponized exploit for {cve}. Immediate patching mandated.",
            )
        elif event_type == "SUBDOMAIN_TAKEOVER_DETECTED":
            provider = payload.get("provider", "Cloud Provider")
            return TriageRemediationSpec(
                cve_id=f"TAKEOVER-{provider.upper().replace(' ', '-')}",
                threat_level="CRITICAL",
                cvss_score=8.6,
                attack_vector="NETWORK",
                remediation_patch="Remove dangling CNAME DNS record or claim the orphaned cloud bucket/app.",
                executive_summary=f"Dangling CNAME record allows unauthenticated takeover of target subdomain on {provider}.",
            )
        return TriageRemediationSpec(
            cve_id=cve,
            threat_level="MEDIUM",
            cvss_score=5.3,
            attack_vector="NETWORK",
            remediation_patch="Review exposed perimeter headers and apply defensive hardening policies.",
            executive_summary=f"Perimeter exposure detected for {cve}. Review access controls.",
        )

    def _publish_triage_complete(self, spec: TriageRemediationSpec, target: str, source_event: str):
        """Emits TRIAGE_COMPLETED event to SQLite WAL Blackboard."""
        if self.bb:
            self.bb.publish(
                event_type="TRIAGE_COMPLETED",
                payload={
                    "target": target,
                    "source_event": source_event,
                    "cve_id": spec.cve_id,
                    "threat_level": spec.threat_level,
                    "cvss_score": spec.cvss_score,
                    "remediation_patch": spec.remediation_patch,
                    "executive_summary": spec.executive_summary,
                    "triaged_at": time.time(),
                },
                source="local-triage-agent",
                topic="intel",
            )
