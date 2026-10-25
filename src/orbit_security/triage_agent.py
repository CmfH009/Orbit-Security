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

import argparse
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
FALLBACK_MODEL_PRIORITY = (
    "qwen2.5-coder:7b-instruct-q4_K_M",
    "orbit-sentinel:latest",
    "orbit-coder:latest",
    "gemma4:e4b",
    "gemma4:e2b",
    "llama3.2:latest",
    "gemma2:2b",
)


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
        self._installed_models: List[str] = []
        if blackboard is None:
            from orbit_security.blackboard import get_blackboard
            self.bb = get_blackboard()
        else:
            self.bb = blackboard

    def is_ollama_available(self, timeout: float = 1.5) -> bool:
        """Checks if local Ollama daemon is reachable and caches installed models."""
        try:
            parsed = urllib.parse.urlparse(self.ollama_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else "http://127.0.0.1:11434"
            req = urllib.request.Request(f"{base_url}/api/tags", headers={"User-Agent": "Orbit-Triage/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    try:
                        raw = resp.read()
                        if raw:
                            tags_data = json.loads(raw.decode("utf-8"))
                            self._installed_models = [
                                m.get("name", "") for m in tags_data.get("models", []) if m.get("name")
                            ]
                    except Exception:
                        pass
                    return True
                return False
        except Exception:
            return False

    def resolve_available_model(self) -> str:
        """Selects configured model if installed, or highest-priority local Orbit/quantized model."""
        if not self._installed_models:
            return self.model_name
        if self.model_name in self._installed_models:
            return self.model_name
        for candidate in FALLBACK_MODEL_PRIORITY:
            if candidate in self._installed_models:
                return candidate
        return self._installed_models[0]

    def triage_vulnerability(
        self,
        event_type: str,
        payload: Dict[str, Any],
        unload_after: bool = True,
        timeout: float = 60.0,
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

        # Attempt live Ollama inference
        if self.is_ollama_available():
            active_model = self.resolve_available_model()
            keep_alive = "0" if unload_after else "5m"
            req_payload = {
                "model": active_model,
                "messages": [{"role": "user", "content": prompt}],
                "format": TriageRemediationSpec.model_json_schema(),
                "options": {"temperature": 0.1},
                "keep_alive": keep_alive,
                "stream": False,
            }
            try:
                body_bytes = json.dumps(req_payload).encode("utf-8")
                req = urllib.request.Request(
                    self.ollama_url,
                    data=body_bytes,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
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


def main():
    parser = argparse.ArgumentParser(description="Orbit Security Local Quantized LLM Triage Agent")
    parser.add_argument("--event-type", default="CISA_KEV_MATCH_DETECTED", help="Security event type")
    parser.add_argument("--cve", default="CVE-2024-21887", help="CVE ID or service component")
    parser.add_argument("--domain", default="vpn.agency-client.example", help="Target domain")
    parser.add_argument("--model", default=None, help="Explicit Ollama model name")
    parser.add_argument("--keep-loaded", action="store_true", help="Keep model in RAM for 5m instead of immediate unload")
    args = parser.parse_args()

    agent = LocalTriageAgent(model_name=args.model)
    online = agent.is_ollama_available()
    resolved_model = agent.resolve_available_model() if online else "offline-fallback"
    spec = agent.triage_vulnerability(
        event_type=args.event_type,
        payload={"domain": args.domain, "cve_id": args.cve},
        unload_after=not args.keep_loaded,
    )
    output = {
        "ollama_online": online,
        "resolved_model": resolved_model,
        "keep_alive": "5m" if args.keep_loaded else "0",
        "triage_spec": spec.model_dump(),
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()

