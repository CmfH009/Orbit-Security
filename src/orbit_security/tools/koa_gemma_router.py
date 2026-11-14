"""Koa / Gemma High-Performance Local Decision Router.

Executes deterministic sub-50ms (and down to 0.5ms via Tier 0 reflex) structured
intent routing on local Ollama (`localhost:11434`) at 0% cloud token cost:
- Maps developer tasks to optimal specialized models (`orbit-coder`, `orbit-critic`, `gemma4:12b`, `gemini-3.8-flash`).
- Automatically resolves required toolsets (`filesystem-tool`, `xh_probe`, `duckdb_analytics`, etc.).
- Enforces strict Pydantic v2 JSON schema contracts.
- Eliminates slow ~1.4s general cloud LLM pre-checks before triggering agent workflows.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("orbit_security.koa_gemma_router")


class TaskType(str, Enum):
    CODING = "coding"
    CODE_REVIEW = "code_review"
    SECURITY_AUDIT = "security_audit"
    ARCHITECTURE = "architecture"
    OSINT_RECON = "osint_recon"
    SYSTEM_COMMAND = "system_command"
    DOCUMENTATION = "documentation"
    GENERAL_CHAT = "general_chat"


class ModelTier(str, Enum):
    ORBIT_CODER_FAST = "orbit-coder-fast:latest"
    ORBIT_CODER = "orbit-coder:latest"
    ORBIT_CRITIC = "orbit-critic:latest"
    ORBIT_THINKER = "orbit-thinker:latest"
    ORBIT_OSINT = "orbit-osint:latest"
    ORBIT_SENTINEL = "orbit-sentinel:latest"
    NOVA_REFLEX = "nova-reflex:latest"
    GEMMA4_12B = "gemma4:12b"
    CLOUD_GEMINI_FLASH = "gemini-3.8-flash"
    CLOUD_GEMINI_PRO = "gemini-3.8-pro"


class RouterDecision(BaseModel):
    """Deterministic Pydantic v2 decision schema emitted by Koa / Gemma Router."""
    task_type: TaskType
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    target_model: str = Field(default=ModelTier.ORBIT_CODER.value)
    required_toolset: List[str] = Field(default_factory=list)
    reason: str = Field(default="")
    latency_ms: float = Field(default=0.0)
    routing_tier: str = Field(default="local_slm")  # "reflex_heuristic" | "local_slm" | "fallback"
    fallback_applied: bool = Field(default=False)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, float(v)))


# Builtin toolsets associated with task domains
DOMAIN_TOOLSETS: Dict[TaskType, List[str]] = {
    TaskType.CODING: ["filesystem-tool", "python_interpreter", "test_runner"],
    TaskType.CODE_REVIEW: ["filesystem-tool", "git_diff", "ast_scanner"],
    TaskType.SECURITY_AUDIT: ["xh_probe", "duckdb_analytics", "attack_tree", "gemini_multimodal"],
    TaskType.ARCHITECTURE: ["graphify_query", "attack_tree", "filesystem-tool"],
    TaskType.OSINT_RECON: ["xh_probe", "adhx_client", "everything_search"],
    TaskType.SYSTEM_COMMAND: ["powershell_runner", "psutil_vitals"],
    TaskType.DOCUMENTATION: ["filesystem-tool", "markdown_generator"],
    TaskType.GENERAL_CHAT: [],
}

# Heuristic patterns for Tier 0 instant routing (<1.0ms)
TIER0_PATTERNS: List[Tuple[re.Pattern, TaskType, str, str]] = [
    (
        re.compile(r"\b(recon|osint|whois|subdomain|dns audit|certificate|shodan)\b", re.I),
        TaskType.OSINT_RECON,
        ModelTier.ORBIT_OSINT.value,
        "Matched passive OSINT/recon pattern",
    ),
    (
        re.compile(r"\b(fix|bug|syntax error|null pointer|refactor|implement|code|tests?|testing|patch|compile|webhook|handler|search|grep|trace|exec_command)\b", re.I),
        TaskType.CODING,
        ModelTier.ORBIT_CODER.value,
        "Matched coding/patching regex pattern",
    ),
    (
        re.compile(r"\b(review|diff|pr|vulnerability|code review|advisory|pgp|owasp|sanitize|critique)\b", re.I),
        TaskType.CODE_REVIEW,
        ModelTier.ORBIT_CRITIC.value,
        "Matched adversarial code review pattern",
    ),
    (
        re.compile(r"\b(architecture|design|pattern|distributed|event bus|microservices|nats|schema design|cortex|dag)\b", re.I),
        TaskType.ARCHITECTURE,
        ModelTier.ORBIT_THINKER.value,
        "Matched architectural deliberation pattern",
    ),
    (
        re.compile(r"\b(status|vitals|cpu temp|temperature|mute|unmute|throttle|cooldown|abort|cancel|stop)\b", re.I),
        TaskType.SYSTEM_COMMAND,
        ModelTier.NOVA_REFLEX.value,
        "Matched tactical system reflex command",
    ),
]


def _validate_local_ollama_url(ollama_url: str) -> str:
    """Validate that the configured Ollama endpoint points to a local loopback host."""
    clean = (ollama_url or "").strip().rstrip("/")
    parsed = urlsplit(clean)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().strip("[]").lower()
    is_loopback = host == "localhost"
    if not is_loopback and host:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if scheme not in ("http", "https") or not is_loopback:
        raise ValueError(f"Ollama URL must target a local loopback host, got {ollama_url!r}")
    return clean


class KoaGemmaDecisionRouter:
    """High-speed local structured intent router.
    
    Routes user tasks to specialized agent models and toolsets within sub-50ms budgets.
    """

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model_name: str = "gemma4:12b",
        enable_tier0_heuristics: bool = True,
        timeout_s: float = 0.8,
    ):
        self.ollama_url = _validate_local_ollama_url(ollama_url)
        self.model_name = model_name
        self.enable_tier0_heuristics = enable_tier0_heuristics
        self.timeout_s = timeout_s
        self._sync_client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(  # roe-exempt: local Ollama loopback inference endpoint
                timeout=self.timeout_s,
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            )
        return self._sync_client

    async def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(  # roe-exempt: local Ollama loopback inference endpoint
                timeout=self.timeout_s,
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            )
        return self._async_client

    def _evaluate_tier0_heuristics(self, prompt: str) -> Optional[RouterDecision]:
        """Sub-1ms deterministic regex & pattern matcher for standard developer prompts."""
        for pattern, task_type, target_model, reason in TIER0_PATTERNS:
            if pattern.search(prompt):
                toolset = DOMAIN_TOOLSETS.get(task_type, [])
                return RouterDecision(
                    task_type=task_type,
                    confidence=0.96,
                    target_model=target_model,
                    required_toolset=list(toolset),
                    reason=reason,
                    routing_tier="reflex_heuristic",
                    fallback_applied=False,
                )
        return None

    def _build_ollama_payload(self, prompt: str) -> Dict[str, Any]:
        """Constructs minimal structured generation prompt for Ollama."""
        system_instructions = (
            "You are Koa, a microsecond decision router. Classify user prompt into JSON: "
            '{"task_type": "coding"|"code_review"|"security_audit"|"architecture"|"osint_recon"|"system_command"|"documentation"|"general_chat", '
            '"confidence": 0.0-1.0, "target_model": string, "required_toolset": [string], "reason": string}'
        )
        return {
            "model": self.model_name,
            "prompt": f"{system_instructions}\nUser: {prompt}\nJSON:",
            "format": "json",
            "stream": False,
            "keep_alive": -1,
            "options": {
                "temperature": 0.0,
                "num_predict": 32,
            },
        }

    def _sanitize_and_parse_json(self, raw_resp: str) -> Dict[str, Any]:
        """Extracts and validates JSON from raw model string."""
        clean = raw_resp.strip()
        if clean.startswith("```"):
            clean = re.sub(r"^```(?:json)?\s*", "", clean)
            clean = re.sub(r"\s*```$", "", clean)
        
        # Try direct parse
        try:
            return json.loads(clean)
        except Exception:
            # Fallback regex extraction of first json object
            m = re.search(r"\{.*\}", clean, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    pass
        return {}

    def _route_via_ollama(self, prompt: str) -> RouterDecision:
        """Executes Tier 1 SLM structured inference over Ollama."""
        client = self._get_sync_client()
        payload = self._build_ollama_payload(prompt)

        resp = client.post(f"{self.ollama_url}/api/generate", json=payload)
        if resp.status_code != 200:
            raise RuntimeError(f"Ollama returned HTTP {resp.status_code}: {resp.text}")

        data = resp.json()
        raw_text = data.get("response", "{}")
        parsed = self._sanitize_and_parse_json(raw_text)

        # Map to valid TaskType
        raw_type = str(parsed.get("task_type", "general_chat")).lower().strip()
        try:
            task_type = TaskType(raw_type)
        except ValueError:
            task_type = TaskType.GENERAL_CHAT

        confidence = float(parsed.get("confidence", 0.9))
        target_model = str(parsed.get("target_model") or self.model_name)
        toolset = parsed.get("required_toolset")
        if not isinstance(toolset, list):
            toolset = DOMAIN_TOOLSETS.get(task_type, [])

        return RouterDecision(
            task_type=task_type,
            confidence=confidence,
            target_model=target_model,
            required_toolset=toolset,
            reason=str(parsed.get("reason", "Local SLM triage")),
            routing_tier="local_slm",
            fallback_applied=False,
        )

    def route(self, prompt: str) -> RouterDecision:
        """Synchronously routes prompt through Tier 0 heuristic or Tier 1 Ollama SLM."""
        t0 = time.perf_counter()

        # 1. Tier 0: Instant heuristic reflex (<1ms)
        if self.enable_tier0_heuristics:
            t0_decision = self._evaluate_tier0_heuristics(prompt)
            if t0_decision:
                t0_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
                return t0_decision

        # 2. Tier 1: Local Ollama SLM query
        try:
            decision = self._route_via_ollama(prompt)
            decision.latency_ms = (time.perf_counter() - t0) * 1000.0
            return decision
        except Exception as e:
            logger.warning(f"Koa router Ollama fallback on error: {e}")
            elapsed = (time.perf_counter() - t0) * 1000.0
            return RouterDecision(
                task_type=TaskType.GENERAL_CHAT,
                confidence=0.5,
                target_model=ModelTier.CLOUD_GEMINI_FLASH.value,
                required_toolset=[],
                reason=f"Routing fallback applied: {e}",
                latency_ms=elapsed,
                routing_tier="fallback",
                fallback_applied=True,
            )

    async def route_async(self, prompt: str) -> RouterDecision:
        """Asynchronously routes prompt with non-blocking I/O."""
        t0 = time.perf_counter()

        if self.enable_tier0_heuristics:
            t0_decision = self._evaluate_tier0_heuristics(prompt)
            if t0_decision:
                t0_decision.latency_ms = (time.perf_counter() - t0) * 1000.0
                return t0_decision

        try:
            client = await self._get_async_client()
            payload = self._build_ollama_payload(prompt)
            resp = await client.post(f"{self.ollama_url}/api/generate", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                parsed = self._sanitize_and_parse_json(data.get("response", "{}"))
                raw_type = str(parsed.get("task_type", "general_chat")).lower().strip()
                try:
                    task_type = TaskType(raw_type)
                except ValueError:
                    task_type = TaskType.GENERAL_CHAT

                decision = RouterDecision(
                    task_type=task_type,
                    confidence=float(parsed.get("confidence", 0.9)),
                    target_model=str(parsed.get("target_model") or self.model_name),
                    required_toolset=parsed.get("required_toolset") or DOMAIN_TOOLSETS.get(task_type, []),
                    reason=str(parsed.get("reason", "Async Local SLM triage")),
                    routing_tier="local_slm",
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )
                return decision
        except Exception as e:
            logger.warning(f"Async Koa router fallback on error: {e}")

        elapsed = (time.perf_counter() - t0) * 1000.0
        return RouterDecision(
            task_type=TaskType.GENERAL_CHAT,
            confidence=0.5,
            target_model=ModelTier.CLOUD_GEMINI_FLASH.value,
            required_toolset=[],
            reason="Async routing fallback applied",
            latency_ms=elapsed,
            routing_tier="fallback",
            fallback_applied=True,
        )

    def benchmark(self, prompts: List[str]) -> Dict[str, Any]:
        """Runs a benchmark across a suite of task prompts and produces latency metrics."""
        results: List[Dict[str, Any]] = []
        latencies: List[float] = []

        for p in prompts:
            decision = self.route(p)
            lat = decision.latency_ms
            latencies.append(lat)
            results.append({
                "prompt": p[:50],
                "task_type": decision.task_type.value,
                "target_model": decision.target_model,
                "tier": decision.routing_tier,
                "latency_ms": round(lat, 2),
            })

        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        min_lat = min(latencies) if latencies else 0.0
        max_lat = max(latencies) if latencies else 0.0

        return {
            "total_prompts": len(prompts),
            "avg_latency_ms": round(avg_lat, 2),
            "min_latency_ms": round(min_lat, 2),
            "max_latency_ms": round(max_lat, 2),
            "sub_50ms_ratio": round(sum(1 for l in latencies if l <= 50.0) / len(latencies), 3) if latencies else 1.0,
            "results": results,
        }
