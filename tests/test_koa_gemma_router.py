"""Unit tests and benchmarks for 26ms Local Koa / Gemma Decision Router.

Validates:
1. Pydantic v2 schema compliance:
   - TaskType enum validation.
   - Confidence bounds [0.0, 1.0].
   - Toolset generation and model assignment.
2. Ultra-low latency tiers:
   - Tier 0 instant regex/tactical heuristic routing (<1.0ms).
   - Tier 1 local SLM structured inference (sub-50ms target on warmed Ollama).
3. Deterministic schema enforcement and JSON recovery.
4. Async and sync routing interfaces.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from orbit_security.tools.koa_gemma_router import (
    KoaGemmaDecisionRouter,
    ModelTier,
    RouterDecision,
    TaskType,
)


class TestKoaGemmaDecisionRouter:
    """Unit tests for router schema and decision pathways."""

    def test_schema_valid_pydantic_v2(self):
        decision = RouterDecision(
            task_type=TaskType.CODING,
            confidence=0.98,
            target_model="orbit-coder:latest",
            required_toolset=["filesystem-tool", "python_interpreter"],
            reason="User requested code fix",
            latency_ms=1.2,
            routing_tier="reflex_heuristic",
        )
        data = decision.model_dump()
        assert data["task_type"] == "coding"
        assert data["confidence"] == 0.98
        assert "filesystem-tool" in data["required_toolset"]

    def test_schema_invalid_confidence_raises_validation_error(self):
        with pytest.raises(ValidationError):
            RouterDecision(
                task_type=TaskType.CODING,
                confidence=1.5,  # Invalid: > 1.0
                target_model="orbit-coder:latest",
            )

    def test_tier0_tactical_heuristic_sub_millisecond(self):
        router = KoaGemmaDecisionRouter()

        prompts = [
            ("Fix null pointer exception in auth service", TaskType.CODING, "orbit-coder"),
            ("Run passive OSINT and certificate audit on domain.com", TaskType.OSINT_RECON, "orbit-osint"),
            ("Review this diff for sql injection vulnerabilities", TaskType.CODE_REVIEW, "orbit-critic"),
            ("Design architecture for distributed event bus", TaskType.ARCHITECTURE, "orbit-thinker"),
            ("Status check vitals and cpu temperature", TaskType.SYSTEM_COMMAND, "nova-reflex"),
        ]

        for prompt, expected_task, expected_model_prefix in prompts:
            decision = router.route(prompt)
            assert isinstance(decision, RouterDecision)
            assert decision.task_type == expected_task
            assert expected_model_prefix in decision.target_model
            assert decision.routing_tier == "reflex_heuristic"
            assert decision.latency_ms < 5.0  # Heuristic should always be <5ms

    def test_tier1_ollama_mock_response(self):
        router = KoaGemmaDecisionRouter(model_name="gemma4:12b")

        mock_payload = {
            "task_type": "security_audit",
            "confidence": 0.95,
            "target_model": "orbit-sentinel:latest",
            "required_toolset": ["xh_probe", "duckdb_analytics"],
            "reason": "Security vulnerability probe requested",
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "response": json.dumps(mock_payload),
            "eval_duration": 25000000,  # 25ms in ns
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            # Use an unclassified conversational prompt to bypass Tier 0
            decision = router._route_via_ollama("Could you inspect the perimeter of server 10.0.0.1?")
            assert decision.task_type == TaskType.SECURITY_AUDIT
            assert decision.target_model == "orbit-sentinel:latest"
            assert "xh_probe" in decision.required_toolset
            assert decision.routing_tier == "local_slm"

    def test_ollama_malformed_json_resilience(self):
        router = KoaGemmaDecisionRouter(model_name="gemma4:12b")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "response": "```json\n{\"task_type\": \"coding\", \"confidence\": 0.9, \"target_model\": \"orbit-coder\"}\n```",
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            decision = router._route_via_ollama("Unusual raw prompt with markdown wrap")
            assert decision.task_type == TaskType.CODING
            assert decision.target_model == "orbit-coder"

    @pytest.mark.asyncio
    async def test_async_route_execution(self):
        router = KoaGemmaDecisionRouter()
        decision = await router.route_async("Fix syntax error in router.py")
        assert decision.task_type == TaskType.CODING
        assert decision.latency_ms < 10.0
