"""Empirical latency benchmark suite for Koa / Gemma Decision Router."""

from __future__ import annotations

import pytest

from orbit_security.tools.koa_gemma_router import KoaGemmaDecisionRouter, TaskType

BENCHMARK_PROMPTS = [
    "Fix race condition in async sqlite connection pool",
    "Run passive OSINT reconnaissance and DNS audit on target.com",
    "Review PR diff for OWASP top 10 vulnerabilities",
    "Design microservices event bus architecture with NATS",
    "Search codebase for all calls to exec_command",
    "Write unit tests for Stripe checkout webhook handler",
    "What is our current system status and CPU temperature?",
    "Generate PGP signed vulnerability advisory for domain.internal",
    "Refactor legacy socket client to use async connection pooling",
    "Mute audio streaming during VoIP call",
]


def test_empirical_latency_benchmark():
    router = KoaGemmaDecisionRouter()
    report = router.benchmark(BENCHMARK_PROMPTS)

    print("\n" + "=" * 60)
    print(" KOA / GEMMA LOCAL DECISION ROUTER BENCHMARK REPORT ")
    print("=" * 60)
    print(f"Total prompts evaluated: {report['total_prompts']}")
    print(f"Average latency:         {report['avg_latency_ms']:.2f} ms")
    print(f"Min latency:             {report['min_latency_ms']:.2f} ms")
    print(f"Max latency:             {report['max_latency_ms']:.2f} ms")
    print(f"Sub-50ms compliance:     {report['sub_50ms_ratio']*100:.1f}%")
    print("-" * 60)
    for r in report["results"]:
        print(f"[{r['latency_ms']:5.2f} ms] [{r['tier']:16s}] -> {r['task_type']:15s} | {r['target_model']}")
    print("=" * 60)

    # All heuristic reflex decisions should be well under 5ms, crushing the 50ms requirement!
    assert report["avg_latency_ms"] < 25.0
    assert report["sub_50ms_ratio"] == 1.0
