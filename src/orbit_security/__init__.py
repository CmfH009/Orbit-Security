"""Orbit Security: Autonomous external perimeter hygiene, subdomain takeover sentinel, and white-label client security auditing."""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_IMPORTS = {
    "AgencyBranding": ("orbit_security.models", "AgencyBranding"),
    "DomainAuditResult": ("orbit_security.models", "DomainAuditResult"),
    "Finding": ("orbit_security.models", "Finding"),
    "Severity": ("orbit_security.models", "Severity"),
    "OrbitSecurityScanner": ("orbit_security.scanner", "OrbitSecurityScanner"),
    "AgencySentryScanner": ("orbit_security.scanner", "AgencySentryScanner"),
    "ReportGenerator": ("orbit_security.reporter", "ReportGenerator"),
    "EmailDispatcher": ("orbit_security.mailer", "EmailDispatcher"),
    "InboxAgent": ("orbit_security.inbox_agent", "InboxAgent"),
    "LeadIntent": ("orbit_security.inbox_agent", "LeadIntent"),
    "VoiceProfile": ("orbit_security.voice_model", "VoiceProfile"),
    "CatVoiceEngine": ("orbit_security.voice_model", "CatVoiceEngine"),
    "RelevanceEngine": ("orbit_security.relevance_engine", "RelevanceEngine"),
    "DiscoveredPost": ("orbit_security.relevance_engine", "DiscoveredPost"),
    "RelevanceScore": ("orbit_security.relevance_engine", "RelevanceScore"),
    "ActionDecision": ("orbit_security.relevance_engine", "ActionDecision"),
    "ActionType": ("orbit_security.relevance_engine", "ActionType"),
    "DiscoveryVector": ("orbit_security.relevance_engine", "DiscoveryVector"),
    "GroundTruthGate": ("orbit_security.ground_truth_gate", "GroundTruthGate"),
    "GateVerdict": ("orbit_security.ground_truth_gate", "GateVerdict"),
    "FeedHarvester": ("orbit_security.feed_harvester", "FeedHarvester"),
    "DesktopAutomationDriver": ("orbit_security.desktop_x_bridge", "DesktopAutomationDriver"),
    "DesktopDriverConfig": ("orbit_security.desktop_x_bridge", "DesktopDriverConfig"),
    "DesktopXBridge": ("orbit_security.desktop_x_bridge", "DesktopXBridge"),
    "CertificateTransparencyStreamer": ("orbit_security.recon_harvester", "CertificateTransparencyStreamer"),
    "ArchiveHarvester": ("orbit_security.recon_harvester", "ArchiveHarvester"),
    "JsRouteExtractor": ("orbit_security.recon_harvester", "JsRouteExtractor"),
    "CloudBucketTakeoverSentinel": ("orbit_security.cloud_sentinels", "CloudBucketTakeoverSentinel"),
    "GraphQLIntrospectionSentinel": ("orbit_security.cloud_sentinels", "GraphQLIntrospectionSentinel"),
    "CorsMisconfigurationSentinel": ("orbit_security.cloud_sentinels", "CorsMisconfigurationSentinel"),
    "BountyAttackGraph": ("orbit_security.bounty_graph", "BountyAttackGraph"),
    "GemmaTriageCopilot": ("orbit_security.bounty_triage_copilot", "GemmaTriageCopilot"),
    "TriageDecision": ("orbit_security.bounty_triage_copilot", "TriageDecision"),
    "HttpRequestSmugglingSentinel": ("orbit_security.smuggling_sentinel", "HttpRequestSmugglingSentinel"),
    "SmugglingFinding": ("orbit_security.smuggling_sentinel", "SmugglingFinding"),
    "SmugglingFlawType": ("orbit_security.smuggling_sentinel", "SmugglingFlawType"),
    "OAuthFlowSentinel": ("orbit_security.oauth_sentinel", "OAuthFlowSentinel"),
    "OAuthFinding": ("orbit_security.oauth_sentinel", "OAuthFinding"),
    "OAuthFlawType": ("orbit_security.oauth_sentinel", "OAuthFlawType"),
    "DependencyConfusionSentinel": ("orbit_security.dependency_sentinel", "DependencyConfusionSentinel"),
    "DependencyFinding": ("orbit_security.dependency_sentinel", "DependencyFinding"),
    "DependencyStatus": ("orbit_security.dependency_sentinel", "DependencyStatus"),
    "OperatorExploitSandbox": ("orbit_security.exploit_sandbox", "OperatorExploitSandbox"),
    "ScriptGenerator": ("orbit_security.exploit_sandbox", "ScriptGenerator"),
    "SandboxExecutionHarness": ("orbit_security.exploit_sandbox", "SandboxExecutionHarness"),
    "EvidenceComparator": ("orbit_security.exploit_sandbox", "EvidenceComparator"),
    "SandboxVerificationReport": ("orbit_security.exploit_sandbox", "SandboxVerificationReport"),
    "EventShuttleSender": ("orbit_security.event_shuttle", "EventShuttleSender"),
    "EventShuttleReceiver": ("orbit_security.event_shuttle", "EventShuttleReceiver"),
    "ShuttleAuth": ("orbit_security.event_shuttle", "ShuttleAuth"),
    "CertificateTransparencyMonitor": ("orbit_security.cert_transparency", "CertificateTransparencyMonitor"),
    "EpssCorrelator": ("orbit_security.epss", "EpssCorrelator"),
    "EpssRecord": ("orbit_security.epss", "EpssRecord"),
    "PassiveTakeoverDetector": ("orbit_security.cname_takeover", "PassiveTakeoverDetector"),
    "TakeoverFinding": ("orbit_security.cname_takeover", "TakeoverFinding"),
    "PrivateAlertSentinel": ("orbit_security.private_alerting", "PrivateAlertSentinel"),
    "PrivateDefensiveAlert": ("orbit_security.private_alerting", "PrivateDefensiveAlert"),
}

__all__ = list(_LAZY_IMPORTS.keys()) + ["hello"]


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        module_name, attr_name = _LAZY_IMPORTS[name]
        module = importlib.import_module(module_name)
        val = getattr(module, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def hello() -> str:
    return "Hello from orbit-security!"
