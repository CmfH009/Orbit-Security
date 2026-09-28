"""Orbit Security: Autonomous external perimeter hygiene, subdomain takeover sentinel, and white-label client security auditing."""

from orbit_security.models import AgencyBranding, DomainAuditResult, Finding, Severity
from orbit_security.scanner import OrbitSecurityScanner, AgencySentryScanner
from orbit_security.reporter import ReportGenerator
from orbit_security.mailer import EmailDispatcher
from orbit_security.inbox_agent import InboxAgent, LeadIntent
from orbit_security.voice_model import VoiceProfile, CatVoiceEngine

__all__ = [
    "AgencyBranding",
    "DomainAuditResult",
    "Finding",
    "Severity",
    "OrbitSecurityScanner",
    "AgencySentryScanner",
    "ReportGenerator",
    "EmailDispatcher",
    "InboxAgent",
    "LeadIntent",
    "VoiceProfile",
    "CatVoiceEngine",
    "hello",
]

def hello() -> str:
    return "Hello from orbit-security!"

