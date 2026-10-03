"""Orbit Security: Dependency Confusion & Internal Package Namespace Takeover Engine (dependency_sentinel.py).

Provides Phase G supply-chain auditing capabilities:
1. Harvest internal/scoped package references from JavaScript bundles, Webpack manifests, and source maps.
2. Query public package registries (npm, PyPI) to detect unclaimed namespace availability.
3. Quantify high-yield supply chain takeover impact (CVSS 9.8 - 10.0 Critical) with non-exploitative safety guarantees.

Safety Invariant:
- Strictly passive metadata query engine.
- NEVER attempts to register, claim, or publish stub packages or payloads.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import enum
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request

from orbit_security.models import Severity
from orbit_security.scanner import is_safe_host

logger = logging.getLogger("orbit_security.dependency_sentinel")


class PackageEcosystem(str, enum.Enum):
    NPM = "npm"
    PYPI = "pypi"


@dataclass
class DependencyStatus:
    """Represents registry lookup state for a package name."""

    package_name: str
    ecosystem: str
    is_claimed_publicly: bool
    status_code: int
    registry_url: str
    is_internal_pattern: bool


@dataclass
class DependencyFinding:
    """Represents a validated Dependency Confusion vulnerability finding."""

    vulnerable: bool
    flaw_type: str = "dependency_confusion_namespace_takeover"
    package_name: str = ""
    ecosystem: str = "npm"
    target_domain: str = ""
    severity: Severity = Severity.CRITICAL
    cvss_score: float = 9.8
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    cwe_id: str = "CWE-427: Uncontrolled Search Path Element"
    evidence: str = ""
    remediation: str = (
        "Immediately reserve internal scoped namespaces on the public registry (e.g. npm scope reservation). "
        "Configure internal package managers (.npmrc / pip.conf) to enforce explicit registry routing for internal "
        "namespaces and disable public upstream fallbacks. Implement an enterprise artifact firewall (e.g. Artifactory, Nexus)."
    )
    bounty_viability: str = "HIGH_CONFIDENCE"
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Converts finding to dictionary representation."""
        data = asdict(self)
        if isinstance(self.severity, Severity):
            data["severity"] = self.severity.value
        return data


class DependencyConfusionSentinel:
    """Detects unclaimed internal package namespaces in public registries to prevent supply chain code execution."""

    # Common internal package name indicators
    INTERNAL_NAME_PATTERNS = [
        re.compile(r"^@[a-z0-9_-]+/[a-z0-9_-]+$", re.IGNORECASE),  # Scoped npm package: @corp/pkg
        re.compile(r"^[a-z0-9_-]+-(internal|private|core|sdk|common|infra|corp)$", re.IGNORECASE),
        re.compile(r"^(internal|private|corp|org)-[a-z0-9_-]+$", re.IGNORECASE),
    ]

    # Regex to capture import / require statements in JS/TS source code
    JS_IMPORT_PATTERNS = [
        re.compile(r"""(?:import\s+(?:[\w*\s{},]+from\s+)?|require\s*\()\s*['"](@[a-z0-9_-]+/[a-z0-9._-]+|[a-z0-9_-]+-(?:internal|private|core|sdk|common))['"]""", re.IGNORECASE),
        re.compile(r"""['"]dependencies['"]\s*:\s*\{([^}]+)\}"""),
        re.compile(r"""['"]devDependencies['"]\s*:\s*\{([^}]+)\}"""),
    ]

    # Regex for requirements.txt or setup.py package declarations
    PYTHON_PACKAGE_PATTERNS = [
        re.compile(r"""^[ \t]*([a-z0-9_-]+-(?:internal|private|core|sdk|common|corp))[ \t]*(?:[><=~!]|\n|$)""", re.MULTILINE | re.IGNORECASE),
    ]

    @classmethod
    def is_internal_naming_pattern(cls, package_name: str, custom_org_names: Optional[List[str]] = None) -> bool:
        """Determines whether a package name matches an internal or enterprise naming convention."""
        pkg = package_name.strip().lower()
        if not pkg:
            return False

        # Match scoped npm pattern (@org/pkg)
        if pkg.startswith("@"):
            if custom_org_names:
                for org in custom_org_names:
                    clean_org = org.strip().lower().lstrip("@")
                    if pkg.startswith(f"@{clean_org}/"):
                        return True
            return True

        # Match custom org prefix
        if custom_org_names:
            for org in custom_org_names:
                clean_org = org.strip().lower().lstrip("@")
                if pkg.startswith(f"{clean_org}-") or pkg.endswith(f"-{clean_org}"):
                    return True

        for pattern in cls.INTERNAL_NAME_PATTERNS:
            if pattern.match(pkg):
                return True

        return False

    @classmethod
    def harvest_package_references(
        cls,
        source_text: str,
        custom_org_names: Optional[List[str]] = None,
    ) -> Set[Tuple[str, str]]:
        """Harvests package names from JS bundles, Webpack manifests, or requirements lists."""
        found: Set[Tuple[str, str]] = set()
        if not source_text:
            return found

        # 1. JS import / require statements
        for pat in cls.JS_IMPORT_PATTERNS:
            for match in pat.finditer(source_text):
                matched_str = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                # If matched json dependency block
                if "{" in matched_str or ":" in matched_str:
                    kv_pairs = re.findall(r"""['"]([^'"]+)['"]\s*:""", matched_str)
                    for pkg in kv_pairs:
                        if cls.is_internal_naming_pattern(pkg, custom_org_names):
                            found.add((pkg, PackageEcosystem.NPM.value))
                else:
                    pkg = matched_str.strip("'\"")
                    if cls.is_internal_naming_pattern(pkg, custom_org_names):
                        found.add((pkg, PackageEcosystem.NPM.value))

        # 2. Python internal requirements
        for pat in cls.PYTHON_PACKAGE_PATTERNS:
            for match in pat.finditer(source_text):
                pkg = match.group(1).strip()
                if cls.is_internal_naming_pattern(pkg, custom_org_names):
                    found.add((pkg, PackageEcosystem.PYPI.value))

        return found

    @classmethod
    def check_npm_registry_availability(
        cls,
        package_name: str,
        timeout: float = 3.5,
        mock_status: Optional[int] = None,
    ) -> DependencyStatus:
        """Queries the public npm registry to verify if an internal package name is claimed."""
        # URL encode scoped package names (@org/pkg -> @org%2fpkg)
        encoded_name = urllib.parse.quote(package_name, safe="@")
        registry_url = f"https://registry.npmjs.org/{encoded_name}"

        if mock_status is not None:
            is_claimed = mock_status != 404
            return DependencyStatus(
                package_name=package_name,
                ecosystem=PackageEcosystem.NPM.value,
                is_claimed_publicly=is_claimed,
                status_code=mock_status,
                registry_url=registry_url,
                is_internal_pattern=True,
            )

        try:
            req = urllib.request.Request(
                registry_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                return DependencyStatus(
                    package_name=package_name,
                    ecosystem=PackageEcosystem.NPM.value,
                    is_claimed_publicly=True,
                    status_code=status,
                    registry_url=registry_url,
                    is_internal_pattern=True,
                )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return DependencyStatus(
                    package_name=package_name,
                    ecosystem=PackageEcosystem.NPM.value,
                    is_claimed_publicly=False,
                    status_code=404,
                    registry_url=registry_url,
                    is_internal_pattern=True,
                )
            return DependencyStatus(
                package_name=package_name,
                ecosystem=PackageEcosystem.NPM.value,
                is_claimed_publicly=True,
                status_code=e.code,
                registry_url=registry_url,
                is_internal_pattern=True,
            )
        except Exception:
            return DependencyStatus(
                package_name=package_name,
                ecosystem=PackageEcosystem.NPM.value,
                is_claimed_publicly=True,
                status_code=0,
                registry_url=registry_url,
                is_internal_pattern=True,
            )

    @classmethod
    def check_pypi_registry_availability(
        cls,
        package_name: str,
        timeout: float = 3.5,
        mock_status: Optional[int] = None,
    ) -> DependencyStatus:
        """Queries the public PyPI registry to verify if an internal package name is claimed."""
        clean_name = package_name.strip().lower()
        registry_url = f"https://pypi.org/pypi/{clean_name}/json"

        if mock_status is not None:
            is_claimed = mock_status != 404
            return DependencyStatus(
                package_name=clean_name,
                ecosystem=PackageEcosystem.PYPI.value,
                is_claimed_publicly=is_claimed,
                status_code=mock_status,
                registry_url=registry_url,
                is_internal_pattern=True,
            )

        try:
            req = urllib.request.Request(
                registry_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitSecurity/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                return DependencyStatus(
                    package_name=clean_name,
                    ecosystem=PackageEcosystem.PYPI.value,
                    is_claimed_publicly=True,
                    status_code=status,
                    registry_url=registry_url,
                    is_internal_pattern=True,
                )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return DependencyStatus(
                    package_name=clean_name,
                    ecosystem=PackageEcosystem.PYPI.value,
                    is_claimed_publicly=False,
                    status_code=404,
                    registry_url=registry_url,
                    is_internal_pattern=True,
                )
            return DependencyStatus(
                package_name=clean_name,
                ecosystem=PackageEcosystem.PYPI.value,
                is_claimed_publicly=True,
                status_code=e.code,
                registry_url=registry_url,
                is_internal_pattern=True,
            )
        except Exception:
            return DependencyStatus(
                package_name=clean_name,
                ecosystem=PackageEcosystem.PYPI.value,
                is_claimed_publicly=True,
                status_code=0,
                registry_url=registry_url,
                is_internal_pattern=True,
            )

    @classmethod
    def evaluate_bounty_impact(
        cls,
        package_name: str,
        ecosystem: str,
        target_domain: str,
        status: Optional[DependencyStatus] = None,
    ) -> Optional[DependencyFinding]:
        """Constructs a deterministic Dependency Finding if the internal package is unclaimed."""
        if status is None:
            if ecosystem == PackageEcosystem.NPM.value:
                status = cls.check_npm_registry_availability(package_name)
            else:
                status = cls.check_pypi_registry_availability(package_name)

        if not status.is_claimed_publicly:
            evidence = (
                f"Internal package reference '{package_name}' discovered in assets for '{target_domain}' "
                f"is UNCLAIMED on the public {ecosystem.upper()} registry ({status.registry_url} returned HTTP 404). "
                f"An attacker can register this package on public {ecosystem.upper()} with a higher semantic version "
                "to execute arbitrary code within corporate CI/CD pipelines, developer machines, and build runners."
            )
            return DependencyFinding(
                vulnerable=True,
                flaw_type="dependency_confusion_namespace_takeover",
                package_name=package_name,
                ecosystem=ecosystem,
                target_domain=target_domain,
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-427: Uncontrolled Search Path Element",
                evidence=evidence,
            )

        return None

    @classmethod
    def audit_source_code(
        cls,
        source_text: str,
        target_domain: str,
        custom_org_names: Optional[List[str]] = None,
        mock_npm_statuses: Optional[Dict[str, int]] = None,
        mock_pypi_statuses: Optional[Dict[str, int]] = None,
    ) -> List[DependencyFinding]:
        """End-to-end harvest and audit pipeline of source code / JavaScript bundles."""
        findings: List[DependencyFinding] = []
        pkgs = cls.harvest_package_references(source_text, custom_org_names=custom_org_names)

        for pkg_name, eco in pkgs:
            if eco == PackageEcosystem.NPM.value:
                m_stat = mock_npm_statuses.get(pkg_name) if mock_npm_statuses else None
                status = cls.check_npm_registry_availability(pkg_name, mock_status=m_stat)
            else:
                m_stat = mock_pypi_statuses.get(pkg_name) if mock_pypi_statuses else None
                status = cls.check_pypi_registry_availability(pkg_name, mock_status=m_stat)

            finding = cls.evaluate_bounty_impact(pkg_name, eco, target_domain, status=status)
            if finding:
                findings.append(finding)

        return findings

    @classmethod
    def audit_target(
        cls,
        target_domain: str,
        source_text: Optional[str] = None,
        custom_org_names: Optional[List[str]] = None,
        mock_npm: Optional[Dict[str, int]] = None,
        mock_pypi: Optional[Dict[str, int]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Unified audit entry point returning highest-priority Dependency Confusion finding."""
        if not source_text:
            return None

        findings = cls.audit_source_code(
            source_text=source_text,
            target_domain=target_domain,
            custom_org_names=custom_org_names,
            mock_npm_statuses=mock_npm,
            mock_pypi_statuses=mock_pypi,
        )

        if not findings:
            return None

        sorted_findings = sorted(findings, key=lambda f: f.cvss_score, reverse=True)
        return sorted_findings[0].to_dict()
