"""nuclei_generator.py — Autonomous Nuclei v3 YAML Template Synthesizer.
========================================================================
Translates Orbit Security's curated SaaS takeover signatures and DNS
vulnerabilities into standardized, reproducible Nuclei v3 YAML templates.
Enables automated bug bounty verification and passive radar sweeps.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from orbit_security.signatures import SAAS_TAKEOVER_SIGNATURES, SaasSignature


class NucleiTemplateGenerator:
    """
    Synthesizes valid Nuclei v3 template structures for vulnerability scanning.
    """

    def __init__(self, author: str = "Orbit Security / rig-bounty-hunter") -> None:
        self.author = author

    @staticmethod
    def _slugify(text: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
        return slug or "unknown"

    def generate_takeover_template(self, sig: SaasSignature) -> Dict[str, Any]:
        """
        Generates Nuclei v3 HTTP subdomain takeover verification template.
        """
        slug = self._slugify(sig.name)
        template_id = f"orbit-takeover-{slug}"

        template = {
            "id": template_id,
            "info": {
                "name": f"Subdomain Takeover - {sig.name}",
                "author": self.author,
                "severity": "high",
                "description": (
                    f"Identifies dangling DNS CNAME records pointing to {sig.name} "
                    f"where the remote resource is unallocated and subject to hostile takeover."
                ),
                "remediation": sig.remediation,
                "reference": [
                    "https://github.com/EdOverflow/can-i-take-over-xyz",
                    "https://orbitsecurity.io/security.txt",
                ],
                "tags": ["takeover", "dns", "subdomain", "orbit-security", slug],
                "metadata": {
                    "verified": True,
                    "max-request": 1,
                    "cname-patterns": sig.cname_patterns,
                },
            },
            "http": [
                {
                    "method": "GET",
                    "path": ["{{BaseURL}}"],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "word",
                            "words": sig.fingerprints,
                            "condition": "or",
                            "part": "body",
                        },
                        {
                            "type": "status",
                            "status": [sig.status_code] if sig.status_code else [404],
                        },
                    ],
                }
            ],
        }
        return template

    def generate_spf_permerror_template(self, domain: str) -> Dict[str, Any]:
        """
        Generates Nuclei v3 DNS-based SPF PermError detection template.
        """
        slug = self._slugify(domain)
        template_id = f"orbit-dns-spf-permerror-{slug}"

        template = {
            "id": template_id,
            "info": {
                "name": f"RFC 7208 SPF PermError - {domain}",
                "author": self.author,
                "severity": "medium",
                "description": (
                    f"Audits SPF TXT records for {domain} to detect DNS lookup exhaustion "
                    f"(>=10 DNS lookups) which causes mail receivers to return PermError."
                ),
                "reference": ["https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4"],
                "tags": ["dns", "spf", "email-security", "orbit-security"],
            },
            "dns": [
                {
                    "name": domain,
                    "type": "TXT",
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["v=spf1"],
                            "part": "raw",
                        }
                    ],
                }
            ],
        }
        return template

    def generate_security_txt_template(self, domain: str) -> Dict[str, Any]:
        """
        Generates RFC 9116 security.txt compliance inspection template.
        """
        slug = self._slugify(domain)
        template_id = f"orbit-rfc9116-security-txt-{slug}"

        template = {
            "id": template_id,
            "info": {
                "name": f"RFC 9116 security.txt Audit - {domain}",
                "author": self.author,
                "severity": "info",
                "description": f"Verifies existence of /.well-known/security.txt for {domain}.",
                "reference": ["https://www.rfc-editor.org/rfc/rfc9116.html"],
                "tags": ["rfc9116", "security-txt", "disclosure", "orbit-security"],
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "{{BaseURL}}/.well-known/security.txt",
                        "{{BaseURL}}/security.txt",
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["Contact:", "Expires:"],
                            "condition": "and",
                            "part": "body",
                        },
                        {
                            "type": "status",
                            "status": [200],
                        },
                    ],
                }
            ],
        }
        return template

    def to_yaml(self, template_data: Dict[str, Any]) -> str:
        """Serializes dictionary template to formatted Nuclei YAML."""
        return yaml.dump(template_data, sort_keys=False, indent=2)

    def export_all_takeover_templates(self, output_dir: Path) -> List[Path]:
        """
        Exports all curated SaaS takeover signatures to Nuclei YAML files.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        exported: List[Path] = []

        for sig in SAAS_TAKEOVER_SIGNATURES:
            slug = self._slugify(sig.name)
            tpl = self.generate_takeover_template(sig)
            out_file = output_dir / f"takeover-{slug}.yaml"
            out_file.write_text(self.to_yaml(tpl), encoding="utf-8")
            exported.append(out_file)

        return exported
