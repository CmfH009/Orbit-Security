"""dns_fixpack_optimizer.py — Automated DNS Fixpack & SPF Tree Optimizer.
=============================================================================
Generates ready-to-apply 1-click DNS fixpacks (Terraform, BIND zone, Cloudflare API)
for RFC 7208 SPF PermErrors and DMARC hardening.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class DnsFixpackBundle:
    domain: str
    original_spf: str
    flattened_spf: str
    total_original_lookups: int
    optimized_lookups: int
    terraform_snippet: str
    bind_zone_snippet: str
    cloudflare_api_json: Dict[str, Any]
    sha256_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DnsFixpackOptimizer:
    """
    Synthesizes compliant, minimal DNS records from complex or broken SPF trees.
    """

    @staticmethod
    def flatten_spf_record(ip4_addresses: List[str], ip6_addresses: Optional[List[str]] = None, qualifier: str = "-all") -> str:
        """
        Builds a canonical, 0-DNS-lookup flattened SPF TXT record.
        """
        parts = ["v=spf1"]
        # Deduplicate and sort
        unique_v4 = sorted(list(set(ip4_addresses)))
        for ip in unique_v4:
            clean_ip = ip.strip()
            if clean_ip:
                parts.append(f"ip4:{clean_ip}")

        if ip6_addresses:
            unique_v6 = sorted(list(set(ip6_addresses)))
            for ip in unique_v6:
                clean_ip = ip.strip()
                if clean_ip:
                    parts.append(f"ip6:{clean_ip}")

        parts.append(qualifier)
        return " ".join(parts)

    def generate_fixpack(
        self,
        domain: str,
        original_spf: str,
        flattened_ips: List[str],
        original_lookups: int = 12,
        zone_id: str = "example_zone_id",
    ) -> DnsFixpackBundle:
        """
        Generates multi-format infrastructure-as-code snippets for DNS remediation.
        """
        flattened_record = self.flatten_spf_record(flattened_ips)

        # Terraform Cloudflare record resource
        tf_snippet = f"""# Terraform Cloudflare SPF Fix for {domain}
resource "cloudflare_record" "spf_remediation" {{
  zone_id = "{zone_id}"
  name    = "@"
  type    = "TXT"
  content = "{flattened_record}"
  ttl     = 300
  comment = "Remediated by Orbit Security (RFC 7208 PermError flattening)"
}}"""

        # BIND 9 Zone Snippet
        bind_snippet = f'; BIND 9 Zone SPF remediation for {domain}\n@    300    IN    TXT    "{flattened_record}"'

        # Cloudflare API REST JSON payload
        cf_api = {
            "type": "TXT",
            "name": "@",
            "content": flattened_record,
            "ttl": 300,
            "comment": "Orbit Security RFC 7208 SPF PermError Flattened Fix",
        }

        # Integrity hash
        raw_pack = f"{domain}:{original_spf}:{flattened_record}:{tf_snippet}"
        sha_hash = hashlib.sha256(raw_pack.encode("utf-8")).hexdigest()

        return DnsFixpackBundle(
            domain=domain,
            original_spf=original_spf,
            flattened_spf=flattened_record,
            total_original_lookups=original_lookups,
            optimized_lookups=0,
            terraform_snippet=tf_snippet,
            bind_zone_snippet=bind_snippet,
            cloudflare_api_json=cf_api,
            sha256_hash=sha_hash,
        )

    def export_fixpack_files(self, bundle: DnsFixpackBundle, output_dir: Path) -> Dict[str, Path]:
        """
        Writes all bundle files to a target directory.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        tf_file = output_dir / f"{bundle.domain}_spf_fix.tf"
        tf_file.write_text(bundle.terraform_snippet, encoding="utf-8")

        bind_file = output_dir / f"{bundle.domain}_zone_spf.txt"
        bind_file.write_text(bundle.bind_zone_snippet, encoding="utf-8")

        cf_file = output_dir / f"{bundle.domain}_cloudflare_api.json"
        cf_file.write_text(json.dumps(bundle.cloudflare_api_json, indent=2), encoding="utf-8")

        manifest_file = output_dir / "manifest.json"
        manifest_file.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")

        return {
            "terraform": tf_file,
            "bind": bind_file,
            "cloudflare_api": cf_file,
            "manifest": manifest_file,
        }
