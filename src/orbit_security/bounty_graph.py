"""Orbit Security: GraphRAG Attack Surface Topology Engine (bounty_graph.py).

Provides Phase C Milestone C.1 capabilities:
1. Ingests BountyProgram models, perimeter domains, CNAME targets, cloud providers, and vulnerabilities.
2. Builds a relational graph topology adhering to the GraphRAG / graphify schema (nodes & edges).
3. Computes node degree centrality to discover critical shared infrastructure.
4. Synchronizes topology into graphify-out/bounty_attack_surface.json and SQLite federated stores.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from orbit_security.bounty_radar import BountyProgram, BountyVulnerability

logger = logging.getLogger("orbit_security.bounty_graph")

WORKSPACE_ROOT = Path(os.environ.get("AGY_HOME", "A:/"))
if not WORKSPACE_ROOT.exists():
    WORKSPACE_ROOT = Path(r"C:\AgyHut")

DEFAULT_GRAPH_OUT_DIR = WORKSPACE_ROOT / "graphify-out"


class BountyAttackGraph:
    """Relational Attack Surface Topology Graph for bug bounty scopes and vulnerabilities."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or DEFAULT_GRAPH_OUT_DIR)
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Adds or updates a typed node in the attack graph."""
        clean_id = str(node_id).strip().lower()
        if clean_id not in self.nodes:
            self.nodes[clean_id] = {
                "id": clean_id,
                "label": label,
                "type": node_type,
                "degree": 0,
                "in_degree": 0,
                "out_degree": 0,
                "meta": meta or {},
            }
        else:
            self.nodes[clean_id]["label"] = label
            self.nodes[clean_id]["type"] = node_type
            if meta:
                self.nodes[clean_id]["meta"].update(meta)
        return self.nodes[clean_id]

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        weight: float = 1.0,
    ):
        """Adds a directed relation edge between two nodes."""
        src = str(source_id).strip().lower()
        tgt = str(target_id).strip().lower()

        # Prevent duplicate identical edges
        for existing in self.edges:
            if existing["source"] == src and existing["target"] == tgt and existing["relation"] == relation:
                return

        edge = {
            "source": src,
            "target": tgt,
            "relation": relation,
            "weight": weight,
        }
        self.edges.append(edge)

        # Update degree counters
        if src in self.nodes:
            self.nodes[src]["out_degree"] += 1
            self.nodes[src]["degree"] += 1
        if tgt in self.nodes:
            self.nodes[tgt]["in_degree"] += 1
            self.nodes[tgt]["degree"] += 1

    def ingest_program(self, program: BountyProgram) -> str:
        """Ingests a bounty program and its in-scope domains into graph nodes and edges."""
        prog_node_id = f"prog:{program.program_id}"
        self.add_node(
            node_id=prog_node_id,
            label=program.name,
            node_type="BOUNTY_PROGRAM",
            meta={
                "platform": program.platform,
                "policy_url": program.policy_url,
                "bounty_tier": program.bounty_tier,
                "max_bounty": program.max_bounty,
            },
        )

        for pattern in program.in_scope:
            clean_pat = pattern.strip().lower()
            domain_node_id = f"domain:{clean_pat.lstrip('*.')}"
            self.add_node(
                node_id=domain_node_id,
                label=clean_pat,
                node_type="PERIMETER_DOMAIN",
                meta={"program_id": program.program_id, "is_wildcard": clean_pat.startswith("*.")},
            )
            self.add_edge(prog_node_id, domain_node_id, relation="MONITORS_DOMAIN")

        for out_pat in program.out_of_scope:
            clean_out = out_pat.strip().lower()
            out_node_id = f"domain:{clean_out.lstrip('*.')}"
            self.add_node(
                node_id=out_node_id,
                label=clean_out,
                node_type="PERIMETER_DOMAIN",
                meta={"program_id": program.program_id, "out_of_scope": True},
            )
            self.add_edge(prog_node_id, out_node_id, relation="EXCLUDES_DOMAIN")

        return prog_node_id

    def ingest_vulnerability(self, vuln: BountyVulnerability) -> str:
        """Ingests a triaged vulnerability finding and links target, CNAME, and provider nodes."""
        vuln_id = f"vuln:{vuln.program_id}:{vuln.target_domain}:{vuln.flaw_type}"
        self.add_node(
            node_id=vuln_id,
            label=f"{vuln.flaw_type.replace('_', ' ').title()} ({vuln.severity.value})",
            node_type="VULNERABILITY",
            meta={
                "flaw_type": vuln.flaw_type,
                "severity": vuln.severity.value,
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "cwe_id": vuln.cwe_id,
                "bounty_viability": vuln.bounty_viability,
                "evidence": vuln.evidence[:300],
            },
        )

        # Link from domain to vulnerability
        domain_node_id = f"domain:{vuln.target_domain.lower()}"
        self.add_node(
            node_id=domain_node_id,
            label=vuln.target_domain,
            node_type="PERIMETER_DOMAIN",
            meta={"program_id": vuln.program_id},
        )
        self.add_edge(domain_node_id, vuln_id, relation="HAS_EXPOSURE", weight=2.0)

        # Link from domain to program
        prog_node_id = f"prog:{vuln.program_id.lower()}"
        if prog_node_id in self.nodes:
            self.add_edge(prog_node_id, domain_node_id, relation="MONITORS_DOMAIN")

        # Link CNAME target if present
        if vuln.cname_target:
            cname_id = f"cname:{vuln.cname_target.lower()}"
            self.add_node(
                node_id=cname_id,
                label=vuln.cname_target,
                node_type="CNAME_TARGET",
                meta={"flaw_type": vuln.flaw_type},
            )
            self.add_edge(domain_node_id, cname_id, relation="POINTS_TO_CNAME")

            # Link cloud provider
            if vuln.provider:
                provider_id = f"provider:{vuln.provider.lower().replace(' ', '_')}"
                self.add_node(
                    node_id=provider_id,
                    label=vuln.provider,
                    node_type="CLOUD_PROVIDER",
                )
                self.add_edge(cname_id, provider_id, relation="HOSTED_BY")
        elif vuln.provider:
            provider_id = f"provider:{vuln.provider.lower().replace(' ', '_')}"
            self.add_node(
                node_id=provider_id,
                label=vuln.provider,
                node_type="CLOUD_PROVIDER",
            )
            self.add_edge(domain_node_id, provider_id, relation="HOSTED_BY")

        return vuln_id

    def calculate_centrality(self) -> List[Tuple[str, int, str]]:
        """Calculates degree centrality and identifies critical shared infrastructure nodes.
        
        Returns sorted list of (node_id, degree, node_type).
        """
        ranking = [
            (nid, data["degree"], data["type"])
            for nid, data in self.nodes.items()
        ]
        ranking.sort(key=lambda x: x[1], reverse=True)
        return ranking

    def export_topology(self) -> Dict[str, Any]:
        """Exports graph topology into standard JSON dictionary matching GraphRAG specs."""
        return {
            "version": "1.0",
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "programs": sum(1 for n in self.nodes.values() if n["type"] == "BOUNTY_PROGRAM"),
                "domains": sum(1 for n in self.nodes.values() if n["type"] == "PERIMETER_DOMAIN"),
                "cnames": sum(1 for n in self.nodes.values() if n["type"] == "CNAME_TARGET"),
                "providers": sum(1 for n in self.nodes.values() if n["type"] == "CLOUD_PROVIDER"),
                "vulnerabilities": sum(1 for n in self.nodes.values() if n["type"] == "VULNERABILITY"),
            },
            "top_central_nodes": self.calculate_centrality()[:10],
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }

    def save(self, filepath: Optional[Path] = None) -> Path:
        """Persists the attack graph JSON to disk."""
        dest = Path(filepath or (self.output_dir / "bounty_attack_surface.json"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(self.export_topology(), f, indent=2)
        logger.info(f"Saved BountyAttackGraph to {dest} ({len(self.nodes)} nodes, {len(self.edges)} edges)")
        return dest
