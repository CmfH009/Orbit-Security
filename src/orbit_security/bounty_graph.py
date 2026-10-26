"""Orbit Security: GraphRAG Attack Surface Topology Engine (bounty_graph.py).

Provides Phase C Milestone C.1 capabilities:
1. Ingests BountyProgram models, perimeter domains, CNAME targets, cloud providers, and vulnerabilities.
2. Builds a relational graph topology adhering to the GraphRAG / graphify schema (nodes & edges).
3. Computes node degree centrality to discover critical shared infrastructure.
4. Synchronizes topology into graphify-out/bounty_attack_surface.json and SQLite federated stores.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
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

    def ingest_shuttle_events(
        self,
        events: List[Dict[str, Any]],
        save_disk: bool = False,
    ) -> Dict[str, Any]:
        """Projects incoming Tailscale shuttle threat events directly into the 3D attack surface graph."""
        processed = 0
        for ev in events:
            ev_type = str(ev.get("event_type", "")).upper()
            payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
            origin = str(
                payload.get("_shuttle_origin")
                or ev.get("origin_node")
                or ev.get("source")
                or "oracle-cloud-sentinel"
            ).replace("shuttle:", "").strip()

            sentinel_id = f"sentinel:{origin.lower()}"
            self.add_node(
                node_id=sentinel_id,
                label=f"Sentinel ({origin})",
                node_type="TAILSCALE_SENTINEL",
                meta={"origin_node": origin},
            )

            domain = (
                payload.get("domain")
                or payload.get("subdomain")
                or payload.get("target")
                or ""
            ).strip().lower()

            if domain:
                domain_id = f"domain:{domain}"
                self.add_node(
                    node_id=domain_id,
                    label=domain,
                    node_type="PERIMETER_DOMAIN",
                    meta={
                        "shuttle_origin": origin,
                        "apex_domain": payload.get("apex_domain", domain),
                    },
                )
                self.add_edge(sentinel_id, domain_id, relation="OBSERVED_OVER_TAILSCALE")

                if ev_type in ("CISA_KEV_MATCH_DETECTED", "CRITICAL_0DAY_CORRELATED", "EPSS_SCORE_EVALUATED"):
                    cve_id = str(payload.get("cve_id", "CVE-UNKNOWN")).upper()
                    vuln_id = f"vuln:shuttle:{domain}:{cve_id.lower()}"
                    self.add_node(
                        node_id=vuln_id,
                        label=f"{cve_id} (CRITICAL)",
                        node_type="VULNERABILITY",
                        meta={
                            "flaw_type": ev_type.lower(),
                            "severity": "CRITICAL",
                            "cve_id": cve_id,
                            "bounty_viability": "HIGH_CONFIDENCE",
                            "shuttle_origin": origin,
                        },
                    )
                    self.add_edge(domain_id, vuln_id, relation="HAS_EXPOSURE", weight=2.5)
                    processed += 1

                elif ev_type == "SUBDOMAIN_TAKEOVER_DETECTED":
                    provider = str(payload.get("provider") or payload.get("service") or "Cloud Provider")
                    cname = str(payload.get("cname_target") or "").strip().lower()
                    vuln_id = f"vuln:shuttle:{domain}:subdomain_takeover"
                    self.add_node(
                        node_id=vuln_id,
                        label=f"Subdomain Takeover ({provider})",
                        node_type="VULNERABILITY",
                        meta={
                            "flaw_type": "subdomain_takeover",
                            "severity": "CRITICAL",
                            "provider": provider,
                            "cname_target": cname,
                            "bounty_viability": "HIGH_CONFIDENCE",
                            "shuttle_origin": origin,
                        },
                    )
                    self.add_edge(domain_id, vuln_id, relation="HAS_EXPOSURE", weight=2.5)
                    if cname:
                        cname_id = f"cname:{cname}"
                        self.add_node(node_id=cname_id, label=cname, node_type="CNAME_TARGET")
                        self.add_edge(domain_id, cname_id, relation="POINTS_TO_CNAME")
                    processed += 1

                elif ev_type in ("CT_LOG_NEW_SUBDOMAIN", "CT_LOG_CERTIFICATE_DISCOVERED", "TRIAGE_COMPLETED"):
                    processed += 1

        if save_disk and processed > 0:
            self.save()

        return {
            "events_processed": processed,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
        }

    def ingest_radar_leads(self, leads: List[Dict[str, Any]]) -> int:
        """Projects live visitor Radar probes and enriched OSINT profiles into the 3D Attack Surface Graph."""
        if not leads:
            return 0
        hub_id = "sentinel:orbit_perimeter_radar"
        self.add_node(
            node_id=hub_id,
            label="ORBIT Perimeter Radar",
            node_type="TAILSCALE_SENTINEL",
            meta={"origin_node": "orbit-radar-terminal", "platform": "GitHub Pages / Live Telemetry"},
        )
        added = 0
        for lead in leads:
            dom = str(lead.get("domain") or "").strip().lower()
            if not dom:
                continue
            node_id = f"radar:{dom}"
            score = lead.get("score")
            grade = str(lead.get("grade") or "--")
            company = str(lead.get("company_name") or dom)
            self.add_node(
                node_id=node_id,
                label=f"{dom} [{grade}]",
                node_type="RADAR_PROBE",
                meta={
                    "domain": dom,
                    "company_name": company,
                    "score": score,
                    "grade": grade,
                    "registrar": lead.get("registrar") or "Unknown",
                    "dns_provider": lead.get("dns_provider") or "Standard DNS",
                    "mx_provider": lead.get("mx_provider") or "Corporate Mail",
                    "tech_stack": lead.get("tech_stack") or [],
                    "device_summary": lead.get("device_summary") or "Web Visitor",
                    "deliverables": lead.get("deliverables") or {},
                    "evidence": f"Score: {score}/100 ({grade}) | Registrar: {lead.get('registrar')} | Tech: {', '.join((lead.get('tech_stack') or [])[:4])}",
                },
            )
            self.add_edge(hub_id, node_id, relation="PROBED_BY_VISITOR", weight=2.0)
            added += 1
        return added

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

    def export_constellation_hubs(self) -> Dict[str, Any]:
        """Formats attack surface graph into Orbit Web Cockpit 3D Constellation schema."""
        hubs = []
        node_list = list(self.nodes.values())
        total = len(node_list)

        type_meta = {
            "BOUNTY_PROGRAM": {"cat": "Bounty Fleet", "color": "#818cf8", "base_r": 120.0, "size": 18.0},
            "TAILSCALE_SENTINEL": {"cat": "Tailscale Sentinel", "color": "#10b981", "base_r": 90.0, "size": 20.0},
            "PERIMETER_DOMAIN": {"cat": "Perimeter Asset", "color": "#38bdf8", "base_r": 210.0, "size": 10.0},
            "CNAME_TARGET": {"cat": "CNAME Target", "color": "#f59e0b", "base_r": 280.0, "size": 12.0},
            "CLOUD_PROVIDER": {"cat": "Cloud Infrastructure", "color": "#c084fc", "base_r": 160.0, "size": 14.0},
            "VULNERABILITY": {"cat": "Vulnerability", "color": "#ef4444", "base_r": 240.0, "size": 16.0},
            "RADAR_PROBE": {"cat": "Radar Probe", "color": "#00f0ff", "base_r": 185.0, "size": 15.0},
        }

        for i, node in enumerate(node_list):
            ntype = node.get("type", "PERIMETER_DOMAIN")
            tinfo = type_meta.get(ntype, {"cat": "Perimeter", "color": "#94a3b8", "base_r": 200.0, "size": 10.0})

            color = tinfo["color"]
            meta = node.get("meta", {})
            if ntype == "VULNERABILITY":
                viability = meta.get("bounty_viability", "")
                severity = meta.get("severity", "").upper()
                if viability == "HIGH_CONFIDENCE" or severity in ("CRITICAL", "HIGH"):
                    color = "#ef4444"  # Red: Cash Ready / High Confidence Takeover
                else:
                    color = "#fbbf24"  # Amber: Conditional / Informational Queue

            # Compute deterministic 3D radial distribution
            golden_angle = math.pi * (3.0 - math.sqrt(5.0))
            theta = i * golden_angle
            phi = math.acos(1.0 - 2.0 * (i + 0.5) / max(1, total))

            r = tinfo["base_r"] + (hash(node["id"]) % 40) - 20
            x = r * math.sin(phi) * math.cos(theta)
            y = r * math.sin(phi) * math.sin(theta) * 0.7  # Flatter ellipsoid
            z = r * math.cos(phi)

            symbols = []
            if meta.get("cname_target"):
                symbols.append(meta["cname_target"])
            if meta.get("platform"):
                symbols.append(meta["platform"])
            if meta.get("flaw_type"):
                symbols.append(meta["flaw_type"])

            hubs.append({
                "id": node["id"],
                "name": node.get("label", node["id"]),
                "category": tinfo["cat"],
                "count": node.get("degree", 1),
                "size": tinfo["size"],
                "color": color,
                "x": round(x, 1),
                "y": round(y, 1),
                "z": round(z, 1),
                "symbols": symbols,
                "description": f"{ntype}: {node.get('label')} (Degree: {node.get('degree', 1)})",
                "meta": meta,
            })

        links = [[e["source"], e["target"]] for e in self.edges]
        return {
            "ok": True,
            "hubs": hubs,
            "links": links,
            "total_nodes": len(hubs),
            "total_links": len(links),
            "stats": self.export_topology().get("stats", {}),
        }

    @classmethod
    def build_from_ecosystem(
        cls,
        programs_path: Optional[Path] = None,
        disclosures_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        save_disk: bool = True,
    ) -> BountyAttackGraph:
        """Constructs an attack graph by ingesting enrolled programs and all persisted disclosures."""
        from orbit_security.bounty_radar import BountyScopeIngester, BountyVulnerability
        from orbit_security.models import Severity

        graph = cls(output_dir=output_dir)

        # 1. Ingest enrolled programs
        ingester = BountyScopeIngester(data_path=programs_path)
        programs = ingester.list_programs()
        for prog in programs:
            graph.ingest_program(prog)

        # 2. Ingest disclosures
        disc_path = Path(disclosures_dir or (WORKSPACE_ROOT / "projects" / "orbit-security" / "data" / "disclosures"))
        if not disc_path.exists():
            disc_path = Path(r"C:\AgyHut\projects\orbit-security\data\disclosures")

        if disc_path.exists():
            for f in sorted(disc_path.glob("*.md")):
                try:
                    content = f.read_text(encoding="utf-8")
                    prog_m = re.search(r"\*\*Program:\*\*\s*(.+)", content)
                    asset_m = re.search(r"\*\*Asset\s*\(In-Scope Target\):\*\*\s*`?([^`\n]+)`?", content)
                    sev_m = re.search(r"\*\*Severity:\*\*\s*(.+)", content)
                    grade_m = re.search(r"\*\*Bounty Viability Grade:\*\*\s*`?([^`\n]+)`?", content)
                    cvss_m = re.search(r"\(CVSS 3\.1:\s*\*\*([0-9.]+)\*\*\)", content)
                    cname_m = re.search(r"dig\s+\S+\s+CNAME\s+\+short[^\n]*\n\s*# Output:\s*(\S+)", content)
                    evidence_m = re.search(r"Observe evidence:\s*`([^`]+)`", content)
                    cat_m = re.search(r"- \*\*Vulnerability Category:\*\*\s*`?([^`\n]+)`?", content)
                    prov_m = re.search(r"- \*\*Affected Provider/Service:\*\*\s*`?([^`\n]+)`?", content)

                    target_domain = asset_m.group(1).strip() if asset_m else f.stem
                    raw_prog = prog_m.group(1).strip() if prog_m else "unknown"
                    prog_id = raw_prog.split(" ")[0].lower()
                    flaw_type = cat_m.group(1).lower().replace(" ", "_") if cat_m else "vulnerability"
                    sev_str = sev_m.group(1).replace("`", "").strip().upper() if sev_m else "HIGH"
                    severity = Severity.HIGH if "HIGH" in sev_str else (Severity.CRITICAL if "CRIT" in sev_str else Severity.MEDIUM)
                    score = float(cvss_m.group(1)) if cvss_m else 7.5
                    cname_val = cname_m.group(1).strip() if cname_m else None
                    evidence = evidence_m.group(1).strip() if evidence_m else "Disclosed vulnerability proof of concept"
                    viability = grade_m.group(1).strip() if grade_m else "HIGH_CONFIDENCE"
                    provider = prov_m.group(1).strip() if prov_m else None

                    vuln = BountyVulnerability(
                        program_id=prog_id,
                        program_name=raw_prog,
                        platform="hackerone",
                        target_domain=target_domain,
                        cname_target=cname_val,
                        flaw_type=flaw_type,
                        provider=provider,
                        severity=severity,
                        cvss_score=score,
                        evidence=evidence,
                        bounty_viability=viability,
                    )
                    graph.ingest_vulnerability(vuln)
                except Exception as e:
                    logger.debug(f"Failed parsing disclosure {f.name}: {e}")

        if save_disk:
            graph.save()
        return graph

