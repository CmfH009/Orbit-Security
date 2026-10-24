"""Attack Tree and Directed Acyclic Graph (DAG) Threat Modeling Engine.

Implements the attack-tree-construction skill patterns for converting OSINT and
reconnaissance scan findings into actionable attack paths, Mermaid diagrams,
and mitigation priorities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class NodeType(Enum):
    OR = "or"
    AND = "and"
    LEAF = "leaf"


class Difficulty(Enum):
    TRIVIAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    EXPERT = 5


class Cost(Enum):
    FREE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4


class DetectionRisk(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CERTAIN = 4


@dataclass
class AttackAttributes:
    difficulty: Difficulty = Difficulty.MEDIUM
    cost: Cost = Cost.MEDIUM
    detection_risk: DetectionRisk = DetectionRisk.MEDIUM
    time_hours: float = 8.0
    requires_insider: bool = False
    requires_physical: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "difficulty": self.difficulty.name,
            "cost": self.cost.name,
            "detection_risk": self.detection_risk.name,
            "time_hours": self.time_hours,
            "requires_insider": self.requires_insider,
            "requires_physical": self.requires_physical,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackAttributes:
        return cls(
            difficulty=Difficulty[data.get("difficulty", "MEDIUM")],
            cost=Cost[data.get("cost", "MEDIUM")],
            detection_risk=DetectionRisk[data.get("detection_risk", "MEDIUM")],
            time_hours=float(data.get("time_hours", 8.0)),
            requires_insider=bool(data.get("requires_insider", False)),
            requires_physical=bool(data.get("requires_physical", False)),
        )


@dataclass
class AttackNode:
    id: str
    name: str
    description: str
    node_type: NodeType
    attributes: AttackAttributes = field(default_factory=AttackAttributes)
    children: List[AttackNode] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    cve_refs: List[str] = field(default_factory=list)

    def add_child(self, child: AttackNode) -> None:
        self.children.append(child)

    def calculate_path_difficulty(self) -> float:
        """Calculate aggregate difficulty for this path."""
        if self.node_type == NodeType.LEAF:
            return float(self.attributes.difficulty.value)

        if not self.children:
            return 0.0

        child_diffs = [c.calculate_path_difficulty() for c in self.children]
        return min(child_diffs) if self.node_type == NodeType.OR else max(child_diffs)

    def calculate_path_cost(self) -> float:
        """Calculate aggregate cost for this path."""
        if self.node_type == NodeType.LEAF:
            return float(self.attributes.cost.value)

        if not self.children:
            return 0.0

        child_costs = [c.calculate_path_cost() for c in self.children]
        return min(child_costs) if self.node_type == NodeType.OR else sum(child_costs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "type": self.node_type.value,
            "attributes": self.attributes.to_dict(),
            "mitigations": self.mitigations,
            "cve_refs": self.cve_refs,
            "children": [c.to_dict() for c in self.children],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackNode:
        attrs = data.get("attributes", {})
        node = cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            node_type=NodeType(data.get("type", "leaf")),
            attributes=AttackAttributes.from_dict(attrs) if attrs else AttackAttributes(),
            mitigations=data.get("mitigations", []),
            cve_refs=data.get("cve_refs", []),
            children=[cls.from_dict(child) for child in data.get("children", [])],
        )
        return node


@dataclass
class AttackTree:
    name: str
    description: str
    root: AttackNode
    version: str = "1.0"

    def find_easiest_path(self) -> List[AttackNode]:
        """Find the path with lowest aggregate difficulty."""
        return self._find_path(self.root, minimize="difficulty")

    def find_cheapest_path(self) -> List[AttackNode]:
        """Find the path with lowest financial cost."""
        return self._find_path(self.root, minimize="cost")

    def find_stealthiest_path(self) -> List[AttackNode]:
        """Find the path with lowest detection risk."""
        return self._find_path(self.root, minimize="detection")

    def _find_path(self, node: AttackNode, minimize: str) -> List[AttackNode]:
        if node.node_type == NodeType.LEAF or not node.children:
            return [node]

        if node.node_type == NodeType.OR:
            best_path = None
            best_score = float("inf")
            for child in node.children:
                child_path = self._find_path(child, minimize)
                score = self._path_score(child_path, minimize)
                if score < best_score:
                    best_score = score
                    best_path = child_path
            return [node] + (best_path or [])
        else:  # AND
            path = [node]
            for child in node.children:
                path.extend(self._find_path(child, minimize))
            return path

    def _path_score(self, path: List[AttackNode], metric: str) -> float:
        if metric == "difficulty":
            return sum(n.attributes.difficulty.value for n in path if n.node_type == NodeType.LEAF)
        elif metric == "cost":
            return sum(n.attributes.cost.value for n in path if n.node_type == NodeType.LEAF)
        elif metric == "detection":
            return sum(n.attributes.detection_risk.value for n in path if n.node_type == NodeType.LEAF)
        return 0.0

    def get_all_leaf_attacks(self) -> List[AttackNode]:
        """Collect all leaf attack nodes."""
        leaves: List[AttackNode] = []
        self._collect_leaves(self.root, leaves)
        return leaves

    def _collect_leaves(self, node: AttackNode, leaves: List[AttackNode]) -> None:
        if node.node_type == NodeType.LEAF:
            leaves.append(node)
        for child in node.children:
            self._collect_leaves(child, leaves)

    def get_unmitigated_attacks(self) -> List[AttackNode]:
        """Find leaf attacks that have zero assigned mitigations."""
        return [n for n in self.get_all_leaf_attacks() if not n.mitigations]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "root": self.root.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackTree:
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            root=AttackNode.from_dict(data["root"]),
        )

    @classmethod
    def from_json(cls, json_str: str) -> AttackTree:
        return cls.from_dict(json.loads(json_str))


class AttackTreeBuilder:
    """Fluent builder for constructing structured attack trees."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._node_stack: List[AttackNode] = []
        self._root: Optional[AttackNode] = None

    def goal(self, id: str, name: str, description: str = "") -> AttackTreeBuilder:
        """Establish the root attacker objective (OR node)."""
        self._root = AttackNode(
            id=id,
            name=name,
            description=description,
            node_type=NodeType.OR,
        )
        self._node_stack = [self._root]
        return self

    def or_node(self, id: str, name: str, description: str = "") -> AttackTreeBuilder:
        """Add an OR sub-goal where any child achieves the parent goal."""
        node = AttackNode(id=id, name=name, description=description, node_type=NodeType.OR)
        self._current().add_child(node)
        self._node_stack.append(node)
        return self

    def and_node(self, id: str, name: str, description: str = "") -> AttackTreeBuilder:
        """Add an AND sub-goal requiring all children to be executed."""
        node = AttackNode(id=id, name=name, description=description, node_type=NodeType.AND)
        self._current().add_child(node)
        self._node_stack.append(node)
        return self

    def attack(
        self,
        id: str,
        name: str,
        description: str = "",
        difficulty: Difficulty = Difficulty.MEDIUM,
        cost: Cost = Cost.MEDIUM,
        detection: DetectionRisk = DetectionRisk.MEDIUM,
        time_hours: float = 8.0,
        mitigations: Optional[List[str]] = None,
        cve_refs: Optional[List[str]] = None,
    ) -> AttackTreeBuilder:
        """Add a leaf attack node representing an atomic technique."""
        node = AttackNode(
            id=id,
            name=name,
            description=description,
            node_type=NodeType.LEAF,
            attributes=AttackAttributes(
                difficulty=difficulty,
                cost=cost,
                detection_risk=detection,
                time_hours=time_hours,
            ),
            mitigations=mitigations or [],
            cve_refs=cve_refs or [],
        )
        self._current().add_child(node)
        return self

    def end(self) -> AttackTreeBuilder:
        """Close current sub-goal and return to parent."""
        if len(self._node_stack) > 1:
            self._node_stack.pop()
        return self

    def build(self) -> AttackTree:
        if not self._root:
            raise ValueError("Root goal must be defined before calling build().")
        return AttackTree(name=self.name, description=self.description, root=self._root)

    def _current(self) -> AttackNode:
        if not self._node_stack:
            raise ValueError("No active node in builder stack.")
        return self._node_stack[-1]


class MermaidExporter:
    """Exports AttackTree structures to stylized Mermaid diagrams."""

    def __init__(self, tree: AttackTree):
        self.tree = tree
        self._lines: List[str] = []
        self._id_map: Dict[str, str] = {}
        self._counter = 0

    def export(self, direction: str = "TD") -> str:
        """Generate Mermaid flowchart string."""
        self._lines = [f"flowchart {direction}"]
        self._id_map = {}
        self._counter = 0

        self._export_node(self.tree.root, None)
        return "\n".join(self._lines)

    def _export_node(self, node: AttackNode, parent_tag: Optional[str]) -> str:
        tag = f"node_{self._counter}"
        self._counter += 1
        self._id_map[node.id] = tag

        label = node.name.replace('"', "'").replace("\r", "").replace("\n", " ").strip()

        if node.node_type == NodeType.OR:
            self._lines.append(f'    {tag}(["{label} (OR)"])')
        elif node.node_type == NodeType.AND:
            self._lines.append(f'    {tag}[["{label} (AND)"]]')
        else:  # LEAF
            self._lines.append(f'    {tag}["{label}"]')
            style = self._get_leaf_style(node)
            self._lines.append(f"    style {tag} {style}")

        if parent_tag:
            connector = "==>" if node.node_type == NodeType.AND else "-->"
            self._lines.append(f"    {parent_tag} {connector} {tag}")

        for child in node.children:
            self._export_node(child, tag)

        return tag

    @staticmethod
    def _get_leaf_style(node: AttackNode) -> str:
        colors = {
            Difficulty.TRIVIAL: "fill:#ff4d4f,color:#fff,stroke:#cf1322",
            Difficulty.LOW: "fill:#ffa940,color:#fff,stroke:#d46b08",
            Difficulty.MEDIUM: "fill:#ffd666,color:#333,stroke:#d48806",
            Difficulty.HIGH: "fill:#52c41a,color:#fff,stroke:#389e0d",
            Difficulty.EXPERT: "fill:#1890ff,color:#fff,stroke:#096dd9",
        }
        return colors.get(node.attributes.difficulty, "fill:#bfbfbf,color:#333")


class AttackPathAnalyzer:
    """Calculates coverage, critical bottlenecks, and optimal mitigation priorities."""

    def __init__(self, tree: AttackTree):
        self.tree = tree

    def get_all_paths(self) -> List[List[AttackNode]]:
        paths: List[List[AttackNode]] = []
        self._collect_paths(self.tree.root, [], paths)
        return paths

    def _collect_paths(
        self,
        node: AttackNode,
        current_path: List[AttackNode],
        all_paths: List[List[AttackNode]],
    ) -> None:
        current_path = current_path + [node]
        if node.node_type == NodeType.LEAF or not node.children:
            all_paths.append(current_path)
            return

        if node.node_type == NodeType.OR:
            for child in node.children:
                self._collect_paths(child, current_path, all_paths)
        else:  # AND
            child_subpaths: List[List[List[AttackNode]]] = []
            for child in node.children:
                sub: List[List[AttackNode]] = []
                self._collect_paths(child, [], sub)
                child_subpaths.append(sub)

            # Cartesian product across AND branches
            combined: List[List[AttackNode]] = [[]]
            for branch_paths in child_subpaths:
                new_comb: List[List[AttackNode]] = []
                for existing in combined:
                    for p in branch_paths:
                        new_comb.append(existing + p)
                combined = new_comb

            for combo in combined:
                all_paths.append(current_path + combo)

    def calculate_path_metrics(self, path: List[AttackNode]) -> Dict[str, Any]:
        leaves = [n for n in path if n.node_type == NodeType.LEAF]
        tot_diff = sum(n.attributes.difficulty.value for n in leaves)
        tot_cost = sum(n.attributes.cost.value for n in leaves)
        tot_time = sum(n.attributes.time_hours for n in leaves)
        max_det = max((n.attributes.detection_risk.value for n in leaves), default=0)

        return {
            "steps": len(leaves),
            "total_difficulty": tot_diff,
            "avg_difficulty": tot_diff / len(leaves) if leaves else 0.0,
            "total_cost": tot_cost,
            "total_time_hours": tot_time,
            "max_detection_risk": max_det,
            "requires_insider": any(n.attributes.requires_insider for n in leaves),
        }

    def identify_critical_nodes(self) -> List[Tuple[AttackNode, int]]:
        """Identify leaf nodes that appear most frequently across all attack paths."""
        paths = self.get_all_paths()
        counts: Dict[str, Tuple[AttackNode, int]] = {}

        for path in paths:
            for node in path:
                if node.node_type == NodeType.LEAF:
                    if node.id not in counts:
                        counts[node.id] = (node, 0)
                    counts[node.id] = (node, counts[node.id][1] + 1)

        return sorted(counts.values(), key=lambda x: x[1], reverse=True)

    def prioritize_mitigations(self) -> List[Dict[str, Any]]:
        """Rank mitigations by their ability to sever the maximum number of attack paths."""
        critical = self.identify_critical_nodes()
        total_paths = max(len(self.get_all_paths()), 1)

        recommendations = []
        for node, count in critical:
            if node.mitigations:
                impact = (count / total_paths) * 100.0
                recommendations.append({
                    "attack_id": node.id,
                    "attack_name": node.name,
                    "paths_blocked": count,
                    "coverage_impact_percent": round(impact, 2),
                    "difficulty": node.attributes.difficulty.name,
                    "mitigations": node.mitigations,
                    "cve_refs": node.cve_refs,
                })

        return sorted(recommendations, key=lambda x: x["coverage_impact_percent"], reverse=True)


def from_osint_findings(target: str, findings: List[Dict[str, Any]]) -> AttackTree:
    """Generate an AttackTree automatically from Orbit OSINT & Reconnaissance findings."""
    builder = AttackTreeBuilder(
        name=f"Compromise Perimeter of {target}",
        description=f"Automated threat model generated from Orbit Sec OSINT findings for {target}",
    )
    builder.goal("ROOT", f"Compromise {target} Infrastructure")

    # Group findings into categories with case-insensitivity and type checks
    takeovers = [
        f for f in findings
        if "takeover" in f.get("category", "").lower() or "cname" in f.get("type", "").lower()
    ]
    web_vulns = [
        f for f in findings
        if any(k in f.get("category", "").lower() or k in f.get("type", "").lower() for k in ("web", "owasp", "sqli", "xss", "rce", "cve", "injection"))
    ]
    dns_email = [
        f for f in findings
        if any(k in f.get("category", "").lower() or k in f.get("type", "").lower() for k in ("email", "dmarc", "spf", "dkim"))
    ]
    cloud_exposures = [
        f for f in findings
        if any(k in f.get("category", "").lower() or k in f.get("type", "").lower() for k in ("cloud", "bucket", "s3", "iam", "storage"))
    ]
    other = [f for f in findings if f not in takeovers + web_vulns + dns_email + cloud_exposures]

    if takeovers:
        builder.or_node("BRANCH_TAKEOVER", "Subdomain Hijacking & DNS Takeover")
        for i, f in enumerate(takeovers, 1):
            builder.attack(
                id=f"ATK_TAKEOVER_{i}",
                name=f.get("title", f"Claim dangling CNAME {f.get('target', '')}"),
                description=f.get("description", "Claim unlinked cloud provider bucket/app"),
                difficulty=Difficulty.TRIVIAL,
                cost=Cost.FREE,
                detection=DetectionRisk.LOW,
                mitigations=[
                    f"Remove stale DNS CNAME for {f.get('target', '')}",
                    "Deploy Orbit Ghost DNS daemon for continuous takeover monitoring",
                ],
            )
        builder.end()

    if web_vulns:
        builder.or_node("BRANCH_WEB", "Web Application Exploitation")
        for i, f in enumerate(web_vulns, 1):
            sev = f.get("severity", "MEDIUM").upper()
            diff = Difficulty.LOW if sev == "CRITICAL" else Difficulty.MEDIUM
            cves = f.get("cves", [])
            if isinstance(cves, str):
                cve_refs = [cves]
            elif isinstance(cves, list):
                cve_refs = [str(c) for c in cves if c]
            else:
                cve_refs = []
            builder.attack(
                id=f"ATK_WEB_{i}",
                name=f.get("title", f"Exploit {f.get('type', 'web')} on {f.get('target', '')}"),
                description=f.get("description", "Execute payload against target endpoint"),
                difficulty=diff,
                cost=Cost.LOW,
                detection=DetectionRisk.MEDIUM,
                mitigations=[
                    f"Patch affected service at {f.get('target', '')}",
                    "Enable WAF rules blocking attack signature",
                ],
                cve_refs=cve_refs,
            )
        builder.end()

    if dns_email:
        builder.or_node("BRANCH_EMAIL", "Email Spoofing & Phishing Impersonation")
        for i, f in enumerate(dns_email, 1):
            builder.attack(
                id=f"ATK_EMAIL_{i}",
                name=f.get("title", f"Spoof emails from {target}"),
                description=f.get("description", "Missing DMARC p=reject enables CEO fraud/phishing"),
                difficulty=Difficulty.TRIVIAL,
                cost=Cost.FREE,
                detection=DetectionRisk.MEDIUM,
                mitigations=[
                    "Publish strict DMARC record: v=DMARC1; p=reject; sp=reject; aspf=s",
                    "Enforce SPF record with -all and valid DKIM selectors",
                ],
            )
        builder.end()

    if cloud_exposures:
        builder.or_node("BRANCH_CLOUD", "Cloud Storage & IAM Leakage")
        for i, f in enumerate(cloud_exposures, 1):
            builder.attack(
                id=f"ATK_CLOUD_{i}",
                name=f.get("title", f"Access public bucket on {target}"),
                description=f.get("description", "Exposed cloud resource with unauthenticated read"),
                difficulty=Difficulty.TRIVIAL,
                cost=Cost.FREE,
                detection=DetectionRisk.NONE,
                mitigations=[
                    "Block public access on cloud storage bucket",
                    "Rotate exposed API keys and credentials",
                ],
            )
        builder.end()

    if other:
        builder.or_node("BRANCH_OTHER", "Perimeter Weaknesses")
        for i, f in enumerate(other, 1):
            builder.attack(
                id=f"ATK_OTHER_{i}",
                name=f.get("title", f"Exploit {f.get('type', 'weakness')}"),
                description=f.get("description", ""),
                difficulty=Difficulty.MEDIUM,
                cost=Cost.LOW,
                detection=DetectionRisk.MEDIUM,
                mitigations=[f"Remediate {f.get('title', 'finding')}"],
            )
        builder.end()

    # If no findings, provide default baseline reconnaissance attack path
    if not findings:
        builder.or_node("BRANCH_DEFAULT", "Credential Compromise & Phishing")
        builder.attack(
            id="ATK_CRED_1",
            name="Credential Stuffing on Corporate Portal",
            difficulty=Difficulty.LOW,
            cost=Cost.LOW,
            detection=DetectionRisk.HIGH,
            mitigations=["Enforce MFA and rate limiting on login gateways"],
        )
        builder.end()

    return builder.build()


def tree_to_mermaid(tree: AttackTree, direction: str = "TD") -> str:
    """Helper to convert AttackTree directly into Mermaid flowchart markdown."""
    return MermaidExporter(tree).export(direction=direction)
