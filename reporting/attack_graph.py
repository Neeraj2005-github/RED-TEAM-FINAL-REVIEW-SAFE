"""
reporting/attack_graph.py — NetworkX-based attack-path graph for the
AI Red Team Framework.

Builds a directed graph of the exploitation chain: hosts → services →
users → credentials → vulnerabilities, with edges representing
exploitation relationships.

Exports to:
  * JSON   (node + edge lists for web visualization)
  * DOT    (GraphViz)
  * PNG    (rendered via matplotlib)

MITRE ATT&CK:
  N/A — this is a reporting / visualisation utility.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import matplotlib
matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.patches import Patch

from config.settings import GRAPHS_DIR, REPORTS_DIR
from core.plugin_loader import ExecutionContext, ExecutionResult
from core.state_manager import state

logger = logging.getLogger(__name__)

os.makedirs(str(GRAPHS_DIR), exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Enums and data-classes
# ═══════════════════════════════════════════════════════════════════════════

class NodeType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    USER = "user"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"


@dataclass
class NodeAttrs:
    """Attributes attached to a graph node."""

    node_type: str = "host"
    label: str = ""
    ip: str = ""
    os: str = ""
    hostname: str = ""
    compromised: bool = False
    privilege_level: str = ""          # user, root, SYSTEM
    port: int = 0
    service_name: str = ""
    version: str = ""
    cve_ids: list[str] = field(default_factory=list)
    high_value: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class EdgeAttrs:
    """Attributes attached to a graph edge."""

    exploitation_type: str = ""        # brute_force, cve_exploit, privesc …
    success: bool = False
    cve_used: str = ""
    technique_id: str = ""             # MITRE ATT&CK
    description: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


# ═══════════════════════════════════════════════════════════════════════════
# 2. AttackGraph class
# ═══════════════════════════════════════════════════════════════════════════

class AttackGraph:
    """Directed graph of the attack chain built on top of ``NetworkX``."""

    # Colour / size presets
    _TYPE_COLORS: dict[str, str] = {
        NodeType.HOST:          "#FF9800",
        NodeType.SERVICE:       "#2196F3",
        NodeType.USER:          "#4CAF50",
        NodeType.CREDENTIAL:    "#E91E63",
        NodeType.VULNERABILITY: "#F44336",
    }
    _COMPROMISED_COLOR = "#D32F2F"
    _HIGH_VALUE_SIZE = 3000
    _DEFAULT_SIZE = 1500

    def __init__(self) -> None:
        self.G: nx.DiGraph = nx.DiGraph()

    # ------------------------------------------------------------------
    # Node helpers
    # ------------------------------------------------------------------

    def add_discovered_host(
        self,
        host: str,
        os_info: str = "",
        hostname: str = "",
        compromised: bool = False,
        high_value: bool = False,
    ) -> str:
        """Add a host node; returns its node-id."""
        nid = f"host:{host}"
        self.G.add_node(nid, **NodeAttrs(
            node_type=NodeType.HOST,
            label=hostname or host,
            ip=host,
            os=os_info,
            hostname=hostname,
            compromised=compromised,
            high_value=high_value,
        ).to_dict())
        return nid

    def add_service(
        self,
        host: str,
        service: str,
        port: int,
        version: str = "",
        cve_ids: list[str] | None = None,
    ) -> str:
        """Add a service node linked to its host."""
        host_nid = f"host:{host}"
        svc_nid = f"svc:{host}:{port}"
        if host_nid not in self.G:
            self.add_discovered_host(host)
        self.G.add_node(svc_nid, **NodeAttrs(
            node_type=NodeType.SERVICE,
            label=f"{service}:{port}",
            ip=host,
            port=port,
            service_name=service,
            version=version,
            cve_ids=cve_ids or [],
        ).to_dict())
        self.G.add_edge(host_nid, svc_nid, **EdgeAttrs(
            exploitation_type="runs",
            success=True,
            description=f"Host exposes {service} on port {port}",
        ).to_dict())
        return svc_nid

    def add_user(
        self,
        host: str,
        username: str,
        privilege_level: str = "user",
    ) -> str:
        """Add a user node linked to its host."""
        host_nid = f"host:{host}"
        user_nid = f"user:{host}:{username}"
        if host_nid not in self.G:
            self.add_discovered_host(host)
        self.G.add_node(user_nid, **NodeAttrs(
            node_type=NodeType.USER,
            label=f"{username}@{host}",
            ip=host,
            privilege_level=privilege_level,
        ).to_dict())
        self.G.add_edge(host_nid, user_nid, **EdgeAttrs(
            exploitation_type="authenticated_as",
            success=True,
        ).to_dict())
        return user_nid

    def add_vulnerability(
        self,
        host: str,
        cve_id: str,
        description: str = "",
    ) -> str:
        """Add a vulnerability node linked to its host."""
        host_nid = f"host:{host}"
        vuln_nid = f"vuln:{host}:{cve_id}"
        if host_nid not in self.G:
            self.add_discovered_host(host)
        self.G.add_node(vuln_nid, **NodeAttrs(
            node_type=NodeType.VULNERABILITY,
            label=cve_id,
            ip=host,
            cve_ids=[cve_id],
        ).to_dict())
        self.G.add_edge(host_nid, vuln_nid, **EdgeAttrs(
            exploitation_type="vulnerable_to",
            cve_used=cve_id,
            description=description,
        ).to_dict())
        return vuln_nid

    # ------------------------------------------------------------------
    # Edge helpers
    # ------------------------------------------------------------------

    def add_exploitation(
        self,
        source: str,
        target: str,
        method: str,
        success: bool = True,
        cve_used: str = "",
        technique_id: str = "",
    ) -> None:
        """Add an exploitation edge between two node-ids (or raw IPs)."""
        src = source if source in self.G else f"host:{source}"
        tgt = target if target in self.G else f"host:{target}"
        if src not in self.G:
            self.add_discovered_host(source)
            src = f"host:{source}"
        if tgt not in self.G:
            self.add_discovered_host(target)
            tgt = f"host:{target}"

        self.G.add_edge(src, tgt, **EdgeAttrs(
            exploitation_type=method,
            success=success,
            cve_used=cve_used,
            technique_id=technique_id,
            timestamp=datetime.utcnow().isoformat(),
        ).to_dict())

        # Mark target compromised on success
        if success and "host:" in tgt:
            self.G.nodes[tgt]["compromised"] = True

    # ------------------------------------------------------------------
    # Path analysis
    # ------------------------------------------------------------------

    def find_critical_paths(self) -> list[list[str]]:
        """Find all simple paths from attacker to any compromised node."""
        paths: list[list[str]] = []
        compromised = [
            n for n, d in self.G.nodes(data=True) if d.get("compromised")
        ]
        # Use the first host as "attacker" if labelled
        sources = [
            n for n, d in self.G.nodes(data=True)
            if d.get("label", "").lower().startswith("attacker")
        ] or ([list(self.G.nodes)[0]] if self.G.nodes else [])

        for src in sources:
            for dst in compromised:
                if src == dst:
                    continue
                try:
                    for p in nx.all_simple_paths(self.G, src, dst, cutoff=10):
                        paths.append(p)
                except nx.NetworkXError:
                    continue
        return paths

    def find_shortest_path_to_admin(self) -> list[str]:
        """Shortest path from any attacker node to a root / SYSTEM user."""
        admin_nodes = [
            n for n, d in self.G.nodes(data=True)
            if d.get("privilege_level") in ("root", "SYSTEM", "admin")
        ]
        sources = [
            n for n, d in self.G.nodes(data=True)
            if d.get("label", "").lower().startswith("attacker")
        ] or ([list(self.G.nodes)[0]] if self.G.nodes else [])

        best: list[str] = []
        for src in sources:
            for dst in admin_nodes:
                try:
                    path = nx.shortest_path(self.G, src, dst)
                    if not best or len(path) < len(best):
                        best = path
                except nx.NetworkXNoPath:
                    continue
        return best

    def find_lateral_movement_targets(self, current_host: str) -> list[str]:
        """Return hosts reachable from *current_host*."""
        nid = f"host:{current_host}" if f"host:{current_host}" in self.G else current_host
        if nid not in self.G:
            return []
        reachable: set[str] = set()
        for succ in nx.descendants(self.G, nid):
            data = self.G.nodes.get(succ, {})
            if data.get("node_type") == NodeType.HOST and succ != nid:
                reachable.add(data.get("ip", succ))
        return sorted(reachable)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """Export as JSON-serialisable node + edge lists."""
        nodes = []
        for nid, attrs in self.G.nodes(data=True):
            nodes.append({"id": nid, **attrs})
        edges = []
        for src, dst, attrs in self.G.edges(data=True):
            edges.append({"source": src, "target": dst, **attrs})
        return {"nodes": nodes, "edges": edges}

    def to_dot(self) -> str:
        """Export as a GraphViz DOT string."""
        lines = ["digraph AttackGraph {", '  rankdir=LR;', '  node [shape=box, style=filled];']
        for nid, attrs in self.G.nodes(data=True):
            label = attrs.get("label", nid)
            ntype = attrs.get("node_type", "host")
            color = self._TYPE_COLORS.get(ntype, "#CCCCCC")
            if attrs.get("compromised"):
                color = self._COMPROMISED_COLOR
            lines.append(f'  "{nid}" [label="{label}", fillcolor="{color}"];')

        for src, dst, attrs in self.G.edges(data=True):
            style = "solid" if attrs.get("success", True) else "dashed"
            label = attrs.get("exploitation_type", "")
            lines.append(f'  "{src}" -> "{dst}" [label="{label}", style={style}];')

        lines.append("}")
        return "\n".join(lines)

    def to_png(self, filepath: str = "") -> str:
        """Render the graph as a PNG image using matplotlib."""
        if not filepath:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filepath = str(GRAPHS_DIR / f"attack_graph_{ts}.png")

        fig, ax = plt.subplots(figsize=(16, 10))
        pos = nx.spring_layout(self.G, seed=42, k=2.5)

        # Draw nodes grouped by type
        for nid, attrs in self.G.nodes(data=True):
            ntype = attrs.get("node_type", "host")
            color = self._TYPE_COLORS.get(ntype, "#CCCCCC")
            if attrs.get("compromised"):
                color = self._COMPROMISED_COLOR
            size = self._HIGH_VALUE_SIZE if attrs.get("high_value") else self._DEFAULT_SIZE
            nx.draw_networkx_nodes(
                self.G, pos, nodelist=[nid],
                node_color=color, node_size=size,
                edgecolors="black", linewidths=1.5, ax=ax,
            )

        # Separate solid (success) / dashed (failed) edges
        solid_edges = [(u, v) for u, v, d in self.G.edges(data=True) if d.get("success", True)]
        dashed_edges = [(u, v) for u, v, d in self.G.edges(data=True) if not d.get("success", True)]

        nx.draw_networkx_edges(
            self.G, pos, edgelist=solid_edges,
            edge_color="#555555", arrows=True, arrowsize=20, width=2,
            connectionstyle="arc3,rad=0.1", ax=ax,
        )
        if dashed_edges:
            nx.draw_networkx_edges(
                self.G, pos, edgelist=dashed_edges,
                edge_color="#AAAAAA", arrows=True, arrowsize=15, width=1,
                style="dashed", connectionstyle="arc3,rad=0.1", ax=ax,
            )

        # Labels
        labels = {nid: d.get("label", nid) for nid, d in self.G.nodes(data=True)}
        nx.draw_networkx_labels(self.G, pos, labels, font_size=8, font_weight="bold", ax=ax)

        edge_labels = {
            (u, v): d.get("exploitation_type", "")
            for u, v, d in self.G.edges(data=True)
        }
        nx.draw_networkx_edge_labels(self.G, pos, edge_labels, font_size=6, ax=ax)

        # Legend
        legend = [
            Patch(facecolor=c, edgecolor="black", label=t.value.title())
            for t, c in self._TYPE_COLORS.items()
        ]
        legend.append(Patch(facecolor=self._COMPROMISED_COLOR, edgecolor="black", label="Compromised"))
        ax.legend(handles=legend, loc="upper left", fontsize=9)
        ax.set_title("Attack Path Graph — AI Red Team Framework", fontsize=14, fontweight="bold")
        ax.axis("off")

        plt.savefig(filepath, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        logger.info("Attack graph PNG saved to %s", filepath)
        return filepath

    # ------------------------------------------------------------------
    # Build from state
    # ------------------------------------------------------------------

    @classmethod
    def from_state(cls) -> "AttackGraph":
        """Construct an ``AttackGraph`` from the current engagement state."""
        graph = cls()
        target = state.get("target", "unknown")
        attacker = "10.0.0.1"

        # Attacker node
        graph.add_discovered_host(attacker, hostname="Attacker", high_value=False)
        graph.G.nodes[f"host:{attacker}"]["label"] = "Attacker"

        # Target node
        os_info = state.get("os_info", "")
        graph.add_discovered_host(target, os_info=os_info, hostname=target, high_value=True)

        # Initial access edge
        graph.add_exploitation(
            f"host:{attacker}", f"host:{target}",
            method="initial_access", success=True,
        )

        # Scan results → services
        scan = state.get("scan_results", {})
        open_ports = scan.get("open_ports", [])
        if isinstance(open_ports, list):
            for entry in open_ports:
                if isinstance(entry, dict):
                    port = entry.get("port", 0)
                    svc = entry.get("service", "unknown")
                    ver = entry.get("version", "")
                    graph.add_service(target, svc, port, version=ver)

        # Exploit results
        for item in state.get("exploit_results", []):
            technique = item.get("technique", "")
            success = item.get("success", False)
            port = item.get("port", 0)
            cve = item.get("cve", "")
            svc_nid = f"svc:{target}:{port}" if port else f"host:{target}"
            if svc_nid not in graph.G:
                svc_nid = f"host:{target}"
            graph.add_exploitation(
                f"host:{attacker}", svc_nid,
                method=technique, success=success, cve_used=cve,
            )

        # Session info → user node
        session = state.get("session_info", {})
        if session.get("username"):
            graph.add_user(target, session["username"], privilege_level="user")

        # Privesc results
        privesc = state.get("privesc_results", {})
        if isinstance(privesc, dict):
            paths = privesc.get("paths", [])
            for p in paths:
                if isinstance(p, dict) and p.get("post_exploit_access"):
                    graph.add_user(target, "root", privilege_level="root")
                    graph.add_exploitation(
                        f"user:{target}:{session.get('username', 'user')}",
                        f"user:{target}:root",
                        method=p.get("method", "privesc"),
                        success=True,
                        technique_id=p.get("mitre_technique", ""),
                    )
                    break

        # Lateral movement hosts
        lat = state.get("lateral_movement", {})
        for host_info in lat.get("hosts_discovered", []):
            ip = host_info.get("ip", "")
            if ip and ip != target:
                graph.add_discovered_host(
                    ip,
                    hostname=host_info.get("hostname", ""),
                    compromised=host_info.get("is_compromised", False),
                    high_value=host_info.get("target_value") == "high",
                )

        for pivot in lat.get("pivots", []):
            graph.add_exploitation(
                f"host:{target}",
                f"host:{pivot.get('target_host', '')}",
                method=pivot.get("method", "pivot"),
                success=True,
            )

        return graph


# ═══════════════════════════════════════════════════════════════════════════
# 3. Plugin interface
# ═══════════════════════════════════════════════════════════════════════════

def metadata() -> dict[str, Any]:
    return {
        "name": "attack_graph",
        "version": "1.0.0",
        "category": "reporting",
        "description": (
            "NetworkX-based attack-path graph with JSON, DOT, and PNG export"
        ),
        "dependencies": ["networkx", "matplotlib"],
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Build the attack graph from state and export all formats."""
    graph = AttackGraph.from_state()

    # Export
    json_data = graph.to_json()
    dot_data = graph.to_dot()
    png_path = graph.to_png()

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = str(GRAPHS_DIR / f"attack_graph_{ts}.json")
    dot_path = str(GRAPHS_DIR / f"attack_graph_{ts}.dot")

    with open(json_path, "w") as fh:
        json.dump(json_data, fh, indent=2, default=str)
    with open(dot_path, "w") as fh:
        fh.write(dot_data)

    results = {
        "graph_json": json_data,
        "png_path": png_path,
        "json_path": json_path,
        "dot_path": dot_path,
        "nodes": len(graph.G.nodes),
        "edges": len(graph.G.edges),
        "critical_paths": graph.find_critical_paths(),
        "shortest_to_admin": graph.find_shortest_path_to_admin(),
    }
    state.set("attack_graph", results)
    return ExecutionResult(success=True, output=results)


# ═══════════════════════════════════════════════════════════════════════════
# Stand-alone
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    from core.state_manager import state as _st
    _target = sys.argv[1] if len(sys.argv) > 1 else _st.target_ip or "<TARGET>"
    ctx = ExecutionContext(phase="reporting", target_info={"target": _target})
    res = execute(ctx)
    print(json.dumps({k: v for k, v in res.output.items() if k != "graph_json"},
                     indent=2, default=str))
