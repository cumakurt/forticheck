"""Network topology and policy graph builder using NetworkX.

Nodes represent zones/subnets, edges represent firewall policies (allow rules).
This graph is the foundation for attack path simulation and exposure analysis.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from forticheck.models.canonical import (
    Device,
    PolicyAction,
    PolicyRule,
    Zone,
)
from forticheck.normalizer.resolver import ObjectResolver

logger = logging.getLogger(__name__)

# Special node for Internet
INTERNET_NODE = "__internet__"


class SecurityGraph:
    """Directed graph modeling network topology and firewall policy edges."""

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()
        self.zone_map: dict[str, Zone] = {}

    def build_from_device(self, device: Device, resolver: ObjectResolver) -> None:
        """Build the complete security graph from a Device model."""
        zones = device.all_zones
        policies = device.all_policies

        # Index zones
        for zone in zones:
            self.zone_map[zone.name] = zone

        # 1) Add zone nodes
        self._add_zone_nodes(zones)

        # 2) Add Internet node
        self._add_internet_node(zones)

        # 3) Add policy edges
        self._add_policy_edges(policies, resolver)

        logger.info(
            "Security graph built: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

    # ------------------------------------------------------------------
    # Node creation
    # ------------------------------------------------------------------

    def _add_zone_nodes(self, zones: list[Zone]) -> None:
        """Add a node for each zone."""
        for zone in zones:
            self.graph.add_node(
                zone.name,
                node_type="zone",
                trust_level=zone.trust_level,
                interfaces=zone.interfaces,
                networks=zone.networks,
                label=zone.name,
            )

    def _add_internet_node(self, zones: list[Zone]) -> None:
        """Add a special Internet node if not already represented."""
        # Check if any zone already represents Internet (trust=0)
        has_internet = any(z.trust_level == 0 for z in zones)
        if not has_internet:
            self.graph.add_node(
                INTERNET_NODE,
                node_type="internet",
                trust_level=0,
                interfaces=[],
                networks=["0.0.0.0/0"],
                label="Internet",
            )

    # ------------------------------------------------------------------
    # Edge creation
    # ------------------------------------------------------------------

    def _add_policy_edges(self, policies: list[PolicyRule],
                          resolver: ObjectResolver) -> None:
        """Add directed edges for each ALLOW policy."""
        for policy in policies:
            if policy.action != PolicyAction.ACCEPT:
                continue
            if not policy.enabled:
                continue

            for src_zone in policy.source_zones:
                for dst_zone in policy.destination_zones:
                    # Resolve zone names (could be interface names)
                    src_node = self._resolve_zone_node(src_zone)
                    dst_node = self._resolve_zone_node(dst_zone)

                    if src_node is None or dst_node is None:
                        continue

                    # Get service sensitivity
                    svc_sensitivity = resolver.get_service_sensitivity(policy.services)

                    self.graph.add_edge(
                        src_node, dst_node,
                        key=policy.id,
                        policy_id=policy.id,
                        policy_name=policy.name,
                        services=policy.services,
                        resolved_services=policy.resolved_services,
                        src_addresses=policy.source_addresses,
                        dst_addresses=policy.destination_addresses,
                        has_security_profile=policy.security_profiles.has_any,
                        is_any_source=policy.is_any_source,
                        is_any_destination=policy.is_any_destination,
                        is_any_service=policy.is_any_service,
                        nat=policy.nat,
                        service_sensitivity=svc_sensitivity.value,
                    )

    def _resolve_zone_node(self, name: str) -> str | None:
        """Resolve a zone/interface name to a graph node name."""
        if name in self.graph:
            return name
        # Check if it's an interface that belongs to a zone
        for zone_name, zone in self.zone_map.items():
            if name in zone.interfaces:
                return zone_name
        # Create it as a standalone node if it doesn't exist
        if name not in self.graph:
            self.graph.add_node(
                name,
                node_type="zone",
                trust_level=50,
                interfaces=[name],
                networks=[],
                label=name,
            )
        return name

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_trust_level(self, node: str) -> int:
        """Get the trust level of a node."""
        data = self.graph.nodes.get(node, {})
        return data.get("trust_level", 50)

    def get_outgoing_policies(self, node: str) -> list[dict[str, Any]]:
        """Get all outgoing policy edges from a node."""
        edges = []
        if node in self.graph:
            for _, dst, data in self.graph.out_edges(node, data=True):
                edges.append({"source": node, "target": dst, **data})
        return edges

    def get_incoming_policies(self, node: str) -> list[dict[str, Any]]:
        """Get all incoming policy edges to a node."""
        edges = []
        if node in self.graph:
            for src, _, data in self.graph.in_edges(node, data=True):
                edges.append({"source": src, "target": node, **data})
        return edges

    def get_zone_pairs(self) -> list[tuple[str, str, list[dict]]]:
        """Get all zone pairs with their policy edges."""
        pairs: dict[tuple[str, str], list[dict]] = {}
        for src, dst, data in self.graph.edges(data=True):
            key = (src, dst)
            pairs.setdefault(key, []).append(data)
        return [(s, d, e) for (s, d), e in pairs.items()]

    def get_all_zone_nodes(self) -> list[str]:
        """Get all zone node names."""
        return [n for n, d in self.graph.nodes(data=True)
                if d.get("node_type") in ("zone", "internet")]

    def has_path(self, source: str, target: str) -> bool:
        """Check if there is any path from source to target."""
        return nx.has_path(self.graph, source, target)

    def get_internet_nodes(self) -> list[str]:
        """Get nodes that represent the Internet (trust=0)."""
        nodes = []
        for n, d in self.graph.nodes(data=True):
            if d.get("trust_level", 50) == 0:
                nodes.append(n)
        return nodes

    def get_high_trust_nodes(self, min_trust: int = 80) -> list[str]:
        """Get nodes with trust level >= threshold."""
        return [n for n, d in self.graph.nodes(data=True)
                if d.get("trust_level", 0) >= min_trust]

    # ------------------------------------------------------------------
    # Next-gen analysis: transitive closure, reachability, blast radius
    # ------------------------------------------------------------------

    def get_reachable_from(self, source: str, max_depth: int = 10) -> set[str]:
        """Get all nodes reachable from source via policy edges (BFS)."""
        if source not in self.graph:
            return set()
        reachable: set[str] = set()
        queue: list[tuple[str, int]] = [(source, 0)]
        visited: set[str] = {source}
        while queue:
            node, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for _, dst, _ in self.graph.out_edges(node, keys=True):
                if dst not in visited:
                    visited.add(dst)
                    reachable.add(dst)
                    queue.append((dst, depth + 1))
        return reachable

    def get_transitive_closure(self, max_depth: int = 10) -> dict[str, set[str]]:
        """Compute transitive closure: for each node, all nodes reachable from it."""
        nodes = self.get_all_zone_nodes()
        return {n: self.get_reachable_from(n, max_depth) for n in nodes}

    def get_direct_edges(self) -> set[tuple[str, str]]:
        """Get all direct (single-hop) zone pairs that have a policy."""
        pairs: set[tuple[str, str]] = set()
        for src, dst, _ in self.graph.edges(keys=True):
            if self.graph.nodes.get(src, {}).get("node_type") in ("zone", "internet"):
                pairs.add((src, dst))
        return pairs

    def get_transitive_only_pairs(
        self,
        direct: set[tuple[str, str]] | None = None,
        closure: dict[str, set[str]] | None = None,
    ) -> list[tuple[str, str, int]]:
        """
        Find (src, dst) pairs that are reachable via transit but NOT via direct policy.
        Returns list of (src, dst, path_length).
        """
        direct = direct or self.get_direct_edges()
        closure = closure or self.get_transitive_closure()

        transitive_only: list[tuple[str, str, int]] = []
        for src, reachable in closure.items():
            for dst in reachable:
                if src == dst:
                    continue
                if (src, dst) in direct:
                    continue
                # Find shortest path length for (src, dst)
                try:
                    path = nx.shortest_path(self.graph, src, dst)
                    depth = len(path) - 1
                    if depth >= 2:  # At least 2 hops = transitive
                        transitive_only.append((src, dst, depth))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    pass
        return transitive_only

    def get_all_simple_paths(
        self, source: str, target: str, cutoff: int = 5
    ) -> list[list[str]]:
        """Get all simple paths from source to target up to cutoff length."""
        try:
            return list(
                nx.all_simple_paths(self.graph, source, target, cutoff=cutoff)
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
