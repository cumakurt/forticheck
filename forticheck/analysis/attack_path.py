"""Attack path simulation engine — discovers multi-hop attack chains through the network."""

from __future__ import annotations

import logging
from collections import deque

from forticheck.graph.builder import SecurityGraph
from forticheck.models.findings import (
    AttackPath,
    AttackPathHop,
    Finding,
    FindingCategory,
    Severity,
)

logger = logging.getLogger(__name__)


class AttackPathEngine:
    """Discover multi-hop attack paths using BFS with trust gradient filtering."""

    def __init__(self, max_depth: int = 5) -> None:
        self.max_depth = max_depth

    def find_attack_paths(self, graph: SecurityGraph) -> list[AttackPath]:
        """Find all attack paths starting from Internet (trust=0) nodes."""
        paths: list[AttackPath] = []
        internet_nodes = graph.get_internet_nodes()
        high_trust_nodes = graph.get_high_trust_nodes(min_trust=70)

        if not internet_nodes:
            logger.warning("No Internet nodes found in graph")
            return paths

        path_id = 0
        for source in internet_nodes:
            discovered = self._bfs_attack_paths(graph, source)
            for raw_path in discovered:
                if len(raw_path) < 2:
                    continue

                # Only keep paths that reach higher trust
                end_trust = graph.get_trust_level(raw_path[-1]["node"])
                start_trust = graph.get_trust_level(source)

                if end_trust <= start_trust:
                    continue

                path_id += 1
                attack_path = self._build_attack_path(
                    graph, raw_path, f"AP-{path_id:03d}",
                    is_internet=True,
                )
                paths.append(attack_path)

        # Sort by risk score descending
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        # Limit to top paths to avoid noise
        paths = paths[:50]

        logger.info("Attack path engine: found %d paths", len(paths))
        return paths

    def generate_findings(self, paths: list[AttackPath]) -> list[Finding]:
        """Convert attack paths to findings."""
        findings: list[Finding] = []

        for path in paths:
            if path.risk_score < 30:
                continue

            severity = Severity.INFO
            if path.risk_score >= 80:
                severity = Severity.CRITICAL
            elif path.risk_score >= 60:
                severity = Severity.HIGH
            elif path.risk_score >= 40:
                severity = Severity.MEDIUM
            elif path.risk_score >= 20:
                severity = Severity.LOW

            policy_ids = [hop.policy_id for hop in path.hops]

            finding = Finding(
                id=f"ATTACK-PATH-{path.id}",
                category=FindingCategory.ATTACK_PATH,
                severity=severity,
                title=f"Attack Path: {path.description}",
                description=(
                    f"A {path.hop_count}-hop attack path exists: {path.description}. "
                    f"Total trust gain: {path.total_trust_gain:.0f}. "
                    f"{'Originates from Internet.' if path.is_internet_originating else ''}"
                ),
                affected_policies=policy_ids,
                affected_zones=[path.start_zone, path.end_zone],
                risk_score=path.risk_score,
                remediation=(
                    f"Break this attack path by restricting access between "
                    f"intermediate zones. Apply security profiles to each hop."
                ),
                details={
                    "hop_count": path.hop_count,
                    "total_trust_gain": path.total_trust_gain,
                    "path_description": path.description,
                    "hops": [
                        {
                            "from": h.source_zone,
                            "to": h.destination_zone,
                            "policy": h.policy_id,
                            "services": h.services,
                        }
                        for h in path.hops
                    ],
                },
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # BFS implementation
    # ------------------------------------------------------------------

    def _bfs_attack_paths(self, graph: SecurityGraph,
                          source: str) -> list[list[dict]]:
        """BFS to find all paths from source with increasing trust."""
        all_paths: list[list[dict]] = []

        # Queue: (current_node, path_so_far, visited_set)
        initial_entry = {"node": source, "edge": None}
        queue: deque = deque([(source, [initial_entry], {source})])

        while queue:
            current, path, visited = queue.popleft()

            if len(path) - 1 >= self.max_depth:
                continue

            current_trust = graph.get_trust_level(current)
            outgoing = graph.get_outgoing_policies(current)

            for edge in outgoing:
                target = edge.get("target", "")
                if target in visited:
                    continue

                target_trust = graph.get_trust_level(target)

                # Only follow paths that maintain or increase trust
                if target_trust < current_trust:
                    continue

                new_entry = {"node": target, "edge": edge}
                new_path = path + [new_entry]
                new_visited = visited | {target}

                # Record this path if trust increased from start
                start_trust = graph.get_trust_level(source)
                if target_trust > start_trust:
                    all_paths.append(new_path)

                # Continue exploring
                queue.append((target, new_path, new_visited))

        return all_paths

    def _build_attack_path(self, graph: SecurityGraph,
                           raw_path: list[dict], path_id: str,
                           is_internet: bool = False) -> AttackPath:
        """Convert raw BFS path to AttackPath model."""
        hops: list[AttackPathHop] = []
        total_trust_gain = 0.0

        for i in range(1, len(raw_path)):
            prev = raw_path[i - 1]
            curr = raw_path[i]
            edge = curr.get("edge", {})

            src_zone = prev["node"]
            dst_zone = curr["node"]
            src_trust = graph.get_trust_level(src_zone)
            dst_trust = graph.get_trust_level(dst_zone)
            delta = max(0, dst_trust - src_trust)
            total_trust_gain += delta

            hop = AttackPathHop(
                source_zone=src_zone,
                source_network="",
                destination_zone=dst_zone,
                destination_network="",
                policy_id=edge.get("policy_id", "?"),
                services=edge.get("services", []),
                trust_delta=delta,
            )
            hops.append(hop)

        # Calculate risk score
        start_trust = graph.get_trust_level(raw_path[0]["node"])
        end_trust = graph.get_trust_level(raw_path[-1]["node"])
        risk = self._calculate_path_risk(
            total_trust_gain, len(hops), end_trust, is_internet,
        )

        return AttackPath(
            id=path_id,
            hops=hops,
            total_trust_gain=total_trust_gain,
            risk_score=risk,
            start_zone=raw_path[0]["node"],
            end_zone=raw_path[-1]["node"],
            is_internet_originating=is_internet,
        )

    @staticmethod
    def _calculate_path_risk(trust_gain: float, hop_count: int,
                             end_trust: int, is_internet: bool) -> float:
        """Calculate composite risk score for an attack path.

        Factors:
        - Trust gain (higher = more dangerous)
        - End zone trust level (reaching DC = critical)
        - Internet origination bonus
        - Depth penalty (longer paths are harder to exploit)
        """
        # Base: trust gain normalized to 0-100
        base = min(100, trust_gain)

        # End trust bonus (reaching high trust zones)
        trust_bonus = end_trust * 0.3

        # Internet origination bonus
        inet_bonus = 20 if is_internet else 0

        # Depth penalty (each hop slightly reduces feasibility)
        depth_penalty = min(20, (hop_count - 1) * 5)

        risk = base * 0.4 + trust_bonus + inet_bonus - depth_penalty
        return max(0, min(100, risk))
