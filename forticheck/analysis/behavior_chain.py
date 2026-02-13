"""Behavior Chain Engine — policy chaining and transit access.

Detects transit paths where intermediate zones enable A -> C without direct A->C policy.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from forticheck.graph.builder import SecurityGraph
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class BehaviorChainEngine:
    """Analyze policy chains and transit access patterns."""

    def analyze(self, graph: SecurityGraph) -> list[Finding]:
        """Find long policy chains and unintended bridge policies."""
        findings: list[Finding] = []

        transitive = graph.get_transitive_only_pairs()
        # Group by path length - long chains are riskier
        long_chains = [(s, d, l) for s, d, l in transitive if l >= 3]

        if len(long_chains) >= 10:
            # Sample for finding
            sample = long_chains[:5]
            path_desc = "; ".join(f"{s}→{d} ({l} hops)" for s, d, l in sample)
            findings.append(Finding(
                id="BEHAVIOR-CHAIN-EXCESSIVE",
                category=FindingCategory.BEHAVIOR_CHAIN,
                severity=Severity.MEDIUM,
                title="Excessive Transit Policy Chains",
                description=(
                    f"{len(long_chains)} zone pairs have 3+ hop transit access. "
                    f"Sample: {path_desc}. Policy chains create unintended access paths."
                ),
                remediation="Review intermediate zone policies. Add explicit denies where appropriate.",
                details={"count": len(long_chains), "sample": sample},
            ))

        # Find potential "bridge" zones - zones that connect many others
        nodes = graph.get_all_zone_nodes()
        bridge_scores: dict[str, int] = {}
        for src, dst, depth in transitive:
            if depth >= 2:
                try:
                    path = nx.shortest_path(graph.graph, src, dst)
                    for mid in path[1:-1]:
                        bridge_scores[mid] = bridge_scores.get(mid, 0) + 1
                except Exception:
                    pass

        for zone, count in sorted(bridge_scores.items(), key=lambda x: -x[1])[:3]:
            if count >= 5:
                findings.append(Finding(
                    id=f"BEHAVIOR-BRIDGE-{zone}",
                    category=FindingCategory.BEHAVIOR_CHAIN,
                    severity=Severity.LOW,
                    title=f"Bridge Zone: {zone}",
                    description=(
                        f"Zone '{zone}' acts as transit for {count}+ indirect access paths. "
                        "Compromise enables lateral movement to multiple zones."
                    ),
                    affected_zones=[zone],
                    remediation="Review policies through this zone. Consider segmentation.",
                    details={"transit_count": count},
                ))

        logger.info("Behavior chain analysis: %d findings", len(findings))
        return findings
