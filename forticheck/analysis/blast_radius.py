"""Blast Radius Engine — compromise containment analysis.

Answers: If a zone/entity is compromised, how far can an attacker spread?
"""

from __future__ import annotations

import logging
from typing import Any

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device
from forticheck.models.findings import Finding, FindingCategory, Severity
from forticheck.normalizer.resolver import ObjectResolver

logger = logging.getLogger(__name__)

SENSITIVE_SERVICES = {
    "RDP", "SMB", "SSH", "TELNET", "WINRM", "VNC", "MS-SQL", "MYSQL",
    "3389", "445", "22", "23", "5900", "1433", "3306", "5985", "5986",
}


class BlastRadiusEngine:
    """Compute blast radius: reachable zones/services from each entry point."""

    def analyze(
        self,
        graph: SecurityGraph,
        device: Device,
        resolver: ObjectResolver,
    ) -> tuple[list[Finding], dict[str, dict[str, Any]]]:
        """Analyze blast radius per zone. Returns findings and zone->radius map."""
        findings: list[Finding] = []
        blast_map: dict[str, dict[str, Any]] = {}

        nodes = graph.get_all_zone_nodes()
        closure = graph.get_transitive_closure()

        for node in nodes:
            reachable = closure.get(node, set())
            trust = graph.get_trust_level(node)

            # Collect services exposed to this node from all incoming paths
            sensitive_count = 0
            total_services: set[str] = set()
            for src in nodes:
                if node in closure.get(src, set()) and src != node:
                    for edge in graph.get_outgoing_policies(src):
                        if edge.get("target") == node:
                            svcs = set(
                                s.upper() for s in edge.get("services", [])
                            ) | set(
                                s.upper() for s in edge.get("resolved_services", [])
                            )
                            total_services.update(svcs)
                            if svcs & SENSITIVE_SERVICES:
                                sensitive_count += len(svcs & SENSITIVE_SERVICES)

            blast_map[node] = {
                "reachable_count": len(reachable),
                "reachable_zones": list(reachable),
                "sensitive_service_exposure": sensitive_count,
                "trust_level": trust,
            }

            # High blast radius = critical finding
            if len(reachable) >= 5 and trust >= 70:
                findings.append(Finding(
                    id=f"BLAST-RADIUS-{node}",
                    category=FindingCategory.BLAST_RADIUS,
                    severity=Severity.HIGH,
                    title=f"High Blast Radius: {node}",
                    description=(
                        f"Zone '{node}' (trust={trust}) can reach {len(reachable)} zones. "
                        "Compromise would enable broad lateral movement."
                    ),
                    affected_zones=[node] + list(reachable)[:5],
                    remediation="Reduce zone-to-zone policy count. Apply micro-segmentation.",
                    details=blast_map[node],
                ))
            elif len(reachable) >= 8:
                findings.append(Finding(
                    id=f"BLAST-RADIUS-{node}",
                    category=FindingCategory.BLAST_RADIUS,
                    severity=Severity.MEDIUM,
                    title=f"Extended Blast Radius: {node}",
                    description=(
                        f"From zone '{node}', {len(reachable)} zones are reachable. "
                        f"Sensitive services exposed: {sensitive_count}."
                    ),
                    affected_zones=[node],
                    remediation="Review policies. Limit transitive access.",
                    details=blast_map[node],
                ))

        logger.info("Blast radius analysis: %d findings, %d zones scored", len(findings), len(blast_map))
        return findings, blast_map
