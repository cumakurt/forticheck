"""Lateral Movement Engine — likelihood of horizontal spread.

Scores each zone by: if compromised, how likely is lateral movement to sensitive targets?
"""

from __future__ import annotations

import logging
from typing import Any

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)

SENSITIVE_SERVICES = {"RDP", "SMB", "SSH", "TELNET", "WinRM", "VNC", "MS-SQL", "MYSQL", "3389", "445", "22", "23", "5900"}
HIGH_TRUST = 70


class LateralMovementEngine:
    """Compute lateral movement likelihood per zone."""

    def analyze(
        self,
        graph: SecurityGraph,
        device: Device,
        exposure_matrix: dict[str, dict[str, list[str]]],
    ) -> tuple[list[Finding], dict[str, float]]:
        """Score each zone. Returns findings and zone->score map."""
        findings: list[Finding] = []
        scores: dict[str, float] = {}

        nodes = graph.get_all_zone_nodes()
        high_trust = graph.get_high_trust_nodes(min_trust=HIGH_TRUST)
        closure = graph.get_transitive_closure()

        for node in nodes:
            reachable = closure.get(node, set())
            reachable_high = [z for z in reachable if z in high_trust or graph.get_trust_level(z) >= HIGH_TRUST]

            # Sensitive service exposure from this zone
            sensitive_exposure = 0
            for dst, services in exposure_matrix.get(node, {}).items():
                svc_set = set(s.upper() for s in services)
                if svc_set & SENSITIVE_SERVICES:
                    sensitive_exposure += len(svc_set & SENSITIVE_SERVICES)

            # Score: alpha * reachable_high + beta * sensitive + gamma * chain_depth
            alpha, beta, gamma = 0.5, 0.3, 0.2
            score = (
                alpha * min(100, len(reachable_high) * 25) +
                beta * min(100, sensitive_exposure * 15) +
                gamma * min(100, len(reachable) * 5)
            )
            score = min(100, score)
            scores[node] = score

            if score >= 60:
                severity = Severity.HIGH if score >= 80 else Severity.MEDIUM
                findings.append(Finding(
                    id=f"LATERAL-{node}",
                    category=FindingCategory.LATERAL_MOVEMENT,
                    severity=severity,
                    title=f"Lateral Movement Risk: {node}",
                    description=(
                        f"Zone '{node}' compromise enables access to {len(reachable)} zones, "
                        f"including {len(reachable_high)} high-trust. "
                        f"Sensitive services exposed: {sensitive_exposure}. "
                        f"Likelihood score: {score:.0f}."
                    ),
                    affected_zones=[node] + reachable_high[:3],
                    remediation="Reduce zone reachability. Restrict sensitive services. Apply segmentation.",
                    details={
                        "score": score,
                        "reachable_count": len(reachable),
                        "high_trust_reachable": len(reachable_high),
                        "sensitive_exposure": sensitive_exposure,
                    },
                ))

        logger.info("Lateral movement analysis: %d zones scored, %d findings", len(scores), len(findings))
        return findings, scores
