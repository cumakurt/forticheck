"""Segmentation Drift Engine — defined vs actual segmentation.

Detects when firewall policies effectively nullify zone segmentation.
"""

from __future__ import annotations

import logging
from typing import Any

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class SegmentationDriftEngine:
    """Compare defined zone boundaries with actual policy-enabled access."""

    def analyze(
        self,
        graph: SecurityGraph,
        device: Device,
        exposure_matrix: dict[str, dict[str, list[str]]],
    ) -> tuple[list[Finding], float]:
        """
        Analyze segmentation effectiveness.
        Returns findings and effectiveness score (0-1, higher = better segmentation).
        """
        findings: list[Finding] = []

        zones = graph.get_all_zone_nodes()
        n = len(zones)
        if n <= 1:
            return findings, 1.0

        # All possible zone pairs (excluding self)
        all_pairs = (n * (n - 1))
        # Actual access pairs (either direction)
        actual_pairs: set[tuple[str, str]] = set()
        for src, dst_data in exposure_matrix.items():
            for dst in dst_data.keys():
                if src != dst and dst_data.get(dst):
                    actual_pairs.add((src, dst))
                    actual_pairs.add((dst, src))  # bidirectional count
        actual_count = len(actual_pairs) // 2  # unique unordered pairs

        # Effectiveness: fewer connections = better segmentation
        # Ideal: only necessary pairs. Worst: all pairs connected.
        effectiveness = 1.0 - (actual_count / max(1, all_pairs // 2))
        effectiveness = max(0, min(1, effectiveness))

        # Drift: if we expect zones to be isolated but most are connected
        if actual_count >= n * (n - 1) // 2 * 0.7:  # 70%+ of pairs connected
            findings.append(Finding(
                id="SEGDRIFT-EFFECTIVE-ANY",
                category=FindingCategory.SEGMENTATION_DRIFT,
                severity=Severity.CRITICAL,
                title="Segmentation Effectively Disabled",
                description=(
                    f"{actual_count} zone pairs have policy-allowed access. "
                    f"Zone segmentation is largely ineffective. "
                    f"Effectiveness score: {effectiveness:.0%}."
                ),
                affected_zones=list(zones),
                remediation="Review policies. Reduce zone-to-zone permissions. Apply micro-segmentation.",
                details={
                    "zone_count": n,
                    "connected_pairs": actual_count,
                    "effectiveness": effectiveness,
                },
            ))
        elif effectiveness < 0.5:
            findings.append(Finding(
                id="SEGDRIFT-WEAK",
                category=FindingCategory.SEGMENTATION_DRIFT,
                severity=Severity.HIGH,
                title="Weak Zone Segmentation",
                description=(
                    f"Segmentation effectiveness: {effectiveness:.0%}. "
                    "Many zones are interconnected. Consider tighter boundaries."
                ),
                remediation="Reduce unnecessary zone-to-zone policies.",
                details={"effectiveness": effectiveness, "connected_pairs": actual_count},
            ))

        logger.info("Segmentation drift: effectiveness=%.2f, %d findings", effectiveness, len(findings))
        return findings, effectiveness
