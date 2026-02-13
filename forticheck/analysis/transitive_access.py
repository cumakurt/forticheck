"""Transitive Access Engine — hidden indirect access paths.

Detects: A -> B and B -> C exist, but A -> C has no direct policy (transitive only).
"""

from __future__ import annotations

import logging
from typing import Any

from forticheck.graph.builder import SecurityGraph
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class TransitiveAccessEngine:
    """Find access paths that exist only via policy chaining."""

    def analyze(
        self, graph: SecurityGraph
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        """Find transitive-only (hidden) access pairs."""
        findings: list[Finding] = []
        pairs_data: list[dict[str, Any]] = []

        direct = graph.get_direct_edges()
        transitive_pairs = graph.get_transitive_only_pairs(direct=direct)

        seen: set[tuple[str, str]] = set()
        for src, dst, depth in transitive_pairs:
            if (src, dst) in seen:
                continue
            seen.add((src, dst))

            src_trust = graph.get_trust_level(src)
            dst_trust = graph.get_trust_level(dst)
            trust_delta = dst_trust - src_trust

            pairs_data.append({
                "source": src,
                "destination": dst,
                "path_depth": depth,
                "src_trust": src_trust,
                "dst_trust": dst_trust,
            })

            severity = Severity.INFO
            if trust_delta >= 50:
                severity = Severity.HIGH
            elif trust_delta >= 30:
                severity = Severity.MEDIUM
            elif depth >= 4:
                severity = Severity.MEDIUM

            findings.append(Finding(
                id=f"TRANSITIVE-{src}-{dst}",
                category=FindingCategory.TRANSITIVE_ACCESS,
                severity=severity,
                title=f"Hidden Transitive Access: {src} → {dst}",
                description=(
                    f"No direct policy exists from {src} to {dst}, "
                    f"but access is possible via {depth}-hop policy chain. "
                    f"Trust delta: {trust_delta}."
                ),
                affected_zones=[src, dst],
                remediation="Review policy chain. Consider explicit deny or segmentation.",
                details={
                    "path_depth": depth,
                    "src_trust": src_trust,
                    "dst_trust": dst_trust,
                },
            ))

        # Limit findings to avoid noise
        findings.sort(key=lambda f: f.risk_score, reverse=True)
        findings = findings[:30]

        logger.info("Transitive access analysis: %d hidden paths, %d findings", len(transitive_pairs), len(findings))
        return findings, pairs_data
