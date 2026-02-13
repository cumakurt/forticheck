"""Shadow and redundancy detection engines."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from forticheck.analysis.logic import PolicyLogicEngine, PolicyRelation
from forticheck.models.canonical import PolicyAction, PolicyRule
from forticheck.models.findings import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _zone_pair_key(p: PolicyRule) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Group key for zone-pair: only policies with same zone pair can shadow/redundant each other."""
    return (tuple(sorted(p.source_zones)), tuple(sorted(p.destination_zones)))


class ShadowDetector:
    """Detect shadow rules — policies that never match any traffic
    because they are fully covered by rules with higher priority (lower sequence).
    Uses zone-pair grouping to reduce comparisons (O(n²) only within each zone pair).
    """

    def __init__(self, logic_engine: PolicyLogicEngine | None = None) -> None:
        self.logic = logic_engine or PolicyLogicEngine()

    def detect(self, policies: list[PolicyRule]) -> list[Finding]:
        """Find all shadowed policies."""
        findings: list[Finding] = []
        enabled = [p for p in policies if p.enabled]
        by_zone_pair: dict[tuple[tuple[str, ...], tuple[str, ...]], list[PolicyRule]] = defaultdict(list)
        for p in enabled:
            by_zone_pair[_zone_pair_key(p)].append(p)

        for _key, group in by_zone_pair.items():
            group_sorted = sorted(group, key=lambda x: x.sequence)
            for i, candidate in enumerate(group_sorted):
                for j in range(i):
                    upper = group_sorted[j]
                    if self.logic.is_shadowed_by(candidate, upper):
                        is_conflict = candidate.action != upper.action
                        severity = Severity.HIGH if is_conflict else Severity.MEDIUM
                        shadow_type = "conflicting" if is_conflict else "full"

                        finding = Finding(
                            id=f"SHADOW-{candidate.id}",
                            category=FindingCategory.SHADOW_RULE,
                            severity=severity,
                            title=f"Shadow Rule Detected: Policy {candidate.id}",
                            description=(
                                f"Policy {candidate.id} is fully shadowed by policy "
                                f"{upper.id} (seq {upper.sequence}). "
                                f"Shadow type: {shadow_type}. "
                                f"{'Actions conflict.' if is_conflict else 'Same action — rule is unreachable.'}"
                            ),
                            affected_policies=[candidate.id, upper.id],
                            affected_zones=candidate.source_zones + candidate.destination_zones,
                            remediation=(
                                f"Review policy {candidate.id}. "
                                f"{'This rule has a conflicting action — potential security risk!' if is_conflict else 'Consider removing this unreachable rule.'}"
                            ),
                            details={
                                "shadowed_policy": candidate.id,
                                "shadowing_policy": upper.id,
                                "shadow_type": shadow_type,
                                "candidate_action": candidate.action.value,
                                "upper_action": upper.action.value,
                            },
                        )
                        findings.append(finding)
                        break  # One shadow finding per policy is enough

        logger.info("Shadow detection: found %d shadowed rules", len(findings))
        return findings


class RedundancyDetector:
    """Detect redundant rules — policies that, if removed,
    would not change the firewall's behavior.
    Uses zone-pair grouping to reduce comparisons.
    """

    def __init__(self, logic_engine: PolicyLogicEngine | None = None) -> None:
        self.logic = logic_engine or PolicyLogicEngine()

    def detect(self, policies: list[PolicyRule]) -> list[Finding]:
        """Find all redundant policies. Each pair (A, B) is reported only once."""
        findings: list[Finding] = []
        enabled = [p for p in policies if p.enabled]
        reported_pairs: set[tuple[str, str]] = set()
        by_zone_pair: dict[tuple[tuple[str, ...], tuple[str, ...]], list[PolicyRule]] = defaultdict(list)
        for p in enabled:
            by_zone_pair[_zone_pair_key(p)].append(p)

        for _key, group in by_zone_pair.items():
            for i, candidate in enumerate(group):
                for j, other in enumerate(group):
                    if i == j:
                        continue
                    if self.logic.is_redundant_with(candidate, other) and candidate.id != other.id:
                        pair_key = tuple(sorted([candidate.id, other.id]))
                        if pair_key in reported_pairs:
                            continue
                        reported_pairs.add(pair_key)
                        finding = Finding(
                            id=f"REDUNDANT-{pair_key[0]}-{pair_key[1]}",
                            category=FindingCategory.REDUNDANT_RULE,
                            severity=Severity.LOW,
                            title=f"Redundant Rules: Policy {candidate.id} and {other.id}",
                            description=(
                                f"Policies {candidate.id} and {other.id} are redundant. "
                                f"Both have action '{candidate.action.value}' "
                                f"and cover overlapping traffic sets. Consider consolidating."
                            ),
                            affected_policies=[candidate.id, other.id],
                            remediation=(
                                f"Consider consolidating policies {candidate.id} and "
                                f"{other.id} to simplify the rule base."
                            ),
                            details={
                                "redundant_policy": candidate.id,
                                "covered_by": other.id,
                            },
                        )
                        findings.append(finding)
                        break

        logger.info("Redundancy detection: found %d redundant pairs", len(findings))
        return findings
