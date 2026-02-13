"""Policy ordering recommendations — suggests moving more specific rules above broader ones."""

from __future__ import annotations

import logging
from collections import defaultdict

from forticheck.models.canonical import PolicyRule
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


def _specificity_score(policy: PolicyRule) -> int:
    """Higher score = more specific (should be higher in order). Any/any/any = 0."""
    score = 0
    if not policy.is_any_source:
        score += 1
    if not policy.is_any_destination:
        score += 1
    if not policy.is_any_service:
        score += 1
    return score


class PolicyOrderingAnalyzer:
    """Suggest policy reordering: more specific rules should appear before broader ones."""

    def analyze(self, policies: list[PolicyRule]) -> list[Finding]:
        """Find policies that are more specific than a rule above them (same zone pair)."""
        findings: list[Finding] = []
        enabled = [p for p in policies if p.enabled]

        # Group by (src_zones, dst_zones) to only compare relevant rules
        zone_pair_to_policies: dict[tuple[tuple[str, ...], tuple[str, ...]], list[PolicyRule]] = defaultdict(list)
        for p in enabled:
            key = (tuple(sorted(p.source_zones)), tuple(sorted(p.destination_zones)))
            zone_pair_to_policies[key].append(p)

        for key, group in zone_pair_to_policies.items():
            if len(group) < 2:
                continue
            # Sort by sequence (order in config)
            group_sorted = sorted(group, key=lambda x: x.sequence)
            for i in range(1, len(group_sorted)):
                lower_rule = group_sorted[i - 1]
                upper_rule = group_sorted[i]
                spec_lower = _specificity_score(lower_rule)
                spec_upper = _specificity_score(upper_rule)
                if spec_upper > spec_lower:
                    findings.append(Finding(
                        id=f"ORDER-{upper_rule.id}",
                        category=FindingCategory.POLICY_ORDERING,
                        severity=Severity.LOW,
                        title=f"Policy Ordering Suggestion: Move {upper_rule.id} above {lower_rule.id}",
                        description=(
                            f"Policy {upper_rule.id} (sequence {upper_rule.sequence}) is more specific than "
                            f"policy {lower_rule.id} (sequence {lower_rule.sequence}). "
                            "More specific rules should typically be placed higher to match intended traffic first."
                        ),
                        affected_policies=[upper_rule.id, lower_rule.id],
                        remediation=(
                            f"Consider moving policy {upper_rule.id} above policy {lower_rule.id} "
                            "for correct match order."
                        ),
                        details={
                            "more_specific_policy": upper_rule.id,
                            "less_specific_policy": lower_rule.id,
                            "specificity_scores": {"upper": spec_upper, "lower": spec_lower},
                        },
                    ))

        logger.info("Policy ordering analysis: %d suggestions", len(findings))
        return findings
