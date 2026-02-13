"""Intent Analysis Engine — defined intent vs actual behavior.

Compares policy comments/naming with actual permissiveness.
Limited without external intent metadata.
"""

from __future__ import annotations

import logging

from forticheck.models.canonical import Device, PolicyAction, PolicyRule
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class IntentAnalysisEngine:
    """Infer intent from comments/naming and compare with policy behavior."""

    def analyze(self, device: Device) -> list[Finding]:
        """
        Heuristic intent-behavior gap.
        Policies with restrictive names/comments but any/any/any behavior.
        """
        findings: list[Finding] = []

        restrictive_keywords = ["restrict", "limit", "only", "specific", "minimal"]
        broad_keywords = ["all", "any", "deny", "block"]

        for policy in device.all_policies:
            if policy.action != PolicyAction.ACCEPT or not policy.enabled:
                continue

            comment = (policy.comments or "").lower()
            name = (policy.name or "").lower()

            has_restrictive_intent = any(kw in comment or kw in name for kw in restrictive_keywords)
            is_overly_permissive = policy.is_overly_permissive or (
                policy.is_any_source and policy.is_any_destination
            )

            if has_restrictive_intent and is_overly_permissive:
                findings.append(Finding(
                    id=f"INTENT-GAP-{policy.id}",
                    category=FindingCategory.INTENT_BEHAVIOR_GAP,
                    severity=Severity.HIGH,
                    title=f"Intent-Behavior Mismatch: Policy {policy.id}",
                    description=(
                        f"Policy {policy.id} has restrictive naming/comments "
                        f"('{policy.comments or policy.name or ''}') but allows "
                        "any/any or very broad access. Intent does not match behavior."
                    ),
                    affected_policies=[policy.id],
                    remediation="Align policy scope with intended restrictions. Narrow source/destination/services.",
                    details={
                        "comment": policy.comments,
                        "name": policy.name,
                        "is_any_any": policy.is_overly_permissive,
                    },
                ))

        logger.info("Intent analysis: %d findings", len(findings))
        return findings
