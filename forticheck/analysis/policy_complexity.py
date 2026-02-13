"""Policy Complexity Engine — overlap, reuse, sprawl risk.

Config complexity as a security risk.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from forticheck.models.canonical import Device, PolicyAction, PolicyRule
from forticheck.models.findings import Finding, FindingCategory, Severity
from forticheck.normalizer.resolver import ObjectResolver

logger = logging.getLogger(__name__)


class PolicyComplexityEngine:
    """Analyze policy overlap, object reuse, and sprawl."""

    def analyze(
        self,
        device: Device,
        resolver: ObjectResolver,
    ) -> list[Finding]:
        """Detect complexity risks."""
        findings: list[Finding] = []
        policies = [p for p in device.all_policies if p.action == PolicyAction.ACCEPT and p.enabled]

        # 1) Object reuse: address/service groups used in many policies
        addr_use: dict[str, list[str]] = defaultdict(list)
        svc_use: dict[str, list[str]] = defaultdict(list)
        for p in policies:
            for a in p.source_addresses + p.destination_addresses:
                if a and a.lower() != "all":
                    addr_use[a].append(p.id)
            for s in p.services:
                if s and s.upper() != "ALL":
                    svc_use[s].append(p.id)

        for obj, policy_ids in addr_use.items():
            if len(policy_ids) >= 15:
                findings.append(Finding(
                    id=f"COMPLEX-REUSE-ADDR-{obj}",
                    category=FindingCategory.POLICY_COMPLEXITY,
                    severity=Severity.MEDIUM,
                    title=f"High Reuse: Address Object '{obj}'",
                    description=(
                        f"Address object '{obj}' is used in {len(policy_ids)} policies. "
                        "Changes propagate widely. Operational risk."
                    ),
                    affected_policies=policy_ids[:10],
                    remediation="Consider splitting into smaller groups. Document impact of changes.",
                    details={"policy_count": len(policy_ids)},
                ))

        for obj, policy_ids in svc_use.items():
            if len(policy_ids) >= 20:
                findings.append(Finding(
                    id=f"COMPLEX-REUSE-SVC-{obj}",
                    category=FindingCategory.POLICY_COMPLEXITY,
                    severity=Severity.LOW,
                    title=f"High Reuse: Service Object '{obj}'",
                    description=f"Service '{obj}' used in {len(policy_ids)} policies.",
                    affected_policies=policy_ids[:10],
                    details={"policy_count": len(policy_ids)},
                ))

        # 2) Policy sprawl heuristic: many policies for similar zone pairs
        pair_count: dict[tuple[str, str], int] = defaultdict(int)
        for p in policies:
            for sz in p.source_zones:
                for dz in p.destination_zones:
                    pair_count[(sz, dz)] += 1

        for (sz, dz), count in pair_count.items():
            if count >= 10:
                findings.append(Finding(
                    id=f"COMPLEX-SPRAWL-{sz}-{dz}",
                    category=FindingCategory.POLICY_COMPLEXITY,
                    severity=Severity.LOW,
                    title=f"Policy Sprawl: {sz} → {dz}",
                    description=(
                        f"{count} policies exist for {sz} → {dz}. "
                        "Consider consolidating or using groups."
                    ),
                    remediation="Consolidate policies. Use address/service groups.",
                    details={"policy_count": count},
                ))

        logger.info("Policy complexity: %d findings", len(findings))
        return findings
