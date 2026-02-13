"""Risk scoring — assigns composite risk scores to findings."""

from __future__ import annotations

import logging

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device, PolicyAction, ServiceSensitivity
from forticheck.models.findings import (
    AnalysisResult,
    Finding,
    FindingCategory,
    RiskScoreBreakdown,
    Severity,
)
from forticheck.normalizer.resolver import ObjectResolver

logger = logging.getLogger(__name__)


class RiskScorer:
    """Assign composite 0-100 risk scores to findings."""

    def __init__(self, graph: SecurityGraph, device: Device,
                 resolver: ObjectResolver) -> None:
        self.graph = graph
        self.device = device
        self.resolver = resolver
        self._policy_map = {p.id: p for p in device.all_policies}

    def score_findings(self, findings: list[Finding]) -> list[Finding]:
        """Score all findings and assign severity based on composite score."""
        for finding in findings:
            if finding.risk_score > 0:
                # Already scored (e.g., attack paths)
                continue

            breakdown = self._calculate_breakdown(finding)
            finding.risk_score = breakdown.calculate()
            finding.severity = breakdown.to_severity()
            finding.details["risk_breakdown"] = {
                "exposure": round(breakdown.exposure, 1),
                "trust_delta": round(breakdown.trust_delta, 1),
                "service_sensitivity": round(breakdown.service_sensitivity, 1),
                "permission_breadth": round(breakdown.permission_breadth, 1),
                "profile_gap": round(breakdown.profile_gap, 1),
                "composite": round(breakdown.composite, 1),
            }

        return findings

    def calculate_device_risk(self, findings: list[Finding]) -> float:
        """Calculate aggregate device risk score."""
        if not findings:
            return 0.0

        scores = [f.risk_score for f in findings]
        scores.sort(reverse=True)

        max_score = scores[0] if scores else 0
        top10_avg = sum(scores[:10]) / min(10, len(scores))

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        density = min(100, (critical_count * 5 + high_count * 3))

        device_risk = max_score * 0.4 + top10_avg * 0.3 + density * 0.3
        return min(100, device_risk)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _calculate_breakdown(self, finding: Finding) -> RiskScoreBreakdown:
        """Calculate the 5-factor risk breakdown for a finding."""
        breakdown = RiskScoreBreakdown()

        policy_ids = finding.affected_policies
        zones = finding.affected_zones

        # 1) Exposure
        breakdown.exposure = self._calc_exposure(finding, zones)

        # 2) Trust delta
        breakdown.trust_delta = self._calc_trust_delta(finding, zones)

        # 3) Service sensitivity
        breakdown.service_sensitivity = self._calc_service_sensitivity(finding, policy_ids)

        # 4) Permission breadth
        breakdown.permission_breadth = self._calc_permission_breadth(finding, policy_ids)

        # 5) Profile gap
        breakdown.profile_gap = self._calc_profile_gap(finding, policy_ids)

        return breakdown

    def _calc_exposure(self, finding: Finding, zones: list[str]) -> float:
        """Calculate exposure score based on category and zones."""
        category_scores = {
            FindingCategory.INTERNET_EXPOSURE: 90,
            FindingCategory.ANY_ANY_ANY: 100,
            FindingCategory.ATTACK_PATH: 80,
            FindingCategory.TRUST_VIOLATION: 60,
            FindingCategory.EAST_WEST_EXPOSURE: 50,
            FindingCategory.OVERLY_PERMISSIVE: 70,
            FindingCategory.SHADOW_RULE: 30,
            FindingCategory.REDUNDANT_RULE: 10,
            FindingCategory.DISABLED_RULE: 5,
            FindingCategory.MISSING_LOG: 15,
            FindingCategory.SECURITY_PROFILE_GAP: 40,
            FindingCategory.WIDE_SERVICE: 50,
            FindingCategory.STALE_OBJECT: 5,
            FindingCategory.POLICY_ORDERING: 10,
            FindingCategory.CUSTOM_RULE_VIOLATION: 60,
            # User & VPN
            FindingCategory.USER_NO_MFA: 95,
            FindingCategory.VPN_WEAK_CRYPTO: 90,
            FindingCategory.VPN_NO_PFS: 60,
            FindingCategory.USER_EXCESSIVE_PRIVILEGE: 40,
            FindingCategory.VPN_SPLIT_TUNNEL: 50,
            # Next-gen
            FindingCategory.IMPLICIT_TRUST: 60,
            FindingCategory.BLAST_RADIUS: 75,
            FindingCategory.SEGMENTATION_DRIFT: 85,
            FindingCategory.TRANSITIVE_ACCESS: 65,
            FindingCategory.BEHAVIOR_CHAIN: 50,
            FindingCategory.TRUST_BOUNDARY_MISMATCH: 70,
            FindingCategory.LATERAL_MOVEMENT: 80,
            FindingCategory.POLICY_COMPLEXITY: 25,
            FindingCategory.INTENT_BEHAVIOR_GAP: 70,
        }
        base = category_scores.get(finding.category, 30)

        # Adjust if involves Internet-facing zones
        for z in zones:
            if self.graph.get_trust_level(z) == 0:
                base = min(100, base + 20)
                break

        return float(base)

    def _calc_trust_delta(self, finding: Finding, zones: list[str]) -> float:
        """Calculate trust delta score."""
        if len(zones) < 2:
            details = finding.details
            return float(details.get("trust_delta", 0))

        trust_levels = [self.graph.get_trust_level(z) for z in zones[:2]]
        delta = abs(trust_levels[1] - trust_levels[0]) if len(trust_levels) >= 2 else 0
        return float(delta)

    def _calc_service_sensitivity(self, finding: Finding,
                                  policy_ids: list[str]) -> float:
        """Calculate service sensitivity score."""
        max_sensitivity = ServiceSensitivity.UNKNOWN
        order = {
            ServiceSensitivity.UNKNOWN: 0,
            ServiceSensitivity.LOW: 25,
            ServiceSensitivity.MEDIUM: 50,
            ServiceSensitivity.HIGH: 75,
            ServiceSensitivity.CRITICAL: 100,
        }

        for pid in policy_ids:
            policy = self._policy_map.get(pid)
            if policy:
                sens = self.resolver.get_service_sensitivity(policy.services)
                if order.get(sens, 0) > order.get(max_sensitivity, 0):
                    max_sensitivity = sens

        return float(order.get(max_sensitivity, 0))

    def _calc_permission_breadth(self, finding: Finding,
                                 policy_ids: list[str]) -> float:
        """Calculate permission breadth score."""
        max_breadth = 0.0

        for pid in policy_ids:
            policy = self._policy_map.get(pid)
            if not policy:
                continue

            src_score = 100.0 if policy.is_any_source else 30.0
            dst_score = 100.0 if policy.is_any_destination else 30.0
            svc_score = 100.0 if policy.is_any_service else 30.0

            breadth = (src_score + dst_score + svc_score) / 3
            max_breadth = max(max_breadth, breadth)

        return max_breadth

    def _calc_profile_gap(self, finding: Finding,
                          policy_ids: list[str]) -> float:
        """Calculate security profile gap score."""
        max_gap = 0.0

        for pid in policy_ids:
            policy = self._policy_map.get(pid)
            if not policy or policy.action != PolicyAction.ACCEPT:
                continue

            profiles = policy.security_profiles
            missing = len(profiles.missing_critical)
            total = profiles.total_expected
            gap = (missing / total) * 100 if total > 0 else 0
            max_gap = max(max_gap, gap)

        return max_gap
