"""Policy logic engine — determines subset/superset relationships between policies.

This is the foundation for shadow and redundancy detection.
Uses IP set comparison via netaddr for accurate CIDR overlap analysis.
"""

from __future__ import annotations

import logging
from enum import Enum

from netaddr import IPSet

from forticheck.models.canonical import PolicyRule

logger = logging.getLogger(__name__)


class PolicyRelation(str, Enum):
    """Relationship between two policies."""
    SUBSET = "subset"        # A ⊂ B (A is fully covered by B)
    SUPERSET = "superset"    # A ⊃ B (A fully covers B)
    EQUAL = "equal"          # A = B
    OVERLAP = "overlap"      # A ∩ B ≠ ∅ (partial overlap)
    DISJOINT = "disjoint"    # A ∩ B = ∅ (no overlap)


class PolicyLogicEngine:
    """Compares policies as traffic sets to determine logical relationships."""

    def compare(self, policy_a: PolicyRule, policy_b: PolicyRule) -> PolicyRelation:
        """Determine the relationship between two policies.

        A policy is modeled as: (src_ip_set × dst_ip_set × zone_pair × service_set)
        """
        # Zone pair must match for comparison to be relevant
        if not self._zones_overlap(policy_a, policy_b):
            return PolicyRelation.DISJOINT

        # Compare IP sets
        src_rel = self._compare_cidr_sets(
            policy_a.resolved_src_cidrs,
            policy_b.resolved_src_cidrs,
        )
        dst_rel = self._compare_cidr_sets(
            policy_a.resolved_dst_cidrs,
            policy_b.resolved_dst_cidrs,
        )
        svc_rel = self._compare_service_sets(
            policy_a.resolved_services,
            policy_b.resolved_services,
        )

        # If any dimension is disjoint, policies are disjoint
        if PolicyRelation.DISJOINT in (src_rel, dst_rel, svc_rel):
            return PolicyRelation.DISJOINT

        # If all dimensions are equal, policies are equal
        if all(r == PolicyRelation.EQUAL for r in (src_rel, dst_rel, svc_rel)):
            return PolicyRelation.EQUAL

        # If all dimensions are subset or equal → A ⊂ B
        if all(r in (PolicyRelation.SUBSET, PolicyRelation.EQUAL)
               for r in (src_rel, dst_rel, svc_rel)):
            return PolicyRelation.SUBSET

        # If all dimensions are superset or equal → A ⊃ B
        if all(r in (PolicyRelation.SUPERSET, PolicyRelation.EQUAL)
               for r in (src_rel, dst_rel, svc_rel)):
            return PolicyRelation.SUPERSET

        return PolicyRelation.OVERLAP

    def is_shadowed_by(self, candidate: PolicyRule, upper: PolicyRule) -> bool:
        """Check if candidate is shadowed (fully covered) by upper policy.

        candidate is shadowed if:
        - upper has higher priority (lower sequence)
        - candidate's traffic set is a subset of upper's traffic set
        """
        if upper.sequence >= candidate.sequence:
            return False

        relation = self.compare(candidate, upper)
        return relation in (PolicyRelation.SUBSET, PolicyRelation.EQUAL)

    def is_redundant_with(self, candidate: PolicyRule, other: PolicyRule) -> bool:
        """Check if candidate is redundant (removing it changes nothing).

        candidate is redundant if:
        - There's another rule (above or below) that covers the same traffic
        - Both have the same action
        """
        if candidate.action != other.action:
            return False

        relation = self.compare(candidate, other)
        return relation in (PolicyRelation.SUBSET, PolicyRelation.EQUAL)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _zones_overlap(a: PolicyRule, b: PolicyRule) -> bool:
        """Check if two policies can match the same zone pair."""
        src_overlap = (
            set(a.source_zones) & set(b.source_zones)
            or "any" in a.source_zones
            or "any" in b.source_zones
        )
        dst_overlap = (
            set(a.destination_zones) & set(b.destination_zones)
            or "any" in a.destination_zones
            or "any" in b.destination_zones
        )
        return bool(src_overlap and dst_overlap)

    @staticmethod
    def _compare_cidr_sets(cidrs_a: list[str], cidrs_b: list[str]) -> PolicyRelation:
        """Compare two sets of CIDRs."""
        if not cidrs_a and not cidrs_b:
            return PolicyRelation.EQUAL
        if not cidrs_a or not cidrs_b:
            return PolicyRelation.DISJOINT

        try:
            set_a = IPSet(cidrs_a)
            set_b = IPSet(cidrs_b)
        except Exception:
            # Fallback: treat as overlapping if we can't parse
            return PolicyRelation.OVERLAP

        if set_a == set_b:
            return PolicyRelation.EQUAL
        if set_a.issubset(set_b):
            return PolicyRelation.SUBSET
        if set_a.issuperset(set_b):
            return PolicyRelation.SUPERSET
        if set_a & set_b:
            return PolicyRelation.OVERLAP
        return PolicyRelation.DISJOINT

    @staticmethod
    def _compare_service_sets(svcs_a: list[str], svcs_b: list[str]) -> PolicyRelation:
        """Compare two sets of service port ranges."""
        ports_a = PolicyLogicEngine._expand_ports(svcs_a)
        ports_b = PolicyLogicEngine._expand_ports(svcs_b)

        if not ports_a and not ports_b:
            return PolicyRelation.EQUAL
        if not ports_a or not ports_b:
            return PolicyRelation.DISJOINT

        if ports_a == ports_b:
            return PolicyRelation.EQUAL
        if ports_a.issubset(ports_b):
            return PolicyRelation.SUBSET
        if ports_a.issuperset(ports_b):
            return PolicyRelation.SUPERSET
        if ports_a & ports_b:
            return PolicyRelation.OVERLAP
        return PolicyRelation.DISJOINT

    @staticmethod
    def _expand_ports(port_ranges: list[str]) -> set[int]:
        """Expand port range strings to a set of port numbers.

        For large ranges (>1000 ports), uses a sentinel representation.
        """
        ports: set[int] = set()
        for pr in port_ranges:
            if not pr:
                continue
            if "-" in pr:
                try:
                    lo, hi = pr.split("-", 1)
                    lo_int, hi_int = int(lo), int(hi)
                    if hi_int - lo_int > 10000:
                        # "ALL" ports — use sentinel
                        return set(range(1, 65536))
                    ports.update(range(lo_int, hi_int + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.add(int(pr))
                except ValueError:
                    pass
        return ports
