"""Trust Boundary Mismatch Engine — Prod/Dev/Mgmt boundary violations.

Detects when policies violate expected trust boundaries (e.g. Dev->Prod, Guest->Internal).
"""

from __future__ import annotations

import logging

from forticheck.graph.builder import SecurityGraph
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)

# Zone name patterns -> role
PROD_PATTERNS = ["prod", "production", "live", "internal", "lan", "servers", "dc", "ad"]
DEV_PATTERNS = ["dev", "development", "test", "staging", "lab"]
MGMT_PATTERNS = ["mgmt", "management", "admin", "ha"]
GUEST_PATTERNS = ["guest", "wifi", "public", "dmz"]


def _zone_role(name: str) -> str:
    """Infer zone role from name."""
    n = name.lower()
    if any(p in n for p in PROD_PATTERNS):
        return "prod"
    if any(p in n for p in DEV_PATTERNS):
        return "dev"
    if any(p in n for p in MGMT_PATTERNS):
        return "mgmt"
    if any(p in n for p in GUEST_PATTERNS):
        return "guest"
    return "other"


# Invalid (src_role, dst_role) combinations
VIOLATIONS = {
    ("dev", "prod"),
    ("guest", "prod"),
    ("guest", "dev"),
    ("guest", "mgmt"),
    ("other", "prod"),  # untagged zone to prod is suspicious
}


class TrustBoundaryMismatchEngine:
    """Detect policy flows that violate expected trust boundaries."""

    def analyze(
        self,
        graph: SecurityGraph,
        exposure_matrix: dict[str, dict[str, list[str]]],
    ) -> list[Finding]:
        """Find zone pairs that violate Prod/Dev/Mgmt/Guest boundaries."""
        findings: list[Finding] = []

        for src, dst_data in exposure_matrix.items():
            src_role = _zone_role(src)
            for dst, services in dst_data.items():
                if not services:
                    continue
                dst_role = _zone_role(dst)
                pair = (src_role, dst_role)
                if pair in VIOLATIONS:
                    findings.append(Finding(
                        id=f"TRUST-MISMATCH-{src}-{dst}",
                        category=FindingCategory.TRUST_BOUNDARY_MISMATCH,
                        severity=Severity.HIGH if pair in {("dev", "prod"), ("guest", "prod")} else Severity.MEDIUM,
                        title=f"Trust Boundary Violation: {src} → {dst}",
                        description=(
                            f"Policy allows {src_role} zone '{src}' to access "
                            f"{dst_role} zone '{dst}'. "
                            f"This violates expected boundaries."
                        ),
                        affected_zones=[src, dst],
                        remediation="Review if this access is required. Apply stricter segmentation.",
                        details={"src_role": src_role, "dst_role": dst_role},
                    ))

        logger.info("Trust boundary mismatch: %d findings", len(findings))
        return findings
