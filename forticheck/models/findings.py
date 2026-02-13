"""Finding and risk models."""

from __future__ import annotations

from enum import Enum
from typing import ClassVar, Optional

from pydantic import BaseModel, Field


class FindingCategory(str, Enum):
    SHADOW_RULE = "shadow_rule"
    REDUNDANT_RULE = "redundant_rule"
    OVERLY_PERMISSIVE = "overly_permissive"
    ANY_ANY_ANY = "any_any_any"
    SECURITY_PROFILE_GAP = "security_profile_gap"
    DISABLED_RULE = "disabled_rule"
    INTERNET_EXPOSURE = "internet_exposure"
    EAST_WEST_EXPOSURE = "east_west_exposure"
    TRUST_VIOLATION = "trust_violation"
    ATTACK_PATH = "attack_path"
    SEGMENTATION_GAP = "segmentation_gap"
    WIDE_SERVICE = "wide_service"
    STALE_RULE = "stale_rule"
    CONFLICTING_RULES = "conflicting_rules"
    MISSING_LOG = "missing_log"
    STALE_OBJECT = "stale_object"
    POLICY_ORDERING = "policy_ordering"
    CUSTOM_RULE_VIOLATION = "custom_rule_violation"
    # User & VPN categories
    USER_NO_MFA = "user_no_mfa"
    USER_DISABLED = "user_disabled"
    USER_EXCESSIVE_PRIVILEGE = "user_excessive_privilege"
    VPN_WEAK_CRYPTO = "vpn_weak_crypto"
    VPN_NO_PFS = "vpn_no_pfs"
    VPN_SPLIT_TUNNEL = "vpn_split_tunnel"
    # Compliance
    CIS_BENCHMARK = "cis_benchmark"
    # Next-gen: Security Intent & Behavior
    IMPLICIT_TRUST = "implicit_trust"
    BLAST_RADIUS = "blast_radius"
    SEGMENTATION_DRIFT = "segmentation_drift"
    TRANSITIVE_ACCESS = "transitive_access"
    BEHAVIOR_CHAIN = "behavior_chain"
    TRUST_BOUNDARY_MISMATCH = "trust_boundary_mismatch"
    LATERAL_MOVEMENT = "lateral_movement"
    POLICY_COMPLEXITY = "policy_complexity"
    INTENT_BEHAVIOR_GAP = "intent_behavior_gap"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single security finding produced by an analysis engine."""

    id: str
    category: FindingCategory
    severity: Severity = Severity.INFO
    title: str
    description: str
    affected_policies: list[str] = Field(default_factory=list)  # policy IDs
    affected_zones: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    remediation: str = ""
    details: dict = Field(default_factory=dict)  # engine-specific extra data


class RiskScoreBreakdown(BaseModel):
    """Breakdown of the 5-factor composite risk score."""

    exposure: float = 0.0       # 0-100
    trust_delta: float = 0.0    # 0-100
    service_sensitivity: float = 0.0  # 0-100
    permission_breadth: float = 0.0   # 0-100
    profile_gap: float = 0.0    # 0-100
    composite: float = 0.0      # 0-100 weighted

    WEIGHTS: ClassVar[dict[str, float]] = {
        "exposure": 0.30,
        "trust_delta": 0.25,
        "service_sensitivity": 0.20,
        "permission_breadth": 0.15,
        "profile_gap": 0.10,
    }

    def calculate(self) -> float:
        self.composite = (
            self.exposure * self.WEIGHTS["exposure"]
            + self.trust_delta * self.WEIGHTS["trust_delta"]
            + self.service_sensitivity * self.WEIGHTS["service_sensitivity"]
            + self.permission_breadth * self.WEIGHTS["permission_breadth"]
            + self.profile_gap * self.WEIGHTS["profile_gap"]
        )
        return self.composite

    def to_severity(self) -> Severity:
        if self.composite >= 85:
            return Severity.CRITICAL
        elif self.composite >= 70:
            return Severity.HIGH
        elif self.composite >= 50:
            return Severity.MEDIUM
        elif self.composite >= 25:
            return Severity.LOW
        return Severity.INFO


class AttackPathHop(BaseModel):
    """A single hop in an attack path."""

    source_zone: str
    source_network: str
    destination_zone: str
    destination_network: str
    policy_id: str
    services: list[str] = Field(default_factory=list)
    trust_delta: float = 0.0


class AttackPath(BaseModel):
    """A multi-hop attack chain through the network."""

    id: str
    hops: list[AttackPathHop] = Field(default_factory=list)
    total_trust_gain: float = 0.0
    risk_score: float = 0.0
    start_zone: str = ""
    end_zone: str = ""
    is_internet_originating: bool = False

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def description(self) -> str:
        if not self.hops:
            return "Empty path"
        zones = [self.hops[0].source_zone]
        for hop in self.hops:
            zones.append(hop.destination_zone)
        return " → ".join(zones)


class AnalysisResult(BaseModel):
    """Complete analysis result for a device."""

    device_hostname: str = ""
    device_vendor: str = ""
    firmware_version: str = ""
    analysis_timestamp: str = ""
    total_policies: int = 0
    total_interfaces: int = 0
    total_zones: int = 0
    total_routes: int = 0
    total_users: int = 0
    total_vpn_tunnels: int = 0
    findings: list[Finding] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    zone_exposure_matrix: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    device_risk_score: float = 0.0
    # User & VPN data for reporting
    users: list[dict] = Field(default_factory=list)
    user_groups: list[dict] = Field(default_factory=list)
    vpn_tunnels: list[dict] = Field(default_factory=list)
    admin_users: list[dict] = Field(default_factory=list)
    cis_score: float = 0.0
    # Infrastructure overview for report
    interfaces: list[dict] = Field(default_factory=list)
    zones: list[dict] = Field(default_factory=list)
    # Next-gen analysis outputs
    blast_radius_map: dict[str, dict] = Field(default_factory=dict)  # zone -> {reachable_count, sensitive_services, ...}
    transitive_access_pairs: list[dict] = Field(default_factory=list)
    segmentation_effectiveness: float = 0.0
    lateral_movement_scores: dict[str, float] = Field(default_factory=dict)
    implicit_trust_findings: list[dict] = Field(default_factory=list)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def info_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.INFO]

    @property
    def findings_by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.category.value, []).append(f)
        return result
