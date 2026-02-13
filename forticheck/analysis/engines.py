"""Trust boundary, exposure, and east-west analysis engines."""

from __future__ import annotations

import logging

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device, PolicyAction, PolicyRule, ServiceSensitivity
from forticheck.models.findings import Finding, FindingCategory, Severity
from forticheck.normalizer.resolver import ObjectResolver

logger = logging.getLogger(__name__)


class TrustBoundaryAnalyzer:
    """Analyze trust boundary violations — low-trust to high-trust access."""

    def analyze(self, graph: SecurityGraph) -> list[Finding]:
        findings: list[Finding] = []

        for src, dst, edges in graph.get_zone_pairs():
            src_trust = graph.get_trust_level(src)
            dst_trust = graph.get_trust_level(dst)
            trust_delta = dst_trust - src_trust

            if trust_delta <= 10:
                continue  # Normal or same-level

            for edge in edges:
                severity = Severity.INFO
                if trust_delta >= 70:
                    severity = Severity.CRITICAL
                elif trust_delta >= 50:
                    severity = Severity.HIGH
                elif trust_delta >= 30:
                    severity = Severity.MEDIUM

                is_any = edge.get("is_any_source") or edge.get("is_any_destination")
                if is_any:
                    severity = Severity.CRITICAL if trust_delta >= 50 else Severity.HIGH

                services_str = ", ".join(edge.get("services", []))
                policy_id = edge.get("policy_id", "?")

                finding = Finding(
                    id=f"TRUST-{policy_id}",
                    category=FindingCategory.TRUST_VIOLATION,
                    severity=severity,
                    title=f"Trust Boundary Violation: {src} → {dst}",
                    description=(
                        f"Policy {policy_id} allows traffic from {src} "
                        f"(trust={src_trust}) to {dst} (trust={dst_trust}). "
                        f"Trust delta: {trust_delta}. Services: {services_str}."
                    ),
                    affected_policies=[policy_id],
                    affected_zones=[src, dst],
                    remediation=(
                        f"Restrict access from {src} to {dst}. "
                        f"Apply security profiles (IPS, AV) and limit services."
                    ),
                    details={
                        "src_trust": src_trust,
                        "dst_trust": dst_trust,
                        "trust_delta": trust_delta,
                        "services": edge.get("services", []),
                        "has_security_profile": edge.get("has_security_profile", False),
                    },
                )
                findings.append(finding)

        logger.info("Trust boundary analysis: %d violations found", len(findings))
        return findings


class InternetExposureAnalyzer:
    """Detect internal resources exposed to the Internet."""

    def analyze(self, graph: SecurityGraph, device: Device) -> list[Finding]:
        findings: list[Finding] = []
        internet_nodes = graph.get_internet_nodes()

        for inet_node in internet_nodes:
            for edge_data in graph.get_outgoing_policies(inet_node):
                target = edge_data.get("target", "")
                target_trust = graph.get_trust_level(target)
                policy_id = edge_data.get("policy_id", "?")
                services = edge_data.get("services", [])
                has_profile = edge_data.get("has_security_profile", False)

                severity = Severity.HIGH
                if target_trust >= 70:
                    severity = Severity.CRITICAL
                if not has_profile:
                    severity = Severity.CRITICAL

                services_str = ", ".join(services)

                finding = Finding(
                    id=f"INET-EXPOSURE-{policy_id}",
                    category=FindingCategory.INTERNET_EXPOSURE,
                    severity=severity,
                    title=f"Internet Exposure: {target} via policy {policy_id}",
                    description=(
                        f"Zone '{target}' (trust={target_trust}) is accessible from "
                        f"the Internet via policy {policy_id}. "
                        f"Services: {services_str}. "
                        f"Security profiles: {'Yes' if has_profile else 'None'}."
                    ),
                    affected_policies=[policy_id],
                    affected_zones=[inet_node, target],
                    remediation=(
                        f"{'Apply IPS, AV, and WAF profiles to this policy. ' if not has_profile else ''}"
                        f"Verify that only required services are exposed. "
                        f"Consider moving the resource to a DMZ zone."
                    ),
                    details={
                        "target_zone": target,
                        "target_trust": target_trust,
                        "services": services,
                        "has_security_profile": has_profile,
                        "dst_addresses": edge_data.get("dst_addresses", []),
                    },
                )
                findings.append(finding)

        logger.info("Internet exposure: %d findings", len(findings))
        return findings


class EastWestAnalyzer:
    """Analyze lateral movement risk between internal zones."""

    # Sensitive services for lateral movement
    LATERAL_SERVICES = {"SMB", "RDP", "SSH", "WinRM", "TELNET", "VNC", "MS-SQL", "MYSQL"}

    def analyze(self, graph: SecurityGraph, device: Device,
                resolver: ObjectResolver) -> tuple[list[Finding], dict]:
        """Analyze east-west exposure.

        Returns findings and a zone exposure matrix.
        """
        findings: list[Finding] = []
        exposure_matrix: dict[str, dict[str, list[str]]] = {}

        internal_zones = [
            n for n in graph.get_all_zone_nodes()
            if graph.get_trust_level(n) >= 20  # Exclude Internet
        ]

        for src in internal_zones:
            src_trust = graph.get_trust_level(src)
            if src_trust == 0:
                continue

            exposure_matrix.setdefault(src, {})

            for dst in internal_zones:
                if src == dst:
                    continue
                dst_trust = graph.get_trust_level(dst)

                edges = graph.get_outgoing_policies(src)
                dst_edges = [e for e in edges if e.get("target") == dst]

                if not dst_edges:
                    continue

                all_services: list[str] = []
                policy_ids: list[str] = []
                for e in dst_edges:
                    all_services.extend(e.get("services", []))
                    policy_ids.append(e.get("policy_id", "?"))

                exposure_matrix[src][dst] = all_services

                # Check for sensitive lateral movement services
                lateral_hit = set(s.upper() for s in all_services) & self.LATERAL_SERVICES
                has_any_svc = any(e.get("is_any_service") for e in dst_edges)

                if lateral_hit or has_any_svc:
                    severity = Severity.HIGH
                    if dst_trust >= 80:
                        severity = Severity.CRITICAL

                    services_str = ", ".join(lateral_hit) if lateral_hit else "ALL"

                    finding = Finding(
                        id=f"EAST-WEST-{src}-{dst}",
                        category=FindingCategory.EAST_WEST_EXPOSURE,
                        severity=severity,
                        title=f"Lateral Movement Risk: {src} → {dst}",
                        description=(
                            f"Zone '{src}' can access zone '{dst}' via sensitive services: "
                            f"{services_str}. This enables lateral movement."
                        ),
                        affected_policies=policy_ids,
                        affected_zones=[src, dst],
                        remediation=(
                            f"Restrict access from {src} to {dst}. "
                            f"Remove {services_str} unless explicitly required. "
                            f"Implement micro-segmentation."
                        ),
                        details={
                            "lateral_services": list(lateral_hit),
                            "all_services": all_services,
                            "src_trust": src_trust,
                            "dst_trust": dst_trust,
                        },
                    )
                    findings.append(finding)

        logger.info("East-west analysis: %d findings", len(findings))
        return findings, exposure_matrix


class BasicPolicyAnalyzer:
    """Basic policy checks: any/any/any, disabled rules, profile gaps, logging."""

    def analyze(self, device: Device, resolver: ObjectResolver) -> list[Finding]:
        findings: list[Finding] = []
        policies = device.all_policies

        for policy in policies:
            # 1) Disabled rules
            if not policy.enabled:
                findings.append(Finding(
                    id=f"DISABLED-{policy.id}",
                    category=FindingCategory.DISABLED_RULE,
                    severity=Severity.INFO,
                    title=f"Disabled Rule: Policy {policy.id}",
                    description=f"Policy {policy.id} is disabled. Consider removing if no longer needed.",
                    affected_policies=[policy.id],
                    remediation="Remove disabled rules to reduce rule base clutter.",
                ))
                continue  # Skip further checks for disabled rules

            if policy.action != PolicyAction.ACCEPT:
                continue  # Only check allow rules

            # 2) Overly permissive (any/any/any)
            if policy.is_overly_permissive:
                findings.append(Finding(
                    id=f"ANY-ANY-ANY-{policy.id}",
                    category=FindingCategory.ANY_ANY_ANY,
                    severity=Severity.CRITICAL,
                    title=f"Any/Any/Any Rule: Policy {policy.id}",
                    description=(
                        f"Policy {policy.id} allows ANY source to ANY destination "
                        f"on ALL services. This is the highest security risk."
                    ),
                    affected_policies=[policy.id],
                    affected_zones=policy.source_zones + policy.destination_zones,
                    remediation=(
                        "Immediately restrict source, destination, and services. "
                        "No policy should use any/any/any in production."
                    ),
                ))
            else:
                # 2b) Partially permissive
                permissive_parts = []
                if policy.is_any_source:
                    permissive_parts.append("ANY source")
                if policy.is_any_destination:
                    permissive_parts.append("ANY destination")
                if policy.is_any_service:
                    permissive_parts.append("ALL services")

                if len(permissive_parts) >= 2:
                    findings.append(Finding(
                        id=f"OVERLY-PERMISSIVE-{policy.id}",
                        category=FindingCategory.OVERLY_PERMISSIVE,
                        severity=Severity.HIGH,
                        title=f"Overly Permissive Rule: Policy {policy.id}",
                        description=(
                            f"Policy {policy.id} uses {', '.join(permissive_parts)}. "
                            f"This creates unnecessary exposure."
                        ),
                        affected_policies=[policy.id],
                        remediation="Narrow down address and service scope.",
                    ))

            # 3) Security profile gap (for ACCEPT rules)
            if not policy.security_profiles.has_any:
                findings.append(Finding(
                    id=f"NO-PROFILE-{policy.id}",
                    category=FindingCategory.SECURITY_PROFILE_GAP,
                    severity=Severity.MEDIUM,
                    title=f"No Security Profiles: Policy {policy.id}",
                    description=(
                        f"Policy {policy.id} has no security inspection profiles "
                        f"(AV, IPS, Web Filter, SSL). Traffic is not inspected."
                    ),
                    affected_policies=[policy.id],
                    remediation=(
                        "Apply appropriate security profiles: antivirus, IPS sensor, "
                        "web filter, and SSL inspection."
                    ),
                    details={
                        "missing_profiles": policy.security_profiles.missing_critical,
                    },
                ))

            # 4) Missing logging
            if not policy.log:
                findings.append(Finding(
                    id=f"NO-LOG-{policy.id}",
                    category=FindingCategory.MISSING_LOG,
                    severity=Severity.LOW,
                    title=f"No Logging: Policy {policy.id}",
                    description=f"Policy {policy.id} does not log traffic. Forensic visibility is lost.",
                    affected_policies=[policy.id],
                    remediation="Enable 'set logtraffic all' for audit and forensic purposes.",
                ))

            # 5) Wide service range
            svc_sensitivity = resolver.get_service_sensitivity(policy.services)
            if svc_sensitivity == ServiceSensitivity.CRITICAL and not policy.is_any_service:
                # Check if sensitive services are exposed
                sensitive_svcs = [
                    s for s in policy.services
                    if resolver.service_objects.get(s, None)
                    and resolver.service_objects[s].sensitivity == ServiceSensitivity.CRITICAL
                ]
                if sensitive_svcs:
                    findings.append(Finding(
                        id=f"WIDE-SVC-{policy.id}",
                        category=FindingCategory.WIDE_SERVICE,
                        severity=Severity.MEDIUM,
                        title=f"Sensitive Services Exposed: Policy {policy.id}",
                        description=(
                            f"Policy {policy.id} exposes sensitive services: "
                            f"{', '.join(sensitive_svcs)}."
                        ),
                        affected_policies=[policy.id],
                        remediation="Restrict sensitive service access to specific source IP ranges.",
                    ))

        logger.info("Basic policy analysis: %d findings", len(findings))
        return findings
