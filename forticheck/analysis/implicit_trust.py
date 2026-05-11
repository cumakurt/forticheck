"""Implicit Trust Engine — discovers hidden trust relationships.

Detects trust that is not explicitly modeled as firewall policy:
- Same-zone trust (traffic within a zone)
- VPN implicit access (split-tunnel, phase2 selectors)
- Management interface trust leakage
"""

from __future__ import annotations

import logging
from typing import Any

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)

MGMT_KEYWORDS = {"mgmt", "management", "admin", "ha-mgmt"}
VPN_SENSITIVE = {"RDP", "SMB", "SSH", "TELNET", "WINRM", "3389", "445", "22", "23"}


class ImplicitTrustEngine:
    """Detect implicit trust channels not visible in policy rules."""

    def analyze(
        self, graph: SecurityGraph, device: Device
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        """Analyze and return findings + raw data for reporting."""
        findings: list[Finding] = []
        raw_data: list[dict[str, Any]] = []

        # 1) Same-zone trust: zones with multiple interfaces = implicit L2/L3 trust
        for zone in device.all_zones:
            if len(zone.interfaces) >= 2:
                raw_data.append({
                    "type": "same_zone_trust",
                    "zone": zone.name,
                    "interfaces": zone.interfaces,
                    "trust_level": zone.trust_level,
                })
                findings.append(Finding(
                    id=f"IMPLICIT-SAMEZONE-{zone.name}",
                    category=FindingCategory.IMPLICIT_TRUST,
                    severity=Severity.LOW,
                    title=f"Same-Zone Implicit Trust: {zone.name}",
                    description=(
                        f"Zone '{zone.name}' contains {len(zone.interfaces)} interfaces. "
                        "Traffic between same-zone interfaces may bypass policy inspection."
                    ),
                    affected_zones=[zone.name],
                    remediation="Consider micro-segmentation within the zone or interface-level policies.",
                    details={"interfaces": zone.interfaces},
                ))

        # 2) Management interface trust leakage
        for iface in device.all_interfaces:
            name_lower = (iface.name or "").lower()
            if any(kw in name_lower for kw in MGMT_KEYWORDS):
                raw_data.append({
                    "type": "mgmt_trust",
                    "interface": iface.name,
                    "zone": iface.zone or "unassigned",
                })
                findings.append(Finding(
                    id=f"IMPLICIT-MGMT-{iface.name}",
                    category=FindingCategory.IMPLICIT_TRUST,
                    severity=Severity.MEDIUM,
                    title=f"Management Interface: {iface.name}",
                    description=(
                        f"Management interface '{iface.name}' is a privileged access point. "
                        "Compromise grants potential network access. Restrict to trusted hosts."
                    ),
                    remediation="Restrict management access to specific trusted hosts. Use MFA.",
                    details={"interface": iface.name, "zone": iface.zone},
                ))

        # 3) VPN implicit access (split-tunnel, broad phase2)
        for tunnel in device.all_vpn_tunnels:
            split_tunnel = getattr(tunnel, "split_tunnelling", False) or getattr(
                tunnel, "split_tunnel", False
            )
            raw_data.append({
                "type": "vpn_implicit",
                "tunnel": tunnel.name,
                "split_tunnel": split_tunnel,
            })
            if split_tunnel:
                findings.append(Finding(
                    id=f"IMPLICIT-VPN-{tunnel.name}",
                    category=FindingCategory.IMPLICIT_TRUST,
                    severity=Severity.HIGH,
                    title=f"VPN Split-Tunnel Implicit Access: {tunnel.name}",
                    description=(
                        f"VPN tunnel '{tunnel.name}' uses split-tunnel. "
                        "Clients can reach internal networks without firewall inspection."
                    ),
                    remediation="Disable split-tunnel or restrict VPN routes to required subnets only.",
                    details={"tunnel": tunnel.name},
                ))

        logger.info("Implicit trust analysis: %d findings", len(findings))
        return findings, raw_data
