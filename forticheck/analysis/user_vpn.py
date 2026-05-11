"""User and VPN analysis engine."""

from __future__ import annotations

import logging

from forticheck.models.canonical import Device, UserRole, UserType
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class UserVpnAnalyzer:
    """Analyze user configurations and VPN tunnels for security risks."""

    def analyze(self, device: Device) -> list[Finding]:
        findings: list[Finding] = []

        # 1. User Analysis
        for user in device.all_users:
            # Check MFA for Admins
            if user.role == UserRole.ADMIN and user.is_active:
                if not user.two_factor:
                    findings.append(Finding(
                        id=f"ADMIN-NO-MFA-{user.name}",
                        category=FindingCategory.USER_NO_MFA,
                        severity=Severity.CRITICAL,
                        title=f"Admin User without MFA: {user.name}",
                        description=(
                            f"Administrator '{user.name}' does not have Two-Factor "
                            f"Authentication (MFA) enabled. This is a critical risk."
                        ),
                        remediation="Enable FortiToken or other MFA method immediately.",
                        details={"user": user.name, "type": user.type},
                        risk_score=95.0,  # Explicit high risk
                    ))

            # Default password policy check (basic heuristic)
            if user.type == UserType.LOCAL and not user.password_policy:
                findings.append(Finding(
                    id=f"USER-NO-PWD-POLICY-{user.name}",
                    category=FindingCategory.USER_EXCESSIVE_PRIVILEGE,
                    severity=Severity.LOW,
                    title=f"Local User without Password Policy: {user.name}",
                    description=f"Local user '{user.name}' has no assigned password policy.",
                    remediation="Assign a strong password policy to all local users.",
                    risk_score=30.0,
                ))

        # 2. VPN Tunnel Analysis
        for tunnel in device.all_vpn_tunnels:
            # Weak Crypto
            if tunnel.has_weak_crypto:
                findings.append(Finding(
                    id=f"VPN-WEAK-CRYPTO-{tunnel.name}",
                    category=FindingCategory.VPN_WEAK_CRYPTO,
                    severity=Severity.HIGH,
                    title=f"Weak VPN Encryption/Hash: {tunnel.name}",
                    description=(
                        f"VPN tunnel '{tunnel.name}' uses weak algorithms "
                        f"(DES, 3DES, MD5, or NULL). Traffic can be decrypted."
                    ),
                    remediation="Use AES-256 and SHA-256 or higher.",
                    details={
                        "p1_enc": tunnel.phase1_encryption,
                        "p1_hash": tunnel.phase1_hash,
                        "p2_enc": tunnel.phase2_encryption,
                        "p2_hash": tunnel.phase2_hash,
                    },
                    risk_score=90.0,
                ))

            # No PFS
            if not tunnel.has_pfs and not tunnel.is_dialup:
                findings.append(Finding(
                    id=f"VPN-NO-PFS-{tunnel.name}",
                    category=FindingCategory.VPN_NO_PFS,
                    severity=Severity.MEDIUM,
                    title=f"No Perfect Forward Secrecy (PFS): {tunnel.name}",
                    description=(
                        f"VPN tunnel '{tunnel.name}' does not use Perfect Forward Secrecy "
                        "in Phase 2. Key compromise allows decrypting past traffic."
                    ),
                    remediation="Enable PFS (Diffie-Hellman groups 14, 19, 20, 21).",
                    risk_score=60.0,
                ))

            # IKEv1 Warning
            if tunnel.ike_version == "1":
                findings.append(Finding(
                    id=f"VPN-IKEv1-{tunnel.name}",
                    category=FindingCategory.VPN_WEAK_CRYPTO,
                    severity=Severity.LOW,
                    title=f"Legacy IKEv1 Protocol: {tunnel.name}",
                    description=f"Tunnel '{tunnel.name}' uses IKEv1. IKEv2 is more secure and efficient.",
                    remediation="Upgrade tunnel to use IKEv2 if supported by peer.",
                    risk_score=40.0,
                ))

        logger.info("User/VPN analysis: %d findings", len(findings))
        return findings

    def get_stats(self, device: Device) -> dict:
        """Collect reporting stats."""
        # Clean user objects for JSON report
        user_list = [u.model_dump(mode="json") for u in device.all_users]
        group_list = [g.model_dump(mode="json") for g in device.all_user_groups]
        tunnel_list = []
        for tunnel in device.all_vpn_tunnels:
            tunnel_data = tunnel.model_dump(mode="json")
            tunnel_data.update({
                "has_weak_crypto": tunnel.has_weak_crypto,
                "has_pfs": tunnel.has_pfs,
                "is_dialup": tunnel.is_dialup,
            })
            tunnel_list.append(tunnel_data)
        admin_list = [u for u in user_list if u.get("role") == "admin"]

        return {
            "users": user_list,
            "groups": group_list,
            "tunnels": tunnel_list,
            "admins": admin_list,
        }
