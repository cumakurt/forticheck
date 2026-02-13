"""CIS Benchmark Compliance Analyzer."""

from __future__ import annotations

import logging
from typing import Any

from forticheck.models.findings import Finding, FindingCategory, Severity
from forticheck.parsers.fortigate import FortiGateParser

logger = logging.getLogger(__name__)


class CisAnalyzer:
    """Check configuration against CIS Benchmarks for FortiGate."""

    def analyze(self, parser: FortiGateParser) -> tuple[list[Finding], float]:
        """Run CIS compliance checks.

        Returns:
            List of findings and a CIS compliance score (0-100).
        """
        findings: list[Finding] = []
        total_checks = 0
        passed_checks = 0
        total_weight = 0
        passed_weight = 0

        # Helper to record result (weight: 1=low, 2=medium, 3=high importance for score)
        def check(
            condition: bool,
            title: str,
            description: str,
            severity: Severity = Severity.MEDIUM,
            remediation: str = "Apply the recommended configuration per CIS FortiGate benchmark. Review vendor documentation for exact CLI commands.",
            weight: int = 1,
        ) -> None:
            nonlocal total_checks, passed_checks, total_weight, passed_weight
            total_checks += 1
            total_weight += weight
            if condition:
                passed_checks += 1
                passed_weight += weight
            else:
                findings.append(Finding(
                    id=f"CIS-{total_checks:02d}",
                    category=FindingCategory.CIS_BENCHMARK,
                    severity=severity,
                    title=f"CIS: {title}",
                    description=description,
                    remediation=remediation,
                    risk_score=50.0 if severity == Severity.MEDIUM else 80.0,
                ))

        # 1. System Global Settings
        sys_global = parser.get_section("system global") or {}

        # 1.1 Hostname
        hostname = sys_global.get("hostname", "")
        check(
            bool(hostname and hostname != "FortiGate"),
            "System Hostname Set",
            (
                f"Hostname is currently '{hostname}'. CIS recommends setting a unique, "
                "descriptive hostname for device identification in log aggregation and "
                "management systems. Default 'FortiGate' facilitates reconnaissance."
            ),
            Severity.LOW,
            "Execute: config system global -> set hostname <unique-name>",
        )

        # 1.2 Admin Timeout
        idle_timeout = sys_global.get("admintimeout")
        timeout_val = int(idle_timeout) if idle_timeout is not None else 5
        check(
            timeout_val <= 10,
            "Admin Idle Timeout",
            (
                f"Admin idle timeout is {timeout_val} minutes. CIS benchmark requires "
                "10 minutes or less to prevent unauthorized session persistence when "
                "administrators leave workstations unattended."
            ),
            Severity.MEDIUM,
            "Execute: config system global -> set admintimeout 10",
            weight=2,
        )

        # 1.3 Admin HTTP Port
        admin_port = sys_global.get("admin-port", "80")
        check(
            admin_port != "80",
            "Change Default Admin HTTP Port",
            (
                f"Administrative HTTP service uses default port {admin_port}. "
                "Using non-standard ports reduces exposure to automated attacks "
                "and port scanners. Consider HTTPS on a custom port or disable HTTP."
            ),
            Severity.LOW,
            "Execute: config system global -> set admin-port <custom-port> or disable HTTP in interface allowaccess",
        )

        # 1.4 Timezone
        timezone = sys_global.get("timezone")
        check(
            timezone is not None,
            "System Timezone Configured",
            (
                "System timezone is not explicitly configured. Accurate timestamps "
                "are critical for log correlation, forensics, and compliance audits."
            ),
            Severity.LOW,
            "Execute: config system global -> set timezone <tz-id> (e.g. 75 for UTC)",
        )

        # 2. DNS
        sys_dns = parser.get_section("system dns") or {}
        primary = sys_dns.get("primary")
        check(
            bool(primary and primary != "0.0.0.0"),
            "DNS Configuration",
            (
                "Primary DNS server is not configured or uses invalid address. "
                "DNS resolution is required for FortiGuard updates, FQDN objects, "
                "and certificate validation. Configure internal DNS forwarder."
            ),
            Severity.HIGH,
            "Execute: config system dns -> set primary <dns-ip>",
            weight=3,
        )

        # 3. NTP
        sys_ntp = parser.get_section("system ntp") or {}
        ntpsync = sys_ntp.get("ntpsync")
        check(
            ntpsync == "enable",
            "NTP Synchronization",
            (
                "NTP synchronization is disabled. Clock drift impacts certificate "
                "validation, log timestamps, and security event correlation. Enable "
                "NTP and use authenticated time sources."
            ),
            Severity.MEDIUM,
            "Execute: config system ntp -> set ntpsync enable, add NTP servers",
            weight=2,
        )

        # 4. Banners
        pre_banner = sys_global.get("pre-login-banner", "disable")
        check(
            pre_banner == "enable",
            "Pre-Login Banner",
            (
                "Pre-login warning banner is disabled. Legal banners inform users "
                "of monitoring and acceptable use. Required for compliance with "
                "regulatory frameworks (e.g., PCI-DSS, ISO 27001)."
            ),
            Severity.LOW,
            "Execute: config system global -> set pre-login-banner enable",
        )

        # 5. Interface Access (Telnet/HTTP)
        interfaces = parser.get_system_interfaces()
        insecure_ifaces = []
        for iface in interfaces:
            allow = iface.get("allowaccess", "")
            if isinstance(allow, list):
                allow = " ".join(allow)

            if "telnet" in allow or "http" in allow:
                insecure_ifaces.append(iface.get("name", "unknown"))

        check(
            len(insecure_ifaces) == 0,
            "Disable Insecure Admin Access",
            (
                f"Telnet or unencrypted HTTP admin access is enabled on: "
                f"{', '.join(insecure_ifaces)}. These protocols transmit credentials "
                "in plaintext. Use SSH for CLI and HTTPS for web management only."
            ),
            Severity.HIGH,
            "For each interface: config system interface -> edit <name> -> set allowaccess ssh https (remove telnet http)",
            weight=3,
        )

        # Weighted score: high-importance checks count more
        score = (passed_weight / total_weight * 100.0) if total_weight > 0 else 0.0
        logger.info(
            "CIS Analysis: %d/%d passed (weighted score: %.1f)",
            passed_checks, total_checks, score,
        )

        return findings, score
