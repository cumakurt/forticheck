"""Custom rules engine — user-defined YAML rules for policy/zone checks."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device
from forticheck.models.findings import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class CustomRulesEngine:
    """Evaluate user-defined rules from a YAML file against device/graph."""

    def __init__(self, rules_path: str | Path) -> None:
        self.rules_path = Path(rules_path)
        self.rules: list[dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_path.exists():
            logger.warning("Custom rules file not found: %s", self.rules_path)
            return
        try:
            with open(self.rules_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self.rules = data.get("rules", []) if isinstance(data, dict) else []
        except (yaml.YAMLError, OSError) as e:
            logger.warning("Could not load custom rules from %s: %s", self.rules_path, e)

    def analyze(
        self,
        device: Device,
        graph: SecurityGraph,
    ) -> list[Finding]:
        """Run all custom rules and return findings for violations."""
        findings: list[Finding] = []
        for rule in self.rules:
            rule_id = rule.get("id", "custom")
            rule_type = rule.get("type", "")
            severity_str = str(rule.get("severity", "medium")).lower()
            severity = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }.get(severity_str, Severity.MEDIUM)

            if rule_type == "forbid_service":
                findings.extend(self._check_forbid_service(device, rule, rule_id, severity))
            elif rule_type == "require_security_profile":
                findings.extend(self._check_require_security_profile(device, rule, rule_id, severity))
            else:
                logger.debug("Unknown custom rule type: %s", rule_type)
        logger.info("Custom rules: %d violations from %d rules", len(findings), len(self.rules))
        return findings

    def _check_forbid_service(
        self,
        device: Device,
        rule: dict[str, Any],
        rule_id: str,
        severity: Severity,
    ) -> list[Finding]:
        """Rule: no policy between given zones should allow given service."""
        findings: list[Finding] = []
        zones = rule.get("zones", [])
        if isinstance(zones, str):
            zones = [zones]
        service = rule.get("service", "")
        if not zones or not service:
            return findings
        service_upper = service.upper()
        for policy in device.all_policies:
            if not policy.enabled or policy.action.value != "accept":
                continue
            src_ok = not zones or any(z in policy.source_zones for z in zones)
            dst_ok = not zones or any(z in policy.destination_zones for z in zones)
            if not (src_ok and dst_ok):
                continue
            services = [s.upper() for s in policy.services]
            if service_upper in services or "ALL" in services:
                findings.append(Finding(
                    id=f"CUSTOM-{rule_id}-{policy.id}",
                    category=FindingCategory.CUSTOM_RULE_VIOLATION,
                    severity=severity,
                    title=f"Custom rule violation: {service} forbidden between zones",
                    description=(
                        f"Policy {policy.id} allows service '{service}' between "
                        f"{policy.source_zones} and {policy.destination_zones}, "
                        f"violating rule '{rule_id}'."
                    ),
                    affected_policies=[policy.id],
                    affected_zones=policy.source_zones + policy.destination_zones,
                    remediation=rule.get("remediation", f"Remove or restrict service {service} per custom rule."),
                    details={"rule_id": rule_id, "rule_type": "forbid_service", "service": service},
                ))
        return findings

    def _check_require_security_profile(
        self,
        device: Device,
        rule: dict[str, Any],
        rule_id: str,
        severity: Severity,
    ) -> list[Finding]:
        """Rule: policies between given zones must have security profiles."""
        findings: list[Finding] = []
        zones = rule.get("zones", [])
        if isinstance(zones, str):
            zones = [zones]
        for policy in device.all_policies:
            if not policy.enabled or policy.action.value != "accept":
                continue
            if policy.security_profiles.has_any:
                continue
            src_ok = not zones or any(z in policy.source_zones for z in zones)
            dst_ok = not zones or any(z in policy.destination_zones for z in zones)
            if src_ok and dst_ok:
                findings.append(Finding(
                    id=f"CUSTOM-{rule_id}-{policy.id}",
                    category=FindingCategory.CUSTOM_RULE_VIOLATION,
                    severity=severity,
                    title="Custom rule violation: security profile required",
                    description=(
                        f"Policy {policy.id} has no security profiles between "
                        f"{policy.source_zones} and {policy.destination_zones}, "
                        f"violating rule '{rule_id}'."
                    ),
                    affected_policies=[policy.id],
                    remediation=rule.get("remediation", "Apply security profiles (IPS, AV, etc.) per custom rule."),
                    details={"rule_id": rule_id, "rule_type": "require_security_profile"},
                ))
        return findings
