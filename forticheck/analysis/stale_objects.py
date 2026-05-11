"""Stale (unused) object detection — finds address and service objects not referenced by any policy."""

from __future__ import annotations

import logging
from typing import Any, Mapping

from forticheck.models.canonical import Device
from forticheck.models.findings import Finding, FindingCategory, Severity
from forticheck.normalizer.resolver import BUILTIN_SERVICE_DEFINITIONS

logger = logging.getLogger(__name__)

# Built-in names that are always "used" by definition
SKIP_OBJECT_NAMES = frozenset({"all", "ALL"})
SKIP_SERVICE_NAMES = SKIP_OBJECT_NAMES | frozenset(BUILTIN_SERVICE_DEFINITIONS)


class StaleObjectAnalyzer:
    """Detect address and service objects that are defined but never used in any policy."""

    def analyze(self, device: Device) -> list[Finding]:
        """Find unused network and service objects."""
        findings: list[Finding] = []

        used_addrs: set[str] = set()
        used_services: set[str] = set()
        for policy in device.all_policies:
            for a in policy.source_addresses + policy.destination_addresses:
                if a and a not in SKIP_OBJECT_NAMES:
                    used_addrs.add(a)
            for s in policy.services:
                if s and s not in SKIP_SERVICE_NAMES:
                    used_services.add(s)

        network_map = {obj.name: obj for obj in device.all_network_objects}
        service_map = {obj.name: obj for obj in device.all_service_objects}
        for name in list(used_addrs):
            self._mark_group_members(name, network_map, used_addrs, set())
        for name in list(used_services):
            self._mark_group_members(name, service_map, used_services, set())

        # Unused address objects
        for obj in device.all_network_objects:
            if obj.name in SKIP_OBJECT_NAMES:
                continue
            if obj.name not in used_addrs:
                findings.append(Finding(
                    id=f"STALE-ADDR-{obj.name}",
                    category=FindingCategory.STALE_OBJECT,
                    severity=Severity.INFO,
                    title=f"Unused Address Object: {obj.name}",
                    description=(
                        f"Address object '{obj.name}' is defined but not referenced by any "
                        "firewall policy. Consider removing it to reduce clutter."
                    ),
                    remediation="Remove unused address objects from the configuration.",
                    details={"object_type": "address", "object_name": obj.name},
                ))

        # Unused service objects (per VDOM we have device.all_service_objects)
        for obj in device.all_service_objects:
            if obj.name in SKIP_SERVICE_NAMES:
                continue
            if obj.name not in used_services:
                findings.append(Finding(
                    id=f"STALE-SVC-{obj.name}",
                    category=FindingCategory.STALE_OBJECT,
                    severity=Severity.INFO,
                    title=f"Unused Service Object: {obj.name}",
                    description=(
                        f"Service object '{obj.name}' is defined but not referenced by any "
                        "firewall policy. Consider removing it."
                    ),
                    remediation="Remove unused service objects from the configuration.",
                    details={"object_type": "service", "object_name": obj.name},
                ))

        logger.info("Stale object analysis: %d unused objects found", len(findings))
        return findings

    @staticmethod
    def _mark_group_members(
        name: str,
        objects: Mapping[str, Any],
        used: set[str],
        visited: set[str],
    ) -> None:
        """Treat members of referenced groups as used too."""
        if name in visited:
            return
        visited.add(name)

        obj = objects.get(name)
        if not obj:
            return

        for member_name in getattr(obj, "members", []):
            if not member_name:
                continue
            used.add(member_name)
            StaleObjectAnalyzer._mark_group_members(member_name, objects, used, visited)
