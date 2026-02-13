"""Policy normalizer — converts parsed FortiGate policy dicts to canonical PolicyRule models."""

from __future__ import annotations

import logging
from typing import Any

from forticheck.models.canonical import (
    PolicyAction,
    PolicyRule,
    SecurityProfiles,
)
from forticheck.normalizer.resolver import ObjectResolver

logger = logging.getLogger(__name__)


class PolicyNormalizer:
    """Convert vendor-specific policy dicts to canonical PolicyRule instances."""

    def __init__(self, resolver: ObjectResolver) -> None:
        self.resolver = resolver

    def normalize_policies(self, raw_policies: list[dict[str, Any]]) -> list[PolicyRule]:
        """Convert a list of raw FortiGate policy dicts to PolicyRule models."""
        policies: list[PolicyRule] = []
        skip_count = 0
        for idx, raw in enumerate(raw_policies):
            try:
                policy = self._normalize_one(raw, idx)
                policies.append(policy)
            except Exception as e:
                pid = raw.get("__name__", idx)
                logger.warning("Failed to normalize policy %s: %s", pid, e)
                skip_count += 1
        if skip_count:
            logger.warning(
                "%d of %d policies could not be normalized (see above for details).",
                skip_count, len(raw_policies),
            )
        return policies

    def _normalize_one(self, raw: dict[str, Any], index: int) -> PolicyRule:
        """Normalize a single FortiGate policy dict."""
        pid = str(raw.get("__name__", index))

        # Source / destination zones (interfaces in FortiGate)
        src_zones = self._to_list(raw.get("srcintf", []))
        dst_zones = self._to_list(raw.get("dstintf", []))

        # Source / destination addresses
        src_addrs = self._to_list(raw.get("srcaddr", ["all"]))
        dst_addrs = self._to_list(raw.get("dstaddr", ["all"]))

        # Services
        services = self._to_list(raw.get("service", ["ALL"]))

        # Action
        action_str = str(raw.get("action", "deny")).lower()
        action_map = {
            "accept": PolicyAction.ACCEPT,
            "deny": PolicyAction.DENY,
            "drop": PolicyAction.DROP,
            "ipsec": PolicyAction.IPSEC,
        }
        action = action_map.get(action_str, PolicyAction.DENY)

        # Status
        status = str(raw.get("status", "enable")).lower()
        enabled = status == "enable"

        # NAT
        nat = str(raw.get("nat", "disable")).lower() == "enable"

        # Logging
        logtraffic = str(raw.get("logtraffic", "disable")).lower()
        log = logtraffic in ("all", "utm")

        # Security profiles
        profiles = SecurityProfiles(
            antivirus=raw.get("av-profile") or raw.get("antivirus-profile"),
            ips=raw.get("ips-sensor"),
            web_filter=raw.get("webfilter-profile"),
            app_control=raw.get("application-list"),
            ssl_inspection=raw.get("ssl-ssh-profile") or raw.get("deep-inspection"),
            dlp=raw.get("dlp-sensor") or raw.get("dlp-profile"),
            email_filter=raw.get("emailfilter-profile"),
            file_filter=raw.get("file-filter-profile"),
        )

        # Schedule
        schedule = str(raw.get("schedule", "always"))

        # Comments
        comments = str(raw.get("comments", ""))

        # Name (FortiGate 7.x+ has a name field)
        name = str(raw.get("name", ""))

        # Source / destination negate
        src_negate = str(raw.get("srcaddr-negate", "disable")).lower() == "enable"
        dst_negate = str(raw.get("dstaddr-negate", "disable")).lower() == "enable"

        # Resolve addresses and services
        resolved_src = self.resolver.resolve_address_names(src_addrs)
        resolved_dst = self.resolver.resolve_address_names(dst_addrs)
        resolved_svc = self.resolver.resolve_service_names(services)

        return PolicyRule(
            id=pid,
            sequence=index,
            name=name,
            enabled=enabled,
            source_zones=src_zones,
            destination_zones=dst_zones,
            source_addresses=src_addrs,
            destination_addresses=dst_addrs,
            source_addresses_negate=src_negate,
            destination_addresses_negate=dst_negate,
            services=services,
            action=action,
            nat=nat,
            log=log,
            security_profiles=profiles,
            schedule=schedule,
            comments=comments,
            resolved_src_cidrs=resolved_src,
            resolved_dst_cidrs=resolved_dst,
            resolved_services=resolved_svc,
        )

    @staticmethod
    def _to_list(val: Any) -> list[str]:
        """Ensure value is a list of strings."""
        if isinstance(val, list):
            return [str(v) for v in val]
        if isinstance(val, str):
            return [val]
        return []
