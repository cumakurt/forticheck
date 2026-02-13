"""Config diff — compare two FortiGate configurations (policy add/remove/change)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from forticheck.models.canonical import Device, PolicyRule

logger = logging.getLogger(__name__)


@dataclass
class PolicyDiff:
    """Single policy change (added, removed, or modified)."""
    policy_id: str
    change_type: str  # "added" | "removed" | "changed"
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    changed_fields: list[str] = field(default_factory=list)


@dataclass
class ConfigDiffResult:
    """Result of comparing two configurations."""
    before_hostname: str = ""
    after_hostname: str = ""
    added: list[PolicyDiff] = field(default_factory=list)
    removed: list[PolicyDiff] = field(default_factory=list)
    changed: list[PolicyDiff] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)


def _policy_snapshot(p: PolicyRule) -> dict[str, Any]:
    """Minimal comparable snapshot of a policy (for change detection)."""
    return {
        "id": p.id,
        "source_zones": sorted(p.source_zones),
        "destination_zones": sorted(p.destination_zones),
        "source_addresses": sorted(p.source_addresses),
        "destination_addresses": sorted(p.destination_addresses),
        "services": sorted(p.services),
        "action": p.action.value,
        "enabled": p.enabled,
        "nat": p.nat,
        "log": p.log,
    }


def diff_devices(before: Device, after: Device) -> ConfigDiffResult:
    """Compare two devices (policy sets). Returns added, removed, and changed policies."""
    result = ConfigDiffResult(
        before_hostname=before.hostname,
        after_hostname=after.hostname,
    )
    before_map = {p.id: p for p in before.all_policies}
    after_map = {p.id: p for p in after.all_policies}

    all_ids = set(before_map) | set(after_map)
    for pid in all_ids:
        b = before_map.get(pid)
        a = after_map.get(pid)
        if b is None and a is not None:
            result.added.append(PolicyDiff(
                policy_id=pid,
                change_type="added",
                after=_policy_snapshot(a),
            ))
        elif b is not None and a is None:
            result.removed.append(PolicyDiff(
                policy_id=pid,
                change_type="removed",
                before=_policy_snapshot(b),
            ))
        elif b is not None and a is not None:
            snap_b = _policy_snapshot(b)
            snap_a = _policy_snapshot(a)
            changes = [k for k in snap_b if k != "id" and snap_b.get(k) != snap_a.get(k)]
            if changes:
                result.changed.append(PolicyDiff(
                    policy_id=pid,
                    change_type="changed",
                    before=snap_b,
                    after=snap_a,
                    changed_fields=changes,
                ))

    logger.info(
        "Config diff: %d added, %d removed, %d changed",
        len(result.added), len(result.removed), len(result.changed),
    )
    return result
