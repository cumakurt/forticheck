"""Tests for analysis engine edge cases."""

from forticheck.analysis.engines import EastWestAnalyzer
from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device, PolicyAction, PolicyRule, VDOM, Zone
from forticheck.normalizer.resolver import ObjectResolver


def test_east_west_detects_sensitive_resolved_service_ports() -> None:
    policy = PolicyRule(
        id="10",
        sequence=0,
        source_zones=["workstations"],
        destination_zones=["servers"],
        source_addresses=["all"],
        destination_addresses=["all"],
        services=["AdminServices"],
        action=PolicyAction.ACCEPT,
        resolved_src_cidrs=["0.0.0.0/0"],
        resolved_dst_cidrs=["10.0.0.0/24"],
        resolved_services=["3389"],
    )
    device = Device(
        hostname="fw",
        vdoms=[
            VDOM(
                name="root",
                zones=[
                    Zone(id="workstations", name="workstations", trust_level=60),
                    Zone(id="servers", name="servers", trust_level=80),
                ],
                policies=[policy],
            )
        ],
    )
    graph = SecurityGraph()
    graph.build_from_device(device, ObjectResolver())

    findings, matrix = EastWestAnalyzer().analyze(graph, device, ObjectResolver())

    assert len(findings) == 1
    assert findings[0].affected_policies == ["10"]
    assert "3389" in findings[0].details["lateral_services"]
    assert matrix["workstations"]["servers"] == ["AdminServices", "3389"]
