"""Tests for shadow and redundancy detectors."""

from forticheck.analysis.shadow import RedundancyDetector, ShadowDetector
from forticheck.models.canonical import PolicyAction, PolicyRule


def _policy(
    pid: str,
    seq: int,
    src_cidrs: list[str] | None = None,
    dst_cidrs: list[str] | None = None,
    services: list[str] | None = None,
) -> PolicyRule:
    return PolicyRule(
        id=pid,
        sequence=seq,
        source_zones=["wan"],
        destination_zones=["lan"],
        source_addresses=["all"],
        destination_addresses=["all"],
        services=services or ["ALL"],
        action=PolicyAction.ACCEPT,
        enabled=True,
        resolved_src_cidrs=src_cidrs or ["0.0.0.0/0"],
        resolved_dst_cidrs=dst_cidrs or ["0.0.0.0/0"],
        resolved_services=services or ["1-65535"],
    )


def test_shadow_detector_finds_shadowed_rule() -> None:
    # Rule 1: broad (10.0.0.0/24 -> any)
    # Rule 2: narrow (10.0.0.0/25 -> 192.168.1.0/24) — shadowed by rule 1
    p1 = _policy("1", seq=0, src_cidrs=["10.0.0.0/24"], dst_cidrs=["0.0.0.0/0"], services=["80"])
    p2 = _policy("2", seq=1, src_cidrs=["10.0.0.0/25"], dst_cidrs=["192.168.1.0/24"], services=["80"])
    detector = ShadowDetector()
    findings = detector.detect([p1, p2])
    assert len(findings) >= 1
    assert any("2" in f.affected_policies for f in findings)


def test_redundancy_detector_deduplicate_pairs() -> None:
    # Two policies that are redundant with each other: only one finding for the pair
    p1 = _policy("A", seq=0, src_cidrs=["10.0.0.0/24"], dst_cidrs=["192.168.1.0/24"], services=["80"])
    p2 = _policy("B", seq=1, src_cidrs=["10.0.0.0/24"], dst_cidrs=["192.168.1.0/24"], services=["80"])
    detector = RedundancyDetector()
    findings = detector.detect([p1, p2])
    assert len(findings) == 1
    assert set(findings[0].affected_policies) == {"A", "B"}
