"""Tests for policy logic engine (shadow/redundancy)."""

import pytest

from forticheck.analysis.logic import PolicyLogicEngine, PolicyRelation
from forticheck.models.canonical import PolicyAction, PolicyRule


def _policy(
    pid: str,
    seq: int = 0,
    src_zones: list[str] | None = None,
    dst_zones: list[str] | None = None,
    src_cidrs: list[str] | None = None,
    dst_cidrs: list[str] | None = None,
    services: list[str] | None = None,
) -> PolicyRule:
    return PolicyRule(
        id=pid,
        sequence=seq,
        source_zones=src_zones or ["wan"],
        destination_zones=dst_zones or ["lan"],
        source_addresses=["all"],
        destination_addresses=["all"],
        services=services or ["ALL"],
        action=PolicyAction.ACCEPT,
        resolved_src_cidrs=src_cidrs or ["0.0.0.0/0"],
        resolved_dst_cidrs=dst_cidrs or ["0.0.0.0/0"],
        resolved_services=services or ["1-65535"],
    )


def test_compare_disjoint_zones() -> None:
    engine = PolicyLogicEngine()
    a = _policy("1", src_zones=["wan"], dst_zones=["lan"])
    b = _policy("2", src_zones=["dmz"], dst_zones=["servers"])
    assert engine.compare(a, b) == PolicyRelation.DISJOINT


def test_compare_equal_policies() -> None:
    engine = PolicyLogicEngine()
    a = _policy("1", src_cidrs=["10.0.0.0/24"], dst_cidrs=["192.168.1.0/24"], services=["80"])
    b = _policy("2", src_cidrs=["10.0.0.0/24"], dst_cidrs=["192.168.1.0/24"], services=["80"])
    rel = engine.compare(a, b)
    assert rel == PolicyRelation.EQUAL


def test_compare_subset() -> None:
    engine = PolicyLogicEngine()
    # a is narrower (subset of b)
    a = _policy("1", src_cidrs=["10.0.0.0/25"], dst_cidrs=["192.168.1.0/25"], services=["80"])
    b = _policy("2", src_cidrs=["10.0.0.0/24"], dst_cidrs=["192.168.1.0/24"], services=["80"])
    rel = engine.compare(a, b)
    assert rel == PolicyRelation.SUBSET


def test_is_shadowed_by_sequence_order() -> None:
    engine = PolicyLogicEngine()
    upper = _policy("upper", seq=0, src_cidrs=["10.0.0.0/24"], dst_cidrs=["0.0.0.0/0"], services=["80"])
    candidate = _policy("candidate", seq=1, src_cidrs=["10.0.0.0/25"], dst_cidrs=["192.168.1.0/24"], services=["80"])
    assert engine.is_shadowed_by(candidate, upper) is True
    assert engine.is_shadowed_by(upper, candidate) is False
