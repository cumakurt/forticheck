"""Tests for risk scorer."""

from unittest.mock import MagicMock

import pytest

from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device, DeviceVendor, VDOM
from forticheck.models.findings import Finding, FindingCategory, Severity
from forticheck.risk.scorer import RiskScorer


def test_score_findings_assigns_severity() -> None:
    graph = SecurityGraph()
    device = Device(hostname="test", vendor=DeviceVendor.FORTIGATE, vdoms=[VDOM(name="root")])
    resolver = MagicMock()
    scorer = RiskScorer(graph, device, resolver)
    finding = Finding(
        id="TEST-1",
        category=FindingCategory.ANY_ANY_ANY,
        title="Test",
        description="Test",
        risk_score=0,
    )
    scored = scorer.score_findings([finding])
    assert len(scored) == 1
    assert scored[0].risk_score > 0
    assert scored[0].severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def test_calculate_device_risk_empty() -> None:
    graph = SecurityGraph()
    device = Device(hostname="test", vendor=DeviceVendor.FORTIGATE, vdoms=[VDOM(name="root")])
    resolver = MagicMock()
    scorer = RiskScorer(graph, device, resolver)
    risk = scorer.calculate_device_risk([])
    assert risk == 0.0


def test_calculate_device_risk_with_findings() -> None:
    graph = SecurityGraph()
    device = Device(hostname="test", vendor=DeviceVendor.FORTIGATE, vdoms=[VDOM(name="root")])
    resolver = MagicMock()
    scorer = RiskScorer(graph, device, resolver)
    findings = [
        Finding(id="1", category=FindingCategory.INTERNET_EXPOSURE, title="X", description="X", risk_score=90),
    ]
    risk = scorer.calculate_device_risk(findings)
    assert 0 <= risk <= 100
