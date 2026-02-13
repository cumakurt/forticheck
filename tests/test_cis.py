"""Tests for CIS benchmark analyzer."""

from unittest.mock import MagicMock

import pytest

from forticheck.analysis.cis import CisAnalyzer
from forticheck.parsers.fortigate import FortiGateParser


def test_cis_analyzer_returns_findings_and_score() -> None:
    parser = FortiGateParser()
    parser.parse_string("""
config system global
    set hostname "FortiGate"
end
config system dns
end
""")
    analyzer = CisAnalyzer()
    findings, score = analyzer.analyze(parser)
    assert isinstance(findings, list)
    assert isinstance(score, float)
    assert 0 <= score <= 100
    # Default hostname and no DNS should produce at least one finding
    assert len(findings) >= 1


def test_cis_weighted_score() -> None:
    parser = FortiGateParser()
    parser.parse_string("""
config system global
    set hostname "MY-FW"
    set admintimeout 5
    set timezone 03
end
config system dns
    set primary 10.1.1.1
end
config system ntp
    set ntpsync enable
end
""")
    analyzer = CisAnalyzer()
    findings, score = analyzer.analyze(parser)
    assert score >= 0 and score <= 100
    # More passed checks => higher score
    assert len(findings) < 10
