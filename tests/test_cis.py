"""Tests for CIS benchmark analyzer."""

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


def test_cis_handles_invalid_timeout_and_reports_interface_name() -> None:
    parser = FortiGateParser()
    parser.parse_string("""
config system global
    set hostname "MY-FW"
    set admintimeout invalid
end
config system interface
    edit "wan1"
        set allowaccess ping http
    next
end
""")

    findings, _ = CisAnalyzer().analyze(parser)
    descriptions = "\n".join(f.description for f in findings)
    assert "wan1" in descriptions
    assert "unknown" not in descriptions
