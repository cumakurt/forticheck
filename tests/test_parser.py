"""Tests for FortiGate parser."""

from pathlib import Path

import pytest

from forticheck.parsers.fortigate import FortiGateParser


def test_parse_string_returns_dict() -> None:
    parser = FortiGateParser()
    text = """
config system global
    set hostname "test-fw"
end
config system interface
    edit "wan1"
        set ip 192.168.1.1 255.255.255.0
    next
end
"""
    result = parser.parse_string(text)
    assert isinstance(result, dict)
    assert "system global" in result
    assert "system interface" in result


def test_get_section() -> None:
    parser = FortiGateParser()
    text = """
config system global
    set hostname "myfw"
    set timezone 03
end
"""
    parser.parse_string(text)
    global_section = parser.get_section("system global")
    assert global_section is not None
    assert isinstance(global_section, dict)
    assert global_section.get("hostname") == "myfw"


def test_get_firewall_policies_empty() -> None:
    parser = FortiGateParser()
    text = "config system global\n    set hostname x\nend\n"
    parser.parse_string(text)
    policies = parser.get_firewall_policies()
    assert policies == []


def test_parse_sample_config(samples_dir: Path) -> None:
    sample = samples_dir / "sample_fortigate.conf"
    if not sample.exists():
        pytest.skip("Sample config not found")
    parser = FortiGateParser()
    parser.parse_file(str(sample))
    assert parser.get_hostname() == "FW-CORP-01"
    policies = parser.get_firewall_policies()
    assert isinstance(policies, list)
    interfaces = parser.get_system_interfaces()
    assert len(interfaces) >= 1


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent / "samples"
