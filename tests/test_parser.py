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


def test_parse_string_resets_previous_metadata() -> None:
    parser = FortiGateParser()
    parser.parse_string("#config-version=FG100F-7.2.5-FW-build1517-230830\n")
    assert parser.firmware_version == "7.2.5"
    assert parser.serial_number == "FG100F"

    parser.parse_string("config system global\n    set hostname next-fw\nend\n")
    assert parser.get_hostname() == "next-fw"
    assert parser.firmware_version == ""
    assert parser.serial_number == ""


def test_nested_config_inside_edit_stays_on_parent_edit() -> None:
    parser = FortiGateParser()
    parser.parse_string("""
config system admin
    edit "admin"
        set accprofile "super_admin"
        config trusthost
            edit 1
                set subnet 10.0.0.0 255.255.255.0
            next
        end
    next
end
""")

    admins = parser.get_system_admin()
    assert len(admins) == 1
    assert admins[0]["__name__"] == "admin"
    assert admins[0]["trusthost"] == [
        {"__name__": "1", "subnet": ["10.0.0.0", "255.255.255.0"]}
    ]
    system_admin = parser.get_section("system admin")
    assert isinstance(system_admin, list)
    assert not any(isinstance(item, dict) and "trusthost" in item for item in system_admin[1:])


def test_append_keeps_all_values() -> None:
    parser = FortiGateParser()
    parser.parse_string("""
config firewall addrgrp
    edit "Servers"
        append member "Web01" "Web02"
    next
end
""")

    groups = parser.get_firewall_addrgrps()
    assert groups[0]["member"] == ["Web01", "Web02"]


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
