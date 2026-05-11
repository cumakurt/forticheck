"""Tests for stale object analysis."""

from forticheck.analysis.stale_objects import StaleObjectAnalyzer
from forticheck.normalizer.builder import CanonicalModelBuilder
from forticheck.parsers.fortigate import FortiGateParser


def test_group_members_and_builtin_services_are_not_reported_stale() -> None:
    parser = FortiGateParser()
    parser.parse_string("""
config firewall address
    edit "AppServer"
        set subnet 10.0.1.10 255.255.255.255
    next
end
config firewall addrgrp
    edit "AppServers"
        set member "AppServer"
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "AppServers"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
""")
    device, _ = CanonicalModelBuilder().build(parser)

    findings = StaleObjectAnalyzer().analyze(device)
    stale_names = {finding.details["object_name"] for finding in findings}
    assert "AppServer" not in stale_names
    assert "HTTPS" not in stale_names
