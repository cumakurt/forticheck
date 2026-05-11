"""Tests for canonical model building edge cases."""

from forticheck.normalizer.builder import CanonicalModelBuilder
from forticheck.parsers.fortigate import FortiGateParser


def _build_device(config: str):
    parser = FortiGateParser()
    parser.parse_string(config)
    return CanonicalModelBuilder().build(parser)[0]


def test_mfa_disable_is_not_treated_as_enabled() -> None:
    device = _build_device("""
config system admin
    edit "admin"
        set two-factor disable
    next
    edit "secure-admin"
        set two-factor fortitoken
    next
end
""")

    users = {user.name: user for user in device.all_users}
    assert users["admin"].two_factor is False
    assert users["admin"].two_factor_method == ""
    assert users["secure-admin"].two_factor is True
    assert users["secure-admin"].two_factor_method == "fortitoken"


def test_vpn_proposals_are_split_into_encryption_and_hash() -> None:
    device = _build_device("""
config vpn ipsec phase1-interface
    edit "legacy"
        set interface "wan1"
        set remote-gw 203.0.113.5
        set proposal des-md5 3des-sha1
    next
end
config vpn ipsec phase2-interface
    edit "legacy-p2"
        set phase1name "legacy"
        set proposal des-md5
        set pfs disable
    next
end
""")

    tunnel = device.all_vpn_tunnels[0]
    assert tunnel.phase1_encryption == ["des", "3des"]
    assert tunnel.phase1_hash == ["md5", "sha1"]
    assert tunnel.phase2_encryption == ["des"]
    assert tunnel.phase2_hash == ["md5"]
    assert tunnel.has_weak_crypto is True
    assert tunnel.has_pfs is False


def test_custom_service_keeps_multiple_destination_ports() -> None:
    parser = FortiGateParser()
    parser.parse_string("""
config firewall service custom
    edit "Web-Alt"
        set tcp-portrange 80 443 8443
    next
end
""")

    _device, resolver = CanonicalModelBuilder().build(parser)
    service = resolver.service_objects["Web-Alt"]
    assert service.resolved_ports == ["80", "443", "8443"]
