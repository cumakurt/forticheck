"""Tests for report context preparation."""

from forticheck.analysis.user_vpn import UserVpnAnalyzer
from forticheck.models.canonical import Device, VDOM, VPNTunnel
from forticheck.models.findings import AnalysisResult
from forticheck.reporting.engine import ReportEngine


def test_vpn_report_data_includes_computed_security_flags() -> None:
    tunnel = VPNTunnel(
        id="legacy",
        name="legacy",
        remote_gateway="203.0.113.5",
        phase1_encryption=["des"],
        phase1_hash=["md5"],
        phase2_pfs="disable",
    )
    device = Device(hostname="fw", vdoms=[VDOM(name="root", vpn_tunnels=[tunnel])])
    stats = UserVpnAnalyzer().get_stats(device)
    result = AnalysisResult(
        device_hostname=device.hostname,
        vpn_tunnels=stats["tunnels"],
    )

    context = ReportEngine()._build_context(result)
    report_tunnel = context["vpn_tunnels"][0]
    assert report_tunnel["has_weak_crypto"] is True
    assert report_tunnel["has_pfs"] is False
    assert report_tunnel["is_dialup"] is False
