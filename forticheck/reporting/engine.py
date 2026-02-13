"""Report engine — generates professional HTML security reports."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from forticheck.models.findings import AnalysisResult, FindingCategory, Severity

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportEngine:
    """Generate professional security analysis reports."""

    def __init__(self) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        self.env.filters["severity_color"] = self._severity_color
        self.env.filters["severity_badge"] = self._severity_badge
        self.env.filters["score_color"] = self._score_color
        self.env.filters["round_score"] = lambda x: round(x, 1)

    def generate_html(self, result: AnalysisResult, output_path: str) -> str:
        """Generate a self-contained HTML report."""
        template = self.env.get_template("report.html")

        # Prepare data
        context = self._build_context(result)

        html = template.render(**context)

        # Write output
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")

        logger.info("Report generated: %s", output_path)
        return str(out.absolute())

    def generate_json(self, result: AnalysisResult, output_path: str) -> str:
        """Export analysis results as JSON. Includes @timestamp for SIEM/log ingestion."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = result.model_dump(mode="json")
        data["@timestamp"] = datetime.now().isoformat()
        data["device_hostname"] = result.device_hostname
        out.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        return str(out.absolute())

    def _build_context(self, result: AnalysisResult) -> dict:
        """Build the template context dict."""
        findings_by_severity = {
            "critical": result.critical_findings,
            "high": result.high_findings,
            "medium": result.medium_findings,
            "low": result.low_findings,
            "info": result.info_findings,
        }

        findings_by_category = result.findings_by_category

        # Category stats
        category_stats = []
        for cat, findings in sorted(findings_by_category.items(),
                                      key=lambda x: -len(x[1])):
            category_stats.append({
                "name": cat.replace("_", " ").title(),
                "count": len(findings),
                "max_severity": max(
                    (f.severity for f in findings),
                    key=lambda s: ["info", "low", "medium", "high", "critical"].index(s.value),
                    default=Severity.INFO,
                ).value,
            })

        # Severity counts
        severity_counts = {
            "critical": len(result.critical_findings),
            "high": len(result.high_findings),
            "medium": len(result.medium_findings),
            "low": len(result.low_findings),
            "info": len(result.info_findings),
        }

        # Zone exposure matrix data for heatmap
        zone_matrix = result.zone_exposure_matrix
        zone_names = sorted(set(
            list(zone_matrix.keys()) +
            [dst for src_data in zone_matrix.values() for dst in src_data.keys()]
        ))

        heatmap_data = []
        for src in zone_names:
            for dst in zone_names:
                services = zone_matrix.get(src, {}).get(dst, [])
                heatmap_data.append({
                    "src": src,
                    "dst": dst,
                    "count": len(services),
                    "services": services[:5],  # limit for display
                })

        # Executive summary (with top 3 attack paths and top 3 critical findings)
        executive_summary = self._build_executive_summary(
            result, severity_counts, len(result.attack_paths),
        )
        top_attack_paths = result.attack_paths[:3]
        top_critical_findings = sorted(
            result.findings, key=lambda x: -x.risk_score,
        )[:3]

        # Next-gen security insights (categorized)
        next_gen_insights = self._build_next_gen_insights(result)

        # Prioritized action items (top 10 by risk)
        action_items = [
            {
                "priority": i + 1,
                "title": f.title,
                "severity": f.severity.value,
                "remediation": f.remediation or "Review and mitigate.",
            }
            for i, f in enumerate(
                sorted(result.findings, key=lambda x: -x.risk_score)[:10]
            )
        ]

        return {
            "report_title": "FortiCheck Security Analysis Report",
            "device_hostname": result.device_hostname,
            "device_vendor": result.device_vendor,
            "firmware_version": result.firmware_version,
            "analysis_timestamp": result.analysis_timestamp,
            "total_policies": result.total_policies,
            "total_interfaces": result.total_interfaces,
            "total_zones": result.total_zones,
            "total_routes": result.total_routes,
            "device_risk_score": round(result.device_risk_score, 1),
            "total_findings": len(result.findings),
            "severity_counts": severity_counts,
            "findings_by_severity": findings_by_severity,
            "findings_by_category": findings_by_category,
            "category_stats": category_stats,
            "attack_paths": result.attack_paths,
            "zone_names": zone_names,
            "heatmap_data": json.dumps(heatmap_data),
            "heatmap_data_raw": heatmap_data,
            "zone_matrix": zone_matrix,
            "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            # User & VPN Data
            "total_users": result.total_users,
            "total_vpn_tunnels": result.total_vpn_tunnels,
            "admin_users": result.admin_users,
            "users": result.users,
            "user_groups": result.user_groups,
            "vpn_tunnels": result.vpn_tunnels,
            "cis_score": round(result.cis_score, 1),
            "cis_findings": [f for f in result.findings if f.category == FindingCategory.CIS_BENCHMARK],
            # Extended report sections
            "executive_summary": executive_summary,
            "action_items": action_items,
            "top_attack_paths": top_attack_paths,
            "top_critical_findings": top_critical_findings,
            "interfaces": result.interfaces,
            "zones": result.zones,
            # Next-gen
            "next_gen_insights": next_gen_insights,
            "segmentation_effectiveness": getattr(result, "segmentation_effectiveness", 0),
            "blast_radius_map": getattr(result, "blast_radius_map", {}),
            "transitive_access_count": len(getattr(result, "transitive_access_pairs", [])),
        }

    def _build_next_gen_insights(self, result: AnalysisResult) -> list[dict]:
        """Build next-gen insight categories from findings."""
        insights: list[dict] = []
        cat_map = {
            "architectural_mismatch": (
                ["intent_behavior_gap", "trust_boundary_mismatch"],
                "Firewall configuration may not align with security intent",
            ),
            "segmentation_ineffective": (
                ["segmentation_drift"],
                "Zone segmentation may be ineffective",
            ),
            "implicit_trust": (
                ["implicit_trust"],
                "Hidden trust relationships detected",
            ),
            "blast_radius_high": (
                ["blast_radius", "lateral_movement"],
                "High attack spread potential from compromise",
            ),
            "transitive_access": (
                ["transitive_access", "behavior_chain"],
                "Hidden transitive access paths exist",
            ),
        }
        for key, (categories, message) in cat_map.items():
            count = sum(
                len(result.findings_by_category.get(cat, []))
                for cat in categories
            )
            if count > 0:
                insights.append({
                    "key": key,
                    "message": message,
                    "count": count,
                    "severity": "high" if count >= 5 else "medium",
                })
        return insights

    def _build_executive_summary(
        self,
        result: AnalysisResult,
        severity_counts: dict[str, int],
        attack_path_count: int,
    ) -> dict:
        """Build executive summary with key highlights and risk assessment."""
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        risk_level = "Critical"
        risk_desc = (
            "Immediate attention required. Critical and high-severity findings "
            "pose significant security exposure."
        )
        if critical == 0 and high == 0:
            if severity_counts.get("medium", 0) == 0:
                risk_level = "Low"
                risk_desc = (
                    "Configuration demonstrates good security posture. "
                    "Address remaining low-severity items during regular maintenance."
                )
            else:
                risk_level = "Moderate"
                risk_desc = (
                    "Some medium-severity items require review. "
                    "Prioritize remediation to improve security posture."
                )
        elif critical == 0:
            risk_level = "Elevated"
            risk_desc = (
                "High-severity findings require prompt remediation. "
                "Schedule review and implement recommended actions."
            )

        return {
            "risk_level": risk_level,
            "risk_description": risk_desc,
            "critical_count": critical,
            "high_count": high,
            "attack_path_count": attack_path_count,
            "cis_score": round(result.cis_score, 1),
            "device_risk_score": round(result.device_risk_score, 1),
        }

    @staticmethod
    def _severity_color(severity: str) -> str:
        colors = {
            "critical": "#dc2626",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#3b82f6",
            "info": "#6b7280",
        }
        return colors.get(severity, "#6b7280")

    @staticmethod
    def _severity_badge(severity: str) -> str:
        color = ReportEngine._severity_color(severity)
        label = severity.upper()
        return (
            f'<span style="background:{color};color:#fff;padding:2px 10px;'
            f'border-radius:4px;font-size:12px;font-weight:700;">{label}</span>'
        )

    @staticmethod
    def _score_color(score: float) -> str:
        if score >= 85:
            return "#dc2626"
        if score >= 70:
            return "#f97316"
        if score >= 50:
            return "#eab308"
        if score >= 25:
            return "#3b82f6"
        return "#6b7280"
