"""Core analysis orchestrator — coordinates all analysis engines."""

from __future__ import annotations

import logging
from datetime import datetime

from forticheck.analysis.attack_path import AttackPathEngine
from forticheck.analysis.behavior_chain import BehaviorChainEngine
from forticheck.analysis.blast_radius import BlastRadiusEngine
from forticheck.analysis.cis import CisAnalyzer
from forticheck.analysis.custom_rules import CustomRulesEngine
from forticheck.analysis.engines import (
    BasicPolicyAnalyzer,
    EastWestAnalyzer,
    InternetExposureAnalyzer,
    TrustBoundaryAnalyzer,
)
from forticheck.analysis.implicit_trust import ImplicitTrustEngine
from forticheck.analysis.intent_analysis import IntentAnalysisEngine
from forticheck.analysis.lateral_movement import LateralMovementEngine
from forticheck.analysis.policy_complexity import PolicyComplexityEngine
from forticheck.analysis.policy_ordering import PolicyOrderingAnalyzer
from forticheck.analysis.segmentation_drift import SegmentationDriftEngine
from forticheck.analysis.shadow import RedundancyDetector, ShadowDetector
from forticheck.analysis.stale_objects import StaleObjectAnalyzer
from forticheck.analysis.transitive_access import TransitiveAccessEngine
from forticheck.analysis.trust_boundary_mismatch import TrustBoundaryMismatchEngine
from forticheck.analysis.user_vpn import UserVpnAnalyzer
from forticheck.graph.builder import SecurityGraph
from forticheck.models.canonical import Device
from forticheck.models.findings import AnalysisResult, Finding
from forticheck.normalizer.resolver import ObjectResolver
from forticheck.risk.scorer import RiskScorer
from forticheck.parsers.fortigate import FortiGateParser

logger = logging.getLogger(__name__)


class Analyzer:
    """Orchestrates the full analysis pipeline."""

    def __init__(
        self,
        device: Device,
        resolver: ObjectResolver,
        parser: FortiGateParser,
        custom_rules_path: str | None = None,
    ) -> None:
        self.device = device
        self.resolver = resolver
        self.parser = parser
        self.custom_rules_path = custom_rules_path
        self.graph = SecurityGraph()
        self.findings: list[Finding] = []

    def run(self) -> AnalysisResult:
        """Execute the complete analysis pipeline."""
        logger.info("Starting analysis for device: %s", self.device.hostname)

        # 1) Build security graph
        logger.info("[1/11] Building security graph...")
        self.graph.build_from_device(self.device, self.resolver)

        # 2) Basic policy analysis
        logger.info("[2/11] Running basic policy analysis...")
        basic = BasicPolicyAnalyzer()
        self.findings.extend(basic.analyze(self.device, self.resolver))

        # 3) Shadow & redundancy detection
        logger.info("[3/11] Running shadow & redundancy detection...")
        shadow = ShadowDetector()
        self.findings.extend(shadow.detect(self.device.all_policies))

        redundancy = RedundancyDetector()
        self.findings.extend(redundancy.detect(self.device.all_policies))

        # 4) Trust boundary analysis
        logger.info("[4/11] Running trust boundary analysis...")
        trust = TrustBoundaryAnalyzer()
        self.findings.extend(trust.analyze(self.graph))

        # 5) Internet exposure analysis
        logger.info("[5/11] Running internet exposure analysis...")
        exposure = InternetExposureAnalyzer()
        self.findings.extend(exposure.analyze(self.graph, self.device))

        # 6) East-west analysis
        logger.info("[6/11] Running east-west exposure analysis...")
        eastwest = EastWestAnalyzer()
        ew_findings, exposure_matrix = eastwest.analyze(
            self.graph, self.device, self.resolver,
        )
        self.findings.extend(ew_findings)

        # 7) Attack Path
        logger.info("[7/11] Running attack path simulation...")
        attack_path_engine = AttackPathEngine()
        attack_paths = attack_path_engine.find_attack_paths(self.graph)
        self.findings.extend(attack_path_engine.generate_findings(attack_paths))

        # 8) User & VPN Analysis
        logger.info("[8/11] Running user & VPN analysis...")
        user_analyzer = UserVpnAnalyzer()
        user_findings = user_analyzer.analyze(self.device)
        self.findings.extend(user_findings)
        user_stats = user_analyzer.get_stats(self.device)

        # 9) CIS Compliance Analysis
        logger.info("[9/11] Running CIS compliance analysis...")
        cis_analyzer = CisAnalyzer()
        cis_findings, cis_score = cis_analyzer.analyze(self.parser)
        self.findings.extend(cis_findings)

        # 10) Stale object detection
        logger.info("[10/11] Running stale object analysis...")
        stale_analyzer = StaleObjectAnalyzer()
        self.findings.extend(stale_analyzer.analyze(self.device))

        # 11) Policy ordering suggestions
        logger.info("[11/11] Running policy ordering analysis...")
        ordering_analyzer = PolicyOrderingAnalyzer()
        self.findings.extend(ordering_analyzer.analyze(self.device.all_policies))

        # 12) Custom rules (optional)
        if self.custom_rules_path:
            logger.info("Running custom rules from %s...", self.custom_rules_path)
            custom_engine = CustomRulesEngine(self.custom_rules_path)
            self.findings.extend(custom_engine.analyze(self.device, self.graph))

        # 13) Next-gen: Implicit Trust
        logger.info("[13/20] Running implicit trust analysis...")
        implicit_engine = ImplicitTrustEngine()
        implicit_findings, implicit_data = implicit_engine.analyze(self.graph, self.device)
        self.findings.extend(implicit_findings)

        # 14) Next-gen: Blast Radius
        logger.info("[14/20] Running blast radius analysis...")
        blast_engine = BlastRadiusEngine()
        blast_findings, blast_map = blast_engine.analyze(
            self.graph, self.device, self.resolver
        )
        self.findings.extend(blast_findings)

        # 15) Next-gen: Transitive Access
        logger.info("[15/20] Running transitive access analysis...")
        transitive_engine = TransitiveAccessEngine()
        transitive_findings, transitive_pairs = transitive_engine.analyze(self.graph)
        self.findings.extend(transitive_findings)

        # 16) Next-gen: Segmentation Drift
        logger.info("[16/20] Running segmentation drift analysis...")
        seg_engine = SegmentationDriftEngine()
        seg_findings, seg_effectiveness = seg_engine.analyze(
            self.graph, self.device, exposure_matrix
        )
        self.findings.extend(seg_findings)

        # 17) Next-gen: Behavior Chain
        logger.info("[17/20] Running behavior chain analysis...")
        chain_engine = BehaviorChainEngine()
        self.findings.extend(chain_engine.analyze(self.graph))

        # 18) Next-gen: Lateral Movement
        logger.info("[18/20] Running lateral movement analysis...")
        lateral_engine = LateralMovementEngine()
        lateral_findings, lateral_scores = lateral_engine.analyze(
            self.graph, self.device, exposure_matrix
        )
        self.findings.extend(lateral_findings)

        # 19) Next-gen: Trust Boundary Mismatch
        logger.info("[19/20] Running trust boundary mismatch analysis...")
        mismatch_engine = TrustBoundaryMismatchEngine()
        self.findings.extend(mismatch_engine.analyze(self.graph, exposure_matrix))

        # 20) Next-gen: Policy Complexity
        logger.info("[20/20] Running policy complexity analysis...")
        complexity_engine = PolicyComplexityEngine()
        self.findings.extend(complexity_engine.analyze(self.device, self.resolver))

        # 21) Next-gen: Intent Analysis
        logger.info("Running intent-behavior gap analysis...")
        intent_engine = IntentAnalysisEngine()
        self.findings.extend(intent_engine.analyze(self.device))

        # Risk scoring
        logger.info("Scoring findings...")
        scorer = RiskScorer(self.graph, self.device, self.resolver)
        self.findings = scorer.score_findings(self.findings)
        device_risk = scorer.calculate_device_risk(self.findings)

        # Sort findings by risk score descending
        self.findings.sort(key=lambda f: f.risk_score, reverse=True)

        # Deduplicate findings by ID
        seen_ids: set[str] = set()
        unique_findings: list[Finding] = []
        for f in self.findings:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                unique_findings.append(f)
        self.findings = unique_findings

        # Build zone-to-interface map for report
        iface_zone_map: dict[str, str] = {}
        for z in self.device.all_zones:
            for iface_name in z.interfaces:
                iface_zone_map[iface_name] = z.name

        # Build infrastructure overview for report
        interfaces_data = [
            {
                "name": i.name,
                "zone": iface_zone_map.get(i.name, i.zone or "unassigned"),
                "ip": i.ip_address or "-",
                "type": i.type.value,
                "description": i.description or "",
            }
            for i in self.device.all_interfaces
        ]
        zones_data = [
            {
                "name": z.name,
                "trust_level": z.trust_level,
                "interfaces": ", ".join(z.interfaces) if z.interfaces else "-",
            }
            for z in self.device.all_zones
        ]

        # Build result
        result = AnalysisResult(
            device_hostname=self.device.hostname,
            device_vendor=self.device.vendor.value,
            firmware_version=self.device.firmware_version,
            analysis_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_policies=len(self.device.all_policies),
            total_interfaces=len(self.device.all_interfaces),
            total_zones=len(self.device.all_zones),
            total_routes=len(self.device.all_routes),
            findings=self.findings,
            attack_paths=attack_paths,
            zone_exposure_matrix=exposure_matrix,
            device_risk_score=device_risk,
            total_users=len(self.device.all_users),
            total_vpn_tunnels=len(self.device.all_vpn_tunnels),
            users=user_stats["users"],
            user_groups=user_stats["groups"],
            vpn_tunnels=user_stats["tunnels"],
            admin_users=user_stats["admins"],
            cis_score=cis_score,
            interfaces=interfaces_data,
            zones=zones_data,
            blast_radius_map=blast_map,
            transitive_access_pairs=transitive_pairs,
            segmentation_effectiveness=seg_effectiveness,
            lateral_movement_scores=lateral_scores,
            implicit_trust_findings=implicit_data,
        )

        logger.info(
            "Analysis complete: %d findings, device risk = %.1f, CIS score = %.1f",
            len(self.findings), device_risk, cis_score,
        )

        return result
