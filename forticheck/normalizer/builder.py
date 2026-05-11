"""Canonical model builder — assembles full Device model from parsed config."""

from __future__ import annotations

import logging
from typing import Any

from forticheck.models.canonical import (
    Device,
    DeviceVendor,
    FirewallUser,
    Interface,
    InterfaceStatus,
    InterfaceType,
    Route,
    RouteType,
    UserGroup,
    UserRole,
    UserType,
    VDOM,
    VPNTunnel,
    VPNType,
    Zone,
)
from forticheck.normalizer.policy import PolicyNormalizer
from forticheck.normalizer.resolver import ObjectResolver
from forticheck.parsers.fortigate import FortiGateParser

logger = logging.getLogger(__name__)

# Default trust levels for common zone names
DEFAULT_TRUST_LEVELS: dict[str, int] = {
    "wan": 0, "wan1": 0, "wan2": 0,
    "internet": 0, "untrust": 0, "outside": 0,
    "dmz": 30, "dmz1": 30, "dmz2": 30,
    "guest": 20, "wifi-guest": 20,
    "internal": 70, "lan": 70, "lan1": 70, "lan2": 70,
    "trust": 70, "inside": 70,
    "servers": 80, "server": 80, "srv": 80,
    "dc": 100, "ad": 100, "management": 95, "mgmt": 95,
    "ha": 90, "heartbeat": 90,
    "voip": 60, "iot": 40, "scada": 85, "ics": 85,
}

DISABLED_VALUES = {"", "disable", "disabled", "none", "no", "false", "0"}
PROPOSAL_HASH_ALGORITHMS = {
    "md5",
    "sha1",
    "sha128",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "prfsha1",
    "prfsha256",
    "prfsha384",
    "prfsha512",
}


class CanonicalModelBuilder:
    """Build a canonical Device model from a parsed FortiGate config."""

    def __init__(self, trust_overrides: dict[str, int] | None = None) -> None:
        self.trust_levels = dict(DEFAULT_TRUST_LEVELS)
        if trust_overrides:
            self.trust_levels.update(trust_overrides)

    def build(self, parser: FortiGateParser) -> tuple[Device, ObjectResolver]:
        """Build complete Device model from parsed FortiGate config."""
        resolver = ObjectResolver()

        # 1) Build network objects
        resolver.build_network_objects(
            parser.get_firewall_addresses(),
            parser.get_firewall_addrgrps(),
        )

        # 2) Build service objects
        resolver.build_service_objects(
            parser.get_firewall_services(),
            parser.get_firewall_service_groups(),
        )

        # 3) Build interfaces
        interfaces = self._build_interfaces(parser.get_system_interfaces())

        # 4) Build zones
        zones = self._build_zones(parser.get_system_zones(), interfaces)

        # 5) Normalize policies
        normalizer = PolicyNormalizer(resolver)
        policies = normalizer.normalize_policies(parser.get_firewall_policies())

        # 6) Build routes
        routes = self._build_routes(parser.get_static_routes())

        # 7) Assemble VDOM
        vdom = VDOM(
            name="root",
            interfaces=interfaces,
            zones=zones,
            policies=policies,
            routes=routes,
            network_objects=list(resolver.network_objects.values()),
            service_objects=list(resolver.service_objects.values()),
            users=self._build_users(parser),
            user_groups=self._build_user_groups(parser),
            vpn_tunnels=self._build_vpn_tunnels(parser),
        )

        # 8) Assemble Device
        device = Device(
            id=parser.serial_number or parser.get_hostname(),
            hostname=parser.get_hostname(),
            vendor=DeviceVendor.FORTIGATE,
            firmware_version=parser.firmware_version,
            serial_number=parser.serial_number,
            vdoms=[vdom],
        )

        logger.info(
            "Built canonical model: hostname=%s, policies=%d, interfaces=%d, zones=%d",
            device.hostname, len(policies), len(interfaces), len(zones),
        )

        return device, resolver

    def _build_interfaces(self, raw_interfaces: list[dict[str, Any]]) -> list[Interface]:
        """Build Interface models from parsed interface data."""
        interfaces: list[Interface] = []
        for iface in raw_interfaces:
            name = iface.get("__name__", "")
            if not name:
                continue

            # Determine type
            iface_type = self._detect_interface_type(iface)

            # IP address
            ip_str = iface.get("ip", "")
            if isinstance(ip_str, list):
                ip_str = " ".join(ip_str)
            ip_cidr = ObjectResolver._ipmask_to_cidr(ip_str) if ip_str else None

            # Connected networks
            connected: list[str] = []
            if ip_cidr and "/" in ip_cidr:
                from netaddr import IPNetwork
                try:
                    net = IPNetwork(ip_cidr)
                    connected.append(str(net.cidr))
                except Exception:
                    pass

            # VLAN
            vlan_id = None
            if iface.get("vlanid"):
                try:
                    vlan_id = int(iface["vlanid"])
                except (ValueError, TypeError):
                    pass

            # Status (up / down / unknown)
            status_str = str(iface.get("status", "up")).lower()
            if status_str in ("down", "disable"):
                iface_status = InterfaceStatus.DOWN
            elif status_str == "up" or status_str == "enable":
                iface_status = InterfaceStatus.UP
            else:
                iface_status = InterfaceStatus.UP

            interface = Interface(
                id=name,
                name=name,
                type=iface_type,
                ip_address=ip_cidr if ip_cidr else None,
                zone=None,  # Will be set during zone building
                vdom=iface.get("vdom", "root"),
                status=iface_status,
                connected_networks=connected,
                vlan_id=vlan_id,
                parent_interface=iface.get("interface"),
                description=iface.get("description", ""),
            )
            interfaces.append(interface)

        return interfaces

    def _build_zones(self, raw_zones: list[dict[str, Any]],
                     interfaces: list[Interface]) -> list[Zone]:
        """Build Zone models and assign interfaces to zones."""
        zones: list[Zone] = []
        interface_zone_map: dict[str, str] = {}

        # Build explicit zones from 'config system zone'
        for raw_zone in raw_zones:
            name = raw_zone.get("__name__", "")
            if not name:
                continue

            # Get zone interfaces
            zone_ifaces_raw = raw_zone.get("interface", [])
            if isinstance(zone_ifaces_raw, str):
                zone_ifaces_raw = [zone_ifaces_raw]
            # Handle nested config format
            if isinstance(zone_ifaces_raw, list) and zone_ifaces_raw:
                if isinstance(zone_ifaces_raw[0], dict):
                    zone_ifaces_raw = [
                        z.get("interface-name", z.get("__name__", ""))
                        for z in zone_ifaces_raw
                    ]

            trust = self._get_trust_level(name)
            zone_networks: list[str] = []
            for iface_name in zone_ifaces_raw:
                interface_zone_map[iface_name] = name
                # Collect networks from interface
                for iface in interfaces:
                    if iface.name == iface_name:
                        zone_networks.extend(iface.connected_networks)

            zone = Zone(
                id=name, name=name,
                trust_level=trust,
                interfaces=zone_ifaces_raw,
                networks=zone_networks,
            )
            zones.append(zone)

        # Create implicit zones for interfaces not in any explicit zone
        for iface in interfaces:
            if iface.name not in interface_zone_map:
                # Interface is its own "zone" in FortiGate without explicit zone config
                zone_name = iface.name
                trust = self._get_trust_level(zone_name)
                zone = Zone(
                    id=zone_name, name=zone_name,
                    trust_level=trust,
                    interfaces=[iface.name],
                    networks=list(iface.connected_networks),
                )
                zones.append(zone)
                interface_zone_map[iface.name] = zone_name

        # Update interface zone assignments
        for iface in interfaces:
            iface.zone = interface_zone_map.get(iface.name)

        return zones

    def _build_routes(self, raw_routes: list[dict[str, Any]]) -> list[Route]:
        """Build Route models from parsed static routes."""
        routes: list[Route] = []
        for raw in raw_routes:
            rid = str(raw.get("__name__", len(routes)))

            dst = raw.get("dst", "0.0.0.0 0.0.0.0")
            if isinstance(dst, list):
                dst = " ".join(dst)
            dst_cidr = ObjectResolver._ipmask_to_cidr(dst)

            gateway = raw.get("gateway", "")
            device = raw.get("device", "")
            distance = 10
            try:
                distance = int(raw.get("distance", 10))
            except (ValueError, TypeError):
                pass

            priority = 0
            try:
                priority = int(raw.get("priority", 0))
            except (ValueError, TypeError):
                pass

            route = Route(
                id=rid,
                destination=dst_cidr if dst_cidr else "0.0.0.0/0",
                gateway=gateway if gateway else None,
                interface=device,
                distance=distance,
                priority=priority,
                type=RouteType.STATIC,
            )
            routes.append(route)

        return routes

    def _get_trust_level(self, zone_name: str) -> int:
        """Get trust level for a zone, using known defaults or heuristics."""
        name_lower = zone_name.lower().strip()
        if name_lower in self.trust_levels:
            return self.trust_levels[name_lower]

        # Heuristic: check for known keywords
        for keyword, trust in self.trust_levels.items():
            if keyword in name_lower:
                return trust

        return 50  # default

    @staticmethod
    def _detect_interface_type(iface: dict[str, Any]) -> InterfaceType:
        itype = str(iface.get("type", "physical")).lower()
        type_map = {
            "physical": InterfaceType.PHYSICAL,
            "vlan": InterfaceType.VLAN,
            "loopback": InterfaceType.LOOPBACK,
            "tunnel": InterfaceType.TUNNEL,
            "aggregate": InterfaceType.AGGREGATE,
            "redundant": InterfaceType.AGGREGATE,
            "switch": InterfaceType.SOFTWARE_SWITCH,
            "hard-switch": InterfaceType.HARD_SWITCH,
        }
        return type_map.get(itype, InterfaceType.PHYSICAL)

    def _build_users(self, parser: FortiGateParser) -> list[FirewallUser]:
        """Build normalized user list including local and admins."""
        users: list[FirewallUser] = []

        # 1. System Admins
        for admin in parser.get_system_admin():
            name = admin.get("__name__", "")
            if not name:
                continue
            two_factor = self._enabled_setting(admin.get("two-factor"))
            users.append(FirewallUser(
                id=f"admin-{name}",
                name=name,
                type=UserType.LOCAL,
                role=UserRole.ADMIN,
                status="enable",  # admin users are enabled if present
                two_factor=two_factor,
                two_factor_method=str(admin.get("two-factor", "")) if two_factor else "",
                email=str(admin.get("email-to", "")),
            ))

        # 2. Local Users
        for local in parser.get_user_local():
            name = local.get("__name__", "")
            if not name:
                continue
            factor = local.get("two-factor", "")
            two_factor = self._enabled_setting(factor)
            users.append(FirewallUser(
                id=f"local-{name}",
                name=name,
                type=UserType.LOCAL,
                role=UserRole.VPN_USER,  # Default assumption for local users
                status=str(local.get("status", "enable")),
                two_factor=two_factor,
                two_factor_method=str(factor) if two_factor else "",
                email=str(local.get("email-to", "")),
                password_policy=str(local.get("passwd-policy", "")),
            ))

        return users

    def _build_user_groups(self, parser: FortiGateParser) -> list[UserGroup]:
        """Build normalized user groups."""
        groups: list[UserGroup] = []

        for grp in parser.get_user_group():
            name = grp.get("__name__", "")
            if not name:
                continue

            members_raw = grp.get("member", [])
            if isinstance(members_raw, str):
                members_raw = [members_raw]
            
            # Handle nested member objects if distinct format used
            members = []
            for m in members_raw:
                if isinstance(m, dict):
                    m_name = m.get("__name__", m.get("name", ""))
                    if m_name:
                        members.append(m_name)
                elif isinstance(m, str):
                    members.append(m)

            groups.append(UserGroup(
                id=name,
                name=name,
                group_type=str(grp.get("group-type", "firewall")),
                members=members,
                auth_type="",  # FortiGate group does not expose auth type here; use group-type for type
            ))
        
        return groups

    def _build_vpn_tunnels(self, parser: FortiGateParser) -> list[VPNTunnel]:
        """Build normalized IPsec and SSL-VPN tunnels."""
        tunnels: list[VPNTunnel] = []

        # IPsec Phase 1
        p1_list = parser.get_vpn_ipsec_phase1()
        for p1 in p1_list:
            name = p1.get("__name__", "")
            if not name:
                continue

            # Phase 2 mapping (find p2 with same phase1name)
            p2_match = {}
            for p2 in parser.get_vpn_ipsec_phase2():
                if p2.get("phase1name") == name:
                    p2_match = p2
                    break

            p1_encryption, p1_hash = self._split_vpn_proposals(p1.get("proposal", []))
            p2_encryption, p2_hash = self._split_vpn_proposals(p2_match.get("proposal", []))

            tunnel = VPNTunnel(
                id=name,
                name=name,
                type=VPNType.DIALUP if p1.get("type") == "dynamic" else VPNType.IPSEC,
                interface=str(p1.get("interface", "")),
                remote_gateway=str(p1.get("remote-gw", "0.0.0.0")),
                phase1_auth=str(p1.get("authmethod", "")),
                phase1_encryption=p1_encryption,
                phase1_hash=p1_hash,
                phase1_dh_group=self._to_list(p1.get("dhgrp", [])),
                ike_version=str(p1.get("ike-version", "1")),
                phase2_encryption=p2_encryption,
                phase2_hash=p2_hash,
                phase2_pfs=str(p2_match.get("pfs", "enable")),
                src_subnet=self._ipmask_value(p2_match.get("src-subnet", "")),
                dst_subnet=self._ipmask_value(p2_match.get("dst-subnet", "")),
            )
            tunnels.append(tunnel)

        return tunnels

    @staticmethod
    def _enabled_setting(value: Any) -> bool:
        """Interpret FortiGate enable/disable-like settings."""
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, list):
            return any(CanonicalModelBuilder._enabled_setting(item) for item in value)
        return str(value).strip().lower() not in DISABLED_VALUES

    @staticmethod
    def _to_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if str(item)]
        value_str = str(value)
        return [value_str] if value_str else []

    @staticmethod
    def _ipmask_value(value: Any) -> str:
        if isinstance(value, list):
            return " ".join(str(item) for item in value)
        return str(value or "")

    @staticmethod
    def _split_vpn_proposals(value: Any) -> tuple[list[str], list[str]]:
        """Split FortiGate proposal tokens such as 'aes256-sha256'."""
        encryption: list[str] = []
        hashes: list[str] = []

        for proposal in CanonicalModelBuilder._to_list(value):
            token = proposal.strip().lower()
            if not token:
                continue

            parts = [part for part in token.split("-") if part]
            hash_part = parts[-1] if parts and parts[-1] in PROPOSAL_HASH_ALGORITHMS else ""
            enc_part = "-".join(parts[:-1]) if hash_part and len(parts) > 1 else token

            if enc_part and enc_part not in encryption:
                encryption.append(enc_part)
            if hash_part and hash_part not in hashes:
                hashes.append(hash_part)

        return encryption, hashes
