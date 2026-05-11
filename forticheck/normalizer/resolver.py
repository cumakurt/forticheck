"""Object resolver — recursively resolves address and service groups to flat lists."""

from __future__ import annotations

import logging
from typing import Any

from netaddr import IPAddress, IPNetwork, IPRange

from forticheck.models.canonical import (
    NetworkObject,
    NetworkObjectType,
    ServiceObject,
    ServiceObjectType,
    ServiceSensitivity,
)

logger = logging.getLogger(__name__)

# Ports considered sensitive by category
CRITICAL_PORTS = {3389, 445, 5985, 5986, 22, 23, 5900}
HIGH_PORTS = {1433, 3306, 5432, 1521, 27017, 389, 636, 88}
MEDIUM_PORTS = {53, 123, 161, 514}
BUILTIN_SERVICE_DEFINITIONS: dict[str, tuple[str, str, ServiceSensitivity]] = {
    "HTTP": ("TCP", "80", ServiceSensitivity.LOW),
    "HTTPS": ("TCP", "443", ServiceSensitivity.LOW),
    "SSH": ("TCP", "22", ServiceSensitivity.CRITICAL),
    "TELNET": ("TCP", "23", ServiceSensitivity.CRITICAL),
    "DNS": ("TCP", "53", ServiceSensitivity.MEDIUM),
    "FTP": ("TCP", "21", ServiceSensitivity.HIGH),
    "SMTP": ("TCP", "25", ServiceSensitivity.MEDIUM),
    "PING": ("ICMP", "", ServiceSensitivity.LOW),
    "RDP": ("TCP", "3389", ServiceSensitivity.CRITICAL),
    "SMB": ("TCP", "445", ServiceSensitivity.CRITICAL),
    "MYSQL": ("TCP", "3306", ServiceSensitivity.HIGH),
    "MS-SQL": ("TCP", "1433", ServiceSensitivity.HIGH),
}


class ObjectResolver:
    """Resolve FortiGate address/service objects into canonical form."""

    def __init__(self) -> None:
        self.network_objects: dict[str, NetworkObject] = {}
        self.service_objects: dict[str, ServiceObject] = {}

    # ------------------------------------------------------------------
    # Network Objects
    # ------------------------------------------------------------------

    def build_network_objects(self, addresses: list[dict[str, Any]],
                              addrgrps: list[dict[str, Any]]) -> None:
        """Build canonical NetworkObject instances from parsed config."""
        # 1) Build individual address objects
        for addr in addresses:
            name = addr.get("__name__", "")
            if not name:
                continue

            obj = NetworkObject(id=name, name=name, type=NetworkObjectType.SUBNET)

            addr_type = addr.get("type", "ipmask")

            if addr_type == "ipmask":
                subnet = addr.get("subnet", "")
                if isinstance(subnet, list):
                    subnet = " ".join(subnet)
                cidr = self._ipmask_to_cidr(subnet)
                obj.type = NetworkObjectType.SUBNET
                obj.value = cidr
                obj.resolved_cidrs = [cidr] if cidr else []

            elif addr_type == "iprange":
                start_ip = addr.get("start-ip", "")
                end_ip = addr.get("end-ip", "")
                obj.type = NetworkObjectType.RANGE
                obj.value = f"{start_ip}-{end_ip}"
                obj.resolved_cidrs = self._range_to_cidrs(start_ip, end_ip)

            elif addr_type == "fqdn":
                fqdn = addr.get("fqdn", name)
                obj.type = NetworkObjectType.FQDN
                obj.value = fqdn

            elif addr_type == "geography":
                country = addr.get("country", "")
                obj.type = NetworkObjectType.GEO
                obj.value = country

            elif addr_type == "wildcard-fqdn":
                obj.type = NetworkObjectType.WILDCARD
                obj.value = addr.get("wildcard-fqdn", name)

            else:
                # Default / fallback
                subnet = addr.get("subnet", "")
                if isinstance(subnet, list):
                    subnet = " ".join(subnet)
                if subnet:
                    cidr = self._ipmask_to_cidr(subnet)
                    obj.value = cidr
                    obj.resolved_cidrs = [cidr] if cidr else []

            self.network_objects[name] = obj

        # Special "all" object
        all_obj = NetworkObject(
            id="all", name="all", type=NetworkObjectType.ALL,
            value="0.0.0.0/0", resolved_cidrs=["0.0.0.0/0"],
        )
        self.network_objects["all"] = all_obj

        # 2) Build address groups
        for grp in addrgrps:
            name = grp.get("__name__", "")
            if not name:
                continue

            members_raw = grp.get("member", [])
            if isinstance(members_raw, str):
                members_raw = [members_raw]

            obj = NetworkObject(
                id=name, name=name,
                type=NetworkObjectType.GROUP,
                members=members_raw,
            )
            self.network_objects[name] = obj

        # 3) Resolve group memberships recursively
        for obj in self.network_objects.values():
            if obj.type == NetworkObjectType.GROUP and not obj.resolved_cidrs:
                obj.resolved_cidrs = self._resolve_network_group(obj.name, set())

    def resolve_address_names(self, names: list[str]) -> list[str]:
        """Resolve a list of address object names to flat CIDR list."""
        cidrs: list[str] = []
        for name in names:
            obj = self.network_objects.get(name)
            if obj:
                cidrs.extend(obj.resolved_cidrs)
            elif name.lower() == "all":
                cidrs.append("0.0.0.0/0")
        return cidrs

    def _resolve_network_group(self, name: str, visited: set[str]) -> list[str]:
        """Recursively resolve a network group to CIDRs."""
        if name in visited:
            logger.warning("Circular reference in address group: %s", name)
            return []
        visited.add(name)

        obj = self.network_objects.get(name)
        if not obj:
            return []

        if obj.type != NetworkObjectType.GROUP:
            return list(obj.resolved_cidrs)

        cidrs: list[str] = []
        for member_name in obj.members:
            member = self.network_objects.get(member_name)
            if member:
                if member.type == NetworkObjectType.GROUP:
                    cidrs.extend(self._resolve_network_group(member_name, visited))
                else:
                    cidrs.extend(member.resolved_cidrs)
        return cidrs

    # ------------------------------------------------------------------
    # Service Objects
    # ------------------------------------------------------------------

    def build_service_objects(self, services: list[dict[str, Any]],
                              service_groups: list[dict[str, Any]]) -> None:
        """Build canonical ServiceObject instances from parsed config."""
        # 1) Build individual service objects
        for svc in services:
            name = svc.get("__name__", "")
            if not name:
                continue

            protocol = svc.get("protocol", "TCP/UDP/SCTP").upper()
            tcp_range = svc.get("tcp-portrange", "")
            udp_range = svc.get("udp-portrange", "")

            if isinstance(tcp_range, list):
                tcp_range = " ".join(tcp_range)
            if isinstance(udp_range, list):
                udp_range = " ".join(udp_range)

            tcp_ports = self._normalize_port_ranges(tcp_range)
            udp_ports = self._normalize_port_ranges(udp_range)

            # Determine type
            if "TCP" in protocol and tcp_ports:
                svc_type = ServiceObjectType.TCP
                resolved_ports = tcp_ports + [p for p in udp_ports if p not in tcp_ports]
            elif "UDP" in protocol and udp_ports:
                svc_type = ServiceObjectType.UDP
                resolved_ports = udp_ports
            elif protocol == "ICMP":
                svc_type = ServiceObjectType.ICMP
                resolved_ports = []
            elif protocol == "IP":
                svc_type = ServiceObjectType.IP
                resolved_ports = self._to_str_list(svc.get("protocol-number", ""))
            else:
                svc_type = ServiceObjectType.TCP
                resolved_ports = tcp_ports or udp_ports

            port_range = " ".join(resolved_ports)

            obj = ServiceObject(
                id=name, name=name, type=svc_type,
                protocol=protocol, port_range=port_range,
            )
            obj.resolved_ports = resolved_ports
            obj.sensitivity = self._max_sensitivity(resolved_ports)
            self.service_objects[name] = obj

        # Special "ALL" service
        all_svc = ServiceObject(
            id="ALL", name="ALL", type=ServiceObjectType.ALL,
            protocol="ALL", port_range="1-65535",
            resolved_ports=["1-65535"],
            sensitivity=ServiceSensitivity.CRITICAL,
        )
        self.service_objects["ALL"] = all_svc

        # Common built-in services if not already defined
        for bname, (proto, port, sens) in BUILTIN_SERVICE_DEFINITIONS.items():
            if bname not in self.service_objects:
                self.service_objects[bname] = ServiceObject(
                    id=bname, name=bname,
                    type=ServiceObjectType.ICMP if proto == "ICMP" else ServiceObjectType.TCP,
                    protocol=proto, port_range=port,
                    resolved_ports=[port] if port else [],
                    sensitivity=sens,
                )

        # 2) Build service groups
        for grp in service_groups:
            name = grp.get("__name__", "")
            if not name:
                continue

            members_raw = grp.get("member", [])
            if isinstance(members_raw, str):
                members_raw = [members_raw]

            obj = ServiceObject(
                id=name, name=name, type=ServiceObjectType.GROUP,
                members=members_raw,
            )
            self.service_objects[name] = obj

        # 3) Resolve groups
        for obj in self.service_objects.values():
            if obj.type == ServiceObjectType.GROUP and not obj.resolved_ports:
                obj.resolved_ports = self._resolve_service_group(obj.name, set())
                obj.sensitivity = self._max_sensitivity(obj.resolved_ports)

    def resolve_service_names(self, names: list[str]) -> list[str]:
        """Resolve service object names to flat port-range list."""
        ports: list[str] = []
        for name in names:
            obj = self.service_objects.get(name)
            if obj:
                ports.extend(obj.resolved_ports)
            elif name.upper() == "ALL":
                ports.append("1-65535")
        return ports

    def get_service_sensitivity(self, names: list[str]) -> ServiceSensitivity:
        """Return the highest sensitivity across given service names."""
        max_sens = ServiceSensitivity.UNKNOWN
        order = [
            ServiceSensitivity.UNKNOWN, ServiceSensitivity.LOW,
            ServiceSensitivity.MEDIUM, ServiceSensitivity.HIGH,
            ServiceSensitivity.CRITICAL,
        ]
        for name in names:
            obj = self.service_objects.get(name)
            if obj and order.index(obj.sensitivity) > order.index(max_sens):
                max_sens = obj.sensitivity
        return max_sens

    def _resolve_service_group(self, name: str, visited: set[str]) -> list[str]:
        if name in visited:
            return []
        visited.add(name)
        obj = self.service_objects.get(name)
        if not obj:
            return []
        if obj.type != ServiceObjectType.GROUP:
            return list(obj.resolved_ports)
        ports: list[str] = []
        for member_name in obj.members:
            member = self.service_objects.get(member_name)
            if member:
                if member.type == ServiceObjectType.GROUP:
                    ports.extend(self._resolve_service_group(member_name, visited))
                else:
                    ports.extend(member.resolved_ports)
        return ports

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _ipmask_to_cidr(subnet_str: str) -> str:
        """Convert FortiGate 'subnet' format to CIDR.

        Input: "10.1.1.0 255.255.255.0" or "10.1.1.0/24"
        Output: "10.1.1.0/24"
        """
        subnet_str = subnet_str.strip()
        if not subnet_str:
            return ""
        if "/" in subnet_str:
            try:
                return str(IPNetwork(subnet_str).cidr)
            except Exception:
                return subnet_str
        parts = subnet_str.split()
        if len(parts) == 2:
            try:
                ip = parts[0]
                mask = parts[1]
                network = IPNetwork(f"{ip}/{mask}")
                return str(network.cidr)
            except Exception:
                return subnet_str
        return subnet_str

    @staticmethod
    def _range_to_cidrs(start_ip: str, end_ip: str) -> list[str]:
        """Convert an IP range to a list of covering CIDRs."""
        if not start_ip or not end_ip:
            return []
        try:
            ip_range = IPRange(start_ip, end_ip)
            return [str(cidr) for cidr in ip_range.cidrs()]
        except Exception:
            return [f"{start_ip}-{end_ip}"]

    @staticmethod
    def _normalize_port_range(port_str: str) -> str:
        """Normalize port range strings.

        Input: "80" or "1024-65535" or "80:1024-65535" (src:dst format)
        Output: "80" or "1024-65535"
        """
        port_str = port_str.strip()
        if not port_str:
            return ""
        # FortiGate sometimes uses "dstport:srcport" format
        # We only care about destination port
        parts = port_str.split()
        if parts:
            port_str = parts[0]  # Take first port range
        if ":" in port_str:
            port_str = port_str.split(":")[0]  # dst port is before ':'
        return port_str

    @staticmethod
    def _normalize_port_ranges(port_str: str) -> list[str]:
        """Normalize one or more FortiGate destination port range tokens."""
        normalized: list[str] = []
        for token in port_str.strip().split():
            port = ObjectResolver._normalize_port_range(token)
            if port and port not in normalized:
                normalized.append(port)
        return normalized

    @staticmethod
    def _to_str_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if str(item)]
        value_str = str(value)
        return [value_str] if value_str else []

    def _classify_service_sensitivity(self, port_range: str) -> ServiceSensitivity:
        """Classify a port range by sensitivity."""
        if not port_range:
            return ServiceSensitivity.UNKNOWN
        ports = self._parse_port_set(port_range)
        if ports & CRITICAL_PORTS:
            return ServiceSensitivity.CRITICAL
        if ports & HIGH_PORTS:
            return ServiceSensitivity.HIGH
        if ports & MEDIUM_PORTS:
            return ServiceSensitivity.MEDIUM
        return ServiceSensitivity.LOW

    def _max_sensitivity(self, port_ranges: list[str]) -> ServiceSensitivity:
        """Return highest sensitivity from a list of port ranges."""
        max_s = ServiceSensitivity.UNKNOWN
        order = [
            ServiceSensitivity.UNKNOWN, ServiceSensitivity.LOW,
            ServiceSensitivity.MEDIUM, ServiceSensitivity.HIGH,
            ServiceSensitivity.CRITICAL,
        ]
        for pr in port_ranges:
            s = self._classify_service_sensitivity(pr)
            if order.index(s) > order.index(max_s):
                max_s = s
        return max_s

    @staticmethod
    def _parse_port_set(port_range: str) -> set[int]:
        """Parse a port range string into a set of port numbers.

        Only expands small ranges to avoid memory issues with large ranges.
        """
        ports: set[int] = set()
        if "-" in port_range:
            try:
                lo, hi = port_range.split("-", 1)
                lo_int, hi_int = int(lo), int(hi)
                if hi_int - lo_int > 1000:
                    # For large ranges, just check endpoints and known ports
                    ports.update({lo_int, hi_int})
                    for p in CRITICAL_PORTS | HIGH_PORTS | MEDIUM_PORTS:
                        if lo_int <= p <= hi_int:
                            ports.add(p)
                else:
                    ports.update(range(lo_int, hi_int + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(port_range))
            except ValueError:
                pass
        return ports
