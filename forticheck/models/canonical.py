"""Canonical vendor-independent firewall data models.

These Pydantic models define the normalized representation of firewall
configurations regardless of vendor. All vendor-specific parsers
produce instances of these models.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DeviceVendor(str, Enum):
    FORTIGATE = "fortigate"
    PALOALTO = "paloalto"
    CISCO_ASA = "cisco_asa"
    GENERIC = "generic"


class HAMode(str, Enum):
    STANDALONE = "standalone"
    ACTIVE_PASSIVE = "active_passive"
    ACTIVE_ACTIVE = "active_active"


class InterfaceType(str, Enum):
    PHYSICAL = "physical"
    VLAN = "vlan"
    LOOPBACK = "loopback"
    TUNNEL = "tunnel"
    AGGREGATE = "aggregate"
    SOFTWARE_SWITCH = "software_switch"
    HARD_SWITCH = "hard_switch"


class InterfaceStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    ADMIN_DOWN = "admin_down"


class NetworkObjectType(str, Enum):
    HOST = "host"
    SUBNET = "subnet"
    RANGE = "range"
    FQDN = "fqdn"
    GEO = "geo"
    WILDCARD = "wildcard"
    GROUP = "group"
    ALL = "all"


class ServiceObjectType(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    GROUP = "group"
    ALL = "all"


class ServiceSensitivity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class PolicyAction(str, Enum):
    ACCEPT = "accept"
    DENY = "deny"
    IPSEC = "ipsec"
    DROP = "drop"


class RouteType(str, Enum):
    STATIC = "static"
    CONNECTED = "connected"
    POLICY_ROUTE = "policy_route"


class UserType(str, Enum):
    LOCAL = "local"
    LDAP = "ldap"
    RADIUS = "radius"
    TACACS = "tacacs"
    PKI = "pki"
    FSSO = "fsso"
    SSO = "sso"


class VPNType(str, Enum):
    IPSEC = "ipsec"
    SSL_VPN = "ssl_vpn"
    DIALUP = "dialup"
    SITE_TO_SITE = "site_to_site"


class UserRole(str, Enum):
    ADMIN = "admin"
    VPN_USER = "vpn_user"
    GUEST = "guest"
    FIREWALL_USER = "firewall_user"
    SSLVPN_USER = "sslvpn_user"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Security Profiles
# ---------------------------------------------------------------------------

class SecurityProfiles(BaseModel):
    """Security inspection profiles attached to a policy."""

    antivirus: Optional[str] = None
    ips: Optional[str] = None
    web_filter: Optional[str] = None
    app_control: Optional[str] = None
    ssl_inspection: Optional[str] = None
    dlp: Optional[str] = None
    email_filter: Optional[str] = None
    file_filter: Optional[str] = None

    @property
    def has_any(self) -> bool:
        """Return True if at least one security profile is attached."""
        return any([
            self.antivirus, self.ips, self.web_filter,
            self.app_control, self.ssl_inspection,
            self.dlp, self.email_filter, self.file_filter,
        ])

    @property
    def missing_critical(self) -> list[str]:
        """Return names of critical profiles that are not assigned."""
        critical = {
            "antivirus": self.antivirus,
            "ips": self.ips,
            "web_filter": self.web_filter,
            "ssl_inspection": self.ssl_inspection,
        }
        return [name for name, val in critical.items() if not val]

    @property
    def assigned_count(self) -> int:
        """Number of assigned profiles."""
        fields = [
            self.antivirus, self.ips, self.web_filter,
            self.app_control, self.ssl_inspection,
        ]
        return sum(1 for f in fields if f)

    @property
    def total_expected(self) -> int:
        return 5


# ---------------------------------------------------------------------------
# Network Object
# ---------------------------------------------------------------------------

class NetworkObject(BaseModel):
    """Normalized network address object."""

    id: str
    name: str
    type: NetworkObjectType
    value: str = ""  # IP, CIDR, range string, FQDN, etc.
    members: list[str] = Field(default_factory=list)  # member IDs for groups
    resolved_cidrs: list[str] = Field(default_factory=list)  # flat resolved CIDRs


# ---------------------------------------------------------------------------
# Service Object
# ---------------------------------------------------------------------------

class ServiceObject(BaseModel):
    """Normalized service/port object."""

    id: str
    name: str
    type: ServiceObjectType
    protocol: str = ""
    port_range: str = ""  # e.g. "80", "1024-65535", ""
    members: list[str] = Field(default_factory=list)
    resolved_ports: list[str] = Field(default_factory=list)  # flat resolved port specs
    sensitivity: ServiceSensitivity = ServiceSensitivity.UNKNOWN


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

class Interface(BaseModel):
    """Normalized network interface."""

    id: str
    name: str
    type: InterfaceType = InterfaceType.PHYSICAL
    ip_address: Optional[str] = None  # CIDR notation  e.g. "10.1.1.1/24"
    zone: Optional[str] = None  # Zone name
    vdom: str = "root"
    status: InterfaceStatus = InterfaceStatus.UP
    connected_networks: list[str] = Field(default_factory=list)
    vlan_id: Optional[int] = None
    parent_interface: Optional[str] = None
    description: str = ""


# ---------------------------------------------------------------------------
# Zone
# ---------------------------------------------------------------------------

class Zone(BaseModel):
    """Normalized security zone."""

    id: str
    name: str
    trust_level: int = 50  # 0=untrusted, 100=most trusted
    interfaces: list[str] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)  # CIDRs in this zone


# ---------------------------------------------------------------------------
# Policy Rule
# ---------------------------------------------------------------------------

class PolicyRule(BaseModel):
    """Canonical firewall policy rule."""

    id: str
    sequence: int = 0
    name: str = ""
    enabled: bool = True
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    source_addresses: list[str] = Field(default_factory=list)
    destination_addresses: list[str] = Field(default_factory=list)
    source_addresses_negate: bool = False
    destination_addresses_negate: bool = False
    services: list[str] = Field(default_factory=list)
    action: PolicyAction = PolicyAction.DENY
    nat: bool = False
    log: bool = False
    security_profiles: SecurityProfiles = Field(default_factory=SecurityProfiles)
    schedule: str = "always"
    comments: str = ""
    # Resolved fields (populated during normalization)
    resolved_src_cidrs: list[str] = Field(default_factory=list)
    resolved_dst_cidrs: list[str] = Field(default_factory=list)
    resolved_services: list[str] = Field(default_factory=list)

    @property
    def is_any_source(self) -> bool:
        return "all" in [a.lower() for a in self.source_addresses]

    @property
    def is_any_destination(self) -> bool:
        return "all" in [a.lower() for a in self.destination_addresses]

    @property
    def is_any_service(self) -> bool:
        return "ALL" in self.services or "all" in [s.lower() for s in self.services]

    @property
    def is_overly_permissive(self) -> bool:
        """Check if this is an any/any/any rule."""
        if self.action != PolicyAction.ACCEPT:
            return False
        return self.is_any_source and self.is_any_destination and self.is_any_service


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

class Route(BaseModel):
    """Normalized routing entry."""

    id: str
    destination: str  # CIDR, e.g. "0.0.0.0/0"
    gateway: Optional[str] = None
    interface: str = ""
    distance: int = 10
    priority: int = 0
    type: RouteType = RouteType.STATIC


# ---------------------------------------------------------------------------
# User & VPN Models
# ---------------------------------------------------------------------------

class FirewallUser(BaseModel):
    """Normalized firewall/VPN user."""

    id: str
    name: str
    type: UserType = UserType.LOCAL
    role: UserRole = UserRole.UNKNOWN
    status: str = "enable"  # enable / disable
    groups: list[str] = Field(default_factory=list)
    two_factor: bool = False
    two_factor_method: str = ""  # fortitoken, email, sms
    email: str = ""
    auth_server: str = ""  # LDAP/RADIUS server name
    password_policy: str = ""
    expire: str = ""  # expiry date or empty
    vpn_access: bool = False  # user has VPN access

    @property
    def is_active(self) -> bool:
        return self.status == "enable"

    @property
    def has_mfa(self) -> bool:
        return self.two_factor


class UserGroup(BaseModel):
    """Normalized user group."""

    id: str
    name: str
    group_type: str = "firewall"  # firewall, fsso, Guest, sslvpn
    members: list[str] = Field(default_factory=list)  # user names
    auth_type: str = ""  # local, radius, ldap, tacacs
    guest_access: bool = False
    sslvpn_portal: str = ""  # Associated SSL VPN portal
    match_entries: list[dict] = Field(default_factory=list)  # LDAP/RADIUS match


class VPNTunnel(BaseModel):
    """Normalized IPsec / SSL-VPN tunnel configuration."""

    id: str
    name: str
    type: VPNType = VPNType.IPSEC
    interface: str = ""  # Bound interface
    remote_gateway: str = ""  # Remote IP or "0.0.0.0" for dialup
    status: str = "enable"
    phase1_auth: str = ""  # psk, signature (cert)
    phase1_encryption: list[str] = Field(default_factory=list)
    phase1_hash: list[str] = Field(default_factory=list)
    phase1_dh_group: list[str] = Field(default_factory=list)
    ike_version: str = ""  # 1 or 2
    dpd: str = ""  # dead-peer-detection
    phase2_encryption: list[str] = Field(default_factory=list)
    phase2_hash: list[str] = Field(default_factory=list)
    phase2_pfs: str = ""  # Perfect forward secrecy group
    src_subnet: str = ""
    dst_subnet: str = ""
    user_groups: list[str] = Field(default_factory=list)  # Dialup user groups
    # SSL-VPN specific
    sslvpn_portal: str = ""
    sslvpn_realm: str = ""
    tunnel_mode: bool = True
    split_tunnelling: bool = False
    split_tunnelling_networks: list[str] = Field(default_factory=list)

    @property
    def is_dialup(self) -> bool:
        return self.remote_gateway in ("", "0.0.0.0") or self.type == VPNType.DIALUP

    @property
    def has_weak_crypto(self) -> bool:
        weak_enc = {"des", "3des", "null"}
        weak_hash = {"md5"}
        for e in self.phase1_encryption + self.phase2_encryption:
            parts = {part for part in e.lower().split("-") if part}
            if e.lower() in weak_enc or parts & weak_enc:
                return True
        for h in self.phase1_hash + self.phase2_hash:
            parts = {part for part in h.lower().split("-") if part}
            if h.lower() in weak_hash or parts & weak_hash:
                return True
        return False

    @property
    def has_pfs(self) -> bool:
        pfs = self.phase2_pfs.strip().lower()
        disabled_values = {"disable", "disabled", "no", "none", "no-pfs", "0", "false"}
        return bool(pfs) and pfs not in disabled_values


# ---------------------------------------------------------------------------
# VDOM
# ---------------------------------------------------------------------------

class VDOM(BaseModel):
    """Virtual domain container."""

    name: str = "root"
    interfaces: list[Interface] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    policies: list[PolicyRule] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    network_objects: list[NetworkObject] = Field(default_factory=list)
    service_objects: list[ServiceObject] = Field(default_factory=list)
    users: list[FirewallUser] = Field(default_factory=list)
    user_groups: list[UserGroup] = Field(default_factory=list)
    vpn_tunnels: list[VPNTunnel] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Device (top-level)
# ---------------------------------------------------------------------------

class Device(BaseModel):
    """Top-level firewall device representation."""

    id: str = ""
    hostname: str = ""
    vendor: DeviceVendor = DeviceVendor.FORTIGATE
    firmware_version: str = ""
    serial_number: str = ""
    ha_mode: HAMode = HAMode.STANDALONE
    vdoms: list[VDOM] = Field(default_factory=list)

    @property
    def default_vdom(self) -> VDOM:
        """Return the root/default VDOM."""
        for vdom in self.vdoms:
            if vdom.name == "root":
                return vdom
        if self.vdoms:
            return self.vdoms[0]
        vdom = VDOM(name="root")
        self.vdoms.append(vdom)
        return vdom

    @property
    def all_policies(self) -> list[PolicyRule]:
        """Flatten all policies across VDOMs."""
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.policies)
        return result

    @property
    def all_interfaces(self) -> list[Interface]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.interfaces)
        return result

    @property
    def all_zones(self) -> list[Zone]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.zones)
        return result

    @property
    def all_network_objects(self) -> list[NetworkObject]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.network_objects)
        return result

    @property
    def all_service_objects(self) -> list[ServiceObject]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.service_objects)
        return result

    @property
    def all_routes(self) -> list[Route]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.routes)
        return result

    @property
    def all_users(self) -> list[FirewallUser]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.users)
        return result

    @property
    def all_user_groups(self) -> list[UserGroup]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.user_groups)
        return result

    @property
    def all_vpn_tunnels(self) -> list[VPNTunnel]:
        result = []
        for vdom in self.vdoms:
            result.extend(vdom.vpn_tunnels)
        return result
