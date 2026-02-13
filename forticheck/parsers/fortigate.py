"""FortiGate configuration file parser.

Parses FortiOS configuration syntax:
    config <section>
        edit <name/id>
            set <key> <value>
            config <sub-section>
                ...
            end
        next
    end

Produces a nested dictionary structure (AST) that can be
consumed by the normalizer layer.
"""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FortiGateParser:
    """Parse FortiGate .conf export files into structured dictionaries."""

    def __init__(self) -> None:
        self.raw_config: dict[str, Any] = {}
        self.hostname: str = ""
        self.firmware_version: str = ""
        self.serial_number: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, filepath: str | Path) -> dict[str, Any]:
        """Parse a FortiGate config file and return structured dict."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        text = filepath.read_text(encoding="utf-8", errors="replace")
        return self.parse_string(text)

    def parse_string(self, text: str) -> dict[str, Any]:
        """Parse FortiGate config text and return structured dict."""
        lines = text.splitlines()
        self._extract_header(lines)

        self.raw_config = {}
        self._parse_block(lines, 0, self.raw_config)

        logger.info(
            "Parsed config: hostname=%s, version=%s, sections=%d",
            self.hostname, self.firmware_version, len(self.raw_config),
        )
        return self.raw_config

    # ------------------------------------------------------------------
    # Header extraction
    # ------------------------------------------------------------------

    def _extract_header(self, lines: list[str]) -> None:
        """Extract hostname, version, serial from config header comments."""
        for line in lines[:20]:
            line = line.strip()
            # #config-version=FG100F-7.2.5-FW-build1517-230830 or FG200D-5.04-FW-build1220
            # Supports X.Y.Z (7.2.5) and X.Y (5.04, 6.0) version formats
            match = re.match(
                r"#config-version=(\S+)-(\d+\.\d+(?:\.\d+)?)-FW-build(\d+)",
                line,
            )
            if match:
                self.serial_number = match.group(1)
                self.firmware_version = match.group(2)
                continue

            # Alternative header format
            if line.startswith("#conf_file_ver="):
                continue

    # ------------------------------------------------------------------
    # Recursive block parser
    # ------------------------------------------------------------------

    def _parse_block(
        self,
        lines: list[str],
        start: int,
        container: dict[str, Any],
    ) -> int:
        """Recursively parse config/edit/set/next/end blocks.

        Returns the line index after the block is closed.
        """
        i = start
        current_edit: dict[str, Any] | None = None
        current_edit_name: str | None = None
        edits_list: list[dict[str, Any]] = []
        section_path: str = ""

        while i < len(lines):
            line = lines[i].strip()
            i += 1

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # ---- config <section> ----
            if line.startswith("config "):
                section_name = line[7:].strip()
                section_path = section_name

                sub_container: dict[str, Any] = {}
                i = self._parse_block(lines, i, sub_container)

                # If the sub-container has __edits__, store as list-dict
                if "__edits__" in sub_container:
                    container[section_name] = sub_container["__edits__"]
                else:
                    container[section_name] = sub_container
                continue

            # ---- edit <name/id> ----
            if line.startswith("edit "):
                edit_name = self._unquote(line[5:].strip())
                current_edit = {"__name__": edit_name}
                current_edit_name = edit_name
                continue

            # ---- next ----
            if line == "next":
                if current_edit is not None:
                    edits_list.append(current_edit)
                    current_edit = None
                    current_edit_name = None
                continue

            # ---- end ----
            if line == "end":
                if current_edit is not None:
                    edits_list.append(current_edit)
                if edits_list:
                    container["__edits__"] = edits_list
                return i

            # ---- set <key> <values...> ----
            if line.startswith("set "):
                parts = self._split_set_line(line[4:])
                if len(parts) >= 2:
                    key = parts[0]
                    values = parts[1:]
                    # Single value → string; multiple values → list
                    value: Any = values[0] if len(values) == 1 else values
                    target = current_edit if current_edit is not None else container
                    target[key] = value
                continue

            # ---- unset <key> ----
            if line.startswith("unset "):
                continue  # ignore unsets

            # ---- append <key> <value> ----
            if line.startswith("append "):
                parts = self._split_set_line(line[7:])
                if len(parts) >= 2:
                    key = parts[0]
                    val = parts[1]
                    target = current_edit if current_edit is not None else container
                    existing = target.get(key, [])
                    if isinstance(existing, str):
                        existing = [existing]
                    existing.append(val)
                    target[key] = existing
                continue

            # ---- Handle "set" continuation / other statements ----
            if current_edit is not None and section_path:
                # Nested config inside edit
                if line.startswith("config "):
                    inner_name = line[7:].strip()
                    inner: dict[str, Any] = {}
                    i = self._parse_block(lines, i, inner)
                    if "__edits__" in inner:
                        current_edit[inner_name] = inner["__edits__"]
                    else:
                        current_edit[inner_name] = inner

        return i

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _unquote(s: str) -> str:
        """Remove surrounding quotes from a string."""
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            return s[1:-1]
        if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
            return s[1:-1]
        return s

    @staticmethod
    def _split_set_line(line: str) -> list[str]:
        """Split a 'set' line respecting quoted strings.

        Example: 'srcaddr "addr1" "addr2"' → ['srcaddr', 'addr1', 'addr2']
        """
        result: list[str] = []
        current = ""
        in_quote = False
        quote_char = ""

        for ch in line:
            if in_quote:
                if ch == quote_char:
                    in_quote = False
                    if current:
                        result.append(current)
                        current = ""
                else:
                    current += ch
            elif ch in ('"', "'"):
                in_quote = True
                quote_char = ch
            elif ch == " ":
                if current:
                    result.append(current)
                    current = ""
            else:
                current += ch

        if current:
            result.append(current)

        return result

    # ------------------------------------------------------------------
    # Convenience accessors for parsed config
    # ------------------------------------------------------------------

    def get_section(self, *path: str) -> Any:
        """Navigate the parsed config tree by section path.

        Example: get_section("firewall policy") or get_section("system interface")
        """
        current: Any = self.raw_config
        for key in path:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
            if current is None:
                return None
        return current

    def get_firewall_policies(self) -> list[dict[str, Any]]:
        """Return list of firewall policy edit blocks."""
        policies = self.get_section("firewall policy")
        if isinstance(policies, list):
            return policies
        return []

    def get_system_interfaces(self) -> list[dict[str, Any]]:
        """Return list of system interface edit blocks."""
        ifaces = self.get_section("system interface")
        if isinstance(ifaces, list):
            return ifaces
        return []

    def get_firewall_addresses(self) -> list[dict[str, Any]]:
        """Return list of firewall address objects."""
        addrs = self.get_section("firewall address")
        if isinstance(addrs, list):
            return addrs
        return []

    def get_firewall_addrgrps(self) -> list[dict[str, Any]]:
        """Return list of firewall address groups."""
        grps = self.get_section("firewall addrgrp")
        if isinstance(grps, list):
            return grps
        return []

    def get_firewall_services(self) -> list[dict[str, Any]]:
        """Return list of firewall service custom objects."""
        svcs = self.get_section("firewall service custom")
        if isinstance(svcs, list):
            return svcs
        return []

    def get_firewall_service_groups(self) -> list[dict[str, Any]]:
        """Return list of firewall service groups."""
        grps = self.get_section("firewall service group")
        if isinstance(grps, list):
            return grps
        return []

    def get_system_zones(self) -> list[dict[str, Any]]:
        """Return list of system zone definitions."""
        zones = self.get_section("system zone")
        if isinstance(zones, list):
            return zones
        return []

    def get_static_routes(self) -> list[dict[str, Any]]:
        """Return list of router static routes."""
        routes = self.get_section("router static")
        if isinstance(routes, list):
            return routes
        return []

    def get_vip_objects(self) -> list[dict[str, Any]]:
        """Return list of firewall VIP (DNAT) objects."""
        vips = self.get_section("firewall vip")
        if isinstance(vips, list):
            return vips
        return []

    # ------------------------------------------------------------------
    # User & VPN Accessors
    # ------------------------------------------------------------------

    def get_user_local(self) -> list[dict[str, Any]]:
        """Return list of local user definitions."""
        users = self.get_section("user local")
        if isinstance(users, list):
            return users
        return []

    def get_user_group(self) -> list[dict[str, Any]]:
        """Return list of user group definitions."""
        groups = self.get_section("user group")
        if isinstance(groups, list):
            return groups
        return []

    def get_user_ldap(self) -> list[dict[str, Any]]:
        """Return list of LDAP server definitions."""
        ldap = self.get_section("user ldap")
        if isinstance(ldap, list):
            return ldap
        return []

    def get_user_radius(self) -> list[dict[str, Any]]:
        """Return list of RADIUS server definitions."""
        radius = self.get_section("user radius")
        if isinstance(radius, list):
            return radius
        return []

    def get_vpn_ipsec_phase1(self) -> list[dict[str, Any]]:
        """Return IPsec Phase 1 interface definitions."""
        p1 = self.get_section("vpn ipsec phase1-interface")
        if isinstance(p1, list):
            return p1
        return []

    def get_vpn_ipsec_phase2(self) -> list[dict[str, Any]]:
        """Return IPsec Phase 2 interface definitions."""
        p2 = self.get_section("vpn ipsec phase2-interface")
        if isinstance(p2, list):
            return p2
        return []

    def get_vpn_ssl_settings(self) -> dict[str, Any] | None:
        """Return SSL-VPN settings."""
        settings = self.get_section("vpn ssl settings")
        if isinstance(settings, dict):
            return settings
        return None

    def get_system_admin(self) -> list[dict[str, Any]]:
        """Return system administrator definitions."""
        admins = self.get_section("system admin")
        if isinstance(admins, list):
            return admins
        return []

    def get_hostname(self) -> str:
        """Extract hostname from parsed config."""
        if self.hostname:
            return self.hostname
        sys_global = self.get_section("system global")
        if isinstance(sys_global, dict):
            self.hostname = sys_global.get("hostname", "unknown")
        return self.hostname or "unknown"
