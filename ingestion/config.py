"""Parse Cisco IOS/NX-OS configuration files and flag potential issues."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from models import Event


# --- Interface extraction ---

_INTERFACE_BLOCK_RE = re.compile(
    r"^interface\s+(\S+)", re.IGNORECASE | re.MULTILINE
)
_SHUTDOWN_RE = re.compile(r"^\s+shutdown\s*$", re.MULTILINE)
_DUPLEX_RE = re.compile(r"^\s+duplex\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_SPEED_RE = re.compile(r"^\s+speed\s+(\d+)", re.MULTILINE | re.IGNORECASE)
_IP_ADDR_RE = re.compile(
    r"^\s+ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
    re.MULTILINE | re.IGNORECASE,
)
_NO_IP_RE = re.compile(r"^\s+no ip address", re.MULTILINE | re.IGNORECASE)
_DESCRIPTION_RE = re.compile(r"^\s+description\s+(.+)", re.MULTILINE | re.IGNORECASE)
_MTU_RE = re.compile(r"^\s+mtu\s+(\d+)", re.MULTILINE | re.IGNORECASE)
_SWITCHPORT_RE = re.compile(r"^\s+switchport", re.MULTILINE | re.IGNORECASE)

# --- Routing ---
_ROUTER_BLOCK_RE = re.compile(
    r"^(router\s+(?:ospf|eigrp|bgp|isis|rip)\s+\S+(?:\s+vrf\s+\S+)?)",
    re.IGNORECASE | re.MULTILINE,
)
_BGP_NEIGHBOR_RE = re.compile(
    r"^\s+neighbor\s+(\S+)\s+remote-as\s+(\d+)", re.MULTILINE | re.IGNORECASE
)
_OSPF_NETWORK_RE = re.compile(
    r"^\s+network\s+(\S+)\s+(\S+)\s+area\s+(\S+)", re.MULTILINE | re.IGNORECASE
)

# --- ACL / security ---
_ACL_RE = re.compile(
    r"^(?:ip\s+access-list|access-list)\s+(\S+)\s+(\S+)?",
    re.IGNORECASE | re.MULTILINE,
)

# Known problem patterns
_HALF_DUPLEX_RE = re.compile(r"^\s+duplex\s+half", re.MULTILINE | re.IGNORECASE)
_AUTONEG_SPEED_RE = re.compile(r"^\s+speed\s+auto", re.MULTILINE | re.IGNORECASE)
_LARGE_MTU_RE = re.compile(r"^\s+mtu\s+([5-9]\d{3}|\d{5,})", re.MULTILINE | re.IGNORECASE)


def _split_interface_blocks(config: str) -> list[tuple[str, str]]:
    """Return [(interface_name, block_text), ...]."""
    blocks: list[tuple[str, str]] = []
    lines = config.splitlines(keepends=True)
    current_name: Optional[str] = None
    current_lines: list[str] = []

    for line in lines:
        m = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
        if m:
            if current_name:
                blocks.append((current_name, "".join(current_lines)))
            current_name = m.group(1)
            current_lines = [line]
        elif current_name:
            if re.match(r"^\S", line) and not re.match(r"^\s", line):
                blocks.append((current_name, "".join(current_lines)))
                current_name = None
                current_lines = []
            else:
                current_lines.append(line)

    if current_name and current_lines:
        blocks.append((current_name, "".join(current_lines)))

    return blocks


def _analyze_interface(name: str, block: str, device: Optional[str]) -> list[Event]:
    events: list[Event] = []

    # Half-duplex mismatch
    duplex_m = _DUPLEX_RE.search(block)
    if duplex_m and duplex_m.group(1).lower() == "half":
        events.append(Event(
            source_type="config",
            severity="P2",
            message=f"Interface {name} configured for half-duplex — likely mismatch",
            raw=block.strip(),
            device=device,
            interface=name,
            facility="CONFIG",
            mnemonic="DUPLEX_MISMATCH",
            metadata={"duplex": "half", "interface": name},
        ))

    # Speed/duplex mismatch: explicit speed but auto duplex (or vice versa)
    speed_m = _SPEED_RE.search(block)
    if speed_m and duplex_m:
        speed = speed_m.group(1)
        duplex = duplex_m.group(1).lower()
        if duplex not in ("full", "half", "auto"):
            pass
        elif speed != "auto" and duplex == "auto":
            events.append(Event(
                source_type="config",
                severity="P3",
                message=f"Interface {name}: speed {speed} hardcoded but duplex auto — potential mismatch",
                raw=block.strip(),
                device=device,
                interface=name,
                facility="CONFIG",
                mnemonic="SPEED_DUPLEX_MISMATCH",
                metadata={"speed": speed, "duplex": duplex},
            ))

    # Shutdown with IP address configured
    ip_m = _IP_ADDR_RE.search(block)
    if ip_m and _SHUTDOWN_RE.search(block):
        events.append(Event(
            source_type="config",
            severity="P3",
            message=f"Interface {name} has IP {ip_m.group(1)} but is administratively shutdown",
            raw=block.strip(),
            device=device,
            interface=name,
            facility="CONFIG",
            mnemonic="SHUTDOWN_WITH_IP",
            metadata={"ip": ip_m.group(1), "shutdown": True},
        ))

    # Non-standard MTU
    mtu_m = _MTU_RE.search(block)
    if mtu_m:
        mtu = int(mtu_m.group(1))
        if mtu not in (1500, 9000, 9216, 9198):
            events.append(Event(
                source_type="config",
                severity="P3",
                message=f"Interface {name} has non-standard MTU {mtu} — verify end-to-end MTU consistency",
                raw=block.strip(),
                device=device,
                interface=name,
                facility="CONFIG",
                mnemonic="NON_STANDARD_MTU",
                metadata={"mtu": mtu},
            ))

    # Routed interface with no IP
    is_switchport = bool(_SWITCHPORT_RE.search(block))
    has_ip = bool(ip_m)
    is_down = bool(_SHUTDOWN_RE.search(block))
    if not is_switchport and not has_ip and not is_down:
        no_ip = bool(_NO_IP_RE.search(block))
        if not no_ip and "Loopback" not in name and "Vlan" not in name:
            events.append(Event(
                source_type="config",
                severity="INFO",
                message=f"Interface {name} is routed but has no IP address configured",
                raw=block.strip(),
                device=device,
                interface=name,
                facility="CONFIG",
                mnemonic="NO_IP_ADDRESS",
                metadata={"interface": name},
            ))

    return events


def _analyze_routing(config: str, device: Optional[str]) -> list[Event]:
    events: list[Event] = []

    # BGP: neighbors without password or route-map
    bgp_neighbors = _BGP_NEIGHBOR_RE.findall(config)
    for neighbor_ip, remote_as in bgp_neighbors:
        # Check if password is configured for this neighbor
        password_re = re.compile(
            rf"neighbor\s+{re.escape(neighbor_ip)}\s+password", re.IGNORECASE
        )
        if not password_re.search(config):
            events.append(Event(
                source_type="config",
                severity="P3",
                message=f"BGP neighbor {neighbor_ip} (AS {remote_as}) has no MD5 password configured",
                raw=f"neighbor {neighbor_ip} remote-as {remote_as}",
                device=device,
                facility="CONFIG",
                mnemonic="BGP_NO_AUTH",
                metadata={"neighbor": neighbor_ip, "remote_as": remote_as},
            ))

    return events


def parse_config(source: str | Path, device: Optional[str] = None) -> list[Event]:
    """Parse a Cisco IOS/NX-OS config and return anomaly Events.

    Args:
        source: Path to config file, or raw config text.
        device: Device hostname for labelling events.
    """
    if isinstance(source, Path) or (
        isinstance(source, str) and "\n" not in str(source) and Path(source).exists()
    ):
        path = Path(source)
        if path.exists():
            config = path.read_text(errors="replace")
        else:
            config = str(source)
    else:
        config = str(source)

    # Try to extract hostname if not provided
    if not device:
        hn_m = re.search(r"^hostname\s+(\S+)", config, re.MULTILINE | re.IGNORECASE)
        if hn_m:
            device = hn_m.group(1)

    events: list[Event] = []

    # Analyse each interface block
    for iface_name, block in _split_interface_blocks(config):
        events.extend(_analyze_interface(iface_name, block, device))

    # Analyse routing
    events.extend(_analyze_routing(config, device))

    # Add a summary INFO event with the full config for LLM context
    events.append(Event(
        source_type="config",
        severity="INFO",
        message=f"Full device configuration ({len(config.splitlines())} lines)",
        raw=config,
        device=device,
        facility="CONFIG",
        mnemonic="FULL_CONFIG",
        metadata={"line_count": len(config.splitlines())},
    ))

    return events
