"""Parse Cisco IOS/NX-OS 'show' command outputs into normalised Events."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from models import Event


# ---------------------------------------------------------------------------
# show interfaces
# ---------------------------------------------------------------------------
_INT_HEADER_RE = re.compile(
    r"^(\S+(?:GigabitEthernet|FastEthernet|TenGigabitEthernet|Serial|Vlan|"
    r"Loopback|Tunnel|Port-channel|Ethernet|TwentyFiveGigE|HundredGigE|Gi|Fa|"
    r"Te|Se|Vl|Lo|Tu|Po)\S*)\s+is\s+(up|down|administratively down),\s+"
    r"line protocol is\s+(up|down)",
    re.IGNORECASE,
)
_INPUT_ERRORS_RE = re.compile(r"(\d+)\s+input errors", re.IGNORECASE)
_OUTPUT_ERRORS_RE = re.compile(r"(\d+)\s+output errors", re.IGNORECASE)
_CRC_RE = re.compile(r"(\d+)\s+CRC", re.IGNORECASE)
_RUNTS_RE = re.compile(r"(\d+)\s+runts", re.IGNORECASE)
_GIANTS_RE = re.compile(r"(\d+)\s+giants", re.IGNORECASE)
_DUPLEX_SHOW_RE = re.compile(r"(Full|Half)-duplex,\s*(\d+)Mb/s", re.IGNORECASE)
_LAST_CLEAR_RE = re.compile(r"Last clearing of.*?counters\s+(\S+)", re.IGNORECASE)
_LOAD_RE = re.compile(r"reliability (\d+)/255,\s+txload (\d+)/255,\s+rxload (\d+)/255")
_QUEUE_DROP_RE = re.compile(r"(\d+)\s+output drops", re.IGNORECASE)

# ---------------------------------------------------------------------------
# show ip route / show ip bgp summary
# ---------------------------------------------------------------------------
_BGP_SUMMARY_HEADER_RE = re.compile(
    r"Neighbor\s+V\s+AS\s+MsgRcvd", re.IGNORECASE
)
_BGP_NEIGHBOR_ROW_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+.*?(\d+)\s*$"
)
_OSPF_NEIGHBOR_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(FULL|2WAY|EXSTART|EXCHANGE|LOADING|DOWN|INIT|ATTEMPT)\s",
    re.IGNORECASE | re.MULTILINE,
)

# ---------------------------------------------------------------------------
# show version
# ---------------------------------------------------------------------------
_VERSION_RE = re.compile(r"Cisco IOS.*?Version\s+(\S+)", re.IGNORECASE)
_UPTIME_RE = re.compile(r"uptime is\s+(.+)", re.IGNORECASE)
_RELOAD_RE = re.compile(r"System restarted.*?--\s+(.+)", re.IGNORECASE)


def _detect_command(text: str) -> str:
    """Guess which show command produced this output."""
    if re.search(r"GigabitEthernet|FastEthernet|input errors|CRC", text, re.IGNORECASE):
        return "show_interfaces"
    if re.search(r"Neighbor\s+V\s+AS|MsgRcvd|BGP router identifier", text, re.IGNORECASE):
        return "show_ip_bgp_summary"
    if re.search(r"OSPF.*State|Dead.*Time.*Pri|FULL|2WAY", text, re.IGNORECASE):
        return "show_ip_ospf_neighbor"
    if re.search(r"Cisco IOS.*Version|uptime is", text, re.IGNORECASE):
        return "show_version"
    if re.search(r"^\s+[DOSCRIA*]\s+\d+\.\d+\.\d+", text, re.IGNORECASE | re.MULTILINE):
        return "show_ip_route"
    return "unknown"


def _parse_show_interfaces(text: str, device: Optional[str]) -> list[Event]:
    events: list[Event] = []
    blocks = re.split(r"(?=^\w.*\bis\b.*line protocol)", text, flags=re.MULTILINE)

    for block in blocks:
        m = _INT_HEADER_RE.match(block.strip())
        if not m:
            continue
        iface, phys_state, proto_state = m.group(1), m.group(2).lower(), m.group(3).lower()

        # Interface down
        if phys_state == "down" or proto_state == "down":
            sev = "P1" if "GigabitEthernet" in iface or "TenGigabitEthernet" in iface else "P2"
            reason = "administratively down" if phys_state == "administratively down" else "link down"
            events.append(Event(
                source_type="cli",
                severity=sev,
                message=f"Interface {iface} is {reason} (protocol: {proto_state})",
                raw=block[:300],
                device=device,
                interface=iface,
                facility="CLI",
                mnemonic="INTERFACE_DOWN",
                metadata={"phys_state": phys_state, "proto_state": proto_state},
            ))

        # CRC errors
        crc_m = _CRC_RE.search(block)
        if crc_m and int(crc_m.group(1)) > 0:
            crc = int(crc_m.group(1))
            sev = "P1" if crc > 1000 else "P2" if crc > 100 else "P3"
            events.append(Event(
                source_type="cli",
                severity=sev,
                message=f"Interface {iface} has {crc:,} CRC errors — likely duplex/cable issue",
                raw=block[:300],
                device=device,
                interface=iface,
                facility="CLI",
                mnemonic="CRC_ERRORS",
                metadata={"crc_errors": crc},
            ))

        # Input errors
        in_err_m = _INPUT_ERRORS_RE.search(block)
        if in_err_m and int(in_err_m.group(1)) > 0:
            errs = int(in_err_m.group(1))
            sev = "P2" if errs > 100 else "P3"
            events.append(Event(
                source_type="cli",
                severity=sev,
                message=f"Interface {iface} has {errs:,} input errors",
                raw=block[:300],
                device=device,
                interface=iface,
                facility="CLI",
                mnemonic="INPUT_ERRORS",
                metadata={"input_errors": errs},
            ))

        # Output drops
        drop_m = _QUEUE_DROP_RE.search(block)
        if drop_m and int(drop_m.group(1)) > 0:
            drops = int(drop_m.group(1))
            sev = "P2" if drops > 1000 else "P3"
            events.append(Event(
                source_type="cli",
                severity=sev,
                message=f"Interface {iface} has {drops:,} output drops — possible congestion",
                raw=block[:300],
                device=device,
                interface=iface,
                facility="CLI",
                mnemonic="OUTPUT_DROPS",
                metadata={"output_drops": drops},
            ))

        # Half duplex in show output
        duplex_m = _DUPLEX_SHOW_RE.search(block)
        if duplex_m and duplex_m.group(1).lower() == "half":
            events.append(Event(
                source_type="cli",
                severity="P2",
                message=f"Interface {iface} operating at half-duplex — performance severely degraded",
                raw=block[:300],
                device=device,
                interface=iface,
                facility="CLI",
                mnemonic="HALF_DUPLEX_ACTIVE",
                metadata={"duplex": "half", "speed": duplex_m.group(2)},
            ))

    return events


def _parse_bgp_summary(text: str, device: Optional[str]) -> list[Event]:
    events: list[Event] = []
    in_table = False

    for line in text.splitlines():
        if _BGP_SUMMARY_HEADER_RE.search(line):
            in_table = True
            continue
        if not in_table:
            continue

        m = _BGP_NEIGHBOR_ROW_RE.match(line.strip())
        if not m:
            continue
        neighbor = m.group(1)
        remote_as = m.group(2)
        msg_rcvd = int(m.group(3))
        msg_sent = int(m.group(4))
        updown = m.group(5)

        # Neighbour recently reset (low updown counter suggests instability)
        # In BGP summary "Up/Down" is a time string in the last column
        # A numeric value could mean it's not fully established
        if msg_rcvd == 0 and msg_sent == 0:
            events.append(Event(
                source_type="cli",
                severity="P1",
                message=f"BGP neighbor {neighbor} (AS {remote_as}) — no messages exchanged, session may be down",
                raw=line,
                device=device,
                facility="CLI",
                mnemonic="BGP_NEIGHBOR_DOWN",
                metadata={"neighbor": neighbor, "remote_as": remote_as},
            ))

    return events


def _parse_ospf_neighbors(text: str, device: Optional[str]) -> list[Event]:
    events: list[Event] = []
    for m in _OSPF_NEIGHBOR_RE.finditer(text):
        neighbor = m.group(1)
        state = m.group(2).upper()
        if state != "FULL":
            sev = "P1" if state in ("DOWN", "INIT", "ATTEMPT") else "P2"
            events.append(Event(
                source_type="cli",
                severity=sev,
                message=f"OSPF neighbor {neighbor} in non-FULL state: {state}",
                raw=m.group(0),
                device=device,
                facility="CLI",
                mnemonic=f"OSPF_NEIGHBOR_{state}",
                metadata={"neighbor": neighbor, "state": state},
            ))
    return events


def parse_cli_output(source: str | Path, device: Optional[str] = None,
                     command: Optional[str] = None) -> list[Event]:
    """Parse 'show' command output into Events.

    Args:
        source: Path to a file containing show command output, or raw text.
        device: Device hostname.
        command: The show command that produced this output (auto-detected if None).
    """
    if isinstance(source, Path) or (
        isinstance(source, str) and "\n" not in str(source) and Path(str(source)).exists()
    ):
        path = Path(str(source))
        if path.exists():
            text = path.read_text(errors="replace")
        else:
            text = str(source)
    else:
        text = str(source)

    detected = command or _detect_command(text)

    # Store the full output as context for the LLM
    events: list[Event] = [Event(
        source_type="cli",
        severity="INFO",
        message=f"CLI output ({detected}): {len(text.splitlines())} lines",
        raw=text,
        device=device,
        facility="CLI",
        mnemonic="CLI_OUTPUT",
        metadata={"command": detected, "line_count": len(text.splitlines())},
    )]

    if detected == "show_interfaces":
        events.extend(_parse_show_interfaces(text, device))
    elif detected == "show_ip_bgp_summary":
        events.extend(_parse_bgp_summary(text, device))
    elif detected == "show_ip_ospf_neighbor":
        events.extend(_parse_ospf_neighbors(text, device))
    else:
        # Generic: look for common error keywords
        for lineno, line in enumerate(text.splitlines(), 1):
            if re.search(r"\b(error|fail|down|reset|timeout|flap)\b", line, re.IGNORECASE):
                events.append(Event(
                    source_type="cli",
                    severity="P3",
                    message=f"Potential issue detected (line {lineno}): {line.strip()[:150]}",
                    raw=line,
                    device=device,
                    facility="CLI",
                    mnemonic="CLI_ANOMALY",
                    metadata={"line": lineno, "command": detected},
                ))

    return events
