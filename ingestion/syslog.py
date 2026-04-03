"""Parse Cisco syslog files or live syslog streams into normalised Events."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from models import (
    Event,
    CISCO_SEV_TO_PRIORITY,
    CRITICAL_FACILITIES,
)

# Cisco syslog line formats
# Format 1: timestamp device %FAC-SEV-MNEM: message
# e.g.  Apr  1 12:34:56 router1 %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/0, changed state to down
_FULL_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?\s+"
    r"(?P<device>\S+)\s+"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<message>.+)"
)

# Format 2: no device, just %FAC-SEV-MNEM: message
_BARE_RE = re.compile(
    r"(?:(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+)?"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<message>.+)"
)

# Interface names in messages
_INTERFACE_RE = re.compile(
    r"\b(GigabitEthernet|FastEthernet|TenGigabitEthernet|TwentyFiveGigE|"
    r"FortyGigabitEthernet|HundredGigE|Loopback|Tunnel|Serial|Vlan|"
    r"Port-channel|Gi|Fa|Te|Tw|Fo|Hu|Lo|Tu|Se|Vl|Po)"
    r"[\d/.:]+",
    re.IGNORECASE,
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(month: Optional[str], day: Optional[str],
                     time_str: Optional[str]) -> Optional[datetime]:
    if not (month and day and time_str):
        return None
    try:
        m = _MONTHS.get(month[:3].capitalize(), 0)
        if not m:
            return None
        h, mi, s = (int(x) for x in time_str.split(":"))
        year = datetime.now().year
        return datetime(year, m, int(day), h, mi, s)
    except (ValueError, AttributeError):
        return None


def _severity_to_priority(cisco_sev: int, facility: str) -> str:
    priority = CISCO_SEV_TO_PRIORITY.get(cisco_sev, "INFO")
    # Escalate errors (3) to P1 for critical facilities
    if cisco_sev == 3 and facility.upper() in CRITICAL_FACILITIES:
        priority = "P1"
    return priority


def _extract_interface(message: str) -> Optional[str]:
    m = _INTERFACE_RE.search(message)
    return m.group(0) if m else None


def _parse_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None

    for pattern in (_FULL_RE, _BARE_RE):
        m = pattern.match(line)
        if not m:
            continue
        gd = m.groupdict()
        facility = gd["facility"].upper()
        sev_num = int(gd["severity"])
        mnemonic = gd["mnemonic"].upper()
        message = gd["message"].strip()
        device = gd.get("device")
        ts = _parse_timestamp(gd.get("month"), gd.get("day"), gd.get("time"))

        priority = _severity_to_priority(sev_num, facility)
        interface = _extract_interface(message)

        return Event(
            source_type="syslog",
            severity=priority,
            message=f"{facility}-{sev_num}-{mnemonic}: {message}",
            raw=line,
            timestamp=ts,
            device=device,
            facility=facility,
            mnemonic=mnemonic,
            interface=interface,
            metadata={
                "cisco_severity": sev_num,
                "cisco_facility": facility,
                "cisco_mnemonic": mnemonic,
            },
        )

    # Non-Cisco line — keep as INFO if it looks meaningful
    if len(line) > 10 and not line.startswith("#"):
        return Event(
            source_type="syslog",
            severity="INFO",
            message=line[:200],
            raw=line,
        )
    return None


def parse_syslog(source: str | Path) -> list[Event]:
    """Parse a syslog file or raw syslog text into Events.

    Args:
        source: Path to a syslog file, or a multi-line string of syslog data.
    """
    if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source):
        path = Path(source)
        if path.exists():
            text = path.read_text(errors="replace")
        else:
            text = str(source)
    else:
        text = source

    events: list[Event] = []
    for line in text.splitlines():
        event = _parse_line(line)
        if event:
            events.append(event)

    return sorted(events)
