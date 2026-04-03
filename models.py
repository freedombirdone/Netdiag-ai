"""Common data models shared across the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


SEVERITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "INFO": 3}

# Cisco syslog numeric severity → NOC priority
CISCO_SEV_TO_PRIORITY = {
    0: "P1",  # Emergency
    1: "P1",  # Alert
    2: "P1",  # Critical
    3: "P2",  # Error
    4: "P2",  # Warning
    5: "P3",  # Notification
    6: "INFO",  # Informational
    7: "INFO",  # Debugging
}

# Facilities that escalate errors to P1
CRITICAL_FACILITIES = {
    "OSPF", "BGP", "EIGRP", "ISIS", "PIM", "MPLS",
    "LINEPROTO", "LINK", "HSRP", "VRRP", "REDUNDANCY",
    "SYS", "FW", "SEC",
}


@dataclass
class Event:
    """Normalised event from any input source."""
    source_type: str          # "syslog" | "config" | "pcap" | "cli"
    severity: str             # "P1" | "P2" | "P3" | "INFO"
    message: str              # Human-readable summary
    raw: str                  # Original text
    timestamp: Optional[datetime] = None
    device: Optional[str] = None
    facility: Optional[str] = None    # Cisco facility (LINEPROTO, BGP, …)
    mnemonic: Optional[str] = None    # Cisco mnemonic (UPDOWN, ADJCHG, …)
    interface: Optional[str] = None   # Affected interface if known
    metadata: dict = field(default_factory=dict)

    def __lt__(self, other: "Event") -> bool:
        ts_self = self.timestamp or datetime.min
        ts_other = other.timestamp or datetime.min
        return ts_self < ts_other


@dataclass
class CorrelatedGroup:
    """A set of events that appear to share a root cause."""
    events: list[Event]
    correlation_reason: str
    overall_severity: str

    @property
    def devices(self) -> list[str]:
        return sorted({e.device for e in self.events if e.device})

    @property
    def interfaces(self) -> list[str]:
        return sorted({e.interface for e in self.events if e.interface})

    @property
    def timespan(self) -> Optional[str]:
        ts = [e.timestamp for e in self.events if e.timestamp]
        if not ts:
            return None
        lo, hi = min(ts), max(ts)
        if lo == hi:
            return lo.strftime("%H:%M:%S")
        return f"{lo.strftime('%H:%M:%S')} – {hi.strftime('%H:%M:%S')}"


@dataclass
class DiagnosisResult:
    """Structured output from the LLM."""
    diagnosis: str
    root_cause: str
    severity: str
    affected_devices: list[str]
    affected_interfaces: list[str]
    remediation: list[dict]    # [{device, commands, description}]
    verification: list[str]    # show commands
    correlations: list[str]
    raw_response: str
