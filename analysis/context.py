"""Build the LLM prompt from ingested events and correlation data."""
from __future__ import annotations

from models import Event, CorrelatedGroup, SEVERITY_ORDER


SYSTEM_PROMPT = """\
You are an expert Cisco network engineer and NOC analyst with deep knowledge of:

- Cisco IOS, IOS-XE, NX-OS, and IOS-XR
- Syslog message codes and their meanings (e.g. %LINEPROTO-5-UPDOWN, %BGP-5-ADJCHG, %OSPF-5-ADJCHG)
- Cisco interface states, error counters, and what they indicate
- BGP, OSPF, EIGRP, ISIS routing protocols and their failure modes
- STP, HSRP, VRRP, port-channels and redundancy issues
- Common misconfigurations: duplex mismatches, MTU mismatches, wrong ACLs, missing summarization
- Cisco show command outputs and how to interpret them
- PCAP analysis and what traffic anomalies mean at the network layer

Your task is to analyse the provided network events from one or more sources (syslog, device config, \
packet capture, CLI show commands), diagnose the root cause, determine severity, and provide \
actionable remediation commands.

IMPORTANT:
- Be specific about device names, interface names, and IP addresses where available
- When events from multiple sources correlate, explain the connection
- Always provide exact Cisco IOS commands for remediation
- Classify overall severity as P1 (outage/critical), P2 (degraded/at-risk), or P3 (warning/advisory)
- After remediation commands, provide verification commands to confirm the fix worked
- Output valid JSON in the exact schema specified

Common Cisco syslog severity levels you will encounter:
- %FACILITY-0/1/2-MNEM: Emergency/Alert/Critical → always P1
- %FACILITY-3-MNEM: Error → P1 for critical facilities (LINEPROTO, BGP, OSPF, HSRP), P2 otherwise
- %FACILITY-4-MNEM: Warning → P2
- %FACILITY-5-MNEM: Notification → P3
- %FACILITY-6/7-MNEM: Informational/Debug → INFO

Key mnemonics to know:
- LINEPROTO-5-UPDOWN: Interface line protocol changed state (often duplex/speed mismatch)
- BGP-5-ADJCHG: BGP adjacency state change
- OSPF-5-ADJCHG: OSPF adjacency state change
- SYS-5-CONFIG_I: Configuration change via console/VTY
- LINK-3-UPDOWN: Interface physical layer state change
- HSRP-5-STATECHANGE: HSRP state transition
- CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch on trunk
- SPANTREE-2-RECV_PVID_ERR: STP PVID error / trunk misconfiguration
"""


def _format_event(e: Event, idx: int) -> str:
    parts = [f"[{idx}] [{e.source_type.upper()}][{e.severity}]"]
    if e.timestamp:
        parts.append(e.timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    if e.device:
        parts.append(f"device={e.device}")
    if e.interface:
        parts.append(f"iface={e.interface}")
    if e.facility and e.mnemonic:
        parts.append(f"{e.facility}-{e.mnemonic}")
    parts.append(f"| {e.message}")
    return " ".join(parts)


def _summarise_correlation(group: CorrelatedGroup, group_idx: int) -> str:
    lines = [
        f"\nCORRELATION GROUP {group_idx} [{group.overall_severity}]: {group.correlation_reason}"
    ]
    if group.timespan:
        lines.append(f"  Timespan: {group.timespan}")
    if group.devices:
        lines.append(f"  Devices: {', '.join(group.devices)}")
    if group.interfaces:
        lines.append(f"  Interfaces: {', '.join(group.interfaces)}")
    lines.append(f"  Event count: {len(group.events)}")
    return "\n".join(lines)


def build_context(
    events: list[Event],
    correlated_groups: list[CorrelatedGroup],
    max_raw_chars: int = 8000,
) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) for the LLM.

    Args:
        events: All normalised events from all sources.
        correlated_groups: Output from correlator.
        max_raw_chars: Limit on raw config/CLI text included to avoid token bloat.

    Returns:
        (system_prompt, user_prompt)
    """
    # Count by severity
    sev_counts: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "INFO": 0}
    for e in events:
        sev_counts[e.severity] = sev_counts.get(e.severity, 0) + 1

    # Source type breakdown
    sources = {}
    for e in events:
        sources[e.source_type] = sources.get(e.source_type, 0) + 1

    # Sort events by severity then timestamp
    sorted_events = sorted(
        events,
        key=lambda e: (SEVERITY_ORDER.get(e.severity, 99), e.timestamp or __import__("datetime").datetime.min),
    )

    # Build event list — include all P1/P2, sample P3/INFO
    lines = ["=== NETWORK EVENTS ===\n"]
    included = []
    p3_info_budget = 20  # max P3/INFO to include in detail
    p3_info_count = 0

    for i, e in enumerate(sorted_events):
        if e.severity in ("P1", "P2"):
            included.append((i + 1, e))
        elif p3_info_count < p3_info_budget:
            included.append((i + 1, e))
            p3_info_count += 1

    for idx, e in included:
        lines.append(_format_event(e, idx))

    if len(sorted_events) > len(included):
        omitted = len(sorted_events) - len(included)
        lines.append(f"\n[...{omitted} additional INFO events omitted for brevity...]")

    # Correlation summary
    if correlated_groups:
        lines.append("\n\n=== CORRELATED INCIDENT GROUPS ===")
        for i, group in enumerate(correlated_groups[:10], 1):
            lines.append(_summarise_correlation(group, i))

    # Include raw config/CLI for context (truncated)
    raw_sections = []
    chars_used = 0
    for e in events:
        if e.mnemonic in ("FULL_CONFIG", "CLI_OUTPUT") and e.raw:
            remaining = max_raw_chars - chars_used
            if remaining <= 0:
                break
            snippet = e.raw[:remaining]
            label = f"device={e.device}" if e.device else "unknown"
            raw_sections.append(
                f"\n=== {e.mnemonic} ({label}) ===\n{snippet}"
                + ("...[truncated]" if len(e.raw) > remaining else "")
            )
            chars_used += len(snippet)

    # Summary header
    summary_parts = [
        f"Total events: {len(events)}",
        f"Severity breakdown: P1={sev_counts['P1']} P2={sev_counts['P2']} "
        f"P3={sev_counts['P3']} INFO={sev_counts['INFO']}",
        f"Input sources: {', '.join(f'{k}({v})' for k, v in sorted(sources.items()))}",
        f"Correlation groups: {len(correlated_groups)}",
    ]

    user_prompt = "\n".join([
        "=== INCIDENT SUMMARY ===",
        "\n".join(summary_parts),
        "",
        "\n".join(lines),
        *raw_sections,
        "",
        "=== ANALYSIS REQUEST ===",
        "Please analyse the above network events and provide your diagnosis as valid JSON "
        "matching this exact schema:",
        "",
        '```json',
        '{',
        '  "diagnosis": "<plain English explanation of what is happening>",',
        '  "root_cause": "<concise root cause in 1-2 sentences>",',
        '  "severity": "<P1|P2|P3>",',
        '  "affected_devices": ["<device1>", ...],',
        '  "affected_interfaces": ["<iface1>", ...],',
        '  "remediation": [',
        '    {',
        '      "device": "<hostname or \'all\'>",',
        '      "description": "<what this fixes>",',
        '      "commands": ["<ios command 1>", "<ios command 2>", ...]',
        '    }',
        '  ],',
        '  "verification": ["<show command 1>", "<show command 2>", ...],',
        '  "correlations": ["<correlation finding 1>", ...]',
        '}',
        '```',
        "",
        "Return ONLY the JSON block. No preamble, no explanation outside the JSON.",
    ])

    return SYSTEM_PROMPT, user_prompt
