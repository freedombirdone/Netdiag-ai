"""Cross-source event correlation: find events that share a root cause."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Optional

from models import Event, CorrelatedGroup, SEVERITY_ORDER


TIME_WINDOW = timedelta(seconds=300)


def _best_severity(events: list[Event]) -> str:
    best = "INFO"
    for e in events:
        if SEVERITY_ORDER.get(e.severity, 99) < SEVERITY_ORDER.get(best, 99):
            best = e.severity
    return best


def _correlate_by_interface(events: list[Event]) -> list[CorrelatedGroup]:
    """Group events that share a specific interface."""
    by_iface: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.interface:
            by_iface[e.interface].append(e)

    groups = []
    for iface, iface_events in by_iface.items():
        if len(iface_events) >= 2:
            sources = {e.source_type for e in iface_events}
            sev = _best_severity(iface_events)
            reason = (
                f"Multiple events on {iface} from sources: {', '.join(sorted(sources))}"
            )
            groups.append(CorrelatedGroup(
                events=sorted(iface_events),
                correlation_reason=reason,
                overall_severity=sev,
            ))
    return groups


def _correlate_by_device(events: list[Event]) -> list[CorrelatedGroup]:
    """Group events from the same device within the time window."""
    by_device: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.device:
            by_device[e.device].append(e)

    groups = []
    for device, dev_events in by_device.items():
        # Only group if multiple source types
        sources = {e.source_type for e in dev_events}
        if len(sources) >= 2 and len(dev_events) >= 2:
            sev = _best_severity(dev_events)
            groups.append(CorrelatedGroup(
                events=sorted(dev_events),
                correlation_reason=f"Multiple source types on {device}: {', '.join(sorted(sources))}",
                overall_severity=sev,
            ))
    return groups


def _correlate_temporal(events: list[Event]) -> list[CorrelatedGroup]:
    """Find bursts of P1/P2 events within the time window across sources."""
    timed = sorted(
        (e for e in events if e.timestamp and e.severity in ("P1", "P2")),
        key=lambda e: e.timestamp,
    )

    if len(timed) < 2:
        return []

    groups = []
    used: set[int] = set()

    for i, anchor in enumerate(timed):
        if i in used:
            continue
        cluster = [anchor]
        for j, other in enumerate(timed[i + 1:], i + 1):
            if j in used:
                continue
            if other.timestamp - anchor.timestamp <= TIME_WINDOW:
                cluster.append(other)
            else:
                break

        if len(cluster) >= 3:
            for idx in range(len(cluster)):
                used.add(i + idx)
            sev = _best_severity(cluster)
            sources = {e.source_type for e in cluster}
            span_s = (cluster[-1].timestamp - cluster[0].timestamp).seconds
            groups.append(CorrelatedGroup(
                events=cluster,
                correlation_reason=(
                    f"Burst of {len(cluster)} high-severity events over {span_s}s "
                    f"from: {', '.join(sorted(sources))}"
                ),
                overall_severity=sev,
            ))

    return groups


def _correlate_syslog_config(events: list[Event]) -> list[CorrelatedGroup]:
    """Specifically look for syslog events that match config anomalies."""
    syslog_ifaces = {e.interface: e for e in events
                     if e.source_type == "syslog" and e.interface}
    config_ifaces = {e.interface: e for e in events
                     if e.source_type == "config" and e.interface}

    overlap = set(syslog_ifaces) & set(config_ifaces)
    groups = []
    for iface in overlap:
        sl_event = syslog_ifaces[iface]
        cfg_event = config_ifaces[iface]
        # Only correlate if both are at least P3
        if sl_event.severity == "INFO" and cfg_event.severity == "INFO":
            continue
        sev = _best_severity([sl_event, cfg_event])
        groups.append(CorrelatedGroup(
            events=[sl_event, cfg_event],
            correlation_reason=(
                f"Syslog event on {iface} correlates with config issue on same interface"
            ),
            overall_severity=sev,
        ))
    return groups


def correlate_events(events: list[Event]) -> list[CorrelatedGroup]:
    """Run all correlation strategies and return deduplicated CorrelatedGroups.

    Events that don't fit any group are returned as individual single-event groups.
    """
    all_groups: list[CorrelatedGroup] = []
    all_groups.extend(_correlate_by_interface(events))
    all_groups.extend(_correlate_by_device(events))
    all_groups.extend(_correlate_temporal(events))
    all_groups.extend(_correlate_syslog_config(events))

    # Sort groups by severity
    all_groups.sort(key=lambda g: SEVERITY_ORDER.get(g.overall_severity, 99))

    return all_groups
