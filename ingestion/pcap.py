"""Parse .pcap files and extract network anomalies as Events.

Requires pyshark (pip install pyshark) or scapy (pip install scapy).
Falls back to a stub if neither is installed.
"""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

from models import Event


def _try_pyshark(pcap_path: str, device: Optional[str]) -> list[Event]:
    import pyshark  # type: ignore

    events: list[Event] = []
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)

    # Counters
    total = 0
    retransmits = 0
    syn_count = 0
    tcp_errors = 0
    icmp_unreach = 0
    proto_counter: Counter = Counter()
    src_dst_counter: Counter = Counter()

    capture_start = None
    capture_end = None

    try:
        for pkt in cap:
            total += 1
            try:
                ts = float(pkt.sniff_timestamp)
                if capture_start is None:
                    capture_start = ts
                capture_end = ts

                if hasattr(pkt, "tcp"):
                    proto_counter["TCP"] += 1
                    flags = int(pkt.tcp.flags, 16) if hasattr(pkt.tcp, "flags") else 0
                    # SYN without ACK
                    if flags & 0x02 and not (flags & 0x10):
                        syn_count += 1
                    # TCP retransmission: analysis.retransmission
                    if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "analysis_retransmission"):
                        retransmits += 1
                    # RST
                    if flags & 0x04:
                        tcp_errors += 1
                    src = getattr(pkt.ip, "src", "?") if hasattr(pkt, "ip") else "?"
                    dst = getattr(pkt.ip, "dst", "?") if hasattr(pkt, "ip") else "?"
                    src_dst_counter[(src, dst)] += 1

                elif hasattr(pkt, "udp"):
                    proto_counter["UDP"] += 1
                elif hasattr(pkt, "icmp"):
                    proto_counter["ICMP"] += 1
                    icmp_type = int(getattr(pkt.icmp, "type", -1))
                    if icmp_type == 3:  # Destination unreachable
                        icmp_unreach += 1
                elif hasattr(pkt, "ip"):
                    proto_counter["Other"] += 1
            except Exception:
                pass
    finally:
        cap.close()

    if total == 0:
        return events

    duration = (capture_end - capture_start) if capture_start and capture_end else 1.0
    syn_rate = syn_count / max(duration, 1)
    retransmit_pct = (retransmits / total) * 100

    # Flag anomalies
    if retransmit_pct > 5:
        sev = "P1" if retransmit_pct > 20 else "P2"
        events.append(Event(
            source_type="pcap",
            severity=sev,
            message=f"High TCP retransmission rate: {retransmit_pct:.1f}% ({retransmits}/{total} packets)",
            raw=f"pcap:{pcap_path}",
            device=device,
            facility="PCAP",
            mnemonic="HIGH_RETRANSMIT",
            metadata={"retransmit_pct": retransmit_pct, "retransmits": retransmits, "total": total},
        ))

    if syn_rate > 100:
        events.append(Event(
            source_type="pcap",
            severity="P1",
            message=f"Potential SYN flood: {syn_rate:.0f} SYN packets/sec detected",
            raw=f"pcap:{pcap_path}",
            device=device,
            facility="PCAP",
            mnemonic="SYN_FLOOD",
            metadata={"syn_rate": syn_rate, "syn_count": syn_count, "duration": duration},
        ))

    if tcp_errors > 0:
        rst_pct = (tcp_errors / total) * 100
        if rst_pct > 2:
            events.append(Event(
                source_type="pcap",
                severity="P2",
                message=f"Elevated TCP RST rate: {rst_pct:.1f}% of traffic ({tcp_errors} RSTs)",
                raw=f"pcap:{pcap_path}",
                device=device,
                facility="PCAP",
                mnemonic="HIGH_RST_RATE",
                metadata={"rst_pct": rst_pct, "rst_count": tcp_errors},
            ))

    if icmp_unreach > 10:
        events.append(Event(
            source_type="pcap",
            severity="P2",
            message=f"ICMP destination unreachable messages detected: {icmp_unreach} packets",
            raw=f"pcap:{pcap_path}",
            device=device,
            facility="PCAP",
            mnemonic="ICMP_UNREACH",
            metadata={"icmp_unreach": icmp_unreach},
        ))

    # Top talkers
    top_pairs = src_dst_counter.most_common(5)
    if top_pairs:
        talkers = ", ".join(f"{s}→{d}({c})" for (s, d), c in top_pairs)
        events.append(Event(
            source_type="pcap",
            severity="INFO",
            message=f"Top traffic flows: {talkers}",
            raw=f"pcap:{pcap_path}",
            device=device,
            facility="PCAP",
            mnemonic="TOP_TALKERS",
            metadata={"top_flows": [{"src": s, "dst": d, "packets": c} for (s, d), c in top_pairs]},
        ))

    # Summary
    events.append(Event(
        source_type="pcap",
        severity="INFO",
        message=(
            f"PCAP summary: {total} packets over {duration:.0f}s — "
            f"TCP:{proto_counter['TCP']} UDP:{proto_counter['UDP']} "
            f"ICMP:{proto_counter['ICMP']} Other:{proto_counter['Other']}"
        ),
        raw=f"pcap:{pcap_path}",
        device=device,
        facility="PCAP",
        mnemonic="PCAP_SUMMARY",
        metadata={
            "total_packets": total,
            "duration_seconds": duration,
            "protocols": dict(proto_counter),
        },
    ))

    return events


def _try_scapy(pcap_path: str, device: Optional[str]) -> list[Event]:
    from scapy.all import rdpcap, TCP, UDP, ICMP, IP  # type: ignore

    events: list[Event] = []
    packets = rdpcap(pcap_path)
    total = len(packets)

    if total == 0:
        return events

    retransmits = 0
    syn_count = 0
    rst_count = 0
    icmp_unreach = 0
    src_dst: Counter = Counter()

    seq_seen: dict = defaultdict(set)
    timestamps = [float(p.time) for p in packets if hasattr(p, "time")]
    duration = (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 1.0

    for pkt in packets:
        if TCP in pkt:
            flags = pkt[TCP].flags
            seq = pkt[TCP].seq
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            src = pkt[IP].src if IP in pkt else "?"
            dst = pkt[IP].dst if IP in pkt else "?"
            src_dst[(src, dst)] += 1

            if flags & 0x02 and not (flags & 0x10):
                syn_count += 1
            if flags & 0x04:
                rst_count += 1
            key = (src, dst, sport, dport)
            if seq in seq_seen[key]:
                retransmits += 1
            seq_seen[key].add(seq)

        if ICMP in pkt:
            if pkt[ICMP].type == 3:
                icmp_unreach += 1

    retransmit_pct = (retransmits / total) * 100
    syn_rate = syn_count / max(duration, 1)

    if retransmit_pct > 5:
        sev = "P1" if retransmit_pct > 20 else "P2"
        events.append(Event(
            source_type="pcap",
            severity=sev,
            message=f"High TCP retransmission rate: {retransmit_pct:.1f}%",
            raw=f"pcap:{pcap_path}",
            device=device,
            facility="PCAP",
            mnemonic="HIGH_RETRANSMIT",
            metadata={"retransmit_pct": retransmit_pct},
        ))

    if syn_rate > 100:
        events.append(Event(
            source_type="pcap",
            severity="P1",
            message=f"Potential SYN flood: {syn_rate:.0f} SYN/sec",
            raw=f"pcap:{pcap_path}",
            device=device,
            facility="PCAP",
            mnemonic="SYN_FLOOD",
            metadata={"syn_rate": syn_rate},
        ))

    events.append(Event(
        source_type="pcap",
        severity="INFO",
        message=f"PCAP summary: {total} packets, {duration:.0f}s capture",
        raw=f"pcap:{pcap_path}",
        device=device,
        facility="PCAP",
        mnemonic="PCAP_SUMMARY",
        metadata={"total_packets": total, "duration_seconds": duration},
    ))

    return events


def parse_pcap(source: str | Path, device: Optional[str] = None) -> list[Event]:
    """Parse a pcap file and return anomaly Events.

    Args:
        source: Path to .pcap or .pcapng file.
        device: Device hostname to associate with events.
    """
    pcap_path = str(source)
    if not os.path.exists(pcap_path):
        return [Event(
            source_type="pcap",
            severity="P3",
            message=f"PCAP file not found: {pcap_path}",
            raw=pcap_path,
            device=device,
            facility="PCAP",
            mnemonic="FILE_NOT_FOUND",
        )]

    # Try pyshark first, then scapy, then stub
    try:
        return _try_pyshark(pcap_path, device)
    except ImportError:
        pass

    try:
        return _try_scapy(pcap_path, device)
    except ImportError:
        pass

    # Stub when no pcap library installed
    return [Event(
        source_type="pcap",
        severity="P3",
        message=(
            f"PCAP file present ({os.path.getsize(pcap_path):,} bytes) but no pcap "
            "library installed. Install pyshark or scapy for full analysis."
        ),
        raw=pcap_path,
        device=device,
        facility="PCAP",
        mnemonic="NO_PCAP_LIB",
        metadata={"file_size": os.path.getsize(pcap_path)},
    )]
