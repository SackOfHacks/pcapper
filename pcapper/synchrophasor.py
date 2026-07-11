from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float, memoize_analysis

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = IPv6 = Raw = None  # type: ignore

# IEEE C37.118 synchrophasor (PMU/PDC) — power-transmission grid monitoring and
# protection. Standard ports are TCP/UDP 4712 (some deployments add 4713). The
# frame begins with sync byte 0xAA; the second byte carries the frame type in
# bits 6-4 and the protocol version in bits 3-0.
SYNCHROPHASOR_PORTS = {4712, 4713}
SYNC_BYTE = 0xAA

C37118_FRAME_TYPES = {
    0: "Data",
    1: "Header",
    2: "Config-1",
    3: "Config-2",
    4: "Command",
    5: "Config-3",
}

# Command-frame CMD field (offset 14, 2 bytes). Turning OFF data transmission
# blinds grid operators/PDCs; reconfiguration commands change PMU behaviour.
C37118_COMMANDS = {
    1: "Turn OFF data transmission",
    2: "Turn ON data transmission",
    3: "Send HDR frame",
    4: "Send CFG-1 frame",
    5: "Send CFG-2 frame",
    6: "Send CFG-3 frame",
    8: "Extended frame",
}
# CMD values that disrupt monitoring (data off) or reconfigure the PMU.
_C37118_DISRUPTIVE_CMDS = {1}


@dataclass(frozen=True)
class SynchrophasorSummary:
    path: Path
    total_packets: int
    synchrophasor_packets: int
    frame_types: Counter[str]
    id_codes: Counter[int]
    commands: Counter[str]
    src_ips: Counter[str]
    dst_ips: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _looks_like_c37118(payload: bytes) -> Optional[int]:
    """Return the frame type if the payload is a plausible C37.118 frame, else None."""
    if len(payload) < 14:
        return None
    if payload[0] != SYNC_BYTE:
        return None
    frame_byte = payload[1]
    if frame_byte & 0x80:  # top bit is reserved/0 in C37.118
        return None
    frame_type = (frame_byte >> 4) & 0x07
    if frame_type not in C37118_FRAME_TYPES:
        return None
    framesize = int.from_bytes(payload[2:4], "big")
    # Framesize must be at least the fixed header+CRC and not absurd; allow the
    # captured payload to be >= the declared size (TCP may coalesce frames).
    if framesize < 14 or framesize > 65535:
        return None
    return frame_type


@memoize_analysis
def analyze_synchrophasor(
    path: Path, show_status: bool = True
) -> SynchrophasorSummary:
    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return SynchrophasorSummary(
            path=path,
            total_packets=0,
            synchrophasor_packets=0,
            frame_types=Counter(),
            id_codes=Counter(),
            commands=Counter(),
            src_ips=Counter(),
            dst_ips=Counter(),
            detections=[],
            errors=[f"{type(exc).__name__}: {exc}"],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    synchrophasor_packets = 0
    frame_types: Counter[str] = Counter()
    id_codes: Counter[int] = Counter()
    commands: Counter[str] = Counter()
    src_ips: Counter[str] = Counter()
    dst_ips: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    command_sources: dict[str, Counter[str]] = {}

    if TCP is None:
        return SynchrophasorSummary(
            path=path,
            total_packets=0,
            synchrophasor_packets=0,
            frame_types=frame_types,
            id_codes=id_codes,
            commands=commands,
            src_ips=src_ips,
            dst_ips=dst_ips,
            detections=detections,
            errors=["Scapy TCP/UDP unavailable"],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            l4 = None
            if pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                l4 = pkt[TCP]  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                l4 = pkt[UDP]  # type: ignore[index]
            if l4 is None:
                continue
            sport = int(getattr(l4, "sport", 0) or 0)
            dport = int(getattr(l4, "dport", 0) or 0)
            on_port = bool({sport, dport} & SYNCHROPHASOR_PORTS)

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw].load)  # type: ignore[index]
                except Exception:
                    payload = b""
            if not payload:
                continue

            frame_type = _looks_like_c37118(payload)
            # Require either the standard port or a strong signature to avoid
            # matching unrelated traffic that happens to start with 0xAA.
            if frame_type is None or not on_port:
                continue

            synchrophasor_packets += 1
            frame_types[C37118_FRAME_TYPES[frame_type]] += 1
            id_codes[int.from_bytes(payload[4:6], "big")] += 1

            src_ip = ""
            dst_ip = ""
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IP].src)  # type: ignore[index]
                dst_ip = str(pkt[IP].dst)  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IPv6].src)  # type: ignore[index]
                dst_ip = str(pkt[IPv6].dst)  # type: ignore[index]
            if src_ip:
                src_ips[src_ip] += 1
            if dst_ip:
                dst_ips[dst_ip] += 1

            # Command frame: decode the CMD field at offset 14.
            if frame_type == 4 and len(payload) >= 16:
                cmd_val = int.from_bytes(payload[14:16], "big")
                cmd_name = C37118_COMMANDS.get(cmd_val, f"CMD 0x{cmd_val:04x}")
                commands[cmd_name] += 1
                command_sources.setdefault(src_ip or "?", Counter())[cmd_name] += 1
    except Exception as exc:
        errors.append(str(exc))
    finally:
        try:
            status.finish()
        except Exception:
            pass
        try:
            reader.close()
        except Exception:
            pass

    # A command to turn OFF data transmission stops the PMU stream a PDC/operator
    # relies on — a denial-of-view against grid monitoring/protection.
    for src, cmds in command_sources.items():
        disruptive = [
            C37118_COMMANDS[c]
            for c in _C37118_DISRUPTIVE_CMDS
            if C37118_COMMANDS[c] in cmds
        ]
        if disruptive:
            detections.append(
                {
                    "severity": "high",
                    "summary": "Synchrophasor data-transmission disabled (denial of view)",
                    "details": (
                        f"{src} sent C37.118 command(s) {', '.join(disruptive)} — "
                        "stops the PMU stream relied on by PDCs/operators for grid "
                        "monitoring and protection (ATT&CK ICS T0804 Block Reporting "
                        "Message / T0814 Denial of View; Industroyer technique)."
                    ),
                    "source": "Synchrophasor",
                }
            )
    if commands:
        detections.append(
            {
                "severity": "warning",
                "summary": "Synchrophasor command frames observed",
                "details": (
                    "C37.118 command frames to PMU(s): "
                    + ", ".join(
                        f"{name} (x{count})" for name, count in commands.most_common(6)
                    )
                    + ". Confirm these originate from an authorized PDC/control host "
                    "(ATT&CK ICS T0855 Unauthorized Command Message)."
                ),
                "source": "Synchrophasor",
            }
        )

    public_endpoints = []
    for ip_value in set(src_ips) | set(dst_ips):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints:
        detections.append(
            {
                "severity": "high",
                "summary": "Synchrophasor (C37.118) exposure to public IP",
                "details": (
                    "C37.118 PMU/PDC traffic with public endpoint(s): "
                    + ", ".join(sorted(public_endpoints)[:5])
                ),
                "source": "Synchrophasor",
            }
        )
    if synchrophasor_packets and not commands:
        detections.append(
            {
                "severity": "info",
                "summary": "IEEE C37.118 synchrophasor traffic observed",
                "details": (
                    f"{synchrophasor_packets} C37.118 frames across "
                    f"{len(id_codes)} PMU/PDC ID code(s)."
                ),
                "source": "Synchrophasor",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return SynchrophasorSummary(
        path=path,
        total_packets=total_packets,
        synchrophasor_packets=synchrophasor_packets,
        frame_types=frame_types,
        id_codes=id_codes,
        commands=commands,
        src_ips=src_ips,
        dst_ips=dst_ips,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
