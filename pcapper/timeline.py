from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import detect_file_type, safe_float
from .files import analyze_files

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore


@dataclass(frozen=True)
class TimelineEvent:
    ts: Optional[float]
    category: str
    summary: str
    details: str


@dataclass(frozen=True)
class TimelineSummary:
    path: Path
    target_ip: str
    total_packets: int
    events: list[TimelineEvent]
    errors: list[str]


def analyze_timeline(path: Path, target_ip: str, show_status: bool = True) -> TimelineSummary:
    errors: list[str] = []
    events: list[TimelineEvent] = []

    file_summary = analyze_files(path, show_status=False)
    artifacts_for_ip = [
        art for art in file_summary.artifacts
        if art.src_ip == target_ip or art.dst_ip == target_ip
    ]
    artifact_indices = {art.packet_index for art in artifacts_for_ip if art.packet_index}

    file_type = detect_file_type(path)
    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))

    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        pass

    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    total_packets = 0
    idx = 0
    index_ts: dict[int, float] = {}
    seen_udp_flows: set[tuple[str, int]] = set()
    seen_domain_flows: set[tuple[str, int, str, str]] = set()
    seen_ldap_flows: set[tuple[str, int, str, str]] = set()
    scan_ports: dict[str, set[int]] = defaultdict(set)
    scan_first: dict[str, float] = {}
    scan_last: dict[str, float] = {}

    domain_ports = {88, 464, 445, 139, 135, 593, 3268, 3269}
    ldap_ports = {389, 636, 3268, 3269}

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            idx += 1
            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

            if idx in artifact_indices and ts is not None:
                index_ts[idx] = ts

            if not src_ip or not dst_ip:
                continue

            if DNS is not None and DNSQR is not None and pkt.haslayer(DNS):  # type: ignore[truthy-bool]
                dns_layer = pkt[DNS]  # type: ignore[index]
                if getattr(dns_layer, "qr", 1) == 0 and src_ip == target_ip:
                    try:
                        qd = dns_layer.qd  # type: ignore[attr-defined]
                        qname = getattr(qd, "qname", b"")
                        qtype = getattr(qd, "qtype", None)
                        name = qname.decode("utf-8", errors="ignore").rstrip(".") if isinstance(qname, (bytes, bytearray)) else str(qname)
                        events.append(TimelineEvent(
                            ts=ts,
                            category="DNS",
                            summary="DNS query",
                            details=f"{target_ip} queried {name} (type {qtype})",
                        ))
                        qname_lower = name.lower()
                        if any(token in qname_lower for token in ("_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_msdcs")):
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service discovery",
                                details=f"{target_ip} queried {name}",
                            ))
                    except Exception:
                        pass

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                flags = getattr(tcp_layer, "flags", None)
                is_syn = False
                if isinstance(flags, str):
                    is_syn = "S" in flags and "A" not in flags
                elif isinstance(flags, int):
                    is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0
                if src_ip == target_ip:
                    dport = int(getattr(tcp_layer, "dport", 0) or 0)
                    payload = None
                    try:
                        payload = bytes(tcp_layer.payload)
                    except Exception:
                        payload = None
                    if payload and payload.startswith(b"POST "):
                        try:
                            line = payload.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
                            host = "-"
                            for header in payload.split(b"\r\n"):
                                if header.lower().startswith(b"host:"):
                                    host = header.decode("latin-1", errors="ignore").split(":", 1)[1].strip()
                                    break
                            events.append(TimelineEvent(
                                ts=ts,
                                category="HTTP",
                                summary="HTTP POST",
                                details=f"{target_ip} -> {dst_ip}:{dport} {line} Host: {host}",
                            ))
                        except Exception:
                            events.append(TimelineEvent(
                                ts=ts,
                                category="HTTP",
                                summary="HTTP POST",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                    if dport in ldap_ports:
                        key = (dst_ip, dport, "TCP", "outbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP connection",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                    if dport in domain_ports:
                        key = (dst_ip, dport, "TCP", "outbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service access",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                    if is_syn and dport:
                        events.append(TimelineEvent(
                            ts=ts,
                            category="Connection",
                            summary="TCP connect attempt",
                            details=f"{target_ip} -> {dst_ip}:{dport} (SYN)",
                        ))
                        scan_ports[dst_ip].add(dport)
                        if ts is not None:
                            scan_first.setdefault(dst_ip, ts)
                            scan_last[dst_ip] = ts
                elif dst_ip == target_ip:
                    sport = int(getattr(tcp_layer, "sport", 0) or 0)
                    if sport in ldap_ports:
                        key = (src_ip, sport, "TCP", "inbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP connection",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
                    if sport in domain_ports:
                        key = (src_ip, sport, "TCP", "inbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service access",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                if src_ip == target_ip:
                    dport = int(getattr(udp_layer, "dport", 0) or 0)
                    if dport:
                        key = (dst_ip, dport)
                        if key not in seen_udp_flows:
                            seen_udp_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="Connection",
                                summary="UDP flow",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                        if dport in ldap_ports:
                            key = (dst_ip, dport, "UDP", "outbound")
                            if key not in seen_ldap_flows:
                                seen_ldap_flows.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="LDAP",
                                    summary="LDAP activity",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                ))
                        if dport in domain_ports:
                            key = (dst_ip, dport, "UDP", "outbound")
                            if key not in seen_domain_flows:
                                seen_domain_flows.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="MS Domain",
                                    summary="Domain service activity",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                ))
                elif dst_ip == target_ip:
                    sport = int(getattr(udp_layer, "sport", 0) or 0)
                    if sport in ldap_ports:
                        key = (src_ip, sport, "UDP", "inbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP activity",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
                    if sport in domain_ports:
                        key = (src_ip, sport, "UDP", "inbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service activity",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
    finally:
        status.finish()
        reader.close()

    for art in artifacts_for_ip:
        ts = index_ts.get(art.packet_index)
        details = f"{art.protocol} {art.filename} ({art.file_type}) {art.src_ip} -> {art.dst_ip}"
        category = "File Transfer"
        if art.protocol.upper().startswith("SMB"):
            category = "SMB"
        events.append(TimelineEvent(
            ts=ts,
            category=category,
            summary="File artifact",
            details=details,
        ))

    for dst_ip, ports in scan_ports.items():
        if len(ports) >= 100:
            first = scan_first.get(dst_ip)
            last = scan_last.get(dst_ip, first)
            duration = "-"
            if first is not None and last is not None:
                duration = f"{max(0.0, last - first):.1f}s"
            events.append(TimelineEvent(
                ts=last,
                category="Recon",
                summary="Potential port scan",
                details=f"{target_ip} -> {dst_ip} touched {len(ports)} ports over {duration}",
            ))

    events.sort(key=lambda item: (item.ts is None, item.ts))

    return TimelineSummary(
        path=path,
        target_ip=target_ip,
        total_packets=total_packets,
        events=events,
        errors=errors + file_summary.errors,
    )
