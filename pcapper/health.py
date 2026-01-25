from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import detect_file_type
from .certificates import analyze_certificates

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


@dataclass(frozen=True)
class HealthSummary:
    path: Path
    total_packets: int
    tcp_packets: int
    udp_packets: int
    retransmissions: int
    retransmission_rate: float
    ttl_expired: int
    ttl_low: int
    dscp_counts: Counter[int]
    ecn_counts: Counter[int]
    snmp_packets: int
    snmp_versions: Counter[str]
    snmp_communities: Counter[str]
    expired_certs: int
    self_signed_certs: int
    findings: list[dict[str, object]]
    errors: list[str]


def _read_ber_length(payload: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset >= len(payload):
        return None, offset
    first = payload[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(payload):
        return None, offset
    length = int.from_bytes(payload[offset:offset + num_bytes], "big")
    offset += num_bytes
    return length, offset


def _parse_snmp(payload: bytes) -> tuple[Optional[str], Optional[str]]:
    if not payload or payload[0] != 0x30:
        return None, None
    length, idx = _read_ber_length(payload, 1)
    if length is None or idx >= len(payload):
        return None, None
    if idx >= len(payload) or payload[idx] != 0x02:
        return None, None
    ver_len, idx = _read_ber_length(payload, idx + 1)
    if ver_len is None or idx + ver_len > len(payload):
        return None, None
    version_val = int.from_bytes(payload[idx:idx + ver_len], "big")
    idx += ver_len
    if idx >= len(payload) or payload[idx] != 0x04:
        return None, None
    comm_len, idx = _read_ber_length(payload, idx + 1)
    if comm_len is None or idx + comm_len > len(payload):
        return None, None
    community = payload[idx:idx + comm_len].decode("latin-1", errors="ignore")

    version_map = {0: "v1", 1: "v2c", 3: "v3"}
    return version_map.get(version_val, f"v{version_val}"), community


def analyze_health(path: Path, show_status: bool = True) -> HealthSummary:
    errors: list[str] = []

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
    tcp_packets = 0
    udp_packets = 0
    retransmissions = 0
    ttl_expired = 0
    ttl_low = 0
    dscp_counts: Counter[int] = Counter()
    ecn_counts: Counter[int] = Counter()
    snmp_packets = 0
    snmp_versions: Counter[str] = Counter()
    snmp_communities: Counter[str] = Counter()

    seen_seq: dict[tuple[str, str, int, int], set[tuple[int, int]]] = defaultdict(set)

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                ttl_val = int(getattr(ip_layer, "ttl", 0) or 0)
                if ttl_val <= 1:
                    ttl_expired += 1
                if ttl_val and ttl_val <= 5:
                    ttl_low += 1
                tos = int(getattr(ip_layer, "tos", 0) or 0)
                dscp_counts[(tos >> 2) & 0x3F] += 1
                ecn_counts[tos & 0x03] += 1
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                hlim = int(getattr(ip_layer, "hlim", 0) or 0)
                if hlim <= 1:
                    ttl_expired += 1
                if hlim and hlim <= 5:
                    ttl_low += 1
                tc = int(getattr(ip_layer, "tc", 0) or 0)
                dscp_counts[(tc >> 2) & 0x3F] += 1
                ecn_counts[tc & 0x03] += 1

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_packets += 1
                tcp_layer = pkt[TCP]  # type: ignore[index]
                if src_ip and dst_ip:
                    try:
                        seq = int(getattr(tcp_layer, "seq", 0) or 0)
                        sport = int(getattr(tcp_layer, "sport", 0) or 0)
                        dport = int(getattr(tcp_layer, "dport", 0) or 0)
                        payload_len = 0
                        if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                            payload_len = len(bytes(pkt[Raw]))  # type: ignore[index]
                        else:
                            try:
                                payload_len = len(bytes(tcp_layer.payload))
                            except Exception:
                                payload_len = 0
                        key = (src_ip, dst_ip, sport, dport)
                        sig = (seq, payload_len)
                        if sig in seen_seq[key]:
                            retransmissions += 1
                        else:
                            seen_seq[key].add(sig)
                        if len(seen_seq[key]) > 20000:
                            seen_seq[key].clear()
                    except Exception:
                        pass

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_packets += 1
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if sport in (161, 162) or dport in (161, 162):
                    snmp_packets += 1
                    payload = None
                    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                        payload = bytes(pkt[Raw])  # type: ignore[index]
                    else:
                        try:
                            payload = bytes(udp_layer.payload)
                        except Exception:
                            payload = None
                    if payload:
                        version, community = _parse_snmp(payload)
                        if version:
                            snmp_versions[version] += 1
                        if community:
                            snmp_communities[community] += 1
    finally:
        status.finish()
        reader.close()

    retransmission_rate = (retransmissions / tcp_packets) if tcp_packets else 0.0

    expired_certs = 0
    self_signed_certs = 0
    try:
        cert_summary = analyze_certificates(path, show_status=False)
        expired_certs = len(cert_summary.expired)
        self_signed_certs = len(cert_summary.self_signed)
        errors.extend(cert_summary.errors)
    except Exception as exc:
        errors.append(str(exc))

    findings: list[dict[str, object]] = []
    if retransmissions > 50 and retransmission_rate > 0.01:
        findings.append({
            "severity": "warning",
            "summary": "Elevated TCP retransmissions",
            "details": f"{retransmissions} retransmissions ({retransmission_rate:.2%} of TCP packets).",
        })
    if ttl_expired:
        findings.append({
            "severity": "warning",
            "summary": "Expired TTL/Hop Limit observed",
            "details": f"{ttl_expired} packets with TTL/Hop Limit <= 1.",
        })
    if ttl_low and ttl_low > ttl_expired:
        findings.append({
            "severity": "info",
            "summary": "Low TTL/Hop Limit values",
            "details": f"{ttl_low} packets with TTL/Hop Limit <= 5.",
        })
    if expired_certs:
        findings.append({
            "severity": "warning",
            "summary": "Expired certificates detected",
            "details": f"{expired_certs} expired or invalid certificate(s).",
        })
    if snmp_packets:
        findings.append({
            "severity": "warning",
            "summary": "SNMP traffic observed",
            "details": f"{snmp_packets} SNMP packets detected; review community strings and access controls.",
        })
        if any(comm.lower() in {"public", "private"} for comm in snmp_communities):
            findings.append({
                "severity": "critical",
                "summary": "Default SNMP community strings detected",
                "details": "SNMP community strings include 'public' or 'private'.",
            })

    return HealthSummary(
        path=path,
        total_packets=total_packets,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        retransmissions=retransmissions,
        retransmission_rate=retransmission_rate,
        ttl_expired=ttl_expired,
        ttl_low=ttl_low,
        dscp_counts=dscp_counts,
        ecn_counts=ecn_counts,
        snmp_packets=snmp_packets,
        snmp_versions=snmp_versions,
        snmp_communities=snmp_communities,
        expired_certs=expired_certs,
        self_signed_certs=self_signed_certs,
        findings=findings,
        errors=errors,
    )
