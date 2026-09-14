from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

try:
    from scapy.layers.inet import UDP  # type: ignore
except Exception:  # pragma: no cover
    UDP = None  # type: ignore


QUIC_PORTS = {443, 4433, 8443, 9443, 784}
# A packet *from* a QUIC port is a server response only when it goes back to
# a client's ephemeral port. Without this, any flow whose ephemeral source port
# happens to be 443/784 and whose payload passes the header check is reported
# as a QUIC server.
_EPHEMERAL_PORT_MIN = 1024


@dataclass(frozen=True)
class QuicSummary:
    path: Path
    total_packets: int
    quic_packets: int
    clients: Counter[str]
    servers: Counter[str]
    versions: Counter[str]
    flow_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _looks_like_quic(payload: bytes) -> bool:
    if not payload:
        return False
    first = payload[0]
    # Long header: Header-Form (0x80) AND Fixed (0x40) bits set, plus a
    # recognized 32-bit version. Requiring the fixed bit + version rejects STUN/
    # DTLS/other UDP on the same port whose first byte merely had 0x80 set.
    if (first & 0xC0) == 0xC0:
        if len(payload) < 5:
            return False
        version = int.from_bytes(payload[1:5], "big")
        return (
            version == 0x00000000  # Version Negotiation
            or version == 0x00000001  # QUIC v1 (RFC 9000)
            or version == 0x6B3343CF  # QUIC v2 (RFC 9369)
            or (version >> 16) == 0xFF00  # IETF drafts ff0000xx
            or (version & 0x0F0F0F0F) == 0x0A0A0A0A  # forced version negotiation
        )
    # Short header: Header-Form bit clear, Fixed bit set. Can't validate further
    # statelessly; already gated to QUIC ports by the caller.
    return (first & 0xC0) == 0x40


def _parse_version(payload: bytes) -> Optional[str]:
    if len(payload) < 5:
        return None
    if (payload[0] & 0x80) == 0:
        return None
    version = int.from_bytes(payload[1:5], "big")
    return f"0x{version:08x}"


def _quic_roles(
    src_ip: str, dst_ip: str, sport: int, dport: int
) -> Optional[tuple[str, str, int]]:
    """(client, server, server_port) for a UDP packet, or None if the QUIC
    port is not on the server side of the exchange."""
    if dport in QUIC_PORTS:
        return src_ip, dst_ip, dport
    if sport in QUIC_PORTS and dport >= _EPHEMERAL_PORT_MIN:
        return dst_ip, src_ip, sport
    return None


@memoize_analysis
def analyze_quic(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> QuicSummary:
    if UDP is None:
        return QuicSummary(
            path,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            [],
            ["Scapy UDP unavailable"],
            None,
            None,
            None,
        )

    total_packets = 0
    quic_packets = 0
    clients: Counter[str] = Counter()
    servers: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    flow_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        udp = pkt.getlayer(UDP)  # type: ignore[arg-type]
        if udp is None:
            continue
        sport = int(getattr(udp, "sport", 0) or 0)
        dport = int(getattr(udp, "dport", 0) or 0)
        if sport not in QUIC_PORTS and dport not in QUIC_PORTS:
            continue

        payload = bytes(getattr(udp, "payload", b""))
        if not _looks_like_quic(payload):
            continue

        src_ip, dst_ip = extract_packet_endpoints(pkt)
        if not src_ip or not dst_ip:
            continue
        roles = _quic_roles(src_ip, dst_ip, sport, dport)
        if roles is None:
            continue
        client, server, server_port = roles

        quic_packets += 1
        # The report window spans QUIC traffic, not every packet in scope.
        ts = safe_float(getattr(pkt, "time", None))
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

        clients[client] += 1
        servers[server] += 1
        version = _parse_version(payload)
        if version:
            versions[version] += 1
        # One flow per client/server pair, whichever direction the packet
        # travelled; keying on the packet's dport split every flow in two,
        # one of them named after the client's ephemeral port.
        flow_counts[f"{client}->{server}:{server_port}"] += 1

    if quic_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "QUIC traffic observed",
                "details": f"{quic_packets} QUIC-like packets detected; check for HTTP/3 usage.",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return QuicSummary(
        path=path,
        total_packets=total_packets,
        quic_packets=quic_packets,
        clients=clients,
        servers=servers,
        versions=versions,
        flow_counts=flow_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
