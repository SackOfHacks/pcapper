"""The communication profile a --baseline records and --baseline-diff compares.

One pass over a capture collects what an OT/ICS/IoT baseline is made of:

* every conversation, as client -> server on the server's service port, with
  its protocol, category (OT, IoT, IT, other), volume and time span;
* the request cadence of each conversation (client -> server packets that
  carry data): an HMI polling its PLC every second is the baseline, the same
  poll every 100 ms or not at all is a deviation;
* layer-2 industrial streams (GOOSE, SV, PROFINET RT, EtherCAT, PTP, LLDP)
  between MAC addresses;
* the IP -> MAC bindings each host announced, from its own frames and ARP.

Commands per pair come from --ot-commands (``OtCommandSummary.pair_commands``);
hosts and services from their own analyses. This module records traffic only.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .lite import UNSUPPORTED, LitePacket
from .ot_ports import OT_PORT_PROTOCOLS
from .pcap_cache import PcapMeta, iter_packets
from .protocols import ETHERTYPE_PROTOCOLS, KNOWN_PORTS
from .utils import (
    extract_packet_endpoints,
    memoize_analysis,
    packet_length,
    safe_float,
    tcp_segment_length,
)

try:  # pragma: no cover - scapy is a hard dependency; the guard keeps imports cheap in tests
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import ARP, Dot1Q, Ether  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = IPv6 = ARP = Dot1Q = Ether = None  # type: ignore

# IoT messaging and constrained-device protocols. CoAP is also in the OT map;
# it is classed here as IoT.
IOT_PORT_PROTOCOLS: dict[int, str] = {
    1883: "MQTT",
    8883: "MQTT-TLS",
    5683: "CoAP",
    5684: "CoAP-DTLS",
    5671: "AMQP-TLS",
    5672: "AMQP",
    61613: "STOMP",
    5222: "XMPP",
}

# Request-interval samples kept per conversation (enough for a stable median
# on a day of 1 s polling; the median of a capped prefix is still the cadence).
MAX_INTERVAL_SAMPLES = 20_000
# Requests closer together than this are one burst (a request split over
# segments, a write followed by its read-back): cadence is burst to burst.
BURST_GAP_SECONDS = 0.005
# Conversations tracked per capture; past the cap, new ones are counted only.
MAX_FLOWS = 200_000

_ETHERTYPE_LABELS: dict[int, str] = dict(ETHERTYPE_PROTOCOLS)
_ARP = 0x0806
_IP_PROTOCOLS: dict[int, str] = {0: "IPv6 hop-by-hop", 1: "ICMP", 2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 112: "VRRP"}


def _ip_protocol(number: int) -> str:
    return _IP_PROTOCOLS.get(number, f"IP/{number}")


def classify_port(port: int) -> tuple[str, str]:
    """(protocol label, category) of a service port."""
    if port in IOT_PORT_PROTOCOLS:
        return IOT_PORT_PROTOCOLS[port], "IoT"
    if port in OT_PORT_PROTOCOLS:
        return OT_PORT_PROTOCOLS[port], "OT"
    if port in KNOWN_PORTS:
        return KNOWN_PORTS[port], "IT"
    return "", "other"


def _service_side(sport: int, dport: int) -> int:
    """Which port is the service: 1 (dst), 0 (src). A known service port wins;
    otherwise the lower port, since clients use ephemeral high ports."""
    d_known = dport in IOT_PORT_PROTOCOLS or dport in OT_PORT_PROTOCOLS or dport in KNOWN_PORTS
    s_known = sport in IOT_PORT_PROTOCOLS or sport in OT_PORT_PROTOCOLS or sport in KNOWN_PORTS
    if d_known and not s_known:
        return 1
    if s_known and not d_known:
        return 0
    return 1 if dport <= sport else 0


@dataclass
class FlowStats:
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    requests: int = 0
    intervals: list[float] = field(default_factory=list)
    last_request: Optional[float] = None

    def add(self, ts: float, size: int) -> None:
        self.packets += 1
        self.bytes += size
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def request(self, ts: float) -> None:
        self.requests += 1
        last = self.last_request
        if last is not None and ts >= last:
            if ts - last < BURST_GAP_SECONDS:
                return  # same burst: the cadence runs from its first request
            if len(self.intervals) < MAX_INTERVAL_SAMPLES:
                self.intervals.append(ts - last)
        self.last_request = ts


@dataclass
class TrafficProfile:
    path: Path
    total_packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    # (client, server, transport, service port) -> stats
    flows: dict[tuple[str, str, str, int], FlowStats] = field(default_factory=dict)
    # (src MAC, dst MAC, protocol label) -> stats
    l2_flows: dict[tuple[str, str, str], FlowStats] = field(default_factory=dict)
    ip_macs: dict[str, Counter[str]] = field(default_factory=dict)
    # (first, last) time each IP was seen sending from each MAC.
    ip_mac_times: dict[tuple[str, str], tuple[float, float]] = field(default_factory=dict)
    skipped_flows: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return max(0.0, self.last_seen - self.first_seen)


def _scapy_fields(pkt) -> tuple:
    """(src_mac, dst_mac, ethertype, src_ip, dst_ip, is_arp, transport, sport,
    dport, payload_len) from a dissected packet."""
    src_mac = dst_mac = None
    ethertype = None
    ether = pkt.getlayer(Ether) if Ether is not None else None
    if ether is not None:
        src_mac = str(getattr(ether, "src", "") or "") or None
        dst_mac = str(getattr(ether, "dst", "") or "") or None
        ethertype = int(getattr(ether, "type", 0) or 0)
        vlan = pkt.getlayer(Dot1Q) if Dot1Q is not None else None
        if vlan is not None:
            ethertype = int(getattr(vlan, "type", 0) or 0)
    arp = pkt.getlayer(ARP) if ARP is not None else None
    if arp is not None:
        return (src_mac, dst_mac, _ARP, str(getattr(arp, "psrc", "") or ""), None, True, None, 0, 0, 0)
    ip_layer = pkt.getlayer(IP) if IP is not None else None
    if ip_layer is None and IPv6 is not None:
        ip_layer = pkt.getlayer(IPv6)
    if ip_layer is None:
        return (src_mac, dst_mac, ethertype, None, None, False, None, 0, 0, 0)
    src_ip = str(getattr(ip_layer, "src", "") or "")
    dst_ip = str(getattr(ip_layer, "dst", "") or "")
    tcp = pkt.getlayer(TCP) if TCP is not None else None
    if tcp is not None:
        seg = tcp_segment_length(tcp, ip_layer)
        if seg is None:
            seg = len(bytes(tcp.payload))
        return (src_mac, dst_mac, ethertype, src_ip, dst_ip, False, "TCP",
                int(tcp.sport), int(tcp.dport), seg)
    udp = pkt.getlayer(UDP) if UDP is not None else None
    if udp is not None:
        return (src_mac, dst_mac, ethertype, src_ip, dst_ip, False, "UDP",
                int(udp.sport), int(udp.dport), max(0, int(getattr(udp, "len", 8) or 8) - 8))
    number = getattr(ip_layer, "proto", None)
    if number is None:
        number = getattr(ip_layer, "nh", 0)
    return (src_mac, dst_mac, ethertype, src_ip, dst_ip, False, _ip_protocol(int(number or 0)), 0, 0, 0)


def _lite_fields(pkt: LitePacket) -> Optional[tuple]:
    """The same fields from the record's bytes; None when scapy must answer."""
    ether, l3, l4 = pkt.headers()
    if ether is UNSUPPORTED or l3 is UNSUPPORTED or l4 is UNSUPPORTED:
        return None
    src_mac = dst_mac = None
    ethertype = None
    if ether is not None:
        first = pkt.lite_first_ether()
        if first is UNSUPPORTED:
            return None
        if first is not None:
            src_mac, dst_mac = first[1], first[2]
        ethertype = ether[0] if ether[0] is not UNSUPPORTED else None
    if l3 is None:
        if l4 is not None:
            return None
        return (src_mac, dst_mac, ethertype, None, None, False, None, 0, 0, 0)
    if l3[0] == 1:  # ARP
        endpoints = pkt.lite_endpoints()
        if endpoints is UNSUPPORTED:
            return None
        return (src_mac, dst_mac, _ARP, endpoints[0], None, True, None, 0, 0, 0)
    src_ip, dst_ip = extract_packet_endpoints(pkt)
    if not src_ip or not dst_ip:
        return None
    data = pkt.original
    kind, offset = l3
    if l4 is None:
        # IPv4 protocol: 3 bytes before the source address; IPv6 next header:
        # 2 bytes after the header start (8 before the source address).
        number = data[offset - 3] if kind == 4 else data[offset - 2]
        return (src_mac, dst_mac, ethertype, src_ip, dst_ip, False, _ip_protocol(number), 0, 0, 0)
    is_tcp, sport, dport = l4[0], l4[1], l4[2]
    if not is_tcp:
        if l4[5] >= 0:
            size = l4[6] - l4[5]
        else:
            data = pkt.original
            start = l4[7] - 8
            size = max(0, ((data[start + 4] << 8) | data[start + 5]) - 8)
        return (src_mac, dst_mac, ethertype, src_ip, dst_ip, False, "UDP", sport, dport, size)
    if kind == 4:  # offset: the source address; the header starts 12 before
        ip = offset - 12
        total = (data[ip + 2] << 8) | data[ip + 3]
        if not total:
            return None
        end = ip + total
    else:  # IPv6: the header starts 8 before; its payload 40 after
        ip = offset - 8
        end = ip + 40 + ((data[ip + 4] << 8) | data[ip + 5])
    body = l4[7]
    seg = end - body if end > body else 0
    return (src_mac, dst_mac, ethertype, src_ip, dst_ip, False, "TCP", sport, dport, seg)


@memoize_analysis
def analyze_baseline_profile(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> TrafficProfile:
    profile = TrafficProfile(path=path)
    if Ether is None and IP is None:
        profile.errors.append("Scapy layers unavailable; install scapy for the baseline profile.")
        return profile

    flows = profile.flows
    l2_flows = profile.l2_flows
    ip_macs: dict[str, Counter[str]] = defaultdict(Counter)
    mac_times = profile.ip_mac_times

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status, lite=True):
        profile.total_packets += 1
        ts = safe_float(getattr(pkt, "time", None))
        if ts is None:
            continue
        if profile.first_seen is None or ts < profile.first_seen:
            profile.first_seen = ts
        if profile.last_seen is None or ts > profile.last_seen:
            profile.last_seen = ts
        size = packet_length(pkt)
        fields = None
        if type(pkt) is LitePacket:
            try:
                fields = _lite_fields(pkt)
            except Exception:  # noqa: BLE001 - scapy answers instead
                fields = None
            if fields is None:
                pkt = pkt.materialize()
        if fields is None:
            try:
                fields = _scapy_fields(pkt)
            except Exception as exc:  # noqa: BLE001 - one bad frame
                if len(profile.errors) < 5:
                    profile.errors.append(f"Unreadable packet skipped: {exc}")
                continue
        src_mac, dst_mac, ethertype, src_ip, dst_ip, is_arp, transport, sport, dport, payload = fields

        if src_ip and src_mac and src_mac != "ff:ff:ff:ff:ff:ff":
            mac = src_mac.lower()
            ip_macs[src_ip][mac] += 1
            seen = mac_times.get((src_ip, mac))
            if seen is None:
                mac_times[(src_ip, mac)] = (ts, ts)
            elif ts > seen[1] or ts < seen[0]:
                mac_times[(src_ip, mac)] = (min(seen[0], ts), max(seen[1], ts))
        if is_arp:
            continue
        if src_ip is None:
            label = _ETHERTYPE_LABELS.get(ethertype or -1)
            if label and src_mac and dst_mac:
                key2 = (src_mac.lower(), dst_mac.lower(), label)
                stats = l2_flows.get(key2)
                if stats is None:
                    stats = l2_flows[key2] = FlowStats()
                stats.add(ts, size)
                stats.request(ts)
            continue
        if not dst_ip:
            continue

        if transport in ("TCP", "UDP"):
            if _service_side(sport, dport):
                client, server, port, to_server = src_ip, dst_ip, dport, True
            else:
                client, server, port, to_server = dst_ip, src_ip, sport, False
        else:
            client, server, port, to_server = src_ip, dst_ip, 0, True
        key = (client, server, transport, port)
        stats = flows.get(key)
        if stats is None:
            if len(flows) >= MAX_FLOWS:
                profile.skipped_flows += 1
                continue
            stats = flows[key] = FlowStats()
        stats.add(ts, size)
        if to_server and (payload > 0 or transport != "TCP"):
            stats.request(ts)

    profile.ip_macs = dict(ip_macs)
    if profile.skipped_flows:
        profile.errors.append(
            f"Conversation cap reached ({MAX_FLOWS:,}); {profile.skipped_flows:,} packets of further conversations not profiled."
        )
    return profile


def interval_stats(intervals: list[float]) -> tuple[Optional[float], Optional[float]]:
    """(median interval, jitter) of request intervals; jitter is the median
    absolute deviation over the median (0 = clockwork). None below 5 samples."""
    if len(intervals) < 5:
        return None, None
    values = sorted(intervals)
    mid = len(values) // 2
    median = values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2
    if median <= 0:
        return median, None
    deviations = sorted(abs(v - median) for v in values)
    mad = deviations[mid] if len(deviations) % 2 else (deviations[mid - 1] + deviations[mid]) / 2
    return median, mad / median
