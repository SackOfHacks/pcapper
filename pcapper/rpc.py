from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterable
import ipaddress
import re
import struct

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore


RPC_PORTS = {135, 445, 593}

PDU_TYPE_MAP = {
    0x00: "request",
    0x02: "response",
    0x0B: "bind",
    0x0C: "bind_ack",
    0x0D: "bind_nak",
    0x0E: "alter_context",
    0x0F: "alter_context_resp",
    0x10: "auth3",
    0x11: "shutdown",
    0x12: "co_cancel",
    0x13: "orphaned",
}

RPC_INTERFACES = {
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "EPM (Endpoint Mapper)",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC (Server Service)",
    "12345778-1234-abcd-ef00-0123456789ab": "LSARPC (LSA)",
    "12345778-1234-abcd-ef00-0123456789ac": "SAMR (SAM)",
    "367abb81-9844-35f1-ad32-98f038001003": "SVCCTL (Service Control)",
    "6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC (Workstation)",
    "12345678-1234-abcd-ef00-01234567cffb": "NETLOGON",
    "1ff70682-0a51-30e8-076d-740be8cee98b": "ATSVC (AT Scheduler)",
    "338cd001-2244-31f1-aaaa-900038001003": "WINREG (Remote Registry)",
}

HOST_RE = re.compile(r"\b([A-Za-z0-9_.-]{2,64})\b")
DOMAIN_USER_RE = re.compile(r"\b([A-Za-z0-9_.-]{1,64})\\([A-Za-z0-9_.-]{1,64})\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")

SUSPICIOUS_STRINGS = [
    (re.compile(r"powershell|cmd\.exe|wmic|winrs", re.IGNORECASE), "Command execution tooling"),
    (re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE), "Malware tooling"),
    (re.compile(r"rundll32|regsvr32|schtasks|at\s+", re.IGNORECASE), "Execution/persistence tooling"),
    (re.compile(r"nmap|masscan|sqlmap", re.IGNORECASE), "Recon tooling"),
]


@dataclass(frozen=True)
class RpcConversation:
    client_ip: str
    server_ip: str
    protocol: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class RpcArtifact:
    kind: str
    detail: str
    src: str
    dst: str


@dataclass(frozen=True)
class RpcSummary:
    path: Path
    total_packets: int
    rpc_packets: int
    total_bytes: int
    total_messages: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    protocol_counts: Counter[str]
    pdu_counts: Counter[str]
    interface_counts: Counter[str]
    hostname_counts: Counter[str]
    domain_user_counts: Counter[str]
    ip_strings: Counter[str]
    mac_strings: Counter[str]
    plaintext_strings: Counter[str]
    conversations: list[RpcConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[RpcArtifact]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "rpc_packets": self.rpc_packets,
            "total_bytes": self.total_bytes,
            "total_messages": self.total_messages,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "protocol_counts": dict(self.protocol_counts),
            "pdu_counts": dict(self.pdu_counts),
            "interface_counts": dict(self.interface_counts),
            "hostname_counts": dict(self.hostname_counts),
            "domain_user_counts": dict(self.domain_user_counts),
            "ip_strings": dict(self.ip_strings),
            "mac_strings": dict(self.mac_strings),
            "plaintext_strings": dict(self.plaintext_strings),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "protocol": conv.protocol,
                    "server_port": conv.server_port,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                }
                for conv in self.conversations
            ],
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "artifacts": [
                {"kind": item.kind, "detail": item.detail, "src": item.src, "dst": item.dst}
                for item in self.artifacts
            ],
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def _rpc_pdu_type(payload: bytes | None) -> Optional[str]:
    if not payload or len(payload) < 16:
        return None
    if payload[0] != 0x05:
        return None
    ptype = payload[2]
    return PDU_TYPE_MAP.get(ptype, f"0x{ptype:02x}")


def _decode_uuid_le(data: bytes) -> Optional[str]:
    if len(data) < 16:
        return None
    try:
        d1, d2, d3 = struct.unpack("<IHH", data[:8])
        d4 = data[8:10]
        d5 = data[10:16]
        return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"
    except Exception:
        return None


def _parse_bind_interfaces(payload: bytes | None) -> list[str]:
    if not payload or len(payload) < 32:
        return []
    if payload[0] != 0x05 or payload[2] != 0x0B:
        return []
    interfaces: list[str] = []
    try:
        idx = 16
        if idx + 10 > len(payload):
            return []
        idx += 2  # max_xmit
        idx += 2  # max_recv
        idx += 4  # assoc_group
        num_ctx = payload[idx]
        idx += 4  # num_ctx + reserved
        for _ in range(num_ctx):
            if idx + 4 > len(payload):
                break
            idx += 2  # context_id
            num_trans = payload[idx]
            idx += 2  # num_trans + reserved
            if idx + 20 > len(payload):
                break
            uuid = _decode_uuid_le(payload[idx:idx + 16])
            idx += 16
            vers = struct.unpack("<HH", payload[idx:idx + 4])
            idx += 4
            if uuid:
                iface = f"{uuid} v{vers[0]}.{vers[1]}"
                interfaces.append(iface)
            for _t in range(num_trans):
                if idx + 20 > len(payload):
                    break
                idx += 16 + 4
    except Exception:
        return interfaces
    return interfaces


def _extract_strings(payload: bytes, limit: int = 200) -> list[str]:
    if not payload:
        return []
    out: list[str] = []
    current = bytearray()
    for b in payload:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= 4:
                out.append(current.decode("latin-1", errors="ignore")[:limit])
            current = bytearray()
    if len(current) >= 4:
        out.append(current.decode("latin-1", errors="ignore")[:limit])
    return out


def _beacon_score(times: list[float]) -> Optional[dict[str, float]]:
    if len(times) < 5:
        return None
    times_sorted = sorted(times)
    deltas = [b - a for a, b in zip(times_sorted, times_sorted[1:]) if b > a]
    if len(deltas) < 4:
        return None
    avg = sum(deltas) / len(deltas)
    if avg <= 0:
        return None
    variance = sum((d - avg) ** 2 for d in deltas) / len(deltas)
    stddev = variance ** 0.5
    if avg < 1 or avg > 3600:
        return None
    if stddev / avg > 0.15:
        return None
    return {"avg": avg, "stddev": stddev}


def analyze_rpc(path: Path, show_status: bool = True, packets: list[object] | None = None, meta: object | None = None) -> RpcSummary:
    errors: list[str] = []
    if TCP is None and UDP is None:
        errors.append("Scapy IP layers unavailable; install scapy for RPC analysis.")
        return RpcSummary(
            path=path,
            total_packets=0,
            rpc_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            pdu_counts=Counter(),
            interface_counts=Counter(),
            hostname_counts=Counter(),
            domain_user_counts=Counter(),
            ip_strings=Counter(),
            mac_strings=Counter(),
            plaintext_strings=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    rpc_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    pdu_counts: Counter[str] = Counter()
    interface_counts: Counter[str] = Counter()
    hostname_counts: Counter[str] = Counter()
    domain_user_counts: Counter[str] = Counter()
    ip_strings: Counter[str] = Counter()
    mac_strings: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    artifacts: list[RpcArtifact] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    dst_by_src: dict[str, set[str]] = defaultdict(set)
    request_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    response_bytes: Counter[tuple[str, str]] = Counter()
    request_bytes: Counter[tuple[str, str]] = Counter()
    bind_failures: Counter[str] = Counter()

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
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

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

            if not src_ip or not dst_ip:
                continue

            proto = None
            sport = None
            dport = None
            payload = None

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                proto = "TCP"
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                try:
                    payload = bytes(tcp_layer.payload)
                except Exception:
                    payload = None
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                proto = "UDP"
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                try:
                    payload = bytes(udp_layer.payload)
                except Exception:
                    payload = None

            if not proto or not payload:
                continue

            pdu_type = _rpc_pdu_type(payload)
            if not pdu_type and sport not in RPC_PORTS and dport not in RPC_PORTS:
                continue
            if not pdu_type:
                continue

            rpc_packets += 1
            total_messages += 1
            protocol_counts[proto] += 1
            server_port = dport if dport in RPC_PORTS else sport
            server_ports[server_port] += 1
            pdu_counts[pdu_type] += 1
            client_counts[src_ip] += 1
            server_counts[dst_ip] += 1
            dst_by_src[src_ip].add(dst_ip)
            if ts is not None:
                request_times[(src_ip, dst_ip)].append(ts)

            if pdu_type in {"response", "bind_ack", "alter_context_resp"}:
                response_bytes[(src_ip, dst_ip)] += pkt_len
            else:
                request_bytes[(src_ip, dst_ip)] += pkt_len
            if pdu_type == "bind_nak":
                bind_failures[src_ip] += 1

            conv_key = (src_ip, dst_ip, proto, int(server_port))
            conv = conv_map.get(conv_key)
            if conv is None:
                conv = {"packets": 0, "bytes": 0, "first_seen": ts, "last_seen": ts}
                conv_map[conv_key] = conv
            conv["packets"] = int(conv["packets"]) + 1
            conv["bytes"] = int(conv["bytes"]) + pkt_len
            if ts is not None:
                if conv["first_seen"] is None or ts < conv["first_seen"]:
                    conv["first_seen"] = ts
                if conv["last_seen"] is None or ts > conv["last_seen"]:
                    conv["last_seen"] = ts

            for iface in _parse_bind_interfaces(payload):
                interface_counts[iface] += 1
                uuid = iface.split(" ", 1)[0]
                label = RPC_INTERFACES.get(uuid)
                if label:
                    artifacts.append(RpcArtifact(kind="interface", detail=f"{label} ({iface})", src=src_ip, dst=dst_ip))

            for item in _extract_strings(payload, limit=200):
                plaintext_strings[item] += 1
                if HOST_RE.fullmatch(item) and len(item) <= 64:
                    hostname_counts[item] += 1
                for match in DOMAIN_USER_RE.findall(item):
                    domain_user_counts[f"{match[0]}\\{match[1]}"] += 1
                for match in IP_RE.findall(item):
                    ip_strings[match] += 1
                for match in MAC_RE.findall(item):
                    mac_strings[match] += 1
                for pattern, reason in SUSPICIOUS_STRINGS:
                    if pattern.search(item):
                        detections.append({
                            "severity": "warning",
                            "summary": f"Suspicious RPC content: {reason}",
                            "details": f"{src_ip}->{dst_ip} {item[:120]}",
                            "source": "RPC",
                        })
    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    for src, dsts in dst_by_src.items():
        if len(dsts) >= 20:
            detections.append({
                "severity": "warning",
                "summary": "RPC scanning/probing detected",
                "details": f"{src} contacted {len(dsts)} RPC endpoints.",
                "source": "RPC",
            })

    for src, count in bind_failures.items():
        if count >= 10:
            detections.append({
                "severity": "warning",
                "summary": "RPC bind failures spike",
                "details": f"{src} saw {count} bind_nak responses.",
                "source": "RPC",
            })

    for flow, times in request_times.items():
        score = _beacon_score(times)
        if score:
            detections.append({
                "severity": "warning",
                "summary": "RPC beaconing suspected",
                "details": f"{flow[0]}->{flow[1]} avg {score['avg']:.1f}s interval.",
                "source": "RPC",
            })

    for flow, resp_bytes in response_bytes.items():
        req_bytes = request_bytes.get(flow, 1)
        if resp_bytes > 50_000 and resp_bytes > req_bytes * 5:
            detections.append({
                "severity": "warning",
                "summary": "RPC data exfiltration suspected",
                "details": f"{flow[0]}->{flow[1]} response bytes {resp_bytes}.",
                "source": "RPC",
            })

    conversations: list[RpcConversation] = []
    for (src, dst, proto, port), data in conv_map.items():
        conversations.append(RpcConversation(
            client_ip=src,
            server_ip=dst,
            protocol=proto,
            server_port=port,
            packets=int(data["packets"]),
            bytes=int(data["bytes"]),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
        ))
    conversations.sort(key=lambda c: c.packets, reverse=True)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return RpcSummary(
        path=path,
        total_packets=total_packets,
        rpc_packets=rpc_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        pdu_counts=pdu_counts,
        interface_counts=interface_counts,
        hostname_counts=hostname_counts,
        domain_user_counts=domain_user_counts,
        ip_strings=ip_strings,
        mac_strings=mac_strings,
        plaintext_strings=plaintext_strings,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_rpc_summaries(summaries: Iterable[RpcSummary]) -> RpcSummary:
    summary_list = list(summaries)
    if not summary_list:
        return RpcSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            rpc_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            pdu_counts=Counter(),
            interface_counts=Counter(),
            hostname_counts=Counter(),
            domain_user_counts=Counter(),
            ip_strings=Counter(),
            mac_strings=Counter(),
            plaintext_strings=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=0.0,
        )

    total_packets = 0
    rpc_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds = 0.0

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    pdu_counts: Counter[str] = Counter()
    interface_counts: Counter[str] = Counter()
    hostname_counts: Counter[str] = Counter()
    domain_user_counts: Counter[str] = Counter()
    ip_strings: Counter[str] = Counter()
    mac_strings: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[RpcArtifact] = []
    errors: list[str] = []

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    det_seen: set[tuple[str, str, str]] = set()
    err_seen: set[str] = set()

    for summary in summary_list:
        total_packets += summary.total_packets
        rpc_packets += summary.rpc_packets
        total_bytes += summary.total_bytes
        total_messages += summary.total_messages
        if summary.first_seen is not None:
            if first_seen is None or summary.first_seen < first_seen:
                first_seen = summary.first_seen
        if summary.last_seen is not None:
            if last_seen is None or summary.last_seen > last_seen:
                last_seen = summary.last_seen
        if summary.duration_seconds is not None:
            duration_seconds += summary.duration_seconds

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        server_ports.update(summary.server_ports)
        protocol_counts.update(summary.protocol_counts)
        pdu_counts.update(summary.pdu_counts)
        interface_counts.update(summary.interface_counts)
        hostname_counts.update(summary.hostname_counts)
        domain_user_counts.update(summary.domain_user_counts)
        ip_strings.update(summary.ip_strings)
        mac_strings.update(summary.mac_strings)
        plaintext_strings.update(summary.plaintext_strings)

        for item in summary.detections:
            key = (str(item.get("severity", "")), str(item.get("summary", "")), str(item.get("details", "")))
            if key in det_seen:
                continue
            det_seen.add(key)
            detections.append(item)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        for err in summary.errors:
            if err in err_seen:
                continue
            err_seen.add(err)
            errors.append(err)

        for conv in summary.conversations:
            key = (conv.client_ip, conv.server_ip, conv.protocol, conv.server_port)
            current = conv_map.get(key)
            if current is None:
                conv_map[key] = {
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                }
                continue
            current["packets"] = int(current["packets"]) + conv.packets
            current["bytes"] = int(current["bytes"]) + conv.bytes
            if conv.first_seen is not None and (current["first_seen"] is None or conv.first_seen < current["first_seen"]):
                current["first_seen"] = conv.first_seen
            if conv.last_seen is not None and (current["last_seen"] is None or conv.last_seen > current["last_seen"]):
                current["last_seen"] = conv.last_seen

    conversations = [
        RpcConversation(
            client_ip=key[0],
            server_ip=key[1],
            protocol=key[2],
            server_port=key[3],
            packets=int(val["packets"]),
            bytes=int(val["bytes"]),
            first_seen=val.get("first_seen"),
            last_seen=val.get("last_seen"),
        )
        for key, val in conv_map.items()
    ]
    conversations.sort(key=lambda c: c.packets, reverse=True)

    return RpcSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        rpc_packets=rpc_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        pdu_counts=pdu_counts,
        interface_counts=interface_counts,
        hostname_counts=hostname_counts,
        domain_user_counts=domain_user_counts,
        ip_strings=ip_strings,
        mac_strings=mac_strings,
        plaintext_strings=plaintext_strings,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
