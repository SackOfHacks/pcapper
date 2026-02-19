from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterable
import ipaddress
import re

from .pcap_cache import get_reader
from .utils import safe_float
from .device_detection import device_fingerprints_from_text

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


SNMP_PORTS = {161, 162}

PDU_TYPE_MAP = {
    0xA0: "GetRequest",
    0xA1: "GetNextRequest",
    0xA2: "GetResponse",
    0xA3: "SetRequest",
    0xA4: "Trap",
    0xA5: "GetBulkRequest",
    0xA6: "InformRequest",
    0xA7: "SNMPv2-Trap",
    0xA8: "Report",
}

OID_LABELS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.2.0": "sysObjectID",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
    "1.3.6.1.2.1.4.20.1.1": "ipAdEntAddr",
    "1.3.6.1.2.1.25.3.2.1.3": "hrDeviceDescr",
    "1.3.6.1.2.1.25.4.2.1.2": "hrSWRunName",
    "1.3.6.1.2.1.25.6.3.1.2": "hrSWInstalledName",
}

SUSPICIOUS_PATTERNS = [
    (re.compile(r"powershell|cmd\.exe|wmic|winrs", re.IGNORECASE), "Command execution tooling"),
    (re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE), "Malware tooling"),
    (re.compile(r"rundll32|regsvr32|schtasks|at\s+", re.IGNORECASE), "Execution/persistence tooling"),
    (re.compile(r"nmap|masscan|sqlmap", re.IGNORECASE), "Recon tooling"),
]


@dataclass(frozen=True)
class SnmpConversation:
    client_ip: str
    server_ip: str
    protocol: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class SnmpArtifact:
    kind: str
    detail: str
    src: str
    dst: str


@dataclass(frozen=True)
class SnmpSummary:
    path: Path
    total_packets: int
    snmp_packets: int
    total_bytes: int
    total_messages: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    protocol_counts: Counter[str]
    version_counts: Counter[str]
    community_counts: Counter[str]
    pdu_counts: Counter[str]
    oid_counts: Counter[str]
    hostnames: Counter[str]
    ip_addresses: Counter[str]
    mac_addresses: Counter[str]
    services: Counter[str]
    plaintext_strings: Counter[str]
    conversations: list[SnmpConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[SnmpArtifact]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "snmp_packets": self.snmp_packets,
            "total_bytes": self.total_bytes,
            "total_messages": self.total_messages,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "protocol_counts": dict(self.protocol_counts),
            "version_counts": dict(self.version_counts),
            "community_counts": dict(self.community_counts),
            "pdu_counts": dict(self.pdu_counts),
            "oid_counts": dict(self.oid_counts),
            "hostnames": dict(self.hostnames),
            "ip_addresses": dict(self.ip_addresses),
            "mac_addresses": dict(self.mac_addresses),
            "services": dict(self.services),
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
                {
                    "kind": item.kind,
                    "detail": item.detail,
                    "src": item.src,
                    "dst": item.dst,
                }
                for item in self.artifacts
            ],
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


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


def _read_tlv(payload: bytes, offset: int) -> tuple[Optional[int], Optional[bytes], int]:
    if offset >= len(payload):
        return None, None, offset
    tag = payload[offset]
    length, idx = _read_ber_length(payload, offset + 1)
    if length is None or idx + length > len(payload):
        return None, None, offset
    value = payload[idx:idx + length]
    return tag, value, idx + length


def _decode_oid(value: bytes) -> Optional[str]:
    if not value:
        return None
    try:
        first = value[0]
        oid = [first // 40, first % 40]
        acc = 0
        for b in value[1:]:
            acc = (acc << 7) | (b & 0x7F)
            if not (b & 0x80):
                oid.append(acc)
                acc = 0
        return ".".join(str(x) for x in oid)
    except Exception:
        return None


def _decode_value(tag: int, value: bytes) -> str:
    if tag == 0x02:
        return str(int.from_bytes(value, "big", signed=False))
    if tag == 0x04:
        try:
            text = value.decode("latin-1", errors="ignore")
            return text
        except Exception:
            return ""
    if tag == 0x06:
        return _decode_oid(value) or ""
    if tag == 0x40 and len(value) == 4:
        return ".".join(str(b) for b in value)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(value, "big", signed=False))
    return ""


def _parse_snmp_message(payload: bytes) -> Optional[dict[str, object]]:
    tag, value, _ = _read_tlv(payload, 0)
    if tag != 0x30 or value is None:
        return None
    idx = 0
    ver_tag, ver_val, idx = _read_tlv(value, idx)
    if ver_tag != 0x02 or ver_val is None:
        return None
    version_val = int.from_bytes(ver_val, "big", signed=False)
    version = {0: "v1", 1: "v2c", 3: "v3"}.get(version_val, f"v{version_val}")
    comm_tag, comm_val, idx = _read_tlv(value, idx)
    if comm_tag != 0x04 or comm_val is None:
        return None
    community = comm_val.decode("latin-1", errors="ignore")
    if idx >= len(value):
        return None
    pdu_tag = value[idx]
    pdu_name = PDU_TYPE_MAP.get(pdu_tag, f"0x{pdu_tag:02x}")
    pdu_len, pdu_idx = _read_ber_length(value, idx + 1)
    if pdu_len is None or pdu_idx + pdu_len > len(value):
        return None
    pdu_value = value[pdu_idx:pdu_idx + pdu_len]
    pidx = 0
    _req_tag, _req_val, pidx = _read_tlv(pdu_value, pidx)
    _err_tag, _err_val, pidx = _read_tlv(pdu_value, pidx)
    _err_idx_tag, _err_idx_val, pidx = _read_tlv(pdu_value, pidx)
    vb_tag, vb_val, _ = _read_tlv(pdu_value, pidx)
    varbinds: list[tuple[str, str]] = []
    if vb_tag == 0x30 and vb_val is not None:
        vb_idx = 0
        while vb_idx < len(vb_val):
            item_tag, item_val, vb_idx = _read_tlv(vb_val, vb_idx)
            if item_tag != 0x30 or item_val is None:
                continue
            item_idx = 0
            oid_tag, oid_val, item_idx = _read_tlv(item_val, item_idx)
            if oid_tag != 0x06 or oid_val is None:
                continue
            oid = _decode_oid(oid_val) or ""
            val_tag, val_val, _ = _read_tlv(item_val, item_idx)
            if val_tag is None or val_val is None:
                continue
            value_text = _decode_value(val_tag, val_val)
            varbinds.append((oid, value_text))
    return {
        "version": version,
        "community": community,
        "pdu": pdu_name,
        "varbinds": varbinds,
    }


def _format_mac(value: str) -> Optional[str]:
    if not value:
        return None
    raw = value.encode("latin-1", errors="ignore")
    if len(raw) == 6:
        return ":".join(f"{b:02x}" for b in raw)
    if len(value) == 17 and all(c in "0123456789abcdefABCDEF:.-" for c in value):
        return value.replace("-", ":").lower()
    return None


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


def analyze_snmp(path: Path, show_status: bool = True, packets: list[object] | None = None, meta: object | None = None) -> SnmpSummary:
    errors: list[str] = []
    if UDP is None and TCP is None:
        errors.append("Scapy IP layers unavailable; install scapy for SNMP analysis.")
        return SnmpSummary(
            path=path,
            total_packets=0,
            snmp_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            version_counts=Counter(),
            community_counts=Counter(),
            pdu_counts=Counter(),
            oid_counts=Counter(),
            hostnames=Counter(),
            ip_addresses=Counter(),
            mac_addresses=Counter(),
            services=Counter(),
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
    snmp_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()
    community_counts: Counter[str] = Counter()
    pdu_counts: Counter[str] = Counter()
    oid_counts: Counter[str] = Counter()
    hostnames: Counter[str] = Counter()
    ip_addresses: Counter[str] = Counter()
    mac_addresses: Counter[str] = Counter()
    services: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    artifacts: list[SnmpArtifact] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    seen_device_artifacts: set[str] = set()

    community_by_flow: dict[tuple[str, str], set[str]] = defaultdict(set)
    dst_by_src: dict[str, set[str]] = defaultdict(set)
    request_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    response_bytes: Counter[tuple[str, str]] = Counter()
    request_bytes: Counter[tuple[str, str]] = Counter()

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

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                proto = "UDP"
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                try:
                    payload = bytes(udp_layer.payload)
                except Exception:
                    payload = None
            elif TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                proto = "TCP"
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                try:
                    payload = bytes(tcp_layer.payload)
                except Exception:
                    payload = None

            if not proto or (sport not in SNMP_PORTS and dport not in SNMP_PORTS):
                continue

            snmp_packets += 1
            protocol_counts[proto] += 1
            server_port = dport if dport in SNMP_PORTS else sport
            server_ports[server_port] += 1

            if payload:
                msg = _parse_snmp_message(payload)
            else:
                msg = None
            if not msg:
                continue

            total_messages += 1
            version = str(msg.get("version", "unknown"))
            community = str(msg.get("community", "-"))
            pdu = str(msg.get("pdu", "-"))
            varbinds = msg.get("varbinds", [])

            version_counts[version] += 1
            if community:
                community_counts[community] += 1
            if pdu:
                pdu_counts[pdu] += 1

            client_counts[src_ip] += 1
            server_counts[dst_ip] += 1
            dst_by_src[src_ip].add(dst_ip)
            community_by_flow[(src_ip, dst_ip)].add(community)

            if ts is not None and pdu in {"GetRequest", "GetNextRequest", "GetBulkRequest", "SetRequest", "InformRequest"}:
                request_times[(src_ip, dst_ip)].append(ts)

            if pdu in {"GetResponse", "SNMPv2-Trap", "Trap", "Report"}:
                response_bytes[(src_ip, dst_ip)] += pkt_len
            else:
                request_bytes[(src_ip, dst_ip)] += pkt_len

            conv_key = (src_ip, dst_ip, proto, int(server_port))
            conv = conv_map.get(conv_key)
            if conv is None:
                conv = {
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": ts,
                    "last_seen": ts,
                }
                conv_map[conv_key] = conv
            conv["packets"] = int(conv["packets"]) + 1
            conv["bytes"] = int(conv["bytes"]) + pkt_len
            if ts is not None:
                if conv["first_seen"] is None or ts < conv["first_seen"]:
                    conv["first_seen"] = ts
                if conv["last_seen"] is None or ts > conv["last_seen"]:
                    conv["last_seen"] = ts

            if isinstance(varbinds, list):
                for oid, value in varbinds:
                    if not oid:
                        continue
                    label = OID_LABELS.get(oid)
                    oid_counts[oid] += 1
                    if label:
                        artifacts.append(SnmpArtifact(kind=label, detail=value, src=src_ip, dst=dst_ip))
                    if label == "sysName" and value:
                        hostnames[value] += 1
                    if label == "sysDescr" and value:
                        plaintext_strings[_truncate(value, 120)] += 1
                        if "windows" in value.lower():
                            detections.append({
                                "severity": "info",
                                "summary": "Windows SNMP device observed",
                                "details": f"{src_ip}->{dst_ip} {value[:80]}",
                                "source": "SNMP",
                            })
                        for detail in device_fingerprints_from_text(value, source="SNMP sysDescr"):
                            key = f"device:{detail}"
                            if key in seen_device_artifacts:
                                continue
                            seen_device_artifacts.add(key)
                            artifacts.append(SnmpArtifact(kind="device", detail=detail, src=src_ip, dst=dst_ip))
                    if label == "ipAdEntAddr" and value:
                        ip_addresses[value] += 1
                    if label == "ifPhysAddress":
                        mac = _format_mac(value)
                        if mac:
                            mac_addresses[mac] += 1
                    if label in {"hrSWRunName", "hrSWInstalledName", "hrDeviceDescr"} and value:
                        services[_truncate(value, 80)] += 1
                        for detail in device_fingerprints_from_text(value, source=f"SNMP {label}"):
                            key = f"device:{detail}"
                            if key in seen_device_artifacts:
                                continue
                            seen_device_artifacts.add(key)
                            artifacts.append(SnmpArtifact(kind="device", detail=detail, src=src_ip, dst=dst_ip))
                    if value:
                        for pattern, reason in SUSPICIOUS_PATTERNS:
                            if pattern.search(value):
                                detections.append({
                                    "severity": "warning",
                                    "summary": f"Suspicious SNMP value: {reason}",
                                    "details": f"{src_ip}->{dst_ip} {value[:120]}",
                                    "source": "SNMP",
                                })
    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    for community in list(community_counts.keys()):
        if community.lower() in {"public", "private"}:
            detections.append({
                "severity": "high",
                "summary": "Default SNMP community string detected",
                "details": f"Community '{community}' observed; review access controls.",
                "source": "SNMP",
            })

    if pdu_counts.get("SetRequest"):
        detections.append({
            "severity": "high",
            "summary": "SNMP SET operations observed",
            "details": f"{pdu_counts.get('SetRequest')} SetRequest PDU(s) detected.",
            "source": "SNMP",
        })

    if version_counts.get("v1"):
        detections.append({
            "severity": "warning",
            "summary": "Legacy SNMPv1 observed",
            "details": f"{version_counts.get('v1')} SNMPv1 message(s) detected.",
            "source": "SNMP",
        })

    for src, dsts in dst_by_src.items():
        if len(dsts) >= 20:
            detections.append({
                "severity": "warning",
                "summary": "SNMP scanning/probing detected",
                "details": f"{src} contacted {len(dsts)} SNMP endpoints.",
                "source": "SNMP",
            })

    for (src, dst), comms in community_by_flow.items():
        if len(comms) >= 6:
            detections.append({
                "severity": "warning",
                "summary": "SNMP community brute-force suspected",
                "details": f"{src} tried {len(comms)} community strings against {dst}.",
                "source": "SNMP",
            })

    for flow, times in request_times.items():
        score = _beacon_score(times)
        if score:
            detections.append({
                "severity": "warning",
                "summary": "SNMP beaconing suspected",
                "details": f"{flow[0]}->{flow[1]} avg {score['avg']:.1f}s interval.",
                "source": "SNMP",
            })

    for flow, resp_bytes in response_bytes.items():
        req_bytes = request_bytes.get(flow, 1)
        if resp_bytes > 50_000 and resp_bytes > req_bytes * 5:
            detections.append({
                "severity": "warning",
                "summary": "SNMP data exfiltration suspected",
                "details": f"{flow[0]}->{flow[1]} response bytes {resp_bytes}.",
                "source": "SNMP",
            })

    conversations: list[SnmpConversation] = []
    for (src, dst, proto, port), data in conv_map.items():
        conversations.append(SnmpConversation(
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

    return SnmpSummary(
        path=path,
        total_packets=total_packets,
        snmp_packets=snmp_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        version_counts=version_counts,
        community_counts=community_counts,
        pdu_counts=pdu_counts,
        oid_counts=oid_counts,
        hostnames=hostnames,
        ip_addresses=ip_addresses,
        mac_addresses=mac_addresses,
        services=services,
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


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def merge_snmp_summaries(summaries: Iterable[SnmpSummary]) -> SnmpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return SnmpSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            snmp_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            version_counts=Counter(),
            community_counts=Counter(),
            pdu_counts=Counter(),
            oid_counts=Counter(),
            hostnames=Counter(),
            ip_addresses=Counter(),
            mac_addresses=Counter(),
            services=Counter(),
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
    snmp_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds = 0.0

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()
    community_counts: Counter[str] = Counter()
    pdu_counts: Counter[str] = Counter()
    oid_counts: Counter[str] = Counter()
    hostnames: Counter[str] = Counter()
    ip_addresses: Counter[str] = Counter()
    mac_addresses: Counter[str] = Counter()
    services: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[SnmpArtifact] = []
    errors: list[str] = []

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    det_seen: set[tuple[str, str, str]] = set()
    err_seen: set[str] = set()

    for summary in summary_list:
        total_packets += summary.total_packets
        snmp_packets += summary.snmp_packets
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
        version_counts.update(summary.version_counts)
        community_counts.update(summary.community_counts)
        pdu_counts.update(summary.pdu_counts)
        oid_counts.update(summary.oid_counts)
        hostnames.update(summary.hostnames)
        ip_addresses.update(summary.ip_addresses)
        mac_addresses.update(summary.mac_addresses)
        services.update(summary.services)
        plaintext_strings.update(summary.plaintext_strings)

        for item in summary.detections:
            key = (str(item.get("severity", "")), str(item.get("summary", "")), str(item.get("details", "")))
            if key in det_seen:
                continue
            det_seen.add(key)
            detections.append(item)
        for item in summary.anomalies:
            anomalies.append(item)
        for item in summary.artifacts:
            artifacts.append(item)
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
        SnmpConversation(
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

    return SnmpSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        snmp_packets=snmp_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        version_counts=version_counts,
        community_counts=community_counts,
        pdu_counts=pdu_counts,
        oid_counts=oid_counts,
        hostnames=hostnames,
        ip_addresses=ip_addresses,
        mac_addresses=mac_addresses,
        services=services,
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
