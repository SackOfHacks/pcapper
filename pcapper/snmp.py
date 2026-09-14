from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .device_detection import device_fingerprints_from_text
from .pcap_cache import iter_packets
from .utils import (
    beacon_score,
    extract_packet_endpoints,
    memoize_analysis,
    packet_length,
    read_ber_length,
    safe_float,
)

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


SNMP_PORTS = {161, 162}
_REQUEST_PDUS = frozenset(
    {"GetRequest", "GetNextRequest", "GetBulkRequest", "SetRequest", "InformRequest"}
)
_RESPONSE_PDUS = frozenset({"GetResponse", "SNMPv2-Trap", "Trap", "Report"})
_LABELLED_SERVICE_OIDS = frozenset({"hrSWRunName", "hrSWInstalledName", "hrDeviceDescr"})
# Per-flow request timestamps kept for beacon scoring; a poller hitting an
# agent every few seconds for a day would otherwise buffer every timestamp.
_MAX_REQUEST_TIMES = 512
# Labelled varbinds are stored as artifacts; a full MIB walk emits thousands.
_MAX_ARTIFACTS = 2000

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
    (
        re.compile(r"powershell|cmd\.exe|wmic|winrs", re.IGNORECASE),
        "Command execution tooling",
    ),
    (
        re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE),
        "Malware tooling",
    ),
    (
        # `at\s+` matched the English word "at "; restrict to `at \\host`.
        re.compile(r"rundll32|regsvr32|schtasks|\bat\s+\\\\", re.IGNORECASE),
        "Execution/persistence tooling",
    ),
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
    # SNMPv3 USM identities (msgUserName) — the device-management accounts. The
    # username is cleartext even in authPriv mode, so it's a useful identity
    # artifact. Defaulted for backward-compatible construction.
    usm_users: Counter[str] = field(default_factory=Counter)

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


def _read_tlv(
    payload: bytes, offset: int
) -> tuple[Optional[int], Optional[bytes], int]:
    if offset >= len(payload):
        return None, None, offset
    tag = payload[offset]
    length, idx = read_ber_length(payload, offset + 1)
    if length is None or idx + length > len(payload):
        return None, None, offset
    value = payload[idx : idx + length]
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

    # SNMPv3 has a different layout: after the version INTEGER comes
    # msgGlobalData (SEQUENCE) then msgSecurityParameters (OCTET STRING wrapping
    # the USM SEQUENCE), NOT a community OCTET STRING. The old code assumed v1/v2c
    # layout and returned None for every v3 message, so the entire v3/USM layer
    # was invisible. Parse it separately so v3 is at least counted, with the USM
    # username/engineID surfaced for triage.
    if version_val == 3:
        username = ""
        engine_id = ""
        glob_tag, _glob_val, idx = _read_tlv(value, idx)  # msgGlobalData SEQUENCE
        sec_tag, sec_val, _ = _read_tlv(value, idx)  # msgSecurityParameters
        if sec_tag == 0x04 and sec_val:
            usm_tag, usm_val, _ = _read_tlv(sec_val, 0)
            if usm_tag == 0x30 and usm_val:
                u = 0
                eng_tag, eng_v, u = _read_tlv(usm_val, u)  # engineID
                if eng_tag == 0x04 and eng_v is not None:
                    engine_id = eng_v.hex()
                _b_tag, _b, u = _read_tlv(usm_val, u)  # engineBoots
                _t_tag, _t, u = _read_tlv(usm_val, u)  # engineTime
                name_tag, name_v, u = _read_tlv(usm_val, u)  # msgUserName
                if name_tag == 0x04 and name_v is not None:
                    username = name_v.decode("latin-1", errors="ignore")
        return {
            "version": version,
            "community": "",
            "pdu": "v3 (USM)",
            "varbinds": [],
            "username": username,
            "engine_id": engine_id,
        }

    comm_tag, comm_val, idx = _read_tlv(value, idx)
    if comm_tag != 0x04 or comm_val is None:
        return None
    community = comm_val.decode("latin-1", errors="ignore")
    if idx >= len(value):
        return None
    pdu_tag = value[idx]
    pdu_name = PDU_TYPE_MAP.get(pdu_tag, f"0x{pdu_tag:02x}")
    pdu_len, pdu_idx = read_ber_length(value, idx + 1)
    if pdu_len is None or pdu_idx + pdu_len > len(value):
        return None
    pdu_value = value[pdu_idx : pdu_idx + pdu_len]
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


def _snmp_beacon(times: list[float]):
    """``utils.beacon_score`` with the SNMP view's tighter jitter tolerance."""
    return beacon_score(
        times, min_interval=1.0, max_interval=3600.0, rel_jitter=0.15, abs_jitter_floor=0.0
    )


@memoize_analysis
def analyze_snmp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> SnmpSummary:
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
    usm_users: Counter[str] = Counter()
    dst_by_src: dict[str, set[str]] = defaultdict(set)
    request_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    response_bytes: Counter[tuple[str, str]] = Counter()
    request_bytes: Counter[tuple[str, str]] = Counter()
    seen_detections: set[tuple[str, str]] = set()
    skipped_packets = 0
    first_skip_error: str | None = None

    def _detect(severity: str, summary_text: str, details: str) -> None:
        # A value repeated in every poll response is one finding, not one per packet.
        key = (summary_text, details)
        if key in seen_detections:
            return
        seen_detections.add(key)
        detections.append(
            {"severity": severity, "summary": summary_text, "details": details, "source": "SNMP"}
        )

    def _artifact(kind: str, detail: str, src: str, dst: str) -> None:
        if len(artifacts) < _MAX_ARTIFACTS:
            artifacts.append(SnmpArtifact(kind=kind, detail=detail, src=src, dst=dst))

    def _device_artifacts(value: str, source: str, src: str, dst: str) -> None:
        for detail in device_fingerprints_from_text(value, source=source):
            key = f"device:{detail}"
            if key in seen_device_artifacts:
                continue
            seen_device_artifacts.add(key)
            _artifact("device", detail, src, dst)

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        pkt_len = packet_length(pkt)
        total_bytes += pkt_len

        transport = pkt.getlayer(UDP) if UDP is not None else None
        proto = "UDP"
        if transport is None and TCP is not None:
            transport = pkt.getlayer(TCP)
            proto = "TCP"
        if transport is None:
            continue
        sport = int(getattr(transport, "sport", 0) or 0)
        dport = int(getattr(transport, "dport", 0) or 0)
        if sport not in SNMP_PORTS and dport not in SNMP_PORTS:
            continue
        try:
            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue
            try:
                payload = bytes(transport.payload)
            except Exception:
                payload = b""

            snmp_packets += 1
            protocol_counts[proto] += 1
            # The report window spans SNMP traffic, not every packet in scope.
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            # Roles by port: an agent answers from its well-known port to the
            # manager's ephemeral port; everything else (requests to 161, traps
            # to 162) flows from the client side to the listener. Counting the
            # packet's src as "client" made every polled agent a client too.
            if sport in SNMP_PORTS and dport not in SNMP_PORTS:
                client_ip, server_ip, server_port = dst_ip, src_ip, sport
            else:
                client_ip, server_ip, server_port = src_ip, dst_ip, dport
            server_ports[server_port] += 1

            msg = _parse_snmp_message(payload) if payload else None
            if not msg:
                continue

            total_messages += 1
            version = str(msg.get("version", "unknown"))
            community = str(msg.get("community", "-"))
            pdu = str(msg.get("pdu", "-"))
            varbinds = msg.get("varbinds", [])

            version_counts[version] += 1
            usm_name = str(msg.get("username", "") or "").strip()
            if usm_name:
                usm_users[usm_name] += 1
            if community:
                community_counts[community] += 1
            if pdu:
                pdu_counts[pdu] += 1

            flow = (client_ip, server_ip)
            client_counts[client_ip] += 1
            server_counts[server_ip] += 1
            dst_by_src[client_ip].add(server_ip)
            community_by_flow[flow].add(community)

            if ts is not None and pdu in _REQUEST_PDUS:
                times = request_times[flow]
                if len(times) < _MAX_REQUEST_TIMES:
                    times.append(ts)

            # Both directions keyed on the same (client, server) flow so the
            # exfil ratio compares an agent's responses with the requests that
            # elicited them (keyed by packet direction they never met, and the
            # request side always read as 1 byte).
            if pdu in _RESPONSE_PDUS:
                response_bytes[flow] += pkt_len
            else:
                request_bytes[flow] += pkt_len

            conv_key = (client_ip, server_ip, proto, int(server_port))
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
                        _artifact(label, value, src_ip, dst_ip)
                    if not value:
                        continue
                    if label == "sysName":
                        hostnames[value] += 1
                    elif label == "sysDescr":
                        plaintext_strings[_truncate(value, 120)] += 1
                        if "windows" in value.lower():
                            _detect(
                                "info",
                                "Windows SNMP device observed",
                                f"{src_ip}->{dst_ip} {value[:80]}",
                            )
                        _device_artifacts(value, "SNMP sysDescr", src_ip, dst_ip)
                    elif label == "ipAdEntAddr":
                        ip_addresses[value] += 1
                    elif label == "ifPhysAddress":
                        mac = _format_mac(value)
                        if mac:
                            mac_addresses[mac] += 1
                    elif label in _LABELLED_SERVICE_OIDS:
                        services[_truncate(value, 80)] += 1
                        _device_artifacts(value, f"SNMP {label}", src_ip, dst_ip)
                    for pattern, reason in SUSPICIOUS_PATTERNS:
                        if pattern.search(value):
                            _detect(
                                "warning",
                                f"Suspicious SNMP value: {reason}",
                                f"{src_ip}->{dst_ip} {value[:120]}",
                            )
        except Exception as exc:  # noqa: BLE001 — one malformed message must not end the pass
            skipped_packets += 1
            if first_skip_error is None:
                first_skip_error = f"{type(exc).__name__}: {exc}"

    if skipped_packets:
        errors.append(
            f"{skipped_packets} SNMP packet(s) skipped after a parse error "
            f"(first: {first_skip_error}); counts are lower bounds."
        )

    for community in community_counts:
        if community.lower() in {"public", "private"}:
            detections.append(
                {
                    "severity": "high",
                    "summary": "Default SNMP community string detected",
                    "details": f"Community '{community}' observed; review access controls.",
                    "source": "SNMP",
                }
            )

    if pdu_counts.get("SetRequest"):
        detections.append(
            {
                "severity": "high",
                "summary": "SNMP SET operations observed",
                "details": f"{pdu_counts.get('SetRequest')} SetRequest PDU(s) detected.",
                "source": "SNMP",
            }
        )

    if version_counts.get("v1"):
        detections.append(
            {
                "severity": "warning",
                "summary": "Legacy SNMPv1 observed",
                "details": f"{version_counts.get('v1')} SNMPv1 message(s) detected.",
                "source": "SNMP",
            }
        )

    for src, dsts in dst_by_src.items():
        if len(dsts) >= 20:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "SNMP scanning/probing detected",
                    "details": f"{src} contacted {len(dsts)} SNMP endpoints.",
                    "source": "SNMP",
                }
            )

    for (src, dst), comms in community_by_flow.items():
        if len(comms) >= 6:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "SNMP community brute-force suspected",
                    "details": f"{src} tried {len(comms)} community strings against {dst}.",
                    "source": "SNMP",
                }
            )

    for flow, times in request_times.items():
        score = _snmp_beacon(times)
        if score:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "SNMP beaconing suspected",
                    "details": f"{flow[0]}->{flow[1]} avg {score['avg']:.1f}s interval.",
                    "source": "SNMP",
                }
            )

    for flow, resp_bytes in response_bytes.items():
        req_bytes = request_bytes.get(flow, 1)
        if resp_bytes > 50_000 and resp_bytes > req_bytes * 5:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "SNMP data exfiltration suspected",
                    "details": f"{flow[0]}->{flow[1]} response bytes {resp_bytes}.",
                    "source": "SNMP",
                }
            )

    conversations: list[SnmpConversation] = []
    for (src, dst, proto, port), data in conv_map.items():
        conversations.append(
            SnmpConversation(
                client_ip=src,
                server_ip=dst,
                protocol=proto,
                server_port=port,
                packets=int(data["packets"]),
                bytes=int(data["bytes"]),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
            )
        )
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
        usm_users=usm_users,
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
    usm_users: Counter[str] = Counter()
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
        usm_users.update(getattr(summary, "usm_users", Counter()))

        for item in summary.detections:
            key = (
                str(item.get("severity", "")),
                str(item.get("summary", "")),
                str(item.get("details", "")),
            )
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
            if conv.first_seen is not None and (
                current["first_seen"] is None or conv.first_seen < current["first_seen"]
            ):
                current["first_seen"] = conv.first_seen
            if conv.last_seen is not None and (
                current["last_seen"] is None or conv.last_seen > current["last_seen"]
            ):
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
        usm_users=usm_users,
    )
