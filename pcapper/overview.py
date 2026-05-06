from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .analyzer import analyze_pcap
from .bacnet import analyze_bacnet
from .cip import analyze_cip
from .coap import analyze_coap
from .control_loop import analyze_control_loop
from .ctf import analyze_ctf
from .dnp3 import analyze_dnp3
from .enip import analyze_enip
from .files import analyze_files
from .goose import analyze_goose
from .hart import analyze_hart
from .iec104 import analyze_iec104
from .lldp_dcp import analyze_lldp_dcp
from .mms import analyze_mms
from .modbus import analyze_modbus
from .mqtt import analyze_mqtt
from .niagara import analyze_niagara
from .odesys import analyze_odesys
from .opc import analyze_opc
from .ot_commands import OtControlConfig, analyze_ot_commands
from .profinet import analyze_profinet
from .protocols import analyze_protocols
from .ptp import analyze_ptp
from .s7 import analyze_s7
from .safety import analyze_safety
from .scan import analyze_scan
from .services import analyze_services
from .sv import analyze_sv
from .threats import analyze_threats


@dataclass(frozen=True)
class OverviewModuleResult:
    module: str
    reason: str
    metrics: dict[str, object] = field(default_factory=dict)
    highlights: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OverviewSummary:
    path: Path
    total_packets: int
    duration_seconds: float
    top_protocols: list[tuple[str, int]]
    top_services: list[tuple[str, int]]
    observed_ips: list[dict[str, object]]
    observed_protocols: list[tuple[str, int]]
    observed_services: list[tuple[str, int]]
    summary_details: dict[str, int]
    ot_protocols: list[str]
    modules_run: list[str]
    module_results: list[OverviewModuleResult]
    ot_highlights: list[str]
    hunt_highlights: list[str]
    forensics_highlights: list[str]
    ctf_highlights: list[str]
    recommendations: list[str]
    errors: list[str]
    capture_start: float | None
    capture_end: float | None
    ip_activity: list[dict[str, object]]
    protocol_activity: list[dict[str, object]]
    service_activity: list[dict[str, object]]
    notable_flows: list[dict[str, object]]
    hunt_leads: list[dict[str, object]]


_OT_PROTOCOL_MATCHERS: list[tuple[str, str, tuple[str, ...]]] = [
    ("modbus", "Modbus/TCP", ("modbus",)),
    ("dnp3", "DNP3", ("dnp3",)),
    ("iec104", "IEC-104", ("iec-104", "iec104", "iec 104")),
    ("bacnet", "BACnet", ("bacnet",)),
    ("enip", "EtherNet/IP", ("ethernet/ip", "enip", "44818")),
    ("cip", "CIP", ("cip", "enip-io", "2222", "cip security")),
    ("profinet", "Profinet", ("profinet", "pnio", "dcp")),
    ("s7", "Siemens S7", ("s7", "s7comm", "siemens", "cotp", "tpkt")),
    ("opc", "OPC UA", ("opc ua", "opc", "opc.tcp", "4840")),
    ("mms", "IEC 61850 MMS", ("mms", "iec 61850 mms", "acse", "61850")),
    ("goose", "IEC 61850 GOOSE", ("goose",)),
    ("sv", "IEC 61850 SV", ("sampled value", "iec 61850 sv")),
    ("lldp", "LLDP/DCP", ("lldp", "profinet dcp")),
    ("ptp", "IEEE 1588 PTP", ("ptp", "1588")),
    ("mqtt", "MQTT", ("mqtt",)),
    ("coap", "CoAP", ("coap",)),
    ("hart", "HART-IP", ("hart",)),
    ("niagara", "Niagara Fox", ("niagara", "fox")),
    ("odesys", "ODESYS/CODESYS", ("odesys", "codesys")),
]


_FILE_TRANSFER_HINTS = (
    "http",
    "ftp",
    "smb",
    "nfs",
    "smtp",
    "imap",
    "pop3",
    "aim",
    "files",
    "mms",
    "enip",
)


_MODULE_LABELS = {
    "threats": "Threat Correlation",
    "scan": "Recon/Scan",
    "ctf": "CTF Decoder",
    "files": "File Forensics",
    "ot_commands": "OT Command Activity",
    "control_loop": "Control Loop",
    "safety": "Safety/SIS",
    "modbus": "Modbus",
    "dnp3": "DNP3",
    "iec104": "IEC-104",
    "bacnet": "BACnet",
    "enip": "EtherNet/IP",
    "cip": "CIP",
    "profinet": "Profinet",
    "s7": "S7",
    "opc": "OPC UA",
    "mms": "MMS",
    "goose": "GOOSE",
    "sv": "SV",
    "lldp": "LLDP/DCP",
    "ptp": "PTP",
    "mqtt": "MQTT",
    "coap": "CoAP",
    "hart": "HART-IP",
    "niagara": "Niagara",
    "odesys": "ODESYS",
}


_OT_MODULES = {
    "ot_commands",
    "control_loop",
    "safety",
    "modbus",
    "dnp3",
    "iec104",
    "bacnet",
    "enip",
    "cip",
    "profinet",
    "s7",
    "opc",
    "mms",
    "goose",
    "sv",
    "lldp",
    "ptp",
    "mqtt",
    "coap",
    "hart",
    "niagara",
    "odesys",
}


_IOT_PROTOCOL_STEPS = {"mqtt", "coap"}


_OT_PORT_HINTS: dict[str, tuple[int, ...]] = {
    "s7": (102,),
    "modbus": (502,),
    "dnp3": (20000,),
    "iec104": (2404,),
    "bacnet": (47808,),
    "enip": (44818, 2222),
    "cip": (2221, 2222, 44818),
    "profinet": (34962, 34963, 34964),
    "opc": (4840,),
    "ptp": (319, 320),
    "mqtt": (1883, 8883),
    "coap": (5683, 5684),
    "hart": (5094,),
    "niagara": (1911, 4911),
    "odesys": (1217, 2455),
}


_AUTO_OT_DEEP_DIVE_LIMIT = 8


_INTERNAL_IPV4_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_INTERNAL_IPV6_RANGES = (ipaddress.ip_network("fc00::/7"),)


def _dedupe_limited(items: list[str], limit: int) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
        if len(output) >= limit:
            break
    return output


def _truncate(text: object, limit: int = 140) -> str:
    value = str(text or "").strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


def _counter_from_obj(value: object) -> Counter[str]:
    if isinstance(value, Counter):
        return Counter({str(k): int(v) for k, v in value.items()})
    if isinstance(value, dict):
        output: Counter[str] = Counter()
        for key, raw in value.items():
            try:
                output[str(key)] += int(raw)
            except Exception:
                continue
        return output
    return Counter()


def _first_counter(summary: object, attrs: tuple[str, ...]) -> Counter[str]:
    for attr in attrs:
        value = getattr(summary, attr, None)
        counter = _counter_from_obj(value)
        if counter:
            return counter
    return Counter()


def _first_int(summary: object, attrs: tuple[str, ...]) -> int | None:
    for attr in attrs:
        value = getattr(summary, attr, None)
        if value is None or isinstance(value, bool):
            continue
        try:
            return int(value)
        except Exception:
            continue
    return None


def _list_len(summary: object, attr: str) -> int:
    values = getattr(summary, attr, None)
    if isinstance(values, list):
        return len(values)
    return 0


def _counter_preview(counter: Counter[str], limit: int = 3) -> str:
    if not counter:
        return "-"
    parts = [f"{_truncate(name, 36)}({count})" for name, count in counter.most_common(limit)]
    return ", ".join(parts) if parts else "-"


def _build_label_blob(protocols, services) -> str:
    parts: list[str] = []
    for name, _count in list(getattr(protocols, "top_protocols", []) or []):
        parts.append(str(name))
    for name, _count in list(getattr(protocols, "port_protocols", []) or []):
        parts.append(str(name))
    hierarchy = getattr(services, "hierarchy", {}) or {}
    if isinstance(hierarchy, dict):
        parts.extend(str(name) for name in hierarchy.keys())
    for asset in list(getattr(services, "assets", []) or []):
        parts.append(str(getattr(asset, "service_name", "") or ""))
    normalized = " ".join(parts).lower().replace("_", " ")
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return f" {normalized} "


def _token_match(blob: str, token: str) -> bool:
    lowered = str(token or "").lower().strip()
    if not lowered:
        return False
    if len(lowered) <= 3:
        pattern = rf"\b{re.escape(lowered)}\b"
        return bool(re.search(pattern, blob))
    return lowered in blob


def _detect_ot_modules(blob: str) -> list[tuple[str, str]]:
    detected: list[tuple[str, str]] = []
    for step, label, tokens in _OT_PROTOCOL_MATCHERS:
        if any(_token_match(blob, token) for token in tokens):
            detected.append((step, label))
    return detected


def _collect_observed_ports(protocols, services) -> tuple[Counter[int], set[int]]:
    port_weights: Counter[int] = Counter()
    service_ports: set[int] = set()

    for conv in list(getattr(protocols, "conversations", []) or []):
        packets = int(getattr(conv, "packets", 0) or 0)
        weight = max(1, packets)
        for raw in set(getattr(conv, "ports", set()) or set()):
            try:
                port = int(raw)
            except Exception:
                continue
            if port <= 0 or port > 65535:
                continue
            port_weights[port] += weight

    for asset in list(getattr(services, "assets", []) or []):
        try:
            port = int(getattr(asset, "port", 0) or 0)
        except Exception:
            continue
        if port <= 0 or port > 65535:
            continue
        service_ports.add(port)
        weight = max(1, int(getattr(asset, "packets", 0) or 0))
        port_weights[port] += weight

    return port_weights, service_ports


def _detect_ot_modules_from_ports(protocols, services) -> dict[str, list[int]]:
    port_weights, service_ports = _collect_observed_ports(protocols, services)
    detected: dict[str, list[int]] = {}
    for step, ports in _OT_PORT_HINTS.items():
        matched: list[int] = []
        for port in ports:
            score = int(port_weights.get(port, 0) or 0)
            if score >= 2 or (score >= 1 and port in service_ports):
                matched.append(port)
        if matched:
            detected[step] = sorted(set(matched))
    return detected


def _ot_marker_tokens(steps: list[str], labels: list[str]) -> set[str]:
    tokens: set[str] = set()
    for step in steps:
        step_text = str(step).strip().lower()
        if step_text:
            tokens.add(step_text)
    for label in labels:
        label_text = str(label).strip().lower()
        if label_text:
            tokens.add(label_text)
    for step, _label, matcher_tokens in _OT_PROTOCOL_MATCHERS:
        if step not in steps:
            continue
        for token in matcher_tokens:
            text = str(token).strip().lower()
            if text:
                tokens.add(text)
    return tokens


def _iot_labels_from_ot_labels(labels: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for label in labels:
        text = str(label).strip()
        lowered = text.lower()
        if not text:
            continue
        if "mqtt" not in lowered and "coap" not in lowered:
            continue
        if text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _top_services(services, limit: int = 10) -> list[tuple[str, int]]:
    hierarchy = getattr(services, "hierarchy", {}) or {}
    if isinstance(hierarchy, Counter):
        return [(str(name), int(count)) for name, count in hierarchy.most_common(limit)]
    if isinstance(hierarchy, dict):
        items: list[tuple[str, int]] = []
        for name, raw in hierarchy.items():
            try:
                items.append((str(name), int(raw)))
            except Exception:
                continue
        items.sort(key=lambda item: item[1], reverse=True)
        return items[:limit]
    return []


def _all_services(services) -> list[tuple[str, int]]:
    hierarchy = getattr(services, "hierarchy", {}) or {}
    if isinstance(hierarchy, Counter):
        return [(str(name), int(count)) for name, count in hierarchy.most_common()]
    if isinstance(hierarchy, dict):
        items: list[tuple[str, int]] = []
        for name, raw in hierarchy.items():
            try:
                items.append((str(name), int(raw)))
            except Exception:
                continue
        items.sort(key=lambda item: item[1], reverse=True)
        return items
    return []


def _coerce_ts(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        ts = float(value)
    except Exception:
        return None
    return ts if ts > 0 else None


def _ip_scope(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link-local"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.version == 4 and any(ip_obj in network for network in _INTERNAL_IPV4_RANGES):
        return "internal"
    if ip_obj.version == 6 and any(ip_obj in network for network in _INTERNAL_IPV6_RANGES):
        return "internal"
    if ip_obj.is_unspecified:
        return "unknown"
    return "public"


def _update_window(bucket: dict[str, object], start: object, end: object) -> None:
    start_ts = _coerce_ts(start)
    end_ts = _coerce_ts(end) or start_ts
    if start_ts is None and end_ts is None:
        return
    current_first = _coerce_ts(bucket.get("first_seen"))
    current_last = _coerce_ts(bucket.get("last_seen"))
    if start_ts is not None and (current_first is None or start_ts < current_first):
        bucket["first_seen"] = start_ts
    if end_ts is not None and (current_last is None or end_ts > current_last):
        bucket["last_seen"] = end_ts


def _ensure_ip_bucket(
    store: dict[str, dict[str, object]], ip_text: str
) -> dict[str, object]:
    existing = store.get(ip_text)
    if existing is not None:
        return existing
    bucket: dict[str, object] = {
        "ip": ip_text,
        "scope": _ip_scope(ip_text),
        "packets_sent": 0,
        "packets_recv": 0,
        "bytes_sent": 0,
        "bytes_recv": 0,
        "conversation_count": 0,
        "conversation_packets": 0,
        "conversation_bytes": 0,
        "first_seen": None,
        "last_seen": None,
        "peer_counter": Counter(),
        "peer_set": set(),
        "public_peers": set(),
        "internal_peers": set(),
        "protocol_counter": Counter(),
        "port_counter": Counter(),
        "hosted_service_counter": Counter(),
        "used_service_counter": Counter(),
        "hosted_service_set": set(),
        "used_service_set": set(),
        "hosted_ports": set(),
        "service_targets": set(),
    }
    store[ip_text] = bucket
    return bucket


def _bucket_top_list(
    counter: object, limit: int = 3, with_counts: bool = False
) -> list[str]:
    if not isinstance(counter, Counter):
        return []
    output: list[str] = []
    for name, count in counter.most_common(limit):
        text = str(name).strip()
        if not text:
            continue
        if with_counts:
            output.append(f"{text}({int(count)})")
        else:
            output.append(text)
    return output


def _ip_role(bucket: dict[str, object]) -> str:
    hosted = len(set(bucket.get("hosted_service_set", set()) or set()))
    used = len(set(bucket.get("used_service_set", set()) or set()))
    sent = int(bucket.get("packets_sent", 0) or 0)
    recv = int(bucket.get("packets_recv", 0) or 0)
    if hosted and not used:
        return "service-host"
    if used and not hosted:
        return "client"
    if hosted and used:
        return "mixed"
    if sent >= 20 and sent > max(1, recv) * 2:
        return "initiator-heavy"
    if recv >= 20 and recv > max(1, sent) * 2:
        return "responder-heavy"
    return "mixed"


def _ip_activity(protocols, services, limit: int = 20) -> list[dict[str, object]]:
    buckets: dict[str, dict[str, object]] = {}

    for endpoint in list(getattr(protocols, "endpoints", []) or []):
        ip_text = str(getattr(endpoint, "address", "") or "").strip()
        if not ip_text:
            continue
        bucket = _ensure_ip_bucket(buckets, ip_text)
        bucket["packets_sent"] = int(bucket.get("packets_sent", 0) or 0) + int(
            getattr(endpoint, "packets_sent", 0) or 0
        )
        bucket["packets_recv"] = int(bucket.get("packets_recv", 0) or 0) + int(
            getattr(endpoint, "packets_recv", 0) or 0
        )
        bucket["bytes_sent"] = int(bucket.get("bytes_sent", 0) or 0) + int(
            getattr(endpoint, "bytes_sent", 0) or 0
        )
        bucket["bytes_recv"] = int(bucket.get("bytes_recv", 0) or 0) + int(
            getattr(endpoint, "bytes_recv", 0) or 0
        )
        proto_counter = bucket.get("protocol_counter")
        if isinstance(proto_counter, Counter):
            for proto in set(getattr(endpoint, "protocols", set()) or set()):
                proto_text = str(proto).strip()
                if proto_text:
                    proto_counter[proto_text] += 1

    for conv in list(getattr(protocols, "conversations", []) or []):
        src = str(getattr(conv, "src", "") or "").strip()
        dst = str(getattr(conv, "dst", "") or "").strip()
        if not src or not dst:
            continue
        proto = str(getattr(conv, "protocol", "") or "Unknown").strip() or "Unknown"
        packets = int(getattr(conv, "packets", 0) or 0)
        bytes_total = int(getattr(conv, "bytes", 0) or 0)
        weight = max(1, packets)
        start_ts = _coerce_ts(getattr(conv, "start_ts", None))
        end_ts = _coerce_ts(getattr(conv, "end_ts", None)) or start_ts

        ports: list[int] = []
        for raw in set(getattr(conv, "ports", set()) or set()):
            try:
                port_value = int(raw)
            except Exception:
                continue
            if port_value < 0:
                continue
            ports.append(port_value)
        ports.sort()

        src_bucket = _ensure_ip_bucket(buckets, src)
        dst_bucket = _ensure_ip_bucket(buckets, dst)
        for bucket, peer in ((src_bucket, dst), (dst_bucket, src)):
            bucket["conversation_count"] = int(bucket.get("conversation_count", 0) or 0) + 1
            bucket["conversation_packets"] = int(
                bucket.get("conversation_packets", 0) or 0
            ) + packets
            bucket["conversation_bytes"] = int(
                bucket.get("conversation_bytes", 0) or 0
            ) + bytes_total
            _update_window(bucket, start_ts, end_ts)

            peer_counter = bucket.get("peer_counter")
            if isinstance(peer_counter, Counter):
                peer_counter[peer] += weight
            peer_set = bucket.get("peer_set")
            if isinstance(peer_set, set):
                peer_set.add(peer)

            peer_scope = _ip_scope(peer)
            if peer_scope == "public":
                public_peers = bucket.get("public_peers")
                if isinstance(public_peers, set):
                    public_peers.add(peer)
            elif peer_scope == "internal":
                internal_peers = bucket.get("internal_peers")
                if isinstance(internal_peers, set):
                    internal_peers.add(peer)

            proto_counter = bucket.get("protocol_counter")
            if isinstance(proto_counter, Counter):
                proto_counter[proto] += weight
            port_counter = bucket.get("port_counter")
            if isinstance(port_counter, Counter):
                for port in ports[:24]:
                    port_counter[port] += weight

    for asset in list(getattr(services, "assets", []) or []):
        asset_ip = str(getattr(asset, "ip", "") or "").strip()
        if not asset_ip:
            continue
        asset_port = int(getattr(asset, "port", 0) or 0)
        asset_proto = str(getattr(asset, "protocol", "") or "").upper().strip() or "TCP"
        service_name = str(getattr(asset, "service_name", "") or "").strip()
        if not service_name:
            service_name = f"{asset_proto}/{asset_port}"
        service_label = f"{service_name}:{asset_port}/{asset_proto}"
        asset_packets = int(getattr(asset, "packets", 0) or 0)
        service_weight = max(1, asset_packets)
        asset_first = _coerce_ts(getattr(asset, "first_seen", None))
        asset_last = _coerce_ts(getattr(asset, "last_seen", None)) or asset_first

        host_bucket = _ensure_ip_bucket(buckets, asset_ip)
        hosted_counter = host_bucket.get("hosted_service_counter")
        if isinstance(hosted_counter, Counter):
            hosted_counter[service_name] += service_weight
        hosted_set = host_bucket.get("hosted_service_set")
        if isinstance(hosted_set, set):
            hosted_set.add(service_label)
        hosted_ports = host_bucket.get("hosted_ports")
        if isinstance(hosted_ports, set):
            hosted_ports.add(asset_port)
        _update_window(host_bucket, asset_first, asset_last)

        clients = set(str(item).strip() for item in set(getattr(asset, "clients", set()) or set()))
        clients.discard("")
        targets = host_bucket.get("service_targets")
        if isinstance(targets, set):
            targets.update(clients)

        for client_ip in clients:
            client_bucket = _ensure_ip_bucket(buckets, client_ip)
            used_counter = client_bucket.get("used_service_counter")
            if isinstance(used_counter, Counter):
                used_counter[service_name] += service_weight
            used_set = client_bucket.get("used_service_set")
            if isinstance(used_set, set):
                used_set.add(service_name)
            client_targets = client_bucket.get("service_targets")
            if isinstance(client_targets, set):
                client_targets.add(asset_ip)
            _update_window(client_bucket, asset_first, asset_last)

    rows: list[dict[str, object]] = []
    for bucket in buckets.values():
        sent = int(bucket.get("packets_sent", 0) or 0)
        recv = int(bucket.get("packets_recv", 0) or 0)
        packets_total = sent + recv
        bytes_sent = int(bucket.get("bytes_sent", 0) or 0)
        bytes_recv = int(bucket.get("bytes_recv", 0) or 0)
        bytes_total = bytes_sent + bytes_recv

        conv_packets = int(bucket.get("conversation_packets", 0) or 0)
        conv_bytes = int(bucket.get("conversation_bytes", 0) or 0)
        if packets_total <= 0 and conv_packets > 0:
            packets_total = conv_packets
        if bytes_total <= 0 and conv_bytes > 0:
            bytes_total = conv_bytes

        first_seen = _coerce_ts(bucket.get("first_seen"))
        last_seen = _coerce_ts(bucket.get("last_seen"))
        active_seconds = (
            max(0.0, float(last_seen or 0.0) - float(first_seen or 0.0))
            if first_seen is not None and last_seen is not None
            else 0.0
        )

        protocol_counter = bucket.get("protocol_counter")
        peer_counter = bucket.get("peer_counter")
        port_counter = bucket.get("port_counter")
        hosted_counter = bucket.get("hosted_service_counter")
        used_counter = bucket.get("used_service_counter")

        top_protocols = _bucket_top_list(protocol_counter, limit=5)
        top_peers = _bucket_top_list(peer_counter, limit=4, with_counts=True)
        top_ports: list[int] = []
        if isinstance(port_counter, Counter):
            for port_value, _count in port_counter.most_common(6):
                try:
                    top_ports.append(int(port_value))
                except Exception:
                    continue
        services_hosted = _bucket_top_list(hosted_counter, limit=4)
        services_used = _bucket_top_list(used_counter, limit=4)
        role = _ip_role(bucket)

        activity_parts: list[str] = []
        if services_hosted:
            activity_parts.append("hosts " + ", ".join(services_hosted[:2]))
        if services_used:
            activity_parts.append("uses " + ", ".join(services_used[:2]))
        if not activity_parts and top_protocols:
            activity_parts.append("speaks " + ", ".join(top_protocols[:3]))
        activity = "; ".join(activity_parts) if activity_parts else "-"

        peer_set = bucket.get("peer_set")
        public_peers = bucket.get("public_peers")
        internal_peers = bucket.get("internal_peers")
        hosted_set = bucket.get("hosted_service_set")
        used_set = bucket.get("used_service_set")

        rows.append(
            {
                "ip": str(bucket.get("ip", "")),
                "scope": str(bucket.get("scope", "unknown")),
                "role": role,
                "activity": activity,
                "packets_sent": sent,
                "packets_recv": recv,
                "packets_total": packets_total,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "bytes_total": bytes_total,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "active_seconds": active_seconds,
                "conversation_count": int(bucket.get("conversation_count", 0) or 0),
                "peer_count": len(peer_set) if isinstance(peer_set, set) else 0,
                "public_peer_count": len(public_peers)
                if isinstance(public_peers, set)
                else 0,
                "internal_peer_count": len(internal_peers)
                if isinstance(internal_peers, set)
                else 0,
                "protocol_count": len(protocol_counter)
                if isinstance(protocol_counter, Counter)
                else 0,
                "protocols": top_protocols,
                "top_protocols": top_protocols,
                "top_peers": top_peers,
                "top_ports": top_ports,
                "services_hosted": services_hosted,
                "services_used": services_used,
                "service_count": len(hosted_set) if isinstance(hosted_set, set) else 0,
                "used_service_count": len(used_set) if isinstance(used_set, set) else 0,
            }
        )

    rows.sort(
        key=lambda item: (
            -int(item.get("bytes_total", 0) or 0),
            -int(item.get("packets_total", 0) or 0),
            -int(item.get("peer_count", 0) or 0),
            str(item.get("ip", "")),
        )
    )
    return rows[:limit]


def _observed_ips(protocols, services, limit: int = 15) -> list[dict[str, object]]:
    return _ip_activity(protocols, services, limit=limit)


def _protocol_activity(protocols, limit: int = 20) -> list[dict[str, object]]:
    buckets: dict[str, dict[str, object]] = {}
    for conv in list(getattr(protocols, "conversations", []) or []):
        name = str(getattr(conv, "protocol", "") or "Unknown").strip() or "Unknown"
        bucket = buckets.setdefault(
            name,
            {
                "protocol": name,
                "packets": 0,
                "bytes": 0,
                "flow_count": 0,
                "hosts": set(),
                "port_counter": Counter(),
                "first_seen": None,
                "last_seen": None,
            },
        )
        packets = int(getattr(conv, "packets", 0) or 0)
        bytes_total = int(getattr(conv, "bytes", 0) or 0)
        weight = max(1, packets)
        bucket["packets"] = int(bucket.get("packets", 0) or 0) + packets
        bucket["bytes"] = int(bucket.get("bytes", 0) or 0) + bytes_total
        bucket["flow_count"] = int(bucket.get("flow_count", 0) or 0) + 1
        hosts = bucket.get("hosts")
        if isinstance(hosts, set):
            src = str(getattr(conv, "src", "") or "").strip()
            dst = str(getattr(conv, "dst", "") or "").strip()
            if src:
                hosts.add(src)
            if dst:
                hosts.add(dst)
        port_counter = bucket.get("port_counter")
        if isinstance(port_counter, Counter):
            for raw in set(getattr(conv, "ports", set()) or set()):
                try:
                    port_value = int(raw)
                except Exception:
                    continue
                if port_value < 0:
                    continue
                port_counter[port_value] += weight
        _update_window(
            bucket,
            getattr(conv, "start_ts", None),
            getattr(conv, "end_ts", None),
        )

    for name, count in list(getattr(protocols, "top_protocols", []) or []):
        text = str(name).strip()
        if not text:
            continue
        bucket = buckets.setdefault(
            text,
            {
                "protocol": text,
                "packets": 0,
                "bytes": 0,
                "flow_count": 0,
                "hosts": set(),
                "port_counter": Counter(),
                "first_seen": None,
                "last_seen": None,
            },
        )
        bucket["packets"] = max(int(bucket.get("packets", 0) or 0), int(count or 0))

    rows: list[dict[str, object]] = []
    for bucket in buckets.values():
        port_counter = bucket.get("port_counter")
        top_ports: list[int] = []
        if isinstance(port_counter, Counter):
            for port_value, _count in port_counter.most_common(5):
                try:
                    top_ports.append(int(port_value))
                except Exception:
                    continue
        hosts = bucket.get("hosts")
        rows.append(
            {
                "protocol": str(bucket.get("protocol", "")),
                "packets": int(bucket.get("packets", 0) or 0),
                "bytes": int(bucket.get("bytes", 0) or 0),
                "flow_count": int(bucket.get("flow_count", 0) or 0),
                "host_count": len(hosts) if isinstance(hosts, set) else 0,
                "first_seen": _coerce_ts(bucket.get("first_seen")),
                "last_seen": _coerce_ts(bucket.get("last_seen")),
                "top_ports": top_ports,
            }
        )
    rows.sort(
        key=lambda item: (
            -int(item.get("packets", 0) or 0),
            -int(item.get("bytes", 0) or 0),
            -int(item.get("flow_count", 0) or 0),
            str(item.get("protocol", "")),
        )
    )
    return rows[:limit]


def _service_activity(services, limit: int = 20) -> list[dict[str, object]]:
    buckets: dict[str, dict[str, object]] = {}

    for asset in list(getattr(services, "assets", []) or []):
        service_name = str(getattr(asset, "service_name", "") or "").strip()
        protocol = str(getattr(asset, "protocol", "") or "").upper().strip() or "TCP"
        port = int(getattr(asset, "port", 0) or 0)
        if not service_name:
            service_name = f"{protocol}/{port}"
        bucket = buckets.setdefault(
            service_name,
            {
                "service": service_name,
                "packets": 0,
                "bytes": 0,
                "asset_count": 0,
                "hosts": set(),
                "clients": set(),
                "port_counter": Counter(),
                "host_counter": Counter(),
                "first_seen": None,
                "last_seen": None,
            },
        )
        packets = int(getattr(asset, "packets", 0) or 0)
        bytes_total = int(getattr(asset, "bytes", 0) or 0)
        weight = max(1, packets)
        bucket["packets"] = int(bucket.get("packets", 0) or 0) + packets
        bucket["bytes"] = int(bucket.get("bytes", 0) or 0) + bytes_total
        bucket["asset_count"] = int(bucket.get("asset_count", 0) or 0) + 1

        hosts = bucket.get("hosts")
        clients = bucket.get("clients")
        if isinstance(hosts, set):
            asset_ip = str(getattr(asset, "ip", "") or "").strip()
            if asset_ip:
                hosts.add(asset_ip)
        if isinstance(clients, set):
            for client_ip in set(getattr(asset, "clients", set()) or set()):
                client_text = str(client_ip).strip()
                if client_text:
                    clients.add(client_text)

        port_counter = bucket.get("port_counter")
        if isinstance(port_counter, Counter):
            port_counter[port] += weight
        host_counter = bucket.get("host_counter")
        if isinstance(host_counter, Counter):
            host_ip = str(getattr(asset, "ip", "") or "").strip()
            if host_ip:
                host_counter[host_ip] += weight

        _update_window(
            bucket,
            getattr(asset, "first_seen", None),
            getattr(asset, "last_seen", None),
        )

    for name, count in _all_services(services):
        bucket = buckets.setdefault(
            str(name),
            {
                "service": str(name),
                "packets": 0,
                "bytes": 0,
                "asset_count": 0,
                "hosts": set(),
                "clients": set(),
                "port_counter": Counter(),
                "host_counter": Counter(),
                "first_seen": None,
                "last_seen": None,
            },
        )
        bucket["asset_count"] = max(int(bucket.get("asset_count", 0) or 0), int(count))

    rows: list[dict[str, object]] = []
    for bucket in buckets.values():
        port_counter = bucket.get("port_counter")
        host_counter = bucket.get("host_counter")
        top_ports: list[int] = []
        if isinstance(port_counter, Counter):
            for port_value, _count in port_counter.most_common(4):
                try:
                    top_ports.append(int(port_value))
                except Exception:
                    continue
        top_hosts = _bucket_top_list(host_counter, limit=3, with_counts=True)
        hosts = bucket.get("hosts")
        clients = bucket.get("clients")
        rows.append(
            {
                "service": str(bucket.get("service", "")),
                "asset_count": int(bucket.get("asset_count", 0) or 0),
                "packets": int(bucket.get("packets", 0) or 0),
                "bytes": int(bucket.get("bytes", 0) or 0),
                "host_count": len(hosts) if isinstance(hosts, set) else 0,
                "client_count": len(clients) if isinstance(clients, set) else 0,
                "first_seen": _coerce_ts(bucket.get("first_seen")),
                "last_seen": _coerce_ts(bucket.get("last_seen")),
                "top_ports": top_ports,
                "top_hosts": top_hosts,
            }
        )
    rows.sort(
        key=lambda item: (
            -int(item.get("packets", 0) or 0),
            -int(item.get("bytes", 0) or 0),
            -int(item.get("asset_count", 0) or 0),
            str(item.get("service", "")),
        )
    )
    return rows[:limit]


def _notable_flows(protocols, limit: int = 20) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for conv in list(getattr(protocols, "conversations", []) or []):
        src = str(getattr(conv, "src", "") or "").strip()
        dst = str(getattr(conv, "dst", "") or "").strip()
        if not src or not dst:
            continue
        protocol = str(getattr(conv, "protocol", "") or "Unknown").strip() or "Unknown"
        packets = int(getattr(conv, "packets", 0) or 0)
        bytes_total = int(getattr(conv, "bytes", 0) or 0)
        start_ts = _coerce_ts(getattr(conv, "start_ts", None))
        end_ts = _coerce_ts(getattr(conv, "end_ts", None)) or start_ts
        duration_seconds = (
            max(0.0, float(end_ts or 0.0) - float(start_ts or 0.0))
            if start_ts is not None and end_ts is not None
            else 0.0
        )

        ports: list[int] = []
        for raw in set(getattr(conv, "ports", set()) or set()):
            try:
                port_value = int(raw)
            except Exception:
                continue
            if port_value < 0:
                continue
            ports.append(port_value)
        ports.sort()

        pps = (float(packets) / duration_seconds) if duration_seconds > 0 else 0.0
        bits_per_sec = (
            int((float(bytes_total) * 8.0) / duration_seconds)
            if duration_seconds > 0 and bytes_total > 0
            else 0
        )
        src_scope = _ip_scope(src)
        dst_scope = _ip_scope(dst)
        rows.append(
            {
                "src": src,
                "dst": dst,
                "scope_pair": f"{src_scope}->{dst_scope}",
                "protocol": protocol,
                "packets": packets,
                "bytes": bytes_total,
                "start_ts": start_ts,
                "end_ts": end_ts,
                "duration_seconds": duration_seconds,
                "packets_per_sec": round(pps, 3) if pps else 0.0,
                "bits_per_sec": bits_per_sec,
                "ports": ports,
            }
        )
    rows.sort(
        key=lambda item: (
            -int(item.get("bytes", 0) or 0),
            -int(item.get("packets", 0) or 0),
            -float(item.get("duration_seconds", 0.0) or 0.0),
            str(item.get("src", "")),
            str(item.get("dst", "")),
            str(item.get("protocol", "")),
        )
    )
    return rows[:limit]


def _capture_window(protocols, services) -> tuple[float | None, float | None]:
    first_seen: float | None = None
    last_seen: float | None = None

    for conv in list(getattr(protocols, "conversations", []) or []):
        start_ts = _coerce_ts(getattr(conv, "start_ts", None))
        end_ts = _coerce_ts(getattr(conv, "end_ts", None)) or start_ts
        if start_ts is not None and (first_seen is None or start_ts < first_seen):
            first_seen = start_ts
        if end_ts is not None and (last_seen is None or end_ts > last_seen):
            last_seen = end_ts

    for asset in list(getattr(services, "assets", []) or []):
        start_ts = _coerce_ts(getattr(asset, "first_seen", None))
        end_ts = _coerce_ts(getattr(asset, "last_seen", None)) or start_ts
        if start_ts is not None and (first_seen is None or start_ts < first_seen):
            first_seen = start_ts
        if end_ts is not None and (last_seen is None or end_ts > last_seen):
            last_seen = end_ts

    return first_seen, last_seen


def _cross_zone_flow_count(protocols) -> int:
    count = 0
    for conv in list(getattr(protocols, "conversations", []) or []):
        src = str(getattr(conv, "src", "") or "").strip()
        dst = str(getattr(conv, "dst", "") or "").strip()
        if not src or not dst:
            continue
        zones = {_ip_scope(src), _ip_scope(dst)}
        if zones == {"internal", "public"}:
            count += 1
    return count


def _cross_zone_ot_iot_flow_count(
    *,
    notable_flows: list[dict[str, object]],
    ot_markers: set[str],
    ot_ports: set[int],
) -> int:
    if not notable_flows:
        return 0
    count = 0
    for flow in notable_flows:
        if not isinstance(flow, dict):
            continue
        scope_pair = str(flow.get("scope_pair", "") or "").strip()
        if scope_pair not in {"internal->public", "public->internal"}:
            continue
        ports: list[int] = []
        for raw in list(flow.get("ports", []) or []):
            try:
                port = int(raw)
            except Exception:
                continue
            if port <= 0:
                continue
            ports.append(port)
        if any(port in ot_ports for port in ports):
            count += 1
            continue
        protocol_blob = f" {str(flow.get('protocol', '') or '').lower()} "
        if any(_token_match(protocol_blob, token) for token in ot_markers if token):
            count += 1
    return count


def _build_hunt_leads(
    *,
    ip_activity: list[dict[str, object]],
    notable_flows: list[dict[str, object]],
    module_results: list[OverviewModuleResult],
    ot_markers: list[str],
    limit: int = 12,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    ot_tokens = {str(item).strip().lower() for item in ot_markers if str(item).strip()}

    def add_lead(
        *,
        score: int,
        entity: str,
        finding: str,
        evidence: str,
        first_seen: float | None = None,
        last_seen: float | None = None,
    ) -> None:
        key = (entity.strip(), finding.strip())
        if not key[0] or not key[1] or key in seen:
            return
        seen.add(key)
        priority = "high" if score >= 85 else "medium" if score >= 70 else "low"
        rows.append(
            {
                "score": int(score),
                "priority": priority,
                "entity": entity.strip(),
                "finding": finding.strip(),
                "evidence": evidence.strip(),
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
        )

    for item in ip_activity:
        if not isinstance(item, dict):
            continue
        ip_text = str(item.get("ip", "") or "").strip()
        if not ip_text:
            continue
        sent = int(item.get("packets_sent", 0) or 0)
        recv = int(item.get("packets_recv", 0) or 0)
        packets_total = int(item.get("packets_total", 0) or 0)
        bytes_total = int(item.get("bytes_total", 0) or 0)
        peer_count = int(item.get("peer_count", 0) or 0)
        public_peers = int(item.get("public_peer_count", 0) or 0)
        top_ports = [int(v) for v in list(item.get("top_ports", []) or [])[:6]]
        services_hosted = list(item.get("services_hosted", []) or [])
        services_used = list(item.get("services_used", []) or [])
        protocol_blob = " " + " ".join(
            str(v).lower() for v in list(item.get("top_protocols", []) or [])
        ) + " "
        service_blob = " " + " ".join(
            str(v).lower() for v in services_hosted[:4] + services_used[:4]
        ) + " "
        is_ot_related = any(
            token
            and (
                _token_match(protocol_blob, token)
                or _token_match(service_blob, token)
            )
            for token in ot_tokens
        )
        avg_bytes_per_packet = float(bytes_total) / float(max(1, packets_total))

        first_seen = _coerce_ts(item.get("first_seen"))
        last_seen = _coerce_ts(item.get("last_seen"))

        if sent >= 100 and sent > max(1, recv) * 3 and public_peers >= 1:
            add_lead(
                score=95,
                entity=ip_text,
                finding="Egress-heavy initiator to public peers",
                evidence=(
                    f"sent={sent} recv={recv} public_peers={public_peers} "
                    f"packets={packets_total} bytes={bytes_total}"
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )

        if peer_count >= 12 and len(top_ports) >= 4 and avg_bytes_per_packet <= 220.0:
            add_lead(
                score=88,
                entity=ip_text,
                finding="Broad low-payload multi-peer activity (scan-like)",
                evidence=(
                    f"peers={peer_count} top_ports={','.join(str(p) for p in top_ports[:5])} "
                    f"avg_bytes_per_packet={avg_bytes_per_packet:.1f}"
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )

        if int(item.get("service_count", 0) or 0) >= 3 and peer_count >= 6:
            add_lead(
                score=74,
                entity=ip_text,
                finding="High-interaction service node worth immediate review",
                evidence=(
                    f"services={','.join(str(v) for v in services_hosted[:3]) or '-'} "
                    f"peers={peer_count} packets={packets_total}"
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )

        if is_ot_related and public_peers >= 1:
            context_items = [
                str(v).strip()
                for v in list(item.get("top_protocols", []) or [])[:2]
                + services_hosted[:1]
                + services_used[:1]
                if str(v).strip()
            ]
            protocol_context = ", ".join(dict.fromkeys(context_items))
            add_lead(
                score=92,
                entity=ip_text,
                finding="OT/ICS-speaking host communicating across boundary",
                evidence=(
                    f"ot_signals={protocol_context or '-'} "
                    f"public_peers={public_peers}"
                ),
                first_seen=first_seen,
                last_seen=last_seen,
            )

    for flow in notable_flows[:20]:
        if not isinstance(flow, dict):
            continue
        src = str(flow.get("src", "") or "").strip()
        dst = str(flow.get("dst", "") or "").strip()
        if not src or not dst:
            continue
        protocol = str(flow.get("protocol", "") or "-")
        packets = int(flow.get("packets", 0) or 0)
        bytes_total = int(flow.get("bytes", 0) or 0)
        duration_seconds = float(flow.get("duration_seconds", 0.0) or 0.0)
        pps = float(flow.get("packets_per_sec", 0.0) or 0.0)
        scope_pair = str(flow.get("scope_pair", "") or "")
        ports = [int(v) for v in list(flow.get("ports", []) or [])[:5]]

        if scope_pair in {"internal->public", "public->internal"} and bytes_total >= 2_000_000:
            add_lead(
                score=90,
                entity=f"{src} -> {dst}",
                finding="Large cross-zone transfer",
                evidence=(
                    f"{protocol} ports={','.join(str(v) for v in ports) or '-'} "
                    f"bytes={bytes_total} packets={packets}"
                ),
                first_seen=_coerce_ts(flow.get("start_ts")),
                last_seen=_coerce_ts(flow.get("end_ts")),
            )

        if duration_seconds >= 900 and packets >= 30 and pps <= 0.2:
            add_lead(
                score=72,
                entity=f"{src} -> {dst}",
                finding="Low-and-slow persistent flow",
                evidence=(
                    f"{protocol} duration={duration_seconds:.1f}s packets={packets} "
                    f"pps={pps:.3f} bytes={bytes_total}"
                ),
                first_seen=_coerce_ts(flow.get("start_ts")),
                last_seen=_coerce_ts(flow.get("end_ts")),
            )

    for result in module_results:
        if result.module == "threats":
            high_sev = int(result.metrics.get("high_severity", 0) or 0)
            if high_sev > 0:
                add_lead(
                    score=82,
                    entity="threat-correlation",
                    finding=f"Critical/high detections observed ({high_sev})",
                    evidence=result.highlights[0] if result.highlights else _module_metric_text(result.metrics),
                )
        elif result.module == "scan":
            scanner_count = int(result.metrics.get("scanners", 0) or 0)
            if scanner_count > 0:
                add_lead(
                    score=76,
                    entity="scan-analysis",
                    finding=f"Scanner activity observed ({scanner_count} source hosts)",
                    evidence=result.highlights[0] if result.highlights else _module_metric_text(result.metrics),
                )
        elif result.module == "ot_commands":
            command_count = int(result.metrics.get("commands", 0) or 0)
            burst = int(result.metrics.get("max_burst", 0) or 0)
            try:
                control_rate = float(result.metrics.get("control_rate_per_min", 0.0) or 0.0)
            except Exception:
                control_rate = 0.0
            if command_count > 0 and (burst >= 5 or control_rate >= 8.0):
                add_lead(
                    score=89,
                    entity="ot-command-activity",
                    finding="Burst OT control/write activity observed",
                    evidence=(
                        f"commands={command_count} max_burst={burst} "
                        f"control_rate_per_min={control_rate:.2f}"
                    ),
                )
        elif result.module == "modbus":
            write_ops = int(result.metrics.get("write_ops", 0) or 0)
            anomalies = int(result.metrics.get("anomalies", 0) or 0)
            if write_ops > 0:
                add_lead(
                    score=84,
                    entity="modbus-analysis",
                    finding="Modbus write operations observed",
                    evidence=f"write_ops={write_ops} anomalies={anomalies}",
                )
        elif result.module == "dnp3":
            control_ops = int(result.metrics.get("control_ops", 0) or 0)
            anomalies = int(result.metrics.get("anomalies", 0) or 0)
            if control_ops > 0:
                add_lead(
                    score=84,
                    entity="dnp3-analysis",
                    finding="DNP3 control/file operations observed",
                    evidence=f"control_ops={control_ops} anomalies={anomalies}",
                )

    if not rows:
        for item in ip_activity[:3]:
            if not isinstance(item, dict):
                continue
            ip_text = str(item.get("ip", "") or "").strip()
            if not ip_text:
                continue
            add_lead(
                score=70,
                entity=ip_text,
                finding="Top talker baseline lead for first-pass scoping",
                evidence=(
                    f"packets={int(item.get('packets_total', 0) or 0)} "
                    f"bytes={int(item.get('bytes_total', 0) or 0)} "
                    f"role={str(item.get('role', 'mixed') or 'mixed')}"
                ),
                first_seen=_coerce_ts(item.get("first_seen")),
                last_seen=_coerce_ts(item.get("last_seen")),
            )

    rows.sort(
        key=lambda item: (
            -int(item.get("score", 0) or 0),
            str(item.get("entity", "")),
            str(item.get("finding", "")),
        )
    )
    return rows[:limit]


def _module_metric_text(metrics: dict[str, object]) -> str:
    if not metrics:
        return "-"
    preferred = [
        "detections",
        "high_severity",
        "packets",
        "requests",
        "responses",
        "commands",
        "anomalies",
        "artifacts",
        "hits",
        "findings",
    ]
    parts: list[str] = []
    for key in preferred:
        if key not in metrics:
            continue
        value = metrics[key]
        if value is None:
            continue
        parts.append(f"{key}={value}")
    if not parts:
        for key, value in metrics.items():
            if value is None:
                continue
            parts.append(f"{key}={value}")
            if len(parts) >= 4:
                break
    return ", ".join(parts) if parts else "-"


def _summary_errors(summary: object) -> list[str]:
    errors = getattr(summary, "errors", None)
    if isinstance(errors, list):
        return [str(item) for item in errors if str(item or "").strip()]
    return []


def _build_module_result(module: str, reason: str, summary: object) -> OverviewModuleResult:
    metrics: dict[str, object] = {}
    highlights: list[str] = []
    errors = _summary_errors(summary)

    packets = _first_int(
        summary,
        (
            "protocol_packets",
            "modbus_packets",
            "dnp3_packets",
            "cip_packets",
            "enip_packets",
            "goose_packets",
            "sv_packets",
            "total_packets",
        ),
    )
    if packets is not None:
        metrics["packets"] = packets

    if module == "threats":
        detections = list(getattr(summary, "detections", []) or [])
        metrics["detections"] = len(detections)
        sev_counts: Counter[str] = Counter()
        for item in detections:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or "info").lower()
            if sev in {"critical", "high", "warning", "medium", "info"}:
                sev_counts[sev] += 1
        high_count = int(sev_counts.get("critical", 0) + sev_counts.get("high", 0))
        metrics["high_severity"] = high_count
        ot_risk_score = getattr(summary, "ot_risk_score", None)
        if isinstance(ot_risk_score, int):
            metrics["ot_risk_score"] = ot_risk_score
        if detections:
            highlights.append(
                f"Detections: {len(detections)} (critical/high: {high_count})."
            )
        if isinstance(ot_risk_score, int):
            findings = list(getattr(summary, "ot_risk_findings", []) or [])
            if findings:
                highlights.append(f"OT risk score {ot_risk_score}/100: {_truncate(findings[0], 120)}")
        for item in detections:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or "").lower()
            if sev not in {"critical", "high"}:
                continue
            source = str(item.get("source") or item.get("protocol") or "")
            summary_text = str(item.get("summary") or item.get("title") or "")
            if summary_text:
                prefix = f"{source}: " if source else ""
                highlights.append(prefix + _truncate(summary_text, 120))
            if len(highlights) >= 4:
                break
        if not detections:
            highlights.append("No threat detections were raised by correlation heuristics.")

    elif module == "scan":
        scan_sources = list(getattr(summary, "scan_sources", []) or [])
        scanner_count = int(getattr(summary, "scanner_count", len(scan_sources)) or 0)
        metrics["scanners"] = scanner_count
        if scanner_count:
            top = scan_sources[0]
            scanner_ip = str(getattr(top, "scanner_ip", "-"))
            scan_type = str(getattr(top, "scan_type", "scan"))
            unique_targets = int(getattr(top, "unique_targets", 0) or 0)
            unique_ports = int(getattr(top, "unique_ports", 0) or 0)
            highlights.append(
                f"Top scanner {scanner_ip} ({scan_type}) targeted {unique_targets} hosts / {unique_ports} ports."
            )
        else:
            highlights.append("No explicit scanning patterns were identified.")

    elif module == "ctf":
        hits = _list_len(summary, "hits")
        decoded_hits = _list_len(summary, "decoded_hits")
        candidates = _list_len(summary, "candidate_findings")
        metrics["hits"] = hits
        metrics["decoded_hits"] = decoded_hits
        metrics["candidates"] = candidates
        if hits or decoded_hits or candidates:
            highlights.append(
                f"CTF artifacts: hits={hits}, decoded={decoded_hits}, candidate findings={candidates}."
            )
            for item in list(getattr(summary, "candidate_findings", []) or []):
                if not isinstance(item, dict):
                    continue
                token = (
                    item.get("candidate")
                    or item.get("value")
                    or item.get("finding")
                    or item.get("token")
                    or item.get("context")
                )
                if token:
                    confidence = str(item.get("confidence") or "").strip()
                    prefix = f"[{confidence}] " if confidence else ""
                    highlights.append(prefix + _truncate(token, 110))
                if len(highlights) >= 4:
                    break
        else:
            highlights.append("No CTF-style flag or encoded token hits were detected.")

    elif module == "files":
        artifacts = list(getattr(summary, "artifacts", []) or [])
        detections = list(getattr(summary, "detections", []) or [])
        metrics["artifacts"] = len(artifacts)
        metrics["detections"] = len(detections)
        proto_counter: Counter[str] = Counter()
        executable_hits = 0
        for item in artifacts:
            protocol = str(getattr(item, "protocol", "") or "")
            if protocol:
                proto_counter[protocol] += 1
            filename = str(getattr(item, "filename", "") or "").lower()
            file_type = str(getattr(item, "file_type", "") or "").upper()
            if (
                file_type in {"EXE/DLL", "ELF"}
                or filename.endswith((".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".js"))
            ):
                executable_hits += 1
        metrics["executable_artifacts"] = executable_hits
        if artifacts:
            highlights.append(
                f"File artifacts={len(artifacts)} across protocols: {_counter_preview(proto_counter, 4)}."
            )
            if executable_hits:
                highlights.append(f"Executable/script-like artifacts: {executable_hits}.")
        else:
            highlights.append("No file transfer artifacts were carved from observed traffic.")
        for item in detections[:2]:
            if isinstance(item, dict):
                detail = str(item.get("summary") or item.get("details") or "").strip()
                if detail:
                    highlights.append(_truncate(detail, 120))

    elif module == "ot_commands":
        command_counts = _counter_from_obj(getattr(summary, "command_counts", None))
        total_commands = int(sum(command_counts.values()))
        metrics["commands"] = total_commands
        control_rate = getattr(summary, "control_rate_per_min", None)
        if control_rate is not None:
            try:
                metrics["control_rate_per_min"] = round(float(control_rate), 2)
            except Exception:
                pass
        burst_max = getattr(summary, "control_burst_max", None)
        if burst_max is not None:
            try:
                metrics["max_burst"] = int(burst_max)
            except Exception:
                pass
        highlights.append(
            f"OT command volume={total_commands}; top commands: {_counter_preview(command_counts, 4)}."
        )

    elif module == "control_loop":
        total_changes = int(getattr(summary, "total_changes", 0) or 0)
        findings = _list_len(summary, "findings")
        metrics["total_changes"] = total_changes
        metrics["findings"] = findings
        kind_counts = _counter_from_obj(getattr(summary, "kind_counts", None))
        if total_changes:
            highlights.append(
                f"Control-loop changes={total_changes}, findings={findings}, kinds={_counter_preview(kind_counts, 3)}."
            )
        else:
            highlights.append("No material Modbus/DNP3 process value changes were observed.")

    elif module == "safety":
        hits = _list_len(summary, "hits")
        metrics["hits"] = hits
        service_counts = _counter_from_obj(getattr(summary, "service_counts", None))
        if hits:
            highlights.append(
                f"Safety/SIS traffic observed ({hits} packets), services: {_counter_preview(service_counts, 3)}."
            )
        else:
            highlights.append("No safety protocol traffic was observed on known SIS ports.")

    elif module == "modbus":
        func_counts = _counter_from_obj(getattr(summary, "func_counts", None))
        anomalies = _list_len(summary, "anomalies")
        writes = sum(
            count for name, count in func_counts.items() if "write" in name.lower()
        )
        metrics["commands"] = int(sum(func_counts.values()))
        metrics["write_ops"] = int(writes)
        metrics["anomalies"] = anomalies
        highlights.append(
            f"Modbus functions: {_counter_preview(func_counts, 4)} (write ops={writes}, anomalies={anomalies})."
        )

    elif module == "dnp3":
        func_counts = _counter_from_obj(getattr(summary, "func_counts", None))
        anomalies = _list_len(summary, "anomalies")
        control_hits = 0
        control_tokens = ("operate", "write", "restart", "freeze", "file", "control")
        for name, count in func_counts.items():
            lowered = name.lower()
            if any(token in lowered for token in control_tokens):
                control_hits += int(count)
        metrics["commands"] = int(sum(func_counts.values()))
        metrics["control_ops"] = int(control_hits)
        metrics["anomalies"] = anomalies
        highlights.append(
            f"DNP3 functions: {_counter_preview(func_counts, 4)} (control/file ops={control_hits}, anomalies={anomalies})."
        )

    else:
        requests = _first_int(summary, ("requests",))
        responses = _first_int(summary, ("responses",))
        anomalies = _list_len(summary, "anomalies")
        detections = _list_len(summary, "detections")
        artifacts = _list_len(summary, "artifacts")
        commands = _first_counter(
            summary,
            (
                "commands",
                "func_counts",
                "cip_services",
                "enip_commands",
                "service_counts",
                "app_ids",
                "data_type_counts",
                "dcp_services",
                "protocol_counts",
            ),
        )
        if requests is not None:
            metrics["requests"] = requests
        if responses is not None:
            metrics["responses"] = responses
        if commands:
            metrics["commands"] = int(sum(commands.values()))
        if anomalies:
            metrics["anomalies"] = anomalies
        if detections:
            metrics["detections"] = detections
        if artifacts:
            metrics["artifacts"] = artifacts
        high_risk_services = _counter_from_obj(
            getattr(summary, "high_risk_services", None)
        )
        if high_risk_services:
            metrics["high_risk_ops"] = int(sum(high_risk_services.values()))
            highlights.append(
                f"High-risk operations: {_counter_preview(high_risk_services, 3)}."
            )
        label = _MODULE_LABELS.get(module, module.upper())
        detail_parts: list[str] = []
        if packets is not None:
            detail_parts.append(f"packets={packets}")
        if requests is not None or responses is not None:
            detail_parts.append(f"req/resp={requests or 0}/{responses or 0}")
        if commands:
            detail_parts.append(f"operations={_counter_preview(commands, 3)}")
        if anomalies:
            detail_parts.append(f"anomalies={anomalies}")
        if detections:
            detail_parts.append(f"detections={detections}")
        if not detail_parts:
            detail_parts.append(_module_metric_text(metrics))
        highlights.append(f"{label}: " + "; ".join(detail_parts))

    if errors:
        highlights.append(f"Errors: {_truncate(errors[0], 120)}")

    return OverviewModuleResult(
        module=module,
        reason=reason,
        metrics=metrics,
        highlights=_dedupe_limited(highlights, 5),
        errors=_dedupe_limited(errors, 8),
    )


def analyze_overview(
    path: Path,
    *,
    show_status: bool = True,
    vt_lookup: bool = False,
    ot_commands_fast: bool = False,
    ot_commands_config: OtControlConfig | None = None,
) -> OverviewSummary:
    base_summary = analyze_pcap(path, show_status=show_status)
    protocol_summary = analyze_protocols(path, show_status=show_status)
    services_summary = analyze_services(path, show_status=show_status)

    top_protocols = [
        (str(name), int(count))
        for name, count in list(getattr(protocol_summary, "top_protocols", []) or [])
    ]
    top_services = _top_services(services_summary, limit=12)
    ip_activity = _ip_activity(protocol_summary, services_summary, limit=24)
    observed_ips = _observed_ips(protocol_summary, services_summary, limit=20)
    protocol_activity = _protocol_activity(protocol_summary, limit=24)
    service_activity = _service_activity(services_summary, limit=24)
    notable_flows = _notable_flows(protocol_summary, limit=30)
    capture_start, capture_end = _capture_window(protocol_summary, services_summary)

    observed_protocols = [
        (str(item.get("protocol", "")), int(item.get("packets", 0) or 0))
        for item in protocol_activity
        if str(item.get("protocol", "")).strip()
        and int(item.get("packets", 0) or 0) > 0
    ]
    if not observed_protocols:
        observed_protocols = list(top_protocols)

    observed_services = [
        (str(item.get("service", "")), int(item.get("asset_count", 0) or 0))
        for item in service_activity
        if str(item.get("service", "")).strip()
        and int(item.get("asset_count", 0) or 0) > 0
    ]
    if not observed_services:
        observed_services = _all_services(services_summary)

    labels_blob = _build_label_blob(protocol_summary, services_summary)
    detected_ot = _detect_ot_modules(labels_blob)
    detected_by_port = _detect_ot_modules_from_ports(protocol_summary, services_summary)

    detected_ot_steps: list[str] = []
    detected_meta: dict[str, dict[str, object]] = {}

    def _register_detected(
        step: str,
        *,
        label: str,
        inventory: bool,
        ports: list[int] | None = None,
    ) -> None:
        if step not in detected_meta:
            detected_meta[step] = {
                "label": label,
                "inventory": False,
                "ports": [],
            }
            detected_ot_steps.append(step)
        meta = detected_meta[step]
        if inventory:
            meta["inventory"] = True
        if ports:
            existing_ports = [int(v) for v in list(meta.get("ports", []) or [])]
            existing_ports.extend(int(v) for v in ports)
            meta["ports"] = sorted(set(existing_ports))

    for step, label in detected_ot:
        _register_detected(step, label=label, inventory=True)
    for step, ports in detected_by_port.items():
        _register_detected(
            step,
            label=_MODULE_LABELS.get(step, step.upper()),
            inventory=False,
            ports=ports,
        )

    detected_ot_labels = [
        str(detected_meta.get(step, {}).get("label") or _MODULE_LABELS.get(step, step))
        for step in detected_ot_steps
    ]
    ot_markers = _ot_marker_tokens(detected_ot_steps, detected_ot_labels)
    detected_iot_labels = _iot_labels_from_ot_labels(detected_ot_labels)

    has_file_hints = any(_token_match(labels_blob, token) for token in _FILE_TRANSFER_HINTS)

    plan: list[tuple[str, str, Callable[[], object]]] = []
    seen_modules: set[str] = set()

    def add_module(module: str, reason: str, runner: Callable[[], object]) -> None:
        if module in seen_modules:
            return
        seen_modules.add(module)
        plan.append((module, reason, runner))

    add_module(
        "threats",
        "Correlate detections across IT and OT protocols for hunt triage.",
        lambda: analyze_threats(path, show_status=show_status, vt_lookup=vt_lookup),
    )
    add_module(
        "scan",
        "Expose reconnaissance and lateral movement setup indicators.",
        lambda: analyze_scan(path, show_status=show_status),
    )
    add_module(
        "ctf",
        "Find potential flags/tokens and decode-able artifacts for challenge workflows.",
        lambda: analyze_ctf(path, show_status=show_status),
    )

    if has_file_hints:
        add_module(
            "files",
            "Protocol/service mix suggests transferable artifacts worth carving.",
            lambda: analyze_files(path, show_status=show_status),
        )

    if detected_ot_steps:
        add_module(
            "ot_commands",
            "OT protocol families detected; normalize control/write command activity.",
            lambda: analyze_ot_commands(
                path,
                show_status=show_status,
                fast=ot_commands_fast,
                config=ot_commands_config,
            ),
        )
        add_module(
            "safety",
            "Check for safety PLC/SIS communications and exposure indicators.",
            lambda: analyze_safety(path, show_status=show_status),
        )
        if "modbus" in detected_ot_steps or "dnp3" in detected_ot_steps:
            add_module(
                "control_loop",
                "Modbus/DNP3 present; evaluate process value changes for control instability.",
                lambda: analyze_control_loop(path, show_status=show_status),
            )

    ot_runners: dict[str, Callable[[], object]] = {
        "modbus": lambda: analyze_modbus(path, show_status=show_status),
        "dnp3": lambda: analyze_dnp3(path, show_status=show_status),
        "iec104": lambda: analyze_iec104(path, show_status=show_status),
        "bacnet": lambda: analyze_bacnet(path, show_status=show_status),
        "enip": lambda: analyze_enip(path, show_status=show_status),
        "cip": lambda: analyze_cip(path, show_status=show_status),
        "profinet": lambda: analyze_profinet(path, show_status=show_status),
        "s7": lambda: analyze_s7(path, show_status=show_status),
        "opc": lambda: analyze_opc(path, show_status=show_status),
        "mms": lambda: analyze_mms(path, show_status=show_status),
        "goose": lambda: analyze_goose(path, show_status=show_status),
        "sv": lambda: analyze_sv(path, show_status=show_status),
        "lldp": lambda: analyze_lldp_dcp(path, show_status=show_status),
        "ptp": lambda: analyze_ptp(path, show_status=show_status),
        "mqtt": lambda: analyze_mqtt(path, show_status=show_status),
        "coap": lambda: analyze_coap(path, show_status=show_status),
        "hart": lambda: analyze_hart(path, show_status=show_status),
        "niagara": lambda: analyze_niagara(path, show_status=show_status),
        "odesys": lambda: analyze_odesys(path, show_status=show_status),
    }

    for step in detected_ot_steps[:_AUTO_OT_DEEP_DIVE_LIMIT]:
        runner = ot_runners.get(step)
        if runner is None:
            continue
        label = _MODULE_LABELS.get(step, step.upper())
        reason_parts: list[str] = []
        meta = detected_meta.get(step, {})
        if bool(meta.get("inventory", False)):
            reason_parts.append("protocol/service labels")
        port_hits = [int(v) for v in list(meta.get("ports", []) or [])]
        if port_hits:
            reason_parts.append("well-known ports " + ",".join(str(v) for v in port_hits[:4]))
        reason = f"Detected {label} in protocol/service inventory."
        if reason_parts:
            reason = f"Detected {label} via " + " and ".join(reason_parts) + "."
        add_module(step, reason, runner)

    module_results: list[OverviewModuleResult] = []
    modules_run = [module for module, _reason, _runner in plan]
    all_errors = [
        str(item)
        for item in list(getattr(protocol_summary, "errors", []) or [])
        + list(getattr(services_summary, "errors", []) or [])
        if str(item or "").strip()
    ]

    for module, reason, runner in plan:
        try:
            summary = runner()
        except Exception as exc:
            error_text = f"{type(exc).__name__}: {exc}"
            module_results.append(
                OverviewModuleResult(
                    module=module,
                    reason=reason,
                    metrics={},
                    highlights=[f"{_MODULE_LABELS.get(module, module.upper())} failed: {error_text}"],
                    errors=[error_text],
                )
            )
            all_errors.append(f"{module}: {error_text}")
            continue

        module_result = _build_module_result(module, reason, summary)
        module_results.append(module_result)
        all_errors.extend(module_result.errors)

    module_lookup = {result.module: result for result in module_results}
    hunt_leads = _build_hunt_leads(
        ip_activity=ip_activity,
        notable_flows=notable_flows,
        module_results=module_results,
        ot_markers=sorted(ot_markers),
        limit=14,
    )

    ot_iot_ports = {
        int(port)
        for step in detected_ot_steps
        for port in _OT_PORT_HINTS.get(step, ())
    }
    cross_zone_ot_iot_flows = _cross_zone_ot_iot_flow_count(
        notable_flows=notable_flows,
        ot_markers=ot_markers,
        ot_ports=ot_iot_ports,
    )

    ot_highlights: list[str] = []
    if detected_ot_labels:
        ot_highlights.append(
            "Detected OT/ICS protocol families: " + ", ".join(detected_ot_labels[:10])
        )
    if detected_iot_labels:
        ot_highlights.append(
            "Detected IoT protocol families: " + ", ".join(detected_iot_labels[:6])
        )
    for result in module_results:
        if result.module in _OT_MODULES:
            ot_highlights.extend(result.highlights[:2])

    hunt_highlights: list[str] = []
    for key in ("threats", "scan", "ot_commands", "control_loop", "safety"):
        result = module_lookup.get(key)
        if result:
            hunt_highlights.extend(result.highlights[:2])
    protocol_verdict = str(getattr(protocol_summary, "analyst_verdict", "") or "").strip()
    if protocol_verdict:
        hunt_highlights.append(f"Protocol posture: {protocol_verdict}")
    service_verdict = str(getattr(services_summary, "analyst_verdict", "") or "").strip()
    if service_verdict:
        hunt_highlights.append(f"Service posture: {service_verdict}")
    for lead in hunt_leads[:4]:
        entity = str(lead.get("entity", "") or "").strip()
        finding = str(lead.get("finding", "") or "").strip()
        if entity and finding:
            hunt_highlights.append(f"{entity}: {finding}")

    forensics_highlights: list[str] = []
    files_result = module_lookup.get("files")
    if files_result:
        forensics_highlights.extend(files_result.highlights[:3])
    threats_result = module_lookup.get("threats")
    if threats_result:
        forensics_highlights.extend(threats_result.highlights[:2])
    if top_services:
        top_service_text = ", ".join(
            f"{name}({count})" for name, count in top_services[:5]
        )
        forensics_highlights.append(f"Top observed services: {top_service_text}.")

    ctf_highlights: list[str] = []
    ctf_result = module_lookup.get("ctf")
    if ctf_result:
        ctf_highlights.extend(ctf_result.highlights[:4])

    recommendations: list[str] = []
    if detected_ot_steps:
        next_flags = []
        for step in detected_ot_steps[:4]:
            flag = "--lldp" if step == "lldp" else f"--{step}"
            next_flags.append(flag)
        recommendations.append(
            "Deep-dive detected OT families with: " + " ".join(next_flags)
        )

    if threats_result:
        high_sev = int(threats_result.metrics.get("high_severity", 0) or 0)
        if high_sev > 0:
            recommendations.append(
                "Prioritize critical/high detections with `--threats --mitre` and scope hosts using `--hostdetails -ip <host>`.")
        ot_risk_score = int(threats_result.metrics.get("ot_risk_score", 0) or 0)
        if ot_risk_score >= 60:
            recommendations.append(
                f"OT risk posture is elevated ({ot_risk_score}/100); verify approved engineering actions and map findings to zones/conduits before remediation."
            )

    if files_result:
        artifacts = int(files_result.metrics.get("artifacts", 0) or 0)
        if artifacts > 0:
            recommendations.append(
                "Investigate transfer artifacts with `--files` and, if needed, extraction/hash options (`-extract`, `-hash`, `-view`)."
            )

    if ctf_result:
        ctf_candidates = int(ctf_result.metrics.get("candidates", 0) or 0)
        if ctf_candidates > 0:
            recommendations.append(
                "CTF candidates found; follow up with `--ctf --strings --decode <token>` for deeper decoding chains."
            )

    ot_commands_result = module_lookup.get("ot_commands")
    if ot_commands_result:
        burst = int(ot_commands_result.metrics.get("max_burst", 0) or 0)
        try:
            control_rate = float(
                ot_commands_result.metrics.get("control_rate_per_min", 0.0) or 0.0
            )
        except Exception:
            control_rate = 0.0
        if burst >= 5 or control_rate >= 8.0:
            recommendations.append(
                "Elevated OT control/write cadence detected; validate maintenance windows and authorized engineering workstations with `--ot-commands`."
            )

    safety_result = module_lookup.get("safety")
    if safety_result and int(safety_result.metrics.get("hits", 0) or 0) > 0:
        recommendations.append(
            "Safety/SIS traffic was observed; confirm strict isolation and one-way monitoring between SIS and process control networks."
        )

    modbus_result = module_lookup.get("modbus")
    if modbus_result and int(modbus_result.metrics.get("write_ops", 0) or 0) > 0:
        recommendations.append(
            "Modbus write operations were observed; correlate with approved change records and inspect affected controllers with `--modbus`."
        )

    dnp3_result = module_lookup.get("dnp3")
    if dnp3_result and int(dnp3_result.metrics.get("control_ops", 0) or 0) > 0:
        recommendations.append(
            "DNP3 control/file operations were observed; validate master authorization and outstation control policy using `--dnp3`."
        )

    if cross_zone_ot_iot_flows > 0:
        recommendations.append(
            "OT/IoT protocol traffic crosses internal/public boundaries; validate segmentation, jump-host controls, and boundary ACLs before further action."
        )

    if detected_iot_labels:
        recommendations.append(
            "IoT messaging protocols detected; verify broker/device authentication, topic ACLs, and TLS usage for MQTT/CoAP paths."
        )

    if len(detected_ot_steps) > _AUTO_OT_DEEP_DIVE_LIMIT:
        overflow = detected_ot_steps[_AUTO_OT_DEEP_DIVE_LIMIT :]
        recommendations.append(
            "Additional OT protocol families detected beyond auto-limit: "
            + ", ".join(_MODULE_LABELS.get(item, item.upper()) for item in overflow[:6])
            + ". Run dedicated flags for full depth."
        )
    if hunt_leads:
        top_entity = str(hunt_leads[0].get("entity", "") or "").strip()
        if top_entity and "->" not in top_entity and top_entity not in {
            "threat-correlation",
            "scan-analysis",
        }:
            recommendations.append(
                f"Start host scoping with `--hostdetails -ip {top_entity}` then inspect related flows with `--streams -ip {top_entity}`."
            )

    module_error_count = sum(1 for item in module_results if item.errors)
    unique_protocols = len({name for name, _count in observed_protocols})
    unique_services = len({name for name, _count in observed_services})
    scope_counts: Counter[str] = Counter(
        str(item.get("scope", "unknown")) for item in ip_activity if isinstance(item, dict)
    )
    flow_count = len(list(getattr(protocol_summary, "conversations", []) or []))
    cross_zone_flows = _cross_zone_flow_count(protocol_summary)
    capture_span_seconds = (
        int(max(0.0, float(capture_end or 0.0) - float(capture_start or 0.0)))
        if capture_start is not None and capture_end is not None
        else int(max(0.0, float(getattr(base_summary, "duration_seconds", 0.0) or 0.0)))
    )
    summary_details = {
        "unique_ips": len(ip_activity),
        "unique_protocols": unique_protocols,
        "unique_services": unique_services,
        "internal_ips": int(scope_counts.get("internal", 0)),
        "public_ips": int(scope_counts.get("public", 0)),
        "flow_count": flow_count,
        "cross_zone_flows": cross_zone_flows,
        "cross_zone_ot_iot_flows": cross_zone_ot_iot_flows,
        "hunt_leads": len(hunt_leads),
        "capture_span_seconds": capture_span_seconds,
        "module_count": len(modules_run),
        "module_errors": module_error_count,
        "ot_family_count": len(detected_ot_labels),
        "iot_family_count": len(detected_iot_labels),
        "protocol_anomalies": len(list(getattr(protocol_summary, "anomalies", []) or [])),
        "service_risks": len(list(getattr(services_summary, "risks", []) or [])),
    }

    return OverviewSummary(
        path=path,
        total_packets=int(getattr(base_summary, "packet_count", 0) or 0),
        duration_seconds=float(getattr(base_summary, "duration_seconds", 0.0) or 0.0),
        top_protocols=top_protocols[:12],
        top_services=top_services,
        observed_ips=observed_ips,
        observed_protocols=observed_protocols[:20],
        observed_services=observed_services[:20],
        summary_details=summary_details,
        ot_protocols=detected_ot_labels,
        modules_run=modules_run,
        module_results=module_results,
        ot_highlights=_dedupe_limited(ot_highlights, 8),
        hunt_highlights=_dedupe_limited(hunt_highlights, 10),
        forensics_highlights=_dedupe_limited(forensics_highlights, 10),
        ctf_highlights=_dedupe_limited(ctf_highlights, 8),
        recommendations=_dedupe_limited(recommendations, 8),
        errors=_dedupe_limited(all_errors, 16),
        capture_start=capture_start,
        capture_end=capture_end,
        ip_activity=ip_activity,
        protocol_activity=protocol_activity,
        service_activity=service_activity,
        notable_flows=notable_flows,
        hunt_leads=hunt_leads,
    )


def merge_overview_summaries(summaries: list[OverviewSummary]) -> OverviewSummary:
    if not summaries:
        return OverviewSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            duration_seconds=0.0,
            top_protocols=[],
            top_services=[],
            observed_ips=[],
            observed_protocols=[],
            observed_services=[],
            summary_details={},
            ot_protocols=[],
            modules_run=[],
            module_results=[],
            ot_highlights=[],
            hunt_highlights=[],
            forensics_highlights=[],
            ctf_highlights=[],
            recommendations=[],
            errors=[],
            capture_start=None,
            capture_end=None,
            ip_activity=[],
            protocol_activity=[],
            service_activity=[],
            notable_flows=[],
            hunt_leads=[],
        )

    total_packets = sum(int(item.total_packets) for item in summaries)
    duration_seconds = sum(float(item.duration_seconds or 0.0) for item in summaries)
    capture_start: float | None = None
    capture_end: float | None = None

    protocol_counter: Counter[str] = Counter()
    service_counter: Counter[str] = Counter()
    ip_aggregate: dict[str, dict[str, object]] = {}

    role_rank = {
        "service-host": 5,
        "mixed": 4,
        "initiator-heavy": 3,
        "responder-heavy": 3,
        "client": 2,
    }

    for summary in summaries:
        if summary.capture_start is not None and (
            capture_start is None or float(summary.capture_start) < capture_start
        ):
            capture_start = float(summary.capture_start)
        if summary.capture_end is not None and (
            capture_end is None or float(summary.capture_end) > capture_end
        ):
            capture_end = float(summary.capture_end)

        protocol_source = summary.observed_protocols or summary.top_protocols
        service_source = summary.observed_services or summary.top_services
        for name, count in protocol_source:
            protocol_counter[str(name)] += int(count)
        for name, count in service_source:
            service_counter[str(name)] += int(count)

        ip_rows = summary.ip_activity or summary.observed_ips
        for row in ip_rows:
            if not isinstance(row, dict):
                continue
            ip_text = str(row.get("ip", "") or "").strip()
            if not ip_text:
                continue
            bucket = ip_aggregate.setdefault(
                ip_text,
                {
                    "ip": ip_text,
                    "scope": "unknown",
                    "role": "mixed",
                    "role_score": 0,
                    "activity_notes": set(),
                    "packets_sent": 0,
                    "packets_recv": 0,
                    "packets_total": 0,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "bytes_total": 0,
                    "conversation_count": 0,
                    "peer_count": 0,
                    "public_peer_count": 0,
                    "internal_peer_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "protocol_counter": Counter(),
                    "peer_counter": Counter(),
                    "port_counter": Counter(),
                    "services_hosted_counter": Counter(),
                    "services_used_counter": Counter(),
                    "service_count": 0,
                    "used_service_count": 0,
                },
            )

            scope = str(row.get("scope", "") or "").strip()
            if scope and str(bucket.get("scope", "unknown")) == "unknown":
                bucket["scope"] = scope

            role_text = str(row.get("role", "") or "").strip()
            rank = role_rank.get(role_text, 1)
            if rank >= int(bucket.get("role_score", 0) or 0):
                bucket["role"] = role_text or str(bucket.get("role", "mixed"))
                bucket["role_score"] = rank

            activity = str(row.get("activity", "") or "").strip()
            notes = bucket.get("activity_notes")
            if activity and isinstance(notes, set):
                notes.add(activity)

            for field_name in (
                "packets_sent",
                "packets_recv",
                "packets_total",
                "bytes_sent",
                "bytes_recv",
                "bytes_total",
                "conversation_count",
                "peer_count",
                "public_peer_count",
                "internal_peer_count",
            ):
                try:
                    bucket[field_name] = int(bucket.get(field_name, 0) or 0) + int(
                        row.get(field_name, 0) or 0
                    )
                except Exception:
                    continue

            bucket["service_count"] = int(bucket.get("service_count", 0) or 0) + int(
                row.get("service_count", 0) or 0
            )
            bucket["used_service_count"] = int(
                bucket.get("used_service_count", 0) or 0
            ) + int(row.get("used_service_count", 0) or 0)

            first_seen = _coerce_ts(row.get("first_seen"))
            last_seen = _coerce_ts(row.get("last_seen"))
            current_first = _coerce_ts(bucket.get("first_seen"))
            current_last = _coerce_ts(bucket.get("last_seen"))
            if first_seen is not None and (
                current_first is None or first_seen < current_first
            ):
                bucket["first_seen"] = first_seen
            if last_seen is not None and (current_last is None or last_seen > current_last):
                bucket["last_seen"] = last_seen

            protocol_values = list(
                row.get("top_protocols", row.get("protocols", [])) or []
            )
            protocol_counter_bucket = bucket.get("protocol_counter")
            if isinstance(protocol_counter_bucket, Counter):
                for proto in protocol_values[:8]:
                    text = str(proto).strip()
                    if text:
                        protocol_counter_bucket[text] += 1

            peer_values = list(row.get("top_peers", []) or [])
            peer_counter_bucket = bucket.get("peer_counter")
            if isinstance(peer_counter_bucket, Counter):
                for peer_value in peer_values[:8]:
                    text = str(peer_value).strip()
                    if not text:
                        continue
                    match = re.match(r"^(.*)\((\d+)\)$", text)
                    if match:
                        peer_name = str(match.group(1)).strip()
                        peer_count = int(match.group(2))
                    else:
                        peer_name = text
                        peer_count = 1
                    if peer_name:
                        peer_counter_bucket[peer_name] += max(1, peer_count)

            port_counter_bucket = bucket.get("port_counter")
            if isinstance(port_counter_bucket, Counter):
                for port_value in list(row.get("top_ports", []) or [])[:10]:
                    try:
                        port_counter_bucket[int(port_value)] += 1
                    except Exception:
                        continue

            hosted_counter_bucket = bucket.get("services_hosted_counter")
            if isinstance(hosted_counter_bucket, Counter):
                for svc in list(row.get("services_hosted", []) or [])[:8]:
                    text = str(svc).strip()
                    if text:
                        hosted_counter_bucket[text] += 1

            used_counter_bucket = bucket.get("services_used_counter")
            if isinstance(used_counter_bucket, Counter):
                for svc in list(row.get("services_used", []) or [])[:8]:
                    text = str(svc).strip()
                    if text:
                        used_counter_bucket[text] += 1

    modules_run: list[str] = []
    seen_modules: set[str] = set()
    module_bucket: dict[str, dict[str, object]] = {}
    for summary in summaries:
        for module in summary.modules_run:
            if module not in seen_modules:
                seen_modules.add(module)
                modules_run.append(module)
        for result in summary.module_results:
            bucket = module_bucket.setdefault(
                result.module,
                {
                    "reason": result.reason,
                    "metrics": {},
                    "highlights": [],
                    "errors": [],
                    "pcaps": 0,
                },
            )
            bucket["pcaps"] = int(bucket.get("pcaps", 0) or 0) + 1
            metrics = bucket.get("metrics")
            if not isinstance(metrics, dict):
                metrics = {}
                bucket["metrics"] = metrics
            for key, value in result.metrics.items():
                existing = metrics.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    if isinstance(existing, (int, float)) and not isinstance(
                        existing, bool
                    ):
                        metrics[key] = existing + value
                    elif existing is None:
                        metrics[key] = value
                elif existing is None:
                    metrics[key] = value
            bucket_highlights = bucket.get("highlights")
            if isinstance(bucket_highlights, list):
                bucket_highlights.extend(result.highlights)
            bucket_errors = bucket.get("errors")
            if isinstance(bucket_errors, list):
                bucket_errors.extend(result.errors)

    module_results: list[OverviewModuleResult] = []
    for module in modules_run:
        bucket = module_bucket.get(module)
        if not isinstance(bucket, dict):
            continue
        metrics = dict(bucket.get("metrics") or {})
        metrics.setdefault("pcaps", int(bucket.get("pcaps", 0) or 0))
        module_results.append(
            OverviewModuleResult(
                module=module,
                reason=str(bucket.get("reason") or ""),
                metrics=metrics,
                highlights=_dedupe_limited(
                    [str(item) for item in list(bucket.get("highlights") or [])], 6
                ),
                errors=_dedupe_limited(
                    [str(item) for item in list(bucket.get("errors") or [])], 10
                ),
            )
        )

    merged_ip_activity: list[dict[str, object]] = []
    merged_observed_ips: list[dict[str, object]] = []
    for bucket in ip_aggregate.values():
        protocols = _bucket_top_list(bucket.get("protocol_counter"), limit=5)
        peers = _bucket_top_list(bucket.get("peer_counter"), limit=4, with_counts=True)
        services_hosted = _bucket_top_list(
            bucket.get("services_hosted_counter"), limit=4
        )
        services_used = _bucket_top_list(bucket.get("services_used_counter"), limit=4)

        top_ports: list[int] = []
        port_counter = bucket.get("port_counter")
        if isinstance(port_counter, Counter):
            for port_value, _count in port_counter.most_common(6):
                try:
                    top_ports.append(int(port_value))
                except Exception:
                    continue

        activity_notes = bucket.get("activity_notes")
        activity = ""
        if isinstance(activity_notes, set):
            activity = "; ".join(sorted(str(v) for v in activity_notes if str(v).strip())[:2])

        row = {
            "ip": str(bucket.get("ip", "")),
            "scope": str(bucket.get("scope", "unknown")),
            "role": str(bucket.get("role", "mixed")),
            "activity": activity or "-",
            "packets_sent": int(bucket.get("packets_sent", 0) or 0),
            "packets_recv": int(bucket.get("packets_recv", 0) or 0),
            "packets_total": int(bucket.get("packets_total", 0) or 0),
            "bytes_sent": int(bucket.get("bytes_sent", 0) or 0),
            "bytes_recv": int(bucket.get("bytes_recv", 0) or 0),
            "bytes_total": int(bucket.get("bytes_total", 0) or 0),
            "conversation_count": int(bucket.get("conversation_count", 0) or 0),
            "peer_count": int(bucket.get("peer_count", 0) or 0),
            "public_peer_count": int(bucket.get("public_peer_count", 0) or 0),
            "internal_peer_count": int(bucket.get("internal_peer_count", 0) or 0),
            "first_seen": _coerce_ts(bucket.get("first_seen")),
            "last_seen": _coerce_ts(bucket.get("last_seen")),
            "protocol_count": len(protocols),
            "protocols": protocols,
            "top_protocols": protocols,
            "top_peers": peers,
            "top_ports": top_ports,
            "services_hosted": services_hosted,
            "services_used": services_used,
            "service_count": int(bucket.get("service_count", 0) or 0),
            "used_service_count": int(bucket.get("used_service_count", 0) or 0),
        }
        merged_ip_activity.append(row)
        merged_observed_ips.append(row)

    merged_ip_activity.sort(
        key=lambda item: (
            -int(item.get("bytes_total", 0) or 0),
            -int(item.get("packets_total", 0) or 0),
            -int(item.get("peer_count", 0) or 0),
            str(item.get("ip", "")),
        )
    )
    merged_observed_ips.sort(
        key=lambda item: (
            -int(item.get("bytes_total", 0) or 0),
            -int(item.get("packets_total", 0) or 0),
            str(item.get("ip", "")),
        )
    )

    protocol_activity_bucket: dict[str, dict[str, object]] = {}
    for summary in summaries:
        source_rows = summary.protocol_activity
        if not source_rows:
            source_rows = [
                {"protocol": name, "packets": count}
                for name, count in (summary.observed_protocols or summary.top_protocols)
            ]
        for row in source_rows:
            if not isinstance(row, dict):
                continue
            protocol_name = str(row.get("protocol", "") or "").strip()
            if not protocol_name:
                continue
            bucket = protocol_activity_bucket.setdefault(
                protocol_name,
                {
                    "protocol": protocol_name,
                    "packets": 0,
                    "bytes": 0,
                    "flow_count": 0,
                    "host_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "port_counter": Counter(),
                },
            )
            bucket["packets"] = int(bucket.get("packets", 0) or 0) + int(
                row.get("packets", 0) or 0
            )
            bucket["bytes"] = int(bucket.get("bytes", 0) or 0) + int(
                row.get("bytes", 0) or 0
            )
            bucket["flow_count"] = int(bucket.get("flow_count", 0) or 0) + int(
                row.get("flow_count", 0) or 0
            )
            bucket["host_count"] = int(bucket.get("host_count", 0) or 0) + int(
                row.get("host_count", 0) or 0
            )
            first_seen = _coerce_ts(row.get("first_seen"))
            last_seen = _coerce_ts(row.get("last_seen"))
            current_first = _coerce_ts(bucket.get("first_seen"))
            current_last = _coerce_ts(bucket.get("last_seen"))
            if first_seen is not None and (
                current_first is None or first_seen < current_first
            ):
                bucket["first_seen"] = first_seen
            if last_seen is not None and (current_last is None or last_seen > current_last):
                bucket["last_seen"] = last_seen
            port_counter = bucket.get("port_counter")
            if isinstance(port_counter, Counter):
                for port in list(row.get("top_ports", []) or [])[:8]:
                    try:
                        port_counter[int(port)] += 1
                    except Exception:
                        continue

    merged_protocol_activity: list[dict[str, object]] = []
    for bucket in protocol_activity_bucket.values():
        top_ports: list[int] = []
        port_counter = bucket.get("port_counter")
        if isinstance(port_counter, Counter):
            for port_value, _count in port_counter.most_common(5):
                try:
                    top_ports.append(int(port_value))
                except Exception:
                    continue
        merged_protocol_activity.append(
            {
                "protocol": str(bucket.get("protocol", "")),
                "packets": int(bucket.get("packets", 0) or 0),
                "bytes": int(bucket.get("bytes", 0) or 0),
                "flow_count": int(bucket.get("flow_count", 0) or 0),
                "host_count": int(bucket.get("host_count", 0) or 0),
                "first_seen": _coerce_ts(bucket.get("first_seen")),
                "last_seen": _coerce_ts(bucket.get("last_seen")),
                "top_ports": top_ports,
            }
        )
    merged_protocol_activity.sort(
        key=lambda item: (
            -int(item.get("packets", 0) or 0),
            -int(item.get("bytes", 0) or 0),
            str(item.get("protocol", "")),
        )
    )

    service_activity_bucket: dict[str, dict[str, object]] = {}
    for summary in summaries:
        source_rows = summary.service_activity
        if not source_rows:
            source_rows = [
                {"service": name, "asset_count": count}
                for name, count in (summary.observed_services or summary.top_services)
            ]
        for row in source_rows:
            if not isinstance(row, dict):
                continue
            service_name = str(row.get("service", "") or "").strip()
            if not service_name:
                continue
            bucket = service_activity_bucket.setdefault(
                service_name,
                {
                    "service": service_name,
                    "asset_count": 0,
                    "packets": 0,
                    "bytes": 0,
                    "host_count": 0,
                    "client_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "port_counter": Counter(),
                    "host_counter": Counter(),
                },
            )
            bucket["asset_count"] = int(bucket.get("asset_count", 0) or 0) + int(
                row.get("asset_count", 0) or 0
            )
            bucket["packets"] = int(bucket.get("packets", 0) or 0) + int(
                row.get("packets", 0) or 0
            )
            bucket["bytes"] = int(bucket.get("bytes", 0) or 0) + int(
                row.get("bytes", 0) or 0
            )
            bucket["host_count"] = int(bucket.get("host_count", 0) or 0) + int(
                row.get("host_count", 0) or 0
            )
            bucket["client_count"] = int(bucket.get("client_count", 0) or 0) + int(
                row.get("client_count", 0) or 0
            )
            first_seen = _coerce_ts(row.get("first_seen"))
            last_seen = _coerce_ts(row.get("last_seen"))
            current_first = _coerce_ts(bucket.get("first_seen"))
            current_last = _coerce_ts(bucket.get("last_seen"))
            if first_seen is not None and (
                current_first is None or first_seen < current_first
            ):
                bucket["first_seen"] = first_seen
            if last_seen is not None and (current_last is None or last_seen > current_last):
                bucket["last_seen"] = last_seen
            port_counter = bucket.get("port_counter")
            if isinstance(port_counter, Counter):
                for port in list(row.get("top_ports", []) or [])[:8]:
                    try:
                        port_counter[int(port)] += 1
                    except Exception:
                        continue
            host_counter = bucket.get("host_counter")
            if isinstance(host_counter, Counter):
                for host in list(row.get("top_hosts", []) or [])[:6]:
                    text = str(host).strip()
                    if not text:
                        continue
                    match = re.match(r"^(.*)\((\d+)\)$", text)
                    if match:
                        host_name = str(match.group(1)).strip()
                        host_count = int(match.group(2))
                    else:
                        host_name = text
                        host_count = 1
                    if host_name:
                        host_counter[host_name] += max(1, host_count)

    merged_service_activity: list[dict[str, object]] = []
    for bucket in service_activity_bucket.values():
        top_ports: list[int] = []
        port_counter = bucket.get("port_counter")
        if isinstance(port_counter, Counter):
            for port_value, _count in port_counter.most_common(4):
                try:
                    top_ports.append(int(port_value))
                except Exception:
                    continue
        top_hosts = _bucket_top_list(bucket.get("host_counter"), limit=3, with_counts=True)
        merged_service_activity.append(
            {
                "service": str(bucket.get("service", "")),
                "asset_count": int(bucket.get("asset_count", 0) or 0),
                "packets": int(bucket.get("packets", 0) or 0),
                "bytes": int(bucket.get("bytes", 0) or 0),
                "host_count": int(bucket.get("host_count", 0) or 0),
                "client_count": int(bucket.get("client_count", 0) or 0),
                "first_seen": _coerce_ts(bucket.get("first_seen")),
                "last_seen": _coerce_ts(bucket.get("last_seen")),
                "top_ports": top_ports,
                "top_hosts": top_hosts,
            }
        )
    merged_service_activity.sort(
        key=lambda item: (
            -int(item.get("packets", 0) or 0),
            -int(item.get("bytes", 0) or 0),
            -int(item.get("asset_count", 0) or 0),
            str(item.get("service", "")),
        )
    )

    merged_notable_flows: list[dict[str, object]] = []
    for summary in summaries:
        merged_notable_flows.extend(list(summary.notable_flows or []))
    merged_notable_flows.sort(
        key=lambda item: (
            -int(item.get("bytes", 0) or 0) if isinstance(item, dict) else 0,
            -int(item.get("packets", 0) or 0) if isinstance(item, dict) else 0,
            str(item.get("src", "")) if isinstance(item, dict) else "",
            str(item.get("dst", "")) if isinstance(item, dict) else "",
        )
    )

    merged_ot_protocols: list[str] = []
    seen_ot: set[str] = set()
    for summary in summaries:
        for protocol in summary.ot_protocols:
            text = str(protocol).strip()
            if not text or text in seen_ot:
                continue
            seen_ot.add(text)
            merged_ot_protocols.append(text)

    lead_map: dict[tuple[str, str], dict[str, object]] = {}
    for summary in summaries:
        for lead in list(summary.hunt_leads or []):
            if not isinstance(lead, dict):
                continue
            entity = str(lead.get("entity", "") or "").strip()
            finding = str(lead.get("finding", "") or "").strip()
            if not entity or not finding:
                continue
            key = (entity, finding)
            existing = lead_map.get(key)
            score = int(lead.get("score", 0) or 0)
            evidence = str(lead.get("evidence", "") or "").strip()
            first_seen = _coerce_ts(lead.get("first_seen"))
            last_seen = _coerce_ts(lead.get("last_seen"))
            if existing is None:
                lead_map[key] = {
                    "score": score,
                    "priority": str(lead.get("priority", "medium") or "medium"),
                    "entity": entity,
                    "finding": finding,
                    "evidence": evidence,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                }
            else:
                existing["score"] = max(int(existing.get("score", 0) or 0), score)
                if evidence and len(evidence) > len(str(existing.get("evidence", ""))):
                    existing["evidence"] = evidence
                ex_first = _coerce_ts(existing.get("first_seen"))
                ex_last = _coerce_ts(existing.get("last_seen"))
                if first_seen is not None and (ex_first is None or first_seen < ex_first):
                    existing["first_seen"] = first_seen
                if last_seen is not None and (ex_last is None or last_seen > ex_last):
                    existing["last_seen"] = last_seen

    merged_hunt_leads = sorted(
        lead_map.values(),
        key=lambda item: (
            -int(item.get("score", 0) or 0),
            str(item.get("entity", "")),
            str(item.get("finding", "")),
        ),
    )
    if not merged_hunt_leads:
        merged_hunt_leads = _build_hunt_leads(
            ip_activity=merged_ip_activity,
            notable_flows=merged_notable_flows,
            module_results=module_results,
            ot_markers=sorted(_ot_marker_tokens([], merged_ot_protocols)),
            limit=14,
        )

    flow_count = sum(
        int(summary.summary_details.get("flow_count", 0) or 0) for summary in summaries
    )
    if flow_count <= 0:
        flow_count = len(merged_notable_flows)

    cross_zone_flows = sum(
        int(summary.summary_details.get("cross_zone_flows", 0) or 0)
        for summary in summaries
    )
    if cross_zone_flows <= 0:
        cross_zone_flows = sum(
            1
            for item in merged_notable_flows
            if isinstance(item, dict)
            and str(item.get("scope_pair", "") or "")
            in {"internal->public", "public->internal"}
        )

    scope_counts: Counter[str] = Counter(
        str(item.get("scope", "unknown"))
        for item in merged_ip_activity
        if isinstance(item, dict)
    )
    module_error_count = sum(1 for item in module_results if item.errors)
    capture_span_seconds = (
        int(max(0.0, float(capture_end or 0.0) - float(capture_start or 0.0)))
        if capture_start is not None and capture_end is not None
        else int(max(0.0, duration_seconds))
    )
    summary_details = {
        "unique_ips": len(merged_ip_activity),
        "unique_protocols": len(protocol_counter),
        "unique_services": len(service_counter),
        "internal_ips": int(scope_counts.get("internal", 0)),
        "public_ips": int(scope_counts.get("public", 0)),
        "flow_count": flow_count,
        "cross_zone_flows": cross_zone_flows,
        "cross_zone_ot_iot_flows": sum(
            int(summary.summary_details.get("cross_zone_ot_iot_flows", 0) or 0)
            for summary in summaries
        ),
        "hunt_leads": len(merged_hunt_leads),
        "capture_span_seconds": capture_span_seconds,
        "module_count": len(modules_run),
        "module_errors": module_error_count,
        "ot_family_count": len(merged_ot_protocols),
        "iot_family_count": len(_iot_labels_from_ot_labels(merged_ot_protocols)),
        "protocol_anomalies": sum(
            int(summary.summary_details.get("protocol_anomalies", 0) or 0)
            for summary in summaries
        ),
        "service_risks": sum(
            int(summary.summary_details.get("service_risks", 0) or 0)
            for summary in summaries
        ),
    }

    return OverviewSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        duration_seconds=duration_seconds,
        top_protocols=protocol_counter.most_common(12),
        top_services=service_counter.most_common(12),
        observed_ips=merged_observed_ips[:20],
        observed_protocols=protocol_counter.most_common(20),
        observed_services=service_counter.most_common(20),
        summary_details=summary_details,
        ot_protocols=merged_ot_protocols,
        modules_run=modules_run,
        module_results=module_results,
        ot_highlights=_dedupe_limited(
            [item for summary in summaries for item in summary.ot_highlights], 12
        ),
        hunt_highlights=_dedupe_limited(
            [item for summary in summaries for item in summary.hunt_highlights], 14
        ),
        forensics_highlights=_dedupe_limited(
            [item for summary in summaries for item in summary.forensics_highlights], 14
        ),
        ctf_highlights=_dedupe_limited(
            [item for summary in summaries for item in summary.ctf_highlights], 12
        ),
        recommendations=_dedupe_limited(
            [item for summary in summaries for item in summary.recommendations], 10
        ),
        errors=_dedupe_limited(
            [item for summary in summaries for item in summary.errors], 20
        ),
        capture_start=capture_start,
        capture_end=capture_end,
        ip_activity=merged_ip_activity[:24],
        protocol_activity=merged_protocol_activity[:24],
        service_activity=merged_service_activity[:24],
        notable_flows=merged_notable_flows[:30],
        hunt_leads=merged_hunt_leads[:14],
    )
