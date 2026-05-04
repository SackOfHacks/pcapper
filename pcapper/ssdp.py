from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .pcap_cache import get_reader
from .utils import safe_float, extract_packet_endpoints

try:
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


SSDP_PORT = 1900
SSDP_MULTICAST = {"239.255.255.250", "ff02::c", "ff05::c"}


@dataclass(frozen=True)
class SsdpArtifact:
    ts: Optional[float]
    kind: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    message_type: str
    detail: str


@dataclass(frozen=True)
class SsdpSummary:
    path: Path
    total_packets: int
    udp_packets: int
    ssdp_packets: int
    total_bytes: int
    msearch_count: int
    notify_count: int
    response_count: int
    other_count: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    host_header_counts: Counter[str]
    st_counts: Counter[str]
    nt_counts: Counter[str]
    usn_counts: Counter[str]
    location_counts: Counter[str]
    server_banner_counts: Counter[str]
    target_port_counts: Counter[int]
    multicast_destinations: Counter[str]
    unicast_destinations: Counter[str]
    public_peers: Counter[str]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[SsdpArtifact]
    deterministic_checks: dict[str, list[str]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
    except Exception:
        return False
    return bool(
        not ip_obj.is_private
        and not ip_obj.is_loopback
        and not ip_obj.is_link_local
        and not ip_obj.is_multicast
        and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )


def _normalize_header_value(value: str) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:256]


def _parse_headers(text: str) -> dict[str, str]:
    lines = text.splitlines()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if not key:
            continue
        headers[key] = _normalize_header_value(value)
    return headers


def _classify_message(start_line: str) -> str:
    line = start_line.strip().upper()
    if line.startswith("M-SEARCH "):
        return "M-SEARCH"
    if line.startswith("NOTIFY "):
        return "NOTIFY"
    if line.startswith("HTTP/1.1 200"):
        return "RESPONSE"
    return "OTHER"


def _looks_like_ssdp(payload: bytes, sport: int, dport: int) -> bool:
    if sport == SSDP_PORT or dport == SSDP_PORT:
        return True
    if not payload:
        return False
    start = payload[:64].decode("latin-1", errors="ignore").upper()
    return (
        start.startswith("M-SEARCH ")
        or start.startswith("NOTIFY ")
        or start.startswith("HTTP/1.1 200")
    )


def analyze_ssdp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> SsdpSummary:
    errors: list[str] = []
    if UDP is None:
        errors.append("Scapy UDP layers unavailable; install scapy for SSDP analysis.")
        return SsdpSummary(
            path=path,
            total_packets=0,
            udp_packets=0,
            ssdp_packets=0,
            total_bytes=0,
            msearch_count=0,
            notify_count=0,
            response_count=0,
            other_count=0,
            client_counts=Counter(),
            server_counts=Counter(),
            host_header_counts=Counter(),
            st_counts=Counter(),
            nt_counts=Counter(),
            usn_counts=Counter(),
            location_counts=Counter(),
            server_banner_counts=Counter(),
            target_port_counts=Counter(),
            multicast_destinations=Counter(),
            unicast_destinations=Counter(),
            public_peers=Counter(),
            detections=[],
            anomalies=[],
            artifacts=[],
            deterministic_checks={},
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path,
        packets=packets,
        meta=meta,
        show_status=show_status,
    )

    total_packets = 0
    udp_packets = 0
    ssdp_packets = 0
    total_bytes = 0
    msearch_count = 0
    notify_count = 0
    response_count = 0
    other_count = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    host_header_counts: Counter[str] = Counter()
    st_counts: Counter[str] = Counter()
    nt_counts: Counter[str] = Counter()
    usn_counts: Counter[str] = Counter()
    location_counts: Counter[str] = Counter()
    server_banner_counts: Counter[str] = Counter()
    target_port_counts: Counter[int] = Counter()
    multicast_destinations: Counter[str] = Counter()
    unicast_destinations: Counter[str] = Counter()
    public_peers: Counter[str] = Counter()

    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[SsdpArtifact] = []

    msearch_by_src: Counter[str] = Counter()
    notify_by_src: Counter[str] = Counter()
    response_to_dst: Counter[str] = Counter()
    msearch_targets_by_src: dict[str, set[str]] = defaultdict(set)
    msearch_times_by_src: dict[str, list[float]] = defaultdict(list)
    notify_times_by_src: dict[str, list[float]] = defaultdict(list)
    usn_sources: dict[str, set[str]] = defaultdict(set)

    malformed_messages = 0
    nonstandard_port_messages = 0
    unicast_discovery = 0
    public_messages = 0
    suspicious_locations = 0
    gateway_enumeration = 0

    def _add_detection(severity: str, title: str, details: str) -> None:
        detections.append({"severity": severity, "title": title, "details": details})

    def _add_anomaly(severity: str, title: str, details: str) -> None:
        anomalies.append({"severity": severity, "title": title, "details": details})

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

            if not pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                continue
            udp_packets += 1
            udp = pkt[UDP]  # type: ignore[index]
            sport = int(getattr(udp, "sport", 0) or 0)
            dport = int(getattr(udp, "dport", 0) or 0)
            payload = bytes(getattr(udp, "payload", b""))
            if not _looks_like_ssdp(payload, sport, dport):
                continue

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            ssdp_packets += 1
            total_bytes += len(payload)
            target_port_counts[dport] += 1

            text = payload.decode("latin-1", errors="ignore")
            lines = text.splitlines()
            start_line = lines[0].strip() if lines else ""
            message_type = _classify_message(start_line)
            headers = _parse_headers(text)

            host = headers.get("host", "")
            st = headers.get("st", "")
            nt = headers.get("nt", "")
            usn = headers.get("usn", "")
            server = headers.get("server", "") or headers.get("user-agent", "")
            location = headers.get("location", "")
            man = headers.get("man", "")

            if host:
                host_header_counts[host] += 1
            if st:
                st_counts[st] += 1
            if nt:
                nt_counts[nt] += 1
            if usn:
                usn_counts[usn] += 1
                usn_sources[usn].add(src_ip)
            if server:
                server_banner_counts[server] += 1
            if location:
                location_counts[location] += 1

            if message_type == "M-SEARCH":
                msearch_count += 1
                client_counts[src_ip] += 1
                msearch_by_src[src_ip] += 1
                msearch_targets_by_src[src_ip].add(dst_ip)
                if ts is not None:
                    msearch_times_by_src[src_ip].append(ts)
            elif message_type == "NOTIFY":
                notify_count += 1
                server_counts[src_ip] += 1
                notify_by_src[src_ip] += 1
                if ts is not None:
                    notify_times_by_src[src_ip].append(ts)
            elif message_type == "RESPONSE":
                response_count += 1
                server_counts[src_ip] += 1
                response_to_dst[dst_ip] += 1
                client_counts[dst_ip] += 1
            else:
                other_count += 1
                malformed_messages += 1

            if dst_ip in SSDP_MULTICAST:
                multicast_destinations[dst_ip] += 1
            else:
                unicast_destinations[dst_ip] += 1

            if message_type == "M-SEARCH" and dst_ip not in SSDP_MULTICAST:
                unicast_discovery += 1

            if sport != SSDP_PORT and dport != SSDP_PORT:
                nonstandard_port_messages += 1

            if _is_public_ip(src_ip) or _is_public_ip(dst_ip):
                public_messages += 1
                public_peers[src_ip] += 1
                public_peers[dst_ip] += 1

            if message_type == "M-SEARCH":
                if not host:
                    malformed_messages += 1
                if man and "SSDP:DISCOVER" not in man.upper():
                    malformed_messages += 1
                if st:
                    st_upper = st.upper()
                    if (
                        "INTERNETGATEWAYDEVICE" in st_upper
                        or "WANIPCONNECTION" in st_upper
                        or "WANPPPCONNECTION" in st_upper
                    ):
                        gateway_enumeration += 1

            if message_type in {"NOTIFY", "RESPONSE"} and not usn:
                malformed_messages += 1

            if location:
                loc_lower = location.lower()
                parsed = urlparse(location)
                if parsed.scheme and parsed.scheme not in {"http", "https"}:
                    suspicious_locations += 1
                if parsed.hostname and _is_public_ip(parsed.hostname):
                    suspicious_locations += 1
                if any(
                    token in loc_lower
                    for token in (
                        "/cmd",
                        "/shell",
                        ".exe",
                        ".bat",
                        ".ps1",
                        "powershell",
                    )
                ):
                    suspicious_locations += 1

            detail = start_line or "(empty start line)"
            artifacts.append(
                SsdpArtifact(
                    ts=ts,
                    kind="ssdp_message",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    message_type=message_type,
                    detail=detail[:220],
                )
            )
    finally:
        status.finish()
        reader.close()

    if ssdp_packets:
        for src, count in msearch_by_src.items():
            unique_targets = len(msearch_targets_by_src.get(src, set()))
            times = sorted(msearch_times_by_src.get(src, []))
            burst_60s = 0
            if len(times) >= 2:
                anchor = 0
                for idx in range(len(times)):
                    while anchor < idx and (times[idx] - times[anchor]) > 60.0:
                        anchor += 1
                    burst_60s = max(burst_60s, idx - anchor + 1)
            if count >= 40 or burst_60s >= 30:
                _add_detection(
                    "HIGH",
                    "SSDP M-SEARCH flood pattern",
                    f"{src} generated {count} discovery probes (max {burst_60s}/60s), indicating potential active reconnaissance or flood behavior.",
                )
            elif count >= 15 and unique_targets >= 6:
                _add_detection(
                    "MEDIUM",
                    "SSDP reconnaissance sweep",
                    f"{src} sent {count} discovery probes to {unique_targets} distinct targets.",
                )

        for src, count in notify_by_src.items():
            times = sorted(notify_times_by_src.get(src, []))
            burst_60s = 0
            if len(times) >= 2:
                anchor = 0
                for idx in range(len(times)):
                    while anchor < idx and (times[idx] - times[anchor]) > 60.0:
                        anchor += 1
                    burst_60s = max(burst_60s, idx - anchor + 1)
            if count >= 50 or burst_60s >= 35:
                _add_detection(
                    "HIGH",
                    "SSDP NOTIFY flood pattern",
                    f"{src} emitted {count} NOTIFY advertisements (max {burst_60s}/60s), consistent with advertisement storm behavior.",
                )
            elif count >= 20:
                _add_detection(
                    "MEDIUM",
                    "Elevated SSDP NOTIFY activity",
                    f"{src} emitted {count} NOTIFY advertisements.",
                )

        for victim, resp_count in response_to_dst.items():
            req_count = msearch_by_src.get(victim, 0)
            if resp_count >= 20 and req_count <= 2:
                _add_detection(
                    "MEDIUM",
                    "Potential SSDP reflection/amplification pattern",
                    f"{victim} received {resp_count} SSDP responses but sent only {req_count} M-SEARCH probes.",
                )

        if public_messages > 0:
            _add_detection(
                "HIGH",
                "SSDP observed over public-addressed path",
                f"{public_messages} SSDP messages involve public IP endpoints; SSDP should typically stay in local segments.",
            )

        if nonstandard_port_messages > 0:
            _add_detection(
                "MEDIUM",
                "SSDP over non-standard UDP port",
                f"{nonstandard_port_messages} SSDP-like messages were seen without UDP/1900 endpoint usage.",
            )

        if unicast_discovery > 0:
            _add_anomaly(
                "MEDIUM",
                "Unicast SSDP discovery requests",
                f"{unicast_discovery} M-SEARCH probes targeted unicast addresses instead of multicast discovery groups.",
            )

        if malformed_messages > 0:
            _add_anomaly(
                "MEDIUM",
                "Malformed/incomplete SSDP messages",
                f"{malformed_messages} SSDP messages had missing/atypical method/header structure.",
            )

        if suspicious_locations > 0:
            _add_detection(
                "HIGH",
                "Suspicious SSDP LOCATION artifact(s)",
                f"{suspicious_locations} LOCATION headers referenced unusual schemes/paths or externally scoped hosts.",
            )

        if gateway_enumeration > 0:
            _add_detection(
                "LOW",
                "UPnP gateway capability enumeration",
                f"{gateway_enumeration} discovery probes requested InternetGatewayDevice/WAN* services.",
            )

        usn_conflicts = [
            usn for usn, ips in usn_sources.items() if usn and len(ips) > 1
        ]
        if usn_conflicts:
            sample = usn_conflicts[:3]
            _add_anomaly(
                "MEDIUM",
                "Duplicate USN identity across multiple source IPs",
                f"{len(usn_conflicts)} USN values appeared from multiple IPs (sample: {', '.join(sample)}).",
            )

    deterministic_checks: dict[str, list[str]] = {
        "ssdp_present": [f"Observed {ssdp_packets} SSDP packets"]
        if ssdp_packets > 0
        else [],
        "msearch_activity": [f"M-SEARCH requests: {msearch_count}"]
        if msearch_count > 0
        else [],
        "notify_activity": [f"NOTIFY advertisements: {notify_count}"]
        if notify_count > 0
        else [],
        "response_activity": [f"SSDP responses: {response_count}"]
        if response_count > 0
        else [],
        "public_ssdp_exposure": [f"Public-address path SSDP packets: {public_messages}"]
        if public_messages > 0
        else [],
        "msearch_flood": [
            item["details"]
            for item in detections
            if item.get("title") == "SSDP M-SEARCH flood pattern"
        ],
        "notify_flood": [
            item["details"]
            for item in detections
            if item.get("title") == "SSDP NOTIFY flood pattern"
        ],
        "reflection_pattern": [
            item["details"]
            for item in detections
            if item.get("title") == "Potential SSDP reflection/amplification pattern"
        ],
        "unicast_discovery": [f"Unicast M-SEARCH count: {unicast_discovery}"]
        if unicast_discovery > 0
        else [],
        "malformed_messages": [
            f"Malformed/atypical SSDP messages: {malformed_messages}"
        ]
        if malformed_messages > 0
        else [],
        "usn_duplication": [
            item["details"]
            for item in anomalies
            if item.get("title") == "Duplicate USN identity across multiple source IPs"
        ],
        "nonstandard_port_usage": [
            f"Non-standard SSDP-like messages: {nonstandard_port_messages}"
        ]
        if nonstandard_port_messages > 0
        else [],
        "upnp_gateway_enumeration": [f"Gateway service probes: {gateway_enumeration}"]
        if gateway_enumeration > 0
        else [],
    }

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return SsdpSummary(
        path=path,
        total_packets=total_packets,
        udp_packets=udp_packets,
        ssdp_packets=ssdp_packets,
        total_bytes=total_bytes,
        msearch_count=msearch_count,
        notify_count=notify_count,
        response_count=response_count,
        other_count=other_count,
        client_counts=client_counts,
        server_counts=server_counts,
        host_header_counts=host_header_counts,
        st_counts=st_counts,
        nt_counts=nt_counts,
        usn_counts=usn_counts,
        location_counts=location_counts,
        server_banner_counts=server_banner_counts,
        target_port_counts=target_port_counts,
        multicast_destinations=multicast_destinations,
        unicast_destinations=unicast_destinations,
        public_peers=public_peers,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        deterministic_checks=deterministic_checks,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
