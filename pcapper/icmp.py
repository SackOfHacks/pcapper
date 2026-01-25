from __future__ import annotations

from collections import Counter, defaultdict
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import safe_float, detect_file_type

try:
    from scapy.layers.inet import IP, ICMP  # type: ignore
    from scapy.layers.inet6 import (
        IPv6,
        ICMPv6Unknown,
        ICMPv6EchoRequest,
        ICMPv6EchoReply,
        ICMPv6DestUnreach,
        ICMPv6TimeExceeded,
        ICMPv6ParamProblem,
        ICMPv6PacketTooBig,
    )  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    ICMP = None  # type: ignore
    IPv6 = None  # type: ignore
    ICMPv6Unknown = None  # type: ignore
    ICMPv6EchoRequest = None  # type: ignore
    ICMPv6EchoReply = None  # type: ignore
    ICMPv6DestUnreach = None  # type: ignore
    ICMPv6TimeExceeded = None  # type: ignore
    ICMPv6ParamProblem = None  # type: ignore
    ICMPv6PacketTooBig = None  # type: ignore


@dataclass(frozen=True)
class IcmpSummary:
    path: Path
    total_packets: int
    total_bytes: int
    ipv4_packets: int
    ipv6_packets: int
    type_counts: Counter[str]
    code_counts: Counter[str]
    src_ip_counts: Counter[str]
    dst_ip_counts: Counter[str]
    src_ips: set[str]
    dst_ips: set[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    avg_payload_bytes: float
    max_payload_bytes: int
    payload_size_variants: int
    payload_summaries: list[dict[str, object]]
    detections: list[dict[str, str]]
    conversations: list[dict[str, object]]
    sessions: list[dict[str, object]]
    request_counts: Counter[str]
    response_counts: Counter[str]
    artifacts: list[str]
    observed_users: Counter[str]
    files_discovered: list[str]
    errors: list[str]


def analyze_icmp(path: Path, show_status: bool = True) -> IcmpSummary:
    errors: list[str] = []
    if ICMP is None and ICMPv6Unknown is None:
        errors.append("Scapy ICMP layers unavailable; install scapy for ICMP analysis.")
        return IcmpSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            ipv4_packets=0,
            ipv6_packets=0,
            type_counts=Counter(),
            code_counts=Counter(),
            src_ip_counts=Counter(),
            dst_ip_counts=Counter(),
            src_ips=set(),
            dst_ips=set(),
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            avg_payload_bytes=0.0,
            max_payload_bytes=0,
            payload_size_variants=0,
            payload_summaries=[],
            detections=[],
            errors=errors,
        )

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
    total_bytes = 0
    ipv4_packets = 0
    ipv6_packets = 0
    type_counts: Counter[str] = Counter()
    code_counts: Counter[str] = Counter()
    src_ip_counts: Counter[str] = Counter()
    dst_ip_counts: Counter[str] = Counter()
    src_ips: set[str] = set()
    dst_ips: set[str] = set()
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    payload_total = 0
    payload_max = 0
    payload_sizes: Counter[int] = Counter()
    payload_counts: Counter[str] = Counter()
    payload_meta: dict[str, dict[str, object]] = {}
    conversations: dict[tuple[str, str, str], dict[str, object]] = {}
    sessions: dict[tuple[str, str, int], dict[str, object]] = {}
    request_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    artifacts: set[str] = set()
    files_discovered: set[str] = set()
    observed_users: Counter[str] = Counter()

    try:
        for pkt in reader:
            src: Optional[str] = None
            dst: Optional[str] = None
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            is_icmpv4 = ICMP is not None and pkt.haslayer(ICMP)  # type: ignore[truthy-bool]
            is_icmpv6 = False
            if ICMPv6Unknown is not None and pkt.haslayer(ICMPv6Unknown):
                is_icmpv6 = True
            elif ICMPv6EchoRequest is not None and pkt.haslayer(ICMPv6EchoRequest):
                is_icmpv6 = True
            elif ICMPv6EchoReply is not None and pkt.haslayer(ICMPv6EchoReply):
                is_icmpv6 = True
            elif ICMPv6DestUnreach is not None and pkt.haslayer(ICMPv6DestUnreach):
                is_icmpv6 = True
            elif ICMPv6TimeExceeded is not None and pkt.haslayer(ICMPv6TimeExceeded):
                is_icmpv6 = True
            elif ICMPv6ParamProblem is not None and pkt.haslayer(ICMPv6ParamProblem):
                is_icmpv6 = True
            elif ICMPv6PacketTooBig is not None and pkt.haslayer(ICMPv6PacketTooBig):
                is_icmpv6 = True
            # Fallback: detect ICMP by IP protocol/next-header if layers are missing
            if not is_icmpv4 and not is_icmpv6:
                if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                    ip_layer = pkt[IP]  # type: ignore[index]
                    if getattr(ip_layer, "proto", None) == 1:
                        is_icmpv4 = True
                if not is_icmpv4 and IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                    ip6_layer = pkt[IPv6]  # type: ignore[index]
                    if getattr(ip6_layer, "nh", None) == 58:
                        is_icmpv6 = True
            if not is_icmpv4 and not is_icmpv6:
                continue

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len

            if is_icmpv4:
                ipv4_packets += 1
                if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
                    icmp_layer = pkt[ICMP]  # type: ignore[index]
                else:
                    icmp_layer = None
                try:
                    if icmp_layer is not None:
                        payload_bytes = bytes(icmp_layer.payload)
                        payload_len = len(payload_bytes)
                    else:
                        payload_bytes = bytes(pkt[IP].payload) if IP is not None and pkt.haslayer(IP) else b""
                        payload_len = len(payload_bytes)
                except Exception:
                    payload_bytes = b""
                    payload_len = 0
                if icmp_layer is not None:
                    icmp_type = getattr(icmp_layer, "type", None)
                    icmp_code = getattr(icmp_layer, "code", None)
                else:
                    icmp_type = payload_bytes[0] if len(payload_bytes) >= 1 else None
                    icmp_code = payload_bytes[1] if len(payload_bytes) >= 2 else None
                if icmp_type is not None:
                    type_counts[f"icmpv4:{icmp_type}"] += 1
                    if icmp_type == 8:
                        request_counts["ICMPv4 Echo"] += 1
                    elif icmp_type == 0:
                        response_counts["ICMPv4 Echo Reply"] += 1
                    elif icmp_type == 3:
                        response_counts["ICMPv4 Destination Unreachable"] += 1
                    elif icmp_type == 11:
                        response_counts["ICMPv4 Time Exceeded"] += 1
                if icmp_code is not None:
                    code_counts[f"icmpv4:{icmp_type}:{icmp_code}"] += 1
                if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                    ip_layer = pkt[IP]  # type: ignore[index]
                    if getattr(ip_layer, "src", None):
                        src = str(ip_layer.src)
                        src_ips.add(src)
                        src_ip_counts[src] += 1
                    if getattr(ip_layer, "dst", None):
                        dst = str(ip_layer.dst)
                        dst_ips.add(dst)
                        dst_ip_counts[dst] += 1

                if icmp_type in (0, 8):
                    icmp_id = getattr(icmp_layer, "id", None)
                    if icmp_id is not None and src and dst:
                        sess_key = (src, dst, int(icmp_id))
                        sess = sessions.setdefault(sess_key, {
                            "src": src,
                            "dst": dst,
                            "id": int(icmp_id),
                            "requests": 0,
                            "replies": 0,
                            "first_seen": None,
                            "last_seen": None,
                            "packets": 0,
                        })
                        sess["packets"] += 1
                        if icmp_type == 8:
                            sess["requests"] += 1
                        else:
                            sess["replies"] += 1
                        if ts is not None:
                            if sess["first_seen"] is None or ts < sess["first_seen"]:
                                sess["first_seen"] = ts
                            if sess["last_seen"] is None or ts > sess["last_seen"]:
                                sess["last_seen"] = ts

            if is_icmpv6:
                ipv6_packets += 1
                if ICMPv6EchoRequest is not None and pkt.haslayer(ICMPv6EchoRequest):
                    icmp6_layer = pkt[ICMPv6EchoRequest]  # type: ignore[index]
                elif ICMPv6EchoReply is not None and pkt.haslayer(ICMPv6EchoReply):
                    icmp6_layer = pkt[ICMPv6EchoReply]  # type: ignore[index]
                elif ICMPv6DestUnreach is not None and pkt.haslayer(ICMPv6DestUnreach):
                    icmp6_layer = pkt[ICMPv6DestUnreach]  # type: ignore[index]
                elif ICMPv6TimeExceeded is not None and pkt.haslayer(ICMPv6TimeExceeded):
                    icmp6_layer = pkt[ICMPv6TimeExceeded]  # type: ignore[index]
                elif ICMPv6ParamProblem is not None and pkt.haslayer(ICMPv6ParamProblem):
                    icmp6_layer = pkt[ICMPv6ParamProblem]  # type: ignore[index]
                elif ICMPv6PacketTooBig is not None and pkt.haslayer(ICMPv6PacketTooBig):
                    icmp6_layer = pkt[ICMPv6PacketTooBig]  # type: ignore[index]
                else:
                    icmp6_layer = pkt[ICMPv6Unknown]  # type: ignore[index]
                try:
                    payload_bytes = bytes(icmp6_layer.payload)
                    payload_len = len(payload_bytes)
                except Exception:
                    payload_bytes = b""
                    payload_len = 0
                icmp6_type = getattr(icmp6_layer, "type", None)
                icmp6_code = getattr(icmp6_layer, "code", None)
                if icmp6_type is None and IPv6 is not None and pkt.haslayer(IPv6):
                    try:
                        raw_bytes = bytes(pkt[IPv6].payload)
                        icmp6_type = raw_bytes[0] if len(raw_bytes) >= 1 else None
                        icmp6_code = raw_bytes[1] if len(raw_bytes) >= 2 else None
                        payload_bytes = raw_bytes
                        payload_len = len(raw_bytes)
                    except Exception:
                        pass
                if icmp6_type is not None:
                    type_counts[f"icmpv6:{icmp6_type}"] += 1
                    if icmp6_type == 128:
                        request_counts["ICMPv6 Echo"] += 1
                    elif icmp6_type == 129:
                        response_counts["ICMPv6 Echo Reply"] += 1
                    elif icmp6_type == 1:
                        response_counts["ICMPv6 Destination Unreachable"] += 1
                    elif icmp6_type == 3:
                        response_counts["ICMPv6 Time Exceeded"] += 1
                if icmp6_code is not None:
                    code_counts[f"icmpv6:{icmp6_type}:{icmp6_code}"] += 1
                if IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                    ip6_layer = pkt[IPv6]  # type: ignore[index]
                    if getattr(ip6_layer, "src", None):
                        src = str(ip6_layer.src)
                        src_ips.add(src)
                        src_ip_counts[src] += 1
                    if getattr(ip6_layer, "dst", None):
                        dst = str(ip6_layer.dst)
                        dst_ips.add(dst)
                        dst_ip_counts[dst] += 1

                if icmp6_type in (128, 129):
                    icmp_id = getattr(icmp6_layer, "id", None)
                    if icmp_id is not None and src and dst:
                        sess_key = (src, dst, int(icmp_id))
                        sess = sessions.setdefault(sess_key, {
                            "src": src,
                            "dst": dst,
                            "id": int(icmp_id),
                            "requests": 0,
                            "replies": 0,
                            "first_seen": None,
                            "last_seen": None,
                            "packets": 0,
                        })
                        sess["packets"] += 1
                        if icmp6_type == 128:
                            sess["requests"] += 1
                        else:
                            sess["replies"] += 1
                        if ts is not None:
                            if sess["first_seen"] is None or ts < sess["first_seen"]:
                                sess["first_seen"] = ts
                            if sess["last_seen"] is None or ts > sess["last_seen"]:
                                sess["last_seen"] = ts

            payload_total += payload_len
            payload_max = max(payload_max, payload_len)
            payload_sizes[payload_len] += 1

            if payload_len > 0:
                digest = payload_bytes[:64].hex()
                payload_counts[digest] += 1
                entry = payload_meta.setdefault(digest, {
                    "size": payload_len,
                    "sources": Counter(),
                    "destinations": Counter(),
                    "samples": payload_bytes[:64],
                })
                if src:
                    entry["sources"][src] += 1  # type: ignore[index]
                if dst:
                    entry["destinations"][dst] += 1  # type: ignore[index]

                # Artifact extraction
                try:
                    text = "".join(chr(b) if 32 <= b <= 126 else " " for b in payload_bytes[:128])
                    for token in text.split():
                        if len(token) >= 4:
                            artifacts.add(token)
                            if token.lower().startswith(("user=", "username=", "login=")):
                                observed_users[token] += 1
                    for name in re.findall(r"[\w\-.()\[\] ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|txt|bat|ps1|jpg|jpeg|png|gif|bmp|tiff)", text, re.IGNORECASE):
                        files_discovered.add(name)
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if src and dst:
                convo_key = (src, dst, "icmpv4" if is_icmpv4 else "icmpv6")
                convo = conversations.setdefault(convo_key, {
                    "src": src,
                    "dst": dst,
                    "protocol": "icmpv4" if is_icmpv4 else "icmpv6",
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": None,
                    "last_seen": None,
                })
                convo["packets"] += 1
                convo["bytes"] += pkt_len
                if ts is not None:
                    if convo["first_seen"] is None or ts < convo["first_seen"]:
                        convo["first_seen"] = ts
                    if convo["last_seen"] is None or ts > convo["last_seen"]:
                        convo["last_seen"] = ts
    finally:
        status.finish()
        reader.close()

    detections: list[dict[str, str]] = []
    duration_seconds: Optional[float] = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    avg_payload = (payload_total / total_packets) if total_packets else 0.0
    payload_variants = len(payload_sizes)
    payload_summaries: list[dict[str, object]] = []

    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        total = len(data)
        return -sum((count / total) * math.log2(count / total) for count in freq.values())

    def _preview_text(data: bytes) -> str:
        if not data:
            return ""
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

    for digest, count in payload_counts.most_common(12):
        meta = payload_meta.get(digest, {})
        sample_bytes = meta.get("samples", b"")
        if isinstance(sample_bytes, bytearray):
            sample_bytes = bytes(sample_bytes)
        if not isinstance(sample_bytes, (bytes, bytearray)):
            sample_bytes = b""

        size = int(meta.get("size", 0))
        sources = meta.get("sources", Counter())
        destinations = meta.get("destinations", Counter())
        top_src = sources.most_common(3) if isinstance(sources, Counter) else []
        top_dst = destinations.most_common(3) if isinstance(destinations, Counter) else []

        payload_summaries.append({
            "payload_hex": bytes(sample_bytes).hex(),
            "payload_preview": _preview_text(bytes(sample_bytes)[:64]),
            "count": count,
            "size": size,
            "entropy": _entropy(bytes(sample_bytes)),
            "top_sources": top_src,
            "top_destinations": top_dst,
        })

    if total_packets == 0:
        detections.append({
            "type": "no_icmp",
            "severity": "info",
            "summary": "No ICMP traffic detected",
            "details": "ICMP/ICMPv6 not observed in capture.",
        })
    else:
        if duration_seconds and duration_seconds > 0:
            pps = total_packets / duration_seconds
            if pps > 5000:
                detections.append({
                    "type": "icmp_flood",
                    "severity": "critical",
                    "summary": f"ICMP flood suspected ({pps:.1f} pkt/s)",
                    "details": "High ICMP packet rate suggests DoS/DDoS or test traffic.",
                    "packet_count": total_packets,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                })
            elif pps > 1000:
                detections.append({
                    "type": "icmp_high_rate",
                    "severity": "warning",
                    "summary": f"High ICMP rate observed ({pps:.1f} pkt/s)",
                    "details": "Investigate bursty ICMP activity for flooding or scanning.",
                    "packet_count": total_packets,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                })

        unreachable_count = sum(
            count for key, count in type_counts.items() if key.endswith(":3") or key.endswith(":1")
        )
        if unreachable_count > 1000:
            detections.append({
                "type": "icmp_unreachable_volume",
                "severity": "warning",
                "summary": f"High ICMP unreachable volume ({unreachable_count} packets)",
                "details": "Potential scanning, routing issues, or blocked services.",
                "packet_count": unreachable_count,
                "unique_sources": len(src_ip_counts),
                "unique_destinations": len(dst_ip_counts),
                "top_sources": src_ip_counts.most_common(3),
                "top_destinations": dst_ip_counts.most_common(3),
            })

        echo_request = type_counts.get("icmpv4:8", 0) + type_counts.get("icmpv6:128", 0)
        echo_reply = type_counts.get("icmpv4:0", 0) + type_counts.get("icmpv6:129", 0)
        if echo_request > 0 and echo_reply == 0:
            detections.append({
                "type": "icmp_echo_no_reply",
                "severity": "info",
                "summary": "ICMP echo requests observed without replies",
                "details": "Potential filtering or one-way traffic capture.",
                "packet_count": echo_request,
                "unique_sources": len(src_ip_counts),
                "unique_destinations": len(dst_ip_counts),
                "top_sources": src_ip_counts.most_common(3),
                "top_destinations": dst_ip_counts.most_common(3),
            })

        if payload_variants > 20 and avg_payload > 100:
            detections.append({
                "type": "icmp_tunneling_suspected",
                "severity": "warning",
                "summary": "ICMP payload variability suggests tunneling",
                "details": f"Observed {payload_variants} payload sizes with avg {avg_payload:.1f} bytes.",
                "packet_count": total_packets,
                "top_sources": src_ip_counts.most_common(3),
                "top_destinations": dst_ip_counts.most_common(3),
            })

        if payload_max >= 1400:
            detections.append({
                "type": "icmp_large_payload",
                "severity": "warning",
                "summary": "Large ICMP payloads observed",
                "details": f"Max payload size {payload_max} bytes.",
                "packet_count": total_packets,
                "top_sources": src_ip_counts.most_common(3),
                "top_destinations": dst_ip_counts.most_common(3),
            })

        high_entropy_payloads = [p for p in payload_summaries if p.get("entropy", 0) >= 7.0]
        if high_entropy_payloads:
            detections.append({
                "type": "icmp_high_entropy",
                "severity": "warning",
                "summary": "High-entropy ICMP payloads detected",
                "details": f"{len(high_entropy_payloads)} payload(s) show high entropy (possible covert/exfil).",
            })

        if echo_request > 200 and avg_payload > 200:
            detections.append({
                "type": "icmp_tunnel_indicator",
                "severity": "warning",
                "summary": "Possible ICMP tunneling behavior",
                "details": f"High echo volume with elevated payload size (avg {avg_payload:.1f} bytes).",
                "packet_count": echo_request,
                "unique_sources": len(src_ip_counts),
                "unique_destinations": len(dst_ip_counts),
                "top_sources": src_ip_counts.most_common(3),
                "top_destinations": dst_ip_counts.most_common(3),
            })

        if payload_max > 1000 or payload_variants > 60:
            detections.append({
                "type": "icmp_payload_anomaly",
                "severity": "warning",
                "summary": "ICMP payload anomalies observed",
                "details": "Large or highly variable payload sizes can indicate covert channels.",
                "packet_count": total_packets,
                "unique_sources": len(src_ip_counts),
                "unique_destinations": len(dst_ip_counts),
                "top_sources": src_ip_counts.most_common(3),
                "top_destinations": dst_ip_counts.most_common(3),
            })

        if src_ip_counts:
            top_src, top_src_count = src_ip_counts.most_common(1)[0]
            unique_dsts = len(dst_ip_counts)
            if unique_dsts > 50 and top_src_count > 50:
                detections.append({
                    "type": "icmp_sweep",
                    "severity": "warning",
                    "summary": "Potential ICMP sweep detected",
                    "details": f"Source {top_src} contacted {unique_dsts} unique destinations.",
                    "packet_count": top_src_count,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": unique_dsts,
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                })

        if dst_ip_counts:
            top_dst, top_dst_count = dst_ip_counts.most_common(1)[0]
            if total_packets > 0 and (top_dst_count / total_packets) > 0.7 and top_dst_count > 500:
                detections.append({
                    "type": "icmp_targeted_flood",
                    "severity": "warning",
                    "summary": "ICMP traffic concentrated on a single target",
                    "details": f"Destination {top_dst} received {top_dst_count} ICMP packets.",
                    "packet_count": top_dst_count,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                })

        if avg_payload > 500 and total_packets > 100:
            detections.append({
                "type": "icmp_exfiltration",
                "severity": "warning",
                "summary": "Potential ICMP data exfiltration",
                "details": "Large average payload sizes over ICMP traffic.",
                "packet_count": total_packets,
                "unique_sources": len(src_ip_counts),
                "unique_destinations": len(dst_ip_counts),
                "top_sources": src_ip_counts.most_common(3),
                "top_destinations": dst_ip_counts.most_common(3),
            })

    return IcmpSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        ipv4_packets=ipv4_packets,
        ipv6_packets=ipv6_packets,
        type_counts=type_counts,
        code_counts=code_counts,
        src_ip_counts=src_ip_counts,
        dst_ip_counts=dst_ip_counts,
        src_ips=src_ips,
        dst_ips=dst_ips,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        avg_payload_bytes=avg_payload,
        max_payload_bytes=payload_max,
        payload_size_variants=payload_variants,
        payload_summaries=payload_summaries,
        detections=detections,
        conversations=list(conversations.values()),
        sessions=list(sessions.values()),
        request_counts=request_counts,
        response_counts=response_counts,
        artifacts=sorted(artifacts),
        observed_users=observed_users,
        files_discovered=sorted(files_discovered),
        errors=errors,
    )
