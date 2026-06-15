from __future__ import annotations

from .utils import is_private_ip as _is_private_ip, packet_length
from .utils import is_public_ip as _is_public_ip
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import memoize_analysis, safe_float

try:
    from scapy.layers.inet import ICMP, IP  # type: ignore
    from scapy.layers.inet6 import (
        ICMPv6DestUnreach,
        ICMPv6EchoReply,
        ICMPv6EchoRequest,
        ICMPv6PacketTooBig,
        ICMPv6ParamProblem,
        ICMPv6TimeExceeded,
        ICMPv6Unknown,
        IPv6,
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
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: list[str] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    asymmetry_profiles: list[dict[str, object]] = field(default_factory=list)
    recon_profiles: list[dict[str, object]] = field(default_factory=list)
    control_plane_profiles: list[dict[str, object]] = field(default_factory=list)
    fragmentation_profiles: list[dict[str, object]] = field(default_factory=list)
    cadence_profiles: list[dict[str, object]] = field(default_factory=list)
    tunneling_profiles: list[dict[str, object]] = field(default_factory=list)
    zone_profiles: list[dict[str, object]] = field(default_factory=list)
    ot_boundary_profiles: list[dict[str, object]] = field(default_factory=list)
    role_drift_profiles: list[dict[str, object]] = field(default_factory=list)
    corroborated_findings: list[dict[str, object]] = field(default_factory=list)
    risk_matrix: list[dict[str, str]] = field(default_factory=list)
    false_positive_context: list[str] = field(default_factory=list)


def _build_icmp_enrichment(
    *,
    total_packets: int,
    duration_seconds: Optional[float],
    type_counts: Counter[str],
    src_ip_counts: Counter[str],
    dst_ip_counts: Counter[str],
    conversations: list[dict[str, object]],
    sessions: list[dict[str, object]],
    payload_summaries: list[dict[str, object]],
    detections: list[dict[str, str]],
) -> dict[str, object]:
    """Derive ICMP triage signals (deterministic checks + analyst verdict) from
    the detections. Drives the verdict-first output and risk matrix so an ICMP
    sweep / tunnel / flood is surfaced as a triage call, not just a raw stat dump.
    """
    _ = (total_packets, type_counts, src_ip_counts, conversations, payload_summaries)
    checks: dict[str, list[str]] = defaultdict(list)
    risk_matrix: list[dict[str, object]] = []

    # Map each detection to a deterministic-check category by intent.
    for det in detections:
        sev = str(det.get("severity", "info")).lower()
        if sev == "info":
            continue
        summary_text = str(det.get("summary", ""))
        dtype = str(det.get("type", "")).lower()
        blob = f"{dtype} {summary_text}".lower()
        evidence = summary_text or dtype
        if "sweep" in blob or "without replies" in blob or "unreachable volume" in blob:
            checks["icmp_recon_sweep_behavior"].append(evidence)
        if any(
            tok in blob
            for tok in ("tunnel", "covert", "high-entropy", "large icmp", "payload variab", "payload anomal", "large icmp payload")
        ):
            checks["icmp_tunneling_signal"].append(evidence)
        if "redirect" in blob or "router advert" in blob or "control-plane" in blob:
            checks["icmp_control_plane_abuse"].append(evidence)
        if "flood" in blob or "high icmp rate" in blob:
            checks["icmp_recon_sweep_behavior"].append(evidence)

    # Verdict: synthesize the categories into a triage call. Covert-channel /
    # exfil (tunneling) and control-plane abuse (ICMP redirect = MITM) are the
    # high-consequence findings; recon sweeps are leads; floods are availability.
    score = 0
    reasons: list[str] = []
    for det in detections:
        sev = str(det.get("severity", "info")).lower()
        score += {"critical": 3, "high": 2, "warning": 1}.get(sev, 0)
    if checks.get("icmp_tunneling_signal"):
        score += 2
        reasons.append(
            "ICMP covert-channel / tunneling indicators (possible C2 or exfiltration over ICMP)"
        )
    if checks.get("icmp_control_plane_abuse"):
        score += 2
        reasons.append("ICMP control-plane abuse (e.g. Redirect — possible MITM)")
    if checks.get("icmp_recon_sweep_behavior"):
        score += 1
        reasons.append("ICMP reconnaissance / host-discovery sweep observed")
    high_ct = sum(
        1 for d in detections if str(d.get("severity", "")).lower() in {"high", "critical"}
    )
    if high_ct:
        reasons.append(f"High-severity ICMP detections: {high_ct}")

    if score >= 6:
        verdict = "YES - high-confidence malicious ICMP activity (covert channel / control-plane abuse) is present."
        confidence = "high"
    elif score >= 4:
        verdict = "LIKELY - suspicious ICMP activity with covert-channel or abuse indicators is present."
        confidence = "medium"
    elif score >= 2:
        verdict = "POSSIBLE - notable ICMP behavior (recon/large-payload) observed; corroboration recommended."
        confidence = "low"
    elif score >= 1:
        verdict = "LOW SIGNAL - minor ICMP anomalies present but not strongly corroborated."
        confidence = "low"
    else:
        verdict = ""
        confidence = "low"
    if not reasons and verdict:
        reasons.append("ICMP anomaly heuristics crossed threshold")

    # Build the risk matrix from the populated checks.
    _risk_meta = {
        "icmp_tunneling_signal": ("ICMP Tunneling/Covert Channel", "High"),
        "icmp_control_plane_abuse": ("ICMP Control-Plane Abuse", "High"),
        "icmp_recon_sweep_behavior": ("ICMP Recon/Sweep", "Medium"),
    }
    for key, (cat, risk) in _risk_meta.items():
        vals = checks.get(key, [])
        if vals:
            risk_matrix.append(
                {
                    "category": cat,
                    "risk": risk,
                    "confidence": "High" if len(vals) >= 2 else "Medium",
                    "evidence": f"{len(vals)} signal(s)",
                }
            )

    return {
        "analyst_verdict": verdict,
        "analyst_confidence": confidence,
        "analyst_reasons": reasons,
        "deterministic_checks": {k: list(dict.fromkeys(v)) for k, v in checks.items()},
        "risk_matrix": risk_matrix,
    }

@memoize_analysis
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
            conversations=[],
            sessions=[],
            request_counts=Counter(),
            response_counts=Counter(),
            artifacts=[],
            observed_users=Counter(),
            files_discovered=[],
            errors=errors,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

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
            ts = safe_float(getattr(pkt, "time", None))
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            # Resolve each scapy layer class at most once per packet via
            # getlayer (haslayer + pkt[X] would walk the layer chain twice).
            icmp_layer = pkt.getlayer(ICMP) if ICMP is not None else None  # type: ignore[arg-type]
            is_icmpv4 = icmp_layer is not None
            ip_layer = None
            ip_layer_resolved = False
            ip6_layer = None
            ip6_layer_resolved = False
            icmp6_unknown = None
            icmp6_echo_request = None
            icmp6_echo_reply = None
            icmp6_dest_unreach = None
            icmp6_time_exceeded = None
            icmp6_param_problem = None
            icmp6_packet_too_big = None
            is_icmpv6 = False
            if (
                ICMPv6Unknown is not None
                and (icmp6_unknown := pkt.getlayer(ICMPv6Unknown)) is not None
            ):
                is_icmpv6 = True
            elif (
                ICMPv6EchoRequest is not None
                and (icmp6_echo_request := pkt.getlayer(ICMPv6EchoRequest)) is not None
            ):
                is_icmpv6 = True
            elif (
                ICMPv6EchoReply is not None
                and (icmp6_echo_reply := pkt.getlayer(ICMPv6EchoReply)) is not None
            ):
                is_icmpv6 = True
            elif (
                ICMPv6DestUnreach is not None
                and (icmp6_dest_unreach := pkt.getlayer(ICMPv6DestUnreach)) is not None
            ):
                is_icmpv6 = True
            elif (
                ICMPv6TimeExceeded is not None
                and (icmp6_time_exceeded := pkt.getlayer(ICMPv6TimeExceeded))
                is not None
            ):
                is_icmpv6 = True
            elif (
                ICMPv6ParamProblem is not None
                and (icmp6_param_problem := pkt.getlayer(ICMPv6ParamProblem))
                is not None
            ):
                is_icmpv6 = True
            elif (
                ICMPv6PacketTooBig is not None
                and (icmp6_packet_too_big := pkt.getlayer(ICMPv6PacketTooBig))
                is not None
            ):
                is_icmpv6 = True
            # Fallback: detect ICMP by IP protocol/next-header if layers are missing
            if not is_icmpv4 and not is_icmpv6:
                if IP is not None:
                    ip_layer = pkt.getlayer(IP)  # type: ignore[arg-type]
                ip_layer_resolved = True
                if ip_layer is not None:
                    if getattr(ip_layer, "proto", None) == 1:
                        is_icmpv4 = True
                if not is_icmpv4:
                    if IPv6 is not None:
                        ip6_layer = pkt.getlayer(IPv6)  # type: ignore[arg-type]
                    ip6_layer_resolved = True
                    if ip6_layer is not None and getattr(ip6_layer, "nh", None) == 58:
                        is_icmpv6 = True
            if not is_icmpv4 and not is_icmpv6:
                continue

            total_packets += 1
            pkt_len = packet_length(pkt)
            total_bytes += pkt_len

            if is_icmpv4:
                ipv4_packets += 1
                try:
                    if icmp_layer is not None:
                        payload_bytes = bytes(icmp_layer.payload)
                        payload_len = len(payload_bytes)
                    else:
                        if not ip_layer_resolved:
                            ip_layer = (
                                pkt.getlayer(IP) if IP is not None else None  # type: ignore[arg-type]
                            )
                            ip_layer_resolved = True
                        payload_bytes = (
                            bytes(ip_layer.payload) if ip_layer is not None else b""
                        )
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
                if not ip_layer_resolved:
                    ip_layer = pkt.getlayer(IP) if IP is not None else None  # type: ignore[arg-type]
                    ip_layer_resolved = True
                if ip_layer is not None:
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
                        sess = sessions.setdefault(
                            sess_key,
                            {
                                "src": src,
                                "dst": dst,
                                "id": int(icmp_id),
                                "requests": 0,
                                "replies": 0,
                                "first_seen": None,
                                "last_seen": None,
                                "packets": 0,
                            },
                        )
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
                icmp6_layer = None
                if icmp6_unknown is None:
                    # Detection above resolved (to None) every class earlier in
                    # this extraction order than its match, so reuse the locals.
                    if icmp6_echo_request is not None:
                        icmp6_layer = icmp6_echo_request
                    elif icmp6_echo_reply is not None:
                        icmp6_layer = icmp6_echo_reply
                    elif icmp6_dest_unreach is not None:
                        icmp6_layer = icmp6_dest_unreach
                    elif icmp6_time_exceeded is not None:
                        icmp6_layer = icmp6_time_exceeded
                    elif icmp6_param_problem is not None:
                        icmp6_layer = icmp6_param_problem
                    elif icmp6_packet_too_big is not None:
                        icmp6_layer = icmp6_packet_too_big
                else:
                    # Detection short-circuited at ICMPv6Unknown, so the other
                    # classes are still unresolved; check them in extraction
                    # order before falling back to the unknown layer.
                    if (
                        ICMPv6EchoRequest is not None
                        and (icmp6_echo_request := pkt.getlayer(ICMPv6EchoRequest))
                        is not None
                    ):
                        icmp6_layer = icmp6_echo_request
                    elif (
                        ICMPv6EchoReply is not None
                        and (icmp6_echo_reply := pkt.getlayer(ICMPv6EchoReply))
                        is not None
                    ):
                        icmp6_layer = icmp6_echo_reply
                    elif (
                        ICMPv6DestUnreach is not None
                        and (icmp6_dest_unreach := pkt.getlayer(ICMPv6DestUnreach))
                        is not None
                    ):
                        icmp6_layer = icmp6_dest_unreach
                    elif (
                        ICMPv6TimeExceeded is not None
                        and (icmp6_time_exceeded := pkt.getlayer(ICMPv6TimeExceeded))
                        is not None
                    ):
                        icmp6_layer = icmp6_time_exceeded
                    elif (
                        ICMPv6ParamProblem is not None
                        and (icmp6_param_problem := pkt.getlayer(ICMPv6ParamProblem))
                        is not None
                    ):
                        icmp6_layer = icmp6_param_problem
                    elif (
                        ICMPv6PacketTooBig is not None
                        and (icmp6_packet_too_big := pkt.getlayer(ICMPv6PacketTooBig))
                        is not None
                    ):
                        icmp6_layer = icmp6_packet_too_big
                    else:
                        icmp6_layer = icmp6_unknown
                try:
                    if icmp6_layer is not None:
                        payload_bytes = bytes(icmp6_layer.payload)
                        payload_len = len(payload_bytes)
                    else:
                        if not ip6_layer_resolved:
                            ip6_layer = (
                                pkt.getlayer(IPv6) if IPv6 is not None else None  # type: ignore[arg-type]
                            )
                            ip6_layer_resolved = True
                        if ip6_layer is not None:
                            payload_bytes = bytes(ip6_layer.payload)
                            payload_len = len(payload_bytes)
                        else:
                            payload_bytes = b""
                            payload_len = 0
                except Exception:
                    payload_bytes = b""
                    payload_len = 0
                icmp6_type = (
                    getattr(icmp6_layer, "type", None)
                    if icmp6_layer is not None
                    else None
                )
                icmp6_code = (
                    getattr(icmp6_layer, "code", None)
                    if icmp6_layer is not None
                    else None
                )
                if icmp6_type is None:
                    if not ip6_layer_resolved:
                        ip6_layer = pkt.getlayer(IPv6) if IPv6 is not None else None  # type: ignore[arg-type]
                        ip6_layer_resolved = True
                    if ip6_layer is not None:
                        try:
                            raw_bytes = bytes(ip6_layer.payload)
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
                if not ip6_layer_resolved:
                    ip6_layer = pkt.getlayer(IPv6) if IPv6 is not None else None  # type: ignore[arg-type]
                    ip6_layer_resolved = True
                if ip6_layer is not None:
                    if getattr(ip6_layer, "src", None):
                        src = str(ip6_layer.src)
                        src_ips.add(src)
                        src_ip_counts[src] += 1
                    if getattr(ip6_layer, "dst", None):
                        dst = str(ip6_layer.dst)
                        dst_ips.add(dst)
                        dst_ip_counts[dst] += 1

                if icmp6_type in (128, 129):
                    icmp_id = (
                        getattr(icmp6_layer, "id", None)
                        if icmp6_layer is not None
                        else None
                    )
                    if icmp_id is not None and src and dst:
                        sess_key = (src, dst, int(icmp_id))
                        sess = sessions.setdefault(
                            sess_key,
                            {
                                "src": src,
                                "dst": dst,
                                "id": int(icmp_id),
                                "requests": 0,
                                "replies": 0,
                                "first_seen": None,
                                "last_seen": None,
                                "packets": 0,
                            },
                        )
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
                entry = payload_meta.setdefault(
                    digest,
                    {
                        "size": payload_len,
                        "sources": Counter(),
                        "destinations": Counter(),
                        "samples": payload_bytes[:64],
                    },
                )
                if src:
                    entry["sources"][src] += 1  # type: ignore[index]
                if dst:
                    entry["destinations"][dst] += 1  # type: ignore[index]

                # Artifact extraction
                try:
                    text = "".join(
                        chr(b) if 32 <= b <= 126 else " " for b in payload_bytes[:128]
                    )
                    for token in text.split():
                        if len(token) >= 4:
                            artifacts.add(token)
                            if token.lower().startswith(
                                ("user=", "username=", "login=")
                            ):
                                observed_users[token] += 1
                    for name in re.findall(
                        r"[\w\-.()\[\] ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|txt|bat|ps1|jpg|jpeg|png|gif|bmp|tiff)",
                        text,
                        re.IGNORECASE,
                    ):
                        files_discovered.add(name)
                except Exception:
                    pass

            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if src and dst:
                convo_key = (src, dst, "icmpv4" if is_icmpv4 else "icmpv6")
                convo = conversations.setdefault(
                    convo_key,
                    {
                        "src": src,
                        "dst": dst,
                        "protocol": "icmpv4" if is_icmpv4 else "icmpv6",
                        "packets": 0,
                        "bytes": 0,
                        "first_seen": None,
                        "last_seen": None,
                    },
                )
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
        return -sum(
            (count / total) * math.log2(count / total) for count in freq.values()
        )

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
        top_dst = (
            destinations.most_common(3) if isinstance(destinations, Counter) else []
        )

        payload_summaries.append(
            {
                "payload_hex": bytes(sample_bytes).hex(),
                "payload_preview": _preview_text(bytes(sample_bytes)[:64]),
                "count": count,
                "size": size,
                "entropy": _entropy(bytes(sample_bytes)),
                "top_sources": top_src,
                "top_destinations": top_dst,
            }
        )

    if total_packets == 0:
        detections.append(
            {
                "type": "no_icmp",
                "severity": "info",
                "summary": "No ICMP traffic detected",
                "details": "ICMP/ICMPv6 not observed in capture.",
            }
        )
    else:
        # A flood is a *sustained* high rate; guard against tiny/short captures
        # where dividing by a near-zero duration yields a meaningless pkt/s.
        if duration_seconds and duration_seconds >= 1.0 and total_packets >= 500:
            pps = total_packets / duration_seconds
            if pps > 5000:
                detections.append(
                    {
                        "type": "icmp_flood",
                        "severity": "critical",
                        "summary": f"ICMP flood suspected ({pps:.1f} pkt/s)",
                        "details": "High ICMP packet rate suggests DoS/DDoS or test traffic.",
                        "packet_count": total_packets,
                        "unique_sources": len(src_ip_counts),
                        "unique_destinations": len(dst_ip_counts),
                        "top_sources": src_ip_counts.most_common(3),
                        "top_destinations": dst_ip_counts.most_common(3),
                    }
                )
            elif pps > 1000:
                detections.append(
                    {
                        "type": "icmp_high_rate",
                        "severity": "warning",
                        "summary": f"High ICMP rate observed ({pps:.1f} pkt/s)",
                        "details": "Investigate bursty ICMP activity for flooding or scanning.",
                        "packet_count": total_packets,
                        "unique_sources": len(src_ip_counts),
                        "unique_destinations": len(dst_ip_counts),
                        "top_sources": src_ip_counts.most_common(3),
                        "top_destinations": dst_ip_counts.most_common(3),
                    }
                )

        # Destination Unreachable is type 3 in ICMPv4 and type 1 in ICMPv6.
        # Match exact keys -- a suffix test on ":3"/":1" wrongly folds in
        # ICMPv6 Time Exceeded (type 3) and any other protocol code 1/3.
        unreachable_count = type_counts.get("icmpv4:3", 0) + type_counts.get(
            "icmpv6:1", 0
        )
        if unreachable_count > 1000:
            detections.append(
                {
                    "type": "icmp_unreachable_volume",
                    "severity": "warning",
                    "summary": f"High ICMP unreachable volume ({unreachable_count} packets)",
                    "details": "Potential scanning, routing issues, or blocked services.",
                    "packet_count": unreachable_count,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                }
            )

        echo_request = type_counts.get("icmpv4:8", 0) + type_counts.get("icmpv6:128", 0)
        echo_reply = type_counts.get("icmpv4:0", 0) + type_counts.get("icmpv6:129", 0)
        if echo_request > 0 and echo_reply == 0:
            detections.append(
                {
                    "type": "icmp_echo_no_reply",
                    "severity": "info",
                    "summary": "ICMP echo requests observed without replies",
                    "details": "Potential filtering or one-way traffic capture.",
                    "packet_count": echo_request,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                }
            )

        if payload_variants > 20 and avg_payload > 100:
            detections.append(
                {
                    "type": "icmp_tunneling_suspected",
                    "severity": "warning",
                    "summary": "ICMP payload variability suggests tunneling",
                    "details": f"Observed {payload_variants} payload sizes with avg {avg_payload:.1f} bytes.",
                    "packet_count": total_packets,
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                }
            )

        if payload_max >= 1400:
            detections.append(
                {
                    "type": "icmp_large_payload",
                    "severity": "warning",
                    "summary": "Large ICMP payloads observed",
                    "details": f"Max payload size {payload_max} bytes.",
                    "packet_count": total_packets,
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                }
            )

        high_entropy_payloads = [
            p for p in payload_summaries if p.get("entropy", 0) >= 7.0
        ]
        if high_entropy_payloads:
            detections.append(
                {
                    "type": "icmp_high_entropy",
                    "severity": "warning",
                    "summary": "High-entropy ICMP payloads detected",
                    "details": f"{len(high_entropy_payloads)} payload(s) show high entropy (possible covert/exfil).",
                }
            )

        if echo_request > 200 and avg_payload > 200:
            detections.append(
                {
                    "type": "icmp_tunnel_indicator",
                    "severity": "warning",
                    "summary": "Possible ICMP tunneling behavior",
                    "details": f"High echo volume with elevated payload size (avg {avg_payload:.1f} bytes).",
                    "packet_count": echo_request,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                }
            )

        if payload_max > 1000 or payload_variants > 60:
            detections.append(
                {
                    "type": "icmp_payload_anomaly",
                    "severity": "warning",
                    "summary": "ICMP payload anomalies observed",
                    "details": "Large or highly variable payload sizes can indicate covert channels.",
                    "packet_count": total_packets,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                }
            )

        if src_ip_counts:
            top_src, top_src_count = src_ip_counts.most_common(1)[0]
            unique_dsts = len(dst_ip_counts)
            if unique_dsts > 50 and top_src_count > 50:
                detections.append(
                    {
                        "type": "icmp_sweep",
                        "severity": "warning",
                        "summary": "Potential ICMP sweep detected",
                        "details": f"Source {top_src} contacted {unique_dsts} unique destinations.",
                        "packet_count": top_src_count,
                        "unique_sources": len(src_ip_counts),
                        "unique_destinations": unique_dsts,
                        "top_sources": src_ip_counts.most_common(3),
                        "top_destinations": dst_ip_counts.most_common(3),
                    }
                )

        if dst_ip_counts:
            top_dst, top_dst_count = dst_ip_counts.most_common(1)[0]
            if (
                total_packets > 0
                and (top_dst_count / total_packets) > 0.7
                and top_dst_count > 500
            ):
                detections.append(
                    {
                        "type": "icmp_targeted_flood",
                        "severity": "warning",
                        "summary": "ICMP traffic concentrated on a single target",
                        "details": f"Destination {top_dst} received {top_dst_count} ICMP packets.",
                        "packet_count": top_dst_count,
                        "unique_sources": len(src_ip_counts),
                        "unique_destinations": len(dst_ip_counts),
                        "top_sources": src_ip_counts.most_common(3),
                        "top_destinations": dst_ip_counts.most_common(3),
                    }
                )

        if avg_payload > 500 and total_packets > 100:
            detections.append(
                {
                    "type": "icmp_exfiltration",
                    "severity": "warning",
                    "summary": "Potential ICMP data exfiltration",
                    "details": "Large average payload sizes over ICMP traffic.",
                    "packet_count": total_packets,
                    "unique_sources": len(src_ip_counts),
                    "unique_destinations": len(dst_ip_counts),
                    "top_sources": src_ip_counts.most_common(3),
                    "top_destinations": dst_ip_counts.most_common(3),
                }
            )

    context = _build_icmp_enrichment(
        total_packets=total_packets,
        duration_seconds=duration_seconds,
        type_counts=type_counts,
        src_ip_counts=src_ip_counts,
        dst_ip_counts=dst_ip_counts,
        conversations=list(conversations.values()),
        sessions=list(sessions.values()),
        payload_summaries=payload_summaries,
        detections=detections,
    )

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
        analyst_verdict=str(context.get("analyst_verdict", "")),
        analyst_confidence=str(context.get("analyst_confidence", "low")),
        analyst_reasons=[
            str(v) for v in list(context.get("analyst_reasons", []) or [])
        ],
        deterministic_checks={
            str(key): [str(v) for v in list(values or [])]
            for key, values in dict(
                context.get("deterministic_checks", {}) or {}
            ).items()
        },
        asymmetry_profiles=list(context.get("asymmetry_profiles", []) or []),
        recon_profiles=list(context.get("recon_profiles", []) or []),
        control_plane_profiles=list(context.get("control_plane_profiles", []) or []),
        fragmentation_profiles=list(context.get("fragmentation_profiles", []) or []),
        cadence_profiles=list(context.get("cadence_profiles", []) or []),
        tunneling_profiles=list(context.get("tunneling_profiles", []) or []),
        zone_profiles=list(context.get("zone_profiles", []) or []),
        ot_boundary_profiles=list(context.get("ot_boundary_profiles", []) or []),
        role_drift_profiles=list(context.get("role_drift_profiles", []) or []),
        corroborated_findings=list(context.get("corroborated_findings", []) or []),
        risk_matrix=[
            dict(item)
            for item in list(context.get("risk_matrix", []) or [])
            if isinstance(item, dict)
        ],
        false_positive_context=[
            str(v) for v in list(context.get("false_positive_context", []) or [])
        ],
    )
