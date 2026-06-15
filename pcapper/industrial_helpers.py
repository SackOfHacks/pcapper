from __future__ import annotations

from .utils import is_public_ip as _is_public_ip, packet_length
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
except ImportError:  # pragma: no cover - scapy optional at runtime
    TCP = UDP = IP = Raw = Ether = None

from .pcap_cache import get_reader
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

DEFAULT_KEYWORDS = {
    "user",
    "username",
    "login",
    "pass",
    "password",
    "token",
    "apikey",
    "secret",
    "auth",
    "cmd",
    "command",
    "write",
    "read",
    "upload",
    "download",
    "file",
    "start",
    "stop",
    "set",
    "get",
    "exec",
}


@dataclass
class IndustrialArtifact:
    kind: str
    detail: str
    src: str
    dst: str
    ts: float


@dataclass
class IndustrialAnomaly:
    severity: str
    title: str
    description: str
    src: str
    dst: str
    ts: float
    # Optional ATT&CK-for-ICS technique id (e.g. "T0855") and supporting
    # evidence strings. Defaulted so existing positional constructors keep
    # working; analyzers populate them to enrich the IR/triage output.
    attack: str = ""
    evidence: list[str] = field(default_factory=list)


def append_public_exposure_anomaly(
    analysis: "IndustrialAnalysis",
    protocol_name: str,
    *,
    max_anomalies: int = 200,
) -> None:
    """Flag an OT protocol observed talking to a public/Internet endpoint.

    Shared by the OT protocol analyzers (was a byte-identical ~12-line block
    copy-pasted across ~25 modules). Carries the ATT&CK-for-ICS technique and
    evidence so every OT protocol reports the exposure consistently.
    """
    public_endpoints = [
        ip
        for ip in set(analysis.src_ips) | set(analysis.dst_ips)
        if _is_public_ip(ip)
    ]
    if public_endpoints and len(analysis.anomalies) < max_anomalies:
        shown = ", ".join(sorted(public_endpoints)[:5])
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title=f"{protocol_name} Exposure to Public IP",
                description=(
                    f"{protocol_name} traffic observed with public endpoint(s): "
                    f"{shown}."
                ),
                src="*",
                dst="*",
                ts=0.0,
                attack="T0883 Internet Accessible Device",
                evidence=[f"public endpoint(s): {', '.join(sorted(public_endpoints)[:8])}"],
            )
        )


@dataclass
class IndustrialCommandEvent:
    ts: float
    src: str
    dst: str
    command: str


@dataclass
class IndustrialAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    protocol_packets: int = 0
    total_bytes: int = 0
    protocol_bytes: int = 0
    requests: int = 0
    responses: int = 0
    src_ips: Counter[str] = field(default_factory=Counter)
    dst_ips: Counter[str] = field(default_factory=Counter)
    client_ips: Counter[str] = field(default_factory=Counter)
    server_ips: Counter[str] = field(default_factory=Counter)
    sessions: Counter[str] = field(default_factory=Counter)
    ports: Counter[int] = field(default_factory=Counter)
    commands: Counter[str] = field(default_factory=Counter)
    service_endpoints: dict[str, Counter[str]] = field(default_factory=dict)
    packet_size_buckets: list["SizeBucket"] = field(default_factory=list)
    payload_size_buckets: list["SizeBucket"] = field(default_factory=list)
    command_events: list[IndustrialCommandEvent] = field(default_factory=list)
    artifacts: list[IndustrialArtifact] = field(default_factory=list)
    anomalies: list[IndustrialAnomaly] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SizeBucket:
    label: str
    count: int
    avg: float
    min: int
    max: int
    pct: float


CommandParser = Callable[[bytes], Iterable[str]]
ArtifactParser = Callable[[bytes], Iterable[tuple[str, str]]]
AnomalyDetector = Callable[
    [bytes, str, str, float, Iterable[str]], Iterable[IndustrialAnomaly]
]
SignatureMatcher = Callable[[bytes], bool]

# Ephemeral/dynamic source-port floor (Linux 32768+, Windows 49152+). A flow is
# treated as OT-protocol traffic only when the OT port is the server side: the
# destination, or the source paired with an ephemeral destination (a response).
# This prevents an ephemeral source port that merely equals an OT port number
# from misclassifying unrelated traffic as OT.
_PORT_SERVER_EPHEMERAL_MIN = 32768


def _format_ascii(payload: bytes, limit: int = 200) -> str:
    if not payload:
        return ""
    text = payload[:limit].decode("utf-8", errors="ignore")
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(cleaned.split())


def _keyword_artifacts(payload: bytes, keywords: set[str]) -> list[tuple[str, str]]:
    text = _format_ascii(payload)
    if not text:
        return []
    lowered = text.lower()
    hits = [kw for kw in keywords if kw in lowered]
    if not hits:
        return []
    detail = text[:160]
    return [("keyword", f"{', '.join(sorted(hits))}: {detail}")]


def _default_artifacts(payload: bytes) -> list[tuple[str, str]]:
    return _keyword_artifacts(payload, DEFAULT_KEYWORDS)


def default_artifacts(payload: bytes) -> list[tuple[str, str]]:
    return _default_artifacts(payload)


def _bucketize(values: list[int]) -> list[SizeBucket]:
    if not values:
        return []
    size_buckets = [
        (0, 19, "0-19"),
        (20, 39, "20-39"),
        (40, 79, "40-79"),
        (80, 159, "80-159"),
        (160, 319, "160-319"),
        (320, 639, "320-639"),
        (640, 1279, "640-1279"),
        (1280, 2559, "1280-2559"),
        (2560, 5119, "2560-5119"),
        (5120, 65535, "5120+"),
    ]
    buckets: list[SizeBucket] = []
    total = len(values)
    for low, high, label in size_buckets:
        entries = [val for val in values if low <= val <= high]
        count = len(entries)
        avg = sum(entries) / count if count else 0.0
        min_val = min(entries) if entries else 0
        max_val = max(entries) if entries else 0
        pct = (count / total) * 100 if total else 0.0
        buckets.append(
            SizeBucket(
                label=label, count=count, avg=avg, min=min_val, max=max_val, pct=pct
            )
        )
    return buckets


def _default_anomalies(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ts: float,
    commands: Iterable[str],
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    lowered = _format_ascii(payload).lower()
    if any(
        token in lowered
        for token in ("password", "passwd", "token", "apikey", "secret")
    ):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="Possible credential material",
                description="Potential credential keywords observed in payload.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(
        cmd.lower().startswith("write") or "write" in cmd.lower() for cmd in commands
    ):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="Write/Control Operation",
                description="Write or control-related operation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def _extract_transport(pkt) -> tuple[bool, str, str, int, int, bytes]:
    src_ip = "?"
    dst_ip = "?"
    sport = 0
    dport = 0
    payload = b""

    if TCP is not None and pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        payload_obj = pkt[TCP].payload
        payload = bytes(payload_obj) if payload_obj else b""
        if not payload and Raw is not None and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                pass
    elif UDP is not None and pkt.haslayer(UDP):
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        payload_obj = pkt[UDP].payload
        payload = bytes(payload_obj) if payload_obj else b""
        if not payload and Raw is not None and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                pass
    else:
        return False, src_ip, dst_ip, sport, dport, payload

    src_raw, dst_raw = extract_packet_endpoints(pkt)
    if src_raw and dst_raw:
        src_ip = src_raw
        dst_ip = dst_raw
    else:
        src_ip = pkt[0].src if hasattr(pkt[0], "src") else "?"
        dst_ip = pkt[0].dst if hasattr(pkt[0], "dst") else "?"

    return True, src_ip, dst_ip, sport, dport, payload


def _extract_ethertype(pkt) -> Optional[int]:
    if Ether is not None and pkt.haslayer(Ether):
        try:
            return int(pkt[Ether].type)
        except Exception:
            return None
    try:
        raw = bytes(pkt)
        if len(raw) >= 14:
            return int.from_bytes(raw[12:14], "big")
    except Exception:
        return None
    return None


@memoize_analysis
def analyze_port_protocol(
    path: Path,
    protocol_name: str,
    tcp_ports: set[int] | None = None,
    udp_ports: set[int] | None = None,
    signature_matcher: SignatureMatcher | None = None,
    command_parser: CommandParser | None = None,
    artifact_parser: ArtifactParser | None = None,
    anomaly_detector: AnomalyDetector | None = None,
    enable_enrichment: bool = False,
    show_status: bool = True,
) -> IndustrialAnalysis:
    if TCP is None and UDP is None:
        return IndustrialAnalysis(
            path=path,
            errors=["Scapy unavailable (TCP/UDP missing)"],
        )

    tcp_ports = tcp_ports or set()
    udp_ports = udp_ports or set()

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return IndustrialAnalysis(path=path, errors=[f"Error: {exc}"])

    analysis = IndustrialAnalysis(path=path)
    # Collapse identical per-packet detector findings (same title/src/dst/detail)
    # to one — OT detectors that emit an anomaly per packet otherwise flood the
    # 200-cap with thousands of identical entries (e.g. one "Control Object
    # Operation" per DNP3 packet) and bury the distinct findings. Detectors that
    # already aggregate (distinct descriptions per sub-event) are unaffected.
    _seen_anoms: set[tuple[str, str, str, str]] = set()
    start_time = None
    last_time = None
    seen_artifacts: set[str] = set()
    payload_sizes: list[int] = []
    packet_sizes: list[int] = []
    session_last_ts: dict[str, float] = {}
    session_intervals: dict[str, list[float]] = defaultdict(list)
    src_requests: Counter[str] = Counter()
    src_responses: Counter[str] = Counter()
    src_dst_bytes: dict[str, Counter[str]] = defaultdict(Counter)

    try:
        with status as pbar:
            try:
                total_count = len(reader)
            except Exception:
                total_count = None
            for idx, pkt in enumerate(reader):
                if total_count and idx % 10 == 0:
                    try:
                        pbar.update(int((idx / max(1, total_count)) * 100))
                    except Exception:
                        pass

                analysis.total_packets += 1
                pkt_len = packet_length(pkt)
                analysis.total_bytes += pkt_len
                ts = safe_float(getattr(pkt, "time", 0))
                if start_time is None:
                    start_time = ts
                last_time = ts

                has_transport, src_ip, dst_ip, sport, dport, payload = (
                    _extract_transport(pkt)
                )
                if not has_transport:
                    continue

                # Classify by port only when the OT port is the *server* side:
                # the destination (client -> server) or the source with an
                # ephemeral destination (server -> client response). A bare
                # "sport or dport in ports" test misclassifies any flow whose
                # ephemeral source port happens to equal an OT port number —
                # e.g. a TCP DNS query to 8.8.8.8:53 whose ephemeral source port
                # is 44818 would otherwise be reported as EtherNet/IP/CSP/PCCC
                # traffic to a public IP. Signature matches are always honored.
                matches_port = (
                    dport in tcp_ports
                    or dport in udp_ports
                    or (
                        (sport in tcp_ports or sport in udp_ports)
                        and dport >= _PORT_SERVER_EPHEMERAL_MIN
                    )
                )
                matches_sig = (
                    signature_matcher(payload)
                    if signature_matcher and payload
                    else False
                )
                if not matches_port and not matches_sig:
                    continue

                analysis.protocol_packets += 1
                analysis.protocol_bytes += pkt_len
                analysis.src_ips[src_ip] += 1
                analysis.dst_ips[dst_ip] += 1
                analysis.sessions[f"{src_ip}:{sport} -> {dst_ip}:{dport}"] += 1
                if sport:
                    analysis.ports[sport] += 1
                if dport:
                    analysis.ports[dport] += 1

                if enable_enrichment:
                    payload_sizes.append(len(payload))
                    packet_sizes.append(pkt_len)
                    session_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                    if session_key in session_last_ts and ts is not None:
                        interval = ts - session_last_ts[session_key]
                        if interval >= 0:
                            session_intervals[session_key].append(interval)
                    if ts is not None:
                        session_last_ts[session_key] = ts

                    is_request = (dport in tcp_ports) or (dport in udp_ports)
                    is_response = (sport in tcp_ports) or (sport in udp_ports)
                    if is_request and not is_response:
                        analysis.requests += 1
                        analysis.client_ips[src_ip] += 1
                        analysis.server_ips[dst_ip] += 1
                        src_requests[src_ip] += 1
                    elif is_response and not is_request:
                        analysis.responses += 1
                        analysis.client_ips[dst_ip] += 1
                        analysis.server_ips[src_ip] += 1
                        src_responses[src_ip] += 1
                    if payload:
                        src_dst_bytes[src_ip][dst_ip] += len(payload)

                commands = list(command_parser(payload)) if command_parser else []
                if commands:
                    analysis.commands.update(commands)
                    if enable_enrichment:
                        for cmd in commands:
                            endpoints = analysis.service_endpoints.setdefault(
                                str(cmd), Counter()
                            )
                            endpoints[f"{src_ip} -> {dst_ip}"] += 1
                    if ts is not None and len(analysis.command_events) < 5000:
                        for cmd in commands:
                            analysis.command_events.append(
                                IndustrialCommandEvent(
                                    ts=ts,
                                    src=src_ip,
                                    dst=dst_ip,
                                    command=str(cmd),
                                )
                            )

                if artifact_parser is None:
                    artifacts = _default_artifacts(payload)
                else:
                    artifacts = list(artifact_parser(payload))
                for kind, detail in artifacts:
                    key = f"{kind}:{detail}"
                    if key in seen_artifacts:
                        continue
                    seen_artifacts.add(key)
                    if len(analysis.artifacts) < 200:
                        analysis.artifacts.append(
                            IndustrialArtifact(
                                kind=kind,
                                detail=detail,
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts,
                            )
                        )

                detector = anomaly_detector or _default_anomalies
                for anomaly in detector(payload, src_ip, dst_ip, ts, commands):
                    _akey = (
                        str(getattr(anomaly, "title", "")),
                        str(getattr(anomaly, "src", "")),
                        str(getattr(anomaly, "dst", "")),
                        str(getattr(anomaly, "description", "")),
                    )
                    if _akey in _seen_anoms:
                        continue
                    _seen_anoms.add(_akey)
                    if len(analysis.anomalies) < 200:
                        analysis.anomalies.append(anomaly)

    except Exception as exc:
        analysis.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            reader.close()
        except Exception:
            pass

    if start_time is not None and last_time is not None:
        analysis.duration = last_time - start_time

    if enable_enrichment:
        analysis.packet_size_buckets = _bucketize(packet_sizes)
        analysis.payload_size_buckets = _bucketize(payload_sizes)

        max_anomalies = 200
        for src, dsts in src_dst_bytes.items():
            unique_dsts = len(dsts)
            req_count = src_requests.get(src, 0)
            resp_count = src_responses.get(src, 0)
            if (
                unique_dsts >= 20
                and req_count > resp_count * 2
                and len(analysis.anomalies) < max_anomalies
            ):
                sample_dsts = ", ".join(
                    str(d)
                    for d, _b in sorted(
                        dsts.items(), key=lambda kv: kv[1], reverse=True
                    )[:6]
                )
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title=f"{protocol_name} Scanning/Probing",
                        description=f"Source contacted {unique_dsts} endpoints with low response rate.",
                        src=src,
                        dst="*",
                        ts=0.0,
                        attack="T0846 Remote System Discovery",
                        evidence=[
                            f"{unique_dsts} unique destinations",
                            f"requests={req_count} responses={resp_count}",
                            f"top dst: {sample_dsts}",
                        ],
                    )
                )

        for session_key, intervals in session_intervals.items():
            if len(intervals) < 6:
                continue
            avg = sum(intervals) / len(intervals)
            if avg <= 0:
                continue
            variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
            cv = (variance**0.5) / avg
            if cv <= 0.2 and 1.0 <= avg <= 300.0:
                src_part, dst_part = session_key.split(" -> ", 1)
                src_ip = src_part.split(":", 1)[0]
                dst_ip = dst_part.split(":", 1)[0]
                # Low-jitter regular intervals are normal SCADA polling; only an
                # EXTERNAL destination makes periodic OT traffic a beacon/C2 lead.
                if not _is_public_ip(dst_ip):
                    continue
                if len(analysis.anomalies) < max_anomalies:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="LOW",
                            title=f"Possible {protocol_name} Beaconing",
                            description=f"Regular interval traffic (~{avg:.2f}s) observed.",
                            src=src_ip,
                            dst=dst_ip,
                            ts=0.0,
                            attack="T0869 Standard Application Layer Protocol",
                            evidence=[
                                f"mean interval ~{avg:.2f}s (CV={cv:.2f}, n={len(intervals)})",
                                f"external destination {dst_ip}",
                            ],
                        )
                    )

        for src, dsts in src_dst_bytes.items():
            for dst, byte_count in dsts.items():
                if (
                    byte_count >= 5_000_000
                    and _is_public_ip(dst)
                    and len(analysis.anomalies) < max_anomalies
                ):
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="MEDIUM",
                            title=f"Possible {protocol_name} Data Exfiltration",
                            description=f"{byte_count} bytes sent to public IP.",
                            src=src,
                            dst=dst,
                            ts=0.0,
                            attack="T0883 Internet Accessible Device",
                            evidence=[
                                f"{byte_count:,} bytes to public IP {dst}",
                            ],
                        )
                    )

    return analysis


@memoize_analysis
def analyze_ethertype_protocol(
    path: Path,
    protocol_name: str,
    ethertype: int,
    command_parser: CommandParser | None = None,
    artifact_parser: ArtifactParser | None = None,
    anomaly_detector: AnomalyDetector | None = None,
    enable_enrichment: bool = False,
    show_status: bool = True,
) -> IndustrialAnalysis:
    if Ether is None:
        return IndustrialAnalysis(
            path=path,
            errors=["Scapy unavailable (Ether missing)"],
        )

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return IndustrialAnalysis(path=path, errors=[f"Error: {exc}"])

    analysis = IndustrialAnalysis(path=path)
    # Collapse identical per-packet detector findings (same title/src/dst/detail)
    # to one — OT detectors that emit an anomaly per packet otherwise flood the
    # 200-cap with thousands of identical entries (e.g. one "Control Object
    # Operation" per DNP3 packet) and bury the distinct findings. Detectors that
    # already aggregate (distinct descriptions per sub-event) are unaffected.
    _seen_anoms: set[tuple[str, str, str, str]] = set()
    start_time = None
    last_time = None
    seen_artifacts: set[str] = set()
    payload_sizes: list[int] = []
    packet_sizes: list[int] = []
    session_last_ts: dict[str, float] = {}
    session_intervals: dict[str, list[float]] = defaultdict(list)
    src_dst_bytes: dict[str, Counter[str]] = defaultdict(Counter)

    try:
        with status as pbar:
            try:
                total_count = len(reader)
            except Exception:
                total_count = None
            for idx, pkt in enumerate(reader):
                if total_count and idx % 10 == 0:
                    try:
                        pbar.update(int((idx / max(1, total_count)) * 100))
                    except Exception:
                        pass

                analysis.total_packets += 1
                pkt_len = packet_length(pkt)
                analysis.total_bytes += pkt_len
                ts = safe_float(getattr(pkt, "time", 0))
                if start_time is None:
                    start_time = ts
                last_time = ts

                etype = _extract_ethertype(pkt)
                if etype != ethertype:
                    continue

                analysis.protocol_packets += 1
                analysis.protocol_bytes += pkt_len
                src_ip = pkt[0].src if hasattr(pkt[0], "src") else "?"
                dst_ip = pkt[0].dst if hasattr(pkt[0], "dst") else "?"
                analysis.src_ips[src_ip] += 1
                analysis.dst_ips[dst_ip] += 1
                analysis.sessions[f"{src_ip} -> {dst_ip}"] += 1

                if enable_enrichment:
                    payload = (
                        bytes(pkt[Ether].payload)
                        if Ether is not None and pkt.haslayer(Ether)
                        else b""
                    )
                    payload_sizes.append(len(payload))
                    packet_sizes.append(pkt_len)
                    analysis.requests += 1
                    analysis.client_ips[src_ip] += 1
                    analysis.server_ips[dst_ip] += 1
                    session_key = f"{src_ip} -> {dst_ip}"
                    if session_key in session_last_ts and ts is not None:
                        interval = ts - session_last_ts[session_key]
                        if interval >= 0:
                            session_intervals[session_key].append(interval)
                    if ts is not None:
                        session_last_ts[session_key] = ts
                    if payload:
                        src_dst_bytes[src_ip][dst_ip] += len(payload)

                payload = (
                    bytes(pkt[Ether].payload)
                    if Ether is not None and pkt.haslayer(Ether)
                    else b""
                )

                commands = list(command_parser(payload)) if command_parser else []
                if commands:
                    analysis.commands.update(commands)
                    if enable_enrichment:
                        for cmd in commands:
                            endpoints = analysis.service_endpoints.setdefault(
                                str(cmd), Counter()
                            )
                            endpoints[f"{src_ip} -> {dst_ip}"] += 1

                if artifact_parser is None:
                    artifacts = _default_artifacts(payload)
                else:
                    artifacts = list(artifact_parser(payload))
                for kind, detail in artifacts:
                    key = f"{kind}:{detail}"
                    if key in seen_artifacts:
                        continue
                    seen_artifacts.add(key)
                    if len(analysis.artifacts) < 200:
                        analysis.artifacts.append(
                            IndustrialArtifact(
                                kind=kind,
                                detail=detail,
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts,
                            )
                        )

                detector = anomaly_detector or _default_anomalies
                for anomaly in detector(payload, src_ip, dst_ip, ts, commands):
                    _akey = (
                        str(getattr(anomaly, "title", "")),
                        str(getattr(anomaly, "src", "")),
                        str(getattr(anomaly, "dst", "")),
                        str(getattr(anomaly, "description", "")),
                    )
                    if _akey in _seen_anoms:
                        continue
                    _seen_anoms.add(_akey)
                    if len(analysis.anomalies) < 200:
                        analysis.anomalies.append(anomaly)

    except Exception as exc:
        analysis.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            reader.close()
        except Exception:
            pass

    if start_time is not None and last_time is not None:
        analysis.duration = last_time - start_time

    if enable_enrichment:
        analysis.packet_size_buckets = _bucketize(packet_sizes)
        analysis.payload_size_buckets = _bucketize(payload_sizes)

        max_anomalies = 200
        for session_key, intervals in session_intervals.items():
            if len(intervals) < 6:
                continue
            avg = sum(intervals) / len(intervals)
            if avg <= 0:
                continue
            variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
            cv = (variance**0.5) / avg
            if cv <= 0.2 and 1.0 <= avg <= 300.0:
                src_ip, dst_ip = session_key.split(" -> ", 1)
                # Only external destinations make periodic OT traffic a beacon
                # lead; internal cyclic polling is normal SCADA baseline.
                if not _is_public_ip(dst_ip.split(":", 1)[0]):
                    continue
                if len(analysis.anomalies) < max_anomalies:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="LOW",
                            title=f"Possible {protocol_name} Beaconing",
                            description=f"Regular interval traffic (~{avg:.2f}s) observed.",
                            src=src_ip,
                            dst=dst_ip,
                            ts=0.0,
                            attack="T0869 Standard Application Layer Protocol",
                            evidence=[
                                f"mean interval ~{avg:.2f}s (CV={cv:.2f}, n={len(intervals)})",
                                f"external destination {dst_ip}",
                            ],
                        )
                    )

        for src, dsts in src_dst_bytes.items():
            for dst, byte_count in dsts.items():
                if (
                    byte_count >= 5_000_000
                    and _is_public_ip(dst)
                    and len(analysis.anomalies) < max_anomalies
                ):
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="MEDIUM",
                            title=f"Possible {protocol_name} Data Exfiltration",
                            description=f"{byte_count} bytes sent to public IP.",
                            src=src,
                            dst=dst,
                            ts=0.0,
                            attack="T0883 Internet Accessible Device",
                            evidence=[
                                f"{byte_count:,} bytes to public IP {dst}",
                            ],
                        )
                    )

    return analysis
