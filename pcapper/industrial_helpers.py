from __future__ import annotations

from .utils import is_public_ip as _is_public_ip, packet_length
import bisect
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Padding, Raw
except ImportError:  # pragma: no cover - scapy optional at runtime
    TCP = UDP = IP = Raw = Ether = Padding = None

from .pcap_cache import iter_packets
from .utils import extract_ethertype, extract_packet_endpoints, safe_float

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

    Mutates ``analysis`` in place. That is safe only because
    :func:`analyze_port_protocol` / :func:`analyze_ethertype_protocol` return
    a fresh object on every call (they are deliberately *not* memoized); the
    outer ``analyze_<protocol>`` function that owns the object is the one
    memoized, after all post-processing has run.
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


def cleared_analysis(analysis: IndustrialAnalysis) -> IndustrialAnalysis:
    """A fresh result keeping only the capture-level facts of ``analysis``.

    Used when a protocol analyzer decides its match was low-confidence (a port
    collision, a few ambiguous packets) and must report "not present" without
    losing the total packet/byte counts, duration and any errors. Building a
    new object — rather than clearing every counter on the old one in place —
    keeps the result independent of anything else still holding the original.
    """
    return IndustrialAnalysis(
        path=analysis.path,
        duration=analysis.duration,
        total_packets=analysis.total_packets,
        total_bytes=analysis.total_bytes,
        errors=list(analysis.errors),
    )


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


_SIZE_BUCKETS: tuple[tuple[int, int, str], ...] = (
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
)
_BUCKET_UPPERS = [high for _low, high, _label in _SIZE_BUCKETS]


def _bucketize(values: list[int]) -> list[SizeBucket]:
    """Histogram of sizes into the fixed bucket ranges, in one pass
    (was one list comprehension per bucket over the whole sample)."""
    if not values:
        return []
    count = [0] * len(_SIZE_BUCKETS)
    total_in = [0] * len(_SIZE_BUCKETS)
    min_in = [0] * len(_SIZE_BUCKETS)
    max_in = [0] * len(_SIZE_BUCKETS)
    for val in values:
        idx = bisect.bisect_left(_BUCKET_UPPERS, val)
        if idx >= len(_SIZE_BUCKETS):
            continue  # above 65535: outside every bucket, as before
        if count[idx] == 0 or val < min_in[idx]:
            min_in[idx] = val
        if val > max_in[idx]:
            max_in[idx] = val
        count[idx] += 1
        total_in[idx] += val
    total = len(values)
    return [
        SizeBucket(
            label=label,
            count=count[i],
            avg=(total_in[i] / count[i]) if count[i] else 0.0,
            min=min_in[i],
            max=max_in[i],
            pct=(count[i] / total) * 100 if total else 0.0,
        )
        for i, (_low, _high, label) in enumerate(_SIZE_BUCKETS)
    ]


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


@dataclass(frozen=True)
class _Matched:
    """One packet the protocol claims: endpoints, ports, payload and role."""

    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes
    is_request: bool
    is_response: bool
    session_key: str


def _strip_padding(layer: object) -> bytes:
    """Bytes of a transport payload without scapy's trailing ``Padding``.

    Ethernet pads short frames to 60 bytes; scapy dissects the pad as a
    ``Padding`` layer *inside* the transport payload, so ``bytes(tcp.payload)``
    of a 12-byte Modbus request comes back as 12 protocol bytes plus zeros
    that the protocol parsers then read as data.
    """
    if not layer:
        return b""
    try:
        raw = bytes(layer)
    except Exception:
        return b""
    pad = layer.getlayer(Padding) if Padding is not None else None
    if pad is not None:
        try:
            raw = raw[: len(raw) - len(bytes(pad))]
        except Exception:
            pass
    return raw


def _extract_transport(pkt: object) -> tuple[bool, str, str, int, int, bytes]:
    """``(has_transport, src, dst, sport, dport, payload)`` for a TCP/UDP packet.

    Kept for the analyzers with their own packet loop (cip, enip,
    ot_commands). One layer walk per transport, padding stripped.
    """
    getlayer = getattr(pkt, "getlayer", None)
    transport = None
    if callable(getlayer):
        transport = getlayer(TCP) if TCP is not None else None
        if transport is None:
            transport = getlayer(UDP) if UDP is not None else None
    if transport is None:
        return False, "?", "?", 0, 0, b""
    sport = int(getattr(transport, "sport", 0) or 0)
    dport = int(getattr(transport, "dport", 0) or 0)
    payload = _strip_padding(transport.payload)
    src, dst = extract_packet_endpoints(pkt)
    if not src or not dst:
        first = pkt[0]  # type: ignore[index]
        src = getattr(first, "src", None) or "?"
        dst = getattr(first, "dst", None) or "?"
    return True, src, dst, sport, dport, payload


def _match_ports(
    pkt: object,
    tcp_ports: set[int],
    udp_ports: set[int],
    signature_matcher: SignatureMatcher | None,
) -> _Matched | None:
    """Port/signature classification for TCP- and UDP-carried protocols."""
    getlayer = pkt.getlayer  # type: ignore[attr-defined]
    transport = getlayer(TCP) if TCP is not None else None
    if transport is None:
        transport = getlayer(UDP) if UDP is not None else None
        if transport is None:
            return None
    sport = int(getattr(transport, "sport", 0) or 0)
    dport = int(getattr(transport, "dport", 0) or 0)
    payload = _strip_padding(transport.payload)

    # Classify by port only when the OT port is the *server* side: the
    # destination (client -> server) or the source with an ephemeral
    # destination (server -> client response). A bare "sport or dport in
    # ports" test misclassifies any flow whose ephemeral source port happens
    # to equal an OT port number — e.g. a TCP DNS query to 8.8.8.8:53 whose
    # ephemeral source port is 44818 would otherwise be reported as
    # EtherNet/IP/CSP/PCCC traffic to a public IP. Signature matches are
    # always honored.
    matches_port = (
        dport in tcp_ports
        or dport in udp_ports
        or ((sport in tcp_ports or sport in udp_ports) and dport >= _PORT_SERVER_EPHEMERAL_MIN)
    )
    matches_sig = bool(signature_matcher and payload and signature_matcher(payload))
    if not matches_port and not matches_sig:
        return None

    src, dst = extract_packet_endpoints(pkt)
    if not src or not dst:
        first = pkt[0]  # type: ignore[index]
        src = getattr(first, "src", None) or "?"
        dst = getattr(first, "dst", None) or "?"
    return _Matched(
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        payload=payload,
        is_request=(dport in tcp_ports) or (dport in udp_ports),
        is_response=(sport in tcp_ports) or (sport in udp_ports),
        session_key=f"{src}:{sport} -> {dst}:{dport}",
    )


def _match_ethertype(pkt: object, ethertype: int) -> _Matched | None:
    """EtherType classification for L2 protocols (GOOSE, SV, PROFINET RT, …).
    Endpoints are MAC addresses; every frame counts as a request."""
    if extract_ethertype(pkt) != ethertype:
        return None
    first = pkt[0]  # type: ignore[index]
    src = getattr(first, "src", None) or "?"
    dst = getattr(first, "dst", None) or "?"
    ether = pkt.getlayer(Ether) if Ether is not None else None  # type: ignore[attr-defined]
    payload = _strip_padding(ether.payload) if ether is not None else b""
    return _Matched(
        src=src, dst=dst, sport=0, dport=0, payload=payload,
        is_request=True, is_response=False, session_key=f"{src} -> {dst}",
    )


_ANOMALY_CAP = 200
_ARTIFACT_CAP = 200
_COMMAND_EVENT_CAP = 5000


def _industrial_pass(
    path: Path,
    protocol_name: str,
    *,
    classify: Callable[[object], "_Matched | None"],
    command_parser: CommandParser | None,
    artifact_parser: ArtifactParser | None,
    anomaly_detector: AnomalyDetector | None,
    enable_enrichment: bool,
    show_status: bool,
    scanning_check: bool,
) -> IndustrialAnalysis:
    """The single packet pass behind every port- and EtherType-based OT analyzer.

    ``classify`` decides whether a packet belongs to the protocol and returns
    its endpoints/payload/role; everything after that — counters, command and
    artifact extraction, per-packet anomaly detection with de-duplication,
    size buckets, cadence (beaconing) and exfiltration checks — is shared.
    Was two ~250-line copies that had already drifted apart.

    A packet that raises inside a protocol parser is counted and skipped;
    the pass no longer aborts at the first malformed packet and reports the
    number skipped, so a partial result is visible as partial.
    """
    analysis = IndustrialAnalysis(path=path)
    # Collapse identical per-packet detector findings (same title/src/dst/detail)
    # to one — OT detectors that emit an anomaly per packet otherwise flood the
    # cap with thousands of identical entries (e.g. one "Control Object
    # Operation" per DNP3 packet) and bury the distinct findings.
    seen_anomalies: set[tuple[str, str, str, str]] = set()
    seen_artifacts: set[str] = set()
    start_time = None
    last_time = None
    payload_sizes: list[int] = []
    packet_sizes: list[int] = []
    session_last_ts: dict[str, float] = {}
    session_intervals: dict[str, list[float]] = defaultdict(list)
    session_endpoints: dict[str, tuple[str, str]] = {}
    src_requests: Counter[str] = Counter()
    src_responses: Counter[str] = Counter()
    src_dst_bytes: dict[str, Counter[str]] = defaultdict(Counter)
    detector = anomaly_detector or _default_anomalies
    skipped = 0
    first_error: str | None = None

    for pkt in iter_packets(path, show_status=show_status):
        analysis.total_packets += 1
        pkt_len = packet_length(pkt)
        analysis.total_bytes += pkt_len
        ts = safe_float(getattr(pkt, "time", 0))
        if start_time is None:
            start_time = ts
        last_time = ts

        try:
            match = classify(pkt)
            if match is None:
                continue

            analysis.protocol_packets += 1
            analysis.protocol_bytes += pkt_len
            analysis.src_ips[match.src] += 1
            analysis.dst_ips[match.dst] += 1
            analysis.sessions[match.session_key] += 1
            if match.sport:
                analysis.ports[match.sport] += 1
            if match.dport:
                analysis.ports[match.dport] += 1
            payload = match.payload

            if enable_enrichment:
                payload_sizes.append(len(payload))
                packet_sizes.append(pkt_len)
                key = match.session_key
                session_endpoints.setdefault(key, (match.src, match.dst))
                if key in session_last_ts and ts is not None:
                    interval = ts - session_last_ts[key]
                    if interval >= 0:
                        session_intervals[key].append(interval)
                if ts is not None:
                    session_last_ts[key] = ts
                if match.is_request and not match.is_response:
                    analysis.requests += 1
                    analysis.client_ips[match.src] += 1
                    analysis.server_ips[match.dst] += 1
                    src_requests[match.src] += 1
                elif match.is_response and not match.is_request:
                    analysis.responses += 1
                    analysis.client_ips[match.dst] += 1
                    analysis.server_ips[match.src] += 1
                    src_responses[match.src] += 1
                if payload:
                    src_dst_bytes[match.src][match.dst] += len(payload)

            commands = list(command_parser(payload)) if command_parser else []
            if commands:
                analysis.commands.update(commands)
                # Attribute command endpoints to the request (client -> server)
                # direction only, so a service isn't listed as both "A -> B" and
                # "B -> A" for one request/response exchange.
                if enable_enrichment and (match.is_request or not match.is_response):
                    for cmd in commands:
                        endpoints = analysis.service_endpoints.setdefault(str(cmd), Counter())
                        endpoints[f"{match.src} -> {match.dst}"] += 1
                if ts is not None and len(analysis.command_events) < _COMMAND_EVENT_CAP:
                    for cmd in commands:
                        analysis.command_events.append(
                            IndustrialCommandEvent(ts=ts, src=match.src, dst=match.dst, command=str(cmd))
                        )

            artifacts = _default_artifacts(payload) if artifact_parser is None else list(artifact_parser(payload))
            for kind, detail in artifacts:
                key = f"{kind}:{detail}"
                if key in seen_artifacts:
                    continue
                seen_artifacts.add(key)
                if len(analysis.artifacts) < _ARTIFACT_CAP:
                    analysis.artifacts.append(
                        IndustrialArtifact(kind=kind, detail=detail, src=match.src, dst=match.dst, ts=ts)
                    )

            for anomaly in detector(payload, match.src, match.dst, ts, commands):
                akey = (
                    str(getattr(anomaly, "title", "")),
                    str(getattr(anomaly, "src", "")),
                    str(getattr(anomaly, "dst", "")),
                    str(getattr(anomaly, "description", "")),
                )
                if akey in seen_anomalies:
                    continue
                seen_anomalies.add(akey)
                if len(analysis.anomalies) < _ANOMALY_CAP:
                    analysis.anomalies.append(anomaly)
        except Exception as exc:  # noqa: BLE001 — one bad packet must not end the pass
            skipped += 1
            if first_error is None:
                first_error = f"{type(exc).__name__}: {exc}"

    if skipped:
        analysis.errors.append(
            f"{skipped} packet(s) skipped by the {protocol_name} parser "
            f"(first error: {first_error}); counts are lower bounds."
        )
    if start_time is not None and last_time is not None:
        analysis.duration = last_time - start_time

    if enable_enrichment:
        analysis.packet_size_buckets = _bucketize(packet_sizes)
        analysis.payload_size_buckets = _bucketize(payload_sizes)

        if scanning_check:
            for src, dsts in src_dst_bytes.items():
                unique_dsts = len(dsts)
                req_count = src_requests.get(src, 0)
                resp_count = src_responses.get(src, 0)
                if unique_dsts >= 20 and req_count > resp_count * 2 and len(analysis.anomalies) < _ANOMALY_CAP:
                    sample_dsts = ", ".join(
                        str(d) for d, _b in sorted(dsts.items(), key=lambda kv: kv[1], reverse=True)[:6]
                    )
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="MEDIUM",
                            title=f"{protocol_name} Scanning/Probing",
                            description=f"Source contacted {unique_dsts} endpoints with low response rate.",
                            src=src, dst="*", ts=0.0,
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
                # Endpoints come from the session record, not from re-parsing
                # the "src:port -> dst:port" key, which cut IPv6 addresses at
                # their first colon.
                src_ip, dst_ip = session_endpoints.get(session_key, ("?", "?"))
                # Low-jitter regular intervals are normal SCADA polling; only an
                # EXTERNAL destination makes periodic OT traffic a beacon/C2 lead.
                if not _is_public_ip(dst_ip):
                    continue
                if len(analysis.anomalies) < _ANOMALY_CAP:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="LOW",
                            title=f"Possible {protocol_name} Beaconing",
                            description=f"Regular interval traffic (~{avg:.2f}s) observed.",
                            src=src_ip, dst=dst_ip, ts=0.0,
                            attack="T0869 Standard Application Layer Protocol",
                            evidence=[
                                f"mean interval ~{avg:.2f}s (CV={cv:.2f}, n={len(intervals)})",
                                f"external destination {dst_ip}",
                            ],
                        )
                    )

        for src, dsts in src_dst_bytes.items():
            for dst, byte_count in dsts.items():
                if byte_count >= 5_000_000 and _is_public_ip(dst) and len(analysis.anomalies) < _ANOMALY_CAP:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="MEDIUM",
                            title=f"Possible {protocol_name} Data Exfiltration",
                            description=f"{byte_count} bytes sent to public IP.",
                            src=src, dst=dst, ts=0.0,
                            attack="T0883 Internet Accessible Device",
                            evidence=[f"{byte_count:,} bytes to public IP {dst}"],
                        )
                    )

    return analysis


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
    """Analyse a TCP/UDP-carried OT protocol. Returns a fresh object every
    call (not memoized) so callers may post-process it in place."""
    if TCP is None and UDP is None:
        return IndustrialAnalysis(path=path, errors=["Scapy unavailable (TCP/UDP missing)"])
    tcp_set = set(tcp_ports or ())
    udp_set = set(udp_ports or ())
    return _industrial_pass(
        path,
        protocol_name,
        classify=lambda pkt: _match_ports(pkt, tcp_set, udp_set, signature_matcher),
        command_parser=command_parser,
        artifact_parser=artifact_parser,
        anomaly_detector=anomaly_detector,
        enable_enrichment=enable_enrichment,
        show_status=show_status,
        scanning_check=True,
    )


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
    """Analyse an EtherType-carried (L2) OT protocol. Returns a fresh object
    every call (not memoized) so callers may post-process it in place."""
    if Ether is None:
        return IndustrialAnalysis(path=path, errors=["Scapy unavailable (Ether missing)"])
    return _industrial_pass(
        path,
        protocol_name,
        classify=lambda pkt: _match_ethertype(pkt, ethertype),
        command_parser=command_parser,
        artifact_parser=artifact_parser,
        anomaly_detector=anomaly_detector,
        enable_enrichment=enable_enrichment,
        show_status=show_status,
        scanning_check=False,
    )
