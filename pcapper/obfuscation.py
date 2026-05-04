from __future__ import annotations

import base64
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .pcap_cache import get_reader
from .utils import safe_float, extract_packet_endpoints

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


MAX_HITS = 200
MAX_ARTIFACTS = 300
MAX_SESSIONS = 200
MIN_PAYLOAD = 64
SCAN_BYTES = 2048
DECODE_BYTES_MAX = 8192
ENTROPY_HIGH = 7.2
PRINTABLE_MIN_RATIO = 0.4

ENCRYPTED_PORTS = {
    22,
    443,
    465,
    853,
    993,
    995,
    1194,
    1701,
    1723,
    3389,
    8443,
    8883,
    9443,
}

DNS_PORTS = {53}
WEB_TUNNEL_PORTS = {80, 8080, 8000, 8888}

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
HEX_RE = re.compile(r"[0-9A-Fa-f]{80,}")

URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]{6,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"
)
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]+\.[a-z]{2,63}\b")
HASH_RE = re.compile(r"\b[A-Fa-f0-9]{32,64}\b")

ATTACK_MARKERS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"(?i)powershell(?:\.exe)?\s+-e(?:n(?:c(?:odedcommand)?)?)?\b|frombase64string"
        ),
        "T1059.001",
        "PowerShell Encoded Command",
    ),
    (
        re.compile(r"(?i)\bcmd(?:\.exe)?\b|/bin/(?:sh|bash)\b"),
        "T1059",
        "Command Shell Invocation",
    ),
    (
        re.compile(
            r"(?i)invoke-webrequest|downloadstring|new-object\s+net\.webclient|curl\s+https?://|wget\s+https?://"
        ),
        "T1105",
        "Ingress Tool Transfer",
    ),
    (
        re.compile(r"(?i)\b(certutil|bitsadmin|mshta|rundll32|regsvr32|wmic)\b"),
        "T1218",
        "Signed Binary Proxy Execution",
    ),
    (
        re.compile(r"(?i)\bmimikatz|sekurlsa|lsass\b"),
        "T1003",
        "Credential Dumping Indicators",
    ),
    (
        re.compile(r"(?i)\bstratum\+tcp://|xmrig|minerd\b"),
        "T1496",
        "Resource Hijacking / Mining",
    ),
]

INTERNAL_DOMAIN_SUFFIXES = (
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".corp",
    ".intranet",
)


@dataclass(frozen=True)
class ObfuscationHit:
    kind: str
    proto: str
    flow_id: str
    src: str
    dst: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    entropy: float
    printable_ratio: float
    sample: str
    ts: Optional[float]
    packet_index: int
    reasoning: str


@dataclass(frozen=True)
class ObfuscationSessionStat:
    flow_id: str
    proto: str
    src: str
    dst: str
    src_port: Optional[int]
    dst_port: Optional[int]
    packets: int
    payload_bytes: int
    suspicious_packets: int
    suspicious_payload_bytes: int
    high_entropy_hits: int
    base64_hits: int
    hex_hits: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    avg_entropy: float
    max_entropy: float


@dataclass(frozen=True)
class ObfuscationArtifact:
    kind: str
    value: str
    source_kind: str
    src: str
    dst: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str
    flow_id: str
    ts: Optional[float]
    confidence: str
    reasoning: str


@dataclass(frozen=True)
class ObfuscationSummary:
    path: Path
    total_packets: int
    total_payload_bytes: int
    suspicious_packets: int
    suspicious_payload_bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    total_sessions: int
    suspicious_sessions: int
    high_entropy_hits: list[ObfuscationHit]
    base64_hits: list[ObfuscationHit]
    hex_hits: list[ObfuscationHit]
    source_counts: Counter[str]
    destination_counts: Counter[str]
    protocol_counts: Counter[str]
    port_counts: Counter[str]
    hit_kind_counts: Counter[str]
    ioc_counts: Counter[str]
    attack_counts: Counter[str]
    session_stats: list[ObfuscationSessionStat]
    artifacts: list[ObfuscationArtifact]
    detections: list[dict[str, object]]
    errors: list[str]


def _empty_summary(path: Path) -> ObfuscationSummary:
    return ObfuscationSummary(
        path=path,
        total_packets=0,
        total_payload_bytes=0,
        suspicious_packets=0,
        suspicious_payload_bytes=0,
        first_seen=None,
        last_seen=None,
        duration_seconds=None,
        total_sessions=0,
        suspicious_sessions=0,
        high_entropy_hits=[],
        base64_hits=[],
        hex_hits=[],
        source_counts=Counter(),
        destination_counts=Counter(),
        protocol_counts=Counter(),
        port_counts=Counter(),
        hit_kind_counts=Counter(),
        ioc_counts=Counter(),
        attack_counts=Counter(),
        session_stats=[],
        artifacts=[],
        detections=[],
        errors=[],
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy_val = 0.0
    for count in counts.values():
        p = count / length
        entropy_val -= p * math.log2(p)
    return entropy_val


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = 0
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            printable += 1
    return printable / len(data)


def _is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            item = int(part)
        except Exception:
            return False
        if item < 0 or item > 255:
            return False
    return True


def _service_port(src_port: Optional[int], dst_port: Optional[int]) -> Optional[int]:
    for port in (dst_port, src_port):
        if isinstance(port, int) and 0 < port <= 1024:
            return port
    return dst_port or src_port


def _flow_id(
    proto: str, src: str, src_port: Optional[int], dst: str, dst_port: Optional[int]
) -> str:
    src_label = f"{src}:{src_port}" if src_port else src
    dst_label = f"{dst}:{dst_port}" if dst_port else dst
    return f"{proto} {src_label} -> {dst_label}"


def _session_state(
    flow_state: dict[str, dict[str, object]],
    flow: str,
    *,
    proto: str,
    src: str,
    dst: str,
    src_port: Optional[int],
    dst_port: Optional[int],
) -> dict[str, object]:
    current = flow_state.get(flow)
    if current is not None:
        return current
    current = {
        "flow_id": flow,
        "proto": proto,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "packets": 0,
        "payload_bytes": 0,
        "suspicious_packets": 0,
        "suspicious_payload_bytes": 0,
        "high_entropy_hits": 0,
        "base64_hits": 0,
        "hex_hits": 0,
        "first_seen": None,
        "last_seen": None,
        "entropy_sum": 0.0,
        "entropy_count": 0,
        "max_entropy": 0.0,
    }
    flow_state[flow] = current
    return current


def _safe_base64_decode(token: str) -> bytes | None:
    stripped = token.strip()
    if not stripped:
        return None
    if len(stripped) > DECODE_BYTES_MAX * 2:
        stripped = stripped[: DECODE_BYTES_MAX * 2]
    padding = (-len(stripped)) % 4
    if padding:
        stripped += "=" * padding
    try:
        return base64.b64decode(stripped, validate=False)
    except Exception:
        return None


def _safe_hex_decode(token: str) -> bytes | None:
    stripped = token.strip()
    if not stripped:
        return None
    if len(stripped) > DECODE_BYTES_MAX * 2:
        stripped = stripped[: DECODE_BYTES_MAX * 2]
    if len(stripped) % 2:
        stripped = stripped[:-1]
    if len(stripped) < 2:
        return None
    try:
        return bytes.fromhex(stripped)
    except Exception:
        return None


def _decoded_preview(data: bytes, limit: int = 80) -> str:
    if not data:
        return "-"
    text = data.decode("utf-8", errors="ignore").strip()
    if text:
        return text[:limit]
    return data[: min(32, len(data))].hex()


def _extract_iocs_from_text(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {
        "url": set(),
        "domain": set(),
        "ipv4": set(),
        "email": set(),
        "hash": set(),
    }
    if not text:
        return out

    for match in URL_RE.findall(text):
        value = match.strip().rstrip("),.;\"'")
        if not value:
            continue
        out["url"].add(value[:240])
        try:
            parsed = urlparse(value)
            host = (parsed.hostname or "").lower().strip(".")
            if host and "." in host and not host.endswith(INTERNAL_DOMAIN_SUFFIXES):
                out["domain"].add(host)
        except Exception:
            pass

    for token in IPV4_RE.findall(text):
        if _is_valid_ipv4(token):
            out["ipv4"].add(token)

    for token in DOMAIN_RE.findall(text):
        host = token.lower().strip(".")
        if not host or host.endswith(INTERNAL_DOMAIN_SUFFIXES):
            continue
        if _is_valid_ipv4(host):
            continue
        out["domain"].add(host)

    for token in EMAIL_RE.findall(text):
        out["email"].add(token.lower())

    for token in HASH_RE.findall(text):
        if len(token) in {32, 40, 64}:
            out["hash"].add(token.lower())

    return out


def _record_artifact(
    artifacts: list[ObfuscationArtifact],
    seen: set[tuple[str, str, str, str, str, str, str]],
    ioc_counts: Counter[str],
    attack_counts: Counter[str],
    *,
    kind: str,
    value: str,
    source_kind: str,
    src: str,
    dst: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    proto: str,
    flow_id: str,
    ts: Optional[float],
    confidence: str,
    reasoning: str,
) -> None:
    cleaned = (value or "").strip()
    if not cleaned:
        return
    key = (kind, cleaned.lower(), source_kind, src, dst, proto, flow_id)
    if key in seen:
        return
    seen.add(key)

    if kind.startswith("ioc_"):
        ioc_counts[f"{kind[4:]}:{cleaned}"] += 1
    elif kind == "attack":
        attack_counts[cleaned] += 1

    if len(artifacts) >= MAX_ARTIFACTS:
        return
    artifacts.append(
        ObfuscationArtifact(
            kind=kind,
            value=cleaned,
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence=confidence,
            reasoning=reasoning,
        )
    )


def _extract_decoded_artifacts(
    decoded: bytes,
    *,
    source_kind: str,
    src: str,
    dst: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    proto: str,
    flow_id: str,
    ts: Optional[float],
    artifacts: list[ObfuscationArtifact],
    artifact_seen: set[tuple[str, str, str, str, str, str, str]],
    ioc_counts: Counter[str],
    attack_counts: Counter[str],
) -> None:
    if not decoded:
        return
    text = decoded.decode("utf-8", errors="ignore")
    preview = _decoded_preview(decoded)
    iocs = _extract_iocs_from_text(text)
    for url_value in sorted(iocs["url"]):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="ioc_url",
            value=url_value,
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="high",
            reasoning=f"Decoded {source_kind} blob exposed URL indicator ({preview}).",
        )
    for domain_value in sorted(iocs["domain"]):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="ioc_domain",
            value=domain_value,
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="high",
            reasoning=f"Decoded {source_kind} blob exposed domain indicator ({preview}).",
        )
    for ip_value in sorted(iocs["ipv4"]):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="ioc_ipv4",
            value=ip_value,
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="high",
            reasoning=f"Decoded {source_kind} blob exposed IPv4 indicator ({preview}).",
        )
    for email_value in sorted(iocs["email"]):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="ioc_email",
            value=email_value,
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="medium",
            reasoning=f"Decoded {source_kind} blob exposed email indicator ({preview}).",
        )
    for hash_value in sorted(iocs["hash"]):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="ioc_hash",
            value=hash_value,
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="medium",
            reasoning=f"Decoded {source_kind} blob exposed hash-like indicator ({preview}).",
        )

    lowered = text.lower()
    for pattern, technique_id, label in ATTACK_MARKERS:
        if pattern.search(lowered):
            _record_artifact(
                artifacts,
                artifact_seen,
                ioc_counts,
                attack_counts,
                kind="attack",
                value=f"{technique_id} {label}",
                source_kind=source_kind,
                src=src,
                dst=dst,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                flow_id=flow_id,
                ts=ts,
                confidence="medium",
                reasoning=f"Decoded {source_kind} blob matched ATT&CK-aligned marker ({preview}).",
            )

    if decoded.startswith(b"MZ"):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="signature",
            value="PE/MZ header in decoded content",
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="high",
            reasoning=f"Decoded {source_kind} blob starts with MZ executable signature.",
        )
    elif decoded.startswith(b"\x1f\x8b"):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="signature",
            value="GZip-compressed blob in decoded content",
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="medium",
            reasoning=f"Decoded {source_kind} blob starts with gzip magic bytes.",
        )
    elif decoded.startswith(b"PK\x03\x04"):
        _record_artifact(
            artifacts,
            artifact_seen,
            ioc_counts,
            attack_counts,
            kind="signature",
            value="ZIP archive signature in decoded content",
            source_kind=source_kind,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            flow_id=flow_id,
            ts=ts,
            confidence="medium",
            reasoning=f"Decoded {source_kind} blob starts with ZIP magic bytes.",
        )


def _port_attack_signal(
    src_port: Optional[int], dst_port: Optional[int]
) -> tuple[str, str] | None:
    ports = {
        int(port) for port in (src_port, dst_port) if isinstance(port, int) and port > 0
    }
    if ports & DNS_PORTS:
        return "T1071.004", "DNS Application Layer Protocol"
    if ports & WEB_TUNNEL_PORTS:
        return "T1071.001", "Web Application Layer Protocol"
    return None


def merge_obfuscation_summaries(
    summaries: list[ObfuscationSummary],
) -> ObfuscationSummary:
    if not summaries:
        return _empty_summary(Path("ALL_PCAPS"))

    total_packets = 0
    total_payload_bytes = 0
    suspicious_packets = 0
    suspicious_payload_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    high_entropy_hits: list[ObfuscationHit] = []
    base64_hits: list[ObfuscationHit] = []
    hex_hits: list[ObfuscationHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    hit_kind_counts: Counter[str] = Counter()
    ioc_counts: Counter[str] = Counter()
    attack_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []

    total_sessions = 0
    suspicious_sessions = 0
    session_stats: list[ObfuscationSessionStat] = []
    artifacts: list[ObfuscationArtifact] = []

    def _scoped_flow_id(path: Path, flow_id: str) -> str:
        label = path.name or str(path)
        return f"{label}::{flow_id}"

    def _scope_hit(path: Path, hit: ObfuscationHit) -> ObfuscationHit:
        return ObfuscationHit(
            kind=hit.kind,
            proto=hit.proto,
            flow_id=_scoped_flow_id(path, hit.flow_id),
            src=hit.src,
            dst=hit.dst,
            src_port=hit.src_port,
            dst_port=hit.dst_port,
            length=hit.length,
            entropy=hit.entropy,
            printable_ratio=hit.printable_ratio,
            sample=hit.sample,
            ts=hit.ts,
            packet_index=hit.packet_index,
            reasoning=hit.reasoning,
        )

    def _scope_session(path: Path, session: ObfuscationSessionStat) -> ObfuscationSessionStat:
        return ObfuscationSessionStat(
            flow_id=_scoped_flow_id(path, session.flow_id),
            proto=session.proto,
            src=session.src,
            dst=session.dst,
            src_port=session.src_port,
            dst_port=session.dst_port,
            packets=session.packets,
            payload_bytes=session.payload_bytes,
            suspicious_packets=session.suspicious_packets,
            suspicious_payload_bytes=session.suspicious_payload_bytes,
            high_entropy_hits=session.high_entropy_hits,
            base64_hits=session.base64_hits,
            hex_hits=session.hex_hits,
            first_seen=session.first_seen,
            last_seen=session.last_seen,
            duration_seconds=session.duration_seconds,
            avg_entropy=session.avg_entropy,
            max_entropy=session.max_entropy,
        )

    def _scope_artifact(path: Path, artifact: ObfuscationArtifact) -> ObfuscationArtifact:
        return ObfuscationArtifact(
            kind=artifact.kind,
            value=artifact.value,
            source_kind=artifact.source_kind,
            src=artifact.src,
            dst=artifact.dst,
            src_port=artifact.src_port,
            dst_port=artifact.dst_port,
            proto=artifact.proto,
            flow_id=_scoped_flow_id(path, artifact.flow_id),
            ts=artifact.ts,
            confidence=artifact.confidence,
            reasoning=artifact.reasoning,
        )

    for summary in summaries:
        total_packets += summary.total_packets
        total_payload_bytes += summary.total_payload_bytes
        suspicious_packets += summary.suspicious_packets
        suspicious_payload_bytes += summary.suspicious_payload_bytes
        if summary.first_seen is not None:
            first_seen = (
                summary.first_seen
                if first_seen is None
                else min(first_seen, summary.first_seen)
            )
        if summary.last_seen is not None:
            last_seen = (
                summary.last_seen
                if last_seen is None
                else max(last_seen, summary.last_seen)
            )

        high_entropy_hits.extend(_scope_hit(summary.path, hit) for hit in summary.high_entropy_hits)
        base64_hits.extend(_scope_hit(summary.path, hit) for hit in summary.base64_hits)
        hex_hits.extend(_scope_hit(summary.path, hit) for hit in summary.hex_hits)
        source_counts.update(summary.source_counts)
        destination_counts.update(summary.destination_counts)
        protocol_counts.update(summary.protocol_counts)
        port_counts.update(summary.port_counts)
        hit_kind_counts.update(summary.hit_kind_counts)
        ioc_counts.update(summary.ioc_counts)
        attack_counts.update(summary.attack_counts)
        detections.extend(summary.detections)
        errors.extend(summary.errors)
        total_sessions += summary.total_sessions
        suspicious_sessions += summary.suspicious_sessions
        session_stats.extend(_scope_session(summary.path, item) for item in summary.session_stats)
        artifacts.extend(_scope_artifact(summary.path, item) for item in summary.artifacts)

    session_stats = sorted(
        session_stats,
        key=lambda item: (
            item.suspicious_packets,
            item.suspicious_payload_bytes,
            item.max_entropy,
        ),
        reverse=True,
    )
    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return ObfuscationSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        total_payload_bytes=total_payload_bytes,
        suspicious_packets=suspicious_packets,
        suspicious_payload_bytes=suspicious_payload_bytes,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        total_sessions=total_sessions,
        suspicious_sessions=suspicious_sessions,
        high_entropy_hits=high_entropy_hits,
        base64_hits=base64_hits,
        hex_hits=hex_hits,
        source_counts=source_counts,
        destination_counts=destination_counts,
        protocol_counts=protocol_counts,
        port_counts=port_counts,
        hit_kind_counts=hit_kind_counts,
        ioc_counts=ioc_counts,
        attack_counts=attack_counts,
        session_stats=session_stats,
        artifacts=artifacts,
        detections=detections,
        errors=sorted({err for err in errors if err}),
    )


def analyze_obfuscation(path: Path, show_status: bool = True) -> ObfuscationSummary:
    if TCP is None and UDP is None:
        summary = _empty_summary(path)
        return ObfuscationSummary(
            **{**summary.__dict__, "errors": ["Scapy TCP/UDP unavailable"]},
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )
    total_packets = 0
    total_payload_bytes = 0
    suspicious_packets = 0
    suspicious_payload_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    high_entropy_hits: list[ObfuscationHit] = []
    base64_hits: list[ObfuscationHit] = []
    hex_hits: list[ObfuscationHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    hit_kind_counts: Counter[str] = Counter()
    ioc_counts: Counter[str] = Counter()
    attack_counts: Counter[str] = Counter()
    errors: list[str] = []

    flow_state: dict[str, dict[str, object]] = {}
    artifacts: list[ObfuscationArtifact] = []
    artifact_seen: set[tuple[str, str, str, str, str, str, str]] = set()

    pkt_index = 0
    try:
        for pkt in reader:
            pkt_index += 1
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            proto = "IP"
            src_port = None
            dst_port = None
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                proto = "TCP"
                src_port = int(getattr(pkt[TCP], "sport", 0) or 0)  # type: ignore[index]
                dst_port = int(getattr(pkt[TCP], "dport", 0) or 0)  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                proto = "UDP"
                src_port = int(getattr(pkt[UDP], "sport", 0) or 0)  # type: ignore[index]
                dst_port = int(getattr(pkt[UDP], "dport", 0) or 0)  # type: ignore[index]

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw].load)  # type: ignore[index]
                except Exception:
                    payload = b""
            if not payload or len(payload) < MIN_PAYLOAD:
                continue

            sample = payload[:SCAN_BYTES]
            total_payload_bytes += len(payload)
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                first_seen = ts if first_seen is None else min(first_seen, ts)
                last_seen = ts if last_seen is None else max(last_seen, ts)

            entropy_val = _entropy(sample)
            printable_val = _printable_ratio(sample)
            flow = _flow_id(proto, src_ip, src_port, dst_ip, dst_port)
            state = _session_state(
                flow_state,
                flow,
                proto=proto,
                src=src_ip,
                dst=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
            )
            state["packets"] = int(state["packets"]) + 1
            state["payload_bytes"] = int(state["payload_bytes"]) + len(payload)
            state["entropy_sum"] = float(state["entropy_sum"]) + entropy_val
            state["entropy_count"] = int(state["entropy_count"]) + 1
            state["max_entropy"] = max(float(state["max_entropy"]), entropy_val)
            if ts is not None:
                current_first = state["first_seen"]
                if current_first is None or ts < current_first:
                    state["first_seen"] = ts
                current_last = state["last_seen"]
                if current_last is None or ts > current_last:
                    state["last_seen"] = ts

            text = sample.decode("latin-1", errors="ignore")
            packet_suspicious = False

            high_entropy_match = (
                entropy_val >= ENTROPY_HIGH
                and printable_val <= PRINTABLE_MIN_RATIO
                and (src_port not in ENCRYPTED_PORTS)
                and (dst_port not in ENCRYPTED_PORTS)
            )
            if high_entropy_match:
                packet_suspicious = True
                state["high_entropy_hits"] = int(state["high_entropy_hits"]) + 1
                hit_kind_counts["high_entropy"] += 1
                ports_text = f"{src_port or '-'}->{dst_port or '-'}"
                reasoning = (
                    f"Entropy {entropy_val:.2f} >= {ENTROPY_HIGH:.2f}, printable ratio "
                    f"{printable_val:.2f} <= {PRINTABLE_MIN_RATIO:.2f}, non-encrypted ports {ports_text}."
                )
                if len(high_entropy_hits) < MAX_HITS:
                    high_entropy_hits.append(
                        ObfuscationHit(
                            kind="high_entropy",
                            proto=proto,
                            flow_id=flow,
                            src=src_ip,
                            dst=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            length=len(payload),
                            entropy=entropy_val,
                            printable_ratio=printable_val,
                            sample=sample[:64].hex(),
                            ts=ts,
                            packet_index=pkt_index,
                            reasoning=reasoning,
                        )
                    )
                attack_signal = _port_attack_signal(src_port, dst_port)
                if attack_signal:
                    technique_id, technique_name = attack_signal
                    _record_artifact(
                        artifacts,
                        artifact_seen,
                        ioc_counts,
                        attack_counts,
                        kind="attack",
                        value=f"{technique_id} {technique_name}",
                        source_kind="high_entropy",
                        src=src_ip,
                        dst=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto,
                        flow_id=flow,
                        ts=ts,
                        confidence="medium",
                        reasoning="High entropy traffic on protocol port commonly abused for C2/tunneling.",
                    )

            for match in BASE64_RE.finditer(text):
                token = match.group(0)
                if len(base64_hits) < MAX_HITS:
                    base64_hits.append(
                        ObfuscationHit(
                            kind="base64",
                            proto=proto,
                            flow_id=flow,
                            src=src_ip,
                            dst=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            length=len(token),
                            entropy=entropy_val,
                            printable_ratio=printable_val,
                            sample=token[:96],
                            ts=ts,
                            packet_index=pkt_index,
                            reasoning=(
                                f"Base64-like token length {len(token)} detected; decoded for IOC/artifact extraction."
                            ),
                        )
                    )
                packet_suspicious = True
                state["base64_hits"] = int(state["base64_hits"]) + 1
                hit_kind_counts["base64"] += 1
                decoded = _safe_base64_decode(token)
                if decoded:
                    _extract_decoded_artifacts(
                        decoded,
                        source_kind="base64",
                        src=src_ip,
                        dst=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto,
                        flow_id=flow,
                        ts=ts,
                        artifacts=artifacts,
                        artifact_seen=artifact_seen,
                        ioc_counts=ioc_counts,
                        attack_counts=attack_counts,
                    )
                break

            for match in HEX_RE.finditer(text):
                token = match.group(0)
                if len(hex_hits) < MAX_HITS:
                    hex_hits.append(
                        ObfuscationHit(
                            kind="hex",
                            proto=proto,
                            flow_id=flow,
                            src=src_ip,
                            dst=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            length=len(token),
                            entropy=entropy_val,
                            printable_ratio=printable_val,
                            sample=token[:96],
                            ts=ts,
                            packet_index=pkt_index,
                            reasoning=(
                                f"Hex-like token length {len(token)} detected; decoded for IOC/artifact extraction."
                            ),
                        )
                    )
                packet_suspicious = True
                state["hex_hits"] = int(state["hex_hits"]) + 1
                hit_kind_counts["hex"] += 1
                decoded = _safe_hex_decode(token)
                if decoded:
                    _extract_decoded_artifacts(
                        decoded,
                        source_kind="hex",
                        src=src_ip,
                        dst=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto,
                        flow_id=flow,
                        ts=ts,
                        artifacts=artifacts,
                        artifact_seen=artifact_seen,
                        ioc_counts=ioc_counts,
                        attack_counts=attack_counts,
                    )
                break

            if packet_suspicious:
                suspicious_packets += 1
                suspicious_payload_bytes += len(payload)
                state["suspicious_packets"] = int(state["suspicious_packets"]) + 1
                state["suspicious_payload_bytes"] = int(
                    state["suspicious_payload_bytes"]
                ) + len(payload)
                source_counts[src_ip] += 1
                destination_counts[dst_ip] += 1
                protocol_counts[proto] += 1
                port = _service_port(src_port, dst_port)
                if port:
                    port_counts[f"{proto}/{port}"] += 1

    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        reader.close()

    session_stats: list[ObfuscationSessionStat] = []
    for state in flow_state.values():
        packets = int(state["packets"])
        entropy_count = int(state["entropy_count"])
        avg_entropy = (
            (float(state["entropy_sum"]) / entropy_count) if entropy_count else 0.0
        )
        first_ts = state["first_seen"]
        last_ts = state["last_seen"]
        duration = None
        if first_ts is not None and last_ts is not None:
            duration = max(0.0, float(last_ts) - float(first_ts))
        session_stats.append(
            ObfuscationSessionStat(
                flow_id=str(state["flow_id"]),
                proto=str(state["proto"]),
                src=str(state["src"]),
                dst=str(state["dst"]),
                src_port=state["src_port"],  # type: ignore[arg-type]
                dst_port=state["dst_port"],  # type: ignore[arg-type]
                packets=packets,
                payload_bytes=int(state["payload_bytes"]),
                suspicious_packets=int(state["suspicious_packets"]),
                suspicious_payload_bytes=int(state["suspicious_payload_bytes"]),
                high_entropy_hits=int(state["high_entropy_hits"]),
                base64_hits=int(state["base64_hits"]),
                hex_hits=int(state["hex_hits"]),
                first_seen=first_ts,  # type: ignore[arg-type]
                last_seen=last_ts,  # type: ignore[arg-type]
                duration_seconds=duration,
                avg_entropy=avg_entropy,
                max_entropy=float(state["max_entropy"]),
            )
        )
    session_stats.sort(
        key=lambda item: (
            item.suspicious_packets,
            item.suspicious_payload_bytes,
            item.max_entropy,
        ),
        reverse=True,
    )
    session_stats = session_stats[:MAX_SESSIONS]
    suspicious_sessions = sum(
        1 for item in session_stats if item.suspicious_packets > 0
    )

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    session_lookup: dict[str, ObfuscationSessionStat] = {
        item.flow_id: item for item in session_stats
    }
    detections: list[dict[str, object]] = []

    def _hit_evidence(hits: list[ObfuscationHit], limit: int = 6) -> list[str]:
        evidence: list[str] = []
        for hit in hits[:limit]:
            session = session_lookup.get(hit.flow_id)
            session_bits = ""
            if session:
                ratio = 0.0
                if session.payload_bytes:
                    ratio = (
                        session.suspicious_payload_bytes / session.payload_bytes
                    ) * 100.0
                session_bits = (
                    f" session={session.suspicious_packets}/{session.packets}pkt "
                    f"susp_bytes={session.suspicious_payload_bytes}/{session.payload_bytes} ({ratio:.1f}%)"
                )
            evidence.append(
                f"pkt={hit.packet_index} {hit.flow_id} len={hit.length} entropy={hit.entropy:.2f} "
                f"print={hit.printable_ratio:.2f}{session_bits} sample={hit.sample}"
            )
        return evidence

    if high_entropy_hits:
        detections.append(
            {
                "severity": "medium",
                "summary": "High-entropy payloads on non-encrypted ports",
                "details": (
                    f"{len(high_entropy_hits)} hit(s) across {suspicious_sessions} suspicious session(s); "
                    f"{suspicious_payload_bytes} suspicious payload bytes."
                ),
                "source": "Obfuscation",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "top_ports": port_counts.most_common(5),
                "evidence": _hit_evidence(high_entropy_hits),
            }
        )
    if base64_hits:
        detections.append(
            {
                "severity": "low",
                "summary": "Base64-like blobs in payloads",
                "details": f"{len(base64_hits)} hit(s); decoded indicators were inspected for IOC/attack signals.",
                "source": "Obfuscation",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "top_ports": port_counts.most_common(5),
                "evidence": _hit_evidence(base64_hits),
            }
        )
    if hex_hits:
        detections.append(
            {
                "severity": "low",
                "summary": "Hex-like blobs in payloads",
                "details": f"{len(hex_hits)} hit(s); decoded indicators were inspected for IOC/attack signals.",
                "source": "Obfuscation",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "top_ports": port_counts.most_common(5),
                "evidence": _hit_evidence(hex_hits),
            }
        )

    if total_payload_bytes and suspicious_payload_bytes:
        suspicious_share = (suspicious_payload_bytes / total_payload_bytes) * 100.0
        if suspicious_share >= 30.0 or suspicious_sessions >= 3:
            detections.append(
                {
                    "severity": "warning" if suspicious_share < 50.0 else "high",
                    "summary": "Potential covert-channel or exfiltration pattern",
                    "details": (
                        f"Suspicious payload share {suspicious_share:.1f}% "
                        f"({suspicious_payload_bytes}/{total_payload_bytes} bytes) across "
                        f"{suspicious_sessions} session(s)."
                    ),
                    "source": "Obfuscation",
                    "top_sources": source_counts.most_common(5),
                    "top_destinations": destination_counts.most_common(5),
                    "top_ports": port_counts.most_common(5),
                }
            )

    if ioc_counts:
        ioc_evidence = [
            f"{name} ({count})" for name, count in ioc_counts.most_common(8)
        ]
        detections.append(
            {
                "severity": "high",
                "summary": "IOCs recovered from encoded payloads",
                "details": (
                    f"{sum(ioc_counts.values())} IOC artifact(s), {len(ioc_counts)} unique indicator(s)."
                ),
                "source": "Obfuscation",
                "evidence": ioc_evidence,
            }
        )
    if attack_counts:
        attack_evidence = [
            f"{name} ({count})" for name, count in attack_counts.most_common(8)
        ]
        detections.append(
            {
                "severity": "high",
                "summary": "Encoded payload content matches attack tradecraft patterns",
                "details": (
                    f"{sum(attack_counts.values())} attack signal(s), "
                    f"{len(attack_counts)} ATT&CK-aligned technique hint(s)."
                ),
                "source": "Obfuscation",
                "evidence": attack_evidence,
            }
        )

    return ObfuscationSummary(
        path=path,
        total_packets=total_packets,
        total_payload_bytes=total_payload_bytes,
        suspicious_packets=suspicious_packets,
        suspicious_payload_bytes=suspicious_payload_bytes,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        total_sessions=len(session_stats),
        suspicious_sessions=suspicious_sessions,
        high_entropy_hits=high_entropy_hits,
        base64_hits=base64_hits,
        hex_hits=hex_hits,
        source_counts=source_counts,
        destination_counts=destination_counts,
        protocol_counts=protocol_counts,
        port_counts=port_counts,
        hit_kind_counts=hit_kind_counts,
        ioc_counts=ioc_counts,
        attack_counts=attack_counts,
        session_stats=session_stats,
        artifacts=artifacts,
        detections=detections,
        errors=errors,
    )
