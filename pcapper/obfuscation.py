from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter, defaultdict
import math
import re

from .pcap_cache import get_reader
from .utils import safe_float

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
MIN_PAYLOAD = 64
SCAN_BYTES = 2048
ENTROPY_HIGH = 7.2
PRINTABLE_MIN_RATIO = 0.4

ENCRYPTED_PORTS = {
    22, 443, 465, 853, 993, 995, 1194, 1701, 1723, 3389,
    8443, 8883, 9443,
}

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
HEX_RE = re.compile(r"[0-9A-Fa-f]{80,}")


@dataclass(frozen=True)
class ObfuscationHit:
    kind: str
    src: str
    dst: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    entropy: float
    sample: str
    ts: Optional[float]


@dataclass(frozen=True)
class ObfuscationSummary:
    path: Path
    total_packets: int
    total_payload_bytes: int
    high_entropy_hits: list[ObfuscationHit]
    base64_hits: list[ObfuscationHit]
    hex_hits: list[ObfuscationHit]
    source_counts: Counter[str]
    destination_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]


def merge_obfuscation_summaries(summaries: list[ObfuscationSummary]) -> ObfuscationSummary:
    if not summaries:
        return ObfuscationSummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            total_payload_bytes=0,
            high_entropy_hits=[],
            base64_hits=[],
            hex_hits=[],
            source_counts=Counter(),
            destination_counts=Counter(),
            detections=[],
            errors=[],
        )
    total_packets = sum(item.total_packets for item in summaries)
    total_payload_bytes = sum(item.total_payload_bytes for item in summaries)
    high_entropy_hits: list[ObfuscationHit] = []
    base64_hits: list[ObfuscationHit] = []
    hex_hits: list[ObfuscationHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    for summary in summaries:
        high_entropy_hits.extend(summary.high_entropy_hits)
        base64_hits.extend(summary.base64_hits)
        hex_hits.extend(summary.hex_hits)
        source_counts.update(summary.source_counts)
        destination_counts.update(summary.destination_counts)
        detections.extend(summary.detections)
        errors.extend(summary.errors)
    return ObfuscationSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        total_payload_bytes=total_payload_bytes,
        high_entropy_hits=high_entropy_hits[:MAX_HITS],
        base64_hits=base64_hits[:MAX_HITS],
        hex_hits=hex_hits[:MAX_HITS],
        source_counts=source_counts,
        destination_counts=destination_counts,
        detections=detections,
        errors=sorted({err for err in errors if err}),
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = 0
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            printable += 1
    return printable / len(data)


def analyze_obfuscation(path: Path, show_status: bool = True) -> ObfuscationSummary:
    if TCP is None and UDP is None:
        return ObfuscationSummary(
            path=path,
            total_packets=0,
            total_payload_bytes=0,
            high_entropy_hits=[],
            base64_hits=[],
            hex_hits=[],
            source_counts=Counter(),
            destination_counts=Counter(),
            detections=[],
            errors=["Scapy TCP/UDP unavailable"],
        )

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    total_payload_bytes = 0
    high_entropy_hits: list[ObfuscationHit] = []
    base64_hits: list[ObfuscationHit] = []
    hex_hits: list[ObfuscationHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    errors: list[str] = []

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IP].src)  # type: ignore[index]
                dst_ip = str(pkt[IP].dst)  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IPv6].src)  # type: ignore[index]
                dst_ip = str(pkt[IPv6].dst)  # type: ignore[index]
            if not src_ip or not dst_ip:
                continue

            src_port = None
            dst_port = None
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                src_port = int(getattr(pkt[TCP], "sport", 0) or 0)  # type: ignore[index]
                dst_port = int(getattr(pkt[TCP], "dport", 0) or 0)  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                src_port = int(getattr(pkt[UDP], "sport", 0) or 0)  # type: ignore[index]
                dst_port = int(getattr(pkt[UDP], "dport", 0) or 0)  # type: ignore[index]

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw].load)  # type: ignore[index]
                except Exception:
                    payload = b""
            if not payload:
                continue

            if len(payload) < MIN_PAYLOAD:
                continue

            sample = payload[:SCAN_BYTES]
            total_payload_bytes += len(payload)
            entropy_val = _entropy(sample)
            printable_ratio = _printable_ratio(sample)
            ts = safe_float(getattr(pkt, "time", None))

            if entropy_val >= ENTROPY_HIGH and printable_ratio <= PRINTABLE_MIN_RATIO:
                if (src_port not in ENCRYPTED_PORTS) and (dst_port not in ENCRYPTED_PORTS):
                    if len(high_entropy_hits) < MAX_HITS:
                        high_entropy_hits.append(
                            ObfuscationHit(
                                kind="high_entropy",
                                src=src_ip,
                                dst=dst_ip,
                                src_port=src_port,
                                dst_port=dst_port,
                                length=len(payload),
                                entropy=entropy_val,
                                sample=sample[:64].hex(),
                                ts=ts,
                            )
                        )
                    source_counts[src_ip] += 1
                    destination_counts[dst_ip] += 1

            text = sample.decode("latin-1", errors="ignore")
            for match in BASE64_RE.finditer(text):
                if len(base64_hits) >= MAX_HITS:
                    break
                token = match.group(0)
                base64_hits.append(
                    ObfuscationHit(
                        kind="base64",
                        src=src_ip,
                        dst=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        length=len(token),
                        entropy=entropy_val,
                        sample=token[:64],
                        ts=ts,
                    )
                )
                source_counts[src_ip] += 1
                destination_counts[dst_ip] += 1
                break

            for match in HEX_RE.finditer(text):
                if len(hex_hits) >= MAX_HITS:
                    break
                token = match.group(0)
                hex_hits.append(
                    ObfuscationHit(
                        kind="hex",
                        src=src_ip,
                        dst=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        length=len(token),
                        entropy=entropy_val,
                        sample=token[:64],
                        ts=ts,
                    )
                )
                source_counts[src_ip] += 1
                destination_counts[dst_ip] += 1
                break

    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        reader.close()

    detections: list[dict[str, object]] = []

    def _hit_evidence(hits: list[ObfuscationHit], limit: int = 6) -> list[str]:
        evidence: list[str] = []
        for hit in hits[:limit]:
            src = f"{hit.src}:{hit.src_port}" if hit.src_port else hit.src
            dst = f"{hit.dst}:{hit.dst_port}" if hit.dst_port else hit.dst
            evidence.append(
                f"{src} -> {dst} len={hit.length} entropy={hit.entropy:.2f} sample={hit.sample}"
            )
        return evidence

    if high_entropy_hits:
        detections.append(
            {
                "severity": "medium",
                "summary": "High-entropy payloads on non-encrypted ports",
                "details": f"{len(high_entropy_hits)} hit(s).",
                "source": "Obfuscation",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "evidence": _hit_evidence(high_entropy_hits),
            }
        )
    if base64_hits:
        detections.append(
            {
                "severity": "low",
                "summary": "Base64-like blobs in payloads",
                "details": f"{len(base64_hits)} hit(s).",
                "source": "Obfuscation",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "evidence": _hit_evidence(base64_hits),
            }
        )
    if hex_hits:
        detections.append(
            {
                "severity": "low",
                "summary": "Hex-like blobs in payloads",
                "details": f"{len(hex_hits)} hit(s).",
                "source": "Obfuscation",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "evidence": _hit_evidence(hex_hits),
            }
        )

    return ObfuscationSummary(
        path=path,
        total_packets=total_packets,
        total_payload_bytes=total_payload_bytes,
        high_entropy_hits=high_entropy_hits,
        base64_hits=base64_hits,
        hex_hits=hex_hits,
        source_counts=source_counts,
        destination_counts=destination_counts,
        detections=detections,
        errors=errors,
    )
