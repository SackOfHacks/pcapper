from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import defaultdict, Counter
import hashlib
import os
import re

from .pcap_cache import get_reader
from .utils import safe_float, detect_file_type_bytes

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


DEFAULT_STREAM_MAX = int(os.environ.get("PCAPPER_CARVE_STREAM_MAX_BYTES", str(8 * 1024 * 1024)))
DEFAULT_CARVE_MAX = int(os.environ.get("PCAPPER_CARVE_MAX_BYTES", str(2 * 1024 * 1024)))
DEFAULT_CARVE_LIMIT = int(os.environ.get("PCAPPER_CARVE_LIMIT", "100"))

SIGNATURES: list[tuple[str, bytes]] = [
    ("PDF", b"%PDF-"),
    ("ZIP", b"PK\x03\x04"),
    ("ZIP", b"PK\x05\x06"),
    ("ELF", b"\x7fELF"),
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("JPG", b"\xff\xd8\xff"),
    ("GIF", b"GIF8"),
    ("GZIP", b"\x1f\x8b\x08"),
    ("RAR", b"Rar!\x1a\x07"),
]


@dataclass(frozen=True)
class CarveHit:
    stream_id: str
    direction: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    offset: int
    length: int
    file_type: str
    sha256: str
    note: str | None = None


@dataclass(frozen=True)
class CarveSummary:
    path: Path
    total_streams: int
    total_hits: int
    hits: list[CarveHit]
    extracted: list[Path]
    detections: list[dict[str, object]]
    errors: list[str]


def merge_carve_summaries(summaries: list[CarveSummary]) -> CarveSummary:
    if not summaries:
        return CarveSummary(
            path=Path("ALL_PCAPS"),
            total_streams=0,
            total_hits=0,
            hits=[],
            extracted=[],
            detections=[],
            errors=[],
        )
    total_streams = sum(item.total_streams for item in summaries)
    total_hits = sum(item.total_hits for item in summaries)
    hits: list[CarveHit] = []
    extracted: list[Path] = []
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    for summary in summaries:
        hits.extend(summary.hits)
        extracted.extend(summary.extracted)
        detections.extend(summary.detections)
        errors.extend(summary.errors)
    return CarveSummary(
        path=Path("ALL_PCAPS"),
        total_streams=total_streams,
        total_hits=total_hits,
        hits=hits[:DEFAULT_CARVE_LIMIT],
        extracted=extracted,
        detections=detections,
        errors=sorted({err for err in errors if err}),
    )


def _canonical_key(src: str, dst: str, sport: int, dport: int) -> tuple[str, int, str, int]:
    left = (src, sport)
    right = (dst, dport)
    if left <= right:
        return (src, sport, dst, dport)
    return (dst, dport, src, sport)


def _stream_id(src: str, sport: int, dst: str, dport: int) -> str:
    raw = f"{src}:{sport}<->{dst}:{dport}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _reassemble(segments: list[tuple[int, bytes]], max_bytes: int) -> bytes:
    if not segments:
        return b""
    segments.sort(key=lambda item: item[0])
    out = bytearray()
    current_end = None
    for seq, data in segments:
        if not data:
            continue
        if current_end is None:
            out.extend(data)
            current_end = seq + len(data)
        else:
            if seq >= current_end:
                out.extend(data)
                current_end = seq + len(data)
            else:
                overlap = current_end - seq
                if overlap < len(data):
                    out.extend(data[overlap:])
                    current_end += len(data) - overlap
        if len(out) >= max_bytes:
            return bytes(out[:max_bytes])
    return bytes(out)


def _sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return cleaned.strip("_") or "carve"


def _find_signatures(data: bytes) -> list[tuple[int, str, bytes]]:
    hits: list[tuple[int, str, bytes]] = []
    for label, sig in SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            hits.append((idx, label, sig))
            start = idx + 1
    hits.sort(key=lambda item: item[0])
    return hits


def _carve_blob(data: bytes, offset: int, max_bytes: int) -> bytes:
    if offset < 0 or offset >= len(data):
        return b""
    end = min(len(data), offset + max_bytes)
    return data[offset:end]


def analyze_carving(
    path: Path,
    show_status: bool = True,
    output_dir: Path | None = None,
    stream_max_bytes: int = DEFAULT_STREAM_MAX,
    carve_max_bytes: int = DEFAULT_CARVE_MAX,
    carve_limit: int = DEFAULT_CARVE_LIMIT,
) -> CarveSummary:
    if TCP is None:
        return CarveSummary(
            path=path,
            total_streams=0,
            total_hits=0,
            hits=[],
            extracted=[],
            detections=[],
            errors=["Scapy TCP unavailable"],
        )

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    segments_ab: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(list)
    segments_ba: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(list)
    segments_ab_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    segments_ba_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    stream_stats: Counter[tuple[str, int, str, int]] = Counter()
    errors: list[str] = []

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue
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

            tcp = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            if sport == 0 or dport == 0:
                continue

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw].load)  # type: ignore[index]
                except Exception:
                    payload = b""
            else:
                try:
                    payload = bytes(getattr(tcp, "payload", b""))
                except Exception:
                    payload = b""

            if not payload:
                continue

            stream_key = _canonical_key(src_ip, dst_ip, sport, dport)
            stream_stats[stream_key] += 1
            seq = int(getattr(tcp, "seq", 0) or 0)
            if (src_ip, sport, dst_ip, dport) == stream_key:
                current = segments_ab_bytes[stream_key]
                if current < stream_max_bytes:
                    remaining = stream_max_bytes - current
                    if remaining <= 0:
                        continue
                    if len(payload) > remaining:
                        payload = payload[:remaining]
                    segments_ab[stream_key].append((seq, payload))
                    segments_ab_bytes[stream_key] += len(payload)
            else:
                current = segments_ba_bytes[stream_key]
                if current < stream_max_bytes:
                    remaining = stream_max_bytes - current
                    if remaining <= 0:
                        continue
                    if len(payload) > remaining:
                        payload = payload[:remaining]
                    segments_ba[stream_key].append((seq, payload))
                    segments_ba_bytes[stream_key] += len(payload)

    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        reader.close()

    hits: list[CarveHit] = []
    extracted: list[Path] = []
    detections: list[dict[str, object]] = []

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    for stream_key in stream_stats.keys():
        src, sport, dst, dport = stream_key
        sid = _stream_id(src, sport, dst, dport)
        for direction, data in (("client", _reassemble(segments_ab.get(stream_key, []), stream_max_bytes)),
                                ("server", _reassemble(segments_ba.get(stream_key, []), stream_max_bytes))):
            if not data:
                continue
            sig_hits = _find_signatures(data)
            for offset, label, _sig in sig_hits:
                if len(hits) >= carve_limit:
                    break
                blob = _carve_blob(data, offset, carve_max_bytes)
                if not blob:
                    continue
                file_type = detect_file_type_bytes(blob) or label
                sha256 = hashlib.sha256(blob).hexdigest()
                name = f"{sid}_{direction}_{offset}_{file_type}".lower()
                filename = f"carve_{_sanitize_name(name)}.bin"
                out_path = None
                if output_dir:
                    out_path = output_dir / filename
                    try:
                        out_path.write_bytes(blob)
                        extracted.append(out_path)
                    except Exception as exc:
                        errors.append(f"Carve write error: {exc}")
                hits.append(
                    CarveHit(
                        stream_id=sid,
                        direction=direction,
                        src=src,
                        dst=dst,
                        src_port=sport,
                        dst_port=dport,
                        offset=offset,
                        length=len(blob),
                        file_type=file_type,
                        sha256=sha256,
                        note=str(out_path) if out_path else None,
                    )
                )
            if len(hits) >= carve_limit:
                break
        if len(hits) >= carve_limit:
            break

    if hits:
        src_counts = Counter(hit.src for hit in hits)
        dst_counts = Counter(hit.dst for hit in hits)
        suspicious_types = {"EXE/DLL", "ELF", "ZIP/Office", "GZIP"}
        suspicious_hits = [hit for hit in hits if hit.file_type in suspicious_types]
        evidence = [
            f"{hit.file_type} {hit.length}B {hit.src}:{hit.src_port}->{hit.dst}:{hit.dst_port} sha256={hit.sha256[:12]}"
            for hit in hits[:8]
        ]
        detail_suffix = ""
        severity = "info"
        if suspicious_hits:
            detail_suffix = f" {len(suspicious_hits)} suspicious type(s) detected."
            severity = "warning"
        detections.append(
            {
                "severity": severity,
                "summary": "Carved file signatures from TCP streams",
                "details": f"{len(hits)} hit(s) across {len(stream_stats)} stream(s).{detail_suffix}",
                "source": "Carving",
                "top_sources": src_counts.most_common(5),
                "top_destinations": dst_counts.most_common(5),
                "evidence": evidence,
            }
        )

    return CarveSummary(
        path=path,
        total_streams=len(stream_stats),
        total_hits=len(hits),
        hits=hits,
        extracted=extracted,
        detections=detections,
        errors=errors,
    )
