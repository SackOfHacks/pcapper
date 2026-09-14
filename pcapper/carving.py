from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .pcap_cache import PcapMeta, iter_packets
from .reassembly import Reassembly, reassemble
from .utils import (
    detect_file_type_bytes,
    env_int,
    extract_packet_endpoints,
    restrict_dir_permissions,
    safe_write_bytes,
)

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


DEFAULT_STREAM_MAX = env_int("PCAPPER_CARVE_STREAM_MAX_BYTES", 8 * 1024 * 1024, minimum=1)
DEFAULT_CARVE_MAX = env_int("PCAPPER_CARVE_MAX_BYTES", 2 * 1024 * 1024, minimum=1)
DEFAULT_CARVE_LIMIT = env_int("PCAPPER_CARVE_LIMIT", 100, minimum=1)

# Signature -> label. Scanned as one alternation (see _SIGNATURE_RE) rather
# than one find() loop per signature. ``MZ`` is only two bytes and would fire
# on noise, so PE hits are validated against the e_lfanew -> "PE\0\0" chain
# in _validate_hit before they count.
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
    ("EXE/DLL", b"MZ"),
    ("OLE2/Office", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("7Z", b"7z\xbc\xaf\x27\x1c"),
    ("CAB", b"MSCF"),
    ("RTF", b"{\\rtf1"),
    ("LNK", b"L\x00\x00\x00\x01\x14\x02\x00"),
]
_SIGNATURE_BY_MAGIC = {magic: label for label, magic in SIGNATURES}
_SIGNATURE_RE = re.compile(
    b"|".join(re.escape(magic) for magic in sorted(_SIGNATURE_BY_MAGIC, key=len, reverse=True))
)
_PE_MAX_LFANEW = 4096
_PE_MAX_SECTIONS = 96


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
    # Bytes missing from the span this artifact was carved out of. Non-zero means
    # the blob — and therefore the SHA-256 above — is a partial reconstruction,
    # not the file that crossed the wire. See _reassemble / reassembly.Gap.
    gap_count: int = 0
    gap_bytes: int = 0
    # True when the format's own end-of-file structure fixed the length
    # (PDF %%EOF, PNG IEND, JPEG EOI, GIF trailer, ZIP end-of-central-directory,
    # PE section table, ELF section-header table). False means the blob is
    # "signature + up to carve_max_bytes": its length and hash are a bound,
    # not the file's.
    exact_length: bool = False

    @property
    def incomplete(self) -> bool:
        return self.gap_count > 0


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


def _canonical_key(
    src: str, dst: str, sport: int, dport: int
) -> tuple[str, int, str, int]:
    left = (src, sport)
    right = (dst, dport)
    if left <= right:
        return (src, sport, dst, dport)
    return (dst, dport, src, sport)


def _stream_id(src: str, sport: int, dst: str, dport: int) -> str:
    raw = f"{src}:{sport}<->{dst}:{dport}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _reassemble(segments: list[tuple[int, bytes]], max_bytes: int) -> Reassembly:
    """Rebuild one direction of a stream for signature scanning.

    Carving zero-fills gaps (``fill_gaps=True``) rather than closing them by
    concatenation. Two reasons, both specific to carving: offsets into the
    result then mean the same thing as offsets into the stream, so a reported
    ``CarveHit.offset`` corresponds to a real position in the conversation; and
    a file signature that straddles a dropped packet yields a blob with a
    visible hole in it rather than one silently spliced together and published
    with an authoritative SHA-256.
    """
    return reassemble(segments, max_bytes, fill_gaps=True)


def _sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return cleaned.strip("_") or "carve"


def _u16(data: bytes, off: int) -> int | None:
    return int.from_bytes(data[off : off + 2], "little") if off + 2 <= len(data) else None


def _u32(data: bytes, off: int) -> int | None:
    return int.from_bytes(data[off : off + 4], "little") if off + 4 <= len(data) else None


def _pe_end(data: bytes, offset: int) -> int | None:
    """On-disk size of a PE image at ``offset``, from its section table.

    Returns None when the MZ bytes are not a real PE header — the check that
    keeps a 2-byte "MZ" signature from firing on arbitrary binary.
    """
    lfanew = _u32(data, offset + 0x3C)
    if lfanew is None or lfanew < 0x40 or lfanew > _PE_MAX_LFANEW:
        return None
    pe = offset + lfanew
    if data[pe : pe + 4] != b"PE\x00\x00":
        return None
    sections = _u16(data, pe + 6)
    opt_size = _u16(data, pe + 20)
    if sections is None or opt_size is None or not (0 < sections <= _PE_MAX_SECTIONS):
        return None
    table = pe + 24 + opt_size
    end = table + sections * 40
    for i in range(sections):
        entry = table + i * 40
        raw_size = _u32(data, entry + 16)
        raw_ptr = _u32(data, entry + 20)
        if raw_size is None or raw_ptr is None:
            break
        end = max(end, offset + raw_ptr + raw_size)
    return end


def _elf_end(data: bytes, offset: int) -> int | None:
    """On-disk size of an ELF at ``offset`` from its section-header table,
    which the toolchains place last."""
    if data[offset : offset + 4] != b"\x7fELF":
        return None
    cls = data[offset + 4] if offset + 5 <= len(data) else 0
    little = (data[offset + 5] if offset + 6 <= len(data) else 1) == 1
    order = "little" if little else "big"

    def field(off: int, size: int) -> int | None:
        chunk = data[offset + off : offset + off + size]
        return int.from_bytes(chunk, order) if len(chunk) == size else None

    if cls == 1:  # ELF32
        shoff, shentsize, shnum = field(0x20, 4), field(0x2E, 2), field(0x30, 2)
    elif cls == 2:  # ELF64
        shoff, shentsize, shnum = field(0x28, 8), field(0x3A, 2), field(0x3C, 2)
    else:
        return None
    if not shoff or not shentsize or shnum is None:
        return None
    return offset + shoff + shentsize * shnum


def _format_end(data: bytes, offset: int, label: str, limit: int) -> int | None:
    """Where the file that starts at ``offset`` ends, when the format says so.

    Searches only within ``limit`` bytes so a trailer marker in a *later*
    file in the same stream is never taken as this one's. None when the
    format has no usable end structure (GZIP, RAR, 7z, CAB, OLE2 need a
    decoder to size).
    """
    window_end = min(len(data), offset + limit)
    window = data[offset:window_end]
    if label == "PDF":
        idx = window.rfind(b"%%EOF")
        if idx < 0:
            return None
        end = idx + len(b"%%EOF")
        for eol in (b"\r\n", b"\n", b"\r"):
            if window[end : end + len(eol)] == eol:
                end += len(eol)
                break
        return offset + end
    if label == "PNG":
        idx = window.find(b"IEND")
        return None if idx < 0 else offset + idx + 4 + 4  # chunk type + CRC
    if label == "JPG":
        idx = window.find(b"\xff\xd9", 2)
        return None if idx < 0 else offset + idx + 2
    if label == "GIF":
        idx = window.find(b"\x00;")
        return None if idx < 0 else offset + idx + 2
    if label == "ZIP":
        idx = window.rfind(b"PK\x05\x06")
        if idx < 0:
            return None
        comment_len = _u16(window, idx + 20) or 0
        return offset + idx + 22 + comment_len
    if label == "EXE/DLL":
        return _pe_end(data, offset)
    if label == "ELF":
        return _elf_end(data, offset)
    return None


def _find_signatures(data: bytes) -> list[tuple[int, str, bytes]]:
    """Every signature occurrence, in offset order, from a single scan."""
    hits: list[tuple[int, str, bytes]] = []
    pos = 0
    while True:
        match = _SIGNATURE_RE.search(data, pos)
        if match is None:
            break
        magic = match.group(0)
        hits.append((match.start(), _SIGNATURE_BY_MAGIC[magic], magic))
        pos = match.start() + 1
    return hits


def _carve_blob(data: bytes, offset: int, max_bytes: int, label: str) -> tuple[bytes, bool]:
    """The carved bytes and whether the length is the file's own or a bound."""
    if offset < 0 or offset >= len(data):
        return b"", False
    end = _format_end(data, offset, label, max_bytes)
    if end is not None and offset < end <= min(len(data), offset + max_bytes):
        return data[offset:end], True
    return data[offset : min(len(data), offset + max_bytes)], False


def analyze_carving(
    path: Path,
    show_status: bool = True,
    output_dir: Path | None = None,
    stream_max_bytes: int = DEFAULT_STREAM_MAX,
    carve_max_bytes: int = DEFAULT_CARVE_MAX,
    carve_limit: int = DEFAULT_CARVE_LIMIT,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
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

    segments_ab: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(
        list
    )
    segments_ba: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(
        list
    )
    segments_ab_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    segments_ba_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    stream_stats: Counter[tuple[str, int, str, int]] = Counter()
    errors: list[str] = []

    try:
        for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
            tcp = pkt.getlayer(TCP)  # type: ignore[arg-type]
            if tcp is None:
                continue
            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            if sport == 0 or dport == 0:
                continue

            # Only the Raw layer is application data. A segment without one
            # is a pure ACK/control packet; falling back to bytes(tcp.payload)
            # pulled scapy's Ethernet Padding into the stream and carved it.
            raw = tcp.getlayer(Raw) if Raw is not None else None
            if raw is None:
                continue
            try:
                payload = bytes(raw.load)
            except Exception:
                continue
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

    hits: list[CarveHit] = []
    extracted: list[Path] = []
    detections: list[dict[str, object]] = []

    if output_dir:
        restrict_dir_permissions(output_dir)

    for stream_key in stream_stats.keys():
        src, sport, dst, dport = stream_key
        sid = _stream_id(src, sport, dst, dport)
        for direction, stream in (
            ("client", _reassemble(segments_ab.get(stream_key, []), stream_max_bytes)),
            ("server", _reassemble(segments_ba.get(stream_key, []), stream_max_bytes)),
        ):
            data = stream.data
            if not data:
                continue
            sig_hits = _find_signatures(data)
            for offset, label, _sig in sig_hits:
                if len(hits) >= carve_limit:
                    break
                if label == "EXE/DLL" and _pe_end(data, offset) is None:
                    continue  # bare "MZ" bytes, not a PE header
                blob, exact = _carve_blob(data, offset, carve_max_bytes, label)
                if not blob:
                    continue
                file_type = detect_file_type_bytes(blob) or label
                sha256 = hashlib.sha256(blob).hexdigest()
                # A blob spanning a gap is a partial reconstruction. Record how
                # much is missing so the hash is never presented as if it were
                # the hash of the file that actually crossed the wire.
                gap_count, gap_bytes = stream.gaps_within(offset, len(blob))
                name = f"{sid}_{direction}_{offset}_{file_type}".lower()
                filename = f"carve_{_sanitize_name(name)}.bin"
                out_path = None
                if output_dir:
                    out_path = output_dir / filename
                    try:
                        safe_write_bytes(out_path, blob)
                        extracted.append(out_path)
                    except Exception as exc:
                        errors.append(f"Carve write error: {exc}")
                note = str(out_path) if out_path else None
                if gap_count:
                    warning = (
                        f"INCOMPLETE: {gap_bytes} byte(s) missing across "
                        f"{gap_count} gap(s); SHA-256 is of the partial "
                        f"reconstruction, not of the original file"
                    )
                    note = f"{note} [{warning}]" if note else warning
                if not exact:
                    warning = (
                        "BOUNDED: no end-of-file structure found; length is "
                        "the carve limit or the stream end, and the SHA-256 is "
                        "of that span, not of the file"
                    )
                    note = f"{note} [{warning}]" if note else warning
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
                        note=note,
                        gap_count=gap_count,
                        gap_bytes=gap_bytes,
                        exact_length=exact,
                    )
                )
            if len(hits) >= carve_limit:
                break
        if len(hits) >= carve_limit:
            break

    if hits:
        src_counts = Counter(hit.src for hit in hits)
        dst_counts = Counter(hit.dst for hit in hits)
        suspicious_types = {"EXE/DLL", "ELF", "ZIP/Office", "GZIP", "OLE2/Office", "7Z", "CAB", "RTF", "LNK", "RAR"}
        suspicious_hits = [hit for hit in hits if hit.file_type in suspicious_types]
        evidence = [
            f"{hit.file_type} {hit.length}B {hit.src}:{hit.src_port}->{hit.dst}:{hit.dst_port} sha256={hit.sha256[:12]}"
            + (
                f" INCOMPLETE({hit.gap_bytes}B missing in {hit.gap_count} gap(s))"
                if hit.incomplete
                else ""
            )
            for hit in hits[:8]
        ]
        detail_suffix = ""
        severity = "info"
        if suspicious_hits:
            detail_suffix = f" {len(suspicious_hits)} suspicious type(s) detected."
            severity = "warning"
        incomplete_hits = [hit for hit in hits if hit.incomplete]
        if incomplete_hits:
            detail_suffix += (
                f" {len(incomplete_hits)} hit(s) carved across gaps in the"
                " reassembled stream — those hashes are of partial"
                " reconstructions and will not match the original files."
            )
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
