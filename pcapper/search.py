from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw, Packet  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore
    Packet = object  # type: ignore


@dataclass(frozen=True)
class SearchHit:
    packet_number: int
    ts: Optional[float]
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    payload_len: int
    context: str


@dataclass(frozen=True)
class SearchSummary:
    path: Path
    query: str
    total_packets: int
    matches: int
    hits: list[SearchHit]
    truncated: bool
    errors: list[str]


def _get_ip_pair(pkt: Packet) -> tuple[str, str]:
    if IP is not None and IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 is not None and IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return "0.0.0.0", "0.0.0.0"


def _get_ports(pkt: Packet) -> tuple[Optional[int], Optional[int], str]:
    if TCP is not None and TCP in pkt:
        try:
            return int(pkt[TCP].sport), int(pkt[TCP].dport), "TCP"
        except Exception:
            return None, None, "TCP"
    if UDP is not None and UDP in pkt:
        try:
            return int(pkt[UDP].sport), int(pkt[UDP].dport), "UDP"
        except Exception:
            return None, None, "UDP"
    return None, None, "OTHER"


def _extract_payload(pkt: Packet) -> bytes:
    if Raw is not None and Raw in pkt:
        try:
            return bytes(pkt[Raw])
        except Exception:
            return b""
    if TCP is not None and TCP in pkt:
        try:
            return bytes(pkt[TCP].payload)
        except Exception:
            return b""
    if UDP is not None and UDP in pkt:
        try:
            return bytes(pkt[UDP].payload)
        except Exception:
            return b""
    return b""


def _build_context(text: str, index: int, query_len: int, max_len: int = 80) -> str:
    if not text:
        return ""
    start = max(0, index - 30)
    end = min(len(text), index + query_len + 30)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    snippet = text[start:end]
    if len(snippet) > max_len:
        snippet = snippet[: max_len - 3] + "..."
        suffix = ""
    return f"{prefix}{snippet}{suffix}"


def _find_match(payload: bytes, query: str, *, case_sensitive: bool) -> Optional[str]:
    if not query:
        return None
    text = payload.decode("latin-1", errors="ignore")
    if case_sensitive:
        idx = text.find(query)
        if idx >= 0:
            return _build_context(text, idx, len(query))
    else:
        query_lower = query.lower()
        text_lower = text.lower()
        idx = text_lower.find(query_lower)
        if idx >= 0:
            return _build_context(text, idx, len(query))

    try:
        query_utf16 = query.encode("utf-16le", errors="ignore")
    except Exception:
        query_utf16 = b""
    if query_utf16 and query_utf16 in payload:
        text16 = payload.decode("utf-16le", errors="ignore")
        if case_sensitive:
            idx = text16.find(query)
            if idx >= 0:
                return _build_context(text16, idx, len(query))
        else:
            query_lower = query.lower()
            idx = text16.lower().find(query_lower)
            if idx >= 0:
                return _build_context(text16, idx, len(query))
        return _build_context(text16, 0, len(query))

    return None


def analyze_search(
    path: Path,
    query: str,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    max_hits: int = 200,
    case_sensitive: bool = False,
) -> SearchSummary:
    if not query:
        return SearchSummary(path, query, 0, 0, [], False, ["Search query is empty."])
    if TCP is None and UDP is None and Raw is None:
        return SearchSummary(path, query, 0, 0, [], False, ["Scapy not available"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return SearchSummary(path, query, 0, 0, [], False, [f"Error opening pcap: {exc}"])

    total_packets = 0
    matches = 0
    hits: list[SearchHit] = []
    errors: list[str] = []

    try:
        for pkt in reader:
            total_packets += 1

            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            payload = _extract_payload(pkt)  # type: ignore[arg-type]
            if not payload:
                continue

            context = _find_match(payload, query, case_sensitive=case_sensitive)
            if context is None:
                continue

            matches += 1
            if len(hits) >= max_hits:
                continue

            src_ip, dst_ip = _get_ip_pair(pkt)  # type: ignore[arg-type]
            src_port, dst_port, proto = _get_ports(pkt)  # type: ignore[arg-type]
            ts = safe_float(getattr(pkt, "time", None))

            hits.append(
                SearchHit(
                    packet_number=total_packets,
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    payload_len=len(payload),
                    context=context,
                )
            )
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    truncated = matches > len(hits)
    return SearchSummary(path, query, total_packets, matches, hits, truncated, errors)
