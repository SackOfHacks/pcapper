from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter
import base64
import binascii
import re
import urllib.parse

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


FLAG_PATTERNS = [
    re.compile(r"(flag\{[^}]{4,}\})", re.IGNORECASE),
    re.compile(r"(ctf\{[^}]{4,}\})", re.IGNORECASE),
    re.compile(r"(htb\{[^}]{4,}\})", re.IGNORECASE),
    re.compile(r"(picoCTF\{[^}]{4,}\})", re.IGNORECASE),
]


@dataclass(frozen=True)
class CtfHit:
    src_ip: str
    dst_ip: str
    protocol: str
    context: str


@dataclass(frozen=True)
class CtfSummary:
    path: Path
    total_packets: int
    hits: list[CtfHit]
    decoded_hits: list[str]
    token_counts: Counter[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _extract_payload(pkt) -> bytes:
    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[Raw].load)  # type: ignore[index]
        except Exception:
            return b""
    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[TCP].payload)  # type: ignore[index]
        except Exception:
            return b""
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[UDP].payload)  # type: ignore[index]
        except Exception:
            return b""
    return b""


def _decode_candidates(text: str) -> list[str]:
    results: list[str] = []
    text = text.strip()
    if not text:
        return results

    try:
        decoded = urllib.parse.unquote_to_bytes(text)
        if decoded and decoded != text.encode("utf-8", errors="ignore"):
            results.append(decoded.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    try:
        if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
            raw = binascii.unhexlify(text)
            results.append(raw.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    try:
        if len(text) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=]+", text):
            raw = base64.b64decode(text + "===")
            results.append(raw.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    return results


def analyze_ctf(path: Path, show_status: bool = True) -> CtfSummary:
    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    hits: list[CtfHit] = []
    decoded_hits: list[str] = []
    token_counts: Counter[str] = Counter()
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

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

            payload = _extract_payload(pkt)
            if not payload:
                continue
            text = payload.decode("latin-1", errors="ignore")

            for pattern in FLAG_PATTERNS:
                for match in pattern.findall(text):
                    token_counts[match] += 1
                    hits.append(CtfHit(src_ip=src_ip, dst_ip=dst_ip, protocol="payload", context=match))

            for token in re.findall(r"[A-Za-z0-9+/=]{12,}", text):
                decoded = _decode_candidates(token)
                for value in decoded:
                    for pattern in FLAG_PATTERNS:
                        if pattern.search(value):
                            decoded_hits.append(value)

    finally:
        status.finish()
        reader.close()

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return CtfSummary(
        path=path,
        total_packets=total_packets,
        hits=hits,
        decoded_hits=decoded_hits[:50],
        token_counts=token_counts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
