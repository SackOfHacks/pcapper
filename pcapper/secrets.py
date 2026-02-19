from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, get_reader
from .utils import safe_float, decode_payload

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw, Packet  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore
    Packet = object  # type: ignore


MAX_PAYLOAD_SCAN = 64 * 1024
MAX_TOKEN_LEN = 4096
MIN_BASE64_LEN = 16
MIN_HEX_LEN = 16
MIN_URLENC_LEN = 12

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
BASE64URL_RE = re.compile(r"(?<![A-Za-z0-9_\-=])[A-Za-z0-9_\-]{16,}={0,2}(?![A-Za-z0-9_\-=])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
URLENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
JWT_RE = re.compile(r"[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]{8,})?")

PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}


@dataclass(frozen=True)
class SecretHit:
    packet_number: int
    ts: Optional[float]
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    offset: Optional[int]
    kind: str
    encoded: str
    decoded: str
    note: str


@dataclass(frozen=True)
class SecretsSummary:
    path: Path
    total_packets: int
    matches: int
    hits: list[SecretHit]
    truncated: bool
    kind_counts: Counter[str]
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


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in PRINTABLE_BYTES)
    return printable / max(len(data), 1)


def _text_score(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / max(len(text), 1)


def _decode_text(data: bytes) -> str:
    if not data:
        return ""
    text_utf8 = decode_payload(data, encoding="utf-8")
    text_latin = decode_payload(data, encoding="latin-1")
    if _text_score(text_utf8) >= _text_score(text_latin):
        return text_utf8
    return text_latin


def _maybe_decompress(data: bytes) -> Optional[bytes]:
    if not data:
        return None
    if data.startswith(b"\x1f\x8b"):
        try:
            import gzip
            return gzip.decompress(data)
        except Exception:
            return None
    if data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        try:
            return zlib.decompress(data)
        except Exception:
            return None
    return None


def _looks_cleartext(data: bytes) -> bool:
    if not data:
        return False
    if data.count(b"\x00") > len(data) * 0.2:
        return False
    ratio = _printable_ratio(data)
    if ratio >= 0.75:
        return True
    if ratio >= 0.6:
        text = _decode_text(data)
        if any(token in text for token in ("{", "}", "=", ":", "<", ">")):
            return True
    return False


def _decode_base64(token: str, *, urlsafe: bool = False) -> Optional[bytes]:
    if not token:
        return None
    padded = token + ("=" * (-len(token) % 4))
    try:
        if urlsafe:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=False)
    except Exception:
        return None


def _decode_hex(token: str) -> Optional[bytes]:
    if not token:
        return None
    if len(token) % 2 != 0:
        return None
    try:
        return binascii.unhexlify(token)
    except Exception:
        return None


def _decode_urlencoded(token: str) -> Optional[bytes]:
    if not token:
        return None
    try:
        return urllib.parse.unquote_to_bytes(token)
    except Exception:
        return None


def analyze_secrets(
    path: Path,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    max_hits: int = 200,
) -> SecretsSummary:
    if TCP is None and UDP is None and Raw is None:
        return SecretsSummary(path, 0, 0, [], False, Counter(), ["Scapy not available"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return SecretsSummary(path, 0, 0, [], False, Counter(), [f"Error opening pcap: {exc}"])

    total_packets = 0
    matches = 0
    hits: list[SecretHit] = []
    kind_counts: Counter[str] = Counter()
    errors: list[str] = []
    truncated = False
    seen: set[tuple[int, str, str, int]] = set()

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1
            payload = _extract_payload(pkt)
            if not payload:
                continue
            if len(payload) > MAX_PAYLOAD_SCAN:
                payload = payload[:MAX_PAYLOAD_SCAN]

            text = decode_payload(payload, encoding="latin-1")
            if not text:
                continue

            src_ip, dst_ip = _get_ip_pair(pkt)
            src_port, dst_port, protocol = _get_ports(pkt)
            ts = safe_float(getattr(pkt, "time", None))

            jwt_spans: list[tuple[int, int]] = []
            for match in JWT_RE.finditer(text):
                token = match.group(0)
                if len(token) > MAX_TOKEN_LEN:
                    continue
                parts = token.split(".")
                if len(parts) < 2:
                    continue
                header_raw = _decode_base64(parts[0], urlsafe=True) or b""
                payload_raw = _decode_base64(parts[1], urlsafe=True) or b""
                decoded_parts = []
                note_parts = []
                if _looks_cleartext(header_raw):
                    decoded_parts.append(f"header={_decode_text(header_raw).strip()}")
                    note_parts.append("header")
                if _looks_cleartext(payload_raw):
                    decoded_parts.append(f"payload={_decode_text(payload_raw).strip()}")
                    note_parts.append("payload")
                if decoded_parts:
                    matches += 1
                    kind_counts["JWT"] += 1
                    key = (total_packets, "JWT", token, match.start())
                    if key not in seen:
                        seen.add(key)
                        if len(hits) < max_hits:
                            hits.append(SecretHit(
                                packet_number=total_packets,
                                ts=ts,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=src_port,
                                dst_port=dst_port,
                                protocol=protocol,
                                offset=match.start(),
                                kind="JWT",
                                encoded=token,
                                decoded=" | ".join(decoded_parts),
                                note="JWT " + "/".join(note_parts),
                            ))
                        else:
                            truncated = True
                jwt_spans.append((match.start(), match.end()))

            def _overlaps_jwt(start: int, end: int) -> bool:
                for s, e in jwt_spans:
                    if start < e and end > s:
                        return True
                return False

            for match in BASE64_RE.finditer(text):
                token = match.group(0)
                if len(token) < MIN_BASE64_LEN or len(token) > MAX_TOKEN_LEN:
                    continue
                if _overlaps_jwt(match.start(), match.end()):
                    continue
                if re.fullmatch(r"[0-9A-Fa-f]+", token or ""):
                    continue
                raw = _decode_base64(token, urlsafe=False)
                if not raw:
                    continue
                note = "base64"
                decoded_bytes = raw
                decompressed = _maybe_decompress(raw)
                if decompressed and _looks_cleartext(decompressed):
                    decoded_bytes = decompressed
                    note = "base64+decompress"
                if not _looks_cleartext(decoded_bytes):
                    continue
                decoded_text = _decode_text(decoded_bytes).strip()
                if not decoded_text:
                    continue
                matches += 1
                kind_counts["Base64"] += 1
                key = (total_packets, "Base64", token, match.start())
                if key in seen:
                    continue
                seen.add(key)
                if len(hits) < max_hits:
                    hits.append(SecretHit(
                        packet_number=total_packets,
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        offset=match.start(),
                        kind="Base64",
                        encoded=token,
                        decoded=decoded_text,
                        note=note,
                    ))
                else:
                    truncated = True

            for match in BASE64URL_RE.finditer(text):
                token = match.group(0)
                if len(token) < MIN_BASE64_LEN or len(token) > MAX_TOKEN_LEN:
                    continue
                if _overlaps_jwt(match.start(), match.end()):
                    continue
                raw = _decode_base64(token, urlsafe=True)
                if not raw:
                    continue
                note = "base64url"
                decoded_bytes = raw
                decompressed = _maybe_decompress(raw)
                if decompressed and _looks_cleartext(decompressed):
                    decoded_bytes = decompressed
                    note = "base64url+decompress"
                if not _looks_cleartext(decoded_bytes):
                    continue
                decoded_text = _decode_text(decoded_bytes).strip()
                if not decoded_text:
                    continue
                matches += 1
                kind_counts["Base64URL"] += 1
                key = (total_packets, "Base64URL", token, match.start())
                if key in seen:
                    continue
                seen.add(key)
                if len(hits) < max_hits:
                    hits.append(SecretHit(
                        packet_number=total_packets,
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        offset=match.start(),
                        kind="Base64URL",
                        encoded=token,
                        decoded=decoded_text,
                        note=note,
                    ))
                else:
                    truncated = True

            for match in HEX_RE.finditer(text):
                token = match.group(0)
                if len(token) < MIN_HEX_LEN or len(token) > MAX_TOKEN_LEN:
                    continue
                if len(token) % 2 != 0:
                    continue
                raw = _decode_hex(token)
                if not raw:
                    continue
                if not _looks_cleartext(raw):
                    continue
                decoded_text = _decode_text(raw).strip()
                if not decoded_text:
                    continue
                matches += 1
                kind_counts["Hex"] += 1
                key = (total_packets, "Hex", token, match.start())
                if key in seen:
                    continue
                seen.add(key)
                if len(hits) < max_hits:
                    hits.append(SecretHit(
                        packet_number=total_packets,
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        offset=match.start(),
                        kind="Hex",
                        encoded=token,
                        decoded=decoded_text,
                        note="hex",
                    ))
                else:
                    truncated = True

            for match in URLENC_RE.finditer(text):
                token = match.group(0)
                if len(token) < MIN_URLENC_LEN or len(token) > MAX_TOKEN_LEN:
                    continue
                raw = _decode_urlencoded(token)
                if not raw:
                    continue
                if not _looks_cleartext(raw):
                    continue
                decoded_text = _decode_text(raw).strip()
                if not decoded_text or decoded_text == token:
                    continue
                matches += 1
                kind_counts["URL-Encoded"] += 1
                key = (total_packets, "URL-Encoded", token, match.start())
                if key in seen:
                    continue
                seen.add(key)
                if len(hits) < max_hits:
                    hits.append(SecretHit(
                        packet_number=total_packets,
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        offset=match.start(),
                        kind="URL-Encoded",
                        encoded=token,
                        decoded=decoded_text,
                        note="url-decode",
                    ))
                else:
                    truncated = True

    except Exception as exc:
        errors.append(f"Error during scan: {type(exc).__name__}: {exc}")
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    return SecretsSummary(
        path=path,
        total_packets=total_packets,
        matches=matches,
        hits=hits,
        truncated=truncated,
        kind_counts=kind_counts,
        errors=errors,
    )
