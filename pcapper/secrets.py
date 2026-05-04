from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import urllib.parse
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, get_reader
from .utils import decode_payload, safe_float, extract_packet_endpoints

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Packet, Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore
    Packet = object  # type: ignore


MAX_PAYLOAD_SCAN = 64 * 1024
MAX_TOKEN_LEN = 4096
MIN_BASE64_LEN = 16
MIN_HEX_LEN = 16
MIN_URLENC_LEN = 12
try:
    MAX_DECOMPRESSED_BYTES = int(
        os.environ.get("PCAPPER_MAX_DECOMPRESSED_BYTES", str(10 * 1024 * 1024))
    )
except Exception:
    MAX_DECOMPRESSED_BYTES = 10 * 1024 * 1024
if MAX_DECOMPRESSED_BYTES < 0:
    MAX_DECOMPRESSED_BYTES = 0

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
BASE64URL_RE = re.compile(
    r"(?<![A-Za-z0-9_\-=])[A-Za-z0-9_\-]{16,}={0,2}(?![A-Za-z0-9_\-=])"
)
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
URLENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
JWT_RE = re.compile(r"[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]{8,})?")

PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}

CRED_KV_RE = re.compile(
    r"\b(?:user(?:name)?|login|account|uid|pass(?:word)?|pwd)\s*[:=]\s*([^\s;&,]{1,128})",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(
    r"\b(?:bearer|token|apikey|api_key|secret|session(?:id)?)\b", re.IGNORECASE
)
PRIVATE_KEY_RE = re.compile(
    r"BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY", re.IGNORECASE
)
LOLBIN_RE = re.compile(
    r"\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)\b",
    re.IGNORECASE,
)
C2_RE = re.compile(
    r"\b(?:beacon|callback|c2|cnc|reverse[_ -]?shell|meterpreter|implant|stager|dropper)\b",
    re.IGNORECASE,
)
EXFIL_RE = re.compile(
    r"\b(?:/upload|/exfil|/gate\.php|multipart/form-data|content-disposition:\s*attachment|ftp put|stor\s+)\b",
    re.IGNORECASE,
)
OT_RE = re.compile(
    r"\b(?:modbus|dnp3|iec[- ]?104|s7(?:comm)?|profinet|ethernet/ip|enip|cip|opc ua|mms|goose|sv|plc|scada|hmi)\b",
    re.IGNORECASE,
)
CTF_RE = re.compile(r"\b(?:flag|ctf|picoctf)\{[^}]{1,220}\}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


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
    top_sources: Counter[str]
    top_destinations: Counter[str]
    protocol_counts: Counter[str]
    deterministic_checks: dict[str, list[str]]
    threat_hypotheses: list[dict[str, object]]
    ot_findings: list[str]
    ctf_indicators: list[str]
    errors: list[str]


def _get_ip_pair(pkt: Packet) -> tuple[str, str]:
    src_ip, dst_ip = extract_packet_endpoints(pkt)
    return src_ip or "0.0.0.0", dst_ip or "0.0.0.0"


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


def _maybe_decompress(
    data: bytes, max_output: int = MAX_DECOMPRESSED_BYTES
) -> Optional[bytes]:
    if not data:
        return None
    if max_output <= 0:
        return b""
    if data.startswith(b"\x1f\x8b"):
        try:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = decompressor.decompress(data, max_output + 1)
            out += decompressor.flush()
            if len(out) > max_output:
                return out[:max_output]
            return out
        except Exception:
            return None
    if data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        try:
            decompressor = zlib.decompressobj()
            out = decompressor.decompress(data, max_output + 1)
            out += decompressor.flush()
            if len(out) > max_output:
                return out[:max_output]
            return out
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


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
        return not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        )
    except Exception:
        return False


def analyze_secrets(
    path: Path,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    max_hits: int = 200,
) -> SecretsSummary:
    if TCP is None and UDP is None and Raw is None:
        return SecretsSummary(
            path,
            0,
            0,
            [],
            False,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            {},
            [],
            [],
            [],
            ["Scapy not available"],
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return SecretsSummary(
            path,
            0,
            0,
            [],
            False,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            {},
            [],
            [],
            [],
            [f"Error opening pcap: {exc}"],
        )

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
                            hits.append(
                                SecretHit(
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
                                )
                            )
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
                    hits.append(
                        SecretHit(
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
                        )
                    )
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
                    hits.append(
                        SecretHit(
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
                        )
                    )
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
                    hits.append(
                        SecretHit(
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
                        )
                    )
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
                    hits.append(
                        SecretHit(
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
                        )
                    )
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

    top_sources: Counter[str] = Counter()
    top_destinations: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    encoded_reuse: Counter[str] = Counter()
    deterministic_checks: dict[str, list[str]] = {
        "cleartext_credentials_in_decoded_secrets": [],
        "token_or_session_material": [],
        "private_key_or_cryptographic_material": [],
        "command_execution_or_lolbin_in_secrets": [],
        "c2_or_exfil_markers_in_decoded_payloads": [],
        "external_public_secret_flow": [],
        "ot_ics_secret_transport_or_context": [],
        "ctf_flag_or_challenge_markers": [],
        "multi_stage_decoding_chain": [],
        "high_reuse_or_staging_pattern": [],
    }
    threat_hypotheses: list[dict[str, object]] = []
    ot_findings: list[str] = []
    ctf_indicators: list[str] = []

    for hit in hits:
        src = str(hit.src_ip or "-")
        dst = str(hit.dst_ip or "-")
        proto = str(hit.protocol or "-")
        top_sources[src] += 1
        top_destinations[dst] += 1
        protocol_counts[proto] += 1
        encoded_reuse[str(hit.encoded)] += 1

        decoded_blob = f"{hit.decoded}\n{hit.encoded}"
        lower_blob = decoded_blob.lower()
        if CRED_KV_RE.search(decoded_blob):
            deterministic_checks["cleartext_credentials_in_decoded_secrets"].append(
                f"pkt {hit.packet_number} {src}->{dst} decoded credential-like key/value"
            )
        if TOKEN_RE.search(decoded_blob):
            deterministic_checks["token_or_session_material"].append(
                f"pkt {hit.packet_number} {src}->{dst} token/session markers in decoded payload"
            )
        if PRIVATE_KEY_RE.search(decoded_blob) or "ssh-rsa" in lower_blob:
            deterministic_checks["private_key_or_cryptographic_material"].append(
                f"pkt {hit.packet_number} {src}->{dst} private key/crypto material signature"
            )
        if LOLBIN_RE.search(decoded_blob):
            deterministic_checks["command_execution_or_lolbin_in_secrets"].append(
                f"pkt {hit.packet_number} {src}->{dst} execution/lolbin command string"
            )
        if C2_RE.search(decoded_blob) or EXFIL_RE.search(decoded_blob):
            deterministic_checks["c2_or_exfil_markers_in_decoded_payloads"].append(
                f"pkt {hit.packet_number} {src}->{dst} C2/exfil marker in decoded payload"
            )
        if ("+" in hit.note and "decompress" in hit.note.lower()) or (
            "+" in hit.note and "decode" in hit.note.lower()
        ):
            deterministic_checks["multi_stage_decoding_chain"].append(
                f"pkt {hit.packet_number} {src}->{dst} multi-stage decoding path ({hit.note})"
            )
        if _is_public_ip(dst):
            deterministic_checks["external_public_secret_flow"].append(
                f"pkt {hit.packet_number} {src}->{dst} decoded secret material to public destination"
            )
        if OT_RE.search(decoded_blob):
            ot_line = (
                f"pkt {hit.packet_number} {src}->{dst} OT/ICS marker in decoded content"
            )
            deterministic_checks["ot_ics_secret_transport_or_context"].append(ot_line)
            if ot_line not in ot_findings and len(ot_findings) < 20:
                ot_findings.append(ot_line)
        if CTF_RE.search(decoded_blob):
            ctf_line = f"pkt {hit.packet_number} {src}->{dst} CTF flag-like marker in decoded content"
            deterministic_checks["ctf_flag_or_challenge_markers"].append(ctf_line)
            if ctf_line not in ctf_indicators and len(ctf_indicators) < 20:
                ctf_indicators.append(ctf_line)
        for url in URL_RE.findall(decoded_blob):
            try:
                host = urllib.parse.urlsplit(url).hostname or ""
            except Exception:
                host = ""
            if host and _is_public_ip(host):
                deterministic_checks["external_public_secret_flow"].append(
                    f"pkt {hit.packet_number} URL host is public IP ({host}) in decoded secret payload"
                )

    for encoded_value, count in encoded_reuse.items():
        if count >= 3:
            preview = encoded_value[:40] + ("..." if len(encoded_value) > 40 else "")
            deterministic_checks["high_reuse_or_staging_pattern"].append(
                f"Encoded token reused {count} times: {preview}"
            )

    for key, values in list(deterministic_checks.items()):
        deterministic_checks[key] = list(dict.fromkeys(values))

    if (
        deterministic_checks["cleartext_credentials_in_decoded_secrets"]
        and deterministic_checks["c2_or_exfil_markers_in_decoded_payloads"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Credential-bearing decoded payloads with C2/exfil semantics",
                "confidence": "high",
                "evidence": len(
                    deterministic_checks["cleartext_credentials_in_decoded_secrets"]
                )
                + len(deterministic_checks["c2_or_exfil_markers_in_decoded_payloads"]),
            }
        )
    if (
        deterministic_checks["token_or_session_material"]
        and deterministic_checks["external_public_secret_flow"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Token/session material transmitted toward external/public infrastructure",
                "confidence": "medium",
                "evidence": len(deterministic_checks["token_or_session_material"])
                + len(deterministic_checks["external_public_secret_flow"]),
            }
        )
    if deterministic_checks["ot_ics_secret_transport_or_context"]:
        threat_hypotheses.append(
            {
                "hypothesis": "OT/ICS context appears in decoded secret-bearing payloads",
                "confidence": "medium",
                "evidence": len(
                    deterministic_checks["ot_ics_secret_transport_or_context"]
                ),
            }
        )
    if deterministic_checks["ctf_flag_or_challenge_markers"]:
        threat_hypotheses.append(
            {
                "hypothesis": "CTF/challenge markers embedded in reversible secret payloads",
                "confidence": "low",
                "evidence": len(deterministic_checks["ctf_flag_or_challenge_markers"]),
            }
        )

    return SecretsSummary(
        path=path,
        total_packets=total_packets,
        matches=matches,
        hits=hits,
        truncated=truncated,
        kind_counts=kind_counts,
        top_sources=top_sources,
        top_destinations=top_destinations,
        protocol_counts=protocol_counts,
        deterministic_checks=deterministic_checks,
        threat_hypotheses=threat_hypotheses,
        ot_findings=ot_findings,
        ctf_indicators=ctf_indicators,
        errors=errors,
    )


def merge_secrets_summaries(
    summaries: list[SecretsSummary]
    | tuple[SecretsSummary, ...]
    | set[SecretsSummary],
) -> SecretsSummary:
    summary_list = list(summaries)
    if not summary_list:
        return SecretsSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            matches=0,
            hits=[],
            truncated=False,
            kind_counts=Counter(),
            top_sources=Counter(),
            top_destinations=Counter(),
            protocol_counts=Counter(),
            deterministic_checks={},
            threat_hypotheses=[],
            ot_findings=[],
            ctf_indicators=[],
            errors=[],
        )

    total_packets = sum(
        int(getattr(item, "total_packets", 0) or 0) for item in summary_list
    )
    matches = sum(int(getattr(item, "matches", 0) or 0) for item in summary_list)
    truncated = any(bool(getattr(item, "truncated", False)) for item in summary_list)

    hits: list[SecretHit] = []
    kind_counts: Counter[str] = Counter()
    top_sources: Counter[str] = Counter()
    top_destinations: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    deterministic_checks: dict[str, list[str]] = {}
    threat_hypotheses: list[dict[str, object]] = []
    ot_findings: list[str] = []
    ctf_indicators: list[str] = []
    errors: set[str] = set()

    for summary in summary_list:
        kind_counts.update(getattr(summary, "kind_counts", Counter()) or Counter())
        top_sources.update(getattr(summary, "top_sources", Counter()) or Counter())
        top_destinations.update(
            getattr(summary, "top_destinations", Counter()) or Counter()
        )
        protocol_counts.update(
            getattr(summary, "protocol_counts", Counter()) or Counter()
        )

        errors.update(
            str(err)
            for err in (getattr(summary, "errors", []) or [])
            if str(err).strip()
        )

        for hit in getattr(summary, "hits", []) or []:
            hits.append(hit)

        checks = getattr(summary, "deterministic_checks", {}) or {}
        for key, values in checks.items():
            bucket = deterministic_checks.setdefault(str(key), [])
            for value in values or []:
                text = str(value).strip()
                if text:
                    bucket.append(text)

        for row in getattr(summary, "threat_hypotheses", []) or []:
            if isinstance(row, dict):
                threat_hypotheses.append(dict(row))

        for line in getattr(summary, "ot_findings", []) or []:
            text = str(line).strip()
            if text:
                ot_findings.append(text)

        for line in getattr(summary, "ctf_indicators", []) or []:
            text = str(line).strip()
            if text:
                ctf_indicators.append(text)

    for key, values in list(deterministic_checks.items()):
        deterministic_checks[key] = list(dict.fromkeys(values))[:100]

    hits.sort(
        key=lambda item: (
            safe_float(getattr(item, "ts", None))
            if getattr(item, "ts", None) is not None
            else float("inf"),
            int(getattr(item, "packet_number", 0) or 0),
        )
    )

    dedup_hypotheses: list[dict[str, object]] = []
    seen_hypotheses: set[str] = set()
    for row in threat_hypotheses:
        sig = repr(sorted((str(k), repr(v)) for k, v in row.items()))
        if sig in seen_hypotheses:
            continue
        seen_hypotheses.add(sig)
        dedup_hypotheses.append(row)

    ot_findings = list(dict.fromkeys(ot_findings))[:100]
    ctf_indicators = list(dict.fromkeys(ctf_indicators))[:100]

    return SecretsSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        matches=matches,
        hits=hits,
        truncated=truncated or matches > len(hits),
        kind_counts=kind_counts,
        top_sources=top_sources,
        top_destinations=top_destinations,
        protocol_counts=protocol_counts,
        deterministic_checks=deterministic_checks,
        threat_hypotheses=dedup_hypotheses,
        ot_findings=ot_findings,
        ctf_indicators=ctf_indicators,
        errors=sorted(errors),
    )
