from __future__ import annotations

from .utils import shannon_entropy as _shannon_entropy, packet_length
import hashlib
import ipaddress
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .certificates import CertificateInfo, analyze_certificates, is_weak_pubkey
from .dns import _vt_lookup_domains
from .http import analyze_http
from .pcap_cache import get_reader
from .progress import run_with_busy_status
from .tls_fingerprints import (
    ALPN_EXT_TYPE,
    SNI_EXT_TYPE,
    _coerce_int_list,
    _extract_alpn,
    _extract_sni,
    _is_grease,
    _iter_tls_extensions,
    _ja3_from_client_hello,
    _ja4_from_client_hello,
    _ja4_alpn_token,
    _ja4s_from_server_hello,
    _resolve_negotiated_version,
    _sha256_12,
    _tls_extension_type,
    lookup_ja3_intel,
)
from .utils import decode_payload, extract_packet_endpoints, memoize_analysis, safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore

try:
    from scapy.layers.tls.handshake import (  # type: ignore
        TLSClientHello,
        TLSServerHello,
    )
    from scapy.layers.tls.record import TLS  # type: ignore
except Exception:  # pragma: no cover
    TLSClientHello = None  # type: ignore
    TLSServerHello = None  # type: ignore
    TLS = None  # type: ignore


TLS_PORTS = {443, 8443, 9443, 4433}
SUSPICIOUS_TLDS = {".ru", ".cn", ".top", ".xyz", ".gq", ".tk", ".ml", ".ga"}
TLS_CONTENT_TYPES = {20, 21, 22, 23}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")
WEAK_CIPHER_IDS = {
    0x0000,  # TLS_NULL_WITH_NULL_NULL
    0x0001,  # TLS_RSA_WITH_NULL_MD5
    0x0002,  # TLS_RSA_WITH_NULL_SHA
    0x0003,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
    0x0004,  # TLS_RSA_WITH_RC4_128_MD5
    0x0005,  # TLS_RSA_WITH_RC4_128_SHA
    0x0006,  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
    0x0007,  # TLS_RSA_WITH_IDEA_CBC_SHA
    0x0008,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0009,  # TLS_RSA_WITH_DES_CBC_SHA
    0x000A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x000B,  # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x000C,  # TLS_DH_DSS_WITH_DES_CBC_SHA
    0x000D,  # TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
    0x000E,  # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x000F,  # TLS_DH_RSA_WITH_DES_CBC_SHA
    0x0010,  # TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
    0x0011,  # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x0012,  # TLS_DHE_DSS_WITH_DES_CBC_SHA
    0x0013,  # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    0x0014,  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0015,  # TLS_DHE_RSA_WITH_DES_CBC_SHA
    0x0016,  # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    0x0017,  # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
    0x0018,  # TLS_DH_anon_WITH_RC4_128_MD5
    0x0019,  # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    0x001A,  # TLS_DH_anon_WITH_DES_CBC_SHA
    0x001B,  # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
}
ECH_EXTENSION_IDS = {0xFE0D}
COMMON_ALPN_TOKENS = {
    "h2",
    "http/1.1",
    "h3",
    "doq",
    "hq",
    "acme-tls/1",
    "mqtt",
    "imap",
    "pop3",
    "smtp",
}
BRAND_KEYWORDS = (
    "microsoft",
    "google",
    "apple",
    "amazon",
    "paypal",
    "okta",
    "cisco",
    "adobe",
    "github",
    "office365",
)


@dataclass(frozen=True)
class _RawClientHello:
    legacy_version: int
    negotiated_version: Optional[int]
    sni: Optional[str]
    alpn: tuple[str, ...]
    ech_present: bool
    ja3: str
    ja3_hash: str
    ja4: str


@dataclass(frozen=True)
class _RawServerHello:
    legacy_version: int
    negotiated_version: Optional[int]
    cipher: int
    alpn: tuple[str, ...]
    ja4s: str


@dataclass(frozen=True)
class TlsConversation:
    client_ip: str
    server_ip: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    sni: Optional[str]
    client_hellos: int = 0
    server_hellos: int = 0
    client_bytes: int = 0
    server_bytes: int = 0
    versions: tuple[str, ...] = ()
    alpn: tuple[str, ...] = ()
    ja3: tuple[str, ...] = ()
    ja4: tuple[str, ...] = ()
    ja4s: tuple[str, ...] = ()


@dataclass(frozen=True)
class TlsSummary:
    path: Path
    total_packets: int
    tls_packets: int
    tls_like_packets: int
    client_hellos: int
    server_hellos: int
    ech_hellos: int
    ech_sni_missing: int
    sni_missing_total: int
    sni_missing_no_ech: int
    versions: Counter[str]
    cipher_suites: Counter[str]
    weak_ciphers: Counter[str]
    sni_counts: Counter[str]
    alpn_counts: Counter[str]
    ja3_counts: Counter[str]
    ja4_counts: Counter[str]
    ja4s_counts: Counter[str]
    sni_to_ja3: dict[str, Counter[str]]
    sni_to_ja4: dict[str, Counter[str]]
    ja3_to_sni: dict[str, Counter[str]]
    ja4_to_sni: dict[str, Counter[str]]
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    conversations: list[TlsConversation]
    http_requests: int
    http_responses: int
    http_methods: Counter[str]
    http_statuses: Counter[str]
    http_urls: Counter[str]
    http_user_agents: Counter[str]
    http_files: Counter[str]
    http_referrers: Counter[str]
    http_referrer_request_hosts: dict[str, Counter[str]]
    http_referrer_hosts: Counter[str]
    http_referrer_schemes: Counter[str]
    http_referrer_paths: Counter[str]
    http_referrer_tokens: Counter[str]
    http_referrer_ip_hosts: Counter[str]
    http_referrer_present: int
    http_referrer_missing: int
    http_referrer_cross_host: int
    http_referrer_https_to_http: int
    http_clients: Counter[str]
    http_servers: Counter[str]
    cert_subjects: Counter[str]
    cert_issuers: Counter[str]
    cert_sans: Counter[str]
    cert_count: int
    weak_certs: int
    expired_certs: int
    self_signed_certs: int
    cert_artifacts: list[CertificateInfo]
    analysis_notes: list[str]
    detections: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    vt_lookup_enabled: bool = False
    vt_results: dict[str, dict[str, object]] = field(default_factory=dict)
    vt_errors: list[str] = field(default_factory=list)
    raw_client_hellos: int = 0
    raw_server_hellos: int = 0
    client_hello_counts: Counter[str] = field(default_factory=Counter)
    server_hello_counts: Counter[str] = field(default_factory=Counter)
    client_sni_counts: dict[str, Counter[str]] = field(default_factory=dict)
    server_sni_counts: dict[str, Counter[str]] = field(default_factory=dict)
    server_endpoint_sni_counts: dict[str, Counter[str]] = field(default_factory=dict)
    sni_to_clients: dict[str, Counter[str]] = field(default_factory=dict)
    sni_to_servers: dict[str, Counter[str]] = field(default_factory=dict)
    client_ja3_counts: dict[str, Counter[str]] = field(default_factory=dict)
    client_ja4_counts: dict[str, Counter[str]] = field(default_factory=dict)
    server_ja4s_counts: dict[str, Counter[str]] = field(default_factory=dict)
    server_endpoint_ja4s_counts: dict[str, Counter[str]] = field(default_factory=dict)
    client_alpn_counts: dict[str, Counter[str]] = field(default_factory=dict)
    client_missing_sni: Counter[str] = field(default_factory=Counter)
    client_missing_sni_no_ech: Counter[str] = field(default_factory=Counter)
    client_ech_counts: Counter[str] = field(default_factory=Counter)
    client_handshake_failures: Counter[str] = field(default_factory=Counter)
    server_handshake_failures: Counter[str] = field(default_factory=Counter)
    nonstandard_tls_clients: Counter[str] = field(default_factory=Counter)
    nonstandard_tls_servers: Counter[str] = field(default_factory=Counter)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "tls_packets": self.tls_packets,
            "tls_like_packets": self.tls_like_packets,
            "client_hellos": self.client_hellos,
            "server_hellos": self.server_hellos,
            "ech_hellos": self.ech_hellos,
            "ech_sni_missing": self.ech_sni_missing,
            "sni_missing_total": self.sni_missing_total,
            "sni_missing_no_ech": self.sni_missing_no_ech,
            "versions": dict(self.versions),
            "cipher_suites": dict(self.cipher_suites),
            "weak_ciphers": dict(self.weak_ciphers),
            "sni_counts": dict(self.sni_counts),
            "alpn_counts": dict(self.alpn_counts),
            "ja3_counts": dict(self.ja3_counts),
            "ja4_counts": dict(self.ja4_counts),
            "ja4s_counts": dict(self.ja4s_counts),
            "sni_to_ja3": {
                sni: dict(counter) for sni, counter in self.sni_to_ja3.items()
            },
            "sni_to_ja4": {
                sni: dict(counter) for sni, counter in self.sni_to_ja4.items()
            },
            "ja3_to_sni": {
                ja3: dict(counter) for ja3, counter in self.ja3_to_sni.items()
            },
            "ja4_to_sni": {
                ja4: dict(counter) for ja4, counter in self.ja4_to_sni.items()
            },
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "server_port": conv.server_port,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                    "sni": conv.sni,
                    "client_hellos": conv.client_hellos,
                    "server_hellos": conv.server_hellos,
                    "client_bytes": conv.client_bytes,
                    "server_bytes": conv.server_bytes,
                    "versions": list(conv.versions),
                    "alpn": list(conv.alpn),
                    "ja3": list(conv.ja3),
                    "ja4": list(conv.ja4),
                    "ja4s": list(conv.ja4s),
                }
                for conv in self.conversations
            ],
            "http_requests": self.http_requests,
            "http_responses": self.http_responses,
            "http_methods": dict(self.http_methods),
            "http_statuses": dict(self.http_statuses),
            "http_urls": dict(self.http_urls),
            "http_user_agents": dict(self.http_user_agents),
            "http_files": dict(self.http_files),
            "http_referrers": dict(self.http_referrers),
            "http_referrer_request_hosts": {
                ref: dict(hosts)
                for ref, hosts in self.http_referrer_request_hosts.items()
            },
            "http_referrer_hosts": dict(self.http_referrer_hosts),
            "http_referrer_schemes": dict(self.http_referrer_schemes),
            "http_referrer_paths": dict(self.http_referrer_paths),
            "http_referrer_tokens": dict(self.http_referrer_tokens),
            "http_referrer_ip_hosts": dict(self.http_referrer_ip_hosts),
            "http_referrer_present": self.http_referrer_present,
            "http_referrer_missing": self.http_referrer_missing,
            "http_referrer_cross_host": self.http_referrer_cross_host,
            "http_referrer_https_to_http": self.http_referrer_https_to_http,
            "http_clients": dict(self.http_clients),
            "http_servers": dict(self.http_servers),
            "cert_subjects": dict(self.cert_subjects),
            "cert_issuers": dict(self.cert_issuers),
            "cert_sans": dict(self.cert_sans),
            "cert_count": self.cert_count,
            "weak_certs": self.weak_certs,
            "expired_certs": self.expired_certs,
            "self_signed_certs": self.self_signed_certs,
            "cert_artifacts": [
                {
                    "subject": cert.subject,
                    "issuer": cert.issuer,
                    "serial": cert.serial,
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "sig_algo": cert.sig_algo,
                    "pubkey_type": cert.pubkey_type,
                    "pubkey_size": cert.pubkey_size,
                    "san": cert.san,
                    "sha1": cert.sha1,
                    "sha256": cert.sha256,
                    "src_ip": cert.src_ip,
                    "dst_ip": cert.dst_ip,
                    "sni": cert.sni,
                }
                for cert in self.cert_artifacts
            ],
            "analysis_notes": list(self.analysis_notes),
            "detections": list(self.detections),
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
            "vt_lookup_enabled": self.vt_lookup_enabled,
            "vt_results": dict(self.vt_results),
            "vt_errors": list(self.vt_errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
            "raw_client_hellos": self.raw_client_hellos,
            "raw_server_hellos": self.raw_server_hellos,
            "client_hello_counts": dict(self.client_hello_counts),
            "server_hello_counts": dict(self.server_hello_counts),
            "client_sni_counts": {
                key: dict(counter) for key, counter in self.client_sni_counts.items()
            },
            "server_sni_counts": {
                key: dict(counter) for key, counter in self.server_sni_counts.items()
            },
            "server_endpoint_sni_counts": {
                key: dict(counter)
                for key, counter in self.server_endpoint_sni_counts.items()
            },
            "sni_to_clients": {
                key: dict(counter) for key, counter in self.sni_to_clients.items()
            },
            "sni_to_servers": {
                key: dict(counter) for key, counter in self.sni_to_servers.items()
            },
            "client_ja3_counts": {
                key: dict(counter) for key, counter in self.client_ja3_counts.items()
            },
            "client_ja4_counts": {
                key: dict(counter) for key, counter in self.client_ja4_counts.items()
            },
            "server_ja4s_counts": {
                key: dict(counter) for key, counter in self.server_ja4s_counts.items()
            },
            "server_endpoint_ja4s_counts": {
                key: dict(counter)
                for key, counter in self.server_endpoint_ja4s_counts.items()
            },
            "client_alpn_counts": {
                key: dict(counter) for key, counter in self.client_alpn_counts.items()
            },
            "client_missing_sni": dict(self.client_missing_sni),
            "client_missing_sni_no_ech": dict(self.client_missing_sni_no_ech),
            "client_ech_counts": dict(self.client_ech_counts),
            "client_handshake_failures": dict(self.client_handshake_failures),
            "server_handshake_failures": dict(self.server_handshake_failures),
            "nonstandard_tls_clients": dict(self.nonstandard_tls_clients),
            "nonstandard_tls_servers": dict(self.nonstandard_tls_servers),
        }







def _is_ech_extension(ext: object) -> bool:
    name = ext.__class__.__name__
    if "EncryptedClientHello" in name or name == "ECH":
        return True
    ext_type = _tls_extension_type(ext)
    return ext_type in ECH_EXTENSION_IDS


def _tls_version_label(value: object) -> str:
    try:
        ver = int(value)
    except Exception:
        return str(value)
    mapping = {
        0x0002: "SSLv2",
        0x0200: "SSLv2",
        0x0300: "SSLv3",
        0x0301: "TLS1.0",
        0x0302: "TLS1.1",
        0x0303: "TLS1.2",
        0x0304: "TLS1.3",
        0xFEFF: "DTLS1.0",
        0xFEFD: "DTLS1.2",
        0xFEFC: "DTLS1.3",
    }
    return mapping.get(ver, f"0x{ver:04x}")


def _looks_like_tls_record(payload: bytes) -> bool:
    if not payload or len(payload) < 5:
        return False
    content_type = payload[0]
    if content_type not in TLS_CONTENT_TYPES:
        return False
    if payload[1] != 0x03:
        return False
    length = int.from_bytes(payload[3:5], "big")
    if length <= 0:
        return False
    if length > 0x4000 + 2048:
        return False
    return True


def _looks_like_ssl2_record(payload: bytes) -> bool:
    # SSLv2 records use a length-prefixed header with the high bit set.
    if not payload or len(payload) < 5:
        return False
    if (payload[0] & 0x80) == 0:
        return False
    rec_len = ((payload[0] & 0x7F) << 8) | payload[1]
    if rec_len <= 0 or rec_len > 0x7FFF:
        return False
    msg_type = payload[2]
    if msg_type not in (1, 2, 4):  # ClientHello, ClientMasterKey, ServerHello
        return False
    version = int.from_bytes(payload[3:5], "big")
    if version in (0x0002, 0x0200, 0x0300, 0x0301, 0x0302, 0x0303):
        return True
    return False


def _record_version_label(payload: bytes) -> Optional[str]:
    if _looks_like_tls_record(payload):
        ver = int.from_bytes(payload[1:3], "big")
        return _tls_version_label(ver)
    if _looks_like_ssl2_record(payload):
        ver = int.from_bytes(payload[3:5], "big")
        return _tls_version_label(ver)
    return None


def _tls_handshake_type(payload: bytes) -> Optional[int]:
    if len(payload) < 6:
        return None
    if payload[0] != 22:
        return None
    return payload[5]


def _tls_handshake_body(payload: bytes, wanted_type: int) -> Optional[bytes]:
    if not _looks_like_tls_record(payload) or payload[0] != 22:
        return None
    if len(payload) < 9:
        return None
    record_len = int.from_bytes(payload[3:5], "big")
    record_end = min(len(payload), 5 + record_len)
    pos = 5
    while pos + 4 <= record_end:
        handshake_type = payload[pos]
        handshake_len = int.from_bytes(payload[pos + 1 : pos + 4], "big")
        body_start = pos + 4
        body_end = body_start + handshake_len
        if body_end > record_end or body_end > len(payload):
            return None
        if handshake_type == wanted_type:
            return payload[body_start:body_end]
        pos = body_end
    return None


def _parse_extensions(data: bytes) -> list[tuple[int, bytes]]:
    extensions: list[tuple[int, bytes]] = []
    pos = 0
    while pos + 4 <= len(data):
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + ext_len > len(data):
            break
        extensions.append((ext_type, data[pos : pos + ext_len]))
        pos += ext_len
    return extensions


def _parse_sni_extension(data: bytes) -> Optional[str]:
    if len(data) < 5:
        return None
    list_len = int.from_bytes(data[0:2], "big")
    pos = 2
    end = min(len(data), 2 + list_len)
    while pos + 3 <= end:
        name_type = data[pos]
        name_len = int.from_bytes(data[pos + 1 : pos + 3], "big")
        pos += 3
        if pos + name_len > end:
            break
        if name_type == 0:
            try:
                return data[pos : pos + name_len].decode(
                    "utf-8", errors="ignore"
                ).strip(".")
            except Exception:
                return None
        pos += name_len
    return None


def _parse_alpn_extension(data: bytes) -> list[str]:
    if len(data) < 3:
        return []
    list_len = int.from_bytes(data[0:2], "big")
    pos = 2
    end = min(len(data), 2 + list_len)
    protocols: list[str] = []
    while pos + 1 <= end:
        proto_len = data[pos]
        pos += 1
        if proto_len <= 0 or pos + proto_len > end:
            break
        protocols.append(
            data[pos : pos + proto_len].decode("utf-8", errors="ignore")
        )
        pos += proto_len
    return protocols


def _parse_supported_versions_client(data: bytes) -> list[int]:
    if len(data) < 3:
        return []
    list_len = int(data[0])
    pos = 1
    end = min(len(data), 1 + list_len)
    versions: list[int] = []
    while pos + 2 <= end:
        versions.append(int.from_bytes(data[pos : pos + 2], "big"))
        pos += 2
    return [version for version in versions if not _is_grease(version)]


def _parse_supported_versions_server(data: bytes) -> list[int]:
    if len(data) < 2:
        return []
    version = int.from_bytes(data[0:2], "big")
    if _is_grease(version):
        return []
    return [version]


def _parse_u16_vector(data: bytes) -> list[int]:
    values: list[int] = []
    pos = 0
    while pos + 2 <= len(data):
        value = int.from_bytes(data[pos : pos + 2], "big")
        if not _is_grease(value):
            values.append(value)
        pos += 2
    return values


def _resolve_raw_tls_version(versions: list[int], fallback: int) -> int:
    if versions:
        tls_versions = [v for v in versions if v < 0xFE00]
        if tls_versions:
            return max(tls_versions)
        return min(versions)
    return fallback


def _join_decimal(values: list[int]) -> str:
    return "-".join(str(value) for value in values)


def _ja4_from_raw_client_hello(
    *,
    version: int,
    ciphers: list[int],
    ext_types: list[int],
    sig_algs: list[int],
    sni: Optional[str],
    alpn: list[str],
) -> str:
    cipher_count = min(len(ciphers), 99)
    ext_count = min(len(ext_types), 99)
    sni_flag = "d" if sni else "i"
    ja4_a = (
        f"t{_tls_fingerprints_version_code(version)}{sni_flag}"
        f"{cipher_count:02d}{ext_count:02d}{_ja4_alpn_token(alpn)}"
    )
    ja4_b = (
        _sha256_12(",".join(f"{cipher:04x}" for cipher in sorted(ciphers)))
        if ciphers
        else "0" * 12
    )
    hash_exts = sorted(
        ext_type
        for ext_type in ext_types
        if ext_type not in (SNI_EXT_TYPE, ALPN_EXT_TYPE)
    )
    if hash_exts:
        ext_str = ",".join(f"{ext_type:04x}" for ext_type in hash_exts)
        if sig_algs:
            ext_str += "_" + ",".join(f"{alg:04x}" for alg in sig_algs)
        ja4_c = _sha256_12(ext_str)
    else:
        ja4_c = "0" * 12
    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def _ja4s_from_raw_server_hello(
    *, version: int, cipher: int, ext_types: list[int], alpn: list[str]
) -> str:
    ja4s_a = (
        f"t{_tls_fingerprints_version_code(version)}"
        f"{min(len(ext_types), 99):02d}{_ja4_alpn_token(alpn)}"
    )
    ja4s_b = f"{cipher:04x}"
    ja4s_c = (
        _sha256_12(",".join(f"{ext_type:04x}" for ext_type in ext_types))
        if ext_types
        else "0" * 12
    )
    return f"{ja4s_a}_{ja4s_b}_{ja4s_c}"


def _tls_fingerprints_version_code(version: Optional[int]) -> str:
    mapping = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0200: "s2",
        0x0002: "s2",
        0xFEFF: "d1",
        0xFEFD: "d2",
        0xFEFC: "d3",
    }
    if version is None:
        return "00"
    return mapping.get(version, "00")


def _parse_raw_client_hello(payload: bytes) -> Optional[_RawClientHello]:
    body = _tls_handshake_body(payload, 1)
    if body is None or len(body) < 41:
        return None
    pos = 0
    legacy_version = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2 + 32
    if pos >= len(body):
        return None
    session_len = int(body[pos])
    pos += 1 + session_len
    if pos + 2 > len(body):
        return None
    cipher_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    if cipher_len <= 0 or pos + cipher_len > len(body):
        return None
    ciphers = _parse_u16_vector(body[pos : pos + cipher_len])
    pos += cipher_len
    if pos >= len(body):
        return None
    compression_len = int(body[pos])
    pos += 1 + compression_len
    if pos + 2 > len(body):
        extensions: list[tuple[int, bytes]] = []
    else:
        ext_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        extensions = _parse_extensions(body[pos : min(len(body), pos + ext_len)])

    sni: Optional[str] = None
    alpn: list[str] = []
    supported_versions: list[int] = []
    groups: list[int] = []
    ec_points: list[int] = []
    sig_algs: list[int] = []
    ech_present = False
    ext_types: list[int] = []
    for ext_type, ext_data in extensions:
        if not _is_grease(ext_type):
            ext_types.append(ext_type)
        if ext_type == SNI_EXT_TYPE and sni is None:
            sni = _parse_sni_extension(ext_data)
        elif ext_type == ALPN_EXT_TYPE and not alpn:
            alpn = _parse_alpn_extension(ext_data)
        elif ext_type == 43:
            supported_versions = _parse_supported_versions_client(ext_data)
        elif ext_type == 10:
            if len(ext_data) >= 2:
                group_len = int.from_bytes(ext_data[0:2], "big")
                groups = _parse_u16_vector(ext_data[2 : 2 + group_len])
        elif ext_type == 11:
            if ext_data:
                point_len = int(ext_data[0])
                ec_points = [
                    int(value)
                    for value in ext_data[1 : 1 + point_len]
                    if not _is_grease(int(value))
                ]
        elif ext_type == 13:
            if len(ext_data) >= 2:
                sig_len = int.from_bytes(ext_data[0:2], "big")
                sig_algs = _parse_u16_vector(ext_data[2 : 2 + sig_len])
        if ext_type in ECH_EXTENSION_IDS:
            ech_present = True

    negotiated_version = _resolve_raw_tls_version(supported_versions, legacy_version)
    ja3 = (
        f"{legacy_version},{_join_decimal(ciphers)},"
        f"{_join_decimal(ext_types)},{_join_decimal(groups)},"
        f"{_join_decimal(ec_points)}"
    )
    ja3_hash = hashlib.md5(ja3.encode("utf-8", errors="ignore")).hexdigest()
    ja4 = _ja4_from_raw_client_hello(
        version=negotiated_version,
        ciphers=ciphers,
        ext_types=ext_types,
        sig_algs=sig_algs,
        sni=sni,
        alpn=alpn,
    )
    return _RawClientHello(
        legacy_version=legacy_version,
        negotiated_version=negotiated_version,
        sni=sni,
        alpn=tuple(alpn),
        ech_present=ech_present,
        ja3=ja3,
        ja3_hash=ja3_hash,
        ja4=ja4,
    )


def _parse_raw_server_hello(payload: bytes) -> Optional[_RawServerHello]:
    body = _tls_handshake_body(payload, 2)
    if body is None or len(body) < 38:
        return None
    pos = 0
    legacy_version = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2 + 32
    if pos >= len(body):
        return None
    session_len = int(body[pos])
    pos += 1 + session_len
    if pos + 3 > len(body):
        return None
    cipher = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    pos += 1  # compression method
    if pos + 2 > len(body):
        extensions: list[tuple[int, bytes]] = []
    else:
        ext_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        extensions = _parse_extensions(body[pos : min(len(body), pos + ext_len)])

    alpn: list[str] = []
    selected_versions: list[int] = []
    ext_types: list[int] = []
    for ext_type, ext_data in extensions:
        if not _is_grease(ext_type):
            ext_types.append(ext_type)
        if ext_type == ALPN_EXT_TYPE and not alpn:
            alpn = _parse_alpn_extension(ext_data)
        elif ext_type == 43:
            selected_versions = _parse_supported_versions_server(ext_data)
    negotiated_version = _resolve_raw_tls_version(selected_versions, legacy_version)
    ja4s = _ja4s_from_raw_server_hello(
        version=negotiated_version,
        cipher=cipher,
        ext_types=ext_types,
        alpn=alpn,
    )
    return _RawServerHello(
        legacy_version=legacy_version,
        negotiated_version=negotiated_version,
        cipher=cipher,
        alpn=tuple(alpn),
        ja4s=ja4s,
    )


def _cipher_label(value: object) -> str:
    try:
        return f"0x{int(value):04x}"
    except Exception:
        return str(value)


def _is_weak_cipher(value: object) -> bool:
    try:
        if int(str(value), 0) in WEAK_CIPHER_IDS:
            return True
    except Exception:
        pass
    upper = str(value).upper()
    return any(marker in upper for marker in WEAK_CIPHER_MARKERS)


def _ssl2_handshake_type(payload: bytes) -> Optional[int]:
    if not _looks_like_ssl2_record(payload):
        return None
    return int(payload[2])


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _parse_iso_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# JA3/JA4/JA4S construction lives in tls_fingerprints (shared with ips.py).
@memoize_analysis
def analyze_tls(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
    vt_lookup: bool = False,
    target_ip: str | None = None,
    hostname_query: str | None = None,
    port_filter: int | None = None,
    search_query: str | None = None,
) -> TlsSummary:
    errors: list[str] = []
    if TLS is None and TLSClientHello is None and TLSServerHello is None:
        errors.append(
            "Scapy TLS layers unavailable; install scapy[tls] for TLS handshake parsing."
        )
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for TLS analysis.")
        return TlsSummary(
            path=path,
            total_packets=0,
            tls_packets=0,
            tls_like_packets=0,
            client_hellos=0,
            server_hellos=0,
            ech_hellos=0,
            ech_sni_missing=0,
            sni_missing_total=0,
            sni_missing_no_ech=0,
            versions=Counter(),
            cipher_suites=Counter(),
            weak_ciphers=Counter(),
            sni_counts=Counter(),
            alpn_counts=Counter(),
            ja3_counts=Counter(),
            ja4_counts=Counter(),
            ja4s_counts=Counter(),
            sni_to_ja3={},
            sni_to_ja4={},
            ja3_to_sni={},
            ja4_to_sni={},
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            conversations=[],
            http_requests=0,
            http_responses=0,
            http_methods=Counter(),
            http_statuses=Counter(),
            http_urls=Counter(),
            http_user_agents=Counter(),
            http_files=Counter(),
            http_referrers=Counter(),
            http_referrer_request_hosts={},
            http_referrer_hosts=Counter(),
            http_referrer_schemes=Counter(),
            http_referrer_paths=Counter(),
            http_referrer_tokens=Counter(),
            http_referrer_ip_hosts=Counter(),
            http_referrer_present=0,
            http_referrer_missing=0,
            http_referrer_cross_host=0,
            http_referrer_https_to_http=0,
            http_clients=Counter(),
            http_servers=Counter(),
            cert_subjects=Counter(),
            cert_issuers=Counter(),
            cert_sans=Counter(),
            cert_count=0,
            weak_certs=0,
            expired_certs=0,
            self_signed_certs=0,
            cert_artifacts=[],
            analysis_notes=[],
            detections=[],
            artifacts=[],
            errors=errors,
            vt_lookup_enabled=bool(vt_lookup),
            vt_results={},
            vt_errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    tls_packets = 0
    tls_like_packets = 0
    client_hellos = 0
    server_hellos = 0
    ech_hellos = 0
    ech_sni_missing = 0
    versions: Counter[str] = Counter()
    cipher_suites: Counter[str] = Counter()
    weak_ciphers: Counter[str] = Counter()
    sni_counts: Counter[str] = Counter()
    alpn_counts: Counter[str] = Counter()
    ja3_counts: Counter[str] = Counter()
    ja4_counts: Counter[str] = Counter()
    ja4s_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    raw_client_hellos = 0
    raw_server_hellos = 0
    client_hello_counts: Counter[str] = Counter()
    server_hello_counts: Counter[str] = Counter()
    sni_to_ja3: dict[str, Counter[str]] = defaultdict(Counter)
    sni_to_ja4: dict[str, Counter[str]] = defaultdict(Counter)
    ja3_to_sni: dict[str, Counter[str]] = defaultdict(Counter)
    ja4_to_sni: dict[str, Counter[str]] = defaultdict(Counter)
    sni_to_alpn: dict[str, Counter[str]] = defaultdict(Counter)
    client_sni_counts: dict[str, Counter[str]] = defaultdict(Counter)
    server_sni_counts: dict[str, Counter[str]] = defaultdict(Counter)
    server_endpoint_sni_counts: dict[str, Counter[str]] = defaultdict(Counter)
    sni_to_clients: dict[str, Counter[str]] = defaultdict(Counter)
    sni_to_servers: dict[str, Counter[str]] = defaultdict(Counter)
    client_ja3_counts: dict[str, Counter[str]] = defaultdict(Counter)
    client_ja4_counts: dict[str, Counter[str]] = defaultdict(Counter)
    server_ja4s_counts: dict[str, Counter[str]] = defaultdict(Counter)
    server_endpoint_ja4s_counts: dict[str, Counter[str]] = defaultdict(Counter)
    client_alpn_counts: dict[str, Counter[str]] = defaultdict(Counter)
    client_missing_sni: Counter[str] = Counter()
    client_missing_sni_no_ech: Counter[str] = Counter()
    client_ech_counts: Counter[str] = Counter()
    nonstandard_tls_clients: Counter[str] = Counter()
    nonstandard_tls_servers: Counter[str] = Counter()
    sni_no_alpn: Counter[str] = Counter()
    server_cipher_counts: dict[str, Counter[str]] = defaultdict(Counter)
    legacy_version_servers: dict[str, Counter[str]] = defaultdict(Counter)

    conversations: dict[tuple[str, str, int], dict[str, object]] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "first_seen": None,
            "last_seen": None,
            "sni": None,
            "client_hellos": 0,
            "server_hellos": 0,
            "client_bytes": 0,
            "server_bytes": 0,
            "versions": Counter(),
            "alpn": Counter(),
            "ja3": Counter(),
            "ja4": Counter(),
            "ja4s": Counter(),
        }
    )

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    analysis_notes: list[str] = []
    sni_ip_literals: set[str] = set()

    target_ip_value = str(target_ip or "").strip()
    hostname_token = str(hostname_query or "").strip().lower()
    search_token = str(search_query or "").strip().lower()
    port_filter_value = int(port_filter) if isinstance(port_filter, int) else None

    def _get_convo_counter(convo: dict[str, object], key: str) -> Counter[str]:
        value = convo.get(key)
        if isinstance(value, Counter):
            return value
        counter: Counter[str] = Counter()
        convo[key] = counter
        return counter

    def _record_client_hello_observation(
        *,
        client: str,
        server: str,
        server_port: int,
        server_endpoint: str,
        convo: dict[str, object],
        version_label: str,
        sni_val: Optional[str],
        alpn_vals: list[str],
        ech_present: bool,
        ja3_hash: Optional[str],
        ja4: Optional[str],
    ) -> None:
        nonlocal client_hellos, ech_hellos, ech_sni_missing
        client_hellos += 1
        client_hello_counts[client] += 1
        convo["client_hellos"] = int(convo.get("client_hellos", 0) or 0) + 1
        versions[version_label] += 1
        _get_convo_counter(convo, "versions")[version_label] += 1
        if version_label in {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"}:
            legacy_version_servers[version_label][server] += 1
        if sni_val:
            sni_counts[sni_val] += 1
            client_sni_counts[client][sni_val] += 1
            server_sni_counts[server][sni_val] += 1
            server_endpoint_sni_counts[server_endpoint][sni_val] += 1
            sni_to_clients[sni_val][client] += 1
            sni_to_servers[sni_val][server_endpoint] += 1
            if convo.get("sni") is None:
                convo["sni"] = sni_val
            if _is_ip_literal(sni_val):
                sni_ip_literals.add(sni_val)
        else:
            client_missing_sni[client] += 1
            if not ech_present:
                client_missing_sni_no_ech[client] += 1
        if ech_present:
            ech_hellos += 1
            client_ech_counts[client] += 1
            if not sni_val:
                ech_sni_missing += 1
        for alpn in alpn_vals:
            alpn_counts[alpn] += 1
            client_alpn_counts[client][alpn] += 1
            _get_convo_counter(convo, "alpn")[alpn] += 1
            if sni_val:
                sni_to_alpn[sni_val][alpn] += 1
        if sni_val and not alpn_vals:
            sni_no_alpn[sni_val] += 1
        if ja3_hash:
            ja3_counts[ja3_hash] += 1
            client_ja3_counts[client][ja3_hash] += 1
            _get_convo_counter(convo, "ja3")[ja3_hash] += 1
            if sni_val:
                sni_to_ja3[sni_val][ja3_hash] += 1
                ja3_to_sni[ja3_hash][sni_val] += 1
        if ja4:
            ja4_counts[ja4] += 1
            client_ja4_counts[client][ja4] += 1
            _get_convo_counter(convo, "ja4")[ja4] += 1
            if sni_val:
                sni_to_ja4[sni_val][ja4] += 1
                ja4_to_sni[ja4][sni_val] += 1
        if server_port not in TLS_PORTS:
            nonstandard_tls_clients[client] += 1
            nonstandard_tls_servers[server_endpoint] += 1

    def _record_server_hello_observation(
        *,
        server: str,
        server_endpoint: str,
        convo: dict[str, object],
        version_label: str,
        cipher: object | None,
        alpn_vals: list[str],
        ja4s: Optional[str],
    ) -> None:
        nonlocal server_hellos
        server_hellos += 1
        server_hello_counts[server] += 1
        convo["server_hellos"] = int(convo.get("server_hellos", 0) or 0) + 1
        versions[version_label] += 1
        _get_convo_counter(convo, "versions")[version_label] += 1
        if version_label in {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"}:
            legacy_version_servers[version_label][server] += 1
        if cipher is not None:
            cipher_name = _cipher_label(cipher)
            cipher_suites[cipher_name] += 1
            server_cipher_counts[server][cipher_name] += 1
            if _is_weak_cipher(cipher):
                weak_ciphers[cipher_name] += 1
        for alpn in alpn_vals:
            _get_convo_counter(convo, "alpn")[alpn] += 1
        if ja4s:
            ja4s_counts[ja4s] += 1
            server_ja4s_counts[server][ja4s] += 1
            server_endpoint_ja4s_counts[server_endpoint][ja4s] += 1
            _get_convo_counter(convo, "ja4s")[ja4s] += 1

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1
            pkt_len = packet_length(pkt)
            ts = safe_float(getattr(pkt, "time", None))

            src_ip, dst_ip = extract_packet_endpoints(pkt)

            if src_ip and dst_ip and ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp_layer, "sport", 0))
            dport = int(getattr(tcp_layer, "dport", 0))
            payload = bytes(getattr(tcp_layer, "payload", b""))
            if target_ip_value and target_ip_value not in {src_ip or "", dst_ip or ""}:
                continue
            if (
                isinstance(port_filter_value, int)
                and port_filter_value > 0
                and sport != port_filter_value
                and dport != port_filter_value
            ):
                continue
            payload_text_lc = ""
            if hostname_token or search_token:
                payload_text_lc = decode_payload(
                    payload, encoding="utf-8", limit=4096
                ).lower()
                if hostname_token and not (
                    hostname_token in payload_text_lc
                    or hostname_token in str(src_ip or "").lower()
                    or hostname_token in str(dst_ip or "").lower()
                ):
                    continue
                if search_token and not (
                    search_token in payload_text_lc
                    or search_token in str(src_ip or "").lower()
                    or search_token in str(dst_ip or "").lower()
                    or search_token in str(sport)
                    or search_token in str(dport)
                ):
                    continue

            is_tls_layer = TLS is not None and pkt.haslayer(TLS)  # type: ignore[truthy-bool]
            has_scapy_client_hello = (
                TLSClientHello is not None and pkt.haslayer(TLSClientHello)
            )
            has_scapy_server_hello = (
                TLSServerHello is not None and pkt.haslayer(TLSServerHello)
            )
            is_tls_like_record = _looks_like_tls_record(payload)
            is_ssl2_like_record = _looks_like_ssl2_record(payload)
            is_tls_like = is_tls_like_record or is_ssl2_like_record
            raw_client_hello = (
                None
                if has_scapy_client_hello
                else _parse_raw_client_hello(payload)
                if is_tls_like_record
                else None
            )
            raw_server_hello = (
                None
                if has_scapy_server_hello
                else _parse_raw_server_hello(payload)
                if is_tls_like_record
                else None
            )
            is_tls_handshake = (
                has_scapy_client_hello
                or has_scapy_server_hello
                or raw_client_hello is not None
                or raw_server_hello is not None
            )
            if not is_tls_layer and not is_tls_handshake and not is_tls_like:
                continue

            tls_like_packets += 1
            if is_tls_layer or is_tls_handshake:
                tls_packets += 1

            handshake_type = None
            if is_tls_like and not (dport in TLS_PORTS or sport in TLS_PORTS):
                if raw_server_hello is not None:
                    handshake_type = 2
                elif raw_client_hello is not None:
                    handshake_type = 1
                elif is_tls_like_record:
                    handshake_type = _tls_handshake_type(payload)
                elif is_ssl2_like_record:
                    ssl2_type = _ssl2_handshake_type(payload)
                    if ssl2_type == 4:
                        handshake_type = 2
                    elif ssl2_type == 1:
                        handshake_type = 1
            if dport in TLS_PORTS:
                client = src_ip or "-"
                server = dst_ip or "-"
                server_port = dport
            elif sport in TLS_PORTS:
                client = dst_ip or "-"
                server = src_ip or "-"
                server_port = sport
            elif handshake_type == 2:
                client = dst_ip or "-"
                server = src_ip or "-"
                server_port = sport
            elif handshake_type == 1:
                client = src_ip or "-"
                server = dst_ip or "-"
                server_port = dport
            else:
                client = src_ip or "-"
                server = dst_ip or "-"
                server_port = dport

            client_counts[client] += 1
            server_counts[server] += 1
            server_ports[server_port] += 1

            convo_key = (client, server, server_port)
            server_endpoint = f"{server}:{server_port}"
            convo = conversations[convo_key]
            convo["packets"] = int(convo["packets"]) + 1
            convo["bytes"] = int(convo["bytes"]) + pkt_len
            if src_ip == client:
                convo["client_bytes"] = int(convo["client_bytes"]) + pkt_len
            elif src_ip == server:
                convo["server_bytes"] = int(convo["server_bytes"]) + pkt_len
            if ts is not None:
                if convo["first_seen"] is None or ts < convo["first_seen"]:
                    convo["first_seen"] = ts
                if convo["last_seen"] is None or ts > convo["last_seen"]:
                    convo["last_seen"] = ts

            if not is_tls_handshake:
                record_version = _record_version_label(payload)
                if record_version:
                    versions[record_version] += 1
                    convo_versions = convo.get("versions")
                    if isinstance(convo_versions, Counter):
                        convo_versions[record_version] += 1
                    if record_version in {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"}:
                        legacy_version_servers[record_version][server] += 1

            if TLSClientHello is not None and pkt.haslayer(TLSClientHello):  # type: ignore[truthy-bool]
                client_hello = pkt[TLSClientHello]  # type: ignore[index]
                client_ver = _tls_version_label(
                    _resolve_negotiated_version(
                        client_hello, getattr(client_hello, "version", "?")
                    )
                )
                sni_val = None
                alpn_vals: list[str] = []
                ech_present = False
                for ext in _iter_tls_extensions(client_hello):
                    if sni_val is None:
                        sni_val = _extract_sni(ext)
                    if not alpn_vals:
                        alpn_vals = _extract_alpn(ext)
                    if not ech_present and _is_ech_extension(ext):
                        ech_present = True

                ja3_hash = None
                ja3 = _ja3_from_client_hello(client_hello)
                if ja3:
                    ja3_hash = hashlib.md5(
                        ja3.encode("utf-8", errors="ignore")
                    ).hexdigest()

                ja4 = _ja4_from_client_hello(client_hello, sni_val, alpn_vals)
                _record_client_hello_observation(
                    client=client,
                    server=server,
                    server_port=server_port,
                    server_endpoint=server_endpoint,
                    convo=convo,
                    version_label=client_ver,
                    sni_val=sni_val,
                    alpn_vals=alpn_vals,
                    ech_present=ech_present,
                    ja3_hash=ja3_hash,
                    ja4=ja4,
                )
            elif raw_client_hello is not None:
                raw_client_hellos += 1
                _record_client_hello_observation(
                    client=client,
                    server=server,
                    server_port=server_port,
                    server_endpoint=server_endpoint,
                    convo=convo,
                    version_label=_tls_version_label(
                        raw_client_hello.negotiated_version
                    ),
                    sni_val=raw_client_hello.sni,
                    alpn_vals=list(raw_client_hello.alpn),
                    ech_present=raw_client_hello.ech_present,
                    ja3_hash=raw_client_hello.ja3_hash,
                    ja4=raw_client_hello.ja4,
                )

            if TLSServerHello is not None and pkt.haslayer(TLSServerHello):  # type: ignore[truthy-bool]
                server_hello = pkt[TLSServerHello]  # type: ignore[index]
                server_ver = _tls_version_label(
                    _resolve_negotiated_version(
                        server_hello, getattr(server_hello, "version", "?")
                    )
                )
                cipher = getattr(server_hello, "cipher", None)

                server_alpn: list[str] = []
                for ext in _iter_tls_extensions(server_hello):
                    if not server_alpn:
                        server_alpn = _extract_alpn(ext)
                ja4s = _ja4s_from_server_hello(server_hello, server_alpn)
                _record_server_hello_observation(
                    server=server,
                    server_endpoint=server_endpoint,
                    convo=convo,
                    version_label=server_ver,
                    cipher=cipher,
                    alpn_vals=server_alpn,
                    ja4s=ja4s,
                )
            elif raw_server_hello is not None:
                raw_server_hellos += 1
                _record_server_hello_observation(
                    server=server,
                    server_endpoint=server_endpoint,
                    convo=convo,
                    version_label=_tls_version_label(
                        raw_server_hello.negotiated_version
                    ),
                    cipher=raw_server_hello.cipher,
                    alpn_vals=list(raw_server_hello.alpn),
                    ja4s=raw_server_hello.ja4s,
                )

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows: list[TlsConversation] = []
    client_handshake_failures: Counter[str] = Counter()
    server_handshake_failures: Counter[str] = Counter()
    for (client, server, port), data in conversations.items():
        conv_client_hellos = int(data.get("client_hellos", 0) or 0)
        conv_server_hellos = int(data.get("server_hellos", 0) or 0)
        failed_hellos = max(0, conv_client_hellos - conv_server_hellos)
        if failed_hellos:
            client_handshake_failures[client] += failed_hellos
            server_handshake_failures[f"{server}:{port}"] += failed_hellos
        conv_versions = data.get("versions")
        conv_alpn = data.get("alpn")
        conv_ja3 = data.get("ja3")
        conv_ja4 = data.get("ja4")
        conv_ja4s = data.get("ja4s")
        conversation_rows.append(
            TlsConversation(
                client_ip=client,
                server_ip=server,
                server_port=port,
                packets=int(data["packets"]),
                bytes=int(data["bytes"]),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                sni=data.get("sni"),
                client_hellos=conv_client_hellos,
                server_hellos=conv_server_hellos,
                client_bytes=int(data.get("client_bytes", 0) or 0),
                server_bytes=int(data.get("server_bytes", 0) or 0),
                versions=tuple(conv_versions.keys())
                if isinstance(conv_versions, Counter)
                else (),
                alpn=tuple(conv_alpn.keys()) if isinstance(conv_alpn, Counter) else (),
                ja3=tuple(conv_ja3.keys()) if isinstance(conv_ja3, Counter) else (),
                ja4=tuple(conv_ja4.keys()) if isinstance(conv_ja4, Counter) else (),
                ja4s=tuple(conv_ja4s.keys()) if isinstance(conv_ja4s, Counter) else (),
            )
        )

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(
            path, show_status, f"TLS: {desc}", func, *args, **kwargs
        )

    http_summary = _busy(
        "HTTP",
        analyze_http,
        path,
        show_status=False,
        packets=packets,
        meta=meta,
        vt_lookup=vt_lookup,
        target_ip=target_ip_value or None,
        hostname_query=hostname_token or None,
        port_filter=port_filter_value,
        search_query=search_token or None,
    )
    cert_summary = _busy("Certificates", analyze_certificates, path, show_status=False)
    allowed_tls_ips = {
        ip
        for conv in conversation_rows
        for ip in (conv.client_ip, conv.server_ip)
        if str(ip).strip()
    }

    def _cert_matches_filters(cert: CertificateInfo) -> bool:
        if target_ip_value and target_ip_value not in {cert.src_ip, cert.dst_ip}:
            return False
        if (
            isinstance(port_filter_value, int)
            and port_filter_value > 0
            and allowed_tls_ips
            and cert.src_ip not in allowed_tls_ips
            and cert.dst_ip not in allowed_tls_ips
        ):
            return False
        if hostname_token:
            host_blob = " ".join(
                [
                    str(cert.sni or ""),
                    str(cert.subject or ""),
                    str(cert.issuer or ""),
                    str(cert.san or ""),
                ]
            ).lower()
            if hostname_token not in host_blob:
                return False
        if search_token:
            blob = " ".join(
                [
                    str(cert.sni or ""),
                    str(cert.subject or ""),
                    str(cert.issuer or ""),
                    str(cert.san or ""),
                    str(cert.src_ip or ""),
                    str(cert.dst_ip or ""),
                    str(cert.pubkey_type or ""),
                    str(cert.pubkey_size or ""),
                    str(cert.not_before or ""),
                    str(cert.not_after or ""),
                    str(cert.sig_algo or ""),
                ]
            ).lower()
            if search_token not in blob:
                return False
        return True

    filtered_cert_artifacts = [
        cert for cert in cert_summary.artifacts if _cert_matches_filters(cert)
    ]
    cert_subjects: Counter[str] = Counter(cert.subject for cert in filtered_cert_artifacts)
    cert_issuers: Counter[str] = Counter(cert.issuer for cert in filtered_cert_artifacts)
    cert_sans: Counter[str] = Counter(cert.san for cert in filtered_cert_artifacts)
    cert_count = len(filtered_cert_artifacts)
    weak_certs = sum(
        1
        for cert in filtered_cert_artifacts
        if is_weak_pubkey(
            str(getattr(cert, "pubkey_type", "")),
            int(getattr(cert, "pubkey_size", 0) or 0),
        )
    )
    expired_certs = 0
    self_signed_certs = 0
    for cert in filtered_cert_artifacts:
        if str(cert.subject or "").strip() and str(cert.subject) == str(cert.issuer):
            self_signed_certs += 1
        end_dt = _parse_iso_ts(cert.not_after)
        if end_dt is not None and end_dt < datetime.now(timezone.utc):
            expired_certs += 1

    def _cert_endpoint_marker(cert: CertificateInfo) -> str:
        host = str(cert.sni or "").strip() or str(cert.dst_ip or "").strip() or "-"
        flow = f"{cert.src_ip}->{cert.dst_ip}"
        return f"{host} [{flow}]"

    weak_cert_endpoints: Counter[str] = Counter()
    expired_cert_endpoints: Counter[str] = Counter()
    self_signed_endpoints: Counter[str] = Counter()
    now_dt = datetime.now(timezone.utc)
    for cert in filtered_cert_artifacts:
        marker = _cert_endpoint_marker(cert)
        if is_weak_pubkey(
            str(getattr(cert, "pubkey_type", "")),
            int(getattr(cert, "pubkey_size", 0) or 0),
        ):
            weak_cert_endpoints[marker] += 1
        if str(cert.subject or "").strip() and str(cert.subject) == str(cert.issuer):
            self_signed_endpoints[marker] += 1
        end_dt = _parse_iso_ts(cert.not_after)
        if end_dt is not None and end_dt < now_dt:
            expired_cert_endpoints[marker] += 1

    if tls_like_packets and tls_packets == 0:
        analysis_notes.append(
            "TLS record headers detected without parsed TLS handshakes; ensure scapy TLS support or provide full streams."
        )
    elif tls_like_packets > tls_packets:
        analysis_notes.append(
            f"{tls_like_packets - tls_packets} TLS-like packet(s) were detected without full handshake parsing."
        )
    if raw_client_hellos or raw_server_hellos:
        analysis_notes.append(
            f"Raw TLS parser recovered {raw_client_hellos} client hello(s) and {raw_server_hellos} server hello(s) that Scapy did not expose as TLS layers."
        )
    if client_hellos and not server_hellos:
        analysis_notes.append(
            "Client hellos observed without any server hellos (possible blocked/failed handshakes)."
        )
    if ech_hellos:
        analysis_notes.append(
            "ECH (Encrypted ClientHello) observed; SNI may be intentionally hidden."
        )
    if http_summary.total_requests or http_summary.total_responses:
        analysis_notes.append(
            "HTTP statistics are capture-wide; use --http for full plaintext context."
        )

    detections: list[dict[str, object]] = []
    legacy_versions = [
        v for v in ("SSLv2", "SSLv3", "TLS1.0", "TLS1.1") if versions.get(v)
    ]
    if legacy_versions:
        legacy_hosts: Counter[str] = Counter()
        for version in legacy_versions:
            legacy_hosts.update(legacy_version_servers.get(version, Counter()))
        host_evidence = [
            (host, count)
            for host, count in legacy_hosts.most_common(8)
            if host and host != "-"
        ]
        details = f"Versions: {', '.join(legacy_versions)}"
        if host_evidence:
            details += " | Service Hosts: " + ", ".join(
                f"{host}({count})" for host, count in host_evidence[:5]
            )
        detections.append(
            {
                "severity": "warning",
                "summary": "Legacy TLS versions observed",
                "details": details,
                "top_destinations": host_evidence,
            }
        )

    # Known-malicious / offensive-tool JA3 fingerprint matches (abuse.ch SSLBL
    # + public C2 research). A malware-family fingerprint is a strong hunting
    # lead (HIGH); the C2-socket fingerprints collide with benign Windows TLS
    # so they are surfaced at INFO with the collision caveat in the detail.
    for ja3_hash, count in ja3_counts.items():
        intel = lookup_ja3_intel(ja3_hash)
        if not intel:
            continue
        label, confidence = intel
        sni_ctx = ja3_to_sni.get(ja3_hash, Counter())
        sni_hosts = ", ".join(host for host, _ in sni_ctx.most_common(5)) or "-"
        if confidence == "low":
            severity = "info"
            qualifier = " (low-confidence: this TLS socket is also used by benign software — corroborate with beacon timing / destination reputation)"
        else:
            severity = "high"
            qualifier = ""
        detections.append(
            {
                "severity": severity,
                "summary": f"Known-malicious JA3 fingerprint: {label}",
                "details": (
                    f"JA3 {ja3_hash} matches threat intel ({label}); {count} "
                    f"handshake(s), SNI: {sni_hosts}{qualifier}."
                ),
                "source": "TLS",
            }
        )

    missing_sni_total = client_hellos - sum(sni_counts.values())
    missing_sni_no_ech = max(0, missing_sni_total - ech_sni_missing)
    if (
        client_hellos >= 20
        and missing_sni_no_ech >= 10
        and (missing_sni_no_ech / max(client_hellos, 1)) >= 0.35
    ):
        client_evidence = ", ".join(
            f"{client}({count}/{client_hello_counts.get(client, 0)})"
            for client, count in client_missing_sni_no_ech.most_common(6)
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "High rate of TLS handshakes without SNI",
                "details": (
                    f"{missing_sni_no_ech}/{client_hellos} client hello(s) missing SNI "
                    f"(excluding ECH)."
                    + (f" Top clients: {client_evidence}." if client_evidence else "")
                ),
            }
        )

    sni_evasion_clients: list[tuple[str, int, int]] = []
    for client, missing_count in client_missing_sni_no_ech.items():
        total_for_client = int(client_hello_counts.get(client, 0))
        if total_for_client >= 5 and missing_count >= 5:
            ratio = missing_count / max(total_for_client, 1)
            if ratio >= 0.7:
                sni_evasion_clients.append((client, int(missing_count), total_for_client))
    if sni_evasion_clients:
        sni_evasion_clients.sort(key=lambda row: (row[1] / max(row[2], 1), row[1]), reverse=True)
        details = ", ".join(
            f"{client} missing_sni={missing}/{total}"
            for client, missing, total in sni_evasion_clients[:6]
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "Client-specific SNI suppression pattern",
                "details": details,
                "top_clients": [(client, missing) for client, missing, _ in sni_evasion_clients[:8]],
            }
        )

    if client_hellos >= 20 and server_hellos < client_hellos:
        failed = client_hellos - server_hellos
        ratio = failed / client_hellos
        if failed >= 10 and ratio >= 0.35:
            severity = "high" if ratio >= 0.65 else "warning"
            client_evidence = ", ".join(
                f"{client}({count})"
                for client, count in client_handshake_failures.most_common(6)
            )
            server_evidence = ", ".join(
                f"{server}({count})"
                for server, count in server_handshake_failures.most_common(6)
            )
            detections.append(
                {
                    "severity": severity,
                    "summary": "TLS handshake failures",
                    "details": (
                        f"{failed}/{client_hellos} client hello(s) without server hello response."
                        + (f" Clients: {client_evidence}." if client_evidence else "")
                        + (f" Destinations: {server_evidence}." if server_evidence else "")
                    ),
                }
            )

    high_entropy_sni = [
        sni
        for sni, count in sni_counts.items()
        if count >= 3 and len(sni) >= 18 and _shannon_entropy(sni) >= 3.85
    ]
    if high_entropy_sni:
        detections.append(
            {
                "severity": "warning",
                "summary": "High-entropy SNI values",
                "details": ", ".join(high_entropy_sni[:5]),
            }
        )

    suspicious_sni = [
        sni
        for sni, count in sni_counts.items()
        if count >= 2 and any(sni.endswith(tld) for tld in SUSPICIOUS_TLDS)
    ]
    if suspicious_sni:
        detections.append(
            {
                "severity": "high",
                "summary": "Suspicious SNI TLDs observed",
                "details": ", ".join(suspicious_sni[:5]),
            }
        )

    if len(sni_ip_literals) >= 2:
        detections.append(
            {
                "severity": "warning",
                "summary": "SNI uses IP literal",
                "details": ", ".join(sorted(sni_ip_literals)[:5]),
            }
        )

    non_standard_ports = [
        (port, count)
        for port, count in server_ports.items()
        if port not in TLS_PORTS and count >= 20
    ]
    if non_standard_ports:
        ports_text = ", ".join(
            f"{port}({count})" for port, count in sorted(non_standard_ports)[:8]
        )
        client_text = ", ".join(
            f"{client}({count})"
            for client, count in nonstandard_tls_clients.most_common(6)
        )
        server_text = ", ".join(
            f"{server}({count})"
            for server, count in nonstandard_tls_servers.most_common(6)
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "Significant TLS on non-standard ports",
                "details": (
                    f"Ports: {ports_text}"
                    + (f" | Clients: {client_text}" if client_text else "")
                    + (f" | Services: {server_text}" if server_text else "")
                ),
            }
        )

    if weak_ciphers:
        top_weak = ", ".join(name for name, _count in weak_ciphers.most_common(5))
        detections.append(
            {
                "severity": "warning",
                "summary": "Weak TLS cipher suites observed",
                "details": top_weak,
            }
        )

    if self_signed_certs:
        sev = "warning" if self_signed_certs >= 3 else "info"
        endpoint_rows = self_signed_endpoints.most_common(6)
        endpoint_text = ", ".join(
            f"{host}({count})" for host, count in endpoint_rows
        )
        detections.append(
            {
                "severity": sev,
                "summary": "Self-signed TLS certificates observed",
                "details": (
                    f"Count: {self_signed_certs}"
                    + (f" | Hosts: {endpoint_text}" if endpoint_text else "")
                ),
                "top_destinations": endpoint_rows,
            }
        )
    if expired_certs:
        sev = "high" if expired_certs >= 3 else "warning"
        endpoint_rows = expired_cert_endpoints.most_common(6)
        endpoint_text = ", ".join(
            f"{host}({count})" for host, count in endpoint_rows
        )
        detections.append(
            {
                "severity": sev,
                "summary": "Expired TLS certificates observed",
                "details": (
                    f"Count: {expired_certs}"
                    + (f" | Hosts: {endpoint_text}" if endpoint_text else "")
                ),
                "top_destinations": endpoint_rows,
            }
        )
    if weak_certs:
        sev = "high" if weak_certs >= 2 else "warning"
        endpoint_rows = weak_cert_endpoints.most_common(6)
        endpoint_text = ", ".join(
            f"{host}({count})" for host, count in endpoint_rows
        )
        detections.append(
            {
                "severity": sev,
                "summary": "Weak TLS certificate keys",
                "details": (
                    f"Count: {weak_certs}"
                    + (f" | Hosts: {endpoint_text}" if endpoint_text else "")
                ),
                "top_destinations": endpoint_rows,
            }
        )

    rotating_sni: list[tuple[str, int, int]] = []
    certs_by_sni: dict[str, set[str]] = defaultdict(set)
    cert_obs_by_sni: Counter[str] = Counter()
    for cert in filtered_cert_artifacts:
        if not cert.sni:
            continue
        sni_key = str(cert.sni).lower()
        sha256 = str(cert.sha256 or "").strip()
        if not sha256 or sha256 == "-":
            continue
        certs_by_sni[sni_key].add(sha256)
        cert_obs_by_sni[sni_key] += 1
    for sni_key, hashes in certs_by_sni.items():
        obs = int(cert_obs_by_sni.get(sni_key, 0))
        if len(hashes) >= 3 and obs >= 3:
            rotating_sni.append((sni_key, len(hashes), obs))
    if rotating_sni:
        rotating_sni.sort(key=lambda row: (row[1], row[2]), reverse=True)
        details = ", ".join(
            f"{sni} certs={uniq}/{obs}" for sni, uniq, obs in rotating_sni[:6]
        )
        detections.append(
            {
                "severity": "high",
                "summary": "Certificate pinning drift / rapid cert rotation",
                "details": details,
            }
        )

    rare_ja3 = [fp for fp, count in ja3_counts.items() if int(count) == 1]
    if client_hellos >= 20 and len(rare_ja3) >= 5:
        detections.append(
            {
                "severity": "warning",
                "summary": "JA3 novelty / rarity spike",
                "details": f"Rare JA3 fingerprints={len(rare_ja3)} of {len(ja3_counts)} total",
            }
        )

    rare_ja4 = [fp for fp, count in ja4_counts.items() if int(count) == 1]
    if client_hellos >= 20 and len(rare_ja4) >= 5:
        detections.append(
            {
                "severity": "warning",
                "summary": "JA4 novelty / rarity spike",
                "details": f"Rare JA4 fingerprints={len(rare_ja4)} of {len(ja4_counts)} total",
            }
        )

    ja3_fanout = []
    for fp, sni_counter in ja3_to_sni.items():
        unique_sni = len(sni_counter)
        total = sum(int(v) for v in sni_counter.values())
        if unique_sni >= 8 and total >= 20:
            ja3_fanout.append((fp, unique_sni, total))
    if ja3_fanout:
        ja3_fanout.sort(key=lambda row: (row[1], row[2]), reverse=True)
        details = ", ".join(f"{fp} sni={u} obs={t}" for fp, u, t in ja3_fanout[:5])
        detections.append(
            {
                "severity": "high",
                "summary": "JA3 to SNI cardinality anomaly",
                "details": details,
            }
        )

    sni_fanout = []
    for sni, fp_counter in sni_to_ja3.items():
        unique_fp = len(fp_counter)
        total = sum(int(v) for v in fp_counter.values())
        if unique_fp >= 6 and total >= 15:
            sni_fanout.append((sni, unique_fp, total))
    if sni_fanout:
        sni_fanout.sort(key=lambda row: (row[1], row[2]), reverse=True)
        details = ", ".join(f"{sni} ja3={u} obs={t}" for sni, u, t in sni_fanout[:5])
        detections.append(
            {
                "severity": "warning",
                "summary": "SNI to JA3 cardinality anomaly",
                "details": details,
            }
        )

    downgrade_servers: list[tuple[str, int, int]] = []
    for server, counter in server_cipher_counts.items():
        weak = 0
        modern = 0
        for name, count in counter.items():
            if _is_weak_cipher(name):
                weak += int(count)
            else:
                modern += int(count)
        if weak >= 3 and modern >= 3:
            downgrade_servers.append((server, weak, modern))
    if downgrade_servers:
        downgrade_servers.sort(key=lambda row: row[1], reverse=True)
        details = ", ".join(
            f"{srv} weak={weak} modern={modern}"
            for srv, weak, modern in downgrade_servers[:6]
        )
        detections.append(
            {
                "severity": "high",
                "summary": "Cipher downgrade inconsistency by endpoint",
                "details": details,
            }
        )

    unknown_alpn = [
        (name, count)
        for name, count in alpn_counts.items()
        if str(name).lower() not in COMMON_ALPN_TOKENS and int(count) >= 3
    ]
    if unknown_alpn:
        unknown_alpn.sort(key=lambda row: row[1], reverse=True)
        details = ", ".join(f"{name}({count})" for name, count in unknown_alpn[:8])
        detections.append(
            {
                "severity": "warning",
                "summary": "ALPN mismatch / uncommon protocol tokens",
                "details": details,
            }
        )

    no_alpn_hotspots = []
    for sni, miss in sni_no_alpn.items():
        total = int(sni_counts.get(sni, 0))
        if total >= 5 and (miss / max(total, 1)) >= 0.7:
            no_alpn_hotspots.append((sni, miss, total))
    if no_alpn_hotspots:
        no_alpn_hotspots.sort(key=lambda row: row[1], reverse=True)
        details = ", ".join(
            f"{sni} no_alpn={miss}/{total}" for sni, miss, total in no_alpn_hotspots[:6]
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "ALPN missing anomaly",
                "details": details,
            }
        )

    very_short = 0
    very_long = 0
    for cert in filtered_cert_artifacts:
        start = _parse_iso_ts(cert.not_before)
        end = _parse_iso_ts(cert.not_after)
        if start is None or end is None:
            continue
        validity_days = (end - start).total_seconds() / 86400.0
        if validity_days <= 14:
            very_short += 1
        elif validity_days >= 825:
            very_long += 1
    if very_short or very_long:
        sev = "high" if very_short >= 2 else "warning"
        detections.append(
            {
                "severity": sev,
                "summary": "Certificate validity outliers",
                "details": f"short_lived={very_short}, long_lived={very_long}",
            }
        )

    impersonation_hits: list[str] = []
    for cert in filtered_cert_artifacts:
        blob = f"{cert.subject} {cert.san}".lower()
        if not any(keyword in blob for keyword in BRAND_KEYWORDS):
            continue
        # A self-signed *CA* (root/intermediate) legitimately has subject==issuer
        # and carries the brand name; only a self-signed leaf is impersonation.
        suspicious = (
            cert.subject == cert.issuer and not getattr(cert, "is_ca", False)
        ) or is_weak_pubkey(
            str(getattr(cert, "pubkey_type", "")),
            int(getattr(cert, "pubkey_size", 0) or 0),
        )
        if cert.sni and any(
            str(cert.sni).lower().endswith(tld) for tld in SUSPICIOUS_TLDS
        ):
            suspicious = True
        if suspicious:
            marker = cert.sni or cert.dst_ip or cert.subject
            impersonation_hits.append(str(marker))
    if impersonation_hits:
        unique_hits = sorted(set(impersonation_hits))
        detections.append(
            {
                "severity": "high",
                "summary": "Issuer/SAN brand impersonation heuristics",
                "details": ", ".join(unique_hits[:8]),
            }
        )

    periodic_candidates: list[tuple[str, str, int, float]] = []
    for conv in conversation_rows:
        if conv.first_seen is None or conv.last_seen is None:
            continue
        if int(conv.packets) < 12:
            continue
        duration = max(0.0, float(conv.last_seen) - float(conv.first_seen))
        if duration < 60.0:
            continue
        avg_gap = duration / max(int(conv.packets) - 1, 1)
        if 5.0 <= avg_gap <= 300.0:
            periodic_candidates.append(
                (conv.client_ip, conv.server_ip, conv.server_port, avg_gap)
            )
    if periodic_candidates:
        periodic_candidates.sort(key=lambda row: row[3])
        details = ", ".join(
            f"{src}->{dst}:{port} avg={gap:.1f}s"
            for src, dst, port, gap in periodic_candidates[:6]
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "TLS handshake periodicity proxy",
                "details": details,
            }
        )

    resumed_proxy = False
    if (
        client_hellos >= 30
        and server_hellos >= int(client_hellos * 0.9)
        and cert_count <= max(3, client_hellos // 20)
    ):
        resumed_proxy = True
    if resumed_proxy:
        detections.append(
            {
                "severity": "info",
                "summary": "Potential session resumption-heavy TLS behavior",
                "details": f"client_hellos={client_hellos}, server_hellos={server_hellos}, certs={cert_count}",
            }
        )

    artifacts: list[str] = []
    for sni, count in sni_counts.most_common(10):
        artifacts.append(f"SNI: {sni} ({count})")
    for alpn, count in alpn_counts.most_common(5):
        artifacts.append(f"ALPN: {alpn} ({count})")
    for ja3, count in ja3_counts.most_common(5):
        artifacts.append(f"JA3: {ja3} ({count})")
    for cert in filtered_cert_artifacts[:5]:
        sha256 = str(getattr(cert, "sha256", "") or "").strip()
        if not sha256 or sha256 == "-":
            continue
        service = str(getattr(cert, "sni", "") or getattr(cert, "dst_ip", "") or "-")
        serial = str(getattr(cert, "serial", "") or "-")
        artifacts.append(f"Cert SHA256: {sha256} serial={serial} service={service}")

    vt_results: dict[str, dict[str, object]] = {}
    vt_errors: list[str] = []
    if vt_lookup:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            vt_errors.append("VT_API_KEY is not set; skipping VirusTotal lookups.")
        else:
            candidate_domains = [
                str(name).strip().lower().strip(".")
                for name, _count in sni_counts.most_common(80)
                if str(name).strip()
            ]
            candidate_domains = [name for name in candidate_domains if "." in name]
            if candidate_domains:
                vt_results, vt_errors = _vt_lookup_domains(candidate_domains, api_key)
                vt_hits = [
                    info
                    for info in vt_results.values()
                    if int(info.get("malicious", 0) or 0) > 0
                    or int(info.get("suspicious", 0) or 0) > 0
                ]
                if vt_hits:
                    top_hit = sorted(
                        vt_hits,
                        key=lambda item: (
                            int(item.get("malicious", 0) or 0),
                            int(item.get("suspicious", 0) or 0),
                        ),
                        reverse=True,
                    )[0]
                    detections.append(
                        {
                            "source": "VirusTotal",
                            "severity": "high"
                            if int(top_hit.get("malicious", 0) or 0) > 0
                            else "warning",
                            "summary": "VirusTotal SNI/domain reputation hit",
                            "details": (
                                f"{len(vt_hits)} TLS SNI target(s) flagged by VT enrichment."
                            ),
                        }
                    )

    return TlsSummary(
        path=path,
        total_packets=total_packets,
        tls_packets=tls_packets,
        tls_like_packets=tls_like_packets,
        client_hellos=client_hellos,
        server_hellos=server_hellos,
        ech_hellos=ech_hellos,
        ech_sni_missing=ech_sni_missing,
        sni_missing_total=missing_sni_total,
        sni_missing_no_ech=missing_sni_no_ech,
        versions=versions,
        cipher_suites=cipher_suites,
        weak_ciphers=weak_ciphers,
        sni_counts=sni_counts,
        alpn_counts=alpn_counts,
        ja3_counts=ja3_counts,
        ja4_counts=ja4_counts,
        ja4s_counts=ja4s_counts,
        sni_to_ja3={key: Counter(val) for key, val in sni_to_ja3.items()},
        sni_to_ja4={key: Counter(val) for key, val in sni_to_ja4.items()},
        ja3_to_sni={key: Counter(val) for key, val in ja3_to_sni.items()},
        ja4_to_sni={key: Counter(val) for key, val in ja4_to_sni.items()},
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        conversations=sorted(conversation_rows, key=lambda c: c.packets, reverse=True),
        http_requests=http_summary.total_requests,
        http_responses=http_summary.total_responses,
        http_methods=http_summary.method_counts,
        http_statuses=http_summary.status_counts,
        http_urls=http_summary.url_counts,
        http_user_agents=http_summary.user_agents,
        http_files=http_summary.file_artifacts,
        http_referrers=http_summary.referrer_counts,
        http_referrer_request_hosts=http_summary.referrer_request_host_counts,
        http_referrer_hosts=http_summary.referrer_host_counts,
        http_referrer_schemes=http_summary.referrer_scheme_counts,
        http_referrer_paths=http_summary.referrer_path_counts,
        http_referrer_tokens=http_summary.referrer_token_counts,
        http_referrer_ip_hosts=http_summary.referrer_ip_hosts,
        http_referrer_present=http_summary.referrer_present,
        http_referrer_missing=http_summary.referrer_missing,
        http_referrer_cross_host=http_summary.referrer_cross_host,
        http_referrer_https_to_http=http_summary.referrer_https_to_http,
        http_clients=http_summary.client_counts,
        http_servers=http_summary.server_counts,
        cert_subjects=cert_subjects,
        cert_issuers=cert_issuers,
        cert_sans=cert_sans,
        cert_count=cert_count,
        weak_certs=weak_certs,
        expired_certs=expired_certs,
        self_signed_certs=self_signed_certs,
        cert_artifacts=list(filtered_cert_artifacts),
        analysis_notes=analysis_notes,
        detections=detections,
        artifacts=artifacts,
        errors=errors + http_summary.errors + cert_summary.errors + vt_errors,
        vt_lookup_enabled=bool(vt_lookup),
        vt_results=vt_results,
        vt_errors=vt_errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        raw_client_hellos=raw_client_hellos,
        raw_server_hellos=raw_server_hellos,
        client_hello_counts=client_hello_counts,
        server_hello_counts=server_hello_counts,
        client_sni_counts={
            key: Counter(val) for key, val in client_sni_counts.items()
        },
        server_sni_counts={
            key: Counter(val) for key, val in server_sni_counts.items()
        },
        server_endpoint_sni_counts={
            key: Counter(val) for key, val in server_endpoint_sni_counts.items()
        },
        sni_to_clients={key: Counter(val) for key, val in sni_to_clients.items()},
        sni_to_servers={key: Counter(val) for key, val in sni_to_servers.items()},
        client_ja3_counts={
            key: Counter(val) for key, val in client_ja3_counts.items()
        },
        client_ja4_counts={
            key: Counter(val) for key, val in client_ja4_counts.items()
        },
        server_ja4s_counts={
            key: Counter(val) for key, val in server_ja4s_counts.items()
        },
        server_endpoint_ja4s_counts={
            key: Counter(val) for key, val in server_endpoint_ja4s_counts.items()
        },
        client_alpn_counts={
            key: Counter(val) for key, val in client_alpn_counts.items()
        },
        client_missing_sni=client_missing_sni,
        client_missing_sni_no_ech=client_missing_sni_no_ech,
        client_ech_counts=client_ech_counts,
        client_handshake_failures=client_handshake_failures,
        server_handshake_failures=server_handshake_failures,
        nonstandard_tls_clients=nonstandard_tls_clients,
        nonstandard_tls_servers=nonstandard_tls_servers,
    )
