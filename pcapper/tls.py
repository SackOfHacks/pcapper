from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import hashlib
import math
import ipaddress

from .pcap_cache import get_reader
from .utils import safe_float
from .http import analyze_http
from .certificates import analyze_certificates, CertificateInfo
from .progress import run_with_busy_status

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore

try:
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello  # type: ignore
    from scapy.layers.tls.record import TLS  # type: ignore
except Exception:  # pragma: no cover
    TLSClientHello = None  # type: ignore
    TLSServerHello = None  # type: ignore
    TLS = None  # type: ignore


TLS_PORTS = {443, 8443, 9443, 4433}
SUSPICIOUS_TLDS = {".ru", ".cn", ".top", ".xyz", ".gq", ".tk", ".ml", ".ga"}
TLS_CONTENT_TYPES = {20, 21, 22, 23}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")
ECH_EXTENSION_IDS = {0xFE0D}


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
            "sni_to_ja3": {sni: dict(counter) for sni, counter in self.sni_to_ja3.items()},
            "sni_to_ja4": {sni: dict(counter) for sni, counter in self.sni_to_ja4.items()},
            "ja3_to_sni": {ja3: dict(counter) for ja3, counter in self.ja3_to_sni.items()},
            "ja4_to_sni": {ja4: dict(counter) for ja4, counter in self.ja4_to_sni.items()},
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
                ref: dict(hosts) for ref, hosts in self.http_referrer_request_hosts.items()
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
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def _is_grease(value: int) -> bool:
    return (value & 0x0f0f) == 0x0a0a


def _coerce_int_list(values: object) -> list[int]:
    if values is None:
        return []
    if isinstance(values, (list, tuple, set)):
        out = []
        for item in values:
            try:
                out.append(int(item))
            except Exception:
                continue
        return out
    try:
        return [int(values)]
    except Exception:
        return []


def _iter_tls_extensions(client_hello) -> list[object]:
    exts = getattr(client_hello, "ext", None)
    if exts is None:
        exts = getattr(client_hello, "extensions", None)
    if exts is None:
        return []
    try:
        return list(exts)
    except Exception:
        return []


def _tls_extension_type(ext: object) -> Optional[int]:
    for attr in ("type", "ext_type", "etype", "extension_type"):
        value = getattr(ext, attr, None)
        if value is not None:
            try:
                return int(value)
            except Exception:
                continue
    return None


def _extract_sni(ext: object) -> Optional[str]:
    name = ext.__class__.__name__
    if "ServerName" not in name and "SNI" not in name:
        return None
    for attr in ("servernames", "server_names", "server_name", "names"):
        names = getattr(ext, attr, None)
        if names:
            try:
                if isinstance(names, (list, tuple)):
                    first = names[0]
                else:
                    first = names
                candidate = getattr(first, "servername", None) or getattr(first, "name", None) or first
                if isinstance(candidate, bytes):
                    return candidate.decode("utf-8", errors="ignore").strip(".")
                return str(candidate).strip(".")
            except Exception:
                return None
    return None


def _extract_alpn(ext: object) -> list[str]:
    name = ext.__class__.__name__
    if "ALPN" not in name and "ApplicationLayerProtocol" not in name:
        return []
    for attr in ("protocols", "alpn_protocols"):
        protocols = getattr(ext, attr, None)
        if protocols:
            out: list[str] = []
            for proto in protocols:
                if isinstance(proto, bytes):
                    out.append(proto.decode("utf-8", errors="ignore"))
                else:
                    out.append(str(proto))
            return out
    return []


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
        0x0300: "SSLv3",
        0x0301: "TLS1.0",
        0x0302: "TLS1.1",
        0x0303: "TLS1.2",
        0x0304: "TLS1.3",
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


def _tls_handshake_type(payload: bytes) -> Optional[int]:
    if len(payload) < 6:
        return None
    if payload[0] != 22:
        return None
    return payload[5]


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _ja3_from_client_hello(client_hello) -> Optional[str]:
    version = getattr(client_hello, "version", None)
    if version is None:
        return None
    try:
        version_val = int(version)
    except Exception:
        return None

    ciphers = []
    for attr in ("ciphers", "cipher_suites", "ciphersuites"):
        ciphers = _coerce_int_list(getattr(client_hello, attr, None))
        if ciphers:
            break
    ciphers = [c for c in ciphers if not _is_grease(c)]

    exts = _iter_tls_extensions(client_hello)
    ext_types = []
    curves = []
    ec_points = []
    for ext in exts:
        ext_type = _tls_extension_type(ext)
        if ext_type is not None and not _is_grease(ext_type):
            ext_types.append(ext_type)

        for attr in ("groups", "supported_groups", "elliptic_curves"):
            groups = _coerce_int_list(getattr(ext, attr, None))
            if groups:
                curves.extend(groups)
                break

        for attr in ("ecpl", "ec_point_formats", "formats", "ec_points"):
            points = _coerce_int_list(getattr(ext, attr, None))
            if points:
                ec_points.extend(points)
                break

    curves = [c for c in curves if not _is_grease(c)]
    ec_points = [p for p in ec_points if not _is_grease(p)]

    def _join(values: list[int]) -> str:
        return "-".join(str(v) for v in values)

    ja3_str = f"{version_val},{_join(ciphers)},{_join(ext_types)},{_join(curves)},{_join(ec_points)}"
    return ja3_str


def _ja4_from_client_hello(client_hello, sni: Optional[str], alpn: list[str]) -> Optional[str]:
    version = getattr(client_hello, "version", None)
    if version is None:
        return None
    try:
        version_val = int(version)
    except Exception:
        return None

    ciphers = []
    for attr in ("ciphers", "cipher_suites", "ciphersuites"):
        ciphers = _coerce_int_list(getattr(client_hello, attr, None))
        if ciphers:
            break
    ciphers = [c for c in ciphers if not _is_grease(c)]
    first_cipher = str(ciphers[0]) if ciphers else "0"

    ext_types = []
    for ext in _iter_tls_extensions(client_hello):
        ext_type = _tls_extension_type(ext)
        if ext_type is not None and not _is_grease(ext_type):
            ext_types.append(ext_type)
    ext_str = "-".join(str(v) for v in ext_types)
    ext_hash = hashlib.sha256(ext_str.encode("utf-8", errors="ignore")).hexdigest()[:8]

    alpn_token = alpn[0] if alpn else "na"
    sni_flag = "s" if sni else "n"
    return f"t{version_val}{sni_flag}-{alpn_token}-{first_cipher}-{ext_hash}"


def _ja4s_from_server_hello(server_hello) -> Optional[str]:
    version = getattr(server_hello, "version", None)
    if version is None:
        return None
    try:
        version_val = int(version)
    except Exception:
        return None

    cipher = getattr(server_hello, "cipher", None)
    try:
        cipher_val = int(cipher) if cipher is not None else 0
    except Exception:
        cipher_val = 0

    ext_types = []
    for ext in _iter_tls_extensions(server_hello):
        ext_type = _tls_extension_type(ext)
        if ext_type is not None and not _is_grease(ext_type):
            ext_types.append(ext_type)
    ext_str = "-".join(str(v) for v in ext_types)
    ext_hash = hashlib.sha256(ext_str.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"s{version_val}-{cipher_val}-{ext_hash}"


def analyze_tls(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> TlsSummary:
    errors: list[str] = []
    if TLS is None and TLSClientHello is None and TLSServerHello is None:
        errors.append("Scapy TLS layers unavailable; install scapy[tls] for TLS handshake parsing.")
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
    sni_to_ja3: dict[str, Counter[str]] = defaultdict(Counter)
    sni_to_ja4: dict[str, Counter[str]] = defaultdict(Counter)
    ja3_to_sni: dict[str, Counter[str]] = defaultdict(Counter)
    ja4_to_sni: dict[str, Counter[str]] = defaultdict(Counter)

    conversations: dict[tuple[str, str, int], dict[str, object]] = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None,
        "sni": None,
    })

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    analysis_notes: list[str] = []
    sni_ip_literals: set[str] = set()

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
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            ts = safe_float(getattr(pkt, "time", None))

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

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

            is_tls_layer = TLS is not None and pkt.haslayer(TLS)  # type: ignore[truthy-bool]
            is_tls_handshake = (
                (TLSClientHello is not None and pkt.haslayer(TLSClientHello))
                or (TLSServerHello is not None and pkt.haslayer(TLSServerHello))
            )
            is_tls_like = _looks_like_tls_record(payload)
            if not is_tls_layer and not is_tls_handshake and not is_tls_like:
                continue

            tls_like_packets += 1
            if is_tls_layer or is_tls_handshake:
                tls_packets += 1

            handshake_type = _tls_handshake_type(payload) if is_tls_like and not (dport in TLS_PORTS or sport in TLS_PORTS) else None
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
            convo = conversations[convo_key]
            convo["packets"] = int(convo["packets"]) + 1
            convo["bytes"] = int(convo["bytes"]) + pkt_len
            if ts is not None:
                if convo["first_seen"] is None or ts < convo["first_seen"]:
                    convo["first_seen"] = ts
                if convo["last_seen"] is None or ts > convo["last_seen"]:
                    convo["last_seen"] = ts

            if TLSClientHello is not None and pkt.haslayer(TLSClientHello):  # type: ignore[truthy-bool]
                client_hello = pkt[TLSClientHello]  # type: ignore[index]
                client_hellos += 1
                versions[_tls_version_label(getattr(client_hello, "version", "?"))] += 1
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
                if sni_val:
                    sni_counts[sni_val] += 1
                    if convo.get("sni") is None:
                        convo["sni"] = sni_val
                    if _is_ip_literal(sni_val):
                        sni_ip_literals.add(sni_val)
                if ech_present:
                    ech_hellos += 1
                    if not sni_val:
                        ech_sni_missing += 1
                for alpn in alpn_vals:
                    alpn_counts[alpn] += 1

                ja3 = _ja3_from_client_hello(client_hello)
                if ja3:
                    ja3_hash = hashlib.md5(ja3.encode("utf-8", errors="ignore")).hexdigest()
                    ja3_counts[ja3_hash] += 1
                    if sni_val:
                        sni_to_ja3[sni_val][ja3_hash] += 1
                        ja3_to_sni[ja3_hash][sni_val] += 1

                ja4 = _ja4_from_client_hello(client_hello, sni_val, alpn_vals)
                if ja4:
                    ja4_counts[ja4] += 1
                    if sni_val:
                        sni_to_ja4[sni_val][ja4] += 1
                        ja4_to_sni[ja4][sni_val] += 1

            if TLSServerHello is not None and pkt.haslayer(TLSServerHello):  # type: ignore[truthy-bool]
                server_hello = pkt[TLSServerHello]  # type: ignore[index]
                server_hellos += 1
                versions[_tls_version_label(getattr(server_hello, "version", "?"))] += 1
                cipher = getattr(server_hello, "cipher", None)
                if cipher is not None:
                    cipher_name = str(cipher)
                    cipher_suites[cipher_name] += 1
                    upper = cipher_name.upper()
                    if any(marker in upper for marker in WEAK_CIPHER_MARKERS):
                        weak_ciphers[cipher_name] += 1

                ja4s = _ja4s_from_server_hello(server_hello)
                if ja4s:
                    ja4s_counts[ja4s] += 1

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows: list[TlsConversation] = []
    for (client, server, port), data in conversations.items():
        conversation_rows.append(TlsConversation(
            client_ip=client,
            server_ip=server,
            server_port=port,
            packets=int(data["packets"]),
            bytes=int(data["bytes"]),
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            sni=data.get("sni"),
        ))

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(path, show_status, f"TLS: {desc}", func, *args, **kwargs)

    http_summary = _busy("HTTP", analyze_http, path, show_status=False, packets=packets, meta=meta)
    cert_summary = _busy("Certificates", analyze_certificates, path, show_status=False)

    if tls_like_packets and tls_packets == 0:
        analysis_notes.append(
            "TLS record headers detected without parsed TLS handshakes; ensure scapy TLS support or provide full streams."
        )
    elif tls_like_packets > tls_packets:
        analysis_notes.append(
            f"{tls_like_packets - tls_packets} TLS-like packet(s) were detected without full handshake parsing."
        )
    if client_hellos and not server_hellos:
        analysis_notes.append("Client hellos observed without any server hellos (possible blocked/failed handshakes).")
    if ech_hellos:
        analysis_notes.append("ECH (Encrypted ClientHello) observed; SNI may be intentionally hidden.")
    if http_summary.total_requests or http_summary.total_responses:
        analysis_notes.append("HTTP statistics are capture-wide; use --http for full plaintext context.")

    detections: list[dict[str, object]] = []
    legacy_versions = [v for v in ("SSLv3", "TLS1.0", "TLS1.1") if versions.get(v)]
    if legacy_versions:
        detections.append({
            "severity": "warning",
            "summary": "Legacy TLS versions observed",
            "details": f"Versions: {', '.join(legacy_versions)}",
        })

    missing_sni_total = client_hellos - sum(sni_counts.values())
    missing_sni_no_ech = max(0, missing_sni_total - ech_sni_missing)
    if ech_hellos:
        detections.append({
            "severity": "info",
            "summary": "ECH (Encrypted ClientHello) observed",
            "details": f"{ech_hellos} client hello(s) advertise ECH.",
        })
    if client_hellos and missing_sni_no_ech > 0:
        detections.append({
            "severity": "info",
            "summary": "TLS handshakes without SNI",
            "details": f"{missing_sni_no_ech} client hello(s) missing SNI (excluding ECH).",
        })
    if ech_sni_missing:
        detections.append({
            "severity": "info",
            "summary": "SNI hidden by ECH",
            "details": f"{ech_sni_missing} client hello(s) omitted SNI but advertised ECH.",
        })

    if client_hellos and server_hellos < client_hellos:
        failed = client_hellos - server_hellos
        ratio = failed / client_hellos
        severity = "high" if ratio >= 0.7 else ("warning" if ratio >= 0.3 and failed >= 5 else "info")
        detections.append({
            "severity": severity,
            "summary": "TLS handshake failures",
            "details": f"{failed} client hello(s) without server hello response.",
        })

    high_entropy_sni = [sni for sni, count in sni_counts.items() if len(sni) >= 12 and _shannon_entropy(sni) >= 3.5]
    if high_entropy_sni:
        detections.append({
            "severity": "warning",
            "summary": "High-entropy SNI values",
            "details": ", ".join(high_entropy_sni[:5]),
        })

    suspicious_sni = [sni for sni in sni_counts if any(sni.endswith(tld) for tld in SUSPICIOUS_TLDS)]
    if suspicious_sni:
        detections.append({
            "severity": "high",
            "summary": "Suspicious SNI TLDs observed",
            "details": ", ".join(suspicious_sni[:5]),
        })

    if sni_ip_literals:
        detections.append({
            "severity": "warning",
            "summary": "SNI uses IP literal",
            "details": ", ".join(sorted(sni_ip_literals)[:5]),
        })

    non_standard_ports = [port for port in server_ports if port not in TLS_PORTS]
    if non_standard_ports:
        ports_text = ", ".join(str(port) for port in sorted(non_standard_ports)[:8])
        detections.append({
            "severity": "info",
            "summary": "TLS on non-standard ports",
            "details": f"Ports: {ports_text}",
        })

    if weak_ciphers:
        top_weak = ", ".join(name for name, _count in weak_ciphers.most_common(5))
        detections.append({
            "severity": "warning",
            "summary": "Weak TLS cipher suites observed",
            "details": top_weak,
        })

    if not alpn_counts and client_hellos:
        detections.append({
            "severity": "info",
            "summary": "No ALPN advertised",
            "details": "TLS handshakes missing ALPN hints (could indicate legacy clients).",
        })
    if any(alpn.startswith("h2") for alpn in alpn_counts):
        detections.append({
            "severity": "info",
            "summary": "HTTP/2 ALPN observed",
            "details": "TLS ALPN indicates HTTP/2 usage (h2).",
        })
    if any(alpn.startswith("h3") for alpn in alpn_counts):
        detections.append({
            "severity": "info",
            "summary": "HTTP/3 ALPN observed",
            "details": "TLS ALPN indicates HTTP/3/QUIC usage (h3).",
        })

    if cert_summary.self_signed:
        detections.append({
            "severity": "warning",
            "summary": "Self-signed TLS certificates observed",
            "details": f"Count: {len(cert_summary.self_signed)}",
        })
    if cert_summary.expired:
        detections.append({
            "severity": "warning",
            "summary": "Expired TLS certificates observed",
            "details": f"Count: {len(cert_summary.expired)}",
        })
    if cert_summary.weak_keys:
        detections.append({
            "severity": "warning",
            "summary": "Weak TLS certificate keys",
            "details": f"Count: {len(cert_summary.weak_keys)}",
        })

    artifacts: list[str] = []
    for sni, count in sni_counts.most_common(10):
        artifacts.append(f"SNI: {sni} ({count})")
    for alpn, count in alpn_counts.most_common(5):
        artifacts.append(f"ALPN: {alpn} ({count})")
    for ja3, count in ja3_counts.most_common(5):
        artifacts.append(f"JA3: {ja3} ({count})")

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
        cert_subjects=cert_summary.subjects,
        cert_issuers=cert_summary.issuers,
        cert_sans=cert_summary.sas,
        cert_count=cert_summary.cert_count,
        weak_certs=len(cert_summary.weak_keys),
        expired_certs=len(cert_summary.expired),
        self_signed_certs=len(cert_summary.self_signed),
        cert_artifacts=list(cert_summary.artifacts),
        analysis_notes=analysis_notes,
        detections=detections,
        artifacts=artifacts,
        errors=errors + http_summary.errors + cert_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
