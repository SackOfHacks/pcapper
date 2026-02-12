from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import hashlib
import math

from .pcap_cache import get_reader
from .utils import safe_float
from .http import analyze_http
from .certificates import analyze_certificates

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
    client_hellos: int
    server_hellos: int
    versions: Counter[str]
    cipher_suites: Counter[str]
    sni_counts: Counter[str]
    alpn_counts: Counter[str]
    ja3_counts: Counter[str]
    ja4_counts: Counter[str]
    ja4s_counts: Counter[str]
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
    cert_count: int
    weak_certs: int
    expired_certs: int
    self_signed_certs: int
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
            "client_hellos": self.client_hellos,
            "server_hellos": self.server_hellos,
            "versions": dict(self.versions),
            "cipher_suites": dict(self.cipher_suites),
            "sni_counts": dict(self.sni_counts),
            "alpn_counts": dict(self.alpn_counts),
            "ja3_counts": dict(self.ja3_counts),
            "ja4_counts": dict(self.ja4_counts),
            "ja4s_counts": dict(self.ja4s_counts),
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
            "cert_count": self.cert_count,
            "weak_certs": self.weak_certs,
            "expired_certs": self.expired_certs,
            "self_signed_certs": self.self_signed_certs,
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
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for TLS analysis.")
        return TlsSummary(
            path=path,
            total_packets=0,
            tls_packets=0,
            client_hellos=0,
            server_hellos=0,
            versions=Counter(),
            cipher_suites=Counter(),
            sni_counts=Counter(),
            alpn_counts=Counter(),
            ja3_counts=Counter(),
            ja4_counts=Counter(),
            ja4s_counts=Counter(),
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
            cert_count=0,
            weak_certs=0,
            expired_certs=0,
            self_signed_certs=0,
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
    client_hellos = 0
    server_hellos = 0
    versions: Counter[str] = Counter()
    cipher_suites: Counter[str] = Counter()
    sni_counts: Counter[str] = Counter()
    alpn_counts: Counter[str] = Counter()
    ja3_counts: Counter[str] = Counter()
    ja4_counts: Counter[str] = Counter()
    ja4s_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()

    conversations: dict[tuple[str, str, int], dict[str, object]] = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None,
        "sni": None,
    })

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

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

            is_tls_layer = TLS is not None and pkt.haslayer(TLS)  # type: ignore[truthy-bool]
            is_tls_handshake = (
                (TLSClientHello is not None and pkt.haslayer(TLSClientHello))
                or (TLSServerHello is not None and pkt.haslayer(TLSServerHello))
            )
            if not is_tls_layer and not is_tls_handshake:
                continue

            tls_packets += 1

            if dport in TLS_PORTS:
                client = src_ip or "-"
                server = dst_ip or "-"
                server_port = dport
            elif sport in TLS_PORTS:
                client = dst_ip or "-"
                server = src_ip or "-"
                server_port = sport
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
                for ext in _iter_tls_extensions(client_hello):
                    if sni_val is None:
                        sni_val = _extract_sni(ext)
                    if not alpn_vals:
                        alpn_vals = _extract_alpn(ext)
                if sni_val:
                    sni_counts[sni_val] += 1
                    if convo.get("sni") is None:
                        convo["sni"] = sni_val
                for alpn in alpn_vals:
                    alpn_counts[alpn] += 1

                ja3 = _ja3_from_client_hello(client_hello)
                if ja3:
                    ja3_hash = hashlib.md5(ja3.encode("utf-8", errors="ignore")).hexdigest()
                    ja3_counts[ja3_hash] += 1

                ja4 = _ja4_from_client_hello(client_hello, sni_val, alpn_vals)
                if ja4:
                    ja4_counts[ja4] += 1

            if TLSServerHello is not None and pkt.haslayer(TLSServerHello):  # type: ignore[truthy-bool]
                server_hello = pkt[TLSServerHello]  # type: ignore[index]
                server_hellos += 1
                versions[_tls_version_label(getattr(server_hello, "version", "?"))] += 1
                cipher = getattr(server_hello, "cipher", None)
                if cipher is not None:
                    cipher_name = str(cipher)
                    cipher_suites[cipher_name] += 1

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

    http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
    cert_summary = analyze_certificates(path, show_status=False)

    detections: list[dict[str, object]] = []
    legacy_versions = [v for v in ("SSLv3", "TLS1.0", "TLS1.1") if versions.get(v)]
    if legacy_versions:
        detections.append({
            "severity": "warning",
            "summary": "Legacy TLS versions observed",
            "details": f"Versions: {', '.join(legacy_versions)}",
        })

    missing_sni = client_hellos - sum(sni_counts.values())
    if client_hellos and missing_sni > 0:
        detections.append({
            "severity": "info",
            "summary": "TLS handshakes without SNI",
            "details": f"{missing_sni} client hello(s) missing SNI.",
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

    if not alpn_counts and client_hellos:
        detections.append({
            "severity": "info",
            "summary": "No ALPN advertised",
            "details": "TLS handshakes missing ALPN hints (could indicate legacy clients).",
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
        client_hellos=client_hellos,
        server_hellos=server_hellos,
        versions=versions,
        cipher_suites=cipher_suites,
        sni_counts=sni_counts,
        alpn_counts=alpn_counts,
        ja3_counts=ja3_counts,
        ja4_counts=ja4_counts,
        ja4s_counts=ja4s_counts,
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
        cert_count=cert_summary.cert_count,
        weak_certs=len(cert_summary.weak_keys),
        expired_certs=len(cert_summary.expired),
        self_signed_certs=len(cert_summary.self_signed),
        detections=detections,
        artifacts=artifacts,
        errors=errors + http_summary.errors + cert_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
