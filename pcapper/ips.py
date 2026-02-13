from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
import ipaddress
import json
import os
import urllib.request
import urllib.error
import hashlib
import math

from .pcap_cache import get_reader
from .utils import safe_float, detect_file_type

try:
    from scapy.layers.inet import IP  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore

try:
    from scapy.layers.inet import TCP  # type: ignore
except Exception:  # pragma: no cover
    TCP = None  # type: ignore

try:
    from scapy.layers.inet import UDP  # type: ignore
except Exception:  # pragma: no cover
    UDP = None  # type: ignore

try:
    from scapy.layers.inet import ICMP  # type: ignore
except Exception:  # pragma: no cover
    ICMP = None  # type: ignore

try:
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IPv6 = None  # type: ignore

try:
    from scapy.layers.inet6 import ICMPv6  # type: ignore
except Exception:  # pragma: no cover
    ICMPv6 = None  # type: ignore

try:
    import geoip2.database  # type: ignore
except Exception:  # pragma: no cover
    geoip2 = None  # type: ignore

try:
    from scapy.layers.tls.handshake import TLSClientHello  # type: ignore
except Exception:  # pragma: no cover
    TLSClientHello = None  # type: ignore

try:
    from scapy.layers.tls.handshake import TLSServerHello, TLSCertificate  # type: ignore
except Exception:  # pragma: no cover
    TLSServerHello = None  # type: ignore
    TLSCertificate = None  # type: ignore

try:
    from scapy.layers.tls.record import TLS  # type: ignore
except Exception:  # pragma: no cover
    TLS = None  # type: ignore

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
except Exception:  # pragma: no cover
    x509 = None  # type: ignore
    default_backend = None  # type: ignore


@dataclass(frozen=True)
class IpConversation:
    src: str
    dst: str
    protocol: str
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    ports: list[int]


@dataclass(frozen=True)
class IpEndpoint:
    ip: str
    packets_sent: int
    packets_recv: int
    bytes_sent: int
    bytes_recv: int
    protocols: list[str]
    peers: list[str]
    ports: list[int]
    first_seen: Optional[float]
    last_seen: Optional[float]
    geo: Optional[str]
    asn: Optional[str]


@dataclass(frozen=True)
class IpSummary:
    path: Path
    total_packets: int
    total_bytes: int
    unique_ips: int
    unique_sources: int
    unique_destinations: int
    ipv4_count: int
    ipv6_count: int
    protocol_counts: Counter[str]
    src_counts: Counter[str]
    dst_counts: Counter[str]
    ip_category_counts: Counter[str]
    endpoints: list[IpEndpoint]
    conversations: list[IpConversation]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    tls_client_hellos: int
    ja3_counts: Counter[str]
    ja4_counts: Counter[str]
    ja4s_counts: Counter[str]
    sni_counts: Counter[str]
    sni_entropy: dict[str, float]
    ja_reputation_hits: list[dict[str, object]]
    tls_cert_risks: list[dict[str, object]]
    suspicious_port_profiles: list[dict[str, object]]
    lateral_movement_scores: list[dict[str, object]]
    intel_findings: list[dict[str, object]]
    detections: list[dict[str, object]]
    errors: list[str]


def merge_ips_summaries(summaries: Iterable[IpSummary]) -> IpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return IpSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            total_bytes=0,
            unique_ips=0,
            unique_sources=0,
            unique_destinations=0,
            ipv4_count=0,
            ipv6_count=0,
            protocol_counts=Counter(),
            src_counts=Counter(),
            dst_counts=Counter(),
            ip_category_counts=Counter(),
            endpoints=[],
            conversations=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=0.0,
            tls_client_hellos=0,
            ja3_counts=Counter(),
            ja4_counts=Counter(),
            ja4s_counts=Counter(),
            sni_counts=Counter(),
            sni_entropy={},
            ja_reputation_hits=[],
            tls_cert_risks=[],
            suspicious_port_profiles=[],
            lateral_movement_scores=[],
            intel_findings=[],
            detections=[],
            errors=[],
        )

    total_packets = 0
    total_bytes = 0
    tls_client_hellos = 0
    duration_seconds = 0.0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    protocol_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    ip_category_counts: Counter[str] = Counter()
    ja3_counts: Counter[str] = Counter()
    ja4_counts: Counter[str] = Counter()
    ja4s_counts: Counter[str] = Counter()
    sni_counts: Counter[str] = Counter()
    sni_entropy: dict[str, float] = {}

    endpoint_map: dict[str, dict[str, object]] = {}
    conversation_map: dict[tuple[str, str, str], dict[str, object]] = {}
    all_ips: set[str] = set()

    tls_cert_risks: list[dict[str, object]] = []
    suspicious_port_profiles: list[dict[str, object]] = []
    lateral_movement_scores: list[dict[str, object]] = []
    intel_findings: list[dict[str, object]] = []

    detection_seen: set[tuple[str, str, str]] = set()
    detections: list[dict[str, object]] = []

    error_seen: set[str] = set()
    errors: list[str] = []

    rep_hits: dict[tuple[str, str, str], int] = defaultdict(int)

    for summary in summary_list:
        total_packets += summary.total_packets
        total_bytes += summary.total_bytes
        tls_client_hellos += summary.tls_client_hellos
        if summary.duration_seconds is not None:
            duration_seconds += summary.duration_seconds

        if summary.first_seen is not None:
            if first_seen is None or summary.first_seen < first_seen:
                first_seen = summary.first_seen
        if summary.last_seen is not None:
            if last_seen is None or summary.last_seen > last_seen:
                last_seen = summary.last_seen

        protocol_counts.update(summary.protocol_counts)
        src_counts.update(summary.src_counts)
        dst_counts.update(summary.dst_counts)
        ip_category_counts.update(summary.ip_category_counts)
        ja3_counts.update(summary.ja3_counts)
        ja4_counts.update(summary.ja4_counts)
        ja4s_counts.update(summary.ja4s_counts)
        sni_counts.update(summary.sni_counts)

        all_ips.update(summary.src_counts.keys())
        all_ips.update(summary.dst_counts.keys())

        for sni, entropy in summary.sni_entropy.items():
            existing = sni_entropy.get(sni)
            if existing is None or entropy > existing:
                sni_entropy[sni] = entropy

        for item in summary.ja_reputation_hits:
            rep_type = str(item.get("type", "-"))
            fp = str(item.get("fingerprint", "-"))
            label = str(item.get("label", "-"))
            count = int(item.get("count", 0) or 0)
            rep_hits[(rep_type, fp, label)] += count

        tls_cert_risks.extend(summary.tls_cert_risks)
        suspicious_port_profiles.extend(summary.suspicious_port_profiles)
        lateral_movement_scores.extend(summary.lateral_movement_scores)
        intel_findings.extend(summary.intel_findings)

        for detection in summary.detections:
            key = (
                str(detection.get("severity", "info")),
                str(detection.get("summary", "")),
                str(detection.get("details", "")),
            )
            if key in detection_seen:
                continue
            detection_seen.add(key)
            detections.append(detection)

        for err in summary.errors:
            if err in error_seen:
                continue
            error_seen.add(err)
            errors.append(err)

        for endpoint in summary.endpoints:
            entry = endpoint_map.setdefault(
                endpoint.ip,
                {
                    "packets_sent": 0,
                    "packets_recv": 0,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "protocols": set(),
                    "peers": set(),
                    "ports": set(),
                    "first_seen": None,
                    "last_seen": None,
                    "geo": None,
                    "asn": None,
                },
            )
            entry["packets_sent"] = int(entry["packets_sent"]) + endpoint.packets_sent
            entry["packets_recv"] = int(entry["packets_recv"]) + endpoint.packets_recv
            entry["bytes_sent"] = int(entry["bytes_sent"]) + endpoint.bytes_sent
            entry["bytes_recv"] = int(entry["bytes_recv"]) + endpoint.bytes_recv
            entry["protocols"].update(endpoint.protocols)
            entry["peers"].update(endpoint.peers)
            entry["ports"].update(endpoint.ports)

            ep_first = endpoint.first_seen
            ep_last = endpoint.last_seen
            cur_first = entry["first_seen"]
            cur_last = entry["last_seen"]
            if ep_first is not None and (cur_first is None or ep_first < cur_first):
                entry["first_seen"] = ep_first
            if ep_last is not None and (cur_last is None or ep_last > cur_last):
                entry["last_seen"] = ep_last

            if entry["geo"] is None and endpoint.geo:
                entry["geo"] = endpoint.geo
            if entry["asn"] is None and endpoint.asn:
                entry["asn"] = endpoint.asn

        for conv in summary.conversations:
            key = (conv.src, conv.dst, conv.protocol)
            entry = conversation_map.setdefault(
                key,
                {
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "ports": set(),
                },
            )
            entry["packets"] = int(entry["packets"]) + conv.packets
            entry["bytes"] = int(entry["bytes"]) + conv.bytes
            entry["ports"].update(conv.ports)

            cur_first = entry["first_seen"]
            cur_last = entry["last_seen"]
            if conv.first_seen is not None and (cur_first is None or conv.first_seen < cur_first):
                entry["first_seen"] = conv.first_seen
            if conv.last_seen is not None and (cur_last is None or conv.last_seen > cur_last):
                entry["last_seen"] = conv.last_seen

    endpoint_rows: list[IpEndpoint] = []
    for ip_text, data in endpoint_map.items():
        endpoint_rows.append(
            IpEndpoint(
                ip=ip_text,
                packets_sent=int(data["packets_sent"]),
                packets_recv=int(data["packets_recv"]),
                bytes_sent=int(data["bytes_sent"]),
                bytes_recv=int(data["bytes_recv"]),
                protocols=sorted(list(data["protocols"])),
                peers=sorted(list(data["peers"])),
                ports=sorted(list(data["ports"])),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                geo=data["geo"],
                asn=data["asn"],
            )
        )

    conversation_rows: list[IpConversation] = []
    for (src, dst, proto), data in conversation_map.items():
        conversation_rows.append(
            IpConversation(
                src=src,
                dst=dst,
                protocol=proto,
                packets=int(data["packets"]),
                bytes=int(data["bytes"]),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                ports=sorted(list(data["ports"])),
            )
        )

    ipv4_count = 0
    ipv6_count = 0
    for ip_text in all_ips:
        try:
            addr = ipaddress.ip_address(ip_text)
            if addr.version == 4:
                ipv4_count += 1
            elif addr.version == 6:
                ipv6_count += 1
        except Exception:
            continue

    ja_reputation_hits = [
        {
            "type": rep_type,
            "fingerprint": fingerprint,
            "label": label,
            "count": count,
        }
        for (rep_type, fingerprint, label), count in rep_hits.items()
    ]

    return IpSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        total_bytes=total_bytes,
        unique_ips=len(all_ips),
        unique_sources=len(src_counts),
        unique_destinations=len(dst_counts),
        ipv4_count=ipv4_count,
        ipv6_count=ipv6_count,
        protocol_counts=protocol_counts,
        src_counts=src_counts,
        dst_counts=dst_counts,
        ip_category_counts=ip_category_counts,
        endpoints=endpoint_rows,
        conversations=conversation_rows,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        tls_client_hellos=tls_client_hellos,
        ja3_counts=ja3_counts,
        ja4_counts=ja4_counts,
        ja4s_counts=ja4s_counts,
        sni_counts=sni_counts,
        sni_entropy=sni_entropy,
        ja_reputation_hits=ja_reputation_hits,
        tls_cert_risks=tls_cert_risks,
        suspicious_port_profiles=suspicious_port_profiles,
        lateral_movement_scores=lateral_movement_scores,
        intel_findings=intel_findings,
        detections=detections,
        errors=errors,
    )


def _classify_ip(ip_text: str) -> list[str]:
    categories: list[str] = []
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return ["invalid"]

    if addr.version == 4 and ip_text == "255.255.255.255":
        categories.append("broadcast")
    if addr.is_multicast:
        categories.append("multicast")
    if addr.is_loopback:
        categories.append("loopback")
    if addr.is_link_local:
        categories.append("link_local")
    if addr.is_private:
        categories.append("private")
    if addr.is_reserved:
        categories.append("reserved")
    if addr.is_unspecified:
        categories.append("unspecified")
    if addr.is_global:
        categories.append("public")

    if not categories:
        categories.append("unknown")
    return categories


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


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


def _load_reputation_list(path_value: Optional[str]) -> dict[str, str]:
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.exists():
        return {}

    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}

    raw = raw.strip()
    if not raw:
        return {}

    if raw.lstrip().startswith("{"):
        try:
            data = json.loads(raw)
        except Exception:
            return {}
        if isinstance(data, dict):
            return {str(k).strip(): str(v) for k, v in data.items()}
        if isinstance(data, list):
            return {str(item).strip(): "listed" for item in data}
        return {}

    rep: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            key, label = line.split(",", 1)
            rep[key.strip()] = label.strip() or "listed"
        else:
            rep[line] = "listed"
    return rep


def _tls_cert_risks_from_payload(cert_payload: object) -> list[dict[str, object]]:
    if x509 is None or default_backend is None:
        return []
    certs = []
    for attr in ("certs", "certificates", "certs_data"):
        value = getattr(cert_payload, attr, None)
        if value:
            certs = value
            break
    if not certs:
        return []

    risks: list[dict[str, object]] = []
    for cert_item in certs:
        raw_bytes = None
        if isinstance(cert_item, (bytes, bytearray)):
            raw_bytes = bytes(cert_item)
        else:
            raw_bytes = getattr(cert_item, "data", None)
            if isinstance(raw_bytes, bytearray):
                raw_bytes = bytes(raw_bytes)
        if not raw_bytes:
            continue

        try:
            cert = x509.load_der_x509_certificate(raw_bytes, default_backend())
        except Exception:
            continue

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        if subject == issuer:
            risks.append({"type": "self_signed", "details": subject})

        now = getattr(cert, "not_valid_before", None)
        current = None
        try:
            from datetime import datetime, timezone
            current = datetime.now(timezone.utc)
        except Exception:
            current = None

        if current is not None:
            try:
                if cert.not_valid_after < current:
                    risks.append({"type": "expired", "details": subject})
                if cert.not_valid_before > current:
                    risks.append({"type": "not_yet_valid", "details": subject})
            except Exception:
                pass

        sig_alg = cert.signature_hash_algorithm
        if sig_alg and sig_alg.name in {"md5", "sha1"}:
            risks.append({"type": "weak_signature", "details": sig_alg.name})

        pubkey = cert.public_key()
        try:
            key_size = getattr(pubkey, "key_size", None)
            if key_size and key_size < 2048:
                risks.append({"type": "weak_key", "details": f"{key_size} bits"})
        except Exception:
            pass

    return risks


def _is_public_ip(ip_text: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_text)
        return addr.is_global
    except ValueError:
        return False


def _load_geoip_readers() -> tuple[object | None, object | None, list[str]]:
    errors: list[str] = []
    city_db = os.environ.get("PCAPPER_GEOIP_CITY_DB")
    asn_db = os.environ.get("PCAPPER_GEOIP_ASN_DB")

    if (city_db or asn_db) and ("geoip2" not in globals() or geoip2 is None):  # type: ignore[truthy-bool]
        errors.append("GeoIP DB configured but geoip2 is not installed (pip install geoip2).")
        return None, None, errors
    city_reader = None
    asn_reader = None

    if city_db:
        try:
            city_reader = geoip2.database.Reader(city_db)  # type: ignore[attr-defined]
        except Exception:
            city_reader = None
    if asn_db:
        try:
            asn_reader = geoip2.database.Reader(asn_db)  # type: ignore[attr-defined]
        except Exception:
            asn_reader = None
    return city_reader, asn_reader, errors


def _geoip_lookup(ip_text: str, city_reader: object | None, asn_reader: object | None) -> tuple[Optional[str], Optional[str]]:
    geo_label = None
    asn_label = None

    if city_reader is not None:
        try:
            city_resp = city_reader.city(ip_text)  # type: ignore[attr-defined]
            country = getattr(getattr(city_resp, "country", None), "name", None)
            city = getattr(getattr(city_resp, "city", None), "name", None)
            region = None
            subdivisions = getattr(city_resp, "subdivisions", None)
            if subdivisions:
                try:
                    region = subdivisions.most_specific.name
                except Exception:
                    region = None
            parts = [p for p in [city, region, country] if p]
            if parts:
                geo_label = ", ".join(parts)
        except Exception:
            geo_label = None

    if asn_reader is not None:
        try:
            asn_resp = asn_reader.asn(ip_text)  # type: ignore[attr-defined]
            asn = getattr(asn_resp, "autonomous_system_number", None)
            org = getattr(asn_resp, "autonomous_system_organization", None)
            if asn or org:
                asn_label = f"AS{asn} {org}".strip()
        except Exception:
            asn_label = None

    return geo_label, asn_label


def _fetch_json(url: str, headers: dict[str, str], timeout: float = 5.0) -> Optional[dict[str, object]]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
        return json.loads(payload.decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return None


def _abuseipdb_lookup(ip_text: str, api_key: str) -> Optional[dict[str, object]]:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_text}&maxAgeInDays=90&verbose=true"
    headers = {"Key": api_key, "Accept": "application/json"}
    data = _fetch_json(url, headers)
    if not data:
        return None
    payload = data.get("data")
    if not isinstance(payload, dict):
        return None
    return {
        "source": "AbuseIPDB",
        "score": payload.get("abuseConfidenceScore"),
        "reports": payload.get("totalReports"),
        "usage": payload.get("usageType"),
        "isp": payload.get("isp"),
        "country": payload.get("countryCode"),
    }


def _otx_lookup(ip_text: str, api_key: str) -> Optional[dict[str, object]]:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_text}/general"
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
    data = _fetch_json(url, headers)
    if not data:
        return None
    pulse_info = data.get("pulse_info")
    if not isinstance(pulse_info, dict):
        return None
    pulse_count = pulse_info.get("count")
    if pulse_count is None:
        return None
    return {
        "source": "OTX",
        "pulses": pulse_count,
    }


def _virustotal_lookup(ip_text: str, api_key: str) -> Optional[dict[str, object]]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_text}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    data = _fetch_json(url, headers)
    if not data:
        return None
    data_obj = data.get("data")
    if not isinstance(data_obj, dict):
        return None
    attrs = data_obj.get("attributes")
    if not isinstance(attrs, dict):
        return None
    stats = attrs.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    return {
        "source": "VirusTotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
    }


def _infer_protocol(pkt) -> str:
    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        return "TCP"
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        return "UDP"
    if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
        return "ICMP"
    if ICMPv6 is not None and pkt.haslayer(ICMPv6):  # type: ignore[truthy-bool]
        return "ICMPv6"
    return "OTHER"


def analyze_ips(path: Path, show_status: bool = True) -> IpSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for IP analysis.")
        return IpSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            unique_ips=0,
            unique_sources=0,
            unique_destinations=0,
            ipv4_count=0,
            ipv6_count=0,
            protocol_counts=Counter(),
            src_counts=Counter(),
            dst_counts=Counter(),
            ip_category_counts=Counter(),
            endpoints=[],
            conversations=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            tls_client_hellos=0,
            ja3_counts=Counter(),
            ja4_counts=Counter(),
            ja4s_counts=Counter(),
            sni_counts=Counter(),
            sni_entropy={},
            ja_reputation_hits=[],
            tls_cert_risks=[],
            suspicious_port_profiles=[],
            lateral_movement_scores=[],
            intel_findings=[],
            detections=[],
            errors=errors,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    total_packets = 0
    total_bytes = 0
    protocol_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    ip_category_counts: Counter[str] = Counter()

    endpoints: dict[str, dict[str, object]] = defaultdict(lambda: {
        "packets_sent": 0,
        "packets_recv": 0,
        "bytes_sent": 0,
        "bytes_recv": 0,
        "protocols": set(),
        "peers": set(),
        "ports": set(),
        "first_seen": None,
        "last_seen": None,
    })

    conversations: dict[tuple[str, str, str], dict[str, object]] = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "ports": set(),
        "first_seen": None,
        "last_seen": None,
    })

    unique_ips: set[str] = set()
    src_ips: set[str] = set()
    dst_ips: set[str] = set()

    ipv4_set: set[str] = set()
    ipv6_set: set[str] = set()

    src_to_ports: dict[str, set[int]] = defaultdict(set)
    src_to_dsts: dict[str, set[str]] = defaultdict(set)
    dst_to_ports: dict[str, set[int]] = defaultdict(set)
    dst_to_srcs: dict[str, set[str]] = defaultdict(set)

    tls_client_hellos = 0
    ja3_counts: Counter[str] = Counter()
    ja4_counts: Counter[str] = Counter()
    ja4s_counts: Counter[str] = Counter()
    sni_counts: Counter[str] = Counter()
    sni_entropy: dict[str, float] = {}
    tls_cert_risks: list[dict[str, object]] = []
    cert_seen: set[tuple[str, str, str]] = set()

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

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                if src_ip:
                    ipv4_set.add(src_ip)
                if dst_ip:
                    ipv4_set.add(dst_ip)
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                if src_ip:
                    ipv6_set.add(src_ip)
                if dst_ip:
                    ipv6_set.add(dst_ip)
            else:
                continue

            if not src_ip or not dst_ip:
                continue

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len

            protocol = _infer_protocol(pkt)
            protocol_counts[protocol] += 1

            unique_ips.update([src_ip, dst_ip])
            src_ips.add(src_ip)
            dst_ips.add(dst_ip)

            src_counts[src_ip] += 1
            dst_counts[dst_ip] += 1

            for category in _classify_ip(src_ip):
                ip_category_counts[category] += 1
            for category in _classify_ip(dst_ip):
                ip_category_counts[category] += 1

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            conv_key = (src_ip, dst_ip, protocol)
            conv = conversations[conv_key]
            conv["packets"] = int(conv["packets"]) + 1
            conv["bytes"] = int(conv["bytes"]) + pkt_len

            if ts is not None:
                if conv["first_seen"] is None or ts < conv["first_seen"]:  # type: ignore[operator]
                    conv["first_seen"] = ts
                if conv["last_seen"] is None or ts > conv["last_seen"]:  # type: ignore[operator]
                    conv["last_seen"] = ts

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                sport = getattr(tcp_layer, "sport", None)
                dport = getattr(tcp_layer, "dport", None)
                if sport is not None:
                    conv["ports"].add(int(sport))
                if dport is not None:
                    conv["ports"].add(int(dport))
                if sport is not None and dport is not None:
                    src_to_ports[src_ip].add(int(dport))
                    src_to_dsts[src_ip].add(dst_ip)
                    dst_to_ports[dst_ip].add(int(dport))
                    dst_to_srcs[dst_ip].add(src_ip)
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = getattr(udp_layer, "sport", None)
                dport = getattr(udp_layer, "dport", None)
                if sport is not None:
                    conv["ports"].add(int(sport))
                if dport is not None:
                    conv["ports"].add(int(dport))
                if sport is not None and dport is not None:
                    src_to_ports[src_ip].add(int(dport))
                    src_to_dsts[src_ip].add(dst_ip)
                    dst_to_ports[dst_ip].add(int(dport))
                    dst_to_srcs[dst_ip].add(src_ip)

            for ip_text, direction in ((src_ip, "sent"), (dst_ip, "recv")):
                entry = endpoints[ip_text]
                if direction == "sent":
                    entry["packets_sent"] = int(entry["packets_sent"]) + 1
                    entry["bytes_sent"] = int(entry["bytes_sent"]) + pkt_len
                else:
                    entry["packets_recv"] = int(entry["packets_recv"]) + 1
                    entry["bytes_recv"] = int(entry["bytes_recv"]) + pkt_len

                entry["protocols"].add(protocol)
                peer = dst_ip if ip_text == src_ip else src_ip
                entry["peers"].add(peer)

                if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                    tcp_layer = pkt[TCP]  # type: ignore[index]
                    port = getattr(tcp_layer, "sport" if ip_text == src_ip else "dport", None)
                    if port is not None:
                        entry["ports"].add(int(port))
                elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                    udp_layer = pkt[UDP]  # type: ignore[index]
                    port = getattr(udp_layer, "sport" if ip_text == src_ip else "dport", None)
                    if port is not None:
                        entry["ports"].add(int(port))

                if ts is not None:
                    if entry["first_seen"] is None or ts < entry["first_seen"]:  # type: ignore[operator]
                        entry["first_seen"] = ts
                    if entry["last_seen"] is None or ts > entry["last_seen"]:  # type: ignore[operator]
                        entry["last_seen"] = ts

            if TLSClientHello is not None and pkt.haslayer(TLSClientHello):  # type: ignore[truthy-bool]
                tls_client_hellos += 1
                client_hello = pkt[TLSClientHello]  # type: ignore[index]
                exts = _iter_tls_extensions(client_hello)
                sni_val = None
                alpn_vals: list[str] = []
                for ext in exts:
                    if sni_val is None:
                        sni_val = _extract_sni(ext)
                    if not alpn_vals:
                        alpn_vals = _extract_alpn(ext)
                if sni_val:
                    sni_counts[sni_val] += 1
                    sni_entropy[sni_val] = _shannon_entropy(sni_val)

                ja3 = _ja3_from_client_hello(client_hello)
                if ja3:
                    ja3_hash = hashlib.md5(ja3.encode("utf-8", errors="ignore")).hexdigest()
                    ja3_counts[ja3_hash] += 1

                ja4 = _ja4_from_client_hello(client_hello, sni_val, alpn_vals)
                if ja4:
                    ja4_counts[ja4] += 1

            if TLSServerHello is not None and pkt.haslayer(TLSServerHello):  # type: ignore[truthy-bool]
                server_hello = pkt[TLSServerHello]  # type: ignore[index]
                ja4s = _ja4s_from_server_hello(server_hello)
                if ja4s:
                    ja4s_counts[ja4s] += 1

            if TLSCertificate is not None and pkt.haslayer(TLSCertificate):  # type: ignore[truthy-bool]
                cert_layer = pkt[TLSCertificate]  # type: ignore[index]
                risks = _tls_cert_risks_from_payload(cert_layer)
                if risks:
                    key = (src_ip, dst_ip, str(len(risks)))
                    if key not in cert_seen:
                        cert_seen.add(key)
                        tls_cert_risks.append({
                            "src": src_ip,
                            "dst": dst_ip,
                            "risks": risks,
                        })
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    endpoint_rows: list[IpEndpoint] = []
    for ip_text, data in endpoints.items():
        endpoint_rows.append(IpEndpoint(
            ip=ip_text,
            packets_sent=int(data["packets_sent"]),
            packets_recv=int(data["packets_recv"]),
            bytes_sent=int(data["bytes_sent"]),
            bytes_recv=int(data["bytes_recv"]),
            protocols=sorted(list(data["protocols"])),
            peers=sorted(list(data["peers"])),
            ports=sorted(list(data["ports"])),
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            geo=None,
            asn=None,
        ))

    conversation_rows: list[IpConversation] = []
    for (src_ip, dst_ip, protocol), data in conversations.items():
        conversation_rows.append(IpConversation(
            src=src_ip,
            dst=dst_ip,
            protocol=protocol,
            packets=int(data["packets"]),
            bytes=int(data["bytes"]),
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            ports=sorted(list(data["ports"])),
        ))

    suspicious_port_profiles: list[dict[str, object]] = []
    for src_ip, ports in src_to_ports.items():
        unique_ports = len(ports)
        unique_dsts = len(src_to_dsts.get(src_ip, set()))
        high_ports = sum(1 for p in ports if p >= 1024)
        if unique_ports >= 100 and unique_dsts >= 10:
            suspicious_port_profiles.append({
                "type": "broad_scan",
                "src": src_ip,
                "unique_ports": unique_ports,
                "unique_dsts": unique_dsts,
                "high_ports": high_ports,
            })
        elif unique_ports >= 50 and unique_dsts >= 3 and high_ports / max(unique_ports, 1) > 0.8:
            suspicious_port_profiles.append({
                "type": "high_port_sweep",
                "src": src_ip,
                "unique_ports": unique_ports,
                "unique_dsts": unique_dsts,
                "high_ports": high_ports,
            })

    lateral_movement_scores: list[dict[str, object]] = []
    for endpoint in endpoint_rows:
        if not _is_public_ip(endpoint.ip):
            unique_peers = len(endpoint.peers)
            unique_ports = len(endpoint.ports)
            score = (unique_peers / 25.0) + (unique_ports / 50.0) + (endpoint.packets_sent / 5000.0)
            if score >= 3.0:
                lateral_movement_scores.append({
                    "ip": endpoint.ip,
                    "score": round(score, 2),
                    "peers": unique_peers,
                    "ports": unique_ports,
                    "packets_sent": endpoint.packets_sent,
                })

    intel_findings: list[dict[str, object]] = []
    ja_reputation_hits: list[dict[str, object]] = []
    geo_reader, asn_reader, geo_errors = _load_geoip_readers()
    errors.extend(geo_errors)

    ja3_rep = _load_reputation_list(os.environ.get("PCAPPER_JA3_REP"))
    ja4_rep = _load_reputation_list(os.environ.get("PCAPPER_JA4_REP"))
    ja4s_rep = _load_reputation_list(os.environ.get("PCAPPER_JA4S_REP"))
    abuse_key = os.environ.get("PCAPPER_ABUSEIPDB_KEY")
    otx_key = os.environ.get("PCAPPER_OTX_KEY")
    vt_key = os.environ.get("PCAPPER_VT_KEY")
    opt_in_raw = os.environ.get("PCAPPER_INTEL_OPT_IN", "0").strip().lower()
    opt_in = opt_in_raw in {"1", "true", "yes", "y"}
    if not opt_in and (abuse_key or otx_key or vt_key):
        errors.append("External IP intelligence lookups disabled; set PCAPPER_INTEL_OPT_IN=1 to enable.")
        abuse_key = None
        otx_key = None
        vt_key = None
    try:
        intel_limit = int(os.environ.get("PCAPPER_IP_INTEL_LIMIT", "10"))
    except Exception:
        intel_limit = 10

    top_endpoints = sorted(
        endpoint_rows,
        key=lambda e: e.bytes_sent + e.bytes_recv,
        reverse=True,
    )

    enriched: dict[str, tuple[Optional[str], Optional[str]]] = {}
    for endpoint in top_endpoints:
        if len(enriched) >= intel_limit:
            break
        if not _is_public_ip(endpoint.ip):
            continue

        geo_label, asn_label = _geoip_lookup(endpoint.ip, geo_reader, asn_reader)
        enriched[endpoint.ip] = (geo_label, asn_label)

        if abuse_key:
            abuse_data = _abuseipdb_lookup(endpoint.ip, abuse_key)
            if abuse_data and abuse_data.get("score"):
                intel_findings.append({
                    "ip": endpoint.ip,
                    **abuse_data,
                })

        if otx_key:
            otx_data = _otx_lookup(endpoint.ip, otx_key)
            if otx_data and otx_data.get("pulses"):
                intel_findings.append({
                    "ip": endpoint.ip,
                    **otx_data,
                })

        if vt_key:
            vt_data = _virustotal_lookup(endpoint.ip, vt_key)
            if vt_data and (vt_data.get("malicious") or vt_data.get("suspicious")):
                intel_findings.append({
                    "ip": endpoint.ip,
                    **vt_data,
                })

    if enriched:
        updated_rows: list[IpEndpoint] = []
        for endpoint in endpoint_rows:
            geo_label, asn_label = enriched.get(endpoint.ip, (None, None))
            updated_rows.append(IpEndpoint(
                ip=endpoint.ip,
                packets_sent=endpoint.packets_sent,
                packets_recv=endpoint.packets_recv,
                bytes_sent=endpoint.bytes_sent,
                bytes_recv=endpoint.bytes_recv,
                protocols=endpoint.protocols,
                peers=endpoint.peers,
                ports=endpoint.ports,
                first_seen=endpoint.first_seen,
                last_seen=endpoint.last_seen,
                geo=geo_label,
                asn=asn_label,
            ))
        endpoint_rows = updated_rows

    if ja3_rep:
        for ja3_hash, count in ja3_counts.items():
            if ja3_hash in ja3_rep:
                ja_reputation_hits.append({
                    "type": "JA3",
                    "fingerprint": ja3_hash,
                    "label": ja3_rep[ja3_hash],
                    "count": count,
                })

    if ja4_rep:
        for ja4_hash, count in ja4_counts.items():
            if ja4_hash in ja4_rep:
                ja_reputation_hits.append({
                    "type": "JA4",
                    "fingerprint": ja4_hash,
                    "label": ja4_rep[ja4_hash],
                    "count": count,
                })

    if ja4s_rep:
        for ja4s_hash, count in ja4s_counts.items():
            if ja4s_hash in ja4s_rep:
                ja_reputation_hits.append({
                    "type": "JA4S",
                    "fingerprint": ja4s_hash,
                    "label": ja4s_rep[ja4s_hash],
                    "count": count,
                })

    if geo_reader is not None:
        try:
            geo_reader.close()  # type: ignore[attr-defined]
        except Exception:
            pass
    if asn_reader is not None:
        try:
            asn_reader.close()  # type: ignore[attr-defined]
        except Exception:
            pass

    detections: list[dict[str, object]] = []
    if total_packets == 0:
        detections.append({
            "severity": "info",
            "summary": "No IP traffic detected",
            "details": "No IPv4/IPv6 packets observed in capture.",
        })
    else:
        if tls_client_hellos > 0:
            high_entropy_sni = [
                (sni, entropy)
                for sni, entropy in sni_entropy.items()
                if entropy >= 4.0 and len(sni) >= 12
            ]
            if high_entropy_sni:
                sample = ", ".join(f"{name}({entropy:.2f})" for name, entropy in high_entropy_sni[:5])
                detections.append({
                    "severity": "warning",
                    "summary": "High-entropy TLS SNI values detected",
                    "details": f"Potential DGA or tunneling indicators: {sample}",
                })

            if len(ja3_counts) > 100:
                detections.append({
                    "severity": "info",
                    "summary": "High JA3 diversity",
                    "details": f"Observed {len(ja3_counts)} unique JA3 hashes; may indicate client variety or evasion.",
                })

        if suspicious_port_profiles:
            detections.append({
                "severity": "warning",
                "summary": "Suspicious port scanning profiles observed",
                "details": f"{len(suspicious_port_profiles)} source(s) show broad/high-port sweep behavior.",
            })

        if lateral_movement_scores:
            top_lm = sorted(lateral_movement_scores, key=lambda x: x.get("score", 0), reverse=True)[:5]
            details = ", ".join(f"{item['ip']}({item['score']})" for item in top_lm)
            detections.append({
                "severity": "warning",
                "summary": "Potential lateral movement patterns",
                "details": f"High internal fan-out/port reach: {details}",
            })

        if ja_reputation_hits:
            detections.append({
                "severity": "warning",
                "summary": "TLS fingerprint reputation hits",
                "details": f"{len(ja_reputation_hits)} JA3/JA4/JA4S matches found.",
            })

        if tls_cert_risks:
            detections.append({
                "severity": "warning",
                "summary": "TLS certificate risk indicators",
                "details": f"{len(tls_cert_risks)} certificate risk observations.",
            })
        for category in ("broadcast", "multicast", "loopback", "link_local", "unspecified"):
            if ip_category_counts.get(category, 0) > 0:
                detections.append({
                    "severity": "warning" if category in ("broadcast", "loopback", "unspecified") else "info",
                    "summary": f"{category.replace('_', ' ').title()} traffic observed",
                    "details": f"{ip_category_counts.get(category, 0)} packets involved in {category} addressing.",
                })

        if duration_seconds and duration_seconds > 0:
            top_src = src_counts.most_common(1)
            if top_src:
                src_ip, src_count = top_src[0]
                src_rate = src_count / duration_seconds
                if src_rate > 5000:
                    detections.append({
                        "severity": "warning",
                        "summary": "High packet rate from a single source",
                        "details": f"{src_ip} sent {src_count} packets (~{src_rate:.1f} pkt/s).",
                        "top_sources": src_counts.most_common(3),
                    })

        for endpoint in endpoint_rows:
            if len(endpoint.peers) > 200:
                detections.append({
                    "severity": "warning",
                    "summary": "High fan-out detected",
                    "details": f"{endpoint.ip} communicated with {len(endpoint.peers)} unique peers.",
                    "top_sources": [(endpoint.ip, len(endpoint.peers))],
                })
                break

        for endpoint in endpoint_rows:
            inbound_peers = len(endpoint.peers)
            if inbound_peers > 200 and endpoint.packets_recv > endpoint.packets_sent:
                detections.append({
                    "severity": "warning",
                    "summary": "High fan-in detected",
                    "details": f"{endpoint.ip} received traffic from {inbound_peers} unique peers.",
                    "top_destinations": [(endpoint.ip, inbound_peers)],
                })
                break

        if total_bytes > 0:
            sorted_endpoints = sorted(endpoint_rows, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True)
            if sorted_endpoints:
                top_endpoint = sorted_endpoints[0]
                share = (top_endpoint.bytes_sent + top_endpoint.bytes_recv) / total_bytes
                if share > 0.5:
                    detections.append({
                        "severity": "info",
                        "summary": "Traffic concentration on a single host",
                        "details": f"{top_endpoint.ip} accounts for {share * 100:.1f}% of IP bytes.",
                    })

    return IpSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        unique_ips=len(unique_ips),
        unique_sources=len(src_ips),
        unique_destinations=len(dst_ips),
        ipv4_count=len(ipv4_set),
        ipv6_count=len(ipv6_set),
        protocol_counts=protocol_counts,
        src_counts=src_counts,
        dst_counts=dst_counts,
        ip_category_counts=ip_category_counts,
        endpoints=endpoint_rows,
        conversations=conversation_rows,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        tls_client_hellos=tls_client_hellos,
        ja3_counts=ja3_counts,
        ja4_counts=ja4_counts,
        ja4s_counts=ja4s_counts,
        sni_counts=sni_counts,
        sni_entropy=sni_entropy,
        ja_reputation_hits=ja_reputation_hits,
        tls_cert_risks=tls_cert_risks,
        suspicious_port_profiles=suspicious_port_profiles,
        lateral_movement_scores=lateral_movement_scores,
        intel_findings=intel_findings,
        detections=detections,
        errors=errors,
    )
