from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import ipaddress
import os
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Iterable, Optional

from .arp import analyze_arp
from .domain import analyze_domain
from .dhcp import analyze_dhcp
from .hostdetails import _infer_operating_system
from .hostname import analyze_hostname
from .ips import analyze_ips
from .ldap import analyze_ldap
from .netbios import analyze_netbios
from .pcap_cache import get_reader
from .services import ServiceAsset, analyze_services
from .smb import analyze_smb
from .progress import run_with_busy_status

try:  # pragma: no cover - guarded for environments without scapy
    from scapy.layers.inet import IP, TCP  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = None  # type: ignore

try:  # pragma: no cover
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IPv6 = None  # type: ignore

MAX_FP_SAMPLES = int(os.getenv("PCAPPER_MAX_OS_FP_SAMPLES", "200000"))
MAX_FP_PER_HOST = int(os.getenv("PCAPPER_MAX_OS_FP_PER_HOST", "250"))
MAX_FP_EVIDENCE = 6


@dataclass(frozen=True)
class HostPort:
    port: int
    protocol: str
    service: str
    software: str | None = None


@dataclass(frozen=True)
class HostRecord:
    ip: str
    mac_addresses: list[str]
    hostnames: list[str]
    operating_system: str
    os_evidence: list[str]
    packets_sent: int
    packets_recv: int
    bytes_sent: int
    bytes_recv: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    open_ports: list[HostPort]


@dataclass(frozen=True)
class HostSummary:
    path: Path
    total_hosts: int
    hosts: list[HostRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _valid_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip_obj.is_unspecified or ip_obj.is_multicast:
        return False
    return True


def _normalize_mac(value: str) -> str | None:
    mac = value.strip().lower()
    if not mac or mac == "00:00:00:00:00:00":
        return None
    return mac


def _normalize_hostname(value: str) -> str:
    hostname = value.strip().strip(".")
    hostname = re.sub(r"\s+", "", hostname)
    if hostname.endswith("$"):
        hostname = hostname[:-1]
    return hostname.lower()


_HOSTNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,251}[a-z0-9]$", re.IGNORECASE)
_HOSTNAME_BLACKLIST = {
    "localdomain",
    "localdomain.local",
    "localhost",
    "localhost.localdomain",
    "local",
    "workgroup",
}
_DOMAIN_PREFIXES = (
    "_ldap._tcp.",
    "_ldap._udp.",
    "_gc._tcp.",
    "_kerberos._tcp.",
    "_kerberos._udp.",
    "_kpasswd._tcp.",
    "_kpasswd._udp.",
    "_msdcs.",
)


def _is_reasonable_hostname(value: str) -> bool:
    if not value:
        return False
    if len(value) > 253:
        return False
    if value.startswith(".") or " " in value:
        return False
    if value.lower().strip(".") in _HOSTNAME_BLACKLIST:
        return False
    if not _HOSTNAME_RE.match(value):
        return False
    return True


def _is_reasonable_domain(value: str) -> bool:
    if not _is_reasonable_hostname(value):
        return False
    if "." not in value:
        return False
    if value.lower().strip(".") in _HOSTNAME_BLACKLIST:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or not re.match(r"^[a-z0-9-]{1,63}$", label, re.IGNORECASE):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def _is_private_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip_obj.is_private


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip_obj.is_global


def _clean_domain_candidate(value: str) -> str:
    if not value:
        return ""
    text = value.strip().lower().strip(".")
    for prefix in _DOMAIN_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix):]
    while text.startswith("_"):
        text = text[1:]
    text = text.strip(".")
    return text


def _collect_domain_suffixes(
    domain_summary,
    ldap_summary,
    dhcp_summary,
    hostname_scores: dict[str, Counter[str]],
) -> list[str]:
    suffix_counts: Counter[str] = Counter()

    for suffix, count in getattr(ldap_summary, "ldap_domains", Counter()).items():
        candidate = _clean_domain_candidate(str(suffix))
        if _is_reasonable_domain(candidate):
            suffix_counts[candidate] += int(count or 1)

    for suffix, count in getattr(dhcp_summary, "domains", Counter()).items():
        candidate = _clean_domain_candidate(str(suffix))
        if _is_reasonable_domain(candidate):
            suffix_counts[candidate] += int(count or 1)

    seeded_suffixes = set(suffix_counts)
    if not seeded_suffixes:
        return []

    for ip_value, counter in hostname_scores.items():
        if not _is_private_ip(ip_value):
            continue
        for name, score in counter.items():
            if "." not in name:
                continue
            suffix = name.split(".", 1)[1]
            candidate = _clean_domain_candidate(suffix)
            if candidate in seeded_suffixes and _is_reasonable_domain(candidate):
                suffix_counts[candidate] += max(1, int(score or 1))

    return [name for name, _count in suffix_counts.most_common(5)]


def _hostname_weight(finding) -> int:
    weight = 1
    confidence = str(getattr(finding, "confidence", "") or "").upper()
    weight += {"HIGH": 4, "MEDIUM": 2, "LOW": 1}.get(confidence, 1)
    method = str(getattr(finding, "method", "") or "").lower()
    protocol = str(getattr(finding, "protocol", "") or "").lower()
    if "ptr" in method:
        weight += 6
    if "dhcp" in method:
        weight += 5
    if "nbns" in method or "netbios" in protocol:
        weight += 4
    if "ntlm" in method or "workstation" in method:
        weight += 4
    if "smb" in protocol:
        weight += 3
    if "tls" in protocol or "sni" in method or "certificate" in method:
        weight += 2
    if "http" in protocol:
        weight += 2
    if "unc" in method:
        weight = max(1, weight - 1)
    return weight


def _adjust_weight_for_ip(weight: int, ip_value: str, method: str, protocol: str) -> int:
    if weight <= 0 or not ip_value:
        return weight
    method_text = method.lower()
    protocol_text = protocol.lower()
    local_signal = any(token in method_text for token in ("nbns", "netbios", "ntlm", "workstation", "dhcp"))
    local_signal = local_signal or any(token in protocol_text for token in ("netbios", "smb", "ldap", "kerberos", "domain"))
    external_signal = any(token in method_text for token in ("http", "host header", "sni", "certificate"))
    external_signal = external_signal or any(token in protocol_text for token in ("http", "https", "tls"))

    if _is_private_ip(ip_value):
        if local_signal:
            weight += 3
        if external_signal:
            weight = max(1, weight - 2)
    elif _is_public_ip(ip_value):
        if external_signal:
            weight += 3
        if local_signal:
            weight = max(1, weight - 2)
    return weight


def _add_hostname_score(
    scores: dict[str, Counter[str]],
    ip_value: str,
    hostname: str,
    weight: int,
    *,
    method: str = "",
    protocol: str = "",
) -> None:
    if not ip_value or not _valid_ip(ip_value):
        return
    normalized = _normalize_hostname(hostname)
    if not _is_reasonable_hostname(normalized):
        return
    weight = _adjust_weight_for_ip(weight, ip_value, method, protocol)
    if weight <= 0:
        return
    scores[ip_value][normalized] += weight


def _build_hostname_scores(hostname_summary, netbios_summary, smb_summary) -> dict[str, Counter[str]]:
    scores: dict[str, Counter[str]] = defaultdict(Counter)

    for finding in getattr(hostname_summary, "findings", []) or []:
        mapped_ip = str(getattr(finding, "mapped_ip", "") or "")
        hostname = str(getattr(finding, "hostname", "") or "")
        if not hostname:
            continue
        base_weight = _hostname_weight(finding)
        method = str(getattr(finding, "method", "") or "")
        protocol = str(getattr(finding, "protocol", "") or "")
        weight = base_weight * max(1, int(getattr(finding, "count", 1) or 1))
        if mapped_ip and _valid_ip(mapped_ip):
            _add_hostname_score(scores, mapped_ip, hostname, weight, method=method, protocol=protocol)
            continue
        for fallback_ip in (getattr(finding, "src_ip", ""), getattr(finding, "dst_ip", "")):
            ip_text = str(fallback_ip or "")
            if _valid_ip(ip_text):
                _add_hostname_score(scores, ip_text, hostname, weight, method=method, protocol=protocol)

    for ip_value, host in getattr(netbios_summary, "hosts", {}).items():
        ip_text = str(ip_value or "")
        if not _valid_ip(ip_text):
            continue
        for nb_name in getattr(host, "names", []) or []:
            suffix = int(getattr(nb_name, "suffix", 0) or 0)
            if suffix in {0x00, 0x20}:
                weight = 6
            elif suffix in {0x1B, 0x1C, 0x1D, 0xE0, 0xDC}:
                weight = 4
            else:
                weight = 2
            _add_hostname_score(
                scores,
                ip_text,
                str(getattr(nb_name, "name", "") or ""),
                weight,
                method="NETBIOS",
                protocol="NETBIOS",
            )

        group_name = str(getattr(host, "group_name", "") or "")
        if group_name:
            _add_hostname_score(scores, ip_text, group_name, 1, method="NETBIOS group", protocol="NETBIOS")

    for session in getattr(smb_summary, "sessions", []) or []:
        workstation = str(getattr(session, "workstation", "") or "")
        client_ip = str(getattr(session, "client_ip", "") or "")
        if workstation:
            _add_hostname_score(scores, client_ip, workstation, 6, method="SMB workstation", protocol="SMB")

    return scores


def _apply_domain_suffixes(
    hostname_scores: dict[str, Counter[str]],
    suffixes: list[str],
) -> None:
    if not suffixes:
        return
    top_suffixes = suffixes[:2]
    for ip_value, counter in hostname_scores.items():
        if not _is_private_ip(ip_value):
            continue
        for name, score in list(counter.items()):
            if "." in name:
                continue
            if not _is_reasonable_hostname(name):
                continue
            for suffix in top_suffixes:
                fqdn = f"{name}.{suffix}"
                if not _is_reasonable_domain(fqdn):
                    continue
                counter[fqdn] += max(1, int(score or 1) + 3)


def _build_services(services_summary) -> dict[str, list[ServiceAsset]]:
    services_by_ip: dict[str, list[ServiceAsset]] = defaultdict(list)
    for asset in getattr(services_summary, "assets", []) or []:
        ip_value = str(getattr(asset, "ip", "") or "")
        if not _valid_ip(ip_value):
            continue
        services_by_ip[ip_value].append(asset)
    return services_by_ip


def _build_macs(ips_summary, arp_summary, dhcp_summary) -> dict[str, Counter[str]]:
    macs_by_ip: dict[str, Counter[str]] = defaultdict(Counter)

    for ip_value, counter in getattr(ips_summary, "ip_mac_counts", {}).items():
        if not _valid_ip(ip_value):
            continue
        for mac, count in counter.items():
            mac_norm = _normalize_mac(str(mac))
            if not mac_norm:
                continue
            try:
                macs_by_ip[ip_value][mac_norm] += int(count)
            except Exception:
                macs_by_ip[ip_value][mac_norm] += 1

    for convo in getattr(arp_summary, "conversations", []) or []:
        src_ip = str(getattr(convo, "src_ip", "") or "")
        dst_ip = str(getattr(convo, "dst_ip", "") or "")
        if src_ip and _valid_ip(src_ip):
            src_mac = _normalize_mac(str(getattr(convo, "src_mac", "") or ""))
            if src_mac:
                macs_by_ip[src_ip][src_mac] += 1
        if dst_ip and _valid_ip(dst_ip):
            dst_mac = _normalize_mac(str(getattr(convo, "dst_mac", "") or ""))
            if dst_mac:
                macs_by_ip[dst_ip][dst_mac] += 1

    for session in getattr(dhcp_summary, "sessions", []) or []:
        client_ip = str(getattr(session, "client_ip", "") or "")
        client_mac = _normalize_mac(str(getattr(session, "client_mac", "") or ""))
        if client_ip and _valid_ip(client_ip) and client_mac:
            macs_by_ip[client_ip][client_mac] += 1

    return macs_by_ip


def _default_ttl(ttl: int | None) -> int | None:
    if ttl is None:
        return None
    if ttl <= 32:
        return 32
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


def _fingerprint_os_hint(
    ttl: int | None,
    window: int | None,
    mss: int | None,
    wscale: int | None,
    sack: bool,
    ts: bool,
) -> tuple[str | None, int]:
    norm_ttl = _default_ttl(ttl)
    if norm_ttl == 128:
        if wscale is not None and wscale >= 8:
            return "Windows", 3
        return "Windows", 2
    if norm_ttl == 64:
        if wscale in {7, 8} and sack and ts:
            return "Linux/Unix", 3
        if wscale in {6} and ts and (mss in {1460, 1440}):
            return "macOS", 3
        return "Linux/Unix", 2
    if norm_ttl == 255:
        return "Network/Appliance", 2
    if norm_ttl == 32:
        return "Embedded/IoT", 1
    return None, 0


def _collect_os_fingerprints(path: Path, show_status: bool) -> tuple[dict[str, Counter[str]], dict[str, list[str]]]:
    if IP is None and IPv6 is None or TCP is None:
        return {}, {}

    hints: dict[str, Counter[str]] = defaultdict(Counter)
    evidence: dict[str, list[str]] = defaultdict(list)
    per_host = Counter()
    total_samples = 0

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    status.update(int(min(100, (stream.tell() / size_bytes) * 100)))
                except Exception:
                    pass

            if total_samples >= MAX_FP_SAMPLES:
                break
            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

            ip_layer = None
            src_ip = ""
            ttl = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", "") or "")
                ttl = int(getattr(ip_layer, "ttl", 0) or 0)
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", "") or "")
                ttl = int(getattr(ip_layer, "hlim", 0) or 0)
            if not src_ip or not _valid_ip(src_ip):
                continue

            if per_host[src_ip] >= MAX_FP_PER_HOST:
                continue

            tcp = pkt[TCP]  # type: ignore[index]
            try:
                flags = int(getattr(tcp, "flags", 0) or 0)
            except Exception:
                flags = 0
            if not (flags & 0x02):
                continue

            window = int(getattr(tcp, "window", 0) or 0)
            options = getattr(tcp, "options", []) or []
            mss = None
            wscale = None
            sack = False
            ts = False
            for opt in options:
                if not isinstance(opt, tuple) or not opt:
                    continue
                name = str(opt[0])
                if name == "MSS":
                    try:
                        mss = int(opt[1])
                    except Exception:
                        mss = None
                elif name in {"WScale", "WS"}:
                    try:
                        wscale = int(opt[1])
                    except Exception:
                        wscale = None
                elif name in {"SAckOK", "SACK"}:
                    sack = True
                elif name == "Timestamp":
                    ts = True

            hint, weight = _fingerprint_os_hint(ttl, window, mss, wscale, sack, ts)
            if hint:
                hints[src_ip][hint] += weight
                if len(evidence[src_ip]) < MAX_FP_EVIDENCE:
                    evidence[src_ip].append(
                        f"tcp_syn ttl={ttl} win={window} mss={mss or '-'} ws={wscale or '-'} "
                        f"sack={int(sack)} ts={int(ts)} -> {hint}"
                    )
            per_host[src_ip] += 1
            total_samples += 1
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    return hints, evidence


def _vendor_classes_for_host(ip_value: str, macs: list[str], dhcp_summary) -> Counter[str]:
    vendor_counter: Counter[str] = Counter()
    for mac in macs:
        vendor_counter.update(getattr(dhcp_summary, "vendor_classes_by_mac", {}).get(mac, Counter()))
    if ip_value:
        vendor_counter.update(getattr(dhcp_summary, "vendor_classes_by_ip", {}).get(ip_value, Counter()))
    return vendor_counter


def _infer_os(
    hostnames: set[str],
    services: list[ServiceAsset],
    vendor_classes: Counter[str] | None,
    fp_hints: Counter[str] | None,
    fp_evidence: list[str] | None,
) -> tuple[str, list[str]]:
    service_payload = [
        {
            "service": str(asset.service_name),
            "software": str(asset.software or ""),
        }
        for asset in services
    ]
    dhcp_stub = SimpleNamespace(vendor_classes=vendor_classes or Counter())
    os_guess, evidence = _infer_operating_system(hostnames, service_payload, dhcp_stub)

    if fp_hints:
        fp_name, fp_score = fp_hints.most_common(1)[0]
        evidence.append(f"tcp_fp:{fp_name}({fp_score})")
        if fp_evidence:
            for entry in fp_evidence[:3]:
                evidence.append(entry)
        if os_guess.lower() == "unknown":
            os_guess = fp_name

    return os_guess, evidence[:10]


def analyze_hosts(path: Path, show_status: bool = True) -> HostSummary:
    errors: list[str] = []

    ips_summary = analyze_ips(path, show_status=show_status)
    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(path, show_status, f"Hosts: {desc}", func, *args, **kwargs)

    hostname_summary = _busy("Hostnames", analyze_hostname, path, None, show_status=False)
    services_summary = _busy("Services", analyze_services, path, show_status=False)
    arp_summary = _busy("ARP", analyze_arp, path, show_status=False)
    dhcp_summary = _busy("DHCP", analyze_dhcp, path, show_status=False)
    domain_summary = _busy("Domain", analyze_domain, path, show_status=False)
    ldap_summary = _busy("LDAP", analyze_ldap, path, show_status=False)
    netbios_summary = _busy("NetBIOS", analyze_netbios, path, show_status=False)
    smb_summary = _busy("SMB", analyze_smb, path, show_status=False)
    fp_hints, fp_evidence = _busy("TCP fingerprints", _collect_os_fingerprints, path, show_status=False)

    errors.extend(getattr(ips_summary, "errors", []) or [])
    errors.extend(getattr(hostname_summary, "errors", []) or [])
    errors.extend(getattr(services_summary, "errors", []) or [])
    errors.extend(getattr(arp_summary, "errors", []) or [])
    errors.extend(getattr(dhcp_summary, "errors", []) or [])
    errors.extend(getattr(domain_summary, "errors", []) or [])
    errors.extend(getattr(ldap_summary, "errors", []) or [])
    errors.extend(getattr(netbios_summary, "errors", []) or [])
    errors.extend(getattr(smb_summary, "errors", []) or [])

    host_ips: set[str] = set()
    for ep in getattr(ips_summary, "endpoints", []) or []:
        ip_value = str(getattr(ep, "ip", "") or "")
        if _valid_ip(ip_value):
            host_ips.add(ip_value)
    for ip_value in getattr(ips_summary, "ip_mac_counts", {}).keys():
        if _valid_ip(ip_value):
            host_ips.add(ip_value)
    for asset in getattr(services_summary, "assets", []) or []:
        ip_value = str(getattr(asset, "ip", "") or "")
        if _valid_ip(ip_value):
            host_ips.add(ip_value)
    for finding in getattr(hostname_summary, "findings", []) or []:
        ip_value = str(getattr(finding, "mapped_ip", "") or "")
        if _valid_ip(ip_value):
            host_ips.add(ip_value)
    for convo in getattr(arp_summary, "conversations", []) or []:
        for ip_value in (getattr(convo, "src_ip", ""), getattr(convo, "dst_ip", "")):
            ip_text = str(ip_value or "")
            if _valid_ip(ip_text):
                host_ips.add(ip_text)
    for session in getattr(dhcp_summary, "sessions", []) or []:
        for ip_value in (getattr(session, "client_ip", ""), getattr(session, "server_ip", "")):
            ip_text = str(ip_value or "")
            if _valid_ip(ip_text):
                host_ips.add(ip_text)
    for ip_value in getattr(netbios_summary, "hosts", {}).keys():
        ip_text = str(ip_value or "")
        if _valid_ip(ip_text):
            host_ips.add(ip_text)
    for session in getattr(smb_summary, "sessions", []) or []:
        for ip_value in (getattr(session, "client_ip", ""), getattr(session, "server_ip", "")):
            ip_text = str(ip_value or "")
            if _valid_ip(ip_text):
                host_ips.add(ip_text)

    endpoints_by_ip = {str(ep.ip): ep for ep in getattr(ips_summary, "endpoints", []) or [] if _valid_ip(str(ep.ip))}
    hostname_scores = _build_hostname_scores(hostname_summary, netbios_summary, smb_summary)
    suffixes = _collect_domain_suffixes(domain_summary, ldap_summary, dhcp_summary, hostname_scores)
    _apply_domain_suffixes(hostname_scores, suffixes)
    services_by_ip = _build_services(services_summary)
    macs_by_ip = _build_macs(ips_summary, arp_summary, dhcp_summary)

    for ip_value, host in getattr(netbios_summary, "hosts", {}).items():
        mac = _normalize_mac(str(getattr(host, "mac", "") or ""))
        if mac and _valid_ip(str(ip_value or "")):
            macs_by_ip[str(ip_value)][mac] += 1

    hosts: list[HostRecord] = []
    for ip_value in sorted(host_ips):
        endpoint = endpoints_by_ip.get(ip_value)
        packets_sent = int(getattr(endpoint, "packets_sent", 0) or 0) if endpoint else 0
        packets_recv = int(getattr(endpoint, "packets_recv", 0) or 0) if endpoint else 0
        bytes_sent = int(getattr(endpoint, "bytes_sent", 0) or 0) if endpoint else 0
        bytes_recv = int(getattr(endpoint, "bytes_recv", 0) or 0) if endpoint else 0
        first_seen = getattr(endpoint, "first_seen", None) if endpoint else None
        last_seen = getattr(endpoint, "last_seen", None) if endpoint else None

        mac_counts = macs_by_ip.get(ip_value, Counter())
        macs = [mac for mac, _count in mac_counts.most_common()] if mac_counts else []

        raw_names = [name for name, _score in hostname_scores.get(ip_value, Counter()).most_common()]
        hostnames: list[str] = []
        for name in raw_names:
            if not _is_reasonable_hostname(name):
                continue
            if _is_public_ip(ip_value) and "." not in name:
                continue
            hostnames.append(name)
        services = services_by_ip.get(ip_value, [])
        vendor_classes = _vendor_classes_for_host(ip_value, macs, dhcp_summary)
        operating_system, os_evidence = _infer_os(
            set(hostnames),
            services,
            vendor_classes,
            fp_hints.get(ip_value, Counter()),
            fp_evidence.get(ip_value, []),
        )

        open_ports: list[HostPort] = []
        for asset in services:
            open_ports.append(
                HostPort(
                    port=int(getattr(asset, "port", 0) or 0),
                    protocol=str(getattr(asset, "protocol", "")) or "-",
                    service=str(getattr(asset, "service_name", "")) or "-",
                    software=str(getattr(asset, "software", "") or "") or None,
                )
            )
        open_ports.sort(key=lambda item: (item.port, item.protocol))

        hosts.append(
            HostRecord(
                ip=ip_value,
                mac_addresses=macs,
                hostnames=hostnames,
                operating_system=operating_system,
                os_evidence=os_evidence,
                packets_sent=packets_sent,
                packets_recv=packets_recv,
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
                first_seen=first_seen,
                last_seen=last_seen,
                open_ports=open_ports,
            )
        )

    hosts.sort(
        key=lambda host: (host.bytes_sent + host.bytes_recv, host.packets_sent + host.packets_recv),
        reverse=True,
    )

    return HostSummary(
        path=path,
        total_hosts=len(hosts),
        hosts=hosts,
        errors=sorted({err for err in errors if err}),
    )


def merge_hosts_summaries(summaries: Iterable[HostSummary]) -> HostSummary:
    summary_list = list(summaries)
    if not summary_list:
        return HostSummary(path=Path("ALL_PCAPS_0"), total_hosts=0, hosts=[], errors=[])

    host_map: dict[str, dict[str, object]] = {}
    error_set: set[str] = set()

    for summary in summary_list:
        error_set.update(getattr(summary, "errors", []) or [])
        for host in getattr(summary, "hosts", []) or []:
            entry = host_map.get(host.ip)
            if entry is None:
                entry = {
                    "macs": set(host.mac_addresses),
                    "hostnames": set(host.hostnames),
                    "open_ports": {},
                    "os_counts": Counter(),
                    "os_evidence": [],
                    "packets_sent": 0,
                    "packets_recv": 0,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "first_seen": None,
                    "last_seen": None,
                }
                host_map[host.ip] = entry

            entry["packets_sent"] = int(entry["packets_sent"]) + host.packets_sent
            entry["packets_recv"] = int(entry["packets_recv"]) + host.packets_recv
            entry["bytes_sent"] = int(entry["bytes_sent"]) + host.bytes_sent
            entry["bytes_recv"] = int(entry["bytes_recv"]) + host.bytes_recv
            entry["macs"].update(host.mac_addresses)
            entry["hostnames"].update(host.hostnames)
            entry["os_counts"].update([host.operating_system])

            for evidence in host.os_evidence:
                if evidence and evidence not in entry["os_evidence"]:
                    entry["os_evidence"].append(evidence)

            for port in host.open_ports:
                key = (port.port, port.protocol)
                existing = entry["open_ports"].get(key)
                if existing is None or (not existing.software and port.software):
                    entry["open_ports"][key] = port

            first_seen = entry["first_seen"]
            last_seen = entry["last_seen"]
            if host.first_seen is not None:
                if first_seen is None or host.first_seen < first_seen:
                    entry["first_seen"] = host.first_seen
            if host.last_seen is not None:
                if last_seen is None or host.last_seen > last_seen:
                    entry["last_seen"] = host.last_seen

    merged_hosts: list[HostRecord] = []
    for ip_value, entry in host_map.items():
        os_counts: Counter[str] = entry["os_counts"]
        os_selection = [
            (name, count) for name, count in os_counts.items() if name and name.lower() != "unknown"
        ]
        if os_selection:
            os_name = max(os_selection, key=lambda item: item[1])[0]
        elif os_counts:
            os_name = os_counts.most_common(1)[0][0]
        else:
            os_name = "Unknown"

        open_ports = list(entry["open_ports"].values())
        open_ports.sort(key=lambda item: (item.port, item.protocol))

        merged_hosts.append(
            HostRecord(
                ip=ip_value,
                mac_addresses=sorted(entry["macs"]),
                hostnames=sorted(entry["hostnames"]),
                operating_system=os_name,
                os_evidence=entry["os_evidence"],
                packets_sent=int(entry["packets_sent"]),
                packets_recv=int(entry["packets_recv"]),
                bytes_sent=int(entry["bytes_sent"]),
                bytes_recv=int(entry["bytes_recv"]),
                first_seen=entry["first_seen"],
                last_seen=entry["last_seen"],
                open_ports=open_ports,
            )
        )

    merged_hosts.sort(
        key=lambda host: (host.bytes_sent + host.bytes_recv, host.packets_sent + host.packets_recv),
        reverse=True,
    )

    return HostSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_hosts=len(merged_hosts),
        hosts=merged_hosts,
        errors=sorted(err for err in error_set if err),
    )
