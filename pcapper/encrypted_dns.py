from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

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


DOT_PORT = 853
DOQ_PORT = 853
DOH_PATH_MARKERS = (b"/dns-query", b"/dns-query?", b"/resolve")

# Public DoH resolvers. Real DoH rides TLS/443 so the cleartext /dns-query path
# never appears -- the network-visible signal is the TLS SNI of a known DoH
# endpoint. DoH to one of these bypasses DNS monitoring (a common C2/exfil
# evasion), so surface it as a hunt lead.
DOH_PROVIDER_HOSTS = (
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "dns.nextdns.io",
    "doh.dns.sb",
    "dns.cloudflare.com",
    "chrome.cloudflare-dns.com",
    "doh.pub",
    "dns.alidns.com",
)


def _is_doh_provider_sni(sni: str) -> bool:
    low = sni.lower().strip(".")
    return any(low == h or low.endswith("." + h) for h in DOH_PROVIDER_HOSTS)


@dataclass(frozen=True)
class EncryptedDnsSummary:
    path: Path
    total_packets: int
    dot_packets: int
    doh_packets: int
    doq_packets: int
    clients: Counter[str]
    servers: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


@memoize_analysis
def analyze_encrypted_dns(path: Path, show_status: bool = True) -> EncryptedDnsSummary:
    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )
    total_packets = 0
    dot_packets = 0
    doh_packets = 0
    doq_packets = 0
    clients: Counter[str] = Counter()
    servers: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
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

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                if sport == DOT_PORT or dport == DOT_PORT:
                    dot_packets += 1
                    clients[src_ip] += 1
                    servers[dst_ip] += 1
                payload = b""
                if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                    try:
                        payload = bytes(pkt[Raw].load)  # type: ignore[index]
                    except Exception:
                        payload = b""
                if payload:
                    if b"GET " in payload or b"POST " in payload:
                        if any(marker in payload for marker in DOH_PATH_MARKERS):
                            doh_packets += 1
                            clients[src_ip] += 1
                            servers[dst_ip] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                if sport == DOQ_PORT or dport == DOQ_PORT:
                    doq_packets += 1
                    clients[src_ip] += 1
                    servers[dst_ip] += 1

    finally:
        status.finish()
        reader.close()

    if dot_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "DNS over TLS observed",
                "details": f"{dot_packets} packets on TCP/853",
            }
        )
    if doh_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "DNS over HTTPS indicators observed",
                "details": f"{doh_packets} HTTP requests with /dns-query paths",
            }
        )
    if doq_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "DNS over QUIC observed",
                "details": f"{doq_packets} packets on UDP/853",
            }
        )

    # DoH-over-TLS detection via SNI of a known public DoH resolver (the real
    # DoH case -- the /dns-query path above only catches cleartext DoH proxies).
    try:
        from .tls import analyze_tls

        tls_summary = analyze_tls(path, show_status=False)
        doh_snis = {
            sni: int(count)
            for sni, count in getattr(tls_summary, "sni_counts", {}).items()
            if _is_doh_provider_sni(str(sni))
        }
        if doh_snis:
            evidence = [
                f"{sni} ({count} TLS session(s))"
                for sni, count in sorted(
                    doh_snis.items(), key=lambda kv: kv[1], reverse=True
                )[:8]
            ]
            detections.append(
                {
                    "severity": "warning",
                    "summary": "DNS over HTTPS to public resolver (TLS SNI)",
                    "details": (
                        "Encrypted DoH to known public resolver(s) observed via TLS "
                        "SNI; DoH bypasses local DNS monitoring and is a common "
                        "C2/exfil evasion channel. Confirm it is sanctioned."
                    ),
                    "evidence": evidence,
                }
            )
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"DoH SNI check unavailable: {type(exc).__name__}: {exc}")

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return EncryptedDnsSummary(
        path=path,
        total_packets=total_packets,
        dot_packets=dot_packets,
        doh_packets=doh_packets,
        doq_packets=doq_packets,
        clients=clients,
        servers=servers,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
