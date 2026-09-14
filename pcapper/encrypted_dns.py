from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

try:
    from scapy.layers.inet import TCP, UDP  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    Raw = None  # type: ignore


DOT_PORT = 853
DOQ_PORT = 853
# A packet *from* port 853 is a resolver's reply only when it goes back to a
# client's ephemeral port; otherwise a flow whose ephemeral source port happens
# to be 853 would be reported as DoT/DoQ with the roles inverted.
_EPHEMERAL_PORT_MIN = 1024

# Cleartext DoH: the request line of an HTTP/1.x request to a resolver path
# (RFC 8484 /dns-query, Google's JSON API /resolve). Only the request line is
# consulted — the old substring test matched "/resolve" anywhere in any
# payload (/resolver, /resolve-ticket, a JSON body) and counted it as DoH.
_HTTP_REQUEST_LINE_RE = re.compile(rb"\A(GET|POST) (\S+) HTTP/1\.[01]\r\n")
_DOH_CONTENT_TYPE_RE = re.compile(rb"(?im)^content-type:[ \t]*application/dns-message")


def _is_doh_request(payload: bytes) -> bool:
    match = _HTTP_REQUEST_LINE_RE.match(payload[:512])
    if not match:
        return False
    target = match.group(2)
    path = target.split(b"?", 1)[0].lower()
    query = target[len(path):].lower()
    if path == b"/dns-query" or path.startswith(b"/dns-query/"):
        return True
    if path == b"/resolve" and b"name=" in query:
        return True
    return bool(_DOH_CONTENT_TYPE_RE.search(payload[:4096]))


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


def _resolver_roles(
    src_ip: str, dst_ip: str, sport: int, dport: int, port: int
) -> Optional[tuple[str, str]]:
    """(client, resolver) when ``port`` is on the server side, else None."""
    if dport == port:
        return src_ip, dst_ip
    if sport == port and dport >= _EPHEMERAL_PORT_MIN:
        return dst_ip, src_ip
    return None


@memoize_analysis
def analyze_encrypted_dns(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> EncryptedDnsSummary:
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

    def _note(pkt: object, client: str, resolver: str) -> None:
        nonlocal first_seen, last_seen
        clients[client] += 1
        servers[resolver] += 1
        # The report window spans encrypted-DNS traffic, not every packet.
        ts = safe_float(getattr(pkt, "time", None))
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        src_ip, dst_ip = extract_packet_endpoints(pkt)
        if not src_ip or not dst_ip:
            continue

        tcp = pkt.getlayer(TCP) if TCP is not None else None  # type: ignore[arg-type]
        if tcp is not None:
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            roles = _resolver_roles(src_ip, dst_ip, sport, dport, DOT_PORT)
            if roles is not None:
                dot_packets += 1
                _note(pkt, *roles)
                continue
            raw = pkt.getlayer(Raw) if Raw is not None else None  # type: ignore[arg-type]
            if raw is not None:
                try:
                    payload = bytes(raw.load)
                except Exception:
                    payload = b""
                if payload and _is_doh_request(payload):
                    doh_packets += 1
                    _note(pkt, src_ip, dst_ip)
            continue

        udp = pkt.getlayer(UDP) if UDP is not None else None  # type: ignore[arg-type]
        if udp is not None:
            sport = int(getattr(udp, "sport", 0) or 0)
            dport = int(getattr(udp, "dport", 0) or 0)
            roles = _resolver_roles(src_ip, dst_ip, sport, dport, DOQ_PORT)
            if roles is not None:
                doq_packets += 1
                _note(pkt, *roles)

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
                "details": f"{doh_packets} cleartext HTTP requests to a DoH resolver path",
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

        tls_summary = analyze_tls(path, show_status=False, packets=packets, meta=meta)
        doh_snis = {
            sni: int(count)
            for sni, count in getattr(tls_summary, "sni_counts", {}).items()
            if _is_doh_provider_sni(str(sni))
        }
        if doh_snis:
            evidence = [
                f"{sni} ({count} TLS session(s))"
                for sni, count in sorted(
                    doh_snis.items(), key=lambda kv: (-kv[1], kv[0])
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
