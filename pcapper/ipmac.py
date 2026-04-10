from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .hostname import analyze_hostname
from .pcap_cache import get_reader

try:
    from scapy.layers.inet import IP  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore

try:
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IPv6 = None  # type: ignore

try:
    from scapy.layers.l2 import ARP, Ether  # type: ignore
except Exception:  # pragma: no cover
    ARP = None  # type: ignore
    Ether = None  # type: ignore

try:
    from scapy.config import conf as scapy_conf  # type: ignore
except Exception:  # pragma: no cover
    scapy_conf = None  # type: ignore

_MAC_HEX_RE = re.compile(r"^[0-9a-fA-F]{12}$")


@dataclass(frozen=True)
class IpMacAssociation:
    ip: str
    mac: str
    discovery_method: str
    count: int


@dataclass(frozen=True)
class MacLookupSummary:
    path: Path
    query_ip: str
    total_packets: int
    matches: int
    associations: list[IpMacAssociation]
    errors: list[str]


@dataclass(frozen=True)
class IpLookupSummary:
    path: Path
    query_mac: str
    total_packets: int
    matches: int
    associations: list[IpMacAssociation]
    ip_hostnames: dict[str, list[str]]
    errors: list[str]


def _canonical_mac(value: str | None) -> str:
    if not value:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", str(value))
    if not _MAC_HEX_RE.match(cleaned):
        return str(value).strip().lower()
    lower = cleaned.lower()
    return ":".join(lower[i : i + 2] for i in range(0, 12, 2))


def _is_usable_mac(value: str) -> bool:
    normalized = _canonical_mac(value)
    return bool(normalized and normalized != "00:00:00:00:00:00")


def _packet_ips(pkt: object) -> tuple[str, str]:
    src = ""
    dst = ""
    try:
        if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
            src = str(pkt[IP].src)  # type: ignore[index]
            dst = str(pkt[IP].dst)  # type: ignore[index]
        elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
            src = str(pkt[IPv6].src)  # type: ignore[index]
            dst = str(pkt[IPv6].dst)  # type: ignore[index]
    except Exception:
        return "", ""
    return src, dst


@lru_cache(maxsize=4096)
def mac_manufacturer(mac_value: str | None) -> str:
    mac = _canonical_mac(mac_value)
    if not _is_usable_mac(mac):
        return "-"
    if scapy_conf is None:
        return "-"
    manufdb = getattr(scapy_conf, "manufdb", None)
    if manufdb is None:
        return "-"
    try:
        result = manufdb.lookup(mac)
        if isinstance(result, tuple):
            for candidate in result:
                text = str(candidate or "").strip()
                if text and text.lower() != mac:
                    return text
            return "-"
        text = str(result or "").strip()
        if not text or text.lower() == mac:
            return "-"
        return text
    except Exception:
        return "-"


def analyze_mac_lookup(
    path: Path,
    ip_query: str | None,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> MacLookupSummary:
    if ARP is None and Ether is None:
        return MacLookupSummary(
            path=path,
            query_ip=str(ip_query),
            total_packets=0,
            matches=0,
            associations=[],
            errors=["Scapy L2 layers unavailable"],
        )

    query = str(ip_query or "").strip()

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path,
            show_status=show_status,
            packets=packets,
            meta=meta,
        )
    except Exception as exc:
        return MacLookupSummary(path, query, 0, 0, [], [f"Error opening pcap: {exc}"])

    total_packets = 0
    counts: dict[tuple[str, str, str], int] = {}

    def add_association(
        ip_value: str, mac_value: str, method: str
    ) -> None:
        ip_text = str(ip_value or "").strip()
        mac = _canonical_mac(mac_value)
        key = (ip_text, mac, method)
        if not ip_text or not _is_usable_mac(mac):
            return
        counts[key] = counts.get(key, 0) + 1

    try:
        for packet_number, pkt in enumerate(reader, start=1):
            total_packets = packet_number
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            if ARP is not None and pkt.haslayer(ARP):  # type: ignore[truthy-bool]
                try:
                    arp = pkt[ARP]  # type: ignore[index]
                    psrc = str(getattr(arp, "psrc", "") or "")
                    pdst = str(getattr(arp, "pdst", "") or "")
                    hwsrc = str(getattr(arp, "hwsrc", "") or "")
                    hwdst = str(getattr(arp, "hwdst", "") or "")
                    if not query or psrc == query:
                        add_association(psrc, hwsrc, "ARP sender")
                    if not query or pdst == query:
                        add_association(pdst, hwdst, "ARP target")
                except Exception:
                    pass

            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                src_ip, dst_ip = _packet_ips(pkt)
                try:
                    eth = pkt[Ether]  # type: ignore[index]
                    src_mac = str(getattr(eth, "src", "") or "")
                    dst_mac = str(getattr(eth, "dst", "") or "")
                    if not query or src_ip == query:
                        add_association(src_ip, src_mac, "Ethernet src")
                    if not query or dst_ip == query:
                        add_association(dst_ip, dst_mac, "Ethernet dst")
                except Exception:
                    pass
    except Exception as exc:
        associations = [
            IpMacAssociation(
                ip=ip,
                mac=mac,
                discovery_method=method,
                count=count,
            )
            for (ip, mac, method), count in counts.items()
        ]
        return MacLookupSummary(
            path,
            query,
            total_packets,
            len(associations),
            sorted(associations, key=lambda item: (-item.count, item.ip, item.mac)),
            [f"{type(exc).__name__}: {exc}"],
        )
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    associations = [
        IpMacAssociation(
            ip=ip,
            mac=mac,
            discovery_method=method,
            count=count,
        )
        for (ip, mac, method), count in counts.items()
    ]
    associations = sorted(associations, key=lambda item: (-item.count, item.ip, item.mac))
    return MacLookupSummary(path, query, total_packets, len(associations), associations, [])


def analyze_ip_lookup(
    path: Path,
    mac_query: str | None,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> IpLookupSummary:
    if ARP is None and Ether is None:
        return IpLookupSummary(
            path=path,
            query_mac=_canonical_mac(mac_query),
            total_packets=0,
            matches=0,
            associations=[],
            ip_hostnames={},
            errors=["Scapy L2 layers unavailable"],
        )

    query = _canonical_mac(mac_query)

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path,
            show_status=show_status,
            packets=packets,
            meta=meta,
        )
    except Exception as exc:
        return IpLookupSummary(
            path, query, 0, 0, [], {}, [f"Error opening pcap: {exc}"]
        )

    total_packets = 0
    counts: dict[tuple[str, str, str], int] = {}

    def add_association(
        ip_value: str, mac_value: str, method: str
    ) -> None:
        ip_text = str(ip_value or "").strip()
        mac_text = _canonical_mac(mac_value)
        key = (ip_text, mac_text, method)
        if not ip_text or not _is_usable_mac(mac_text):
            return
        counts[key] = counts.get(key, 0) + 1

    try:
        for packet_number, pkt in enumerate(reader, start=1):
            total_packets = packet_number
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            if ARP is not None and pkt.haslayer(ARP):  # type: ignore[truthy-bool]
                try:
                    arp = pkt[ARP]  # type: ignore[index]
                    psrc = str(getattr(arp, "psrc", "") or "")
                    pdst = str(getattr(arp, "pdst", "") or "")
                    hwsrc = _canonical_mac(str(getattr(arp, "hwsrc", "") or ""))
                    hwdst = _canonical_mac(str(getattr(arp, "hwdst", "") or ""))
                    if not query or hwsrc == query:
                        add_association(psrc, hwsrc, "ARP sender")
                    if not query or hwdst == query:
                        add_association(pdst, hwdst, "ARP target")
                except Exception:
                    pass

            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                src_ip, dst_ip = _packet_ips(pkt)
                try:
                    eth = pkt[Ether]  # type: ignore[index]
                    src_mac = _canonical_mac(str(getattr(eth, "src", "") or ""))
                    dst_mac = _canonical_mac(str(getattr(eth, "dst", "") or ""))
                    if not query or src_mac == query:
                        add_association(src_ip, src_mac, "Ethernet src")
                    if not query or dst_mac == query:
                        add_association(dst_ip, dst_mac, "Ethernet dst")
                except Exception:
                    pass
    except Exception as exc:
        associations = [
            IpMacAssociation(
                ip=ip,
                mac=mac,
                discovery_method=method,
                count=count,
            )
            for (ip, mac, method), count in counts.items()
        ]
        return IpLookupSummary(
            path,
            query,
            total_packets,
            len(associations),
            sorted(associations, key=lambda item: (-item.count, item.mac, item.ip)),
            {},
            [f"{type(exc).__name__}: {exc}"],
        )
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    associations = [
        IpMacAssociation(
            ip=ip,
            mac=mac,
            discovery_method=method,
            count=count,
        )
        for (ip, mac, method), count in counts.items()
    ]
    associations = sorted(associations, key=lambda item: (-item.count, item.mac, item.ip))
    ip_hostnames: dict[str, list[str]] = {}
    try:
        hostname_summary = analyze_hostname(path, target_ip=None, show_status=False)
        hostname_counts: dict[str, dict[str, int]] = {}
        for finding in list(getattr(hostname_summary, "findings", []) or []):
            ip_value = str(getattr(finding, "mapped_ip", "") or "").strip()
            host_value = str(getattr(finding, "hostname", "") or "").strip()
            if not ip_value or not host_value:
                continue
            per_ip = hostname_counts.setdefault(ip_value, {})
            per_ip[host_value] = per_ip.get(host_value, 0) + int(
                getattr(finding, "count", 1) or 1
            )
        for ip_value, counters in hostname_counts.items():
            ordered = sorted(counters.items(), key=lambda item: (-item[1], item[0]))
            ip_hostnames[ip_value] = [name for name, _count in ordered[:3]]
    except Exception:
        ip_hostnames = {}
    return IpLookupSummary(
        path,
        query,
        total_packets,
        len(associations),
        associations,
        ip_hostnames,
        [],
    )
