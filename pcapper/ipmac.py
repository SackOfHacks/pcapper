"""IP <-> MAC association lookups (``--mac`` and ``--ip``).

One packet pass serves both directions: every ARP sender/target pair and
every Ethernet src/dst pair is an (ip, mac, method) observation, and the two
CLI modes differ only in which side of the pair the query filters on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

from .hostname import analyze_hostname
from .pcap_cache import iter_packets
from .utils import extract_packet_endpoints, memoize_analysis

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


def _ip_mac_pass(
    path: Path,
    *,
    keep: Callable[[str, str], bool],
    show_status: bool,
    packets: list[object] | None,
    meta: object | None,
) -> tuple[int, dict[tuple[str, str, str], int], list[str]]:
    """Count every (ip, canonical mac, method) observation ``keep`` accepts.

    Returns ``(total_packets, counts, errors)``. A packet that raises during
    dissection is skipped and counted, not allowed to end the pass.
    """
    counts: dict[tuple[str, str, str], int] = {}
    total_packets = 0
    skipped = 0
    first_error: str | None = None

    def add(ip_value: object, mac_value: object, method: str) -> None:
        ip_text = str(ip_value or "").strip()
        mac = _canonical_mac(str(mac_value or ""))
        if not ip_text or not _is_usable_mac(mac) or not keep(ip_text, mac):
            return
        key = (ip_text, mac, method)
        counts[key] = counts.get(key, 0) + 1

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        try:
            getlayer = pkt.getlayer  # type: ignore[attr-defined]
            arp = getlayer(ARP) if ARP is not None else None
            if arp is not None:
                add(getattr(arp, "psrc", ""), getattr(arp, "hwsrc", ""), "ARP sender")
                add(getattr(arp, "pdst", ""), getattr(arp, "hwdst", ""), "ARP target")
            eth = getlayer(Ether) if Ether is not None else None
            if eth is not None:
                src_ip, dst_ip = extract_packet_endpoints(pkt, include_arp=False)
                add(src_ip or "", getattr(eth, "src", ""), "Ethernet src")
                add(dst_ip or "", getattr(eth, "dst", ""), "Ethernet dst")
        except Exception as exc:  # noqa: BLE001 — one bad packet must not end the pass
            skipped += 1
            if first_error is None:
                first_error = f"{type(exc).__name__}: {exc}"

    errors: list[str] = []
    if skipped:
        errors.append(
            f"{skipped} packet(s) skipped during IP/MAC association "
            f"(first error: {first_error}); counts are lower bounds."
        )
    return total_packets, counts, errors


def _associations(
    counts: dict[tuple[str, str, str], int], key: Callable[[IpMacAssociation], tuple]
) -> list[IpMacAssociation]:
    return sorted(
        (
            IpMacAssociation(ip=ip, mac=mac, discovery_method=method, count=count)
            for (ip, mac, method), count in counts.items()
        ),
        key=key,
    )


@memoize_analysis
def analyze_mac_lookup(
    path: Path,
    ip_query: str | None,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> MacLookupSummary:
    """MACs seen for an IP (``--mac -ip X``), or every IP->MAC pair."""
    query = str(ip_query or "").strip()
    if ARP is None and Ether is None:
        return MacLookupSummary(path, query, 0, 0, [], ["Scapy L2 layers unavailable"])
    total, counts, errors = _ip_mac_pass(
        path,
        keep=lambda ip, _mac: not query or ip == query,
        show_status=show_status,
        packets=packets,
        meta=meta,
    )
    associations = _associations(counts, key=lambda a: (-a.count, a.ip, a.mac))
    return MacLookupSummary(path, query, total, len(associations), associations, errors)


@memoize_analysis
def analyze_ip_lookup(
    path: Path,
    mac_query: str | None,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> IpLookupSummary:
    """IPs seen for a MAC (``--ip -mac X``), or every MAC->IP pair, with the
    hostnames discovered for each IP."""
    query = _canonical_mac(mac_query)
    if ARP is None and Ether is None:
        return IpLookupSummary(path, query, 0, 0, [], {}, ["Scapy L2 layers unavailable"])
    total, counts, errors = _ip_mac_pass(
        path,
        keep=lambda _ip, mac: not query or mac == query,
        show_status=show_status,
        packets=packets,
        meta=meta,
    )
    associations = _associations(counts, key=lambda a: (-a.count, a.mac, a.ip))

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
    except Exception as exc:  # noqa: BLE001
        errors = [*errors, f"hostname enrichment unavailable: {type(exc).__name__}: {exc}"]
    return IpLookupSummary(
        path, query, total, len(associations), associations, ip_hostnames, errors
    )


def _merged_counts(
    summaries: list, key: Callable[[IpMacAssociation], tuple]
) -> tuple[int, list[IpMacAssociation], list[str]]:
    total_packets = sum(int(item.total_packets or 0) for item in summaries)
    counts: dict[tuple[str, str, str], int] = {}
    errors: list[str] = []
    for item in summaries:
        errors.extend(list(item.errors or []))
        for assoc in list(item.associations or []):
            k = (str(assoc.ip), str(assoc.mac), str(assoc.discovery_method))
            counts[k] = counts.get(k, 0) + int(assoc.count or 0)
    return total_packets, _associations(counts, key=key), errors


def merge_mac_lookup_summaries(summaries: list[MacLookupSummary]) -> MacLookupSummary:
    if not summaries:
        return MacLookupSummary(Path("ALL_PCAPS"), "", 0, 0, [], [])
    total, associations, errors = _merged_counts(
        summaries, key=lambda a: (-a.count, a.ip, a.mac)
    )
    return MacLookupSummary(
        Path("ALL_PCAPS"), summaries[0].query_ip, total, len(associations), associations, errors
    )


def merge_ip_lookup_summaries(summaries: list[IpLookupSummary]) -> IpLookupSummary:
    if not summaries:
        return IpLookupSummary(Path("ALL_PCAPS"), "", 0, 0, [], {}, [])
    total, associations, errors = _merged_counts(
        summaries, key=lambda a: (-a.count, a.mac, a.ip)
    )
    hostnames_by_ip: dict[str, list[str]] = {}
    for item in summaries:
        for ip_value, names in dict(item.ip_hostnames or {}).items():
            existing = hostnames_by_ip.setdefault(str(ip_value), [])
            for name in list(names or []):
                text = str(name or "").strip()
                if text and text not in existing:
                    existing.append(text)
    return IpLookupSummary(
        Path("ALL_PCAPS"),
        summaries[0].query_mac,
        total,
        len(associations),
        associations,
        hostnames_by_ip,
        errors,
    )
