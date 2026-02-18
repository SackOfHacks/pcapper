from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter
import re

from .pcap_cache import get_reader
from .utils import safe_float
from .files import analyze_files

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


@dataclass(frozen=True)
class IocSummary:
    path: Path
    total_packets: int
    ip_hits: Counter[str]
    domain_hits: Counter[str]
    hash_hits: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _load_iocs(path: Path) -> tuple[set[str], set[str], set[str]]:
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    try:
        for line in path.read_text().splitlines():
            token = line.strip()
            if not token or token.startswith("#"):
                continue
            if re.fullmatch(r"[0-9a-fA-F]{32,64}", token):
                hashes.add(token.lower())
            elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", token):
                ips.add(token)
            else:
                domains.add(token.lower())
    except Exception:
        pass
    return ips, domains, hashes


def _extract_payload(pkt) -> bytes:
    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[Raw].load)  # type: ignore[index]
        except Exception:
            return b""
    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[TCP].payload)  # type: ignore[index]
        except Exception:
            return b""
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[UDP].payload)  # type: ignore[index]
        except Exception:
            return b""
    return b""


def analyze_iocs(path: Path, ioc_path: Path, show_status: bool = True) -> IocSummary:
    ips, domains, hashes = _load_iocs(ioc_path)
    ip_hits: Counter[str] = Counter()
    domain_hits: Counter[str] = Counter()
    hash_hits: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []

    files_summary = analyze_files(path, show_status=show_status)
    for artifact in files_summary.artifacts:
        sha = getattr(artifact, "sha256", None)
        md5 = getattr(artifact, "md5", None)
        if sha and sha.lower() in hashes:
            hash_hits[sha.lower()] += 1
        if md5 and md5.lower() in hashes:
            hash_hits[md5.lower()] += 1

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
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

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IP].src)  # type: ignore[index]
                dst_ip = str(pkt[IP].dst)  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IPv6].src)  # type: ignore[index]
                dst_ip = str(pkt[IPv6].dst)  # type: ignore[index]

            if src_ip and src_ip in ips:
                ip_hits[src_ip] += 1
            if dst_ip and dst_ip in ips:
                ip_hits[dst_ip] += 1

            if domains:
                payload = _extract_payload(pkt)
                if payload:
                    text = payload.decode("latin-1", errors="ignore").lower()
                    for domain in domains:
                        if domain in text:
                            domain_hits[domain] += 1

    finally:
        status.finish()
        reader.close()

    if ip_hits:
        detections.append({
            "severity": "high",
            "summary": "IOC IP match",
            "details": "; ".join(f"{ip} ({count})" for ip, count in ip_hits.most_common(5)),
        })
    if domain_hits:
        detections.append({
            "severity": "high",
            "summary": "IOC domain match",
            "details": "; ".join(f"{dom} ({count})" for dom, count in domain_hits.most_common(5)),
        })
    if hash_hits:
        detections.append({
            "severity": "critical",
            "summary": "IOC hash match",
            "details": "; ".join(f"{h} ({count})" for h, count in hash_hits.most_common(5)),
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return IocSummary(
        path=path,
        total_packets=total_packets,
        ip_hits=ip_hits,
        domain_hits=domain_hits,
        hash_hits=hash_hits,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
