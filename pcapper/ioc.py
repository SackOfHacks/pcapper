from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from collections import Counter
import re
import json

from .pcap_cache import get_reader
from .utils import safe_float, safe_read_text
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
    indicator_meta: dict[str, dict[str, object]] = field(default_factory=dict)
    source_counts: Counter[str] = field(default_factory=Counter)
    tag_counts: Counter[str] = field(default_factory=Counter)
    mitre_counts: Counter[str] = field(default_factory=Counter)
    avg_confidence: Optional[float] = None


def _load_iocs(path: Path, errors: list[str] | None = None) -> tuple[set[str], set[str], set[str], dict[str, dict[str, object]]]:
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    meta: dict[str, dict[str, object]] = {}
    raw = safe_read_text(path, error_list=errors, context="IOC file read")
    if not raw:
        return ips, domains, hashes, meta

    def _record_indicator(value: str, kind: str, entry: dict[str, object]) -> None:
        normalized = value.lower() if kind in {"domain", "hash"} else value
        if kind == "ip":
            ips.add(normalized)
        elif kind == "domain":
            domains.add(normalized)
        elif kind == "hash":
            hashes.add(normalized)
        if entry:
            meta[normalized] = entry

    if path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
        except Exception as exc:
            if errors is not None:
                errors.append(f"IOC JSON parse error: {exc}")
            data = None
        if isinstance(data, list) or isinstance(data, dict):
            entries = data if isinstance(data, list) else (data.get("indicators") or [])
            if isinstance(entries, list):
                for item in entries:
                    if not isinstance(item, dict):
                        continue
                    value = str(item.get("value") or "").strip()
                    if not value:
                        continue
                    kind = str(item.get("type") or item.get("kind") or "").strip().lower()
                    if not kind:
                        if re.fullmatch(r"[0-9a-fA-F]{32,64}", value):
                            kind = "hash"
                        elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
                            kind = "ip"
                        else:
                            kind = "domain"
                    source = str(item.get("source") or "").strip() or None
                    confidence = item.get("confidence")
                    conf_val: Optional[float] = None
                    if confidence is not None:
                        try:
                            conf_val = float(confidence)
                            if conf_val <= 1.0:
                                conf_val *= 100.0
                        except Exception:
                            conf_val = None
                    tags = item.get("tags") or []
                    if isinstance(tags, str):
                        tags = [t.strip() for t in tags.split(",") if t.strip()]
                    mitre = item.get("mitre") or item.get("mitre_attack") or []
                    if isinstance(mitre, str):
                        mitre = [m.strip() for m in mitre.split(",") if m.strip()]
                    entry = {
                        "source": source,
                        "confidence": conf_val,
                        "tags": tags,
                        "mitre": mitre,
                    }
                    _record_indicator(value, kind, entry)
                return ips, domains, hashes, meta

    for line in raw.splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        if re.fullmatch(r"[0-9a-fA-F]{32,64}", token):
            hashes.add(token.lower())
        elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", token):
            ips.add(token)
        else:
            domains.add(token.lower())
    return ips, domains, hashes, meta


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
    errors: list[str] = []
    ips, domains, hashes, meta = _load_iocs(ioc_path, errors=errors)
    ip_hits: Counter[str] = Counter()
    domain_hits: Counter[str] = Counter()
    hash_hits: Counter[str] = Counter()
    detections: list[dict[str, object]] = []

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
        def _format_hit(value: str, count: int) -> str:
            entry = meta.get(value)
            if not entry:
                return f"{value} ({count})"
            parts = []
            if entry.get("source"):
                parts.append(f"src={entry.get('source')}")
            if entry.get("confidence") is not None:
                parts.append(f"conf={int(entry.get('confidence') or 0)}")
            mitre = entry.get("mitre") or []
            if mitre:
                parts.append(f"mitre={','.join(str(m) for m in mitre[:3])}")
            suffix = f" ({count})"
            if parts:
                suffix = f" ({count}, {', '.join(parts)})"
            return f"{value}{suffix}"
        detections.append({
            "severity": "high",
            "summary": "IOC IP match",
            "details": "; ".join(_format_hit(ip, count) for ip, count in ip_hits.most_common(5)),
        })
    if domain_hits:
        def _format_hit(value: str, count: int) -> str:
            entry = meta.get(value)
            if not entry:
                return f"{value} ({count})"
            parts = []
            if entry.get("source"):
                parts.append(f"src={entry.get('source')}")
            if entry.get("confidence") is not None:
                parts.append(f"conf={int(entry.get('confidence') or 0)}")
            mitre = entry.get("mitre") or []
            if mitre:
                parts.append(f"mitre={','.join(str(m) for m in mitre[:3])}")
            suffix = f" ({count})"
            if parts:
                suffix = f" ({count}, {', '.join(parts)})"
            return f"{value}{suffix}"
        detections.append({
            "severity": "high",
            "summary": "IOC domain match",
            "details": "; ".join(_format_hit(dom, count) for dom, count in domain_hits.most_common(5)),
        })
    if hash_hits:
        def _format_hit(value: str, count: int) -> str:
            entry = meta.get(value)
            if not entry:
                return f"{value} ({count})"
            parts = []
            if entry.get("source"):
                parts.append(f"src={entry.get('source')}")
            if entry.get("confidence") is not None:
                parts.append(f"conf={int(entry.get('confidence') or 0)}")
            mitre = entry.get("mitre") or []
            if mitre:
                parts.append(f"mitre={','.join(str(m) for m in mitre[:3])}")
            suffix = f" ({count})"
            if parts:
                suffix = f" ({count}, {', '.join(parts)})"
            return f"{value}{suffix}"
        detections.append({
            "severity": "critical",
            "summary": "IOC hash match",
            "details": "; ".join(_format_hit(h, count) for h, count in hash_hits.most_common(5)),
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    source_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    mitre_counts: Counter[str] = Counter()
    conf_total = 0.0
    conf_count = 0

    def _accumulate(counter: Counter[str], hit_counter: Counter[str]) -> None:
        nonlocal conf_total, conf_count
        for value, count in hit_counter.items():
            entry = meta.get(value)
            if not entry:
                continue
            source = entry.get("source")
            if source:
                counter[source] += count
            tags = entry.get("tags") or []
            for tag in tags:
                tag_counts[str(tag)] += count
            mitre = entry.get("mitre") or []
            for item in mitre:
                mitre_counts[str(item)] += count
            conf = entry.get("confidence")
            if conf is not None:
                try:
                    conf_total += float(conf) * count
                    conf_count += count
                except Exception:
                    continue

    _accumulate(source_counts, ip_hits)
    _accumulate(source_counts, domain_hits)
    _accumulate(source_counts, hash_hits)
    avg_confidence = (conf_total / conf_count) if conf_count else None
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
        indicator_meta=meta,
        source_counts=source_counts,
        tag_counts=tag_counts,
        mitre_counts=mitre_counts,
        avg_confidence=avg_confidence,
    )
