from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter, defaultdict
import math

from .pcap_cache import get_reader
from .utils import safe_float
from .icmp import analyze_icmp
from .dns import analyze_dns
from .beacon import analyze_beacons
from .ips import analyze_ips
from .files import analyze_files

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


@dataclass(frozen=True)
class ThreatSummary:
    path: Path
    detections: list[dict[str, object]]
    errors: list[str]


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    mid = len(vals) // 2
    if len(vals) % 2 == 0:
        return (vals[mid - 1] + vals[mid]) / 2
    return vals[mid]


def _mad(values: list[float], center: float) -> float:
    if not values:
        return 0.0
    deviations = [abs(v - center) for v in values]
    return _median(deviations)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _base_domain(name: str) -> str:
    parts = [part for part in name.strip(".").split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name.strip(".")


def _country_from_geo(geo: Optional[str]) -> Optional[str]:
    if not geo:
        return None
    parts = [part.strip() for part in str(geo).split(",") if part.strip()]
    if not parts:
        return None
    return parts[-1]


def analyze_threats(path: Path, show_status: bool = True) -> ThreatSummary:
    errors: list[str] = []
    detections: list[dict[str, object]] = []

    # Aggregate detections from specialized modules
    icmp_summary = analyze_icmp(path, show_status=show_status)
    dns_summary = analyze_dns(path, show_status=show_status)
    beacon_summary = analyze_beacons(path, show_status=show_status)
    ip_summary = analyze_ips(path, show_status=show_status)
    files_summary = analyze_files(path, show_status=show_status)

    for item in icmp_summary.detections:
        detections.append({
            "source": "ICMP",
            **item,
        })
    for item in dns_summary.detections:
        detections.append({
            "source": "DNS",
            **item,
        })
    for item in beacon_summary.detections:
        detections.append({
            "source": "Beacon",
            **item,
        })
    for item in ip_summary.detections:
        detections.append({
            "source": "IP",
            **item,
        })

    smb1_sources: Counter[str] = Counter()
    smb1_destinations: Counter[str] = Counter()
    smb1_detected = False
    for item in files_summary.detections:
        detections.append({
            "source": "Files",
            **item,
        })
        if str(item.get("summary", "")).lower().startswith("smbv1 detected"):
            smb1_detected = True
            for ip, count in item.get("top_sources", []) or []:
                smb1_sources[ip] += count
            for ip, count in item.get("top_destinations", []) or []:
                smb1_destinations[ip] += count

    for art in files_summary.artifacts:
        if str(getattr(art, "protocol", "")).upper() == "SMB1":
            smb1_detected = True
            if art.src_ip:
                smb1_sources[art.src_ip] += 1
            if art.dst_ip:
                smb1_destinations[art.dst_ip] += 1

    if beacon_summary.candidates:
        for candidate in beacon_summary.candidates[:10]:
            duration = 0.0
            if candidate.first_seen is not None and candidate.last_seen is not None:
                duration = max(0.0, candidate.last_seen - candidate.first_seen)
            if candidate.src_port and candidate.dst_port:
                proto_label = f"{candidate.proto}:{candidate.src_port}->{candidate.dst_port}"
            elif candidate.dst_port:
                proto_label = f"{candidate.proto}:{candidate.dst_port}"
            else:
                proto_label = candidate.proto
            detections.append({
                "source": "Beacon",
                "severity": "info",
                "summary": "Beacon candidate flow",
                "details": f"{candidate.src_ip} -> {candidate.dst_ip} ({proto_label}) {candidate.count} events, "
                           f"mean {candidate.mean_interval:.2f}s, jitter {candidate.jitter:.2f}, duration {duration:.0f}s, "
                           f"top interval {candidate.top_interval}s, avg bytes {candidate.avg_bytes:.0f}",
                "top_sources": [(candidate.src_ip, candidate.count)],
                "top_destinations": [(candidate.dst_ip, candidate.count)],
            })

        c2_candidates = [c for c in beacon_summary.candidates if c.score >= 0.7]
        if c2_candidates:
            top_c2 = c2_candidates[:5]
            details = "; ".join(
                f"{c.src_ip}->{c.dst_ip} {c.proto}:{c.dst_port or '-'} score {c.score:.2f} "
                f"periodicity {c.periodicity_score:.2f} duration {c.duration_score:.2f}"
                for c in top_c2
            )
            high_risk = [c for c in c2_candidates if c.score >= 0.85 and c.periodicity_score >= 0.8]
            detections.append({
                "source": "Beacon",
                "severity": "critical" if high_risk else "warning",
                "summary": "C2 beacon scoring anomalies",
                "details": f"{len(c2_candidates)} high-scoring beacon flow(s). Top: {details}",
                "top_sources": Counter(c.src_ip for c in c2_candidates).most_common(5),
                "top_destinations": Counter(c.dst_ip for c in c2_candidates).most_common(5),
            })

    # Suspicious file download detection
    suspicious_exts = {
        ".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr",
        ".sys", ".lnk", ".zip", ".rar", ".7z", ".iso", ".img",
    }
    suspicious_artifacts: list[dict[str, object]] = []
    src_counts_files: Counter[str] = Counter()
    dst_counts_files: Counter[str] = Counter()
    for art in files_summary.artifacts:
        fname = art.filename.lower()
        ext = f".{fname.split('.')[-1]}" if "." in fname else ""
        is_suspicious = ext in suspicious_exts
        if not is_suspicious and "extracted_pe" in fname:
            is_suspicious = True
        ftype = getattr(art, "file_type", "UNKNOWN")
        if ftype in ("EXE/DLL", "ARCHIVE"):
            is_suspicious = True
        if is_suspicious:
            suspicious_artifacts.append({
                "filename": art.filename,
                "protocol": art.protocol,
                "file_type": ftype,
                "src": art.src_ip,
                "dst": art.dst_ip,
                "size": art.size_bytes,
            })
            if art.src_ip:
                src_counts_files[art.src_ip] += 1
            if art.dst_ip:
                dst_counts_files[art.dst_ip] += 1

    if suspicious_artifacts:
        detections.append({
            "source": "Files",
            "severity": "warning",
            "summary": "Potential malicious file downloads detected",
            "details": f"{len(suspicious_artifacts)} suspicious file(s) observed (executables/scripts/archives).",
            "top_sources": src_counts_files.most_common(3),
            "top_destinations": dst_counts_files.most_common(3),
        })
        for item in suspicious_artifacts[:10]:
            fname = str(item.get("filename", ""))
            ftype = str(item.get("file_type", "UNKNOWN"))
            ext = f".{fname.lower().split('.')[-1]}" if "." in fname else ""
            expected_type = None
            if ext in {".exe", ".dll", ".sys", ".scr"}:
                expected_type = "EXE/DLL"
            elif ext in {".zip", ".rar", ".7z", ".iso", ".img"}:
                expected_type = "ARCHIVE"
            elif ext in {".pdf"}:
                expected_type = "PDF"
            elif ext in {".doc", ".docx"}:
                expected_type = "DOC"
            elif ext in {".xls", ".xlsx"}:
                expected_type = "XLS"
            elif ext in {".ppt", ".pptx"}:
                expected_type = "PPT"
            elif ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"}:
                expected_type = "IMAGE"
            elif ext in {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm"}:
                expected_type = "VIDEO"

            mismatch = False
            if expected_type and ftype not in ("UNKNOWN", expected_type):
                mismatch = True

            detections.append({
                "source": "Files",
                "severity": "high" if mismatch else "info",
                "summary": "Suspicious file artifact" + (" (type mismatch)" if mismatch else ""),
                "details": f"{item['protocol']} {item['filename']} ({item['file_type']}) {item['src']} -> {item['dst']}",
            })

    # DGA-style heuristics (high-entropy/long DNS labels)
    if dns_summary.qname_counts:
        suspicious_qnames: list[tuple[str, int, float]] = []
        for qname, count in dns_summary.qname_counts.items():
            name = str(qname).strip(".")
            if not name or "." not in name:
                continue
            labels = [part for part in name.split(".") if part]
            if not labels:
                continue
            longest = max(labels, key=len)
            entropy = _shannon_entropy(longest)
            if len(longest) >= 12 and entropy >= 4.0:
                suspicious_qnames.append((name, int(count), entropy))

        if suspicious_qnames:
            ratio = len(suspicious_qnames) / max(1, len(dns_summary.qname_counts))
            if len(suspicious_qnames) >= 20 or (ratio >= 0.2 and len(suspicious_qnames) >= 5):
                top_q = sorted(suspicious_qnames, key=lambda x: (x[1], x[2]), reverse=True)[:5]
                details = ", ".join(f"{name}({count},H={entropy:.2f})" for name, count, entropy in top_q)
                detections.append({
                    "source": "DNS",
                    "severity": "warning",
                    "summary": "Potential DGA-style DNS activity",
                    "details": f"{len(suspicious_qnames)} high-entropy query names observed. Top: {details}",
                    "top_sources": dns_summary.client_counts.most_common(3),
                    "top_destinations": dns_summary.server_counts.most_common(3),
                })

    # Rare ASN / country alerts (requires GeoIP enrichment)
    if ip_summary.endpoints:
        asn_counts: Counter[str] = Counter()
        asn_bytes: Counter[str] = Counter()
        country_counts: Counter[str] = Counter()
        country_bytes: Counter[str] = Counter()

        for endpoint in ip_summary.endpoints:
            total_bytes = int(getattr(endpoint, "bytes_sent", 0) + getattr(endpoint, "bytes_recv", 0))
            if endpoint.asn:
                asn_counts[endpoint.asn] += 1
                asn_bytes[endpoint.asn] += total_bytes
            country = _country_from_geo(endpoint.geo)
            if country:
                country_counts[country] += 1
                country_bytes[country] += total_bytes

        if len(asn_counts) >= 5:
            rare_asn = [asn for asn, count in asn_counts.items() if count == 1 and asn_bytes[asn] >= 50000]
            if rare_asn:
                details = ", ".join(f"{asn}({asn_bytes[asn]} bytes)" for asn in rare_asn[:5])
                detections.append({
                    "source": "IP",
                    "severity": "warning",
                    "summary": "Rare ASN destinations observed",
                    "details": f"{len(rare_asn)} ASN(s) seen only once with notable traffic. Top: {details}",
                })

        if len(country_counts) >= 5:
            rare_countries = [c for c, count in country_counts.items() if count == 1 and country_bytes[c] >= 50000]
            if rare_countries:
                details = ", ".join(f"{c}({country_bytes[c]} bytes)" for c in rare_countries[:5])
                detections.append({
                    "source": "IP",
                    "severity": "warning",
                    "summary": "Rare country destinations observed",
                    "details": f"{len(rare_countries)} country/countries seen only once with notable traffic. Top: {details}",
                })

    if smb1_detected:
        detections.append({
            "source": "Files",
            "severity": "critical",
            "summary": "SMBv1 hosts detected",
            "details": "Hosts observed communicating with legacy SMBv1.",
            "top_sources": smb1_sources.most_common(10),
            "top_destinations": smb1_destinations.most_common(10),
        })

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    dst_port_counts: Counter[tuple[str, str]] = Counter()
    syn_counts: Counter[str] = Counter()
    udp_target_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    src_buckets: dict[str, Counter[int]] = defaultdict(Counter)
    dst_buckets: dict[str, Counter[int]] = defaultdict(Counter)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    bucket_seconds = 60.0

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

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

            if src_ip:
                src_counts[src_ip] += 1
                if ts is not None:
                    bucket = int(ts // bucket_seconds)
                    src_buckets[src_ip][bucket] += 1
            if dst_ip:
                dst_counts[dst_ip] += 1
                if ts is not None:
                    bucket = int(ts // bucket_seconds)
                    dst_buckets[dst_ip][bucket] += 1

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                dport = int(getattr(tcp_layer, "dport", 0))
                if src_ip and dst_ip and dport:
                    dst_port_counts[(src_ip, dst_ip)] += 1

                flags = getattr(tcp_layer, "flags", None)
                if flags is not None and "S" in str(flags) and "A" not in str(flags):
                    if src_ip:
                        syn_counts[src_ip] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                if dst_ip and getattr(udp_layer, "dport", None) is not None:
                    udp_target_counts[dst_ip] += 1
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    # Port scan heuristics
    for (src_ip, dst_ip), count in dst_port_counts.items():
        if count > 200:
            detections.append({
                "source": "Flow",
                "severity": "warning",
                "summary": "Potential port scan activity",
                "details": f"{src_ip} contacted many ports on {dst_ip} ({count} SYN/ports)",
                "top_sources": [(src_ip, count)],
                "top_destinations": [(dst_ip, count)],
            })
            break

    # SYN flood / scan rate
    if syn_counts:
        top_src, top_count = syn_counts.most_common(1)[0]
        if top_count > 2000:
            detections.append({
                "source": "TCP",
                "severity": "warning",
                "summary": "High SYN volume",
                "details": f"Source {top_src} sent {top_count} SYN packets.",
                "top_sources": syn_counts.most_common(3),
            })

    # UDP amplification / flood indicator
    if udp_target_counts:
        top_dst, top_count = udp_target_counts.most_common(1)[0]
        if top_count > 5000:
            detections.append({
                "source": "UDP",
                "severity": "warning",
                "summary": "Potential UDP flood",
                "details": f"Destination {top_dst} received {top_count} UDP packets.",
                "top_destinations": udp_target_counts.most_common(3),
            })

    # Generic high-volume target indicator
    if dst_counts:
        top_dst, top_dst_count = dst_counts.most_common(1)[0]
        if duration_seconds and duration_seconds > 0:
            rate = top_dst_count / duration_seconds
            if rate > 5000:
                detections.append({
                    "source": "Traffic",
                    "severity": "warning",
                    "summary": "High traffic concentration on a target",
                    "details": f"{top_dst} received {top_dst_count} packets (~{rate:.1f} pkt/s).",
                    "top_destinations": dst_counts.most_common(3),
                })

    # Burst analysis with baseline (per-minute buckets)
    burst_findings: list[dict[str, object]] = []
    for ip_key, bucket_counts in src_buckets.items():
        counts = list(bucket_counts.values())
        if len(counts) < 5:
            continue
        median = _median([float(v) for v in counts])
        mad = _mad([float(v) for v in counts], median)
        max_count = max(counts) if counts else 0
        threshold = max(50.0, median + (6.0 * mad))
        if max_count >= threshold and max_count >= (median * 5 if median > 0 else 50):
            peak_bucket = max(bucket_counts, key=bucket_counts.get)
            burst_findings.append({
                "role": "source",
                "ip": ip_key,
                "peak": int(max_count),
                "baseline": round(median, 2),
                "mad": round(mad, 2),
                "bucket": int(peak_bucket),
            })

    for ip_key, bucket_counts in dst_buckets.items():
        counts = list(bucket_counts.values())
        if len(counts) < 5:
            continue
        median = _median([float(v) for v in counts])
        mad = _mad([float(v) for v in counts], median)
        max_count = max(counts) if counts else 0
        threshold = max(50.0, median + (6.0 * mad))
        if max_count >= threshold and max_count >= (median * 5 if median > 0 else 50):
            peak_bucket = max(bucket_counts, key=bucket_counts.get)
            burst_findings.append({
                "role": "destination",
                "ip": ip_key,
                "peak": int(max_count),
                "baseline": round(median, 2),
                "mad": round(mad, 2),
                "bucket": int(peak_bucket),
            })

    if burst_findings:
        burst_findings.sort(key=lambda item: int(item.get("peak", 0)), reverse=True)
        top_bursts = burst_findings[:5]
        details = "; ".join(
            f"{item['role']} {item['ip']} peak {item['peak']} (baseline {item['baseline']}, MAD {item['mad']})"
            for item in top_bursts
        )
        detections.append({
            "source": "Traffic",
            "severity": "warning",
            "summary": "Burst traffic anomalies detected",
            "details": f"Baselined per-minute bursts identified. Top: {details}",
        })

    return ThreatSummary(path=path, detections=detections, errors=errors)
