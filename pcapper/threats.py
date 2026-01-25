from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter, defaultdict

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import safe_float, detect_file_type
from .icmp import analyze_icmp
from .dns import analyze_dns
from .beacon import analyze_beacons
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


def analyze_threats(path: Path, show_status: bool = True) -> ThreatSummary:
    errors: list[str] = []
    detections: list[dict[str, object]] = []

    # Aggregate detections from specialized modules
    icmp_summary = analyze_icmp(path, show_status=show_status)
    dns_summary = analyze_dns(path, show_status=show_status)
    beacon_summary = analyze_beacons(path, show_status=show_status)
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

    if smb1_detected:
        detections.append({
            "source": "Files",
            "severity": "critical",
            "summary": "SMBv1 hosts detected",
            "details": "Hosts observed communicating with legacy SMBv1.",
            "top_sources": smb1_sources.most_common(10),
            "top_destinations": smb1_destinations.most_common(10),
        })

    file_type = detect_file_type(path)
    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))

    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        pass
        
    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    dst_port_counts: Counter[tuple[str, str]] = Counter()
    syn_counts: Counter[str] = Counter()
    udp_target_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
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
            if dst_ip:
                dst_counts[dst_ip] += 1

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

    return ThreatSummary(path=path, detections=detections, errors=errors)
