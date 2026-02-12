from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import ipaddress
import re
import textwrap
from typing import Iterable

from .models import PcapSummary
from .utils import format_bytes_as_mb, format_duration, format_speed_bps, format_ts, sparkline, hexdump
from .coloring import danger, header, label, muted, ok, warn, highlight, orange
from .vlan import VlanSummary, VlanStat
from .icmp import IcmpSummary
from .dns import DnsSummary
from .beacon import BeaconSummary
from .threats import ThreatSummary
from .files import FileTransferSummary
from .protocols import ProtocolSummary
from .services import ServiceSummary, COMMON_PORTS
from .smb import SmbSummary
from .nfs import NfsSummary
from .strings import StringsSummary
from .creds import CredentialSummary
from .search import SearchSummary
from .certificates import CertificateSummary
from .tls import TlsSummary
from .ssh import SshSummary
from .syslog import SyslogSummary
from .tcp import TcpSummary
from .udp import UdpSummary, UdpConversation
from .exfil import ExfilSummary
from .http import HttpSummary
from .sizes import SizeSummary, render_size_sparkline
from .ips import IpSummary
from .timeline import TimelineSummary
from .health import HealthSummary


SECTION_BAR = "=" * 72
SUBSECTION_BAR = "-" * 72


def _format_linktype(value: object | None) -> str:
    if value is None:
        return "-"
    try:
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if isinstance(value, int):
            common = {
                0: "Null/Loopback",
                1: "Ethernet",
                6: "802.5 Token Ring",
                7: "ARCnet",
                8: "SLIP",
                9: "PPP",
                101: "Raw IP",
                105: "IEEE 802.11",
                113: "Linux cooked capture",
            }
            if value in common:
                return common[value]
            try:
                from scapy.data import l2types  # type: ignore

                mapped = l2types.get(value)
                if mapped is not None:
                    return str(mapped)
            except Exception:
                pass
            return f"LINKTYPE_{value}"
        return str(value)
    except Exception:
        return str(value)


def _format_kv(label_text: str, value: str, width: int = 24, color: bool | None = None) -> str:
    return f"{label(label_text, color):<{width}}: {value}"


def _format_table(rows: Iterable[list[str]]) -> str:
    rows = list(rows)
    if not rows:
        return "(none)"

    def _visible_len(text: str) -> int:
        return len(re.sub(r"\x1b\[[0-9;]*m", "", text))

    widths = [max(_visible_len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = []
    for row in rows:
        parts = []
        for idx, value in enumerate(row):
            pad = widths[idx] - _visible_len(value)
            parts.append(value + (" " * max(0, pad)))
        line = "  ".join(parts)
        lines.append(line)
    return "\n".join(lines)


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b[0-9A-Fa-f:]{2,}\b")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _highlight_public_ips(text: str) -> str:
    def _replace_ipv4(match: re.Match[str]) -> str:
        ip_value = match.group(0)
        return danger(ip_value) if _is_public_ip(ip_value) else ip_value

    def _replace_ipv6(match: re.Match[str]) -> str:
        token = match.group(0)
        if ":" not in token:
            return token
        return danger(token) if _is_public_ip(token) else token

    text = _IPV4_RE.sub(_replace_ipv4, text)
    return _IPV6_RE.sub(_replace_ipv6, text)


def _finalize_output(lines: list[str]) -> str:
    return _highlight_public_ips("\n".join(lines))


def _truncate_text(value: str, max_len: int = 80) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def render_generic_rollup(title: str, summaries: Iterable[object]) -> str:
    summary_list = list(summaries)
    if not summary_list:
        return ""

    totals: dict[str, float] = {}
    counters: dict[str, Counter[str]] = {}
    unions: dict[str, set[object]] = {}
    service_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    packet_buckets: dict[str, dict[str, float]] = {}
    payload_buckets: dict[str, dict[str, float]] = {}
    artifact_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()

    preferred_numeric = {
        "total_packets": "Total Packets",
        "total_bytes": "Total Bytes",
        "packet_count": "Total Packets",
        "packets": "Total Packets",
        "protocol_packets": "Protocol Packets",
        "protocol_bytes": "Protocol Bytes",
        "duration_seconds": "Combined Duration",
        "duration": "Combined Duration",
        "modbus_packets": "Modbus Packets",
        "dnp3_packets": "DNP3 Packets",
        "total_requests": "Total Requests",
        "total_responses": "Total Responses",
        "requests": "Total Requests",
        "responses": "Total Responses",
        "total_tagged_packets": "Tagged Packets",
        "total_tagged_bytes": "Tagged Bytes",
    }

    preferred_sets = {
        "src_ips": "Unique Source IPs",
        "dst_ips": "Unique Destination IPs",
        "client_ips": "Unique Clients",
        "server_ips": "Unique Servers",
        "clients": "Unique Clients",
        "servers": "Unique Servers",
    }

    for summary in summary_list:
        for name, value in vars(summary).items():
            if isinstance(value, Counter):
                counters.setdefault(name, Counter()).update(value)
            elif isinstance(value, set):
                unions.setdefault(name, set()).update(value)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                if name in preferred_numeric:
                    totals[name] = totals.get(name, 0.0) + float(value)

        summary_service_endpoints = getattr(summary, "service_endpoints", None)
        if isinstance(summary_service_endpoints, dict):
            for service, endpoints in summary_service_endpoints.items():
                if isinstance(endpoints, Counter):
                    service_endpoints[str(service)].update(endpoints)

        for bucket_name, bucket_store in (
            ("packet_size_buckets", packet_buckets),
            ("payload_size_buckets", payload_buckets),
        ):
            buckets = getattr(summary, bucket_name, None)
            if not buckets:
                continue
            for bucket in buckets:
                bucket_label = getattr(bucket, "label", None)
                if bucket_label is None:
                    continue
                entry = bucket_store.setdefault(
                    str(bucket_label),
                    {"count": 0.0, "sum": 0.0, "min": 0.0, "max": 0.0},
                )
                count = float(getattr(bucket, "count", 0) or 0)
                avg = float(getattr(bucket, "avg", 0.0) or 0.0)
                min_val = float(getattr(bucket, "min", 0) or 0)
                max_val = float(getattr(bucket, "max", 0) or 0)
                if entry["count"] == 0:
                    entry["min"] = min_val
                    entry["max"] = max_val
                else:
                    entry["min"] = min(entry["min"], min_val)
                    entry["max"] = max(entry["max"], max_val)
                entry["count"] += count
                entry["sum"] += avg * count

        artifacts = getattr(summary, "artifacts", None)
        if isinstance(artifacts, list):
            for artifact in artifacts:
                kind = str(getattr(artifact, "kind", "artifact"))
                detail = str(getattr(artifact, "detail", ""))
                artifact_counts[f"{kind}: {detail}"] += 1

        anomalies = getattr(summary, "anomalies", None)
        if isinstance(anomalies, list):
            for anomaly in anomalies:
                title = str(getattr(anomaly, "title", "Event"))
                anomaly_counts[title] += 1

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"{title} :: ALL PCAPS ({len(summary_list)})"))
    lines.append(SECTION_BAR)
    lines.append(_format_kv("PCAPs Analyzed", str(len(summary_list))))

    for key, label_text in preferred_numeric.items():
        if key in totals:
            value = totals[key]
            if key.endswith("bytes"):
                lines.append(_format_kv(label_text, format_bytes_as_mb(int(value))))
            elif "duration" in key:
                lines.append(_format_kv(label_text, format_duration(value)))
            else:
                lines.append(_format_kv(label_text, str(int(value))))

    for key, label_text in preferred_sets.items():
        if key in unions:
            lines.append(_format_kv(label_text, str(len(unions[key]))))

    client_counter = counters.get("client_ips") or counters.get("clients") or counters.get("src_ips")
    server_counter = counters.get("server_ips") or counters.get("servers") or counters.get("dst_ips")
    if client_counter or server_counter:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Endpoint Statistics"))
        col_width = 45
        lines.append(highlight(f"{'Clients':<{col_width}} | {'Servers'}"))
        lines.append(muted("-" * 90))
        clients = client_counter.most_common(10) if client_counter else []
        servers = server_counter.most_common(10) if server_counter else []
        max_rows = max(len(clients), len(servers))
        for i in range(max_rows):
            c_str = ""
            s_str = ""
            if i < len(clients):
                ip, cnt = clients[i]
                c_str = f"{ip} ({cnt})"
            if i < len(servers):
                ip, cnt = servers[i]
                s_str = f"{ip} ({cnt})"
            lines.append(f"{c_str:<{col_width}} | {s_str}")

    if counters:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Aggregated Counters"))
        ordered_counters = sorted(counters.items(), key=lambda item: sum(item[1].values()), reverse=True)
        for name, counter in ordered_counters[:4]:
            lines.append(label(name.replace("_", " ").title()))
            rows = [["Item", "Count"]]
            for item, count in counter.most_common(10):
                rows.append([str(item), str(count)])
            lines.append(_format_table(rows))

    if service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints"))
        rows = [["Service", "Top Endpoints"]]
        for service, counter in Counter({
            svc: sum(cnt.values()) for svc, cnt in service_endpoints.items()
        }).most_common(10):
            endpoints = service_endpoints.get(service, Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(3))
            rows.append([service, top_eps or "-"])
        lines.append(_format_table(rows))

    if packet_buckets or payload_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet/Payload Size Analysis"))

        def _render_bucket_table(bucket_store: dict[str, dict[str, float]], label_text: str) -> None:
            if not bucket_store:
                return
            total = sum(entry["count"] for entry in bucket_store.values())
            if not total:
                return
            rows = [["Bucket", "Count", "Pct", "Min", "Avg", "Max"]]
            for bucket_label, entry in bucket_store.items():
                avg = (entry["sum"] / entry["count"]) if entry["count"] else 0.0
                pct = (entry["count"] / total) * 100
                rows.append([
                    bucket_label,
                    str(int(entry["count"])),
                    f"{pct:.1f}%",
                    str(int(entry["min"])) if entry["min"] else "0",
                    f"{avg:.1f}",
                    str(int(entry["max"])) if entry["max"] else "0",
                ])
            lines.append(label(label_text))
            lines.append(_format_table(rows))

        _render_bucket_table(packet_buckets, "Packet Buckets")
        _render_bucket_table(payload_buckets, "Payload Buckets")

    if artifact_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Artifact", "Count"]]
        for detail, count in artifact_counts.most_common(12):
            rows.append([detail, str(count)])
        lines.append(_format_table(rows))

    if anomaly_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        rows = [["Title", "Count"]]
        for title, count in anomaly_counts.most_common(12):
            rows.append([title, str(count)])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def _protocol_rows(protocol_counts: Counter[str], packet_count: int, limit: int) -> list[list[str]]:
    rows = [["Protocol", "Packets", "Presence"]]
    for name, count in protocol_counts.most_common(limit):
        pct = "-"
        if packet_count:
            pct = f"{(count / packet_count) * 100:.1f}%"
        rows.append([name, str(count), pct])
    return rows


def render_summary(summary: PcapSummary, protocol_limit: int = 15) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"PCAPPER REPORT :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Path", str(summary.path)))
    lines.append(_format_kv("Type", summary.file_type))
    lines.append(_format_kv("Size", format_bytes_as_mb(summary.size_bytes)))
    lines.append(_format_kv("Packets", str(summary.packet_count)))
    lines.append(_format_kv("Start", format_ts(summary.start_ts)))
    lines.append(_format_kv("End", format_ts(summary.end_ts)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Interfaces", str(len(summary.interface_stats))))
    linktypes = sorted({iface.linktype for iface in summary.interface_stats if iface.linktype})
    snaplens = sorted({iface.snaplen for iface in summary.interface_stats if iface.snaplen is not None})
    if linktypes:
        lines.append(_format_kv("LinkTypes", ", ".join(linktypes)))
    if snaplens:
        lines.append(_format_kv("SnapLen", ", ".join(str(val) for val in snaplens)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Interface Statistics"))
    rows = [["Interface Name", "Dropped Packets", "Capture Filter", "Link Type", "Packet Size Limit"]]
    for iface in summary.interface_stats:
        if summary.file_type == "pcap":
            dropped = str(iface.dropped_packets) if iface.dropped_packets is not None else "not recorded"
            capture_filter = iface.capture_filter or "not recorded"
        else:
            dropped = str(iface.dropped_packets) if iface.dropped_packets is not None else "-"
            capture_filter = iface.capture_filter or "-"
        link_type = _format_linktype(iface.linktype)
        snaplen = str(iface.snaplen) if iface.snaplen is not None else "-"
        rows.append([
            iface.name,
            dropped,
            capture_filter,
            link_type,
            snaplen,
        ])
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Summary (presence across packets)"))
    lines.append(_format_table(_protocol_rows(summary.protocol_counts, summary.packet_count, protocol_limit)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("VLAN Summary"))
    vlan_ids: set[int] = set()
    for iface in summary.interface_stats:
        vlan_ids.update(iface.vlan_ids)
    if vlan_ids:
        vlan_list = ", ".join(str(vlan) for vlan in sorted(vlan_ids))
        lines.append(_format_kv("VLANs Observed", str(len(vlan_ids))))
        lines.append(_format_kv("VLAN IDs", vlan_list))
    else:
        lines.append(muted("No VLAN-tagged traffic detected."))
    lines.append(SECTION_BAR)

    return _finalize_output(lines)


def render_vlan_summary(summary: VlanSummary, limit: int = 20, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"VLAN ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Tagged Packets", str(summary.total_tagged_packets)))
    lines.append(_format_kv("Tagged Bytes", format_bytes_as_mb(summary.total_tagged_bytes)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if summary.vlan_stats:
        lines.append(SUBSECTION_BAR)
        lines.append(header("VLAN Inventory"))
        rows = [["VLAN", "Packets", "Bytes", "IPs", "Top Protocols", "First Seen", "Last Seen"]]
        for vlan in summary.vlan_stats[:limit]:
            ip_count = len(vlan.src_ips.union(vlan.dst_ips))
            proto_preview = ", ".join(name for name, _count in vlan.protocols.most_common(4)) or "-"
            rows.append([
                str(vlan.vlan_id),
                str(vlan.packets),
                format_bytes_as_mb(vlan.bytes),
                str(ip_count),
                proto_preview,
                format_ts(vlan.first_seen),
                format_ts(vlan.last_seen),
            ])
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("IPs Per VLAN"))
        ip_rows = [["VLAN", "IP Count", "IPs"]]
        for vlan in summary.vlan_stats[:limit]:
            ip_list = sorted(vlan.src_ips.union(vlan.dst_ips))
            preview = ip_list[:10]
            if len(ip_list) > 10:
                preview_text = ", ".join(preview) + f" (+{len(ip_list) - 10} more)"
            else:
                preview_text = ", ".join(preview) if preview else "-"
            ip_rows.append([
                str(vlan.vlan_id),
                str(len(ip_list)),
                preview_text,
            ])
        lines.append(_format_table(ip_rows))

        if verbose:
            lines.append(SUBSECTION_BAR)
            lines.append(header("VLAN Detailed Artifacts"))
            for vlan in summary.vlan_stats[:limit]:
                lines.append(label(f"VLAN {vlan.vlan_id}"))
                ip_list = sorted(vlan.src_ips.union(vlan.dst_ips))
                mac_list = sorted(vlan.src_macs.union(vlan.dst_macs))
                proto_list = ", ".join(
                    f"{name}({count})" for name, count in vlan.protocols.most_common(10)
                )
                lines.append(f"  IPs: {', '.join(ip_list) if ip_list else '-'}")
                lines.append(f"  MACs: {', '.join(mac_list) if mac_list else '-'}")
                lines.append(f"  Protocols: {proto_list if proto_list else '-'}")
    else:
        lines.append(muted("No VLAN-tagged traffic detected."))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = item.get("summary", "")
            details = item.get("details", "")
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            packet_count = item.get("packet_count")
            unique_sources = item.get("unique_sources")
            unique_destinations = item.get("unique_destinations")
            if packet_count is not None:
                lines.append(muted(f"  Packets: {packet_count}"))
            if unique_sources is not None or unique_destinations is not None:
                src_val = str(unique_sources) if unique_sources is not None else "-"
                dst_val = str(unique_destinations) if unique_destinations is not None else "-"
                lines.append(muted(f"  Unique Sources/Dests: {src_val}/{dst_val}"))
            top_sources = item.get("top_sources")
            if top_sources:
                src_text = ", ".join(f"{ip}({count})" for ip, count in top_sources)
                lines.append(muted(f"  Sources: {src_text}"))
            top_destinations = item.get("top_destinations")
            if top_destinations:
                dst_text = ", ".join(f"{ip}({count})" for ip, count in top_destinations)
                lines.append(muted(f"  Destinations: {dst_text}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_vlan_rollup(summaries: Iterable[VlanSummary], limit: int = 20, verbose: bool = False) -> str:
    summary_list = list(summaries)
    if not summary_list:
        return ""

    combined: dict[int, dict[str, object]] = {}
    total_tagged_packets = 0
    total_tagged_bytes = 0
    errors: set[str] = set()

    for summary in summary_list:
        total_tagged_packets += summary.total_tagged_packets
        total_tagged_bytes += summary.total_tagged_bytes
        errors.update(summary.errors)
        for stat in summary.vlan_stats:
            info = combined.setdefault(stat.vlan_id, {
                "packets": 0,
                "bytes": 0,
                "src_macs": set(),
                "dst_macs": set(),
                "src_ips": set(),
                "dst_ips": set(),
                "protocols": Counter(),
                "first_seen": None,
                "last_seen": None,
            })
            info["packets"] = int(info["packets"]) + stat.packets
            info["bytes"] = int(info["bytes"]) + stat.bytes
            info["src_macs"].update(stat.src_macs)
            info["dst_macs"].update(stat.dst_macs)
            info["src_ips"].update(stat.src_ips)
            info["dst_ips"].update(stat.dst_ips)
            info["protocols"].update(stat.protocols)
            if stat.first_seen is not None:
                if info["first_seen"] is None or stat.first_seen < info["first_seen"]:
                    info["first_seen"] = stat.first_seen
            if stat.last_seen is not None:
                if info["last_seen"] is None or stat.last_seen > info["last_seen"]:
                    info["last_seen"] = stat.last_seen

    stats_list: list[VlanStat] = []
    for vlan_id, info in combined.items():
        stats_list.append(
            VlanStat(
                vlan_id=vlan_id,
                packets=int(info["packets"]),
                bytes=int(info["bytes"]),
                src_macs=set(info["src_macs"]),
                dst_macs=set(info["dst_macs"]),
                src_ips=set(info["src_ips"]),
                dst_ips=set(info["dst_ips"]),
                protocols=Counter(info["protocols"]),
                first_seen=info["first_seen"],
                last_seen=info["last_seen"],
            )
        )

    stats_list.sort(key=lambda item: item.packets, reverse=True)

    detections: list[dict[str, str]] = []
    if stats_list:
        vlan_ids = sorted(v.vlan_id for v in stats_list)
        if 1 in vlan_ids:
            detections.append({
                "type": "vlan_default_used",
                "severity": "warning",
                "summary": "VLAN 1 (default) observed",
                "details": "Default VLAN is in use; consider verifying network segmentation policy.",
            })

        total_packets = sum(v.packets for v in stats_list)
        for stat in stats_list:
            if total_packets > 0:
                ratio = stat.packets / total_packets
                if ratio > 0.8 and stat.packets > 1000:
                    detections.append({
                        "type": "vlan_traffic_concentration",
                        "severity": "warning",
                        "summary": f"VLAN {stat.vlan_id} carries {ratio:.1%} of tagged traffic",
                        "details": "Check for misconfiguration or single-VLAN dependency.",
                    })
                if stat.packets < 10:
                    detections.append({
                        "type": "vlan_low_activity",
                        "severity": "info",
                        "summary": f"VLAN {stat.vlan_id} has low activity ({stat.packets} packets)",
                        "details": "Low activity VLANs can be normal; validate against expectations.",
                    })

    rollup_summary = VlanSummary(
        path=Path("ALL_PCAPS"),
        total_tagged_packets=total_tagged_packets,
        total_tagged_bytes=total_tagged_bytes,
        vlan_stats=stats_list,
        detections=detections,
        errors=sorted(errors),
    )
    return render_vlan_summary(rollup_summary, limit=limit, verbose=verbose)

def render_domain_summary(summary: "DomainAnalysis", limit: int = 25) -> str:
    from .domain import DomainAnalysis

    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MS AD & DOMAIN ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))

    if summary.domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Domain Names"))
        rows = [["Domain", "Count"]]
        for name, count in summary.domains.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.dc_hosts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Controllers (NetBIOS/DNS)"))
        rows = [["IP", "Count"]]
        for ip, count in summary.dc_hosts.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    if summary.service_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Services"))
        rows = [["Service", "Name", "Count"]]
        for svc, count in summary.service_counts.most_common(limit):
            svc_name = "-"
            try:
                _proto, port_str = svc.split("/", 1)
                port = int(port_str)
                svc_name = COMMON_PORTS.get(port, "-")
            except Exception:
                svc_name = "-"
            rows.append([svc, svc_name, str(count)])
        lines.append(_format_table(rows))

    if summary.servers or summary.clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Domain Servers & Clients"))
        rows = [["Servers", "Clients"]]
        server_text = ", ".join(f"{ip}({count})" for ip, count in summary.servers.most_common(10)) or "-"
        client_text = ", ".join(f"{ip}({count})" for ip, count in summary.clients.most_common(10)) or "-"
        rows.append([server_text, client_text])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Conversations"))
        rows = [["Src", "Dst", "Port", "Proto", "Packets"]]
        for convo in summary.conversations[:limit]:
            rows.append([convo.src_ip, convo.dst_ip, str(convo.dst_port), convo.proto, str(convo.packets)])
        lines.append(_format_table(rows))

    if summary.urls:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed URLs"))
        rows = [["URL", "Count"]]
        for url, count in summary.urls.most_common(limit):
            rows.append([url, str(count)])
        lines.append(_format_table(rows))

    if summary.user_agents:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed User Agents"))
        rows = [["User Agent", "Count"]]
        for ua, count in summary.user_agents.most_common(limit):
            rows.append([ua, str(count)])
        lines.append(_format_table(rows))

    if summary.users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for user, count in summary.users.most_common(limit):
            rows.append([user, str(count)])
        lines.append(_format_table(rows))

    if summary.credentials:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Credentials"))
        rows = [["Credential", "Count"]]
        for cred, count in summary.credentials.most_common(limit):
            rows.append([cred, str(count)])
        lines.append(_format_table(rows))

    if summary.computer_names:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Computer Names"))
        rows = [["Computer", "Count"]]
        for name, count in summary.computer_names.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.response_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["Code", "Count"]]
        for code, count in summary.response_codes.most_common(limit):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    if summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request Summary"))
        rows = [["Request", "Count"]]
        for name, count in summary.request_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.files:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        for name in summary.files[:limit]:
            lines.append(f"- {name}")

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            lines.append(warn(f"- {item}"))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            summary_lower = summary_text.lower()
            if "extension/type mismatch" in summary_lower:
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            elif severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_ldap_summary(summary: "LdapAnalysis", limit: int = 25) -> str:
    from .ldap import LdapAnalysis

    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"LDAP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    if summary.session_stats:
        lines.append(_format_kv("LDAP Sessions", str(summary.session_stats.get("total_sessions", 0))))
        lines.append(_format_kv("Unique Clients", str(summary.session_stats.get("unique_clients", 0))))
        lines.append(_format_kv("Unique Servers", str(summary.session_stats.get("unique_servers", 0))))

    if summary.ldap_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP-Related DNS"))
        rows = [["Domain", "Count"]]
        for name, count in summary.ldap_domains.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.servers or summary.clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top LDAP Servers & Clients"))
        rows = [["Servers", "Clients"]]
        server_text = ", ".join(f"{ip}({count})" for ip, count in summary.servers.most_common(10)) or "-"
        client_text = ", ".join(f"{ip}({count})" for ip, count in summary.clients.most_common(10)) or "-"
        rows.append([server_text, client_text])
        lines.append(_format_table(rows))

    if summary.service_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Service Ports"))
        rows = [["Service", "Name", "Count"]]
        for svc, count in summary.service_counts.most_common(limit):
            svc_name = "-"
            try:
                _proto, port_str = svc.split("/", 1)
                port = int(port_str)
                svc_name = COMMON_PORTS.get(port, "-")
            except Exception:
                svc_name = "-"
            rows.append([svc, svc_name, str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Conversations"))
        rows = [["Src", "Dst", "Port", "Proto", "Packets"]]
        for convo in summary.conversations[:limit]:
            rows.append([convo.src_ip, convo.dst_ip, str(convo.dst_port), convo.proto, str(convo.packets)])
        lines.append(_format_table(rows))

    if summary.ldap_queries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Queries"))
        rows = [["Query", "Count"]]
        for query, count in summary.ldap_queries.most_common(limit):
            rows.append([query, str(count)])
        lines.append(_format_table(rows))

    if summary.ldap_filter_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top LDAP Queries by Filter Type"))
        rows = [["Filter Type", "Count"]]
        for name, count in summary.ldap_filter_types.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.ldap_binds:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Binds"))
        rows = [["Bind Identity", "Count"]]
        for name, count in summary.ldap_binds.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.ldap_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Users"))
        rows = [["User", "Count"]]
        for user, count in summary.ldap_users.most_common(limit):
            rows.append([user, str(count)])
        lines.append(_format_table(rows))

    if summary.ldap_systems:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Systems"))
        rows = [["System", "Count"]]
        for system, count in summary.ldap_systems.most_common(limit):
            rows.append([system, str(count)])
        lines.append(_format_table(rows))

    if summary.response_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Response Codes"))
        rows = [["Code", "Count"]]
        for code, count in summary.response_codes.most_common(limit):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    if summary.ldap_error_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top LDAP Errors by Code"))
        rows = [["Error", "Count"]]
        for code, count in summary.ldap_error_codes.most_common(limit):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    if summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Requests"))
        rows = [["Request", "Count"]]
        for name, count in summary.request_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.cleartext_packets or summary.ldaps_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Cleartext vs LDAPS Ratio"))
        total = summary.cleartext_packets + summary.ldaps_packets
        clear_pct = (summary.cleartext_packets / total * 100.0) if total else 0.0
        ldaps_pct = (summary.ldaps_packets / total * 100.0) if total else 0.0
        rows = [["Type", "Packets", "Percent"]]
        rows.append(["Cleartext", str(summary.cleartext_packets), f"{clear_pct:.1f}%"])
        rows.append(["LDAPS", str(summary.ldaps_packets), f"{ldaps_pct:.1f}%"])
        lines.append(_format_table(rows))

    if summary.secrets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Secrets/Passwords"))
        rows = [["Value", "Count"]]
        for secret, count in summary.secrets.most_common(limit):
            rows.append([secret, str(count)])
        lines.append(_format_table(rows))

    if summary.public_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Public IP LDAP Endpoints"))
        rows = [["Endpoint", "Count"]]
        for ip, count in summary.public_endpoints.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_attributes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Attributes Queried"))
        rows = [["Attribute", "Count"]]
        for name, count in summary.suspicious_attributes.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.bind_bursts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Burst Activity / Brute Force Indicators"))
        rows = [["Client", "Peak Binds/Min"]]
        for client, count in summary.bind_bursts.most_common(limit):
            rows.append([client, str(count)])
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        lines.append(muted(", ".join(summary.artifacts[:limit])))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            lines.append(warn(f"- {item}"))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if "extension/type mismatch" in summary_text.lower():
                severity = "high"
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_kerberos_summary(summary: "KerberosAnalysis", limit: int = 25) -> str:
    from .kerberos import KerberosAnalysis

    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"KERBEROS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    if summary.session_stats:
        lines.append(_format_kv("Kerberos Sessions", str(summary.session_stats.get("total_sessions", 0))))
        lines.append(_format_kv("Unique Clients", str(summary.session_stats.get("unique_clients", 0))))
        lines.append(_format_kv("Unique Servers", str(summary.session_stats.get("unique_servers", 0))))

    if summary.servers or summary.clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Kerberos Servers & Clients"))
        rows = [["Servers", "Clients"]]
        server_text = ", ".join(f"{ip}({count})" for ip, count in summary.servers.most_common(10)) or "-"
        client_text = ", ".join(f"{ip}({count})" for ip, count in summary.clients.most_common(10)) or "-"
        rows.append([server_text, client_text])
        lines.append(_format_table(rows))

    if summary.service_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Service Ports"))
        rows = [["Service", "Name", "Count"]]
        for svc, count in summary.service_counts.most_common(limit):
            svc_name = "-"
            try:
                _proto, port_str = svc.split("/", 1)
                port = int(port_str)
                svc_name = COMMON_PORTS.get(port, "-")
            except Exception:
                svc_name = "-"
            rows.append([svc, svc_name, str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Conversations"))
        rows = [["Src", "Dst", "Port", "Proto", "Packets"]]
        for convo in summary.conversations[:limit]:
            rows.append([convo.src_ip, convo.dst_ip, str(convo.dst_port), convo.proto, str(convo.packets)])
        lines.append(_format_table(rows))

    if summary.request_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Request Types"))
        rows = [["Type", "Count"]]
        for name, count in summary.request_types.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.error_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Kerberos Errors by Code"))
        rows = [["Error", "Count"]]
        for name, count in summary.error_codes.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.realms:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Realms"))
        rows = [["Realm", "Count"]]
        for name, count in summary.realms.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.principals:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Principals"))
        rows = [["Principal", "Count"]]
        for name, count in summary.principals.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.spns:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Principals (SPNs)"))
        rows = [["SPN", "Count"]]
        for name, count in summary.spns.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.public_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Public IP Kerberos Endpoints"))
        rows = [["Endpoint", "Count"]]
        for ip, count in summary.public_endpoints.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_attributes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Kerberos Indicators"))
        rows = [["Indicator", "Count"]]
        for name, count in summary.suspicious_attributes.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.bind_bursts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Burst Activity / Brute Force Indicators"))
        rows = [["Client", "Peak AS/TGS Requests/Min"]]
        for client, count in summary.bind_bursts.most_common(limit):
            rows.append([client, str(count)])
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        lines.append(muted(", ".join(summary.artifacts[:limit])))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            lines.append(warn(f"- {item}"))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_icmp_summary(summary: IcmpSummary, limit: int = 12, verbose: bool = False) -> str:
    def _icmpv4_type_name(type_id: int) -> str:
        return {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            9: "Router Advertisement",
            10: "Router Solicitation",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply",
            17: "Address Mask Request",
            18: "Address Mask Reply",
        }.get(type_id, "Unknown")

    def _icmpv4_code_name(type_id: int, code_id: int) -> str:
        if type_id == 3:
            return {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Needed",
                5: "Source Route Failed",
                6: "Network Unknown",
                7: "Host Unknown",
                8: "Host Isolated",
                9: "Network Prohibited",
                10: "Host Prohibited",
                11: "Network Unreachable for TOS",
                12: "Host Unreachable for TOS",
                13: "Communication Prohibited",
                14: "Host Precedence Violation",
                15: "Precedence Cutoff",
            }.get(code_id, "Unknown")
        if type_id == 5:
            return {
                0: "Redirect for Network",
                1: "Redirect for Host",
                2: "Redirect for TOS and Network",
                3: "Redirect for TOS and Host",
            }.get(code_id, "Unknown")
        if type_id == 11:
            return {
                0: "TTL Exceeded in Transit",
                1: "Fragment Reassembly Time Exceeded",
            }.get(code_id, "Unknown")
        if type_id == 12:
            return {
                0: "Pointer Indicates Error",
                1: "Missing Required Option",
                2: "Bad Length",
            }.get(code_id, "Unknown")
        return "Unknown"

    def _icmpv6_type_name(type_id: int) -> str:
        return {
            1: "Destination Unreachable",
            2: "Packet Too Big",
            3: "Time Exceeded",
            4: "Parameter Problem",
            128: "Echo Request",
            129: "Echo Reply",
            133: "Router Solicitation",
            134: "Router Advertisement",
            135: "Neighbor Solicitation",
            136: "Neighbor Advertisement",
            137: "Redirect",
        }.get(type_id, "Unknown")

    def _icmpv6_code_name(type_id: int, code_id: int) -> str:
        if type_id == 1:
            return {
                0: "No Route to Destination",
                1: "Admin Prohibited",
                2: "Beyond Scope",
                3: "Address Unreachable",
                4: "Port Unreachable",
                5: "Source Address Failed Policy",
                6: "Reject Route",
            }.get(code_id, "Unknown")
        if type_id == 3:
            return {
                0: "Hop Limit Exceeded",
                1: "Fragment Reassembly Time Exceeded",
            }.get(code_id, "Unknown")
        if type_id == 4:
            return {
                0: "Erroneous Header Field",
                1: "Unrecognized Next Header",
                2: "Unrecognized IPv6 Option",
            }.get(code_id, "Unknown")
        return "Unknown"

    def _type_label(key: str) -> str:
        try:
            family, type_id = key.split(":", 1)
            type_num = int(type_id)
        except Exception:
            return key
        if family == "icmpv4":
            return f"ICMPv4 {_icmpv4_type_name(type_num)} ({type_num})"
        if family == "icmpv6":
            return f"ICMPv6 {_icmpv6_type_name(type_num)} ({type_num})"
        return key

    def _code_label(key: str) -> str:
        try:
            family, type_id, code_id = key.split(":", 2)
            type_num = int(type_id)
            code_num = int(code_id)
        except Exception:
            return key
        if family == "icmpv4":
            return f"ICMPv4 {_icmpv4_type_name(type_num)}: {_icmpv4_code_name(type_num, code_num)} ({type_num}/{code_num})"
        if family == "icmpv6":
            return f"ICMPv6 {_icmpv6_type_name(type_num)}: {_icmpv6_code_name(type_num, code_num)} ({type_num}/{code_num})"
        return key
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ICMP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("ICMP Packets", str(summary.total_packets)))
    lines.append(_format_kv("ICMP Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("ICMPv4", str(summary.ipv4_packets)))
    lines.append(_format_kv("ICMPv6", str(summary.ipv6_packets)))
    lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
    lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    lines.append(_format_kv("Avg Payload", f"{summary.avg_payload_bytes:.1f} bytes"))
    lines.append(_format_kv("Max Payload", f"{summary.max_payload_bytes} bytes"))
    lines.append(_format_kv("Payload Variants", str(summary.payload_size_variants)))
    if summary.duration_seconds:
        pps = summary.total_packets / summary.duration_seconds if summary.duration_seconds else 0.0
        lines.append(_format_kv("ICMP Rate", f"{pps:.1f} pkt/s"))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if summary.type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Types"))
        rows = [["Type", "Packets"]]
        for name, count in summary.type_counts.most_common(limit):
            rows.append([_type_label(name), str(count)])
        lines.append(_format_table(rows))

    if summary.code_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Codes"))
        rows = [["Type:Code", "Packets"]]
        for name, count in summary.code_counts.most_common(limit):
            rows.append([_code_label(name), str(count)])
        lines.append(_format_table(rows))

    if summary.request_counts or summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Requests & Responses"))
        rows = [["Category", "Requests", "Responses"]]
        categories = set(summary.request_counts.keys()).union(summary.response_counts.keys())
        for name in sorted(categories):
            rows.append([
                name,
                str(summary.request_counts.get(name, 0)),
                str(summary.response_counts.get(name, 0)),
            ])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Conversations"))
        rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "First Seen", "Last Seen"]]
        for convo in sorted(summary.conversations, key=lambda c: c.get("packets", 0), reverse=True)[:12]:
            rows.append([
                str(convo.get("src", "-")),
                str(convo.get("dst", "-")),
                str(convo.get("protocol", "-")),
                str(convo.get("packets", "-")),
                format_bytes_as_mb(int(convo.get("bytes", 0))),
                format_ts(convo.get("first_seen")),
                format_ts(convo.get("last_seen")),
            ])
        lines.append(_format_table(rows))

    if summary.sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Echo Sessions"))
        rows = [["Src", "Dst", "ID", "Requests", "Replies", "Packets", "First Seen", "Last Seen"]]
        for sess in summary.sessions[:12]:
            rows.append([
                str(sess.get("src", "-")),
                str(sess.get("dst", "-")),
                str(sess.get("id", "-")),
                str(sess.get("requests", "-")),
                str(sess.get("replies", "-")),
                str(sess.get("packets", "-")),
                format_ts(sess.get("first_seen")),
                format_ts(sess.get("last_seen")),
            ])
        lines.append(_format_table(rows))

    if summary.payload_summaries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Payload Summary"))
        rows = [["Payload (cleartext preview)", "Count", "Size", "Entropy", "Top Sources", "Top Destinations"]]
        for item in summary.payload_summaries[:limit]:
            top_src = ", ".join(f"{ip}({count})" for ip, count in item.get("top_sources", []))
            top_dst = ", ".join(f"{ip}({count})" for ip, count in item.get("top_destinations", []))
            rows.append([
                str(item.get("payload_preview", "-")),
                str(item.get("count", "-")),
                str(item.get("size", "-")),
                f"{item.get('entropy', 0):.2f}",
                top_src or "-",
                top_dst or "-",
            ])
        lines.append(_format_table(rows))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Artifacts"))
        lines.append(f"Sources: {', '.join(sorted(summary.src_ips)) if summary.src_ips else '-'}")
        lines.append(f"Destinations: {', '.join(sorted(summary.dst_ips)) if summary.dst_ips else '-'}")
        if summary.src_ip_counts:
            top_sources = ", ".join(f"{ip}({count})" for ip, count in summary.src_ip_counts.most_common(10))
            lines.append(f"Top Sources: {top_sources}")
        if summary.dst_ip_counts:
            top_dests = ", ".join(f"{ip}({count})" for ip, count in summary.dst_ip_counts.most_common(10))
            lines.append(f"Top Destinations: {top_dests}")

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = item.get("summary", "")
            details = item.get("details", "")
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Artifacts"))
        lines.append(muted(", ".join(summary.artifacts[:30])))

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for name, count in summary.observed_users.most_common(10):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        lines.append(muted(", ".join(summary.files_discovered[:20])))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_dns_summary(summary: DnsSummary, limit: int = 12, verbose: bool = False) -> str:
    def _dns_type_name(type_id: int) -> str:
        return {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            41: "OPT",
            43: "DS",
            46: "RRSIG",
            47: "NSEC",
            48: "DNSKEY",
            50: "NSEC3",
            51: "NSEC3PARAM",
            252: "AXFR",
            251: "IXFR",
            255: "ANY",
        }.get(type_id, "UNKNOWN")

    def _dns_rcode_name(rcode_id: int) -> str:
        return {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
            6: "YXDOMAIN",
            7: "YXRRSET",
            8: "NXRRSET",
            9: "NOTAUTH",
            10: "NOTZONE",
        }.get(rcode_id, "UNKNOWN")
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DNS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("DNS Packets", str(summary.total_packets)))
    lines.append(_format_kv("DNS Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Queries", str(summary.query_packets)))
    lines.append(_format_kv("Responses", str(summary.response_packets)))
    lines.append(_format_kv("UDP", str(summary.udp_packets)))
    lines.append(_format_kv("TCP", str(summary.tcp_packets)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Unique QNames", str(summary.unique_qnames)))
    lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
    lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    if summary.mdns_packets:
        lines.append(_format_kv("mDNS Packets", str(summary.mdns_packets)))
        lines.append(_format_kv("mDNS Queries", str(summary.mdns_query_packets)))
        lines.append(_format_kv("mDNS Responses", str(summary.mdns_response_packets)))
        lines.append(_format_kv("mDNS Clients", str(summary.unique_mdns_clients)))
        lines.append(_format_kv("mDNS Servers", str(summary.unique_mdns_servers)))
        lines.append(_format_kv("mDNS Error Responses", str(summary.mdns_error_responses)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if summary.type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Query Types"))
        rows = [["Type", "Count"]]
        for name, count in summary.type_counts.most_common(limit):
            try:
                type_id = int(name)
                label = f"{_dns_type_name(type_id)} ({type_id})"
            except Exception:
                label = str(name)
            rows.append([label, str(count)])
        lines.append(_format_table(rows))

    if summary.rcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["RCode", "Count"]]
        for name, count in summary.rcode_counts.most_common(limit):
            try:
                rcode_id = int(name)
                label = f"{_dns_rcode_name(rcode_id)} ({rcode_id})"
            except Exception:
                label = str(name)
            rows.append([label, str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients"))
        rows = [["Client", "Queries"]]
        for name, count in summary.client_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Servers"))
        rows = [["Server", "Responses"]]
        for name, count in summary.server_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Queried Names"))
        rows = [["QName", "Count"]]
        for name, count in summary.qname_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Bottom Queried Names"))
        rows = [["QName", "Count"]]
        bottom_names = sorted(summary.qname_counts.items(), key=lambda item: (item[1], item[0]))[:15]
        for name, count in bottom_names:
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.mdns_qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("mDNS Queries"))
        rows = [["QName", "Count"]]
        for name, count in summary.mdns_qname_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.mdns_service_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("mDNS Services (SRV)"))
        rows = [["Service", "Count"]]
        for name, count in summary.mdns_service_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("mDNS Service Announcements"))
        rows = [["Service", "Announcements"]]
        for name, count in summary.mdns_service_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.packet_length_stats:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Packet Length Analysis"))
        rows = [["Size Bucket", "Count", "Avg", "Min", "Max", "Rate(pkt/s)", "%", "Burst Rate", "Burst Start"]]
        for item in summary.packet_length_stats:
            rows.append([
                str(item.get("bucket", "-")),
                str(item.get("count", "-")),
                f"{item.get('avg', 0):.1f}",
                str(item.get("min", "-")),
                str(item.get("max", "-")),
                f"{item.get('rate', 0):.2f}",
                f"{item.get('pct', 0):.1f}%",
                f"{item.get('burst_rate', 0):.0f}",
                format_ts(item.get("burst_start")) if item.get("burst_start") else "-",
            ])
        lines.append(_format_table(rows))

    if summary.multicast_streams:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Multicast Streams Summary"))
        rows = [["Group", "Proto", "Port", "Packets", "Bytes", "Sources", "First Seen", "Last Seen"]]
        for item in summary.multicast_streams:
            sources = item.get("sources", [])
            source_text = ", ".join(f"{ip}({count})" for ip, count in sources)
            rows.append([
                str(item.get("group", "-")),
                str(item.get("protocol", "-")),
                str(item.get("port", "-")),
                str(item.get("count", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0))),
                source_text or "-",
                format_ts(item.get("first_seen")),
                format_ts(item.get("last_seen")),
            ])
        lines.append(_format_table(rows))

    if verbose and summary.qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Artifacts"))
        qnames = ", ".join(name for name, _count in summary.qname_counts.most_common(25))
        lines.append(f"Observed QNames: {qnames}")

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            top_clients = item.get("top_clients")
            if top_clients:
                client_text = ", ".join(f"{ip}({count})" for ip, count in top_clients)
                lines.append(muted(f"  Clients: {client_text}"))
            top_servers = item.get("top_servers")
            if top_servers:
                server_text = ", ".join(f"{ip}({count})" for ip, count in top_servers)
                lines.append(muted(f"  Servers: {server_text}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_ips_summary(summary: IpSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"IP INTELLIGENCE & CONVERSATIONS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Unique IPs", str(summary.unique_ips)))
    lines.append(_format_kv("Unique Sources", str(summary.unique_sources)))
    lines.append(_format_kv("Unique Destinations", str(summary.unique_destinations)))
    lines.append(_format_kv("IPv4 / IPv6", f"{summary.ipv4_count} / {summary.ipv6_count}"))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("TLS ClientHello", str(summary.tls_client_hellos)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("IP Protocol Utilization"))
    rows = [["Protocol", "Packets", "% traffic"]]
    for name, count in summary.protocol_counts.most_common(limit):
        pct = (count / summary.total_packets * 100) if summary.total_packets else 0
        rows.append([name, str(count), f"{pct:.1f}%"])
    lines.append(_format_table(rows))

    if summary.ip_category_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Addressing Observations"))
        rows = [["Category", "Packets"]]
        preferred = [
            "public",
            "private",
            "multicast",
            "broadcast",
            "loopback",
            "link_local",
            "reserved",
            "unspecified",
            "invalid",
            "unknown",
        ]
        for cat in preferred:
            if summary.ip_category_counts.get(cat, 0) > 0:
                rows.append([cat.replace("_", " "), str(summary.ip_category_counts[cat])])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Sources (prevalence)"))
    rows = [["Source", "Packets", "% of IP traffic"]]
    for ip, count in summary.src_counts.most_common(limit):
        pct = (count / summary.total_packets * 100) if summary.total_packets else 0
        rows.append([ip, str(count), f"{pct:.1f}%"])
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Destinations (utilization)"))
    rows = [["Destination", "Packets", "% of IP traffic"]]
    for ip, count in summary.dst_counts.most_common(limit):
        pct = (count / summary.total_packets * 100) if summary.total_packets else 0
        rows.append([ip, str(count), f"{pct:.1f}%"])
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Endpoints (bytes + peers)"))
    sorted_eps = sorted(
        summary.endpoints,
        key=lambda e: e.bytes_sent + e.bytes_recv,
        reverse=True,
    )[:limit]
    rows = [["IP", "Sent", "Recv", "Total", "Peers", "Ports", "Protocols", "Geo", "ASN"]]
    for ep in sorted_eps:
        ports_str = ",".join(str(p) for p in ep.ports[:6])
        if len(ep.ports) > 6:
            ports_str += "..."
        proto_str = ",".join(ep.protocols[:4])
        if len(ep.protocols) > 4:
            proto_str += "..."
        rows.append([
            ep.ip,
            format_bytes_as_mb(ep.bytes_sent),
            format_bytes_as_mb(ep.bytes_recv),
            format_bytes_as_mb(ep.bytes_sent + ep.bytes_recv),
            str(len(ep.peers)),
            ports_str or "-",
            proto_str or "-",
            ep.geo or "-",
            ep.asn or "-",
        ])
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top IP Conversations"))
    sorted_convs = sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)[:limit]
    rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "Duration", "Ports"]]
    for conv in sorted_convs:
        duration = "-"
        if conv.first_seen is not None and conv.last_seen is not None:
            duration = format_duration(conv.last_seen - conv.first_seen)
        ports_str = ",".join(str(p) for p in conv.ports[:6])
        if len(conv.ports) > 6:
            ports_str += "..."
        rows.append([
            conv.src,
            conv.dst,
            conv.protocol,
            str(conv.packets),
            format_bytes_as_mb(conv.bytes),
            duration,
            ports_str or "-",
        ])
    lines.append(_format_table(rows))

    if summary.tls_client_hellos:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Fingerprints & SNI"))

        if summary.ja3_counts:
            rows = [["JA3 (md5)", "Count"]]
            for ja3, count in summary.ja3_counts.most_common(limit):
                rows.append([ja3, str(count)])
            lines.append(_format_table(rows))

        if summary.ja4_counts:
            lines.append("")
            rows = [["JA4 (heuristic)", "Count"]]
            for ja4, count in summary.ja4_counts.most_common(limit):
                rows.append([ja4, str(count)])
            lines.append(_format_table(rows))

        if summary.ja4s_counts:
            lines.append("")
            rows = [["JA4S (server)", "Count"]]
            for ja4s, count in summary.ja4s_counts.most_common(limit):
                rows.append([ja4s, str(count)])
            lines.append(_format_table(rows))

        if summary.sni_counts:
            lines.append("")
            rows = [["SNI", "Count", "Entropy"]]
            for sni, count in summary.sni_counts.most_common(limit):
                entropy = summary.sni_entropy.get(sni, 0.0)
                rows.append([sni, str(count), f"{entropy:.2f}"])
            lines.append(_format_table(rows))

    if summary.ja_reputation_hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Fingerprint Reputation"))
        rows = [["Type", "Fingerprint", "Label", "Count"]]
        for item in summary.ja_reputation_hits[:limit]:
            rows.append([
                str(item.get("type", "-")),
                str(item.get("fingerprint", "-")),
                str(item.get("label", "-")),
                str(item.get("count", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.tls_cert_risks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Certificate Risks"))
        rows = [["Server", "Risk Type", "Details"]]
        for item in summary.tls_cert_risks[:limit]:
            src = str(item.get("src", "-"))
            dst = str(item.get("dst", "-"))
            risks = item.get("risks", [])
            if isinstance(risks, list):
                for risk in risks[:5]:
                    rows.append([
                        f"{src}->{dst}",
                        str(risk.get("type", "-")),
                        str(risk.get("details", "-")),
                    ])
        lines.append(_format_table(rows))

    if summary.suspicious_port_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Port Profiles"))
        rows = [["Type", "Source", "Unique Ports", "Unique Targets", "High Ports"]]
        for item in summary.suspicious_port_profiles[:limit]:
            rows.append([
                str(item.get("type", "-")),
                str(item.get("src", "-")),
                str(item.get("unique_ports", "-")),
                str(item.get("unique_dsts", "-")),
                str(item.get("high_ports", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.lateral_movement_scores:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Scoring"))
        rows = [["IP", "Score", "Peers", "Ports", "Packets Sent"]]
        for item in sorted(summary.lateral_movement_scores, key=lambda x: x.get("score", 0), reverse=True)[:limit]:
            rows.append([
                str(item.get("ip", "-")),
                str(item.get("score", "-")),
                str(item.get("peers", "-")),
                str(item.get("ports", "-")),
                str(item.get("packets_sent", "-")),
            ])
        lines.append(_format_table(rows))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Endpoint Timing"))
        rows = [["IP", "First Seen", "Last Seen", "Duration"]]
        for ep in sorted_eps:
            ep_duration = "-"
            if ep.first_seen is not None and ep.last_seen is not None:
                ep_duration = format_duration(ep.last_seen - ep.first_seen)
            rows.append([
                ep.ip,
                format_ts(ep.first_seen),
                format_ts(ep.last_seen),
                ep_duration,
            ])
        lines.append(_format_table(rows))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            top_sources = item.get("top_sources")
            if top_sources:
                src_text = ", ".join(f"{ip}({count})" for ip, count in top_sources)
                lines.append(muted(f"  Sources: {src_text}"))
            top_destinations = item.get("top_destinations")
            if top_destinations:
                dst_text = ", ".join(f"{ip}({count})" for ip, count in top_destinations)
                lines.append(muted(f"  Destinations: {dst_text}"))

    if summary.intel_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Threat Intel Hits"))
        rows = [["IP", "Source", "Signal", "Details"]]
        for item in summary.intel_findings:
            ip = str(item.get("ip", ""))
            source = str(item.get("source", ""))
            signal = "-"
            details = []
            if source == "AbuseIPDB":
                score = item.get("score")
                reports = item.get("reports")
                if score is not None:
                    signal = f"score {score}"
                if reports is not None:
                    details.append(f"reports {reports}")
                usage = item.get("usage")
                if usage:
                    details.append(f"usage {usage}")
                country = item.get("country")
                if country:
                    details.append(f"country {country}")
            elif source == "OTX":
                pulses = item.get("pulses")
                if pulses is not None:
                    signal = f"pulses {pulses}"
            elif source == "VirusTotal":
                malicious = item.get("malicious")
                suspicious = item.get("suspicious")
                harmless = item.get("harmless")
                signal = f"mal {malicious} / sus {suspicious}"
                if harmless is not None:
                    details.append(f"harmless {harmless}")

            rows.append([ip, source, signal, "; ".join(details) or "-"])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_http_summary(summary: HttpSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"HTTP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("HTTP Requests", str(summary.total_requests)))
    lines.append(_format_kv("HTTP Responses", str(summary.total_responses)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    if summary.method_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request Methods"))
        rows = [["Method", "Count"]]
        for method, count in summary.method_counts.most_common(limit):
            rows.append([method, str(count)])
        lines.append(_format_table(rows))

    if summary.version_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP Versions"))
        rows = [["Version", "Count"]]
        for version, count in summary.version_counts.most_common(limit):
            rows.append([version, str(count)])
        lines.append(_format_table(rows))

    if summary.status_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["Status", "Count"]]
        for code, count in summary.status_counts.most_common(limit):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    if summary.host_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hosts"))
        rows = [["Host", "Requests"]]
        for host, count in summary.host_counts.most_common(limit):
            rows.append([host, str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients"))
        rows = [["Client", "Requests"]]
        for client, count in summary.client_counts.most_common(limit):
            rows.append([client, str(count)])
        lines.append(_format_table(rows))

    if summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Servers"))
        rows = [["Server", "Responses"]]
        for server, count in summary.server_counts.most_common(limit):
            rows.append([server, str(count)])
        lines.append(_format_table(rows))

    if summary.url_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top URLs"))
        rows = [["URL", "Count"]]
        for url, count in summary.url_counts.most_common(limit):
            rows.append([url, str(count)])
        lines.append(_format_table(rows))

    if summary.user_agents:
        lines.append(SUBSECTION_BAR)
        lines.append(header("User Agents"))
        rows = [["User-Agent", "Count"]]
        for ua, count in summary.user_agents.most_common(limit):
            rows.append([ua, str(count)])
        lines.append(_format_table(rows))

    if summary.referrer_counts or summary.referrer_present or summary.referrer_missing:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP Referrer Analysis"))

        def _normalize_referrer_items(items: list[tuple[str, int]], truncate: bool) -> list[tuple[str, int]]:
            ordered = sorted(items, key=lambda item: (-item[1], item[0]))
            if not truncate:
                return ordered
            if verbose:
                return ordered
            merged: dict[str, int] = {}
            for value, count in ordered:
                display = _truncate_text(value, max_len=96)
                merged[display] = merged.get(display, 0) + count
            return sorted(merged.items(), key=lambda item: (-item[1], item[0]))

        def _append_referrer_table(title: str, header_text: str, items: list[tuple[str, int]], truncate: bool = False) -> None:
            if not items:
                return
            normalized = _normalize_referrer_items(items, truncate)
            if not normalized:
                return
            lines.append(label(title))
            count_width = max(1, max(len(str(count)) for _, count in normalized))
            rows = [[label(header_text), label("Count")]]
            for value, count in normalized:
                rows.append([value, str(count).rjust(count_width)])
            lines.append(_format_table(rows))

        lines.append(label("Summary"))
        stats_rows = [
            [label("Metric"), label("Value")],
            ["Referrers Present", str(summary.referrer_present)],
            ["Referrers Missing", str(summary.referrer_missing)],
            ["Unique Referrers", str(len(summary.referrer_counts))],
            ["Unique Referrer Hosts", str(len(summary.referrer_host_counts))],
            ["Cross-Host Referrers", str(summary.referrer_cross_host)],
            ["HTTPS→HTTP Referrers", str(summary.referrer_https_to_http)],
            ["Referrers w/ Tokens", str(sum(summary.referrer_token_counts.values()))],
            ["Referrers w/ IP Hosts", str(len(summary.referrer_ip_hosts))],
        ]
        lines.append(_format_table(stats_rows))

        anomalies: list[str] = []
        if summary.referrer_https_to_http:
            anomalies.append(f"Mixed content/downgrade referrers: {summary.referrer_https_to_http}")
        if summary.referrer_token_counts:
            anomalies.append(f"Token-like strings in referrers: {sum(summary.referrer_token_counts.values())}")
        if summary.referrer_ip_hosts:
            anomalies.append(f"IP-literal referrer hosts: {len(summary.referrer_ip_hosts)}")
        if summary.referrer_cross_host and summary.referrer_present:
            ratio = summary.referrer_cross_host / max(1, summary.referrer_present)
            if ratio > 0.7:
                anomalies.append(f"High cross-site referrer rate: {summary.referrer_cross_host}/{summary.referrer_present}")
        if anomalies:
            lines.append(header("Referrer Anomalies/Threats"))
            for item in anomalies:
                lines.append(warn(f"- {item}"))

        if summary.referrer_scheme_counts:
            _append_referrer_table(
                "Scheme Counts",
                "Scheme",
                summary.referrer_scheme_counts.most_common(limit),
            )

        if summary.referrer_host_counts:
            _append_referrer_table(
                "Referrer Hosts",
                "Referrer Host",
                summary.referrer_host_counts.most_common(limit),
            )

        show_paths = bool(summary.referrer_path_counts) and (
            verbose
            or not summary.referrer_counts
            or len(summary.referrer_path_counts) != len(summary.referrer_counts)
        )
        if show_paths:
            _append_referrer_table(
                "Referrer Paths",
                "Referrer Path",
                summary.referrer_path_counts.most_common(limit),
                truncate=True,
            )

        if summary.referrer_counts:
            _append_referrer_table(
                "Referrers",
                "Referrer",
                summary.referrer_counts.most_common(limit),
                truncate=True,
            )

        if summary.referrer_token_counts:
            _append_referrer_table(
                "Token Fingerprints",
                "Token Fingerprint",
                summary.referrer_token_counts.most_common(limit),
            )

    if summary.server_headers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Headers"))
        rows = [["Server", "Count"]]
        for server, count in summary.server_headers.most_common(limit):
            rows.append([server, str(count)])
        lines.append(_format_table(rows))

    if summary.content_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Content Types"))
        rows = [["Content-Type", "Count"]]
        for ctype, count in summary.content_types.most_common(limit):
            rows.append([ctype, str(count)])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files & Artifacts"))
        rows = [["File", "Count"]]
        for name, count in summary.file_artifacts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.downloads:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Downloaded Files"))
        rows = [["File", "Detected", "Expected", "Bytes", "Status", "Src", "Dst"]]
        for item in summary.downloads[:limit]:
            name = str(item.get("filename", "-"))
            detected = str(item.get("detected_type", "-"))
            expected = str(item.get("expected_type", "-"))
            if item.get("mismatch"):
                detected = danger(detected)
            rows.append([
                name,
                detected,
                expected,
                str(item.get("bytes", "-")),
                str(item.get("status", "-")),
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.post_payloads:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP POST Payloads"))
        rows = [["Src", "Dst", "Host", "URI", "Bytes", "Content-Type", "Sample"]]
        for item in summary.post_payloads[:limit]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("host", "-")) or "-",
                str(item.get("uri", "-")),
                str(item.get("bytes", "-")),
                str(item.get("content_type", "-")) or "-",
                str(item.get("sample", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.session_tokens:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Session Tokens Observed"))
        rows = [["Token", "Count"]]
        for token, count in summary.session_tokens.most_common(limit):
            rows.append([token, str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP Conversations"))
        rows = [["Client", "Server", "Requests", "Responses", "Bytes", "Methods", "Statuses"]]
        for conv in sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)[:limit]:
            methods = ",".join(f"{m}({c})" for m, c in conv.methods.most_common(3))
            statuses = ",".join(f"{s}({c})" for s, c in conv.statuses.most_common(3))
            rows.append([
                conv.client_ip,
                conv.server_ip,
                str(conv.requests),
                str(conv.responses),
                format_bytes_as_mb(conv.bytes),
                methods or "-",
                statuses or "-",
            ])
        lines.append(_format_table(rows))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_tls_summary(summary: TlsSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TLS/HTTPS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("TLS Packets", str(summary.tls_packets)))
    lines.append(_format_kv("Client Hellos", str(summary.client_hellos)))
    lines.append(_format_kv("Server Hellos", str(summary.server_hellos)))
    lines.append(_format_kv("Unique Clients", str(len(summary.client_counts))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_counts))))
    lines.append(_format_kv("Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    if summary.versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Versions"))
        rows = [["Version", "Count"]]
        for version, count in summary.versions.most_common(limit):
            rows.append([version, str(count)])
        lines.append(_format_table(rows))

    if summary.cipher_suites:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Cipher Suites (Server Selected)"))
        rows = [["Cipher", "Count"]]
        for cipher, count in summary.cipher_suites.most_common(limit):
            rows.append([cipher, str(count)])
        lines.append(_format_table(rows))

    if summary.sni_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Name Indication (SNI)"))
        rows = [["SNI", "Count"]]
        for sni, count in summary.sni_counts.most_common(limit):
            rows.append([sni, str(count)])
        lines.append(_format_table(rows))

    if summary.alpn_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ALPN Protocols"))
        rows = [["ALPN", "Count"]]
        for alpn, count in summary.alpn_counts.most_common(limit):
            rows.append([alpn, str(count)])
        lines.append(_format_table(rows))

    if summary.ja3_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("JA3 Fingerprints"))
        rows = [["JA3", "Count"]]
        for ja3, count in summary.ja3_counts.most_common(limit):
            rows.append([ja3, str(count)])
        lines.append(_format_table(rows))

    if summary.ja4_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("JA4 Fingerprints"))
        rows = [["JA4", "Count"]]
        for ja4, count in summary.ja4_counts.most_common(limit):
            rows.append([ja4, str(count)])
        lines.append(_format_table(rows))

    if summary.ja4s_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("JA4S Fingerprints"))
        rows = [["JA4S", "Count"]]
        for ja4s, count in summary.ja4s_counts.most_common(limit):
            rows.append([ja4s, str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Conversations"))
        rows = [["Client", "Server", "Port", "Packets", "Bytes", "First Seen", "Last Seen", "SNI"]]
        for convo in summary.conversations[:limit]:
            rows.append([
                convo.client_ip,
                convo.server_ip,
                str(convo.server_port),
                str(convo.packets),
                format_bytes_as_mb(convo.bytes),
                format_ts(convo.first_seen),
                format_ts(convo.last_seen),
                convo.sni or "-",
            ])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TLS Clients & Servers"))
        rows = [["Clients", "Servers"]]
        client_text = ", ".join(f"{ip}({count})" for ip, count in summary.client_counts.most_common(10)) or "-"
        server_text = ", ".join(f"{ip}({count})" for ip, count in summary.server_counts.most_common(10)) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Service Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

        if summary.http_referrers or summary.http_referrer_present or summary.http_referrer_missing:
            lines.append(header("HTTP Referrer Analysis (Plaintext)"))
            stats_rows = [
                ["Metric", "Value"],
                ["Referrers Present", str(summary.http_referrer_present)],
                ["Referrers Missing", str(summary.http_referrer_missing)],
                ["Unique Referrers", str(len(summary.http_referrers))],
                ["Unique Referrer Hosts", str(len(summary.http_referrer_hosts))],
                ["Cross-Host Referrers", str(summary.http_referrer_cross_host)],
                ["HTTPS→HTTP Referrers", str(summary.http_referrer_https_to_http)],
                ["Referrers w/ Tokens", str(sum(summary.http_referrer_tokens.values()))],
                ["Referrers w/ IP Hosts", str(len(summary.http_referrer_ip_hosts))],
            ]
            lines.append(_format_table(stats_rows))

            if summary.http_referrer_schemes:
                rows = [["Scheme", "Count"]]
                for scheme, count in summary.http_referrer_schemes.most_common(limit):
                    rows.append([scheme, str(count)])
                lines.append(_format_table(rows))

            if summary.http_referrer_hosts:
                rows = [["Referrer Host", "Count"]]
                for host, count in summary.http_referrer_hosts.most_common(limit):
                    rows.append([host, str(count)])
                lines.append(_format_table(rows))

            if summary.http_referrers:
                rows = [["Referrer", "Count"]]
                for ref, count in summary.http_referrers.most_common(limit):
                    display = ref if verbose else _truncate_text(ref, max_len=96)
                    rows.append([display, str(count)])
                lines.append(_format_table(rows))

            show_paths = bool(summary.http_referrer_paths) and (
                verbose
                or not summary.http_referrers
                or len(summary.http_referrer_paths) != len(summary.http_referrers)
            )
            if show_paths:
                rows = [["Referrer Path", "Count"]]
                for path, count in summary.http_referrer_paths.most_common(limit):
                    display = path if verbose else _truncate_text(path, max_len=96)
                    rows.append([display, str(count)])
                lines.append(_format_table(rows))

            if summary.http_referrer_tokens:
                rows = [["Token Fingerprint", "Count"]]
                for token, count in summary.http_referrer_tokens.most_common(limit):
                    rows.append([token, str(count)])
                lines.append(_format_table(rows))

    if summary.cert_count:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Certificates"))
        lines.append(_format_kv("Certificates", str(summary.cert_count)))
        if summary.cert_subjects:
            rows = [["Subject", "Count"]]
            for subject, count in summary.cert_subjects.most_common(limit):
                rows.append([subject, str(count)])
            lines.append(_format_table(rows))
        if summary.cert_issuers:
            rows = [["Issuer", "Count"]]
            for issuer, count in summary.cert_issuers.most_common(limit):
                rows.append([issuer, str(count)])
            lines.append(_format_table(rows))
        if summary.weak_certs or summary.expired_certs or summary.self_signed_certs:
            rows = [["Weak", "Expired", "Self-Signed"]]
            rows.append([str(summary.weak_certs), str(summary.expired_certs), str(summary.self_signed_certs)])
            lines.append(_format_table(rows))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            if summary_text == "TCP retransmission spikes" and summary.retrans_timeseries:
                lines.append(muted(f"  Trend: {sparkline(summary.retrans_timeseries)}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_ssh_summary(summary: SshSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SSH ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("SSH Packets", str(summary.ssh_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top SSH Clients & Servers"))
        rows = [["Clients", "Servers"]]
        client_text = ", ".join(
            f"{ip}({count})" for ip, count in summary.client_counts.most_common(8)
        ) or "-"
        server_text = ", ".join(
            f"{ip}({count})" for ip, count in summary.server_counts.most_common(8)
        ) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.client_versions or summary.server_versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Versions"))
        rows = [["Client Versions", "Server Versions"]]
        client_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.client_versions.most_common(6)
        ) or "-"
        server_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.server_versions.most_common(6)
        ) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.client_software or summary.server_software:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Software"))
        rows = [["Clients", "Servers"]]
        client_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.client_software.most_common(6)
        ) or "-"
        server_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.server_software.most_common(6)
        ) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.kex_algorithms or summary.cipher_algorithms or summary.mac_algorithms or summary.host_key_algorithms:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Crypto Negotiation"))
        rows = [["KEX", "Host Key", "Cipher", "MAC", "Compression"]]
        rows.append([
            ", ".join(f"{name}({count})" for name, count in summary.kex_algorithms.most_common(3)) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.host_key_algorithms.most_common(3)) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.cipher_algorithms.most_common(3)) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.mac_algorithms.most_common(3)) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.compression_algorithms.most_common(3)) or "-",
        ])
        lines.append(_format_table(rows))

    if summary.auth_methods:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Auth Methods"))
        rows = [["Method", "Count"]]
        for name, count in summary.auth_methods.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.request_counts or summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Requests & Responses"))
        rows = [["Requests", "Responses"]]
        req_text = ", ".join(
            f"{name.replace('SSH_MSG_', '')}({count})"
            for name, count in summary.request_counts.most_common(6)
        ) or "-"
        resp_text = ", ".join(
            f"{name.replace('SSH_MSG_', '')}({count})"
            for name, count in summary.response_counts.most_common(6)
        ) or "-"
        rows.append([req_text, resp_text])
        lines.append(_format_table(rows))

    if summary.disconnect_reasons:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Disconnect Reasons"))
        rows = [["Reason", "Count"]]
        for reason, count in summary.disconnect_reasons.most_common(limit):
            rows.append([reason, str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        rows = [["File", "Count"]]
        for name, count in summary.file_artifacts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            title = str(item.get("title", "Event"))
            details = str(item.get("details", ""))
            if details:
                lines.append(warn(f"- {title}: {details}"))
            else:
                lines.append(warn(f"- {title}"))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity in {"critical", "high"}:
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(f"- {_truncate_text(item, 80)}")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_syslog_summary(summary: SyslogSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SYSLOG ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Syslog Packets", str(summary.syslog_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Messages", str(summary.total_messages)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Syslog Clients & Servers"))
        rows = [["Clients", "Servers"]]
        client_text = ", ".join(
            f"{ip}({count})" for ip, count in summary.client_counts.most_common(8)
        ) or "-"
        server_text = ", ".join(
            f"{ip}({count})" for ip, count in summary.server_counts.most_common(8)
        ) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Hostnames"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostname_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.appname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Applications"))
        rows = [["App", "Count"]]
        for name, count in summary.appname_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.version_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Syslog Versions"))
        rows = [["Version", "Count"]]
        for version, count in summary.version_counts.most_common(limit):
            rows.append([str(version), str(count)])
        lines.append(_format_table(rows))

    if summary.facility_counts or summary.severity_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Facility & Severity"))
        rows = [["Facilities", "Severities"]]
        facility_text = ", ".join(
            f"{name}({count})" for name, count in summary.facility_counts.most_common(6)
        ) or "-"
        severity_text = ", ".join(
            f"{name}({count})" for name, count in summary.severity_counts.most_common(6)
        ) or "-"
        rows.append([facility_text, severity_text])
        lines.append(_format_table(rows))

    if summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request Summary"))
        rows = [["Request", "Count"]]
        for name, count in summary.request_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.response_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["Code", "Count"]]
        for name, count in summary.response_codes.most_common(limit):
            rows.append([_truncate_text(name, 30), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Syslog Conversations"))
        rows = [["Client", "Server", "Proto", "Port", "Packets", "Bytes"]]
        for convo in summary.conversations[:limit]:
            rows.append([
                convo.client_ip,
                convo.server_ip,
                convo.protocol,
                str(convo.server_port),
                str(convo.packets),
                format_bytes_as_mb(convo.bytes),
            ])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        rows = [["File", "Count"]]
        for name, count in summary.file_artifacts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            title = item.title
            details = item.details
            sev = item.severity
            sev_color = danger if sev in ("HIGH", "CRITICAL") else warn
            lines.append(sev_color(f"[{sev}] {title}: {details}"))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity in {"critical", "high"}:
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for item in summary.artifacts[:limit]:
            rows.append([
                str(item.kind),
                _truncate_text(str(item.detail), 60),
                str(item.src),
                str(item.dst),
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_tcp_summary(summary: TcpSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TCP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    tcp_packet_ratio = (summary.tcp_packets / summary.total_packets) if summary.total_packets else 0.0
    tcp_byte_ratio = (summary.tcp_bytes / summary.total_bytes) if summary.total_bytes else 0.0
    avg_tcp_pkt = (summary.tcp_bytes / summary.tcp_packets) if summary.tcp_packets else 0.0
    avg_tcp_payload = (summary.tcp_payload_bytes / summary.tcp_packets) if summary.tcp_packets else 0.0
    tcp_pps = (summary.tcp_packets / summary.duration_seconds) if summary.duration_seconds else 0.0
    tcp_bps = (summary.tcp_bytes / summary.duration_seconds) if summary.duration_seconds else 0.0

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Statistics"))
    lines.append(_format_kv("TCP Packets", f"{summary.tcp_packets} ({tcp_packet_ratio:.1%})"))
    lines.append(_format_kv("TCP Bytes", f"{format_bytes_as_mb(summary.tcp_bytes)} ({tcp_byte_ratio:.1%})"))
    lines.append(_format_kv("Unique Clients", str(len(summary.client_counts))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_counts))))
    lines.append(_format_kv("Unique Endpoints", str(len(getattr(summary, "endpoint_packets", {})))))
    lines.append(_format_kv("Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("TCP Payload Bytes", format_bytes_as_mb(summary.tcp_payload_bytes)))
    lines.append(_format_kv("Avg TCP Packet Size", f"{avg_tcp_pkt:.1f} bytes"))
    lines.append(_format_kv("Avg TCP Payload Size", f"{avg_tcp_payload:.1f} bytes"))
    lines.append(_format_kv("TCP Packets/sec", f"{tcp_pps:.2f}"))
    lines.append(_format_kv("TCP Bytes/sec", f"{tcp_bps:.2f}"))

    if summary.packet_size_hist or summary.payload_size_hist:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet & Payload Size Distribution"))
        bucket_labels = ["<=64", "65-128", "129-256", "257-512", "513-1024", "1025-1500", "1501-9000", ">9000"]
        if summary.packet_size_hist:
            packet_series = [summary.packet_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Packet Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Packet Size Spark", sparkline(packet_series)))
            stats = summary.packet_size_stats
            lines.append(_format_kv("Packet Size Stats", f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}"))
        if summary.payload_size_hist:
            payload_series = [summary.payload_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Payload Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Payload Size Spark", sparkline(payload_series)))
            stats = summary.payload_size_stats
            lines.append(_format_kv("Payload Size Stats", f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}"))
        if summary.zero_payload_packets:
            lines.append(_format_kv("Zero Payload Packets", str(summary.zero_payload_packets)))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Conversations"))
        rows = [["Src", "Dst", "Sport", "Dport", "Packets", "Bytes", "SYN", "SYN-ACK", "RST", "FIN"]]
        for convo in summary.conversations[:limit]:
            rows.append([
                convo.src_ip,
                convo.dst_ip,
                str(convo.src_port),
                str(convo.dst_port),
                str(convo.packets),
                format_bytes_as_mb(convo.bytes),
                str(convo.syn),
                str(convo.syn_ack),
                str(convo.rst),
                str(convo.fin),
            ])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Client/Server Statistics"))
        client_bytes = summary.client_bytes if isinstance(summary.client_bytes, Counter) else Counter()
        server_bytes = summary.server_bytes if isinstance(summary.server_bytes, Counter) else Counter()
        rows = [["Client", "Server"]]
        client_list = [
            f"{ip}({summary.client_counts[ip]}/{format_bytes_as_mb(client_bytes.get(ip, 0))})"
            for ip, _count in summary.client_counts.most_common(10)
        ]
        server_list = [
            f"{ip}({summary.server_counts[ip]}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
            for ip, _count in summary.server_counts.most_common(10)
        ]
        max_rows = max(len(client_list), len(server_list), 1)
        for idx in range(max_rows):
            rows.append([
                client_list[idx] if idx < len(client_list) else "-",
                server_list[idx] if idx < len(server_list) else "-",
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "endpoint_packets", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Endpoint Statistics"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        endpoint_bytes = summary.endpoint_bytes if isinstance(summary.endpoint_bytes, Counter) else Counter()
        for ip, count in summary.endpoint_packets.most_common(limit):
            rows.append([ip, str(count), format_bytes_as_mb(endpoint_bytes.get(ip, 0))])
        lines.append(_format_table(rows))

    if summary.port_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TCP Destination Ports"))
        rows = [["Port", "Count", "Destinations"]]
        port_destinations = summary.port_destinations if isinstance(summary.port_destinations, dict) else {}
        for port, count in summary.port_counts.most_common(limit):
            dsts = port_destinations.get(port, Counter())
            dst_text = ", ".join(f"{ip}({cnt})" for ip, cnt in dsts.most_common(3)) or "-"
            rows.append([str(port), str(count), dst_text])
        lines.append(_format_table(rows))

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Services (Endpoints)"))
        rows = [["Service", "Endpoint", "Port", "Clients", "Count"]]
        for svc in summary.services[:limit]:
            client_note = str(svc.get("clients", "-"))
            if svc.get("client_count"):
                client_note = f"{svc.get('client_count')} :: {client_note}"
            rows.append([
                str(svc.get("service", "-")),
                str(svc.get("endpoint", "-")),
                str(svc.get("port", "-")),
                client_note,
                str(svc.get("count", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered (All Protocols)"))
        rows = [["Filename", "Count"]]
        for fname, count in summary.file_artifacts.most_common(limit):
            rows.append([fname, str(count)])
        lines.append(_format_table(rows))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_udp_summary(summary: UdpSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"UDP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    udp_packet_ratio = (summary.udp_packets / summary.total_packets) if summary.total_packets else 0.0
    udp_byte_ratio = (summary.udp_bytes / summary.total_bytes) if summary.total_bytes else 0.0
    avg_udp_pkt = (summary.udp_bytes / summary.udp_packets) if summary.udp_packets else 0.0
    avg_udp_payload = (summary.udp_payload_bytes / summary.udp_packets) if summary.udp_packets else 0.0
    udp_pps = (summary.udp_packets / summary.duration_seconds) if summary.duration_seconds else 0.0
    udp_bps = (summary.udp_bytes / summary.duration_seconds) if summary.duration_seconds else 0.0

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Statistics"))
    lines.append(_format_kv("UDP Packets", f"{summary.udp_packets} ({udp_packet_ratio:.1%})"))
    lines.append(_format_kv("UDP Bytes", f"{format_bytes_as_mb(summary.udp_bytes)} ({udp_byte_ratio:.1%})"))
    lines.append(_format_kv("Unique Clients", str(len(summary.client_counts))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_counts))))
    lines.append(_format_kv("Unique Endpoints", str(len(summary.endpoint_packets))))
    lines.append(_format_kv("Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("UDP Payload Bytes", format_bytes_as_mb(summary.udp_payload_bytes)))
    lines.append(_format_kv("Avg UDP Packet Size", f"{avg_udp_pkt:.1f} bytes"))
    lines.append(_format_kv("Avg UDP Payload Size", f"{avg_udp_payload:.1f} bytes"))
    lines.append(_format_kv("UDP Packets/sec", f"{udp_pps:.2f}"))
    lines.append(_format_kv("UDP Bytes/sec", f"{udp_bps:.2f}"))

    if summary.packet_size_hist or summary.payload_size_hist:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet & Payload Size Distribution"))
        bucket_labels = ["<=64", "65-128", "129-256", "257-512", "513-1024", "1025-1500", "1501-9000", ">9000"]
        if summary.packet_size_hist:
            packet_series = [summary.packet_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Packet Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Packet Size Spark", sparkline(packet_series)))
            stats = summary.packet_size_stats
            lines.append(_format_kv("Packet Size Stats", f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}"))
        if summary.payload_size_hist:
            payload_series = [summary.payload_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Payload Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Payload Size Spark", sparkline(payload_series)))
            stats = summary.payload_size_stats
            lines.append(_format_kv("Payload Size Stats", f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}"))
        if summary.zero_payload_packets:
            lines.append(_format_kv("Zero Payload Packets", str(summary.zero_payload_packets)))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Conversations"))
        rows = [["Src", "Dst", "Sport", "Dport", "Packets", "Bytes"]]
        for convo in summary.conversations[:limit]:
            rows.append([
                convo.src_ip,
                convo.dst_ip,
                str(convo.src_port),
                str(convo.dst_port),
                str(convo.packets),
                format_bytes_as_mb(convo.bytes),
            ])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Client/Server Statistics"))
        client_bytes = summary.client_bytes if isinstance(summary.client_bytes, Counter) else Counter()
        server_bytes = summary.server_bytes if isinstance(summary.server_bytes, Counter) else Counter()
        rows = [["Client", "Server"]]
        client_list = [
            f"{ip}({summary.client_counts[ip]}/{format_bytes_as_mb(client_bytes.get(ip, 0))})"
            for ip, _count in summary.client_counts.most_common(10)
        ]
        server_list = [
            f"{ip}({summary.server_counts[ip]}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
            for ip, _count in summary.server_counts.most_common(10)
        ]
        max_rows = max(len(client_list), len(server_list))
        for idx in range(max_rows):
            rows.append([
                client_list[idx] if idx < len(client_list) else "-",
                server_list[idx] if idx < len(server_list) else "-",
            ])
        lines.append(_format_table(rows))

    if summary.endpoint_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Endpoint Statistics"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        endpoint_bytes = summary.endpoint_bytes if isinstance(summary.endpoint_bytes, Counter) else Counter()
        for ip, count in summary.endpoint_packets.most_common(limit):
            rows.append([ip, str(count), format_bytes_as_mb(endpoint_bytes.get(ip, 0))])
        lines.append(_format_table(rows))

    if summary.port_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top UDP Destination Ports"))
        rows = [["Port", "Count", "Destinations"]]
        port_destinations = summary.port_destinations if isinstance(summary.port_destinations, dict) else {}
        for port, count in summary.port_counts.most_common(limit):
            dsts = port_destinations.get(port, Counter())
            dst_text = ", ".join(f"{ip}({cnt})" for ip, cnt in dsts.most_common(3)) or "-"
            rows.append([str(port), str(count), dst_text])
        lines.append(_format_table(rows))

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Services (Endpoints)"))
        rows = [["Service", "Endpoint", "Port", "Clients", "Count"]]
        for svc in summary.services[:limit]:
            client_note = str(svc.get("clients", "-"))
            if svc.get("client_count"):
                client_note = f"{svc.get('client_count')} :: {client_note}"
            rows.append([
                str(svc.get("service", "-")),
                str(svc.get("endpoint", "-")),
                str(svc.get("port", "-")),
                client_note,
                str(svc.get("count", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered (All Protocols)"))
        rows = [["Filename", "Count"]]
        for fname, count in summary.file_artifacts.most_common(limit):
            rows.append([fname, str(count)])
        lines.append(_format_table(rows))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def _udp_bucket_ranges() -> list[tuple[str, int, int]]:
    return [
        ("<=64", 0, 64),
        ("65-128", 65, 128),
        ("129-256", 129, 256),
        ("257-512", 257, 512),
        ("513-1024", 513, 1024),
        ("1025-1500", 1025, 1500),
        ("1501-9000", 1501, 9000),
        (">9000", 9001, 9001),
    ]


def _approx_hist_stats(hist: Counter[str]) -> dict[str, float]:
    if not hist:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}

    ranges = _udp_bucket_ranges()
    total = sum(hist.values())
    if total <= 0:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}

    min_val = 0.0
    max_val = 0.0
    for label, low, high in ranges:
        if hist.get(label, 0) > 0:
            min_val = float(low)
            break
    for label, low, high in reversed(ranges):
        if hist.get(label, 0) > 0:
            max_val = float(high)
            break

    def _quantile(target_pct: float) -> float:
        target = total * (target_pct / 100.0)
        running = 0
        for label, low, high in ranges:
            running += hist.get(label, 0)
            if running >= target:
                if label == ">9000":
                    return float(low)
                return float((low + high) / 2)
        return max_val

    weighted_sum = 0.0
    for label, low, high in ranges:
        mid = float(low) if label == ">9000" else float((low + high) / 2)
        weighted_sum += mid * hist.get(label, 0)

    return {
        "min": min_val,
        "max": max_val,
        "avg": weighted_sum / total,
        "p50": _quantile(50.0),
        "p95": _quantile(95.0),
    }


def render_udp_rollup(summaries: Iterable[UdpSummary], limit: int = 12, verbose: bool = False) -> str:
    summary_list = list(summaries)
    if not summary_list:
        return ""

    total_packets = sum(item.total_packets for item in summary_list)
    total_bytes = sum(item.total_bytes for item in summary_list)
    udp_packets = sum(item.udp_packets for item in summary_list)
    udp_bytes = sum(item.udp_bytes for item in summary_list)
    udp_payload_bytes = sum(item.udp_payload_bytes for item in summary_list)
    zero_payload_packets = sum(item.zero_payload_packets for item in summary_list)

    client_counts: Counter[str] = Counter()
    client_bytes: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_bytes: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    port_destinations: dict[int, Counter[str]] = defaultdict(Counter)
    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    packet_size_hist: Counter[str] = Counter()
    payload_size_hist: Counter[str] = Counter()
    http_methods: Counter[str] = Counter()
    http_statuses: Counter[str] = Counter()
    http_urls: Counter[str] = Counter()
    http_user_agents: Counter[str] = Counter()
    http_files: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    errors: list[str] = []

    first_seen = None
    last_seen = None

    conversations: dict[tuple[str, str, int, int], dict[str, object]] = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None,
    })

    detections: dict[tuple[str, str], dict[str, object]] = {}
    artifact_counts: Counter[str] = Counter()

    services_agg: dict[tuple[str, str, int, str], dict[str, object]] = {}

    for item in summary_list:
        client_counts.update(item.client_counts if isinstance(item.client_counts, Counter) else Counter())
        client_bytes.update(item.client_bytes if isinstance(item.client_bytes, Counter) else Counter())
        server_counts.update(item.server_counts if isinstance(item.server_counts, Counter) else Counter())
        server_bytes.update(item.server_bytes if isinstance(item.server_bytes, Counter) else Counter())
        port_counts.update(item.port_counts if isinstance(item.port_counts, Counter) else Counter())
        endpoint_packets.update(item.endpoint_packets if isinstance(item.endpoint_packets, Counter) else Counter())
        endpoint_bytes.update(item.endpoint_bytes if isinstance(item.endpoint_bytes, Counter) else Counter())
        packet_size_hist.update(item.packet_size_hist if isinstance(item.packet_size_hist, Counter) else Counter())
        payload_size_hist.update(item.payload_size_hist if isinstance(item.payload_size_hist, Counter) else Counter())
        http_methods.update(item.http_methods if isinstance(item.http_methods, Counter) else Counter())
        http_statuses.update(item.http_statuses if isinstance(item.http_statuses, Counter) else Counter())
        http_urls.update(item.http_urls if isinstance(item.http_urls, Counter) else Counter())
        http_user_agents.update(item.http_user_agents if isinstance(item.http_user_agents, Counter) else Counter())
        http_files.update(item.http_files if isinstance(item.http_files, Counter) else Counter())
        file_artifacts.update(item.file_artifacts if isinstance(item.file_artifacts, Counter) else Counter())
        errors.extend(item.errors if isinstance(item.errors, list) else [])

        port_map = item.port_destinations if isinstance(item.port_destinations, dict) else {}
        for port, counter in port_map.items():
            if isinstance(counter, Counter):
                port_destinations[port].update(counter)

        for convo in item.conversations:
            key = (convo.src_ip, convo.dst_ip, convo.src_port, convo.dst_port)
            info = conversations[key]
            info["packets"] = int(info["packets"]) + convo.packets
            info["bytes"] = int(info["bytes"]) + convo.bytes
            if convo.first_seen is not None:
                if info["first_seen"] is None or convo.first_seen < info["first_seen"]:
                    info["first_seen"] = convo.first_seen
            if convo.last_seen is not None:
                if info["last_seen"] is None or convo.last_seen > info["last_seen"]:
                    info["last_seen"] = convo.last_seen

        for det in item.detections:
            summary_text = str(det.get("summary", ""))
            details = str(det.get("details", ""))
            if not summary_text:
                continue
            detections.setdefault((summary_text, details), det)

        for artifact in item.artifacts:
            artifact_counts[artifact] += 1

        for svc in item.services:
            service = str(svc.get("service", "-"))
            endpoint = str(svc.get("endpoint", "-"))
            port = int(svc.get("port", 0)) if str(svc.get("port", "")).isdigit() else 0
            proto = str(svc.get("proto", "UDP"))
            key = (service, endpoint, port, proto)
            entry = services_agg.setdefault(key, {
                "service": service,
                "endpoint": endpoint,
                "port": port,
                "proto": proto,
                "count": 0,
                "client_count": 0,
                "clients": set(),
            })
            entry["count"] = int(entry["count"]) + int(svc.get("count", 0) or 0)
            entry["client_count"] = int(entry["client_count"]) + int(svc.get("client_count", 0) or 0)
            clients_text = str(svc.get("clients", "-"))
            if clients_text and clients_text != "-":
                for part in clients_text.split(","):
                    value = part.strip()
                    if value:
                        entry["clients"].add(value)

        if item.first_seen is not None:
            if first_seen is None or item.first_seen < first_seen:
                first_seen = item.first_seen
        if item.last_seen is not None:
            if last_seen is None or item.last_seen > last_seen:
                last_seen = item.last_seen

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows: list[UdpConversation] = []
    for (src_ip, dst_ip, sport, dport), info in conversations.items():
        conversation_rows.append(UdpConversation(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            packets=int(info["packets"]),
            bytes=int(info["bytes"]),
            first_seen=info["first_seen"],
            last_seen=info["last_seen"],
        ))

    services: list[dict[str, object]] = []
    for entry in services_agg.values():
        clients_list = sorted(entry["clients"])[:5]
        services.append({
            "service": entry["service"],
            "endpoint": entry["endpoint"],
            "port": entry["port"],
            "proto": entry["proto"],
            "count": entry["count"],
            "client_count": entry["client_count"],
            "clients": ", ".join(clients_list) if clients_list else "-",
        })

    services.sort(key=lambda value: int(value.get("count", 0)), reverse=True)
    errors = sorted({err for err in errors if err})

    rollup = UdpSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        total_bytes=total_bytes,
        udp_packets=udp_packets,
        udp_bytes=udp_bytes,
        udp_payload_bytes=udp_payload_bytes,
        conversations=sorted(conversation_rows, key=lambda item: item.packets, reverse=True),
        client_counts=client_counts,
        client_bytes=client_bytes,
        server_counts=server_counts,
        server_bytes=server_bytes,
        port_counts=port_counts,
        port_destinations=port_destinations,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        packet_size_hist=packet_size_hist,
        payload_size_hist=payload_size_hist,
        packet_size_stats=_approx_hist_stats(packet_size_hist),
        payload_size_stats=_approx_hist_stats(payload_size_hist),
        zero_payload_packets=zero_payload_packets,
        http_requests=sum(item.http_requests for item in summary_list),
        http_responses=sum(item.http_responses for item in summary_list),
        http_methods=http_methods,
        http_statuses=http_statuses,
        http_urls=http_urls,
        http_user_agents=http_user_agents,
        http_files=http_files,
        file_artifacts=file_artifacts,
        services=services,
        detections=list(detections.values()),
        artifacts=[f"{name} ({count})" for name, count in artifact_counts.most_common(20)],
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )

    return render_udp_summary(rollup, limit=limit, verbose=verbose)


def render_exfil_summary(summary: ExfilSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"EXFILTRATION ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Outbound Bytes", format_bytes_as_mb(summary.outbound_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    if summary.outbound_flows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Outbound Flows (Private -> Public)"))
        rows = [["Src", "Dst", "Bytes"]]
        for item in summary.outbound_flows[:limit]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0))),
            ])
        lines.append(_format_table(rows))

    if summary.dns_tunnel_suspects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Tunneling Heuristics"))
        rows = [["Src", "Total", "Unique", "Long"]]
        for item in summary.dns_tunnel_suspects[:limit]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("total", "-")),
                str(item.get("unique", "-")),
                str(item.get("long", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.http_post_suspects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Large HTTP POST Payloads"))
        rows = [["Src", "Dst", "Host", "URI", "Bytes", "Content-Type"]]
        for item in summary.http_post_suspects[:limit]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("host", "-")),
                str(item.get("uri", "-")),
                str(item.get("bytes", "-")),
                str(item.get("content_type", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        rows = [["Filename", "Size", "Note"]]
        for item in summary.file_artifacts[:limit]:
            size_val = item.get("size")
            rows.append([
                str(item.get("filename", "-")),
                format_bytes_as_mb(int(size_val)) if isinstance(size_val, int) else "-",
                str(item.get("note", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_sizes_summary(summary: SizeSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"PACKET SIZE ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    if summary.buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet Size Distribution"))
        rows = [["Bucket", "Count", "Avg", "Min", "Max", "Rate(pkt/s)", "%", "Burst Rate", "Burst Start"]]
        for bucket in summary.buckets:
            rows.append([
                bucket.label,
                str(bucket.count),
                f"{bucket.avg:.1f}",
                str(bucket.min),
                str(bucket.max),
                f"{bucket.rate:.2f}",
                f"{bucket.pct:.1f}%",
                f"{bucket.burst_rate:.0f}",
                format_ts(bucket.burst_start) if bucket.burst_start else "-",
            ])
        lines.append(_format_table(rows))
        lines.append("")
        lines.append(muted(f"Distribution Sparkline: {render_size_sparkline(summary.buckets)}"))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_beacon_summary(summary: BeaconSummary, limit: int = 12, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"BEACON ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Candidates", str(summary.candidate_count)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if summary.candidates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Beacon Candidates (RITA-style scoring)"))
        rows = [[
            "Src",
            "Dst",
            "Proto",
            "Count",
            "Duration",
            "Mean",
            "MAD",
            "Avg Bytes",
            "Size MAD",
            "Periodicity",
            "Size",
            "Duration",
            "Count",
            "Score",
        ]]
        for cand in summary.candidates[:limit]:
            if cand.src_port and cand.dst_port:
                proto_label = f"{cand.proto}:{cand.src_port}->{cand.dst_port}"
            elif cand.src_port:
                proto_label = f"{cand.proto}:{cand.src_port}"
            else:
                proto_label = cand.proto
            score_text = f"{cand.score:.2f}"
            if cand.score >= 0.85:
                score_text = danger(score_text)
            elif cand.score >= 0.65:
                score_text = warn(score_text)
            else:
                score_text = ok(score_text)
            duration_text = format_duration(cand.duration_seconds) if cand.duration_seconds else "-"
            rows.append([
                cand.src_ip,
                cand.dst_ip,
                proto_label,
                str(cand.count),
                duration_text,
                f"{cand.mean_interval:.2f}s",
                f"{cand.mad_interval:.2f}s",
                f"{cand.avg_bytes:.0f}",
                f"{cand.mad_bytes:.0f}",
                f"{cand.periodicity_score:.2f}",
                f"{cand.size_score:.2f}",
                f"{cand.duration_score:.2f}",
                f"{cand.count_score:.2f}",
                score_text,
            ])
        lines.append(_format_table(rows))
        lines.append(muted(
            "Scores: Periodicity=1-MAD/Median interval, Size=1-MAD/Median bytes, "
            "Duration=duration/1h, Count=connections/50. Total score is weighted."
        ))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Beacon Timelines"))
        for cand in summary.candidates[:limit]:
            graph = sparkline(cand.timeline)
            lines.append(f"{cand.src_ip} -> {cand.dst_ip}  {graph}")
            if verbose:
                lines.append(muted(
                    "  Mean {mean:.2f}s | Median {median:.2f}s | MAD {mad:.2f}s | "
                    "Avg Bytes {avg_bytes:.0f} | Size MAD {size_mad:.0f} | "
                    "Scores P:{p:.2f} S:{s:.2f} D:{d:.2f} C:{c:.2f} | Total {score:.2f}"
                    .format(
                        mean=cand.mean_interval,
                        median=cand.median_interval,
                        mad=cand.mad_interval,
                        avg_bytes=cand.avg_bytes,
                        size_mad=cand.mad_bytes,
                        p=cand.periodicity_score,
                        s=cand.size_score,
                        d=cand.duration_score,
                        c=cand.count_score,
                        score=cand.score,
                    )
                ))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_threats_summary(summary: ThreatSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"THREATS OVERVIEW :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    def _highlight_public_ips(text: str) -> str:
        tokens = text.split()
        for idx, token in enumerate(tokens):
            stripped = token.strip("[](),;|")
            try:
                ip = ipaddress.ip_address(stripped)
            except Exception:
                continue
            if ip.is_global:
                tokens[idx] = token.replace(stripped, danger(stripped))
        return " ".join(tokens)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections (by severity)"))

        severity_order = {
            "critical": 0,
            "high": 1,
            "warning": 2,
            "info": 3,
        }

        grouped: dict[str, dict[str, list[dict[str, object]]]] = {}
        for item in summary.detections:
            severity = str(item.get("severity", "info")).lower()
            source = str(item.get("source", "Threats"))
            grouped.setdefault(severity, {}).setdefault(source, []).append(item)

        for severity in sorted(grouped.keys(), key=lambda key: severity_order.get(key, 99)):
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")

            lines.append(label(f"{marker} {severity.upper()}"))
            sources = grouped[severity]
            for source in sorted(sources.keys()):
                lines.append(muted(f"  Source: {source}"))
                for item in sources[source]:
                    summary_text = _highlight_public_ips(str(item.get("summary", "")))
                    details = _highlight_public_ips(str(item.get("details", "")))
                    lines.append(f"  - {summary_text}")
                    if details:
                        lines.append(muted(f"      {details}"))
                    top_sources = item.get("top_sources")
                    if top_sources:
                        src_text = ", ".join(
                            f"{_highlight_public_ips(str(ip))}({count})" for ip, count in top_sources
                        )
                        lines.append(muted(f"      Sources: {src_text}"))
                    top_destinations = item.get("top_destinations")
                    if top_destinations:
                        dst_text = ", ".join(
                            f"{_highlight_public_ips(str(ip))}({count})" for ip, count in top_destinations
                        )
                        lines.append(muted(f"      Destinations: {dst_text}"))
                    top_clients = item.get("top_clients")
                    if top_clients:
                        client_text = ", ".join(
                            f"{_highlight_public_ips(str(ip))}({count})" for ip, count in top_clients
                        )
                        lines.append(muted(f"      Clients: {client_text}"))
                    top_servers = item.get("top_servers")
                    if top_servers:
                        server_text = ", ".join(
                            f"{_highlight_public_ips(str(ip))}({count})" for ip, count in top_servers
                        )
                        lines.append(muted(f"      Servers: {server_text}"))
    else:
        lines.append(muted("No notable threats detected."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_files_summary(summary: FileTransferSummary, limit: int | None = None) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"FILES OVERVIEW :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Candidates", str(summary.total_candidates)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    effective_limit = limit if limit is not None else max(len(summary.candidates), len(summary.artifacts), 0)

    if summary.candidates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("File Transfer Candidates"))
        rows = [["Protocol", "Src", "Dst", "Ports", "Packets", "Bytes", "Note"]]
        for item in summary.candidates[:effective_limit]:
            ports = "-"
            if item.src_port is not None and item.dst_port is not None:
                ports = f"{item.src_port}->{item.dst_port}"
            rows.append([
                item.protocol,
                item.src_ip,
                item.dst_ip,
                ports,
                str(item.packets),
                format_bytes_as_mb(item.bytes),
                item.note or "-",
            ])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No file-transfer candidates detected."))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovered Files"))
        rows = [["Protocol", "Filename", "Type", "Size", "Packet", "Src", "Dst", "Note"]]
        for item in summary.artifacts[:effective_limit]:
            size = format_bytes_as_mb(item.size_bytes) if item.size_bytes is not None else "-"
            # Fallback for old artifacts without file_type
            ftype = getattr(item, "file_type", "UNKNOWN")
            rows.append([
                item.protocol,
                item.filename,
                ftype,
                size,
                str(item.packet_index),
                item.src_ip,
                item.dst_ip,
                item.note or "-",
            ])
        lines.append(_format_table(rows))

    if summary.extracted:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Extracted Files"))
        for path in summary.extracted:
            lines.append(ok(f"- {path}"))

    if summary.views:
        lines.append(SUBSECTION_BAR)
        lines.append(header("File View (ASCII/HEX)"))
        for item in summary.views:
            filename = str(item.get("filename", ""))
            payload = item.get("payload")
            size = item.get("size")
            if isinstance(payload, (bytes, bytearray)):
                lines.append(label(f"{filename} ({size} bytes)"))
                lines.append(hexdump(bytes(payload)))

    if summary.detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in summary.detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_protocols_summary(summary: ProtocolSummary, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"PROTOCOL & CONVERSATION ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Duration", format_duration(summary.duration)))

    # 1. Top Protocols
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Protocols"))
    rows = [["Protocol", "Packets", "% traffic"]]
    for name, count in summary.top_protocols:
        pct = (count / summary.total_packets * 100) if summary.total_packets else 0
        rows.append([name, str(count), f"{pct:.1f}%"])
    lines.append(_format_table(rows))

    if summary.port_protocols:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Port-Based Protocols (Service Heuristics)"))
        rows = [["Protocol", "Packets", "% traffic"]]
        for name, count in summary.port_protocols:
            pct = (count / summary.total_packets * 100) if summary.total_packets else 0
            rows.append([name, str(count), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    if summary.ethertype_protocols:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Ethertype Protocols (L2)"))
        rows = [["Protocol", "Packets", "% traffic"]]
        for name, count in summary.ethertype_protocols:
            pct = (count / summary.total_packets * 100) if summary.total_packets else 0
            rows.append([name, str(count), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    # 2. Hierarchy
    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Hierarchy"))
    
    def _clean_proto_name(name: str) -> str:
        # 1. Scapy "Layer in Layer" simplification
        if " in ICMP" in name:
             name = name.replace(" in ICMP", " (quoted)")
             
        # 2. Shorten verbose IPv6/ICMPv6 names
        mappings = [
            ("ICMPv6 Neighbor Discovery - Neighbor Solicitation", "ICMPv6 Neighbor Sol."),
            ("ICMPv6 Neighbor Discovery - Neighbor Advertisement", "ICMPv6 Neighbor Adv."),
            ("ICMPv6 Neighbor Discovery - Router Solicitation", "ICMPv6 Router Sol."),
            ("ICMPv6 Neighbor Discovery - Router Advertisement", "ICMPv6 Router Adv."),
            ("ICMPv6 Neighbor Discovery Option - Scapy Unimplemented", "ICMPv6 Option (Unknown)"),
            ("ICMPv6 Neighbor Discovery Option", "ICMPv6 Option"),
            ("IPv6 Extension Header - Hop-by-Hop Options Header", "IPv6 Hop-by-Hop"),
            ("IPv6 Extension Header", "IPv6 Ext"),
            ("MLDv2 - Multicast Listener Report", "MLDv2 Report"),
        ]
        
        for old, new in mappings:
            if old in name:
                name = name.replace(old, new)
        return name

    def render_node(node, depth=0):
        res = []
        indent = "  " * depth
        
        # Display:  |- HTTP (50 pkts, 10.2%)
        tree_char = "|- " if depth > 0 else ""
        
        clean_name = _clean_proto_name(node.name)
        name_display = f"{indent}{tree_char}{clean_name}"
        stats_display = f"{node.packets} pkts, {format_bytes_as_mb(node.bytes)}"
        
        # Dynamic padding calc could be better but fixed width for now
        res.append(f"{name_display:<50} {stats_display}")
        
        # Sort sub-protocols by packet count for better visibility
        sorted_subs = sorted(node.sub_protocols.values(), key=lambda x: x.packets, reverse=True)
        
        for sub in sorted_subs:
            res.extend(render_node(sub, depth + 1))
        return res
        
    hierarchy_lines = render_node(summary.hierarchy)
    # Remove Root if it's just a wrapper
    if len(summary.hierarchy.sub_protocols) > 0:
        hierarchy_lines = []
        # Sort root children too
        sorted_root_subs = sorted(summary.hierarchy.sub_protocols.values(), key=lambda x: x.packets, reverse=True)
        for sub in sorted_root_subs:
            hierarchy_lines.extend(render_node(sub, 0))
            
    lines.extend(hierarchy_lines)

    # 3. Anomalies / Threats
    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Potential Risks"))
        for a in summary.anomalies:
            sev_color = danger if a.severity in ("HIGH", "CRITICAL") else warn
            lines.append(sev_color(f"[{a.severity}] {a.type}: {a.description}"))
            if a.src or a.dst:
                lines.append(muted(f"  src: {str(a.src)} -> dst: {str(a.dst)}"))
    else:
        lines.append(SUBSECTION_BAR)
        lines.append(ok("No clear anomalies detected."))

    # 4. Conversations (Top 10 by bytes)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Conversations (by volume)"))
    
    sorted_convs = sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)[:10]
    
    rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "Duration", "Ports"]]
    for c in sorted_convs:
        # Sort ports by value for consistent display
        ports_list = sorted(list(c.ports))
        ports_str = ",".join(map(str, ports_list[:4]))
        if len(ports_list) > 4: ports_str += "..."
        
        dur = format_duration(c.end_ts - c.start_ts)
        rows.append([
            c.src, c.dst, c.protocol, str(c.packets), 
            format_bytes_as_mb(c.bytes), dur, ports_str
        ])
    lines.append(_format_table(rows))

    if verbose:
        # 5. Top Endpoints
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Endpoints"))
        sorted_eps = sorted(summary.endpoints, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True)[:10]
        rows = [["Address", "Sent", "Recv", "Total Bytes", "Protocols"]]
        for e in sorted_eps:
             protos = ",".join(list(e.protocols)[:4])
             rows.append([
                 e.address, 
                 str(e.packets_sent), 
                 str(e.packets_recv), 
                 format_bytes_as_mb(e.bytes_sent + e.bytes_recv), 
                 protos
             ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_services_summary(summary: ServiceSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SERVICE DISCOVERY & RISK ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    
    if summary.errors:
        lines.append(SUBSECTION_BAR)
        for err in summary.errors:
            lines.append(danger(f"Error: {err}"))
            
    lines.append(_format_kv("Total Services", str(summary.total_services)))
    
    # 1. Active Services Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("Active Services (Servers)"))
    
    if not summary.assets:
        lines.append(muted("No active services identified (no SYN-ACK/Response traffic seen)."))
    else:
        rows = [["Address", "Port", "Proto", "Service", "Software", "Clients", "Vol"]]
        for asset in summary.assets:
            software = asset.software or "-"
            vol = format_bytes_as_mb(asset.bytes)
            rows.append([
                asset.ip,
                str(asset.port),
                asset.protocol,
                asset.service_name,
                software,
                str(len(asset.clients)),
                vol
            ])
        lines.append(_format_table(rows))

    if summary.hierarchy:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Prevalence"))
        rows = [["Service", "Count"]]
        for name, count in sorted(summary.hierarchy.items(), key=lambda item: item[1], reverse=True):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    banners = [asset for asset in summary.assets if asset.software]
    if banners:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Service Banners"))
        rows = [["Address", "Port", "Service", "Banner"]]
        for asset in banners:
            rows.append([
                asset.ip,
                str(asset.port),
                asset.service_name,
                asset.software or "-",
            ])
        lines.append(_format_table(rows))

    # 2. Risks / Threats
    lines.append(SUBSECTION_BAR)
    lines.append(header("Cybersecurity Risks"))
    
    if not summary.risks:
        lines.append(ok("No high-confidence service risks detected."))
    else:
        # Group by severity
        for risk in sorted(summary.risks, key=lambda x: x.severity):
            sev_color = danger if risk.severity in ("CRITICAL", "HIGH") else warn
            if risk.severity == "LOW": sev_color = muted
            
            lines.append(sev_color(f"[{risk.severity}] {risk.title}"))
            lines.append(f"  Target: {risk.affected_asset}")
            lines.append(muted(f"  Details: {risk.description}"))
            lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_smb_summary(summary: SmbSummary, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SMB PROTOCOL ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("SMB Packets", str(summary.smb_packets)))
    versions_text = ", ".join([f"{k} ({v})" for k, v in summary.versions.items()]) if summary.versions else "-"
    lines.append(_format_kv("SMB Versions", versions_text))
    lines.append(_format_kv("Unique Clients", str(len(summary.clients))))
    lines.append(_format_kv("Unique Servers", str(len(summary.servers))))
    lines.append(_format_kv("Sessions", str(len(summary.sessions))))
    
    if summary.versions.get("SMB1"):
        lines.append(danger(f"SMBv1 DETECTED: {summary.versions['SMB1']} packets! Legacy/Insecure."))

    # 0. Request/Response Summary
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Requests vs Responses"))
    if not summary.requests and not summary.responses:
        lines.append(muted("No SMB command directionality captured."))
    else:
        rows = [["Command", "Requests", "Responses"]]
        all_cmds = set(summary.requests.keys()).union(summary.responses.keys())
        for cmd in sorted(all_cmds):
            rows.append([cmd, str(summary.requests.get(cmd, 0)), str(summary.responses.get(cmd, 0))])
        lines.append(_format_table(rows))

    # 1. Top Commands
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top SMB Commands"))
    if not summary.commands:
        lines.append(muted("No command usage stats."))
    else:
        rows = [["Command", "Count"]]
        for cmd, count in summary.commands.most_common(10):
            rows.append([cmd, str(count)])
        lines.append(_format_table(rows))

    # 2. Shares Accessed
    if summary.shares:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Shares Accessed"))
        rows = [["Server", "Share Path", "Count", "Type"]]
        for s in summary.shares:
            stype = "Admin" if s.is_admin else "Normal"
            rows.append([s.server_ip, s.name, str(s.connect_count), stype])
        lines.append(_format_table(rows))
    
    # 3. Top Clients/Servers
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Clients"))
    rows = [["Client IP", "Packets"]]
    for ip, count in summary.top_clients.most_common(5):
        rows.append([ip, str(count)])
    lines.append(_format_table(rows))
    
    lines.append("")
    lines.append(header("Top Servers"))
    rows = [["Server IP", "Packets"]]
    for ip, count in summary.top_servers.most_common(5):
        rows.append([ip, str(count)])
    lines.append(_format_table(rows))

    # 4. Error Codes / Failures
    if summary.error_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Error/Status Codes"))
        rows = [["Status Code", "Count"]]
        for code, count in summary.error_codes.most_common(10):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    # 5. Conversations
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Conversations"))
    if not summary.conversations:
        lines.append(muted("No SMB conversations summarized."))
    else:
        rows = [["Client", "Server", "Packets", "Bytes", "Requests", "Responses", "First Seen", "Last Seen"]]
        for convo in sorted(summary.conversations, key=lambda c: c.packets, reverse=True)[:10]:
            rows.append([
                convo.client_ip,
                convo.server_ip,
                str(convo.packets),
                format_bytes_as_mb(convo.bytes),
                str(convo.requests),
                str(convo.responses),
                format_ts(convo.first_seen),
                format_ts(convo.last_seen),
            ])
        lines.append(_format_table(rows))

    # 6. Server Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Servers"))
    if not summary.servers:
        lines.append(muted("No SMB servers identified."))
    else:
        rows = [["Server", "Dialects", "Signing Required", "Shares", "Capabilities"]]
        for srv in summary.servers:
            dialects = ", ".join(sorted(srv.dialects)) if srv.dialects else "-"
            signing = "Yes" if srv.signing_required else ("No" if srv.signing_required is not None else "-")
            shares = ", ".join(sorted(srv.shares)) if srv.shares else "-"
            caps = ", ".join(sorted(srv.capabilities)) if srv.capabilities else "-"
            rows.append([srv.ip, dialects, signing, shares, caps])
        lines.append(_format_table(rows))

    # 7. Client Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Clients"))
    if not summary.clients:
        lines.append(muted("No SMB clients identified."))
    else:
        rows = [["Client", "Dialects", "Client GUID", "Users", "Domains"]]
        for cli in summary.clients:
            dialects = ", ".join(sorted(cli.dialects)) if cli.dialects else "-"
            guid = cli.client_guid or "-"
            users = ", ".join(sorted(cli.usernames)) if cli.usernames else "-"
            domains = ", ".join(sorted(cli.domains)) if cli.domains else "-"
            rows.append([cli.ip, dialects, guid, users, domains])
        lines.append(_format_table(rows))

    # 8. Sessions
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Sessions"))
    if not summary.sessions:
        lines.append(muted("No SMB sessions decoded."))
    else:
        rows = [["Client", "Server", "Session", "User", "Domain", "Auth", "Signing", "Packets", "First Seen", "Last Seen"]]
        for sess in summary.sessions:
            rows.append([
                sess.client_ip,
                sess.server_ip,
                str(sess.session_id) if sess.session_id is not None else "-",
                sess.username or "-",
                sess.domain or "-",
                sess.auth_type or "-",
                "Yes" if sess.signing_required else ("No" if sess.signing_required is not None else "-"),
                str(sess.packets),
                format_ts(sess.start_ts if sess.start_ts else None),
                format_ts(sess.last_seen if sess.last_seen else None),
            ])
        lines.append(_format_table(rows))

    # 9. Files and Artifacts
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Files & Artifacts"))
    if summary.files:
        rows = [["Action", "File", "Share", "Size", "Client", "Server"]]
        for item in summary.files[:20]:
            rows.append([
                item.action,
                item.filename,
                item.share or "-",
                format_bytes_as_mb(item.size) if item.size else "-",
                item.client_ip or "-",
                item.server_ip or "-",
            ])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No SMB file operations extracted."))

    if summary.artifacts:
        lines.append(muted("Artifacts: " + ", ".join(summary.artifacts[:25])))

    # 10. Users & Domains
    if summary.observed_users or summary.observed_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users & Domains"))
        if summary.observed_users:
            rows = [["User", "Count"]]
            for user, count in summary.observed_users.most_common(10):
                rows.append([user, str(count)])
            lines.append(_format_table(rows))
        if summary.observed_domains:
            rows = [["Domain", "Count"]]
            for domain, count in summary.observed_domains.most_common(10):
                rows.append([domain, str(count)])
            lines.append(_format_table(rows))

    # 11. Anomalies & Risks (summary by default, detailed with verbose)
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Anomalies & Risks"))

    if not summary.anomalies:
        lines.append(ok("No SMB-specific anomalies detected."))
    else:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_counts = Counter(a.severity for a in summary.anomalies)
        rows = [["Severity", "Count", "Indicators"]]
        for sev in severity_order:
            if severity_counts.get(sev):
                indicators = Counter(a.title for a in summary.anomalies if a.severity == sev)
                indicator_text = ", ".join(
                    f"{title} ({count})" for title, count in indicators.most_common(5)
                )
                sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
                if sev == "LOW":
                    sev_color = muted
                rows.append([
                    sev_color(sev),
                    str(severity_counts[sev]),
                    muted(indicator_text) if indicator_text else muted("-"),
                ])
        lines.append(_format_table(rows))

        if verbose:
            lines.append("")
            for a in summary.anomalies:
                sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
                lines.append(sev_color(f"[{a.severity}] {a.title}"))
                lines.append(f"  {a.description}")
                lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
                lines.append("")

    if not summary.lateral_movement:
        lines.append(ok("No SMB lateral movement indicators detected."))
    else:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMB Lateral Movement Scoring"))
        top_scores = sorted(summary.lateral_movement, key=lambda x: x.get("score", 0), reverse=True)[:5]
        rows = [["Client", "Servers", "Admin Shares", "Failures", "Score"]]
        for item in top_scores:
            rows.append([
                str(item.get("client", "-")),
                str(item.get("servers", "-")),
                str(item.get("admin_shares", "-")),
                str(item.get("failures", "-")),
                str(item.get("score", "-")),
            ])
        lines.append(_format_table(rows))

        if verbose:
            lines.append(SUBSECTION_BAR)
            lines.append(header("SMB Lateral Movement Scoring (Detailed)"))
            rows = [["Client", "Servers", "Admin Shares", "Failures", "Score"]]
            for item in summary.lateral_movement[:10]:
                rows.append([
                    str(item.get("client", "-")),
                    str(item.get("servers", "-")),
                    str(item.get("admin_shares", "-")),
                    str(item.get("failures", "-")),
                    str(item.get("score", "-")),
                ])
            lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_nfs_summary(summary: NfsSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"NFS PROTOCOL ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("NFS Packets", str(summary.nfs_packets)))
    versions_text = ", ".join([f"{k} ({v})" for k, v in summary.versions.items()]) if summary.versions else "-"
    lines.append(_format_kv("NFS Versions", versions_text))
    lines.append(_format_kv("Unique Clients", str(len(summary.clients))))
    lines.append(_format_kv("Unique Servers", str(len(summary.servers))))
    lines.append(_format_kv("RPC Sessions", str(len(summary.sessions))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Requests vs Responses"))
    if not summary.requests and not summary.responses:
        lines.append(muted("No NFS request/response counts."))
    else:
        rows = [["Procedure", "Requests", "Responses"]]
        all_cmds = set(summary.requests.keys()).union(summary.responses.keys())
        for cmd in sorted(all_cmds):
            rows.append([cmd, str(summary.requests.get(cmd, 0)), str(summary.responses.get(cmd, 0))])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top NFS Procedures"))
    if not summary.procedures:
        lines.append(muted("No NFS procedures decoded."))
    else:
        rows = [["Procedure", "Count"]]
        for proc, count in summary.procedures.most_common(12):
            rows.append([proc, str(count)])
        lines.append(_format_table(rows))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NFS Status Codes"))
        rows = [["Status", "Count"]]
        for code, count in summary.status_codes.most_common(12):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Conversations"))
    if not summary.conversations:
        lines.append(muted("No NFS conversations summarized."))
    else:
        rows = [["Client", "Server", "Packets", "Bytes", "Requests", "Responses", "First Seen", "Last Seen"]]
        for convo in sorted(summary.conversations, key=lambda c: c.packets, reverse=True)[:10]:
            rows.append([
                convo.client_ip,
                convo.server_ip,
                str(convo.packets),
                format_bytes_as_mb(convo.bytes),
                str(convo.requests),
                str(convo.responses),
                format_ts(convo.first_seen),
                format_ts(convo.last_seen),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Servers"))
    if not summary.servers:
        lines.append(muted("No NFS servers identified."))
    else:
        rows = [["Server", "Versions", "Packets", "First Seen", "Last Seen"]]
        for srv in summary.servers:
            rows.append([
                srv.ip,
                ", ".join(sorted(srv.versions)) if srv.versions else "-",
                str(srv.packets),
                format_ts(srv.first_seen),
                format_ts(srv.last_seen),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Clients"))
    if not summary.clients:
        lines.append(muted("No NFS clients identified."))
    else:
        rows = [["Client", "Versions", "Users", "UIDs", "Packets"]]
        for cli in summary.clients:
            users = ", ".join(sorted(cli.usernames)) if cli.usernames else "-"
            uids = ", ".join(str(uid) for uid in sorted(cli.uids)) if cli.uids else "-"
            rows.append([
                cli.ip,
                ", ".join(sorted(cli.versions)) if cli.versions else "-",
                users,
                uids,
                str(cli.packets),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Files & Artifacts"))
    if summary.files:
        rows = [["Action", "Name", "Client", "Server", "Time"]]
        for item in summary.files[:20]:
            rows.append([
                item.action,
                item.name,
                item.client_ip,
                item.server_ip,
                format_ts(item.ts),
            ])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No file operations decoded."))

    if summary.artifacts:
        lines.append(muted("Artifacts: " + ", ".join(summary.artifacts[:25])))

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for user, count in summary.observed_users.most_common(10):
            rows.append([user, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Anomalies & Risks"))
    if not summary.anomalies:
        lines.append(ok("No NFS-specific anomalies detected."))
    else:
        for a in summary.anomalies:
            sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
            lines.append(sev_color(f"[{a.severity}] {a.title}"))
            lines.append(f"  {a.description}")
            lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
            lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_strings_summary(summary: StringsSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"STRINGS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Strings Found", str(summary.strings_found)))
    lines.append(_format_kv("Unique Strings", str(summary.unique_strings)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Cleartext Strings"))
    if not summary.top_strings:
        lines.append(muted("No cleartext strings extracted."))
    else:
        rows = [["String", "Count"]]
        for item in summary.top_strings:
            rows.append([item.value, str(item.count)])
        lines.append(_format_table(rows))

    if summary.urls or summary.emails or summary.domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        if summary.urls:
            rows = [["URL", "Count"]]
            for item in summary.urls:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))
        if summary.emails:
            rows = [["Email", "Count"]]
            for item in summary.emails:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))
        if summary.domains:
            rows = [["Domain", "Count"]]
            for item in summary.domains:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))

    if summary.suspicious_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious or Malicious Indicators"))
        rows = [["String", "Count", "Reason", "Top Sources", "Top Destinations"]]
        if summary.suspicious_details:
            for item in summary.suspicious_details:
                reasons = ", ".join(item.get("reasons", [])) or "-"
                top_src = ", ".join(f"{ip}({count})" for ip, count in item.get("top_sources", [])) or "-"
                top_dst = ", ".join(f"{ip}({count})" for ip, count in item.get("top_destinations", [])) or "-"
                rows.append([
                    str(item.get("value", "-")),
                    str(item.get("count", "-")),
                    reasons,
                    top_src,
                    top_dst,
                ])
        else:
            for item in summary.suspicious_strings:
                rows.append([item.value, str(item.count), "-", "-", "-"])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client Cleartext Highlights"))
    if not summary.client_strings:
        lines.append(muted("No client-attributed strings."))
    else:
        for ip, items in summary.client_strings.items():
            lines.append(label(f"Client {ip}"))
            rows = [["String", "Count"]]
            for item in items:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Server Cleartext Highlights"))
    if not summary.server_strings:
        lines.append(muted("No server-attributed strings."))
    else:
        for ip, items in summary.server_strings.items():
            lines.append(label(f"Server {ip}"))
            rows = [["String", "Count"]]
            for item in items:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Strings Anomalies"))
    if not summary.anomalies:
        lines.append(ok("No string-specific anomalies detected."))
    else:
        for item in summary.anomalies:
            lines.append(warn(f"[WARN] {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_search_summary(summary: SearchSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SEARCH RESULTS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Query", summary.query))
    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("Matches", str(summary.matches)))
    if summary.truncated:
        lines.append(warn(f"[WARN] Showing first {len(summary.hits)} matches."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Match Details"))
    if not summary.hits:
        lines.append(muted("No matches found."))
    else:
        rows = [["Pkt", "Time", "Src", "Dst", "Proto", "Sport", "Dport", "Len", "Context"]]
        for hit in summary.hits:
            rows.append([
                str(hit.packet_number),
                format_ts(hit.ts),
                hit.src_ip,
                hit.dst_ip,
                hit.protocol,
                str(hit.src_port) if hit.src_port is not None else "-",
                str(hit.dst_port) if hit.dst_port is not None else "-",
                str(hit.payload_len),
                _truncate_text(hit.context, 80),
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_creds_summary(summary: CredentialSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"CREDENTIAL EXPOSURE :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("Matches", str(summary.matches)))

    if summary.kind_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Match Types"))
        rows = [["Type", "Count"]]
        for kind, count in summary.kind_counts.most_common(15):
            rows.append([kind, str(count)])
        lines.append(_format_table(rows))

    if summary.user_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for user, count in summary.user_counts.most_common(15):
            rows.append([user, str(count)])
        lines.append(_format_table(rows))

    if summary.truncated:
        lines.append(warn(f"[WARN] Showing first {len(summary.hits)} matches."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Credential Hits"))
    if not summary.hits:
        lines.append(muted("No credential material detected."))
    else:
        for hit in summary.hits:
            header_line = (
                f"Pkt {hit.packet_number}  {format_ts(hit.ts)}  "
                f"{hit.src_ip} -> {hit.dst_ip}  {hit.protocol}"
            )
            lines.append(header_line)
            lines.append(
                f"  Kind: {hit.kind} | User: {hit.username or '-'} | Secret: {hit.secret or '-'}"
            )
            if hit.evidence:
                lines.append(f"  Evidence: {hit.evidence}")
            lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_certificates_summary(summary: CertificateSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TLS CERTIFICATES :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("TLS Packets", str(summary.tls_packets)))
    lines.append(_format_kv("Certificates", str(summary.cert_count)))

    if summary.subjects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Subjects"))
        rows = [["Subject", "Count"]]
        for subj, count in summary.subjects.most_common(10):
            rows.append([subj, str(count)])
        lines.append(_format_table(rows))

    if summary.issuers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Issuers"))
        rows = [["Issuer", "Count"]]
        for issuer, count in summary.issuers.most_common(10):
            rows.append([issuer, str(count)])
        lines.append(_format_table(rows))

    if summary.sas:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top SANs"))
        rows = [["SAN", "Count"]]
        for name, count in summary.sas.most_common(10):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.weak_keys:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Weak Keys"))
        rows = [["Subject", "Key Size", "Src", "Dst"]]
        for item in summary.weak_keys[:10]:
            rows.append([
                str(item.get("subject", "-")),
                str(item.get("size", "-")),
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.expired:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Expired / Invalid Certificates"))
        lines.append(muted("  Expired or invalid validity windows can indicate misconfigurations, expired infrastructure, or opportunistic interception."))
        rows = [["Subject", "Reason", "Src", "Dst"]]
        for item in summary.expired[:10]:
            rows.append([
                str(item.get("subject", "-")),
                str(item.get("reason", "-")),
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.self_signed:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Self-Signed Certificates"))
        lines.append(muted("  Self-signed certs may be benign in labs but can also signal spoofed services, internal C2, or TLS interception."))
        rows = [["Subject", "Src", "Dst"]]
        for item in summary.self_signed[:10]:
            rows.append([
                str(item.get("subject", "-")),
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Certificate Artifacts"))
        rows = [["Subject", "Issuer", "Not After", "Key", "SHA256"]]
        for cert in summary.artifacts[:10]:
            rows.append([
                cert.subject,
                cert.issuer,
                cert.not_after,
                f"{cert.pubkey_type} {cert.pubkey_size}",
                cert.sha256[:32] + "...",
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_health_summary(summary: HealthSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TRAFFIC HEALTH :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("TCP Packets", str(summary.tcp_packets)))
    lines.append(_format_kv("UDP Packets", str(summary.udp_packets)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Throughput"))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    if summary.duration_seconds:
        pps = summary.total_packets / summary.duration_seconds
        bps = (summary.total_bytes / summary.duration_seconds) * 8
        lines.append(_format_kv("Packets/sec", f"{pps:.2f}"))
        lines.append(_format_kv("Bits/sec", format_speed_bps(int(bps))))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Retransmissions"))
    lines.append(_format_kv("TCP Retransmissions", str(summary.retransmissions)))
    lines.append(_format_kv("Retransmission Rate", f"{summary.retransmission_rate:.2%}"))

    if summary.endpoint_bytes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Talkers"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        endpoint_packets = summary.endpoint_packets if isinstance(summary.endpoint_packets, Counter) else Counter()
        endpoint_bytes = summary.endpoint_bytes if isinstance(summary.endpoint_bytes, Counter) else Counter()
        for ip, byte_count in endpoint_bytes.most_common(10):
            rows.append([
                ip,
                str(endpoint_packets.get(ip, 0)),
                format_bytes_as_mb(byte_count),
            ])
        lines.append(_format_table(rows))

    if summary.flow_duration_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Flow Duration Distribution"))
        bucket_order = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
        for key, label_text in (("all", "All"), ("tcp", "TCP"), ("udp", "UDP")):
            buckets = summary.flow_duration_buckets.get(key, Counter())
            if not buckets:
                continue
            counts = [int(buckets.get(bucket, 0)) for bucket in bucket_order]
            lines.append(_format_kv(f"{label_text} Buckets", ", ".join(bucket_order)))
            lines.append(_format_kv(f"{label_text} Counts", ", ".join(str(val) for val in counts)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("TTL / Hop Limit"))
    lines.append(_format_kv("Expired TTL/Hop Limit", str(summary.ttl_expired)))
    lines.append(_format_kv("Low TTL/Hop Limit (<=5)", str(summary.ttl_low)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("TCP/UDP Health Indicators"))
    syn_only = summary.tcp_syn - summary.tcp_syn_ack
    rst_ratio = (summary.tcp_rst / summary.tcp_syn) if summary.tcp_syn else 0.0
    lines.append(_format_kv("TCP SYN", str(summary.tcp_syn)))
    lines.append(_format_kv("TCP SYN-ACK", str(summary.tcp_syn_ack)))
    lines.append(_format_kv("TCP RST", str(summary.tcp_rst)))
    lines.append(_format_kv("SYN without SYN-ACK", str(max(0, syn_only))))
    lines.append(_format_kv("RST/SYN Ratio", f"{rst_ratio:.2%}"))
    lines.append(_format_kv("Zero-Window", str(summary.tcp_zero_window)))
    lines.append(_format_kv("Small-Window", str(summary.tcp_small_window)))
    if summary.tcp_zero_window_sources:
        top_zero = ", ".join(f"{ip}({count})" for ip, count in summary.tcp_zero_window_sources.most_common(5))
        lines.append(_format_kv("Zero-Window Sources", top_zero))
    if summary.tcp_rst_sources:
        top_rst = ", ".join(f"{ip}({count})" for ip, count in summary.tcp_rst_sources.most_common(5))
        lines.append(_format_kv("RST Sources", top_rst))
    if summary.udp_amp_candidates:
        lines.append(_format_kv("UDP Amplification", str(len(summary.udp_amp_candidates))))
        lines.append(_format_kv("Top Candidates", ", ".join(summary.udp_amp_candidates[:5])))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Quality of Service (DSCP/ECN)"))
    top_dscp = ", ".join(f"{dscp}({count})" for dscp, count in summary.dscp_counts.most_common(5)) or "-"
    top_ecn = ", ".join(f"{ecn}({count})" for ecn, count in summary.ecn_counts.most_common(5)) or "-"
    lines.append(_format_kv("Top DSCP", top_dscp))
    lines.append(_format_kv("Top ECN", top_ecn))

    lines.append(SUBSECTION_BAR)
    lines.append(header("SNMP"))
    lines.append(_format_kv("SNMP Packets", str(summary.snmp_packets)))
    versions = ", ".join(f"{ver}({count})" for ver, count in summary.snmp_versions.most_common(5)) or "-"
    communities = ", ".join(f"{comm}({count})" for comm, count in summary.snmp_communities.most_common(5)) or "-"
    lines.append(_format_kv("Versions", versions))
    lines.append(_format_kv("Communities", communities))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Certificates"))
    lines.append(_format_kv("Expired/Invalid", str(summary.expired_certs)))
    lines.append(_format_kv("Self-Signed", str(summary.self_signed_certs)))

    if summary.ot_timing:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Cycle/Jitter"))
        for key, label_text in (
            ("profinet_rt", "Profinet RT"),
            ("enip_io", "ENIP IO"),
            ("s7_rosctr", "S7 COTP/ROSCTR"),
        ):
            entries = summary.ot_timing.get(key, [])
            if not entries:
                continue
            lines.append(muted(label_text))
            rows = [["Session", "Avg(s)", "Std(s)", "CV", "Min", "Max", "Samples"]]
            for item in entries:
                rows.append([
                    str(item.get("session", "-")),
                    f"{float(item.get('avg', 0.0)):.3f}",
                    f"{float(item.get('std', 0.0)):.3f}",
                    f"{float(item.get('cv', 0.0)):.2f}",
                    f"{float(item.get('min', 0.0)):.3f}",
                    f"{float(item.get('max', 0.0)):.3f}",
                    str(item.get("count", 0)),
                ])
            lines.append(_format_table(rows))

    if summary.findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Findings"))
        for item in summary.findings:
            severity = str(item.get("severity", "info"))
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_timeline_summary(summary: TimelineSummary, limit: int = 200) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TIMELINE :: {summary.target_ip} :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Events", str(len(summary.events))))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    def _severity_for_event(item: TimelineEvent) -> str:
        text = f"{item.summary} {item.details}".lower()
        if "potential port scan" in text:
            return "suspicious"
        if "http post" in text:
            return "suspicious"
        if "file artifact" in text:
            if any(token in text for token in [
                "(exe/dll)", "(archive)", ".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js"
            ]):
                return "malicious"
            return "suspicious"
        if "tcp connect attempt" in text:
            for port in (445, 3389, 22, 23, 135, 139, 5985, 5986):
                if f":{port}" in text:
                    return "suspicious"
        return "info"

    def _highlight_ips(text: str, target_ip: str) -> str:
        tokens = text.split()
        for idx, token in enumerate(tokens):
            stripped = token.strip("[](),;|")
            candidate = stripped
            if ":" in candidate and not candidate.startswith("["):
                host_part, port_part = candidate.rsplit(":", 1)
                if port_part.isdigit():
                    candidate = host_part
            if candidate == target_ip:
                continue
            try:
                ip = ipaddress.ip_address(candidate)
            except Exception:
                continue
            if ip.is_private:
                tokens[idx] = token.replace(stripped, orange(stripped))
            elif ip.is_global:
                tokens[idx] = token.replace(stripped, danger(stripped))
            else:
                tokens[idx] = token.replace(stripped, ok(stripped))
        return " ".join(tokens)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Activity Timeline"))
    lines.append(muted("Time | Category | Summary | Details"))
    for event in summary.events[:limit]:
        severity = _severity_for_event(event)
        summary_text = event.summary
        if severity == "malicious":
            summary_text = danger(event.summary)
        elif severity == "suspicious":
            summary_text = warn(event.summary)
        details_text = _highlight_ips(event.details, summary.target_ip)
        lines.append(f"{format_ts(event.ts)} | {event.category} | {summary_text} | {details_text}")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)

def render_ntlm_summary(summary: "NtlmAnalysis") -> str:
    """
    Render NTLM analysis results.
    """
    from .ntlm import NtlmAnalysis
    from .utils import format_ts

    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"NTLM ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    # 1. Overview
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("Authenticated", str(summary.authenticated_sessions)))
    lines.append(_format_kv("Unique Users", str(len(summary.unique_users))))
    lines.append(_format_kv("Unique Domains", str(len(summary.unique_domains))))
    lines.append(_format_kv("Unique Sources", str(len(summary.src_counts))))
    lines.append(_format_kv("Unique Destinations", str(len(summary.dst_counts))))
    
    # Check for legacy NTLM usage
    legacy_count = sum(1 for s in summary.sessions if s.version == "NTLMv1")
    if legacy_count > 0:
        lines.append(danger(f"Legacy NTLMv1 Sessions: {legacy_count}"))
    else:
        lines.append(ok("No Legacy NTLMv1 detected."))

    # 2. Users & Domains
    lines.append(SUBSECTION_BAR)
    lines.append(header("Identified User Accounts"))
    if not summary.unique_users:
        lines.append(muted("No usernames extracted."))
    else:
        # Group by domain
        by_domain = {}
        for dom, user in summary.unique_users:
            if dom not in by_domain:
                by_domain[dom] = []
            by_domain[dom].append(user)
        
        for dom, users in sorted(by_domain.items()):
            display_dom = dom if dom != "<NO_DOMAIN>" else "(No Domain)"
            lines.append(highlight(f"Domain: {display_dom}"))
            for u in sorted(users):
                lines.append(f"  - {u}")

    # 3. Workstations
        # 4. Requests & Responses
        if summary.request_counts or summary.response_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Requests & Responses"))
            rows = [["Message", "Requests", "Responses"]]
            all_msgs = set(summary.request_counts.keys()).union(summary.response_counts.keys())
            for name in sorted(all_msgs):
                rows.append([
                    name,
                    str(summary.request_counts.get(name, 0)),
                    str(summary.response_counts.get(name, 0)),
                ])
            lines.append(_format_table(rows))

        if summary.services:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Services"))
            rows = [["Service", "Count"]]
            for name, count in summary.services.most_common(10):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))

        if summary.status_codes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Status Codes"))
            rows = [["Status", "Count"]]
            for name, count in summary.status_codes.most_common(10):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))

        # 5. Conversations
        lines.append(SUBSECTION_BAR)
        lines.append(header("NTLM Conversations"))
        if not summary.conversations:
            lines.append(muted("No NTLM conversations summarized."))
        else:
            rows = [["Src", "Dst", "Ports", "Packets", "First Seen", "Last Seen"]]
            for convo in sorted(summary.conversations, key=lambda c: c.packets, reverse=True)[:12]:
                rows.append([
                    convo.src_ip,
                    convo.dst_ip,
                    f"{convo.src_port}->{convo.dst_port}",
                    str(convo.packets),
                    format_ts(convo.first_seen),
                    format_ts(convo.last_seen),
                ])
            lines.append(_format_table(rows))

        # 6. Artifacts
        if summary.artifacts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Artifacts"))
            rows = [["Artifact", "Description"]]
            for item in summary.artifacts[:15]:
                rows.append([item.value, item.description])
            lines.append(_format_table(rows))
    lines.append(SUBSECTION_BAR)
    lines.append(header("Client Workstations"))
    if not summary.unique_workstations:
        lines.append(muted("No workstation names extracted."))
    else:
        for ws in sorted(summary.unique_workstations):
            lines.append(f"  - {ws}")

    # 4. Session Details (Top 10)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Recent NTLM Sessions (Max 10)"))
    
    sorted_sessions = sorted(summary.sessions, key=lambda x: x.ts, reverse=True)[:10]
    if not sorted_sessions:
        lines.append(muted("No sessions."))
    else:
        # Table Header
        # TS | Src -> Dst | User | Domain | Ver
        row_fmt = "{:<20} | {:<35} | {:<15} | {:<15} | {:<10}"
        lines.append(muted(row_fmt.format("Timestamp", "Src -> Dst", "User", "Domain", "Ver")))
        lines.append(muted("-" * 105))
        
        for s in sorted_sessions:
            ts_str = format_ts(s.ts)
            flow_str = f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}"
            user_str = s.username if s.username else "-"
            dom_str = s.domain if s.domain else "-"
            ver_str = s.version
            
            line_str = row_fmt.format(ts_str, flow_str, user_str, dom_str, ver_str)
            if s.version == "NTLMv1":
                lines.append(danger(line_str))
            else:
                lines.append(line_str)

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_netbios_summary(summary: "NetbiosAnalysis") -> str:
    """
    Render NetBIOS analysis results.
    """
    from .netbios import NetbiosAnalysis

    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"NETBIOS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    # 1. Overview
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total NetBIOS Packets", str(summary.total_packets)))
    lines.append(_format_kv("Unique Hosts", str(len(summary.hosts))))
    lines.append(_format_kv("Unique NetBIOS Names", str(len(summary.unique_names))))
    lines.append(_format_kv("Unique Sources", str(len(summary.src_counts))))
    lines.append(_format_kv("Unique Destinations", str(len(summary.dst_counts))))
    
    if summary.name_conflicts > 0:
        lines.append(danger(f"Name Conflicts: {summary.name_conflicts}"))
    else:
        lines.append(ok("No Name Conflicts detected."))

    # 1b. Traffic Summary
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top NetBIOS Sources & Destinations"))
    if summary.src_counts:
        rows = [["Source", "Packets"]]
        for ip, count in summary.src_counts.most_common(8):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))
    if summary.dst_counts:
        rows = [["Destination", "Packets"]]
        for ip, count in summary.dst_counts.most_common(8):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    if summary.request_counts or summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NetBIOS Requests & Responses"))
        rows = [["Type", "Requests", "Responses"]]
        all_types = set(summary.request_counts.keys()).union(summary.response_counts.keys())
        for name in sorted(all_types):
            rows.append([
                name,
                str(summary.request_counts.get(name, 0)),
                str(summary.response_counts.get(name, 0)),
            ])
        lines.append(_format_table(rows))

    if summary.service_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NetBIOS Services"))
        rows = [["Service", "Count"]]
        for name, count in summary.service_counts.most_common(10):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.nbss_message_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NBSS Message Types"))
        rows = [["Type", "Count"]]
        for name, count in summary.nbss_message_types.most_common(10):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.smb_versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMB over NetBIOS (NBSS)"))
        rows = [["SMB Version", "Count"]]
        for name, count in summary.smb_versions.most_common(5):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.smb_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMB Command Summary"))
        rows = [["Command", "Count"]]
        for name, count in summary.smb_commands.most_common(12):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.smb_users or summary.smb_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMB Users/Domains (NTLM)"))
        if summary.smb_users:
            rows = [["User", "Count"]]
            for name, count in summary.smb_users.most_common(10):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))
        if summary.smb_domains:
            rows = [["Domain", "Count"]]
            for name, count in summary.smb_domains.most_common(10):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))
        if summary.smb_sources or summary.smb_destinations:
            rows = [["Top Sources", "Top Destinations"]]
            src_text = ", ".join(f"{ip}({count})" for ip, count in summary.smb_sources.most_common(5)) or "-"
            dst_text = ", ".join(f"{ip}({count})" for ip, count in summary.smb_destinations.most_common(5)) or "-"
            rows.append([src_text, dst_text])
            lines.append(_format_table(rows))

    if summary.response_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NBNS Response Codes"))
        rows = [["Code", "Count"]]
        for code, count in summary.response_codes.most_common(10):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    # 2. Hosts & Names
    lines.append(SUBSECTION_BAR)
    lines.append(header("NetBIOS Hosts & Names"))
    
    if not summary.hosts:
        lines.append(muted("No NetBIOS hosts identified."))
    else:
        for ip, host in sorted(summary.hosts.items()):
            # Determine role icons/text
            roles = []
            if host.is_domain_controller:
                roles.append("DC")
            if host.is_master_browser:
                roles.append("Master Browser")
            
            role_str = f" [{', '.join(roles)}]" if roles else ""
            
            lines.append(highlight(f"Host: {ip}{role_str}"))
            if host.mac:
                lines.append(muted(f"  MAC: {host.mac}"))
            
            if not host.names:
                lines.append(muted("  (No advertised names seen)"))
            else:
                for nb_name in host.names:
                    # Colorize special suffixes
                    suffix_hex = f"<0x{nb_name.suffix:02X}>"
                    lines.append(f"  - {nb_name.name:<16} {suffix_hex} : {nb_name.type_str}")
            lines.append("")

    # 3. Conversations
    lines.append(SUBSECTION_BAR)
    lines.append(header("NetBIOS Conversations"))
    if not summary.conversations:
        lines.append(muted("No NetBIOS conversations summarized."))
    else:
        rows = [["Src", "Dst", "Proto", "Ports", "Packets", "First Seen", "Last Seen"]]
        for convo in sorted(summary.conversations, key=lambda c: c.packets, reverse=True)[:12]:
            ports = f"{convo.src_port}->{convo.dst_port}"
            rows.append([
                convo.src_ip,
                convo.dst_ip,
                convo.protocol,
                ports,
                str(convo.packets),
                format_ts(convo.first_seen),
                format_ts(convo.last_seen),
            ])
        lines.append(_format_table(rows))

    # 4. SMB Client Details (NetBIOS Session Service)
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Clients over NetBIOS"))
    if not summary.smb_clients:
        lines.append(muted("No SMB-over-NetBIOS clients detected."))
    else:
        rows = [["Client", "Sessions"]]
        for ip, count in summary.smb_clients.most_common(10):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    # 5. Artifacts & Observed Users
    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        lines.append(muted(", ".join(summary.artifacts[:30])))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        lines.append(muted(", ".join(summary.files_discovered[:30])))

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed NetBIOS Names"))
        rows = [["Name", "Count"]]
        for name, count in summary.observed_users.most_common(12):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    # 6. Sessions
    lines.append(SUBSECTION_BAR)
    lines.append(header("NetBIOS Sessions"))
    if not summary.sessions:
        lines.append(muted("No NetBIOS sessions identified."))
    else:
        rows = [["Src", "Dst", "Ports", "Packets", "First Seen", "Last Seen"]]
        for sess in summary.sessions[:12]:
            rows.append([
                sess.src_ip,
                sess.dst_ip,
                f"{sess.src_port}->{sess.dst_port}",
                str(sess.packets),
                format_ts(sess.first_seen),
                format_ts(sess.last_seen),
            ])
        lines.append(_format_table(rows))

    # 7. Anomalies
    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Events"))
        for a in summary.anomalies:
            ts = f"{a.timestamp:.2f}"
            sev_color = danger if a.severity in ("HIGH", "CRITICAL") else warn
            lines.append(sev_color(f"[{ts}] {a.type}: {a.details}"))
            lines.append(muted(f"  Src: {a.src_ip} -> Dst: {a.dst_ip}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)

def render_modbus_summary(summary: "ModbusAnalysis", verbose: bool = False) -> str:
    """
    Render Modbus analysis results.
    """
    from .modbus import ModbusAnalysis
    from .utils import format_ts

    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MODBUS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    # 1. Overview
    total_packets = summary.total_packets
    total_bytes = summary.total_bytes
    modbus_packets = summary.modbus_packets
    modbus_bytes = summary.modbus_bytes
    modbus_payload_bytes = summary.modbus_payload_bytes
    modbus_packet_ratio = (modbus_packets / total_packets) if total_packets else 0.0
    modbus_byte_ratio = (modbus_bytes / total_bytes) if total_bytes else 0.0
    avg_modbus_pkt = (modbus_bytes / modbus_packets) if modbus_packets else 0.0
    avg_modbus_payload = (modbus_payload_bytes / modbus_packets) if modbus_packets else 0.0

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(total_bytes)))
    if summary.duration:
        pps = total_packets / summary.duration
        bps = (total_bytes / summary.duration) * 8
        lines.append(_format_kv("Packets/sec", f"{pps:.2f}"))
        lines.append(_format_kv("Bits/sec", format_speed_bps(int(bps))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Modbus Protocol Statistics"))
    lines.append(_format_kv("Modbus Packets", f"{modbus_packets} ({modbus_packet_ratio:.1%})"))
    lines.append(_format_kv("Modbus Bytes", f"{format_bytes_as_mb(modbus_bytes)} ({modbus_byte_ratio:.1%})"))
    lines.append(_format_kv("Modbus Payload Bytes", format_bytes_as_mb(modbus_payload_bytes)))
    lines.append(_format_kv("Avg Modbus Packet Size", f"{avg_modbus_pkt:.1f} bytes"))
    lines.append(_format_kv("Avg Modbus Payload Size", f"{avg_modbus_payload:.1f} bytes"))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Error Rate", f"{summary.error_rate:.2f}%"))
    
    # 2. Function Codes
    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed Commands"))
    if not summary.func_counts:
        lines.append(muted("No Modbus functions detected."))
    else:
        for func, count in summary.func_counts.most_common():
            lowered = func.lower()
            is_write = "write" in lowered
            is_diag = any(token in lowered for token in ("diagnostic", "encapsulated", "report server", "file"))
            if is_write:
                color = danger
            elif is_diag:
                color = warn
            else:
                color = lambda x: x
            lines.append(color(f"{func:<40} : {count}"))
            
    # 3. Unit IDs
    lines.append(SUBSECTION_BAR)
    lines.append(header("Active Unit IDs"))
    if not summary.unit_ids:
        lines.append(muted("No Unit IDs found."))
    else:
        # Show top 10
        top_units = summary.unit_ids.most_common(10)
        u_strs = [f"ID {uid} ({cnt})" for uid, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))
        if len(summary.unit_ids) > 10:
            lines.append(muted(f"  ... and {len(summary.unit_ids) - 10} more"))

    # 4. Endpoints
    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if summary.endpoint_packets:
        rows = [["Endpoint", "Packets", "Bytes"]]
        for ip, count in summary.endpoint_packets.most_common(10):
            rows.append([
                ip,
                str(count),
                format_bytes_as_mb(summary.endpoint_bytes.get(ip, 0)),
            ])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No Modbus endpoints detected."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Statistics"))
    col_width = 45
    lines.append(highlight(f"{'Clients (Controllers)':<{col_width}} | {'Servers (PLCs/Sensors)'}"))
    lines.append(muted("-" * 90))
    clients = summary.src_ips.most_common(10)
    servers = summary.dst_ips.most_common(10)
    max_rows = max(len(clients), len(servers))
    for i in range(max_rows):
        c_str = ""
        s_str = ""
        if i < len(clients):
            ip, cnt = clients[i]
            c_bytes = format_bytes_as_mb(summary.client_bytes.get(ip, 0))
            c_str = f"{ip} ({cnt}/{c_bytes})"
        if i < len(servers):
            ip, cnt = servers[i]
            s_bytes = format_bytes_as_mb(summary.server_bytes.get(ip, 0))
            s_str = f"{ip} ({cnt}/{s_bytes})"
        lines.append(f"{c_str:<{col_width}} | {s_str}")

    if summary.service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Modbus Services (Endpoints)"))
        rows = [["Service", "Top Endpoints"]]
        for func_name, counter in Counter({
            name: sum(cnt.values()) for name, cnt in summary.service_endpoints.items()
        }).most_common(10):
            endpoints = summary.service_endpoints.get(func_name, Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(3))
            rows.append([func_name, top_eps or "-"])
        lines.append(_format_table(rows))

    if summary.artifacts:
        equipment_hits = [
            artifact for artifact in summary.artifacts
            if str(getattr(artifact, "kind", "")) == "equipment"
        ]
        if equipment_hits:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Equipment Inventory"))
            counts = Counter(str(getattr(artifact, "detail", "")) for artifact in equipment_hits)
            endpoints: dict[str, Counter[str]] = defaultdict(Counter)
            for artifact in equipment_hits:
                detail = str(getattr(artifact, "detail", ""))
                src = str(getattr(artifact, "src", "?"))
                dst = str(getattr(artifact, "dst", "?"))
                endpoints[detail][f"{src} -> {dst}"] += 1
            rows = [["Equipment", "Count", "Top Endpoints"]]
            for detail, count in counts.most_common(12):
                top_eps = ", ".join(
                    f"{ep} ({cnt})" for ep, cnt in endpoints[detail].most_common(3)
                )
                rows.append([detail, str(count), top_eps or "-"])
            lines.append(_format_table(rows))

    if summary.packet_size_hist or summary.payload_size_hist:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet & Payload Size Distribution"))
        bucket_labels = ["<=64", "65-128", "129-256", "257-512", "513-1024", "1025-1500", "1501-9000", ">9000"]
        if summary.packet_size_hist:
            packet_series = [summary.packet_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Packet Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Packet Size Spark", sparkline(packet_series)))
            stats = summary.packet_size_stats
            lines.append(_format_kv("Packet Size Stats", f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}"))
        if summary.payload_size_hist:
            payload_series = [summary.payload_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Payload Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Payload Size Spark", sparkline(payload_series)))
            stats = summary.payload_size_stats
            lines.append(_format_kv("Payload Size Stats", f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}"))

    if summary.flow_duration_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Flow Duration Distribution"))
        bucket_order = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
        for key, label_text in (("all", "All"), ("requests", "Requests"), ("responses", "Responses")):
            buckets = summary.flow_duration_buckets.get(key, Counter())
            if not buckets:
                continue
            counts = [int(buckets.get(bucket, 0)) for bucket in bucket_order]
            lines.append(_format_kv(f"{label_text} Buckets", ", ".join(bucket_order)))
            lines.append(_format_kv(f"{label_text} Counts", ", ".join(str(val) for val in counts)))

    if summary.messages:
        exception_counts = Counter(
            f"{msg.exception_desc or 'Exception'}" for msg in summary.messages if msg.is_exception
        )
        if exception_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Exception Responses"))
            rows = [["Exception", "Count"]]
            for exc, count in exception_counts.most_common(10):
                rows.append([exc, str(count)])
            lines.append(_format_table(rows))

    # 5. Anomalies
    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats"))

        if not verbose:
            lines.append(_format_kv("Total Anomalies", str(len(summary.anomalies))))
            sev_counts = Counter(a.severity for a in summary.anomalies)
            sev_rows = [["Severity", "Count"]]
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev_counts.get(severity):
                    sev_rows.append([severity, str(sev_counts[severity])])
            if len(sev_rows) > 1:
                lines.append(_format_table(sev_rows))
            title_counts = Counter(a.title for a in summary.anomalies)
            if title_counts:
                lines.append(SUBSECTION_BAR)
                lines.append(header("Top Anomaly Types"))
                rows = [["Type", "Count"]]
                for title, count in title_counts.most_common(10):
                    rows.append([title, str(count)])
                lines.append(_format_table(rows))
            lines.append(muted("Use -v for detailed anomaly listings."))
        else:
            # Sort by severity
            sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_anoms = sorted(summary.anomalies, key=lambda x: sev_map.get(x.severity, 99))
            
            for a in sorted_anoms:
                sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
                if a.severity == "LOW": sev_color = muted
                
                lines.append(sev_color(f"[{a.severity}] {a.title}"))
                lines.append(f"  {a.description}")
                lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
                lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_modbus_rollup(summaries: Iterable["ModbusAnalysis"]) -> str:
    """
    Render Modbus rollup results across multiple pcaps.
    """
    from .modbus import ModbusAnalysis

    summary_list = list(summaries)
    if not summary_list:
        return ""

    total_pcaps = len(summary_list)
    total_duration = 0.0
    total_modbus_packets = 0
    total_packets = 0
    total_bytes = 0
    total_modbus_bytes = 0
    total_modbus_payload_bytes = 0
    total_messages = 0
    total_exceptions = 0
    func_counts = Counter()
    unit_ids = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    client_bytes = Counter()
    server_bytes = Counter()
    endpoint_packets = Counter()
    endpoint_bytes = Counter()
    service_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    packet_size_hist = Counter()
    payload_size_hist = Counter()
    flow_duration_buckets: dict[str, Counter[str]] = {
        "all": Counter(),
        "requests": Counter(),
        "responses": Counter(),
    }
    equipment_counts: Counter[str] = Counter()
    equipment_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    all_anomalies = []
    errors = Counter()

    for summary in summary_list:
        total_duration += summary.duration
        total_packets += summary.total_packets
        total_bytes += summary.total_bytes
        total_modbus_packets += summary.modbus_packets
        total_modbus_bytes += summary.modbus_bytes
        total_modbus_payload_bytes += summary.modbus_payload_bytes
        func_counts.update(summary.func_counts)
        unit_ids.update(summary.unit_ids)
        src_ips.update(summary.src_ips)
        dst_ips.update(summary.dst_ips)
        client_bytes.update(summary.client_bytes)
        server_bytes.update(summary.server_bytes)
        endpoint_packets.update(summary.endpoint_packets)
        endpoint_bytes.update(summary.endpoint_bytes)
        packet_size_hist.update(summary.packet_size_hist)
        payload_size_hist.update(summary.payload_size_hist)
        for name, counter in summary.service_endpoints.items():
            service_endpoints[name].update(counter)
        for artifact in summary.artifacts:
            if str(getattr(artifact, "kind", "")) != "equipment":
                continue
            detail = str(getattr(artifact, "detail", ""))
            equipment_counts[detail] += 1
            src = str(getattr(artifact, "src", "?"))
            dst = str(getattr(artifact, "dst", "?"))
            equipment_endpoints[detail][f"{src} -> {dst}"] += 1
        for key in ("all", "requests", "responses"):
            flow_duration_buckets[key].update(summary.flow_duration_buckets.get(key, Counter()))
        total_messages += len(summary.messages)
        total_exceptions += sum(1 for msg in summary.messages if msg.is_exception)
        all_anomalies.extend(summary.anomalies)
        for err in summary.errors:
            errors[err] += 1

    error_rate = (total_exceptions / total_messages) * 100 if total_messages else 0.0

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MODBUS ANALYSIS :: ALL PCAPS ({total_pcaps})"))
    lines.append(SECTION_BAR)

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err, count in errors.most_common(10):
            suffix = f" (x{count})" if count > 1 else ""
            lines.append(danger(f"- {err}{suffix}"))

    lines.append(_format_kv("PCAPs Analyzed", str(total_pcaps)))
    lines.append(_format_kv("Combined Duration", f"{total_duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(total_bytes)))
    lines.append(_format_kv("Modbus Packets", str(total_modbus_packets)))
    lines.append(_format_kv("Modbus Bytes", format_bytes_as_mb(total_modbus_bytes)))
    lines.append(_format_kv("Modbus Payload Bytes", format_bytes_as_mb(total_modbus_payload_bytes)))
    lines.append(_format_kv("Total Messages", str(total_messages)))
    lines.append(_format_kv("Unique Clients", str(len(src_ips))))
    lines.append(_format_kv("Unique Servers", str(len(dst_ips))))
    lines.append(_format_kv("Error Rate", f"{error_rate:.2f}%"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Function Code Usage"))
    if not func_counts:
        lines.append(muted("No Modbus functions detected."))
    else:
        for func, count in func_counts.most_common():
            is_write = "Write" in func
            c = danger if is_write else lambda x: x
            lines.append(c(f"{func:<40} : {count}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Active Unit IDs"))
    if not unit_ids:
        lines.append(muted("No Unit IDs found."))
    else:
        top_units = unit_ids.most_common(10)
        u_strs = [f"ID {uid} ({cnt})" for uid, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))
        if len(unit_ids) > 10:
            lines.append(muted(f"  ... and {len(unit_ids) - 10} more"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Modbus Endpoints"))
    col_width = 45
    lines.append(highlight(f"{'Clients (Controllers)':<{col_width}} | {'Servers (PLCs/Sensors)'}"))
    lines.append(muted("-" * 90))
    clients = src_ips.most_common(10)
    servers = dst_ips.most_common(10)
    max_rows = max(len(clients), len(servers))
    for i in range(max_rows):
        c_str = ""
        s_str = ""
        if i < len(clients):
            ip, cnt = clients[i]
            c_str = f"{ip} ({cnt}/{format_bytes_as_mb(client_bytes.get(ip, 0))})"
        if i < len(servers):
            ip, cnt = servers[i]
            s_str = f"{ip} ({cnt}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
        lines.append(f"{c_str:<{col_width}} | {s_str}")

    if endpoint_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Endpoints"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        for ip, count in endpoint_packets.most_common(10):
            rows.append([
                ip,
                str(count),
                format_bytes_as_mb(endpoint_bytes.get(ip, 0)),
            ])
        lines.append(_format_table(rows))

    if service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Modbus Services (Endpoints)"))
        rows = [["Service", "Top Endpoints"]]
        for func_name, counter in Counter({
            name: sum(cnt.values()) for name, cnt in service_endpoints.items()
        }).most_common(10):
            endpoints = service_endpoints.get(func_name, Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(3))
            rows.append([func_name, top_eps or "-"])
        lines.append(_format_table(rows))

    if equipment_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Equipment Inventory"))
        rows = [["Equipment", "Count", "Top Endpoints"]]
        for detail, count in equipment_counts.most_common(12):
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in equipment_endpoints[detail].most_common(3)
            )
            rows.append([detail, str(count), top_eps or "-"])
        lines.append(_format_table(rows))

    if packet_size_hist or payload_size_hist:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet & Payload Size Distribution"))
        bucket_labels = ["<=64", "65-128", "129-256", "257-512", "513-1024", "1025-1500", "1501-9000", ">9000"]
        if packet_size_hist:
            packet_series = [packet_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Packet Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Packet Size Spark", sparkline(packet_series)))
        if payload_size_hist:
            payload_series = [payload_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Payload Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Payload Size Spark", sparkline(payload_series)))

    if flow_duration_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Flow Duration Distribution"))
        bucket_order = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
        for key, label_text in (("all", "All"), ("requests", "Requests"), ("responses", "Responses")):
            buckets = flow_duration_buckets.get(key, Counter())
            if not buckets:
                continue
            counts = [int(buckets.get(bucket, 0)) for bucket in bucket_order]
            lines.append(_format_kv(f"{label_text} Buckets", ", ".join(bucket_order)))
            lines.append(_format_kv(f"{label_text} Counts", ", ".join(str(val) for val in counts)))

    if all_anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats (Aggregated)"))
        lines.append(_format_kv("Total Anomalies", str(len(all_anomalies))))
        sev_counts = Counter(a.severity for a in all_anomalies)
        sev_rows = [["Severity", "Count"]]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(severity):
                sev_rows.append([severity, str(sev_counts[severity])])
        if len(sev_rows) > 1:
            lines.append(_format_table(sev_rows))
        title_counts = Counter(a.title for a in all_anomalies)
        if title_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Top Anomaly Types"))
            rows = [["Type", "Count"]]
            for title, count in title_counts.most_common(10):
                rows.append([title, str(count)])
            lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)

def render_dnp3_summary(summary: "Dnp3Analysis") -> str:
    """
    Render DNP3 analysis results.
    """
    from .dnp3 import Dnp3Analysis

    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DNP3 ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    # 1. Overview
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("DNP3 Packets", str(summary.dnp3_packets)))
    lines.append(_format_kv("Active TCP/UDP IPs", str(len(summary.ip_endpoints))))
    lines.append(_format_kv("DNP3 Addresses", str(summary.unique_dnp3_addresses)))
    
    # 2. Function Codes
    lines.append(SUBSECTION_BAR)
    lines.append(header("Function Code Usage"))
    if not summary.func_counts:
        lines.append(muted("No DNP3 functions detected."))
    else:
        for func, count in summary.func_counts.most_common():
            # Highlight potentially dangerous functions
            is_risk = any(x in func for x in ["Write", "Restart", "File", "Freeze"])
            c = danger if is_risk else lambda x: x
            
            lines.append(c(f"{func:<40} : {count}"))

    # 3. Addresses
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top DNP3 Addresses (Data Link)"))
    if not summary.src_addrs:
        lines.append(muted("No DNP3 addresses found."))
    else:
        # Combine src and dst
        all_addrs = summary.src_addrs + summary.dst_addrs
        top_units = all_addrs.most_common(10)
        u_strs = [f"Addr {addr} ({cnt})" for addr, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))

    # 4. Anomalies
    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats"))
        
        # Sort by severity
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_anoms = sorted(summary.anomalies, key=lambda x: sev_map.get(x.severity, 99))
        
        for a in sorted_anoms:
            sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
            if a.severity == "LOW": sev_color = muted
            
            lines.append(sev_color(f"[{a.severity}] {a.title}"))
            lines.append(f"  {a.description}")
            lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
            lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_dnp3_rollup(summaries: Iterable["Dnp3Analysis"]) -> str:
    """
    Render DNP3 rollup results across multiple pcaps.
    """
    from .dnp3 import Dnp3Analysis

    summary_list = list(summaries)
    if not summary_list:
        return ""

    total_pcaps = len(summary_list)
    total_duration = 0.0
    total_dnp3_packets = 0
    func_counts = Counter()
    src_addrs = Counter()
    dst_addrs = Counter()
    ip_endpoints = Counter()
    all_anomalies = []
    errors = Counter()

    for summary in summary_list:
        total_duration += summary.duration
        total_dnp3_packets += summary.dnp3_packets
        func_counts.update(summary.func_counts)
        src_addrs.update(summary.src_addrs)
        dst_addrs.update(summary.dst_addrs)
        ip_endpoints.update(summary.ip_endpoints)
        all_anomalies.extend(summary.anomalies)
        for err in summary.errors:
            errors[err] += 1

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DNP3 ANALYSIS :: ALL PCAPS ({total_pcaps})"))
    lines.append(SECTION_BAR)

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err, count in errors.most_common(10):
            suffix = f" (x{count})" if count > 1 else ""
            lines.append(danger(f"- {err}{suffix}"))

    lines.append(_format_kv("PCAPs Analyzed", str(total_pcaps)))
    lines.append(_format_kv("Combined Duration", f"{total_duration:.2f}s"))
    lines.append(_format_kv("DNP3 Packets", str(total_dnp3_packets)))
    lines.append(_format_kv("Active TCP/UDP IPs", str(len(ip_endpoints))))
    unique_addrs = len(set(list(src_addrs.keys()) + list(dst_addrs.keys())))
    lines.append(_format_kv("DNP3 Addresses", str(unique_addrs)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Function Code Usage"))
    if not func_counts:
        lines.append(muted("No DNP3 functions detected."))
    else:
        for func, count in func_counts.most_common():
            is_risk = any(x in func for x in ["Write", "Restart", "File", "Freeze"])
            c = danger if is_risk else lambda x: x
            lines.append(c(f"{func:<40} : {count}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top DNP3 Addresses (Data Link)"))
    if not src_addrs and not dst_addrs:
        lines.append(muted("No DNP3 addresses found."))
    else:
        all_addrs = src_addrs + dst_addrs
        top_units = all_addrs.most_common(10)
        u_strs = [f"Addr {addr} ({cnt})" for addr, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))

    if all_anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats (Aggregated)"))
        lines.append(_format_kv("Total Anomalies", str(len(all_anomalies))))
        sev_counts = Counter(a.severity for a in all_anomalies)
        sev_rows = [["Severity", "Count"]]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(severity):
                sev_rows.append([severity, str(sev_counts[severity])])
        if len(sev_rows) > 1:
            lines.append(_format_table(sev_rows))
        title_counts = Counter(a.title for a in all_anomalies)
        if title_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Top Anomaly Types"))
            rows = [["Type", "Count"]]
            for title, count in title_counts.most_common(10):
                rows.append([title, str(count)])
            lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def _render_industrial_summary(title: str, summary: object, packet_label: str = "Protocol Packets") -> str:
    if not summary:
        return ""

    total_packets = getattr(summary, "total_packets", 0)
    protocol_packets = getattr(summary, "protocol_packets", 0)
    duration = getattr(summary, "duration", 0.0)
    src_ips = getattr(summary, "src_ips", Counter())
    dst_ips = getattr(summary, "dst_ips", Counter())
    sessions = getattr(summary, "sessions", Counter())
    commands = getattr(summary, "commands", Counter())
    artifacts = getattr(summary, "artifacts", [])
    anomalies = getattr(summary, "anomalies", [])
    errors = getattr(summary, "errors", [])

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"{title.upper()} ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scan Duration", f"{duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv(packet_label, str(protocol_packets)))
    lines.append(_format_kv("Unique Clients", str(len(src_ips))))
    lines.append(_format_kv("Unique Servers", str(len(dst_ips))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Endpoints"))
    if not src_ips and not dst_ips:
        lines.append(muted("No endpoints detected."))
    else:
        col_width = 45
        lines.append(highlight(f"{'Clients':<{col_width}} | {'Servers'}"))
        lines.append(muted("-" * 90))
        clients = src_ips.most_common(10)
        servers = dst_ips.most_common(10)
        max_rows = max(len(clients), len(servers))
        for i in range(max_rows):
            c_str = ""
            s_str = ""
            if i < len(clients):
                ip, cnt = clients[i]
                c_str = f"{ip} ({cnt})"
            if i < len(servers):
                ip, cnt = servers[i]
                s_str = f"{ip} ({cnt})"
            lines.append(f"{c_str:<{col_width}} | {s_str}")

    if commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Commands/Operations"))
        rows = [["Command", "Count"]]
        for cmd, count in commands.most_common(12):
            rows.append([str(cmd), str(count)])
        lines.append(_format_table(rows))

    if sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in sessions.most_common(10):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for artifact in artifacts[:12]:
            rows.append([
                str(getattr(artifact, "kind", "artifact")),
                str(getattr(artifact, "detail", ""))[:80],
                str(getattr(artifact, "src", "?")),
                str(getattr(artifact, "dst", "?")),
            ])
        lines.append(_format_table(rows))

    if anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Events"))
        for anomaly in anomalies[:12]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            lines.append(sev_color(f"[{sev}] {getattr(anomaly, 'title', 'Event')}: {getattr(anomaly, 'description', '')}"))
            lines.append(muted(f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_iec104_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("IEC-104", summary, packet_label="IEC-104 Packets")


def render_bacnet_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("BACnet", summary, packet_label="BACnet Packets")


def render_enip_summary(summary: "ENIPAnalysis") -> str:
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ETHERNET/IP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    duration = summary.duration
    rate = (summary.enip_bytes / duration) if duration and duration > 0 else 0

    lines.append(_format_kv("Scan Duration", f"{duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("ENIP Packets", str(summary.enip_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("ENIP Bytes", format_bytes_as_mb(summary.enip_bytes)))
    lines.append(_format_kv("ENIP Throughput", format_speed_bps(int(rate * 8))))
    lines.append(_format_kv("Requests", str(summary.requests)))
    lines.append(_format_kv("Responses", str(summary.responses)))
    lines.append(_format_kv("Connected/Unconnected", f"{summary.connected_packets}/{summary.unconnected_packets}"))
    lines.append(_format_kv("I/O Packets (UDP/2222)", str(summary.io_packets)))
    lines.append(_format_kv("Unique Clients", str(len(summary.client_ips))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_ips))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if not summary.client_ips and not summary.server_ips:
        lines.append(muted("No ENIP endpoints detected."))
    else:
        col_width = 45
        lines.append(highlight(f"{'Clients':<{col_width}} | {'Servers'}"))
        lines.append(muted("-" * 90))
        clients = summary.client_ips.most_common(10)
        servers = summary.server_ips.most_common(10)
        max_rows = max(len(clients), len(servers))
        for i in range(max_rows):
            c_str = ""
            s_str = ""
            if i < len(clients):
                ip, cnt = clients[i]
                c_str = f"{ip} ({cnt})"
            if i < len(servers):
                ip, cnt = servers[i]
                s_str = f"{ip} ({cnt})"
            lines.append(f"{c_str:<{col_width}} | {s_str}")

    if summary.sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in summary.sessions.most_common(12):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if summary.enip_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ENIP Encapsulation Commands"))
        rows = [["Command", "Count", "Risk"]]
        suspicious = {
            "ListServices",
            "ListIdentity",
            "ListInterfaces",
            "RegisterSession",
            "WriteObjectInstanceAttributes",
        }
        for cmd, count in summary.enip_commands.most_common(12):
            risk = "Normal"
            display = cmd
            if cmd in suspicious:
                risk = "Suspicious"
                display = warn(cmd)
            rows.append([display, str(count), risk])
        lines.append(_format_table(rows))

    if summary.cip_services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Encapsulated CIP Services"))
        rows = [["Service", "Count", "Risk"]]
        dangerous = {
            "Reset",
            "Start",
            "Stop",
            "ProgramDownload",
            "ProgramCommand",
            "WriteTag",
            "WriteTagFragmented",
            "ReadModifyWriteTag",
            "WriteData",
        }
        suspicious = {
            "Set_Attribute_List",
            "Set_Attribute_Single",
            "Set_Attributes_All",
            "Forward_Open",
            "Forward_Close",
            "Create",
            "Delete",
            "ProgramUpload",
        }
        for service, count in summary.cip_services.most_common(16):
            risk = "Normal"
            display = service
            if service in dangerous:
                risk = "Dangerous"
                display = danger(service)
            elif service in suspicious:
                risk = "Suspicious"
                display = warn(service)
            rows.append([display, str(count), risk])
        lines.append(_format_table(rows))

    if summary.service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints"))
        rows = [["Service", "Top Endpoints"]]
        for service, count in summary.cip_services.most_common(8):
            endpoints = summary.service_endpoints.get(service, Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(3)
            )
            rows.append([service, top_eps or "-"])
        lines.append(_format_table(rows))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ENIP/CIP Status Codes"))
        rows = [["Status", "Count"]]
        for status, count in summary.status_codes.most_common(12):
            rows.append([str(status), str(count)])
        lines.append(_format_table(rows))

    if getattr(summary, "identities", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Inventory (ListIdentity)"))
        rows = [[
            "IP",
            "Vendor ID",
            "Device Type",
            "Product Code",
            "Revision",
            "Serial",
            "Product Name",
        ]]
        def _format_identity_label(name: object | None, code: object | None, label: str) -> str:
            if name:
                return f"{name} ({code})"
            if code is None or code == "-":
                return "-"
            try:
                code_val = int(code)
            except Exception:
                return str(code)
            if code_val == 0:
                return f"Unknown {label} (0)"
            return f"{label} {code_val}"

        for ident in summary.identities[:20]:
            vendor_id = getattr(ident, "vendor_id", "-")
            vendor_name = getattr(ident, "vendor_name", None)
            vendor_display = _format_identity_label(vendor_name, vendor_id, "Vendor")

            device_type = getattr(ident, "device_type", "-")
            device_type_name = getattr(ident, "device_type_name", None)
            device_display = _format_identity_label(device_type_name, device_type, "DeviceType")

            product_code = getattr(ident, "product_code", "-")
            product_name = getattr(ident, "product_code_name", None)
            product_display = _format_identity_label(product_name, product_code, "Product")

            rows.append([
                str(getattr(ident, "src_ip", "?")),
                vendor_display,
                device_display,
                product_display,
                str(getattr(ident, "revision", "-")),
                str(getattr(ident, "serial_number", "-")),
                _truncate_text(str(getattr(ident, "product_name", "-")), 32),
            ])
        lines.append(_format_table(rows))

    if summary.packet_size_buckets or summary.payload_size_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet/Payload Size Analysis"))

        def _summarize_buckets(buckets: list[SizeBucket]) -> tuple[int, float, int, int]:
            total = sum(bucket.count for bucket in buckets)
            if not total:
                return 0, 0.0, 0, 0
            avg = sum(bucket.avg * bucket.count for bucket in buckets) / total
            min_val = min(bucket.min for bucket in buckets if bucket.count)
            max_val = max(bucket.max for bucket in buckets if bucket.count)
            return total, avg, min_val, max_val

        if summary.packet_size_buckets:
            total, avg, min_val, max_val = _summarize_buckets(summary.packet_size_buckets)
            counts = [bucket.count for bucket in summary.packet_size_buckets]
            lines.append(label("Packet Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))

        if summary.payload_size_buckets:
            total, avg, min_val, max_val = _summarize_buckets(summary.payload_size_buckets)
            counts = [bucket.count for bucket in summary.payload_size_buckets]
            lines.append(label("Payload Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))

        rows = [["Bucket", "Packets", "Pct", "Min", "Avg", "Max"]]
        for bucket in summary.packet_size_buckets[:10]:
            rows.append([
                bucket.label,
                str(bucket.count),
                f"{bucket.pct:.1f}%",
                str(bucket.min),
                f"{bucket.avg:.1f}",
                str(bucket.max),
            ])
        if len(rows) > 1:
            lines.append(label("Packet Buckets"))
            lines.append(_format_table(rows))

        rows = [["Bucket", "Payloads", "Pct", "Min", "Avg", "Max"]]
        for bucket in summary.payload_size_buckets[:10]:
            rows.append([
                bucket.label,
                str(bucket.count),
                f"{bucket.pct:.1f}%",
                str(bucket.min),
                f"{bucket.avg:.1f}",
                str(bucket.max),
            ])
        if len(rows) > 1:
            lines.append(label("Payload Buckets"))
            lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [[label("Type"), label("Detail"), label("Src"), label("Dst")]]
        for artifact in summary.artifacts[:12]:
            kind = str(getattr(artifact, "kind", "artifact"))
            detail = str(getattr(artifact, "detail", ""))
            detail = " ".join(detail.split())
            if kind == "tag":
                tokens = re.findall(r"[A-Za-z0-9_]{3,}", detail)
                if tokens:
                    unique = []
                    seen = set()
                    for tok in tokens:
                        if tok in seen:
                            continue
                        unique.append(tok)
                        seen.add(tok)
                    preview = ", ".join(unique[:4])
                    extra = len(unique) - 4
                    if extra > 0:
                        preview = f"{preview} (+{extra})"
                    detail = preview
                else:
                    detail = _truncate_text(detail, 32)
            detail_lines = [detail]
            if kind == "tag":
                kind_display = highlight(kind)
            elif kind == "identity":
                kind_display = warn(kind)
            else:
                kind_display = label(kind)
            src = str(getattr(artifact, "src", "?"))
            dst = str(getattr(artifact, "dst", "?"))
            rows.append([kind_display, detail_lines[0], src, dst])
            for extra in detail_lines[1:]:
                rows.append([muted("·"), muted(extra), "", ""])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats"))
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_anoms = sorted(summary.anomalies, key=lambda x: sev_map.get(x.severity, 99))
        for anomaly in sorted_anoms[:20]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            if sev == "LOW":
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {getattr(anomaly, 'title', 'Event')}: {getattr(anomaly, 'description', '')}"))
            lines.append(muted(f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def _render_ot_protocol_summary(
    title: str,
    summary: object,
    packet_label: str,
    dangerous_tokens: set[str] | None = None,
    suspicious_tokens: set[str] | None = None,
) -> str:
    if not summary:
        return ""

    total_packets = getattr(summary, "total_packets", 0)
    protocol_packets = getattr(summary, "protocol_packets", 0)
    total_bytes = getattr(summary, "total_bytes", 0)
    protocol_bytes = getattr(summary, "protocol_bytes", 0)
    duration = getattr(summary, "duration", 0.0)
    src_ips = getattr(summary, "src_ips", Counter())
    dst_ips = getattr(summary, "dst_ips", Counter())
    client_ips = getattr(summary, "client_ips", Counter())
    server_ips = getattr(summary, "server_ips", Counter())
    sessions = getattr(summary, "sessions", Counter())
    commands = getattr(summary, "commands", Counter())
    service_endpoints = getattr(summary, "service_endpoints", {})
    packet_buckets = getattr(summary, "packet_size_buckets", [])
    payload_buckets = getattr(summary, "payload_size_buckets", [])
    artifacts = getattr(summary, "artifacts", [])
    anomalies = getattr(summary, "anomalies", [])
    errors = getattr(summary, "errors", [])

    def _summarize_buckets(buckets: list[SizeBucket]) -> tuple[int, float, int, int]:
        total = sum(bucket.count for bucket in buckets)
        if not total:
            return 0, 0.0, 0, 0
        avg = sum(bucket.avg * bucket.count for bucket in buckets) / total
        min_val = min(bucket.min for bucket in buckets if bucket.count)
        max_val = max(bucket.max for bucket in buckets if bucket.count)
        return total, avg, min_val, max_val

    dangerous_tokens = dangerous_tokens or set()
    suspicious_tokens = suspicious_tokens or set()

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"{title.upper()} ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scan Duration", f"{duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv(packet_label, str(protocol_packets)))
    lines.append(_format_kv("Total Bytes", str(total_bytes)))
    lines.append(_format_kv(f"{title} Bytes", str(protocol_bytes)))
    if protocol_packets:
        lines.append(_format_kv("Avg Packet Size", f"{protocol_bytes / protocol_packets:.1f}"))

    if packet_buckets or payload_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet/Payload Size Analysis"))
        if packet_buckets:
            total, avg, min_val, max_val = _summarize_buckets(packet_buckets)
            counts = [bucket.count for bucket in packet_buckets]
            lines.append(label("Packet Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))
        if payload_buckets:
            total, avg, min_val, max_val = _summarize_buckets(payload_buckets)
            counts = [bucket.count for bucket in payload_buckets]
            lines.append(label("Payload Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    lines.append(_format_kv("Unique Clients", str(len(client_ips) or len(src_ips))))
    lines.append(_format_kv("Unique Servers", str(len(server_ips) or len(dst_ips))))
    col_width = 45
    lines.append(highlight(f"{'Clients':<{col_width}} | {'Servers'}"))
    lines.append(muted("-" * 90))
    clients = (client_ips or src_ips).most_common(10)
    servers = (server_ips or dst_ips).most_common(10)
    max_rows = max(len(clients), len(servers))
    for i in range(max_rows):
        c_str = ""
        s_str = ""
        if i < len(clients):
            ip, cnt = clients[i]
            c_str = f"{ip} ({cnt})"
        if i < len(servers):
            ip, cnt = servers[i]
            s_str = f"{ip} ({cnt})"
        lines.append(f"{c_str:<{col_width}} | {s_str}")

    if sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in sessions.most_common(10):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Commands/Operations"))
        rows = [["Command", "Count", "Risk"]]
        for cmd, count in commands.most_common(16):
            cmd_text = str(cmd)
            lowered = cmd_text.lower()
            risk = "Normal"
            display = cmd_text
            if any(token in lowered for token in dangerous_tokens):
                risk = "Dangerous"
                display = danger(cmd_text)
            elif any(token in lowered for token in suspicious_tokens):
                risk = "Suspicious"
                display = warn(cmd_text)
            rows.append([display, str(count), risk])
        lines.append(_format_table(rows))

    if service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints"))
        rows = [["Service", "Top Endpoints"]]
        for service, _count in commands.most_common(10):
            endpoints = service_endpoints.get(str(service), Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(3))
            rows.append([str(service), top_eps or "-"])
        lines.append(_format_table(rows))

    if artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for artifact in artifacts[:16]:
            rows.append([
                str(getattr(artifact, "kind", "artifact")),
                str(getattr(artifact, "detail", ""))[:80],
                str(getattr(artifact, "src", "?")),
                str(getattr(artifact, "dst", "?")),
            ])
        lines.append(_format_table(rows))

        equipment_hits = [
            artifact for artifact in artifacts
            if str(getattr(artifact, "kind", "")) == "equipment"
        ]
        if equipment_hits:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Equipment Inventory"))
            counts = Counter(str(getattr(artifact, "detail", "")) for artifact in equipment_hits)
            endpoints: dict[str, Counter[str]] = defaultdict(Counter)
            for artifact in equipment_hits:
                detail = str(getattr(artifact, "detail", ""))
                src = str(getattr(artifact, "src", "?"))
                dst = str(getattr(artifact, "dst", "?"))
                endpoints[detail][f"{src} -> {dst}"] += 1
            rows = [["Equipment", "Count", "Top Endpoints"]]
            for detail, count in counts.most_common(12):
                top_eps = ", ".join(
                    f"{ep} ({cnt})" for ep, cnt in endpoints[detail].most_common(3)
                )
                rows.append([detail, str(count), top_eps or "-"])
            lines.append(_format_table(rows))

    if anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        for anomaly in anomalies[:16]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            lines.append(sev_color(f"[{sev}] {getattr(anomaly, 'title', 'Event')}: {getattr(anomaly, 'description', '')}"))
            lines.append(muted(f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_profinet_summary(summary: "IndustrialAnalysis") -> str:
    return _render_ot_protocol_summary(
        "Profinet",
        summary,
        packet_label="Profinet Packets",
        dangerous_tokens={"set", "write", "alarm", "download", "upload"},
        suspicious_tokens={"identify", "query", "scan"},
    )


def render_s7_summary(summary: "IndustrialAnalysis") -> str:
    return _render_ot_protocol_summary(
        "S7",
        summary,
        packet_label="S7 Packets",
        dangerous_tokens={"write", "stop", "download", "upload", "start", "plc"},
        suspicious_tokens={"read", "setup", "userdata", "block", "diag"},
    )


def render_opc_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("OPC UA", summary, packet_label="OPC UA Packets")


def render_ethercat_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("EtherCAT", summary, packet_label="EtherCAT Packets")


def render_fins_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("FINS", summary, packet_label="FINS Packets")


def render_crimson_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("Crimson V3", summary, packet_label="Crimson Packets")


def render_pcworx_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("PCWorx", summary, packet_label="PCWorx Packets")


def render_melsec_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("MELSEC-Q", summary, packet_label="MELSEC Packets")


def render_cip_summary(summary: "CIPAnalysis") -> str:
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"CIP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    duration = summary.duration
    rate = (summary.cip_bytes / duration) if duration and duration > 0 else 0

    lines.append(_format_kv("Scan Duration", f"{duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("CIP Packets", str(summary.cip_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("CIP Bytes", format_bytes_as_mb(summary.cip_bytes)))
    lines.append(_format_kv("CIP Throughput", format_speed_bps(int(rate * 8))))
    lines.append(_format_kv("Requests", str(summary.requests)))
    lines.append(_format_kv("Responses", str(summary.responses)))
    lines.append(_format_kv("Connected/Unconnected", f"{summary.connected_packets}/{summary.unconnected_packets}"))
    lines.append(_format_kv("I/O Packets (UDP/2222)", str(summary.io_packets)))
    lines.append(_format_kv("Unique Clients", str(len(summary.client_ips))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_ips))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if not summary.client_ips and not summary.server_ips:
        lines.append(muted("No CIP endpoints detected."))
    else:
        col_width = 45
        lines.append(highlight(f"{'Clients':<{col_width}} | {'Servers'}"))
        lines.append(muted("-" * 90))
        clients = summary.client_ips.most_common(10)
        servers = summary.server_ips.most_common(10)
        max_rows = max(len(clients), len(servers))
        for i in range(max_rows):
            c_str = ""
            s_str = ""
            if i < len(clients):
                ip, cnt = clients[i]
                c_str = f"{ip} ({cnt})"
            if i < len(servers):
                ip, cnt = servers[i]
                s_str = f"{ip} ({cnt})"
            lines.append(f"{c_str:<{col_width}} | {s_str}")

    if summary.sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in summary.sessions.most_common(12):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if summary.enip_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ENIP Encapsulation Commands"))
        rows = [["Command", "Count"]]
        for cmd, count in summary.enip_commands.most_common(12):
            rows.append([str(cmd), str(count)])
        lines.append(_format_table(rows))

    if summary.cip_services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CIP Service Usage"))
        rows = [["Service", "Count", "Risk"]]
        dangerous = {
            "Reset",
            "Start",
            "Stop",
            "ProgramDownload",
            "ProgramCommand",
            "WriteTag",
            "WriteTagFragmented",
            "ReadModifyWriteTag",
            "WriteData",
        }
        suspicious = {
            "Set_Attribute_List",
            "Set_Attribute_Single",
            "Set_Attributes_All",
            "Forward_Open",
            "Forward_Close",
            "Create",
            "Delete",
            "ProgramUpload",
        }
        for service, count in summary.cip_services.most_common(16):
            risk = "Normal"
            display = service
            if service in dangerous:
                risk = "Dangerous"
                display = danger(service)
            elif service in suspicious:
                risk = "Suspicious"
                display = warn(service)
            rows.append([display, str(count), risk])
        lines.append(_format_table(rows))

    if summary.service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints"))
        rows = [["Service", "Top Endpoints"]]
        for service, count in summary.cip_services.most_common(8):
            endpoints = summary.service_endpoints.get(service, Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(3)
            )
            rows.append([service, top_eps or "-"])
        lines.append(_format_table(rows))

    if summary.class_ids or summary.instance_ids or summary.attribute_ids:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CIP Object Path Statistics"))
        if summary.class_ids:
            rows = [["Class ID", "Count"]]
            for class_id, count in summary.class_ids.most_common(10):
                rows.append([str(class_id), str(count)])
            lines.append(label("Top Class IDs"))
            lines.append(_format_table(rows))
        if summary.instance_ids:
            rows = [["Instance ID", "Count"]]
            for inst_id, count in summary.instance_ids.most_common(10):
                rows.append([str(inst_id), str(count)])
            lines.append(label("Top Instance IDs"))
            lines.append(_format_table(rows))
        if summary.attribute_ids:
            rows = [["Attribute ID", "Count"]]
            for attr_id, count in summary.attribute_ids.most_common(10):
                rows.append([str(attr_id), str(count)])
            lines.append(label("Top Attribute IDs"))
            lines.append(_format_table(rows))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CIP Status Codes"))
        rows = [["Status", "Count"]]
        for status, count in summary.status_codes.most_common(12):
            rows.append([str(status), str(count)])
        lines.append(_format_table(rows))

    if summary.packet_size_buckets or summary.payload_size_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet/Payload Size Analysis"))

        def _summarize_buckets(buckets: list[SizeBucket]) -> tuple[int, float, int, int]:
            total = sum(bucket.count for bucket in buckets)
            if not total:
                return 0, 0.0, 0, 0
            avg = sum(bucket.avg * bucket.count for bucket in buckets) / total
            min_val = min(bucket.min for bucket in buckets if bucket.count)
            max_val = max(bucket.max for bucket in buckets if bucket.count)
            return total, avg, min_val, max_val

        if summary.packet_size_buckets:
            total, avg, min_val, max_val = _summarize_buckets(summary.packet_size_buckets)
            counts = [bucket.count for bucket in summary.packet_size_buckets]
            lines.append(label("Packet Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))

        if summary.payload_size_buckets:
            total, avg, min_val, max_val = _summarize_buckets(summary.payload_size_buckets)
            counts = [bucket.count for bucket in summary.payload_size_buckets]
            lines.append(label("Payload Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))

        rows = [["Bucket", "Packets", "Pct", "Min", "Avg", "Max"]]
        for bucket in summary.packet_size_buckets[:10]:
            rows.append([
                bucket.label,
                str(bucket.count),
                f"{bucket.pct:.1f}%",
                str(bucket.min),
                f"{bucket.avg:.1f}",
                str(bucket.max),
            ])
        if len(rows) > 1:
            lines.append(label("Packet Buckets"))
            lines.append(_format_table(rows))

        rows = [["Bucket", "Payloads", "Pct", "Min", "Avg", "Max"]]
        for bucket in summary.payload_size_buckets[:10]:
            rows.append([
                bucket.label,
                str(bucket.count),
                f"{bucket.pct:.1f}%",
                str(bucket.min),
                f"{bucket.avg:.1f}",
                str(bucket.max),
            ])
        if len(rows) > 1:
            lines.append(label("Payload Buckets"))
            lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for artifact in summary.artifacts[:12]:
            rows.append([
                str(getattr(artifact, "kind", "artifact")),
                _truncate_text(str(getattr(artifact, "detail", "")), 80),
                str(getattr(artifact, "src", "?")),
                str(getattr(artifact, "dst", "?")),
            ])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats"))
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_anoms = sorted(summary.anomalies, key=lambda x: sev_map.get(x.severity, 99))
        for anomaly in sorted_anoms[:20]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            if sev == "LOW":
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {getattr(anomaly, 'title', 'Event')}: {getattr(anomaly, 'description', '')}"))
            lines.append(muted(f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_odesys_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("ODESYS", summary, packet_label="ODESYS Packets")


def render_niagara_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("Niagara Fox", summary, packet_label="Niagara Packets")


def render_mms_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("IEC 61850 MMS", summary, packet_label="MMS Packets")


def render_srtp_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("GE SRTP", summary, packet_label="SRTP Packets")


def render_df1_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("DF1", summary, packet_label="DF1 Packets")


def render_pccc_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("PCCC", summary, packet_label="PCCC Packets")


def render_csp_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("CSP", summary, packet_label="CSP Packets")


def render_modicon_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("Modicon", summary, packet_label="Modicon Packets")


def render_yokogawa_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("Yokogawa Vnet/IP", summary, packet_label="Yokogawa Packets")


def render_honeywell_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("Honeywell CDA", summary, packet_label="Honeywell Packets")


def render_mqtt_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("MQTT", summary, packet_label="MQTT Packets")


def render_coap_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("CoAP", summary, packet_label="CoAP Packets")


def render_hart_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("HART-IP", summary, packet_label="HART Packets")


def render_prconos_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("ProConOS", summary, packet_label="ProConOS Packets")


def render_iccp_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("ICCP/TASE.2", summary, packet_label="ICCP Packets")
