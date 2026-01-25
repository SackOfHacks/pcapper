from __future__ import annotations

from collections import Counter
import ipaddress
import re
from typing import Iterable

from .models import PcapSummary
from .utils import format_bytes_as_mb, format_duration, format_speed_bps, format_ts, sparkline, hexdump
from .coloring import danger, header, label, muted, ok, warn, highlight, orange
from .vlan import VlanSummary
from .icmp import IcmpSummary
from .dns import DnsSummary
from .beacon import BeaconSummary
from .threats import ThreatSummary
from .files import FileTransferSummary
from .protocols import ProtocolSummary
from .services import ServiceSummary
from .smb import SmbSummary
from .nfs import NfsSummary
from .strings import StringsSummary
from .certificates import CertificateSummary
from .http import HttpSummary
from .sizes import SizeSummary, render_size_sparkline
from .ips import IpSummary
from .timeline import TimelineSummary
from .health import HealthSummary


SECTION_BAR = "=" * 72
SUBSECTION_BAR = "-" * 72


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

    lines.append(SUBSECTION_BAR)
    lines.append(header("Interface Statistics"))
    rows = [["Interface", "LinkType", "SnapLen", "Speed", "Packets", "VLANs", "Details"]]
    for iface in summary.interface_stats:
        vlan_display = ",".join(str(vlan) for vlan in iface.vlan_ids) if iface.vlan_ids else "-"
        details_parts = []
        if iface.description:
            details_parts.append(iface.description)
        if iface.mac:
            details_parts.append(f"mac {iface.mac}")
        if iface.os:
            details_parts.append(f"os {iface.os}")
        details = "; ".join(details_parts) if details_parts else "-"
        rows.append([
            iface.name,
            iface.linktype or "-",
            str(iface.snaplen) if iface.snaplen is not None else "-",
            format_speed_bps(iface.speed_bps),
            str(iface.packet_count) if iface.packet_count is not None else "-",
            vlan_display,
            details,
        ])
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Summary (presence across packets)"))
    lines.append(_format_table(_protocol_rows(summary.protocol_counts, summary.packet_count, protocol_limit)))
    lines.append(SECTION_BAR)

    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


def render_files_summary(summary: FileTransferSummary, limit: int = 15) -> str:
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

    if summary.candidates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("File Transfer Candidates"))
        rows = [["Protocol", "Src", "Dst", "Ports", "Packets", "Bytes", "Note"]]
        for item in summary.candidates[:limit]:
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
        for item in summary.artifacts[:limit]:
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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


def render_smb_summary(summary: SmbSummary) -> str:
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

    # 11. Anomalies
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Anomalies & Risks"))
    if not summary.anomalies:
        lines.append(ok("No SMB-specific anomalies detected."))
    else:
        for a in summary.anomalies:
            sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
            lines.append(sev_color(f"[{a.severity}] {a.title}"))
            lines.append(f"  {a.description}")
            lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
            lines.append("")

    if summary.lateral_movement:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMB Lateral Movement Scoring"))
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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


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
    return "\n".join(lines)


def render_health_summary(summary: HealthSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TRAFFIC HEALTH :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("TCP Packets", str(summary.tcp_packets)))
    lines.append(_format_kv("UDP Packets", str(summary.udp_packets)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Retransmissions"))
    lines.append(_format_kv("TCP Retransmissions", str(summary.retransmissions)))
    lines.append(_format_kv("Retransmission Rate", f"{summary.retransmission_rate:.2%}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("TTL / Hop Limit"))
    lines.append(_format_kv("Expired TTL/Hop Limit", str(summary.ttl_expired)))
    lines.append(_format_kv("Low TTL/Hop Limit (<=5)", str(summary.ttl_low)))

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
    return "\n".join(lines)


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
    return "\n".join(lines)

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
    return "\n".join(lines)


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
    return "\n".join(lines)

def render_modbus_summary(summary: "ModbusAnalysis") -> str:
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
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Modbus Packets", str(summary.modbus_packets)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Error Rate", f"{summary.error_rate:.2f}%"))
    
    # 2. Function Codes
    lines.append(SUBSECTION_BAR)
    lines.append(header("Function Code Usage"))
    if not summary.func_counts:
        lines.append(muted("No Modbus functions detected."))
    else:
        for func, count in summary.func_counts.most_common():
            # Highlight potentially dangerous functions
            is_write = "Write" in func
            c = danger if is_write else lambda x: x
            
            lines.append(c(f"{func:<40} : {count}"))
            
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
    lines.append(header("Modbus Endpoints"))
    
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
            c_str = f"{ip} ({cnt})"
        
        if i < len(servers):
            ip, cnt = servers[i]
            s_str = f"{ip} ({cnt})"
            
        lines.append(f"{c_str:<{col_width}} | {s_str}")

    # 5. Anomalies
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
    return "\n".join(lines)

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
    return "\n".join(lines)
