from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import ipaddress
import re
import textwrap
import hashlib
from typing import Iterable, Callable

from .models import PcapSummary
from .utils import format_bytes_as_mb, format_duration, format_speed_bps, format_ts, sparkline, hexdump, decode_payload
from .coloring import danger, header, label, muted, ok, warn, highlight, orange, danger_bg
from .vlan import VlanSummary, VlanStat
from .icmp import IcmpSummary
from .dns import DnsSummary, PUBLIC_DNS_RESOLVERS
from .beacon import BeaconSummary
from .threats import ThreatSummary
from .files import FileTransferSummary
from .protocols import ProtocolSummary
from .services import ServiceSummary, COMMON_PORTS
from .smb import SmbSummary
from .nfs import NfsSummary
from .strings import StringsSummary
from .creds import CredentialSummary
from .secrets import SecretsSummary
from .search import SearchSummary
from .certificates import CertificateSummary
from .tls import TlsSummary
from .ssh import SshSummary
from .syslog import SyslogSummary
from .snmp import SnmpSummary
from .smtp import SmtpSummary
from .rpc import RpcSummary
from .tcp import TcpSummary
from .udp import UdpSummary, UdpConversation
from .exfil import ExfilSummary
from .http import HttpSummary
from .ftp import FtpSummary
from .sizes import SizeSummary, render_size_sparkline
from .ips import IpSummary
from .timeline import TimelineSummary
from .health import HealthSummary
from .rdp import RdpSummary
from .telnet import TelnetSummary
from .vnc import VncSummary
from .teamviewer import TeamviewerSummary
from .winrm import WinrmSummary
from .wmic import WmicSummary
from .powershell import PowershellSummary
from .compromised import CompromiseSummary
from .hostname import HostnameSummary
from .hosts import HostSummary
from .hostdetails import HostDetailsSummary
from .arp import ArpSummary
from .dhcp import DhcpSummary
from .pcapmeta import PcapMetaSummary
from .quic import QuicSummary
from .http2 import Http2Summary
from .encrypted_dns import EncryptedDnsSummary
from .ntp import NtpSummary
from .vpn import VpnSummary
from .routing import RoutingSummary
from .goose import GooseSummary
from .sv import SvSummary
from .lldp_dcp import LldpDcpSummary
from .ptp import PtpSummary
from .opc_classic import OpcClassicSummary
from .streams import StreamSummary
from .ctf import CtfSummary
from .ioc import IocSummary
from .ot_commands import OtCommandSummary
from .iec101_103 import Iec101103Summary


SECTION_BAR = "=" * 72
SUBSECTION_BAR = "-" * 72

_REDACT_SECRETS = True
_VERBOSE_OUTPUT = False
_FULL_OUTPUT_LIMIT = 1_000_000


def set_redact_secrets(enabled: bool) -> None:
    global _REDACT_SECRETS
    _REDACT_SECRETS = enabled


def set_verbose_output(enabled: bool) -> None:
    global _VERBOSE_OUTPUT
    _VERBOSE_OUTPUT = enabled


def _apply_verbose_limit(limit: int | None) -> int | None:
    if _VERBOSE_OUTPUT:
        if limit is None:
            return None
        return _FULL_OUTPUT_LIMIT
    return limit


def _limit_value(value: int) -> int:
    return _FULL_OUTPUT_LIMIT if _VERBOSE_OUTPUT else value


def _secret_fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    return f"redacted:{digest[:_limit_value(8)]}"


def _redact_secret(value: str | None) -> str:
    if value is None:
        return "-"
    if not _REDACT_SECRETS:
        return value
    return _secret_fingerprint(value)


_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(pass(word)?|passwd|pwd|secret|token|apikey|api_key|api-key|bearer)\b\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\bPASS\s+(\S+)"),
]

_HTTP_STATUS_TEXT = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    208: "Already Reported",
    226: "IM Used",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a Teapot",
    421: "Misdirected Request",
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required",
}


def _redact_in_text(text: str) -> str:
    if not _REDACT_SECRETS or not text:
        return text

    def _repl(match: re.Match) -> str:
        if match.lastindex and match.lastindex >= 3:
            key = match.group(1)
            value = match.group(3)
            return f"{key}={_secret_fingerprint(value)}"
        value = match.group(match.lastindex or 1)
        return f"PASS {_secret_fingerprint(value)}"

    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(_repl, redacted)
    return redacted


def _http_status_text(value: object) -> str:
    try:
        code = int(str(value).strip())
    except Exception:
        return "-"
    return _HTTP_STATUS_TEXT.get(code, "-")


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


def _format_counter(counter: object, limit: int = 5, key_max: int = 40) -> str:
    if not counter:
        return "-"
    if hasattr(counter, "most_common"):
        items = list(counter.most_common(_limit_value(limit)))
    elif isinstance(counter, dict):
        items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:_limit_value(limit)]
    else:
        return "-"
    parts: list[str] = []
    for key, value in items:
        name = _truncate_text(str(key), key_max)
        try:
            count = int(value)
        except Exception:
            count = value
        parts.append(f"{name}({count})")
    return ", ".join(parts) if parts else "-"


def _format_table(rows: Iterable[list[str]]) -> str:
    rows = list(rows)
    if not rows:
        return "(none)"

    def _cell_text(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    rows = [[_cell_text(cell) for cell in row] for row in rows]

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

def _filtered_detections(summary, verbose: bool) -> list[dict[str, object]]:
    detections = list(getattr(summary, "detections", []) or [])
    if not detections:
        return []
    if not verbose:
        filtered = []
        for item in detections:
            severity = str(item.get("severity") or "info").lower()
            if severity in {"info", "informational"}:
                continue
            filtered.append(item)
        detections = filtered
    if not detections:
        return []
    ot_counts_raw = getattr(summary, "ot_protocol_counts", None)
    ot_counts = {str(k).upper(): int(v) for k, v in (ot_counts_raw or {}).items()} if ot_counts_raw else {}
    ot_aliases = {
        "DF1": ["DF1"],
        "PCCC": ["PCCC"],
        "MODBUS": ["MODBUS"],
        "DNP3": ["DNP3"],
        "IEC-104": ["IEC-104"],
        "BACNET": ["BACNET"],
        "ETHERNET/IP": ["ETHERNET/IP"],
        "CIP": ["CIP"],
        "PROFINET": ["PROFINET"],
        "S7": ["S7"],
        "OPC UA": ["OPC UA"],
        "OPC CLASSIC": ["OPC CLASSIC"],
        "ETHERCAT": ["ETHERCAT"],
        "FINS": ["FINS"],
        "CRIMSON": ["CRIMSON"],
        "PCWORX": ["PCWORX"],
        "MELSEC": ["MELSEC"],
        "ODESYS": ["ODESYS"],
        "NIAGARA": ["NIAGARA"],
        "MMS": ["MMS"],
        "SRTP": ["SRTP"],
        "CSP": ["CSP"],
        "MODICON": ["MODICON"],
        "YOKOGAWA": ["YOKOGAWA"],
        "HONEYWELL": ["HONEYWELL"],
        "MQTT": ["MQTT"],
        "COAP": ["COAP"],
        "HART-IP": ["HART-IP", "HART"],
        "PROCONOS": ["PROCONOS"],
        "ICCP": ["ICCP"],
        "GOOSE": ["GOOSE"],
        "SV": ["SV"],
        "PTP": ["PTP"],
        "LLDP/DCP": ["LLDP", "DCP"],
        "LLDP": ["LLDP"],
        "DCP": ["DCP"],
    }

    def _ot_present(label: str) -> bool:
        for token in ot_aliases.get(label, [label]):
            if ot_counts.get(token.upper(), 0) > 0:
                return True
        return False

    def _detect_ot_label(item: dict[str, object]) -> str | None:
        source = str(item.get("source", ""))
        summary_text = str(item.get("summary", ""))
        details_text = str(item.get("details", ""))
        blob = f"{source} {summary_text} {details_text}".upper()
        for label in ot_aliases.keys():
            if label in blob:
                return label
        return None

    proto_counts = getattr(summary, "protocol_counts", None)
    if proto_counts:
        proto_set = {str(key).upper() for key in proto_counts.keys()}
        filtered = []
        for item in detections:
            proto = item.get("protocol") or item.get("proto")
            if proto:
                if str(proto).upper() not in proto_set:
                    continue
            if ot_counts:
                ot_label = _detect_ot_label(item)
                if ot_label and not _ot_present(ot_label):
                    continue
            filtered.append(item)
        detections = filtered
    elif ot_counts:
        filtered = []
        for item in detections:
            ot_label = _detect_ot_label(item)
            if ot_label and not _ot_present(ot_label):
                continue
            filtered.append(item)
        detections = filtered
    return detections



def _highlight_search_text(text: str, query: str) -> str:
    if not text or not query:
        return text
    try:
        pattern = re.compile(re.escape(query), re.IGNORECASE)
    except re.error:
        return text
    return pattern.sub(lambda match: ok(match.group(0)), text)


def _format_client_server_table(
    client_counts: Counter[str],
    server_counts: Counter[str],
    limit: int = 8,
) -> str:
    rows = [["Clients", "Servers"]]
    client_items = [
        f"{ip}({count})" for ip, count in client_counts.most_common(_limit_value(limit))
    ]
    server_items = [
        f"{ip}({count})" for ip, count in server_counts.most_common(_limit_value(limit))
    ]
    max_len = max(len(client_items), len(server_items))
    if max_len == 0:
        rows.append(["-", "-"])
    else:
        for idx in range(max_len):
            rows.append([
                client_items[idx] if idx < len(client_items) else "-",
                server_items[idx] if idx < len(server_items) else "-",
            ])
    return _format_table(rows)


def _conv_value(conv: object, name: str, default: object | None = None) -> object | None:
    if isinstance(conv, dict):
        return conv.get(name, default)
    return getattr(conv, name, default)


def _format_sessions_table(
    conversations: list[object],
    limit: int,
    *,
    packet_label: str = "Packets",
    packet_value_fn: Callable[[object], object] | None = None,
    extra_cols: list[tuple[str, Callable[[object], object]]] | None = None,
) -> str:
    extra_cols = extra_cols or []
    rows = [["Client", "Server", "Start", "End", "Duration", packet_label, "Size"] + [label for label, _fn in extra_cols]]

    def _to_float(value: object | None) -> float | None:
        if value is None:
            return None
        try:
            return float(value)
        except Exception:
            return None

    def _session_sort_key(conv: object) -> tuple[float, float]:
        bytes_val = _conv_value(conv, "bytes", 0) or 0
        packets_val = _conv_value(conv, "packets", 0) or 0
        try:
            return (float(bytes_val), float(packets_val))
        except Exception:
            return (0.0, 0.0)

    top_sessions = sorted(conversations, key=_session_sort_key, reverse=True)[:limit]
    for conv in top_sessions:
        client_ip = (
            _conv_value(conv, "client_ip")
            or _conv_value(conv, "src_ip")
            or _conv_value(conv, "src")
            or "-"
        )
        server_ip = (
            _conv_value(conv, "server_ip")
            or _conv_value(conv, "dst_ip")
            or _conv_value(conv, "dst")
            or "-"
        )
        client_port = _conv_value(conv, "client_port") or _conv_value(conv, "src_port")
        server_port = _conv_value(conv, "server_port") or _conv_value(conv, "dst_port")
        client = f"{client_ip}:{client_port}" if client_port is not None else str(client_ip)
        server = f"{server_ip}:{server_port}" if server_port is not None else str(server_ip)

        first_seen = _conv_value(conv, "first_seen")
        last_seen = _conv_value(conv, "last_seen")
        first_val = _to_float(first_seen)
        last_val = _to_float(last_seen)
        duration = None
        if first_val is not None and last_val is not None:
            duration = max(0.0, last_val - first_val)

        if packet_value_fn is not None:
            packet_val = packet_value_fn(conv)
        else:
            packet_val = _conv_value(conv, "packets")
            if packet_val is None:
                requests = _conv_value(conv, "requests")
                responses = _conv_value(conv, "responses")
                if requests is not None or responses is not None:
                    packet_val = int(requests or 0) + int(responses or 0)
        packet_text = str(packet_val) if packet_val is not None else "-"

        bytes_val = _conv_value(conv, "bytes")
        size_text = format_bytes_as_mb(int(bytes_val)) if isinstance(bytes_val, (int, float)) else "-"

        row = [
            client,
            server,
            format_ts(first_seen if isinstance(first_seen, (int, float)) else first_val),
            format_ts(last_seen if isinstance(last_seen, (int, float)) else last_val),
            format_duration(duration),
            packet_text,
            size_text,
        ]
        for _label, extractor in extra_cols:
            try:
                value = extractor(conv)
            except Exception:
                value = "-"
            row.append(str(value))
        rows.append(row)

    return _format_table(rows)


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
    if lines and not _VERBOSE_OUTPUT:
        lines.append(muted("Output is summarized/truncated. Use -v to view all output."))
    return _highlight_public_ips("\n".join(lines))


def _truncate_text(value: str, max_len: int = 80) -> str:
    if _VERBOSE_OUTPUT:
        return value
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
        clients = client_counter.most_common(_limit_value(10)) if client_counter else []
        servers = server_counter.most_common(_limit_value(10)) if server_counter else []
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
        for name, counter in ordered_counters[:_limit_value(4)]:
            lines.append(label(name.replace("_", " ").title()))
            rows = [["Item", "Count"]]
            for item, count in counter.most_common(_limit_value(10)):
                rows.append([str(item), str(count)])
            lines.append(_format_table(rows))

    if service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints"))
        rows = [["Service", "Top Endpoints"]]
        for service, counter in Counter({
            svc: sum(cnt.values()) for svc, cnt in service_endpoints.items()
        }).most_common(_limit_value(10)):
            endpoints = service_endpoints.get(service, Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3)))
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
        for detail, count in artifact_counts.most_common(_limit_value(12)):
            rows.append([detail, str(count)])
        lines.append(_format_table(rows))

    if anomaly_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        rows = [["Title", "Count"]]
        for title, count in anomaly_counts.most_common(_limit_value(12)):
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
    protocol_limit = _apply_verbose_limit(protocol_limit)
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
    limit = _apply_verbose_limit(limit)
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

    if getattr(summary, "analysis_notes", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes:
            lines.append(muted(f"- {note}"))

    if summary.vlan_stats:
        lines.append(SUBSECTION_BAR)
        lines.append(header("VLAN Inventory"))
        rows = [["VLAN", "Packets", "Bytes", "IPs", "Top Protocols", "First Seen", "Last Seen"]]
        for vlan in summary.vlan_stats[:limit]:
            ip_count = len(vlan.src_ips.union(vlan.dst_ips))
            proto_preview = ", ".join(name for name, _count in vlan.protocols.most_common(_limit_value(4))) or "-"
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
            preview = ip_list[:_limit_value(10)]
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
                    f"{name}({count})" for name, count in vlan.protocols.most_common(_limit_value(10))
                )
                lines.append(f"  IPs: {', '.join(ip_list) if ip_list else '-'}")
                lines.append(f"  MACs: {', '.join(mac_list) if mac_list else '-'}")
                lines.append(f"  Protocols: {proto_list if proto_list else '-'}")
    else:
        lines.append(muted("No VLAN-tagged traffic detected."))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
    limit = _apply_verbose_limit(limit)
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

def render_domain_summary(summary: "DomainAnalysis", limit: int = 25, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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
        server_text = ", ".join(f"{ip}({count})" for ip, count in summary.servers.most_common(_limit_value(10))) or "-"
        client_text = ", ".join(f"{ip}({count})" for ip, count in summary.clients.most_common(_limit_value(10))) or "-"
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
            rows.append([_redact_in_text(str(cred)), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
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


def render_ldap_summary(summary: "LdapAnalysis", limit: int = 25, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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
        server_text = ", ".join(f"{ip}({count})" for ip, count in summary.servers.most_common(_limit_value(10))) or "-"
        client_text = ", ".join(f"{ip}({count})" for ip, count in summary.clients.most_common(_limit_value(10))) or "-"
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
            rows.append([_redact_secret(str(secret)), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
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


def render_kerberos_summary(summary: "KerberosAnalysis", limit: int = 25, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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

    lines.append(_format_kv("Start", format_ts(getattr(summary, "first_seen", None))))
    lines.append(_format_kv("End", format_ts(getattr(summary, "last_seen", None))))
    lines.append(_format_kv("Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("TCP Packets", str(getattr(summary, "tcp_packets", 0))))
    lines.append(_format_kv("UDP Packets", str(getattr(summary, "udp_packets", 0))))
    if summary.session_stats:
        lines.append(_format_kv("Kerberos Sessions", str(summary.session_stats.get("total_sessions", 0))))
        lines.append(_format_kv("Unique Clients", str(summary.session_stats.get("unique_clients", 0))))
        lines.append(_format_kv("Unique Servers", str(summary.session_stats.get("unique_servers", 0))))

    if summary.servers or summary.clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Kerberos Servers & Clients"))
        rows = [["Servers", "Clients"]]
        server_text = ", ".join(f"{ip}({count})" for ip, count in summary.servers.most_common(_limit_value(10))) or "-"
        client_text = ", ".join(f"{ip}({count})" for ip, count in summary.clients.most_common(_limit_value(10))) or "-"
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
        lines.append(header("Kerberos Commands / Requests"))
        rows = [["Command", "Count"]]
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

    discovered_users = Counter()
    for principal, count in summary.principals.items():
        local = str(principal).split("@", 1)[0]
        if "/" in local:
            continue
        if not local:
            continue
        discovered_users[local] += int(count)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Usernames"))
    if discovered_users:
        rows = [["Username", "Count"]]
        for name, count in discovered_users.most_common(limit):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No Kerberos usernames discovered."))

    discovered_hosts = Counter()
    for spn, count in summary.spns.items():
        spn_name = str(spn).split("@", 1)[0]
        if "/" not in spn_name:
            continue
        _, host = spn_name.split("/", 1)
        if not host:
            continue
        discovered_hosts[host] += int(count)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Hostnames"))
    if discovered_hosts:
        rows = [["Hostname", "Count"]]
        for name, count in discovered_hosts.most_common(limit):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No Kerberos hostnames discovered."))

    if getattr(summary, "principal_evidence", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Principal Evidence (Per Flow)"))
        rows = [["Src", "Dst", "Port", "Proto", "Principal", "Kind"]]
        for item in summary.principal_evidence[:limit]:
            rows.append([
                str(item.get("src_ip", "-")),
                str(item.get("dst_ip", "-")),
                str(item.get("dst_port", "-")),
                str(item.get("protocol", "-")),
                _truncate_text(str(item.get("principal", "-")), 60),
                str(item.get("kind", "-")),
            ])
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
        rows = [["Artifact"]]
        for item in summary.artifacts[:limit]:
            rows.append([_truncate_text(str(item), 100)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            lines.append(warn(f"- {item}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
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
    limit = _apply_verbose_limit(limit)
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
        for convo in sorted(summary.conversations, key=lambda c: c.get("packets", 0), reverse=True)[:_limit_value(12)]:
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
        for sess in summary.sessions[:_limit_value(12)]:
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
            top_sources = ", ".join(f"{ip}({count})" for ip, count in summary.src_ip_counts.most_common(_limit_value(10)))
            lines.append(f"Top Sources: {top_sources}")
        if summary.dst_ip_counts:
            top_dests = ", ".join(f"{ip}({count})" for ip, count in summary.dst_ip_counts.most_common(_limit_value(10)))
            lines.append(f"Top Destinations: {top_dests}")

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
        lines.append(muted(", ".join(summary.artifacts[:_limit_value(30)])))

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for name, count in summary.observed_users.most_common(_limit_value(10)):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        lines.append(muted(", ".join(summary.files_discovered[:_limit_value(20)])))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_dns_summary(summary: DnsSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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

    def _dns_opcode_name(opcode_id: int) -> str:
        return {
            0: "QUERY",
            1: "IQUERY",
            2: "STATUS",
            4: "NOTIFY",
            5: "UPDATE",
        }.get(opcode_id, "OPCODE")

    def _dns_base_domain(name: str) -> str:
        parts = [part for part in name.strip(".").split(".") if part]
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return name.strip(".")

    def _vt_info(name: str) -> tuple[str, str]:
        if not summary.vt_results:
            return "-", "-"
        info = summary.vt_results.get(name)
        if info is None:
            info = summary.vt_results.get(_dns_base_domain(name))
        if not info:
            return "-", "-"
        return str(info.get("score", "-")), str(info.get("rating", "-"))
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
    if summary.edns0_opt_count:
        lines.append(_format_kv("EDNS0 OPT Records", str(summary.edns0_opt_count)))
    if summary.mdns_packets:
        lines.append(_format_kv("mDNS Packets", str(summary.mdns_packets)))
        lines.append(_format_kv("mDNS Queries", str(summary.mdns_query_packets)))
        lines.append(_format_kv("mDNS Responses", str(summary.mdns_response_packets)))
        lines.append(_format_kv("mDNS Clients", str(summary.unique_mdns_clients)))
        lines.append(_format_kv("mDNS Servers", str(summary.unique_mdns_servers)))
        lines.append(_format_kv("mDNS Error Responses", str(summary.mdns_error_responses)))
    if summary.llmnr_packets:
        lines.append(_format_kv("LLMNR Packets", str(summary.llmnr_packets)))
        lines.append(_format_kv("LLMNR Queries", str(summary.llmnr_query_packets)))
        lines.append(_format_kv("LLMNR Responses", str(summary.llmnr_response_packets)))

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

    if summary.opcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Opcodes"))
        rows = [["Opcode", "Count"]]
        for opcode, count in summary.opcode_counts.most_common(limit):
            label = f"{_dns_opcode_name(int(opcode))} ({opcode})"
            rows.append([label, str(count)])
        lines.append(_format_table(rows))

    if summary.flag_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Flags"))
        rows = [["Flag", "Count"]]
        for flag, count in summary.flag_counts.most_common(limit):
            rows.append([flag, str(count)])
        lines.append(_format_table(rows))

    if summary.query_size_stats or summary.response_size_stats:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Payload Sizes"))
        rows = [["Metric", "Query", "Response"]]
        metrics = ["count", "min", "max", "avg", "median", "p95"]
        for metric in metrics:
            qval = summary.query_size_stats.get(metric, "-") if summary.query_size_stats else "-"
            rval = summary.response_size_stats.get(metric, "-") if summary.response_size_stats else "-"
            if metric == "avg":
                qval = f"{float(qval):.1f}" if isinstance(qval, (int, float)) else qval
                rval = f"{float(rval):.1f}" if isinstance(rval, (int, float)) else rval
            rows.append([metric, str(qval), str(rval)])
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

    if summary.public_resolver_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Public DNS Resolvers"))
        rows = [["Resolver", "Count", "Provider"]]
        for ip_value, count in summary.public_resolver_counts.most_common(limit):
            rows.append([ip_value, str(count), PUBLIC_DNS_RESOLVERS.get(ip_value, "-")])
        lines.append(_format_table(rows))

    if summary.base_domain_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Base Domains"))
        if summary.vt_results:
            rows = [["Base Domain", "Count", "VT Score", "VT Rating"]]
            for name, count in summary.base_domain_counts.most_common(limit):
                score, rating = _vt_info(name)
                rows.append([name, str(count), score, rating])
        else:
            rows = [["Base Domain", "Count"]]
            for name, count in summary.base_domain_counts.most_common(limit):
                rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Queried Names"))
        if summary.vt_results:
            rows = [["QName", "Count", "VT Score", "VT Rating"]]
            for name, count in summary.qname_counts.most_common(limit):
                score, rating = _vt_info(name)
                rows.append([name, str(count), score, rating])
        else:
            rows = [["QName", "Count"]]
            for name, count in summary.qname_counts.most_common(limit):
                rows.append([name, str(count)])
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Bottom Queried Names"))
        rows = [["QName", "Count"]]
        bottom_names = sorted(summary.qname_counts.items(), key=lambda item: (item[1], item[0]))[:_limit_value(15)]
        for name, count in bottom_names:
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.tld_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TLDs"))
        rows = [["TLD", "Count"]]
        for name, count in summary.tld_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.answers_by_qname:
        candidates = [(name, answers) for name, answers in summary.answers_by_qname.items() if len(answers) > 1]
        if candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Answer Variability (QName)"))
            rows = [["QName", "Unique Answers", "Sample"]]
            for name, answers in sorted(candidates, key=lambda item: len(item[1]), reverse=True)[:limit]:
                sample = ", ".join(sorted(list(answers))[:_limit_value(3)])
                if len(answers) > _limit_value(3):
                    sample += "..."
                rows.append([name, str(len(answers)), sample or "-"])
            lines.append(_format_table(rows))

    if summary.base_domain_answers:
        candidates = [(name, answers) for name, answers in summary.base_domain_answers.items() if len(answers) > 1]
        if candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Answer Variability (Base Domain)"))
            rows = [["Domain", "Unique Answers", "Sample"]]
            for name, answers in sorted(candidates, key=lambda item: len(item[1]), reverse=True)[:limit]:
                sample = ", ".join(sorted(list(answers))[:_limit_value(3)])
                if len(answers) > _limit_value(3):
                    sample += "..."
                rows.append([name, str(len(answers)), sample or "-"])
            lines.append(_format_table(rows))

    if summary.local_unicast_qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Unicast Local TLD Queries"))
        rows = [["QName", "Count"]]
        for name, count in summary.local_unicast_qname_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.ot_keyword_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Keywords"))
        rows = [["Keyword", "Count"]]
        for name, count in summary.ot_keyword_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.ot_qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Hostname Indicators"))
        rows = [["QName", "Count"]]
        for name, count in summary.ot_qname_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.zone_transfer_requests:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Transfer Requests"))
        samples = ", ".join(sorted(summary.zone_transfer_requests)[:_limit_value(20)])
        lines.append(muted(samples or "-"))

    if summary.txt_query_names:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TXT Query Names"))
        samples = ", ".join(sorted(summary.txt_query_names)[:_limit_value(20)])
        lines.append(muted(samples or "-"))

    if summary.vt_results:
        vt_hits = [
            item for item in summary.vt_results.values()
            if int(item.get("score", 0) or 0) > 0
        ]
        lines.append(SUBSECTION_BAR)
        lines.append(header("VirusTotal Reputation"))
        if vt_hits:
            rows = [["Domain", "Score", "Rating", "Reputation", "Last Analysis"]]
            for item in sorted(
                vt_hits,
                key=lambda entry: int(entry.get("score", 0) or 0),
                reverse=True,
            )[:limit]:
                last_seen = format_ts(item.get("last_analysis_date")) if item.get("last_analysis_date") else "-"
                rows.append([
                    str(item.get("domain", "-")),
                    str(item.get("score", "-")),
                    str(item.get("rating", "-")),
                    str(item.get("reputation", "-")),
                    last_seen,
                ])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No malicious/suspicious VirusTotal hits in sampled domains."))

    if summary.llmnr_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LLMNR Clients"))
        rows = [["Client", "Queries"]]
        for name, count in summary.llmnr_client_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("LLMNR Servers"))
        rows = [["Server", "Responses"]]
        for name, count in summary.llmnr_server_counts.most_common(limit):
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
        total_packets = summary.total_packets or sum(
            int(item.get("count", 0) or 0) for item in summary.packet_length_stats
        )

        def _bucket_range(label: str) -> tuple[int, int | None]:
            if label.endswith("+"):
                try:
                    return int(label[:-1]), None
                except Exception:
                    return 0, None
            if "-" in label:
                low_text, high_text = label.split("-", 1)
                try:
                    return int(low_text), int(high_text)
                except Exception:
                    return 0, 0
            return 0, 0

        short_total = 0
        long_total = 0
        dominant_bucket = None
        dominant_pct = 0.0
        outlier_rows: list[list[str]] = []
        count_threshold = max(50, int(total_packets * 0.25)) if total_packets else 50

        for item in summary.packet_length_stats:
            label = str(item.get("bucket", "-"))
            count = int(item.get("count", 0) or 0)
            pct = (count / total_packets * 100) if total_packets else 0.0
            low, high = _bucket_range(label)
            is_short = (high is not None and high <= 100)
            is_long = (low >= 1201)
            notes: list[str] = []
            if is_short:
                short_total += count
                notes.append("very short")
            if is_long:
                long_total += count
                notes.append("very long")
            if pct >= 40.0:
                notes.append("dominant")
            elif count >= count_threshold:
                notes.append("high count")
            if pct > dominant_pct:
                dominant_pct = pct
                dominant_bucket = label
            if notes:
                outlier_rows.append([
                    label,
                    str(count),
                    f"{pct:.1f}%",
                    ", ".join(notes),
                    f"{item.get('burst_rate', 0):.0f}",
                    format_ts(item.get("burst_start")) if item.get("burst_start") else "-",
                ])

        if total_packets:
            short_pct = (short_total / total_packets * 100) if total_packets else 0.0
            long_pct = (long_total / total_packets * 100) if total_packets else 0.0
            lines.append(_format_kv("Very Short DNS Packets (<=100B)", f"{short_total} ({short_pct:.1f}%)"))
            lines.append(_format_kv("Very Large DNS Packets (>=1201B)", f"{long_total} ({long_pct:.1f}%)"))
            if dominant_bucket:
                lines.append(_format_kv("Dominant Size Bucket", f"{dominant_bucket} ({dominant_pct:.1f}%)"))

        if outlier_rows:
            lines.append("")
            lines.append(muted("Outlier Buckets"))
            rows = [["Size Bucket", "Count", "%", "Note", "Burst Rate", "Burst Start"]]
            rows.extend(outlier_rows)
            lines.append(_format_table(rows))

        lines.append("")
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
        lines.append("")
        lines.append(muted(f"Distribution Sparkline: {sparkline([int(item.get('count', 0) or 0) for item in summary.packet_length_stats])}"))

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
        qnames = ", ".join(name for name, _count in summary.qname_counts.most_common(_limit_value(25)))
        lines.append(f"Observed QNames: {qnames}")

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
                lines.append(muted(f"  Details: {details}"))
            top_clients = item.get("top_clients")
            if top_clients:
                client_text = ", ".join(f"{ip}({count})" for ip, count in top_clients)
                lines.append(muted(f"  Clients: {client_text}"))
            top_servers = item.get("top_servers")
            if top_servers:
                server_text = ", ".join(f"{ip}({count})" for ip, count in top_servers)
                lines.append(muted(f"  Servers: {server_text}"))

            artifacts = item.get("artifacts")
            if isinstance(artifacts, list) and artifacts:
                lines.append(muted("  Artifacts:"))
                for art in artifacts[:_limit_value(8)]:
                    lines.append(muted(f"    {str(art)}"))
                if len(artifacts) > _limit_value(8):
                    lines.append(muted(f"    ... {len(artifacts) - _limit_value(8)} more"))

            evidence = item.get("evidence")
            if isinstance(evidence, list) and evidence:
                lines.append(muted("  Evidence:"))
                for ev in evidence[:_limit_value(8)]:
                    lines.append(muted(f"    {str(ev)}"))
                if len(evidence) > _limit_value(8):
                    lines.append(muted(f"    ... {len(evidence) - _limit_value(8)} more"))

            vt_findings = item.get("vt_findings")
            if isinstance(vt_findings, list) and vt_findings:
                lines.append(muted("  VirusTotal (target | benign | suspicious | malicious | report):"))
                for entry in vt_findings[:_limit_value(12)]:
                    target = str(entry.get("domain") or entry.get("target", "-"))
                    benign = int(entry.get("harmless", 0) or 0)
                    suspicious = int(entry.get("suspicious", 0) or 0)
                    malicious = int(entry.get("malicious", 0) or 0)
                    report = str(entry.get("report_url", "-"))
                    vt_line = f"{target} | {benign} | {suspicious} | {malicious} | {report}"
                    if malicious > 0:
                        lines.append(danger(f"    {vt_line}"))
                    elif suspicious > 0:
                        lines.append(warn(f"    {vt_line}"))
                    else:
                        lines.append(ok(f"    {vt_line}"))
                if len(vt_findings) > _limit_value(12):
                    lines.append(muted(f"    ... {len(vt_findings) - _limit_value(12)} more"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_ips_summary(summary: IpSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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

    if summary.ip_mac_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IP to MAC Mapping"))
        rows = [["IP", "MACs (count)", "Observations", "Unique MACs"]]
        sorted_macs = sorted(
            summary.ip_mac_counts.items(),
            key=lambda item: sum(item[1].values()),
            reverse=True,
        )
        for ip_value, mac_counts in sorted_macs[:limit]:
            macs = ", ".join(
                f"{mac}({count})" for mac, count in mac_counts.most_common(_limit_value(3))
            )
            if len(mac_counts) > 3:
                macs += "..."
            rows.append([
                ip_value,
                macs or "-",
                str(sum(mac_counts.values())),
                str(len(mac_counts)),
            ])
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
        ports_str = ",".join(str(p) for p in ep.ports[:_limit_value(6)])
        if len(ep.ports) > 6:
            ports_str += "..."
        proto_str = ",".join(ep.protocols[:_limit_value(4)])
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
        ports_str = ",".join(str(p) for p in conv.ports[:_limit_value(6)])
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
                for risk in risks[:_limit_value(5)]:
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        for item in detections:
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
    limit = _apply_verbose_limit(limit)
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
        rows = [["Status", "Description", "Count"]]
        for code, count in summary.status_counts.most_common(limit):
            rows.append([str(code), _http_status_text(code), str(count)])
        lines.append(_format_table(rows))

    if summary.host_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hosts"))
        rows = [["Host", "IPs", "Requests", "Note"]]
        host_ip_map = getattr(summary, "host_ip_counts", {}) or {}
        for host, count in summary.host_counts.most_common(limit):
            host_key = host.lower().split(":", 1)[0]
            ip_counter = host_ip_map.get(host) or host_ip_map.get(host_key, Counter())
            ip_text = "-"
            note = "-"
            if ip_counter:
                ip_text = ", ".join(
                    f"{ip}({cnt})" for ip, cnt in ip_counter.most_common(_limit_value(3))
                )
                if len(ip_counter) > 3:
                    ip_text += "..."
                if len(ip_counter) > 1:
                    note = "multiple IPs"
            rows.append([host, ip_text, str(count), note])
        lines.append(_format_table(rows))

    if summary.client_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients"))
        rows = [["Client", "Hostname", "Requests"]]
        client_host_map = getattr(summary, "client_host_counts", {}) or {}
        for client, count in summary.client_counts.most_common(limit):
            host_counter = client_host_map.get(client, Counter())
            host_text = "-"
            if host_counter:
                top_host, _hcount = host_counter.most_common(1)[0]
                extra = len(host_counter) - 1
                host_text = f"{top_host} (+{extra} more)" if extra > 0 else top_host
            rows.append([client, host_text, str(count)])
        lines.append(_format_table(rows))

    if summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Servers"))
        rows = [["Server", "Hostname", "Responses"]]
        server_host_map = getattr(summary, "server_host_counts", {}) or {}
        for server, count in summary.server_counts.most_common(limit):
            host_counter = server_host_map.get(server, Counter())
            host_text = "-"
            if host_counter:
                top_host, _hcount = host_counter.most_common(1)[0]
                extra = len(host_counter) - 1
                host_text = f"{top_host} (+{extra} more)" if extra > 0 else top_host
            rows.append([server, host_text, str(count)])
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
                "Top Referrer Hosts",
                "Host",
                summary.referrer_host_counts.most_common(limit),
            )

        show_paths = bool(summary.referrer_path_counts) and (
            verbose
            or not summary.referrer_counts
            or len(summary.referrer_path_counts) != len(summary.referrer_counts)
        )
        if show_paths:
            _append_referrer_table(
                "Top Referrer Paths",
                "Path",
                summary.referrer_path_counts.most_common(limit),
                truncate=True,
            )

        if summary.referrer_counts:
            raw_referrers = summary.referrer_counts.most_common(limit)
            normalized_referrers = _normalize_referrer_items(raw_referrers, True)
            if normalized_referrers:
                lines.append(label("Top Referrer URLs"))
                count_width = max(1, max(len(str(count)) for _, count in normalized_referrers))
                rows = [[label("URL"), label("Host"), label("Count")]]
                host_map = getattr(summary, "referrer_request_host_counts", {}) or {}
                display_host_map: dict[str, Counter[str]] = defaultdict(Counter)
                for ref_value, _ in raw_referrers:
                    display_value = ref_value if verbose else _truncate_text(ref_value, max_len=96)
                    host_counter = host_map.get(ref_value)
                    if not host_counter:
                        continue
                    for host, host_count in host_counter.items():
                        display_host_map[display_value][host] += int(host_count)
                for value, count in normalized_referrers:
                    host_counter = display_host_map.get(value)
                    if host_counter:
                        top_hosts = host_counter.most_common(_limit_value(2))
                        host_display = ", ".join(
                            f"{host} ({host_count})" for host, host_count in top_hosts
                        )
                    else:
                        host_display = "-"
                    rows.append([value, host_display, str(count).rjust(count_width)])
                lines.append(_format_table(rows))

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

    if getattr(summary, "device_fingerprints", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        rows = [["Fingerprint", "Count"]]
        for fp, count in summary.device_fingerprints.most_common(limit):
            rows.append([_truncate_text(fp, 90), str(count)])
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
        rows = [["File", "Detected", "Expected", "Bytes", "Status", "Packet", "Src", "Dst"]]
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
                str(item.get("packet", "-")),
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
        lines.append(header("HTTP Sessions"))

        def _http_requests(conv: object) -> object:
            return _conv_value(conv, "requests") or 0

        def _http_responses(conv: object) -> object:
            return _conv_value(conv, "responses") or 0

        def _http_methods(conv: object) -> object:
            methods = _conv_value(conv, "methods")
            if hasattr(methods, "most_common"):
                return ",".join(f"{m}({c})" for m, c in methods.most_common(_limit_value(3))) or "-"
            return "-"

        def _http_statuses(conv: object) -> object:
            statuses = _conv_value(conv, "statuses")
            if hasattr(statuses, "most_common"):
                return ",".join(f"{s}({c})" for s, c in statuses.most_common(_limit_value(3))) or "-"
            return "-"

        lines.append(
            _format_sessions_table(
                summary.conversations,
                limit,
                packet_label="Requests",
                packet_value_fn=_http_requests,
                extra_cols=[
                    ("Responses", _http_responses),
                    ("Methods", _http_methods),
                    ("Statuses", _http_statuses),
                ],
            )
        )

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        evidence_limit = _limit_value(6)
        artifact_limit = _limit_value(8)
        vt_limit = _limit_value(12)

        def _format_ip_counts(value: object) -> str:
            if isinstance(value, Counter):
                counter = value
            elif isinstance(value, dict):
                counter = Counter({str(k): int(v) for k, v in value.items() if v is not None})
            elif isinstance(value, list):
                counter = Counter(str(v) for v in value if v is not None)
            else:
                return "-"
            items = counter.most_common(_limit_value(6))
            if not items:
                return "-"
            return ", ".join(f"{ip}({count})" for ip, count in items)

        def _format_evidence_item(item: dict[str, object]) -> str:
            parts: list[str] = []
            pkt = item.get("packet")
            if isinstance(pkt, int) or (isinstance(pkt, str) and pkt not in ("", "-")):
                parts.append(f"pkt {pkt}")
            src = item.get("src") or item.get("client") or item.get("ip")
            dst = item.get("dst") or item.get("server")
            if src or dst:
                parts.append(f"{src or '-'} -> {dst or '-'}")
            method = item.get("method")
            if method:
                parts.append(f"method {method}")
            status = item.get("status")
            if status:
                parts.append(f"status {status}")
            host = item.get("host")
            if host:
                parts.append(f"host {host}")
            uri = item.get("uri") or item.get("url")
            if uri:
                safe_uri = _redact_in_text(str(uri))
                parts.append(f"uri {_truncate_text(safe_uri, 80)}")
            ua = item.get("user_agent")
            if ua:
                safe_ua = _redact_in_text(str(ua))
                parts.append(f"ua {_truncate_text(safe_ua, 80)}")
            ref = item.get("referrer")
            if ref:
                safe_ref = _redact_in_text(str(ref))
                parts.append(f"referrer {_truncate_text(safe_ref, 80)}")
            token_fp = item.get("token_fp")
            if token_fp:
                parts.append(f"token {token_fp}")
            filename = item.get("filename")
            if filename:
                parts.append(f"file {filename}")
            detected_type = item.get("detected_type")
            expected_type = item.get("expected_type")
            if detected_type or expected_type:
                parts.append(f"type {detected_type or '-'} -> {expected_type or '-'}")
            byte_count = item.get("bytes")
            if byte_count not in (None, ""):
                parts.append(f"bytes {byte_count}")
            length = item.get("length")
            if length not in (None, ""):
                parts.append(f"len {length}")
            content_type = item.get("content_type")
            if content_type:
                parts.append(f"ctype {content_type}")
            server = item.get("server")
            if server:
                parts.append(f"server {server}")
            ref_host = item.get("referrer_host")
            if ref_host:
                parts.append(f"ref_host {ref_host}")
            return " | ".join(str(part) for part in parts if part)

        def _append_detail(label_text: str, value: str) -> None:
            if value:
                lines.append(muted(f"  {label_text}: {value}"))

        for item in detections:
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
                _append_detail("Details", details)

            ip_counts = item.get("ip_counts") or item.get("ips")
            if ip_counts:
                _append_detail("IPs", _format_ip_counts(ip_counts))

            packets = item.get("packets")
            if isinstance(packets, list):
                pkt_values = [str(p) for p in packets if p not in (None, "")]
                if pkt_values:
                    display = ", ".join(pkt_values[:_limit_value(12)])
                    if len(pkt_values) > _limit_value(12):
                        display += "..."
                    _append_detail("Packets", display)

            artifacts = item.get("artifacts")
            if isinstance(artifacts, list) and artifacts:
                shown = artifacts[:artifact_limit]
                lines.append(muted("  Artifacts:"))
                for val in shown:
                    display = _truncate_text(_redact_in_text(str(val)), 96)
                    lines.append(muted(f"    {display}"))
                if len(artifacts) > len(shown):
                    lines.append(muted(f"    ... {len(artifacts) - len(shown)} more"))

            vt_findings = item.get("vt_findings")
            if isinstance(vt_findings, list) and vt_findings:
                lines.append(muted("  VirusTotal (target | benign | suspicious | malicious | report):"))
                for entry in vt_findings[:vt_limit]:
                    target = str(entry.get("target", "-"))
                    benign = int(entry.get("harmless", 0) or 0)
                    suspicious = int(entry.get("suspicious", 0) or 0)
                    malicious = int(entry.get("malicious", 0) or 0)
                    report = str(entry.get("report_url", "-"))
                    vt_line = f"{target} | {benign} | {suspicious} | {malicious} | {report}"
                    if malicious > 0:
                        lines.append(danger(f"    {vt_line}"))
                    elif suspicious > 0:
                        lines.append(warn(f"    {vt_line}"))
                    else:
                        lines.append(ok(f"    {vt_line}"))
                if len(vt_findings) > vt_limit:
                    lines.append(muted(f"    ... {len(vt_findings) - vt_limit} more"))

            evidence = item.get("evidence")
            if isinstance(evidence, list) and evidence:
                lines.append(muted("  Evidence:"))
                shown = 0
                for ev in evidence:
                    if shown >= evidence_limit:
                        break
                    if isinstance(ev, dict):
                        ev_text = _format_evidence_item(ev)
                    else:
                        ev_text = str(ev)
                    if ev_text:
                        lines.append(muted(f"    {ev_text}"))
                        shown += 1
                if len(evidence) > shown:
                    lines.append(muted(f"    ... {len(evidence) - shown} more"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_ftp_summary(summary: FtpSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"FTP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("FTP Packets", str(summary.ftp_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("FTP Bytes", format_bytes_as_mb(summary.ftp_bytes)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.command_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Commands"))
        rows = [["Command", "Count"]]
        for cmd, count in summary.command_counts.most_common(limit):
            rows.append([cmd, str(count)])
        lines.append(_format_table(rows))

    if summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Responses"))
        rows = [["Code", "Count"]]
        for code, count in summary.response_counts.most_common(limit):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.user_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for user, count in summary.user_counts.most_common(limit):
            rows.append([_truncate_text(user, 32), str(count)])
        lines.append(_format_table(rows))

    if summary.banner_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Banners"))
        rows = [["Banner", "Count"]]
        for banner, count in summary.banner_counts.most_common(limit):
            rows.append([_truncate_text(banner, 72), str(count)])
        lines.append(_format_table(rows))

    if summary.server_software:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Software"))
        rows = [["Token", "Count"]]
        for token, count in summary.server_software.most_common(limit):
            rows.append([_truncate_text(token, 48), str(count)])
        lines.append(_format_table(rows))

    if summary.system_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SYST Responses"))
        rows = [["System", "Count"]]
        for system, count in summary.system_types.most_common(limit):
            rows.append([_truncate_text(system, 64), str(count)])
        lines.append(_format_table(rows))

    if summary.feature_counts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("FEAT Features"))
        rows = [["Feature", "Count"]]
        for feat, count in summary.feature_counts.most_common(limit):
            rows.append([_truncate_text(feat, 64), str(count)])
        lines.append(_format_table(rows))

    if summary.mac_addresses and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("MAC Addresses"))
        rows = [["Host", "MACs"]]
        for host, macs in sorted(summary.mac_addresses.items()):
            rows.append([host, ", ".join(sorted(macs))])
        lines.append(_format_table(rows))

    if summary.transfers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Data Transfers"))
        rows = [["Direction", "Bytes", "File", "Client", "Server"]]
        for transfer in summary.transfers[:limit]:
            rows.append(
                [
                    transfer.direction,
                    format_bytes_as_mb(transfer.bytes),
                    _truncate_text(transfer.filename or "-", 48),
                    transfer.client_ip,
                    transfer.server_ip,
                ]
            )
        lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for detection in detections[: max(limit, 20)]:
            severity = str(detection.get("severity", "info")).lower()
            summary_text = str(detection.get("summary", ""))
            details = detection.get("details", "")
            if severity == "high":
                marker = danger("[HIGH]")
            elif severity == "medium":
                marker = warn("[MED]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.credential_hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Credential Hits"))
        for hit in summary.credential_hits[:limit]:
            lines.append(
                f"{format_ts(hit.ts)}  {hit.client_ip} -> {hit.server_ip}  "
                f"USER {hit.username or '-'} PASS {_redact_secret(hit.password)}"
            )

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_tls_summary(summary: TlsSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TLS/HTTPS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if getattr(summary, "analysis_notes", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes:
            lines.append(muted(f"- {note}"))

    lines.append(_format_kv("TLS Packets", str(summary.tls_packets)))
    if getattr(summary, "tls_like_packets", 0) and summary.tls_like_packets != summary.tls_packets:
        lines.append(_format_kv("TLS-Like Packets", str(summary.tls_like_packets)))
    lines.append(_format_kv("Client Hellos", str(summary.client_hellos)))
    lines.append(_format_kv("Server Hellos", str(summary.server_hellos)))
    if getattr(summary, "ech_hellos", 0):
        lines.append(_format_kv("ECH Hellos", str(summary.ech_hellos)))
    if getattr(summary, "sni_missing_no_ech", 0):
        lines.append(_format_kv("SNI Missing (Non-ECH)", str(summary.sni_missing_no_ech)))
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

    if getattr(summary, "weak_ciphers", None):
        weak = summary.weak_ciphers
        if weak:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Weak/Legacy Cipher Suites"))
            rows = [["Cipher", "Count"]]
            for cipher, count in weak.most_common(limit):
                rows.append([cipher, str(count)])
            lines.append(_format_table(rows))

    if summary.sni_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Name Indication (SNI)"))
        rows = [["SNI", "Count"]]
        for sni, count in summary.sni_counts.most_common(limit):
            safe_sni = _truncate_text(_redact_in_text(str(sni)), 96)
            rows.append([safe_sni, str(count)])
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

    if getattr(summary, "sni_to_ja3", None) and getattr(summary, "ja3_to_sni", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("JA3 ↔ SNI (Top)"))
        rows = [["SNI", "Top JA3", "Count"]]
        for sni, _count in summary.sni_counts.most_common(limit):
            counter = summary.sni_to_ja3.get(sni)
            if not counter:
                continue
            top_val, top_count = counter.most_common(1)[0]
            rows.append([_truncate_text(_redact_in_text(str(sni)), 80), top_val, str(top_count)])
        if len(rows) > 1:
            lines.append(_format_table(rows))
        rows = [["JA3", "Top SNI", "Count"]]
        for ja3, _count in summary.ja3_counts.most_common(limit):
            counter = summary.ja3_to_sni.get(ja3)
            if not counter:
                continue
            top_val, top_count = counter.most_common(1)[0]
            rows.append([ja3, _truncate_text(_redact_in_text(str(top_val)), 80), str(top_count)])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    if getattr(summary, "sni_to_ja4", None) and getattr(summary, "ja4_to_sni", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("JA4 ↔ SNI (Top)"))
        rows = [["SNI", "Top JA4", "Count"]]
        for sni, _count in summary.sni_counts.most_common(limit):
            counter = summary.sni_to_ja4.get(sni)
            if not counter:
                continue
            top_val, top_count = counter.most_common(1)[0]
            rows.append([_truncate_text(_redact_in_text(str(sni)), 80), top_val, str(top_count)])
        if len(rows) > 1:
            lines.append(_format_table(rows))
        rows = [["JA4", "Top SNI", "Count"]]
        for ja4, _count in summary.ja4_counts.most_common(limit):
            counter = summary.ja4_to_sni.get(ja4)
            if not counter:
                continue
            top_val, top_count = counter.most_common(1)[0]
            rows.append([ja4, _truncate_text(_redact_in_text(str(top_val)), 80), str(top_count)])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Sessions"))
        lines.append(
            _format_sessions_table(
                summary.conversations,
                limit,
                extra_cols=[("SNI", lambda c: _conv_value(c, "sni") or "-")],
            )
        )

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TLS Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Service Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.http_requests or summary.http_responses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Plaintext HTTP (Capture-Wide)"))
        lines.append(muted("HTTP stats reflect plaintext traffic in the capture; use --http for full details."))
        lines.append(_format_kv("HTTP Requests", str(summary.http_requests)))
        lines.append(_format_kv("HTTP Responses", str(summary.http_responses)))
        if summary.http_methods:
            rows = [["Method", "Count"]]
            for method, count in summary.http_methods.most_common(limit):
                rows.append([method, str(count)])
            lines.append(_format_table(rows))
        if summary.http_statuses:
            rows = [["Status", "Count"]]
            for status, count in summary.http_statuses.most_common(limit):
                rows.append([status, str(count)])
            lines.append(_format_table(rows))
        if summary.http_user_agents:
            rows = [["User-Agent", "Count"]]
            for ua, count in summary.http_user_agents.most_common(limit):
                rows.append([_truncate_text(_redact_in_text(str(ua)), 96), str(count)])
            lines.append(_format_table(rows))

    if summary.http_referrers or summary.http_referrer_present or summary.http_referrer_missing:
        lines.append(SUBSECTION_BAR)
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
            rows = [["Host", "Count"]]
            for host, count in summary.http_referrer_hosts.most_common(limit):
                rows.append([_truncate_text(_redact_in_text(str(host)), 96), str(count)])
            lines.append(_format_table(rows))

        if summary.http_referrers:
            rows = [["URL", "Host", "Count"]]
            host_map = getattr(summary, "http_referrer_request_hosts", {}) or {}
            for ref, count in summary.http_referrers.most_common(limit):
                display = ref if verbose else _truncate_text(ref, max_len=96)
                display = _redact_in_text(display)
                host_counter = host_map.get(ref)
                if host_counter:
                    top_hosts = host_counter.most_common(_limit_value(2))
                    host_display = ", ".join(
                        f"{_redact_in_text(host)} ({host_count})" for host, host_count in top_hosts
                    )
                else:
                    host_display = "-"
                rows.append([display, host_display, str(count)])
            lines.append(_format_table(rows))

        show_paths = bool(summary.http_referrer_paths) and (
            verbose
            or not summary.http_referrers
            or len(summary.http_referrer_paths) != len(summary.http_referrers)
        )
        if show_paths:
            rows = [["Path", "Count"]]
            for path, count in summary.http_referrer_paths.most_common(limit):
                display = path if verbose else _truncate_text(path, max_len=96)
                display = _redact_in_text(display)
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
                rows.append([_truncate_text(_redact_in_text(subject), 96), str(count)])
            lines.append(_format_table(rows))
        if summary.cert_issuers:
            rows = [["Issuer", "Count"]]
            for issuer, count in summary.cert_issuers.most_common(limit):
                rows.append([_truncate_text(_redact_in_text(issuer), 96), str(count)])
            lines.append(_format_table(rows))
        if getattr(summary, "cert_sans", None):
            sans = summary.cert_sans
            if sans:
                rows = [["SAN", "Count"]]
                for name, count in sans.most_common(limit):
                    rows.append([_truncate_text(_redact_in_text(name), 96), str(count)])
                lines.append(_format_table(rows))
        if summary.weak_certs or summary.expired_certs or summary.self_signed_certs:
            rows = [["Weak", "Expired", "Self-Signed"]]
            rows.append([str(summary.weak_certs), str(summary.expired_certs), str(summary.self_signed_certs)])
            lines.append(_format_table(rows))
        if getattr(summary, "cert_artifacts", None):
            if summary.cert_artifacts:
                rows = [["Subject", "Issuer", "Not After", "Key", "SHA256"]]
                for cert in summary.cert_artifacts[:limit]:
                    key_text = f"{cert.pubkey_type} {cert.pubkey_size}" if cert.pubkey_type else "-"
                    rows.append([
                        _truncate_text(_redact_in_text(cert.subject), 60),
                        _truncate_text(_redact_in_text(cert.issuer), 40),
                        cert.not_after,
                        key_text,
                        cert.sha256[:_limit_value(32)] + "...",
                    ])
                lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
            lines.append(muted(f"- {_truncate_text(_redact_in_text(str(item)), 96)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_ssh_summary(summary: SshSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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

    if getattr(summary, "analysis_notes", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes:
            lines.append(muted(f"- {note}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("SSH Packets", str(summary.ssh_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
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
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.client_versions or summary.server_versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Versions"))
        rows = [["Client Versions", "Server Versions"]]
        client_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.client_versions.most_common(_limit_value(6))
        ) or "-"
        server_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.server_versions.most_common(_limit_value(6))
        ) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.client_software or summary.server_software:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Software"))
        rows = [["Clients", "Servers"]]
        client_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.client_software.most_common(_limit_value(6))
        ) or "-"
        server_text = ", ".join(
            f"{_truncate_text(name, 40)}({count})" for name, count in summary.server_software.most_common(_limit_value(6))
        ) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if getattr(summary, "device_fingerprints", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        rows = [["Fingerprint", "Count"]]
        for fp, count in summary.device_fingerprints.most_common(limit):
            rows.append([_truncate_text(fp, 90), str(count)])
        lines.append(_format_table(rows))

    if summary.client_hassh:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Client HASSH"))
        rows = [["HASSH", "Count", "KEX String"]]
        for value, count in summary.client_hassh.most_common(limit):
            detail = summary.client_hassh_strings.get(value, "")
            rows.append([value, str(count), _truncate_text(detail, 70)])
        lines.append(_format_table(rows))

    if summary.server_hassh:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server HASSH"))
        rows = [["HASSH", "Count", "KEX String"]]
        for value, count in summary.server_hassh.most_common(limit):
            detail = summary.server_hassh_strings.get(value, "")
            rows.append([value, str(count), _truncate_text(detail, 70)])
        lines.append(_format_table(rows))

    if summary.host_key_fingerprints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Key Fingerprints"))
        rows = [["Fingerprint", "Count"]]
        for fp, count in summary.host_key_fingerprints.most_common(limit):
            rows.append([fp, str(count)])
        lines.append(_format_table(rows))

    if summary.host_key_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Key Types"))
        rows = [["Type", "Count"]]
        for name, count in summary.host_key_types.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.kex_algorithms or summary.cipher_algorithms or summary.mac_algorithms or summary.host_key_algorithms:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Crypto Negotiation"))
        rows = [["KEX", "Host Key", "Cipher", "MAC", "Compression"]]
        rows.append([
            ", ".join(f"{name}({count})" for name, count in summary.kex_algorithms.most_common(_limit_value(3))) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.host_key_algorithms.most_common(_limit_value(3))) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.cipher_algorithms.most_common(_limit_value(3))) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.mac_algorithms.most_common(_limit_value(3))) or "-",
            ", ".join(f"{name}({count})" for name, count in summary.compression_algorithms.most_common(_limit_value(3))) or "-",
        ])
        lines.append(_format_table(rows))

    if summary.auth_methods:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Auth Methods"))
        rows = [["Method", "Count"]]
        for name, count in summary.auth_methods.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if getattr(summary, "auth_usernames", None):
        if summary.auth_usernames:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Auth Usernames (Decrypted)"))
            rows = [["Username", "Count"]]
            for name, count in summary.auth_usernames.most_common(limit):
                rows.append([_truncate_text(name, 40), str(count)])
            lines.append(_format_table(rows))

    if summary.auth_failures_by_client or summary.auth_successes_by_client:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Outcomes (By Client)"))
        rows = [["Client", "Failures", "Successes"]]
        ranked_clients = sorted(
            set(summary.auth_failures_by_client.keys()) | set(summary.auth_successes_by_client.keys()),
            key=lambda ip: summary.auth_failures_by_client.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_clients[:limit]:
            rows.append([
                ip,
                str(summary.auth_failures_by_client.get(ip, 0)),
                str(summary.auth_successes_by_client.get(ip, 0)),
            ])
        lines.append(_format_table(rows))

    if summary.request_counts or summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Requests & Responses"))
        rows = [["Requests", "Responses"]]
        req_text = ", ".join(
            f"{name.replace('SSH_MSG_', '')}({count})"
            for name, count in summary.request_counts.most_common(_limit_value(6))
        ) or "-"
        resp_text = ", ".join(
            f"{name.replace('SSH_MSG_', '')}({count})"
            for name, count in summary.response_counts.most_common(_limit_value(6))
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
        lines.append(header("Observed Plaintext (Pre-Encryption)"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_plaintext:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Plaintext Indicators"))
        rows = [["Indicator", "Count"]]
        for text, count in summary.suspicious_plaintext.most_common(limit):
            rows.append([_truncate_text(text, 80), str(count)])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        rows = [["File", "Count"]]
        for name, count in summary.file_artifacts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "Auth Fail/OK"]]
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            rows.append([
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                f"{conv.client_bytes / (1024 * 1024):.1f}",
                f"{conv.server_bytes / (1024 * 1024):.1f}",
                str(conv.packets),
                f"{conv.auth_failures}/{conv.auth_successes}",
            ])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
                summary_text = danger(summary_text)
            elif severity == "high":
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
            lines.append(muted(f"- {_truncate_text(_redact_in_text(item), 80)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_rdp_summary(summary: RdpSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"RDP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("RDP Packets", str(summary.rdp_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("TCP Sessions", str(summary.tcp_sessions)))
    lines.append(_format_kv("UDP Sessions", str(summary.udp_sessions)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_tcp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server TCP Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_tcp_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.server_udp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server UDP Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_udp_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top RDP Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RDP Sessions"))
        rows = [["Client", "Server", "Start", "End", "Duration", "Packets", "Size"]]
        if verbose:
            rows[0].extend(["UDP", "TLS"])
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            duration = None
            if conv.first_seen is not None and conv.last_seen is not None:
                duration = max(0.0, conv.last_seen - conv.first_seen)
            row = [
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                format_ts(conv.first_seen),
                format_ts(conv.last_seen),
                format_duration(duration),
                str(conv.packets),
                format_bytes_as_mb(conv.bytes),
            ]
            if verbose:
                row.extend([
                    "yes" if conv.udp_detected else "no",
                    "yes" if conv.tls_detected else "no",
                ])
            rows.append(row)
        lines.append(_format_table(rows))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.client_names:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Client Hostnames (mstshash)"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.client_names.most_common(limit):
            rows.append([_truncate_text(name, 48), str(count)])
        lines.append(_format_table(rows))

    if summary.tls_handshakes or getattr(summary, "dtls_handshakes", 0):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Security"))
        lines.append(_format_kv("TLS Handshakes Detected", str(summary.tls_handshakes)))
        if getattr(summary, "dtls_handshakes", 0):
            lines.append(_format_kv("DTLS Handshakes Detected", str(summary.dtls_handshakes)))

    if getattr(summary, "requested_protocols", None):
        if summary.requested_protocols or summary.selected_protocols:
            lines.append(SUBSECTION_BAR)
            lines.append(header("RDP Negotiation"))
            rows = [["Requested", "Selected"]]
            req_text = ", ".join(
                f"{name}({count})" for name, count in summary.requested_protocols.most_common(_limit_value(6))
            ) or "-"
            sel_text = ", ".join(
                f"{name}({count})" for name, count in summary.selected_protocols.most_common(_limit_value(6))
            ) or "-"
            rows.append([req_text, sel_text])
            lines.append(_format_table(rows))

    if getattr(summary, "client_builds", None):
        if summary.client_builds:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Client Builds"))
            rows = [["Build", "Count"]]
            for name, count in summary.client_builds.most_common(limit):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))

    if getattr(summary, "decrypted_username", None):
        if summary.decrypted_username or summary.decrypted_domain or summary.decrypted_client_name:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Decrypted Identity"))
            rows = [["Usernames", "Domains", "Client Names"]]
            user_text = ", ".join(
                f"{_truncate_text(name, 32)}({count})" for name, count in summary.decrypted_username.most_common(_limit_value(6))
            ) or "-"
            domain_text = ", ".join(
                f"{_truncate_text(name, 32)}({count})" for name, count in summary.decrypted_domain.most_common(_limit_value(6))
            ) or "-"
            client_text = ", ".join(
                f"{_truncate_text(name, 32)}({count})" for name, count in summary.decrypted_client_name.most_common(_limit_value(6))
            ) or "-"
            rows.append([user_text, domain_text, client_text])
            lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext (Pre-Encryption/Decrypted)"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_plaintext:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Plaintext Indicators"))
        rows = [["Indicator", "Count"]]
        for text, count in summary.suspicious_plaintext.most_common(limit):
            rows.append([_truncate_text(text, 80), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
                summary_text = danger(summary_text)
            elif severity == "high":
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
            lines.append(muted(f"- {_truncate_text(_redact_in_text(item), 80)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_telnet_summary(summary: TelnetSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TELNET ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Telnet Packets", str(summary.telnet_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
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
        lines.append(header("Top Telnet Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Telnet Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.usernames or summary.passwords:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Credentials"))
        rows = [["Usernames", "Passwords"]]
        user_text = ", ".join(
            f"{name}({count})" for name, count in summary.usernames.most_common(_limit_value(6))
        ) or "-"
        pass_text = ", ".join(
            f"{_truncate_text(_redact_secret(name), 20)}({count})" for name, count in summary.passwords.most_common(_limit_value(6))
        ) or "-"
        rows.append([user_text, pass_text])
        lines.append(_format_table(rows))

    if summary.commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Commands"))
        rows = [["Command", "Count"]]
        for name, count in summary.commands.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "Users"]]
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            rows.append([
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                f"{conv.client_bytes / (1024 * 1024):.1f}",
                f"{conv.server_bytes / (1024 * 1024):.1f}",
                str(conv.packets),
                ", ".join(conv.usernames) if conv.usernames else "-",
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_vnc_summary(summary: VncSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"VNC ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("VNC Packets", str(summary.vnc_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
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
        lines.append(header("Top VNC Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("VNC Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.client_banners or summary.server_banners:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RFB Versions"))
        rows = [["Clients", "Servers"]]
        client_text = ", ".join(
            f"{name}({count})" for name, count in summary.client_banners.most_common(_limit_value(6))
        ) or "-"
        server_text = ", ".join(
            f"{name}({count})" for name, count in summary.server_banners.most_common(_limit_value(6))
        ) or "-"
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.auth_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Types"))
        rows = [["Auth", "Count"]]
        for name, count in summary.auth_types.most_common(limit):
            rows.append([_truncate_text(name, 40), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "Client RFB", "Server RFB"]]
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            rows.append([
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                f"{conv.client_bytes / (1024 * 1024):.1f}",
                f"{conv.server_bytes / (1024 * 1024):.1f}",
                str(conv.packets),
                conv.client_banner or "-",
                conv.server_banner or "-",
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_teamviewer_summary(summary: TeamviewerSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TEAMVIEWER ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("TeamViewer Packets", str(summary.tv_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("TCP Sessions", str(summary.tcp_sessions)))
    lines.append(_format_kv("UDP Sessions", str(summary.udp_sessions)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_tcp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server TCP Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_tcp_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.server_udp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server UDP Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_udp_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TeamViewer Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TeamViewer Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.hints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TeamViewer Hints"))
        rows = [["Hint", "Count"]]
        for hint, count in summary.hints.most_common(limit):
            rows.append([_truncate_text(hint, 60), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "UDP", "Hints"]]
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            rows.append([
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                f"{conv.client_bytes / (1024 * 1024):.1f}",
                f"{conv.server_bytes / (1024 * 1024):.1f}",
                str(conv.packets),
                "yes" if conv.udp_detected else "no",
                ", ".join(conv.hints) if conv.hints else "-",
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_winrm_summary(summary: WinrmSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"WINRM ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("WinRM Packets", str(summary.winrm_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("HTTP Sessions", str(summary.http_sessions)))
    lines.append(_format_kv("HTTPS Sessions", str(summary.https_sessions)))
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
        lines.append(header("Top WinRM Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WinRM Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.http_hosts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP Hosts"))
        rows = [["Host", "Count"]]
        for host, count in summary.http_hosts.most_common(limit):
            rows.append([_truncate_text(host, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.user_agents:
        lines.append(SUBSECTION_BAR)
        lines.append(header("User Agents"))
        rows = [["User-Agent", "Count"]]
        for agent, count in summary.user_agents.most_common(limit):
            rows.append([_truncate_text(agent, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.auth_schemes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Schemes"))
        rows = [["Scheme", "Count"]]
        for scheme, count in summary.auth_schemes.most_common(limit):
            rows.append([_truncate_text(scheme, 40), str(count)])
        lines.append(_format_table(rows))

    if summary.soap_actions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SOAP Actions"))
        rows = [["Action", "Count"]]
        for action, count in summary.soap_actions.most_common(limit):
            rows.append([_truncate_text(action, 60), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "HTTP", "HTTPS"]]
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            rows.append([
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                f"{conv.client_bytes / (1024 * 1024):.1f}",
                f"{conv.server_bytes / (1024 * 1024):.1f}",
                str(conv.packets),
                "yes" if conv.http_detected else "no",
                "yes" if conv.https_detected else "no",
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_wmic_summary(summary: WmicSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"WMIC/WMI ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("WMIC Packets", str(summary.wmic_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
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
        lines.append(header("Top WMIC Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMIC Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.hostnames or summary.ip_strings or summary.mac_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Details"))
        rows = [["Hostnames", "IPs", "MACs"]]
        host_text = ", ".join(name for name, _count in summary.hostnames.most_common(_limit_value(8))) if summary.hostnames else "-"
        ip_text = ", ".join(ip for ip, _count in summary.ip_strings.most_common(_limit_value(8))) if summary.ip_strings else "-"
        mac_text = ", ".join(mac for mac, _count in summary.mac_strings.most_common(_limit_value(6))) if summary.mac_strings else "-"
        rows.append([_truncate_text(host_text, 60), _truncate_text(ip_text, 60), _truncate_text(mac_text, 60)])
        lines.append(_format_table(rows))

    if summary.domains or summary.usernames:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain & Users"))
        rows = [["Domains", "Users"]]
        domain_text = ", ".join(dom for dom, _count in summary.domains.most_common(_limit_value(8))) if summary.domains else "-"
        user_text = ", ".join(user for user, _count in summary.usernames.most_common(_limit_value(8))) if summary.usernames else "-"
        rows.append([_truncate_text(domain_text, 60), _truncate_text(user_text, 60)])
        lines.append(_format_table(rows))

    if summary.wmi_namespaces:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMI Namespaces"))
        rows = [["Namespace", "Count"]]
        for name, count in summary.wmi_namespaces.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.wmi_classes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMI Classes"))
        rows = [["Class", "Count"]]
        for name, count in summary.wmi_classes.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.wmic_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMIC Commands"))
        rows = [["Command", "Count"]]
        for cmd, count in summary.wmic_commands.most_common(limit):
            rows.append([_truncate_text(cmd, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.wmi_queries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMI Queries"))
        rows = [["Query", "Count"]]
        for query, count in summary.wmi_queries.most_common(limit):
            rows.append([_truncate_text(query, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Indicators"))
        rows = [["Indicator", "Count"]]
        for name, count in summary.services.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.error_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth & RPC Errors"))
        rows = [["Error", "Count"]]
        for name, count in summary.error_counts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Commands"))
        rows = [["Indicator", "Count"]]
        for name, count in summary.suspicious_commands.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "Hints"]]
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            rows.append([
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                f"{conv.client_bytes / (1024 * 1024):.1f}",
                f"{conv.server_bytes / (1024 * 1024):.1f}",
                str(conv.packets),
                ", ".join(conv.hints) if conv.hints else "-",
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_powershell_summary(summary: PowershellSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"POWERSHELL ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("PowerShell Packets", str(summary.powershell_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(_format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes)))
        lines.append(_format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes)))
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
        lines.append(header("Top PowerShell Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PowerShell Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0) + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = ", ".join(summary.ip_to_macs.get(ip, [])) or "-"
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.hostnames or summary.ip_strings or summary.mac_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Details"))
        rows = [["Hostnames", "IPs", "MACs"]]
        host_text = ", ".join(name for name, _count in summary.hostnames.most_common(_limit_value(8))) if summary.hostnames else "-"
        ip_text = ", ".join(ip for ip, _count in summary.ip_strings.most_common(_limit_value(8))) if summary.ip_strings else "-"
        mac_text = ", ".join(mac for mac, _count in summary.mac_strings.most_common(_limit_value(6))) if summary.mac_strings else "-"
        rows.append([_truncate_text(host_text, 60), _truncate_text(ip_text, 60), _truncate_text(mac_text, 60)])
        lines.append(_format_table(rows))

    if summary.domains or summary.usernames:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain & Users"))
        rows = [["Domains", "Users"]]
        domain_text = ", ".join(dom for dom, _count in summary.domains.most_common(_limit_value(8))) if summary.domains else "-"
        user_text = ", ".join(user for user, _count in summary.usernames.most_common(_limit_value(8))) if summary.usernames else "-"
        rows.append([_truncate_text(domain_text, 60), _truncate_text(user_text, 60)])
        lines.append(_format_table(rows))

    if summary.commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PowerShell Commands"))
        rows = [["Command", "Count"]]
        for cmd, count in summary.commands.most_common(limit):
            rows.append([_truncate_text(cmd, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.urls:
        lines.append(SUBSECTION_BAR)
        lines.append(header("URLs"))
        rows = [["URL", "Count"]]
        for url, count in summary.urls.most_common(limit):
            rows.append([_truncate_text(url, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.ad_queries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Active Directory Queries"))
        rows = [["Cmdlet", "Count"]]
        for name, count in summary.ad_queries.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.network_discovery:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Network Discovery"))
        rows = [["Cmdlet", "Count"]]
        for name, count in summary.network_discovery.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_indicators:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Indicators"))
        rows = [["Indicator", "Count"]]
        for name, count in summary.suspicious_indicators.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "Hints"]]
        top_sessions = sorted(summary.conversations, key=lambda conv: conv.bytes, reverse=True)[:limit]
        for conv in top_sessions:
            rows.append([
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                f"{conv.client_bytes / (1024 * 1024):.1f}",
                f"{conv.server_bytes / (1024 * 1024):.1f}",
                str(conv.packets),
                ", ".join(conv.hints) if conv.hints else "-",
            ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_syslog_summary(summary: SyslogSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

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
            f"{name}({count})" for name, count in summary.facility_counts.most_common(_limit_value(6))
        ) or "-"
        severity_text = ", ".join(
            f"{name}({count})" for name, count in summary.severity_counts.most_common(_limit_value(6))
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
        lines.append(header("Syslog Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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


def render_snmp_summary(summary: SnmpSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SNMP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("SNMP Packets", str(summary.snmp_packets)))
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
        lines.append(header("Top SNMP Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.version_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SNMP Versions"))
        rows = [["Version", "Count"]]
        for version, count in summary.version_counts.most_common(limit):
            rows.append([version, str(count)])
        lines.append(_format_table(rows))

    if summary.community_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Community Strings"))
        rows = [["Community", "Count"]]
        for comm, count in summary.community_counts.most_common(limit):
            rows.append([_redact_secret(comm), str(count)])
        lines.append(_format_table(rows))

    if summary.pdu_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PDU Types"))
        rows = [["PDU", "Count"]]
        for pdu, count in summary.pdu_counts.most_common(limit):
            rows.append([pdu, str(count)])
        lines.append(_format_table(rows))

    if summary.oid_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top OIDs"))
        rows = [["OID", "Count"]]
        for oid, count in summary.oid_counts.most_common(limit):
            rows.append([_truncate_text(oid, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.hostnames:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Hostnames"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostnames.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.ip_addresses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IP Addresses"))
        rows = [["IP", "Count"]]
        for ip_addr, count in summary.ip_addresses.most_common(limit):
            rows.append([ip_addr, str(count)])
        lines.append(_format_table(rows))

    if summary.mac_addresses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("MAC Addresses"))
        rows = [["MAC", "Count"]]
        for mac, count in summary.mac_addresses.most_common(limit):
            rows.append([mac, str(count)])
        lines.append(_format_table(rows))

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovered Services"))
        rows = [["Service", "Count"]]
        for name, count in summary.services.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SNMP Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
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


def render_smtp_summary(summary: SmtpSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SMTP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("SMTP Packets", str(summary.smtp_packets)))
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
        lines.append(header("Top SMTP Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Hostnames (HELO/EHLO)"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostname_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.command_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMTP Commands"))
        rows = [["Command", "Count"]]
        for name, count in summary.command_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["Code", "Count"]]
        for name, count in summary.response_counts.most_common(limit):
            rows.append([str(name), str(count)])
        lines.append(_format_table(rows))

    if summary.auth_methods:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Methods"))
        rows = [["Method", "Count"]]
        for name, count in summary.auth_methods.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.auth_failures or summary.auth_successes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Outcomes"))
        rows = [["Failures", "Successes"]]
        fail_text = ", ".join(
            f"{ip}({count})" for ip, count in summary.auth_failures.most_common(_limit_value(6))
        ) or "-"
        succ_text = ", ".join(
            f"{ip}({count})" for ip, count in summary.auth_successes.most_common(_limit_value(6))
        ) or "-"
        rows.append([fail_text, succ_text])
        lines.append(_format_table(rows))

    if summary.email_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Email Addresses"))
        rows = [["Email", "Count"]]
        for name, count in summary.email_counts.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.domain_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domains"))
        rows = [["Domain", "Count"]]
        for name, count in summary.domain_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMTP Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
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


def render_rpc_summary(summary: RpcSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"RPC ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("RPC Packets", str(summary.rpc_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Messages", str(summary.total_messages)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.protocol_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Activity"))
        rows = [["Protocol", "Count"]]
        for proto, count in summary.protocol_counts.most_common(limit):
            rows.append([str(proto), str(count)])
        lines.append(_format_table(rows))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        rows = [["Port", "Count"]]
        for port, count in summary.server_ports.most_common(limit):
            rows.append([str(port), str(count)])
        lines.append(_format_table(rows))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top RPC Clients & Servers"))
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))

    if summary.pdu_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC PDU Types"))
        rows = [["PDU", "Count"]]
        for name, count in summary.pdu_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.interface_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC Interfaces"))
        rows = [["Interface", "Count"]]
        for name, count in summary.interface_counts.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if getattr(summary, "command_counts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC Commands"))
        rows = [["Command", "Count"]]
        for name, count in summary.command_counts.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.share_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Shares"))
        rows = [["Share", "Count", "Type"]]
        for share, count in summary.share_counts.most_common(limit):
            share_name = str(share).split("\\")[-1]
            share_type = "Admin" if share_name.upper().endswith("$") else "Normal"
            rows.append([_truncate_text(_redact_in_text(str(share)), 70), str(count), share_type])
        lines.append(_format_table(rows))

    if summary.pipe_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Named Pipes"))
        rows = [["Pipe", "Count"]]
        for name, count in summary.pipe_counts.most_common(limit):
            rows.append([_truncate_text(_redact_in_text(str(name)), 70), str(count)])
        lines.append(_format_table(rows))

    if summary.hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Hostnames"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostname_counts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.domain_user_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Users"))
        rows = [["Domain\\User", "Count"]]
        for name, count in summary.domain_user_counts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.ip_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IP Strings"))
        rows = [["IP", "Count"]]
        for name, count in summary.ip_strings.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.mac_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("MAC Strings"))
        rows = [["MAC", "Count"]]
        for name, count in summary.mac_strings.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_strings.most_common(limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
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
    limit = _apply_verbose_limit(limit)
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
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Client/Server Statistics"))
        client_bytes = summary.client_bytes if isinstance(summary.client_bytes, Counter) else Counter()
        server_bytes = summary.server_bytes if isinstance(summary.server_bytes, Counter) else Counter()
        rows = [["Client", "Server"]]
        client_list = [
            f"{ip}({summary.client_counts[ip]}/{format_bytes_as_mb(client_bytes.get(ip, 0))})"
            for ip, _count in summary.client_counts.most_common(_limit_value(10))
        ]
        server_list = [
            f"{ip}({summary.server_counts[ip]}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
            for ip, _count in summary.server_counts.most_common(_limit_value(10))
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
            dst_text = ", ".join(f"{ip}({cnt})" for ip, cnt in dsts.most_common(_limit_value(3))) or "-"
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
    limit = _apply_verbose_limit(limit)
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
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Client/Server Statistics"))
        client_bytes = summary.client_bytes if isinstance(summary.client_bytes, Counter) else Counter()
        server_bytes = summary.server_bytes if isinstance(summary.server_bytes, Counter) else Counter()
        rows = [["Client", "Server"]]
        client_list = [
            f"{ip}({summary.client_counts[ip]}/{format_bytes_as_mb(client_bytes.get(ip, 0))})"
            for ip, _count in summary.client_counts.most_common(_limit_value(10))
        ]
        server_list = [
            f"{ip}({summary.server_counts[ip]}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
            for ip, _count in summary.server_counts.most_common(_limit_value(10))
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
            dst_text = ", ".join(f"{ip}({cnt})" for ip, cnt in dsts.most_common(_limit_value(3))) or "-"
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
    limit = _apply_verbose_limit(limit)
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
        clients_list = sorted(entry["clients"])[:_limit_value(5)]
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
        artifacts=[f"{name} ({count})" for name, count in artifact_counts.most_common(_limit_value(20))],
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )

    return render_udp_summary(rollup, limit=limit, verbose=verbose)


def render_exfil_summary(summary: ExfilSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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
        rows = [["Src", "Dst", "Proto", "DPort", "Packets", "Bytes", "Duration", "Rate"]]
        for item in summary.outbound_flows[:limit]:
            duration_seconds = float(item.get("duration_seconds", 0.0) or 0.0)
            bytes_per_second = float(item.get("bytes_per_second", 0.0) or 0.0)
            dport = item.get("dst_port")
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("proto", "-")),
                str(dport) if isinstance(dport, int) and dport > 0 else "-",
                str(item.get("packets", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0))),
                format_duration(duration_seconds),
                f"{format_bytes_as_mb(int(bytes_per_second * 60))}/min" if bytes_per_second > 0 else "-",
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "internal_flows", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Internal Flows (Private -> Private)"))
        rows = [["Src", "Dst", "Proto", "DPort", "Packets", "Bytes", "Duration", "Rate"]]
        for item in summary.internal_flows[:limit]:
            duration_seconds = float(item.get("duration_seconds", 0.0) or 0.0)
            bytes_per_second = float(item.get("bytes_per_second", 0.0) or 0.0)
            dport = item.get("dst_port")
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("proto", "-")),
                str(dport) if isinstance(dport, int) and dport > 0 else "-",
                str(item.get("packets", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0))),
                format_duration(duration_seconds),
                f"{format_bytes_as_mb(int(bytes_per_second * 60))}/min" if bytes_per_second > 0 else "-",
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "ot_flows", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Control-Port Flows"))
        rows = [["Src", "Dst", "Proto", "DPort", "Packets", "Bytes", "Duration", "Rate"]]
        for item in summary.ot_flows[:limit]:
            duration_seconds = float(item.get("duration_seconds", 0.0) or 0.0)
            bytes_per_second = float(item.get("bytes_per_second", 0.0) or 0.0)
            dport = item.get("dst_port")
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("proto", "-")),
                str(dport) if isinstance(dport, int) and dport > 0 else "-",
                str(item.get("packets", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0))),
                format_duration(duration_seconds),
                f"{format_bytes_as_mb(int(bytes_per_second * 60))}/min" if bytes_per_second > 0 else "-",
            ])
        lines.append(_format_table(rows))

    if summary.dns_tunnel_suspects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Tunneling Heuristics"))
        rows = [["Src", "Total", "Unique", "Long", "Entropy", "MaxLabel"]]
        for item in summary.dns_tunnel_suspects[:limit]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("total", "-")),
                str(item.get("unique", "-")),
                str(item.get("long", "-")),
                str(item.get("avg_entropy", "-")),
                str(item.get("max_label", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.http_post_suspects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Large HTTP POST Payloads"))
        rows = [["Src", "Dst", "Host", "URI", "Bytes", "Requests", "Mode", "Content-Type"]]
        for item in summary.http_post_suspects[:limit]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("host", "-")),
                str(item.get("uri", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0))) if str(item.get("bytes", "")).isdigit() else str(item.get("bytes", "-")),
                str(item.get("requests", 1)),
                str(item.get("mode", "single")),
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

    if getattr(summary, "file_exfil_suspects", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Potential Exfil File Transfers"))
        rows = [["Src", "Dst", "Proto", "File", "Size", "Packet", "Note"]]
        for item in summary.file_exfil_suspects[:limit]:
            size_val = item.get("size")
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("protocol", "-")),
                str(item.get("filename", "-")),
                format_bytes_as_mb(int(size_val)) if isinstance(size_val, int) else "-",
                str(item.get("packet", "-")),
                str(item.get("note", "-")) if item.get("note") else "-",
            ])
        lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
            evidence_items = item.get("evidence", [])
            if isinstance(evidence_items, list):
                for evidence in evidence_items[:_limit_value(8)]:
                    lines.append(muted(f"    - {_redact_in_text(str(evidence))}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_sizes_summary(summary: SizeSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = item.get("severity", "info")
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
            evidence_items = item.get("evidence", [])
            if isinstance(evidence_items, list):
                for evidence in evidence_items[:_limit_value(8)]:
                    lines.append(muted(f"    - {_redact_in_text(str(evidence))}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_beacon_summary(summary: BeaconSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
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

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
            if isinstance(top_sources, list) and top_sources:
                src_text = ", ".join(f"{ip}({count})" for ip, count in top_sources[:_limit_value(6)])
                lines.append(muted(f"  Sources: {src_text}"))
            top_destinations = item.get("top_destinations")
            if isinstance(top_destinations, list) and top_destinations:
                dst_text = ", ".join(f"{ip}({count})" for ip, count in top_destinations[:_limit_value(6)])
                lines.append(muted(f"  Destinations: {dst_text}"))
            evidence_items = item.get("evidence", [])
            if isinstance(evidence_items, list) and evidence_items:
                for evidence in evidence_items[:_limit_value(8)]:
                    lines.append(muted(f"    - {_redact_in_text(str(evidence))}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_threats_summary(summary: ThreatSummary, verbose: bool = False) -> str:
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

    def _infer_tactic(item: dict[str, object]) -> str:
        source = str(item.get("source", "")).lower()
        blob = f"{item.get('summary', '')} {item.get('details', '')}".lower()

        if any(token in source for token in ("scan", "recon", "icmp", "discovery")) or any(
            token in blob for token in ("scan", "recon", "probing", "enumeration")
        ):
            return "Reconnaissance"
        if any(token in source for token in ("bruteforce", "auth", "credential", "creds")) or any(
            token in blob for token in ("password", "login", "credential", "auth failure")
        ):
            return "Credential Access"
        if any(token in source for token in ("lateral", "smb", "rdp", "winrm", "ssh")) or any(
            token in blob for token in ("lateral", "pivot", "east-west")
        ):
            return "Lateral Movement"
        if any(token in source for token in ("beacon", "c2", "command")) or any(
            token in blob for token in ("beacon", "command and control", "c2")
        ):
            return "Command & Control"
        if any(token in source for token in ("exfil", "dns")) or any(
            token in blob for token in ("exfil", "tunnel", "high entropy", "txt-query")
        ):
            return "Exfiltration"
        if any(token in source for token in ("ot", "ics", "modbus", "dnp3", "s7", "enip", "opc", "bacnet")):
            return "OT/ICS"
        if any(token in source for token in ("payload", "malware", "tooling")) or any(
            token in blob for token in ("powershell", "mimikatz", "rundll32", "wmic", "base64")
        ):
            return "Execution"
        if any(token in blob for token in ("flood", "dos", "impact", "disruption")):
            return "Impact"
        return "Other"

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    detections = _filtered_detections(summary, verbose)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Overview"))
    lines.append(_format_kv("Detections", str(len(detections))))
    if summary.total_packets:
        lines.append(_format_kv("Packets", str(summary.total_packets)))
    if summary.first_seen is not None or summary.last_seen is not None:
        lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
        lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    if summary.duration is not None:
        lines.append(_format_kv("Duration", f"{summary.duration:.1f}s"))
    if summary.ot_protocol_counts:
        proto_text = ", ".join(f"{name} ({count})" for name, count in sorted(summary.ot_protocol_counts.items(), key=lambda item: (-item[1], item[0]))[:_limit_value(6)])
        lines.append(_format_kv("OT Protocols", proto_text))
    if summary.public_ot_pairs:
        lines.append(_format_kv("Public OT Flows", str(len(summary.public_ot_pairs))))
    if summary.ot_risk_score:
        risk_level = "LOW"
        if summary.ot_risk_score >= 60:
            risk_level = "HIGH"
        elif summary.ot_risk_score >= 25:
            risk_level = "MEDIUM"
        lines.append(_format_kv("OT Risk Posture", f"{summary.ot_risk_score}/100 ({risk_level})"))
        if summary.ot_risk_findings:
            lines.append(muted("Findings:"))
            for finding in summary.ot_risk_findings:
                lines.append(muted(f"- {finding}"))
    if summary.storyline:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Probable Attack Storyline"))
        for line in summary.storyline:
            lines.append(muted(f"- {line}"))
    if summary.ot_peer_internal or summary.ot_peer_external:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top OT Peers"))
        if summary.ot_peer_internal:
            internal_list = ", ".join(f"{ip}({count})" for ip, count in summary.ot_peer_internal[:_limit_value(10)])
            lines.append(muted(f"Internal: {internal_list}"))
        if summary.ot_peer_external:
            external_list = ", ".join(f"{ip}({count})" for ip, count in summary.ot_peer_external[:_limit_value(10)])
            lines.append(muted(f"External: {_highlight_public_ips(external_list)}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        severity_counts: Counter[str] = Counter(str(item.get("severity", "info")).lower() for item in detections)
        lines.append(SUBSECTION_BAR)
        lines.append(header("Severity Breakdown"))
        for sev in ("critical", "high", "warning", "info"):
            if sev in severity_counts:
                lines.append(muted(f"- {sev}: {severity_counts[sev]}"))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections (by severity)"))

        severity_order = {
            "critical": 0,
            "high": 1,
            "warning": 2,
            "info": 3,
        }

        grouped: dict[str, dict[str, list[dict[str, object]]]] = {}
        for item in detections:
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
                    summary_text = _highlight_public_ips(_redact_in_text(str(item.get("summary", ""))))
                    details = _highlight_public_ips(_redact_in_text(str(item.get("details", ""))))
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
                    evidence = item.get("evidence")
                    if isinstance(evidence, list) and evidence:
                        lines.append(muted("      Evidence:"))
                        for entry in evidence[:_limit_value(10)]:
                            lines.append(muted(f"        - {_highlight_public_ips(_redact_in_text(str(entry)))}"))
                    elif isinstance(evidence, str) and evidence.strip():
                        lines.append(muted(f"      Evidence: {_highlight_public_ips(_redact_in_text(evidence))}"))

        if verbose:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Tactic Mapping (Hunt View)"))
            mitre_map = {
                "Reconnaissance": "TA0043",
                "Credential Access": "TA0006",
                "Lateral Movement": "TA0008",
                "Command & Control": "TA0011",
                "Exfiltration": "TA0010",
                "Execution": "TA0002",
                "Impact": "TA0040",
            }
            tactic_counts: Counter[str] = Counter()
            tactic_examples: dict[str, list[str]] = {}
            for item in detections:
                tactic = _infer_tactic(item)
                tactic_counts[tactic] += 1
                tactic_examples.setdefault(tactic, [])
                if len(tactic_examples[tactic]) < 3:
                    tactic_examples[tactic].append(str(item.get("summary", "")))

            for tactic, count in tactic_counts.most_common():
                tactic_label = label(tactic)
                mitre = mitre_map.get(tactic)
                if mitre:
                    tactic_label = f"{tactic_label} ({mitre})"
                lines.append(f"- {tactic_label}: {count}")
                examples = [value for value in tactic_examples.get(tactic, []) if value]
                if examples:
                    lines.append(muted(f"  Examples: {'; '.join(examples)}"))
    else:
        lines.append(muted("No notable threats detected."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_files_summary(summary: FileTransferSummary, limit: int | None = None, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"FILES OVERVIEW :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    effective_limit = limit if limit is not None else max(len(summary.artifacts), 0)

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovered Files"))
        # Define executable types and extension mappings
        executable_types = {"EXE/DLL", "ELF"}
        type_extensions = {
            "EXE/DLL": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"},
            "PDF": {".pdf"},
            "ZIP/Office": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".odp", ".docm", ".xlsm", ".pptm"},
            "ELF": {".elf", ".so", ".bin", ".out"},
            "PNG": {".png"},
            "JPG": {".jpg", ".jpeg"},
            "GIF": {".gif"},
            "GZIP": {".gz", ".tgz", ".gzip"},
            "HTML": {".html", ".htm", ".xhtml", ".shtml"},
            "X509": {".cer", ".crt", ".pem", ".der", ".p7b", ".pfx", ".p12"},
            "DICOM": {".dcm"},
        }
        rows = [["Protocol", "Filename", "Type", "Size", "Packet", "Src", "Dst", "Hostname", "Content Type", "Note"]]
        for item in summary.artifacts[:effective_limit]:
            size = format_bytes_as_mb(item.size_bytes) if item.size_bytes is not None else "-"
            # Fallback for old artifacts without file_type
            ftype = getattr(item, "file_type", "UNKNOWN")
            hostname = getattr(item, "hostname", None) or "-"
            
            # Apply coloring
            colored_filename = item.filename
            colored_ftype = ftype
            
            # Orange for executables (type) and red background for filenames
            if ftype in executable_types:
                colored_ftype = orange(ftype)
                colored_filename = danger_bg(item.filename)
            
            # Orange for BINARY filenames
            if ftype == "BINARY":
                colored_filename = orange(item.filename)
            
            # Red for extension mismatch
            if ftype in type_extensions:
                expected_exts = type_extensions[ftype]
                filename_lower = item.filename.lower()
                has_expected_ext = any(filename_lower.endswith(ext) for ext in expected_exts)
                if not has_expected_ext and item.filename != "http_response.bin" and not item.filename.startswith("extracted_"):
                    colored_filename = danger(item.filename)
            
            rows.append([
                item.protocol,
                colored_filename,
                colored_ftype,
                size,
                str(item.packet_index),
                item.src_ip,
                item.dst_ip,
                hostname,
                getattr(item, "content_type", "-"),
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
        raw_mode = any(bool(item.get("raw")) for item in summary.views)
        lines.append(header("File View (Raw Text)" if raw_mode else "File View (ASCII/HEX)"))
        for item in summary.views:
            filename = str(item.get("filename", ""))
            payload = item.get("payload")
            size = item.get("size")
            if isinstance(payload, (bytes, bytearray)):
                lines.append(label(f"{filename} ({size} bytes)"))
                if item.get("raw"):
                    text = decode_payload(bytes(payload), encoding="latin-1")
                    lines.append(text if text else muted("<no printable text>"))
                else:
                    lines.append(hexdump(bytes(payload)))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
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
        if verbose:
            for a in summary.anomalies:
                sev_color = danger if a.severity in ("HIGH", "CRITICAL") else warn
                lines.append(sev_color(f"[{a.severity}] {a.type}: {a.description}"))
                if a.src or a.dst:
                    lines.append(muted(f"  src: {str(a.src)} -> dst: {str(a.dst)}"))
        else:
            lines.append(_format_kv("Total Anomalies", str(len(summary.anomalies))))
            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            grouped: dict[tuple[str, str, str], dict[str, object]] = {}
            for a in summary.anomalies:
                key = (a.severity, a.type, a.description)
                entry = grouped.setdefault(key, {"count": 0, "examples": []})
                entry["count"] = int(entry["count"]) + 1
                if (a.src or a.dst) and len(entry["examples"]) < 3:
                    example = f"{a.src or '-'} -> {a.dst or '-'}"
                    if example not in entry["examples"]:
                        entry["examples"].append(example)

            grouped_items = sorted(
                grouped.items(),
                key=lambda item: (
                    severity_rank.get(item[0][0], 9),
                    -int(item[1]["count"]),
                    item[0][1],
                ),
            )
            limit = _limit_value(8)
            for (sev, a_type, desc), data in grouped_items[:limit]:
                sev_color = danger if sev in ("HIGH", "CRITICAL") else warn if sev == "MEDIUM" else muted
                lines.append(sev_color(f"[{sev}] {a_type}: {desc} (x{data['count']})"))
                examples = data.get("examples", [])
                if examples:
                    for ex in examples:
                        lines.append(muted(f"  example: {ex}"))
            if len(grouped_items) > limit:
                lines.append(muted(f"... {len(grouped_items) - limit} more anomaly patterns (use -v for full list)"))
    else:
        lines.append(SUBSECTION_BAR)
        lines.append(ok("No clear anomalies detected."))

    # 4. Conversations (Top 10 by bytes)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Conversations (by volume)"))
    
    sorted_convs = sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)[:_limit_value(10)]
    
    rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "Duration", "Ports"]]
    for c in sorted_convs:
        # Sort ports by value for consistent display
        ports_list = sorted(list(c.ports))
        ports_str = ",".join(map(str, ports_list[:_limit_value(4)]))
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
        sorted_eps = sorted(summary.endpoints, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True)[:_limit_value(10)]
        rows = [["Address", "Sent", "Recv", "Total Bytes", "Protocols"]]
        for e in sorted_eps:
             protos = ",".join(list(e.protocols)[:_limit_value(4)])
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
        if _VERBOSE_OUTPUT:
            for risk in sorted(summary.risks, key=lambda x: x.severity):
                sev_color = danger if risk.severity in ("CRITICAL", "HIGH") else warn
                if risk.severity == "LOW":
                    sev_color = muted
                
                lines.append(sev_color(f"[{risk.severity}] {risk.title}"))
                lines.append(f"  Target: {risk.affected_asset}")
                lines.append(muted(f"  Details: {risk.description}"))
                lines.append("")
        else:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            grouped: dict[tuple[str, str, str], list[str]] = {}
            for risk in summary.risks:
                key = (risk.severity, risk.title, risk.description)
                grouped.setdefault(key, []).append(risk.affected_asset)

            def _sort_key(item: tuple[tuple[str, str, str], list[str]]) -> tuple[int, int]:
                sev = item[0][0]
                return (severity_order.get(sev, 99), -len(item[1]))

            for (severity, title, desc), assets in sorted(grouped.items(), key=_sort_key)[:_limit_value(12)]:
                sev_color = danger if severity in ("CRITICAL", "HIGH") else warn
                if severity == "LOW":
                    sev_color = muted
                sample = ", ".join(sorted(set(assets))[:_limit_value(3)])
                lines.append(sev_color(f"[{severity}] {title} (x{len(assets)})"))
                if sample:
                    lines.append(muted(f"  Targets: {sample}"))
                lines.append(muted(f"  Details: {desc}"))
                lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_smb_summary(summary: SmbSummary, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SMB PROTOCOL ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    effective_verbose = _VERBOSE_OUTPUT or verbose

    def _preview_values(values: object, limit: int = 3, max_len: int = 60, show_count: bool = True) -> str:
        if not values:
            return "-"
        if effective_verbose:
            items: list[str]
            if isinstance(values, (set, list, tuple)):
                items = sorted(str(v) for v in values)
            else:
                try:
                    items = sorted(str(v) for v in list(values))
                except Exception:
                    items = [str(values)]
            if not items:
                return "-"
            return ", ".join(_redact_in_text(item) for item in items)
        items: list[str]
        if isinstance(values, (set, list, tuple)):
            items = sorted(str(v) for v in values)
        else:
            try:
                items = sorted(str(v) for v in list(values))
            except Exception:
                items = [str(values)]
        if not items:
            return "-"
        total = len(items)
        preview = items[:limit]
        text = ", ".join(_redact_in_text(item) for item in preview)
        if total > limit:
            text = f"{text} (+{total - limit} more)"
        if show_count and total > limit:
            text = f"{total}: {text}"
        return _truncate_text(text, max_len)

    def _looks_like_smb_token(value: str) -> bool:
        if not value:
            return False
        token = value.strip()
        if token in {"-", "(unknown)"}:
            return False
        if len(token) < 2 or len(token) > 64:
            return False
        if not any(ch.isalpha() for ch in token):
            return False
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@$ ")
        if any(ch not in allowed for ch in token):
            return False
        return True

    def _smb_preview_tokens(values: object, limit: int = 3, max_len: int = 60) -> tuple[str, bool]:
        if not values:
            return "-", False
        if effective_verbose:
            items: list[str]
            if isinstance(values, (set, list, tuple)):
                items = sorted(str(v) for v in values)
            else:
                try:
                    items = sorted(str(v) for v in list(values))
                except Exception:
                    items = [str(values)]
            if not items:
                return "-", False
            return ", ".join(_redact_in_text(item) for item in items), False
        items: list[str]
        if isinstance(values, (set, list, tuple)):
            items = sorted(str(v) for v in values)
        else:
            try:
                items = sorted(str(v) for v in list(values))
            except Exception:
                items = [str(values)]
        if not items:
            return "-", False
        total = len(items)
        filtered = [item for item in items if _looks_like_smb_token(item)]
        used = filtered if filtered else items
        preview = used[:limit]
        text = ", ".join(_redact_in_text(item) for item in preview)
        if len(used) > limit:
            text = f"{text} (+{len(used) - limit} more)"
        if total > limit:
            if filtered and len(filtered) != total:
                text = f"{total} ({len(filtered)} filtered): {text}"
            else:
                text = f"{total}: {text}"
        return _truncate_text(text, max_len), bool(filtered and len(filtered) != total)

    def _looks_like_smb_token(value: str) -> bool:
        if not value:
            return False
        token = value.strip()
        if token in {"-", "(unknown)"}:
            return False
        if len(token) < 2 or len(token) > 64:
            return False
        if not any(ch.isalpha() for ch in token):
            return False
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@$")
        if any(ch not in allowed for ch in token):
            return False
        return True

    def _smb_preview_tokens(values: object, limit: int = 3, max_len: int = 60) -> tuple[str, bool]:
        if not values:
            return "-", False
        items: list[str]
        if isinstance(values, (set, list, tuple)):
            items = sorted(str(v) for v in values)
        else:
            try:
                items = sorted(str(v) for v in list(values))
            except Exception:
                items = [str(values)]
        if not items:
            return "-", False
        total = len(items)
        filtered = [item for item in items if _looks_like_smb_token(item)]
        used = filtered if filtered else items
        preview = used[:limit]
        text = ", ".join(_redact_in_text(item) for item in preview)
        if len(used) > limit:
            text = f"{text} (+{len(used) - limit} more)"
        if total > limit:
            if filtered and len(filtered) != total:
                text = f"{total} ({len(filtered)} filtered): {text}"
            else:
                text = f"{total}: {text}"
        return _truncate_text(text, max_len), bool(filtered and len(filtered) != total)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if getattr(summary, "analysis_notes", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes:
            lines.append(muted(f"- {note}"))

    lines.append(_format_kv("SMB Packets", str(summary.smb_packets)))
    if getattr(summary, "smb_ports", None):
        ports_text = ", ".join(
            f"{port} ({count})" for port, count in summary.smb_ports.most_common(_limit_value(6))
        ) if summary.smb_ports else "-"
        lines.append(_format_kv("SMB Ports", ports_text))
    versions_text = ", ".join([f"{k} ({v})" for k, v in summary.versions.items()]) if summary.versions else "-"
    lines.append(_format_kv("SMB Versions", versions_text))
    lines.append(_format_kv("Unique Clients", str(len(summary.clients))))
    lines.append(_format_kv("Unique Servers", str(len(summary.servers))))
    lines.append(_format_kv("Sessions", str(len(summary.sessions))))
    if getattr(summary, "signed_packets", 0) or getattr(summary, "unsigned_packets", 0):
        signed_text = f"{summary.signed_packets} signed / {summary.unsigned_packets} unsigned"
        lines.append(_format_kv("Signed Packets", signed_text))
    if getattr(summary, "encrypted_packets", 0):
        encrypted_sessions = sum(1 for sess in summary.sessions if getattr(sess, "encrypted", False))
        lines.append(_format_kv("Encrypted Packets", str(summary.encrypted_packets)))
        lines.append(_format_kv("Encrypted Sessions", str(encrypted_sessions)))
    
    if summary.versions.get("SMB1"):
        lines.append(danger(f"SMBv1 DETECTED: {summary.versions['SMB1']} packets! Legacy/Insecure."))

    # 0. Request/Response Summary
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Requests vs Responses"))
    if not summary.requests and not summary.responses:
        lines.append(muted("No SMB command directionality captured."))
    else:
        rows = [["Command", "Requests", "Responses"]]
        all_cmds = []
        for cmd in set(summary.requests.keys()).union(summary.responses.keys()):
            req = summary.requests.get(cmd, 0)
            resp = summary.responses.get(cmd, 0)
            total = req + resp
            all_cmds.append((cmd, req, resp, total))
        all_cmds.sort(key=lambda item: item[3], reverse=True)
        limit = _limit_value(20)
        for cmd, req, resp, _total in all_cmds[:limit]:
            rows.append([cmd, str(req), str(resp)])
        lines.append(_format_table(rows))
        if len(all_cmds) > limit:
            lines.append(muted(f"Showing top {limit} commands by volume."))

    # 1. Top Commands
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top SMB Commands"))
    if not summary.commands:
        lines.append(muted("No command usage stats."))
    else:
        rows = [["Command", "Count"]]
        for cmd, count in summary.commands.most_common(_limit_value(10)):
            rows.append([cmd, str(count)])
        lines.append(_format_table(rows))

    # 2. Shares Accessed
    if summary.shares:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Shares Accessed"))
        rows = [["Server", "Share Path", "Count", "Type"]]
        for s in summary.shares:
            stype = "Admin" if s.is_admin else "Normal"
            rows.append([s.server_ip, _truncate_text(_redact_in_text(str(s.name)), 60), str(s.connect_count), stype])
        lines.append(_format_table(rows))
    
    # 3. Top Clients/Servers
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Clients"))
    rows = [["Client IP", "Packets"]]
    for ip, count in summary.top_clients.most_common(_limit_value(5)):
        rows.append([ip, str(count)])
    lines.append(_format_table(rows))
    
    lines.append("")
    lines.append(header("Top Servers"))
    rows = [["Server IP", "Packets"]]
    for ip, count in summary.top_servers.most_common(_limit_value(5)):
        rows.append([ip, str(count)])
    lines.append(_format_table(rows))

    # 4. Error Codes / Failures
    if summary.error_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Error/Status Codes"))
        rows = [["Status Code", "Count"]]
        for code, count in summary.error_codes.most_common(_limit_value(10)):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    # 5. Conversations
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Conversations"))
    if not summary.conversations:
        lines.append(muted("No SMB conversations summarized."))
    else:
        lines.append(
            _format_sessions_table(
                summary.conversations,
                _limit_value(10),
                extra_cols=[
                    ("Requests", lambda c: _conv_value(c, "requests") or 0),
                    ("Responses", lambda c: _conv_value(c, "responses") or 0),
                ],
            )
        )

    # 6. Server Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Servers"))
    if not summary.servers:
        lines.append(muted("No SMB servers identified."))
    else:
        rows = [["Server", "Dialects", "Signing Required", "Shares", "Capabilities"]]
        for srv in summary.servers:
            dialects = _preview_values(srv.dialects, limit=3, max_len=50)
            signing = "Yes" if srv.signing_required else ("No" if srv.signing_required is not None else "-")
            if effective_verbose:
                shares = _preview_values(srv.shares, limit=_FULL_OUTPUT_LIMIT, max_len=_FULL_OUTPUT_LIMIT, show_count=False)
                caps = _preview_values(srv.capabilities, limit=_FULL_OUTPUT_LIMIT, max_len=_FULL_OUTPUT_LIMIT, show_count=False)
            else:
                shares = _preview_values(srv.shares, limit=1, max_len=80)
                caps = _preview_values(srv.capabilities, limit=3, max_len=60)
            rows.append([srv.ip, dialects, signing, shares, caps])
        lines.append(_format_table(rows))

    # 7. Client Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Clients"))
    if not summary.clients:
        lines.append(muted("No SMB clients identified."))
    else:
        rows = [["Client", "Dialects", "Client GUID", "Users", "Domains"]]
        filtered_notice = False
        for cli in summary.clients:
            dialects = _preview_values(cli.dialects, limit=3, max_len=50)
            guid = cli.client_guid or "-"
            if effective_verbose:
                users = _preview_values(cli.usernames, limit=_FULL_OUTPUT_LIMIT, max_len=_FULL_OUTPUT_LIMIT, show_count=False)
                domains = _preview_values(cli.domains, limit=_FULL_OUTPUT_LIMIT, max_len=_FULL_OUTPUT_LIMIT, show_count=False)
                users_filtered = False
                domains_filtered = False
            else:
                users, users_filtered = _smb_preview_tokens(cli.usernames, limit=3, max_len=60)
                domains, domains_filtered = _smb_preview_tokens(cli.domains, limit=3, max_len=60)
                if users_filtered or domains_filtered:
                    filtered_notice = True
            rows.append([cli.ip, dialects, guid, users, domains])
        lines.append(_format_table(rows))
        noisy_clients = [
            cli.ip for cli in summary.clients
            if (len(getattr(cli, "usernames", [])) > 20 or len(getattr(cli, "domains", [])) > 20)
        ]
        if noisy_clients:
            if not effective_verbose:
                lines.append(muted("Large user/domain lists may include noisy string extraction; use -v for full lists."))
        if filtered_notice:
            if not effective_verbose:
                lines.append(muted("User/domain previews are filtered for readable tokens; use -v for raw lists."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Usernames"))
    if summary.observed_users:
        rows = [["Username", "Count"]]
        for name, count in summary.observed_users.most_common(_limit_value(25)):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No SMB usernames discovered."))

    discovered_hosts = Counter()
    for sess in summary.sessions:
        workstation = getattr(sess, "workstation", None)
        if workstation:
            discovered_hosts[str(workstation)] += 1
    for cli in summary.clients:
        for workstation in getattr(cli, "workstations", []) or []:
            if workstation not in discovered_hosts:
                discovered_hosts[str(workstation)] += 1
    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Hostnames"))
    if discovered_hosts:
        rows = [["Hostname", "Count"]]
        for name, count in discovered_hosts.most_common(_limit_value(25)):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No SMB hostnames discovered."))

    # 8. Sessions
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Sessions"))
    if not summary.sessions:
        lines.append(muted("No SMB sessions decoded."))
    else:
        client_user_map = {}
        client_domain_map = {}
        client_workstation_map = {}
        client_workstation_candidates = {}
        for cli in summary.clients:
            if len(cli.usernames) == 1:
                client_user_map[cli.ip] = next(iter(cli.usernames))
            if len(cli.domains) == 1:
                client_domain_map[cli.ip] = next(iter(cli.domains))
            if getattr(cli, "workstations", None) and len(cli.workstations) == 1:
                client_workstation_map[cli.ip] = next(iter(cli.workstations))
            if getattr(cli, "workstation_candidates", None):
                client_workstation_candidates[cli.ip] = list(cli.workstation_candidates)
        rows = [[
            "Client",
            "Server",
            "Session",
            "Version",
            "User",
            "Domain",
            "Workstation",
            "Auth",
            "Signing Req",
            "Signing Used",
            "Encrypt Req",
            "Encrypted",
            "Packets",
            "Bytes",
            "First Seen",
            "Last Seen",
            "Duration",
        ]]
        for sess in summary.sessions:
            display_user = sess.username or client_user_map.get(sess.client_ip) or "-"
            display_domain = sess.domain or client_domain_map.get(sess.client_ip) or "-"
            display_workstation = sess.workstation or client_workstation_map.get(sess.client_ip) or "-"
            signed_used = "-"
            if getattr(sess, "signed_packets", 0) and getattr(sess, "unsigned_packets", 0):
                signed_used = "Mixed"
            elif getattr(sess, "signed_packets", 0):
                signed_used = "Yes"
            elif getattr(sess, "unsigned_packets", 0):
                signed_used = "No"
            encrypt_req = "Yes" if getattr(sess, "encryption_required", None) else ("No" if sess.encryption_required is not None else "-")
            encrypted = "Yes" if getattr(sess, "encrypted", False) else "No"
            duration = None
            if sess.start_ts and sess.last_seen:
                duration = max(0.0, sess.last_seen - sess.start_ts)
            rows.append([
                sess.client_ip,
                sess.server_ip,
                str(sess.session_id) if sess.session_id is not None else "-",
                sess.smb_version or "-",
                _truncate_text(_redact_in_text(str(display_user)), 30) if display_user else "-",
                _truncate_text(_redact_in_text(str(display_domain)), 30) if display_domain else "-",
                _truncate_text(_redact_in_text(str(display_workstation)), 30) if display_workstation else "-",
                _truncate_text(_redact_in_text(str(sess.auth_type)), 20) if sess.auth_type else "-",
                "Yes" if sess.signing_required else ("No" if sess.signing_required is not None else "-"),
                signed_used,
                encrypt_req,
                encrypted,
                str(sess.packets),
                format_bytes_as_mb(sess.bytes) if sess.bytes else "-",
                format_ts(sess.start_ts if sess.start_ts else None),
                format_ts(sess.last_seen if sess.last_seen else None),
                format_duration(duration),
            ])
        lines.append(_format_table(rows))

        if verbose and client_workstation_candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Workstation Candidates (Raw)"))
            rows = [["Client", "Candidates"]]
            for ip in sorted(client_workstation_candidates.keys()):
                candidates = sorted(client_workstation_candidates.get(ip, []))
                preview = ", ".join(_truncate_text(_redact_in_text(c), 30) for c in candidates[:_limit_value(10)])
                if len(candidates) > _limit_value(10):
                    preview += f" (+{len(candidates) - _limit_value(10)} more)"
                rows.append([ip, preview or "-"])
            lines.append(_format_table(rows))

    # 9. Files and Artifacts
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Files & Artifacts"))
    if summary.files:
        suspicious_ext = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr", ".sys", ".lnk", ".zip", ".rar", ".7z"}
        known_ops: dict[tuple[str, str, str, str], dict[str, object]] = {}
        unknown_ops: dict[tuple[str, str, str, str], dict[str, object]] = {}

        def _is_unknown(name: str | None) -> bool:
            if not name:
                return True
            lowered = name.lower()
            return lowered.startswith("(unknown") or lowered in {"-", "unknown"}

        for item in summary.files:
            filename = item.filename or "(unknown)"
            share = item.share or "-"
            client = item.client_ip or "-"
            server = item.server_ip or "-"
            size = int(item.size or 0)
            ts = item.ts or 0.0
            action = item.action or "Op"
            file_id = item.file_id or ""
            if _is_unknown(filename):
                ukey = (action, share, client, server)
                entry = unknown_ops.setdefault(ukey, {
                    "action": action,
                    "share": share,
                    "client": client,
                    "server": server,
                    "count": 0,
                    "bytes": 0,
                    "first_ts": None,
                    "last_ts": None,
                    "file_ids": set(),
                })
                entry["count"] = int(entry["count"]) + 1
                entry["bytes"] = int(entry["bytes"]) + size
                if file_id:
                    entry["file_ids"].add(file_id)
                first_ts = entry["first_ts"]
                last_ts = entry["last_ts"]
                if first_ts is None or (ts and ts < first_ts):
                    entry["first_ts"] = ts
                if last_ts is None or (ts and ts > last_ts):
                    entry["last_ts"] = ts
                continue

            key = (filename, share, client, server)
            entry = known_ops.setdefault(key, {
                "filename": filename,
                "share": share,
                "client": client,
                "server": server,
                "actions": Counter(),
                "bytes": 0,
                "file_ids": set(),
                "first_ts": None,
                "last_ts": None,
            })
            entry["actions"][action] += 1
            entry["bytes"] = int(entry["bytes"]) + size
            if item.file_id:
                entry["file_ids"].add(item.file_id)
            first_ts = entry["first_ts"]
            last_ts = entry["last_ts"]
            if first_ts is None or (ts and ts < first_ts):
                entry["first_ts"] = ts
            if last_ts is None or (ts and ts > last_ts):
                entry["last_ts"] = ts

        if known_ops or unknown_ops:
            lines.append(muted("File Operations (Aggregated)"))
            rows = [["File", "Share", "Activity", "Bytes", "Client", "Server", "First Seen", "Last Seen", "File IDs", "Flags"]]
            def _known_sort(entry: dict[str, object]) -> tuple[int, int]:
                total_bytes = int(entry.get("bytes", 0))
                action_count = sum(int(v) for v in entry.get("actions", Counter()).values())
                return (total_bytes, action_count)

            for entry in sorted(known_ops.values(), key=_known_sort, reverse=True)[:_limit_value(20)]:
                actions = entry.get("actions", Counter())
                action_text = ", ".join(
                    f"{name} x{count}" for name, count in actions.most_common(3)
                ) if actions else "-"
                if actions and len(actions) > 3:
                    action_text += " …"
                filename = str(entry.get("filename", "-"))
                share = str(entry.get("share", "-"))
                flags: list[str] = []
                lower_name = filename.lower()
                if any(lower_name.endswith(ext) for ext in suspicious_ext):
                    flags.append("SuspiciousExt")
                if "admin$" in share.lower() or "ipc$" in share.lower() or share.lower().endswith("\\c$"):
                    flags.append("AdminShare")
                if "\\pipe\\" in lower_name:
                    flags.append("NamedPipe")
                flag_text = ", ".join(flags) if flags else "-"
                file_ids = sorted(entry.get("file_ids", set()))
                file_id_text = ", ".join(file_ids[:3]) if file_ids else "-"
                if len(file_ids) > 3:
                    file_id_text += f" (+{len(file_ids) - 3} more)"
                rows.append([
                    _truncate_text(_redact_in_text(filename), 80),
                    _truncate_text(_redact_in_text(share), 60),
                    action_text,
                    format_bytes_as_mb(int(entry.get("bytes", 0))) if entry.get("bytes") else "-",
                    entry.get("client", "-"),
                    entry.get("server", "-"),
                    format_ts(entry.get("first_ts")),
                    format_ts(entry.get("last_ts")),
                    _truncate_text(file_id_text, 60),
                    flag_text,
                ])

            if unknown_ops:
                def _unknown_sort(entry: dict[str, object]) -> tuple[int, int]:
                    return (int(entry.get("bytes", 0)), int(entry.get("count", 0)))
                for entry in sorted(unknown_ops.values(), key=_unknown_sort, reverse=True)[:_limit_value(15)]:
                    file_ids = sorted(entry.get("file_ids", set()))
                    file_id_text = ", ".join(file_ids[:3]) if file_ids else "-"
                    if len(file_ids) > 3:
                        file_id_text += f" (+{len(file_ids) - 3} more)"
                    rows.append([
                        "(unknown)",
                        _truncate_text(_redact_in_text(str(entry.get("share", "-"))), 50),
                        f"{entry.get('action', '-') } x{entry.get('count', 0)}",
                        format_bytes_as_mb(int(entry.get("bytes", 0))) if entry.get("bytes") else "-",
                        entry.get("client", "-"),
                        entry.get("server", "-"),
                        format_ts(entry.get("first_ts")),
                        format_ts(entry.get("last_ts")),
                        _truncate_text(file_id_text, 60),
                        "UnknownName",
                    ])

            lines.append(_format_table(rows))

        if not known_ops and not unknown_ops:
            lines.append(muted("No SMB file operations extracted."))
    else:
        lines.append(muted("No SMB file operations extracted."))

    if summary.artifacts:
        pipes = [item for item in summary.artifacts if "\\pipe\\" in str(item).lower()]
        other = [item for item in summary.artifacts if item not in pipes]
        if pipes:
            pipe_text = ", ".join(
                _truncate_text(_redact_in_text(str(item)), 80)
                for item in pipes[:_limit_value(10)]
            )
            lines.append(muted(f"Named Pipes: {pipe_text}"))
        if other:
            safe_artifacts = ", ".join(
                _truncate_text(_redact_in_text(str(item)), 80)
                for item in other[:_limit_value(15)]
            )
            lines.append(muted(f"Artifacts: {safe_artifacts}"))

    # 10. Users & Domains
    if summary.observed_users or summary.observed_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users & Domains"))
        if summary.observed_users:
            rows = [["User", "Count"]]
            for user, count in summary.observed_users.most_common(_limit_value(10)):
                rows.append([user, str(count)])
            lines.append(_format_table(rows))
        if summary.observed_domains:
            rows = [["Domain", "Count"]]
            for domain, count in summary.observed_domains.most_common(_limit_value(10)):
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
                    f"{title} ({count})" for title, count in indicators.most_common(_limit_value(5))
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
        top_scores = sorted(summary.lateral_movement, key=lambda x: x.get("score", 0), reverse=True)[:_limit_value(5)]
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
            for item in summary.lateral_movement[:_limit_value(10)]:
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
        for proc, count in summary.procedures.most_common(_limit_value(12)):
            rows.append([proc, str(count)])
        lines.append(_format_table(rows))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NFS Status Codes"))
        rows = [["Status", "Count"]]
        for code, count in summary.status_codes.most_common(_limit_value(12)):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Sessions"))
    if not summary.conversations:
        lines.append(muted("No NFS sessions summarized."))
    else:
        lines.append(
            _format_sessions_table(
                summary.conversations,
                _limit_value(10),
                extra_cols=[
                    ("Requests", lambda c: _conv_value(c, "requests") or 0),
                    ("Responses", lambda c: _conv_value(c, "responses") or 0),
                ],
            )
        )

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
        for item in summary.files[:_limit_value(20)]:
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
        lines.append(muted("Artifacts: " + ", ".join(summary.artifacts[:_limit_value(25)])))

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for user, count in summary.observed_users.most_common(_limit_value(10)):
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

    lines.append(_format_kv("Query", ok(summary.query)))
    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("Matches", str(summary.matches)))
    if summary.truncated:
        lines.append(warn(f"[WARN] Showing first {len(summary.hits)} matches."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Match Details"))
    if not summary.hits:
        lines.append(muted("No matches found."))
    else:
        header_row = ["Pkt", "Time", "Src", "Dst", "Proto", "Sport", "Dport", "Len"]
        data_rows = []
        for hit in summary.hits:
            data_rows.append([
                str(hit.packet_number),
                format_ts(hit.ts),
                hit.src_ip,
                hit.dst_ip,
                hit.protocol,
                str(hit.src_port) if hit.src_port is not None else "-",
                str(hit.dst_port) if hit.dst_port is not None else "-",
                str(hit.payload_len),
            ])

        def _visible_len(text: str) -> int:
            return len(re.sub(r"\x1b\[[0-9;]*m", "", text))

        rows = [header_row] + data_rows
        widths = [max(_visible_len(row[i]) for row in rows) for i in range(len(header_row))]

        def _format_row(row: list[str]) -> str:
            parts = []
            for idx, value in enumerate(row):
                pad = widths[idx] - _visible_len(value)
                parts.append(value + (" " * max(0, pad)))
            return "  ".join(parts)

        lines.append(_format_row(header_row))
        context_indent = " " * (widths[0] + 2)
        for hit, row in zip(summary.hits, data_rows):
            lines.append(_format_row(row))
            context_text = _truncate_text(hit.context, 80)
            if context_text:
                context_text = _highlight_search_text(context_text, summary.query)
                context_lines = context_text.splitlines() or [""]
                label_text = "Context: "
                lines.append(f"{context_indent}{label_text}{context_lines[0]}")
                continuation_indent = context_indent + (" " * len(label_text))
                for extra_line in context_lines[1:]:
                    lines.append(f"{continuation_indent}{extra_line}")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_search_rollup(summaries: Iterable[SearchSummary], limit: int = 20) -> str:
    limit = _apply_verbose_limit(limit)
    summary_list = list(summaries)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SEARCH RESULTS :: ALL PCAPS ({len(summary_list)})"))
    lines.append(SECTION_BAR)

    if not summary_list:
        lines.append(muted("No search summaries to aggregate."))
        lines.append(SECTION_BAR)
        return _finalize_output(lines)

    query_counts: Counter[str] = Counter()
    total_packets = 0
    total_matches = 0
    total_hits = 0
    truncated_pcaps = 0
    all_errors: list[str] = []
    rows = [["PCAP", "Matches", "Packets", "Shown Hits", "Errors"]]

    for summary in summary_list:
        query_counts.update([summary.query])
        total_packets += summary.total_packets
        total_matches += summary.matches
        total_hits += len(summary.hits)
        if summary.truncated:
            truncated_pcaps += 1
        err_count = len(summary.errors)
        rows.append([
            summary.path.name,
            str(summary.matches),
            str(summary.total_packets),
            str(len(summary.hits)),
            str(err_count),
        ])
        for err in summary.errors:
            all_errors.append(f"{summary.path.name}: {err}")

    query = query_counts.most_common(_limit_value(1))[0][0] if query_counts else "-"
    lines.append(_format_kv("Query", ok(query) if query != "-" else query))
    lines.append(_format_kv("PCAPs Analyzed", str(len(summary_list))))
    lines.append(_format_kv("Packets Scanned", str(total_packets)))
    lines.append(_format_kv("Total Matches", str(total_matches)))
    lines.append(_format_kv("Shown Hits", str(total_hits)))
    lines.append(_format_kv("Truncated PCAPs", str(truncated_pcaps)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Per-PCAP Match Totals"))
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Match Details"))
    detail_rows = [["PCAP", "Pkt", "Time", "Src", "Dst", "Proto", "Sport", "Dport", "Len", "Context"]]
    for summary in sorted(summary_list, key=lambda item: item.matches, reverse=True):
        for hit in summary.hits:
            if len(detail_rows) > limit:
                break
            detail_rows.append([
                summary.path.name,
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
        if len(detail_rows) > limit:
            break

    if len(detail_rows) == 1:
        lines.append(muted("No matches found."))
    else:
        lines.append(_format_table(detail_rows))
        shown = len(detail_rows) - 1
        if shown < total_hits:
            lines.append(warn(f"[WARN] Showing first {shown} hit rows across all pcaps."))

    if all_errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in all_errors[:_limit_value(25)]:
            lines.append(danger(f"- {err}"))
        if len(all_errors) > 25:
            lines.append(muted(f"... {len(all_errors) - 25} more errors"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_creds_summary(summary: CredentialSummary, show_secrets: bool = False) -> str:
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
        for kind, count in summary.kind_counts.most_common(_limit_value(15)):
            rows.append([kind, str(count)])
        lines.append(_format_table(rows))

    if summary.user_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for user, count in summary.user_counts.most_common(_limit_value(15)):
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
            secret_value = hit.secret if show_secrets else _redact_secret(hit.secret)
            evidence_value = hit.evidence if show_secrets else _redact_in_text(hit.evidence)
            line = f"  Kind: {hit.kind} | User: {hit.username or '-'} | Secret: {secret_value}"
            if evidence_value:
                line = f"{line} | Evidence: {evidence_value}"
            lines.append(line)
            lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_secrets_summary(summary: SecretsSummary, show_secrets: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SECRET DISCOVERY :: {summary.path.name}"))
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
        for kind, count in summary.kind_counts.most_common(_limit_value(12)):
            rows.append([kind, str(count)])
        lines.append(_format_table(rows))

    if summary.truncated:
        lines.append(warn(f"[WARN] Showing first {len(summary.hits)} matches."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Findings"))
    if not summary.hits:
        lines.append(muted("No reversible obfuscated secrets detected."))
    else:
        rows = [["Type", "Secret", "Cleartext", "Location", "Src", "Dst", "Proto", "Note"]]
        for hit in summary.hits:
            secret_value = hit.encoded if show_secrets else _redact_secret(hit.encoded)
            clear_value = hit.decoded if show_secrets else _redact_secret(hit.decoded)
            loc_parts = [f"pkt {hit.packet_number}"]
            if hit.offset is not None:
                loc_parts.append(f"@{hit.offset}")
            if hit.ts is not None:
                loc_parts.append(format_ts(hit.ts))
            location = " ".join(loc_parts)
            src = hit.src_ip
            dst = hit.dst_ip
            if hit.src_port is not None:
                src = f"{src}:{hit.src_port}"
            if hit.dst_port is not None:
                dst = f"{dst}:{hit.dst_port}"
            rows.append([
                hit.kind,
                _truncate_text(secret_value, 48),
                _truncate_text(clear_value, 64),
                location,
                src,
                dst,
                hit.protocol,
                _truncate_text(hit.note or "-", 40),
            ])
        lines.append(_format_table(rows))

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
        for subj, count in summary.subjects.most_common(_limit_value(10)):
            rows.append([subj, str(count)])
        lines.append(_format_table(rows))

    if summary.issuers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Issuers"))
        rows = [["Issuer", "Count"]]
        for issuer, count in summary.issuers.most_common(_limit_value(10)):
            rows.append([issuer, str(count)])
        lines.append(_format_table(rows))

    if summary.sas:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top SANs"))
        rows = [["SAN", "Count"]]
        for name, count in summary.sas.most_common(_limit_value(10)):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.weak_keys:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Weak Keys"))
        rows = [["Subject", "Key Size", "Src", "Dst"]]
        for item in summary.weak_keys[:_limit_value(10)]:
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
        for item in summary.expired[:_limit_value(10)]:
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
        for item in summary.self_signed[:_limit_value(10)]:
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
        for cert in summary.artifacts[:_limit_value(10)]:
            rows.append([
                cert.subject,
                cert.issuer,
                cert.not_after,
                f"{cert.pubkey_type} {cert.pubkey_size}",
                cert.sha256[:_limit_value(32)] + "...",
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
        for ip, byte_count in endpoint_bytes.most_common(_limit_value(10)):
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
        top_zero = ", ".join(f"{ip}({count})" for ip, count in summary.tcp_zero_window_sources.most_common(_limit_value(5)))
        lines.append(_format_kv("Zero-Window Sources", top_zero))
    if summary.tcp_rst_sources:
        top_rst = ", ".join(f"{ip}({count})" for ip, count in summary.tcp_rst_sources.most_common(_limit_value(5)))
        lines.append(_format_kv("RST Sources", top_rst))
    if summary.udp_amp_candidates:
        lines.append(_format_kv("UDP Amplification", str(len(summary.udp_amp_candidates))))
        lines.append(_format_kv("Top Candidates", ", ".join(summary.udp_amp_candidates[:_limit_value(5)])))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Quality of Service (DSCP/ECN)"))
    top_dscp = ", ".join(f"{dscp}({count})" for dscp, count in summary.dscp_counts.most_common(_limit_value(5))) or "-"
    top_ecn = ", ".join(f"{ecn}({count})" for ecn, count in summary.ecn_counts.most_common(_limit_value(5))) or "-"
    lines.append(_format_kv("Top DSCP", top_dscp))
    lines.append(_format_kv("Top ECN", top_ecn))

    lines.append(SUBSECTION_BAR)
    lines.append(header("SNMP"))
    lines.append(_format_kv("SNMP Packets", str(summary.snmp_packets)))
    versions = ", ".join(f"{ver}({count})" for ver, count in summary.snmp_versions.most_common(_limit_value(5))) or "-"
    communities = ", ".join(f"{comm}({count})" for comm, count in summary.snmp_communities.most_common(_limit_value(5))) or "-"
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


def render_compromised_summary(summary: CompromiseSummary, limit: int = 20, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"COMPROMISE ASSESSMENT :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in (summary.errors if verbose else summary.errors[:_limit_value(20)]):
            lines.append(danger(f"- {err}"))
        if not verbose and len(summary.errors) > 20:
            lines.append(muted(f"... {len(summary.errors) - 20} more errors"))

    lines.append(_format_kv("Total Hosts", str(summary.total_hosts)))
    lines.append(_format_kv("Compromised Hosts", str(len(summary.compromised_hosts))))

    if not summary.compromised_hosts:
        lines.append(SUBSECTION_BAR)
        lines.append(ok("No hosts met compromise thresholds based on available evidence."))
        lines.append(SECTION_BAR)
        return _finalize_output(lines)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Compromised Hosts"))
    rows = [["Hostname", "IP", "Detection Time", "Explanation", "Evidence", "IOCs"]]
    row_hosts = summary.compromised_hosts if verbose else summary.compromised_hosts[:limit]
    for host in row_hosts:
        evidence_text = " | ".join(host.evidence[:3]) if host.evidence else "-"
        ioc_text = ", ".join(host.iocs[:4]) if host.iocs else "-"
        rows.append([
            host.hostname or "-",
            host.ip,
            format_ts(host.detection_time),
            _truncate_text(host.explanation or "-", 60),
            _truncate_text(evidence_text, 70),
            _truncate_text(ioc_text, 60),
        ])
    lines.append(_format_table(rows))
    if not verbose and len(summary.compromised_hosts) > limit:
        lines.append(muted(f"... {len(summary.compromised_hosts) - limit} additional compromised hosts"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Forensics Notes"))
    lines.append(muted("- Compromise assessment is heuristic and should be validated with endpoint telemetry."))
    lines.append(muted("- Evidence and IOCs are extracted from high-signal detections (beaconing, exfil, creds, threats)."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_hosts_summary(summary: HostSummary, limit: int = 30, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"HOST INVENTORY :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in (summary.errors if verbose else summary.errors[:_limit_value(20)]):
            lines.append(danger(f"- {err}"))
        if not verbose and len(summary.errors) > 20:
            lines.append(muted(f"... {len(summary.errors) - 20} more errors"))

    total_hosts = summary.total_hosts or len(summary.hosts)
    with_macs = sum(1 for host in summary.hosts if host.mac_addresses)
    with_hostnames = sum(1 for host in summary.hosts if host.hostnames)
    with_os = sum(
        1
        for host in summary.hosts
        if host.operating_system and host.operating_system.lower() != "unknown"
    )
    total_bytes = sum(host.bytes_sent + host.bytes_recv for host in summary.hosts)

    lines.append(_format_kv("Total Hosts", str(total_hosts)))
    lines.append(_format_kv("Hosts w/ MAC", str(with_macs)))
    lines.append(_format_kv("Hosts w/ Hostname", str(with_hostnames)))
    lines.append(_format_kv("Hosts w/ OS Guess", str(with_os)))
    lines.append(_format_kv("Total Host Traffic", format_bytes_as_mb(total_bytes)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Host Table"))
    if not summary.hosts:
        lines.append(muted("No host entries discovered in the capture."))
    else:
        rows = [["IP", "MAC", "Hostname", "OS", "Sent", "Recv", "Open Ports"]]

        def _join_limited(values: list[str], max_items: int, max_len: int) -> str:
            if not values:
                return "-"
            display = ", ".join(values[:max_items])
            if len(values) > max_items:
                display += "..."
            return _truncate_text(display, max_len)

        def _format_ports(ports: list[object]) -> str:
            if not ports:
                return "-"
            entries: list[str] = []
            for port in ports:
                proto = str(getattr(port, "protocol", "") or "").lower() or "-"
                service = str(getattr(port, "service", "") or "-")
                label_text = f"{int(getattr(port, 'port', 0) or 0)}/{proto} {service}"
                if verbose:
                    software = str(getattr(port, "software", "") or "")
                    if software:
                        label_text = f"{label_text} ({software})"
                entries.append(label_text)
            port_limit = _limit_value(6)
            display = ", ".join(_truncate_text(item, 48) for item in entries[:port_limit])
            if len(entries) > port_limit:
                display += "..."
            return display or "-"

        row_hosts = summary.hosts if verbose else summary.hosts[:limit]
        for host in row_hosts:
            mac_display = _join_limited(host.mac_addresses, _limit_value(3), 48)
            host_display = _join_limited(host.hostnames, _limit_value(3), 48)
            os_display = _truncate_text(host.operating_system or "Unknown", 28)
            sent_display = f"{format_bytes_as_mb(host.bytes_sent)} ({host.packets_sent})"
            recv_display = f"{format_bytes_as_mb(host.bytes_recv)} ({host.packets_recv})"
            ports_display = _format_ports(host.open_ports)
            rows.append([
                host.ip,
                mac_display,
                host_display,
                os_display,
                sent_display,
                recv_display,
                ports_display,
            ])
        lines.append(_format_table(rows))
        if not verbose and len(summary.hosts) > limit:
            lines.append(muted(f"... {len(summary.hosts) - limit} additional hosts"))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OS Evidence"))
        evidence_rows = [["IP", "OS Guess", "Evidence"]]
        for host in summary.hosts:
            if not host.os_evidence:
                continue
            evidence_rows.append([
                host.ip,
                host.operating_system or "Unknown",
                _truncate_text(" | ".join(host.os_evidence), 120),
            ])
        if len(evidence_rows) == 1:
            lines.append(muted("No OS fingerprinting evidence captured for hosts."))
        else:
            lines.append(_format_table(evidence_rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Forensics Notes"))
    lines.append(muted("- OS guesses are passive and should be confirmed with endpoint telemetry."))
    lines.append(muted("- Open ports are inferred from server-side responses or banners; absence does not imply closed."))
    lines.append(muted("- MACs are derived from IP/Ethernet/ARP mapping and can change across segments."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_hostname_summary(summary: HostnameSummary, limit: int = 25, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    all_ip_mode = not bool(summary.target_ip)
    lines.append(SECTION_BAR)
    lines.append(header(f"HOSTNAME DISCOVERY :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        error_rows = summary.errors if verbose else summary.errors[:_limit_value(25)]
        for err in error_rows:
            lines.append(danger(f"- {err}"))
        if not verbose and len(summary.errors) > 25:
            lines.append(muted(f"... {len(summary.errors) - 25} more errors"))

    lines.append(_format_kv("Target IP", summary.target_ip or "ALL"))
    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("Relevant Packets", str(summary.relevant_packets)))
    lines.append(_format_kv("Hostnames Found", str(len({item.hostname for item in summary.findings}))))
    lines.append(_format_kv("Evidence Rows", str(sum(item.count for item in summary.findings))))

    if summary.protocol_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Evidence"))
        rows = [["Protocol", "Count"]]
        proto_limit = None if verbose else 10
        for proto, count in summary.protocol_counts.most_common(proto_limit):
            rows.append([str(proto), str(count)])
        lines.append(_format_table(rows))

    if summary.method_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovery Methods"))
        rows = [["Method", "Count"]]
        method_limit = None if verbose else 12
        for method, count in summary.method_counts.most_common(method_limit):
            rows.append([str(method), str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("IP ↔ Hostname Correlation"))
    if not summary.findings:
        lines.append(muted("No hostname-to-IP correlation evidence found in inspected protocols."))
    else:
        ip_hosts: dict[str, set[str]] = defaultdict(set)
        ip_evidence: Counter[str] = Counter()
        for finding in summary.findings:
            if not finding.mapped_ip:
                continue
            ip_hosts[finding.mapped_ip].add(finding.hostname)
            ip_evidence[finding.mapped_ip] += finding.count

        if not ip_hosts:
            lines.append(muted("No attributable IP mappings were extracted from hostname evidence."))
        else:
            rows = [["IP Address", "Hostnames", "Evidence"]]
            corr_limit = None if verbose else limit
            for ip_addr, evidence_count in ip_evidence.most_common(corr_limit):
                hosts = sorted(ip_hosts.get(ip_addr, set()))
                host_display = ", ".join(hosts) if verbose else ", ".join(hosts[:_limit_value(3)])
                rows.append([ip_addr, host_display, str(evidence_count)])
            lines.append(_format_table(rows))
            if not verbose and len(ip_evidence) > limit:
                lines.append(muted(f"... {len(ip_evidence) - limit} additional IP correlation rows"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Hostnames"))
    if not summary.findings:
        if all_ip_mode:
            lines.append(muted("No hostname evidence found in inspected protocols."))
        else:
            lines.append(muted("No hostname evidence found for target IP in inspected protocols."))
    else:
        rows = [["Hostname", "Mapped IP", "Method", "Protocol", "Confidence", "Seen", "Flow", "Details"]]
        row_findings = summary.findings if verbose else summary.findings[:limit]
        for finding in row_findings:
            confidence = str(finding.confidence)
            if confidence == "HIGH":
                confidence_display = ok(confidence)
            elif confidence == "MEDIUM":
                confidence_display = warn(confidence)
            else:
                confidence_display = muted(confidence)

            rows.append([
                str(finding.hostname),
                str(finding.mapped_ip or "-"),
                str(finding.method),
                str(finding.protocol),
                confidence_display,
                str(finding.count),
                f"{finding.src_ip} -> {finding.dst_ip}",
                str(finding.details) if verbose else _truncate_text(str(finding.details), 70),
            ])
        lines.append(_format_table(rows))
        if not verbose and len(summary.findings) > limit:
            lines.append(muted(f"... {len(summary.findings) - limit} additional hostname evidence rows"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Forensics Notes"))
    lines.append(muted("- DNS A/AAAA and PTR mappings are strongest hostname-to-IP attribution evidence."))
    lines.append(muted("- HTTP Host and TLS SNI indicate intended server name and can reveal virtual-host targeting."))
    lines.append(muted("- NTLM/NetBIOS names are contextual clues and may reflect client/workstation naming."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_hostdetails_summary(summary: HostDetailsSummary, limit: int = 20, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"HOST DETAILS :: {summary.target_ip} :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    target_ip = summary.target_ip

    def _matches_target(value: object) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return target_ip in value
        if isinstance(value, (list, tuple, set)):
            return any(_matches_target(item) for item in value)
        if isinstance(value, dict):
            return any(_matches_target(item) for item in value.values())
        return target_ip in str(value)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in (summary.errors if verbose else summary.errors[:_limit_value(20)]):
            lines.append(danger(f"- {err}"))
        if not verbose and len(summary.errors) > 20:
            lines.append(muted(f"... {len(summary.errors) - 20} more errors"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Host Details"))
    lines.append(_format_kv("IP Address", summary.target_ip))
    lines.append(_format_kv("Associated MAC", ", ".join(summary.mac_addresses[:_limit_value(6)]) if summary.mac_addresses else "-"))
    lines.append(_format_kv("Operating System", summary.operating_system or "Unknown"))
    lines.append(_format_kv("OS Evidence", " | ".join(summary.os_evidence[:_limit_value(4)]) if summary.os_evidence else "-"))
    lines.append(_format_kv("Hostname", ", ".join(summary.hostnames[:_limit_value(8)]) if summary.hostnames else "-"))
    if summary.relevant_packets == 0:
        lines.append(warn("No host-relevant packets matched the target IP in this capture. Results may be incomplete."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Hostname Evidence"))
    hostname_findings = [item for item in summary.hostname_findings if _matches_target(item)]
    if hostname_findings:
        rows = [["Hostname", "Mapped IP", "Method", "Protocol", "Confidence", "Seen", "Flow", "Details"]]
        row_findings = hostname_findings if verbose else hostname_findings[:limit]
        for finding in row_findings:
            confidence = str(finding.get("confidence", ""))
            if confidence == "HIGH":
                confidence_display = ok(confidence)
            elif confidence == "MEDIUM":
                confidence_display = warn(confidence)
            else:
                confidence_display = muted(confidence or "-")
            flow = f"{finding.get('src_ip', '-')} -> {finding.get('dst_ip', '-')}"
            rows.append([
                _truncate_text(str(finding.get("hostname", "-")), 40),
                str(finding.get("mapped_ip", "-")),
                _truncate_text(str(finding.get("method", "-")), 28),
                str(finding.get("protocol", "-")),
                confidence_display,
                str(finding.get("count", "-")),
                _truncate_text(flow, 36),
                _truncate_text(_redact_in_text(str(finding.get("details", "-"))), 70),
            ])
        lines.append(_format_table(rows))
        if not verbose and len(hostname_findings) > limit:
            lines.append(muted(f"... {len(hostname_findings) - limit} additional hostname evidence rows"))
    else:
        lines.append(muted("No hostname evidence found for target IP in inspected protocols."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Services Discovered"))
    services = [item for item in summary.services if _matches_target(item)]
    if services:
        rows = [["Role", "Asset", "Service", "Proto", "Packets", "Bytes", "Peers", "Software"]]
        for item in (services if verbose else services[:limit]):
            rows.append([
                str(item.get("role", "-")),
                str(item.get("asset", "-")),
                str(item.get("service", "-")),
                str(item.get("protocol", "-")),
                str(item.get("packets", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0) or 0)),
                str(item.get("peers", "-")),
                str(item.get("software", "-")),
            ])
        lines.append(_format_table(rows))
        if not verbose and len(services) > limit:
            lines.append(muted(f"... {len(services) - limit} additional service rows"))
    else:
        lines.append(muted("No services discovered for target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("User Evidence"))
    user_evidence = [item for item in summary.user_evidence if _matches_target(item)]
    if user_evidence:
        rows = [["User", "Domain", "Full Name", "Method", "Location", "Details"]]
        evidence_rows = user_evidence if verbose else user_evidence[:limit]
        for item in evidence_rows:
            rows.append([
                str(item.get("username", "-")),
                str(item.get("domain", "-")),
                str(item.get("full_name", "-")),
                str(item.get("method", "-")),
                str(item.get("location", "-")),
                str(item.get("details", "-")),
            ])
        lines.append(_format_table(rows))
        if not verbose and len(user_evidence) > limit:
            lines.append(muted(f"... {len(user_evidence) - limit} additional user evidence rows"))

        lines.append(SUBSECTION_BAR)
        lines.append(header("User Summary"))
        grouped_users: dict[tuple[str, str], set[str]] = {}
        grouped_fullnames: dict[tuple[str, str], set[str]] = {}
        grouped_counts: Counter[tuple[str, str]] = Counter()
        empty_tokens = {"", "-", "unknown", "n/a", "none"}
        for item in user_evidence:
            method = str(item.get("method", "-"))
            domain = str(item.get("domain", "-"))
            user = str(item.get("username", "-"))
            full_name = str(item.get("full_name", "-"))
            grouped_users.setdefault((method, domain), set()).add(user)
            if full_name.strip().lower() not in empty_tokens:
                grouped_fullnames.setdefault((method, domain), set()).add(full_name)
            grouped_counts[(method, domain)] += 1
        rows = [["Method", "Domain", "Users", "Full Names", "Evidence Rows"]]
        for (method, domain), count in grouped_counts.most_common():
            users = sorted(grouped_users.get((method, domain), set()))
            full_names = sorted(grouped_fullnames.get((method, domain), set()))
            user_value = users[0] if users else "-"
            name_value = full_names[0] if full_names else "-"
            rows.append([method, domain, user_value, name_value, str(count)])
            for idx in range(1, max(len(users), len(full_names))):
                next_user = f"  {users[idx]}" if idx < len(users) else ""
                next_name = f"  {full_names[idx]}" if idx < len(full_names) else ""
                rows.append(["", "", next_user, next_name, ""])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No usernames attributed to the target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Files Transferred"))
    file_transfers = [item for item in summary.file_transfers if _matches_target(item)]
    if file_transfers:
        rows = [["Direction", "Type", "Filename", "Size", "Proto", "Flow", "Details", "Hashes"]]
        transfer_rows = file_transfers if verbose else file_transfers[:limit]
        for item in transfer_rows:
            direction = str(item.get("direction", "-"))
            if direction == "upload":
                direction_display = warn(direction)
            elif direction == "download":
                direction_display = ok(direction)
            elif direction == "loopback":
                direction_display = muted(direction)
            else:
                direction_display = direction or "-"
            kind = str(item.get("kind", "-"))
            if kind == "artifact":
                kind_display = ok(kind)
            elif kind == "candidate":
                kind_display = muted(kind)
            else:
                kind_display = kind or "-"

            size_value = item.get("size_bytes") or item.get("bytes")
            size_text = format_bytes_as_mb(int(size_value)) if size_value else "-"
            proto = str(item.get("protocol", "-"))
            src_port = item.get("src_port")
            dst_port = item.get("dst_port")
            src_port_text = str(src_port) if src_port is not None else "-"
            dst_port_text = str(dst_port) if dst_port is not None else "-"
            flow = f"{item.get('src_ip', '-')}:{src_port_text} -> {item.get('dst_ip', '-')}:{dst_port_text}"

            details_bits: list[str] = []
            note = str(item.get("note", "") or "").strip()
            if note:
                details_bits.append(note)
            file_type = str(item.get("file_type", "") or "").strip()
            if file_type and file_type.upper() != "UNKNOWN":
                details_bits.append(f"type={file_type}")
            hostname = str(item.get("hostname", "") or "").strip()
            if hostname:
                details_bits.append(f"host={hostname}")
            content_type = str(item.get("content_type", "") or "").strip()
            if content_type:
                details_bits.append(f"content-type={content_type}")
            packets = item.get("packets")
            if packets is not None:
                details_bits.append(f"packets={packets}")
            packet_index = item.get("packet_index")
            if packet_index is not None:
                details_bits.append(f"pkt={packet_index}")
            first_seen = item.get("first_seen")
            last_seen = item.get("last_seen")
            if first_seen is not None:
                details_bits.append(f"first={format_ts(first_seen)}")
            if last_seen is not None and last_seen != first_seen:
                details_bits.append(f"last={format_ts(last_seen)}")
            details_text = " | ".join(details_bits) if details_bits else "-"

            hashes_bits: list[str] = []
            sha256 = str(item.get("sha256", "") or "").strip()
            if sha256:
                hashes_bits.append(f"sha256={sha256[:12]}")
            md5 = str(item.get("md5", "") or "").strip()
            if md5:
                hashes_bits.append(f"md5={md5[:8]}")
            hashes_text = " ".join(hashes_bits) if hashes_bits else "-"

            rows.append([
                direction_display,
                kind_display,
                _truncate_text(str(item.get("filename", "-")), 36),
                size_text,
                proto,
                _truncate_text(_redact_in_text(flow), 42),
                _truncate_text(_redact_in_text(details_text), 90),
                _truncate_text(hashes_text, 36),
            ])
        lines.append(_format_table(rows))
        if not verbose and len(file_transfers) > limit:
            lines.append(muted(f"... {len(file_transfers) - limit} additional file transfers"))
    else:
        lines.append(muted("No file transfers attributed to the target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Traffic Overview"))
    lines.append(_format_kv("Packets (PCAP)", str(summary.total_packets)))
    lines.append(_format_kv("Packets (Host Relevance)", str(summary.relevant_packets)))
    lines.append(_format_kv("Sent / Received", f"{summary.packets_sent} / {summary.packets_recv}"))
    lines.append(_format_kv("Bytes Sent", format_bytes_as_mb(summary.bytes_sent)))
    lines.append(_format_kv("Bytes Received", format_bytes_as_mb(summary.bytes_recv)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("DNS Queries Performed"))
    if summary.dns_queries:
        dns_items = [item for item in summary.dns_queries if _matches_target(item)]
        query_counts: Counter[str] = Counter()
        for item in dns_items:
            name = str(item.get("name", "-"))
            if name and name != "-":
                query_counts[name] += 1
        top_limit = 10
        if query_counts:
            lines.append(muted("Top 10 Most Queried"))
            rows = [["Query", "Count"]]
            for name, count in query_counts.most_common(top_limit):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))

            lines.append(muted("Top 10 Least Queried"))
            least = sorted(query_counts.items(), key=lambda kv: (kv[1], kv[0]))[:top_limit]
            rows = [["Query", "Count"]]
            for name, count in least:
                rows.append([name, str(count)])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No DNS queries attributed to the target IP."))
    else:
        lines.append(muted("No DNS queries attributed to the target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Remote Hosts (Top Peers)"))
    if summary.peer_counts:
        rows = [["Peer", "Hostname(s)", "Evidence Count"]]
        peer_hostnames: dict[str, set[str]] = {}
        for finding in summary.hostname_findings:
            src_ip = str(finding.get("src_ip", "") or "")
            dst_ip = str(finding.get("dst_ip", "") or "")
            hostname = str(finding.get("hostname", "") or "")
            if not hostname:
                continue
            mapped_ip = str(finding.get("mapped_ip", "") or "")
            if mapped_ip and mapped_ip != summary.target_ip:
                peer_hostnames.setdefault(mapped_ip, set()).add(hostname)
                continue
            for ip_value in {src_ip, dst_ip}:
                if not ip_value or ip_value == summary.target_ip:
                    continue
                peer_hostnames.setdefault(ip_value, set()).add(hostname)
        for peer, count in summary.peer_counts.most_common(limit):
            hostnames = ", ".join(sorted(peer_hostnames.get(peer, set()))[:3]) or "-"
            rows.append([peer, hostnames, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No peer connections attributed to the target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Activity"))
    if summary.protocol_counts:
        rows = [["Protocol", "Count"]]
        for proto, count in summary.protocol_counts.most_common(limit):
            rows.append([proto, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No protocol activity attributed to the target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Conversations"))
    if summary.conversations:
        conv_source = [item for item in summary.conversations if _matches_target(item)]
        conv_limit = 25 if not verbose else len(conv_source)
        conv_rows = conv_source if verbose else conv_source[:conv_limit]
        rows = [["Flow", "Service", "Protocol", "Packets", "Bytes", "Start", "End"]]
        for item in conv_rows:
            direction = str(item.get("direction", "-")).lower()
            peer = str(item.get("peer", "-"))
            proto = str(item.get("protocol", "-"))
            packets = str(item.get("packets", "-"))
            bytes_count = str(item.get("bytes", "-"))
            start_ts = format_ts(item.get("first_seen"))
            end_ts = format_ts(item.get("last_seen"))
            ports_text = str(item.get("ports", "-"))
            ports = [p.strip() for p in ports_text.split(",") if p.strip()] if ports_text and ports_text != "-" else ["-"]
            for port in ports:
                service = "-"
                if port.isdigit():
                    service = COMMON_PORTS.get(int(port), "-")
                if direction == "outbound":
                    flow = f"{summary.target_ip}:{port} -> {peer}"
                elif direction == "inbound":
                    flow = f"{peer}:{port} -> {summary.target_ip}"
                else:
                    flow = f"{summary.target_ip}:{port} -> {peer}"
                rows.append([flow, service, proto, packets, bytes_count, start_ts, end_ts])
        lines.append(_format_table(rows))
        if not verbose and len(conv_source) > len(conv_rows):
            lines.append(muted(f"... {len(conv_source) - len(conv_rows)} additional conversation rows"))
    else:
        lines.append(muted("No conversations attributed to the target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Activity Timeline"))
    lines.append(muted("Time | Category | Summary | Details"))
    if summary.timeline_events:
        timeline_events = [item for item in summary.timeline_events if _matches_target(item)]
        event_rows = timeline_events if verbose else timeline_events[:_limit_value(limit * 3)]

        def _timeline_severity(summary_text: str, details_text: str, category: str) -> str:
            text = f"{summary_text} {details_text}".lower()
            if "handshake incomplete" in text or "final ack missing" in text:
                return "suspicious"
            if "potential port scan" in text or "scan" in text or "probe" in text:
                return "suspicious"
            if "http post" in text:
                return "suspicious"
            if "file artifact" in text:
                if any(token in text for token in [
                    "(exe/dll)", "(archive)", ".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js"
                ]):
                    return "malicious"
                return "suspicious"
            if "tcp connect attempt" in text and any(f":{port}" in text for port in (445, 3389, 22, 23, 135, 139, 5985, 5986)):
                return "suspicious"
            if any(token in text for token in ("write", "control", "start", "stop", "setpoint", "program", "firmware")):
                if category in {"Modbus", "DNP3", "IEC-104", "S7", "CIP", "ENIP", "BACnet", "OPC UA", "PROFINET"}:
                    return "suspicious"
            return "info"

        for event in event_rows:
            summary_text = str(event.get("summary", ""))
            details_text = _redact_in_text(str(event.get("details", "")))
            category = str(event.get("category", ""))
            severity = _timeline_severity(summary_text, details_text, category)
            if severity == "malicious":
                summary_text = danger(summary_text)
            elif severity == "suspicious":
                summary_text = warn(summary_text)
            lines.append(
                f"{format_ts(event.get('ts'))} | {category} | {summary_text} | {details_text}"
            )
        if not verbose and len(timeline_events) > len(event_rows):
            lines.append(muted(f"... {len(timeline_events) - len(event_rows)} additional timeline events"))
    else:
        lines.append(muted("No timeline events attributed to the target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Detections / IOCs"))
    detections = [item for item in _filtered_detections(summary, verbose) if _matches_target(item)]
    if detections:

        flow_pattern = re.compile(
            r"(?P<src>[0-9A-Fa-f:.]+)(?::(?P<sport>\d{1,5}))?\s*->\s*(?P<dst>[0-9A-Fa-f:.]+)(?::(?P<dport>\d{1,5}))?"
        )

        def _normalize_flow(flow_text: str) -> str | None:
            match = flow_pattern.search(flow_text)
            if not match:
                return None
            src = match.group("src")
            dst = match.group("dst")
            sport = match.group("sport") or "-"
            dport = match.group("dport") or "-"
            if not src or not dst:
                return None
            return f"{src}:{sport}->{dst}:{dport}"

        for item in (detections if verbose else detections[:limit * 3]):
            severity = str(item.get("severity", "info")).lower()
            source = str(item.get("source", "HostDetails"))
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity in {"warning", "warn", "medium"}:
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} [{source}] {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

            flow_values: list[str] = []
            seen_flows: set[str] = set()
            for blob in [details] + [str(value) for value in (item.get("evidence", []) or [])]:
                normalized = _normalize_flow(_redact_in_text(blob))
                if not normalized or normalized in seen_flows:
                    continue
                seen_flows.add(normalized)
                flow_values.append(normalized)

            if flow_values:
                lines.append(muted(f"  Flow Summary: {', '.join(flow_values[:_limit_value(4)])}"))

            top_sources = item.get("top_sources")
            if isinstance(top_sources, list) and top_sources:
                src_text = ", ".join(f"{ip}({count})" for ip, count in top_sources[:_limit_value(6)])
                lines.append(muted(f"  Top Sources: {src_text}"))
            top_destinations = item.get("top_destinations")
            if isinstance(top_destinations, list) and top_destinations:
                dst_text = ", ".join(f"{ip}({count})" for ip, count in top_destinations[:_limit_value(6)])
                lines.append(muted(f"  Top Destinations: {dst_text}"))
            evidence_items = item.get("evidence")
            if isinstance(evidence_items, list) and evidence_items:
                lines.append(muted("  Evidence:"))
                for evidence in evidence_items[:_limit_value(10)]:
                    lines.append(muted(f"    - {_redact_in_text(str(evidence))}"))
        if not verbose and len(detections) > limit * 3:
            lines.append(muted(f"... {len(detections) - (limit * 3)} additional detections"))
    else:
        lines.append(ok("No host-specific detections or IOCs observed."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Attack Categories"))
    if summary.attack_categories:
        rows = [["Category", "Signals"]]
        for category, count in summary.attack_categories.most_common(limit):
            rows.append([category.replace("_", " "), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No attack categories inferred for target IP."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Artifacts"))
    if summary.artifacts:
        artifact_source = [item for item in summary.artifacts if _matches_target(item)]
        artifact_rows = artifact_source if verbose else artifact_source[:limit]
        for item in artifact_rows:
            lines.append(muted(f"- {item}"))
        if not verbose and len(artifact_source) > limit:
            lines.append(muted(f"... {len(artifact_source) - limit} additional artifacts"))
    else:
        lines.append(muted("No host-specific artifacts extracted."))

    lines.append(SECTION_BAR)
    return _highlight_public_ips("\n".join(lines))


def render_timeline_summary(summary: TimelineSummary, limit: int = 200, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TIMELINE :: {summary.target_ip} :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Events", str(len(summary.events))))
    if summary.first_seen is not None or summary.last_seen is not None:
        lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
        lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    if summary.duration is not None:
        lines.append(_format_kv("Duration", f"{summary.duration:.1f}s"))
    if summary.peer_counts:
        lines.append(_format_kv("Unique Peers", str(len(summary.peer_counts))))
    if summary.port_counts:
        lines.append(_format_kv("Unique Ports", str(len(summary.port_counts))))
    if summary.ot_risk_score:
        risk_level = "LOW"
        if summary.ot_risk_score >= 60:
            risk_level = "HIGH"
        elif summary.ot_risk_score >= 25:
            risk_level = "MEDIUM"
        score_text = f"{summary.ot_risk_score}/100 ({risk_level})"
        lines.append(_format_kv("OT Risk Posture", score_text))
        if summary.ot_risk_findings:
            lines.append(muted("Findings:"))
            for finding in summary.ot_risk_findings:
                lines.append(muted(f"- {finding}"))
    if summary.ot_storyline:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Attack Storyline"))
        for line in summary.ot_storyline:
            lines.append(muted(f"- {line}"))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    def _severity_for_event(item: TimelineEvent) -> str:
        text = f"{item.summary} {item.details}".lower()
        if "handshake incomplete" in text or "final ack missing" in text:
            return "suspicious"
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
        if any(token in text for token in ("write", "control", "start", "stop", "setpoint", "program", "firmware")):
            if item.category in {"Modbus", "DNP3", "IEC-104", "S7", "CIP", "ENIP", "BACnet", "OPC UA", "PROFINET"}:
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

    def _extract_ips(text: str) -> list[str]:
        candidates: list[str] = []
        for token in re.split(r"[\s,;()\[\]{}<>]", text):
            if not token:
                continue
            value = token.strip(".,;:|")
            if ":" in value and not value.startswith("[") and value.count(":") == 1:
                host_part, port_part = value.rsplit(":", 1)
                if port_part.isdigit():
                    value = host_part
            value = value.strip("[]")
            try:
                ipaddress.ip_address(value)
            except Exception:
                continue
            candidates.append(value)
        return candidates

    def _event_tags(item: TimelineEvent) -> list[str]:
        text = f"{item.category} {item.summary} {item.details}".lower()
        tags: list[str] = []
        if any(token in text for token in ("scan", "recon", "probe", "enumeration", "icmp", "arp", "nbns", "mdns")):
            tags.append("Recon")
        if any(token in text for token in ("dns", "hostname", "domain", "netbios", "whoami", "ipconfig")):
            tags.append("Discovery")
        if any(token in text for token in ("auth", "login", "credential", "ntlm", "kerberos", "password")):
            tags.append("Credential")
        if any(token in text for token in ("smb", "rdp", "winrm", "wmic", "ssh", "rpc", "lateral", "pivot")):
            tags.append("Lateral")
        if any(token in text for token in ("powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "bitsadmin", "wmic", "schtasks", "msiexec")):
            tags.append("Execution")
            tags.append("LOLBAS")
        if any(token in text for token in ("beacon", "c2", "command and control")):
            tags.append("C2")
        if any(token in text for token in ("exfil", "tunnel", "dns txt", "http post", "upload")):
            tags.append("Exfil")
        if any(token in text for token in ("write", "setpoint", "operate", "trip", "shutdown", "stop", "start")) and item.category in {"Modbus", "DNP3", "IEC-104", "S7", "CIP", "ENIP", "BACnet", "OPC UA", "PROFINET", "Triconex/SIS"}:
            tags.append("OT Control")
        if any(token in text for token in ("dos", "flood", "impact", "disruption")):
            tags.append("Impact")
        if any(token in text for token in (".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js")):
            tags.append("Payload")
        if not tags:
            return []
        # Deduplicate while preserving order
        seen: set[str] = set()
        ordered: list[str] = []
        for tag in tags:
            if tag in seen:
                continue
            seen.add(tag)
            ordered.append(tag)
        return ordered[:3]

    if summary.dns_queries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Queries Performed"))
        dns_rows = summary.dns_queries if verbose else summary.dns_queries[:_limit_value(limit)]
        for item in dns_rows:
            qtype = item.qtype or "-"
            port = item.dst_port if item.dst_port is not None else "-"
            detail = f"{item.src_ip} -> {item.dst_ip}:{port} {item.protocol}"
            detail = _highlight_ips(_redact_in_text(detail), summary.target_ip)
            lines.append(muted(f"- {format_ts(item.ts)} {item.name} (type {qtype}) {detail}"))
        if not verbose and len(summary.dns_queries) > len(dns_rows):
            lines.append(muted(f"... {len(summary.dns_queries) - len(dns_rows)} additional DNS queries"))

    if summary.file_downloads:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Downloaded"))
        file_rows = summary.file_downloads if verbose else summary.file_downloads[:_limit_value(limit)]
        for item in file_rows:
            size_text = f"{item.size_bytes} bytes" if item.size_bytes is not None else "-"
            meta_bits = []
            if item.hostname:
                meta_bits.append(f"host={item.hostname}")
            if item.content_type:
                meta_bits.append(f"type={item.content_type}")
            if item.sha256:
                meta_bits.append(f"sha256={item.sha256}")
            elif item.md5:
                meta_bits.append(f"md5={item.md5}")
            meta_text = " ".join(meta_bits)
            detail = f"{item.src_ip} -> {item.dst_ip} {item.protocol} {size_text}"
            detail = _highlight_ips(_redact_in_text(detail), summary.target_ip)
            line = f"- {format_ts(item.ts)} {item.filename} ({item.file_type}) {detail}"
            if meta_text:
                line = f"{line} {meta_text}"
            lines.append(muted(line))
        if not verbose and len(summary.file_downloads) > len(file_rows):
            lines.append(muted(f"... {len(summary.file_downloads) - len(file_rows)} additional downloads"))

    event_limit = len(summary.events)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Activity Timeline"))
    lines.append(muted("Time | Category | Summary | Details"))
    tag_counts: Counter[str] = Counter()
    last_event_by_actor: dict[str, tuple[float, str, str]] = {}
    for event in summary.events[:event_limit]:
        severity = _severity_for_event(event)
        summary_text = event.summary
        tags = _event_tags(event)
        for tag in tags:
            tag_counts[tag] += 1
        if tags:
            summary_text = f"[{'] ['.join(tags)}] {summary_text}"
        if severity == "malicious":
            summary_text = danger(summary_text)
        elif severity == "suspicious":
            summary_text = warn(summary_text)
        details_text = _highlight_ips(_redact_in_text(event.details), summary.target_ip)
        actor_ip = None
        if event.ts is not None:
            ips = _extract_ips(event.details)
            if ips:
                if summary.target_ip in ips and len(ips) > 1:
                    actor_ip = next((ip for ip in ips if ip != summary.target_ip), None)
                else:
                    actor_ip = ips[0]
            if actor_ip:
                prev = last_event_by_actor.get(actor_ip)
                if prev:
                    prev_ts, prev_cat, prev_summary = prev
                    dt = float(event.ts) - float(prev_ts)
                    if 0 <= dt <= 600:
                        link = f"linked to {prev_cat}: {_truncate_text(prev_summary, max_len=48)} (+{dt:.0f}s)"
                        details_text = f"{details_text} | {link}"
                last_event_by_actor[actor_ip] = (float(event.ts), event.category, event.summary)
        lines.append(f"{format_ts(event.ts)} | {event.category} | {summary_text} | {details_text}")

    if summary.category_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Category Overview"))
        categories = sorted(summary.category_counts.items(), key=lambda item: (-item[1], item[0]))
        if not verbose:
            categories = categories[:_limit_value(12)]
        for name, count in categories:
            lines.append(muted(f"- {name}: {count}"))

    if tag_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kill-Chain Tags"))
        for tag, count in tag_counts.most_common():
            lines.append(muted(f"- {tag}: {count}"))

    if summary.ot_protocol_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Protocols Seen"))
        for name, count in sorted(summary.ot_protocol_counts.items(), key=lambda item: (-item[1], item[0])):
            lines.append(muted(f"- {name}: {count}"))

    if summary.ot_activity_bins:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Activity Sparklines"))
        for name, bins in sorted(summary.ot_activity_bins.items(), key=lambda item: (-sum(item[1]), item[0])):
            graph = sparkline(bins)
            lines.append(muted(f"- {name}: {graph} ({sum(bins)})"))
    if summary.non_ot_activity_bins:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Non-OT Activity Sparkline"))
        graph = sparkline(summary.non_ot_activity_bins)
        lines.append(muted(f"- Non-OT: {graph} ({sum(summary.non_ot_activity_bins)})"))

    if summary.peer_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Peers"))
        peer_items = Counter(summary.peer_counts).most_common()
        if not verbose:
            peer_items = peer_items[:_limit_value(10)]
        for peer, count in peer_items:
            peer_text = _highlight_ips(peer, summary.target_ip)
            lines.append(muted(f"- {peer_text}: {count}"))

    if summary.port_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Ports"))
        port_items = Counter(summary.port_counts).most_common()
        if not verbose:
            port_items = port_items[:_limit_value(10)]
        for port, count in port_items:
            svc = COMMON_PORTS.get(port, "-")
            lines.append(muted(f"- {port} ({svc}): {count}"))

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
            for name, count in summary.services.most_common(_limit_value(10)):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))

        if summary.status_codes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Status Codes"))
            rows = [["Status", "Count"]]
            for name, count in summary.status_codes.most_common(_limit_value(10)):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))

        # 5. Conversations
        lines.append(SUBSECTION_BAR)
        lines.append(header("NTLM Conversations"))
        if not summary.conversations:
            lines.append(muted("No NTLM conversations summarized."))
        else:
            rows = [["Src", "Dst", "Ports", "Packets", "First Seen", "Last Seen"]]
            for convo in sorted(summary.conversations, key=lambda c: c.packets, reverse=True)[:_limit_value(12)]:
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
            for item in summary.artifacts[:_limit_value(15)]:
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
    
    sorted_sessions = sorted(summary.sessions, key=lambda x: x.ts, reverse=True)[:_limit_value(10)]
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
        for err in summary.errors[:_limit_value(25)]:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total NetBIOS Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total NetBIOS Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Unique Hosts", str(len(summary.hosts))))
    lines.append(_format_kv("Unique Sources", str(len(summary.src_counts))))
    lines.append(_format_kv("Unique Destinations", str(len(summary.dst_counts))))
    lines.append(_format_kv("Unique NetBIOS Names", str(len(summary.unique_names))))
    lines.append(_format_kv("Name Conflicts", str(summary.name_conflicts)))
    lines.append(_format_kv("Browser Elections", str(summary.browser_elections)))

    if summary.protocol_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Statistics"))
        rows = [["Protocol", "Packets"]]
        for proto, count in summary.protocol_packets.most_common(_limit_value(10)):
            rows.append([proto, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if not summary.src_counts and not summary.dst_counts:
        lines.append(muted("No endpoint statistics available."))
    else:
        rows = [["Endpoint", "Packets", "Bytes Sent", "Bytes Recv"]]
        endpoints = Counter(summary.src_counts)
        endpoints.update(summary.dst_counts)
        for endpoint, count in endpoints.most_common(_limit_value(15)):
            rows.append([
                endpoint,
                str(count),
                format_bytes_as_mb(summary.endpoint_bytes_sent.get(endpoint, 0)),
                format_bytes_as_mb(summary.endpoint_bytes_recv.get(endpoint, 0)),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top NetBIOS Sources & Destinations"))
    if summary.src_counts:
        rows = [["Source", "Packets"]]
        for ip, count in summary.src_counts.most_common(_limit_value(12)):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No source statistics available."))
    if summary.dst_counts:
        rows = [["Destination", "Packets"]]
        for ip, count in summary.dst_counts.most_common(_limit_value(12)):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No destination statistics available."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Statistics"))
    if not summary.smb_clients and not summary.smb_servers:
        lines.append(muted("No SMB-over-NetBIOS client/server stats detected."))
    else:
        rows = [["Top Clients", "Sessions", "Top Servers", "Sessions"]]
        clients = summary.smb_clients.most_common(_limit_value(10))
        servers = summary.smb_servers.most_common(_limit_value(10))
        max_len = max(len(clients), len(servers))
        for idx in range(max_len):
            c_ip, c_cnt = clients[idx] if idx < len(clients) else ("-", 0)
            s_ip, s_cnt = servers[idx] if idx < len(servers) else ("-", 0)
            rows.append([c_ip, str(c_cnt) if c_ip != "-" else "-", s_ip, str(s_cnt) if s_ip != "-" else "-"])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed NETBIOS Functions / Services / Commands"))
    if summary.service_counts:
        rows = [["Service", "Count"]]
        for service, count in summary.service_counts.most_common(_limit_value(15)):
            rows.append([service, str(count)])
        lines.append(_format_table(rows))
    if summary.nbss_message_types:
        rows = [["NBSS Type", "Count"]]
        for msg, count in summary.nbss_message_types.most_common(_limit_value(15)):
            rows.append([msg, str(count)])
        lines.append(_format_table(rows))
    if summary.smb_commands:
        rows = [["SMB Command", "Count", "Risk"]]
        for cmd, count in summary.smb_commands.most_common(_limit_value(20)):
            risk = "Normal"
            if cmd in summary.suspicious_smb_commands:
                risk = "Suspicious"
            if any(token in cmd for token in ("Write", "Set Info", "Ioctl")):
                risk = "High-Risk"
            rows.append([cmd, str(count), risk])
        lines.append(_format_table(rows))
        if summary.suspicious_smb_commands:
            lines.append(warn("Suspicious/High-risk SMB commands observed."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NETBIOS Services Statistics (Endpoints Involved)"))
    if not summary.service_endpoints:
        lines.append(muted("No service endpoint mapping available."))
    else:
        rows = [["Service", "Top Endpoints"]]
        for service, counter in summary.service_endpoints.items():
            endpoints = ", ".join(f"{ep} ({cnt})" for ep, cnt in counter.most_common(_limit_value(5)))
            rows.append([service, endpoints or "-"])
        lines.append(_format_table(rows))

    if summary.smb_versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Client/Server Versions"))
        rows = [["Version", "Count"]]
        for version, count in summary.smb_versions.most_common(_limit_value(10)):
            rows.append([version, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NetBIOS Hosts & Names"))
    if not summary.hosts:
        lines.append(muted("No NetBIOS hosts identified."))
    else:
        for ip, host in sorted(summary.hosts.items()):
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
                for item in host.names[:_limit_value(20)]:
                    lines.append(f"  - {item.name:<16} <0x{item.suffix:02X}> : {item.type_str}")

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed NetBIOS Names"))
    if not summary.observed_users:
        lines.append(muted("No observed NetBIOS names."))
    else:
        rows = [["Name", "Count"]]
        for name, count in summary.observed_users.most_common(_limit_value(20)):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.response_codes or summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request / Response Code Summary"))
        if summary.request_counts:
            rows = [["Request Type", "Count"]]
            for name, count in summary.request_counts.most_common(_limit_value(15)):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))
        if summary.response_codes:
            rows = [["Response Code", "Count", "Risk"]]
            for code, count in summary.response_codes.most_common(_limit_value(15)):
                risk = "High" if code in {"Refused", "ServFail", "FormErr"} else "Info"
                rows.append([code, str(count), risk])
            lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Conversations & Sessions"))
    if summary.conversations:
        rows = [["Src", "Dst", "Proto", "Ports", "Pkts", "Req", "Resp", "First", "Last"]]
        for convo in summary.conversations[:_limit_value(12)]:
            rows.append([
                convo.src_ip,
                convo.dst_ip,
                convo.protocol,
                f"{convo.src_port}->{convo.dst_port}",
                str(convo.packets),
                str(convo.requests),
                str(convo.responses),
                format_ts(convo.first_seen),
                format_ts(convo.last_seen),
            ])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No NetBIOS conversations summarized."))

    if summary.sessions:
        rows = [["Src", "Dst", "Ports", "Pkts", "First", "Last"]]
        for sess in summary.sessions[:_limit_value(12)]:
            rows.append([
                sess.src_ip,
                sess.dst_ip,
                f"{sess.src_port}->{sess.dst_port}",
                str(sess.packets),
                format_ts(sess.first_seen),
                format_ts(sess.last_seen),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Threat Hunting Detections"))
    if summary.threat_summary:
        rows = [["Threat", "Count"]]
        for threat, count in summary.threat_summary.most_common(_limit_value(20)):
            rows.append([threat, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(ok("No high-confidence threat clusters detected."))

    if summary.scanning_sources:
        rows = [["Scan Source", "Indicator Count"]]
        for src, count in summary.scanning_sources.most_common(_limit_value(10)):
            rows.append([src, str(count)])
        lines.append(_format_table(rows))
    if summary.probe_sources:
        rows = [["Probe Source", "Indicator Count"]]
        for src, count in summary.probe_sources.most_common(_limit_value(10)):
            rows.append([src, str(count)])
        lines.append(_format_table(rows))
    if summary.brute_force_sources:
        rows = [["Bruteforce Source", "Attempts"]]
        for src, count in summary.brute_force_sources.most_common(_limit_value(10)):
            rows.append([src, str(count)])
        lines.append(_format_table(rows))
    if summary.beacon_candidates:
        rows = [["Beacon Flow", "Intervals"]]
        for flow, count in summary.beacon_candidates.most_common(_limit_value(10)):
            rows.append([flow, str(count)])
        lines.append(_format_table(rows))
    if summary.exfil_candidates:
        rows = [["Exfil Candidate", "Bytes"]]
        for src, count in summary.exfil_candidates.most_common(_limit_value(10)):
            rows.append([src, format_bytes_as_mb(count)])
        lines.append(_format_table(rows))

    if summary.smb_users or summary.smb_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Identities (SMB/NTLM)"))
        if summary.smb_users:
            rows = [["User", "Count"]]
            for name, count in summary.smb_users.most_common(_limit_value(12)):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))
        if summary.smb_domains:
            rows = [["Domain", "Count"]]
            for name, count in summary.smb_domains.most_common(_limit_value(12)):
                rows.append([name, str(count)])
            lines.append(_format_table(rows))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        for item in summary.files_discovered[:_limit_value(30)]:
            lines.append(f"  - {item}")

    if summary.plaintext_observed:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext Artifacts"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_observed.most_common(_limit_value(15)):
            rows.append([_truncate_text(text, 88), str(count)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Attack Signals"))
        for item in summary.anomalies[:_limit_value(40)]:
            sev_color = danger if item.severity in ("HIGH", "CRITICAL") else warn
            lines.append(sev_color(f"[{item.severity}] {item.type}: {item.details}"))
            lines.append(muted(f"  {item.src_ip} -> {item.dst_ip} @ {format_ts(item.timestamp)}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Additional Artifacts"))
        for value in summary.artifacts[:_limit_value(40)]:
            lines.append(f"  - {_truncate_text(value, 120)}")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_arp_summary(summary: ArpSummary, limit: int = 15, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ARP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("ARP Packets", str(summary.arp_packets)))
    lines.append(_format_kv("ARP Requests", str(summary.arp_requests)))
    lines.append(_format_kv("ARP Replies", str(summary.arp_replies)))
    lines.append(_format_kv("Gratuitous ARP", str(summary.gratuitous_arp)))
    lines.append(_format_kv("ARP Probes", str(summary.arp_probes)))
    lines.append(_format_kv("Unsolicited Replies", str(summary.unsolicited_replies)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Conversations"))
    if not summary.conversations:
        lines.append(muted("No ARP conversations identified."))
    else:
        rows = [["Src IP", "Dst IP", "Src MAC", "Dst MAC", "Opcode", "Packets", "First", "Last"]]
        for item in summary.conversations[:limit]:
            rows.append([
                item.src_ip,
                item.dst_ip,
                item.src_mac,
                item.dst_mac,
                item.opcode,
                str(item.packets),
                format_ts(item.first_seen),
                format_ts(item.last_seen),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Source/Destination IP Statistics"))
    if summary.src_ips:
        rows = [["Source IP", "Packets"]]
        for ip, count in summary.src_ips.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))
    if summary.dst_ips:
        rows = [["Destination IP", "Packets"]]
        for ip, count in summary.dst_ips.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Server/Service Details"))
    if not summary.server_details:
        lines.append(muted("No ARP server behavior identified."))
    else:
        rows = [["Responder IP", "Replies"]]
        for ip, count in summary.server_details.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Client Details"))
    if not summary.client_details:
        lines.append(muted("No ARP client behavior identified."))
    else:
        rows = [["Requester IP", "Requests"]]
        for ip, count in summary.client_details.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed Plaintext"))
    if not summary.plaintext_observed:
        lines.append(muted("No plaintext content observed in ARP-adjacent payloads."))
    else:
        rows = [["String", "Count"]]
        for value, count in summary.plaintext_observed.most_common(limit):
            rows.append([_truncate_text(value, 96), str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Versions"))
    if not summary.client_versions and not summary.server_versions:
        lines.append(muted("No explicit ARP stack versions available; using hw/proto tuple fingerprints."))
    else:
        if summary.client_versions:
            rows = [["Client Fingerprint", "Count"]]
            for value, count in summary.client_versions.most_common(limit):
                rows.append([value, str(count)])
            lines.append(_format_table(rows))
        if summary.server_versions:
            rows = [["Server Fingerprint", "Count"]]
            for value, count in summary.server_versions.most_common(limit):
                rows.append([value, str(count)])
            lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Response Code Summary"))
    if not summary.response_codes:
        lines.append(muted("No ARP response codes/opcodes recorded."))
    else:
        rows = [["Response Type", "Count"]]
        for code, count in summary.response_codes.most_common(limit):
            rows.append([code, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Requests Summary"))
    if not summary.request_summary:
        lines.append(muted("No ARP request categories recorded."))
    else:
        rows = [["Request Type", "Count"]]
        for req, count in summary.request_summary.most_common(limit):
            rows.append([req, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Files Discovered"))
    if not summary.files_discovered:
        lines.append(muted("No file indicators discovered."))
    else:
        for name in summary.files_discovered[:limit]:
            lines.append(f"  - {name}")

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed Session Statistics"))
    if not summary.sessions:
        lines.append(muted("No ARP request/reply session pairs identified."))
    else:
        rows = [["Client", "Server", "Requests", "Replies", "First", "Last"]]
        for sess in summary.sessions[:limit]:
            rows.append([
                sess.client_ip,
                sess.server_ip,
                str(sess.requests),
                str(sess.replies),
                format_ts(sess.first_seen),
                format_ts(sess.last_seen),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Threats / Attacks / Anomalies"))
    if not summary.threats and not summary.anomalies:
        lines.append(ok("No high-confidence ARP threats detected."))
    else:
        if summary.threats:
            rows = [["Threat", "Count"]]
            for threat, count in summary.threats.most_common(limit):
                rows.append([threat, str(count)])
            lines.append(_format_table(rows))
        for item in summary.anomalies[:limit]:
            sev = danger if item.severity in {"HIGH", "CRITICAL"} else warn
            lines.append(sev(f"[{item.severity}] {item.title}: {item.description}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Artifacts"))
    if not summary.artifacts:
        lines.append(muted("No ARP artifacts recorded."))
    else:
        rows = [["Kind", "Detail", "Src", "Dst", "TS"]]
        for item in summary.artifacts[:limit]:
            rows.append([item.kind, _truncate_text(item.detail, 72), item.src, item.dst, format_ts(item.ts)])
        lines.append(_format_table(rows))

    if verbose and summary.opcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Opcode Frequency"))
        rows = [["Opcode", "Count"]]
        for opcode, count in summary.opcode_counts.most_common(limit):
            rows.append([opcode, str(count)])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_dhcp_summary(summary: DhcpSummary, limit: int = 15, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DHCP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[:_limit_value(25)]:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("DHCP Packets", str(summary.dhcp_packets)))
    lines.append(_format_kv("Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Sessions", str(len(summary.sessions))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Message Type Statistics"))
    if not summary.message_types:
        lines.append(muted("No DHCP message types observed."))
    else:
        rows = [["Type", "Count"]]
        for item, count in summary.message_types.most_common(limit):
            rows.append([item, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Details"))
    if summary.client_details:
        rows = [["Client MAC", "Packets"]]
        for client, count in summary.client_details.most_common(limit):
            rows.append([client, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No client details observed."))

    if summary.server_details:
        rows = [["Server", "Packets"]]
        for server, count in summary.server_details.most_common(limit):
            rows.append([server, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No server details observed."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Lease and Option Intelligence"))
    if summary.lease_servers:
        rows = [["Lease Server", "Count"]]
        for server, count in summary.lease_servers.most_common(limit):
            rows.append([server, str(count)])
        lines.append(_format_table(rows))
    if summary.requested_ips:
        rows = [["Requested IP", "Count"]]
        for ip_value, count in summary.requested_ips.most_common(limit):
            rows.append([ip_value, str(count)])
        lines.append(_format_table(rows))
    if summary.offered_ips:
        rows = [["Offered/Assigned IP", "Count"]]
        for ip_value, count in summary.offered_ips.most_common(limit):
            rows.append([ip_value, str(count)])
        lines.append(_format_table(rows))
    if summary.lease_time_buckets:
        rows = [["Lease Bucket", "Count"]]
        for bucket, count in summary.lease_time_buckets.most_common(limit):
            rows.append([bucket, str(count)])
        lines.append(_format_table(rows))
    if summary.hostnames:
        rows = [["Hostname", "Count"]]
        for host, count in summary.hostnames.most_common(limit):
            rows.append([host, str(count)])
        lines.append(_format_table(rows))
    if summary.vendor_classes:
        rows = [["Vendor Class", "Count"]]
        for value, count in summary.vendor_classes.most_common(limit):
            rows.append([_truncate_text(value, 72), str(count)])
        lines.append(_format_table(rows))

    device_hits = [item for item in summary.artifacts if str(getattr(item, "kind", "")) == "device"]
    if device_hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        device_counts: Counter[str] = Counter()
        device_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
        for item in device_hits:
            detail = str(getattr(item, "detail", "") or "")
            device_counts[detail] += 1
            src = str(getattr(item, "src", "?"))
            dst = str(getattr(item, "dst", "?"))
            device_endpoints[detail][f"{src} -> {dst}"] += 1
        rows = [["Fingerprint", "Count", "Top Endpoints"]]
        for detail, count in device_counts.most_common(limit):
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in device_endpoints[detail].most_common(_limit_value(3))
            )
            rows.append([_truncate_text(detail, 90), str(count), top_eps or "-"])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if summary.src_ips:
        rows = [["Source IP", "Packets"]]
        for item, count in summary.src_ips.most_common(limit):
            rows.append([item, str(count)])
        lines.append(_format_table(rows))
    if summary.dst_ips:
        rows = [["Destination IP", "Packets"]]
        for item, count in summary.dst_ips.most_common(limit):
            rows.append([item, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Hunt Detections"))
    if not summary.threat_summary and not summary.anomalies:
        lines.append(ok("No high-confidence DHCP threat clusters detected."))
    else:
        if summary.threat_summary:
            rows = [["Threat", "Count"]]
            for threat, count in summary.threat_summary.most_common(limit):
                rows.append([threat, str(count)])
            lines.append(_format_table(rows))

        if summary.beacon_candidates:
            rows = [["Beacon Candidate", "Intervals"]]
            for endpoint, count in summary.beacon_candidates.most_common(limit):
                rows.append([endpoint, str(count)])
            lines.append(_format_table(rows))

        if summary.exfil_candidates:
            rows = [["Exfil Candidate", "Signals"]]
            for endpoint, count in summary.exfil_candidates.most_common(limit):
                rows.append([endpoint, str(count)])
            lines.append(_format_table(rows))

        if summary.probe_sources:
            rows = [["Probe Source", "Count"]]
            for endpoint, count in summary.probe_sources.most_common(limit):
                rows.append([endpoint, str(count)])
            lines.append(_format_table(rows))

        if summary.brute_force_sources:
            rows = [["Brute-Force Source", "Count"]]
            for endpoint, count in summary.brute_force_sources.most_common(limit):
                rows.append([endpoint, str(count)])
            lines.append(_format_table(rows))

        for item in summary.anomalies[:limit]:
            sev = danger if item.severity in {"HIGH", "CRITICAL"} else warn
            lines.append(sev(f"[{item.severity}] {item.title}: {item.description}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Conversations and Sessions"))
    if summary.conversations:
        rows = [["Src", "Dst", "Msg", "Ports", "Packets", "First", "Last"]]
        for item in summary.conversations[:limit]:
            rows.append([
                item.src_ip,
                item.dst_ip,
                item.message_type,
                f"{item.src_port}->{item.dst_port}",
                str(item.packets),
                format_ts(item.first_seen),
                format_ts(item.last_seen),
            ])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No DHCP conversations identified."))

    if summary.sessions:
        rows = [["Client MAC", "Client IP", "Server", "Req", "Offer", "Ack", "Nak", "First", "Last"]]
        for item in summary.sessions[:limit]:
            rows.append([
                item.client_mac,
                item.client_ip,
                item.server_ip,
                str(item.requests),
                str(item.offers),
                str(item.acks),
                str(item.naks),
                format_ts(item.first_seen),
                format_ts(item.last_seen),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Artifacts"))
    if summary.artifacts:
        rows = [["Kind", "Detail", "Src", "Dst", "TS"]]
        for item in summary.artifacts[:limit]:
            rows.append([item.kind, _truncate_text(item.detail, 72), item.src, item.dst, format_ts(item.ts)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No DHCP artifacts recorded."))

    if summary.plaintext_observed:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for item, count in summary.plaintext_observed.most_common(limit):
            rows.append([_truncate_text(item, 96), str(count)])
        lines.append(_format_table(rows))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        for item in summary.files_discovered[:limit]:
            lines.append(f"  - {item}")

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
        top_units = summary.unit_ids.most_common(_limit_value(10))
        u_strs = [f"ID {uid} ({cnt})" for uid, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))
        if len(summary.unit_ids) > 10:
            lines.append(muted(f"  ... and {len(summary.unit_ids) - 10} more"))

    # 4. Endpoints
    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if summary.endpoint_packets:
        rows = [["Endpoint", "Packets", "Bytes"]]
        for ip, count in summary.endpoint_packets.most_common(_limit_value(10)):
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
    clients = summary.src_ips.most_common(_limit_value(10))
    servers = summary.dst_ips.most_common(_limit_value(10))
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
        }).most_common(_limit_value(10)):
            endpoints = summary.service_endpoints.get(func_name, Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3)))
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
            for detail, count in counts.most_common(_limit_value(12)):
                top_eps = ", ".join(
                    f"{ep} ({cnt})" for ep, cnt in endpoints[detail].most_common(_limit_value(3))
                )
                rows.append([detail, str(count), top_eps or "-"])
            lines.append(_format_table(rows))

        device_hits = [
            artifact for artifact in summary.artifacts
            if str(getattr(artifact, "kind", "")) == "device"
        ]
        if device_hits:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Device Fingerprints"))
            counts = Counter(str(getattr(artifact, "detail", "")) for artifact in device_hits)
            endpoints: dict[str, Counter[str]] = defaultdict(Counter)
            for artifact in device_hits:
                detail = str(getattr(artifact, "detail", ""))
                src = str(getattr(artifact, "src", "?"))
                dst = str(getattr(artifact, "dst", "?"))
                endpoints[detail][f"{src} -> {dst}"] += 1
            rows = [["Fingerprint", "Count", "Top Endpoints"]]
            for detail, count in counts.most_common(_limit_value(12)):
                top_eps = ", ".join(
                    f"{ep} ({cnt})" for ep, cnt in endpoints[detail].most_common(_limit_value(3))
                )
                rows.append([_truncate_text(detail, 90), str(count), top_eps or "-"])
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
            for exc, count in exception_counts.most_common(_limit_value(10)):
                rows.append([exc, str(count)])
            lines.append(_format_table(rows))

    if getattr(summary, "value_changes", None):
        if summary.value_changes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Write Value Changes (Preview)"))
            rows = [["Target", "Old", "New", "Src", "Dst", "TS"]]
            for item in summary.value_changes[:_limit_value(8)]:
                rows.append([
                    str(item.get("target", "")),
                    str(item.get("old", "")),
                    str(item.get("new", "")),
                    str(item.get("src", "")),
                    str(item.get("dst", "")),
                    format_ts(item.get("ts")),
                ])
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
                for title, count in title_counts.most_common(_limit_value(10)):
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
    device_counts: Counter[str] = Counter()
    device_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
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
        for artifact in summary.artifacts:
            if str(getattr(artifact, "kind", "")) != "device":
                continue
            detail = str(getattr(artifact, "detail", ""))
            device_counts[detail] += 1
            src = str(getattr(artifact, "src", "?"))
            dst = str(getattr(artifact, "dst", "?"))
            device_endpoints[detail][f"{src} -> {dst}"] += 1
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
        for err, count in errors.most_common(_limit_value(10)):
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
        top_units = unit_ids.most_common(_limit_value(10))
        u_strs = [f"ID {uid} ({cnt})" for uid, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))
        if len(unit_ids) > 10:
            lines.append(muted(f"  ... and {len(unit_ids) - 10} more"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Modbus Endpoints"))
    col_width = 45
    lines.append(highlight(f"{'Clients (Controllers)':<{col_width}} | {'Servers (PLCs/Sensors)'}"))
    lines.append(muted("-" * 90))
    clients = src_ips.most_common(_limit_value(10))
    servers = dst_ips.most_common(_limit_value(10))
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
        for ip, count in endpoint_packets.most_common(_limit_value(10)):
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
        }).most_common(_limit_value(10)):
            endpoints = service_endpoints.get(func_name, Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3)))
            rows.append([func_name, top_eps or "-"])
        lines.append(_format_table(rows))

    if equipment_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Equipment Inventory"))
        rows = [["Equipment", "Count", "Top Endpoints"]]
        for detail, count in equipment_counts.most_common(_limit_value(12)):
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in equipment_endpoints[detail].most_common(_limit_value(3))
            )
            rows.append([detail, str(count), top_eps or "-"])
        lines.append(_format_table(rows))

    if device_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        rows = [["Fingerprint", "Count", "Top Endpoints"]]
        for detail, count in device_counts.most_common(_limit_value(12)):
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in device_endpoints[detail].most_common(_limit_value(3))
            )
            rows.append([_truncate_text(detail, 90), str(count), top_eps or "-"])
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
            for title, count in title_counts.most_common(_limit_value(10)):
                rows.append([title, str(count)])
            lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)

def render_dnp3_summary(summary: "Dnp3Analysis") -> str:
    """
    Render DNP3 analysis results.
    """
    from .dnp3 import Dnp3Analysis
    from .utils import format_ts

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

    # 2b. Object Groups / Variations
    if getattr(summary, "object_group_counts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Object Groups"))
        lines.append(_format_kv("Groups", _format_counter(summary.object_group_counts, 6)))
    if getattr(summary, "object_counts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Object Variations"))
        lines.append(_format_kv("Objects", _format_counter(summary.object_counts, 6)))

    if getattr(summary, "value_changes", None):
        if summary.value_changes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Value Changes (Preview)"))
            rows = [["Point", "Old", "New", "Src", "Dst", "TS"]]
            for item in summary.value_changes[:_limit_value(8)]:
                group = item.get("group")
                variation = item.get("variation")
                index = item.get("index")
                label = f"{group}.{variation}[{index}]"
                rows.append([
                    label,
                    str(item.get("old", "")),
                    str(item.get("new", "")),
                    str(item.get("src", "")),
                    str(item.get("dst", "")),
                    format_ts(item.get("ts")),
                ])
            lines.append(_format_table(rows))

    # 3. Addresses
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top DNP3 Addresses (Data Link)"))
    if not summary.src_addrs:
        lines.append(muted("No DNP3 addresses found."))
    else:
        # Combine src and dst
        all_addrs = summary.src_addrs + summary.dst_addrs
        top_units = all_addrs.most_common(_limit_value(10))
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
        for err, count in errors.most_common(_limit_value(10)):
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
        top_units = all_addrs.most_common(_limit_value(10))
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
            for title, count in title_counts.most_common(_limit_value(10)):
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
        clients = src_ips.most_common(_limit_value(10))
        servers = dst_ips.most_common(_limit_value(10))
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
        for cmd, count in commands.most_common(_limit_value(12)):
            rows.append([str(cmd), str(count)])
        lines.append(_format_table(rows))

    if sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in sessions.most_common(_limit_value(10)):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for artifact in artifacts[:_limit_value(12)]:
            rows.append([
                str(getattr(artifact, "kind", "artifact")),
                str(getattr(artifact, "detail", ""))[:_limit_value(80)],
                str(getattr(artifact, "src", "?")),
                str(getattr(artifact, "dst", "?")),
            ])
        lines.append(_format_table(rows))

    if anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Events"))
        for anomaly in anomalies[:_limit_value(12)]:
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
        clients = summary.client_ips.most_common(_limit_value(10))
        servers = summary.server_ips.most_common(_limit_value(10))
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
        for sess, count in summary.sessions.most_common(_limit_value(12)):
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
        for cmd, count in summary.enip_commands.most_common(_limit_value(12)):
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
        for service, count in summary.cip_services.most_common(_limit_value(16)):
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
        for service, count in summary.cip_services.most_common(_limit_value(8)):
            endpoints = summary.service_endpoints.get(service, Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3))
            )
            rows.append([service, top_eps or "-"])
        lines.append(_format_table(rows))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ENIP/CIP Status Codes"))
        rows = [["Status", "Count"]]
        for status, count in summary.status_codes.most_common(_limit_value(12)):
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

        for ident in summary.identities[:_limit_value(20)]:
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

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [[label("Type"), label("Detail"), label("Src"), label("Dst")]]
        for artifact in summary.artifacts[:_limit_value(12)]:
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
                    preview = ", ".join(unique[:_limit_value(4)])
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

    lines.append(SUBSECTION_BAR)
    lines.append(header("Anomalies & Threats"))
    if summary.anomalies:
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_anoms = sorted(summary.anomalies, key=lambda x: sev_map.get(x.severity, 99))
        for anomaly in sorted_anoms[:_limit_value(20)]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            if sev == "LOW":
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {getattr(anomaly, 'title', 'Event')}: {getattr(anomaly, 'description', '')}"))
            lines.append(muted(f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"))
    else:
        lines.append(muted("No ENIP anomalies detected."))

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
    clients = (client_ips or src_ips).most_common(_limit_value(10))
    servers = (server_ips or dst_ips).most_common(_limit_value(10))
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
        for sess, count in sessions.most_common(_limit_value(10)):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Commands/Operations"))
        rows = [["Command", "Count", "Risk"]]
        for cmd, count in commands.most_common(_limit_value(16)):
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
        for service, _count in commands.most_common(_limit_value(10)):
            endpoints = service_endpoints.get(str(service), Counter())
            top_eps = ", ".join(f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3)))
            rows.append([str(service), top_eps or "-"])
        lines.append(_format_table(rows))

    if artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for artifact in artifacts[:_limit_value(16)]:
            rows.append([
                str(getattr(artifact, "kind", "artifact")),
                str(getattr(artifact, "detail", ""))[:_limit_value(80)],
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
            for detail, count in counts.most_common(_limit_value(12)):
                top_eps = ", ".join(
                    f"{ep} ({cnt})" for ep, cnt in endpoints[detail].most_common(_limit_value(3))
                )
                rows.append([detail, str(count), top_eps or "-"])
            lines.append(_format_table(rows))

    if anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        for anomaly in anomalies[:_limit_value(16)]:
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
        clients = summary.client_ips.most_common(_limit_value(10))
        servers = summary.server_ips.most_common(_limit_value(10))
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
        for sess, count in summary.sessions.most_common(_limit_value(12)):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if summary.enip_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ENIP Encapsulation Commands"))
        rows = [["Command", "Count"]]
        for cmd, count in summary.enip_commands.most_common(_limit_value(12)):
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
        for service, count in summary.cip_services.most_common(_limit_value(16)):
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

        high_risk_total = sum(summary.high_risk_services.values())
        suspicious_total = sum(summary.suspicious_services.values())
        total_services = sum(summary.cip_services.values())
        normal_total = max(0, total_services - high_risk_total - suspicious_total)

        lines.append(SUBSECTION_BAR)
        lines.append(header("Command Risking Overview"))
        lines.append(_format_kv("Total Service Invocations", str(total_services)))
        lines.append(_format_kv("High-Risk Invocations", str(high_risk_total)))
        lines.append(_format_kv("Suspicious Invocations", str(suspicious_total)))
        lines.append(_format_kv("Normal Invocations", str(normal_total)))

        if summary.source_risky_commands:
            rows = [["Source", "High-Risk Commands"]]
            for src, count in summary.source_risky_commands.most_common(_limit_value(10)):
                rows.append([str(src), str(count)])
            lines.append(label("Top Risky Command Sources"))
            lines.append(_format_table(rows))

        if summary.server_error_responses:
            rows = [["Server", "Failed Responses"]]
            for server, count in summary.server_error_responses.most_common(_limit_value(10)):
                rows.append([str(server), str(count)])
            lines.append(label("Error-Heavy Servers"))
            lines.append(_format_table(rows))

    if summary.service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints"))
        rows = [["Service", "Top Endpoints"]]
        for service, count in summary.cip_services.most_common(_limit_value(8)):
            endpoints = summary.service_endpoints.get(service, Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3))
            )
            rows.append([service, top_eps or "-"])
        lines.append(_format_table(rows))

    if summary.class_ids or summary.instance_ids or summary.attribute_ids:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CIP Object Path Statistics"))
        if summary.class_ids:
            rows = [["Class ID", "Count"]]
            for class_id, count in summary.class_ids.most_common(_limit_value(10)):
                rows.append([str(class_id), str(count)])
            lines.append(label("Top Class IDs"))
            lines.append(_format_table(rows))
        if summary.instance_ids:
            rows = [["Instance ID", "Count"]]
            for inst_id, count in summary.instance_ids.most_common(_limit_value(10)):
                rows.append([str(inst_id), str(count)])
            lines.append(label("Top Instance IDs"))
            lines.append(_format_table(rows))
        if summary.attribute_ids:
            rows = [["Attribute ID", "Count"]]
            for attr_id, count in summary.attribute_ids.most_common(_limit_value(10)):
                rows.append([str(attr_id), str(count)])
            lines.append(label("Top Attribute IDs"))
            lines.append(_format_table(rows))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CIP Status Codes"))
        rows = [["Status", "Count"]]
        for status, count in summary.status_codes.most_common(_limit_value(12)):
            rows.append([str(status), str(count)])
        lines.append(_format_table(rows))

        if summary.service_error_counts:
            rows = [["Service", "Failed Responses"]]
            for service, count in summary.service_error_counts.most_common(_limit_value(12)):
                rows.append([str(service), str(count)])
            lines.append(label("Error Responses by Service"))
            lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for artifact in summary.artifacts[:_limit_value(12)]:
            rows.append([
                str(getattr(artifact, "kind", "artifact")),
                _truncate_text(str(getattr(artifact, "detail", "")), 80),
                str(getattr(artifact, "src", "?")),
                str(getattr(artifact, "dst", "?")),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Anomalies & Threats"))
    if summary.anomalies:
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_anoms = sorted(summary.anomalies, key=lambda x: sev_map.get(x.severity, 99))
        for anomaly in sorted_anoms[:_limit_value(20)]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            if sev == "LOW":
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {getattr(anomaly, 'title', 'Event')}: {getattr(anomaly, 'description', '')}"))
            lines.append(muted(f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"))
    else:
        lines.append(muted("No CIP anomalies detected."))

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


def render_pcapmeta_summary(summary: PcapMetaSummary) -> str:
    lines = [header("PCAP METADATA")]
    lines.append(_format_kv("File Type", summary.file_type))
    lines.append(_format_kv("Size Bytes", str(summary.size_bytes)))
    lines.append(_format_kv("Linktype", str(summary.linktype or "-")))
    lines.append(_format_kv("Snaplen", str(summary.snaplen or "-")))
    lines.append(_format_kv("Interfaces", str(summary.interface_count)))
    if summary.interface_names:
        lines.append(_format_kv("Interface Names", ", ".join(summary.interface_names[:_limit_value(6)])))
    if summary.dropcount is not None:
        lines.append(_format_kv("Drop Count", str(summary.dropcount)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    return _finalize_output(lines)


def render_quic_summary(summary: QuicSummary) -> str:
    lines = [header("QUIC ANALYSIS")]
    lines.append(_format_kv("QUIC Packets", str(summary.quic_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.clients, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.servers, 5)))
    if summary.versions:
        lines.append(_format_kv("Versions", _format_counter(summary.versions, 5)))
    return _finalize_output(lines)


def render_http2_summary(summary: Http2Summary) -> str:
    lines = [header("HTTP/2 ANALYSIS")]
    lines.append(_format_kv("HTTP/2 Packets", str(summary.http2_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    return _finalize_output(lines)


def render_encrypted_dns_summary(summary: EncryptedDnsSummary) -> str:
    lines = [header("ENCRYPTED DNS ANALYSIS")]
    lines.append(_format_kv("DoT Packets", str(summary.dot_packets)))
    lines.append(_format_kv("DoH Packets", str(summary.doh_packets)))
    lines.append(_format_kv("DoQ Packets", str(summary.doq_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.clients, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.servers, 5)))
    return _finalize_output(lines)


def render_ntp_summary(summary: NtpSummary) -> str:
    lines = [header("NTP ANALYSIS")]
    lines.append(_format_kv("NTP Packets", str(summary.ntp_packets)))
    lines.append(_format_kv("Modes", _format_counter(summary.mode_counts, 5)))
    lines.append(_format_kv("Versions", _format_counter(summary.version_counts, 5)))
    lines.append(_format_kv("Stratum", _format_counter(summary.stratum_counts, 5)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    return _finalize_output(lines)


def render_vpn_summary(summary: VpnSummary) -> str:
    lines = [header("VPN/TUNNEL ANALYSIS")]
    lines.append(_format_kv("VPN Packets", str(summary.vpn_packets)))
    lines.append(_format_kv("Services", _format_counter(summary.service_counts, 6)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    return _finalize_output(lines)


def render_routing_summary(summary: RoutingSummary, limit: int = 200, verbose: bool = False) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ROUTING ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Routing Packets", str(summary.routing_packets)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", f"{summary.duration_seconds:.1f}s"))
    if summary.endpoint_counts:
        lines.append(_format_kv("Unique Endpoints", str(len(summary.endpoint_counts))))

    if summary.protocol_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocols"))
        for name, count in summary.protocol_counts.most_common(_limit_value(12)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.message_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Message Types"))
        for name, count in summary.message_counts.most_common(_limit_value(12)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.lsa_type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OSPF LSA Types"))
        for name, count in summary.lsa_type_counts.most_common(_limit_value(12)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.lsa_adv_router_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OSPF LSA Advertising Routers"))
        for rid, count in summary.lsa_adv_router_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {rid}: {count}"))

    if summary.lsa_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OSPF LSA IDs"))
        for ls_id, count in summary.lsa_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {ls_id}: {count}"))

    if summary.bgp_prefix_counts or summary.bgp_withdraw_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP Prefixes"))
        if summary.bgp_prefix_counts:
            lines.append(muted(f"- Announced: {_format_counter(summary.bgp_prefix_counts, 8)}"))
        if summary.bgp_withdraw_counts:
            lines.append(muted(f"- Withdrawn: {_format_counter(summary.bgp_withdraw_counts, 8)}"))

    if summary.bgp_next_hop_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP Next-Hops"))
        for hop, count in summary.bgp_next_hop_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {hop}: {count}"))

    if summary.bgp_path_attr_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP Path Attributes"))
        for name, count in summary.bgp_path_attr_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.bgp_as_path_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP AS Paths"))
        for path, count in summary.bgp_as_path_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {path}: {count}"))

    if summary.isis_system_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS System IDs"))
        for sysid, count in summary.isis_system_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {sysid}: {count}"))

    if summary.isis_area_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Areas"))
        for area, count in summary.isis_area_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {area}: {count}"))

    if summary.isis_hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Hostnames"))
        for host, count in summary.isis_hostname_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {host}: {count}"))

    if summary.isis_neighbor_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Neighbors"))
        for nbr, count in summary.isis_neighbor_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {nbr}: {count}"))

    if summary.isis_reachability_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Reachability"))
        for prefix, count in summary.isis_reachability_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {prefix}: {count}"))

    if summary.isis_tlv_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS TLVs"))
        for name, count in summary.isis_tlv_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.isis_lsp_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS LSP IDs"))
        for lsp_id, count in summary.isis_lsp_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {lsp_id}: {count}"))

    if summary.pim_type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Messages"))
        for name, count in summary.pim_type_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.pim_group_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Groups"))
        for group, count in summary.pim_group_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {group}: {count}"))

    if summary.pim_source_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Sources"))
        for source, count in summary.pim_source_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {source}: {count}"))

    if summary.pim_options_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Hello Options"))
        for name, count in summary.pim_options_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.pim_dr_priority_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM DR Priorities"))
        for pri, count in summary.pim_dr_priority_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {pri}: {count}"))

    if summary.sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sessions"))
        sessions = sorted(summary.sessions, key=lambda s: s.packets, reverse=True)
        if not verbose:
            sessions = sessions[:_limit_value(12)]
        for sess in sessions:
            ports = ""
            if sess.src_port or sess.dst_port:
                ports = f":{sess.src_port}->{sess.dst_port}"
            detail = f"{sess.protocol} {sess.src_ip}{ports} -> {sess.dst_ip} ({sess.packets} pkts)"
            if sess.details:
                detail = f"{detail} [{sess.details}]"
            lines.append(muted(f"- {detail}"))

    if summary.endpoint_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Endpoints"))
        for name, count in summary.endpoint_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.router_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Router IDs"))
        for rid, count in summary.router_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {rid}: {count}"))

    if summary.asn_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ASNs"))
        for asn, count in summary.asn_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {asn}: {count}"))

    if summary.auth_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Authentication"))
        for name, count in summary.auth_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections[:_limit_value(10)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = _redact_in_text(str(item.get("summary", "")))
            details = _redact_in_text(str(item.get("details", "")))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))

    if summary.insights:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Insights"))
        for item in summary.insights[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        artifact_rows = summary.artifacts if verbose else summary.artifacts[:_limit_value(20)]
        for item in artifact_rows:
            detail = _redact_in_text(str(getattr(item, "detail", item)))
            lines.append(muted(f"- {detail}"))
        if not verbose and len(summary.artifacts) > _limit_value(20):
            lines.append(muted(f"... {len(summary.artifacts) - _limit_value(20)} additional artifacts"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_goose_summary(summary: GooseSummary, verbose: bool = False) -> str:
    lines = [header("GOOSE ANALYSIS")]
    lines.append(_format_kv("GOOSE Packets", str(summary.goose_packets)))
    lines.append(_format_kv("Top Sources", _format_counter(summary.src_macs, 5)))
    lines.append(_format_kv("Top Destinations", _format_counter(summary.dst_macs, 5)))
    lines.append(_format_kv("APPIDs", _format_counter(summary.app_ids, 5)))
    if getattr(summary, "datasets", None):
        lines.append(_format_kv("Datasets", _format_counter(summary.datasets, 5)))
    if getattr(summary, "gocb_refs", None):
        lines.append(_format_kv("GOCB Refs", _format_counter(summary.gocb_refs, 5)))
    if getattr(summary, "st_nums", None):
        lines.append(_format_kv("stNum", _format_counter(summary.st_nums, 5)))
    if getattr(summary, "sq_nums", None):
        lines.append(_format_kv("sqNum", _format_counter(summary.sq_nums, 5)))
    if getattr(summary, "conf_revs", None):
        lines.append(_format_kv("confRev", _format_counter(summary.conf_revs, 5)))
    if getattr(summary, "num_entries", None):
        lines.append(_format_kv("numDatSetEntries", _format_counter(summary.num_entries, 5)))
    if getattr(summary, "all_data_lengths", None):
        lines.append(_format_kv("allData Len", _format_counter(summary.all_data_lengths, 5)))
    if getattr(summary, "data_type_counts", None):
        lines.append(_format_kv("Data Types", _format_counter(summary.data_type_counts, 6)))
    if getattr(summary, "data_value_samples", None):
        samples = ", ".join(
            f"{_truncate_text(name, 40)}({count})"
            for name, count in summary.data_value_samples.most_common(5)
        )
        if samples:
            lines.append(_format_kv("Sample Values", samples))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[:_limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)


def render_sv_summary(summary: SvSummary, verbose: bool = False) -> str:
    lines = [header("SV ANALYSIS")]
    lines.append(_format_kv("SV Packets", str(summary.sv_packets)))
    lines.append(_format_kv("Top Sources", _format_counter(summary.src_macs, 5)))
    lines.append(_format_kv("Top Destinations", _format_counter(summary.dst_macs, 5)))
    lines.append(_format_kv("APPIDs", _format_counter(summary.app_ids, 5)))
    if getattr(summary, "sv_ids", None):
        lines.append(_format_kv("svID", _format_counter(summary.sv_ids, 5)))
    if getattr(summary, "conf_revs", None):
        lines.append(_format_kv("ConfRev", _format_counter(summary.conf_revs, 5)))
    if getattr(summary, "seq_data_lengths", None):
        lines.append(_format_kv("SeqOfData Len", _format_counter(summary.seq_data_lengths, 5)))
    if getattr(summary, "data_type_counts", None):
        lines.append(_format_kv("SeqOfData Types", _format_counter(summary.data_type_counts, 5)))
    if getattr(summary, "data_value_samples", None):
        samples = ", ".join(
            f"{_truncate_text(name, 40)}({count})"
            for name, count in summary.data_value_samples.most_common(5)
        )
        if samples:
            lines.append(_format_kv("Sample Values", samples))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[:_limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)


def render_lldp_dcp_summary(summary: LldpDcpSummary, verbose: bool = False) -> str:
    lines = [header("LLDP/DCP ANALYSIS")]
    lines.append(_format_kv("LLDP Packets", str(summary.lldp_packets)))
    lines.append(_format_kv("DCP Packets", str(summary.dcp_packets)))
    lines.append(_format_kv("System Names", _format_counter(summary.system_names, 5)))
    lines.append(_format_kv("Chassis IDs", _format_counter(summary.chassis_ids, 5)))
    lines.append(_format_kv("Port IDs", _format_counter(summary.port_ids, 5)))
    lines.append(_format_kv("DCP Frame IDs", _format_counter(summary.dcp_frame_ids, 5)))
    if getattr(summary, "dcp_services", None):
        lines.append(_format_kv("DCP Services", _format_counter(summary.dcp_services, 5)))
    if getattr(summary, "dcp_device_names", None):
        lines.append(_format_kv("DCP Device Names", _format_counter(summary.dcp_device_names, 5)))
    if getattr(summary, "dcp_ips", None):
        lines.append(_format_kv("DCP IPs", _format_counter(summary.dcp_ips, 5)))
    if getattr(summary, "artifacts", None):
        device_counts = Counter(
            str(getattr(item, "detail", ""))
            for item in summary.artifacts
            if str(getattr(item, "kind", "")) == "device"
        )
        if device_counts:
            preview = ", ".join(
                f"{_truncate_text(detail, 60)}({count})" for detail, count in device_counts.most_common(5)
            )
            lines.append(_format_kv("Device Fingerprints", preview))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[:_limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)


def render_ptp_summary(summary: PtpSummary, verbose: bool = False) -> str:
    lines = [header("PTP ANALYSIS")]
    lines.append(_format_kv("PTP Packets", str(summary.ptp_packets)))
    lines.append(_format_kv("Message Types", _format_counter(summary.msg_types, 6)))
    if getattr(summary, "domain_numbers", None):
        lines.append(_format_kv("Domains", _format_counter(summary.domain_numbers, 6)))
    lines.append(_format_kv("Top Sources", _format_counter(summary.src_macs or summary.src_ips, 5)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[:_limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)


def render_opc_classic_summary(summary: OpcClassicSummary) -> str:
    lines = [header("OPC CLASSIC ANALYSIS")]
    lines.append(_format_kv("OPC Packets", str(summary.opc_packets)))
    lines.append(_format_kv("Interfaces", _format_counter(summary.interface_counts, 6)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    return _finalize_output(lines)


def render_streams_summary(summary: StreamSummary) -> str:
    lines = [header("STREAM ANALYSIS")]
    lines.append(_format_kv("Total Streams", str(summary.total_streams)))
    if summary.top_streams:
        lines.append(_format_kv("Top Stream IDs", ", ".join(summary.top_streams[:_limit_value(6)])))
    if summary.lookup_stream_id:
        lines.append(_format_kv("Lookup Stream ID", summary.lookup_stream_id))
        lines.append(_format_kv("Lookup 5-Tuple", summary.lookup_tuple or "Not found"))
    if summary.streams:
        lines.append(header("Top Streams" if not summary.streams_full else "All Streams"))
        ordered = sorted(summary.streams, key=lambda item: item.bytes, reverse=True)
        top = ordered if summary.streams_full else ordered[:_limit_value(10)]
        for rec in top:
            tuple_text = f"TCP {rec.src}:{rec.src_port} <-> {rec.dst}:{rec.dst_port}"
            client_gap_text = ",".join(f"@{g['at_seq']}+{g['gap_bytes']}" for g in rec.client_gaps) or "-"
            server_gap_text = ",".join(f"@{g['at_seq']}+{g['gap_bytes']}" for g in rec.server_gaps) or "-"
            gap_text = f"client_gaps={client_gap_text} server_gaps={server_gap_text}"
            lines.append(f"{rec.stream_id} {tuple_text} {gap_text}")
    if summary.followed_stream_id:
        lines.append(_format_kv("Followed Stream", summary.followed_stream_id))
        if summary.followed_client_payload:
            lines.append("Client Payload (first 256 bytes):")
            lines.append(hexdump(summary.followed_client_payload[:_limit_value(256)]))
        if summary.followed_server_payload:
            lines.append("Server Payload (first 256 bytes):")
            lines.append(hexdump(summary.followed_server_payload[:_limit_value(256)]))
        if summary.followed_client_gaps:
            gap_line = ", ".join(f"@{g['at_seq']}+{g['gap_bytes']}" for g in summary.followed_client_gaps[:_limit_value(6)])
            lines.append(_format_kv("Client Gaps", gap_line))
        if summary.followed_server_gaps:
            gap_line = ", ".join(f"@{g['at_seq']}+{g['gap_bytes']}" for g in summary.followed_server_gaps[:_limit_value(6)])
            lines.append(_format_kv("Server Gaps", gap_line))
    return _finalize_output(lines)


def render_ctf_summary(summary: CtfSummary) -> str:
    lines = [header("CTF ANALYSIS")]
    lines.append(_format_kv("Hits", str(len(summary.hits))))
    if summary.token_counts:
        lines.append(_format_kv("Top Tokens", _format_counter(summary.token_counts, 6)))
    if summary.decoded_hits:
        lines.append(_format_kv("Decoded Hits", "; ".join(summary.decoded_hits[:_limit_value(5)])))
    if getattr(summary, "file_hints", None):
        if summary.file_hints:
            lines.append(_format_kv("File Hints", "; ".join(summary.file_hints[:_limit_value(5)])))
    return _finalize_output(lines)


def render_ioc_summary(summary: IocSummary) -> str:
    lines = [header("IOC ANALYSIS")]
    lines.append(_format_kv("IP Hits", _format_counter(summary.ip_hits, 6)))
    lines.append(_format_kv("Domain Hits", _format_counter(summary.domain_hits, 6)))
    lines.append(_format_kv("Hash Hits", _format_counter(summary.hash_hits, 6)))
    if getattr(summary, "source_counts", None):
        if summary.source_counts:
            lines.append(_format_kv("Sources", _format_counter(summary.source_counts, 6)))
    if getattr(summary, "tag_counts", None):
        if summary.tag_counts:
            lines.append(_format_kv("Tags", _format_counter(summary.tag_counts, 6)))
    if getattr(summary, "mitre_counts", None):
        if summary.mitre_counts:
            lines.append(_format_kv("MITRE", _format_counter(summary.mitre_counts, 6)))
    if getattr(summary, "avg_confidence", None) is not None:
        lines.append(_format_kv("Avg Confidence", f"{summary.avg_confidence:.1f}"))
    return _finalize_output(lines)


def render_obfuscation_summary(summary) -> str:
    from .obfuscation import ObfuscationSummary

    if not summary:
        return ""
    lines = [header("OBFUSCATION / TUNNELING")]
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Payload Bytes", str(summary.total_payload_bytes)))
    lines.append(_format_kv("High Entropy Hits", str(len(summary.high_entropy_hits))))
    lines.append(_format_kv("Base64 Hits", str(len(summary.base64_hits))))
    lines.append(_format_kv("Hex Hits", str(len(summary.hex_hits))))
    if summary.source_counts:
        lines.append(_format_kv("Top Sources", _format_counter(summary.source_counts, 6)))
    if summary.destination_counts:
        lines.append(_format_kv("Top Destinations", _format_counter(summary.destination_counts, 6)))
    if summary.high_entropy_hits:
        lines.append(header("High-Entropy Samples"))
        rows = [["Src", "Dst", "Len", "Entropy"]]
        for hit in summary.high_entropy_hits[:_limit_value(6)]:
            rows.append([hit.src, hit.dst, str(hit.length), f"{hit.entropy:.2f}"])
        lines.append(_format_table(rows))
    if summary.base64_hits:
        lines.append(header("Base64 Samples"))
        for hit in summary.base64_hits[:_limit_value(4)]:
            lines.append(muted(f"{hit.src}:{hit.src_port} -> {hit.dst}:{hit.dst_port} len={hit.length} sample={hit.sample}"))
    if summary.hex_hits:
        lines.append(header("Hex Samples"))
        for hit in summary.hex_hits[:_limit_value(4)]:
            lines.append(muted(f"{hit.src}:{hit.src_port} -> {hit.dst}:{hit.dst_port} len={hit.length} sample={hit.sample}"))
    return _finalize_output(lines)


def render_control_loop_summary(summary) -> str:
    from .control_loop import ControlLoopSummary

    if not summary:
        return ""
    lines = [header("CONTROL LOOP ANALYSIS")]
    lines.append(_format_kv("Value Changes", str(summary.total_changes)))
    lines.append(_format_kv("Targets", str(summary.total_targets)))
    if summary.kind_counts:
        lines.append(_format_kv("Findings", _format_counter(summary.kind_counts, 6)))
    if summary.source_counts:
        lines.append(_format_kv("Top Sources", _format_counter(summary.source_counts, 6)))
    if summary.destination_counts:
        lines.append(_format_kv("Top Destinations", _format_counter(summary.destination_counts, 6)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.findings:
        rows = [["Proto", "Target", "Kind", "Delta", "Src", "Dst"]]
        for item in summary.findings[:_limit_value(10)]:
            delta = item.delta
            delta_text = f"{delta:.1f}" if isinstance(delta, (int, float)) else "-"
            rows.append([
                item.protocol,
                item.target,
                item.kind,
                delta_text,
                item.src or "-",
                item.dst or "-",
            ])
        lines.append(_format_table(rows))
    return _finalize_output(lines)


def render_safety_summary(summary) -> str:
    from .safety import SafetySummary

    if not summary:
        return ""
    lines = [header("SAFETY SYSTEMS")]
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Hits", str(len(summary.hits))))
    if summary.service_counts:
        lines.append(_format_kv("Services", _format_counter(summary.service_counts, 6)))
    if summary.source_counts:
        lines.append(_format_kv("Top Sources", _format_counter(summary.source_counts, 6)))
    if summary.destination_counts:
        lines.append(_format_kv("Top Destinations", _format_counter(summary.destination_counts, 6)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.hits:
        rows = [["Proto", "Service", "Src", "Dst"]]
        for hit in summary.hits[:_limit_value(10)]:
            rows.append([
                hit.protocol,
                hit.service,
                f"{hit.src}:{hit.src_port}",
                f"{hit.dst}:{hit.dst_port}",
            ])
        lines.append(_format_table(rows))
    return _finalize_output(lines)


def render_carve_summary(summary) -> str:
    from .carving import CarveSummary

    if not summary:
        return ""
    lines = [header("STREAM CARVING")]
    lines.append(_format_kv("Streams", str(summary.total_streams)))
    lines.append(_format_kv("Hits", str(summary.total_hits)))
    if summary.extracted:
        lines.append(_format_kv("Extracted", str(len(summary.extracted))))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.hits:
        rows = [["Stream", "Dir", "Type", "Len", "Src", "Dst"]]
        for hit in summary.hits[:_limit_value(10)]:
            rows.append([
                hit.stream_id,
                hit.direction,
                hit.file_type,
                str(hit.length),
                f"{hit.src}:{hit.src_port}",
                f"{hit.dst}:{hit.dst_port}",
            ])
        lines.append(_format_table(rows))
    return _finalize_output(lines)


def render_correlation_summary(summary, min_count: int = 2, verbose: bool = False) -> str:
    from .correlation import CorrelationSummary

    if not summary:
        return ""
    lines = [header("CORRELATION (MULTI-PCAP)")]
    lines.append(_format_kv("PCAPs", str(summary.total_pcaps)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.host_counts:
        lines.append(_format_kv("Hosts Seen", str(len(summary.host_counts))))
        rows = [["Host", "PCAPs"]]
        for ip, count in summary.host_counts.most_common(_limit_value(10)):
            if count < min_count:
                continue
            rows.append([ip, str(count)])
        if len(rows) > 1:
            lines.append(_format_table(rows))
    if summary.service_counts:
        rows = [["Service", "PCAPs"]]
        for svc, count in summary.service_counts.most_common(_limit_value(10)):
            if count < min_count:
                continue
            rows.append([svc, str(count)])
        if len(rows) > 1:
            lines.append(header("Repeated Services"))
            lines.append(_format_table(rows))
    if verbose:
        if summary.host_presence:
            lines.append(header("Host Presence"))
            for ip, pcaps in list(summary.host_presence.items())[:_limit_value(6)]:
                lines.append(muted(f"{ip}: {', '.join(pcaps)}"))
    return _finalize_output(lines)


def render_rules_summary(summary) -> str:
    from .rules import RulesSummary

    if not summary:
        return ""
    lines = [header("RULES ANALYSIS")]
    lines.append(_format_kv("Rules Loaded", str(summary.total_rules)))
    lines.append(_format_kv("Matches", str(summary.total_matches)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.hits:
        lines.append(header("Rule Hits"))
        rows = [["Rule", "Severity", "Count", "Sources"]]
        for hit in summary.hits[:_limit_value(10)]:
            sources = ", ".join(hit.sources) if hit.sources else "-"
            rows.append([hit.title, hit.severity.upper(), str(hit.count), sources])
        lines.append(_format_table(rows))
        for hit in summary.hits[:_limit_value(5)]:
            if hit.examples:
                lines.append(muted(f"{hit.title} examples:"))
                for example in hit.examples[:_limit_value(3)]:
                    lines.append(muted(f"  {example}"))
    return _finalize_output(lines)


def render_baseline_delta(delta) -> str:
    from .baseline import BaselineDelta

    if not delta:
        return ""
    lines = [header("BASELINE DRIFT")]
    lines.append(_format_kv("Baseline Version", delta.baseline_version or "-"))
    lines.append(_format_kv("Current Version", delta.current_version or "-"))
    if delta.notes:
        lines.append(_format_kv("Notes", "; ".join(delta.notes)))
    lines.append(_format_kv("New Hosts", str(len(delta.new_hosts))))
    lines.append(_format_kv("Missing Hosts", str(len(delta.missing_hosts))))
    lines.append(_format_kv("Host Changes", str(len(delta.host_changes))))
    lines.append(_format_kv("New Services", str(len(delta.new_services))))
    lines.append(_format_kv("Missing Services", str(len(delta.missing_services))))
    lines.append(_format_kv("Service Changes", str(len(delta.service_changes))))
    lines.append(_format_kv("New OT Commands", str(len(delta.new_ot_commands))))
    lines.append(_format_kv("Missing OT Commands", str(len(delta.missing_ot_commands))))
    lines.append(_format_kv("OT Command Changes", str(len(delta.ot_command_changes))))
    lines.append(_format_kv("New Control Targets", str(len(delta.new_control_targets))))
    lines.append(_format_kv("Missing Control Targets", str(len(delta.missing_control_targets))))

    if delta.new_hosts:
        lines.append(header("New Hosts"))
        lines.append(muted(", ".join(delta.new_hosts[:_limit_value(10)])))
    if delta.missing_hosts:
        lines.append(header("Missing Hosts"))
        lines.append(muted(", ".join(delta.missing_hosts[:_limit_value(10)])))
    if delta.host_changes:
        lines.append(header("Host Changes"))
        rows = [["Host", "Change"]]
        for item in delta.host_changes[:_limit_value(8)]:
            ip = item.get("ip", "")
            changes = []
            if item.get("new_hostnames"):
                changes.append(f"new_hostnames={len(item.get('new_hostnames'))}")
            if item.get("missing_hostnames"):
                changes.append(f"missing_hostnames={len(item.get('missing_hostnames'))}")
            if item.get("new_ports"):
                changes.append(f"new_ports={len(item.get('new_ports'))}")
            if item.get("missing_ports"):
                changes.append(f"missing_ports={len(item.get('missing_ports'))}")
            if item.get("os_change"):
                changes.append("os_change")
            rows.append([str(ip), ", ".join(changes)])
        lines.append(_format_table(rows))
    if delta.service_changes:
        lines.append(header("Service Changes"))
        rows = [["Service", "Change"]]
        for item in delta.service_changes[:_limit_value(8)]:
            label = f"{item.get('ip')}:{item.get('port')}/{item.get('protocol')}"
            change = f"{item.get('from_service')} -> {item.get('to_service')}"
            if item.get("from_software") or item.get("to_software"):
                change = f"{change} ({item.get('from_software')} -> {item.get('to_software')})"
            rows.append([label, change])
        lines.append(_format_table(rows))
    if delta.ot_command_changes:
        lines.append(header("OT Command Drift"))
        rows = [["Command", "Baseline", "Current", "Delta"]]
        for item in delta.ot_command_changes[:_limit_value(8)]:
            rows.append([
                str(item.get("command", "")),
                str(item.get("baseline", "")),
                str(item.get("current", "")),
                str(item.get("delta", "")),
            ])
        lines.append(_format_table(rows))
    return _finalize_output(lines)


def render_decrypt_summary(summary) -> str:
    from .decryption import DecryptSummary

    if not summary:
        return ""
    lines = [header(f"{summary.protocol} DECRYPTION")]
    lines.append(_format_kv("Streams", str(summary.stream_count)))
    lines.append(_format_kv("Output Dir", str(summary.output_dir)))
    if summary.outputs:
        lines.append(_format_kv("Outputs", str(len(summary.outputs))))
    if summary.notes:
        lines.append(_format_kv("Notes", "; ".join(summary.notes)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    return _finalize_output(lines)


def render_ot_commands_summary(summary: OtCommandSummary, session_limit: int = 10, verbose: bool = False) -> str:
    lines = [header("OT COMMANDS")]
    if getattr(summary, "fast_mode", False):
        lines.append(_format_kv("Mode", "FAST (port heuristic)"))
        for note in getattr(summary, "fast_notes", []) or []:
            lines.append(muted(f"- {note}"))
    lines.append(_format_kv("Commands", _format_counter(summary.command_counts, 8)))
    lines.append(_format_kv("Top Sources", _format_counter(summary.sources, 5)))
    lines.append(_format_kv("Top Destinations", _format_counter(summary.destinations, 5)))
    if getattr(summary, "control_rate_per_min", None) is not None:
        rate = float(summary.control_rate_per_min or 0.0)
        lines.append(_format_kv("Control Rate", f"{rate:.2f}/min"))
        lines.append(_format_kv("Control Burst (60s)", str(getattr(summary, "control_burst_max", 0))))
    if getattr(summary, "command_sessions", None):
        lines.append(header("Top Command Sessions"))
        rows = [["Session", "Count", "First Seen", "Last Seen"]]
        session_times = getattr(summary, "command_session_times", {}) or {}
        for session, count in summary.command_sessions.most_common(_limit_value(session_limit)):
            first, last = session_times.get(session, (None, None))
            rows.append([session, str(count), format_ts(first), format_ts(last)])
        lines.append(_format_table(rows))
    if getattr(summary, "control_targets", None):
        targets = summary.control_targets or {}
        if targets:
            lines.append(header("Top Control Targets"))
            for proto in sorted(targets.keys(), key=str.casefold):
                rows = [["Target", "Count"]]
                for target, count in targets[proto].most_common(_limit_value(6)):
                    rows.append([target, str(count)])
                if len(rows) > 1:
                    lines.append(muted(proto))
                    lines.append(_format_table(rows))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[:_limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)


def render_iec101_103_summary(summary: Iec101103Summary, verbose: bool = False) -> str:
    lines = [header("IEC 101/103 ANALYSIS")]
    lines.append(_format_kv("Candidate Packets", str(summary.candidate_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    if getattr(summary, "type_counts", None):
        lines.append(_format_kv("ASDU Types", _format_counter(summary.type_counts, 5)))
    if getattr(summary, "cause_counts", None):
        lines.append(_format_kv("COT", _format_counter(summary.cause_counts, 5)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[:_limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)
