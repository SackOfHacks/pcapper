from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import ipaddress
import re
import textwrap
import hashlib
from typing import TYPE_CHECKING, Callable, Iterable, Protocol

from .models import PcapSummary
from .utils import format_bytes_as_mb, format_duration, format_speed_bps, format_ts, sparkline, hexdump, decode_payload, safe_float
from .coloring import danger, header, label, muted, ok, warn, highlight, orange, danger_bg, warn_bg
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
from .mitre import MitreSummary


if TYPE_CHECKING:
    from .cip import CIPAnalysis
    from .dnp3 import Dnp3Analysis
    from .domain import DomainAnalysis
    from .enip import ENIPAnalysis
    from .industrial_helpers import IndustrialAnalysis
    from .kerberos import KerberosAnalysis
    from .ldap import LdapAnalysis
    from .modbus import ModbusAnalysis
    from .netbios import NetbiosAnalysis
    from .ntlm import NtlmAnalysis
    from .timeline import TimelineEvent


class _SizeBucketLike(Protocol):
    count: int
    avg: float
    min: int
    max: int


SECTION_BAR = "=" * 72
SUBSECTION_BAR = "-" * 72

_REDACT_SECRETS = False
_VERBOSE_OUTPUT = False
_FULL_OUTPUT_LIMIT = 1_000_000


def set_redact_secrets(enabled: bool) -> None:
    global _REDACT_SECRETS
    # Redaction is intentionally disabled globally.
    _REDACT_SECRETS = False


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
    return value


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
    return text


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

    def _hard_wrap_visible(text: str, width: int) -> list[str]:
        if width <= 0:
            return [text]
        if not text:
            return [""]
        chunks: list[str] = []
        visible_count = 0
        current: list[str] = []
        i = 0
        while i < len(text):
            ch = text[i]
            # Preserve ANSI color sequences without counting them toward visible width.
            if ch == "\x1b":
                m = re.match(r"\x1b\[[0-9;]*m", text[i:])
                if m:
                    seq = m.group(0)
                    current.append(seq)
                    i += len(seq)
                    continue
            if ch == "\n":
                chunks.append("".join(current))
                current = []
                visible_count = 0
                i += 1
                continue
            current.append(ch)
            visible_count += 1
            i += 1
            if visible_count >= width:
                chunks.append("".join(current))
                current = []
                visible_count = 0
        chunks.append("".join(current))
        return chunks or [""]

    def _wrap_cell_lines(text: str, width: int) -> list[str]:
        if width <= 0:
            return [text]
        if not text:
            return [""]

        max_visible = max(_visible_len(part) for part in text.splitlines() or [text])
        if max_visible <= width and "\n" not in text:
            return [text]

        wrapped: list[str] = []
        for base_line in (text.splitlines() or [text]):
            if not base_line:
                wrapped.append("")
                continue
            plain_line = re.sub(r"\x1b\[[0-9;]*m", "", base_line)
            if _visible_len(base_line) <= width:
                wrapped.append(base_line)
                continue
            # For whitespace-rich text, wrap on words; for long tokens, fall back to hard-wrap.
            if re.search(r"\s", plain_line):
                # Keep no line longer than width while preserving words when possible.
                word_wrapped = textwrap.wrap(
                    base_line,
                    width=width,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                if word_wrapped:
                    for seg in word_wrapped:
                        if _visible_len(seg) <= width:
                            wrapped.append(seg)
                        else:
                            wrapped.extend(_hard_wrap_visible(seg, width))
                    continue
            wrapped.extend(_hard_wrap_visible(base_line, width))
        return wrapped or [""]

    widths = [max(_visible_len(row[i]) for row in rows) for i in range(len(rows[0]))]
    # Cap cell width globally so very long values don't destroy table readability.
    max_col_width = 56
    wrapped_widths = [min(width, max_col_width) for width in widths]

    lines: list[str] = []
    for row in rows:
        wrapped_cells = [_wrap_cell_lines(value, wrapped_widths[idx]) for idx, value in enumerate(row)]
        row_height = max((len(cell_lines) for cell_lines in wrapped_cells), default=1)

        for line_idx in range(row_height):
            parts: list[str] = []
            for idx, cell_lines in enumerate(wrapped_cells):
                value = cell_lines[line_idx] if line_idx < len(cell_lines) else ""
                pad = wrapped_widths[idx] - _visible_len(value)
                parts.append(value + (" " * max(0, pad)))
            lines.append("  ".join(parts))
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


def _finalize_output(lines: list[str], show_truncation_note: bool = True) -> str:
    if lines and show_truncation_note and not _VERBOSE_OUTPUT:
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

    def _domain_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        checks = getattr(summary, "deterministic_checks", {}) or {}

        def _count_check(key: str) -> int:
            items = checks.get(key, []) if isinstance(checks, dict) else []
            return len([v for v in (items or []) if str(v).strip()])

        high_impact = {
            "dcsync_replication_activity": 4,
            "kerberos_ticket_abuse": 3,
            "ntlm_downgrade_or_relay_exposure": 3,
            "ldap_bind_risk": 2,
            "auth_sequence_plausibility": 2,
            "dc_role_consistency": 2,
            "name_resolution_poisoning_context": 1,
            "privileged_account_spread": 1,
        }

        for key, weight in high_impact.items():
            count = _count_check(key)
            if not count:
                continue
            score += min(4, weight + min(2, count - 1))
            reasons.append(f"{key.replace('_', ' ')} evidence ({count})")

        high_count = sum(1 for item in (summary.detections or []) if str(item.get("severity", "")).lower() in {"high", "critical"})
        warning_count = sum(1 for item in (summary.detections or []) if str(item.get("severity", "")).lower() == "warning")
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity domain detections observed ({high_count})")
        if warning_count >= 2:
            score += 1
            reasons.append(f"Multiple warning-level domain detections observed ({warning_count})")

        if score >= 8:
            verdict = "YES - high-confidence malicious or compromised domain activity is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - suspicious domain activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - risky domain behavior is present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious domain pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence domain threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _domain_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    if summary.clients:
        lines.append(muted("Who:"))
        lines.append(muted("- Top initiating hosts"))
        for ip, count in summary.clients.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))
    if summary.servers:
        lines.append(muted("Where:"))
        lines.append(muted("- Top domain infrastructure targets"))
        for ip, count in summary.servers.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))
    if summary.detections:
        lines.append(muted("What:"))
        lines.append(muted("- Top domain detections"))
        for item in summary.detections[:_limit_value(6)]:
            lines.append(
                muted(
                    f"- [{str(item.get('severity', 'info')).upper()}] {_redact_in_text(str(item.get('summary', '-')))}"
                )
            )
    if getattr(summary, "incident_clusters", None):
        lines.append(muted("When:"))
        lines.append(muted("- Incident cluster context"))
        for item in list(summary.incident_clusters or [])[:_limit_value(4)]:
            lines.append(
                muted(
                    f"- {_redact_in_text(str(item.get('cluster', '-')))} host={_highlight_public_ips(str(item.get('host', '-')))} "
                    f"signals={len(item.get('indicators', []) if isinstance(item.get('indicators', []), list) else [])}"
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Domain Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("dc_role_consistency", "DC Role Consistency"),
        ("kerberos_ticket_abuse", "Kerberos Ticket Abuse"),
        ("dcsync_replication_activity", "DCSync/Replication-like Activity"),
        ("ldap_bind_risk", "LDAP Bind Risk"),
        ("ntlm_downgrade_or_relay_exposure", "NTLM Downgrade/Relay Exposure"),
        ("auth_sequence_plausibility", "Authentication Sequence Plausibility"),
        ("name_resolution_poisoning_context", "Name Resolution Poisoning Context"),
        ("privileged_account_spread", "Privileged Account Spread"),
    ]
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))

            if key in {"dcsync_replication_activity", "kerberos_ticket_abuse", "ntlm_downgrade_or_relay_exposure"}:
                risk = "High"
                conf_level = "High"
            elif key in {"ldap_bind_risk", "auth_sequence_plausibility", "dc_role_consistency"}:
                risk = "Medium"
                conf_level = "Medium"
            else:
                risk = "Low"
                conf_level = "Medium"
            matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Domain Risk Matrix"))
    lines.append(_format_table(matrix_rows))

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

    if getattr(summary, "host_attack_paths", None):
        paths = list(summary.host_attack_paths or [])
        if paths:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Host-Centric Attack Paths"))
            rows = [["Host", "Confidence", "Targets", "Steps"]]
            for item in paths[:limit]:
                targets = item.get("targets", [])
                step_values = item.get("steps", [])
                target_text = ", ".join(str(v) for v in targets[:3]) if isinstance(targets, list) and targets else "-"
                steps_text = "; ".join(str(v) for v in step_values[:3]) if isinstance(step_values, list) and step_values else "-"
                rows.append([
                    _highlight_public_ips(str(item.get("host", "-"))),
                    str(item.get("confidence", "-")),
                    _truncate_text(target_text, 40),
                    _truncate_text(steps_text, 80),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Incident Clusters"))
            rows = [["Cluster", "Host", "Signals", "Targets", "Confidence"]]
            for item in clusters[:limit]:
                signals = item.get("indicators", [])
                rows.append([
                    str(item.get("cluster", "-")),
                    _highlight_public_ips(str(item.get("host", "-"))),
                    str(len(signals) if isinstance(signals, list) else 0),
                    str(item.get("target_count", "-")),
                    str(item.get("confidence", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "campaign_indicators", None):
        campaigns = list(summary.campaign_indicators or [])
        if campaigns:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Shared Campaign Indicators"))
            rows = [["Indicator", "Value", "Hosts"]]
            for item in campaigns[:limit]:
                hosts = item.get("hosts", [])
                host_text = ", ".join(_highlight_public_ips(str(v)) for v in hosts[:4]) if isinstance(hosts, list) else "-"
                rows.append([
                    _truncate_text(str(item.get("indicator", "-")), 40),
                    _truncate_text(str(item.get("value", "-")), 40),
                    _truncate_text(host_text or "-", 60),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "dc_role_drift", None):
        drift = list(summary.dc_role_drift or [])
        if drift:
            lines.append(SUBSECTION_BAR)
            lines.append(header("DC Role Drift Signals"))
            rows = [["Server", "Service Mix", "Packets"]]
            for item in drift[:limit]:
                services = item.get("services", [])
                svc_text = ", ".join(str(v) for v in services) if isinstance(services, list) else "-"
                rows.append([
                    _highlight_public_ips(str(item.get("server", "-"))),
                    _truncate_text(svc_text, 60),
                    str(item.get("packets", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "sequence_violations", None):
        seq = list(summary.sequence_violations or [])
        if seq:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Sequence Plausibility Violations"))
            rows = [["Source", "Reason", "Lateral Hits", "Auth Signals"]]
            for item in seq[:limit]:
                rows.append([
                    _highlight_public_ips(str(item.get("src", "-"))),
                    _truncate_text(str(item.get("reason", "-")), 56),
                    str(item.get("lateral_hits", "-")),
                    str(item.get("auth_signals", "-")),
                ])
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

    if getattr(summary, "benign_context", None):
        benign_notes = [str(v) for v in (summary.benign_context or []) if str(v).strip()]
        if benign_notes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for note in benign_notes[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(note)}"))

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
    verbose = True
    limit = _FULL_OUTPUT_LIMIT
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

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        for reason in reasons[:_limit_value(8)]:
            lines.append(muted(f"- {reason}"))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic ICMP Security Checks"))
        check_labels = {
            "icmp_request_reply_asymmetry": "ICMP request/reply asymmetry",
            "icmp_recon_sweep_behavior": "ICMP recon/sweep behavior",
            "icmp_control_plane_abuse": "ICMP control-plane abuse",
            "icmp_fragmentation_pmtud_abuse": "ICMP fragmentation/PMTUD abuse",
            "icmp_periodic_cadence": "ICMP periodic cadence",
            "icmp_tunneling_signal": "ICMP tunneling/covert signal",
            "icmp_zone_boundary_exposure": "ICMP zone boundary exposure",
            "icmp_ot_boundary_crossing": "ICMP OT boundary crossing",
            "icmp_role_drift": "ICMP role drift",
            "cross_signal_corroboration": "Cross-signal corroboration",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label}: {len(values)}"))
                for item in values[:_limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label}: none"))

    risk_matrix = list(getattr(summary, "risk_matrix", []) or [])
    if risk_matrix:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Risk Matrix"))
        rows = [["Category", "Risk", "Confidence", "Evidence"]]
        for row in risk_matrix[:_limit_value(12)]:
            if not isinstance(row, dict):
                continue
            rows.append([
                str(row.get("category", "")),
                str(row.get("risk", "")),
                str(row.get("confidence", "")),
                str(row.get("evidence", "")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    asymmetry_profiles = list(getattr(summary, "asymmetry_profiles", []) or [])
    if asymmetry_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Asymmetry Matrix"))
        rows = [["Scope", "Requests", "Replies", "Reply Ratio", "Confidence"]]
        for profile in asymmetry_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("scope", "-")),
                str(profile.get("requests", "-")),
                str(profile.get("replies", "-")),
                str(profile.get("reply_ratio", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    recon_profiles = list(getattr(summary, "recon_profiles", []) or [])
    if recon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recon Indicators"))
        rows = [["Source", "Targets", "Packets", "Confidence"]]
        for profile in recon_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("source", "-")),
                str(profile.get("targets", "-")),
                str(profile.get("packets", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    control_plane_profiles = list(getattr(summary, "control_plane_profiles", []) or [])
    if control_plane_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Control-Plane Abuse"))
        rows = [["Type", "Count", "Confidence"]]
        for profile in control_plane_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("type", "-")),
                str(profile.get("count", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    fragmentation_profiles = list(getattr(summary, "fragmentation_profiles", []) or [])
    if fragmentation_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Fragmentation/Path-MTU Anomalies"))
        rows = [["Packet Too Big", "Fragmentation Related", "Confidence"]]
        for profile in fragmentation_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("packet_too_big", "-")),
                str(profile.get("fragmentation_related", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    cadence_profiles = list(getattr(summary, "cadence_profiles", []) or [])
    if cadence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Cadence Anomalies"))
        rows = [["Flow", "Packets", "Duration", "PPS", "Confidence"]]
        for profile in cadence_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("flow", "-")),
                str(profile.get("packets", "-")),
                str(profile.get("duration_s", "-")),
                str(profile.get("pps", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    tunneling_profiles = list(getattr(summary, "tunneling_profiles", []) or [])
    if tunneling_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Encapsulation/Tunneling Suspicion"))
        rows = [["Entropy", "Size", "Count", "Preview", "Confidence"]]
        for profile in tunneling_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("entropy", "-")),
                str(profile.get("size", "-")),
                str(profile.get("count", "-")),
                str(profile.get("preview", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    zone_profiles = list(getattr(summary, "zone_profiles", []) or [])
    if zone_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Posture (East-West / North-South)"))
        rows = [["Src", "Dst", "Zone", "Packets", "Confidence"]]
        for profile in zone_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("zone", "-")),
                str(profile.get("packets", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by ICMP Behavior"))
        rows = [["Host", "Dst", "Packets", "Reason", "Confidence"]]
        for profile in role_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("packets", "-")),
                str(profile.get("reason", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    ot_profiles = list(getattr(summary, "ot_boundary_profiles", []) or [])
    if ot_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Boundary Crossing Profiles"))
        rows = [["Src", "Dst", "Packets", "Confidence"]]
        for profile in ot_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("packets", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["Host", "Score", "Confidence", "Reasons"]]
        for finding in corroborated_findings[:limit]:
            if not isinstance(finding, dict):
                continue
            rows.append([
                str(finding.get("host", "-")),
                str(finding.get("score", "-")),
                str(finding.get("confidence", "-")),
                ", ".join(str(v) for v in list(finding.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Flow", "Protocol", "Packets", "Bytes", "Reasons"]]
        for pivot in pivots[:limit]:
            if not isinstance(pivot, dict):
                continue
            rows.append([
                str(pivot.get("flow", "-")),
                str(pivot.get("protocol", "-")),
                str(pivot.get("packets", "-")),
                format_bytes_as_mb(int(pivot.get("bytes", 0) or 0)),
                ", ".join(str(v) for v in list(pivot.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [str(v) for v in list(getattr(summary, "false_positive_context", []) or []) if str(v).strip()]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context[:_limit_value(8)]:
            lines.append(muted(f"- {item}"))

    if summary.type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Types"))
        rows = [["Type", "Packets"]]
        for name, count in summary.type_counts.most_common(_FULL_OUTPUT_LIMIT):
            rows.append([_type_label(name), str(count)])
        lines.append(_format_table(rows))

    if summary.code_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Codes"))
        rows = [["Type:Code", "Packets"]]
        for name, count in summary.code_counts.most_common(_FULL_OUTPUT_LIMIT):
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
        for convo in sorted(summary.conversations, key=lambda c: c.get("packets", 0), reverse=True):
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
        for sess in summary.sessions:
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
            top_sources = ", ".join(f"{ip}({count})" for ip, count in summary.src_ip_counts.most_common(_FULL_OUTPUT_LIMIT))
            lines.append(f"Top Sources: {top_sources}")
        if summary.dst_ip_counts:
            top_dests = ", ".join(f"{ip}({count})" for ip, count in summary.dst_ip_counts.most_common(_FULL_OUTPUT_LIMIT))
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
        lines.append(muted(", ".join(summary.artifacts)))

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for name, count in summary.observed_users.most_common(_FULL_OUTPUT_LIMIT):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        lines.append(muted(", ".join(summary.files_discovered)))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


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

    def _dns_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])
        warn_count = sum(1 for item in detections if str(item.get("severity", "")).lower() == "warning")
        if warn_count:
            score += min(3, warn_count)
            reasons.append(f"Warning-level DNS detections observed ({warn_count})")

        checks = getattr(summary, "deterministic_checks", {}) or {}
        high_signal_keys = (
            "dns_tunneling_indicators",
            "dga_like_behavior",
            "fast_flux_or_rebinding",
            "zone_transfer_attempt",
            "dnssec_or_integrity_anomaly",
            "amplification_abuse_signal",
        )
        for key in high_signal_keys:
            values = checks.get(key, []) if isinstance(checks, dict) else []
            if values:
                score += 1
                reasons.append(f"{key.replace('_', ' ')} evidence observed ({len(values)})")

        if getattr(summary, "transaction_violations", None):
            score += 2
            reasons.append(f"Transaction integrity violations observed ({len(summary.transaction_violations)})")
        if getattr(summary, "resolver_drift", None):
            score += 1
            reasons.append(f"Resolver drift observed ({len(summary.resolver_drift)} clients)")

        if score >= 8:
            verdict = "YES - high-confidence suspicious DNS abuse or compromise indicators are present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - significant suspicious DNS behavior is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate suspicious DNS indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk DNS threat pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence DNS threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _dns_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.client_counts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top querying clients"))
        for client, count in summary.client_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(client))}: {int(count)}"))
    if summary.server_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top DNS servers"))
        for server, count in summary.server_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)}"))
    if summary.qname_counts:
        lines.append(muted("What:"))
        lines.append(muted("- Top queried names"))
        for qname, count in summary.qname_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_redact_in_text(str(qname))}: {int(count)}"))
    if getattr(summary, "transaction_violations", None):
        tv = list(summary.transaction_violations or [])
        if tv:
            lines.append(muted("When:"))
            lines.append(muted("- Transaction integrity violations"))
            for item in tv[:_limit_value(6)]:
                lines.append(
                    muted(
                        f"- id={item.get('id', '-')} {_highlight_public_ips(str(item.get('src', '-')))}"
                        f"->{_highlight_public_ips(str(item.get('dst', '-')))} at {format_ts(item.get('ts'))}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic DNS Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("dns_tunneling_indicators", "DNS Tunneling Indicators"),
        ("dga_like_behavior", "DGA-like Behavior"),
        ("fast_flux_or_rebinding", "Fast-Flux/Rebinding"),
        ("zone_transfer_attempt", "Zone Transfer Attempt"),
        ("resolver_policy_violation", "Resolver Policy Violation"),
        ("dnssec_or_integrity_anomaly", "DNSSEC/Integrity Anomaly"),
        ("amplification_abuse_signal", "Amplification Abuse Signal"),
        ("likely_benign_cdn_rotation", "Likely Benign CDN Rotation"),
    ]
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "likely_benign_cdn_rotation":
                lines.append(ok(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                matrix_rows.append([label_text, "Low", "Medium", f"{len(evidence_items)} signal(s)"])
            else:
                lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                if key in {"dns_tunneling_indicators", "dga_like_behavior", "fast_flux_or_rebinding", "zone_transfer_attempt"}:
                    risk = "High"
                    conf_level = "High"
                elif key in {"resolver_policy_violation", "dnssec_or_integrity_anomaly", "amplification_abuse_signal"}:
                    risk = "Medium"
                    conf_level = "Medium"
                else:
                    risk = "Low"
                    conf_level = "Low"
                matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
            for item in evidence_items[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("DNS Risk Matrix"))
    lines.append(_format_table(matrix_rows))
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
                type_label = f"{_dns_type_name(type_id)} ({type_id})"
            except Exception:
                type_label = str(name)
            rows.append([type_label, str(count)])
        lines.append(_format_table(rows))

    if summary.rcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["RCode", "Count"]]
        for name, count in summary.rcode_counts.most_common(limit):
            try:
                rcode_id = int(name)
                rcode_label = f"{_dns_rcode_name(rcode_id)} ({rcode_id})"
            except Exception:
                rcode_label = str(name)
            rows.append([rcode_label, str(count)])
        lines.append(_format_table(rows))

    if summary.opcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Opcodes"))
        rows = [["Opcode", "Count"]]
        for opcode, count in summary.opcode_counts.most_common(limit):
            opcode_label = f"{_dns_opcode_name(int(opcode))} ({opcode})"
            rows.append([opcode_label, str(count)])
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

    if getattr(summary, "resolver_drift", None):
        if summary.resolver_drift:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Resolver Drift Profiles"))
            rows = [["Client", "Resolvers", "Public", "Private", "Top Resolvers"]]
            for item in summary.resolver_drift[:limit]:
                tops = item.get("top_resolvers", [])
                top_text = ", ".join(f"{ip}({count})" for ip, count in (tops[:3] if isinstance(tops, list) else []))
                rows.append([
                    str(item.get("client", "-")),
                    str(item.get("resolver_count", "-")),
                    str(item.get("public", "-")),
                    str(item.get("private", "-")),
                    top_text or "-",
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "client_abuse_profiles", None):
        if summary.client_abuse_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Client Abuse Profiles"))
            rows = [["Client", "Queries", "Unique", "Unique Ratio", "Avg Entropy", "NXDOMAIN", "TXT", "Long"]]
            for item in summary.client_abuse_profiles[:limit]:
                rows.append([
                    str(item.get("client", "-")),
                    str(item.get("queries", "-")),
                    str(item.get("unique_qnames", "-")),
                    str(item.get("unique_ratio", "-")),
                    str(item.get("avg_entropy", "-")),
                    str(item.get("nxdomain", "-")),
                    str(item.get("txt_queries", "-")),
                    str(item.get("long_queries", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "ttl_outliers", None):
        if summary.ttl_outliers:
            lines.append(SUBSECTION_BAR)
            lines.append(header("TTL Outliers"))
            rows = [["QName", "Samples", "Unique TTL", "Min TTL", "Max TTL"]]
            for item in summary.ttl_outliers[:limit]:
                rows.append([
                    _truncate_text(str(item.get("qname", "-")), 64),
                    str(item.get("samples", "-")),
                    str(item.get("unique_ttl", "-")),
                    str(item.get("min_ttl", "-")),
                    str(item.get("max_ttl", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "cname_anomalies", None):
        if summary.cname_anomalies:
            lines.append(SUBSECTION_BAR)
            lines.append(header("CNAME Anomalies"))
            rows = [["QName", "Targets", "Sample Targets"]]
            for item in summary.cname_anomalies[:limit]:
                targets = item.get("targets", [])
                target_text = ", ".join(str(v) for v in (targets[:3] if isinstance(targets, list) else []))
                rows.append([
                    _truncate_text(str(item.get("qname", "-")), 64),
                    str(item.get("target_count", "-")),
                    _truncate_text(target_text or "-", 80),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "transaction_violations", None):
        if summary.transaction_violations:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Transaction Integrity Violations"))
            rows = [["DNS ID", "Source", "Destination", "Time"]]
            for item in summary.transaction_violations[:limit]:
                rows.append([
                    str(item.get("id", "-")),
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    format_ts(item.get("ts")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "amplification_candidates", None):
        if summary.amplification_candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Amplification Candidates"))
            rows = [["Client", "Resolver", "Query Bytes", "Response Bytes", "Ratio"]]
            for item in summary.amplification_candidates[:limit]:
                rows.append([
                    str(item.get("client", "-")),
                    str(item.get("resolver", "-")),
                    str(item.get("query_bytes", "-")),
                    str(item.get("response_bytes", "-")),
                    str(item.get("ratio", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "timeline", None):
        if summary.timeline:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Attack Timeline"))
            rows = [["Time", "Event", "Summary", "Details"]]
            for item in summary.timeline[:limit]:
                rows.append([
                    format_ts(item.get("ts")),
                    str(item.get("event", "-")),
                    _truncate_text(_redact_in_text(str(item.get("summary", "-"))), 56),
                    _truncate_text(_redact_in_text(str(item.get("details", "-"))), 90),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "benign_context", None):
        if summary.benign_context:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for item in summary.benign_context[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(str(item))}"))

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
            bucket_label = str(item.get("bucket", "-"))
            count = int(item.get("count", 0) or 0)
            pct = (count / total_packets * 100) if total_packets else 0.0
            low, high = _bucket_range(bucket_label)
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
                dominant_bucket = bucket_label
            if notes:
                outlier_rows.append([
                    bucket_label,
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

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        for reason in reasons[:_limit_value(8)]:
            lines.append(muted(f"- {reason}"))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic IPS Security Checks"))
        check_labels = {
            "indicator_quality_gate": "Indicator quality gate",
            "recency_and_persistence": "Recency and persistence",
            "boundary_cross_zone_contact": "Boundary cross-zone contact",
            "internal_critical_asset_contact": "Internal critical asset contact",
            "corroborated_multi_signal_hit": "Corroborated multi-signal hit",
            "infrastructure_clustering": "Infrastructure clustering",
            "intent_heuristics": "Intent heuristics",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label}: {len(values)}"))
                for item in values[:_limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label}: none"))

    risk_matrix = list(getattr(summary, "risk_matrix", []) or [])
    if risk_matrix:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IPS Risk Matrix"))
        rows = [["Category", "Risk", "Confidence", "Evidence"]]
        for row in risk_matrix[:_limit_value(12)]:
            if not isinstance(row, dict):
                continue
            rows.append([
                str(row.get("category", "")),
                str(row.get("risk", "")),
                str(row.get("confidence", "")),
                str(row.get("evidence", "")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    priority_asset_profiles = list(getattr(summary, "priority_asset_profiles", []) or [])
    if priority_asset_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Priority Asset Impact"))
        rows = [["IP", "Score", "Peers", "Ports", "Packets Sent", "Confidence"]]
        for item in priority_asset_profiles[:limit]:
            if not isinstance(item, dict):
                continue
            rows.append([
                str(item.get("ip", "-")),
                str(item.get("score", "-")),
                str(item.get("peers", "-")),
                str(item.get("ports", "-")),
                str(item.get("packets_sent", "-")),
                str(item.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    exposure_profiles = list(getattr(summary, "exposure_profiles", []) or [])
    if exposure_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Exposure Posture"))
        rows = [["Src", "Dst", "Protocol", "Direction", "Packets", "Bytes", "Confidence"]]
        for item in exposure_profiles[:limit]:
            if not isinstance(item, dict):
                continue
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("protocol", "-")),
                str(item.get("direction", "-")),
                str(item.get("packets", "-")),
                str(item.get("bytes", "-")),
                str(item.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["IP", "Score", "Confidence", "Reasons"]]
        for item in corroborated_findings[:limit]:
            if not isinstance(item, dict):
                continue
            reasons_text = "; ".join(str(v) for v in list(item.get("reasons", []) or [])[:3])
            rows.append([
                str(item.get("ip", "-")),
                str(item.get("score", "-")),
                str(item.get("confidence", "-")),
                reasons_text or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    infrastructure_clusters = list(getattr(summary, "infrastructure_clusters", []) or [])
    if infrastructure_clusters:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Infrastructure Clusters"))
        rows = [["Cluster", "IP Count", "IPs", "Confidence"]]
        for item in infrastructure_clusters[:limit]:
            if not isinstance(item, dict):
                continue
            ips = ",".join(str(v) for v in list(item.get("ips", []) or [])[:_limit_value(5)])
            rows.append([
                str(item.get("cluster", "-")),
                str(item.get("ip_count", "-")),
                ips or "-",
                str(item.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    intent_profiles = list(getattr(summary, "intent_profiles", []) or [])
    if intent_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Intent Heuristics"))
        rows = [["Src", "Dst", "Protocol", "Ports", "Intent", "Confidence"]]
        for item in intent_profiles[:limit]:
            if not isinstance(item, dict):
                continue
            ports = ",".join(str(v) for v in list(item.get("ports", []) or [])[:_limit_value(6)])
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("protocol", "-")),
                ports or "-",
                str(item.get("intent", "-")),
                str(item.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

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

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Flow", "Proto", "Packets", "Bytes", "Ports", "Reasons"]]
        for item in pivots[:limit]:
            if not isinstance(item, dict):
                continue
            ports = ",".join(str(v) for v in list(item.get("ports", []) or [])[:_limit_value(6)])
            reasons_text = "; ".join(str(v) for v in list(item.get("reasons", []) or [])[:3])
            rows.append([
                str(item.get("flow", "-")),
                str(item.get("protocol", "-")),
                str(item.get("packets", "-")),
                format_bytes_as_mb(int(item.get("bytes", 0) or 0)),
                ports or "-",
                reasons_text or "-",
            ])
        if len(rows) > 1:
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

    false_positive_context = [str(v) for v in list(getattr(summary, "false_positive_context", []) or [])]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context[:_limit_value(8)]:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_http_summary(summary: HttpSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _FULL_OUTPUT_LIMIT
    verbose = True
    _limit_value = lambda value: _FULL_OUTPUT_LIMIT
    _truncate_text = lambda text, max_len=0: str(text)
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

    def _http_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])
        suspicious_ua_markers = (
            "sqlmap",
            "nikto",
            "nmap",
            "acunetix",
            "python-requests",
            "curl",
            "wget",
            "masscan",
        )

        critical_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "critical")
        high_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "high")
        warning_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "warning")

        if critical_count:
            score += min(4, critical_count * 2)
            reasons.append(f"Critical HTTP findings detected ({critical_count})")
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity HTTP findings detected ({high_count})")
        if warning_count >= 2:
            score += 1
            reasons.append(f"Multiple warning-level HTTP findings detected ({warning_count})")

        if summary.downloads:
            mismatch_count = sum(1 for item in summary.downloads if bool(item.get("mismatch")))
            if mismatch_count:
                score += 3
                reasons.append(f"HTTP download type mismatches observed ({mismatch_count})")

        suspicious_ua_hits = sum(
            int(count) for ua, count in summary.user_agents.items() if any(tag in ua.lower() for tag in suspicious_ua_markers)
        )
        if suspicious_ua_hits:
            score += 1
            reasons.append(f"Suspicious scanner/tool user-agents observed ({suspicious_ua_hits})")

        risky_method_hits = int(summary.method_counts.get("TRACE", 0)) + int(summary.method_counts.get("CONNECT", 0))
        if risky_method_hits:
            score += 1
            reasons.append(f"Risky HTTP methods observed ({risky_method_hits})")

        if summary.referrer_token_counts:
            token_hits = sum(int(v) for v in summary.referrer_token_counts.values())
            if token_hits:
                score += 1
                reasons.append(f"Potential token leakage in referrers ({token_hits})")

        vt_mal = 0
        vt_sus = 0
        for det in detections:
            findings = det.get("vt_findings")
            if not isinstance(findings, list):
                continue
            for item in findings:
                if not isinstance(item, dict):
                    continue
                vt_mal += int(item.get("malicious", 0) or 0)
                vt_sus += int(item.get("suspicious", 0) or 0)
        if vt_mal > 0:
            score += 3
            reasons.append(f"VirusTotal malicious verdicts present (sum={vt_mal})")
        elif vt_sus > 0:
            score += 1
            reasons.append(f"VirusTotal suspicious verdicts present (sum={vt_sus})")

        if score >= 7:
            verdict = "YES - high-confidence malicious or compromised HTTP activity is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - suspicious HTTP activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - potentially risky HTTP activity is present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious HTTP pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence HTTP threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _http_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.host_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top HTTP hosts"))
        for host, count in summary.host_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_redact_in_text(str(host))}: {int(count)}"))
    if summary.client_counts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top source clients"))
        for client, count in summary.client_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(client))}: {int(count)}"))
    if summary.server_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top target servers"))
        for server, count in summary.server_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)}"))
    suspicious_downloads = [item for item in summary.downloads if bool(item.get("mismatch"))]
    if suspicious_downloads:
        lines.append(muted("What:"))
        lines.append(muted("- Suspicious downloads"))
        for item in suspicious_downloads[:_limit_value(6)]:
            lines.append(
                muted(
                    f"- {_highlight_public_ips(str(item.get('src', '-')))}"
                    f"->{_highlight_public_ips(str(item.get('dst', '-')))} "
                    f"file={_redact_in_text(str(item.get('filename', '-')))} "
                    f"type={_redact_in_text(str(item.get('content_type', '-')))}"
                )
            )
    if summary.detections:
        lines.append(muted("What:"))
        lines.append(muted("- Top detections"))
        for det in summary.detections[:_limit_value(6)]:
            lines.append(
                muted(
                    f"- [{str(det.get('severity', 'info')).upper()}] "
                    f"{_redact_in_text(str(det.get('summary', '-')))}"
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Threat & Compromise Overview"))
    detection_counts = Counter(str(item.get("severity", "info")).lower() for item in (summary.detections or []))
    lines.append(_format_kv("Critical Findings", str(detection_counts.get("critical", 0))))
    lines.append(_format_kv("High Findings", str(detection_counts.get("high", 0))))
    lines.append(_format_kv("Warning Findings", str(detection_counts.get("warning", 0))))
    lines.append(_format_kv("Suspicious Downloads", str(sum(1 for item in summary.downloads if bool(item.get("mismatch"))))))
    lines.append(_format_kv("POST Payload Samples", str(len(summary.post_payloads))))
    lines.append(_format_kv("Unique Session Tokens", str(len(summary.session_tokens))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic HTTP Security Checks"))

    detection_items = list(getattr(summary, "detections", []) or [])

    def _matching_detections(keywords: tuple[str, ...]) -> list[dict[str, object]]:
        matches: list[dict[str, object]] = []
        for det in detection_items:
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            blob = f"{summary_text} {details_text}".lower()
            if any(key in blob for key in keywords):
                matches.append(det)
        return matches

    def _matching_detection_lines(keywords: tuple[str, ...], limit_lines: int = 4) -> list[str]:
        out: list[str] = []
        for det in _matching_detections(keywords):
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            line = summary_text
            if details_text:
                line = f"{summary_text}: {details_text}"
            out.append(_redact_in_text(line))
            artifacts = det.get("artifacts")
            if isinstance(artifacts, list) and artifacts:
                out.append(_redact_in_text("artifacts=" + ", ".join(str(v) for v in artifacts[:3])))
            if len(out) >= limit_lines:
                break
        return out[:limit_lines]

    checks: list[tuple[str, tuple[str, ...]]] = [
        ("Authentication Abuse", ("authentication abuse", "authorization schemes")),
        ("Suspicious Upload Activity", ("upload profile", "upload")),
        ("Web Shell/Dropper Behavior", ("web shell", "dropper")),
        ("HTTP Beaconing/C2-like Check-ins", ("periodic http check-in", "check-in behavior")),
        ("URI/Token Obfuscation", ("high-entropy uri/token", "entropy")),
        ("Host Header / Fronting Anomalies", ("host header / destination anomalies", "host-to-ip churn")),
        ("Method Misuse/Tunneling", ("method misuse/tunneling", "risky http methods")),
        ("User-Agent Impersonation", ("browser ua impersonation", "suspicious user agents")),
        ("Session Token Replay", ("token replay", "token leakage")),
        ("Burst/Fan-out Reconnaissance", ("burst/fan-out reconnaissance", "single http uri reached many targets")),
        ("Content-Type/Payload Mismatch", ("content-type/payload mismatch", "file type discrepancies")),
        ("Threat Intelligence Reputation", ("threat intelligence", "virustotal")),
    ]

    def _matrix_rating_for_keywords(keywords: tuple[str, ...]) -> tuple[str, str, str]:
        matches = _matching_detections(keywords)
        if not matches:
            return "None", "Low", "No matching detections"

        severity_weight = {"critical": 4, "high": 3, "warning": 2, "info": 1}
        weight_to_label = {4: "Critical", 3: "High", 2: "Warning", 1: "Info", 0: "Info"}

        max_weight = 0
        for det in matches:
            sev = str(det.get("severity", "info") or "info").lower()
            max_weight = max(max_weight, severity_weight.get(sev, 1))

        evidence_count = len(matches)
        score = max_weight + min(3, evidence_count)

        if score >= 7:
            risk = "High"
            confidence = "High"
        elif score >= 5:
            risk = "Medium"
            confidence = "Medium"
        else:
            risk = "Low"
            confidence = "Low"

        severity_label = weight_to_label.get(max_weight, "Info")
        evidence_note = f"{evidence_count} detection(s), max severity={severity_label}"
        return risk, confidence, evidence_note

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for label_text, keywords in checks:
        lines.append(label(label_text))
        evidence_lines = _matching_detection_lines(keywords)
        if evidence_lines:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_lines:
                lines.append(muted(f"- {item}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))

        risk, confidence_level, evidence_note = _matrix_rating_for_keywords(keywords)
        matrix_rows.append([label_text, risk, confidence_level, evidence_note])

    lines.append(SUBSECTION_BAR)
    lines.append(header("HTTP Risk Matrix"))
    lines.append(_format_table(matrix_rows))

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
    return _finalize_output(lines, show_truncation_note=False)


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

    def _ftp_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        checks = getattr(summary, "deterministic_checks", {}) or {}
        detections = list(getattr(summary, "detections", []) or [])

        def _check_count(key: str) -> int:
            values = checks.get(key, []) if isinstance(checks, dict) else []
            return len([v for v in (values or []) if str(v).strip()])

        weighted_checks = {
            "cleartext_credential_exposure": 3,
            "anonymous_or_guest_abuse": 2,
            "bruteforce_or_spray": 3,
            "active_passive_mode_abuse": 2,
            "data_channel_integrity": 3,
            "high_risk_file_staging": 3,
            "ftps_downgrade_or_weak_protection": 1,
            "ftp_exfiltration_signal": 4,
        }
        for key, weight in weighted_checks.items():
            count = _check_count(key)
            if count:
                score += min(4, weight + min(2, count - 1))
                reasons.append(f"{key.replace('_', ' ')} evidence ({count})")

        high_count = sum(1 for d in detections if str(d.get("severity", "")).lower() in {"high", "critical"})
        med_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "medium")
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity FTP detections observed ({high_count})")
        if med_count >= 2:
            score += 1
            reasons.append(f"Multiple medium-severity FTP detections observed ({med_count})")

        if score >= 8:
            verdict = "YES - high-confidence malicious or compromised FTP activity is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - suspicious FTP activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - risky FTP behavior is present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious FTP pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence FTP threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _ftp_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    if summary.client_counts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top FTP clients"))
        for client, count in summary.client_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(client))}: {int(count)}"))
    if summary.server_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top FTP servers"))
        for server, count in summary.server_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)}"))
    if summary.command_counts:
        lines.append(muted("What:"))
        lines.append(muted("- Top FTP commands"))
        for cmd, count in summary.command_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {cmd}: {int(count)}"))
    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(muted("When:"))
            lines.append(muted("- Incident cluster context"))
            for item in clusters[:_limit_value(4)]:
                lines.append(
                    muted(
                        f"- {_redact_in_text(str(item.get('cluster', '-')))} host={_highlight_public_ips(str(item.get('host', '-')))} "
                        f"signals={len(item.get('indicators', []) if isinstance(item.get('indicators', []), list) else [])}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic FTP Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("cleartext_credential_exposure", "Cleartext Credential Exposure"),
        ("anonymous_or_guest_abuse", "Anonymous/Guest Abuse"),
        ("bruteforce_or_spray", "Bruteforce/Spray Behavior"),
        ("active_passive_mode_abuse", "Active/Passive Mode Abuse"),
        ("data_channel_integrity", "Data Channel Integrity"),
        ("high_risk_file_staging", "High-Risk File Staging"),
        ("ftps_downgrade_or_weak_protection", "FTPS Downgrade/Weak Protection"),
        ("ftp_exfiltration_signal", "FTP Exfiltration Signal"),
    ]
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))

            if key in {"cleartext_credential_exposure", "bruteforce_or_spray", "data_channel_integrity", "high_risk_file_staging", "ftp_exfiltration_signal"}:
                risk = "High"
                conf_level = "High"
            elif key in {"anonymous_or_guest_abuse", "active_passive_mode_abuse"}:
                risk = "Medium"
                conf_level = "Medium"
            else:
                risk = "Low"
                conf_level = "Low"
            matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("FTP Risk Matrix"))
    lines.append(_format_table(matrix_rows))

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

    if getattr(summary, "host_attack_paths", None):
        paths = list(summary.host_attack_paths or [])
        if paths:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Host-Centric Attack Paths"))
            rows = [["Host", "Confidence", "Targets", "Steps"]]
            for item in paths[:limit]:
                targets = item.get("targets", [])
                steps = item.get("steps", [])
                rows.append([
                    _highlight_public_ips(str(item.get("host", "-"))),
                    str(item.get("confidence", "-")),
                    _truncate_text(", ".join(str(v) for v in targets[:4]) if isinstance(targets, list) else str(targets), 52),
                    _truncate_text("; ".join(str(v) for v in steps[:3]) if isinstance(steps, list) else str(steps), 70),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Incident Clusters"))
            rows = [["Cluster", "Host", "Signals", "Targets", "Confidence"]]
            for item in clusters[:limit]:
                indicators = item.get("indicators", [])
                rows.append([
                    str(item.get("cluster", "-")),
                    _highlight_public_ips(str(item.get("host", "-"))),
                    str(len(indicators) if isinstance(indicators, list) else 0),
                    str(item.get("target_count", "-")),
                    str(item.get("confidence", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "campaign_indicators", None):
        campaigns = list(summary.campaign_indicators or [])
        if campaigns:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Shared Campaign Indicators"))
            rows = [["Indicator", "Value", "Hosts"]]
            for item in campaigns[:limit]:
                hosts = item.get("hosts", [])
                rows.append([
                    _truncate_text(str(item.get("indicator", "-")), 40),
                    _truncate_text(_redact_in_text(str(item.get("value", "-"))), 40),
                    _truncate_text(", ".join(_highlight_public_ips(str(v)) for v in hosts[:4]) if isinstance(hosts, list) else "-", 70),
                ])
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

    if getattr(summary, "benign_context", None):
        notes = [str(v) for v in (summary.benign_context or []) if str(v).strip()]
        if notes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for note in notes[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(note)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_tls_summary(summary: TlsSummary, limit: int = 12, verbose: bool = False) -> str:
    limit = _FULL_OUTPUT_LIMIT
    verbose = True
    _limit_value = lambda value: _FULL_OUTPUT_LIMIT
    _truncate_text = lambda text, max_len=0: str(text)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TLS/HTTPS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("TLS Posture"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("TLS Packets", str(summary.tls_packets)))
    if summary.total_packets:
        lines.append(_format_kv("TLS Share", f"{(summary.tls_packets / max(summary.total_packets, 1)) * 100.0:.1f}%"))
    if getattr(summary, "tls_like_packets", 0) and summary.tls_like_packets != summary.tls_packets:
        lines.append(_format_kv("TLS-Like Packets", str(summary.tls_like_packets)))
    lines.append(_format_kv("Client Hellos", str(summary.client_hellos)))
    lines.append(_format_kv("Server Hellos", str(summary.server_hellos)))
    if summary.client_hellos:
        lines.append(_format_kv("Handshake Success", f"{(summary.server_hellos / max(summary.client_hellos, 1)) * 100.0:.1f}%"))
    lines.append(_format_kv("Unique TLS Clients", str(len(summary.client_counts))))
    lines.append(_format_kv("Unique TLS Servers", str(len(summary.server_counts))))
    lines.append(_format_kv("TLS Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    def _tls_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])

        critical_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "critical")
        high_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "high")
        warning_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "warning")
        if critical_count:
            score += min(4, critical_count * 2)
            reasons.append(f"Critical TLS findings detected ({critical_count})")
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity TLS findings detected ({high_count})")
        if warning_count >= 2:
            score += 1
            reasons.append(f"Multiple warning-level TLS findings detected ({warning_count})")

        if summary.weak_certs:
            score += 2
            reasons.append(f"Weak certificate keys detected ({summary.weak_certs})")
        if summary.expired_certs:
            score += 2
            reasons.append(f"Expired certificates detected ({summary.expired_certs})")
        if summary.self_signed_certs:
            score += 1
            reasons.append(f"Self-signed certificates detected ({summary.self_signed_certs})")
        if summary.weak_ciphers:
            score += 1
            reasons.append(f"Weak cipher suites detected ({sum(summary.weak_ciphers.values())})")
        if summary.sni_missing_no_ech >= 10 and summary.client_hellos:
            score += 1
            reasons.append(
                f"SNI missing (excluding ECH) for {summary.sni_missing_no_ech}/{summary.client_hellos} client hellos"
            )

        if score >= 7:
            verdict = "YES - high-confidence TLS security risks or compromise indicators are present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - significant TLS security issues are present and warrant response."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - TLS security issues are present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk TLS compromise pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence TLS threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _tls_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.server_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top TLS servers"))
        for server, count in summary.server_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)}"))
    if summary.client_counts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top TLS clients"))
        for client, count in summary.client_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(client))}: {int(count)}"))
    if summary.sni_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top SNI targets"))
        for sni, count in summary.sni_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_redact_in_text(str(sni))}: {int(count)}"))
    if summary.weak_ciphers:
        lines.append(muted("What:"))
        lines.append(muted("- Weak cipher evidence"))
        for cipher_name, count in summary.weak_ciphers.most_common(_limit_value(6)):
            lines.append(muted(f"- {_redact_in_text(str(cipher_name))}: {int(count)}"))
    if summary.detections:
        lines.append(muted("What:"))
        lines.append(muted("- Top TLS detections"))
        for det in summary.detections[:_limit_value(6)]:
            lines.append(
                muted(
                    f"- [{str(det.get('severity', 'info')).upper()}] "
                    f"{_redact_in_text(str(det.get('summary', '-')))}"
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Threat & Compromise Overview"))
    detection_counts = Counter(str(item.get("severity", "info")).lower() for item in (summary.detections or []))
    lines.append(_format_kv("Critical Findings", str(detection_counts.get("critical", 0))))
    lines.append(_format_kv("High Findings", str(detection_counts.get("high", 0))))
    lines.append(_format_kv("Warning Findings", str(detection_counts.get("warning", 0))))
    lines.append(_format_kv("Weak Certificates", str(summary.weak_certs)))
    lines.append(_format_kv("Expired Certificates", str(summary.expired_certs)))
    lines.append(_format_kv("Self-Signed Certificates", str(summary.self_signed_certs)))
    lines.append(_format_kv("Weak Cipher Observations", str(sum(summary.weak_ciphers.values()))))
    lines.append(_format_kv("SNI Missing (no ECH)", f"{summary.sni_missing_no_ech}/{max(summary.client_hellos, 1)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic TLS Security Checks"))

    detection_items = list(getattr(summary, "detections", []) or [])

    def _matching_tls_detections(keywords: tuple[str, ...]) -> list[dict[str, object]]:
        matches: list[dict[str, object]] = []
        for det in detection_items:
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            blob = f"{summary_text} {details_text}".lower()
            if any(key in blob for key in keywords):
                matches.append(det)
        return matches

    def _matching_tls_lines(keywords: tuple[str, ...], limit_lines: int = 4) -> list[str]:
        out: list[str] = []
        for det in _matching_tls_detections(keywords):
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            line = summary_text
            if details_text:
                line = f"{summary_text}: {details_text}"
            out.append(_redact_in_text(line))
            if len(out) >= limit_lines:
                break
        return out[:limit_lines]

    def _tls_matrix_rating_for_keywords(keywords: tuple[str, ...]) -> tuple[str, str, str]:
        matches = _matching_tls_detections(keywords)
        if not matches:
            return "None", "Low", "No matching detections"

        severity_weight = {"critical": 4, "high": 3, "warning": 2, "info": 1}
        weight_to_label = {4: "Critical", 3: "High", 2: "Warning", 1: "Info", 0: "Info"}
        max_weight = 0
        for det in matches:
            sev = str(det.get("severity", "info") or "info").lower()
            max_weight = max(max_weight, severity_weight.get(sev, 1))

        evidence_count = len(matches)
        score = max_weight + min(3, evidence_count)
        if score >= 7:
            risk = "High"
            confidence_level = "High"
        elif score >= 5:
            risk = "Medium"
            confidence_level = "Medium"
        else:
            risk = "Low"
            confidence_level = "Low"

        evidence_note = f"{evidence_count} detection(s), max severity={weight_to_label.get(max_weight, 'Info')}"
        return risk, confidence_level, evidence_note

    tls_checks: list[tuple[str, tuple[str, ...]]] = [
        ("Certificate Pinning Drift", ("certificate pinning drift", "cert rotation")),
        ("JA3/JA4 Novelty", ("ja3 novelty", "ja4 novelty", "rarity spike")),
        ("Fingerprint Cardinality Anomalies", ("cardinality anomaly", "ja3 to sni", "sni to ja3")),
        ("Cipher Downgrade Inconsistency", ("cipher downgrade inconsistency",)),
        ("ALPN Mismatch/Anomalies", ("alpn mismatch", "alpn missing anomaly", "uncommon protocol tokens")),
        ("Certificate Validity Outliers", ("certificate validity outliers",)),
        ("Issuer/SAN Impersonation", ("impersonation heuristics", "issuer/san")),
        ("Handshake Periodicity", ("handshake periodicity",)),
        ("Session Resumption Abuse", ("session resumption-heavy", "session resumption")),
        ("SNI Evasion/Anomaly", ("sni missing", "high-entropy sni", "suspicious sni", "sni uses ip literal")),
        ("Legacy/Weak TLS Crypto", ("legacy tls versions", "weak tls cipher", "weak tls certificate keys")),
        ("TLS Handshake Failure Pattern", ("tls handshake failures", "without server hello")),
    ]

    tls_matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for label_text, keywords in tls_checks:
        lines.append(label(label_text))
        evidence_lines = _matching_tls_lines(keywords)
        if evidence_lines:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_lines:
                lines.append(muted(f"- {item}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
        risk, confidence_level, evidence_note = _tls_matrix_rating_for_keywords(keywords)
        tls_matrix_rows.append([label_text, risk, confidence_level, evidence_note])

    lines.append(SUBSECTION_BAR)
    lines.append(header("TLS Risk Matrix"))
    lines.append(_format_table(tls_matrix_rows))

    tls_total_bytes = sum(max(0, int(conv.bytes)) for conv in summary.conversations)
    lines.append(_format_kv("TLS Bytes (Conversations)", str(tls_total_bytes)))
    if summary.conversations:
        lines.append(_format_kv("Avg Bytes / Conversation", f"{tls_total_bytes / max(len(summary.conversations), 1):.1f}"))
        lines.append(_format_kv("Avg Packets / Conversation", f"{sum(int(conv.packets) for conv in summary.conversations) / max(len(summary.conversations), 1):.1f}"))

    if getattr(summary, "analysis_notes", None) and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes[:_limit_value(8)]:
            lines.append(muted(f"- {note}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Systems Communicating Over TLS"))
    if summary.client_counts or summary.server_counts:
        lines.append(_format_client_server_table(summary.client_counts, summary.server_counts))
    else:
        lines.append(muted("No TLS client/server pairs detected."))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Service Ports"))
        port_total = sum(summary.server_ports.values())
        rows = [["Port", "Count", "% TLS"]]
        for port, count in summary.server_ports.most_common(_limit_value(limit)):
            pct = (count / max(port_total, 1)) * 100.0
            rows.append([str(port), str(count), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Traffic Statistics"))
        rows = [["Client", "Server", "Port", "Packets", "Bytes", "First", "Last", "SNI"]]
        for conv in summary.conversations[:_limit_value(limit)]:
            rows.append([
                conv.client_ip,
                conv.server_ip,
                str(conv.server_port),
                str(conv.packets),
                str(conv.bytes),
                format_ts(conv.first_seen),
                format_ts(conv.last_seen),
                _truncate_text(_redact_in_text(conv.sni or "-"), 64),
            ])
        lines.append(_format_table(rows))

        repeated = [conv for conv in summary.conversations if int(conv.packets) >= 20]
        if repeated:
            lines.append(muted("Repeated TLS conversations (>=20 packets):"))
            for conv in repeated[:_limit_value(10)]:
                lines.append(
                    muted(
                        f"- {conv.client_ip} -> {conv.server_ip}:{conv.server_port} packets={conv.packets} bytes={conv.bytes}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Certificate Posture"))
    lines.append(_format_kv("Certificates", str(summary.cert_count)))
    lines.append(_format_kv("Self-Signed", str(summary.self_signed_certs)))
    lines.append(_format_kv("Expired", str(summary.expired_certs)))
    lines.append(_format_kv("Weak Keys", str(summary.weak_certs)))
    if summary.cert_issuers:
        rows = [["Issuer", "Count"]]
        for issuer, count in summary.cert_issuers.most_common(_limit_value(limit)):
            rows.append([_truncate_text(_redact_in_text(issuer), 96), str(count)])
        lines.append(_format_table(rows))
    if summary.cert_artifacts:
        rows = [["Subject", "Issuer", "Not After", "Key", "SNI", "Flow"]]
        for cert in summary.cert_artifacts[:_limit_value(limit)]:
            key_text = f"{cert.pubkey_type} {cert.pubkey_size}" if cert.pubkey_type else "-"
            rows.append([
                _truncate_text(_redact_in_text(cert.subject), 40),
                _truncate_text(_redact_in_text(cert.issuer), 34),
                cert.not_after,
                key_text,
                _truncate_text(_redact_in_text(cert.sni or "-"), 28),
                f"{cert.src_ip}->{cert.dst_ip}",
            ])
        lines.append(_format_table(rows))

    if summary.versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Versions"))
        rows = [["Version", "Count"]]
        for version, count in summary.versions.most_common(_limit_value(limit)):
            rows.append([version, str(count)])
        lines.append(_format_table(rows))

    if summary.cipher_suites:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Cipher Suites"))
        rows = [["Cipher", "Count", "Class"]]
        for name, count in summary.cipher_suites.most_common(_limit_value(limit)):
            klass = "weak" if name in summary.weak_ciphers else "modern"
            rows.append([str(name), str(count), klass])
        lines.append(_format_table(rows))

    if summary.weak_ciphers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Weak/Legacy Ciphers"))
        rows = [["Cipher", "Count"]]
        for cipher, count in summary.weak_ciphers.most_common(_limit_value(limit)):
            rows.append([cipher, str(count)])
        lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    noisy_info = {
        "ECH (Encrypted ClientHello) observed",
        "SNI hidden by ECH",
        "HTTP/2 ALPN observed",
        "HTTP/3 ALPN observed",
        "No ALPN advertised",
        "TLS handshakes without SNI",
    }
    actionable: list[dict[str, object]] = []
    for item in detections:
        summary_text = str(item.get("summary", "")).strip()
        if summary_text in noisy_info:
            continue
        actionable.append(item)

    if summary.http_requests or summary.http_responses:
        actionable.append({
            "severity": "warning",
            "summary": "Plaintext HTTP also present in this capture",
            "details": (
                f"Observed {summary.http_requests} plaintext request(s) and {summary.http_responses} response(s). "
                "Review --http output for potential downgrade/mixed-security exposure."
            ),
        })

    if actionable:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Actionable TLS Findings"))
        for item in actionable[:_limit_value(limit if verbose else max(6, limit // 2))]:
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

    if summary.sni_counts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top SNI"))
        rows = [["SNI", "Count"]]
        for sni, count in summary.sni_counts.most_common(_limit_value(limit)):
            rows.append([_truncate_text(_redact_in_text(str(sni)), 96), str(count)])
        lines.append(_format_table(rows))

    if summary.ja3_counts or summary.ja4_counts or summary.ja4s_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Fingerprint Intelligence"))
        if summary.ja3_counts:
            rows = [["JA3", "Count"]]
            for fp, count in summary.ja3_counts.most_common(_limit_value(limit)):
                rows.append([str(fp), str(count)])
            lines.append(label("Top JA3"))
            lines.append(_format_table(rows))
        if summary.ja4_counts:
            rows = [["JA4", "Count"]]
            for fp, count in summary.ja4_counts.most_common(_limit_value(limit)):
                rows.append([str(fp), str(count)])
            lines.append(label("Top JA4"))
            lines.append(_format_table(rows))
        if summary.ja4s_counts:
            rows = [["JA4S", "Count"]]
            for fp, count in summary.ja4s_counts.most_common(_limit_value(limit)):
                rows.append([str(fp), str(count)])
            lines.append(label("Top JA4S"))
            lines.append(_format_table(rows))

    if summary.artifacts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Artifacts"))
        for item in summary.artifacts[:_limit_value(limit)]:
            lines.append(muted(f"- {_truncate_text(_redact_in_text(str(item)), 96)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


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
    verbose = True
    limit = _FULL_OUTPUT_LIMIT
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TCP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        for reason in reasons[:_limit_value(8)]:
            lines.append(muted(f"- {reason}"))

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

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic TCP Security Checks"))
        check_labels = {
            "session_state_integrity": "Session state integrity",
            "handshake_asymmetry_or_recon": "Handshake asymmetry/recon",
            "rst_teardown_abuse": "RST/teardown abuse",
            "tcp_periodic_cadence": "TCP periodic cadence",
            "lateral_movement_surface": "Lateral movement surface",
            "egress_exfil_outlier": "Egress exfil outlier",
            "service_role_drift": "Service role drift",
            "transport_window_or_retrans_abuse": "Transport retrans/window abuse",
            "cross_signal_corroboration": "Cross-signal corroboration",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label}: {len(values)}"))
                for item in values[:_limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label}: none"))

    risk_matrix = list(getattr(summary, "risk_matrix", []) or [])
    if risk_matrix:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Risk Matrix"))
        rows = [["Category", "Risk", "Confidence", "Evidence"]]
        for row in risk_matrix[:_limit_value(12)]:
            if not isinstance(row, dict):
                continue
            rows.append([
                str(row.get("category", "")),
                str(row.get("risk", "")),
                str(row.get("confidence", "")),
                str(row.get("evidence", "")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    session_profiles = list(getattr(summary, "session_integrity_profiles", []) or [])
    if session_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Session State Integrity"))
        rows = [["Flow", "Issue", "Packets", "Confidence"]]
        for profile in session_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("flow", "-")),
                str(profile.get("issue", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    recon_profiles = list(getattr(summary, "recon_profiles", []) or [])
    if recon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recon and Scan Indicators"))
        rows = [["Source", "Port", "Unique Ports", "Targets", "Confidence"]]
        for profile in recon_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("source", "-")),
                str(profile.get("port", "-")),
                str(profile.get("unique_ports", "-")),
                str(profile.get("targets", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    teardown_profiles = list(getattr(summary, "teardown_profiles", []) or [])
    if teardown_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Connection Teardown Anomalies"))
        rows = [["Flow", "RST", "FIN", "Confidence"]]
        for profile in teardown_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("flow", "-")),
                str(profile.get("rst", 0)),
                str(profile.get("fin", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    cadence_profiles = list(getattr(summary, "cadence_profiles", []) or [])
    if cadence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Cadence Anomalies"))
        rows = [["Flow", "Packets", "Duration", "PPS", "Avg Packet"]]
        for profile in cadence_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("flow", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("duration_s", "-")),
                str(profile.get("pps", "-")),
                str(profile.get("avg_packet", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    lateral_profiles = list(getattr(summary, "lateral_movement_profiles", []) or [])
    if lateral_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Candidates"))
        rows = [["Source", "Targets", "Admin Ports", "Confidence"]]
        for profile in lateral_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("source", "-")),
                str(profile.get("targets", "-")),
                str(profile.get("admin_ports", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    egress_profiles = list(getattr(summary, "egress_outlier_profiles", []) or [])
    if egress_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Egress Outlier Matrix"))
        rows = [["Src", "Dst", "Bytes", "Confidence"]]
        for profile in egress_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                format_bytes_as_mb(int(profile.get("bytes", 0) or 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by TCP Behavior"))
        rows = [["Host", "Dst", "Port", "Reason", "Confidence"]]
        for profile in role_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("port", "-")),
                str(profile.get("reason", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    transport_profiles = list(getattr(summary, "transport_abuse_profiles", []) or [])
    if transport_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Transport Reliability Anomalies"))
        rows = [["Host", "Type", "Count", "Confidence"]]
        for profile in transport_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                str(profile.get("type", "-")),
                str(profile.get("count", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["Host", "Score", "Confidence", "Reasons"]]
        for finding in corroborated_findings[:limit]:
            if not isinstance(finding, dict):
                continue
            rows.append([
                str(finding.get("host", "-")),
                str(finding.get("score", "-")),
                str(finding.get("confidence", "-")),
                ", ".join(str(v) for v in list(finding.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Flow", "Packets", "Bytes", "SYN", "SYN-ACK", "RST", "Reasons"]]
        for pivot in pivots[:limit]:
            if not isinstance(pivot, dict):
                continue
            rows.append([
                str(pivot.get("flow", "-")),
                str(pivot.get("packets", 0)),
                format_bytes_as_mb(int(pivot.get("bytes", 0) or 0)),
                str(pivot.get("syn", 0)),
                str(pivot.get("syn_ack", 0)),
                str(pivot.get("rst", 0)),
                ", ".join(str(v) for v in list(pivot.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [str(v) for v in list(getattr(summary, "false_positive_context", []) or []) if str(v).strip()]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context[:_limit_value(8)]:
            lines.append(muted(f"- {item}"))

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
            for ip, _count in summary.client_counts.most_common(_FULL_OUTPUT_LIMIT)
        ]
        server_list = [
            f"{ip}({summary.server_counts[ip]}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
            for ip, _count in summary.server_counts.most_common(_FULL_OUTPUT_LIMIT)
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
            dst_text = ", ".join(f"{ip}({cnt})" for ip, cnt in dsts.most_common(_FULL_OUTPUT_LIMIT)) or "-"
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
        for item in summary.artifacts:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


def render_udp_summary(summary: UdpSummary, limit: int = 12, verbose: bool = False) -> str:
    verbose = True
    limit = _FULL_OUTPUT_LIMIT
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"UDP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        for reason in reasons[:_limit_value(8)]:
            lines.append(muted(f"- {reason}"))

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

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic UDP Security Checks"))
        check_labels = {
            "udp_request_response_asymmetry": "UDP request/response asymmetry",
            "reflection_amplification_risk": "Reflection/amplification risk",
            "udp_recon_scan_behavior": "UDP recon/scan behavior",
            "udp_periodic_cadence": "UDP periodic cadence",
            "udp_tunneling_signal": "UDP tunneling/covert signal",
            "udp_zone_boundary_exposure": "UDP zone boundary exposure",
            "ot_udp_boundary_crossing": "OT UDP boundary crossing",
            "udp_role_drift": "UDP role drift",
            "udp_transport_fragmentation_reliability": "UDP transport/reliability abuse",
            "cross_signal_corroboration": "Cross-signal corroboration",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label}: {len(values)}"))
                for item in values[:_limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label}: none"))

    risk_matrix = list(getattr(summary, "risk_matrix", []) or [])
    if risk_matrix:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Risk Matrix"))
        rows = [["Category", "Risk", "Confidence", "Evidence"]]
        for row in risk_matrix[:_limit_value(12)]:
            if not isinstance(row, dict):
                continue
            rows.append([
                str(row.get("category", "")),
                str(row.get("risk", "")),
                str(row.get("confidence", "")),
                str(row.get("evidence", "")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    asymmetry_profiles = list(getattr(summary, "asymmetry_profiles", []) or [])
    if asymmetry_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Asymmetry Matrix"))
        rows = [["Flow", "Packets", "Avg Packet", "Confidence"]]
        for profile in asymmetry_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("flow", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("avg_packet", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    amplification_profiles = list(getattr(summary, "amplification_profiles", []) or [])
    if amplification_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Reflection/Amplification Candidates"))
        rows = [["Client", "Server", "Port", "Ratio", "Confidence"]]
        for profile in amplification_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("client", "-")),
                str(profile.get("server", "-")),
                str(profile.get("port", "-")),
                str(profile.get("ratio", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    recon_profiles = list(getattr(summary, "recon_profiles", []) or [])
    if recon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recon Indicators"))
        rows = [["Source", "Port", "Unique Ports", "Targets", "Confidence"]]
        for profile in recon_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("source", "-")),
                str(profile.get("port", "-")),
                str(profile.get("unique_ports", "-")),
                str(profile.get("targets", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    cadence_profiles = list(getattr(summary, "cadence_profiles", []) or [])
    if cadence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Cadence Anomalies"))
        rows = [["Flow", "Packets", "Duration", "PPS", "Avg Packet"]]
        for profile in cadence_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("flow", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("duration_s", "-")),
                str(profile.get("pps", "-")),
                str(profile.get("avg_packet", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    tunneling_profiles = list(getattr(summary, "tunneling_profiles", []) or [])
    if tunneling_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Encapsulation/Tunneling Suspicion"))
        rows = [["Host", "Queries", "Unique Ratio", "Avg Len", "Entropy", "Confidence"]]
        for profile in tunneling_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                str(profile.get("queries", 0)),
                str(profile.get("unique_ratio", "-")),
                str(profile.get("avg_len", "-")),
                str(profile.get("avg_entropy", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    zone_profiles = list(getattr(summary, "zone_profiles", []) or [])
    if zone_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Posture (East-West / North-South)"))
        rows = [["Src", "Dst", "Port", "Zone", "Packets", "Confidence"]]
        for profile in zone_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("port", "-")),
                str(profile.get("zone", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by UDP Behavior"))
        rows = [["Host", "Dst", "Port", "Reason", "Confidence"]]
        for profile in role_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("port", "-")),
                str(profile.get("reason", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    ot_profiles = list(getattr(summary, "ot_boundary_profiles", []) or [])
    if ot_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Boundary Crossing Profiles"))
        rows = [["Src", "Dst", "Port", "Packets", "Confidence"]]
        for profile in ot_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("port", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    transport_profiles = list(getattr(summary, "transport_profiles", []) or [])
    if transport_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Transport Reliability Anomalies"))
        rows = [["Src", "Dst", "Type", "Bytes", "Confidence"]]
        for profile in transport_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("type", "-")),
                format_bytes_as_mb(int(profile.get("bytes", 0) or 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["Host", "Score", "Confidence", "Reasons"]]
        for finding in corroborated_findings[:limit]:
            if not isinstance(finding, dict):
                continue
            rows.append([
                str(finding.get("host", "-")),
                str(finding.get("score", "-")),
                str(finding.get("confidence", "-")),
                ", ".join(str(v) for v in list(finding.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Flow", "Packets", "Bytes", "Reasons"]]
        for pivot in pivots[:limit]:
            if not isinstance(pivot, dict):
                continue
            rows.append([
                str(pivot.get("flow", "-")),
                str(pivot.get("packets", 0)),
                format_bytes_as_mb(int(pivot.get("bytes", 0) or 0)),
                ", ".join(str(v) for v in list(pivot.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [str(v) for v in list(getattr(summary, "false_positive_context", []) or []) if str(v).strip()]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context[:_limit_value(8)]:
            lines.append(muted(f"- {item}"))

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
            for ip, _count in summary.client_counts.most_common(_FULL_OUTPUT_LIMIT)
        ]
        server_list = [
            f"{ip}({summary.server_counts[ip]}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
            for ip, _count in summary.server_counts.most_common(_FULL_OUTPUT_LIMIT)
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
            dst_text = ", ".join(f"{ip}({cnt})" for ip, cnt in dsts.most_common(_FULL_OUTPUT_LIMIT)) or "-"
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
        for item in summary.artifacts:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


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
    # Analyst-heavy output: always render full detail regardless of -v.
    limit = _FULL_OUTPUT_LIMIT
    verbose = True
    _limit_value = lambda value: _FULL_OUTPUT_LIMIT
    _truncate_text = lambda text, max_len=0: str(text)
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

    def _exfil_verdict() -> tuple[str, str, list[str], int]:
        reasons: list[str] = []
        score = 0

        total = int(summary.total_bytes or 0)
        outbound = int(summary.outbound_bytes or 0)
        outbound_ratio = (outbound / max(total, 1)) if total > 0 else 0.0
        if outbound >= 5_000_000:
            score += 2
            reasons.append(f"Outbound volume {format_bytes_as_mb(outbound)} exceeds high-risk threshold")
        if total >= 2_000_000 and outbound_ratio >= 0.60:
            score += 1
            reasons.append(f"Outbound ratio is {outbound_ratio * 100:.1f}% of capture bytes")

        if summary.outbound_flows:
            top = summary.outbound_flows[0]
            top_bytes = int(top.get("bytes", 0) or 0)
            if top_bytes >= 5_000_000:
                score += 2
                reasons.append(
                    f"Dominant outbound flow {top.get('src')}->{top.get('dst')} carried {format_bytes_as_mb(top_bytes)}"
                )

        if summary.top_external_dsts and outbound >= 3_000_000:
            dst, dst_bytes = summary.top_external_dsts.most_common(1)[0]
            share = dst_bytes / max(outbound, 1)
            if share >= 0.70:
                score += 1
                reasons.append(
                    f"{dst} received {share * 100:.1f}% of outbound bytes ({format_bytes_as_mb(dst_bytes)})"
                )

        if summary.dns_tunnel_suspects:
            strongest_dns_confidence = 0
            for item in summary.dns_tunnel_suspects:
                try:
                    total = int(item.get("total", 0) or 0)
                    unique = int(item.get("unique", 0) or 0)
                    long_q = int(item.get("long", 0) or 0)
                    entropy = float(item.get("avg_entropy", 0.0) or 0.0)
                    max_label = int(item.get("max_label", 0) or 0)
                except Exception:
                    continue

                confidence_points = 0
                if total >= 50 and unique >= int(total * 0.85):
                    confidence_points += 1
                if long_q >= 20:
                    confidence_points += 1
                if entropy >= 3.6:
                    confidence_points += 1
                if max_label >= 45:
                    confidence_points += 1
                if confidence_points > strongest_dns_confidence:
                    strongest_dns_confidence = confidence_points

            if strongest_dns_confidence >= 2:
                score += 4
                reasons.append(
                    f"High-confidence DNS tunneling heuristics triggered by {len(summary.dns_tunnel_suspects)} source(s)"
                )
            else:
                score += 3
                reasons.append(f"DNS tunneling heuristics triggered by {len(summary.dns_tunnel_suspects)} source(s)")
        if summary.http_post_suspects:
            score += 1
            reasons.append(f"Large HTTP POST channels detected ({len(summary.http_post_suspects)})")
        if summary.file_exfil_suspects:
            high_risk_files = [item for item in summary.file_exfil_suspects if int(item.get("risk_score", 0) or 0) >= 5]
            score += 2 if high_risk_files else 1
            reasons.append(
                f"Suspicious file transfer suspects detected ({len(summary.file_exfil_suspects)}; high-risk={len(high_risk_files)})"
            )
        if summary.ot_flows:
            large_ot = [item for item in summary.ot_flows if int(item.get("bytes", 0) or 0) >= 1_000_000]
            if large_ot:
                score += 1
                reasons.append(f"Large OT/ICS control-port transfers observed ({len(large_ot)})")

        if score >= 7:
            verdict = "YES - exfiltration activity is likely occurring in this PCAP based on corroborated indicators."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - exfiltration activity is suspected with multiple supporting indicators."
            confidence = "Medium"
        elif score >= 3:
            verdict = "POSSIBLE - weak-to-moderate exfiltration indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - current heuristics do not show convincing exfiltration activity."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence exfiltration heuristic crossed its threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _exfil_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete evidence context directly in the verdict block for analyst triage.
    if summary.outbound_flows:
        lines.append(muted("Where:"))
        lines.append(muted("- Dominant outbound flows"))
        for item in summary.outbound_flows[:_limit_value(6)]:
            lines.append(
                muted(
                    f"- {item.get('src', '-')}->{item.get('dst', '-')} "
                    f"proto={item.get('proto', '-')} dport={item.get('dst_port', '-')} "
                    f"bytes={format_bytes_as_mb(int(item.get('bytes', 0) or 0))} "
                    f"packets={int(item.get('packets', 0) or 0)}"
                )
            )

    if summary.dns_tunnel_suspects:
        lines.append(muted("What:"))
        lines.append(muted("- DNS tunnel suspects"))
        for item in summary.dns_tunnel_suspects[:_limit_value(6)]:
            lines.append(
                muted(
                    f"- src={item.get('src', '-')} total={item.get('total', '-')} unique={item.get('unique', '-')} "
                    f"long={item.get('long', '-')} entropy={item.get('avg_entropy', '-')} max_label={item.get('max_label', '-')}"
                )
            )

    if summary.http_post_suspects:
        lines.append(muted("What:"))
        lines.append(muted("- HTTP POST exfil channels"))
        for item in summary.http_post_suspects[:_limit_value(6)]:
            lines.append(
                muted(
                    f"- {item.get('src', '-')}->{item.get('dst', '-')} host={item.get('host', '-')} "
                    f"uri={item.get('uri', '-')} bytes={format_bytes_as_mb(int(item.get('bytes', 0) or 0))} "
                    f"req={int(item.get('requests', 0) or 0)} risk={int(item.get('risk_score', 0) or 0)}"
                )
            )

    if getattr(summary, "file_exfil_suspects", None):
        file_suspects = list(summary.file_exfil_suspects or [])
        if file_suspects:
            lines.append(muted("What:"))
            lines.append(muted("- File exfil suspects"))
            for item in file_suspects[:_limit_value(6)]:
                lines.append(
                    muted(
                        f"- {item.get('src', '-')}->{item.get('dst', '-')} file={item.get('filename', '-')} "
                        f"type={item.get('file_type', '-') or '-'} size={format_bytes_as_mb(int(item.get('size', 0) or 0))} "
                        f"risk={int(item.get('risk_score', 0) or 0)} packet={item.get('packet', '-')}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Protocol Checks"))

    protocol_labels = [
        ("dns", "DNS"),
        ("http_https", "HTTP/HTTPS"),
        ("icmp", "ICMP"),
        ("ftp", "FTP"),
        ("smtp", "SMTP"),
        ("websockets", "WebSockets"),
        ("ntp", "NTP"),
    ]
    protocol_checks = getattr(summary, "protocol_exfil_checks", {}) or {}
    for key, label_text in protocol_labels:
        evidence = protocol_checks.get(key, []) if isinstance(protocol_checks, dict) else []
        lines.append(label(f"{label_text} Exfil Check"))
        if evidence:
            lines.append(warn(f"Yes, there is evidence for {label_text} exfil, here is the evidence:"))
            for item in evidence[:_limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(str(item))}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text} exfil in this capture."))

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
        if summary.top_external_dsts:
            top_dst, top_bytes = summary.top_external_dsts.most_common(1)[0]
            share = (top_bytes / max(int(summary.outbound_bytes or 0), 1)) * 100.0
            lines.append(muted(f"Primary external destination: {top_dst} ({format_bytes_as_mb(top_bytes)}, {share:.1f}% of outbound)"))

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
        lines.append(header("Large HTTP POST Payloads (Evidence)"))
        rows = [["Src", "Dst", "Host", "URI", "Bytes", "Req", "Mode", "Risk", "Packets", "Assessment"]]
        for item in summary.http_post_suspects[:limit]:
            bytes_val = int(item.get("bytes", 0) or 0)
            req_val = int(item.get("requests", 1) or 1)
            risk_score = int(item.get("risk_score", 0) or 0)
            packet_examples = str(item.get("packet_examples", item.get("packet", "-")) or "-")
            assessment = "high" if risk_score >= 3 or bytes_val >= 5_000_000 or req_val >= 30 else "medium"
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("host", "-")),
                str(item.get("uri", "-")),
                format_bytes_as_mb(bytes_val),
                str(req_val),
                str(item.get("mode", "single")),
                str(risk_score),
                packet_examples,
                assessment,
            ])
        lines.append(_format_table(rows))

        lines.append(muted("HTTP POST Evidence Details:"))
        for item in summary.http_post_suspects[:_limit_value(10 if verbose else 6)]:
            risk_score = int(item.get("risk_score", 0) or 0)
            risk_reasons = item.get("risk_reasons", [])
            reason_text = ", ".join(str(v) for v in risk_reasons[:3]) if isinstance(risk_reasons, list) and risk_reasons else "-"
            packet_examples = str(item.get("packet_examples", item.get("packet", "-")) or "-")
            lines.append(muted(
                f"- {item.get('src')}->{item.get('dst')} host={item.get('host')} risk={risk_score} "
                f"why={_redact_in_text(reason_text)} packets={packet_examples}"
            ))
            sample_text = str(item.get("sample", "") or "").strip()
            if sample_text and sample_text != "-":
                lines.append(muted(f"  sample={_redact_in_text(sample_text[:120])}"))

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
        lines.append(header("Potential Exfil File Transfers (Evidence)"))
        rows = [["Src", "Dst", "Proto", "File", "Type", "Size", "Risk", "Packet", "Note"]]
        for item in summary.file_exfil_suspects[:limit]:
            size_val = item.get("size")
            risk_score = int(item.get("risk_score", 0) or 0)
            risk_text = "high" if risk_score >= 5 else "medium" if risk_score >= 3 else "low"
            reasons = item.get("risk_reasons", [])
            reason_text = ", ".join(str(r) for r in reasons[:3]) if isinstance(reasons, list) and reasons else "-"
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("protocol", "-")),
                str(item.get("filename", "-")),
                str(item.get("file_type", "-") or "-"),
                format_bytes_as_mb(int(size_val)) if isinstance(size_val, int) else "-",
                f"{risk_text} ({risk_score})",
                str(item.get("packet", "-")),
                reason_text if reason_text != "-" else (str(item.get("note", "-")) if item.get("note") else "-"),
            ])
        lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections (Ranked Evidence)"))
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
    return _finalize_output(lines, show_truncation_note=False)


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

    if getattr(summary, "campaign_summaries", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Beacon Campaign Summary"))
        rows = [["Campaign", "Host", "Cadence", "Flows", "Destinations", "Channels", "Max Score"]]
        for item in summary.campaign_summaries[:limit]:
            rows.append([
                str(item.get("campaign_id", "-")),
                str(item.get("host", "-")),
                str(item.get("cadence_family", "-")),
                str(item.get("flows", "-")),
                str(item.get("destinations", "-")),
                str(item.get("channels", "-")),
                str(item.get("max_score", "-")),
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "host_rollups", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host-Centric Verdict Rollup"))
        rows = [["Host", "Candidates", "Channels", "Destinations", "Top Cadence", "Max Score"]]
        for item in summary.host_rollups[:limit]:
            channels = item.get("channels", [])
            channel_text = ",".join(str(v) for v in channels) if isinstance(channels, list) else str(channels)
            rows.append([
                str(item.get("host", "-")),
                str(item.get("candidate_count", "-")),
                channel_text or "-",
                str(item.get("destinations", "-")),
                f"{float(item.get('top_cadence_s', 0.0) or 0.0):.2f}s",
                str(item.get("max_score", "-")),
            ])
        lines.append(_format_table(rows))

    def _beacon_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        candidates = list(getattr(summary, "candidates", []) or [])
        checks = getattr(summary, "protocol_beacon_checks", {}) or {}
        http_posts = list(getattr(summary, "http_post_beacons", []) or [])

        if candidates:
            top_score = max((float(item.score) for item in candidates), default=0.0)
            if top_score >= 0.85:
                score += 2
                reasons.append(f"Top beacon candidate score is {top_score:.2f}")
            elif top_score >= 0.70:
                score += 1
                reasons.append(f"Top beacon candidate score is {top_score:.2f}")
            if len(candidates) >= 3:
                score += 1
                reasons.append(f"Multiple beacon candidates detected ({len(candidates)})")

        protocol_hits = 0
        if isinstance(checks, dict):
            for key in ("dns", "http_https", "icmp", "ntp"):
                values = checks.get(key, [])
                if isinstance(values, list) and values:
                    protocol_hits += 1
        if protocol_hits:
            score += min(2, protocol_hits)
            reasons.append(f"Deterministic checks found evidence in {protocol_hits} protocol channel(s)")

        if http_posts:
            max_http_risk = max((int(item.get("risk_score", 0) or 0) for item in http_posts), default=0)
            score += 2 if max_http_risk >= 3 else 1
            reasons.append(f"HTTP POST beacon channels detected ({len(http_posts)}; max risk={max_http_risk})")

        if score >= 6:
            verdict = "YES - beaconing activity is likely occurring in this capture."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - beaconing indicators are present with corroborating evidence."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate beaconing indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - current heuristics do not show convincing beaconing activity."
            confidence = "Low"

        if not reasons:
            reasons.append("No beaconing heuristic crossed a high-confidence threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _beacon_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Reasons:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

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

    checks = getattr(summary, "protocol_beacon_checks", {}) or {}
    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Beacon Checks"))
    protocol_labels = [
        ("dns", "DNS"),
        ("http_https", "HTTP/HTTPS"),
        ("icmp", "ICMP"),
        ("ntp", "NTP"),
    ]
    for key, proto_label in protocol_labels:
        evidence = checks.get(key) if isinstance(checks, dict) else []
        evidence_items = [str(item) for item in (evidence or []) if str(item).strip()]
        if evidence_items:
            lines.append(danger(f"Yes, there is evidence for {proto_label} beaconing, here is the evidence:"))
            for item in evidence_items[:_limit_value(10)]:
                lines.append(muted(f"  - {_redact_in_text(item)}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {proto_label} beaconing."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Beacon Category Checks"))
    category_checks = getattr(summary, "deterministic_category_checks", {}) or {}
    category_labels = [
        ("single_target_periodic_c2", "Single-Target Periodic C2"),
        ("multi_target_synchronized", "Multi-Target Synchronized Beaconing"),
        ("cross_protocol_cadence", "Cross-Protocol Cadence Reuse"),
        ("burst_sleep_pattern", "Burst-Sleep Beacon Profile"),
        ("low_slow_persistence", "Low-and-Slow Persistence"),
        ("benign_periodic_likely", "Likely Benign Periodic Pattern"),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in category_labels:
        evidence = category_checks.get(key, []) if isinstance(category_checks, dict) else []
        evidence_items = [str(item) for item in (evidence or []) if str(item).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "benign_periodic_likely":
                lines.append(ok(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            else:
                lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(10 if verbose else 6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
            if key == "benign_periodic_likely":
                matrix_rows.append([label_text, "Low", "Medium", f"{len(evidence_items)} signal(s)"])
            elif key in {"multi_target_synchronized", "cross_protocol_cadence"}:
                matrix_rows.append([label_text, "High", "High", f"{len(evidence_items)} signal(s)"])
            elif key in {"single_target_periodic_c2", "low_slow_persistence"}:
                matrix_rows.append([label_text, "Medium", "Medium", f"{len(evidence_items)} signal(s)"])
            else:
                matrix_rows.append([label_text, "Medium", "Low", f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Beacon Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    if summary.candidates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Beacon Timeline Heatmap"))
        for item in summary.candidates[:limit]:
            cadence = f"{item.mean_interval:.1f}s"
            lines.append(
                f"{item.src_ip}->{item.dst_ip} [{item.proto}] cadence={cadence} {sparkline(item.timeline)}"
            )

    pivots = list(getattr(summary, "beacon_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Actionable Hunting Pivots"))
        rows = [["Src", "Dst", "Proto", "Interval", "Score", "URI Hash", "First", "Last"]]
        for item in pivots[:limit]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("proto", "-")),
                f"{float(item.get('interval', 0.0) or 0.0):.2f}s",
                str(item.get("score", "-")),
                str(item.get("uri_template_hash", "-")),
                format_ts(item.get("first_seen")),
                format_ts(item.get("last_seen")),
            ])
        lines.append(_format_table(rows))

    explainability = list(getattr(summary, "explainability", []) or [])
    if explainability:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Explainability"))
        for item in explainability[:_limit_value(12 if verbose else 8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    http_post_beacons = list(getattr(summary, "http_post_beacons", []) or [])
    if http_post_beacons:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP POST Beacon Discovery"))
        rows = [["Source", "Destination", "Host", "URI(s)", "Req", "Bytes", "Stability", "Linked", "Risk", "Packets"]]
        for item in http_post_beacons[:_limit_value(10)]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("host", "-")),
                str(item.get("uri", "-")),
                str(int(item.get("requests", 0) or 0)),
                str(int(item.get("bytes", 0) or 0)),
                f"{float(item.get('size_stability', 0.0) or 0.0):.2f}",
                f"{float(item.get('linked_beacon_score', 0.0) or 0.0):.2f}",
                str(int(item.get("risk_score", 0) or 0)),
                str(item.get("packet_examples", "-")),
            ])
        lines.append(_format_table(rows))
        lines.append(muted("HTTP POST Beacon Evidence Details:"))
        for item in http_post_beacons[:_limit_value(10 if verbose else 6)]:
            reason_values = item.get("risk_reasons", [])
            reason_text = ", ".join(str(v) for v in reason_values[:3]) if isinstance(reason_values, list) and reason_values else "-"
            lines.append(muted(
                f"- {item.get('src')}->{item.get('dst')} host={item.get('host')} risk={int(item.get('risk_score', 0) or 0)} "
                f"why={_redact_in_text(reason_text)}"
            ))
            sample_text = str(item.get("sample", "") or "").strip()
            if sample_text and sample_text != "-":
                lines.append(muted(f"  sample={_redact_in_text(sample_text[:120])}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_threats_summary(summary: ThreatSummary, verbose: bool = False) -> str:
    # Analyst-heavy output: always render full detail regardless of -v.
    verbose = True
    _limit_value = lambda value: _FULL_OUTPUT_LIMIT
    _truncate_text = lambda text, max_len=0: str(text)

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

    def _is_network_attack_detection(item: dict[str, object]) -> bool:
        source = str(item.get("source", "")).strip().lower()
        summary_text = str(item.get("summary", "")).strip().lower()
        details_text = str(item.get("details", "")).strip().lower()
        blob = f"{source} {summary_text} {details_text}"

        network_sources = {
            "arp",
            "dhcp",
            "dns",
            "icmp",
            "tcp",
            "udp",
            "recon",
            "traffic",
            "auth",
            "lateral",
            "c2",
            "exfil",
            "payload",
            "smb",
            "rdp",
            "winrm",
            "ssh",
            "rpc",
            "snmp",
            "suricata",
        }
        if source in network_sources:
            return True

        strong_network_tokens = (
            "arp",
            "spoof",
            "poison",
            "mitm",
            "man in the middle",
            "scan",
            "probing",
            "recon",
            "syn",
            "flood",
            "dos",
            "denial of service",
            "udp flood",
            "dns tunn",
            "beacon",
            "c2",
            "lateral movement",
            "brute-force",
            "authentication fail",
            "public->",
            "private->public",
            "exfil",
        )
        return any(token in blob for token in strong_network_tokens)

    detections = [item for item in detections if _is_network_attack_detection(item)]

    def _threats_verdict() -> tuple[str, str, list[str], int]:
        reasons: list[str] = []
        score = 0
        sev = Counter(str(item.get("severity", "info")).lower() for item in detections)
        if sev.get("critical", 0):
            score += min(4, int(sev.get("critical", 0) or 0) * 2)
            reasons.append(f"Critical detections observed ({int(sev.get('critical', 0) or 0)})")
        if sev.get("high", 0):
            score += min(3, int(sev.get("high", 0) or 0))
            reasons.append(f"High-severity detections observed ({int(sev.get('high', 0) or 0)})")
        if len(detections) >= 8:
            score += 1
            reasons.append(f"Detection volume is elevated ({len(detections)})")
        if summary.public_ot_pairs:
            score += 1
            reasons.append(f"Public OT/ICS communication pairs observed ({len(summary.public_ot_pairs)})")
        if getattr(summary, "suricata_metadata", None):
            score += 1
            reasons.append("Suricata corroboration is present")

        if score >= 7:
            return "YES - high-confidence network attack activity is present.", "High", reasons, score
        if score >= 4:
            return "LIKELY - suspicious network attack activity is present.", "Medium", reasons, score
        if score >= 2:
            return "POSSIBLE - weak-to-moderate attack indicators are present.", "Low", reasons, score
        return "NO STRONG SIGNAL - no convincing high-confidence attack pattern from current heuristics.", "Low", reasons if reasons else ["No high-confidence heuristic crossed threshold"], score

    verdict, confidence, verdict_reasons, verdict_score = _threats_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    if detections:
        lines.append(muted("What:"))
        lines.append(muted("- Top detections"))
        for item in detections[:_limit_value(8)]:
            lines.append(
                muted(
                    f"- [{str(item.get('severity', 'info')).upper()}] {_redact_in_text(str(item.get('summary', '-')))} "
                    f"(source={item.get('source', '-')})"
                )
            )

    source_counter: Counter[str] = Counter()
    destination_counter: Counter[str] = Counter()
    for item in detections:
        for key, target_counter in (("top_sources", source_counter), ("top_clients", source_counter), ("top_destinations", destination_counter), ("top_servers", destination_counter)):
            values = item.get(key)
            if not isinstance(values, list):
                continue
            for pair in values[:_limit_value(6)]:
                if isinstance(pair, tuple) and len(pair) >= 2:
                    try:
                        target_counter[str(pair[0])] += int(pair[1])
                    except Exception:
                        continue

    if source_counter:
        lines.append(muted("Who:"))
        lines.append(muted("- Top suspected sources"))
        for ip_value, count in source_counter.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip_value))}: {int(count)}"))
    if destination_counter:
        lines.append(muted("Where:"))
        lines.append(muted("- Top targeted destinations"))
        for ip_value, count in destination_counter.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip_value))}: {int(count)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overview"))
    lines.append(_format_kv("Scope", "Network-based attacks only"))
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

    suricata_mode = bool(getattr(summary, "suricata_metadata", None)) or any(
        str(item.get("source", "")).strip().lower() == "suricata" for item in detections
    )
    if suricata_mode:
        suricata_metadata = getattr(summary, "suricata_metadata", {}) or {}
        suricata_checks = getattr(summary, "suricata_checks", {}) or {}
        suricata_event_counts = getattr(summary, "suricata_event_counts", {}) or {}
        suricata_pivots = getattr(summary, "suricata_pivots", {}) or {}

        if suricata_metadata:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Suricata Run Metadata"))
            for key, label_text in (
                ("engine", "Engine"),
                ("version", "Version"),
                ("binary", "Binary"),
                ("rules", "Rules"),
                ("rules_age_days", "Rules Age (days)"),
                ("config", "Config"),
                ("scan_seconds", "Scan Duration (s)"),
                ("exit_code", "Exit Code"),
                ("pcap_sha256", "PCAP SHA256"),
                ("eve_lines", "EVE Lines"),
                ("event_types", "Event Types Parsed"),
                ("pcaps_scanned", "PCAPs Scanned"),
            ):
                if key in suricata_metadata and suricata_metadata.get(key) not in {None, ""}:
                    lines.append(_format_kv(label_text, str(suricata_metadata.get(key))))

        if suricata_checks:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Deterministic Suricata Checks"))
            check_labels = [
                ("ids_alert_presence", "IDS Alert Presence"),
                ("high_severity_alerts", "High-Severity Alert Cluster"),
                ("multi_host_fanout", "Multi-Host Fanout"),
                ("dns_suspicious_activity", "DNS Suspicious Activity"),
                ("http_c2_upload_activity", "HTTP C2/Upload Activity"),
                ("tls_sni_anomaly", "TLS SNI/Handshake Anomaly"),
                ("file_transfer_artifacts", "File Transfer Artifacts"),
                ("engine_health", "Engine Health"),
            ]
            matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
            for key, label_text in check_labels:
                evidence_items = suricata_checks.get(key, []) if isinstance(suricata_checks, dict) else []
                evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
                lines.append(label(label_text))
                if evidence_items:
                    lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                    for item in evidence_items[:_limit_value(8 if verbose else 5)]:
                        lines.append(muted(f"- {_redact_in_text(item)}"))
                    risk = "High" if key in {"high_severity_alerts", "multi_host_fanout", "ids_alert_presence"} else "Medium"
                    confidence_level = "High" if len(evidence_items) >= 2 else "Medium"
                    if key == "engine_health":
                        risk = "Low"
                        confidence_level = "Medium"
                    matrix_rows.append([label_text, risk, confidence_level, f"{len(evidence_items)} signal(s)"])
                else:
                    lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
                    matrix_rows.append([label_text, "None", "Low", "No matching detections"])
            lines.append(SUBSECTION_BAR)
            lines.append(header("Suricata Risk Matrix"))
            lines.append(_format_table(matrix_rows))

        if suricata_event_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Suricata Event Coverage"))
            rows = [["Event Type", "Count"]]
            for event_name, count in sorted(suricata_event_counts.items(), key=lambda item: (-int(item[1]), str(item[0]))):
                rows.append([str(event_name), str(count)])
            lines.append(_format_table(rows))

        if suricata_pivots:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Suricata Analyst Pivots"))
            top_sources = suricata_pivots.get("top_sources", []) if isinstance(suricata_pivots, dict) else []
            top_destinations = suricata_pivots.get("top_destinations", []) if isinstance(suricata_pivots, dict) else []
            top_signatures = suricata_pivots.get("top_signatures", []) if isinstance(suricata_pivots, dict) else []
            if top_sources:
                lines.append(muted("Top Sources:"))
                for ip_value, count in top_sources[:_limit_value(10)]:
                    lines.append(muted(f"- {_highlight_public_ips(str(ip_value))}: {int(count)}"))
            if top_destinations:
                lines.append(muted("Top Destinations:"))
                for ip_value, count in top_destinations[:_limit_value(10)]:
                    lines.append(muted(f"- {_highlight_public_ips(str(ip_value))}: {int(count)}"))
            if top_signatures:
                lines.append(muted("Top Signatures:"))
                for sig_value, count in top_signatures[:_limit_value(10)]:
                    lines.append(muted(f"- {_redact_in_text(str(sig_value))}: {int(count)}"))

    if detections:
        severity_counts: Counter[str] = Counter(str(item.get("severity", "info")).lower() for item in detections)
        lines.append(SUBSECTION_BAR)
        lines.append(header("Severity Breakdown"))
        for sev in ("critical", "high", "warning", "info"):
            if sev in severity_counts:
                lines.append(muted(f"- {sev}: {severity_counts[sev]}"))

        def _max_pair_count(values: object) -> int:
            if not isinstance(values, list) or not values:
                return 0
            try:
                return max(int(pair[1]) for pair in values if isinstance(pair, tuple) and len(pair) >= 2)
            except Exception:
                return 0

        def _item_strength(item: dict[str, object]) -> int:
            severity = str(item.get("severity", "info")).lower()
            base = {"critical": 40, "high": 30, "warning": 20, "info": 0}.get(severity, 0)
            evidence = item.get("evidence")
            evidence_count = len(evidence) if isinstance(evidence, list) else (1 if isinstance(evidence, str) and evidence.strip() else 0)
            source_signal = _max_pair_count(item.get("top_sources"))
            destination_signal = _max_pair_count(item.get("top_destinations"))
            client_signal = _max_pair_count(item.get("top_clients"))
            server_signal = _max_pair_count(item.get("top_servers"))
            return base + min(10, evidence_count * 2) + min(10, max(source_signal, destination_signal, client_signal, server_signal))

        severity_order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
        ranked = sorted(
            detections,
            key=lambda item: (
                severity_order.get(str(item.get("severity", "info")).lower(), 99),
                -_item_strength(item),
                str(item.get("source", "")),
                str(item.get("summary", "")),
            ),
        )

        max_rows = _limit_value(30 if verbose else 12)
        displayed = ranked[:max_rows]

        def _is_sweep_detection(item: dict[str, object]) -> bool:
            source = str(item.get("source", "")).lower()
            summary_text = str(item.get("summary", "")).lower()
            if source not in {"tcp", "udp", "recon"}:
                return False
            return "port sweep" in summary_text or "host sweep" in summary_text

        def _split_sweep_details(details_text: str) -> list[str]:
            text = details_text.strip()
            if not text:
                return []
            # Sweep details are commonly emitted as comma-delimited items.
            parts = [chunk.strip() for chunk in text.split(",")]
            return [chunk for chunk in parts if chunk]

        def _is_large_outbound_transfer(item: dict[str, object]) -> bool:
            source = str(item.get("source", "")).lower().strip()
            summary_text = str(item.get("summary", "")).lower().strip()
            return source == "tcp" and "large outbound tcp transfer" in summary_text

        lines.append(SUBSECTION_BAR)
        lines.append(header("Actionable Detections"))
        for item in displayed:
            severity = str(item.get("severity", "info")).lower()
            source = str(item.get("source", "Threats"))
            summary_text = _highlight_public_ips(_redact_in_text(str(item.get("summary", ""))))
            details = _highlight_public_ips(_redact_in_text(str(item.get("details", ""))))

            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")

            lines.append(f"{marker} {summary_text} {muted(f'({source})')}")
            if details:
                if _is_sweep_detection(item):
                    lines.append(muted("  Sweep Details:"))
                    for entry in _split_sweep_details(details):
                        lines.append(muted(f"    - {_highlight_public_ips(_redact_in_text(entry))}"))
                elif _is_large_outbound_transfer(item):
                    transfer_src = str(item.get("transfer_src", "") or "-")
                    transfer_dst = str(item.get("transfer_dst", "") or "-")
                    transfer_bytes = int(item.get("transfer_bytes", 0) or 0)
                    transfer_packets = int(item.get("transfer_packets", 0) or 0)
                    transfer_first_seen = safe_float(item.get("transfer_first_seen"))
                    transfer_last_seen = safe_float(item.get("transfer_last_seen"))
                    transfer_duration = safe_float(item.get("transfer_duration"))
                    transfer_ports = item.get("transfer_ports")

                    lines.append(muted("  Who:"))
                    lines.append(muted(f"    - Source: {_highlight_public_ips(_redact_in_text(transfer_src))}"))
                    lines.append(muted(f"    - Destination: {_highlight_public_ips(_redact_in_text(transfer_dst))}"))

                    lines.append(muted("  What:"))
                    lines.append(muted(f"    - Bytes sent: {transfer_bytes}"))
                    if transfer_packets:
                        lines.append(muted(f"    - Packets: {transfer_packets}"))

                    if isinstance(transfer_ports, list) and transfer_ports:
                        port_text = ", ".join(
                            f"{int(port)}({int(count)})"
                            for port, count in transfer_ports[:_limit_value(10)]
                        )
                        lines.append(muted(f"    - Destination ports: {port_text}"))

                    lines.append(muted("  When:"))
                    if transfer_first_seen is not None:
                        lines.append(muted(f"    - First seen: {format_ts(transfer_first_seen)}"))
                    if transfer_last_seen is not None:
                        lines.append(muted(f"    - Last seen: {format_ts(transfer_last_seen)}"))
                    if transfer_duration is not None:
                        lines.append(muted(f"    - Duration: {transfer_duration:.1f}s"))

                    lines.append(muted("  Where:"))
                    lines.append(muted(f"    - Flow: {_highlight_public_ips(_redact_in_text(transfer_src))} -> {_highlight_public_ips(_redact_in_text(transfer_dst))}"))

                    evidence = item.get("evidence")
                    if isinstance(evidence, list) and evidence:
                        lines.append(muted("  Transfer Clues:"))
                        for entry in evidence[:_limit_value(10 if verbose else 5)]:
                            lines.append(muted(f"    - {_highlight_public_ips(_redact_in_text(str(entry)))}"))
                else:
                    lines.append(muted(f"  {_truncate_text(details, 180)}"))

            context_parts: list[str] = []
            for key, label_text in (
                ("top_sources", "src"),
                ("top_destinations", "dst"),
                ("top_clients", "client"),
                ("top_servers", "server"),
            ):
                values = item.get(key)
                if isinstance(values, list) and values:
                    value_text = ", ".join(
                        f"{_highlight_public_ips(str(ip))}({count})"
                        for ip, count in values[:_limit_value(3)]
                    )
                    context_parts.append(f"{label_text}: {value_text}")
            if context_parts:
                lines.append(muted(f"  {' | '.join(context_parts)}"))

            if not _is_large_outbound_transfer(item):
                evidence = item.get("evidence")
                if isinstance(evidence, list) and evidence:
                    for entry in evidence[:_limit_value(5 if verbose else 2)]:
                        lines.append(muted(f"    - {_highlight_public_ips(_redact_in_text(str(entry)))}"))
                elif isinstance(evidence, str) and evidence.strip():
                    lines.append(muted(f"    - {_highlight_public_ips(_redact_in_text(evidence))}"))

        hidden_count = max(0, len(ranked) - len(displayed))
        if hidden_count:
            lines.append(muted(f"{hidden_count} additional detection(s) suppressed for readability."))

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
            for item in ranked:
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
    return _finalize_output(lines, show_truncation_note=False)


def render_mitre_summary(summary: MitreSummary, verbose: bool = False) -> str:
    # MITRE is an analyst-first report: always render full detail regardless of -v.
    verbose = True
    _limit_value = lambda value: _FULL_OUTPUT_LIMIT
    _truncate_text = lambda text, max_len=0: str(text)

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MITRE ATT&CK MAPPING :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(SUBSECTION_BAR)
    lines.append(header("ATT&CK Corpus"))
    lines.append(_format_kv("Enterprise Corpus", str(getattr(summary, "attack_enterprise_version", "-"))))
    lines.append(_format_kv("ICS Corpus", str(getattr(summary, "attack_ics_version", "-"))))
    lines.append(_format_kv("Mapping Pack", str(getattr(summary, "mapping_pack_version", "-"))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Executive Assessment"))
    verdict = str(getattr(summary, "executive_verdict", "") or "LOW-CONFIDENCE SIGNAL")
    confidence = str(getattr(summary, "executive_confidence", "low") or "low")
    if verdict.startswith("LIKELY"):
        lines.append(danger(verdict))
    elif verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", confidence))
    for reason in (getattr(summary, "executive_reasons", []) or [])[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(str(reason))}"))

    checks = getattr(summary, "checks", {}) or {}
    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Checks"))
    check_labels = [
        ("cross_signal_corroboration", "Cross-Signal Corroboration"),
        ("sequence_plausibility", "Sequence Plausibility"),
        ("ics_process_impact", "ICS Process/Safety Impact"),
        ("host_boundary_activity", "Host Boundary Activity"),
    ]
    matrix_rows = [["Check", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
            risk = "High" if key in {"cross_signal_corroboration", "ics_process_impact"} else "Medium"
            conf_level = "High" if len(evidence_items) >= 2 else "Medium"
            matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching evidence"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("MITRE Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[:_limit_value(10)]:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Coverage"))
    lines.append(_format_kv("Total Detections", str(summary.total_detections)))
    lines.append(_format_kv("Mapped to ATT&CK", str(summary.mapped_detections)))
    if summary.total_detections > 0:
        ratio = (float(summary.mapped_detections) / float(summary.total_detections)) * 100.0
        lines.append(_format_kv("Mapping Ratio", f"{ratio:.1f}%"))
    if summary.first_seen is not None:
        lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
    if summary.last_seen is not None:
        lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", f"{summary.duration_seconds:.1f}s"))
    lines.append(_format_kv("Framework Split", _format_counter(summary.framework_counts, 4)))
    lines.append(_format_kv("Top Tactics", _format_counter(summary.tactic_counts, 8, key_max=56)))
    lines.append(_format_kv("Top Techniques", _format_counter(summary.technique_counts, 10, key_max=64)))
    lines.append(_format_kv("Top Procedures", _format_counter(summary.procedure_counts, 8, key_max=70)))

    technique_heat = list(getattr(summary, "technique_heat", []) or [])
    if technique_heat:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Technique Heat Table"))
        rows = [["Framework", "Tactic", "Technique", "Count", "Hosts", "Sources", "Evidence", "Confidence", "First", "Last"]]
        for item in technique_heat[:_limit_value(30 if verbose else 14)]:
            rows.append([
                str(item.get("framework", "-")),
                str(item.get("tactic", "-")),
                f"{item.get('technique', '-')} ({item.get('technique_id', '-')})",
                str(item.get("count", "-")),
                str(item.get("host_count", "-")),
                str(item.get("source_count", "-")),
                str(item.get("evidence_count", "-")),
                str(item.get("confidence", "-")),
                format_ts(item.get("first_seen")),
                format_ts(item.get("last_seen")),
            ])
        lines.append(_format_table(rows))

    host_paths = getattr(summary, "host_attack_paths", {}) or {}
    host_roles = getattr(summary, "host_roles", {}) or {}
    if host_paths:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host-Centric ATT&CK Chains"))
        rows = [["Host", "Role(s)", "Chain Length", "Chain Preview"]]
        for host, chain in list(host_paths.items())[:_limit_value(24 if verbose else 10)]:
            role_text = ",".join(host_roles.get(host, [])[:4]) if isinstance(host_roles, dict) else "-"
            preview = " -> ".join(chain[:3]) if chain else "-"
            rows.append([
                str(host),
                role_text or "-",
                str(len(chain)),
                _truncate_text(preview, 120),
            ])
        lines.append(_format_table(rows))

    sequence_issues = list(getattr(summary, "sequence_issues", []) or [])
    if sequence_issues:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence Plausibility Warnings"))
        for item in sequence_issues[:_limit_value(10 if verbose else 6)]:
            lines.append(warn(f"- {_redact_in_text(str(item))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Attack Path Visualization"))
    if summary.attack_path:
        unique_nodes: list[str] = []
        seen_nodes: set[str] = set()
        for edge in summary.attack_path[:_limit_value(40 if verbose else 20)]:
            lines.append(f"  {muted('->')} {edge}")
            for node in [part.strip() for part in edge.split("->") if part.strip()]:
                if node not in seen_nodes:
                    seen_nodes.add(node)
                    unique_nodes.append(node)
        if unique_nodes:
            lines.append(muted("Path Nodes:"))
            for idx, node in enumerate(unique_nodes[:_limit_value(18 if verbose else 10)], start=1):
                lines.append(muted(f"  {idx:02d}. {node}"))
    else:
        lines.append(muted("No attack chain could be inferred from current detections."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Evidence and Artifacts/IOC"))
    lines.append(_format_kv("IOC Highlights", _format_counter(summary.ioc_counts, 12, key_max=56)))
    lines.append(_format_kv("Artifact Highlights", _format_counter(summary.artifact_counts, 12, key_max=56)))
    total_evidence_items = sum(len(hit.evidence) for hit in summary.hits)
    total_packet_refs = sum(len(list(getattr(hit, "packet_refs", []) or [])) for hit in summary.hits)
    total_flow_refs = sum(len(list(getattr(hit, "flow_refs", []) or [])) for hit in summary.hits)
    total_host_refs = sum(len(list(getattr(hit, "host_refs", []) or [])) for hit in summary.hits)
    lines.append(_format_kv("Evidence Entries", str(total_evidence_items)))
    lines.append(_format_kv("Packet References", str(total_packet_refs)))
    lines.append(_format_kv("Flow References", str(total_flow_refs)))
    lines.append(_format_kv("Host References", str(total_host_refs)))

    if summary.hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Evidence Deep Dive"))
        rows = [["Technique", "Source", "Severity", "Confidence", "Evidence", "Packets", "Flows", "Hosts"]]
        for hit in summary.hits[:_limit_value(200)]:
            rows.append([
                f"{hit.technique} ({hit.technique_id})",
                str(hit.source),
                str(hit.severity),
                str(hit.confidence),
                str(len(hit.evidence)),
                str(len(list(getattr(hit, "packet_refs", []) or []))),
                str(len(list(getattr(hit, "flow_refs", []) or []))),
                str(len(list(getattr(hit, "host_refs", []) or []))),
            ])
        lines.append(_format_table(rows))

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Investigation Pivots"))
        rows = [["Technique", "Source", "Hosts", "Flows", "Packets", "IOC/Artifact"]]
        for item in pivots[:_limit_value(18 if verbose else 8)]:
            hosts = item.get("hosts", [])
            flows = item.get("flows", [])
            packets = item.get("packets", [])
            iocs = item.get("iocs", [])
            artifacts = item.get("artifacts", [])
            ioc_art = ", ".join([str(v) for v in (iocs[:2] if isinstance(iocs, list) else [])] + [str(v) for v in (artifacts[:2] if isinstance(artifacts, list) else [])])
            rows.append([
                f"{item.get('technique_id', '-')} {item.get('tactic', '-')}",
                str(item.get("source", "-")),
                ",".join(str(v) for v in (hosts[:3] if isinstance(hosts, list) else [])) or "-",
                ",".join(str(v) for v in (flows[:2] if isinstance(flows, list) else [])) or "-",
                ",".join(str(v) for v in (packets[:4] if isinstance(packets, list) else [])) or "-",
                _truncate_text(ioc_art or "-", 120),
            ])
        lines.append(_format_table(rows))

    alternates = list(getattr(summary, "alternate_explanations", []) or [])
    if alternates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Alternative Explanations"))
        for item in alternates[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if summary.hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TTP Details"))
        max_hits = _limit_value(200)
        for hit in summary.hits[:max_hits]:
            title = (
                f"[{hit.framework.upper()}] {hit.tactic} ({hit.tactic_id}) -> "
                f"{hit.technique} ({hit.technique_id})"
            )
            lines.append(label(title))
            lines.append(muted(f"  Procedure: {hit.procedure}"))
            lines.append(muted(f"  Source/Severity/Confidence: {hit.source} / {hit.severity} / {hit.confidence}"))
            lines.append(muted(f"  Occurrence: {hit.occurrence}"))
            lines.append(muted(f"  First/Last Seen: {format_ts(hit.first_seen)} / {format_ts(hit.last_seen)}"))
            lines.append(muted(f"  Corroborating Sources: {int(getattr(hit, 'corroborating_sources', 0) or 0)}"))
            if getattr(hit, "rationale", ""):
                lines.append(muted(f"  Rationale: {_truncate_text(_redact_in_text(str(hit.rationale)), 260)}"))
            if getattr(hit, "matched_keywords", None):
                lines.append(muted(f"  Matched Keywords: {', '.join(list(getattr(hit, 'matched_keywords', []) or [])[:8])}"))
            if getattr(hit, "packet_refs", None):
                lines.append(muted(f"  Packet Refs: {', '.join(list(getattr(hit, 'packet_refs', []) or [])[:8])}"))
            if getattr(hit, "flow_refs", None):
                lines.append(muted(f"  Flow Refs: {', '.join(list(getattr(hit, 'flow_refs', []) or [])[:4])}"))
            if getattr(hit, "host_refs", None):
                lines.append(muted(f"  Host Refs: {', '.join(list(getattr(hit, 'host_refs', []) or [])[:8])}"))
            if getattr(hit, "contradictory_signals", None):
                lines.append(muted(f"  Contradictions: {', '.join(list(getattr(hit, 'contradictory_signals', []) or []))}"))
            if hit.details:
                lines.append(muted(f"  Explanation: {_truncate_text(_redact_in_text(hit.details), 240)}"))
            if hit.evidence:
                lines.append(muted("  Evidence:"))
                for idx, evidence in enumerate(hit.evidence[:_limit_value(200)], start=1):
                    lines.append(muted(f"    {idx:02d}. {_redact_in_text(str(evidence))}"))
            if hit.artifacts:
                lines.append(muted(f"  Artifacts: {', '.join(hit.artifacts[:_limit_value(40)])}"))
            if hit.iocs:
                lines.append(muted(f"  IOC: {', '.join(hit.iocs[:_limit_value(40)])}"))
        hidden = max(0, len(summary.hits) - max_hits)
        if hidden:
            lines.append(muted(f"{hidden} additional mapped TTP entries suppressed for readability."))
    else:
        lines.append(muted("No MITRE ATT&CK TTP mappings were derived from this capture."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


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

    def _files_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])
        checks = getattr(summary, "deterministic_checks", {}) or {}

        def _check_count(key: str) -> int:
            values = checks.get(key, []) if isinstance(checks, dict) else []
            return len([v for v in (values or []) if str(v).strip()])

        high_weight_checks = {
            "multi_signal_masquerade": 3,
            "archive_container_abuse": 3,
            "macro_script_lolbas_staging": 3,
            "exfiltration_file_movement": 3,
            "lateral_copy_propagation": 4,
            "auth_file_correlation": 2,
            "reputation_or_prevalence_outlier": 1,
            "reconstruction_confidence": 1,
        }
        for key, base_weight in high_weight_checks.items():
            count = _check_count(key)
            if not count:
                continue
            score += min(4, base_weight + min(2, count - 1))
            reasons.append(f"{key.replace('_', ' ')} evidence ({count})")

        high_findings = sum(1 for d in detections if str(d.get("severity", "")).lower() in {"high", "critical"})
        warn_findings = sum(1 for d in detections if str(d.get("severity", "")).lower() == "warning")
        if high_findings:
            score += min(3, high_findings)
            reasons.append(f"High-severity file detections observed ({high_findings})")
        if warn_findings >= 2:
            score += 1
            reasons.append(f"Multiple warning-level file detections observed ({warn_findings})")

        if score >= 8:
            verdict = "YES - high-confidence malicious file activity is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - suspicious file activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - risky file-transfer behavior is present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious file pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence file threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _files_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    if summary.artifacts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top source hosts by artifact count"))
        src_counts = Counter(item.src_ip for item in summary.artifacts if item.src_ip)
        for ip, count in src_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))

        lines.append(muted("Where:"))
        lines.append(muted("- Top destinations by artifact count"))
        dst_counts = Counter(item.dst_ip for item in summary.artifacts if item.dst_ip)
        for ip, count in dst_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))

        lines.append(muted("What:"))
        lines.append(muted("- Top transferred filenames"))
        name_counts = Counter(item.filename for item in summary.artifacts if item.filename)
        for name, count in name_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_redact_in_text(str(name))}: {int(count)}"))

    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(muted("When:"))
            lines.append(muted("- Incident cluster context"))
            for item in clusters[:_limit_value(4)]:
                lines.append(
                    muted(
                        f"- {_redact_in_text(str(item.get('cluster', '-')))} src={_highlight_public_ips(str(item.get('src', '-')))} "
                        f"findings={len(item.get('findings', []) if isinstance(item.get('findings', []), list) else [])}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Files Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("reconstruction_confidence", "Reconstruction Confidence"),
        ("multi_signal_masquerade", "Multi-signal Masquerade"),
        ("archive_container_abuse", "Archive/Container Abuse"),
        ("macro_script_lolbas_staging", "Macro/Script/LOLBAS Staging"),
        ("exfiltration_file_movement", "Exfiltration File Movement"),
        ("lateral_copy_propagation", "Lateral Copy Propagation"),
        ("auth_file_correlation", "Auth-to-File Correlation"),
        ("reputation_or_prevalence_outlier", "Reputation/Prevalence Outliers"),
    ]
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))

            if key in {"multi_signal_masquerade", "archive_container_abuse", "macro_script_lolbas_staging", "exfiltration_file_movement", "lateral_copy_propagation"}:
                risk = "High"
                conf_level = "High"
            elif key in {"auth_file_correlation", "reputation_or_prevalence_outlier"}:
                risk = "Medium"
                conf_level = "Medium"
            else:
                risk = "Low"
                conf_level = "Low"
            matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Files Risk Matrix"))
    lines.append(_format_table(matrix_rows))

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

    if getattr(summary, "lineage_chains", None):
        chains = list(summary.lineage_chains or [])
        if chains:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Artifact Lineage Chains"))
            rows = [["Source", "Steps", "Evidence"]]
            for item in chains[:effective_limit]:
                steps = item.get("steps", [])
                evidence = item.get("evidence", [])
                rows.append([
                    _highlight_public_ips(str(item.get("src", "-"))),
                    _truncate_text("; ".join(str(v) for v in steps[:3]) if isinstance(steps, list) else str(steps), 70),
                    _truncate_text(", ".join(_redact_in_text(str(v)) for v in evidence[:4]) if isinstance(evidence, list) else _redact_in_text(str(evidence)), 90),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Incident Clusters"))
            rows = [["Cluster", "Source", "Artifacts", "Findings", "Confidence"]]
            for item in clusters[:effective_limit]:
                findings = item.get("findings", [])
                rows.append([
                    str(item.get("cluster", "-")),
                    _highlight_public_ips(str(item.get("src", "-"))),
                    str(item.get("artifacts", "-")),
                    _truncate_text("; ".join(str(v) for v in findings[:3]) if isinstance(findings, list) else str(findings), 76),
                    str(item.get("confidence", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "campaign_indicators", None):
        campaigns = list(summary.campaign_indicators or [])
        if campaigns:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Shared Campaign Indicators"))
            rows = [["Indicator", "Value", "Hosts"]]
            for item in campaigns[:effective_limit]:
                hosts = item.get("hosts", [])
                host_text = ", ".join(_highlight_public_ips(str(v)) for v in hosts[:4]) if isinstance(hosts, list) else "-"
                rows.append([
                    _truncate_text(str(item.get("indicator", "-")), 42),
                    _truncate_text(_redact_in_text(str(item.get("value", "-"))), 42),
                    _truncate_text(host_text or "-", 68),
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

    if getattr(summary, "benign_context", None):
        notes = [str(v) for v in (summary.benign_context or []) if str(v).strip()]
        if notes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for note in notes[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(note)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_protocols_summary(summary: ProtocolSummary, verbose: bool = False) -> str:
    # Protocol output is intentionally always full-detail for analyst workflows.
    verbose = True
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"PROTOCOL & CONVERSATION ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        for reason in reasons:
            lines.append(muted(f"- {reason}"))

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

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Protocol Security Checks"))
        check_labels = {
            "protocol_identity_mismatch": "Protocol identity mismatch",
            "anomalous_protocol_sequence": "Anomalous protocol sequence",
            "boundary_cross_zone_protocol": "Boundary cross-zone protocol",
            "tunneling_or_encapsulation_signal": "Tunneling/encapsulation signal",
            "periodic_beacon_profile": "Periodic beacon profile",
            "role_inversion_signal": "Role inversion signal",
            "ot_protocol_boundary_crossing": "OT protocol boundary crossing",
            "rare_or_low_prevalence_protocol": "Rare/low-prevalence protocol",
            "cross_protocol_corroboration": "Cross-protocol corroboration",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label}: {len(values)}"))
                for item in values:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label}: none"))

    risk_matrix = list(getattr(summary, "risk_matrix", []) or [])
    if risk_matrix:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Risk Matrix"))
        rows = [["Category", "Risk", "Confidence", "Evidence"]]
        for row in risk_matrix:
            if not isinstance(row, dict):
                continue
            rows.append([
                str(row.get("category", "")),
                str(row.get("risk", "")),
                str(row.get("confidence", "")),
                str(row.get("evidence", "")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["Host", "Score", "Confidence", "Reasons"]]
        for finding in corroborated_findings:
            if not isinstance(finding, dict):
                continue
            rows.append([
                str(finding.get("host", "-")),
                str(finding.get("score", 0)),
                str(finding.get("confidence", "-")),
                ", ".join(str(v) for v in list(finding.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    sequence_profiles = list(getattr(summary, "sequence_profiles", []) or [])
    if sequence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Sequence Integrity"))
        rows = [["Entity", "Sequence", "Evidence", "Confidence"]]
        for profile in sequence_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("entity", "-")),
                " -> ".join(str(v) for v in list(profile.get("sequence", []) or [])) or "-",
                str(profile.get("evidence_count", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    zone_profiles = list(getattr(summary, "zone_protocol_profiles", []) or [])
    if zone_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Posture (East-West / North-South)"))
        rows = [["Src", "Dst", "Proto", "Zone", "Packets", "Confidence"]]
        for profile in zone_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("protocol", "-")),
                str(profile.get("zone_pair", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    baseline_profiles = list(getattr(summary, "baseline_drift_profiles", []) or [])
    if baseline_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Baseline Drift"))
        rows = [["Protocol", "Baseline", "Current %", "Status"]]
        for profile in baseline_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("protocol", "-")),
                str(profile.get("baseline_prevalence", "-")),
                str(profile.get("current_prevalence_pct", "-")),
                str(profile.get("status", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    tunneling_profiles = list(getattr(summary, "tunneling_profiles", []) or [])
    if tunneling_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Encapsulation/Tunneling Suspicion"))
        rows = [["Src", "Dst", "Proto", "Avg Payload", "Packets", "Confidence"]]
        for profile in tunneling_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("protocol", "-")),
                str(profile.get("avg_payload", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    beacon_profiles = list(getattr(summary, "beacon_profiles", []) or [])
    if beacon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Cadence Anomalies"))
        rows = [["Src", "Dst", "Proto", "Packets", "Duration", "PPS"]]
        for profile in beacon_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("src", "-")),
                str(profile.get("dst", "-")),
                str(profile.get("protocol", "-")),
                str(profile.get("packets", 0)),
                str(profile.get("duration_s", "-")),
                str(profile.get("pps", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_inversion_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by Protocol"))
        rows = [["Host", "Protocol", "Protocol Count", "Zone", "Confidence"]]
        for profile in role_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                str(profile.get("protocol", "-")),
                str(profile.get("protocol_count", 0)),
                str(profile.get("zone", "-")),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Conversation", "Protocol", "Packets", "Bytes", "Reasons"]]
        for pivot in pivots:
            if not isinstance(pivot, dict):
                continue
            rows.append([
                str(pivot.get("conversation", "-")),
                str(pivot.get("protocol", "-")),
                str(pivot.get("packets", 0)),
                format_bytes_as_mb(int(pivot.get("bytes", 0) or 0)),
                ", ".join(str(v) for v in list(pivot.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [
        str(v) for v in list(getattr(summary, "false_positive_context", []) or []) if str(v).strip()
    ]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context:
            lines.append(muted(f"- {item}"))

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
            limit = len(grouped_items)
            for (sev, a_type, desc), data in grouped_items[:limit]:
                sev_color = danger if sev in ("HIGH", "CRITICAL") else warn if sev == "MEDIUM" else muted
                lines.append(sev_color(f"[{sev}] {a_type}: {desc} (x{data['count']})"))
                examples = data.get("examples", [])
                if examples:
                    for ex in examples:
                        lines.append(muted(f"  example: {ex}"))
    else:
        lines.append(SUBSECTION_BAR)
        lines.append(ok("No clear anomalies detected."))

    # 4. Conversations (Top 10 by bytes)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Conversations (by volume)"))
    
    sorted_convs = sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)
    
    rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "Duration", "Ports"]]
    for c in sorted_convs:
        # Sort ports by value for consistent display
        ports_list = sorted(list(c.ports))
        ports_str = ",".join(map(str, ports_list))
        
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
        sorted_eps = sorted(summary.endpoints, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True)
        rows = [["Address", "Sent", "Recv", "Total Bytes", "Protocols"]]
        for e in sorted_eps:
             protos = ",".join(sorted(str(p) for p in list(e.protocols)))
             rows.append([
                 e.address, 
                 str(e.packets_sent), 
                 str(e.packets_recv), 
                 format_bytes_as_mb(e.bytes_sent + e.bytes_recv), 
                 protos
             ])
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


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
        for risk in sorted(summary.risks, key=lambda x: x.severity):
            sev_color = danger if risk.severity in ("CRITICAL", "HIGH") else warn
            if risk.severity == "LOW":
                sev_color = muted
            lines.append(sev_color(f"[{risk.severity}] {risk.title}"))
            lines.append(f"  Target: {risk.affected_asset}")
            lines.append(muted(f"  Details: {risk.description}"))
            lines.append("")

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        if reasons:
            for reason in reasons:
                lines.append(muted(f"- {reason}"))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Service Security Checks"))
        check_labels = {
            "service_identity_mismatch": "Service identity mismatch",
            "rare_or_newly_exposed_service": "Rare/newly exposed service",
            "lateral_admin_surface": "Lateral admin surface",
            "public_edge_admin_exposure": "Public edge admin exposure",
            "service_drift_or_churn": "Service drift/churn",
            "beacon_or_periodic_service_profile": "Beacon/periodic profile",
            "ot_it_boundary_mix": "OT/IT boundary mix",
            "udp_amplification_readiness": "UDP amplification readiness",
            "legacy_or_weak_service_hygiene": "Legacy/weak hygiene",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label}: {len(values)}"))
                for item in values:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label}: none"))

    risk_matrix = list(getattr(summary, "risk_matrix", []) or [])
    if risk_matrix:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Risk Matrix"))
        rows = [["Category", "Risk", "Confidence", "Evidence"]]
        for row in risk_matrix:
            if not isinstance(row, dict):
                continue
            rows.append([
                str(row.get("category", "")),
                str(row.get("risk", "")),
                str(row.get("confidence", "")),
                str(row.get("evidence", "")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    mismatch_profiles = list(getattr(summary, "service_mismatch_profiles", []) or [])
    if mismatch_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Mismatch Profiles"))
        rows = [["Asset", "Service", "Software", "Reasons"]]
        for profile in mismatch_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("asset", "-")),
                str(profile.get("service", "-")),
                str(profile.get("software", "-")),
                ", ".join(str(v) for v in list(profile.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    drift_profiles = list(getattr(summary, "service_drift_profiles", []) or [])
    if drift_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Drift Profiles"))
        rows = [["Host", "Service", "Ports", "Banner Count"]]
        for profile in drift_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                str(profile.get("service", "-")),
                ",".join(str(v) for v in list(profile.get("ports", []) or [])) or "-",
                str(profile.get("banner_count", 0)),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    lateral_profiles = list(getattr(summary, "lateral_surface_profiles", []) or [])
    if lateral_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Surface Profiles"))
        rows = [["Host", "Admin Ports", "Count", "Confidence"]]
        for profile in lateral_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                ",".join(str(v) for v in list(profile.get("admin_ports", []) or [])) or "-",
                str(profile.get("admin_port_count", 0)),
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    boundary_profiles = list(getattr(summary, "boundary_exposure_profiles", []) or [])
    if boundary_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Boundary Exposure Profiles"))
        rows = [["Asset", "Service", "Clients", "Packets"]]
        for profile in boundary_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("asset", "-")),
                str(profile.get("service", "-")),
                str(profile.get("clients", 0)),
                str(profile.get("packets", 0)),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    ot_it_profiles = list(getattr(summary, "ot_it_crossing_profiles", []) or [])
    if ot_it_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/IT Crossing Profiles"))
        rows = [["Host", "OT Ports", "Admin Ports", "Confidence"]]
        for profile in ot_it_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append([
                str(profile.get("host", "-")),
                ",".join(str(v) for v in list(profile.get("ot_ports", []) or [])) or "-",
                ",".join(str(v) for v in list(profile.get("admin_ports", []) or [])) or "-",
                str(profile.get("confidence", "-")),
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Asset", "Service", "Clients", "Packets", "Reasons"]]
        for pivot in pivots:
            if not isinstance(pivot, dict):
                continue
            rows.append([
                str(pivot.get("asset", "-")),
                str(pivot.get("service", "-")),
                str(pivot.get("clients", 0)),
                str(pivot.get("packets", 0)),
                ", ".join(str(v) for v in list(pivot.get("reasons", []) or [])) or "-",
            ])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [str(v) for v in list(getattr(summary, "false_positive_context", []) or []) if str(v).strip()]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


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

    def _creds_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_conf = int(getattr(summary, "confidence_counts", Counter()).get("high", 0))
        medium_conf = int(getattr(summary, "confidence_counts", Counter()).get("medium", 0))
        if high_conf:
            score += min(3, high_conf)
            reasons.append(f"High-confidence credential exposures observed ({high_conf})")
        if medium_conf >= 3:
            score += 1
            reasons.append(f"Multiple medium-confidence exposures observed ({medium_conf})")
        if getattr(summary, "auth_abuse_sequences", None):
            score += 2
            reasons.append(f"Authentication abuse sequence indicators observed ({len(summary.auth_abuse_sequences)})")
        if getattr(summary, "replay_candidates", None):
            score += 2
            reasons.append(f"Credential replay candidates observed ({len(summary.replay_candidates)})")
        if getattr(summary, "token_fanout", None):
            score += 2
            reasons.append(f"Token fan-out misuse observed ({len(summary.token_fanout)})")
        if getattr(summary, "privileged_exposures", None):
            score += 2
            reasons.append(f"Privileged-account credential exposure observed ({len(summary.privileged_exposures)})")
        if getattr(summary, "external_exposures", None):
            score += 1
            reasons.append(f"Credential material exposed to public destinations ({len(summary.external_exposures)})")

        if score >= 8:
            verdict = "YES - high-confidence credential compromise exposure is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - significant credential exposure risk is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate credential exposure indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk credential exposure pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence credential exposure heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _creds_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Reasons:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Credential Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("plaintext_credential_exposure", "Plaintext Credential Exposure"),
        ("auth_abuse_pattern", "Authentication Abuse Pattern"),
        ("credential_replay", "Credential Replay Behavior"),
        ("privileged_account_exposure", "Privileged Account Exposure"),
        ("token_misuse_fanout", "Token Misuse/Fan-out"),
        ("external_destination_exposure", "External Destination Exposure"),
        ("likely_benign_test_credentials", "Likely Benign Test Credentials"),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "likely_benign_test_credentials":
                lines.append(ok(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                matrix_rows.append([label_text, "Low", "Medium", f"{len(evidence_items)} signal(s)"])
            else:
                lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                risk = "High" if key in {"auth_abuse_pattern", "credential_replay", "token_misuse_fanout", "privileged_account_exposure"} else "Medium"
                conf = "High" if key in {"credential_replay", "token_misuse_fanout"} else "Medium"
                matrix_rows.append([label_text, risk, conf, f"{len(evidence_items)} signal(s)"])
            for item in evidence_items[:_limit_value(8 if show_secrets else 5)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Credential Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    if getattr(summary, "auth_abuse_sequences", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Authentication Abuse Sequences"))
        rows = [["Source", "Events", "Users", "Targets"]]
        for item in summary.auth_abuse_sequences[:_limit_value(12)]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("events", "-")),
                str(item.get("users", "-")),
                str(item.get("dsts", "-")),
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "replay_candidates", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Credential Replay Candidates"))
        rows = [["Type", "Value", "Destinations", "Top Targets"]]
        for item in summary.replay_candidates[:_limit_value(12)]:
            dsts = item.get("dsts", [])
            dst_text = ", ".join(str(v) for v in dsts[:_limit_value(4)]) if isinstance(dsts, list) else str(dsts)
            rows.append([
                str(item.get("type", "-")),
                _truncate_text(str(item.get("value", "-")), 28),
                str(item.get("dst_count", "-")),
                dst_text or "-",
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "token_fanout", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Token Fan-out Misuse"))
        rows = [["Token", "Destinations", "Top Targets"]]
        for item in summary.token_fanout[:_limit_value(12)]:
            dsts = item.get("dsts", [])
            dst_text = ", ".join(str(v) for v in dsts[:_limit_value(4)]) if isinstance(dsts, list) else str(dsts)
            rows.append([
                _truncate_text(str(item.get("token", "-")), 28),
                str(item.get("dst_count", "-")),
                dst_text or "-",
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "privileged_exposures", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Privileged Account Exposures"))
        rows = [["User", "Source", "Destination", "Type", "Packet"]]
        for item in summary.privileged_exposures[:_limit_value(12)]:
            rows.append([
                str(item.get("user", "-")),
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("kind", "-")),
                str(item.get("pkt", "-")),
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "external_exposures", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("External Destination Exposures"))
        rows = [["Source", "Destination", "Type", "User", "Packet"]]
        for item in summary.external_exposures[:_limit_value(12)]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("kind", "-")),
                str(item.get("user", "-")),
                str(item.get("pkt", "-")),
            ])
        lines.append(_format_table(rows))

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

    def _cert_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        if summary.weak_keys:
            score += min(2, len(summary.weak_keys))
            reasons.append(f"Weak key certificates detected ({len(summary.weak_keys)})")
        if summary.weak_signatures:
            score += min(2, len(summary.weak_signatures))
            reasons.append(f"Weak signature algorithms detected ({len(summary.weak_signatures)})")
        if summary.expired:
            score += 1
            reasons.append(f"Expired/invalid certificates detected ({len(summary.expired)})")
        if summary.eku_mismatches or summary.key_usage_issues:
            score += 1
            reasons.append("EKU/KeyUsage mismatches observed")
        if summary.name_mismatches:
            score += 1
            reasons.append(f"Name/SAN mismatches observed ({len(summary.name_mismatches)})")
        if summary.issuer_impersonation:
            score += 2
            reasons.append(f"Issuer/SAN impersonation signals observed ({len(summary.issuer_impersonation)})")
        if summary.fingerprint_reuse or summary.serial_reuse:
            score += 1
            reasons.append("Fingerprint/serial reuse across contexts observed")

        if score >= 7:
            verdict = "YES - high-confidence certificate security risks or interception indicators are present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - significant certificate anomalies are present and require investigation."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - certificate anomalies are present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk certificate abuse pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence certificate threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _cert_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Certificate Security Checks"))

    checks: list[tuple[str, list[dict[str, object]]]] = [
        ("Chain/Trust Gaps", list(getattr(summary, "chain_gaps", []) or [])),
        ("Weak Signature Algorithms", list(getattr(summary, "weak_signatures", []) or [])),
        ("EKU/KeyUsage Mismatch", list(getattr(summary, "eku_mismatches", []) or []) + list(getattr(summary, "key_usage_issues", []) or [])),
        ("Name/SAN Mismatch", list(getattr(summary, "name_mismatches", []) or [])),
        ("Validity Outliers", list(getattr(summary, "validity_outliers", []) or [])),
        ("Issuer/SAN Impersonation", list(getattr(summary, "issuer_impersonation", []) or [])),
        ("Fingerprint/Serial Reuse", list(getattr(summary, "fingerprint_reuse", []) or []) + list(getattr(summary, "serial_reuse", []) or [])),
        ("Revocation Posture Gaps", list(getattr(summary, "revocation_gaps", []) or [])),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for label_text, evidence_items in checks:
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(6)]:
                if isinstance(item, dict):
                    if "subject" in item and "reason" in item:
                        ev = f"subject={item.get('subject')} reason={item.get('reason')} src={item.get('src', '-')} dst={item.get('dst', '-')}"
                    elif "sha256" in item:
                        ev = f"sha256={item.get('sha256')} contexts={item.get('count')}"
                    elif "serial" in item:
                        ev = f"serial={item.get('serial')} contexts={item.get('count')}"
                    else:
                        ev = ", ".join(f"{k}={v}" for k, v in item.items())
                else:
                    ev = str(item)
                lines.append(muted(f"- {_redact_in_text(ev)}"))

            if label_text in {"Weak Signature Algorithms", "Issuer/SAN Impersonation", "Fingerprint/Serial Reuse"}:
                matrix_rows.append([label_text, "High", "High", f"{len(evidence_items)} signal(s)"])
            elif label_text in {"Chain/Trust Gaps", "EKU/KeyUsage Mismatch", "Name/SAN Mismatch", "Validity Outliers"}:
                matrix_rows.append([label_text, "Medium", "Medium", f"{len(evidence_items)} signal(s)"])
            else:
                matrix_rows.append([label_text, "Low", "Low", f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Certificate Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    endpoint_profiles = list(getattr(summary, "endpoint_profiles", []) or [])
    if endpoint_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Endpoint Certificate Profiles"))
        rows = [["Endpoint", "Certs", "Subjects", "Issuers", "Flows", "Latest NotAfter"]]
        for item in endpoint_profiles[:_limit_value(12)]:
            rows.append([
                str(item.get("endpoint", "-")),
                str(item.get("fingerprints", "-")),
                str(item.get("subjects", "-")),
                str(item.get("issuers", "-")),
                str(item.get("flows", "-")),
                str(item.get("latest_not_after", "-")),
            ])
        lines.append(_format_table(rows))

    timeline = list(getattr(summary, "timeline", []) or [])
    if timeline:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Certificate Timeline"))
        rows = [["Event", "Subject", "Issuer", "Src", "Dst", "NotAfter"]]
        for item in timeline[:_limit_value(15)]:
            rows.append([
                str(item.get("event", "-")),
                _truncate_text(str(item.get("subject", "-")), 48),
                _truncate_text(str(item.get("issuer", "-")), 48),
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("not_after", "-")),
            ])
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Actionable Hunting Pivots"))
        rows = [["SHA256", "Serial", "Subject", "Issuer", "SAN", "Flow"]]
        for cert in summary.artifacts[:_limit_value(12)]:
            rows.append([
                cert.sha256[:12],
                cert.serial,
                _truncate_text(cert.subject, 30),
                _truncate_text(cert.issuer, 30),
                _truncate_text(cert.san, 24),
                f"{cert.src_ip}->{cert.dst_ip}",
            ])
        lines.append(_format_table(rows))

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
    lines.append(header("Analyst Verdict"))
    verdict = summary.analyst_verdict or "NO STRONG SIGNAL - no convincing high-confidence health risk pattern from current heuristics"
    confidence = (summary.analyst_confidence or "low").strip().lower()
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", confidence.capitalize()))
    if summary.analyst_reasons:
        lines.append(muted("Why confidence:"))
        for reason in summary.analyst_reasons[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(reason))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Health Security Checks"))
    checks = summary.deterministic_checks or {}
    check_labels = [
        ("syn_scan_or_exhaustion", "SYN Scan or Service Exhaustion"),
        ("tcp_reset_storm", "TCP Reset Storm"),
        ("persistent_zero_window", "Persistent Zero-Window"),
        ("udp_reflection_amplification", "UDP Reflection/Amplification"),
        ("qos_marking_anomaly", "QoS Marking Anomaly"),
        ("snmp_exposure_risk", "SNMP Exposure Risk"),
        ("ot_cycle_instability", "OT Cycle-Time Instability"),
        ("certificate_hygiene_risk", "Certificate Hygiene Risk"),
        ("sequence_degradation_chain", "Sequence Degradation Chain"),
        ("zone_policy_drift", "Peer Trust Zoning Drift"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = [str(v) for v in list(checks.get(key, []) or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
            risk = "High" if key in {"udp_reflection_amplification", "snmp_exposure_risk", "ot_cycle_instability", "sequence_degradation_chain"} else "Medium"
            conf = "High" if key in {"snmp_exposure_risk", "evidence_provenance"} else "Medium"
            matrix_rows.append([label_text, risk, conf, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Health Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    sequence_rows = list(getattr(summary, "sequence_findings", []) or [])
    if sequence_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence-Based Degradation Checks"))
        rows = [["Sequence", "Confidence", "Details"]]
        for item in sequence_rows[:_limit_value(10)]:
            rows.append([
                str(item.get("sequence", "-")),
                str(item.get("confidence", "-")).upper(),
                _truncate_text(str(item.get("details", "-")), 90),
            ])
        lines.append(_format_table(rows))

    host_rows = list(getattr(summary, "host_risk_profiles", []) or [])
    if host_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Per-Host Risk Profiles"))
        rows = [["Host", "Score", "Severity", "Confidence", "SYN", "RST", "ZeroWin", "Targets", "Reasons"]]
        for item in host_rows[:_limit_value(12)]:
            reasons = item.get("reasons", [])
            reason_text = " | ".join(str(v) for v in reasons[:3]) if isinstance(reasons, list) else str(reasons)
            rows.append([
                str(item.get("host", "-")),
                str(item.get("score", "-")),
                str(item.get("severity", "-")).upper(),
                str(item.get("confidence", "-")).upper(),
                str(item.get("syn", "-")),
                str(item.get("rst", "-")),
                str(item.get("zero_window", "-")),
                str(item.get("targets", "-")),
                _truncate_text(reason_text or "-", 72),
            ])
        lines.append(_format_table(rows))

    outlier_rows = list(getattr(summary, "outlier_windows", []) or [])
    if outlier_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Temporal Outlier Windows"))
        rows = [["Metric", "Window Start", "Window End", "Value", "Baseline", "Threshold", "Sample"]]
        for item in outlier_rows[:_limit_value(12)]:
            rows.append([
                str(item.get("metric", "-")),
                format_ts(item.get("window_start")),
                format_ts(item.get("window_end")),
                str(item.get("value", "-")),
                str(item.get("baseline", "-")),
                str(item.get("threshold", "-")),
                _truncate_text(str(item.get("sample", "-")), 72),
            ])
        lines.append(_format_table(rows))

    snmp_rows = list(getattr(summary, "snmp_risks", []) or [])
    if snmp_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SNMP Security Analytics"))
        rows = [["Risk", "Details"]]
        for item in snmp_rows[:_limit_value(10)]:
            rows.append([
                str(item.get("risk", "-")),
                _truncate_text(str(item.get("details", "-")), 96),
            ])
        lines.append(_format_table(rows))

    ot_rows = list(getattr(summary, "ot_risk_profiles", []) or [])
    if ot_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Health Safety Checks"))
        rows = [["Family", "Session", "Avg(s)", "Std(s)", "CV", "Samples", "Severity"]]
        for item in ot_rows[:_limit_value(10)]:
            rows.append([
                str(item.get("family", "-")),
                _truncate_text(str(item.get("session", "-")), 44),
                f"{float(item.get('avg', 0.0)):.3f}",
                f"{float(item.get('std', 0.0)):.3f}",
                f"{float(item.get('cv', 0.0)):.2f}",
                str(item.get("count", "-")),
                str(item.get("severity", "-")).upper(),
            ])
        lines.append(_format_table(rows))

    if summary.zone_anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Peer Trust Zoning Checks"))
        for item in summary.zone_anomalies[:_limit_value(10)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    anchors = list(getattr(summary, "evidence_anchors", []) or [])
    if anchors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Evidence Anchors"))
        rows = [["Packet", "Signal", "Details"]]
        for item in anchors[:_limit_value(12)]:
            rows.append([
                str(item.get("packet", "-")),
                str(item.get("signal", "-")),
                _truncate_text(str(item.get("details", "-")), 88),
            ])
        lines.append(_format_table(rows))

    benign = list(getattr(summary, "benign_context", []) or [])
    if benign:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in benign[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

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
    # Analyst-heavy output: always render full detail regardless of -v.
    limit = _FULL_OUTPUT_LIMIT
    verbose = True
    _limit_value = lambda value: _FULL_OUTPUT_LIMIT
    _truncate_text = lambda text, max_len=0: str(text)

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

    def _compromised_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_hosts = [host for host in summary.compromised_hosts if host.severity in {"high", "critical"}]
        if high_hosts:
            score += min(4, len(high_hosts))
            reasons.append(f"High-severity compromised hosts identified ({len(high_hosts)})")
        if getattr(summary, "incidents", None):
            score += 1
            reasons.append(f"Incident clusters detected ({len(summary.incidents)})")
        if getattr(summary, "campaigns", None):
            score += 2
            reasons.append(f"Shared campaign indicators across hosts ({len(summary.campaigns)})")

        checks = getattr(summary, "deterministic_checks", {}) or {}
        staged = checks.get("multi_stage_sequence", []) if isinstance(checks, dict) else []
        if staged:
            score += 2
            reasons.append(f"Multi-stage compromise sequencing observed ({len(staged)})")

        if score >= 7:
            verdict = "YES - high-confidence host compromise activity is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - multiple compromise indicators are present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate compromise indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-confidence compromise pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence compromise heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _compromised_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete evidence context directly in the verdict block for analyst triage.
    if summary.compromised_hosts:
        lines.append(muted("Who:"))
        lines.append(muted("- Compromised hosts"))
        for host in summary.compromised_hosts[:_limit_value(8)]:
            lines.append(
                muted(
                    f"- {(host.hostname or '-')} ({host.ip}) severity={host.severity} "
                    f"score={host.score} detected={format_ts(host.detection_time)}"
                )
            )

    incidents = list(getattr(summary, "incidents", []) or [])
    if incidents:
        lines.append(muted("When:"))
        lines.append(muted("- Incident clusters"))
        for item in incidents[:_limit_value(8)]:
            stages = item.get("stages", [])
            stage_text = ",".join(str(v) for v in stages[:5]) if isinstance(stages, list) else str(stages)
            lines.append(
                muted(
                    f"- host={item.get('ip', '-')} events={item.get('count', '-')} "
                    f"window={format_ts(item.get('first_ts'))}..{format_ts(item.get('last_ts'))} "
                    f"stages={stage_text or '-'}"
                )
            )

    campaigns = list(getattr(summary, "campaigns", []) or [])
    if campaigns:
        lines.append(muted("What:"))
        lines.append(muted("- Shared campaign indicators"))
        for item in campaigns[:_limit_value(8)]:
            hosts = item.get("hosts", [])
            host_text = ", ".join(str(v) for v in hosts[:_limit_value(5)]) if isinstance(hosts, list) else str(hosts)
            lines.append(
                muted(
                    f"- {item.get('campaign_id', '-')} ioc={_redact_in_text(str(item.get('ioc', '-')))} "
                    f"host_count={item.get('host_count', '-')} hosts={host_text or '-'}"
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Compromise Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("credential_abuse", "Credential Abuse Evidence"),
        ("beacon_c2", "Beacon/C2 Evidence"),
        ("exfiltration", "Exfiltration Evidence"),
        ("lateral_movement", "Lateral Movement Evidence"),
        ("multi_stage_sequence", "Multi-Stage Sequence Evidence"),
        ("high_confidence_ioc", "High-Confidence IOC Correlation"),
        ("benign_automation_likely", "Likely Benign Automation"),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "benign_automation_likely":
                lines.append(ok(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                risk = "Low"
                conf_level = "Medium"
            else:
                lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                risk = "High" if key in {"multi_stage_sequence", "high_confidence_ioc"} else "Medium"
                conf_level = "High" if key in {"multi_stage_sequence", "high_confidence_ioc"} else "Medium"
            for item in evidence_items[:_limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
            matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Compromise Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    priority_rows = list(getattr(summary, "host_priority", []) or [])
    if priority_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Priority Queue"))
        rows = [["Host", "IP", "Score", "Severity", "Stages", "IOC Count", "Detection Time"]]
        for item in priority_rows[:limit]:
            stages = item.get("stages", [])
            stage_text = ",".join(stages) if isinstance(stages, list) else str(stages)
            rows.append([
                str(item.get("host", "-")),
                str(item.get("ip", "-")),
                str(item.get("score", "-")),
                str(item.get("severity", "-")),
                stage_text or "-",
                str(item.get("ioc_count", "-")),
                format_ts(item.get("detection_time")),
            ])
        lines.append(_format_table(rows))

    incidents = list(getattr(summary, "incidents", []) or [])
    if incidents:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Incident Timeline"))
        rows = [["Host IP", "First", "Last", "Events", "Stages", "Duration"]]
        for item in incidents[:limit]:
            first_ts = item.get("first_ts")
            last_ts = item.get("last_ts")
            duration = None
            if isinstance(first_ts, (int, float)) and isinstance(last_ts, (int, float)):
                duration = max(0.0, float(last_ts) - float(first_ts))
            stages = item.get("stages", [])
            rows.append([
                str(item.get("ip", "-")),
                format_ts(first_ts),
                format_ts(last_ts),
                str(item.get("count", "-")),
                ",".join(str(v) for v in stages) if isinstance(stages, list) else str(stages),
                format_duration(duration),
            ])
        lines.append(_format_table(rows))

    campaigns = list(getattr(summary, "campaigns", []) or [])
    if campaigns:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Campaign Correlation"))
        rows = [["Campaign", "Shared IOC", "Host Count", "Hosts"]]
        for item in campaigns[:limit]:
            hosts = item.get("hosts", [])
            host_text = ", ".join(str(v) for v in hosts[:_limit_value(4)]) if isinstance(hosts, list) else str(hosts)
            if isinstance(hosts, list) and len(hosts) > _limit_value(4):
                host_text += "..."
            rows.append([
                str(item.get("campaign_id", "-")),
                _truncate_text(str(item.get("ioc", "-")), 48),
                str(item.get("host_count", "-")),
                host_text or "-",
            ])
        lines.append(_format_table(rows))

    benign_context = list(getattr(summary, "benign_context", []) or [])
    if benign_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in benign_context[:_limit_value(10 if verbose else 6)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if not summary.compromised_hosts:
        lines.append(SUBSECTION_BAR)
        lines.append(ok("No hosts met compromise thresholds based on available evidence."))
        lines.append(SECTION_BAR)
        return _finalize_output(lines, show_truncation_note=False)

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
    return _finalize_output(lines, show_truncation_note=False)


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
    lines.append(header("Analyst Verdict"))
    verdict = str(getattr(summary, "analyst_verdict", "") or "NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE HOST RISK PATTERN")
    confidence = str(getattr(summary, "analyst_confidence", "low") or "low").capitalize()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or []) if str(v).strip()]
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", confidence))
    lines.append(muted("Why confidence:"))
    for reason in reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    checks = getattr(summary, "deterministic_checks", {}) or {}
    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Host Security Checks"))
    check_labels = [
        ("host_role_impersonation_or_drift", "Host Role Impersonation or Drift"),
        ("east_west_lateral_fanout", "East-West Lateral Fan-out"),
        ("service_exposure_risk", "Service Exposure Risk"),
        ("identity_drift_or_collision", "Identity Drift or Collision"),
        ("protocol_consistency_mismatch", "Protocol Consistency Mismatch"),
        ("boundary_cross_zone_exposure", "Boundary Cross-Zone Exposure"),
        ("beacon_or_periodic_profile", "Beacon or Periodic Profile"),
        ("ot_it_boundary_crossing", "OT/IT Boundary Crossing"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    for key, label_text in check_labels:
        lines.append(label(label_text))
        values = [str(v) for v in list(checks.get(key, []) or []) if str(v).strip()]
        if values:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for value in values[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(value)}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Host Risk Matrix"))
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    matrix_items = list(getattr(summary, "risk_matrix", []) or [])
    if matrix_items:
        for item in matrix_items[:_limit_value(12)]:
            matrix_rows.append([
                str(item.get("category", "-")),
                str(item.get("risk", "-")),
                str(item.get("confidence", "-")),
                str(item.get("evidence", "-")),
            ])
    else:
        for key, label_text in check_labels[:6]:
            evidence_count = len([str(v) for v in list(checks.get(key, []) or []) if str(v).strip()])
            matrix_rows.append([
                label_text,
                "Medium" if evidence_count else "None",
                "Medium" if evidence_count else "Low",
                str(evidence_count) if evidence_count else "No matching detections",
            ])
    lines.append(_format_table(matrix_rows))

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

    host_risks = list(getattr(summary, "host_risk_profiles", []) or [])
    if host_risks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Priority Host Queue"))
        rows = [["Host", "Score", "Severity", "Confidence", "OS", "Reasons"]]
        for item in host_risks[:_limit_value(limit if verbose else 15)]:
            reasons_val = item.get("reasons", [])
            rows.append([
                str(item.get("host", "-")),
                str(item.get("score", "-")),
                str(item.get("severity", "-")),
                str(item.get("confidence", "-")),
                _truncate_text(str(item.get("os", "-")), 32),
                _truncate_text(", ".join(str(v) for v in (reasons_val[:3] if isinstance(reasons_val, list) else [])) or "-", 90),
            ])
        lines.append(_format_table(rows))

    lateral_profiles = list(getattr(summary, "lateral_movement_profiles", []) or [])
    if lateral_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Analytics"))
        rows = [["Host", "Admin Ports", "Port Count", "Confidence"]]
        for item in lateral_profiles[:_limit_value(limit if verbose else 12)]:
            ports = item.get("admin_ports", [])
            rows.append([
                str(item.get("host", "-")),
                ", ".join(str(v) for v in (ports[:8] if isinstance(ports, list) else [])) or "-",
                str(item.get("admin_port_count", "-")),
                str(item.get("confidence", "-")),
            ])
        lines.append(_format_table(rows))

    role_drift = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_drift:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift Profiles"))
        rows = [["Host", "Roles", "Hostnames", "Admin Ports", "OS"]]
        for item in role_drift[:_limit_value(limit if verbose else 12)]:
            roles = item.get("roles", [])
            hostnames = item.get("hostnames", [])
            admin_ports = item.get("admin_ports", [])
            rows.append([
                str(item.get("host", "-")),
                _truncate_text(", ".join(str(v) for v in (roles[:4] if isinstance(roles, list) else [])) or "-", 50),
                _truncate_text(", ".join(str(v) for v in (hostnames[:3] if isinstance(hostnames, list) else [])) or "-", 70),
                _truncate_text(", ".join(str(v) for v in (admin_ports[:8] if isinstance(admin_ports, list) else [])) or "-", 40),
                _truncate_text(str(item.get("os", "-")), 28),
            ])
        lines.append(_format_table(rows))

    identity_drift = list(getattr(summary, "identity_drift_profiles", []) or [])
    if identity_drift:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Identity Drift Profiles"))
        rows = [["Hostname", "Host Count", "Hosts"]]
        for item in identity_drift[:_limit_value(limit if verbose else 12)]:
            hosts = item.get("hosts", [])
            rows.append([
                _truncate_text(str(item.get("hostname", "-")), 50),
                str(item.get("host_count", "-")),
                _truncate_text(", ".join(str(v) for v in (hosts[:6] if isinstance(hosts, list) else [])) or "-", 90),
            ])
        lines.append(_format_table(rows))

    clusters = list(getattr(summary, "incident_clusters", []) or [])
    if clusters:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Incident Clusters"))
        rows = [["Cluster", "Host", "Indicators", "Targets", "Confidence"]]
        for item in clusters[:_limit_value(limit if verbose else 12)]:
            indicators = item.get("indicators", [])
            rows.append([
                str(item.get("cluster", "-")),
                str(item.get("host", "-")),
                str(len(indicators) if isinstance(indicators, list) else 0),
                str(item.get("target_count", "-")),
                str(item.get("confidence", "-")),
            ])
        lines.append(_format_table(rows))

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Host", "Hostnames", "OS", "Ports", "Why"]]
        for item in pivots[:_limit_value(limit if verbose else 12)]:
            hostnames = item.get("hostnames", [])
            ports = item.get("ports", [])
            reasons_val = item.get("reasons", [])
            rows.append([
                str(item.get("host", "-")),
                _truncate_text(", ".join(str(v) for v in (hostnames[:3] if isinstance(hostnames, list) else [])) or "-", 60),
                _truncate_text(str(item.get("os", "-")), 28),
                _truncate_text(", ".join(str(v) for v in (ports[:6] if isinstance(ports, list) else [])) or "-", 80),
                _truncate_text(", ".join(str(v) for v in (reasons_val[:3] if isinstance(reasons_val, list) else [])) or "-", 90),
            ])
        lines.append(_format_table(rows))

    false_positive = [str(v) for v in list(getattr(summary, "false_positive_context", []) or []) if str(v).strip()]
    if false_positive:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for note in false_positive[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(note)}"))

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

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    verdict = str(getattr(summary, "analyst_verdict", "") or "NO STRONG SIGNAL - NO CONVINCING HOSTNAME ABUSE PATTERN FROM CURRENT HEURISTICS")
    confidence = str(getattr(summary, "analyst_confidence", "low") or "low").capitalize()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or []) if str(v).strip()]
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", confidence))
    lines.append(muted("Why confidence:"))
    for reason in reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    checks = getattr(summary, "deterministic_checks", {}) or {}
    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Hostname Security Checks"))
    check_labels = [
        ("hostname_collision_or_spoofing", "Hostname Collision or Spoofing"),
        ("ip_alias_or_fronting_anomaly", "IP Alias or Fronting Anomaly"),
        ("cross_protocol_corroboration", "Cross-Protocol Corroboration"),
        ("hostname_temporal_drift", "Hostname Temporal Drift"),
        ("protocol_identity_mismatch", "Protocol Identity Mismatch"),
        ("ad_naming_privilege_abuse", "AD/Privileged Naming Abuse"),
        ("suspicious_naming_pattern", "Suspicious Naming Pattern"),
        ("boundary_leak_or_cross_zone", "Boundary Leakage/Cross-Zone"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    for key, label_text in check_labels:
        lines.append(label(label_text))
        values = [str(v) for v in list(checks.get(key, []) or []) if str(v).strip()]
        if values:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for value in values[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(value)}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Hostname Risk Matrix"))
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    matrix_items = list(getattr(summary, "risk_matrix", []) or [])
    if matrix_items:
        for item in matrix_items[:_limit_value(12)]:
            matrix_rows.append([
                str(item.get("category", "-")),
                str(item.get("risk", "-")),
                str(item.get("confidence", "-")),
                str(item.get("evidence", "-")),
            ])
    else:
        for key, label_text in check_labels[:8]:
            evidence_count = len([str(v) for v in list(checks.get(key, []) or []) if str(v).strip()])
            matrix_rows.append([
                label_text,
                "Medium" if evidence_count else "None",
                "Medium" if evidence_count else "Low",
                str(evidence_count) if evidence_count else "No matching detections",
            ])
    lines.append(_format_table(matrix_rows))

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

    conflict_profiles = list(getattr(summary, "conflict_profiles", []) or [])
    if conflict_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Conflict Profiles"))
        rows = [["Type", "Hostname/IP", "Scope", "Evidence", "Methods"]]
        for item in conflict_profiles[:_limit_value(limit if verbose else 12)]:
            profile_type = str(item.get("type", "-") or "-")
            if profile_type == "hostname_to_many_ips":
                identity = str(item.get("hostname", "-"))
                scope = f"ips={int(item.get('ip_count', 0) or 0)}"
            else:
                identity = str(item.get("ip", "-"))
                scope = f"hosts={int(item.get('host_count', 0) or 0)}"
            methods = item.get("methods", [])
            rows.append([
                profile_type,
                identity,
                scope,
                str(item.get("evidence", "-")),
                _truncate_text(", ".join(str(v) for v in methods[:4]) if isinstance(methods, list) else "-", 70),
            ])
        lines.append(_format_table(rows))

    drift_profiles = list(getattr(summary, "drift_profiles", []) or [])
    if drift_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Temporal Drift Profiles"))
        rows = [["Hostname", "First Seen", "Last Seen", "IP Count", "IPs"]]
        for item in drift_profiles[:_limit_value(limit if verbose else 10)]:
            ips = item.get("ips", [])
            rows.append([
                str(item.get("hostname", "-")),
                format_ts(item.get("first_seen")),
                format_ts(item.get("last_seen")),
                str(item.get("ip_count", "-")),
                _truncate_text(", ".join(str(v) for v in (ips[:5] if isinstance(ips, list) else [])) or "-", 80),
            ])
        lines.append(_format_table(rows))

    corroboration = list(getattr(summary, "cross_protocol_corroboration", []) or [])
    if corroboration:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Cross-Protocol Corroboration"))
        rows = [["Hostname", "Protocols", "Methods", "Confidence", "Evidence"]]
        for item in corroboration[:_limit_value(limit if verbose else 12)]:
            protocols = item.get("protocols", [])
            methods = item.get("methods", [])
            rows.append([
                str(item.get("hostname", "-")),
                _truncate_text(", ".join(str(v) for v in (protocols[:4] if isinstance(protocols, list) else [])) or "-", 50),
                _truncate_text(", ".join(str(v) for v in (methods[:3] if isinstance(methods, list) else [])) or "-", 70),
                str(item.get("confidence", "-")),
                str(item.get("evidence", "-")),
            ])
        lines.append(_format_table(rows))

    suspicious_names = list(getattr(summary, "suspicious_name_profiles", []) or [])
    if suspicious_names:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Naming Analytics"))
        rows = [["Hostname", "Reasons", "Entropy", "Evidence", "Mapped IPs"]]
        for item in suspicious_names[:_limit_value(limit if verbose else 12)]:
            reasons_val = item.get("reasons", [])
            ips = item.get("ips", [])
            rows.append([
                str(item.get("hostname", "-")),
                _truncate_text(", ".join(str(v) for v in (reasons_val[:4] if isinstance(reasons_val, list) else [])) or "-", 70),
                str(item.get("entropy", "-")),
                str(item.get("evidence", "-")),
                _truncate_text(", ".join(str(v) for v in (ips[:4] if isinstance(ips, list) else [])) or "-", 70),
            ])
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

    pivots = list(getattr(summary, "investigation_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hunt Pivots"))
        rows = [["Hostname", "Mapped IPs", "Methods", "First Packet", "Last Packet"]]
        for item in pivots[:_limit_value(limit if verbose else 12)]:
            mapped_ips = item.get("mapped_ips", [])
            methods = item.get("methods", [])
            rows.append([
                str(item.get("hostname", "-")),
                _truncate_text(", ".join(str(v) for v in (mapped_ips[:4] if isinstance(mapped_ips, list) else [])) or "-", 60),
                _truncate_text(", ".join(str(v) for v in (methods[:3] if isinstance(methods, list) else [])) or "-", 70),
                str(item.get("first_packet", "-")),
                str(item.get("last_packet", "-")),
            ])
        lines.append(_format_table(rows))

    false_positive_context = [str(v) for v in list(getattr(summary, "false_positive_context", []) or []) if str(v).strip()]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for note in false_positive_context[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(note)}"))

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

    def _classify_stage(category: str, summary_text: str, details_text: str) -> str | None:
        text = f"{category} {summary_text} {details_text}".lower()
        if any(token in text for token in ("scan", "probe", "recon", "enumeration", "icmp", "nbns", "mdns")):
            return "Recon"
        if any(token in text for token in ("auth", "login", "credential", "kerberos", "ntlm", "password", "ldap", "domain service")):
            return "Access"
        if any(token in text for token in ("powershell", "wmic", "winrm", "telnet command", "cmd.exe", "execution")):
            return "Execution"
        if any(token in text for token in ("beacon", "c2", "command and control")):
            return "C2"
        if any(token in text for token in ("http post", "upload", "stor", "exfil", "file artifact")):
            return "Exfil"
        if any(token in text for token in ("write", "setpoint", "trip", "shutdown", "impact", "firmware")):
            return "Impact"
        return None

    timeline_items = list(summary.timeline_events or [])
    detections = list(summary.detections or [])
    attack_categories = summary.attack_categories or Counter()
    file_transfers = list(summary.file_transfers or [])
    dns_items = list(summary.dns_queries or [])
    user_items = list(summary.user_evidence or [])

    stage_order = ["Recon", "Access", "Execution", "C2", "Exfil", "Impact"]
    stage_times: dict[str, list[float]] = {name: [] for name in stage_order}
    stage_evidence: dict[str, list[str]] = {name: [] for name in stage_order}
    for event in timeline_items:
        stage = _classify_stage(str(event.get("category", "")), str(event.get("summary", "")), str(event.get("details", "")))
        if not stage:
            continue
        ts = event.get("ts")
        if isinstance(ts, (int, float)):
            stage_times[stage].append(float(ts))
        if len(stage_evidence[stage]) < 5:
            stage_evidence[stage].append(f"{event.get('category', '-')}: {event.get('summary', '-')}")

    sequence_rows: list[dict[str, object]] = []
    for stage in stage_order:
        values = sorted(stage_times[stage])
        if not values:
            continue
        sequence_rows.append({
            "stage": stage,
            "first": values[0],
            "last": values[-1],
            "count": len(values),
            "dwell": max(0.0, values[-1] - values[0]),
            "evidence": stage_evidence[stage][:3],
        })

    present_stage_names = [str(item.get("stage", "")) for item in sequence_rows]
    sequence_violations: list[str] = []
    if "Execution" in present_stage_names and "Access" not in present_stage_names:
        sequence_violations.append("Execution-like activity without clear access precursor")
    if "Exfil" in present_stage_names and "Execution" not in present_stage_names:
        sequence_violations.append("Exfiltration-like activity without clear execution stage")
    if "Impact" in present_stage_names and "Recon" not in present_stage_names:
        sequence_violations.append("Impact-like activity seen without early recon/discovery evidence")

    high_detection_count = sum(1 for item in detections if str(item.get("severity", "")).lower() in {"high", "critical"})
    warning_detection_count = sum(1 for item in detections if str(item.get("severity", "")).lower() in {"warning", "warn", "medium"})

    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counter = Counter(value)
        total = float(len(value))
        import math
        return -sum((count / total) * math.log2(count / total) for count in counter.values() if count)

    high_entropy_domains: list[str] = []
    dns_by_name: dict[str, list[float]] = {}
    for item in dns_items:
        name = str(item.get("name", "") or "")
        if not name:
            continue
        labels = [part for part in name.split(".") if part]
        longest = max((len(label) for label in labels), default=0)
        ent = _entropy(name)
        if longest >= 24 or ent >= 3.8:
            high_entropy_domains.append(f"{name} (entropy={ent:.2f})")
        ts = item.get("ts")
        if isinstance(ts, (int, float)):
            dns_by_name.setdefault(name.lower(), []).append(float(ts))

    dns_periodic: list[str] = []
    for name, timestamps in dns_by_name.items():
        values = sorted(set(timestamps))
        if len(values) < 4:
            continue
        intervals = [values[idx] - values[idx - 1] for idx in range(1, len(values)) if values[idx] - values[idx - 1] > 0]
        if len(intervals) < 3:
            continue
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            continue
        import math
        variance = sum((v - mean) ** 2 for v in intervals) / len(intervals)
        std = math.sqrt(variance)
        cv = std / mean if mean else 1.0
        if 3.0 <= mean <= 3600.0 and cv <= 0.35:
            dns_periodic.append(f"{name} interval={mean:.1f}s cv={cv:.2f}")

    suspicious_extensions = {".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js", ".hta"}
    risky_files: list[str] = []
    hash_hosts: dict[str, set[str]] = {}
    public_exfil_files: list[str] = []
    for item in file_transfers:
        filename = str(item.get("filename", "") or "")
        file_type = str(item.get("file_type", "") or "")
        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[1].lower()
        if ext in suspicious_extensions or any(token in file_type.lower() for token in ("exe", "dll", "script", "archive")):
            risky_files.append(f"{filename} type={file_type or '-'} dir={item.get('direction', '-')}")
        sha256 = str(item.get("sha256", "") or "")
        if sha256:
            peer = str(item.get("dst_ip", "-") if str(item.get("src_ip", "")) == summary.target_ip else item.get("src_ip", "-"))
            hash_hosts.setdefault(sha256, set()).add(peer)
        dst_ip = str(item.get("dst_ip", "") or "")
        src_ip = str(item.get("src_ip", "") or "")
        if src_ip == summary.target_ip:
            try:
                if ipaddress.ip_address(dst_ip).is_global:
                    public_exfil_files.append(f"{filename or '-'} -> {dst_ip}")
            except Exception:
                pass

    propagated_hashes = [f"{digest[:12]} to {len(hosts)} hosts" for digest, hosts in hash_hosts.items() if len(hosts) >= 2]

    privileged_markers = {"administrator", "domain admin", "enterprise admin", "root", "admin"}
    privileged_users: Counter[str] = Counter()
    user_by_method: Counter[str] = Counter()
    for item in user_items:
        user = str(item.get("username", "") or "").lower()
        method = str(item.get("method", "") or "")
        if method:
            user_by_method[method] += 1
        if any(marker in user for marker in privileged_markers):
            privileged_users[user or "-"] += 1

    peer_risk: Counter[str] = Counter()
    for peer, count in summary.peer_counts.most_common(30):
        peer_risk[peer] += int(count // 5)
    for item in detections:
        for ip_value, count in item.get("top_sources", []) or []:
            peer_risk[str(ip_value)] += int(count)
        for ip_value, count in item.get("top_destinations", []) or []:
            peer_risk[str(ip_value)] += int(count)

    attack_path_steps: list[str] = []
    if attack_categories.get("scanning_probe", 0):
        attack_path_steps.append("Recon/scan indicators")
    if attack_categories.get("bruteforce_auth", 0) or privileged_users:
        attack_path_steps.append("Access/credential indicators")
    if attack_categories.get("malware_tooling", 0):
        attack_path_steps.append("Execution tooling indicators")
    if attack_categories.get("lateral_movement", 0):
        attack_path_steps.append("Lateral movement indicators")
    if attack_categories.get("beaconing", 0):
        attack_path_steps.append("C2/beacon indicators")
    if attack_categories.get("exfiltration", 0) or public_exfil_files:
        attack_path_steps.append("Exfiltration indicators")
    if attack_categories.get("ot_ics", 0):
        attack_path_steps.append("OT/ICS impact pathway")

    deterministic_checks: dict[str, list[str]] = {
        "credential_abuse_concentration": [],
        "lateral_movement_fanout": [],
        "execution_tooling_chain": [],
        "exfiltration_chain": [],
        "dns_c2_periodicity": [],
        "ot_control_impact_sequence": [],
        "identity_privilege_spread": [],
        "cross_zone_service_access": [],
        "file_risk_staging": [],
        "evidence_provenance": [],
    }

    if warning_detection_count or high_detection_count:
        deterministic_checks["credential_abuse_concentration"].extend([
            f"high/critical detections={high_detection_count}",
            f"warning detections={warning_detection_count}",
        ])
    top_peers = summary.peer_counts.most_common(8)
    if top_peers and len(top_peers) >= 3:
        deterministic_checks["lateral_movement_fanout"].append(
            f"host touched {len(summary.peer_counts)} peers; top peer volume {top_peers[0][0]}({top_peers[0][1]})"
        )
    if attack_categories.get("malware_tooling", 0) or any("powershell" in str(item.get("summary", "")).lower() for item in timeline_items):
        deterministic_checks["execution_tooling_chain"].append("Execution tooling indicators present in timeline/detections")
    deterministic_checks["exfiltration_chain"].extend(public_exfil_files[:6])
    deterministic_checks["dns_c2_periodicity"].extend(dns_periodic[:6])
    if attack_categories.get("ot_ics", 0):
        deterministic_checks["ot_control_impact_sequence"].append("OT/ICS protocol indicators linked to host activity")
    if privileged_users:
        deterministic_checks["identity_privilege_spread"].extend([f"{user}({count})" for user, count in privileged_users.most_common(5)])
    for conv in summary.conversations:
        peer = str(conv.get("peer", ""))
        if not peer:
            continue
        try:
            peer_ip = ipaddress.ip_address(peer)
            local_private = ipaddress.ip_address(summary.target_ip).is_private
            if peer_ip.is_private != local_private:
                deterministic_checks["cross_zone_service_access"].append(
                    f"{summary.target_ip} -> {peer} protocol={conv.get('protocol', '-')}, ports={conv.get('ports', '-') }"
                )
        except Exception:
            continue
    deterministic_checks["file_risk_staging"].extend((risky_files + propagated_hashes)[:8])

    anchor_rows: list[dict[str, object]] = []
    for item in file_transfers:
        pkt = item.get("packet_index")
        if pkt is None:
            continue
        anchor_rows.append({
            "packet": pkt,
            "source": "files",
            "signal": f"{item.get('filename', '-')}",
            "details": f"{item.get('src_ip', '-')}: {item.get('src_port', '-')} -> {item.get('dst_ip', '-')}: {item.get('dst_port', '-')} {item.get('protocol', '-')}",
        })
    for event in timeline_items:
        pkt = event.get("packet_index")
        if pkt is None:
            continue
        anchor_rows.append({
            "packet": pkt,
            "source": event.get("source", "timeline"),
            "signal": event.get("summary", "-"),
            "details": event.get("details", "-"),
        })
    anchor_rows.sort(key=lambda item: (item.get("packet") is None, item.get("packet")))
    if anchor_rows:
        deterministic_checks["evidence_provenance"].append(f"{len(anchor_rows)} packet-anchored evidence row(s)")

    verdict_score = 0
    verdict_score += 2 if deterministic_checks["execution_tooling_chain"] else 0
    verdict_score += 2 if deterministic_checks["exfiltration_chain"] else 0
    verdict_score += 1 if deterministic_checks["credential_abuse_concentration"] else 0
    verdict_score += 1 if deterministic_checks["lateral_movement_fanout"] else 0
    verdict_score += 1 if deterministic_checks["dns_c2_periodicity"] else 0
    verdict_score += 1 if deterministic_checks["identity_privilege_spread"] else 0
    verdict_score += 1 if deterministic_checks["ot_control_impact_sequence"] else 0
    verdict_score += 1 if deterministic_checks["cross_zone_service_access"] else 0
    verdict_score += 1 if deterministic_checks["file_risk_staging"] else 0

    verdict_reasons: list[str] = []
    if deterministic_checks["execution_tooling_chain"]:
        verdict_reasons.append("Execution tooling behavior observed")
    if deterministic_checks["exfiltration_chain"]:
        verdict_reasons.append("Possible host exfiltration chain observed")
    if deterministic_checks["lateral_movement_fanout"]:
        verdict_reasons.append("Broad peer fan-out from host")
    if deterministic_checks["dns_c2_periodicity"]:
        verdict_reasons.append("Beacon-like DNS periodicity observed")
    if deterministic_checks["identity_privilege_spread"]:
        verdict_reasons.append("Privileged identity usage pattern observed")
    if deterministic_checks["ot_control_impact_sequence"]:
        verdict_reasons.append("OT/ICS control-impact signals linked to host")
    if sequence_violations:
        verdict_reasons.extend(sequence_violations[:2])

    if verdict_score >= 8:
        host_verdict = "YES - HIGH-CONFIDENCE HOST COMPROMISE/ABUSE PATTERN DETECTED"
        host_confidence = "high"
    elif verdict_score >= 5:
        host_verdict = "LIKELY - MULTIPLE CORROBORATING HOST-RISK INDICATORS DETECTED"
        host_confidence = "medium"
    elif verdict_score >= 3:
        host_verdict = "POSSIBLE - HOST-RISK INDICATORS REQUIRE CORROBORATION"
        host_confidence = "medium"
    else:
        host_verdict = "NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE HOST ABUSE PATTERN"
        host_confidence = "low"

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if host_verdict.startswith("YES"):
        lines.append(danger(host_verdict))
    elif host_verdict.startswith("LIKELY") or host_verdict.startswith("POSSIBLE"):
        lines.append(warn(host_verdict))
    else:
        lines.append(ok(host_verdict))
    lines.append(_format_kv("Confidence", f"{host_confidence.capitalize()} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Host Security Checks"))
    check_labels = [
        ("credential_abuse_concentration", "Credential Abuse Concentration"),
        ("lateral_movement_fanout", "Lateral Movement Fan-Out"),
        ("execution_tooling_chain", "Execution Tooling Chain"),
        ("exfiltration_chain", "Exfiltration Chain"),
        ("dns_c2_periodicity", "DNS C2/Beacon Periodicity"),
        ("ot_control_impact_sequence", "OT Control-Impact Sequence"),
        ("identity_privilege_spread", "Identity Privilege Spread"),
        ("cross_zone_service_access", "Cross-Zone Service Access"),
        ("file_risk_staging", "File-Risk Staging"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = [str(v) for v in deterministic_checks.get(key, []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
            risk = "High" if key in {"execution_tooling_chain", "exfiltration_chain", "ot_control_impact_sequence", "identity_privilege_spread"} else "Medium"
            conf = "High" if key in {"evidence_provenance", "execution_tooling_chain"} else "Medium"
            matrix_rows.append([label_text, risk, conf, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Host Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    if sequence_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence Plausibility"))
        rows = [["Stage", "First", "Last", "Count", "Dwell", "Evidence"]]
        for item in sequence_rows[:_limit_value(10)]:
            rows.append([
                str(item.get("stage", "-")),
                format_ts(item.get("first")),
                format_ts(item.get("last")),
                str(item.get("count", "-")),
                format_duration(item.get("dwell")),
                _truncate_text(" | ".join(str(v) for v in item.get("evidence", [])[:2]), 64),
            ])
        lines.append(_format_table(rows))
    if sequence_violations:
        lines.append(muted("Sequence violations:"))
        for item in sequence_violations[:_limit_value(6)]:
            lines.append(warn(f"- {_redact_in_text(item)}"))

    if attack_path_steps:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Attack Path Summary"))
        path_text = " -> ".join(attack_path_steps[:6])
        lines.append(muted(f"- {path_text}"))
        targets = [peer for peer, _ in summary.peer_counts.most_common(_limit_value(5))]
        if targets:
            lines.append(muted(f"- Primary peer targets: {', '.join(targets)}"))

    if peer_risk:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Remote Host Risk"))
        rows = [["Peer", "Risk Score", "Evidence Count"]]
        for peer, score in peer_risk.most_common(_limit_value(10)):
            rows.append([peer, str(score), str(summary.peer_counts.get(peer, 0))])
        lines.append(_format_table(rows))

    if user_items:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Identity Abuse Analytics"))
        rows = [["Signal", "Details"]]
        if privileged_users:
            rows.append(["Privileged Identities", ", ".join(f"{user}({count})" for user, count in privileged_users.most_common(5))])
        if user_by_method:
            rows.append(["Identity Collection Methods", ", ".join(f"{method}({count})" for method, count in user_by_method.most_common(6))])
        if len(rows) == 1:
            rows.append(["Status", "No strong identity abuse concentration detected"])
        lines.append(_format_table(rows))

    if high_entropy_domains or dns_periodic:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Behavior Checks"))
        if high_entropy_domains:
            lines.append(muted("- High-entropy/suspicious DNS queries:"))
            for item in high_entropy_domains[:_limit_value(6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        if dns_periodic:
            lines.append(muted("- Periodic DNS patterns:"))
            for item in dns_periodic[:_limit_value(6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))

    if risky_files or propagated_hashes or public_exfil_files:
        lines.append(SUBSECTION_BAR)
        lines.append(header("File Risk Checks"))
        for item in (risky_files + propagated_hashes + public_exfil_files)[:_limit_value(10)]:
            lines.append(muted(f"- {_redact_in_text(item)}"))

    if anchor_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Evidence Anchors"))
        rows = [["Packet", "Source", "Signal", "Details"]]
        for item in anchor_rows[:_limit_value(12)]:
            rows.append([
                str(item.get("packet", "-")),
                str(item.get("source", "-")),
                _truncate_text(str(item.get("signal", "-")), 30),
                _truncate_text(_redact_in_text(str(item.get("details", "-"))), 84),
            ])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ATT&CK Tactic Mapping"))
    tactic_rows = [["Tactic", "Evidence"]]
    mapping = [
        ("TA0043 Reconnaissance", int(attack_categories.get("scanning_probe", 0))),
        ("TA0001 Initial Access", int(attack_categories.get("bruteforce_auth", 0))),
        ("TA0002 Execution", int(attack_categories.get("malware_tooling", 0))),
        ("TA0008 Lateral Movement", int(attack_categories.get("lateral_movement", 0))),
        ("TA0011 Command and Control", int(attack_categories.get("beaconing", 0))),
        ("TA0010 Exfiltration", int(attack_categories.get("exfiltration", 0))),
        ("TA0040 Impact", int(attack_categories.get("dos_impact", 0)) + int(attack_categories.get("ot_ics", 0))),
    ]
    for name, count in mapping:
        if count > 0:
            tactic_rows.append([name, str(count)])
    if len(tactic_rows) == 1:
        tactic_rows.append(["No strong tactic mapping", "0"])
    lines.append(_format_table(tactic_rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Hunt Pivots"))
    pivot_rows = [["Pivot Type", "Value"]]
    for peer, _count in summary.peer_counts.most_common(_limit_value(3)):
        pivot_rows.append(["Peer IP", peer])
    for item in file_transfers[:_limit_value(3)]:
        sha256 = str(item.get("sha256", "") or "")
        if sha256:
            pivot_rows.append(["File SHA256", sha256])
    for item in dns_items[:_limit_value(3)]:
        name = str(item.get("name", "") or "")
        if name:
            pivot_rows.append(["Domain", name])
    for item in user_items[:_limit_value(3)]:
        username = str(item.get("username", "") or "")
        if username and username != "-":
            pivot_rows.append(["Username", username])
    if len(pivot_rows) == 1:
        pivot_rows.append(["Status", "No strong pivots extracted"])
    lines.append(_format_table(pivot_rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("False-Positive Context"))
    benign_context: list[str] = []
    if not deterministic_checks["execution_tooling_chain"]:
        benign_context.append("No strong host execution-tooling chain was identified")
    if not deterministic_checks["dns_c2_periodicity"]:
        benign_context.append("No high-confidence beacon-like DNS periodicity was detected")
    if not deterministic_checks["cross_zone_service_access"]:
        benign_context.append("No cross-zone service access drift was detected for this host")
    if not deterministic_checks["file_risk_staging"]:
        benign_context.append("No strong malicious file staging chain was reconstructed")
    for item in benign_context[:_limit_value(6)]:
        lines.append(muted(f"- {_redact_in_text(item)}"))

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
            summary_text = summary_text.replace(
                "[C2] [Payload] File artifact",
                warn_bg("[C2] [Payload] File artifact"),
            )
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

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    verdict_text = summary.analyst_verdict or "NO STRONG SIGNAL - timeline heuristics did not cross confidence threshold"
    confidence_text = (summary.analyst_confidence or "low").strip().lower()
    if verdict_text.startswith("YES"):
        lines.append(danger(verdict_text))
    elif verdict_text.startswith("LIKELY") or verdict_text.startswith("POSSIBLE"):
        lines.append(warn(verdict_text))
    else:
        lines.append(ok(verdict_text))
    lines.append(_format_kv("Confidence", confidence_text.capitalize()))
    if summary.analyst_reasons:
        lines.append(muted("Why confidence:"))
        for reason in summary.analyst_reasons[:_limit_value(10 if verbose else 6)]:
            lines.append(muted(f"- {_redact_in_text(str(reason))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Timeline Security Checks"))
    checks = summary.deterministic_checks or {}
    check_labels = [
        ("recon_to_access_sequence", "Recon to Access Sequence"),
        ("access_to_execution_sequence", "Access to Execution Sequence"),
        ("execution_to_c2_or_exfil", "Execution to C2 or Exfil Sequence"),
        ("ot_control_after_discovery", "OT Control After Discovery"),
        ("beaconing_periodicity", "Beaconing Periodicity"),
        ("authentication_abuse", "Authentication Abuse"),
        ("lateral_movement_fanout", "Lateral Movement Fan-Out"),
        ("exfiltration_chain", "Exfiltration Chain"),
        ("ot_impact_signal", "OT Impact Signal"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = [str(v) for v in list(checks.get(key, []) or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence_items[:_limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
            risk = "High" if key in {"execution_to_c2_or_exfil", "exfiltration_chain", "ot_impact_signal"} else "Medium"
            conf = "High" if key in {"execution_to_c2_or_exfil", "evidence_provenance"} else "Medium"
            matrix_rows.append([label_text, risk, conf, f"{len(evidence_items)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Timeline Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    sequence_rows = list(getattr(summary, "sequence_timeline", []) or [])
    if sequence_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence Plausibility Timeline"))
        rows = [["Stage", "First Seen", "Last Seen", "Count", "Dwell", "Evidence"]]
        for item in sequence_rows[:_limit_value(20 if verbose else 10)]:
            evidence = item.get("evidence", [])
            if isinstance(evidence, list):
                evidence_text = " | ".join(str(v) for v in evidence[:3])
            else:
                evidence_text = str(evidence)
            rows.append([
                str(item.get("stage", "-")),
                format_ts(item.get("first_ts")),
                format_ts(item.get("last_ts")),
                str(item.get("count", "-")),
                format_duration(item.get("dwell")),
                _truncate_text(evidence_text or "-", 70),
            ])
        lines.append(_format_table(rows))

    if summary.sequence_violations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence Violations"))
        for item in summary.sequence_violations[:_limit_value(10 if verbose else 6)]:
            lines.append(warn(f"- {_redact_in_text(str(item))}"))

    beacon_rows = list(getattr(summary, "beacon_candidates", []) or [])
    if beacon_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Beaconing Candidates"))
        rows = [["Peer", "Category", "Signal", "Count", "Mean Interval", "Jitter", "CV", "Confidence"]]
        for item in beacon_rows[:_limit_value(12 if verbose else 8)]:
            rows.append([
                str(item.get("peer", "-")),
                str(item.get("category", "-")),
                _truncate_text(str(item.get("summary", "-")), 32),
                str(item.get("count", "-")),
                f"{item.get('mean_interval', '-')}s",
                f"{item.get('jitter', '-')}s",
                str(item.get("cv", "-")),
                str(item.get("confidence", "-")).upper(),
            ])
        lines.append(_format_table(rows))

    auth_rows = list(getattr(summary, "auth_abuse_profiles", []) or [])
    if auth_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Authentication Abuse Profiles"))
        rows = [["Source", "Target", "Attempts", "Target Count", "Confidence"]]
        for item in auth_rows[:_limit_value(12 if verbose else 8)]:
            rows.append([
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("attempts", "-")),
                str(item.get("target_count", "-")),
                str(item.get("confidence", "-")).upper(),
            ])
        lines.append(_format_table(rows))

    lateral_rows = list(getattr(summary, "lateral_movement_paths", []) or [])
    if lateral_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Paths"))
        rows = [["Source", "Peers", "Admin Hits", "Top Peers", "Confidence"]]
        for item in lateral_rows[:_limit_value(12 if verbose else 8)]:
            peers = item.get("peers", [])
            peer_text = ", ".join(str(v) for v in peers[:4]) if isinstance(peers, list) else str(peers)
            rows.append([
                str(item.get("src", "-")),
                str(item.get("peer_count", "-")),
                str(item.get("admin_hits", "-")),
                _truncate_text(peer_text or "-", 48),
                str(item.get("confidence", "-")).upper(),
            ])
        lines.append(_format_table(rows))

    exfil_rows = list(getattr(summary, "exfiltration_chains", []) or [])
    if exfil_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Exfiltration Chain Signals"))
        for item in exfil_rows[:_limit_value(14 if verbose else 8)]:
            lines.append(muted(f"- {_redact_in_text(str(item.get('signal', '-')))}"))

    ot_impact_rows = list(getattr(summary, "ot_impact_signals", []) or [])
    if ot_impact_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Impact Signals"))
        rows = [["Protocol", "Summary", "Timestamp", "Details"]]
        for item in ot_impact_rows[:_limit_value(14 if verbose else 8)]:
            rows.append([
                str(item.get("protocol", "-")),
                _truncate_text(str(item.get("summary", "-")), 32),
                format_ts(item.get("ts")),
                _truncate_text(_redact_in_text(str(item.get("details", "-"))), 80),
            ])
        lines.append(_format_table(rows))

    anchors = list(getattr(summary, "evidence_anchors", []) or [])
    if anchors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Evidence Anchors"))
        rows = [["Packet", "Source", "Category", "Summary", "Details"]]
        for item in anchors[:_limit_value(18 if verbose else 10)]:
            rows.append([
                str(item.get("packet", "-")),
                str(item.get("source", "-")),
                str(item.get("category", "-")),
                _truncate_text(str(item.get("summary", "-")), 28),
                _truncate_text(_redact_in_text(str(item.get("details", "-"))), 72),
            ])
        lines.append(_format_table(rows))

    benign_rows = list(getattr(summary, "benign_context", []) or [])
    if benign_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in benign_rows[:_limit_value(10 if verbose else 6)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

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

    def _highlight_c2_payload_file_artifact(text: str) -> str:
        return text.replace("[C2] [Payload] File artifact", warn_bg("[C2] [Payload] File artifact"))

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
        summary_text = _highlight_c2_payload_file_artifact(summary_text)
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

    def _arp_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_anomalies = sum(1 for item in summary.anomalies if item.severity in {"HIGH", "CRITICAL"})
        med_anomalies = sum(1 for item in summary.anomalies if item.severity == "MEDIUM")
        if high_anomalies:
            score += min(5, high_anomalies * 2)
            reasons.append(f"High-severity ARP anomalies observed ({high_anomalies})")
        if med_anomalies >= 2:
            score += 1
            reasons.append(f"Multiple medium-severity ARP anomalies observed ({med_anomalies})")
        if summary.unsolicited_replies >= 20:
            score += 2
            reasons.append(f"Unsolicited ARP replies are elevated ({summary.unsolicited_replies})")
        if getattr(summary, "gateway_ip", "") and len(getattr(summary, "gateway_mac_candidates", {})) > 1:
            score += 2
            reasons.append("Gateway ARP MAC mapping changed")
        if summary.gratuitous_arp >= 25:
            score += 1
            reasons.append(f"Excess gratuitous ARP frames observed ({summary.gratuitous_arp})")

        if score >= 7:
            verdict = "YES - high-confidence ARP poisoning or MITM-style behavior is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - suspicious ARP behavior with attack indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - potentially malicious ARP behavior observed; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk ARP attack pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence ARP attack heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _arp_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.gateway_ip:
        lines.append(muted("Where:"))
        lines.append(muted(f"- Gateway under observation: {_highlight_public_ips(summary.gateway_ip)}"))
    if summary.gateway_mac_candidates:
        lines.append(muted("What:"))
        lines.append(muted("- Gateway MAC candidates"))
        for mac, count in summary.gateway_mac_candidates.most_common(_limit_value(6)):
            lines.append(muted(f"- {mac}: {int(count)} replies"))
    if summary.victim_conflicts:
        lines.append(muted("Who:"))
        lines.append(muted("- Victim conflict highlights"))
        for ip_value, mac_counter in sorted(summary.victim_conflicts.items(), key=lambda item: sum(item[1].values()), reverse=True)[:_limit_value(6)]:
            claims = ", ".join(f"{mac}({cnt})" for mac, cnt in mac_counter.most_common(4))
            lines.append(muted(f"- {_highlight_public_ips(ip_value)} claimed by {claims}"))
    if summary.anomalies:
        lines.append(muted("When:"))
        lines.append(muted("- Top ARP anomalies"))
        for item in summary.anomalies[:_limit_value(6)]:
            lines.append(muted(f"- [{item.severity}] {_redact_in_text(item.title)}: {_redact_in_text(item.description)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Threat & Compromise Overview"))
    lines.append(_format_kv("Threat Categories", str(sum(summary.threats.values()))))
    lines.append(_format_kv("Anomalies", str(len(summary.anomalies))))
    lines.append(_format_kv("High Severity Anomalies", str(sum(1 for item in summary.anomalies if item.severity in {"HIGH", "CRITICAL"}))))
    lines.append(_format_kv("Benign Indicators", str(sum(getattr(summary, "benign_indicators", Counter()).values()))))
    lines.append(_format_kv("Gateway Candidate", getattr(summary, "gateway_ip", "-") or "-"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic ARP Security Checks"))

    def _arp_signal(*tokens: str) -> list[str]:
        matches: list[str] = []
        lowered_tokens = tuple(token.lower() for token in tokens)
        for threat, count in summary.threats.items():
            text = f"{threat}: {count}"
            blob = text.lower()
            if any(token in blob for token in lowered_tokens):
                matches.append(text)
        for item in summary.anomalies:
            text = f"{item.title}: {item.description}"
            blob = text.lower()
            if any(token in blob for token in lowered_tokens):
                matches.append(text)
        return matches[:_limit_value(4)]

    checks: list[tuple[str, tuple[str, ...]]] = [
        ("Gateway ARP Integrity", ("gateway", "mac flip", "integrity")),
        ("Poisoning Pair Pattern", ("poisoning pair", "claims", "high-value ips")),
        ("Unsolicited Reply Abuse", ("unsolicited", "poisoning indicators")),
        ("ARP Recon/Sweep Activity", ("sweep", "recon")),
        ("ARP Flood/Storm", ("flood", "storm", "high arp traffic")),
        ("Duplicate IP Ownership", ("ip/mac conflict", "multiple macs")),
        ("Proxy ARP Misuse", ("proxy arp", "proxy arp-like")),
        ("Likely Benign Failover", ("failover", "virtual mac")),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for label_text, tokens in checks:
        lines.append(label(label_text))
        evidence = _arp_signal(*tokens)
        if evidence:
            lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
            for item in evidence:
                lines.append(muted(f"- {_redact_in_text(item)}"))
            high_hits = sum(1 for item in evidence if "high" in item.lower() or "poison" in item.lower())
            risk = "High" if high_hits > 0 else "Medium"
            conf = "High" if len(evidence) >= 2 else "Medium"
            matrix_rows.append([label_text, risk, conf, f"{len(evidence)} signal(s)"])
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Risk Matrix"))
    lines.append(_format_table(matrix_rows))

    if getattr(summary, "gateway_mac_candidates", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Gateway Mapping Integrity"))
        rows = [["Gateway IP", "Observed MAC", "Replies"]]
        gateway_ip = getattr(summary, "gateway_ip", "-") or "-"
        for mac, count in summary.gateway_mac_candidates.most_common(limit):
            rows.append([gateway_ip, mac, str(count)])
        lines.append(_format_table(rows))

    if getattr(summary, "victim_conflicts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Victim-Centric Conflict View"))
        rows = [["Victim IP", "Claiming MACs", "Conflict Count"]]
        for victim_ip, mac_counter in sorted(
            summary.victim_conflicts.items(),
            key=lambda item: sum(item[1].values()),
            reverse=True,
        )[:limit]:
            mac_text = ", ".join(f"{mac}({count})" for mac, count in mac_counter.most_common(_limit_value(3)))
            rows.append([victim_ip, mac_text or "-", str(sum(mac_counter.values()))])
        lines.append(_format_table(rows))

    if getattr(summary, "timeline", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Attack Chain Timeline"))
        rows = [["Timestamp", "Event", "Source", "Destination"]]
        for item in summary.timeline[:limit]:
            rows.append([
                format_ts(item.ts),
                _truncate_text(_redact_in_text(item.detail), 88),
                item.src,
                item.dst,
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "proxy_arp_candidates", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Proxy ARP Candidates"))
        rows = [["MAC", "Dst Targets", "Claimed IPs"]]
        for item in summary.proxy_arp_candidates[:limit]:
            rows.append([
                str(item.get("mac", "-")),
                str(item.get("dst_targets", "-")),
                str(item.get("claimed_ips", "-")),
            ])
        lines.append(_format_table(rows))

    if getattr(summary, "reply_latency_summary", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Reply Timing"))
        lines.append(_format_kv("Median Reply Latency", f"{float(summary.reply_latency_summary.get('median_s', 0.0)) * 1000.0:.2f} ms"))
        lines.append(_format_kv("p95 Reply Latency", f"{float(summary.reply_latency_summary.get('p95_s', 0.0)) * 1000.0:.2f} ms"))
        lines.append(_format_kv("Samples", str(int(float(summary.reply_latency_summary.get('samples', 0.0))))))

    if getattr(summary, "pps_by_source", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("ARP Rate Baseline"))
        rows = [["Source", "Requests", "Packets/sec"]]
        for src, count in summary.client_details.most_common(limit):
            pps = float(summary.pps_by_source.get(src, 0.0))
            rows.append([src, str(count), f"{pps:.2f}"])
        lines.append(_format_table(rows))

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

    def _dhcp_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_anomalies = sum(1 for item in summary.anomalies if item.severity in {"HIGH", "CRITICAL"})
        if high_anomalies:
            score += min(4, high_anomalies)
            reasons.append(f"High-severity DHCP anomalies observed ({high_anomalies})")
        if summary.transaction_violations:
            score += 2
            reasons.append(f"Transaction integrity violations observed ({len(summary.transaction_violations)})")
        if summary.policy_tampering:
            score += 2
            reasons.append(f"DHCP policy tampering/drift observed ({len(summary.policy_tampering)})")
        if summary.lease_conflicts:
            score += 2
            reasons.append(f"Duplicate lease assignment conflicts observed ({len(summary.lease_conflicts)})")
        if summary.relay_anomalies:
            score += 1
            reasons.append(f"Relay-agent anomalies observed ({len(summary.relay_anomalies)})")
        if summary.attacks.get("Rogue DHCP Server", 0):
            score += 2
            reasons.append("Competing/rogue DHCP server evidence observed")
        if summary.attacks.get("DHCP Starvation", 0):
            score += 2
            reasons.append("DHCP starvation/exhaustion behavior observed")

        if score >= 8:
            verdict = "YES - high-confidence DHCP abuse or policy-hijack activity is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - significant suspicious DHCP activity is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate DHCP threat indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk DHCP attack pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence DHCP heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _dhcp_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.server_details:
        lines.append(muted("Where:"))
        lines.append(muted("- Top DHCP servers"))
        for server, count in summary.server_details.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)} packets"))
    if summary.client_details:
        lines.append(muted("Who:"))
        lines.append(muted("- Top DHCP clients"))
        for client, count in summary.client_details.most_common(_limit_value(8)):
            lines.append(muted(f"- {client}: {int(count)} packets"))
    if summary.attacks:
        lines.append(muted("What:"))
        lines.append(muted("- Attack category hits"))
        for attack, count in summary.attacks.most_common(_limit_value(8)):
            lines.append(muted(f"- {_redact_in_text(str(attack))}: {int(count)}"))
    if getattr(summary, "transaction_violations", None):
        violations = list(summary.transaction_violations or [])
        if violations:
            lines.append(muted("When:"))
            lines.append(muted("- Transaction violations"))
            for item in violations[:_limit_value(6)]:
                lines.append(
                    muted(
                        f"- {item.get('type', '-')} xid={item.get('xid', '-')} "
                        f"server={_highlight_public_ips(str(item.get('server', '-')))} "
                        f"client={item.get('client_mac', '-')} at {format_ts(item.get('ts'))}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic DHCP Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("transaction_integrity_violation", "Transaction Integrity Violation"),
        ("rogue_competing_server_evidence", "Rogue/Competing Server Evidence"),
        ("starvation_exhaustion_behavior", "Starvation/Exhaustion Behavior"),
        ("option_tampering_router_dns_routes_wpad_pxe", "Option Tampering (Router/DNS/Routes/WPAD/PXE)"),
        ("relay_abuse_option82", "Relay Abuse / Option 82 Anomaly"),
        ("lease_conflict_duplicate_assignment", "Lease Conflict / Duplicate Assignment"),
        ("beacon_periodic_dhcp", "Periodic DHCP Beacon Behavior"),
        ("likely_benign_failover_context", "Likely Benign Failover Context"),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "likely_benign_failover_context":
                lines.append(ok(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                matrix_rows.append([label_text, "Low", "Medium", f"{len(evidence_items)} signal(s)"])
            else:
                lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                if key in {"transaction_integrity_violation", "option_tampering_router_dns_routes_wpad_pxe", "lease_conflict_duplicate_assignment"}:
                    risk = "High"
                    conf_level = "High"
                elif key in {"rogue_competing_server_evidence", "starvation_exhaustion_behavior", "relay_abuse_option82"}:
                    risk = "Medium"
                    conf_level = "Medium"
                else:
                    risk = "Low"
                    conf_level = "Low"
                matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
            for item in evidence_items[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("DHCP Risk Matrix"))
    lines.append(_format_table(matrix_rows))

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

    if getattr(summary, "server_policy_profiles", None):
        if summary.server_policy_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Server Policy Profiles"))
            rows = [["Server", "Router", "DNS", "Domain", "WPAD", "Routes", "PXE"]]
            for item in summary.server_policy_profiles[:limit]:
                pxe_value = str(item.get("bootfile_value", "") or item.get("tftp_value", "") or "-")
                rows.append([
                    str(item.get("server", "-")),
                    _truncate_text(str(item.get("router_value", "-")), 22),
                    _truncate_text(str(item.get("dns_value", "-")), 22),
                    _truncate_text(str(item.get("domain_value", "-")), 18),
                    _truncate_text(str(item.get("wpad_value", "-")), 16),
                    _truncate_text(str(item.get("routes_value", "-")), 18),
                    _truncate_text(pxe_value, 18),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "client_abuse_profiles", None):
        if summary.client_abuse_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Client Abuse Profiles"))
            rows = [["Client MAC", "Req", "Requested IPs", "XIDs", "Hostnames", "Client IDs", "Vendors"]]
            for item in summary.client_abuse_profiles[:limit]:
                rows.append([
                    str(item.get("client_mac", "-")),
                    str(item.get("requests", "-")),
                    str(item.get("requested_ip_count", "-")),
                    str(item.get("xid_count", "-")),
                    str(item.get("hostname_count", "-")),
                    str(item.get("client_id_count", "-")),
                    str(item.get("vendor_class_count", "-")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "policy_tampering", None):
        if summary.policy_tampering:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Option Policy Drift/Tampering"))
            rows = [["Server", "Signals"]]
            for item in summary.policy_tampering[:limit]:
                drift = item.get("drift", [])
                drift_text = "; ".join(str(v) for v in (drift[:3] if isinstance(drift, list) else [drift]))
                rows.append([
                    str(item.get("server", "-")),
                    _truncate_text(drift_text or "-", 92),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "transaction_violations", None):
        if summary.transaction_violations:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Transaction Integrity Violations"))
            rows = [["Type", "Server", "Client", "XID", "Flow", "Time"]]
            for item in summary.transaction_violations[:limit]:
                rows.append([
                    str(item.get("type", "-")),
                    str(item.get("server", "-")),
                    str(item.get("client_mac", "-")),
                    str(item.get("xid", "-")),
                    f"{item.get('src', '-')}->{item.get('dst', '-')}",
                    format_ts(item.get("ts")),
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "lease_conflicts", None):
        if summary.lease_conflicts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Lease Conflict View"))
            rows = [["IP", "Client Count", "Clients"]]
            for item in summary.lease_conflicts[:limit]:
                clients = item.get("clients", [])
                client_text = ", ".join(str(v) for v in (clients[:4] if isinstance(clients, list) else [clients]))
                rows.append([
                    str(item.get("ip", "-")),
                    str(item.get("count", "-")),
                    client_text,
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "relay_anomalies", None):
        if summary.relay_anomalies:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Relay Abuse Indicators"))
            rows = [["Relay", "Servers", "Clients", "Top Servers"]]
            for item in summary.relay_anomalies[:limit]:
                servers = item.get("servers", [])
                top_servers = ", ".join(str(v) for v in (servers[:3] if isinstance(servers, list) else [servers]))
                rows.append([
                    str(item.get("relay", "-")),
                    str(item.get("server_count", "-")),
                    str(item.get("client_count", "-")),
                    top_servers,
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "timeline", None):
        if summary.timeline:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Attack Chain Timeline"))
            rows = [["Time", "Event", "Detail", "Flow"]]
            for item in summary.timeline[:limit]:
                rows.append([
                    format_ts(item.get("ts")),
                    str(item.get("event", "-")),
                    _truncate_text(_redact_in_text(str(item.get("detail", "-"))), 96),
                    f"{item.get('src', '-')}->{item.get('dst', '-')}",
                ])
            lines.append(_format_table(rows))

    if getattr(summary, "benign_context", None):
        if summary.benign_context:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for item in summary.benign_context[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(str(item))}"))

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

        high_risk_total = sum(getattr(summary, "high_risk_services", Counter()).values())
        suspicious_total = sum(getattr(summary, "suspicious_services", Counter()).values())
        total_services = sum(summary.cip_services.values())
        normal_total = max(0, total_services - high_risk_total - suspicious_total)
        lines.append(SUBSECTION_BAR)
        lines.append(header("Command Risking Overview"))
        lines.append(_format_kv("Total Service Invocations", str(total_services)))
        lines.append(_format_kv("High-Risk Invocations", str(high_risk_total)))
        lines.append(_format_kv("Suspicious Invocations", str(suspicious_total)))
        lines.append(_format_kv("Normal Invocations", str(normal_total)))

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

    def _summarize_buckets(buckets: list[_SizeBucketLike]) -> tuple[int, float, int, int]:
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
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"CTF ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Hits", str(len(summary.hits))))
    lines.append(_format_kv("Decoded Hits", str(len(summary.decoded_hits))))
    lines.append(_format_kv("Candidate Findings", str(len(getattr(summary, "candidate_findings", []) or []))))
    lines.append(_format_kv("Start", format_ts(getattr(summary, "first_seen", None))))
    lines.append(_format_kv("End", format_ts(getattr(summary, "last_seen", None))))
    lines.append(_format_kv("Duration", format_duration(getattr(summary, "duration_seconds", None))))

    def _ctf_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_conf = int(getattr(summary, "confidence_counts", Counter()).get("high", 0))
        medium_conf = int(getattr(summary, "confidence_counts", Counter()).get("medium", 0))
        checks = getattr(summary, "deterministic_checks", {}) or {}

        if high_conf:
            score += min(4, high_conf)
            reasons.append(f"High-confidence CTF candidates observed ({high_conf})")
        if medium_conf >= 2:
            score += 1
            reasons.append(f"Multiple medium-confidence candidates observed ({medium_conf})")
        if checks.get("decoded_wrapper_pattern_present"):
            score += 2
            reasons.append("Decoded wrapper-pattern matches observed")
        if checks.get("multi_source_corroboration"):
            score += 1
            reasons.append("Cross-source corroboration observed")
        if checks.get("stream_reassembled_match"):
            score += 1
            reasons.append("Stream-boundary reconstruction recovered wrapper match")
        if checks.get("external_replay_exfil_behavior"):
            score += 1
            reasons.append("Candidate replay/exfil behavior observed")

        if score >= 7:
            verdict = "YES - high-confidence CTF flag evidence is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - strong CTF evidence is present with corroboration."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate CTF evidence is present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-confidence CTF evidence from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence CTF heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _ctf_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Reasons:"))
    for reason in verdict_reasons[:_limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    if summary.token_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Tokens"))
        lines.append(_format_kv("Token Frequency", _format_counter(summary.token_counts, 10)))

    if summary.decoded_hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Decoded Wrapper Hits"))
        for item in summary.decoded_hits[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(item)}"))

    if getattr(summary, "file_hints", None):
        if summary.file_hints:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Challenge File Hints"))
            for item in summary.file_hints[:_limit_value(10)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic CTF Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("flag_wrapper_pattern_present", "Flag Wrapper Pattern Present"),
        ("decoded_wrapper_pattern_present", "Decoded Wrapper Pattern Present"),
        ("multi_source_corroboration", "Multi-Source Corroboration"),
        ("stream_reassembled_match", "Stream-Reassembled Match"),
        ("external_replay_exfil_behavior", "External Replay/Exfil Behavior"),
        ("challenge_file_hint_correlation", "Challenge File Hint Correlation"),
        ("likely_secret_not_flag", "Likely Secret (Not Flag)"),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "likely_secret_not_flag":
                lines.append(ok(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                matrix_rows.append([label_text, "Low", "Medium", f"{len(evidence_items)} signal(s)"])
            else:
                lines.append(warn(f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"))
                risk = "High" if key in {"flag_wrapper_pattern_present", "decoded_wrapper_pattern_present", "stream_reassembled_match"} else "Medium"
                conf_level = "High" if key in {"decoded_wrapper_pattern_present", "multi_source_corroboration"} else "Medium"
                matrix_rows.append([label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"])
            for item in evidence_items[:_limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(ok(f"No, there is no strong evidence for {label_text.lower()} in this capture."))
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("CTF Confidence Matrix"))
    lines.append(_format_table(matrix_rows))

    findings = list(getattr(summary, "candidate_findings", []) or [])
    if findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Candidate Provenance"))
        rows = [["Candidate", "Score", "Confidence", "Decode", "Source", "Flow", "Packet", "Time"]]
        for item in findings[:_limit_value(15)]:
            rows.append([
                _truncate_text(_redact_in_text(str(item.get("candidate", "-"))), 36),
                str(item.get("score", "-")),
                str(item.get("confidence", "-")),
                str(item.get("decode_chain", "raw")),
                str(item.get("source", "-")),
                f"{item.get('src', '-')}->{item.get('dst', '-')}",
                str(item.get("packet", "-")),
                format_ts(item.get("ts")),
            ])
        lines.append(_format_table(rows))

    timeline = list(getattr(summary, "timeline", []) or [])
    if timeline:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Timeline"))
        rows = [["Time", "Event", "Candidate", "Confidence", "Flow", "Packet"]]
        for item in timeline[:_limit_value(15)]:
            rows.append([
                format_ts(item.get("ts")),
                str(item.get("event", "-")),
                _truncate_text(_redact_in_text(str(item.get("candidate", "-"))), 42),
                str(item.get("confidence", "-")),
                f"{item.get('src', '-')}->{item.get('dst', '-')}",
                str(item.get("packet", "-")),
            ])
        lines.append(_format_table(rows))

    pivots = list(getattr(summary, "hunting_pivots", []) or [])
    if pivots:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Actionable Hunting Pivots"))
        rows = [["Packet", "Source", "Destination", "Proto", "Candidate", "Decode"]]
        for item in pivots[:_limit_value(15)]:
            rows.append([
                str(item.get("packet", "-")),
                str(item.get("src", "-")),
                str(item.get("dst", "-")),
                str(item.get("protocol", "-")),
                _truncate_text(_redact_in_text(str(item.get("candidate", "-"))), 42),
                str(item.get("decode_chain", "raw")),
            ])
        lines.append(_format_table(rows))

    false_context = list(getattr(summary, "false_positive_context", []) or [])
    if false_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_context[:_limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(item)}"))

    lines.append(SECTION_BAR)
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
    if not summary:
        return ""
    lines = [header("OBFUSCATION / TUNNELING")]
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Payload Bytes", str(summary.total_payload_bytes)))
    lines.append(_format_kv("Suspicious Packets", str(getattr(summary, "suspicious_packets", 0))))
    lines.append(_format_kv("Suspicious Bytes", str(getattr(summary, "suspicious_payload_bytes", 0))))
    if getattr(summary, "total_payload_bytes", 0):
        suspicious_share = (getattr(summary, "suspicious_payload_bytes", 0) / summary.total_payload_bytes) * 100.0
        lines.append(_format_kv("Suspicious Byte Share", f"{suspicious_share:.1f}%"))
    lines.append(_format_kv("Start", format_ts(getattr(summary, "first_seen", None))))
    lines.append(_format_kv("End", format_ts(getattr(summary, "last_seen", None))))
    lines.append(_format_kv("Duration", format_duration(getattr(summary, "duration_seconds", None))))
    duration = getattr(summary, "duration_seconds", None)
    if isinstance(duration, (int, float)) and duration > 0 and summary.total_payload_bytes:
        lines.append(_format_kv("Observed Throughput", format_speed_bps(int((summary.total_payload_bytes * 8) / duration))))
    if isinstance(duration, (int, float)) and duration > 0 and getattr(summary, "suspicious_payload_bytes", 0):
        lines.append(_format_kv("Suspicious Throughput", format_speed_bps(int((summary.suspicious_payload_bytes * 8) / duration))))
    lines.append(_format_kv("Sessions (Susp/Total)", f"{getattr(summary, 'suspicious_sessions', 0)}/{getattr(summary, 'total_sessions', 0)}"))
    lines.append(_format_kv("High Entropy Hits", str(len(summary.high_entropy_hits))))
    lines.append(_format_kv("Base64 Hits", str(len(summary.base64_hits))))
    lines.append(_format_kv("Hex Hits", str(len(summary.hex_hits))))
    if getattr(summary, "hit_kind_counts", None):
        if summary.hit_kind_counts:
            lines.append(_format_kv("Hit Kinds", _format_counter(summary.hit_kind_counts, 6)))
    if summary.source_counts:
        lines.append(_format_kv("Top Sources", _format_counter(summary.source_counts, 6)))
    if summary.destination_counts:
        lines.append(_format_kv("Top Destinations", _format_counter(summary.destination_counts, 6)))
    if getattr(summary, "protocol_counts", None):
        if summary.protocol_counts:
            lines.append(_format_kv("Suspicious Protocols", _format_counter(summary.protocol_counts, 6)))
    if getattr(summary, "port_counts", None):
        if summary.port_counts:
            lines.append(_format_kv("Suspicious Ports", _format_counter(summary.port_counts, 6)))
    if getattr(summary, "ioc_counts", None):
        if summary.ioc_counts:
            lines.append(_format_kv("Recovered IOCs", _format_counter(summary.ioc_counts, 8)))
    if getattr(summary, "attack_counts", None):
        if summary.attack_counts:
            lines.append(_format_kv("Attack Signals", _format_counter(summary.attack_counts, 8)))

    session_lookup: dict[str, object] = {}
    if getattr(summary, "session_stats", None):
        session_lookup = {str(item.flow_id): item for item in summary.session_stats}

    if getattr(summary, "session_stats", None):
        suspicious_sessions = [item for item in summary.session_stats if getattr(item, "suspicious_packets", 0)]
        if suspicious_sessions:
            lines.append(header("Suspicious Sessions"))
            rows = [["Session", "Hits(H/B/X)", "Packets", "Payload", "Susp Bytes", "Timerange", "Duration"]]
            for item in suspicious_sessions[:_limit_value(8)]:
                timerange = f"{format_ts(getattr(item, 'first_seen', None))} -> {format_ts(getattr(item, 'last_seen', None))}"
                rows.append([
                    getattr(item, "flow_id", "-"),
                    f"{getattr(item, 'high_entropy_hits', 0)}/{getattr(item, 'base64_hits', 0)}/{getattr(item, 'hex_hits', 0)}",
                    str(getattr(item, "packets", 0)),
                    str(getattr(item, "payload_bytes", 0)),
                    str(getattr(item, "suspicious_payload_bytes", 0)),
                    timerange,
                    format_duration(getattr(item, "duration_seconds", None)),
                ])
            lines.append(_format_table(rows))

    if summary.high_entropy_hits:
        lines.append(header("High-Entropy Samples"))
        rows = [["Time", "Session", "Len", "Entropy", "Print", "Timerange", "Session Stats", "Traffic", "Reasoning"]]
        for hit in summary.high_entropy_hits[:_limit_value(8)]:
            session = session_lookup.get(str(getattr(hit, "flow_id", "")))
            timerange = "-"
            session_stats = "-"
            traffic = "-"
            if session is not None:
                timerange = f"{format_ts(getattr(session, 'first_seen', None))} -> {format_ts(getattr(session, 'last_seen', None))}"
                session_stats = (
                    f"pkts={getattr(session, 'packets', 0)} "
                    f"susp={getattr(session, 'suspicious_packets', 0)} "
                    f"hits={getattr(session, 'high_entropy_hits', 0)}/{getattr(session, 'base64_hits', 0)}/{getattr(session, 'hex_hits', 0)}"
                )
                payload_bytes = int(getattr(session, "payload_bytes", 0) or 0)
                suspicious_bytes = int(getattr(session, "suspicious_payload_bytes", 0) or 0)
                if payload_bytes > 0:
                    traffic = f"{suspicious_bytes}/{payload_bytes} ({(suspicious_bytes / payload_bytes) * 100.0:.1f}%)"
                else:
                    traffic = f"{suspicious_bytes}/0"
            rows.append([
                format_ts(getattr(hit, "ts", None)),
                getattr(hit, "flow_id", f"{hit.src}:{hit.src_port}->{hit.dst}:{hit.dst_port}"),
                str(hit.length),
                f"{hit.entropy:.2f}",
                f"{getattr(hit, 'printable_ratio', 0.0):.2f}",
                timerange,
                session_stats,
                traffic,
                _truncate_text(getattr(hit, "reasoning", "-"), 96),
            ])
        lines.append(_format_table(rows))
        lines.append(muted("Evidence:"))
        for hit in summary.high_entropy_hits[:_limit_value(6)]:
            lines.append(
                muted(
                    f"pkt={getattr(hit, 'packet_index', '-')} "
                    f"time={format_ts(getattr(hit, 'ts', None))} "
                    f"session={getattr(hit, 'flow_id', '-')} "
                    f"sample={_truncate_text(getattr(hit, 'sample', '-'), 96)}"
                )
            )

    if getattr(summary, "artifacts", None):
        if summary.artifacts:
            lines.append(header("Recovered Artifacts"))
            rows = [["Type", "Value", "Source", "Session", "Time", "Confidence", "Reasoning"]]
            for item in summary.artifacts[:_limit_value(12)]:
                rows.append([
                    getattr(item, "kind", "-"),
                    _truncate_text(str(getattr(item, "value", "-")), 56),
                    getattr(item, "source_kind", "-"),
                    _truncate_text(getattr(item, "flow_id", "-"), 44),
                    format_ts(getattr(item, "ts", None)),
                    getattr(item, "confidence", "-"),
                    _truncate_text(getattr(item, "reasoning", "-"), 84),
                ])
            lines.append(_format_table(rows))

    if summary.base64_hits:
        lines.append(header("Base64 Samples"))
        for hit in summary.base64_hits[:_limit_value(4)]:
            lines.append(
                muted(
                    f"{format_ts(getattr(hit, 'ts', None))} "
                    f"{hit.src}:{hit.src_port} -> {hit.dst}:{hit.dst_port} "
                    f"len={hit.length} entropy={hit.entropy:.2f} "
                    f"reason={_truncate_text(getattr(hit, 'reasoning', '-'), 72)} "
                    f"sample={_truncate_text(getattr(hit, 'sample', '-'), 72)}"
                )
            )
    if summary.hex_hits:
        lines.append(header("Hex Samples"))
        for hit in summary.hex_hits[:_limit_value(4)]:
            lines.append(
                muted(
                    f"{format_ts(getattr(hit, 'ts', None))} "
                    f"{hit.src}:{hit.src_port} -> {hit.dst}:{hit.dst_port} "
                    f"len={hit.length} entropy={hit.entropy:.2f} "
                    f"reason={_truncate_text(getattr(hit, 'reasoning', '-'), 72)} "
                    f"sample={_truncate_text(getattr(hit, 'sample', '-'), 72)}"
                )
            )
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
