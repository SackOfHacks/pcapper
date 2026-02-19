from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional
import re
import ipaddress

from .pcap_cache import get_reader
from .utils import safe_float, counter_inc, decode_payload
from .files import analyze_files
from .powershell import PS_COMMAND_RE
from .wmic import WMIC_COMMAND_RE
from .winrm import WINRM_PORTS, WSMAN_RE
from .telnet import TELNET_PORTS
from .modbus import FUNC_NAMES as MODBUS_FUNC_NAMES, EXCEPTION_CODES as MODBUS_EXC_CODES
from .cip import ENIP_COMMANDS
from .opc import OPC_TYPES, OPC_UA_PORT
from .modbus import MODBUS_TCP_PORT
from .dnp3 import DNP3_PORT
from .iec104 import IEC104_PORT
from .s7 import S7_PORT
from .bacnet import BACNET_PORT
from .profinet import PROFINET_PORTS
from .dnp3 import analyze_dnp3
from .iec104 import analyze_iec104
from .s7 import analyze_s7
from .ot_risk import compute_ot_risk_posture, dedupe_findings

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet import ICMP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore
    ICMP = None  # type: ignore
    ICMPv6EchoRequest = None  # type: ignore
    ICMPv6EchoReply = None  # type: ignore
    ICMPv6ND_NS = None  # type: ignore
    ICMPv6ND_NA = None  # type: ignore

try:
    from scapy.layers.netbios import NBNS, NBNSQueryRequest, NBNSQueryResponse  # type: ignore
except Exception:  # pragma: no cover
    NBNS = None  # type: ignore
    NBNSQueryRequest = None  # type: ignore
    NBNSQueryResponse = None  # type: ignore


@dataclass(frozen=True)
class TimelineEvent:
    ts: Optional[float]
    category: str
    summary: str
    details: str


@dataclass(frozen=True)
class TimelineSummary:
    path: Path
    target_ip: str
    total_packets: int
    events: list[TimelineEvent]
    errors: list[str]
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration: Optional[float] = None
    category_counts: dict[str, int] = field(default_factory=dict)
    peer_counts: dict[str, int] = field(default_factory=dict)
    port_counts: dict[int, int] = field(default_factory=dict)
    ot_protocol_counts: dict[str, int] = field(default_factory=dict)
    ot_activity_bins: dict[str, list[int]] = field(default_factory=dict)
    ot_activity_bin_count: int = 0
    non_ot_activity_bins: list[int] = field(default_factory=list)
    non_ot_activity_bin_count: int = 0
    ot_risk_score: int = 0
    ot_risk_findings: list[str] = field(default_factory=list)
    ot_storyline: list[str] = field(default_factory=list)


def merge_timeline_summaries(summaries: Iterable[TimelineSummary]) -> TimelineSummary:
    summary_list = list(summaries)
    if not summary_list:
        return TimelineSummary(
            path=Path("ALL_PCAPS_0"),
            target_ip="-",
            total_packets=0,
            events=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration=None,
            category_counts={},
            peer_counts={},
            port_counts={},
            ot_protocol_counts={},
            ot_activity_bins={},
            ot_activity_bin_count=0,
            non_ot_activity_bins=[],
            non_ot_activity_bin_count=0,
            ot_risk_score=0,
            ot_risk_findings=[],
            ot_storyline=[],
        )

    target_ip = summary_list[0].target_ip
    total_packets = sum(item.total_packets for item in summary_list)
    merged_events: list[TimelineEvent] = []
    for item in summary_list:
        merged_events.extend(item.events)
    merged_events.sort(key=lambda event: (event.ts is None, event.ts))

    seen_errors: set[str] = set()
    errors: list[str] = []
    for item in summary_list:
        for err in item.errors:
            if err in seen_errors:
                continue
            seen_errors.add(err)
            errors.append(err)

    first_seen = None
    last_seen = None
    category_counts: Counter[str] = Counter()
    peer_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    ot_protocol_counts: Counter[str] = Counter()
    ot_activity_bins: dict[str, list[int]] = {}
    ot_bin_count = 0
    non_ot_bins: list[int] = []
    non_ot_bin_count = 0

    for item in summary_list:
        if item.first_seen is not None:
            first_seen = item.first_seen if first_seen is None else min(first_seen, item.first_seen)
        if item.last_seen is not None:
            last_seen = item.last_seen if last_seen is None else max(last_seen, item.last_seen)
        category_counts.update(item.category_counts or {})
        peer_counts.update(item.peer_counts or {})
        port_counts.update(item.port_counts or {})
        ot_protocol_counts.update(item.ot_protocol_counts or {})
        if item.ot_activity_bins:
            ot_bin_count = max(ot_bin_count, item.ot_activity_bin_count)
            for proto, bins in item.ot_activity_bins.items():
                merged = ot_activity_bins.setdefault(proto, [0] * len(bins))
                if len(merged) < len(bins):
                    merged.extend([0] * (len(bins) - len(merged)))
                for idx, val in enumerate(bins):
                    merged[idx] += val
        if item.non_ot_activity_bins:
            non_ot_bin_count = max(non_ot_bin_count, item.non_ot_activity_bin_count)
            if not non_ot_bins:
                non_ot_bins = [0] * len(item.non_ot_activity_bins)
            if len(non_ot_bins) < len(item.non_ot_activity_bins):
                non_ot_bins.extend([0] * (len(item.non_ot_activity_bins) - len(non_ot_bins)))
            for idx, val in enumerate(item.non_ot_activity_bins):
                non_ot_bins[idx] += val

    duration = None
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    merged = TimelineSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        target_ip=target_ip,
        total_packets=total_packets,
        events=merged_events,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration=duration,
        category_counts=dict(category_counts),
        peer_counts=dict(peer_counts),
        port_counts=dict(port_counts),
        ot_protocol_counts=dict(ot_protocol_counts),
        ot_activity_bins=ot_activity_bins,
        ot_activity_bin_count=ot_bin_count,
        non_ot_activity_bins=non_ot_bins,
        non_ot_activity_bin_count=non_ot_bin_count,
    )
    risk_score, risk_findings = _compute_ot_risk_posture(merged.events, target_ip)
    storyline = _compute_ot_storyline(merged.events, target_ip, merged.ot_protocol_counts, risk_score, risk_findings)
    merged = TimelineSummary(
        path=merged.path,
        target_ip=merged.target_ip,
        total_packets=merged.total_packets,
        events=merged.events,
        errors=merged.errors,
        first_seen=merged.first_seen,
        last_seen=merged.last_seen,
        duration=merged.duration,
        category_counts=merged.category_counts,
        peer_counts=merged.peer_counts,
        port_counts=merged.port_counts,
        ot_protocol_counts=merged.ot_protocol_counts,
        ot_activity_bins=merged.ot_activity_bins,
        ot_activity_bin_count=merged.ot_activity_bin_count,
        non_ot_activity_bins=merged.non_ot_activity_bins,
        non_ot_activity_bin_count=merged.non_ot_activity_bin_count,
        ot_risk_score=risk_score,
        ot_risk_findings=risk_findings,
        ot_storyline=storyline,
    )
    return merged


EMAIL_PORT_SERVICES: dict[int, str] = {
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP Submission",
    2525: "SMTP Alternate",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
}

OT_PORT_PROTOCOLS: dict[int, str] = {
    MODBUS_TCP_PORT: "Modbus",
    DNP3_PORT: "DNP3",
    IEC104_PORT: "IEC-104",
    S7_PORT: "S7",
    44818: "ENIP",
    2222: "CIP",
    BACNET_PORT: "BACnet",
    OPC_UA_PORT: "OPC UA",
    1911: "Niagara Fox",
    4911: "Niagara Fox",
    9600: "FINS",
    5094: "HART-IP",
    18245: "SRTP",
    18246: "SRTP",
    1962: "PCWorx",
    5006: "MELSEC",
    5007: "MELSEC",
    20547: "ProConOS",
    2455: "CODESYS",
    1217: "CODESYS",
    5683: "CoAP",
    5684: "CoAP",
}

for _port in PROFINET_PORTS:
    OT_PORT_PROTOCOLS[_port] = "PROFINET"

OT_CATEGORIES = {
    "Modbus",
    "DNP3",
    "IEC-104",
    "S7",
    "ENIP",
    "CIP",
    "BACnet",
    "OPC UA",
    "PROFINET",
    "Niagara Fox",
    "FINS",
    "HART-IP",
    "SRTP",
    "PCWorx",
    "MELSEC",
    "ProConOS",
    "CODESYS",
    "CoAP",
}

NON_OT_CATEGORIES = {
    "Connection",
    "DNS",
    "Email",
    "File Transfer",
    "HTTP",
    "ICMP",
    "LDAP",
    "MS Domain",
    "NetBIOS",
    "PowerShell",
    "RPC",
    "Recon",
    "SMB",
    "SNMP",
    "Telnet",
    "WMIC",
    "WinRM",
    "mDNS",
}

TIMELINE_CATEGORIES = tuple(sorted(OT_CATEGORIES | NON_OT_CATEGORIES, key=str.casefold))


def _decode_payload_line(payload: bytes | None) -> str:
    if not payload:
        return ""
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return ""
    first = text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    return first[:200]


def _extract_email_action(service: str, first_line: str) -> str | None:
    if not first_line:
        return None
    upper = first_line.upper()

    if service.startswith("SMTP"):
        smtp_cmds = (
            "EHLO", "HELO", "MAIL FROM", "RCPT TO", "DATA", "STARTTLS", "AUTH", "QUIT", "NOOP", "RSET", "VRFY", "EXPN"
        )
        for cmd in smtp_cmds:
            if upper.startswith(cmd):
                return cmd
        if re.match(r"^\d{3}\b", upper):
            return f"SMTP reply {upper[:3]}"

    if service.startswith("IMAP"):
        imap_cmds = (
            "LOGIN", "AUTHENTICATE", "SELECT", "EXAMINE", "FETCH", "UID", "SEARCH", "STORE", "COPY", "APPEND", "IDLE", "LOGOUT", "STARTTLS", "CAPABILITY"
        )
        parts = upper.split()
        if parts:
            if parts[0] in {"*", "+"} and len(parts) >= 2:
                token = parts[1]
                if token in {"OK", "NO", "BAD", "BYE", "PREAUTH"}:
                    return f"IMAP reply {token}"
            if len(parts) >= 2:
                token = parts[1]
                if token in imap_cmds:
                    return token

    if service.startswith("POP3"):
        pop3_cmds = (
            "USER", "PASS", "APOP", "AUTH", "STAT", "LIST", "RETR", "DELE", "TOP", "UIDL", "CAPA", "STLS", "QUIT"
        )
        for cmd in pop3_cmds:
            if upper.startswith(cmd):
                return cmd
        if upper.startswith("+OK"):
            return "POP3 reply +OK"
        if upper.startswith("-ERR"):
            return "POP3 reply -ERR"

    return None


def _extract_email_command(service: str, first_line: str) -> str | None:
    action = _extract_email_action(service, first_line)
    if action:
        return action
    if not first_line:
        return None
    upper = first_line.upper()
    if service.startswith("SMTP"):
        if upper.startswith(("EHLO", "HELO", "MAIL FROM", "RCPT TO", "DATA", "STARTTLS", "AUTH", "QUIT", "NOOP", "RSET", "VRFY", "EXPN")):
            return first_line
    if service.startswith("IMAP"):
        parts = upper.split()
        if len(parts) >= 2 and parts[1].isalpha():
            return first_line
    if service.startswith("POP3"):
        if upper.startswith(("USER", "PASS", "APOP", "AUTH", "STAT", "LIST", "RETR", "DELE", "TOP", "UIDL", "CAPA", "STLS", "QUIT", "+OK", "-ERR")):
            return first_line
    return None


def _extract_powershell_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    match = PS_COMMAND_RE.search(text[:2000])
    if not match:
        return None
    return match.group(0).strip()[:200]


def _extract_wmic_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    match = WMIC_COMMAND_RE.search(text[:2000])
    if not match:
        return None
    return match.group(0).strip()[:200]


WINRM_COMMAND_RE = re.compile(
    r"(?:\bwinrs\b[^\r\n]{0,200}|<Command>([^<]{1,200})</Command>|CommandLine>\s*([^<]{1,200}))",
    re.IGNORECASE,
)


def _extract_winrm_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    match = WINRM_COMMAND_RE.search(text[:4000])
    if not match:
        return None
    if match.group(1):
        return match.group(1).strip()[:200]
    if match.group(2):
        return match.group(2).strip()[:200]
    return match.group(0).strip()[:200]


TELNET_COMMAND_RE = re.compile(r"^[#>$]\s*([A-Za-z0-9._:/\\-]+(?:\s+[^\r\n]{0,160})?)$", re.IGNORECASE | re.MULTILINE)


def _extract_telnet_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    match = TELNET_COMMAND_RE.search(text[:2000])
    if not match:
        return None
    return match.group(1).strip()[:200]


def _rpc_packet_type(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 6:
        return None
    try:
        if payload[0] != 0x05:
            return None
        ptype = payload[2]
    except Exception:
        return None
    return {
        0x00: "request",
        0x02: "response",
        0x0B: "bind",
        0x0C: "bind_ack",
        0x0D: "bind_nak",
        0x0E: "alter_context",
        0x0F: "alter_context_resp",
    }.get(ptype)


def _snmp_pdu_type(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 10:
        return None
    if payload[0] != 0x30:
        return None
    length, idx = _read_ber_length(payload, 1)
    if length is None or idx >= len(payload):
        return None
    if idx >= len(payload) or payload[idx] != 0x02:
        return None
    ver_len, idx = _read_ber_length(payload, idx + 1)
    if ver_len is None or idx + ver_len > len(payload):
        return None
    idx += ver_len
    if idx >= len(payload) or payload[idx] != 0x04:
        return None
    comm_len, idx = _read_ber_length(payload, idx + 1)
    if comm_len is None or idx + comm_len > len(payload):
        return None
    idx += comm_len
    if idx >= len(payload):
        return None
    pdu = payload[idx]
    return {
        0xA0: "GetRequest",
        0xA1: "GetNextRequest",
        0xA2: "GetResponse",
        0xA3: "SetRequest",
        0xA4: "Trap",
        0xA5: "GetBulkRequest",
        0xA6: "InformRequest",
        0xA7: "SNMPv2-Trap",
        0xA8: "Report",
    }.get(pdu)


def _parse_modbus_command(payload: bytes | None) -> tuple[int, str, bool, int | None, str | None] | None:
    if not payload or len(payload) < 8:
        return None
    try:
        unit_id = payload[6]
        func_code = payload[7]
    except Exception:
        return None
    is_exception = func_code >= 0x80
    base_code = func_code & 0x7F
    name = MODBUS_FUNC_NAMES.get(base_code, f"Function {base_code}")
    exc_code = None
    exc_desc = None
    if is_exception and len(payload) >= 9:
        exc_code = payload[8]
        exc_desc = MODBUS_EXC_CODES.get(exc_code)
    return func_code, name, is_exception, unit_id, exc_desc


def _parse_enip_command(payload: bytes | None) -> tuple[int, str | None] | None:
    if not payload or len(payload) < 2:
        return None
    cmd = int.from_bytes(payload[:2], "little", signed=False)
    return cmd, ENIP_COMMANDS.get(cmd)


def _parse_opcua_message(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 3:
        return None
    return OPC_TYPES.get(payload[:3])


def _iec104_frame_type(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 6:
        return None
    if payload[0] != 0x68:
        return None
    ctrl = payload[2:6]
    if (ctrl[0] & 0x01) == 0:
        return "I-frame"
    if (ctrl[0] & 0x03) == 1:
        return "S-frame"
    if (ctrl[0] & 0x03) == 3:
        return "U-frame"
    return None


def _dnp3_frame_seen(payload: bytes | None) -> bool:
    if not payload:
        return False
    return payload.find(b"\x05\x64") != -1


def _s7comm_seen(payload: bytes | None) -> bool:
    if not payload:
        return False
    if len(payload) >= 4 and payload[:2] == b"\x03\x00":
        return b"\x32" in payload
    return False


def _extract_ip_candidates(text: str) -> set[str]:
    candidates: set[str] = set()
    for token in re.findall(r"(?:\\d{1,3}\\.){3}\\d{1,3}", text):
        candidates.add(token)
    return candidates


def _compute_ot_activity_bins(
    events: list[TimelineEvent],
    first_seen: Optional[float],
    last_seen: Optional[float],
    bins: int = 24,
) -> tuple[dict[str, list[int]], int]:
    if not events or first_seen is None or last_seen is None or last_seen <= first_seen:
        return {}, 0
    duration = max(1.0, last_seen - first_seen)
    bin_size = duration / bins
    protocol_bins: dict[str, list[int]] = {}
    for event in events:
        if event.ts is None:
            continue
        if event.category not in OT_CATEGORIES:
            continue
        idx = int((event.ts - first_seen) / bin_size)
        if idx >= bins:
            idx = bins - 1
        if idx < 0:
            idx = 0
        bucket = protocol_bins.setdefault(event.category, [0] * bins)
        bucket[idx] += 1
    return protocol_bins, bins


def _compute_non_ot_activity_bins(
    events: list[TimelineEvent],
    first_seen: Optional[float],
    last_seen: Optional[float],
    bins: int = 24,
) -> tuple[list[int], int]:
    if not events or first_seen is None or last_seen is None or last_seen <= first_seen:
        return [], 0
    duration = max(1.0, last_seen - first_seen)
    bin_size = duration / bins
    bucket = [0] * bins
    for event in events:
        if event.ts is None:
            continue
        if event.category in OT_CATEGORIES:
            continue
        idx = int((event.ts - first_seen) / bin_size)
        if idx >= bins:
            idx = bins - 1
        if idx < 0:
            idx = 0
        bucket[idx] += 1
    return bucket, bins


def _compute_ot_risk_posture(events: list[TimelineEvent], target_ip: str) -> tuple[int, list[str]]:
    if not events:
        return 0, []
    public_peers: set[str] = set()
    control_hits = 0
    transfer_hits = 0
    anomaly_hits = 0

    control_tokens = (
        "write", "control", "setpoint", "start", "stop", "program", "download", "upload", "firmware",
        "plcstop", "plchotstart", "plccoldstart", "writevar",
    )
    for event in events:
        if event.category not in OT_CATEGORIES:
            continue
        detail = f"{event.summary} {event.details}".lower()
        if any(token in detail for token in control_tokens):
            control_hits += 1
        if any(token in detail for token in ("download", "upload", "file operation", "program transfer")):
            transfer_hits += 1
        if "anomaly" in detail or "restart" in detail or "command" in detail:
            if "error" not in detail:
                anomaly_hits += 1
        for ip_text in _extract_ip_candidates(event.details):
            if ip_text == target_ip:
                continue
            try:
                if ipaddress.ip_address(ip_text).is_global:
                    public_peers.add(ip_text)
            except Exception:
                continue

    score, findings = compute_ot_risk_posture(
        public_ot_flows=len(public_peers),
        control_hits=control_hits,
        anomaly_hits=anomaly_hits,
    )
    if transfer_hits:
        findings.append(f"OT program/file transfer indicators ({transfer_hits}).")
    return score, dedupe_findings(findings, limit=6)


def _compute_ot_storyline(
    events: list[TimelineEvent],
    target_ip: str,
    ot_protocol_counts: dict[str, int],
    risk_score: int,
    risk_findings: list[str],
) -> list[str]:
    if not ot_protocol_counts:
        return [f"No OT/ICS protocols observed for {target_ip}."]
    top_protocols = sorted(ot_protocol_counts.items(), key=lambda item: (-item[1], item[0]))
    proto_text = ", ".join(f"{name} ({count})" for name, count in top_protocols[:4])
    storyline = [f"OT protocols observed: {proto_text}."]
    if risk_score:
        storyline.append(f"OT risk posture scored {risk_score}/100.")
    if risk_findings:
        storyline.append("Key signals: " + "; ".join(risk_findings[:3]))
    control_hits = 0
    for event in events:
        if event.category not in OT_CATEGORIES:
            continue
        detail = f"{event.summary} {event.details}".lower()
        if any(token in detail for token in ("write", "control", "setpoint", "start", "stop", "program", "download", "upload", "firmware")):
            control_hits += 1
    if control_hits:
        storyline.append(f"Control or program-change indications seen ({control_hits}).")
    return storyline


def _first_ts_for_category(events: list[TimelineEvent], category: str) -> Optional[float]:
    timestamps = [event.ts for event in events if event.category == category and event.ts is not None]
    return min(timestamps) if timestamps else None


def _read_ber_length(payload: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset >= len(payload):
        return None, offset
    first = payload[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(payload):
        return None, offset
    length = int.from_bytes(payload[offset:offset + num_bytes], "big")
    offset += num_bytes
    return length, offset


def _icmp_label(pkt) -> str | None:
    if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
        try:
            icmp = pkt[ICMP]  # type: ignore[index]
            itype = int(getattr(icmp, "type", -1))
            code = int(getattr(icmp, "code", -1))
        except Exception:
            return "ICMP"
        if itype == 8:
            return "ICMP Echo Request"
        if itype == 0:
            return "ICMP Echo Reply"
        if itype == 3:
            return f"ICMP Destination Unreachable (code {code})"
        if itype == 11:
            return f"ICMP Time Exceeded (code {code})"
        return f"ICMP type {itype} code {code}"
    if ICMPv6EchoRequest is not None and pkt.haslayer(ICMPv6EchoRequest):  # type: ignore[truthy-bool]
        return "ICMPv6 Echo Request"
    if ICMPv6EchoReply is not None and pkt.haslayer(ICMPv6EchoReply):  # type: ignore[truthy-bool]
        return "ICMPv6 Echo Reply"
    if ICMPv6ND_NS is not None and pkt.haslayer(ICMPv6ND_NS):  # type: ignore[truthy-bool]
        return "ICMPv6 Neighbor Solicitation"
    if ICMPv6ND_NA is not None and pkt.haslayer(ICMPv6ND_NA):  # type: ignore[truthy-bool]
        return "ICMPv6 Neighbor Advertisement"
    return None


def _nbns_info(pkt) -> tuple[str, str]:
    action = "NetBIOS activity"
    name = "-"
    if NBNSQueryRequest is not None and pkt.haslayer(NBNSQueryRequest):  # type: ignore[truthy-bool]
        action = "NBNS name query"
    elif NBNSQueryResponse is not None and pkt.haslayer(NBNSQueryResponse):  # type: ignore[truthy-bool]
        action = "NBNS name response"
    if NBNS is not None and pkt.haslayer(NBNS):  # type: ignore[truthy-bool]
        try:
            nb = pkt[NBNS]  # type: ignore[index]
            qd = getattr(nb, "qd", None)
            qname = getattr(qd, "qname", None)
            if qname is not None:
                name = str(qname).strip(".")
        except Exception:
            name = "-"
    return action, name


def _netbios_session_hint(payload: bytes | None) -> str | None:
    if not payload:
        return None
    if b"NTLMSSP" in payload or b"\xfeSMB" in payload or b"\xffSMB" in payload:
        return "NetBIOS/SMB session setup"
    return None


def analyze_timeline(
    path: Path,
    target_ip: str,
    show_status: bool = True,
    timeline_bins: int = 24,
    timeline_storyline_off: bool = False,
    categories: set[str] | None = None,
) -> TimelineSummary:
    errors: list[str] = []
    events: list[TimelineEvent] = []

    file_summary = analyze_files(path, show_status=False)
    artifacts_for_ip = [
        art for art in file_summary.artifacts
        if art.src_ip == target_ip or art.dst_ip == target_ip
    ]
    artifact_indices = {art.packet_index for art in artifacts_for_ip if art.packet_index}

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    total_packets = 0
    idx = 0
    index_ts: dict[int, float] = {}
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    peer_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    ot_protocol_counts: Counter[str] = Counter()
    seen_ot_flows: set[tuple[str, str, str, int]] = set()
    seen_ot_commands: set[tuple[str, str, str, int, str]] = set()
    seen_udp_flows: set[tuple[str, int]] = set()
    seen_domain_flows: set[tuple[str, int, str, str]] = set()
    seen_ldap_flows: set[tuple[str, int, str, str]] = set()
    seen_email_flows: set[tuple[str, int, str, str, str]] = set()
    seen_email_actions: set[tuple[str, int, str, str, str, str]] = set()
    scan_ports: dict[str, set[int]] = defaultdict(set)
    scan_first: dict[str, float] = {}
    scan_last: dict[str, float] = {}
    seen_ps_commands: set[tuple[str, str, int, str]] = set()
    seen_wmic_commands: set[tuple[str, str, int, str]] = set()
    seen_winrm_commands: set[tuple[str, str, int, str]] = set()
    seen_telnet_commands: set[tuple[str, str, int, str]] = set()
    seen_rpc_events: set[tuple[str, str, int, str]] = set()
    seen_mdns_events: set[tuple[str, str, str]] = set()
    seen_nbns_events: set[tuple[str, str, str]] = set()
    seen_snmp_events: set[tuple[str, str, int, str]] = set()
    seen_netbios_sessions: set[tuple[str, str, int]] = set()
    tcp_handshakes: dict[tuple[str, str, int, int], list[dict[str, Optional[float]]]] = defaultdict(list)

    def _new_handshake(syn_ts: Optional[float] = None, synack_ts: Optional[float] = None) -> dict[str, Optional[float]]:
        return {"syn": syn_ts, "synack": synack_ts, "ack": None}

    def _find_handshake_for_synack(items: list[dict[str, Optional[float]]]) -> dict[str, Optional[float]] | None:
        for handshake in reversed(items):
            if handshake["syn"] is not None and handshake["synack"] is None:
                return handshake
        for handshake in reversed(items):
            if handshake["synack"] is None:
                return handshake
        return None

    def _find_handshake_for_ack(items: list[dict[str, Optional[float]]]) -> dict[str, Optional[float]] | None:
        for handshake in reversed(items):
            if handshake["synack"] is not None and handshake["ack"] is None:
                return handshake
        return None

    domain_ports = {88, 464, 445, 139, 135, 593, 3268, 3269}
    ldap_ports = {389, 636, 3268, 3269}

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            idx += 1
            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))

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

            if idx in artifact_indices and ts is not None:
                index_ts[idx] = ts

            if not src_ip or not dst_ip:
                continue

            if (src_ip == target_ip or dst_ip == target_ip):
                if ts is not None:
                    if first_seen is None or ts < first_seen:
                        first_seen = ts
                    if last_seen is None or ts > last_seen:
                        last_seen = ts
                peer_ip = dst_ip if src_ip == target_ip else src_ip
                if peer_ip:
                    counter_inc(peer_counts, peer_ip)

            if (src_ip == target_ip or dst_ip == target_ip):
                label = _icmp_label(pkt)
                if label:
                    events.append(TimelineEvent(
                        ts=ts,
                        category="ICMP",
                        summary=label,
                        details=f"{src_ip} -> {dst_ip}",
                    ))

            if DNS is not None and DNSQR is not None and pkt.haslayer(DNS):  # type: ignore[truthy-bool]
                dns_layer = pkt[DNS]  # type: ignore[index]
                if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                    udp_layer = pkt[UDP]  # type: ignore[index]
                    sport = int(getattr(udp_layer, "sport", 0) or 0)
                    dport = int(getattr(udp_layer, "dport", 0) or 0)
                    if sport == 5353 or dport == 5353:
                        try:
                            qd = dns_layer.qd  # type: ignore[attr-defined]
                            qname = getattr(qd, "qname", b"")
                            qtype = getattr(qd, "qtype", None)
                            name = qname.decode("utf-8", errors="ignore").rstrip(".") if isinstance(qname, (bytes, bytearray)) else str(qname)
                        except Exception:
                            name = "-"
                            qtype = None
                        direction = "query" if getattr(dns_layer, "qr", 1) == 0 else "response"
                        key = (direction, name, str(qtype))
                        if key not in seen_mdns_events and (src_ip == target_ip or dst_ip == target_ip):
                            seen_mdns_events.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="mDNS",
                                summary=f"mDNS {direction}",
                                details=f"{src_ip} -> {dst_ip} {name} (type {qtype})",
                            ))
                if getattr(dns_layer, "qr", 1) == 0 and src_ip == target_ip:
                    try:
                        qd = dns_layer.qd  # type: ignore[attr-defined]
                        qname = getattr(qd, "qname", b"")
                        qtype = getattr(qd, "qtype", None)
                        name = qname.decode("utf-8", errors="ignore").rstrip(".") if isinstance(qname, (bytes, bytearray)) else str(qname)
                        events.append(TimelineEvent(
                            ts=ts,
                            category="DNS",
                            summary="DNS query",
                            details=f"{target_ip} queried {name} (type {qtype})",
                        ))
                        qname_lower = name.lower()
                        if any(token in qname_lower for token in ("_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_msdcs")):
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service discovery",
                                details=f"{target_ip} queried {name}",
                            ))
                    except Exception:
                        pass

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                flags = getattr(tcp_layer, "flags", None)
                is_syn = False
                is_ack = False
                is_rst = False
                is_fin = False
                if isinstance(flags, str):
                    flag_text = flags
                else:
                    flag_text = None
                flag_bits: Optional[int] = None
                if flag_text is None and flags is not None:
                    try:
                        flag_bits = int(flags)
                    except Exception:
                        try:
                            flag_text = str(flags)
                        except Exception:
                            flag_text = None
                if flag_text is not None:
                    is_syn = "S" in flag_text
                    is_ack = "A" in flag_text
                    is_rst = "R" in flag_text
                    is_fin = "F" in flag_text
                elif flag_bits is not None:
                    is_syn = (flag_bits & 0x02) != 0
                    is_ack = (flag_bits & 0x10) != 0
                    is_rst = (flag_bits & 0x04) != 0
                    is_fin = (flag_bits & 0x01) != 0
                is_synack = is_syn and is_ack
                is_syn_only = is_syn and not is_ack
                is_final_ack = is_ack and not is_syn and not is_rst and not is_fin
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                payload = None
                try:
                    payload = bytes(tcp_layer.payload)
                except Exception:
                    payload = None
                if (src_ip == target_ip or dst_ip == target_ip) and sport and dport:
                    if is_syn_only:
                        key = (src_ip, dst_ip, sport, dport)
                        tcp_handshakes[key].append(_new_handshake(syn_ts=ts))
                    elif is_synack:
                        key = (dst_ip, src_ip, dport, sport)
                        bucket = tcp_handshakes[key]
                        handshake = _find_handshake_for_synack(bucket)
                        if handshake is None:
                            handshake = _new_handshake()
                            bucket.append(handshake)
                        handshake["synack"] = ts
                    elif is_final_ack:
                        key = (src_ip, dst_ip, sport, dport)
                        bucket = tcp_handshakes.get(key)
                        if bucket:
                            handshake = _find_handshake_for_ack(bucket)
                            if handshake is not None:
                                handshake["ack"] = ts
                if src_ip == target_ip or dst_ip == target_ip:
                    port_key = dport if src_ip == target_ip else sport
                    if port_key:
                        counter_inc(port_counts, port_key)
                        proto = OT_PORT_PROTOCOLS.get(port_key)
                        if proto:
                            ot_protocol_counts[proto] += 1
                            direction = "outbound" if src_ip == target_ip else "inbound"
                            peer_ip = dst_ip if src_ip == target_ip else src_ip
                            if peer_ip:
                                cmd_event_added = False
                                if proto == "Modbus" and port_key == MODBUS_TCP_PORT:
                                    parsed = _parse_modbus_command(payload)
                                    if parsed:
                                        func_code, func_name, is_exc, unit_id, exc_desc = parsed
                                        label = f"Modbus {func_name}"
                                        if is_exc:
                                            label = f"Modbus exception {func_name}"
                                        key = (proto, direction, peer_ip, port_key, label)
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            detail = f"{target_ip} -> {peer_ip}:{port_key} unit {unit_id} {func_name}"
                                            if is_exc and exc_desc:
                                                detail += f" (Exception: {exc_desc})"
                                            events.append(TimelineEvent(
                                                ts=ts,
                                                category="Modbus",
                                                summary=label,
                                                details=detail,
                                            ))
                                            cmd_event_added = True
                                elif proto in {"ENIP", "CIP"} and port_key in {44818, 2222}:
                                    enip = _parse_enip_command(payload)
                                    if enip:
                                        cmd, name = enip
                                        label = name or f"ENIP cmd 0x{cmd:04x}"
                                        key = (proto, direction, peer_ip, port_key, label)
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            events.append(TimelineEvent(
                                                ts=ts,
                                                category=proto,
                                                summary=f"{proto} {label}",
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            ))
                                            cmd_event_added = True
                                elif proto == "OPC UA" and port_key == OPC_UA_PORT:
                                    msg = _parse_opcua_message(payload)
                                    if msg:
                                        label = f"OPC UA {msg}"
                                        key = (proto, direction, peer_ip, port_key, label)
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            events.append(TimelineEvent(
                                                ts=ts,
                                                category="OPC UA",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            ))
                                            cmd_event_added = True
                                elif proto == "IEC-104" and port_key == IEC104_PORT:
                                    frame = _iec104_frame_type(payload)
                                    if frame:
                                        label = f"IEC-104 {frame}"
                                        key = (proto, direction, peer_ip, port_key, label)
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            events.append(TimelineEvent(
                                                ts=ts,
                                                category="IEC-104",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            ))
                                            cmd_event_added = True
                                elif proto == "DNP3" and port_key == DNP3_PORT:
                                    if _dnp3_frame_seen(payload):
                                        label = "DNP3 frame"
                                        key = (proto, direction, peer_ip, port_key, label)
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            events.append(TimelineEvent(
                                                ts=ts,
                                                category="DNP3",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            ))
                                            cmd_event_added = True
                                elif proto == "S7" and port_key == S7_PORT:
                                    if _s7comm_seen(payload):
                                        label = "S7comm packet"
                                        key = (proto, direction, peer_ip, port_key, label)
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            events.append(TimelineEvent(
                                                ts=ts,
                                                category="S7",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            ))
                                            cmd_event_added = True

                                if not cmd_event_added:
                                    flow_key = (proto, direction, peer_ip, port_key)
                                    if flow_key not in seen_ot_flows:
                                        seen_ot_flows.add(flow_key)
                                        events.append(TimelineEvent(
                                            ts=ts,
                                            category=proto,
                                            summary=f"{proto} flow",
                                            details=f"{target_ip} -> {peer_ip}:{port_key}",
                                        ))
                if src_ip == target_ip:
                    if dport in {139, 445}:
                        hint = _netbios_session_hint(payload)
                        if hint:
                            key = (src_ip, dst_ip, dport)
                            if key not in seen_netbios_sessions:
                                seen_netbios_sessions.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="NetBIOS",
                                    summary=hint,
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                ))
                    rpc_type = _rpc_packet_type(payload)
                    if rpc_type and dport in {135, 445, 593}:
                        key = (src_ip, dst_ip, dport, rpc_type)
                        if key not in seen_rpc_events:
                            seen_rpc_events.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="RPC",
                                summary=f"RPC {rpc_type}",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                    ps_cmd = _extract_powershell_command(payload)
                    if ps_cmd:
                        key = (src_ip, dst_ip, dport, ps_cmd)
                        if key not in seen_ps_commands:
                            seen_ps_commands.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="PowerShell",
                                summary="PowerShell command",
                                details=f"{target_ip} -> {dst_ip}:{dport} {ps_cmd}",
                            ))
                    wmic_cmd = _extract_wmic_command(payload)
                    if wmic_cmd:
                        key = (src_ip, dst_ip, dport, wmic_cmd)
                        if key not in seen_wmic_commands:
                            seen_wmic_commands.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="WMIC",
                                summary="WMIC command",
                                details=f"{target_ip} -> {dst_ip}:{dport} {wmic_cmd}",
                            ))
                    payload_text = decode_payload(payload, encoding="latin-1") if payload else ""
                    if payload and (dport in WINRM_PORTS or (payload_text and WSMAN_RE.search(payload_text))):
                        winrm_cmd = _extract_winrm_command(payload)
                        if winrm_cmd:
                            key = (src_ip, dst_ip, dport, winrm_cmd)
                            if key not in seen_winrm_commands:
                                seen_winrm_commands.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="WinRM",
                                    summary="WinRM command",
                                    details=f"{target_ip} -> {dst_ip}:{dport} {winrm_cmd}",
                                ))
                    if payload and dport in TELNET_PORTS:
                        telnet_cmd = _extract_telnet_command(payload)
                        if telnet_cmd:
                            key = (src_ip, dst_ip, dport, telnet_cmd)
                            if key not in seen_telnet_commands:
                                seen_telnet_commands.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="Telnet",
                                    summary="Telnet command",
                                    details=f"{target_ip} -> {dst_ip}:{dport} {telnet_cmd}",
                                ))
                    if payload and payload.startswith(b"POST "):
                        try:
                            line = payload.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
                            host = "-"
                            for header in payload.split(b"\r\n"):
                                if header.lower().startswith(b"host:"):
                                    host = header.decode("latin-1", errors="ignore").split(":", 1)[1].strip()
                                    break
                            events.append(TimelineEvent(
                                ts=ts,
                                category="HTTP",
                                summary="HTTP POST",
                                details=f"{target_ip} -> {dst_ip}:{dport} {line} Host: {host}",
                            ))
                        except Exception:
                            events.append(TimelineEvent(
                                ts=ts,
                                category="HTTP",
                                summary="HTTP POST",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                    if dport in EMAIL_PORT_SERVICES:
                        service = EMAIL_PORT_SERVICES[dport]
                        flow_key = (dst_ip, dport, "TCP", "outbound", service)
                        if flow_key not in seen_email_flows:
                            seen_email_flows.add(flow_key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="Email",
                                summary=f"{service} connection",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                        first_line = _decode_payload_line(payload)
                        command = _extract_email_command(service, first_line)
                        if command:
                            action_key = (dst_ip, dport, "TCP", "outbound", service, command)
                            if action_key not in seen_email_actions:
                                seen_email_actions.add(action_key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="Email",
                                    summary=f"{service} command",
                                    details=f"{target_ip} -> {dst_ip}:{dport} {command}",
                                ))
                    if dport in ldap_ports:
                        key = (dst_ip, dport, "TCP", "outbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP connection",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                    if dport in domain_ports:
                        key = (dst_ip, dport, "TCP", "outbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service access",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                    if is_syn_only and dport:
                        events.append(TimelineEvent(
                            ts=ts,
                            category="Connection",
                            summary="TCP connect attempt",
                            details=f"{target_ip} -> {dst_ip}:{dport} (SYN)",
                        ))
                        scan_ports[dst_ip].add(dport)
                        if ts is not None:
                            scan_first.setdefault(dst_ip, ts)
                            scan_last[dst_ip] = ts
                    if is_synack and sport:
                        events.append(TimelineEvent(
                            ts=ts,
                            category="Connection",
                            summary="TCP SYN-ACK",
                            details=f"{target_ip} -> {dst_ip}:{sport} (SYN-ACK)",
                        ))
                elif dst_ip == target_ip:
                    if is_syn_only and dport:
                        events.append(TimelineEvent(
                            ts=ts,
                            category="Connection",
                            summary="TCP connect attempt",
                            details=f"{src_ip} -> {target_ip}:{dport} (SYN)",
                        ))
                    if is_synack and sport:
                        events.append(TimelineEvent(
                            ts=ts,
                            category="Connection",
                            summary="TCP SYN-ACK",
                            details=f"{src_ip} -> {target_ip}:{sport} (SYN-ACK)",
                        ))
                    if sport in {139, 445}:
                        hint = _netbios_session_hint(payload)
                        if hint:
                            key = (src_ip, dst_ip, sport)
                            if key not in seen_netbios_sessions:
                                seen_netbios_sessions.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="NetBIOS",
                                    summary=hint,
                                    details=f"{src_ip} -> {target_ip}:{sport}",
                                ))
                    rpc_type = _rpc_packet_type(payload)
                    if rpc_type and sport in {135, 445, 593}:
                        key = (src_ip, dst_ip, sport, rpc_type)
                        if key not in seen_rpc_events:
                            seen_rpc_events.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="RPC",
                                summary=f"RPC {rpc_type}",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
                    ps_cmd = _extract_powershell_command(payload)
                    if ps_cmd:
                        key = (src_ip, dst_ip, sport, ps_cmd)
                        if key not in seen_ps_commands:
                            seen_ps_commands.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="PowerShell",
                                summary="PowerShell command",
                                details=f"{src_ip} -> {target_ip}:{sport} {ps_cmd}",
                            ))
                    wmic_cmd = _extract_wmic_command(payload)
                    if wmic_cmd:
                        key = (src_ip, dst_ip, sport, wmic_cmd)
                        if key not in seen_wmic_commands:
                            seen_wmic_commands.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="WMIC",
                                summary="WMIC command",
                                details=f"{src_ip} -> {target_ip}:{sport} {wmic_cmd}",
                            ))
                    payload_text = decode_payload(payload, encoding="latin-1") if payload else ""
                    if payload and (sport in WINRM_PORTS or (payload_text and WSMAN_RE.search(payload_text))):
                        winrm_cmd = _extract_winrm_command(payload)
                        if winrm_cmd:
                            key = (src_ip, dst_ip, sport, winrm_cmd)
                            if key not in seen_winrm_commands:
                                seen_winrm_commands.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="WinRM",
                                    summary="WinRM command",
                                    details=f"{src_ip} -> {target_ip}:{sport} {winrm_cmd}",
                                ))
                    if payload and sport in TELNET_PORTS:
                        telnet_cmd = _extract_telnet_command(payload)
                        if telnet_cmd:
                            key = (src_ip, dst_ip, sport, telnet_cmd)
                            if key not in seen_telnet_commands:
                                seen_telnet_commands.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="Telnet",
                                    summary="Telnet command",
                                    details=f"{src_ip} -> {target_ip}:{sport} {telnet_cmd}",
                                ))
                    if sport in EMAIL_PORT_SERVICES:
                        service = EMAIL_PORT_SERVICES[sport]
                        flow_key = (src_ip, sport, "TCP", "inbound", service)
                        if flow_key not in seen_email_flows:
                            seen_email_flows.add(flow_key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="Email",
                                summary=f"{service} connection",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
                        first_line = _decode_payload_line(payload)
                        command = _extract_email_command(service, first_line)
                        if command:
                            action_key = (src_ip, sport, "TCP", "inbound", service, command)
                            if action_key not in seen_email_actions:
                                seen_email_actions.add(action_key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="Email",
                                    summary=f"{service} command",
                                    details=f"{src_ip} -> {target_ip}:{sport} {command}",
                                ))
                    if sport in ldap_ports:
                        key = (src_ip, sport, "TCP", "inbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP connection",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
                    if sport in domain_ports:
                        key = (src_ip, sport, "TCP", "inbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service access",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                payload = None
                try:
                    payload = bytes(udp_layer.payload)
                except Exception:
                    payload = None
                if src_ip == target_ip or dst_ip == target_ip:
                    port_key = dport if src_ip == target_ip else sport
                    if port_key:
                        counter_inc(port_counts, port_key)
                        proto = OT_PORT_PROTOCOLS.get(port_key)
                        if proto:
                            ot_protocol_counts[proto] += 1
                            direction = "outbound" if src_ip == target_ip else "inbound"
                            peer_ip = dst_ip if src_ip == target_ip else src_ip
                            if peer_ip:
                                cmd_event_added = False
                                if proto == "DNP3" and port_key == DNP3_PORT:
                                    if _dnp3_frame_seen(payload):
                                        label = "DNP3 frame"
                                        key = (proto, direction, peer_ip, port_key, label)
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            events.append(TimelineEvent(
                                                ts=ts,
                                                category="DNP3",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            ))
                                            cmd_event_added = True
                                if not cmd_event_added:
                                    flow_key = (proto, direction, peer_ip, port_key)
                                    if flow_key not in seen_ot_flows:
                                        seen_ot_flows.add(flow_key)
                                        events.append(TimelineEvent(
                                            ts=ts,
                                            category=proto,
                                            summary=f"{proto} flow",
                                            details=f"{target_ip} -> {peer_ip}:{port_key}",
                                        ))
                if src_ip == target_ip:
                    if dport:
                        key = (dst_ip, dport)
                        if key not in seen_udp_flows:
                            seen_udp_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="Connection",
                                summary="UDP flow",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            ))
                        rpc_type = _rpc_packet_type(payload)
                        if rpc_type and dport in {135, 445, 593}:
                            key = (src_ip, dst_ip, dport, rpc_type)
                            if key not in seen_rpc_events:
                                seen_rpc_events.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="RPC",
                                    summary=f"RPC {rpc_type}",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                ))
                        if dport in {137, 138, 139}:
                            action, name = _nbns_info(pkt)
                            key = ("outbound", action, name)
                            if key not in seen_nbns_events:
                                seen_nbns_events.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="NetBIOS",
                                    summary=action,
                                    details=f"{target_ip} -> {dst_ip}:{dport} {name}",
                                ))
                        if dport in {161, 162}:
                            snmp_type = _snmp_pdu_type(payload)
                            if snmp_type:
                                key = (src_ip, dst_ip, dport, snmp_type)
                                if key not in seen_snmp_events:
                                    seen_snmp_events.add(key)
                                    events.append(TimelineEvent(
                                        ts=ts,
                                        category="SNMP",
                                        summary=f"SNMP {snmp_type}",
                                        details=f"{target_ip} -> {dst_ip}:{dport}",
                                    ))
                        if dport in ldap_ports:
                            key = (dst_ip, dport, "UDP", "outbound")
                            if key not in seen_ldap_flows:
                                seen_ldap_flows.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="LDAP",
                                    summary="LDAP activity",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                ))
                        if dport in domain_ports:
                            key = (dst_ip, dport, "UDP", "outbound")
                            if key not in seen_domain_flows:
                                seen_domain_flows.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="MS Domain",
                                    summary="Domain service activity",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                ))
                elif dst_ip == target_ip:
                    rpc_type = _rpc_packet_type(payload)
                    if rpc_type and sport in {135, 445, 593}:
                        key = (src_ip, dst_ip, sport, rpc_type)
                        if key not in seen_rpc_events:
                            seen_rpc_events.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="RPC",
                                summary=f"RPC {rpc_type}",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
                    if sport in {137, 138, 139}:
                        action, name = _nbns_info(pkt)
                        key = ("inbound", action, name)
                        if key not in seen_nbns_events:
                            seen_nbns_events.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="NetBIOS",
                                summary=action,
                                details=f"{src_ip} -> {target_ip}:{sport} {name}",
                            ))
                    if sport in {161, 162}:
                        snmp_type = _snmp_pdu_type(payload)
                        if snmp_type:
                            key = (src_ip, dst_ip, sport, snmp_type)
                            if key not in seen_snmp_events:
                                seen_snmp_events.add(key)
                                events.append(TimelineEvent(
                                    ts=ts,
                                    category="SNMP",
                                    summary=f"SNMP {snmp_type}",
                                    details=f"{src_ip} -> {target_ip}:{sport}",
                                ))
                    if sport in ldap_ports:
                        key = (src_ip, sport, "UDP", "inbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP activity",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
                    if sport in domain_ports:
                        key = (src_ip, sport, "UDP", "inbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            events.append(TimelineEvent(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service activity",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            ))
    finally:
        status.finish()
        reader.close()

    for art in artifacts_for_ip:
        ts = index_ts.get(art.packet_index)
        details = f"{art.protocol} {art.filename} ({art.file_type}) {art.src_ip} -> {art.dst_ip}"
        category = "File Transfer"
        if art.protocol.upper().startswith("SMB"):
            category = "SMB"
        events.append(TimelineEvent(
            ts=ts,
            category=category,
            summary="File artifact",
            details=details,
        ))

    for dst_ip, ports in scan_ports.items():
        if len(ports) >= 100:
            first = scan_first.get(dst_ip)
            last = scan_last.get(dst_ip, first)
            duration = "-"
            if first is not None and last is not None:
                duration = f"{max(0.0, last - first):.1f}s"
            events.append(TimelineEvent(
                ts=last,
                category="Recon",
                summary="Potential port scan",
                details=f"{target_ip} -> {dst_ip} touched {len(ports)} ports over {duration}",
            ))

    for (client_ip, server_ip, client_port, server_port), handshakes in tcp_handshakes.items():
        for handshake in handshakes:
            if handshake["syn"] is None or handshake["synack"] is None:
                continue
            if handshake["ack"] is not None:
                continue
            detail = (
                f"{client_ip}:{client_port} -> {server_ip}:{server_port} "
                "(SYN/SYN-ACK seen, final ACK missing)"
            )
            events.append(TimelineEvent(
                ts=handshake["synack"],
                category="Connection",
                summary="TCP handshake incomplete",
                details=detail,
            ))

    if "DNP3" in ot_protocol_counts:
        dnp3_summary = analyze_dnp3(path, show_status=False)
        errors.extend(dnp3_summary.errors)
        seen_msgs: set[tuple[str, str, str, int, int]] = set()
        for msg in dnp3_summary.messages:
            if msg.src_ip != target_ip and msg.dst_ip != target_ip:
                continue
            key = (msg.src_ip, msg.dst_ip, msg.func_name, msg.src_addr, msg.dst_addr)
            if key in seen_msgs:
                continue
            seen_msgs.add(key)
            events.append(TimelineEvent(
                ts=msg.ts,
                category="DNP3",
                summary=f"DNP3 {msg.func_name}",
                details=f"{msg.src_ip} -> {msg.dst_ip} addr {msg.src_addr}->{msg.dst_addr}",
            ))
            if len(seen_msgs) >= 200:
                break
        for anomaly in dnp3_summary.anomalies:
            if anomaly.src != target_ip and anomaly.dst != target_ip:
                continue
            events.append(TimelineEvent(
                ts=anomaly.ts,
                category="DNP3",
                summary=anomaly.title,
                details=f"{anomaly.description} ({anomaly.src} -> {anomaly.dst})",
            ))

    if "IEC-104" in ot_protocol_counts:
        iec_summary = analyze_iec104(path, show_status=False)
        errors.extend(iec_summary.errors)
        for anomaly in iec_summary.anomalies:
            if anomaly.src != target_ip and anomaly.dst != target_ip:
                continue
            events.append(TimelineEvent(
                ts=anomaly.ts,
                category="IEC-104",
                summary=anomaly.title,
                details=f"{anomaly.description} ({anomaly.src} -> {anomaly.dst})",
            ))
        for artifact in iec_summary.artifacts:
            if artifact.src != target_ip and artifact.dst != target_ip:
                continue
            events.append(TimelineEvent(
                ts=artifact.ts,
                category="IEC-104",
                summary=f"IEC-104 artifact ({artifact.kind})",
                details=f"{artifact.detail} ({artifact.src} -> {artifact.dst})",
            ))
        if iec_summary.command_events:
            seen_cmds: set[tuple[str, str, str, int]] = set()
            for cmd_event in iec_summary.command_events:
                if cmd_event.src != target_ip and cmd_event.dst != target_ip:
                    continue
                key = (cmd_event.src, cmd_event.dst, cmd_event.command, int(cmd_event.ts or 0))
                if key in seen_cmds:
                    continue
                seen_cmds.add(key)
                events.append(TimelineEvent(
                    ts=cmd_event.ts,
                    category="IEC-104",
                    summary=f"IEC-104 {cmd_event.command}",
                    details=f"{cmd_event.src} -> {cmd_event.dst}",
                ))

    if "S7" in ot_protocol_counts:
        s7_summary = analyze_s7(path, show_status=False)
        errors.extend(s7_summary.errors)
        for anomaly in s7_summary.anomalies:
            if anomaly.src != target_ip and anomaly.dst != target_ip:
                continue
            events.append(TimelineEvent(
                ts=anomaly.ts,
                category="S7",
                summary=anomaly.title,
                details=f"{anomaly.description} ({anomaly.src} -> {anomaly.dst})",
            ))
        for artifact in s7_summary.artifacts:
            if artifact.src != target_ip and artifact.dst != target_ip:
                continue
            events.append(TimelineEvent(
                ts=artifact.ts,
                category="S7",
                summary=f"S7 artifact ({artifact.kind})",
                details=f"{artifact.detail} ({artifact.src} -> {artifact.dst})",
            ))
        if s7_summary.command_events:
            seen_cmds: set[tuple[str, str, str, int]] = set()
            for cmd_event in s7_summary.command_events:
                if cmd_event.src != target_ip and cmd_event.dst != target_ip:
                    continue
                key = (cmd_event.src, cmd_event.dst, cmd_event.command, int(cmd_event.ts or 0))
                if key in seen_cmds:
                    continue
                seen_cmds.add(key)
                events.append(TimelineEvent(
                    ts=cmd_event.ts,
                    category="S7",
                    summary=f"S7 {cmd_event.command}",
                    details=f"{cmd_event.src} -> {cmd_event.dst}",
                ))

    if categories is not None:
        events = [event for event in events if event.category in categories]
        if ot_protocol_counts:
            ot_protocol_counts = Counter({
                name: count for name, count in ot_protocol_counts.items()
                if name in categories
            })

    events.sort(key=lambda item: (item.ts is None, item.ts))
    category_counts = Counter(event.category for event in events)
    duration = None
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)
    ot_activity_bins, ot_bin_count = _compute_ot_activity_bins(events, first_seen, last_seen, bins=max(4, timeline_bins))
    non_ot_bins, non_ot_bin_count = _compute_non_ot_activity_bins(events, first_seen, last_seen, bins=max(4, timeline_bins))
    ot_risk_score, ot_risk_findings = _compute_ot_risk_posture(events, target_ip)
    ot_storyline = [] if timeline_storyline_off else _compute_ot_storyline(
        events,
        target_ip,
        dict(ot_protocol_counts),
        ot_risk_score,
        ot_risk_findings,
    )

    return TimelineSummary(
        path=path,
        target_ip=target_ip,
        total_packets=total_packets,
        events=events,
        errors=errors + file_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration=duration,
        category_counts=dict(category_counts),
        peer_counts=dict(peer_counts),
        port_counts=dict(port_counts),
        ot_protocol_counts=dict(ot_protocol_counts),
        ot_activity_bins=ot_activity_bins,
        ot_activity_bin_count=ot_bin_count,
        non_ot_activity_bins=non_ot_bins,
        non_ot_activity_bin_count=non_ot_bin_count,
        ot_risk_score=ot_risk_score,
        ot_risk_findings=ot_risk_findings,
        ot_storyline=ot_storyline,
    )
