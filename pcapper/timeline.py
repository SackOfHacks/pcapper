from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
import re

from .pcap_cache import get_reader
from .utils import safe_float
from .files import analyze_files
from .powershell import PS_COMMAND_RE
from .wmic import WMIC_COMMAND_RE
from .winrm import WINRM_PORTS, WSMAN_RE
from .telnet import TELNET_PORTS

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


def merge_timeline_summaries(summaries: Iterable[TimelineSummary]) -> TimelineSummary:
    summary_list = list(summaries)
    if not summary_list:
        return TimelineSummary(
            path=Path("ALL_PCAPS_0"),
            target_ip="-",
            total_packets=0,
            events=[],
            errors=[],
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

    return TimelineSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        target_ip=target_ip,
        total_packets=total_packets,
        events=merged_events,
        errors=errors,
    )


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


def _decode_payload_line(payload: bytes | None) -> str:
    if not payload:
        return ""
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return ""
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
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
    if not text:
        return None
    match = PS_COMMAND_RE.search(text[:2000])
    if not match:
        return None
    return match.group(0).strip()[:200]


def _extract_wmic_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
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
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
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
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
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


def analyze_timeline(path: Path, target_ip: str, show_status: bool = True) -> TimelineSummary:
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
                if isinstance(flags, str):
                    is_syn = "S" in flags and "A" not in flags
                elif isinstance(flags, int):
                    is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0
                if src_ip == target_ip:
                    dport = int(getattr(tcp_layer, "dport", 0) or 0)
                    payload = None
                    try:
                        payload = bytes(tcp_layer.payload)
                    except Exception:
                        payload = None
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
                    if payload and (dport in WINRM_PORTS or WSMAN_RE.search(payload.decode("latin-1", errors="ignore"))):
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
                    if is_syn and dport:
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
                elif dst_ip == target_ip:
                    sport = int(getattr(tcp_layer, "sport", 0) or 0)
                    payload = None
                    try:
                        payload = bytes(tcp_layer.payload)
                    except Exception:
                        payload = None
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
                    if payload and (sport in WINRM_PORTS or WSMAN_RE.search(payload.decode("latin-1", errors="ignore"))):
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
                if src_ip == target_ip:
                    dport = int(getattr(udp_layer, "dport", 0) or 0)
                    payload = None
                    try:
                        payload = bytes(udp_layer.payload)
                    except Exception:
                        payload = None
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
                    sport = int(getattr(udp_layer, "sport", 0) or 0)
                    payload = None
                    try:
                        payload = bytes(udp_layer.payload)
                    except Exception:
                        payload = None
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

    events.sort(key=lambda item: (item.ts is None, item.ts))

    return TimelineSummary(
        path=path,
        target_ip=target_ip,
        total_packets=total_packets,
        events=events,
        errors=errors + file_summary.errors,
    )
