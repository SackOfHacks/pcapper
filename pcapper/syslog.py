from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import ipaddress
import re

from .pcap_cache import get_reader
from .utils import safe_float

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


SYSLOG_UDP_PORTS = {514, 5514}
SYSLOG_TCP_PORTS = {514, 601, 6514}
SYSLOG_PORTS = SYSLOG_UDP_PORTS | SYSLOG_TCP_PORTS

SYSLOG_PRI_RE = re.compile(r"^<(\d{1,3})>")
SYSLOG_5424_RE = re.compile(
    r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$"
)
SYSLOG_3164_RE = re.compile(
    r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s*(.*)$"
)

FACILITY_NAMES = {
    0: "kernel",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "clock",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "audit",
    14: "alert",
    15: "clock2",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

SEVERITY_NAMES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug",
}

SUSPICIOUS_PATTERNS = [
    (re.compile(r"failed\s+password", re.IGNORECASE), "Authentication failure"),
    (re.compile(r"invalid\s+user", re.IGNORECASE), "Invalid user attempts"),
    (re.compile(r"authentication\s+failure", re.IGNORECASE), "Authentication failure"),
    (re.compile(r"sudo:\s+authentication\s+failure", re.IGNORECASE), "Privileged auth failure"),
    (re.compile(r"session\s+opened|session\s+closed", re.IGNORECASE), "Auth session activity"),
    (re.compile(r"accepted\s+password", re.IGNORECASE), "Password login accepted"),
    (re.compile(r"root\s+login|root\s+user", re.IGNORECASE), "Root login activity"),
    (re.compile(r"useradd|usermod|passwd\s+", re.IGNORECASE), "Account management"),
    (re.compile(r"ssh-\d", re.IGNORECASE), "SSH version exposure"),
    (re.compile(r"nmap|masscan|sqlmap", re.IGNORECASE), "Recon tooling"),
    (re.compile(r"wget\s+http|curl\s+http", re.IGNORECASE), "Download tooling"),
    (re.compile(r"powershell|cmd\.exe|/bin/(sh|bash)", re.IGNORECASE), "Command execution"),
    (re.compile(r"ransom|malware|c2|beacon", re.IGNORECASE), "Malware indicator"),
]

FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SyslogConversation:
    client_ip: str
    server_ip: str
    protocol: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class SyslogArtifact:
    kind: str
    detail: str
    src: str
    dst: str


@dataclass(frozen=True)
class SyslogAnomaly:
    title: str
    details: str
    severity: str


@dataclass(frozen=True)
class SyslogSummary:
    path: Path
    total_packets: int
    syslog_packets: int
    total_bytes: int
    total_messages: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    protocol_counts: Counter[str]
    hostname_counts: Counter[str]
    appname_counts: Counter[str]
    procid_counts: Counter[str]
    msgid_counts: Counter[str]
    facility_counts: Counter[str]
    severity_counts: Counter[str]
    version_counts: Counter[str]
    request_counts: Counter[str]
    response_codes: Counter[str]
    plaintext_strings: Counter[str]
    file_artifacts: Counter[str]
    conversations: list[SyslogConversation]
    detections: list[dict[str, object]]
    anomalies: list[SyslogAnomaly]
    artifacts: list[SyslogArtifact]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "syslog_packets": self.syslog_packets,
            "total_bytes": self.total_bytes,
            "total_messages": self.total_messages,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "protocol_counts": dict(self.protocol_counts),
            "hostname_counts": dict(self.hostname_counts),
            "appname_counts": dict(self.appname_counts),
            "procid_counts": dict(self.procid_counts),
            "msgid_counts": dict(self.msgid_counts),
            "facility_counts": dict(self.facility_counts),
            "severity_counts": dict(self.severity_counts),
            "version_counts": dict(self.version_counts),
            "request_counts": dict(self.request_counts),
            "response_codes": dict(self.response_codes),
            "plaintext_strings": dict(self.plaintext_strings),
            "file_artifacts": dict(self.file_artifacts),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "protocol": conv.protocol,
                    "server_port": conv.server_port,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                }
                for conv in self.conversations
            ],
            "detections": list(self.detections),
            "anomalies": [
                {
                    "title": item.title,
                    "details": item.details,
                    "severity": item.severity,
                }
                for item in self.anomalies
            ],
            "artifacts": [
                {
                    "kind": item.kind,
                    "detail": item.detail,
                    "src": item.src,
                    "dst": item.dst,
                }
                for item in self.artifacts
            ],
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _extract_ascii_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> list[str]:
    results: list[str] = []
    if not data:
        return results
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                value = current.decode("latin-1", errors="ignore")
                results.append(value[:max_len])
            current = bytearray()
    if len(current) >= min_len:
        value = current.decode("latin-1", errors="ignore")
        results.append(value[:max_len])
    return results


def _parse_syslog(text: str) -> dict[str, Optional[str]]:
    match_5424 = SYSLOG_5424_RE.match(text)
    if match_5424:
        pri, version, timestamp, hostname, appname, procid, msgid, message = match_5424.groups()
        return {
            "pri": pri,
            "version": version,
            "timestamp": timestamp,
            "hostname": hostname,
            "appname": appname,
            "procid": procid,
            "msgid": msgid,
            "message": message or "",
        }

    match_3164 = SYSLOG_3164_RE.match(text)
    if match_3164:
        pri, timestamp, hostname, message = match_3164.groups()
        return {
            "pri": pri,
            "version": None,
            "timestamp": timestamp,
            "hostname": hostname,
            "appname": None,
            "procid": None,
            "msgid": None,
            "message": message or "",
        }

    match_pri = SYSLOG_PRI_RE.match(text)
    if match_pri:
        return {
            "pri": match_pri.group(1),
            "version": None,
            "timestamp": None,
            "hostname": None,
            "appname": None,
            "procid": None,
            "msgid": None,
            "message": text,
        }

    return {
        "pri": None,
        "version": None,
        "timestamp": None,
        "hostname": None,
        "appname": None,
        "procid": None,
        "msgid": None,
        "message": text,
    }


def analyze_syslog(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> SyslogSummary:
    errors: list[str] = []
    if TCP is None and UDP is None:
        errors.append("Scapy TCP/UDP layers unavailable; install scapy for syslog analysis.")
        return SyslogSummary(
            path=path,
            total_packets=0,
            syslog_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            hostname_counts=Counter(),
            appname_counts=Counter(),
            procid_counts=Counter(),
            msgid_counts=Counter(),
            facility_counts=Counter(),
            severity_counts=Counter(),
            version_counts=Counter(),
            request_counts=Counter(),
            response_codes=Counter(),
            plaintext_strings=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    syslog_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()

    hostname_counts: Counter[str] = Counter()
    appname_counts: Counter[str] = Counter()
    procid_counts: Counter[str] = Counter()
    msgid_counts: Counter[str] = Counter()
    facility_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()

    request_counts: Counter[str] = Counter()
    response_codes: Counter[str] = Counter()

    plaintext_strings: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    artifacts: list[SyslogArtifact] = []
    anomalies: list[SyslogAnomaly] = []
    detections: list[dict[str, object]] = []

    conversations: dict[tuple[str, str, str, int], SyslogConversation] = {}
    suspicious_counter: Counter[str] = Counter()
    message_cache: set[str] = set()

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len

            ip_layer = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
            if ip_layer is None:
                continue

            src_ip = str(getattr(ip_layer, "src", ""))
            dst_ip = str(getattr(ip_layer, "dst", ""))
            if not src_ip or not dst_ip:
                continue

            proto = None
            sport = 0
            dport = 0
            payload = b""

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                proto = "TCP"
                try:
                    payload = bytes(tcp.payload)
                except Exception:
                    payload = b""
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                proto = "UDP"
                try:
                    payload = bytes(udp.payload)
                except Exception:
                    payload = b""
            else:
                continue

            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw])  # type: ignore[index]
                except Exception:
                    pass

            if not payload:
                continue

            is_syslog = sport in SYSLOG_PORTS or dport in SYSLOG_PORTS
            if not is_syslog and b"<" not in payload[:4]:
                continue

            text = payload.decode("latin-1", errors="ignore").strip()
            if not text:
                continue

            syslog_packets += 1
            total_messages += 1

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if dport in SYSLOG_PORTS:
                client_ip = src_ip
                server_ip = dst_ip
                server_port = dport
            elif sport in SYSLOG_PORTS:
                client_ip = dst_ip
                server_ip = src_ip
                server_port = sport
            else:
                client_ip = src_ip
                server_ip = dst_ip
                server_port = dport

            client_counts[client_ip] += 1
            server_counts[server_ip] += 1
            server_ports[server_port] += 1
            protocol_counts[proto or "-"] += 1

            conv_key = (client_ip, server_ip, proto or "-", server_port)
            existing = conversations.get(conv_key)
            if existing is None:
                conversations[conv_key] = SyslogConversation(
                    client_ip=client_ip,
                    server_ip=server_ip,
                    protocol=proto or "-",
                    server_port=server_port,
                    packets=1,
                    bytes=pkt_len,
                    first_seen=ts,
                    last_seen=ts,
                )
            else:
                conversations[conv_key] = SyslogConversation(
                    client_ip=existing.client_ip,
                    server_ip=existing.server_ip,
                    protocol=existing.protocol,
                    server_port=existing.server_port,
                    packets=existing.packets + 1,
                    bytes=existing.bytes + pkt_len,
                    first_seen=existing.first_seen if existing.first_seen is not None else ts,
                    last_seen=ts or existing.last_seen,
                )

            parsed = _parse_syslog(text)
            pri_text = parsed.get("pri")
            if pri_text and pri_text.isdigit():
                pri_val = int(pri_text)
                facility = FACILITY_NAMES.get(pri_val // 8, f"facility_{pri_val // 8}")
                severity = SEVERITY_NAMES.get(pri_val % 8, f"severity_{pri_val % 8}")
                facility_counts[facility] += 1
                severity_counts[severity] += 1
                response_codes[severity] += 1

            version = parsed.get("version")
            if version:
                version_counts[str(version)] += 1

            hostname = parsed.get("hostname")
            if hostname:
                hostname_counts[hostname] += 1

            appname = parsed.get("appname")
            if appname:
                appname_counts[appname] += 1
                request_counts[appname] += 1

            procid = parsed.get("procid")
            if procid:
                procid_counts[procid] += 1

            msgid = parsed.get("msgid")
            if msgid:
                msgid_counts[msgid] += 1

            message = parsed.get("message") or text
            if message:
                if len(plaintext_strings) < 2000 or message in plaintext_strings:
                    plaintext_strings[message] += 1
                for match in FILE_NAME_RE.findall(message):
                    file_artifacts[match] += 1
                    if len(artifacts) < 200:
                        artifacts.append(SyslogArtifact("file", match, client_ip, server_ip))

                for pattern, summary in SUSPICIOUS_PATTERNS:
                    if pattern.search(message):
                        suspicious_counter[summary] += 1

            for value in _extract_ascii_strings(payload):
                if len(plaintext_strings) < 2000 or value in plaintext_strings:
                    plaintext_strings[value] += 1

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows = sorted(
        conversations.values(), key=lambda item: (item.packets, item.bytes), reverse=True
    )

    if suspicious_counter:
        for summary, count in suspicious_counter.most_common(10):
            detections.append({
                "severity": "warning",
                "summary": summary,
                "details": f"Observed {count} occurrences in syslog messages.",
            })

    for server_ip, count in server_counts.most_common(10):
        if _is_public_ip(server_ip) and count > 10:
            anomalies.append(SyslogAnomaly(
                title="Syslog to public endpoint",
                details=f"{server_ip} received {count} syslog messages.",
                severity="MEDIUM",
            ))

    for client_ip, count in client_counts.most_common(5):
        if count >= 5000:
            anomalies.append(SyslogAnomaly(
                title="High-volume syslog source",
                details=f"{client_ip} sent {count} messages.",
                severity="LOW",
            ))

    if severity_counts.get("Critical") or severity_counts.get("Alert") or severity_counts.get("Emergency"):
        anomalies.append(SyslogAnomaly(
            title="High-severity syslog events",
            details="Critical/Alert/Emergency severity events observed.",
            severity="HIGH",
        ))

    for value in list(file_artifacts.keys())[:30]:
        if len(artifacts) >= 200:
            break
        if value not in message_cache:
            message_cache.add(value)
            artifacts.append(SyslogArtifact("file", value, "-", "-"))

    return SyslogSummary(
        path=path,
        total_packets=total_packets,
        syslog_packets=syslog_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        hostname_counts=hostname_counts,
        appname_counts=appname_counts,
        procid_counts=procid_counts,
        msgid_counts=msgid_counts,
        facility_counts=facility_counts,
        severity_counts=severity_counts,
        version_counts=version_counts,
        request_counts=request_counts,
        response_codes=response_codes,
        plaintext_strings=plaintext_strings,
        file_artifacts=file_artifacts,
        conversations=conversation_rows,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
