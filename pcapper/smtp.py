from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterable
import base64
import re

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


SMTP_PORTS = {25, 465, 587, 2525}

SMTP_COMMANDS = (
    "HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "RSET", "NOOP", "QUIT",
    "VRFY", "EXPN", "STARTTLS", "AUTH", "HELP", "BDAT",
)

EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
DOMAIN_RE = re.compile(r"\b([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")
HOST_RE = re.compile(r"^(?:HELO|EHLO)\s+(\S+)", re.IGNORECASE)
AUTH_RE = re.compile(r"^AUTH\s+([A-Za-z0-9_-]+)\s*(.*)$", re.IGNORECASE)
RESPONSE_RE = re.compile(r"^(\d{3})(?:\s|$)")
FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)",
    re.IGNORECASE,
)
ATTACHMENT_RE = re.compile(r'filename=\"?([^\";]+)\"?', re.IGNORECASE)
NAME_RE = re.compile(r'name=\"?([^\";]+)\"?', re.IGNORECASE)

SUSPICIOUS_PATTERNS = [
    (re.compile(r"powershell|cmd\.exe|wmic|winrs", re.IGNORECASE), "Command execution tooling"),
    (re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE), "Malware tooling"),
    (re.compile(r"rundll32|regsvr32|schtasks|at\s+", re.IGNORECASE), "Execution/persistence tooling"),
    (re.compile(r"nmap|masscan|sqlmap", re.IGNORECASE), "Recon tooling"),
]


@dataclass(frozen=True)
class SmtpConversation:
    client_ip: str
    server_ip: str
    protocol: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class SmtpArtifact:
    kind: str
    detail: str
    src: str
    dst: str


@dataclass(frozen=True)
class SmtpSummary:
    path: Path
    total_packets: int
    smtp_packets: int
    total_bytes: int
    total_messages: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    protocol_counts: Counter[str]
    hostname_counts: Counter[str]
    domain_counts: Counter[str]
    email_counts: Counter[str]
    command_counts: Counter[str]
    response_counts: Counter[str]
    auth_methods: Counter[str]
    auth_failures: Counter[str]
    auth_successes: Counter[str]
    plaintext_strings: Counter[str]
    file_artifacts: Counter[str]
    conversations: list[SmtpConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[SmtpArtifact]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "smtp_packets": self.smtp_packets,
            "total_bytes": self.total_bytes,
            "total_messages": self.total_messages,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "protocol_counts": dict(self.protocol_counts),
            "hostname_counts": dict(self.hostname_counts),
            "domain_counts": dict(self.domain_counts),
            "email_counts": dict(self.email_counts),
            "command_counts": dict(self.command_counts),
            "response_counts": dict(self.response_counts),
            "auth_methods": dict(self.auth_methods),
            "auth_failures": dict(self.auth_failures),
            "auth_successes": dict(self.auth_successes),
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
            "anomalies": list(self.anomalies),
            "artifacts": [
                {"kind": item.kind, "detail": item.detail, "src": item.src, "dst": item.dst}
                for item in self.artifacts
            ],
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def _readable_text(payload: bytes) -> str:
    try:
        return payload.decode("latin-1", errors="ignore")
    except Exception:
        return ""


def _beacon_score(times: list[float]) -> Optional[dict[str, float]]:
    if len(times) < 5:
        return None
    times_sorted = sorted(times)
    deltas = [b - a for a, b in zip(times_sorted, times_sorted[1:]) if b > a]
    if len(deltas) < 4:
        return None
    avg = sum(deltas) / len(deltas)
    if avg <= 0:
        return None
    variance = sum((d - avg) ** 2 for d in deltas) / len(deltas)
    stddev = variance ** 0.5
    if avg < 1 or avg > 3600:
        return None
    if stddev / avg > 0.15:
        return None
    return {"avg": avg, "stddev": stddev}


def analyze_smtp(path: Path, show_status: bool = True, packets: list[object] | None = None, meta: object | None = None) -> SmtpSummary:
    errors: list[str] = []
    if TCP is None:
        errors.append("Scapy TCP layers unavailable; install scapy for SMTP analysis.")
        return SmtpSummary(
            path=path,
            total_packets=0,
            smtp_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            hostname_counts=Counter(),
            domain_counts=Counter(),
            email_counts=Counter(),
            command_counts=Counter(),
            response_counts=Counter(),
            auth_methods=Counter(),
            auth_failures=Counter(),
            auth_successes=Counter(),
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
    smtp_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    hostname_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    email_counts: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    auth_methods: Counter[str] = Counter()
    auth_failures: Counter[str] = Counter()
    auth_successes: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    artifacts: list[SmtpArtifact] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    dst_by_src: dict[str, set[str]] = defaultdict(set)
    auth_fail_by_src: Counter[str] = Counter()
    auth_succ_by_src: Counter[str] = Counter()
    data_bytes_by_flow: Counter[tuple[str, str]] = Counter()
    request_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    stream_buffers: dict[tuple[str, str, int, int], dict[str, object]] = {}

    def _stream_state(src: str, dst: str, sport: int, dport: int) -> dict[str, object]:
        key = (src, dst, sport, dport)
        state = stream_buffers.get(key)
        if state is None:
            state = {"buf": "", "in_data": False, "data_lines": []}
            stream_buffers[key] = state
        return state

    def _process_smtp_lines(src: str, dst: str, dport: int, lines: list[str], state: dict[str, object]) -> None:
        nonlocal total_messages
        in_data = bool(state.get("in_data"))
        data_lines: list[str] = list(state.get("data_lines") or [])
        for line in lines:
            if not line:
                continue
            total_messages += 1
            upper = line.upper()
            if in_data:
                if line == ".":
                    in_data = False
                    state["in_data"] = False
                    state["data_lines"] = []
                    mime_text = "\n".join(data_lines)
                    for match in ATTACHMENT_RE.findall(mime_text):
                        file_artifacts[match] += 1
                        artifacts.append(SmtpArtifact(kind="attachment", detail=match, src=src, dst=dst))
                    for match in NAME_RE.findall(mime_text):
                        file_artifacts[match] += 1
                    data_lines = []
                    continue
                data_lines.append(line)
                continue
            for cmd in SMTP_COMMANDS:
                if upper.startswith(cmd):
                    command_counts[cmd] += 1
                    if cmd in {"HELO", "EHLO"}:
                        match = HOST_RE.search(line)
                        if match:
                            hostname_counts[match.group(1)] += 1
                    if cmd in {"MAIL FROM", "RCPT TO"}:
                        for email in EMAIL_RE.findall(line):
                            email_counts[email] += 1
                            domain = email.split("@")[-1]
                            domain_counts[domain] += 1
                    if cmd == "AUTH":
                        match = AUTH_RE.search(line)
                        if match:
                            method = match.group(1).upper()
                            auth_methods[method] += 1
                            if match.group(2):
                                try:
                                    decoded = base64.b64decode(match.group(2).encode(), validate=False)
                                    artifacts.append(SmtpArtifact(
                                        kind="auth",
                                        detail=decoded.decode("utf-8", errors="ignore"),
                                        src=src,
                                        dst=dst,
                                    ))
                                except Exception:
                                    pass
                    if cmd == "DATA":
                        in_data = True
                        state["in_data"] = True
                        state["data_lines"] = []
                    break
            for email in EMAIL_RE.findall(line):
                email_counts[email] += 1
                domain = email.split("@")[-1]
                domain_counts[domain] += 1
            for dom in DOMAIN_RE.findall(line):
                domain_counts[dom] += 1
            for pattern, reason in SUSPICIOUS_PATTERNS:
                if pattern.search(line):
                    detections.append({
                        "severity": "warning",
                        "summary": f"Suspicious SMTP content: {reason}",
                        "details": f"{src}->{dst} {line[:120]}",
                        "source": "SMTP",
                    })
            for match in FILE_NAME_RE.findall(line):
                file_artifacts[match] += 1
        state["in_data"] = in_data
        state["data_lines"] = data_lines

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

            if not src_ip or not dst_ip:
                continue

            if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue
            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp_layer, "sport", 0) or 0)
            dport = int(getattr(tcp_layer, "dport", 0) or 0)
            if sport not in SMTP_PORTS and dport not in SMTP_PORTS:
                continue

            smtp_packets += 1
            protocol_counts["TCP"] += 1
            server_port = dport if dport in SMTP_PORTS else sport
            server_ports[server_port] += 1

            payload = None
            try:
                payload = bytes(tcp_layer.payload)
            except Exception:
                payload = None

            conv_key = (src_ip, dst_ip, "TCP", int(server_port))
            conv = conv_map.get(conv_key)
            if conv is None:
                conv = {"packets": 0, "bytes": 0, "first_seen": ts, "last_seen": ts}
                conv_map[conv_key] = conv
            conv["packets"] = int(conv["packets"]) + 1
            conv["bytes"] = int(conv["bytes"]) + pkt_len
            if ts is not None:
                if conv["first_seen"] is None or ts < conv["first_seen"]:
                    conv["first_seen"] = ts
                if conv["last_seen"] is None or ts > conv["last_seen"]:
                    conv["last_seen"] = ts

            if not payload:
                continue

            text = _readable_text(payload)
            if not text:
                continue

            state = _stream_state(src_ip, dst_ip, sport, dport)
            state["buf"] = str(state.get("buf", "")) + text
            buf = state["buf"]
            if "\n" in buf:
                raw_lines = buf.splitlines()
                if not (buf.endswith("\n") or buf.endswith("\r\n")):
                    state["buf"] = raw_lines[-1]
                    raw_lines = raw_lines[:-1]
                else:
                    state["buf"] = ""
                lines = [line.strip() for line in raw_lines if line.strip()]
            else:
                continue

            if dport in SMTP_PORTS:
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1
                dst_by_src[src_ip].add(dst_ip)
                if ts is not None:
                    request_times[(src_ip, dst_ip)].append(ts)
                _process_smtp_lines(src_ip, dst_ip, dport, lines[:200], state)
            else:
                client_counts[dst_ip] += 1
                server_counts[src_ip] += 1
                for line in lines[:20]:
                    match = RESPONSE_RE.match(line)
                    if match:
                        code = match.group(1)
                        response_counts[code] += 1
                        if code in {"535", "534", "530"}:
                            auth_failures[src_ip] += 1
                            auth_fail_by_src[dst_ip] += 1
                        if code in {"235", "250"}:
                            auth_successes[src_ip] += 1
                            auth_succ_by_src[dst_ip] += 1

            if dport in SMTP_PORTS:
                data_bytes_by_flow[(src_ip, dst_ip)] += pkt_len
            else:
                data_bytes_by_flow[(dst_ip, src_ip)] += pkt_len

            for line in lines[:50]:
                if len(plaintext_strings) < 2000 or line in plaintext_strings:
                    plaintext_strings[line] += 1
                for match in EMAIL_RE.findall(line):
                    email_counts[match] += 1
                for match in DOMAIN_RE.findall(line):
                    domain_counts[match] += 1
                for match in FILE_NAME_RE.findall(line):
                    file_artifacts[match] += 1

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    for src, dsts in dst_by_src.items():
        if len(dsts) >= 20:
            detections.append({
                "severity": "warning",
                "summary": "SMTP scanning/probing detected",
                "details": f"{src} contacted {len(dsts)} SMTP endpoints.",
                "source": "SMTP",
            })

    for src, count in auth_fail_by_src.items():
        if count >= 10:
            detections.append({
                "severity": "warning",
                "summary": "SMTP auth brute-force suspected",
                "details": f"{src} saw {count} auth failures.",
                "source": "SMTP",
            })

    for flow, times in request_times.items():
        score = _beacon_score(times)
        if score:
            detections.append({
                "severity": "warning",
                "summary": "SMTP beaconing suspected",
                "details": f"{flow[0]}->{flow[1]} avg {score['avg']:.1f}s interval.",
                "source": "SMTP",
            })

    for flow, bytes_sent in data_bytes_by_flow.items():
        if bytes_sent > 1_000_000:
            detections.append({
                "severity": "warning",
                "summary": "SMTP data exfiltration suspected",
                "details": f"{flow[0]}->{flow[1]} sent {bytes_sent} bytes.",
                "source": "SMTP",
            })

    conversations: list[SmtpConversation] = []
    for (src, dst, proto, port), data in conv_map.items():
        conversations.append(SmtpConversation(
            client_ip=src,
            server_ip=dst,
            protocol=proto,
            server_port=port,
            packets=int(data["packets"]),
            bytes=int(data["bytes"]),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
        ))
    conversations.sort(key=lambda c: c.packets, reverse=True)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return SmtpSummary(
        path=path,
        total_packets=total_packets,
        smtp_packets=smtp_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        hostname_counts=hostname_counts,
        domain_counts=domain_counts,
        email_counts=email_counts,
        command_counts=command_counts,
        response_counts=response_counts,
        auth_methods=auth_methods,
        auth_failures=auth_failures,
        auth_successes=auth_successes,
        plaintext_strings=plaintext_strings,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_smtp_summaries(summaries: Iterable[SmtpSummary]) -> SmtpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return SmtpSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            smtp_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            hostname_counts=Counter(),
            domain_counts=Counter(),
            email_counts=Counter(),
            command_counts=Counter(),
            response_counts=Counter(),
            auth_methods=Counter(),
            auth_failures=Counter(),
            auth_successes=Counter(),
            plaintext_strings=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=0.0,
        )

    total_packets = 0
    smtp_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds = 0.0

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    hostname_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    email_counts: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    auth_methods: Counter[str] = Counter()
    auth_failures: Counter[str] = Counter()
    auth_successes: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[SmtpArtifact] = []
    errors: list[str] = []

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    det_seen: set[tuple[str, str, str]] = set()
    err_seen: set[str] = set()

    for summary in summary_list:
        total_packets += summary.total_packets
        smtp_packets += summary.smtp_packets
        total_bytes += summary.total_bytes
        total_messages += summary.total_messages
        if summary.first_seen is not None:
            if first_seen is None or summary.first_seen < first_seen:
                first_seen = summary.first_seen
        if summary.last_seen is not None:
            if last_seen is None or summary.last_seen > last_seen:
                last_seen = summary.last_seen
        if summary.duration_seconds is not None:
            duration_seconds += summary.duration_seconds

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        server_ports.update(summary.server_ports)
        protocol_counts.update(summary.protocol_counts)
        hostname_counts.update(summary.hostname_counts)
        domain_counts.update(summary.domain_counts)
        email_counts.update(summary.email_counts)
        command_counts.update(summary.command_counts)
        response_counts.update(summary.response_counts)
        auth_methods.update(summary.auth_methods)
        auth_failures.update(summary.auth_failures)
        auth_successes.update(summary.auth_successes)
        plaintext_strings.update(summary.plaintext_strings)
        file_artifacts.update(summary.file_artifacts)

        for item in summary.detections:
            key = (str(item.get("severity", "")), str(item.get("summary", "")), str(item.get("details", "")))
            if key in det_seen:
                continue
            det_seen.add(key)
            detections.append(item)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        for err in summary.errors:
            if err in err_seen:
                continue
            err_seen.add(err)
            errors.append(err)

        for conv in summary.conversations:
            key = (conv.client_ip, conv.server_ip, conv.protocol, conv.server_port)
            current = conv_map.get(key)
            if current is None:
                conv_map[key] = {
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                }
                continue
            current["packets"] = int(current["packets"]) + conv.packets
            current["bytes"] = int(current["bytes"]) + conv.bytes
            if conv.first_seen is not None and (current["first_seen"] is None or conv.first_seen < current["first_seen"]):
                current["first_seen"] = conv.first_seen
            if conv.last_seen is not None and (current["last_seen"] is None or conv.last_seen > current["last_seen"]):
                current["last_seen"] = conv.last_seen

    conversations = [
        SmtpConversation(
            client_ip=key[0],
            server_ip=key[1],
            protocol=key[2],
            server_port=key[3],
            packets=int(val["packets"]),
            bytes=int(val["bytes"]),
            first_seen=val.get("first_seen"),
            last_seen=val.get("last_seen"),
        )
        for key, val in conv_map.items()
    ]
    conversations.sort(key=lambda c: c.packets, reverse=True)

    return SmtpSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        smtp_packets=smtp_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        hostname_counts=hostname_counts,
        domain_counts=domain_counts,
        email_counts=email_counts,
        command_counts=command_counts,
        response_counts=response_counts,
        auth_methods=auth_methods,
        auth_failures=auth_failures,
        auth_successes=auth_successes,
        plaintext_strings=plaintext_strings,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
