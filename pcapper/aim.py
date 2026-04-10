from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import parse_qsl

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


AIM_PORTS = {5190}
TLS_TUNNEL_PORTS = {443}
USER_RE = re.compile(
    r"\b(?:sn|screenname|screen_name|username|user|login)\b\s*[:=]\s*([A-Za-z0-9._@-]{2,64})",
    re.IGNORECASE,
)
PASS_RE = re.compile(
    r"\b(?:pass|password|pwd)\b\s*[:=]\s*([^\s&;,]{1,128})", re.IGNORECASE
)
SECRET_RE = re.compile(
    r"\b(?:secret|token|apikey|api_key|api-key|session|sessionid|auth|authorization)\b\s*[:=]\s*([^\s&;,]{3,256})",
    re.IGNORECASE,
)
MSG_RE = re.compile(
    r"\b(?:message|msg|im|text|body)\b\s*[:=]\s*([^&\r\n]{1,512})", re.IGNORECASE
)
KV_RE = re.compile(
    r"[\"']?(sn|screenname|screen_name|username|user|login|pass|password|pwd|secret|token|apikey|api_key|api-key|session|sessionid|auth|authorization|message|msg|im|text|body)[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{1,512})[\"']",
    re.IGNORECASE,
)
FILE_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.()\[\] -]{0,220}\.(?:docx|xlsx|pptx|txt|rtf|doc|xls|ppt|pdf|zip|rar|7z|jpg|jpeg|png|gif|bmp|avi|mp4|mp3|wav|exe|dll|ps1|js|py|bat)",
    re.IGNORECASE,
)
TEXT_LINE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.,'\":;!?()/\\-]{8,}")
CHAT_LINE_RE = re.compile(r"^[A-Za-z0-9._@-]{2,40}\s*:\s*(.{3,512})$")
AIM_STRONG_MARKERS = (
    "oft2",
    "cool filexfer",
    "oscar",
    "aol instant messenger",
)


@dataclass(frozen=True)
class AimArtifact:
    kind: str
    detail: str
    src: str
    dst: str
    packet_index: int


@dataclass(frozen=True)
class AimConversation:
    client_ip: str
    server_ip: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class AimSummary:
    path: Path
    total_packets: int
    aim_packets: int
    total_bytes: int
    aim_bytes: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    username_counts: Counter[str]
    password_counts: Counter[str]
    secret_counts: Counter[str]
    message_counts: Counter[str]
    file_counts: Counter[str]
    artifacts: list[AimArtifact]
    conversations: list[AimConversation]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _decode_payload(payload: bytes) -> str:
    try:
        return payload.decode("latin-1", errors="ignore")
    except Exception:
        return ""


def _looks_like_aim_payload(payload: bytes, text: str) -> bool:
    if not payload:
        return False
    if payload.startswith(b"OFT2"):
        return True
    lowered = text.lower()
    if any(marker in lowered for marker in AIM_STRONG_MARKERS):
        return True

    score = 0
    if USER_RE.search(text):
        score += 1
    if PASS_RE.search(text) or SECRET_RE.search(text):
        score += 1
    if MSG_RE.search(text):
        score += 1
    if FILE_RE.search(text):
        score += 1
    if re.search(r"sec\d{2,4}user\d+", lowered):
        score += 1
    return score >= 2


def _add_from_query_like(
    text: str,
    usernames: Counter[str],
    passwords: Counter[str],
    secrets: Counter[str],
    messages: Counter[str],
    files: Counter[str],
) -> None:
    if "=" not in text:
        return
    normalized = text.replace("\r", "&").replace("\n", "&").replace(";", "&")
    for key, value in parse_qsl(normalized, keep_blank_values=False):
        lk = key.strip().lower()
        val = value.strip()
        if not val:
            continue
        if lk in {"sn", "screenname", "screen_name", "username", "user", "login"}:
            usernames[val] += 1
        elif lk in {"pass", "password", "pwd"}:
            passwords[val] += 1
            secrets[val] += 1
        elif lk in {
            "secret",
            "token",
            "apikey",
            "api_key",
            "api-key",
            "session",
            "sessionid",
            "auth",
            "authorization",
        }:
            secrets[val] += 1
        elif lk in {"message", "msg", "im", "text", "body"}:
            messages[val] += 1
        elif lk in {"file", "filename", "name"} and FILE_RE.search(val):
            files[val] += 1


def analyze_aim(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> AimSummary:
    errors: list[str] = []
    if TCP is None:
        errors.append("Scapy TCP layers unavailable; install scapy for AIM analysis.")
        return AimSummary(
            path=path,
            total_packets=0,
            aim_packets=0,
            total_bytes=0,
            aim_bytes=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            username_counts=Counter(),
            password_counts=Counter(),
            secret_counts=Counter(),
            message_counts=Counter(),
            file_counts=Counter(),
            artifacts=[],
            conversations=[],
            detections=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    aim_packets = 0
    total_bytes = 0
    aim_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    username_counts: Counter[str] = Counter()
    password_counts: Counter[str] = Counter()
    secret_counts: Counter[str] = Counter()
    message_counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()
    artifacts: list[AimArtifact] = []
    conv_map: dict[tuple[str, str, int], dict[str, object]] = {}
    detections: list[dict[str, object]] = []
    non_standard_ports: Counter[int] = Counter()

    try:
        for idx, pkt in enumerate(reader, start=1):
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
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

            if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue
            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp_layer, "sport", 0) or 0)
            dport = int(getattr(tcp_layer, "dport", 0) or 0)

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

            try:
                payload = bytes(tcp_layer.payload)
            except Exception:
                payload = b""
            text = _decode_payload(payload)
            is_standard_aim = sport in AIM_PORTS or dport in AIM_PORTS
            looks_tunneled_aim = False
            if (sport in TLS_TUNNEL_PORTS or dport in TLS_TUNNEL_PORTS) and payload:
                looks_tunneled_aim = _looks_like_aim_payload(payload, text)
            if not is_standard_aim and not looks_tunneled_aim:
                continue

            aim_packets += 1
            aim_bytes += pkt_len
            if dport in AIM_PORTS:
                server_port = dport
            elif sport in AIM_PORTS:
                server_port = sport
            elif dport in TLS_TUNNEL_PORTS:
                server_port = dport
            else:
                server_port = sport
            server_ports[server_port] += 1
            if server_port not in AIM_PORTS:
                non_standard_ports[server_port] += 1

            if dport in AIM_PORTS:
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1
                client_ip, server_ip = src_ip, dst_ip
            elif sport in AIM_PORTS:
                client_counts[dst_ip] += 1
                server_counts[src_ip] += 1
                client_ip, server_ip = dst_ip, src_ip
            elif dport in TLS_TUNNEL_PORTS:
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1
                client_ip, server_ip = src_ip, dst_ip
            else:
                client_counts[dst_ip] += 1
                server_counts[src_ip] += 1
                client_ip, server_ip = dst_ip, src_ip

            conv_key = (client_ip, server_ip, int(server_port))
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

            if not payload or not text:
                continue

            _add_from_query_like(
                text,
                username_counts,
                password_counts,
                secret_counts,
                message_counts,
                file_counts,
            )

            for key, value in KV_RE.findall(text):
                lk = key.lower().strip()
                val = value.strip()
                if not val:
                    continue
                if lk in {
                    "sn",
                    "screenname",
                    "screen_name",
                    "username",
                    "user",
                    "login",
                }:
                    username_counts[val] += 1
                elif lk in {"pass", "password", "pwd"}:
                    password_counts[val] += 1
                    secret_counts[val] += 1
                elif lk in {
                    "secret",
                    "token",
                    "apikey",
                    "api_key",
                    "api-key",
                    "session",
                    "sessionid",
                    "auth",
                    "authorization",
                }:
                    secret_counts[val] += 1
                elif lk in {"message", "msg", "im", "text", "body"}:
                    message_counts[val] += 1

            for user in USER_RE.findall(text):
                username_counts[user] += 1
            for password in PASS_RE.findall(text):
                pw = password if isinstance(password, str) else password[0]
                if pw:
                    password_counts[pw] += 1
                    secret_counts[pw] += 1
            for secret in SECRET_RE.findall(text):
                sec = secret.strip()
                if sec:
                    secret_counts[sec] += 1
            for message in MSG_RE.findall(text):
                msg = message.strip()
                if len(msg) >= 3:
                    message_counts[msg] += 1
            for fname in FILE_RE.findall(text):
                file_counts[fname] += 1

            for line in text.splitlines():
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                if TEXT_LINE_RE.fullmatch(line) and not line.lower().startswith(
                    ("host:", "user-agent:", "cookie:", "accept:", "connection:")
                ):
                    if len(line.split()) >= 3:
                        message_counts[line] += 1
                chat_match = CHAT_LINE_RE.match(line)
                if chat_match:
                    msg = chat_match.group(1).strip()
                    if msg:
                        message_counts[msg] += 1

            for user in USER_RE.findall(text):
                artifacts.append(AimArtifact("username", user, src_ip, dst_ip, idx))
            for password in PASS_RE.findall(text):
                pw = password if isinstance(password, str) else password[0]
                if pw:
                    artifacts.append(AimArtifact("password", pw, src_ip, dst_ip, idx))
                    artifacts.append(AimArtifact("secret", pw, src_ip, dst_ip, idx))
            for secret in SECRET_RE.findall(text):
                sec = secret.strip()
                if sec:
                    artifacts.append(AimArtifact("secret", sec, src_ip, dst_ip, idx))
            for msg in MSG_RE.findall(text):
                cleaned = msg.strip()
                if cleaned:
                    artifacts.append(
                        AimArtifact("message", cleaned, src_ip, dst_ip, idx)
                    )
            for fname in FILE_RE.findall(text):
                artifacts.append(AimArtifact("file", fname, src_ip, dst_ip, idx))

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    if password_counts:
        detections.append(
            {
                "severity": "high",
                "summary": "AIM credential exposure detected",
                "details": f"Observed {sum(password_counts.values())} password artifact(s) in AIM traffic.",
                "source": "AIM",
            }
        )
    if secret_counts:
        detections.append(
            {
                "severity": "high",
                "summary": "AIM secrets exposure detected",
                "details": f"Observed {sum(secret_counts.values())} secret/token artifact(s) in AIM traffic.",
                "source": "AIM",
            }
        )
    if file_counts:
        detections.append(
            {
                "severity": "warning",
                "summary": "AIM file transfer artifacts observed",
                "details": f"Observed {sum(file_counts.values())} AIM file artifact(s).",
                "source": "AIM",
            }
        )
    if message_counts:
        detections.append(
            {
                "severity": "info",
                "summary": "AIM message content recovered",
                "details": f"Recovered {sum(message_counts.values())} AIM message artifact(s).",
                "source": "AIM",
            }
        )

    conversations: list[AimConversation] = []
    for (client_ip, server_ip, server_port), data in conv_map.items():
        conversations.append(
            AimConversation(
                client_ip=client_ip,
                server_ip=server_ip,
                server_port=server_port,
                packets=int(data.get("packets", 0) or 0),
                bytes=int(data.get("bytes", 0) or 0),
                first_seen=safe_float(data.get("first_seen")),
                last_seen=safe_float(data.get("last_seen")),
            )
        )

    if conversations:
        detections.append(
            {
                "severity": "info",
                "summary": "AIM conversation activity observed",
                "details": f"Observed {len(conversations)} AIM conversation(s).",
                "source": "AIM",
            }
        )
    if non_standard_ports:
        details = ", ".join(
            f"{port}({count})" for port, count in non_standard_ports.most_common(8)
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "AIM traffic observed on non-standard/tunneled ports",
                "details": f"Observed AIM-like traffic on: {details}",
                "source": "AIM",
            }
        )

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return AimSummary(
        path=path,
        total_packets=total_packets,
        aim_packets=aim_packets,
        total_bytes=total_bytes,
        aim_bytes=aim_bytes,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        username_counts=username_counts,
        password_counts=password_counts,
        secret_counts=secret_counts,
        message_counts=message_counts,
        file_counts=file_counts,
        artifacts=artifacts,
        conversations=conversations,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_aim_summaries(summaries: Iterable[AimSummary]) -> AimSummary:
    summary_list = list(summaries)
    if not summary_list:
        return AimSummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            aim_packets=0,
            total_bytes=0,
            aim_bytes=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            username_counts=Counter(),
            password_counts=Counter(),
            secret_counts=Counter(),
            message_counts=Counter(),
            file_counts=Counter(),
            artifacts=[],
            conversations=[],
            detections=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    first_seen_values = [s.first_seen for s in summary_list if s.first_seen is not None]
    last_seen_values = [s.last_seen for s in summary_list if s.last_seen is not None]
    first_seen = min(first_seen_values) if first_seen_values else None
    last_seen = max(last_seen_values) if last_seen_values else None
    duration = None
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    username_counts: Counter[str] = Counter()
    password_counts: Counter[str] = Counter()
    secret_counts: Counter[str] = Counter()
    message_counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()
    artifacts: list[AimArtifact] = []
    conversations: list[AimConversation] = []
    detections: list[dict[str, object]] = []
    errors: list[str] = []

    total_packets = 0
    aim_packets = 0
    total_bytes = 0
    aim_bytes = 0
    for summary in summary_list:
        total_packets += int(summary.total_packets)
        aim_packets += int(summary.aim_packets)
        total_bytes += int(summary.total_bytes)
        aim_bytes += int(summary.aim_bytes)
        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        server_ports.update(summary.server_ports)
        username_counts.update(summary.username_counts)
        password_counts.update(summary.password_counts)
        secret_counts.update(summary.secret_counts)
        message_counts.update(summary.message_counts)
        file_counts.update(summary.file_counts)
        artifacts.extend(summary.artifacts)
        conversations.extend(summary.conversations)
        detections.extend(summary.detections)
        errors.extend(summary.errors)

    return AimSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        aim_packets=aim_packets,
        total_bytes=total_bytes,
        aim_bytes=aim_bytes,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        username_counts=username_counts,
        password_counts=password_counts,
        secret_counts=secret_counts,
        message_counts=message_counts,
        file_counts=file_counts,
        artifacts=artifacts,
        conversations=conversations,
        detections=detections,
        errors=sorted(set(errors)),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
