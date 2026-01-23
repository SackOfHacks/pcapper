from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import re

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import safe_float, detect_file_type

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
SUSPICIOUS_UA = ("sqlmap", "nikto", "nmap", "acunetix", "python-requests", "curl", "wget", "masscan")
SUSPICIOUS_EXT = {".exe", ".dll", ".ps1", ".vbs", ".js", ".jar", ".bat", ".scr", ".zip", ".rar"}


@dataclass(frozen=True)
class HttpConversation:
    client_ip: str
    server_ip: str
    requests: int
    responses: int
    bytes: int
    methods: Counter[str]
    statuses: Counter[str]
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class HttpSummary:
    path: Path
    total_packets: int
    total_bytes: int
    total_requests: int
    total_responses: int
    unique_clients: int
    unique_servers: int
    method_counts: Counter[str]
    status_counts: Counter[str]
    host_counts: Counter[str]
    url_counts: Counter[str]
    user_agents: Counter[str]
    server_headers: Counter[str]
    content_types: Counter[str]
    file_artifacts: Counter[str]
    session_tokens: Counter[str]
    conversations: list[HttpConversation]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def _extract_url(host: str, uri: str) -> str:
    if uri.startswith("http://") or uri.startswith("https://"):
        return uri
    if host:
        return f"http://{host}{uri}"
    return uri


def _extract_filename(headers: dict[str, str], uri: str) -> Optional[str]:
    content_disp = headers.get("content-disposition", "")
    match = re.search(r"filename=\"?([^\";]+)", content_disp, re.IGNORECASE)
    if match:
        return match.group(1)
    if "/" in uri:
        name = uri.split("?")[0].rsplit("/", 1)[-1]
        if "." in name:
            return name
    return None


def _extract_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    patterns = [
        r"(?i)(session|sessid|jsessionid|phpsessid|token|auth|sid)=([A-Za-z0-9._-]{6,})",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            tokens.append(match.group(0))
    return tokens


def analyze_http(path: Path, show_status: bool = True) -> HttpSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for HTTP analysis.")
        return HttpSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            total_requests=0,
            total_responses=0,
            unique_clients=0,
            unique_servers=0,
            method_counts=Counter(),
            status_counts=Counter(),
            host_counts=Counter(),
            url_counts=Counter(),
            user_agents=Counter(),
            server_headers=Counter(),
            content_types=Counter(),
            file_artifacts=Counter(),
            session_tokens=Counter(),
            conversations=[],
            detections=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

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

    total_packets = 0
    total_bytes = 0
    total_requests = 0
    total_responses = 0
    method_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    url_counts: Counter[str] = Counter()
    user_agents: Counter[str] = Counter()
    server_headers: Counter[str] = Counter()
    content_types: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    session_tokens: Counter[str] = Counter()

    conversations: dict[tuple[str, str], dict[str, object]] = defaultdict(lambda: {
        "requests": 0,
        "responses": 0,
        "bytes": 0,
        "methods": Counter(),
        "statuses": Counter(),
        "first_seen": None,
        "last_seen": None,
    })

    clients: set[str] = set()
    servers: set[str] = set()

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

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len

            if TCP is None or Raw is None:
                continue
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                continue

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

            payload = bytes(pkt[Raw])
            if not payload:
                continue

            try:
                text = payload.decode("utf-8", errors="ignore")
            except Exception:
                continue

            lines = text.split("\r\n")
            if not lines:
                continue

            start = lines[0]
            headers = _parse_headers(lines[1:])
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if any(start.startswith(m + " ") for m in HTTP_METHODS):
                parts = start.split(" ")
                if len(parts) >= 2:
                    method = parts[0]
                    uri = parts[1]
                    host = headers.get("host", "")
                    url = _extract_url(host, uri)

                    total_requests += 1
                    method_counts[method] += 1
                    if host:
                        host_counts[host] += 1
                    url_counts[url] += 1

                    ua = headers.get("user-agent", "")
                    if ua:
                        user_agents[ua] += 1

                    tokens = _extract_tokens(uri)
                    for token in tokens:
                        session_tokens[token] += 1

                    filename = _extract_filename(headers, uri)
                    if filename:
                        file_artifacts[filename] += 1

                    conv = conversations[(src_ip, dst_ip)]
                    conv["requests"] = int(conv["requests"]) + 1
                    conv["methods"][method] += 1
                    conv["bytes"] = int(conv["bytes"]) + pkt_len
                    if conv["first_seen"] is None or (ts is not None and ts < conv["first_seen"]):
                        conv["first_seen"] = ts
                    if conv["last_seen"] is None or (ts is not None and ts > conv["last_seen"]):
                        conv["last_seen"] = ts

                    clients.add(src_ip)
                    servers.add(dst_ip)

            elif start.startswith("HTTP/"):
                parts = start.split(" ")
                if len(parts) >= 2 and parts[1].isdigit():
                    status_code = parts[1]
                    total_responses += 1
                    status_counts[status_code] += 1

                    server = headers.get("server", "")
                    if server:
                        server_headers[server] += 1

                    content_type = headers.get("content-type", "")
                    if content_type:
                        content_types[content_type] += 1

                    filename = _extract_filename(headers, "")
                    if filename:
                        file_artifacts[filename] += 1

                    set_cookie = headers.get("set-cookie", "")
                    if set_cookie:
                        tokens = _extract_tokens(set_cookie)
                        for token in tokens:
                            session_tokens[token] += 1

                    conv = conversations[(dst_ip, src_ip)]
                    conv["responses"] = int(conv["responses"]) + 1
                    conv["statuses"][status_code] += 1
                    conv["bytes"] = int(conv["bytes"]) + pkt_len
                    if conv["first_seen"] is None or (ts is not None and ts < conv["first_seen"]):
                        conv["first_seen"] = ts
                    if conv["last_seen"] is None or (ts is not None and ts > conv["last_seen"]):
                        conv["last_seen"] = ts

                    servers.add(src_ip)
                    clients.add(dst_ip)
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows: list[HttpConversation] = []
    for (client, server), data in conversations.items():
        conversation_rows.append(HttpConversation(
            client_ip=client,
            server_ip=server,
            requests=int(data["requests"]),
            responses=int(data["responses"]),
            bytes=int(data["bytes"]),
            methods=data["methods"],
            statuses=data["statuses"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
        ))

    detections: list[dict[str, object]] = []
    error_responses = sum(count for code, count in status_counts.items() if code.startswith("4") or code.startswith("5"))
    if total_responses and (error_responses / total_responses) > 0.3:
        detections.append({
            "severity": "warning",
            "summary": "High HTTP error rate",
            "details": f"{error_responses}/{total_responses} responses are 4xx/5xx.",
        })

    if any(method in ("TRACE", "CONNECT") for method in method_counts):
        detections.append({
            "severity": "warning",
            "summary": "Risky HTTP methods observed",
            "details": f"Methods: {', '.join([m for m in method_counts if m in ('TRACE', 'CONNECT')])}.",
        })

    suspicious_ua_hits = [ua for ua in user_agents if any(tag in ua.lower() for tag in SUSPICIOUS_UA)]
    if suspicious_ua_hits:
        detections.append({
            "severity": "warning",
            "summary": "Suspicious user agents observed",
            "details": ", ".join(suspicious_ua_hits[:5]),
        })

    long_urls = [url for url in url_counts if len(url) > 200]
    if long_urls:
        detections.append({
            "severity": "info",
            "summary": "Long URLs observed",
            "details": f"{len(long_urls)} URL(s) longer than 200 chars.",
        })

    suspicious_files = [name for name in file_artifacts if any(name.lower().endswith(ext) for ext in SUSPICIOUS_EXT)]
    if suspicious_files:
        detections.append({
            "severity": "warning",
            "summary": "Suspicious file artifacts observed",
            "details": ", ".join(suspicious_files[:5]),
        })

    return HttpSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        total_requests=total_requests,
        total_responses=total_responses,
        unique_clients=len(clients),
        unique_servers=len(servers),
        method_counts=method_counts,
        status_counts=status_counts,
        host_counts=host_counts,
        url_counts=url_counts,
        user_agents=user_agents,
        server_headers=server_headers,
        content_types=content_types,
        file_artifacts=file_artifacts,
        session_tokens=session_tokens,
        conversations=conversation_rows,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
