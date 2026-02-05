from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import hashlib
import re

from .pcap_cache import PcapMeta, get_reader

from .utils import safe_float, detect_file_type, detect_file_type_bytes

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
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP_PORTS = {80, 8080, 8000, 8008, 3128, 8888}


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
    client_counts: Counter[str]
    server_counts: Counter[str]
    version_counts: Counter[str]
    http2_prefaces: int
    http2_sessions: int
    post_payloads: list[dict[str, object]]
    downloads: list[dict[str, object]]
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


def _token_fingerprint(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()
    return f"sha256:{digest[:16]}"


def _reassemble_stream(chunks: list[tuple[int, bytes]], limit: int = 50_000_000) -> bytes:
    if not chunks:
        return b""
    chunks.sort(key=lambda item: item[0])
    assembled = bytearray()
    expected_seq: Optional[int] = None
    for seq, payload in chunks:
        if not payload:
            continue
        if expected_seq is None:
            expected_seq = seq
        if seq < expected_seq:
            overlap = expected_seq - seq
            if overlap >= len(payload):
                continue
            payload = payload[overlap:]
            seq = expected_seq
        if seq > expected_seq:
            expected_seq = seq
        if len(assembled) + len(payload) > limit:
            remaining = max(0, limit - len(assembled))
            assembled.extend(payload[:remaining])
            break
        assembled.extend(payload)
        expected_seq = seq + len(payload)
    return bytes(assembled)


def _find_http_start(data: bytes, start_idx: int) -> int:
    idx = start_idx
    while idx < len(data):
        line_end = data.find(b"\r\n", idx)
        if line_end == -1:
            return -1
        line = data[idx:line_end]
        if any(line.startswith((m + " ").encode("ascii")) for m in HTTP_METHODS):
            return idx
        if line.startswith(b"HTTP/"):
            return idx
        if line.startswith(b"PRI * HTTP/2.0"):
            return idx
        idx = line_end + 2
    return -1


def _parse_chunked_length(data: bytes, start_idx: int) -> Optional[int]:
    idx = start_idx
    total = 0
    while idx < len(data):
        line_end = data.find(b"\r\n", idx)
        if line_end == -1:
            return None
        size_line = data[idx:line_end].split(b";", 1)[0]
        try:
            size_val = int(size_line.strip(), 16)
        except Exception:
            return None
        idx = line_end + 2
        if size_val == 0:
            trailer_end = data.find(b"\r\n\r\n", idx)
            if trailer_end == -1:
                return None
            return (trailer_end + 4) - start_idx
        if idx + size_val > len(data):
            return None
        idx += size_val + 2
        total += size_val
    return None


def analyze_http(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> HttpSummary:
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
            client_counts=Counter(),
            server_counts=Counter(),
            version_counts=Counter(),
            http2_prefaces=0,
            http2_sessions=0,
            post_payloads=[],
            downloads=[],
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
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()
    http2_prefaces = 0
    http2_sessions = 0
    post_payloads: list[dict[str, object]] = []
    downloads: list[dict[str, object]] = []

    conversations: dict[tuple[str, str], dict[str, object]] = defaultdict(lambda: {
        "requests": 0,
        "responses": 0,
        "bytes": 0,
        "methods": Counter(),
        "statuses": Counter(),
        "first_seen": None,
        "last_seen": None,
    })
    pending_requests: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)

    stream_chunks: dict[tuple[str, str, int, int], list[tuple[int, bytes]]] = defaultdict(list)
    stream_times: dict[tuple[str, str, int, int], dict[str, Optional[float]]] = defaultdict(lambda: {
        "first_seen": None,
        "last_seen": None,
    })

    clients: set[str] = set()
    servers: set[str] = set()

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def _register_message(
        start_line: str,
        headers: dict[str, str],
        body: bytes,
        src_ip: str,
        dst_ip: str,
        message_bytes: int,
        first_seen_ts: Optional[float],
        last_seen_ts: Optional[float],
    ) -> None:
        nonlocal total_requests
        nonlocal total_responses

        if any(start_line.startswith(m + " ") for m in HTTP_METHODS):
            parts = start_line.split(" ")
            if len(parts) >= 2:
                method = parts[0]
                uri = parts[1]
                version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
                if version.startswith("HTTP/"):
                    version_counts[version] += 1
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
                    session_tokens[_token_fingerprint(token)] += 1

                filename = _extract_filename(headers, uri)
                if filename:
                    file_artifacts[filename] += 1
                pending_requests[(src_ip, dst_ip)].append({
                    "uri": uri,
                    "filename": filename or "",
                })

                conv = conversations[(src_ip, dst_ip)]
                conv["requests"] = int(conv["requests"]) + 1
                conv["methods"][method] += 1
                conv["bytes"] = int(conv["bytes"]) + message_bytes
                if conv["first_seen"] is None or (first_seen_ts is not None and first_seen_ts < conv["first_seen"]):
                    conv["first_seen"] = first_seen_ts
                if conv["last_seen"] is None or (last_seen_ts is not None and last_seen_ts > conv["last_seen"]):
                    conv["last_seen"] = last_seen_ts

                clients.add(src_ip)
                servers.add(dst_ip)
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1

                if method == "POST" and body:
                    content_length = headers.get("content-length", "")
                    content_type = headers.get("content-type", "")
                    sample = body[:160]
                    sample_text = sample.decode("latin-1", errors="ignore").replace("\r", " ").replace("\n", " ")
                    post_payloads.append({
                        "src": src_ip,
                        "dst": dst_ip,
                        "host": host,
                        "uri": uri,
                        "bytes": len(body),
                        "content_type": content_type,
                        "content_length": content_length,
                        "sample": sample_text,
                    })
            return

        if start_line.startswith("HTTP/"):
            parts = start_line.split(" ")
            if len(parts) >= 2 and parts[1].isdigit():
                version = parts[0]
                if version.startswith("HTTP/"):
                    version_counts[version] += 1
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
                        session_tokens[_token_fingerprint(token)] += 1

                conv = conversations[(dst_ip, src_ip)]
                conv["responses"] = int(conv["responses"]) + 1
                conv["statuses"][status_code] += 1
                conv["bytes"] = int(conv["bytes"]) + message_bytes
                if conv["first_seen"] is None or (first_seen_ts is not None and first_seen_ts < conv["first_seen"]):
                    conv["first_seen"] = first_seen_ts
                if conv["last_seen"] is None or (last_seen_ts is not None and last_seen_ts > conv["last_seen"]):
                    conv["last_seen"] = last_seen_ts

                servers.add(src_ip)
                clients.add(dst_ip)
                server_counts[src_ip] += 1
                client_counts[dst_ip] += 1

                if body:
                    detected_type = detect_file_type_bytes(body)
                    fname = _extract_filename(headers, "")
                    pending_key = (dst_ip, src_ip)
                    if not fname and pending_requests.get(pending_key):
                        req_info = pending_requests[pending_key].pop(0)
                        fname = req_info.get("filename") or fname
                        if not fname:
                            uri = req_info.get("uri", "")
                            fname = _extract_filename({}, uri) or fname
                    ext = ""
                    if fname and "." in fname:
                        ext = "." + fname.lower().split(".")[-1]
                    expected_type = None
                    if ext in {".exe", ".dll", ".sys", ".scr"}:
                        expected_type = "EXE/DLL"
                    elif ext in {".zip", ".rar", ".7z", ".iso", ".img"}:
                        expected_type = "ZIP/Office"
                    elif ext in {".pdf"}:
                        expected_type = "PDF"
                    elif ext in {".png"}:
                        expected_type = "PNG"
                    elif ext in {".jpg", ".jpeg"}:
                        expected_type = "JPG"
                    elif ext in {".gif"}:
                        expected_type = "GIF"
                    elif not expected_type:
                        ctype = headers.get("content-type", "").lower()
                        if "pdf" in ctype:
                            expected_type = "PDF"
                        elif "zip" in ctype:
                            expected_type = "ZIP/Office"
                        elif "msword" in ctype or "word" in ctype:
                            expected_type = "DOC"
                        elif "excel" in ctype:
                            expected_type = "XLS"
                        elif "powerpoint" in ctype:
                            expected_type = "PPT"
                        elif "png" in ctype:
                            expected_type = "PNG"
                        elif "jpeg" in ctype or "jpg" in ctype:
                            expected_type = "JPG"
                        elif "gif" in ctype:
                            expected_type = "GIF"
                    mismatch = bool(expected_type and detected_type not in ("BINARY", expected_type))
                    if fname or detected_type not in ("BINARY", "HTML"):
                        downloads.append({
                            "src": src_ip,
                            "dst": dst_ip,
                            "filename": fname or "-",
                            "detected_type": detected_type,
                            "expected_type": expected_type or "-",
                            "bytes": len(body),
                            "content_type": headers.get("content-type", ""),
                            "status": status_code,
                            "mismatch": mismatch,
                        })

    def _parse_stream(data: bytes, src_ip: str, dst_ip: str, first_ts: Optional[float], last_ts: Optional[float]) -> None:
        nonlocal http2_prefaces
        nonlocal http2_sessions

        if HTTP2_PREFACE in data:
            http2_prefaces += data.count(HTTP2_PREFACE)
            http2_sessions += 1

        idx = 0
        while True:
            start_idx = _find_http_start(data, idx)
            if start_idx == -1:
                break
            line_end = data.find(b"\r\n", start_idx)
            if line_end == -1:
                break
            start_line = data[start_idx:line_end].decode("utf-8", errors="ignore")

            if start_line.startswith("PRI * HTTP/2.0"):
                idx = start_idx + len(HTTP2_PREFACE)
                continue

            header_end = data.find(b"\r\n\r\n", line_end + 2)
            if header_end == -1:
                break
            header_text = data[line_end + 2:header_end].decode("utf-8", errors="ignore")
            headers = _parse_headers(header_text.split("\r\n"))

            body_start = header_end + 4
            body_len = 0
            transfer_encoding = headers.get("transfer-encoding", "").lower()
            if "chunked" in transfer_encoding:
                chunk_len = _parse_chunked_length(data, body_start)
                if chunk_len is None:
                    break
                body_len = chunk_len
            else:
                content_length = headers.get("content-length", "")
                try:
                    body_len = int(content_length) if content_length else 0
                except Exception:
                    body_len = 0
                if body_start + body_len > len(data):
                    body_len = max(0, len(data) - body_start)

            message_end = body_start + body_len
            body = data[body_start:message_end] if body_len else b""
            message_bytes = message_end - start_idx

            _register_message(start_line, headers, body, src_ip, dst_ip, message_bytes, first_ts, last_ts)

            if message_end <= idx:
                idx = message_end + 1
            else:
                idx = message_end

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

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts
            tcp_layer = pkt[TCP]  # type: ignore[index]
            seq = int(getattr(tcp_layer, "seq", 0))
            sport = int(getattr(tcp_layer, "sport", 0))
            dport = int(getattr(tcp_layer, "dport", 0))
            flow_key = (src_ip, dst_ip, sport, dport)
            stream_chunks[flow_key].append((seq, payload))
            flow_ts = stream_times[flow_key]
            if ts is not None:
                if flow_ts["first_seen"] is None or ts < flow_ts["first_seen"]:
                    flow_ts["first_seen"] = ts
                if flow_ts["last_seen"] is None or ts > flow_ts["last_seen"]:
                    flow_ts["last_seen"] = ts
    finally:
        status.finish()
        reader.close()

    for (src_ip, dst_ip, sport, dport), chunks in stream_chunks.items():
        data = _reassemble_stream(chunks)
        if not data:
            continue
        if dport not in HTTP_PORTS and sport not in HTTP_PORTS:
            sample = data[:2048]
            if HTTP2_PREFACE not in sample and b"HTTP/" not in sample:
                continue
        flow_ts = stream_times[(src_ip, dst_ip, sport, dport)]
        _parse_stream(data, src_ip, dst_ip, flow_ts["first_seen"], flow_ts["last_seen"])

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

    mismatch_downloads = [item for item in downloads if item.get("mismatch")]
    if mismatch_downloads:
        detections.append({
            "severity": "critical",
            "summary": "HTTP file type discrepancies",
            "details": f"{len(mismatch_downloads)} downloads where filename/type mismatched (possible masquerading).",
        })

    if post_payloads:
        detections.append({
            "severity": "info",
            "summary": "HTTP POST payloads observed",
            "details": f"{len(post_payloads)} POST payload(s) captured.",
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
        client_counts=client_counts,
        server_counts=server_counts,
        version_counts=version_counts,
        http2_prefaces=http2_prefaces,
        http2_sessions=http2_sessions,
        post_payloads=post_payloads,
        downloads=downloads,
        conversations=conversation_rows,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
