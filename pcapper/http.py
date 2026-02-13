from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
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
    referrer_counts: Counter[str]
    referrer_request_host_counts: dict[str, Counter[str]]
    referrer_host_counts: Counter[str]
    referrer_scheme_counts: Counter[str]
    referrer_path_counts: Counter[str]
    referrer_token_counts: Counter[str]
    referrer_ip_hosts: Counter[str]
    referrer_present: int
    referrer_missing: int
    referrer_cross_host: int
    referrer_https_to_http: int
    user_agents: Counter[str]
    server_headers: Counter[str]
    content_types: Counter[str]
    file_artifacts: Counter[str]
    session_tokens: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    version_counts: Counter[str]
    post_payloads: list[dict[str, object]]
    downloads: list[dict[str, object]]
    conversations: list[HttpConversation]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_requests": self.total_requests,
            "total_responses": self.total_responses,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "method_counts": dict(self.method_counts),
            "status_counts": dict(self.status_counts),
            "host_counts": dict(self.host_counts),
            "url_counts": dict(self.url_counts),
            "referrer_counts": dict(self.referrer_counts),
            "referrer_request_host_counts": {
                ref: dict(hosts) for ref, hosts in self.referrer_request_host_counts.items()
            },
            "referrer_host_counts": dict(self.referrer_host_counts),
            "referrer_scheme_counts": dict(self.referrer_scheme_counts),
            "referrer_path_counts": dict(self.referrer_path_counts),
            "referrer_token_counts": dict(self.referrer_token_counts),
            "referrer_ip_hosts": dict(self.referrer_ip_hosts),
            "referrer_present": self.referrer_present,
            "referrer_missing": self.referrer_missing,
            "referrer_cross_host": self.referrer_cross_host,
            "referrer_https_to_http": self.referrer_https_to_http,
            "user_agents": dict(self.user_agents),
            "server_headers": dict(self.server_headers),
            "content_types": dict(self.content_types),
            "file_artifacts": dict(self.file_artifacts),
            "session_tokens": dict(self.session_tokens),
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "version_counts": dict(self.version_counts),
            "post_payloads": list(self.post_payloads),
            "downloads": list(self.downloads),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "requests": conv.requests,
                    "responses": conv.responses,
                    "bytes": conv.bytes,
                    "methods": dict(conv.methods),
                    "statuses": dict(conv.statuses),
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                }
                for conv in self.conversations
            ],
            "detections": list(self.detections),
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


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


def _parse_referrer(referrer: str) -> tuple[str, str, str]:
    ref = referrer.strip()
    if not ref or ref == "-":
        return "", "", ""
    parsed = urlparse(ref)
    if not parsed.scheme and not parsed.netloc and ref.startswith("/"):
        return "", "", ref
    if not parsed.scheme and not parsed.netloc:
        parsed = urlparse(f"http://{ref}")
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, host, path


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
            referrer_counts=Counter(),
            referrer_request_host_counts={},
            referrer_host_counts=Counter(),
            referrer_scheme_counts=Counter(),
            referrer_path_counts=Counter(),
            referrer_token_counts=Counter(),
            referrer_ip_hosts=Counter(),
            referrer_present=0,
            referrer_missing=0,
            referrer_cross_host=0,
            referrer_https_to_http=0,
            user_agents=Counter(),
            server_headers=Counter(),
            content_types=Counter(),
            file_artifacts=Counter(),
            session_tokens=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            version_counts=Counter(),
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
    referrer_counts: Counter[str] = Counter()
    referrer_request_host_counts: dict[str, Counter[str]] = defaultdict(Counter)
    referrer_host_counts: Counter[str] = Counter()
    referrer_scheme_counts: Counter[str] = Counter()
    referrer_path_counts: Counter[str] = Counter()
    referrer_token_counts: Counter[str] = Counter()
    referrer_ip_hosts: Counter[str] = Counter()
    referrer_present = 0
    referrer_missing = 0
    referrer_cross_host = 0
    referrer_https_to_http = 0
    user_agents: Counter[str] = Counter()
    server_headers: Counter[str] = Counter()
    content_types: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    session_tokens: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()
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
                    version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
                    if version.startswith("HTTP/"):
                        version_counts[version] += 1
                    host = headers.get("host", "")
                    host_norm = host.lower().split(":", 1)[0] if host else ""
                    url = _extract_url(host, uri)

                    referrer = headers.get("referer") or headers.get("referrer", "")
                    if referrer:
                        referrer_present += 1
                        referrer_counts[referrer] += 1
                        if host_norm:
                            referrer_request_host_counts[referrer][host_norm] += 1
                        scheme, ref_host, ref_path = _parse_referrer(referrer)
                        if scheme:
                            referrer_scheme_counts[scheme] += 1
                        if ref_host:
                            referrer_host_counts[ref_host] += 1
                            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ref_host) or ":" in ref_host:
                                referrer_ip_hosts[ref_host] += 1
                        if ref_path:
                            referrer_path_counts[ref_path] += 1
                        if host_norm and ref_host and ref_host != host_norm:
                            referrer_cross_host += 1
                        if scheme == "https":
                            referrer_https_to_http += 1
                        for token in _extract_tokens(referrer):
                            referrer_token_counts[_token_fingerprint(token)] += 1
                    else:
                        referrer_missing += 1

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
                    conv["bytes"] = int(conv["bytes"]) + pkt_len
                    if conv["first_seen"] is None or (ts is not None and ts < conv["first_seen"]):
                        conv["first_seen"] = ts
                    if conv["last_seen"] is None or (ts is not None and ts > conv["last_seen"]):
                        conv["last_seen"] = ts

                    clients.add(src_ip)
                    servers.add(dst_ip)
                    client_counts[src_ip] += 1
                    server_counts[dst_ip] += 1

                    if method == "POST":
                        body = b""
                        if b"\r\n\r\n" in payload:
                            body = payload.split(b"\r\n\r\n", 1)[1]
                        if body:
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

            elif start.startswith("HTTP/"):
                parts = start.split(" ")
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
                    conv["bytes"] = int(conv["bytes"]) + pkt_len
                    if conv["first_seen"] is None or (ts is not None and ts < conv["first_seen"]):
                        conv["first_seen"] = ts
                    if conv["last_seen"] is None or (ts is not None and ts > conv["last_seen"]):
                        conv["last_seen"] = ts

                    servers.add(src_ip)
                    clients.add(dst_ip)
                    server_counts[src_ip] += 1
                    client_counts[dst_ip] += 1

                    body = b""
                    if b"\r\n\r\n" in payload:
                        body = payload.split(b"\r\n\r\n", 1)[1]
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

    if referrer_counts:
        if referrer_https_to_http:
            detections.append({
                "severity": "info",
                "summary": "HTTPS referrer to HTTP request",
                "details": f"{referrer_https_to_http} HTTP requests referenced HTTPS pages (mixed content/downgrade).",
            })
        if referrer_token_counts:
            detections.append({
                "severity": "warning",
                "summary": "Potential tokens in HTTP referrers",
                "details": f"{sum(referrer_token_counts.values())} referrer token(s) observed.",
            })
        if referrer_ip_hosts:
            detections.append({
                "severity": "warning",
                "summary": "IP-literal HTTP referrers observed",
                "details": f"{len(referrer_ip_hosts)} referrer host(s) are IP addresses.",
            })
        if referrer_cross_host and referrer_present:
            ratio = referrer_cross_host / max(1, referrer_present)
            if ratio > 0.7:
                detections.append({
                    "severity": "info",
                    "summary": "High cross-site HTTP referrer rate",
                    "details": f"{referrer_cross_host}/{referrer_present} referrers point to different hosts.",
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
        referrer_counts=referrer_counts,
        referrer_request_host_counts=dict(referrer_request_host_counts),
        referrer_host_counts=referrer_host_counts,
        referrer_scheme_counts=referrer_scheme_counts,
        referrer_path_counts=referrer_path_counts,
        referrer_token_counts=referrer_token_counts,
        referrer_ip_hosts=referrer_ip_hosts,
        referrer_present=referrer_present,
        referrer_missing=referrer_missing,
        referrer_cross_host=referrer_cross_host,
        referrer_https_to_http=referrer_https_to_http,
        user_agents=user_agents,
        server_headers=server_headers,
        content_types=content_types,
        file_artifacts=file_artifacts,
        session_tokens=session_tokens,
        client_counts=client_counts,
        server_counts=server_counts,
        version_counts=version_counts,
        post_payloads=post_payloads,
        downloads=downloads,
        conversations=conversation_rows,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
