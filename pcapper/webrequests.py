from __future__ import annotations

import ipaddress
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlsplit

from .dns import _vt_lookup_domains
from .pcap_cache import PcapMeta, get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Packet, Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore
    Packet = object  # type: ignore


HTTP_REQUEST_LINE_RE = re.compile(
    r"(?im)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+([^\s]+)\s+HTTP/(\d(?:\.\d+)?)"
)
HTTP_RESPONSE_LINE_RE = re.compile(
    r"(?im)HTTP/(\d(?:\.\d+)?)\s+(\d{3})(?:\s+([^\r\n]*))?"
)
COMMON_HTTP_PROXY_PORTS = {
    80,
    81,
    443,
    591,
    593,
    8000,
    8008,
    8080,
    8081,
    8082,
    8083,
    8118,
    8123,
    8443,
    8880,
    8888,
    3128,
    3129,
}

_SUSPICIOUS_UA_RE = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|havij|wpscan|dirbuster|gobuster|curl/|wget/|python-requests)\b"
)
_SQLI_RE = re.compile(
    r"(?i)(\bunion\s+select\b|\bor\s+1=1\b|information_schema|sleep\(|benchmark\(|'\s*or\s*'1'='1)"
)
_TRAVERSAL_RE = re.compile(r"(?i)(\.\./|%2e%2e%2f|%252e%252e%252f)")
_CMD_INJECT_RE = re.compile(
    r"(?i)(;|\|\||&&|\$\(|`)(?:[^\\n\\r]{0,80})(cmd|sh|bash|powershell|whoami|curl|wget)"
)
_SSRF_RE = re.compile(
    r"(?i)(https?://)?(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0)"
)
_LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{200,}={0,2}\b")
_CRED_KEYS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "auth",
    "authorization",
}


@dataclass(frozen=True)
class WebRequestEntry:
    packet_number: int
    ts: Optional[float]
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    target_role: str
    method: str
    host: str
    uri: str
    http_version: str
    params: list[tuple[str, str]]
    headers: dict[str, str]
    request_line: str
    body: str
    response_code: Optional[int]
    response_name: str
    response_location: str
    risk_score: int
    risk_level: str
    risk_reasons: list[str]


@dataclass(frozen=True)
class WebRequestSummary:
    path: Path
    target_ip: str
    post_only: bool
    scoped: bool
    total_packets: int
    http_packets: int
    matched_requests: int
    method_counts: Counter[str]
    request_port_counts: Counter[int]
    proxy_port_counts: Counter[int]
    host_counts: Counter[str]
    uri_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    risk_level_counts: Counter[str]
    suspicious_requests: int
    requests: list[WebRequestEntry]
    errors: list[str]
    high_only: bool = False
    search_query: str = ""
    vt_lookup_enabled: bool = False
    vt_results: dict[str, dict[str, object]] = field(default_factory=dict)
    vt_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "target_ip": self.target_ip,
            "scoped": self.scoped,
            "high_only": self.high_only,
            "search_query": self.search_query,
            "total_packets": self.total_packets,
            "http_packets": self.http_packets,
            "matched_requests": self.matched_requests,
            "method_counts": dict(self.method_counts),
            "request_port_counts": dict(self.request_port_counts),
            "proxy_port_counts": dict(self.proxy_port_counts),
            "host_counts": dict(self.host_counts),
            "uri_counts": dict(self.uri_counts),
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "risk_level_counts": dict(self.risk_level_counts),
            "suspicious_requests": self.suspicious_requests,
            "requests": [
                {
                    "packet_number": item.packet_number,
                    "ts": item.ts,
                    "src_ip": item.src_ip,
                    "dst_ip": item.dst_ip,
                    "src_port": item.src_port,
                    "dst_port": item.dst_port,
                    "target_role": item.target_role,
                    "method": item.method,
                    "host": item.host,
                    "uri": item.uri,
                    "http_version": item.http_version,
                    "params": list(item.params),
                    "headers": dict(item.headers),
                    "request_line": item.request_line,
                    "body": item.body,
                    "response_code": item.response_code,
                    "response_name": item.response_name,
                    "response_location": item.response_location,
                    "risk_score": item.risk_score,
                    "risk_level": item.risk_level,
                    "risk_reasons": list(item.risk_reasons),
                }
                for item in self.requests
            ],
            "errors": list(self.errors),
            "vt_lookup_enabled": self.vt_lookup_enabled,
            "vt_results": dict(self.vt_results),
            "vt_errors": list(self.vt_errors),
        }


def _score_request(
    method: str,
    dst_ip: str,
    uri: str,
    headers: dict[str, str],
    params: list[tuple[str, str]],
    body: str,
) -> tuple[int, str, list[str]]:
    score = 0
    reasons: list[str] = []
    method_u = str(method or "").upper()
    uri_t = str(uri or "")
    body_t = str(body or "")
    ua = str(headers.get("user-agent", "") or "")
    content_type = str(headers.get("content-type", "") or "")
    combined = f"{uri_t}\n{body_t}"

    def _is_public_ip(value: str) -> bool:
        try:
            addr = ipaddress.ip_address(str(value).strip())
        except Exception:
            return False
        if getattr(addr, "is_private", False):
            return False
        if getattr(addr, "is_loopback", False):
            return False
        if getattr(addr, "is_link_local", False):
            return False
        if getattr(addr, "is_multicast", False):
            return False
        if getattr(addr, "is_reserved", False):
            return False
        if getattr(addr, "is_unspecified", False):
            return False
        return True

    if method_u in {"TRACE", "CONNECT"}:
        score += 2
        reasons.append(f"uncommon_method={method_u}")
    if method_u == "POST":
        # Baseline hunting stance: POST carries payload and deserves elevated scrutiny.
        score += 3
        reasons.append("post_request_baseline")
    if method_u == "POST" and _is_public_ip(dst_ip):
        # Deterministic baseline: outbound POST to public IP is suspicious until proven benign.
        score += 3
        reasons.append(f"post_to_public_ip={dst_ip}")
    if _SQLI_RE.search(combined):
        score += 3
        reasons.append("sqli_pattern")
    if _TRAVERSAL_RE.search(combined):
        score += 3
        reasons.append("path_traversal_pattern")
    if _CMD_INJECT_RE.search(combined):
        score += 3
        reasons.append("command_injection_pattern")
    if _SSRF_RE.search(combined):
        score += 3
        reasons.append("ssrf_internal_target")
    if _SUSPICIOUS_UA_RE.search(ua):
        score += 2
        reasons.append(f"suspicious_user_agent={ua[:60]}")

    for key, value in params:
        k = str(key or "").strip().lower()
        v = str(value or "")
        if k in _CRED_KEYS and v:
            if method_u == "GET":
                score += 3
                reasons.append(f"credential_in_get_param={k}")
            else:
                score += 1
                reasons.append(f"credential_param={k}")
        if _SSRF_RE.search(v):
            score += 2
            reasons.append(f"ssrf_param={k}")

    body_l = body_t.lower()
    for key in _CRED_KEYS:
        if f"{key}=" in body_l or f'"{key}"' in body_l:
            score += 2 if method_u == "GET" else 1
            reasons.append(f"credential_marker_in_body={key}")
            break
    if _LONG_B64_RE.search(body_t):
        score += 2
        reasons.append("long_base64_blob")
    if len(body_t) >= 50000:
        score += 1
        reasons.append(f"large_body={len(body_t)}")
    if "multipart/form-data" in content_type.lower() and (
        "../" in uri_t or _TRAVERSAL_RE.search(body_t)
    ):
        score += 2
        reasons.append("suspicious_upload_pattern")

    if score >= 6:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"
    return score, level, reasons


def _ip_pair(pkt: Packet) -> tuple[str, str]:
    if IP is not None and IP in pkt:
        return str(pkt[IP].src), str(pkt[IP].dst)
    if IPv6 is not None and IPv6 in pkt:
        return str(pkt[IPv6].src), str(pkt[IPv6].dst)
    return "0.0.0.0", "0.0.0.0"


def _ports(pkt: Packet) -> tuple[Optional[int], Optional[int]]:
    if TCP is None or TCP not in pkt:
        return None, None
    try:
        return int(pkt[TCP].sport), int(pkt[TCP].dport)
    except Exception:
        return None, None


def _payload(pkt: Packet) -> bytes:
    if Raw is not None and Raw in pkt:
        try:
            return bytes(pkt[Raw])
        except Exception:
            return b""
    if TCP is not None and TCP in pkt:
        try:
            return bytes(pkt[TCP].payload)
        except Exception:
            return b""
    return b""


def _safe_decode(data: bytes) -> str:
    try:
        return data.decode("latin-1", errors="ignore")
    except Exception:
        return ""


def _parse_headers(lines: list[str]) -> tuple[dict[str, str], int]:
    headers: dict[str, str] = {}
    body_start = len(lines)
    for idx, line in enumerate(lines):
        if not line.strip():
            body_start = idx + 1
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_n = key.strip().lower()
        value_n = value.strip()
        if key_n and value_n:
            headers[key_n] = value_n
    return headers, body_start


def _extract_request_from_block(
    method: str, uri: str, http_version: str, block: str, body: str
) -> dict[str, object]:
    lines = block.splitlines()
    headers, body_start = _parse_headers(lines[1:])
    host = headers.get("host", "").strip()
    parsed = None
    try:
        parsed = urlsplit(uri)
    except Exception:
        parsed = None
    if (not host) and parsed is not None and parsed.hostname:
        host = str(parsed.hostname)
    params: list[tuple[str, str]] = []
    try:
        if parsed is None:
            parsed = urlsplit(uri)
        params = [
            (str(k), str(v)) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    except Exception:
        params = []
    return {
        "method": method,
        "uri": uri,
        "http_version": http_version,
        "host": host,
        "headers": headers,
        "params": params,
        "request_line": lines[0] if lines else f"{method} {uri} HTTP/{http_version}",
        "body": body,
    }


def _consume_http_requests(buffer: str) -> tuple[list[dict[str, object]], str]:
    if not buffer or "HTTP/" not in buffer:
        if len(buffer) > 262144:
            return [], buffer[-131072:]
        return [], buffer

    out: list[dict[str, object]] = []
    cursor = 0
    while True:
        match = HTTP_REQUEST_LINE_RE.search(buffer, cursor)
        if not match:
            break
        start = int(match.start())
        method = str(match.group(1) or "").upper()
        uri = str(match.group(2) or "").strip()
        http_version = str(match.group(3) or "").strip()

        line_end = buffer.find("\n", start)
        if line_end == -1:
            break

        header_end = buffer.find("\r\n\r\n", line_end)
        term_len = 4
        if header_end == -1:
            header_end = buffer.find("\n\n", line_end)
            term_len = 2
        if header_end == -1:
            # Incomplete request headers; keep from this request start.
            return out, buffer[start:]

        header_block_end = header_end + term_len
        header_block = buffer[start:header_block_end]
        header_lines = header_block.splitlines()
        headers, _body_start = _parse_headers(
            header_lines[1:] if len(header_lines) > 1 else []
        )

        content_length = 0
        cl_text = str(headers.get("content-length", "") or "").strip()
        if cl_text.isdigit():
            try:
                content_length = max(0, int(cl_text))
            except Exception:
                content_length = 0

        block_end = header_block_end + content_length
        if block_end > len(buffer):
            return out, buffer[start:]

        body_text = buffer[header_block_end:block_end] if content_length > 0 else ""
        out.append(
            _extract_request_from_block(
                method, uri, http_version, header_block, body_text
            )
        )
        cursor = block_end

    remaining = buffer[cursor:]
    if len(remaining) > 262144:
        remaining = remaining[-131072:]
    return out, remaining


def _consume_http_responses(buffer: str) -> tuple[list[tuple[int, str, str]], str]:
    if not buffer or "HTTP/" not in buffer:
        if len(buffer) > 262144:
            return [], buffer[-131072:]
        return [], buffer

    out: list[tuple[int, str, str]] = []
    cursor = 0
    while True:
        match = HTTP_RESPONSE_LINE_RE.search(buffer, cursor)
        if not match:
            break
        start = int(match.start())
        line_end = buffer.find("\n", start)
        if line_end == -1:
            break
        header_end = buffer.find("\r\n\r\n", line_end)
        term_len = 4
        if header_end == -1:
            header_end = buffer.find("\n\n", line_end)
            term_len = 2
        if header_end == -1:
            return out, buffer[start:]

        header_block_end = header_end + term_len
        header_block = buffer[start:header_block_end]
        header_lines = header_block.splitlines()
        headers, _body_start = _parse_headers(
            header_lines[1:] if len(header_lines) > 1 else []
        )

        code_text = str(match.group(2) or "").strip()
        reason_text = str(match.group(3) or "").strip()
        location_text = str(headers.get("location", "") or "").strip()
        try:
            code_value = int(code_text)
        except Exception:
            code_value = 0

        content_length = 0
        cl_text = str(headers.get("content-length", "") or "").strip()
        if cl_text.isdigit():
            try:
                content_length = max(0, int(cl_text))
            except Exception:
                content_length = 0

        block_end = header_block_end + content_length
        if block_end > len(buffer):
            return out, buffer[start:]

        if code_value > 0:
            out.append((code_value, reason_text, location_text))
        cursor = block_end

    remaining = buffer[cursor:]
    if len(remaining) > 262144:
        remaining = remaining[-131072:]
    return out, remaining


def analyze_webrequests(
    path: Path,
    target_ip: str | None = None,
    post_only: bool = False,
    high_only: bool = False,
    search_query: str | None = None,
    vt_lookup: bool = False,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> WebRequestSummary:
    requested_target_ip = str(target_ip or "").strip()
    errors: list[str] = []
    search_text = str(search_query or "").strip()
    search_token = search_text.lower()
    search_all_requests = bool(search_token)
    # When search is active we must search across all HTTP requests, regardless of
    # optional scope/high/post filters.
    target_ip_value = "" if search_all_requests else requested_target_ip
    scoped = bool(target_ip_value)
    post_filter_enabled = bool(post_only and not search_all_requests)
    high_filter_enabled = bool(high_only and not search_all_requests)

    def _matches_search(
        *,
        method: str,
        host: str,
        uri: str,
        request_line: str,
        headers: dict[str, str],
        params: list[tuple[str, str]],
        body: str,
        response_code: Optional[int],
        response_name: str,
        response_location: str,
    ) -> bool:
        if not search_token:
            return True
        host_t = str(host or "")
        uri_t = str(uri or "")
        combined_target = f"{host_t}{uri_t}" if host_t else uri_t
        haystack_parts: list[str] = [
            str(method or ""),
            host_t,
            uri_t,
            combined_target,
            str(request_line or ""),
            str(body or ""),
            str(response_name or ""),
            str(response_location or ""),
            str(response_code if response_code is not None else ""),
        ]
        if host_t and uri_t.startswith("/"):
            haystack_parts.append(f"http://{host_t}{uri_t}")
            haystack_parts.append(f"https://{host_t}{uri_t}")
        if headers:
            for key, value in headers.items():
                haystack_parts.append(f"{key}: {value}")
        if params:
            for key, value in params:
                haystack_parts.append(f"{key}={value}")
        haystack = "\n".join(haystack_parts).lower()
        return search_token in haystack

    if TCP is None:
        return WebRequestSummary(
            path=path,
            target_ip=target_ip_value or "ALL",
            post_only=post_filter_enabled,
            high_only=high_filter_enabled,
            scoped=scoped,
            total_packets=0,
            http_packets=0,
            matched_requests=0,
            method_counts=Counter(),
            request_port_counts=Counter(),
            proxy_port_counts=Counter(),
            host_counts=Counter(),
            uri_counts=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            risk_level_counts=Counter(),
            suspicious_requests=0,
            requests=[],
            errors=[
                "Scapy TCP layers unavailable; install scapy for web request analysis."
            ],
            search_query=search_text,
            vt_lookup_enabled=bool(vt_lookup),
            vt_results={},
            vt_errors=[],
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return WebRequestSummary(
            path=path,
            target_ip=target_ip_value or "ALL",
            post_only=post_filter_enabled,
            high_only=high_filter_enabled,
            scoped=scoped,
            total_packets=0,
            http_packets=0,
            matched_requests=0,
            method_counts=Counter(),
            request_port_counts=Counter(),
            proxy_port_counts=Counter(),
            host_counts=Counter(),
            uri_counts=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            risk_level_counts=Counter(),
            suspicious_requests=0,
            requests=[],
            errors=[f"Error opening pcap: {exc}"],
            search_query=search_text,
            vt_lookup_enabled=bool(vt_lookup),
            vt_results={},
            vt_errors=[],
        )

    total_packets = 0
    http_packets = 0
    method_counts: Counter[str] = Counter()
    request_port_counts: Counter[int] = Counter()
    proxy_port_counts: Counter[int] = Counter()
    host_counts: Counter[str] = Counter()
    uri_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    risk_level_counts: Counter[str] = Counter()
    requests: list[WebRequestEntry] = []
    stream_buffers: dict[tuple[str, str, int, int], str] = {}
    response_stream_buffers: dict[tuple[str, str, int, int], str] = {}
    response_queues: dict[tuple[str, str, int, int], list[tuple[int, str, str]]] = {}

    try:
        for pkt in reader:
            total_packets += 1
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            if TCP is None or TCP not in pkt:
                continue
            src_ip, dst_ip = _ip_pair(pkt)  # type: ignore[arg-type]
            if scoped and src_ip != target_ip_value and dst_ip != target_ip_value:
                continue

            src_port, dst_port = _ports(pkt)  # type: ignore[arg-type]
            payload = _payload(pkt)  # type: ignore[arg-type]
            if not payload:
                continue
            text = _safe_decode(payload)
            if not text:
                continue
            s_port = int(src_port or 0)
            d_port = int(dst_port or 0)
            stream_key = (src_ip, dst_ip, s_port, d_port)

            existing_resp = response_stream_buffers.get(stream_key, "")
            combined_resp = existing_resp + text
            parsed_responses, remaining_resp = _consume_http_responses(combined_resp)
            response_stream_buffers[stream_key] = remaining_resp
            if parsed_responses and s_port > 0 and d_port > 0:
                conv_key = (dst_ip, src_ip, d_port, s_port)
                queue = response_queues.setdefault(conv_key, [])
                queue.extend(parsed_responses)

            existing = stream_buffers.get(stream_key, "")
            combined = existing + text
            parsed_requests, remaining = _consume_http_requests(combined)
            stream_buffers[stream_key] = remaining
            if not parsed_requests:
                continue
            http_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            target_role = (
                "client"
                if (scoped and src_ip == target_ip_value)
                else ("server" if scoped else "unscoped")
            )
            for item in parsed_requests:
                method = str(item.get("method", "") or "-")
                host = str(item.get("host", "") or "-")
                uri = str(item.get("uri", "") or "-")
                headers = dict(item.get("headers", {}) or {})
                params = list(item.get("params", []) or [])
                body = str(item.get("body", "") or "")
                risk_score, risk_level, risk_reasons = _score_request(
                    method, dst_ip, uri, headers, params, body
                )
                response_code: Optional[int] = None
                response_name = "-"
                response_location = ""
                if s_port > 0 and d_port > 0:
                    conv_key = (src_ip, dst_ip, s_port, d_port)
                    queue = response_queues.get(conv_key, [])
                    if queue:
                        code_value, reason_value, location_value = queue.pop(0)
                        response_code = int(code_value)
                        response_name = str(reason_value or "").strip() or "-"
                        response_location = str(location_value or "").strip()
                request_line = str(item.get("request_line", "") or "")
                if not _matches_search(
                    method=method,
                    host=host,
                    uri=uri,
                    request_line=request_line,
                    headers=headers,
                    params=params,
                    body=body,
                    response_code=response_code,
                    response_name=response_name,
                    response_location=response_location,
                ):
                    continue
                if post_filter_enabled and method.upper() != "POST":
                    continue
                if high_filter_enabled and str(risk_level).lower() == "low":
                    continue
                risk_level_counts[risk_level] += 1
                method_counts[method] += 1
                request_port = int(dst_port or 0)
                if request_port > 0:
                    request_port_counts[request_port] += 1
                    if request_port in COMMON_HTTP_PROXY_PORTS:
                        proxy_port_counts[request_port] += 1
                if host and host != "-":
                    host_counts[host] += 1
                if uri and uri != "-":
                    uri_counts[uri] += 1
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1
                requests.append(
                    WebRequestEntry(
                        packet_number=total_packets,
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        target_role=target_role,
                        method=method,
                        host=host,
                        uri=uri,
                        http_version=str(item.get("http_version", "") or "-"),
                        params=params,
                        headers=headers,
                        request_line=request_line,
                        body=body,
                        response_code=response_code,
                        response_name=response_name,
                        response_location=response_location,
                        risk_score=risk_score,
                        risk_level=risk_level,
                        risk_reasons=risk_reasons,
                    )
                )
    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    requests.sort(
        key=lambda item: (
            item.packet_number,
            item.src_ip,
            item.dst_ip,
            item.method,
            item.uri,
        )
    )

    vt_results: dict[str, dict[str, object]] = {}
    vt_errors: list[str] = []
    if vt_lookup:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            vt_errors.append("VT_API_KEY is not set; skipping VirusTotal lookups.")
        else:
            def _normalized_domain(host_value: str) -> str:
                host_text = str(host_value or "").strip().lower()
                if not host_text:
                    return ""
                if host_text.startswith("[") and "]" in host_text:
                    host_text = host_text[1 : host_text.index("]")]
                elif ":" in host_text and host_text.count(":") == 1:
                    candidate, maybe_port = host_text.rsplit(":", 1)
                    if maybe_port.isdigit():
                        host_text = candidate
                try:
                    ipaddress.ip_address(host_text)
                    return ""
                except Exception:
                    pass
                if "." not in host_text:
                    return ""
                return host_text.strip(".")

            ranked_hosts = [
                host
                for host, _count in host_counts.most_common(80)
                if _normalized_domain(host)
            ]
            vt_domains = [_normalized_domain(host) for host in ranked_hosts]
            vt_domains = [domain for domain in vt_domains if domain]
            if vt_domains:
                vt_results, vt_errors = _vt_lookup_domains(vt_domains, api_key)
                errors.extend(vt_errors)

    return WebRequestSummary(
        path=path,
        target_ip=target_ip_value or "ALL",
        post_only=post_filter_enabled,
        high_only=high_filter_enabled,
        scoped=scoped,
        total_packets=total_packets,
        http_packets=http_packets,
        matched_requests=len(requests),
        method_counts=method_counts,
        request_port_counts=request_port_counts,
        proxy_port_counts=proxy_port_counts,
        host_counts=host_counts,
        uri_counts=uri_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        risk_level_counts=risk_level_counts,
        suspicious_requests=sum(
            1 for req in requests if req.risk_level in {"medium", "high"}
        ),
        requests=requests,
        errors=errors,
        search_query=search_text,
        vt_lookup_enabled=bool(vt_lookup),
        vt_results=vt_results,
        vt_errors=vt_errors,
    )


def merge_webrequests_summaries(
    summaries: Iterable[WebRequestSummary],
) -> WebRequestSummary:
    summary_list = list(summaries)
    if not summary_list:
        return WebRequestSummary(
            path=Path("ALL_PCAPS_0"),
            target_ip="-",
            post_only=False,
            high_only=False,
            scoped=False,
            total_packets=0,
            http_packets=0,
            matched_requests=0,
            method_counts=Counter(),
            request_port_counts=Counter(),
            proxy_port_counts=Counter(),
            host_counts=Counter(),
            uri_counts=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            risk_level_counts=Counter(),
            suspicious_requests=0,
            requests=[],
            errors=[],
            search_query="",
            vt_lookup_enabled=False,
            vt_results={},
            vt_errors=[],
        )

    total_packets = sum(int(item.total_packets) for item in summary_list)
    http_packets = sum(int(item.http_packets) for item in summary_list)
    method_counts: Counter[str] = Counter()
    request_port_counts: Counter[int] = Counter()
    proxy_port_counts: Counter[int] = Counter()
    host_counts: Counter[str] = Counter()
    uri_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    risk_level_counts: Counter[str] = Counter()
    requests: list[WebRequestEntry] = []
    errors: set[str] = set()
    target_ip = str(summary_list[0].target_ip)
    post_only = bool(summary_list[0].post_only)
    high_only = bool(getattr(summary_list[0], "high_only", False))
    search_query = str(getattr(summary_list[0], "search_query", "") or "")
    vt_lookup_enabled = any(
        bool(getattr(item, "vt_lookup_enabled", False)) for item in summary_list
    )
    merged_vt_results: dict[str, dict[str, object]] = {}
    merged_vt_errors: set[str] = set()
    scoped = bool(summary_list[0].scoped)

    seen_requests: set[tuple[object, ...]] = set()
    for item in summary_list:
        method_counts.update(item.method_counts)
        request_port_counts.update(item.request_port_counts)
        proxy_port_counts.update(item.proxy_port_counts)
        host_counts.update(item.host_counts)
        uri_counts.update(item.uri_counts)
        client_counts.update(item.client_counts)
        server_counts.update(item.server_counts)
        risk_level_counts.update(
            getattr(item, "risk_level_counts", Counter()) or Counter()
        )
        errors.update(str(err) for err in item.errors if str(err).strip())
        merged_vt_results.update(dict(getattr(item, "vt_results", {}) or {}))
        merged_vt_errors.update(
            str(err).strip()
            for err in list(getattr(item, "vt_errors", []) or [])
            if str(err).strip()
        )
        for req in item.requests:
            key = (
                int(req.packet_number),
                req.src_ip,
                req.dst_ip,
                req.src_port,
                req.dst_port,
                req.method,
                req.host,
                req.uri,
                req.http_version,
                req.request_line,
                req.response_code,
                req.response_name,
                req.response_location,
                req.risk_score,
                req.risk_level,
            )
            if key in seen_requests:
                continue
            seen_requests.add(key)
            requests.append(req)

    requests.sort(
        key=lambda item: (
            item.packet_number,
            item.src_ip,
            item.dst_ip,
            item.method,
            item.uri,
        )
    )
    return WebRequestSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        target_ip=target_ip,
        post_only=post_only,
        high_only=high_only,
        scoped=scoped,
        total_packets=total_packets,
        http_packets=http_packets,
        matched_requests=len(requests),
        method_counts=method_counts,
        request_port_counts=request_port_counts,
        proxy_port_counts=proxy_port_counts,
        host_counts=host_counts,
        uri_counts=uri_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        risk_level_counts=risk_level_counts,
        suspicious_requests=sum(
            1 for req in requests if req.risk_level in {"medium", "high"}
        ),
        requests=requests,
        errors=sorted(errors),
        search_query=search_query,
        vt_lookup_enabled=vt_lookup_enabled,
        vt_results=merged_vt_results,
        vt_errors=sorted(merged_vt_errors),
    )
