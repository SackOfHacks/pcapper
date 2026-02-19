from __future__ import annotations

from collections import Counter, defaultdict, OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
import base64
import hashlib
import ipaddress
import json
import re
import os
import time
import urllib.error
import urllib.request

from .pcap_cache import PcapMeta, get_reader

from .utils import safe_float, detect_file_type, detect_file_type_bytes, decode_payload, counter_inc, set_add_cap, setdict_add
from .device_detection import device_fingerprints_from_text, append_device_fingerprints

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

MAX_HTTP_UNIQUE = int(os.getenv("PCAPPER_MAX_HTTP_UNIQUE", "50000"))
MAX_HTTP_CONVERSATIONS = int(os.getenv("PCAPPER_MAX_HTTP_CONVERSATIONS", "50000"))
MAX_HTTP_PENDING = int(os.getenv("PCAPPER_MAX_HTTP_PENDING", "200"))
MIN_HTTP_DOWNLOAD_BYTES = int(os.getenv("PCAPPER_MIN_HTTP_DOWNLOAD_BYTES", "512"))
MAX_HTTP_DETECTION_EVIDENCE = int(os.getenv("PCAPPER_MAX_HTTP_DETECTION_EVIDENCE", "12"))
MAX_VT_CACHE = int(os.getenv("PCAPPER_VT_CACHE_SIZE", "2048"))
MAX_VT_LOOKUPS = int(os.getenv("PCAPPER_VT_MAX_LOOKUPS", "500"))
VT_TIMEOUT = float(os.getenv("PCAPPER_VT_TIMEOUT", "8"))

INTERNAL_TLDS = {
    "local",
    "lan",
    "localdomain",
    "home",
    "corp",
    "internal",
    "intranet",
}

_VT_CACHE: "OrderedDict[str, dict[str, object]]" = OrderedDict()


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
    host_ip_counts: dict[str, Counter[str]]
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
    device_fingerprints: Counter[str]
    content_types: Counter[str]
    file_artifacts: Counter[str]
    session_tokens: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    client_host_counts: dict[str, Counter[str]]
    server_host_counts: dict[str, Counter[str]]
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
            "host_ip_counts": {
                host: dict(ips) for host, ips in self.host_ip_counts.items()
            },
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
            "device_fingerprints": dict(self.device_fingerprints),
            "content_types": dict(self.content_types),
            "file_artifacts": dict(self.file_artifacts),
            "session_tokens": dict(self.session_tokens),
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "client_host_counts": {
                ip: dict(hosts) for ip, hosts in self.client_host_counts.items()
            },
            "server_host_counts": {
                ip: dict(hosts) for ip, hosts in self.server_host_counts.items()
            },
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


def _parse_content_length(headers: dict[str, str]) -> Optional[int]:
    value = headers.get("content-length", "")
    if not value:
        return None
    try:
        length = int(value.strip())
    except Exception:
        return None
    if length < 0:
        return None
    return length


def _is_internal_host(host: str) -> bool:
    if not host:
        return True
    host = host.strip(".")
    if not host or "." not in host:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        pass
    tld = host.rsplit(".", 1)[-1].lower()
    return tld in INTERNAL_TLDS


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8", errors="ignore")).decode("ascii").rstrip("=")


def _vt_lookup_domain(domain: str, api_key: str) -> tuple[Optional[dict[str, object]], Optional[str]]:
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(vt_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as resp:
            if resp.status != 200:
                return None, f"VT lookup failed for {domain}: HTTP {resp.status}"
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, None
        return None, f"VT lookup failed for {domain}: HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, f"VT lookup failed for {domain}: {exc.reason}"
    except Exception as exc:
        return None, f"VT lookup failed for {domain}: {type(exc).__name__}: {exc}"

    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    result = {
        "target": domain,
        "type": "domain",
        "harmless": int(stats.get("harmless", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "malicious": int(stats.get("malicious", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
        "reputation": attrs.get("reputation", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "report_url": f"https://www.virustotal.com/gui/domain/{domain}",
    }
    return result, None


def _vt_lookup_url(url: str, api_key: str) -> tuple[Optional[dict[str, object]], Optional[str]]:
    url_id = _vt_url_id(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(vt_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as resp:
            if resp.status != 200:
                return None, f"VT lookup failed for {url}: HTTP {resp.status}"
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, None
        return None, f"VT lookup failed for {url}: HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, f"VT lookup failed for {url}: {exc.reason}"
    except Exception as exc:
        return None, f"VT lookup failed for {url}: {type(exc).__name__}: {exc}"

    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    result = {
        "target": url,
        "type": "url",
        "harmless": int(stats.get("harmless", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "malicious": int(stats.get("malicious", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
        "reputation": attrs.get("reputation", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "report_url": f"https://www.virustotal.com/gui/url/{url_id}",
    }
    return result, None


def _vt_lookup_targets(targets: list[tuple[str, str]], api_key: str) -> tuple[list[dict[str, object]], list[str]]:
    results: list[dict[str, object]] = []
    errors: list[str] = []
    if not targets:
        return results, errors

    max_lookups = MAX_VT_LOOKUPS
    if max_lookups <= 0:
        max_lookups = len(targets)

    for idx, (kind, target) in enumerate(targets):
        if idx >= max_lookups:
            errors.append(
                f"VT lookups capped at {max_lookups} targets (set PCAPPER_VT_MAX_LOOKUPS to raise)."
            )
            break
        key = f"{kind}:{target}"
        cached = _VT_CACHE.get(key)
        if cached is not None:
            _VT_CACHE.move_to_end(key)
            results.append(cached)
            continue
        if kind == "url":
            vt_result, err = _vt_lookup_url(target, api_key)
        else:
            vt_result, err = _vt_lookup_domain(target, api_key)
        if vt_result:
            results.append(vt_result)
            _VT_CACHE[key] = vt_result
            if len(_VT_CACHE) > MAX_VT_CACHE:
                _VT_CACHE.popitem(last=False)
        if err:
            errors.append(err)
        if idx > 0:
            time.sleep(0.05)
    return results, errors


def _append_evidence(bucket: list[dict[str, object]], item: dict[str, object]) -> None:
    if len(bucket) >= MAX_HTTP_DETECTION_EVIDENCE:
        return
    bucket.append(item)


def _summarize_evidence(evidence: list[dict[str, object]]) -> tuple[Counter[str], list[int]]:
    ip_counts: Counter[str] = Counter()
    packets: list[int] = []
    for item in evidence:
        for key in ("src", "dst", "client", "server", "ip"):
            value = item.get(key)
            if value:
                ip_counts[str(value)] += 1
        pkt = item.get("packet")
        if isinstance(pkt, int):
            packets.append(pkt)
    return ip_counts, packets


def analyze_http(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    vt_lookup: bool = False,
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
            host_ip_counts={},
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
            device_fingerprints=Counter(),
            content_types=Counter(),
            file_artifacts=Counter(),
            session_tokens=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            client_host_counts={},
            server_host_counts={},
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
    host_ip_counts: dict[str, Counter[str]] = defaultdict(Counter)
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
    device_fingerprints: Counter[str] = Counter()
    content_types: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    session_tokens: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_host_counts: dict[str, Counter[str]] = defaultdict(Counter)
    server_host_counts: dict[str, Counter[str]] = defaultdict(Counter)
    version_counts: Counter[str] = Counter()
    post_payloads: list[dict[str, object]] = []
    downloads: list[dict[str, object]] = []
    risky_method_evidence: list[dict[str, object]] = []
    suspicious_ua_evidence: list[dict[str, object]] = []
    long_url_evidence: list[dict[str, object]] = []
    suspicious_file_evidence: list[dict[str, object]] = []
    error_response_evidence: list[dict[str, object]] = []
    referrer_https_to_http_evidence: list[dict[str, object]] = []
    referrer_token_evidence: list[dict[str, object]] = []
    referrer_ip_evidence: list[dict[str, object]] = []
    referrer_cross_host_evidence: list[dict[str, object]] = []

    conversations: dict[tuple[str, str], dict[str, object]] = defaultdict(lambda: {
        "requests": 0,
        "responses": 0,
        "bytes": 0,
        "methods": Counter(),
        "statuses": Counter(),
        "first_seen": None,
        "last_seen": None,
    })
    pending_requests: dict[tuple[str, int, str, int], list[dict[str, str]]] = defaultdict(list)

    clients: set[str] = set()
    servers: set[str] = set()

    skipped_conversations = 0

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    try:
        for pkt_index, pkt in enumerate(reader, start=1):
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

            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = getattr(tcp_layer, "sport", None)
            dport = getattr(tcp_layer, "dport", None)
            if sport is None or dport is None:
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

            text = decode_payload(payload, encoding="utf-8", limit=8192)
            if not text:
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
                        counter_inc(version_counts, version)
                    host = headers.get("host", "")
                    host_norm = host.lower().split(":", 1)[0] if host else ""
                    url = _extract_url(host, uri)

                    if method in ("TRACE", "CONNECT"):
                        _append_evidence(risky_method_evidence, {
                            "packet": pkt_index,
                            "src": src_ip,
                            "dst": dst_ip,
                            "method": method,
                            "host": host_norm or host,
                            "uri": uri,
                            "url": url,
                        })

                    if len(url) > 200:
                        _append_evidence(long_url_evidence, {
                            "packet": pkt_index,
                            "src": src_ip,
                            "dst": dst_ip,
                            "url": url,
                            "length": len(url),
                        })

                    referrer = headers.get("referer") or headers.get("referrer", "")
                    if referrer:
                        referrer_present += 1
                        counter_inc(referrer_counts, referrer)
                        if host_norm:
                            counter_inc(referrer_request_host_counts[referrer], host_norm)
                        scheme, ref_host, ref_path = _parse_referrer(referrer)
                        if scheme:
                            counter_inc(referrer_scheme_counts, scheme)
                        if ref_host:
                            counter_inc(referrer_host_counts, ref_host)
                            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ref_host) or ":" in ref_host:
                                counter_inc(referrer_ip_hosts, ref_host)
                                _append_evidence(referrer_ip_evidence, {
                                    "packet": pkt_index,
                                    "src": src_ip,
                                    "dst": dst_ip,
                                    "referrer_host": ref_host,
                                    "referrer": referrer,
                                    "host": host_norm or host,
                                    "uri": uri,
                                })
                        if ref_path:
                            counter_inc(referrer_path_counts, ref_path)
                        if host_norm and ref_host and ref_host != host_norm:
                            referrer_cross_host += 1
                            _append_evidence(referrer_cross_host_evidence, {
                                "packet": pkt_index,
                                "src": src_ip,
                                "dst": dst_ip,
                                "referrer_host": ref_host,
                                "host": host_norm or host,
                                "uri": uri,
                                "referrer": referrer,
                            })
                        if scheme == "https":
                            referrer_https_to_http += 1
                            _append_evidence(referrer_https_to_http_evidence, {
                                "packet": pkt_index,
                                "src": src_ip,
                                "dst": dst_ip,
                                "referrer": referrer,
                                "host": host_norm or host,
                                "uri": uri,
                            })
                        for token in _extract_tokens(referrer):
                            token_fp = _token_fingerprint(token)
                            counter_inc(referrer_token_counts, token_fp)
                            _append_evidence(referrer_token_evidence, {
                                "packet": pkt_index,
                                "src": src_ip,
                                "dst": dst_ip,
                                "token_fp": token_fp,
                                "referrer": referrer,
                                "host": host_norm or host,
                                "uri": uri,
                            })
                    else:
                        referrer_missing += 1

                    total_requests += 1
                    counter_inc(method_counts, method)
                    if host:
                        counter_inc(host_counts, host)
                    host_key = host_norm or host.lower()
                    if host_key:
                        counter_inc(host_ip_counts[host_key], dst_ip)
                        counter_inc(client_host_counts[src_ip], host_key)
                        counter_inc(server_host_counts[dst_ip], host_key)
                    counter_inc(url_counts, url)

                    ua = headers.get("user-agent", "")
                    if ua:
                        counter_inc(user_agents, ua)
                        append_device_fingerprints(device_fingerprints, device_fingerprints_from_text(ua, source="HTTP User-Agent"))
                        if any(tag in ua.lower() for tag in SUSPICIOUS_UA):
                            _append_evidence(suspicious_ua_evidence, {
                                "packet": pkt_index,
                                "src": src_ip,
                                "dst": dst_ip,
                                "user_agent": ua,
                                "host": host_norm or host,
                                "uri": uri,
                            })

                    tokens = _extract_tokens(uri)
                    for token in tokens:
                        counter_inc(session_tokens, _token_fingerprint(token))

                    filename = _extract_filename(headers, uri)
                    if filename:
                        counter_inc(file_artifacts, filename)
                        if any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXT):
                            _append_evidence(suspicious_file_evidence, {
                                "packet": pkt_index,
                                "src": src_ip,
                                "dst": dst_ip,
                                "filename": filename,
                                "host": host_norm or host,
                                "uri": uri,
                            })
                    pending_key = (src_ip, int(sport), dst_ip, int(dport))
                    if len(pending_requests[pending_key]) < MAX_HTTP_PENDING:
                        pending_requests[pending_key].append({
                            "uri": uri,
                            "filename": filename or "",
                        })

                    conv_key = (src_ip, dst_ip)
                    conv = None
                    if conv_key not in conversations and len(conversations) >= MAX_HTTP_CONVERSATIONS:
                        skipped_conversations += 1
                    else:
                        conv = conversations[conv_key]
                        conv["requests"] = int(conv["requests"]) + 1
                        counter_inc(conv["methods"], method)
                        conv["bytes"] = int(conv["bytes"]) + pkt_len
                    if conv is not None:
                        if conv["first_seen"] is None or (ts is not None and ts < conv["first_seen"]):
                            conv["first_seen"] = ts
                        if conv["last_seen"] is None or (ts is not None and ts > conv["last_seen"]):
                            conv["last_seen"] = ts

                    set_add_cap(clients, src_ip, max_size=MAX_HTTP_UNIQUE)
                    set_add_cap(servers, dst_ip, max_size=MAX_HTTP_UNIQUE)
                    counter_inc(client_counts, src_ip)
                    counter_inc(server_counts, dst_ip)

                    if method == "POST":
                        body = b""
                        if b"\r\n\r\n" in payload:
                            body = payload.split(b"\r\n\r\n", 1)[1]
                        if body:
                            content_length = headers.get("content-length", "")
                            content_type = headers.get("content-type", "")
                            sample = body[:160]
                            sample_text = decode_payload(sample, encoding="latin-1").replace("\r", " ").replace("\n", " ")
                            post_payloads.append({
                                "src": src_ip,
                                "dst": dst_ip,
                                "host": host,
                                "uri": uri,
                                "packet": pkt_index,
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
                        counter_inc(version_counts, version)
                    status_code = parts[1]
                    total_responses += 1
                    counter_inc(status_counts, status_code)

                    server = headers.get("server", "")
                    if server:
                        counter_inc(server_headers, server)
                        append_device_fingerprints(device_fingerprints, device_fingerprints_from_text(server, source="HTTP Server"))

                    content_type = headers.get("content-type", "")
                    if content_type:
                        counter_inc(content_types, content_type)
                    if status_code.startswith("4") or status_code.startswith("5"):
                        _append_evidence(error_response_evidence, {
                            "packet": pkt_index,
                            "src": src_ip,
                            "dst": dst_ip,
                            "status": status_code,
                            "server": server,
                            "content_type": content_type,
                        })

                    filename = _extract_filename(headers, "")
                    if filename:
                        counter_inc(file_artifacts, filename)
                        if any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXT):
                            _append_evidence(suspicious_file_evidence, {
                                "packet": pkt_index,
                                "src": src_ip,
                                "dst": dst_ip,
                                "filename": filename,
                            })

                    set_cookie = headers.get("set-cookie", "")
                    if set_cookie:
                        tokens = _extract_tokens(set_cookie)
                        for token in tokens:
                            counter_inc(session_tokens, _token_fingerprint(token))

                    conv_key = (dst_ip, src_ip)
                    conv = None
                    if conv_key not in conversations and len(conversations) >= MAX_HTTP_CONVERSATIONS:
                        skipped_conversations += 1
                    else:
                        conv = conversations[conv_key]
                        conv["responses"] = int(conv["responses"]) + 1
                        counter_inc(conv["statuses"], status_code)
                        conv["bytes"] = int(conv["bytes"]) + pkt_len
                    if conv is not None:
                        if conv["first_seen"] is None or (ts is not None and ts < conv["first_seen"]):
                            conv["first_seen"] = ts
                        if conv["last_seen"] is None or (ts is not None and ts > conv["last_seen"]):
                            conv["last_seen"] = ts

                    set_add_cap(servers, src_ip, max_size=MAX_HTTP_UNIQUE)
                    set_add_cap(clients, dst_ip, max_size=MAX_HTTP_UNIQUE)
                    counter_inc(server_counts, src_ip)
                    counter_inc(client_counts, dst_ip)

                    body = b""
                    if b"\r\n\r\n" in payload:
                        body = payload.split(b"\r\n\r\n", 1)[1]
                    if body:
                        content_length = _parse_content_length(headers)
                        transfer_encoding = headers.get("transfer-encoding", "").lower()
                        is_chunked = "chunked" in transfer_encoding
                        body_complete = True
                        if content_length is not None:
                            body_complete = len(body) >= content_length
                            if body_complete and len(body) > content_length:
                                body = body[:content_length]
                        elif is_chunked:
                            body_complete = b"\r\n0\r\n" in body
                        detected_type = detect_file_type_bytes(body)
                        fname = _extract_filename(headers, "")
                        pending_key = (dst_ip, int(dport), src_ip, int(sport))
                        req_info = None
                        if pending_requests.get(pending_key):
                            req_info = pending_requests[pending_key].pop(0)
                            if not pending_requests[pending_key]:
                                del pending_requests[pending_key]
                        if req_info and not fname:
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
                        mismatch = bool(
                            body_complete
                            and expected_type
                            and detected_type not in ("BINARY", expected_type)
                        )
                        allow_small = content_length is not None and content_length > 0
                        if body_complete and (fname or detected_type not in ("BINARY", "HTML")) and (
                            len(body) >= MIN_HTTP_DOWNLOAD_BYTES or allow_small
                        ):
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
                                "packet": pkt_index,
                            })
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)
    if skipped_conversations:
        errors.append(f"HTTP conversation cap reached; {skipped_conversations} updates skipped.")

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

    # Use dpkt-based file discovery to align with --files parsing
    try:
        dpkt_summary = analyze_files(path, show_status=False)
    except Exception:
        dpkt_summary = None

    if dpkt_summary is not None:
        file_artifacts = Counter()
        downloads = []
        for art in dpkt_summary.artifacts:
            if getattr(art, "protocol", "") != "HTTP":
                continue
            filename = getattr(art, "filename", "") or "-"
            file_artifacts[filename] += 1
            if filename and any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXT):
                _append_evidence(suspicious_file_evidence, {
                    "packet": getattr(art, "packet_index", None),
                    "src": getattr(art, "src_ip", "-"),
                    "dst": getattr(art, "dst_ip", "-"),
                    "filename": filename,
                })
            detected_type = getattr(art, "file_type", "") or "UNKNOWN"
            content_type = getattr(art, "content_type", "") or ""
            expected_type = _expected_type_from_filename(filename, content_type)
            mismatch = bool(expected_type and detected_type not in ("BINARY", expected_type))
            size_bytes = getattr(art, "size_bytes", None)
            downloads.append({
                "src": getattr(art, "src_ip", "-"),
                "dst": getattr(art, "dst_ip", "-"),
                "filename": filename,
                "detected_type": detected_type,
                "expected_type": expected_type or "-",
                "bytes": int(size_bytes) if size_bytes is not None else 0,
                "content_type": content_type,
                "status": "-",
                "mismatch": mismatch,
                "packet": getattr(art, "packet_index", "-"),
            })
        if dpkt_summary.errors:
            errors.extend([f"HTTP file discovery (dpkt): {err}" for err in dpkt_summary.errors])

    detections: list[dict[str, object]] = []

    def _append_detection(
        severity: str,
        summary: str,
        details: str | None = None,
        *,
        evidence: list[dict[str, object]] | None = None,
        artifacts: list[str] | None = None,
    ) -> None:
        item: dict[str, object] = {
            "severity": severity,
            "summary": summary,
        }
        if details:
            item["details"] = details
        if artifacts:
            item["artifacts"] = artifacts
        if evidence:
            ip_counts, packets = _summarize_evidence(evidence)
            if ip_counts:
                item["ip_counts"] = dict(ip_counts)
            if packets:
                item["packets"] = sorted(set(packets))[:MAX_HTTP_DETECTION_EVIDENCE]
            item["evidence"] = list(evidence)
        detections.append(item)

    error_responses = sum(count for code, count in status_counts.items() if code.startswith("4") or code.startswith("5"))
    if total_responses and (error_responses / total_responses) > 0.3:
        error_codes = Counter({code: count for code, count in status_counts.items() if code.startswith("4") or code.startswith("5")})
        top_codes = [f"{code}({count})" for code, count in error_codes.most_common(5)]
        details = f"{error_responses}/{total_responses} responses are 4xx/5xx."
        if top_codes:
            details = f"{details} Top: {', '.join(top_codes)}."
        _append_detection(
            "warning",
            "High HTTP error rate",
            details,
            evidence=error_response_evidence,
            artifacts=top_codes or None,
        )

    risky_methods = Counter({m: method_counts[m] for m in method_counts if m in ("TRACE", "CONNECT")})
    if risky_methods:
        detail_methods = ", ".join(f"{m}({c})" for m, c in risky_methods.most_common())
        _append_detection(
            "warning",
            "Risky HTTP methods observed",
            f"Methods: {detail_methods}.",
            evidence=risky_method_evidence,
            artifacts=[m for m, _ in risky_methods.most_common(5)],
        )

    suspicious_ua_counts = Counter({ua: count for ua, count in user_agents.items() if any(tag in ua.lower() for tag in SUSPICIOUS_UA)})
    if suspicious_ua_counts:
        ua_details = ", ".join(f"{ua}({count})" for ua, count in suspicious_ua_counts.most_common(5))
        _append_detection(
            "warning",
            "Suspicious user agents observed",
            ua_details,
            evidence=suspicious_ua_evidence,
            artifacts=[ua for ua, _ in suspicious_ua_counts.most_common(5)],
        )

    long_urls = [url for url in url_counts if len(url) > 200]
    if long_urls:
        artifacts = [url for url in long_urls[:5]]
        _append_detection(
            "info",
            "Long URLs observed",
            f"{len(long_urls)} URL(s) longer than 200 chars.",
            evidence=long_url_evidence,
            artifacts=artifacts,
        )

    suspicious_files = [name for name in file_artifacts if any(name.lower().endswith(ext) for ext in SUSPICIOUS_EXT)]
    if suspicious_files:
        _append_detection(
            "warning",
            "Suspicious file artifacts observed",
            ", ".join(suspicious_files[:5]),
            evidence=suspicious_file_evidence,
            artifacts=suspicious_files[:10],
        )

    mismatch_downloads = [item for item in downloads if item.get("mismatch")]
    if mismatch_downloads:
        mismatch_evidence: list[dict[str, object]] = []
        mismatch_artifacts: list[str] = []
        for item in mismatch_downloads:
            filename = str(item.get("filename", "-"))
            mismatch_artifacts.append(filename)
            _append_evidence(mismatch_evidence, {
                "packet": item.get("packet"),
                "src": item.get("src"),
                "dst": item.get("dst"),
                "filename": filename,
                "detected_type": item.get("detected_type"),
                "expected_type": item.get("expected_type"),
                "bytes": item.get("bytes"),
                "status": item.get("status"),
            })
        _append_detection(
            "critical",
            "HTTP file type discrepancies",
            f"{len(mismatch_downloads)} downloads where filename/type mismatched (possible masquerading).",
            evidence=mismatch_evidence,
            artifacts=mismatch_artifacts[:10],
        )

    if post_payloads:
        post_evidence: list[dict[str, object]] = []
        for item in post_payloads:
            _append_evidence(post_evidence, {
                "packet": item.get("packet"),
                "src": item.get("src"),
                "dst": item.get("dst"),
                "host": item.get("host"),
                "uri": item.get("uri"),
                "bytes": item.get("bytes"),
                "content_type": item.get("content_type"),
            })
        _append_detection(
            "info",
            "HTTP POST payloads observed",
            f"{len(post_payloads)} POST payload(s) captured.",
            evidence=post_evidence,
        )

    if referrer_counts:
        if referrer_https_to_http:
            _append_detection(
                "info",
                "HTTPS referrer to HTTP request",
                f"{referrer_https_to_http} HTTP requests referenced HTTPS pages (mixed content/downgrade).",
                evidence=referrer_https_to_http_evidence,
            )
        if referrer_token_counts:
            token_artifacts = [token for token, _ in referrer_token_counts.most_common(8)]
            _append_detection(
                "warning",
                "Potential tokens in HTTP referrers",
                f"{sum(referrer_token_counts.values())} referrer token(s) observed.",
                evidence=referrer_token_evidence,
                artifacts=token_artifacts,
            )
        if referrer_ip_hosts:
            ip_artifacts = [host for host, _ in referrer_ip_hosts.most_common(8)]
            _append_detection(
                "warning",
                "IP-literal HTTP referrers observed",
                f"{len(referrer_ip_hosts)} referrer host(s) are IP addresses.",
                evidence=referrer_ip_evidence,
                artifacts=ip_artifacts,
            )
        if referrer_cross_host and referrer_present:
            ratio = referrer_cross_host / max(1, referrer_present)
            if ratio > 0.7:
                _append_detection(
                    "info",
                    "High cross-site HTTP referrer rate",
                    f"{referrer_cross_host}/{referrer_present} referrers point to different hosts.",
                    evidence=referrer_cross_host_evidence,
                )

    if vt_lookup:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            errors.append("VT_API_KEY is not set; skipping VirusTotal lookups.")
        else:
            target_counts: dict[tuple[str, str], int] = {}
            for host, count in host_counts.items():
                host_key = host.lower().split(":", 1)[0]
                if not host_key or _is_internal_host(host_key):
                    continue
                target_counts[("domain", host_key)] = target_counts.get(("domain", host_key), 0) + int(count)
            for url, count in url_counts.items():
                if not url:
                    continue
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
                if host and _is_internal_host(host):
                    continue
                if not parsed.hostname:
                    continue
                target_counts[("url", url)] = target_counts.get(("url", url), 0) + int(count)

            ranked_targets = [
                target for target, _count in sorted(target_counts.items(), key=lambda item: item[1], reverse=True)
            ]
            vt_findings, vt_errors = _vt_lookup_targets(ranked_targets, api_key)
            errors.extend(vt_errors)
            if vt_findings:
                vt_findings.sort(
                    key=lambda item: (
                        int(item.get("malicious", 0) or 0) > 0,
                        int(item.get("suspicious", 0) or 0) > 0,
                        int(item.get("malicious", 0) or 0),
                        int(item.get("suspicious", 0) or 0),
                        int(item.get("harmless", 0) or 0),
                    ),
                    reverse=True,
                )
                severity = "warning" if any(
                    int(item.get("malicious", 0) or 0) > 0 or int(item.get("suspicious", 0) or 0) > 0
                    for item in vt_findings
                ) else "info"
                detections.append({
                    "severity": severity,
                    "summary": "VirusTotal URL/Domain reputation",
                    "vt_findings": vt_findings,
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
        host_ip_counts=dict(host_ip_counts),
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
        device_fingerprints=device_fingerprints,
        content_types=content_types,
        file_artifacts=file_artifacts,
        session_tokens=session_tokens,
        client_counts=client_counts,
        server_counts=server_counts,
        client_host_counts=dict(client_host_counts),
        server_host_counts=dict(server_host_counts),
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
