from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import base64
import re

from .pcap_cache import PcapMeta, get_reader
from .utils import safe_float
from .ntlm import analyze_ntlm
from .kerberos import analyze_kerberos
from .smb import analyze_smb

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
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

AUTH_HEADER_RE = re.compile(r"^(authorization|proxy-authorization):\s*(.+)$", re.IGNORECASE)
DIGEST_KV_RE = re.compile(r"(\w+)=(?:\"([^\"]*)\"|([^,\s]+))")


@dataclass(frozen=True)
class CredentialArtifact:
    source: str
    auth_type: str
    username: Optional[str]
    secret: Optional[str]
    details: dict[str, object]


@dataclass(frozen=True)
class CredsSummary:
    path: Path
    total_packets: int
    http_auth_schemes: Counter[str]
    http_basic: list[CredentialArtifact]
    http_digest: list[CredentialArtifact]
    http_other: list[CredentialArtifact]
    ntlm_users: Counter[str]
    kerberos_principals: Counter[str]
    kerberos_spns: Counter[str]
    smb_sessions: list[dict[str, object]]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


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


def _parse_headers(block: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_line in block.split(b"\r\n"):
        if b":" not in raw_line:
            continue
        key, value = raw_line.split(b":", 1)
        try:
            headers[key.decode("utf-8", errors="ignore").strip().lower()] = value.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
    return headers


def _parse_basic(value: str) -> tuple[Optional[str], Optional[str]]:
    parts = value.split(None, 1)
    if len(parts) != 2:
        return None, None
    if parts[0].lower() != "basic":
        return None, None
    try:
        decoded = base64.b64decode(parts[1]).decode("utf-8", errors="ignore")
    except Exception:
        return None, None
    if ":" in decoded:
        user, password = decoded.split(":", 1)
        return user, password
    return decoded, None


def _parse_digest(value: str) -> dict[str, str]:
    parts = value.split(None, 1)
    if len(parts) != 2:
        return {}
    if parts[0].lower() != "digest":
        return {}
    matches = DIGEST_KV_RE.findall(parts[1])
    parsed: dict[str, str] = {}
    for key, qval, val in matches:
        parsed[key.lower()] = qval or val
    return parsed


def analyze_creds(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> CredsSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for credential analysis.")
        return CredsSummary(
            path=path,
            total_packets=0,
            http_auth_schemes=Counter(),
            http_basic=[],
            http_digest=[],
            http_other=[],
            ntlm_users=Counter(),
            kerberos_principals=Counter(),
            kerberos_spns=Counter(),
            smb_sessions=[],
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
    http_auth_schemes: Counter[str] = Counter()
    http_basic: list[CredentialArtifact] = []
    http_digest: list[CredentialArtifact] = []
    http_other: list[CredentialArtifact] = []

    stream_chunks: dict[tuple[str, str, int, int], list[tuple[int, bytes]]] = {}
    stream_times: dict[tuple[str, str, int, int], dict[str, Optional[float]]] = {}

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
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

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

            tcp_layer = pkt[TCP]  # type: ignore[index]
            seq = int(getattr(tcp_layer, "seq", 0))
            sport = int(getattr(tcp_layer, "sport", 0))
            dport = int(getattr(tcp_layer, "dport", 0))
            key = (src_ip, dst_ip, sport, dport)
            stream_chunks.setdefault(key, []).append((seq, payload))
            stream_times.setdefault(key, {"first_seen": None, "last_seen": None})
            if ts is not None:
                flow_ts = stream_times[key]
                if flow_ts["first_seen"] is None or ts < flow_ts["first_seen"]:
                    flow_ts["first_seen"] = ts
                if flow_ts["last_seen"] is None or ts > flow_ts["last_seen"]:
                    flow_ts["last_seen"] = ts

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    def _register_auth(header_value: str, src_ip: str, dst_ip: str, first_ts: Optional[float], last_ts: Optional[float]) -> None:
        scheme = header_value.split(None, 1)[0] if header_value else ""
        if scheme:
            http_auth_schemes[scheme.lower()] += 1

        user, password = _parse_basic(header_value)
        if user:
            http_basic.append(CredentialArtifact(
                source=f"http {src_ip}->{dst_ip}",
                auth_type="basic",
                username=user,
                secret=password,
                details={"scheme": "basic", "first_seen": first_ts, "last_seen": last_ts},
            ))
            return

        digest_fields = _parse_digest(header_value)
        if digest_fields:
            http_digest.append(CredentialArtifact(
                source=f"http {src_ip}->{dst_ip}",
                auth_type="digest",
                username=digest_fields.get("username"),
                secret=None,
                details=digest_fields | {"scheme": "digest", "first_seen": first_ts, "last_seen": last_ts},
            ))
            return

        if header_value:
            http_other.append(CredentialArtifact(
                source=f"http {src_ip}->{dst_ip}",
                auth_type=scheme.lower() if scheme else "unknown",
                username=None,
                secret=None,
                details={"value": header_value[:200], "first_seen": first_ts, "last_seen": last_ts},
            ))

    for (src_ip, dst_ip, sport, dport), chunks in stream_chunks.items():
        data = _reassemble_stream(chunks)
        if not data:
            continue
        if HTTP2_PREFACE not in data and b"HTTP/" not in data:
            continue
        flow_ts = stream_times.get((src_ip, dst_ip, sport, dport), {})
        first_ts = flow_ts.get("first_seen")
        last_ts = flow_ts.get("last_seen")

        idx = 0
        while True:
            start_idx = _find_http_start(data, idx)
            if start_idx == -1:
                break
            line_end = data.find(b"\r\n", start_idx)
            if line_end == -1:
                break
            if data[start_idx:start_idx + len(HTTP2_PREFACE)] == HTTP2_PREFACE:
                idx = start_idx + len(HTTP2_PREFACE)
                continue
            header_end = data.find(b"\r\n\r\n", line_end + 2)
            if header_end == -1:
                break
            headers = _parse_headers(data[line_end + 2:header_end])
            for key, value in headers.items():
                match = AUTH_HEADER_RE.match(f"{key}: {value}")
                if match:
                    _register_auth(value, src_ip, dst_ip, first_ts, last_ts)
            idx = header_end + 4

    ntlm_summary = analyze_ntlm(path, show_status=False)
    kerberos_summary = analyze_kerberos(path, show_status=False, packets=packets, meta=meta)
    smb_summary = analyze_smb(path, show_status=False)

    ntlm_users = Counter()
    for session in ntlm_summary.sessions:
        if session.username and session.username != "Unknown":
            if session.domain and session.domain != "Unknown":
                ntlm_users[f"{session.domain}\\{session.username}"] += 1
            else:
                ntlm_users[session.username] += 1

    kerberos_principals = kerberos_summary.principals
    kerberos_spns = kerberos_summary.spns

    smb_sessions = []
    for sess in smb_summary.sessions:
        smb_sessions.append({
            "client": sess.client_ip,
            "server": sess.server_ip,
            "username": sess.username,
            "domain": sess.domain,
            "workstation": sess.workstation,
            "auth": sess.auth_type,
            "guest": sess.is_guest,
            "smb_version": sess.smb_version,
            "signing_required": sess.signing_required,
        })

    detections: list[dict[str, object]] = []
    if http_basic:
        detections.append({
            "severity": "critical",
            "summary": "HTTP Basic credentials observed",
            "details": f"{len(http_basic)} credential(s) extracted.",
        })
    if ntlm_users:
        detections.append({
            "severity": "info",
            "summary": "NTLM authentication artifacts observed",
            "details": f"{len(ntlm_users)} user(s) seen.",
        })
    if kerberos_principals:
        detections.append({
            "severity": "info",
            "summary": "Kerberos principals observed",
            "details": f"{len(kerberos_principals)} principal(s) seen.",
        })
    if smb_sessions:
        detections.append({
            "severity": "info",
            "summary": "SMB sessions observed",
            "details": f"{len(smb_sessions)} session(s) parsed.",
        })

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return CredsSummary(
        path=path,
        total_packets=total_packets,
        http_auth_schemes=http_auth_schemes,
        http_basic=http_basic,
        http_digest=http_digest,
        http_other=http_other,
        ntlm_users=ntlm_users,
        kerberos_principals=kerberos_principals,
        kerberos_spns=kerberos_spns,
        smb_sessions=smb_sessions,
        detections=detections,
        errors=errors + ntlm_summary.errors + kerberos_summary.errors + smb_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
