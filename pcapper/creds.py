from __future__ import annotations

import base64
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, get_reader
from .services import COMMON_PORTS
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.packet import Raw, Packet  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore
    DNS = DNSQR = None  # type: ignore
    Packet = object  # type: ignore


USER_KEYS = ("user", "username", "login", "email", "account")
PASS_KEYS = ("pass", "password", "passwd", "pwd", "passcode")
TOKEN_KEYS = ("token", "apikey", "api_key", "api-key", "secret", "bearer")

USER_RE = re.compile(r"(?i)\b(user(name)?|login|email|account)\b\s*[:=]\s*([^\s&'\";]+)")
PASS_RE = re.compile(r"(?i)\b(pass(word)?|passwd|pwd|passcode)\b\s*[:=]\s*([^\s&'\";]+)")
TOKEN_RE = re.compile(r"(?i)\b(token|api[_-]?key|secret|bearer)\b\s*[:=]\s*([A-Za-z0-9._~+/=-]{6,})")
URL_USER_RE = re.compile(r"(?i)(?:^|[?&])(user(name)?|login|email|account)=([^&\s]+)")
URL_PASS_RE = re.compile(r"(?i)(?:^|[?&])(pass(word)?|passwd|pwd|passcode)=([^&\s]+)")
JSON_USER_RE = re.compile(r"(?i)\"(user(name)?|login|email|account)\"\s*:\s*\"([^\"]{1,128})\"")
JSON_PASS_RE = re.compile(r"(?i)\"(pass(word)?|passwd|pwd|passcode)\"\s*:\s*\"([^\"]{1,128})\"")

HTTP_BASIC_RE = re.compile(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]+)")
HTTP_PROXY_BASIC_RE = re.compile(r"(?i)proxy-authorization:\s*basic\s+([A-Za-z0-9+/=]+)")
HTTP_BEARER_RE = re.compile(r"(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/=-]{6,})")

FTP_USER_RE = re.compile(r"(?i)^USER\s+(.+)$")
FTP_PASS_RE = re.compile(r"(?i)^PASS\s+(.+)$")
POP_USER_RE = re.compile(r"(?i)^USER\s+(.+)$")
POP_PASS_RE = re.compile(r"(?i)^PASS\s+(.+)$")
IMAP_LOGIN_RE = re.compile(r"(?i)^\w+\s+LOGIN\s+(\"?[^\"\s]+\"?)\s+(\"?[^\"\s]+\"?)")
SMTP_AUTH_PLAIN_RE = re.compile(r"(?i)^AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)$")
SMTP_AUTH_LOGIN_RE = re.compile(r"(?i)^AUTH\s+LOGIN\s*([A-Za-z0-9+/=]+)?$")


@dataclass(frozen=True)
class CredentialHit:
    packet_number: int
    ts: Optional[float]
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    kind: str
    username: Optional[str]
    secret: Optional[str]
    evidence: str


@dataclass(frozen=True)
class CredentialSummary:
    path: Path
    total_packets: int
    matches: int
    hits: list[CredentialHit]
    truncated: bool
    kind_counts: Counter[str]
    user_counts: Counter[str]
    errors: list[str]


def _get_ip_pair(pkt: Packet) -> tuple[str, str]:
    if IP is not None and IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 is not None and IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return "0.0.0.0", "0.0.0.0"


def _get_ports(pkt: Packet) -> tuple[Optional[int], Optional[int], str]:
    if TCP is not None and TCP in pkt:
        try:
            return int(pkt[TCP].sport), int(pkt[TCP].dport), "TCP"
        except Exception:
            return None, None, "TCP"
    if UDP is not None and UDP in pkt:
        try:
            return int(pkt[UDP].sport), int(pkt[UDP].dport), "UDP"
        except Exception:
            return None, None, "UDP"
    return None, None, "OTHER"


def _service_name(sport: Optional[int], dport: Optional[int], proto: str) -> str:
    if sport is not None and sport in COMMON_PORTS:
        return COMMON_PORTS[sport]
    if dport is not None and dport in COMMON_PORTS:
        return COMMON_PORTS[dport]
    if sport is not None and proto in ("TCP", "UDP"):
        return f"{proto}/{sport}"
    return proto


def _extract_payload(pkt: Packet) -> bytes:
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
    if UDP is not None and UDP in pkt:
        try:
            return bytes(pkt[UDP].payload)
        except Exception:
            return b""
    return b""


def _safe_decode(value: bytes) -> str:
    return value.decode("latin-1", errors="ignore")


def _build_context(text: str, needle: str, max_len: int = 80) -> str:
    if not text or not needle:
        return ""
    idx = text.lower().find(needle.lower())
    if idx < 0:
        snippet = text[:max_len]
        return snippet + ("..." if len(text) > max_len else "")
    start = max(0, idx - 30)
    end = min(len(text), idx + len(needle) + 30)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    snippet = text[start:end]
    if len(snippet) > max_len:
        snippet = snippet[: max_len - 3] + "..."
        suffix = ""
    return f"{prefix}{snippet}{suffix}"


def _decode_base64(token: str) -> Optional[str]:
    if not token:
        return None
    try:
        padded = token + ("=" * (-len(token) % 4))
        decoded = base64.b64decode(padded, validate=False)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _extract_http_basic(text: str) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    for regex in (HTTP_BASIC_RE, HTTP_PROXY_BASIC_RE):
        for match in regex.finditer(text):
            token = match.group(1)
            decoded = _decode_base64(token)
            if decoded and ":" in decoded:
                user, secret = decoded.split(":", 1)
                evidence = match.group(0)
                hits.append(("HTTP Basic Auth", user, secret, evidence))
            else:
                hits.append(("HTTP Basic Auth", None, None, match.group(0)))
    for match in HTTP_BEARER_RE.finditer(text):
        token = match.group(1)
        hits.append(("HTTP Bearer Token", None, token, match.group(0)))
    return hits


def _extract_kv_creds(text: str) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    for match in USER_RE.finditer(text):
        user = match.group(3)
        hits.append(("Credential Field", user, None, match.group(0)))
    for match in PASS_RE.finditer(text):
        secret = match.group(3)
        hits.append(("Credential Field", None, secret, match.group(0)))
    for match in TOKEN_RE.finditer(text):
        token = match.group(2)
        hits.append(("Token Field", None, token, match.group(0)))

    for match in URL_USER_RE.finditer(text):
        user = match.group(3)
        hits.append(("URL Credential", user, None, match.group(0)))
    for match in URL_PASS_RE.finditer(text):
        secret = match.group(3)
        hits.append(("URL Credential", None, secret, match.group(0)))

    for match in JSON_USER_RE.finditer(text):
        user = match.group(3)
        hits.append(("JSON Credential", user, None, match.group(0)))
    for match in JSON_PASS_RE.finditer(text):
        secret = match.group(3)
        hits.append(("JSON Credential", None, secret, match.group(0)))
    return hits


def _extract_mail_auth(lines: list[str]) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    auth_login_seen = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        match = SMTP_AUTH_PLAIN_RE.match(stripped)
        if match:
            decoded = _decode_base64(match.group(1))
            if decoded and "\x00" in decoded:
                parts = decoded.split("\x00")
                if len(parts) >= 3:
                    hits.append(("SMTP AUTH PLAIN", parts[-2], parts[-1], stripped))
                else:
                    hits.append(("SMTP AUTH PLAIN", None, None, stripped))
            else:
                hits.append(("SMTP AUTH PLAIN", None, None, stripped))
            continue

        match = SMTP_AUTH_LOGIN_RE.match(stripped)
        if match:
            auth_login_seen = True
            token = match.group(1)
            if token:
                decoded = _decode_base64(token)
                hits.append(("SMTP AUTH LOGIN", None, decoded, stripped))
            continue

        if auth_login_seen:
            token = stripped
            if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", token):
                decoded = _decode_base64(token)
                if decoded:
                    hits.append(("SMTP AUTH LOGIN", None, decoded, stripped))
    return hits


def _extract_line_creds(lines: list[str]) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        ftp_user = FTP_USER_RE.match(stripped)
        if ftp_user:
            hits.append(("FTP USER", ftp_user.group(1).strip(), None, stripped))
            continue
        ftp_pass = FTP_PASS_RE.match(stripped)
        if ftp_pass:
            hits.append(("FTP PASS", None, ftp_pass.group(1).strip(), stripped))
            continue
        pop_user = POP_USER_RE.match(stripped)
        if pop_user:
            hits.append(("POP3 USER", pop_user.group(1).strip(), None, stripped))
            continue
        pop_pass = POP_PASS_RE.match(stripped)
        if pop_pass:
            hits.append(("POP3 PASS", None, pop_pass.group(1).strip(), stripped))
            continue
        imap_login = IMAP_LOGIN_RE.match(stripped)
        if imap_login:
            user = imap_login.group(1).strip("\"")
            secret = imap_login.group(2).strip("\"")
            hits.append(("IMAP LOGIN", user, secret, stripped))
            continue
    return hits


def _extract_prompt_creds(text: str) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    prompt_user = re.findall(r"(?i)\b(?:login|username|user)\b\s*[:=]\s*([^\s]+)", text)
    for user in prompt_user:
        hits.append(("Prompt Credential", user, None, _build_context(text, user)))
    prompt_pass = re.findall(r"(?i)\b(?:password|pass|passwd|pwd)\b\s*[:=]\s*([^\s]+)", text)
    for secret in prompt_pass:
        hits.append(("Prompt Credential", None, secret, _build_context(text, secret)))
    return hits


def _scan_dns(pkt: Packet) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    if DNS is None or DNSQR is None:
        return hits
    if DNS in pkt and getattr(pkt[DNS], "qd", None) is not None:
        qd = pkt[DNS].qd
        try:
            qname = qd.qname.decode("utf-8", errors="ignore") if hasattr(qd, "qname") else ""
        except Exception:
            qname = ""
        if not qname:
            return hits
        lowered = qname.lower()
        if any(token in lowered for token in USER_KEYS + PASS_KEYS + TOKEN_KEYS):
            hits.append(("DNS Query", None, None, qname))
        if "user=" in lowered or "pass=" in lowered or "token=" in lowered:
            hits.append(("DNS Query", None, None, qname))
    return hits


def analyze_creds(
    path: Path,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    max_hits: int = 200,
) -> CredentialSummary:
    if TCP is None and UDP is None and Raw is None:
        return CredentialSummary(path, 0, 0, [], False, Counter(), Counter(), ["Scapy not available"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return CredentialSummary(path, 0, 0, [], False, Counter(), Counter(), [f"Error opening pcap: {exc}"])

    total_packets = 0
    matches = 0
    hits: list[CredentialHit] = []
    errors: list[str] = []
    kind_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()

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

            payload = _extract_payload(pkt)  # type: ignore[arg-type]
            if not payload and DNS is None:
                continue

            src_ip, dst_ip = _get_ip_pair(pkt)  # type: ignore[arg-type]
            src_port, dst_port, proto = _get_ports(pkt)  # type: ignore[arg-type]
            service = _service_name(src_port, dst_port, proto)
            ts = safe_float(getattr(pkt, "time", None))

            seen: set[tuple[str, Optional[str], Optional[str], str]] = set()

            for item in _scan_dns(pkt):
                seen.add(item)

            if payload:
                text = _safe_decode(payload)
                lines = text.splitlines()

                for item in _extract_http_basic(text):
                    seen.add(item)
                for item in _extract_kv_creds(text):
                    seen.add(item)
                for item in _extract_line_creds(lines):
                    seen.add(item)
                for item in _extract_mail_auth(lines):
                    seen.add(item)
                for item in _extract_prompt_creds(text):
                    seen.add(item)

            for kind, user, secret, evidence in seen:
                matches += 1
                kind_counts[kind] += 1
                if user:
                    user_counts[user] += 1
                if len(hits) < max_hits:
                    hits.append(
                        CredentialHit(
                            packet_number=total_packets,
                            ts=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=service,
                            kind=kind,
                            username=user,
                            secret=secret,
                            evidence=evidence,
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

    truncated = matches > len(hits)
    return CredentialSummary(
        path=path,
        total_packets=total_packets,
        matches=matches,
        hits=hits,
        truncated=truncated,
        kind_counts=kind_counts,
        user_counts=user_counts,
        errors=errors,
    )
