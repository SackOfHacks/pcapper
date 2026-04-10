from __future__ import annotations

import base64
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from .pcap_cache import PcapMeta, get_reader
from .services import COMMON_PORTS
from .utils import decode_payload, safe_float

try:
    from .cip import (
        CIP_SECURITY_CLASS_IDS,
        CIP_SECURITY_PORT,
        CIP_SERVICE_NAMES,
        CIP_TCP_PORT,
        CIP_UDP_PORT,
        ENIP_COMMANDS,
        WRITE_SERVICE_CODES,
        _extract_symbol,
        _parse_cip_message,
        _parse_enip_details,
    )
except Exception:  # pragma: no cover
    CIP_TCP_PORT = 44818
    CIP_UDP_PORT = 2222
    CIP_SECURITY_PORT = 2221
    CIP_SECURITY_CLASS_IDS = set()
    CIP_SERVICE_NAMES = {}
    ENIP_COMMANDS = {}
    WRITE_SERVICE_CODES = set()
    _extract_symbol = None  # type: ignore[assignment]
    _parse_cip_message = None  # type: ignore[assignment]
    _parse_enip_details = None  # type: ignore[assignment]

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Packet, Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore
    Packet = object  # type: ignore


USER_KEYS = (
    "user",
    "username",
    "userid",
    "login",
    "loginid",
    "email",
    "account",
    "accountname",
    "principal",
    "samaccountname",
    "upn",
    "owner",
    "operator",
)
PASS_KEYS = (
    "pass",
    "password",
    "passwd",
    "pwd",
    "passcode",
    "pin",
    "pincode",
)
TOKEN_KEYS = (
    "token",
    "usertoken",
    "user_token",
    "ftusertoken",
    "ft_user_token",
    "apikey",
    "api_key",
    "api-key",
    "access_token",
    "refresh_token",
    "id_token",
    "sessionid",
    "session_token",
    "secret",
    "secret_key",
    "client_secret",
    "private_key",
    "ssh_key",
    "bearer",
)

USER_KEY_PATTERN = (
    r"(?:user(?:name|id)?|user[_-]?id|login(?:id)?|email|account(?:name)?|principal|"
    r"samaccountname|upn|owner|operator)"
)
PASS_KEY_PATTERN = r"(?:pass(?:word)?|passwd|pwd|passcode|pin(?:code)?)"
TOKEN_KEY_PATTERN = (
    r"(?:token|user[_-]?token|ft[_-]?user[_-]?token|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"secret(?:[_-]?key)?|client[_-]?secret|session(?:[_-]?(?:id|token))?|"
    r"private[_-]?key|ssh[_-]?key|bearer)"
)

USER_RE = re.compile(rf"(?i)\b{USER_KEY_PATTERN}\b\s*[:=]\s*([^\s&'\";]+)")
PASS_RE = re.compile(rf"(?i)\b{PASS_KEY_PATTERN}\b\s*[:=]\s*([^\s&'\";]+)")
TOKEN_RE = re.compile(
    rf"(?i)\b{TOKEN_KEY_PATTERN}\b\s*[:=]\s*([A-Za-z0-9._~+/=-]{{6,}})"
)
URL_USER_RE = re.compile(rf"(?i)(?:^|[?&]){USER_KEY_PATTERN}=([^&\s]+)")
URL_PASS_RE = re.compile(rf"(?i)(?:^|[?&]){PASS_KEY_PATTERN}=([^&\s]+)")
URL_TOKEN_RE = re.compile(rf"(?i)(?:^|[?&]){TOKEN_KEY_PATTERN}=([^&\s]+)")
JSON_USER_RE = re.compile(rf"(?i)\"{USER_KEY_PATTERN}\"\s*:\s*\"([^\"]{{1,128}})\"")
JSON_PASS_RE = re.compile(rf"(?i)\"{PASS_KEY_PATTERN}\"\s*:\s*\"([^\"]{{1,128}})\"")
JSON_TOKEN_RE = re.compile(rf"(?i)\"{TOKEN_KEY_PATTERN}\"\s*:\s*\"([^\"]{{6,256}})\"")
PROMPT_USER_RE = re.compile(rf"(?i)\b{USER_KEY_PATTERN}\b\s*[:=]\s*([^\s]+)")
PROMPT_SECRET_RE = re.compile(
    rf"(?i)\b(?:{PASS_KEY_PATTERN}|{TOKEN_KEY_PATTERN})\b\s*[:=]\s*([^\s]+)"
)
XML_USER_RE = re.compile(
    rf"(?is)<\s*(?:[\w.-]+:)?({USER_KEY_PATTERN})\b[^>]*>\s*([^<]{{1,1024}}?)\s*<\s*/\s*(?:[\w.-]+:)?(?:{USER_KEY_PATTERN})\s*>"
)
XML_SECRET_RE = re.compile(
    rf"(?is)<\s*(?:[\w.-]+:)?(?:{PASS_KEY_PATTERN}|{TOKEN_KEY_PATTERN})\b[^>]*>\s*([^<]{{1,4096}}?)\s*<\s*/\s*(?:[\w.-]+:)?(?:{PASS_KEY_PATTERN}|{TOKEN_KEY_PATTERN})\s*>"
)

HTTP_BASIC_RE = re.compile(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]+)")
HTTP_PROXY_BASIC_RE = re.compile(
    r"(?i)proxy-authorization:\s*basic\s+([A-Za-z0-9+/=]+)"
)
HTTP_BEARER_RE = re.compile(r"(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/=-]{6,})")
HTTP_TOKEN_AUTH_RE = re.compile(
    r"(?i)authorization:\s*(?:token|api[_-]?key)\s+([A-Za-z0-9._~+/=-]{6,})"
)
HTTP_DIGEST_USER_RE = re.compile(
    r"(?i)authorization:\s*digest[^\r\n]*\busername=\"([^\"]+)\""
)
HTTP_COOKIE_RE = re.compile(r"(?i)\bcookie:\s*([^\r\n]+)")
HTTP_NTLM_RE = re.compile(r"(?i)authorization:\s*ntlm\s+([A-Za-z0-9+/=]+)")
HTTP_REQUEST_LINE_RE = re.compile(
    r"(?im)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+([^\s]+)\s+HTTP/\d(?:\.\d+)?$"
)
HTTP_HOST_RE = re.compile(r"(?im)^Host:\s*([^\s:\r\n]+)(?::\d+)?\s*$")

FTP_USER_RE = re.compile(r"(?im)^USER\s+([^\r\n]{1,160})\s*$")
FTP_PASS_RE = re.compile(r"(?im)^PASS\s+([^\r\n]{1,160})\s*$")
POP_USER_RE = re.compile(r"(?im)^USER\s+([^\r\n]{1,160})\s*$")
POP_PASS_RE = re.compile(r"(?im)^PASS\s+([^\r\n]{1,160})\s*$")
IMAP_LOGIN_RE = re.compile(r"(?i)^\w+\s+LOGIN\s+(\"?[^\"\s]+\"?)\s+(\"?[^\"\s]+\"?)")
SMTP_AUTH_PLAIN_RE = re.compile(r"(?i)^AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)$")
SMTP_AUTH_LOGIN_RE = re.compile(r"(?i)^AUTH\s+LOGIN\s*([A-Za-z0-9+/=]+)?$")
PRIV_USER_RE = re.compile(
    r"(?i)\b(admin|administrator|root|svc_|service|backup|dbadmin|domain\\admin|krbtgt)\b"
)
PLACEHOLDER_SECRETS = {
    "admin",
    "password",
    "test",
    "123456",
    "changeme",
    "default",
    "qwerty",
}
PROMPT_LABEL_SECRET_NOISE = {
    "password",
    "passwd",
    "passcode",
    "pass phrase",
    "passphrase",
    "token",
    "secret",
    "api key",
    "username",
    "user name",
    "user id",
    "login",
}
OT_VALUE_TOKEN_BYTES_RE = re.compile(rb"[A-Za-z0-9._~!$%&*+=:@/-]{3,96}")
HTTP_METHOD_PREFIXES = (
    "GET ",
    "POST ",
    "PUT ",
    "PATCH ",
    "DELETE ",
    "HEAD ",
    "OPTIONS ",
    "TRACE ",
    "CONNECT ",
    "HTTP/1.",
    "HTTP/2",
    "PRI * HTTP/2.0",
)
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 8443}
FTP_PORTS = {20, 21, 2121}
POP3_PORTS = {110}
IMAP_PORTS = {143}
SMTP_PORTS = {25, 465, 587, 2525}
TELNET_PORTS = {23, 2323}
TFTP_PORTS = {69}
SMB_PORTS = {445, 139}
NETBIOS_PORTS = {137, 138, 139}
NTLM_SIGNATURE = b"NTLMSSP\x00"
SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"
NTLM_UNICODE_FLAG = 0x00000001
USERNAME_TOKEN_RE = re.compile(r"[A-Za-z0-9._@\\-]{3,96}")
ASCII_STRINGS_RE = re.compile(rb"[ -~]{4,96}")
UTF16LE_STRINGS_RE = re.compile(rb"(?:[ -~]\x00){4,96}")
CIP_STRING_TYPE = 0xD0
CIP_STRING2_TYPE = 0xD5
CIP_STRINGN_TYPE = 0xD9
CIP_SHORT_STRING_TYPE = 0xDA
CIP_STRING_TYPES = {
    CIP_STRING_TYPE,
    CIP_STRING2_TYPE,
    CIP_STRINGN_TYPE,
    CIP_SHORT_STRING_TYPE,
}
OT_USERNAME_NOISE = {
    "factorytalk",
    "service",
    "message",
    "router",
    "logical",
    "class",
    "attribute",
    "token",
    "auditeventlogentry",
    "newdataset",
    "diffgram",
    "table",
    "addlogentry",
    "soap",
    "envelope",
    "body",
    "comments",
    "datetimelogged",
    "transactionid",
    "attachmentcount",
    "mtkappclt120",
    "operatorinterfacecomponent",
    "operatorinterface",
    "component",
    "file",
    "directory",
    "revision",
    "checksum",
    "encoding",
    "timeout",
    "upload",
    "download",
    "transfer",
    "servicecode",
    "messagerouter",
    "status",
    "request",
    "response",
}
OT_DROP_TOKENS = {
    "class",
    "instance",
    "attribute",
    "service",
    "symbol",
    "readtag",
    "writetag",
    "set_attribute_single",
    "get_attribute_single",
}
OT_WRITE_SERVICE_CODES = set(WRITE_SERVICE_CODES) | {0x0F, 0x4C, 0x4E, 0x4F}


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
    confidence_counts: Counter[str] = field(default_factory=Counter)
    auth_abuse_sequences: list[dict[str, object]] = field(default_factory=list)
    replay_candidates: list[dict[str, object]] = field(default_factory=list)
    token_fanout: list[dict[str, object]] = field(default_factory=list)
    privileged_exposures: list[dict[str, object]] = field(default_factory=list)
    external_exposures: list[dict[str, object]] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


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
    return decode_payload(value, encoding="latin-1")


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


def _looks_reasonable_credential(value: str, max_len: int = 128) -> bool:
    token = str(value or "").strip()
    if not token or len(token) > max_len:
        return False
    if any(ch in token for ch in ("\r", "\n", "\t")):
        return False
    printable = sum(1 for ch in token if ch.isprintable())
    if printable < len(token):
        return False
    return True


def _decode_bytes_variants(decoded: bytes) -> list[str]:
    variants: list[str] = []
    for encoding in ("utf-8", "utf-16le", "latin-1"):
        try:
            text = decoded.decode(encoding, errors="ignore")
        except Exception:
            continue
        text = "".join(ch if ch.isprintable() else " " for ch in text)
        text = " ".join(text.split())
        if len(text) >= 4:
            variants.append(text)
    return list(dict.fromkeys(variants))


def _extract_bytes_strings(decoded: bytes) -> list[str]:
    values: list[str] = []
    for match in ASCII_STRINGS_RE.finditer(decoded):
        text = _clean_value(
            match.group(0).decode("ascii", errors="ignore"),
            allow_spaces=False,
            max_len=128,
        )
        if text:
            values.append(text)
    for match in UTF16LE_STRINGS_RE.finditer(decoded):
        try:
            text = match.group(0).decode("utf-16le", errors="ignore")
        except Exception:
            continue
        text = _clean_value(text, allow_spaces=False, max_len=128)
        if text:
            values.append(text)
    return list(dict.fromkeys(values))


def _decode_base64_variants(token: str) -> list[str]:
    if not token:
        return []
    try:
        padded = token + ("=" * (-len(token) % 4))
        decoded = base64.b64decode(padded, validate=False)
    except Exception:
        return []
    return _decode_bytes_variants(decoded)


def _clean_value(
    value: str, *, allow_spaces: bool = False, max_len: int = 256
) -> Optional[str]:
    candidate = unescape(value).strip().strip("\"'").strip()
    # Trim common code punctuation wrappers (for example: Password"; or 'abc',).
    while candidate and candidate[-1] in ";,)]}":
        candidate = candidate[:-1].strip()
    while candidate and candidate[:1] in "([{":
        candidate = candidate[1:].strip()
    candidate = candidate.strip("\"'").strip()
    if not candidate:
        return None
    if "<" in candidate or ">" in candidate:
        return None
    if not allow_spaces and any(ch.isspace() for ch in candidate):
        return None
    if candidate.endswith(":") and len(candidate) <= 48:
        return None
    if len(candidate) > max_len:
        candidate = candidate[:max_len]
    return candidate


def _looks_like_prompt_label_secret(value: str) -> bool:
    normalized = " ".join(str(value or "").strip().strip("\"'").split()).lower()
    if not normalized:
        return True
    return normalized in PROMPT_LABEL_SECRET_NOISE


def _is_likely_username(value: str) -> bool:
    if not value:
        return False
    token = value.strip().strip("\"'").strip()
    if not token or len(token) < 3 or len(token) > 96:
        return False
    if " " in token:
        return False
    lower = token.lower()
    if lower in OT_USERNAME_NOISE:
        return False
    if lower.startswith("0x"):
        return False
    if re.fullmatch(r"[0-9a-f]{16,}", lower):
        return False
    if re.fullmatch(r"[0-9a-f-]{32,}", lower):
        return False
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", token):
        return False
    if not re.fullmatch(r"[A-Za-z0-9._@\\-]{3,96}", token):
        return False
    return any(ch.isalpha() for ch in token)


def _is_likely_secret(value: str) -> bool:
    token = value.strip().strip("\"'").strip()
    if len(token) < 6:
        return False
    if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", token):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{16,}", token):
        return True
    has_upper = any(ch.isupper() for ch in token)
    has_lower = any(ch.islower() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    has_symbol = any(not ch.isalnum() for ch in token)
    if has_symbol and len(token) >= 8:
        return True
    # Password-like mixed complexity.
    if has_upper and has_lower and has_digit and len(token) >= 8:
        return True
    return False


def _extract_ot_username_candidates(data: bytes) -> list[str]:
    candidates: set[str] = set()
    for candidate in _extract_bytes_strings(data[:768]):
        if _is_likely_username(candidate):
            lowered = candidate.lower()
            if "." in lowered and "@" not in lowered:
                continue
            candidates.add(candidate)
    for variant in _decode_bytes_variants(data[:768]):
        for token in USERNAME_TOKEN_RE.findall(variant):
            cleaned = _clean_value(token, allow_spaces=False, max_len=96)
            if cleaned and _is_likely_username(cleaned):
                lowered = cleaned.lower()
                if "." in lowered and "@" not in lowered:
                    continue
                candidates.add(cleaned)
    return sorted(candidates)[:6]


def _extract_path_symbols(path_str: str) -> list[str]:
    if not path_str:
        return []
    values: list[str] = []
    for segment in path_str.split("/"):
        if not segment.startswith("Symbol:"):
            continue
        symbol = segment.split(":", 1)[-1].strip()
        if symbol:
            values.append(symbol)
    return values


def _parse_cip_string_value(
    data: bytes, offset: int, string_type: int
) -> tuple[Optional[str], int]:
    if offset < 0 or offset >= len(data):
        return None, 0
    if string_type == CIP_SHORT_STRING_TYPE:
        if offset + 1 > len(data):
            return None, 0
        string_len = data[offset]
        start = offset + 1
        end = start + string_len
        if end > len(data):
            return None, max(1, len(data) - offset)
        value = data[start:end].decode("latin-1", errors="ignore")
        cleaned = _clean_value(value, allow_spaces=False, max_len=96)
        return cleaned, 1 + string_len

    if string_type == CIP_STRING_TYPE:
        if offset + 2 > len(data):
            return None, 0
        string_len = int.from_bytes(data[offset : offset + 2], "little")
        start = offset + 2
        end = start + string_len
        if end > len(data):
            return None, max(2, len(data) - offset)
        value = data[start:end].decode("latin-1", errors="ignore")
        cleaned = _clean_value(value, allow_spaces=False, max_len=96)
        return cleaned, 2 + string_len

    if string_type == CIP_STRING2_TYPE:
        if offset + 2 > len(data):
            return None, 0
        string_len = int.from_bytes(data[offset : offset + 2], "little") * 2
        start = offset + 2
        end = start + string_len
        if end > len(data):
            return None, max(2, len(data) - offset)
        value = data[start:end].decode("utf-16le", errors="ignore")
        cleaned = _clean_value(value, allow_spaces=False, max_len=96)
        return cleaned, 2 + string_len

    if string_type == CIP_STRINGN_TYPE:
        if offset + 4 > len(data):
            return None, 0
        char_size = int.from_bytes(data[offset : offset + 2], "little") * 2
        char_count = int.from_bytes(data[offset + 2 : offset + 4], "little")
        if char_size not in {1, 2, 4}:
            return None, 4
        string_len = char_count * char_size
        start = offset + 4
        end = start + string_len
        if end > len(data):
            return None, max(4, len(data) - offset)
        if char_size == 1:
            value = data[start:end].decode("latin-1", errors="ignore")
        elif char_size == 2:
            value = data[start:end].decode("utf-16le", errors="ignore")
        else:
            value = data[start:end].decode("utf-32le", errors="ignore")
        cleaned = _clean_value(value, allow_spaces=False, max_len=96)
        return cleaned, 4 + string_len

    return None, 0


def _extract_cip_stringi_usernames(data: bytes) -> list[str]:
    if len(data) < 8:
        return []
    candidates: set[str] = set()
    max_start = min(96, len(data) - 8)
    for start in range(max_start + 1):
        num_entries = data[start]
        if num_entries <= 0 or num_entries > 4:
            continue
        idx = start + 1
        parsed_any = False
        valid_layout = True
        for _ in range(num_entries):
            if idx + 6 > len(data):
                valid_layout = False
                break
            lang = data[idx : idx + 3]
            if any(ch < 0x20 or ch > 0x7E for ch in lang):
                valid_layout = False
                break
            idx += 3
            string_type = data[idx]
            idx += 1
            if string_type not in CIP_STRING_TYPES:
                valid_layout = False
                break
            idx += 2  # charset
            value, consumed = _parse_cip_string_value(data, idx, string_type)
            if consumed <= 0:
                valid_layout = False
                break
            idx += consumed
            if value and _is_likely_username(value):
                candidates.add(value)
                parsed_any = True
        if valid_layout and parsed_any:
            continue
    return sorted(candidates)[:6]


def _extract_cip_length_prefixed_usernames(data: bytes) -> list[str]:
    candidates: set[str] = set()
    if len(data) >= 2:
        size8 = data[0]
        if 3 <= size8 <= 64 and 1 + size8 <= len(data):
            raw = data[1 : 1 + size8]
            for encoding in ("ascii", "utf-8", "utf-16le"):
                try:
                    text = raw.decode(encoding, errors="ignore")
                except Exception:
                    continue
                cleaned = _clean_value(text, allow_spaces=False, max_len=96)
                if cleaned and _is_likely_username(cleaned):
                    candidates.add(cleaned)
    if len(data) >= 4:
        size16 = int.from_bytes(data[0:2], "little")
        if 3 <= size16 <= 64 and 2 + size16 <= len(data):
            raw = data[2 : 2 + size16]
            for encoding in ("ascii", "utf-8", "utf-16le"):
                try:
                    text = raw.decode(encoding, errors="ignore")
                except Exception:
                    continue
                cleaned = _clean_value(text, allow_spaces=False, max_len=96)
                if cleaned and _is_likely_username(cleaned):
                    candidates.add(cleaned)
    return sorted(candidates)[:6]


def _extract_cip_service_0x37_usernames(
    path_str: str, cip_data: bytes
) -> list[tuple[str, str]]:
    source_rank = {
        "path-symbol": 0,
        "stringi": 1,
        "kv": 2,
        "prompt": 3,
        "xml": 4,
        "length-prefixed": 5,
    }
    language_tags = {
        "eng",
        "deu",
        "fra",
        "spa",
        "ita",
        "jpn",
        "kor",
        "zho",
        "rus",
        "por",
    }
    candidates: dict[str, set[str]] = {}

    def _add(candidate: str, source: str) -> None:
        cleaned = _clean_value(candidate, allow_spaces=False, max_len=96)
        if not cleaned or not _is_likely_username(cleaned):
            return
        if len(cleaned) < 4:
            return
        if cleaned.lower() in language_tags:
            return
        candidates.setdefault(cleaned, set()).add(source)

    for symbol in _extract_path_symbols(path_str):
        _add(symbol, "path-symbol")

    normalized = _normalize_printable(cip_data)
    if normalized:
        for _kind, user, _secret, _evidence in _extract_kv_creds(normalized):
            if user:
                _add(user, "kv")
        for _kind, user, _secret, _evidence in _extract_prompt_creds(normalized):
            if user:
                _add(user, "prompt")
        for _kind, user, _secret, _evidence in _extract_xml_creds(normalized):
            if user:
                _add(user, "xml")

    for candidate in _extract_cip_stringi_usernames(cip_data):
        _add(candidate, "stringi")
    for candidate in _extract_cip_length_prefixed_usernames(cip_data):
        _add(candidate, "length-prefixed")

    ordered = sorted(
        candidates.items(),
        key=lambda item: (
            min(source_rank.get(src, 99) for src in item[1]),
            item[0],
        ),
    )
    results: list[tuple[str, str]] = []
    for username, sources in ordered[:6]:
        source_text = ",".join(
            sorted(sources, key=lambda src: source_rank.get(src, 99))
        )
        results.append((username, source_text))
    return results


def _decode_base64_bytes(token: str) -> Optional[bytes]:
    if not token:
        return None
    try:
        padded = token + ("=" * (-len(token) % 4))
        return base64.b64decode(padded, validate=False)
    except Exception:
        return None


def _read_ntlm_secbuf(payload: bytes, base: int, field_offset: int) -> bytes:
    start = base + field_offset
    if start + 8 > len(payload):
        return b""
    length = int.from_bytes(payload[start : start + 2], "little")
    data_offset = int.from_bytes(payload[start + 4 : start + 8], "little")
    if length <= 0:
        return b""
    data_start = base + data_offset
    data_end = data_start + length
    if data_start < base or data_end > len(payload):
        return b""
    return payload[data_start:data_end]


def _decode_ntlm_text(
    data: bytes, *, unicode_text: bool, max_len: int = 96
) -> Optional[str]:
    if not data:
        return None
    try:
        text = data.decode("utf-16le" if unicode_text else "latin-1", errors="ignore")
    except Exception:
        return None
    return _clean_value(text, allow_spaces=False, max_len=max_len)


def _extract_ntlm_credentials(
    payload: bytes, source: str
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    cursor = 0
    while cursor < len(payload):
        idx = payload.find(NTLM_SIGNATURE, cursor)
        if idx < 0:
            break
        cursor = idx + len(NTLM_SIGNATURE)
        if idx + 12 > len(payload):
            continue
        try:
            msg_type = int.from_bytes(payload[idx + 8 : idx + 12], "little")
        except Exception:
            continue
        if msg_type != 3:
            continue

        flags = 0
        if idx + 64 <= len(payload):
            flags = int.from_bytes(payload[idx + 60 : idx + 64], "little")
        is_unicode = bool(flags & NTLM_UNICODE_FLAG)

        lm_resp = _read_ntlm_secbuf(payload, idx, 12)
        nt_resp = _read_ntlm_secbuf(payload, idx, 20)
        domain_raw = _read_ntlm_secbuf(payload, idx, 28)
        user_raw = _read_ntlm_secbuf(payload, idx, 36)
        workstation_raw = _read_ntlm_secbuf(payload, idx, 44)

        user = _decode_ntlm_text(user_raw, unicode_text=is_unicode, max_len=96)
        if user and not _is_likely_username(user):
            user = None
        domain = _decode_ntlm_text(domain_raw, unicode_text=is_unicode, max_len=96)
        workstation = _decode_ntlm_text(
            workstation_raw, unicode_text=is_unicode, max_len=96
        )

        response_blob = nt_resp or lm_resp
        response_secret = response_blob.hex()[:128] if response_blob else None

        evidence_parts = [f"{source} NTLM Type3"]
        if domain:
            evidence_parts.append(f"domain={domain}")
        if workstation:
            evidence_parts.append(f"workstation={workstation}")
        evidence = " ".join(evidence_parts)

        if user:
            hits.append(("NTLM Authenticate User", user, None, evidence))
        if user and response_secret:
            hits.append(
                (
                    "NTLM Challenge Response",
                    user,
                    response_secret,
                    f"{evidence} response={response_secret[:32]}...",
                )
            )
    return hits


def _ports_match(sport: Optional[int], dport: Optional[int], ports: set[int]) -> bool:
    return (sport in ports) or (dport in ports)


def _looks_like_http(
    text: str, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service.startswith("HTTP") or _ports_match(sport, dport, HTTP_PORTS):
        return True
    sample = text[:2048].lstrip()
    if any(sample.startswith(prefix) for prefix in HTTP_METHOD_PREFIXES):
        return True
    lowered = sample.lower()
    if "\r\nhost:" in lowered or "\nhost:" in lowered:
        return True
    return False


def _looks_like_ftp(
    text: str, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service == "FTP" or _ports_match(sport, dport, FTP_PORTS):
        return True
    lines = [line.strip() for line in text.splitlines() if line.strip()][:12]
    cmd_hits = sum(
        1
        for line in lines
        if re.match(
            r"(?i)^(USER|PASS|ACCT|AUTH|SYST|FEAT|CWD|PWD|TYPE|PASV|PORT|RETR|STOR)\b",
            line,
        )
    )
    response_hits = sum(1 for line in lines if re.match(r"^\d{3}[ -]", line))
    return cmd_hits >= 2 or (cmd_hits >= 1 and response_hits >= 1)


def _looks_like_pop3(
    text: str, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service == "POP3" or _ports_match(sport, dport, POP3_PORTS):
        return True
    lines = [line.strip() for line in text.splitlines() if line.strip()][:12]
    cmd_hits = sum(
        1 for line in lines if re.match(r"(?i)^(USER|PASS|APOP|AUTH)\b", line)
    )
    response_hits = sum(
        1 for line in lines if line.startswith("+OK") or line.startswith("-ERR")
    )
    return cmd_hits >= 2 or (cmd_hits >= 1 and response_hits >= 1)


def _looks_like_imap(
    text: str, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service == "IMAP" or _ports_match(sport, dport, IMAP_PORTS):
        return True
    lines = [line.strip() for line in text.splitlines() if line.strip()][:12]
    return any(re.match(r"(?i)^\w+\s+LOGIN\s+", line) for line in lines)


def _looks_like_smtp(
    text: str, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service == "SMTP" or _ports_match(sport, dport, SMTP_PORTS):
        return True
    lines = [line.strip() for line in text.splitlines() if line.strip()][:12]
    cmd_hits = sum(
        1
        for line in lines
        if re.match(r"(?i)^(EHLO|HELO|AUTH|MAIL FROM|RCPT TO|DATA)\b", line)
    )
    response_hits = sum(1 for line in lines if re.match(r"^\d{3}[ -]", line))
    return cmd_hits >= 1 and response_hits >= 1


def _looks_like_telnet(
    text: str, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service == "Telnet" or _ports_match(sport, dport, TELNET_PORTS):
        return True
    lowered = text[:2048].lower()
    return (
        "login:" in lowered or "username:" in lowered or "password:" in lowered
    ) and ("telnet" in lowered or "login:" in lowered)


def _looks_like_tftp(
    payload: bytes, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service == "TFTP" or _ports_match(sport, dport, TFTP_PORTS):
        return True
    if len(payload) < 2:
        return False
    opcode = int.from_bytes(payload[:2], "big")
    return opcode in {1, 2, 3, 4, 5, 6}


def _looks_like_smb_netbios(
    payload: bytes, sport: Optional[int], dport: Optional[int], service: str
) -> bool:
    if service in {"SMB", "NetBIOS"}:
        return True
    if _ports_match(sport, dport, SMB_PORTS | NETBIOS_PORTS):
        return True
    if payload.startswith(SMB1_MAGIC) or payload.startswith(SMB2_MAGIC):
        return True
    return NTLM_SIGNATURE in payload


def _extract_http_basic(
    text: str,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
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
    for match in HTTP_TOKEN_AUTH_RE.finditer(text):
        token = match.group(1)
        hits.append(("HTTP Token Auth", None, token, match.group(0)))
    for match in HTTP_NTLM_RE.finditer(text):
        token = match.group(1)
        decoded_bytes = _decode_base64_bytes(token)
        if decoded_bytes:
            for item in _extract_ntlm_credentials(decoded_bytes, "HTTP/NTLM"):
                hits.append(item)
        else:
            cleaned = _clean_value(token, allow_spaces=False, max_len=256)
            if cleaned:
                hits.append(("HTTP NTLM Token", None, cleaned, match.group(0)))
    for match in HTTP_DIGEST_USER_RE.finditer(text):
        user = _clean_value(match.group(1), allow_spaces=False, max_len=128)
        if user:
            hits.append(("HTTP Digest Auth", user, None, match.group(0)))
    for match in HTTP_COOKIE_RE.finditer(text):
        raw_cookie = match.group(1)
        for item in raw_cookie.split(";"):
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            key_l = key.strip().lower().replace("-", "").replace("_", "")
            cleaned = _clean_value(value, allow_spaces=False, max_len=256)
            if not cleaned:
                continue
            if key_l in {
                "user",
                "username",
                "userid",
                "login",
                "loginid",
                "email",
                "account",
            }:
                hits.append(
                    (
                        "HTTP Cookie Credential",
                        cleaned,
                        None,
                        f"Cookie: {key.strip()}={value.strip()}",
                    )
                )
            elif key_l in {
                "token",
                "usertoken",
                "ftusertoken",
                "apikey",
                "accesstoken",
                "refreshtoken",
                "idtoken",
                "sessionid",
                "sessiontoken",
                "secret",
                "secretkey",
                "clientsecret",
                "privatekey",
                "sshkey",
                "bearer",
                "password",
                "passwd",
                "passcode",
                "pwd",
            }:
                hits.append(
                    (
                        "HTTP Cookie Credential",
                        None,
                        cleaned,
                        f"Cookie: {key.strip()}={value.strip()}",
                    )
                )
    return hits


def _extract_http_query_creds(
    text: str,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    seen: set[tuple[str, Optional[str], Optional[str], str]] = set()
    user_keys = {
        "user",
        "username",
        "userid",
        "login",
        "loginid",
        "email",
        "account",
        "accountname",
        "ut",
        "uid",
        "uname",
        "user_name",
    }

    def _add_hit(
        kind: str, user: Optional[str], secret: Optional[str], evidence: str
    ) -> None:
        item = (kind, user, secret, evidence[:220])
        if item in seen:
            return
        seen.add(item)
        hits.append(item)

    for _method, raw_uri in HTTP_REQUEST_LINE_RE.findall(text):
        uri = str(raw_uri or "").strip()
        if not uri:
            continue
        query = ""
        try:
            if "://" in uri:
                query = urlsplit(uri).query
            else:
                normalized = uri if uri.startswith("/") else f"/{uri}"
                query = urlsplit(f"http://local{normalized}").query
        except Exception:
            query = ""
        if not query and "?" in uri:
            query = uri.split("?", 1)[1]
        if not query:
            continue

        for key_raw, value_raw in parse_qsl(query, keep_blank_values=False):
            key = str(key_raw or "").strip()
            key_n = key.lower().replace("-", "_")
            value = unquote_plus(str(value_raw or ""))
            cleaned = _clean_value(value, allow_spaces=False, max_len=256)
            if not cleaned:
                continue

            # Common username-style keys in query strings.
            if key_n in user_keys:
                candidate = re.split(r"[!,:;|/\\]+", cleaned, maxsplit=1)[0]
                user = _clean_value(candidate, allow_spaces=False, max_len=96)
                if user and _is_likely_username(user):
                    _add_hit("HTTP Query Username", user, None, f"{key}={cleaned}")

            # Privileged account hints embedded in non-standard keys (for example guid=ADMINISTRATOR!HOST!...)
            for token in re.split(r"[!,:;|/\\]+", cleaned):
                candidate = _clean_value(token, allow_spaces=False, max_len=96)
                if not candidate:
                    continue
                if PRIV_USER_RE.search(candidate) and _is_likely_username(candidate):
                    _add_hit(
                        "HTTP Query Privileged Username",
                        candidate,
                        None,
                        f"{key}={cleaned}",
                    )

    return hits


def _extract_http_query_creds_from_uri(
    uri: str,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    text = str(uri or "").strip()
    if not text or "?" not in text:
        return []
    synthetic = f"GET {text} HTTP/1.1"
    return _extract_http_query_creds(synthetic)


def _extract_http_request_urls(text: str) -> list[str]:
    urls: list[str] = []
    hosts = [str(v).strip() for v in HTTP_HOST_RE.findall(text or "") if str(v).strip()]
    host = hosts[0] if hosts else ""
    for _method, raw_uri in HTTP_REQUEST_LINE_RE.findall(text or ""):
        uri = str(raw_uri or "").strip()
        if not uri:
            continue
        if "://" in uri:
            urls.append(uri)
            continue
        normalized = uri if uri.startswith("/") else f"/{uri}"
        if host:
            urls.append(f"http://{host}{normalized}")
        else:
            urls.append(normalized)
    return urls


def _extract_kv_creds(
    text: str, *, kind_prefix: str = ""
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    for match in USER_RE.finditer(text):
        user = _clean_value(match.group(1), allow_spaces=False, max_len=128)
        if user:
            hits.append((f"{kind_prefix}Credential Field", user, None, match.group(0)))
    for match in PASS_RE.finditer(text):
        secret = _clean_value(match.group(1), allow_spaces=False, max_len=256)
        if secret:
            hits.append(
                (f"{kind_prefix}Credential Field", None, secret, match.group(0))
            )
    for match in TOKEN_RE.finditer(text):
        token = _clean_value(match.group(1), allow_spaces=False, max_len=512)
        if token:
            hits.append((f"{kind_prefix}Token Field", None, token, match.group(0)))

    for match in URL_USER_RE.finditer(text):
        user = _clean_value(match.group(1), allow_spaces=False, max_len=128)
        if user:
            hits.append((f"{kind_prefix}URL Credential", user, None, match.group(0)))
    for match in URL_PASS_RE.finditer(text):
        secret = _clean_value(match.group(1), allow_spaces=False, max_len=256)
        if secret:
            hits.append((f"{kind_prefix}URL Credential", None, secret, match.group(0)))
    for match in URL_TOKEN_RE.finditer(text):
        token = _clean_value(match.group(1), allow_spaces=False, max_len=512)
        if token:
            hits.append((f"{kind_prefix}URL Token", None, token, match.group(0)))

    for match in JSON_USER_RE.finditer(text):
        user = _clean_value(match.group(1), allow_spaces=False, max_len=128)
        if user:
            hits.append((f"{kind_prefix}JSON Credential", user, None, match.group(0)))
    for match in JSON_PASS_RE.finditer(text):
        secret = _clean_value(match.group(1), allow_spaces=False, max_len=256)
        if secret:
            hits.append((f"{kind_prefix}JSON Credential", None, secret, match.group(0)))
    for match in JSON_TOKEN_RE.finditer(text):
        token = _clean_value(match.group(1), allow_spaces=False, max_len=512)
        if token:
            hits.append((f"{kind_prefix}JSON Token", None, token, match.group(0)))
    return hits


def _extract_mail_auth(
    lines: list[str],
    state: Optional[dict[str, object]] = None,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    auth_login_seen = bool(state.get("auth_login_seen")) if state else False
    awaiting_login = str(state.get("awaiting_login") or "") if state else ""
    pending_login_user = str(state.get("pending_login_user") or "") if state else ""
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
                    user = _clean_value(parts[-2], allow_spaces=False, max_len=128)
                    secret = _clean_value(parts[-1], allow_spaces=False, max_len=256)
                    if (
                        user
                        and secret
                        and _looks_reasonable_credential(user)
                        and _looks_reasonable_credential(secret)
                    ):
                        hits.append(("SMTP AUTH PLAIN", user, secret, stripped))
                else:
                    hits.append(("SMTP AUTH PLAIN", None, None, stripped))
            else:
                hits.append(("SMTP AUTH PLAIN", None, None, stripped))
            continue

        match = SMTP_AUTH_LOGIN_RE.match(stripped)
        if match:
            auth_login_seen = True
            awaiting_login = "username"
            pending_login_user = ""
            token = match.group(1)
            if token:
                decoded = _decode_base64(token)
                cleaned = _clean_value(decoded or "", allow_spaces=False, max_len=256)
                if cleaned:
                    if awaiting_login == "username" and _is_likely_username(cleaned):
                        pending_login_user = cleaned
                        awaiting_login = "password"
                        hits.append(
                            ("SMTP AUTH LOGIN Username", cleaned, None, stripped)
                        )
                    elif awaiting_login == "password" and _looks_reasonable_credential(
                        cleaned
                    ):
                        hits.append(
                            (
                                "SMTP AUTH LOGIN Password",
                                pending_login_user or None,
                                cleaned,
                                stripped,
                            )
                        )
                        auth_login_seen = False
                        pending_login_user = ""
                        awaiting_login = ""
            continue

        if auth_login_seen:
            if stripped.startswith("334 "):
                challenge = stripped[4:].strip()
                decoded_challenge = (_decode_base64(challenge) or "").lower()
                if "username" in decoded_challenge:
                    awaiting_login = "username"
                elif "password" in decoded_challenge:
                    awaiting_login = "password"
                continue
            if re.match(r"^\d{3}\b", stripped):
                if stripped.startswith(("235", "535", "454", "530")):
                    auth_login_seen = False
                    awaiting_login = ""
                    pending_login_user = ""
                continue
            token = stripped
            if awaiting_login in {"username", "password"} and re.fullmatch(
                r"[A-Za-z0-9+/=]{8,}", token
            ):
                decoded = _decode_base64(token)
                cleaned = _clean_value(decoded or "", allow_spaces=False, max_len=256)
                if cleaned:
                    if awaiting_login == "username" and _is_likely_username(cleaned):
                        pending_login_user = cleaned
                        awaiting_login = "password"
                        hits.append(
                            ("SMTP AUTH LOGIN Username", cleaned, None, stripped)
                        )
                    elif awaiting_login == "password":
                        if _looks_reasonable_credential(cleaned):
                            hits.append(
                                (
                                    "SMTP AUTH LOGIN Password",
                                    pending_login_user or None,
                                    cleaned,
                                    stripped,
                                )
                            )
                            auth_login_seen = False
                            pending_login_user = ""
                            awaiting_login = ""
            if stripped.upper().startswith(
                ("MAIL FROM", "RCPT TO", "DATA", "RSET", "QUIT")
            ):
                auth_login_seen = False
                awaiting_login = ""
                pending_login_user = ""
    if state is not None:
        state["auth_login_seen"] = auth_login_seen
        state["awaiting_login"] = awaiting_login
        state["pending_login_user"] = pending_login_user
    return hits


def _extract_line_creds(
    text: str,
    *,
    looks_ftp: bool,
    looks_pop3: bool,
    looks_imap: bool,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if looks_ftp:
        for match in FTP_USER_RE.finditer(text):
            user = _clean_value(match.group(1), allow_spaces=False, max_len=128)
            if user:
                hits.append(("FTP USER", user, None, match.group(0).strip()))
        for match in FTP_PASS_RE.finditer(text):
            secret = _clean_value(match.group(1), allow_spaces=False, max_len=256)
            if secret:
                hits.append(("FTP PASS", None, secret, match.group(0).strip()))
    if looks_pop3:
        for match in POP_USER_RE.finditer(text):
            user = _clean_value(match.group(1), allow_spaces=False, max_len=128)
            if user:
                hits.append(("POP3 USER", user, None, match.group(0).strip()))
        for match in POP_PASS_RE.finditer(text):
            secret = _clean_value(match.group(1), allow_spaces=False, max_len=256)
            if secret:
                hits.append(("POP3 PASS", None, secret, match.group(0).strip()))
    if looks_imap:
        for line in lines:
            imap_login = IMAP_LOGIN_RE.match(line)
            if not imap_login:
                continue
            user = _clean_value(
                imap_login.group(1).strip('"'), allow_spaces=False, max_len=128
            )
            secret = _clean_value(
                imap_login.group(2).strip('"'), allow_spaces=False, max_len=256
            )
            hits.append(("IMAP LOGIN", user, secret, line))
    return hits


def _extract_telnet_creds(
    text: str,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    for match in re.finditer(
        r"(?im)\b(?:login|username)\s*[:=]\s*([^\r\n]{1,96})", text
    ):
        user = _clean_value(match.group(1), allow_spaces=False, max_len=96)
        if user and _is_likely_username(user):
            hits.append(("TELNET Username", user, None, match.group(0).strip()))
    for match in re.finditer(
        r"(?im)\b(?:password|passwd|passcode)\s*[:=]\s*([^\r\n]{1,160})", text
    ):
        secret = _clean_value(match.group(1), allow_spaces=False, max_len=160)
        if secret:
            hits.append(("TELNET Password", None, secret, match.group(0).strip()))
    for item in _extract_kv_creds(text, kind_prefix="TELNET "):
        hits.append(item)
    for item in _extract_prompt_creds(text, kind_prefix="TELNET "):
        hits.append(item)
    return hits


def _extract_tftp_creds(
    payload: bytes,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    if len(payload) < 2:
        return hits
    opcode = int.from_bytes(payload[:2], "big")
    if opcode not in {1, 2, 6}:
        return hits

    data = payload[2:]
    parts = data.split(b"\x00")
    if len(parts) < 2:
        return hits
    filename = (
        _clean_value(
            parts[0].decode("latin-1", errors="ignore"), allow_spaces=False, max_len=256
        )
        or ""
    )
    mode = (
        _clean_value(
            parts[1].decode("latin-1", errors="ignore"), allow_spaces=False, max_len=64
        )
        or ""
    )

    request_type = "RRQ" if opcode == 1 else "WRQ" if opcode == 2 else "OACK"
    if filename:
        filename_context = f"filename={filename} mode={mode or '-'}"
        for kind, user, secret, evidence in _extract_kv_creds(
            filename, kind_prefix="TFTP "
        ):
            hits.append(
                (kind, user, secret, f"{request_type} {filename_context} {evidence}")
            )
        for kind, user, secret, evidence in _extract_prompt_creds(
            filename, kind_prefix="TFTP "
        ):
            hits.append(
                (kind, user, secret, f"{request_type} {filename_context} {evidence}")
            )

    # Parse options (RFC 2347 style key/value string pairs).
    if len(parts) > 3:
        for idx in range(2, len(parts) - 1, 2):
            key = _clean_value(
                parts[idx].decode("latin-1", errors="ignore"),
                allow_spaces=False,
                max_len=64,
            )
            value = _clean_value(
                parts[idx + 1].decode("latin-1", errors="ignore"),
                allow_spaces=False,
                max_len=256,
            )
            if not key or not value:
                continue
            key_n = key.lower().replace("-", "").replace("_", "")
            if key_n in {
                "user",
                "username",
                "userid",
                "login",
                "account",
                "accountname",
            } and _is_likely_username(value):
                hits.append(
                    (
                        "TFTP Username Option",
                        value,
                        None,
                        f"{request_type} option {key}={value}",
                    )
                )
            elif key_n in {
                "pass",
                "password",
                "passwd",
                "pwd",
                "token",
                "secret",
                "apikey",
                "accesstoken",
                "refreshtoken",
            }:
                hits.append(
                    (
                        "TFTP Secret Option",
                        None,
                        value,
                        f"{request_type} option {key}={value}",
                    )
                )
    return hits


def _extract_smb_netbios_ntlm_creds(
    payload: bytes,
    text: str,
    sport: Optional[int],
    dport: Optional[int],
    service: str,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    source = (
        "SMB"
        if _ports_match(sport, dport, SMB_PORTS) or service == "SMB"
        else "NetBIOS"
    )

    if NTLM_SIGNATURE in payload:
        for item in _extract_ntlm_credentials(payload, f"{source}/NTLM"):
            hits.append(item)

    lowered = text.lower()
    if any(
        token in lowered
        for token in ("user=", "username=", "password=", "token=", "ntlmssp")
    ):
        for item in _extract_kv_creds(text, kind_prefix=f"{source} "):
            hits.append(item)
        for item in _extract_prompt_creds(text, kind_prefix=f"{source} "):
            hits.append(item)
    return hits


def _extract_prompt_creds(
    text: str, *, kind_prefix: str = ""
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    for match in PROMPT_USER_RE.finditer(text):
        user = _clean_value(match.group(1), allow_spaces=False, max_len=128)
        if user:
            hits.append(
                (
                    f"{kind_prefix}Prompt Credential",
                    user,
                    None,
                    _build_context(text, user),
                )
            )
    for match in PROMPT_SECRET_RE.finditer(text):
        secret = _clean_value(match.group(1), allow_spaces=False, max_len=256)
        if secret:
            if _looks_like_prompt_label_secret(secret):
                continue
            hits.append(
                (
                    f"{kind_prefix}Prompt Credential",
                    None,
                    secret,
                    _build_context(text, secret),
                )
            )
    return hits


def _extract_xml_creds(
    text: str, *, kind_prefix: str = ""
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    for match in XML_USER_RE.finditer(text):
        user = _clean_value(match.group(2), allow_spaces=True, max_len=256)
        if user:
            hits.append(
                (f"{kind_prefix}XML Credential", user, None, match.group(0)[:180])
            )
    for match in XML_SECRET_RE.finditer(text):
        secret_raw = _clean_value(match.group(1), allow_spaces=False, max_len=512)
        if not secret_raw:
            continue
        hits.append(
            (f"{kind_prefix}XML Credential", None, secret_raw, match.group(0)[:180])
        )
        for decoded in _decode_base64_variants(secret_raw):
            for _kind, user, secret, evidence in _extract_kv_creds(
                decoded, kind_prefix=kind_prefix
            ):
                hits.append((_kind, user, secret, f"decoded-base64: {evidence}"))
            for _kind, user, secret, evidence in _extract_prompt_creds(
                decoded, kind_prefix=kind_prefix
            ):
                hits.append((_kind, user, secret, f"decoded-base64: {evidence}"))
    return hits


def _normalize_printable(value: bytes | str, max_len: int = 240) -> str:
    if isinstance(value, bytes):
        text = _safe_decode(value)
    else:
        text = value
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    normalized = " ".join(cleaned.split())
    return normalized[:max_len]


def _tokenize_identifier(value: str) -> list[str]:
    if not value:
        return []
    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    cleaned = re.sub(r"[^A-Za-z0-9]+", " ", split_camel).lower()
    return [part for part in cleaned.split() if part]


def _classify_ot_tag(tag_name: str) -> Optional[str]:
    parts = _tokenize_identifier(tag_name)
    if not parts:
        return None
    for part in parts:
        if part in USER_KEYS:
            return "user"
    for part in parts:
        if part in PASS_KEYS or part in TOKEN_KEYS:
            return "secret"
    if "credential" in parts or "auth" in parts:
        return "secret"
    return None


def _clean_value_candidate(value: str) -> Optional[str]:
    candidate = value.strip().strip("\"'").strip()
    if not candidate:
        return None
    return candidate[:96]


def _extract_ot_value_hint(service_code: int, payload: bytes) -> Optional[str]:
    data = payload
    if service_code == 0x4C and len(data) > 4:
        data = data[4:]
    elif service_code == 0x4E and len(data) > 8:
        data = data[8:]
    elif service_code == 0x4F and len(data) > 2:
        data = data[2:]

    normalized = _normalize_printable(data)
    if normalized:
        for _kind, user, secret, _evidence in _extract_kv_creds(normalized):
            candidate = _clean_value_candidate(secret or user or "")
            if candidate:
                return candidate
        for _kind, user, secret, _evidence in _extract_prompt_creds(normalized):
            candidate = _clean_value_candidate(secret or user or "")
            if candidate:
                return candidate
        for _kind, user, secret, _evidence in _extract_xml_creds(normalized):
            candidate = _clean_value_candidate(secret or user or "")
            if candidate:
                return candidate

    for variant in _decode_bytes_variants(data[:160]):
        for _kind, user, secret, _evidence in _extract_kv_creds(variant):
            candidate = _clean_value_candidate(secret or user or "")
            if candidate:
                return candidate

    for match in OT_VALUE_TOKEN_BYTES_RE.finditer(data[:160]):
        token = match.group(0).decode("ascii", errors="ignore")
        candidate = _clean_value_candidate(token)
        if not candidate:
            continue
        if candidate.lower() in OT_DROP_TOKENS:
            continue
        return candidate
    return None


def _is_ot_port(sport: Optional[int], dport: Optional[int]) -> bool:
    ports = {CIP_TCP_PORT, CIP_UDP_PORT, CIP_SECURITY_PORT}
    return (sport in ports) or (dport in ports)


def _extract_cip_credential_hits(
    payload: bytes,
    transport: str,
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    if _parse_cip_message is None:
        return []

    try:
        (
            service,
            service_name,
            is_request,
            _general_status,
            _status_text,
            class_id,
            _instance_id,
            _attribute_id,
            path_str,
            cip_data,
        ) = _parse_cip_message(payload)
    except Exception:
        return []

    if service is None:
        return []
    if service_name is None and class_id is None and not path_str:
        return []

    service_code = service & 0x7F
    label = (
        service_name
        or CIP_SERVICE_NAMES.get(service_code)
        or f"Service 0x{service_code:02x}"
    )
    hits: list[tuple[str, Optional[str], Optional[str], str]] = []

    path_is_msg_router = "Class:2" in path_str if path_str else False
    if (
        bool(is_request)
        and service_code == 0x37
        and (class_id == 0x02 or path_is_msg_router)
    ):
        for username_candidate, source in _extract_cip_service_0x37_usernames(
            path_str, cip_data
        ):
            detail_parts = [
                f"{transport} {label}",
                f"username={username_candidate}",
                f"source={source}",
            ]
            if class_id is not None:
                detail_parts.append(f"class={class_id}")
            if path_str:
                detail_parts.append(
                    f"path={_normalize_printable(path_str, max_len=120)}"
                )
            hits.append(
                (
                    "CIP Service 0x37 Username",
                    username_candidate,
                    None,
                    " ".join(detail_parts),
                )
            )

    tag_name = _extract_symbol(path_str) if _extract_symbol is not None else None
    tag_role = _classify_ot_tag(tag_name or "")
    is_write = bool(is_request) and service_code in OT_WRITE_SERVICE_CODES
    if bool(is_request) and tag_name and tag_role:
        value_hint = _extract_ot_value_hint(service_code, cip_data)
        username: Optional[str] = None
        secret: Optional[str] = None
        if tag_role == "user":
            username = value_hint or tag_name
        else:
            secret = value_hint or tag_name
        evidence_parts = [f"{transport} {label}", f"tag={tag_name}"]
        if value_hint:
            evidence_parts.append(f"value={value_hint}")
        hits.append(("CIP Credential Tag", username, secret, " ".join(evidence_parts)))

    if bool(is_request) and class_id in CIP_SECURITY_CLASS_IDS and is_write:
        detail = f"{transport} {label} class={class_id}"
        if path_str:
            detail = f"{detail} path={_normalize_printable(path_str, max_len=120)}"
        value_hint = _extract_ot_value_hint(service_code, cip_data)
        username_hint: Optional[str] = None
        secret_hint: Optional[str] = None
        if value_hint:
            if _is_likely_secret(value_hint):
                secret_hint = value_hint
            elif _is_likely_username(value_hint):
                username_hint = value_hint
            else:
                secret_hint = value_hint
        if value_hint:
            detail = f"{detail} value={value_hint}"
        hits.append(
            ("CIP Security Credential Operation", username_hint, secret_hint, detail)
        )
        for username_candidate in _extract_ot_username_candidates(cip_data):
            hits.append(
                (
                    "CIP Security Username Candidate",
                    username_candidate,
                    None,
                    f"{transport} {label} class={class_id} candidate={username_candidate}",
                )
            )

    if tag_role or class_id in CIP_SECURITY_CLASS_IDS:
        normalized = _normalize_printable(cip_data)
        if normalized:
            for kind, user, secret, evidence in _extract_kv_creds(normalized):
                hits.append(
                    (f"{transport} {kind}", user, secret, f"{label} {evidence}")
                )
            for kind, user, secret, evidence in _extract_prompt_creds(normalized):
                hits.append(
                    (f"{transport} {kind}", user, secret, f"{label} {evidence}")
                )
            for kind, user, secret, evidence in _extract_xml_creds(normalized):
                hits.append(
                    (f"{transport} {kind}", user, secret, f"{label} {evidence}")
                )

    return hits


def _extract_ot_protocol_creds(
    payload: bytes,
    sport: Optional[int],
    dport: Optional[int],
) -> list[tuple[str, Optional[str], Optional[str], str]]:
    if not payload:
        return []

    hits: list[tuple[str, Optional[str], Optional[str], str]] = []
    on_ot_port = _is_ot_port(sport, dport)
    enip_parsed = False

    if _parse_enip_details is not None and (on_ot_port or len(payload) >= 24):
        try:
            enip = _parse_enip_details(payload)
            command = enip.get("command")
            command_name = enip.get("command_name")
            if isinstance(command, int) and (command_name or command in ENIP_COMMANDS):
                enip_parsed = True
                cip_payload = enip.get("cip_payload")
                if isinstance(cip_payload, (bytes, bytearray)):
                    hits.extend(
                        _extract_cip_credential_hits(bytes(cip_payload), "ENIP/CIP")
                    )
        except Exception:
            pass

    if on_ot_port and not enip_parsed:
        hits.extend(_extract_cip_credential_hits(payload, "CIP"))

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
        return CredentialSummary(
            path, 0, 0, [], False, Counter(), Counter(), ["Scapy not available"]
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return CredentialSummary(
            path, 0, 0, [], False, Counter(), Counter(), [f"Error opening pcap: {exc}"]
        )

    total_packets = 0
    matches = 0
    hits: list[CredentialHit] = []
    errors: list[str] = []
    kind_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    smtp_auth_state: dict[tuple[str, str, int, int], dict[str, object]] = {}
    http_url_observations: dict[
        str, tuple[int, Optional[float], str, str, Optional[int], Optional[int]]
    ] = {}

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
            if not payload:
                continue

            src_ip, dst_ip = _get_ip_pair(pkt)  # type: ignore[arg-type]
            src_port, dst_port, proto = _get_ports(pkt)  # type: ignore[arg-type]
            service = _service_name(src_port, dst_port, proto)
            ts = safe_float(getattr(pkt, "time", None))

            seen: set[tuple[str, Optional[str], Optional[str], str]] = set()

            text = _safe_decode(payload)
            lines = text.splitlines()
            looks_http = _looks_like_http(text, src_port, dst_port, service)
            looks_ftp = _looks_like_ftp(text, src_port, dst_port, service)
            looks_pop3 = _looks_like_pop3(text, src_port, dst_port, service)
            looks_imap = _looks_like_imap(text, src_port, dst_port, service)
            looks_smtp = _looks_like_smtp(text, src_port, dst_port, service)
            looks_telnet = _looks_like_telnet(text, src_port, dst_port, service)
            looks_tftp = _looks_like_tftp(payload, src_port, dst_port, service)
            looks_smb_netbios = _looks_like_smb_netbios(
                payload, src_port, dst_port, service
            )
            protocol_label = service
            if looks_smtp:
                protocol_label = "SMTP"
            elif looks_imap:
                protocol_label = "IMAP"
            elif looks_pop3:
                protocol_label = "POP3"
            elif looks_ftp:
                protocol_label = "FTP"
            elif looks_http:
                protocol_label = "HTTP"

            if looks_http:
                for observed_url in _extract_http_request_urls(text):
                    if observed_url and observed_url not in http_url_observations:
                        http_url_observations[observed_url] = (
                            total_packets,
                            ts,
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                        )
                for item in _extract_http_basic(text):
                    seen.add(item)
                for item in _extract_http_query_creds(text):
                    seen.add(item)
                for item in _extract_kv_creds(text, kind_prefix="HTTP "):
                    seen.add(item)
                for item in _extract_prompt_creds(text, kind_prefix="HTTP "):
                    seen.add(item)
                for item in _extract_xml_creds(text, kind_prefix="HTTP "):
                    seen.add(item)
            else:
                for item in _extract_kv_creds(text):
                    seen.add(item)
                for item in _extract_prompt_creds(text):
                    seen.add(item)
                for item in _extract_xml_creds(text):
                    seen.add(item)

            for item in _extract_line_creds(
                text,
                looks_ftp=looks_ftp,
                looks_pop3=looks_pop3,
                looks_imap=looks_imap,
            ):
                seen.add(item)
            if looks_smtp:
                s_port = int(src_port or 0)
                d_port = int(dst_port or 0)
                side_a = (src_ip, s_port)
                side_b = (dst_ip, d_port)
                if side_a <= side_b:
                    flow_key = (side_a[0], side_b[0], side_a[1], side_b[1])
                else:
                    flow_key = (side_b[0], side_a[0], side_b[1], side_a[1])
                state = smtp_auth_state.setdefault(
                    flow_key,
                    {
                        "auth_login_seen": False,
                        "awaiting_login": "",
                        "pending_login_user": "",
                    },
                )
                for item in _extract_mail_auth(lines, state):
                    seen.add(item)
            if looks_telnet:
                for item in _extract_telnet_creds(text):
                    seen.add(item)
            if looks_tftp:
                for item in _extract_tftp_creds(payload):
                    seen.add(item)
            if looks_smb_netbios:
                for item in _extract_smb_netbios_ntlm_creds(
                    payload, text, src_port, dst_port, service
                ):
                    seen.add(item)
            for item in _extract_ot_protocol_creds(payload, src_port, dst_port):
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
                            protocol=protocol_label,
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

    # Supplemental HTTP URL mining: recover credentials from reconstructed request URLs
    # that may not appear contiguously in single packet payloads.
    try:
        from .http import analyze_http  # local import to avoid heavyweight import path

        http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
        seen_hit_keys: set[tuple[str, Optional[str], Optional[str], str]] = {
            (str(hit.kind), hit.username, hit.secret, str(hit.evidence)) for hit in hits
        }
        for url, count in (http_summary.url_counts or Counter()).items():
            if int(count or 0) <= 0:
                continue
            observed = http_url_observations.get(str(url))
            for kind, user, secret, evidence in _extract_http_query_creds_from_uri(
                str(url)
            ):
                enriched_evidence = f"url={url} {evidence}"
                key = (kind, user, secret, enriched_evidence)
                if key in seen_hit_keys:
                    continue
                seen_hit_keys.add(key)
                matches += 1
                kind_counts[kind] += 1
                if user:
                    user_counts[user] += 1
                if len(hits) < max_hits:
                    packet_number = 0
                    ts_value: Optional[float] = http_summary.first_seen
                    src_ip = "-"
                    dst_ip = "-"
                    src_port: Optional[int] = None
                    dst_port: Optional[int] = None
                    if observed is not None:
                        (
                            packet_number,
                            ts_value,
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                        ) = observed
                    hits.append(
                        CredentialHit(
                            packet_number=packet_number,
                            ts=ts_value,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol="HTTP",
                            kind=kind,
                            username=user,
                            secret=secret,
                            evidence=enriched_evidence[:240],
                        )
                    )
    except Exception as exc:
        errors.append(f"HTTP URL credential mining error: {exc}")

    truncated = matches > len(hits)

    auth_abuse_sequences: list[dict[str, object]] = []
    replay_candidates: list[dict[str, object]] = []
    token_fanout: list[dict[str, object]] = []
    privileged_exposures: list[dict[str, object]] = []
    external_exposures: list[dict[str, object]] = []
    deterministic_checks: dict[str, list[str]] = {
        "plaintext_credential_exposure": [],
        "auth_abuse_pattern": [],
        "credential_replay": [],
        "privileged_account_exposure": [],
        "token_misuse_fanout": [],
        "external_destination_exposure": [],
        "likely_benign_test_credentials": [],
    }

    def _is_public_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_global
        except Exception:
            return False

    for hit in hits:
        score = 0
        secret = str(hit.secret or "")
        user = str(hit.username or "")
        kind_l = hit.kind.lower()
        if "basic" in kind_l or "pass" in kind_l or "credential" in kind_l:
            score += 2
        elif "token" in kind_l or "bearer" in kind_l:
            score += 1
        if user:
            score += 1
        if secret and len(secret) >= 10:
            score += 1
        if _is_public_ip(hit.dst_ip):
            score += 1

        if score >= 4:
            confidence = "high"
        elif score >= 2:
            confidence = "medium"
        else:
            confidence = "low"
        confidence_counts[confidence] += 1

        deterministic_checks["plaintext_credential_exposure"].append(
            f"pkt={hit.packet_number} {hit.src_ip}->{hit.dst_ip} {hit.kind} confidence={confidence}"
        )

        if _is_public_ip(hit.dst_ip):
            external_exposures.append(
                {
                    "src": hit.src_ip,
                    "dst": hit.dst_ip,
                    "kind": hit.kind,
                    "user": hit.username or "-",
                    "pkt": hit.packet_number,
                }
            )
            deterministic_checks["external_destination_exposure"].append(
                f"{hit.src_ip}->{hit.dst_ip} kind={hit.kind}"
            )

        if user and PRIV_USER_RE.search(user):
            privileged_exposures.append(
                {
                    "src": hit.src_ip,
                    "dst": hit.dst_ip,
                    "user": user,
                    "kind": hit.kind,
                    "pkt": hit.packet_number,
                }
            )
            deterministic_checks["privileged_account_exposure"].append(
                f"{user} exposed via {hit.kind} {hit.src_ip}->{hit.dst_ip}"
            )

        if secret and secret.lower() in PLACEHOLDER_SECRETS:
            deterministic_checks["likely_benign_test_credentials"].append(
                f"placeholder secret on pkt={hit.packet_number} {hit.src_ip}->{hit.dst_ip}"
            )

    by_src: dict[str, list[CredentialHit]] = {}
    for hit in hits:
        by_src.setdefault(hit.src_ip, []).append(hit)
    for src_ip, items in by_src.items():
        unique_users = {str(item.username).lower() for item in items if item.username}
        unique_dsts = {item.dst_ip for item in items}
        if len(items) >= 8 and (len(unique_users) >= 4 or len(unique_dsts) >= 4):
            auth_abuse_sequences.append(
                {
                    "src": src_ip,
                    "events": len(items),
                    "users": len(unique_users),
                    "dsts": len(unique_dsts),
                }
            )
            deterministic_checks["auth_abuse_pattern"].append(
                f"{src_ip} events={len(items)} users={len(unique_users)} dsts={len(unique_dsts)}"
            )

    replay_index: dict[tuple[str, str], set[str]] = {}
    for hit in hits:
        key_user = str(hit.username or "").strip().lower()
        if key_user:
            replay_index.setdefault(("user", key_user), set()).add(hit.dst_ip)
        key_secret = str(hit.secret or "").strip()
        if key_secret and len(key_secret) >= 8:
            replay_index.setdefault(("secret", key_secret), set()).add(hit.dst_ip)

    for (rtype, value), dsts in replay_index.items():
        if len(dsts) >= 3:
            replay_candidates.append(
                {
                    "type": rtype,
                    "value": value[:48],
                    "dst_count": len(dsts),
                    "dsts": sorted(dsts)[:8],
                }
            )
            deterministic_checks["credential_replay"].append(
                f"{rtype} reused across {len(dsts)} destinations value={value[:24]}"
            )

    token_index: dict[str, set[str]] = {}
    for hit in hits:
        if "token" not in hit.kind.lower() and "bearer" not in hit.kind.lower():
            continue
        token = str(hit.secret or "").strip()
        if not token or len(token) < 8:
            continue
        token_index.setdefault(token, set()).add(hit.dst_ip)
    for token, dsts in token_index.items():
        if len(dsts) >= 3:
            token_fanout.append(
                {
                    "token": token[:24],
                    "dst_count": len(dsts),
                    "dsts": sorted(dsts)[:8],
                }
            )
            deterministic_checks["token_misuse_fanout"].append(
                f"token={token[:24]} used across {len(dsts)} destinations"
            )

    return CredentialSummary(
        path=path,
        total_packets=total_packets,
        matches=matches,
        hits=hits,
        truncated=truncated,
        kind_counts=kind_counts,
        user_counts=user_counts,
        confidence_counts=confidence_counts,
        auth_abuse_sequences=auth_abuse_sequences,
        replay_candidates=replay_candidates,
        token_fanout=token_fanout,
        privileged_exposures=privileged_exposures,
        external_exposures=external_exposures,
        deterministic_checks={
            key: values[:40] for key, values in deterministic_checks.items()
        },
        errors=errors,
    )


def merge_creds_summaries(
    summaries: list[CredentialSummary]
    | tuple[CredentialSummary, ...]
    | set[CredentialSummary],
) -> CredentialSummary:
    summary_list = list(summaries)
    if not summary_list:
        return CredentialSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            matches=0,
            hits=[],
            truncated=False,
            kind_counts=Counter(),
            user_counts=Counter(),
            confidence_counts=Counter(),
            auth_abuse_sequences=[],
            replay_candidates=[],
            token_fanout=[],
            privileged_exposures=[],
            external_exposures=[],
            deterministic_checks={},
            errors=[],
        )

    total_packets = sum(
        int(getattr(item, "total_packets", 0) or 0) for item in summary_list
    )
    matches = sum(int(getattr(item, "matches", 0) or 0) for item in summary_list)
    truncated = any(bool(getattr(item, "truncated", False)) for item in summary_list)

    hits: list[CredentialHit] = []
    kind_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    auth_abuse_sequences: list[dict[str, object]] = []
    replay_candidates: list[dict[str, object]] = []
    token_fanout: list[dict[str, object]] = []
    privileged_exposures: list[dict[str, object]] = []
    external_exposures: list[dict[str, object]] = []
    deterministic_checks: dict[str, list[str]] = {}
    errors: set[str] = set()

    seen_hits: set[tuple[object, ...]] = set()

    def _dedup_dict_rows(
        rows: list[dict[str, object]], limit: int = 200
    ) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        seen: set[str] = set()
        for row in rows:
            key = repr(sorted((str(k), repr(v)) for k, v in row.items()))
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
            if len(out) >= limit:
                break
        return out

    for summary in summary_list:
        kind_counts.update(getattr(summary, "kind_counts", Counter()) or Counter())
        user_counts.update(getattr(summary, "user_counts", Counter()) or Counter())
        confidence_counts.update(
            getattr(summary, "confidence_counts", Counter()) or Counter()
        )
        errors.update(
            str(err)
            for err in (getattr(summary, "errors", []) or [])
            if str(err).strip()
        )

        for hit in getattr(summary, "hits", []) or []:
            key = (
                int(getattr(hit, "packet_number", 0) or 0),
                str(getattr(hit, "src_ip", "") or ""),
                str(getattr(hit, "dst_ip", "") or ""),
                int(getattr(hit, "src_port", 0) or 0)
                if getattr(hit, "src_port", None) is not None
                else None,
                int(getattr(hit, "dst_port", 0) or 0)
                if getattr(hit, "dst_port", None) is not None
                else None,
                str(getattr(hit, "protocol", "") or ""),
                str(getattr(hit, "kind", "") or ""),
                str(getattr(hit, "username", "") or ""),
                str(getattr(hit, "secret", "") or ""),
                str(getattr(hit, "evidence", "") or ""),
            )
            if key in seen_hits:
                continue
            seen_hits.add(key)
            hits.append(hit)

        auth_abuse_sequences.extend(
            list(getattr(summary, "auth_abuse_sequences", []) or [])
        )
        replay_candidates.extend(list(getattr(summary, "replay_candidates", []) or []))
        token_fanout.extend(list(getattr(summary, "token_fanout", []) or []))
        privileged_exposures.extend(
            list(getattr(summary, "privileged_exposures", []) or [])
        )
        external_exposures.extend(
            list(getattr(summary, "external_exposures", []) or [])
        )

        checks = getattr(summary, "deterministic_checks", {}) or {}
        for key, values in checks.items():
            bucket = deterministic_checks.setdefault(str(key), [])
            for value in values or []:
                text = str(value).strip()
                if text:
                    bucket.append(text)

    for key, values in list(deterministic_checks.items()):
        deterministic_checks[key] = sorted(set(values))[:80]

    hits.sort(
        key=lambda item: (
            safe_float(getattr(item, "ts", None))
            if getattr(item, "ts", None) is not None
            else float("inf"),
            int(getattr(item, "packet_number", 0) or 0),
        )
    )

    return CredentialSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        matches=matches,
        hits=hits,
        truncated=truncated or matches > len(hits),
        kind_counts=kind_counts,
        user_counts=user_counts,
        confidence_counts=confidence_counts,
        auth_abuse_sequences=_dedup_dict_rows(auth_abuse_sequences, limit=200),
        replay_candidates=_dedup_dict_rows(replay_candidates, limit=200),
        token_fanout=_dedup_dict_rows(token_fanout, limit=200),
        privileged_exposures=_dedup_dict_rows(privileged_exposures, limit=200),
        external_exposures=_dedup_dict_rows(external_exposures, limit=200),
        deterministic_checks=deterministic_checks,
        errors=sorted(errors),
    )
