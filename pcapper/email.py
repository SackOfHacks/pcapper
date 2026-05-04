from __future__ import annotations

import base64
import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable, Optional

from .device_detection import device_fingerprints_from_text
from .pcap_cache import get_reader
from .utils import extract_packet_endpoints, safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


SMTP_PORTS = {25, 465, 587, 2525}
POP3_PORTS = {110, 995}
IMAP_PORTS = {143, 993}
MAIL_PORTS = SMTP_PORTS | POP3_PORTS | IMAP_PORTS

EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
SUBJECT_RE = re.compile(r"^Subject:\s*(.+)$", re.IGNORECASE)
FROM_RE = re.compile(r"^From:\s*(.+)$", re.IGNORECASE)
TO_RE = re.compile(r"^(?:To|Cc|Bcc):\s*(.+)$", re.IGNORECASE)
MESSAGE_ID_RE = re.compile(r"^Message-ID:\s*<?([^>\s]+)>?$", re.IGNORECASE)
AUTH_RE = re.compile(r"^AUTH\s+([A-Za-z0-9_-]+)\s*(.*)$", re.IGNORECASE)
SMTP_RESPONSE_RE = re.compile(r"^(\d{3})(?:\s|$)")
IMAP_LINE_RE = re.compile(r"^([A-Za-z0-9._-]+)\s+([A-Za-z]+)\s*(.*)$")
IMAP_STATUS_RE = re.compile(r"^[A-Za-z0-9._-]+\s+(OK|NO|BAD)\b", re.IGNORECASE)
POP3_STATUS_RE = re.compile(r"^(\+OK|-ERR)\b", re.IGNORECASE)
FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img|eml|msg)",
    re.IGNORECASE,
)
ATTACHMENT_RE = re.compile(r'filename\*?="?([^";\r\n]+)', re.IGNORECASE)
NAME_RE = re.compile(r'name="?([^";\r\n]+)', re.IGNORECASE)
USER_RE = re.compile(
    r"\b(?:user|username|login|account|uid|screenname)\b\s*[:=]\s*([^\s&;,]{1,128})",
    re.IGNORECASE,
)
PASS_RE = re.compile(
    r"\b(?:pass|password|pwd)\b\s*[:=]\s*([^\s&;,]{1,128})", re.IGNORECASE
)
SECRET_RE = re.compile(
    r"\b(?:secret|token|apikey|api_key|api-key|session|sessionid|auth|authorization)\b\s*[:=]\s*([^\s&;,]{3,256})",
    re.IGNORECASE,
)

SUSPICIOUS_SUBJECT_RE = re.compile(
    r"invoice|payment|wire|urgent|action required|verify account|password reset|gift card|bank transfer|mfa",
    re.IGNORECASE,
)
SUSPICIOUS_CONTENT_RE = [
    (
        re.compile(r"powershell|cmd\.exe|wmic|winrs", re.IGNORECASE),
        "Command execution tooling",
    ),
    (
        re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE),
        "Malware tooling",
    ),
    (
        re.compile(r"rundll32|regsvr32|schtasks|at\s+", re.IGNORECASE),
        "Execution/persistence tooling",
    ),
    (re.compile(r"nmap|masscan|sqlmap", re.IGNORECASE), "Recon tooling"),
]
RISKY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".ps1",
    ".hta",
    ".jar",
    ".lnk",
    ".iso",
    ".img",
    ".docm",
    ".xlsm",
    ".pptm",
}

MAIL_TEXT_CUES = (
    "mail from:",
    "rcpt to:",
    "subject:",
    "message-id:",
    "from:",
    "to:",
    "pop3",
    "imap",
    "smtp",
    "auth login",
    "content-disposition: attachment",
)

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
HTTP_REQUEST_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d", re.IGNORECASE
)
HTTP_HOST_RE = re.compile(r"^Host:\s*([^\s:]+)", re.IGNORECASE)
HTTP_REFERER_RE = re.compile(r"^Referer:\s*(\S+)", re.IGNORECASE)
HTTP_UA_RE = re.compile(r"^User-Agent:\s*(.+)$", re.IGNORECASE)
WEBMAIL_PROVIDER_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("Gmail", ("mail.google.com", "gmail.com", "googlemail.com")),
    (
        "Microsoft/Outlook",
        (
            "outlook.live.com",
            "outlook.office.com",
            "office365.com",
            "outlook.com",
            "hotmail.com",
            "live.com",
            "microsoftonline.com",
        ),
    ),
    ("Yahoo Mail", ("mail.yahoo.com", "yahoo.com", "ymail.com")),
    ("Proton Mail", ("mail.proton.me", "protonmail.com", "proton.me")),
    ("Zoho Mail", ("mail.zoho.com", "zoho.com")),
    ("AOL Mail", ("mail.aol.com", "aol.com")),
    ("iCloud Mail", ("icloud.com", "me.com", "mac.com")),
    ("Yandex Mail", ("mail.yandex.com", "yandex.com", "yandex.ru")),
    ("GMX/Web.de", ("gmx.com", "web.de", "gmx.net")),
    ("Fastmail", ("fastmail.com", "fastmail.fm")),
    ("Tutanota", ("mail.tutanota.com", "tutanota.com")),
    ("Roundcube", ("roundcube",)),
    ("SquirrelMail", ("squirrelmail",)),
    ("Horde", ("horde",)),
    ("Zimbra", ("zimbra",)),
    ("RainLoop", ("rainloop",)),
    ("Atmail", ("atmail",)),
]
WEBMAIL_PATH_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (
        "Login",
        ("/login", "/signin", "/auth", "/owa/auth", "/account/login", "/session"),
    ),
    ("Inbox", ("/inbox", "/mail", "/messages", "/mailbox")),
    ("Compose", ("/compose", "/send", "/newmessage", "/mail/compose")),
    ("Attachment", ("/attachment", "/download", "/upload", "attachment", "filename=")),
    ("API", ("/api/", "/ews/", "/mapi/", "/autodiscover", "/activesync", "/graphql")),
]


@dataclass(frozen=True)
class EmailConversation:
    client_ip: str
    server_ip: str
    protocol: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class EmailArtifact:
    kind: str
    detail: str
    src: str
    dst: str
    packet: int | None = None


@dataclass(frozen=True)
class EmailTimelineEvent:
    ts: Optional[float]
    protocol: str
    direction: str
    stage: str
    action: str
    detail: str
    src: str
    dst: str
    packet: int | None = None


@dataclass(frozen=True)
class EmailSummary:
    path: Path
    total_packets: int
    email_packets: int
    total_bytes: int
    total_messages: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    protocol_counts: Counter[str]
    email_counts: Counter[str]
    from_counts: Counter[str]
    to_counts: Counter[str]
    subject_counts: Counter[str]
    username_counts: Counter[str]
    password_counts: Counter[str]
    secret_counts: Counter[str]
    auth_methods: Counter[str]
    smtp_command_counts: Counter[str]
    imap_command_counts: Counter[str]
    pop3_command_counts: Counter[str]
    response_counts: Counter[str]
    webmail_provider_counts: Counter[str]
    webmail_host_counts: Counter[str]
    webmail_page_counts: Counter[str]
    webmail_action_counts: Counter[str]
    attachment_counts: Counter[str]
    message_id_counts: Counter[str]
    plaintext_strings: Counter[str]
    conversations: list[EmailConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[EmailArtifact]
    timeline_events: list[EmailTimelineEvent]
    deterministic_checks: dict[str, list[str]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "email_packets": self.email_packets,
            "total_bytes": self.total_bytes,
            "total_messages": self.total_messages,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "protocol_counts": dict(self.protocol_counts),
            "email_counts": dict(self.email_counts),
            "from_counts": dict(self.from_counts),
            "to_counts": dict(self.to_counts),
            "subject_counts": dict(self.subject_counts),
            "username_counts": dict(self.username_counts),
            "password_counts": dict(self.password_counts),
            "secret_counts": dict(self.secret_counts),
            "auth_methods": dict(self.auth_methods),
            "smtp_command_counts": dict(self.smtp_command_counts),
            "imap_command_counts": dict(self.imap_command_counts),
            "pop3_command_counts": dict(self.pop3_command_counts),
            "response_counts": dict(self.response_counts),
            "webmail_provider_counts": dict(self.webmail_provider_counts),
            "webmail_host_counts": dict(self.webmail_host_counts),
            "webmail_page_counts": dict(self.webmail_page_counts),
            "webmail_action_counts": dict(self.webmail_action_counts),
            "attachment_counts": dict(self.attachment_counts),
            "message_id_counts": dict(self.message_id_counts),
            "plaintext_strings": dict(self.plaintext_strings),
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
                {
                    "kind": item.kind,
                    "detail": item.detail,
                    "src": item.src,
                    "dst": item.dst,
                    "packet": item.packet,
                }
                for item in self.artifacts
            ],
            "timeline_events": [
                {
                    "ts": item.ts,
                    "protocol": item.protocol,
                    "direction": item.direction,
                    "stage": item.stage,
                    "action": item.action,
                    "detail": item.detail,
                    "src": item.src,
                    "dst": item.dst,
                    "packet": item.packet,
                }
                for item in self.timeline_events
            ],
            "deterministic_checks": {
                k: list(v) for k, v in self.deterministic_checks.items()
            },
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


def _looks_like_mail_text(text: str) -> bool:
    lowered = text.lower()
    cue_hits = sum(1 for cue in MAIL_TEXT_CUES if cue in lowered)
    if cue_hits >= 1:
        return True
    return bool(EMAIL_RE.search(text) and ("subject:" in lowered or "auth " in lowered))


def _is_http_request_line(line: str) -> bool:
    upper = (line or "").upper()
    return any(upper.startswith(f"{method} ") for method in HTTP_METHODS)


def _extract_http_context(text: str) -> dict[str, str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return {}
    first_line = lines[0]
    context: dict[str, str] = {"request_line": first_line}
    req_match = HTTP_REQUEST_RE.match(first_line)
    if req_match:
        context["method"] = req_match.group(1).upper()
        context["uri"] = req_match.group(2)
    for line in lines[1:40]:
        host_match = HTTP_HOST_RE.match(line)
        if host_match and "host" not in context:
            context["host"] = host_match.group(1).strip().lower()
            continue
        ref_match = HTTP_REFERER_RE.match(line)
        if ref_match and "referer" not in context:
            context["referer"] = ref_match.group(1).strip()
            continue
        ua_match = HTTP_UA_RE.match(line)
        if ua_match and "user_agent" not in context:
            context["user_agent"] = ua_match.group(1).strip()
    return context


def _webmail_provider_from_host(host: str) -> str:
    host_value = (host or "").lower().strip()
    if not host_value:
        return ""
    for provider, patterns in WEBMAIL_PROVIDER_PATTERNS:
        for pattern in patterns:
            check = str(pattern).lower()
            if check in host_value:
                return provider
    return ""


def _webmail_pages_from_uri(uri: str) -> list[str]:
    uri_value = (uri or "").lower().strip()
    if not uri_value:
        return []
    pages: list[str] = []
    for label, tokens in WEBMAIL_PATH_KEYWORDS:
        if any(token in uri_value for token in tokens):
            pages.append(label)
    return pages


def _detect_webmail_context(text: str) -> dict[str, object] | None:
    context = _extract_http_context(text)
    host = str(context.get("host", "")).lower().strip()
    uri = str(context.get("uri", "")).strip()
    referer = str(context.get("referer", "")).strip().lower()
    request_line = str(context.get("request_line", ""))
    user_agent = str(context.get("user_agent", ""))
    provider = _webmail_provider_from_host(host)
    pages = _webmail_pages_from_uri(uri)

    host_hit = bool(provider) or (
        host
        and any(
            token in host
            for token in (
                "mail.",
                "webmail",
                "roundcube",
                "squirrelmail",
                "zimbra",
                "horde",
                "rainloop",
                "owa",
            )
        )
    )
    uri_hit = bool(pages) or any(
        token in uri.lower()
        for token in (
            "/owa/",
            "/ews/",
            "/mail",
            "/webmail",
            "/roundcube",
            "/squirrelmail",
            "/zimbra",
        )
    )
    referer_hit = any(
        token in referer
        for token in (
            "mail.",
            "webmail",
            "/owa/",
            "/mail",
            "/roundcube",
            "/zimbra",
            "/horde",
        )
    )
    ua_hit = "outlook" in user_agent.lower() and "http" in request_line.lower()

    if not (host_hit or uri_hit or referer_hit or ua_hit):
        return None

    method = str(context.get("method", "")).upper()
    actions: list[str] = []
    if method:
        actions.append(method)
    for page in pages:
        actions.append(page)
    if not actions and host_hit:
        actions.append("Browse")
    return {
        "provider": provider or "Generic Webmail",
        "host": host or "-",
        "uri": uri or "-",
        "request_line": request_line or "-",
        "method": method or "-",
        "pages": pages,
        "actions": actions,
        "user_agent": user_agent,
    }


def _protocol_from_ports_or_text(sport: int, dport: int, text: str) -> str:
    if sport in SMTP_PORTS or dport in SMTP_PORTS:
        return "SMTP"
    if sport in POP3_PORTS or dport in POP3_PORTS:
        return "POP3"
    if sport in IMAP_PORTS or dport in IMAP_PORTS:
        return "IMAP"
    upper = text.upper()
    if any(
        token in upper
        for token in ("MAIL FROM", "RCPT TO", "HELO", "EHLO", "STARTTLS", "AUTH")
    ):
        return "SMTP"
    if " LOGIN " in upper or " FETCH " in upper or " UID " in upper:
        return "IMAP"
    if "USER " in upper or "PASS " in upper or "+OK" in upper or "-ERR" in upper:
        return "POP3"
    return "MAIL-OTHER"


def _is_client_to_server(sport: int, dport: int, text: str) -> bool:
    if dport in MAIL_PORTS:
        return True
    if sport in MAIL_PORTS:
        return False
    line = (text.splitlines()[0] if text.splitlines() else "").strip()
    upper = line.upper()
    if SMTP_RESPONSE_RE.match(line):
        return False
    if POP3_STATUS_RE.match(line):
        return False
    if IMAP_STATUS_RE.match(line):
        return False
    if upper.startswith(
        ("MAIL FROM", "RCPT TO", "HELO", "EHLO", "AUTH ", "USER ", "PASS ")
    ):
        return True
    return True


def _safe_b64decode(value: str) -> str:
    token = value.strip()
    if not token:
        return ""
    try:
        raw = base64.b64decode(token.encode("ascii"), validate=False)
    except Exception:
        return ""
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="ignore").replace("\x00", " ").strip()
    return text


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


def _looks_human_text(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if len(text) > 240:
        text = text[:240]
    printable = sum(1 for ch in text if ch.isprintable())
    if printable < max(1, int(len(text) * 0.9)):
        return False
    alpha = sum(1 for ch in text if ch.isalpha())
    return alpha >= 3


def _looks_base64_blob(value: str) -> bool:
    token = str(value or "").strip()
    if len(token) < 40:
        return False
    if " " in token:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]{40,}", token))


def _extract_pair_tokens(
    text: str,
    username_counts: Counter[str],
    password_counts: Counter[str],
    secret_counts: Counter[str],
) -> None:
    for user in USER_RE.findall(text):
        token = user.strip()
        if token:
            username_counts[token] += 1
    for password in PASS_RE.findall(text):
        token = password.strip()
        if token:
            password_counts[token] += 1
            secret_counts[token] += 1
    for secret in SECRET_RE.findall(text):
        token = secret.strip()
        if token:
            secret_counts[token] += 1


def _parse_mime_message(mime_text: str) -> dict[str, object]:
    result: dict[str, object] = {
        "subject": "",
        "from": "",
        "to": "",
        "message_id": "",
        "emails": set(),
        "attachments": [],
        "body_lines": [],
        "errors": [],
    }
    if not mime_text or not mime_text.strip():
        return result
    try:
        raw = mime_text.encode("utf-8", errors="ignore")
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        result["errors"] = [f"MIME parse failed: {type(exc).__name__}: {exc}"]
        return result

    def _add_emails(value: str) -> None:
        for addr in EMAIL_RE.findall(str(value or "")):
            if isinstance(result.get("emails"), set):
                result["emails"].add(addr)  # type: ignore[union-attr]

    subject = str(msg.get("Subject", "") or "").strip()
    from_value = str(msg.get("From", "") or "").strip()
    to_value = " ".join(
        str(msg.get(name, "") or "").strip() for name in ("To", "Cc", "Bcc")
    ).strip()
    message_id = str(msg.get("Message-ID", "") or "").strip("<> ")
    result["subject"] = subject
    result["from"] = from_value
    result["to"] = to_value
    result["message_id"] = message_id
    _add_emails(subject)
    _add_emails(from_value)
    _add_emails(to_value)

    attachments: list[dict[str, object]] = []
    body_lines: list[str] = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        ctype = str(part.get_content_type() or "").lower()
        cdisp = str(part.get_content_disposition() or "").lower()
        filename = str(part.get_filename() or "").strip()
        if not filename:
            filename = str(part.get_param("name", header="content-type") or "").strip()
        payload_bytes: bytes = b""
        try:
            decoded = part.get_payload(decode=True)
            if isinstance(decoded, bytes):
                payload_bytes = decoded
            elif decoded is None:
                fallback = part.get_payload()
                if isinstance(fallback, str):
                    payload_bytes = fallback.encode("utf-8", errors="ignore")
        except Exception:
            payload_bytes = b""
        payload_size = len(payload_bytes)

        is_attachment = bool(filename) or cdisp == "attachment"
        if is_attachment:
            att_name = filename or f"part-{len(attachments) + 1}"
            sha256 = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes else ""
            attachments.append(
                {
                    "filename": att_name,
                    "content_type": ctype or "-",
                    "size": payload_size,
                    "sha256": sha256,
                }
            )

        if ctype.startswith("text/") and len(body_lines) < 24:
            text_payload = ""
            try:
                text_payload = part.get_content()
            except Exception:
                if payload_bytes:
                    text_payload = payload_bytes.decode("utf-8", errors="ignore")
            if text_payload:
                for line in str(text_payload).splitlines():
                    line_text = line.strip()
                    if not line_text:
                        continue
                    _add_emails(line_text)
                    if (
                        len(body_lines) < 24
                        and _looks_human_text(line_text)
                        and not _looks_base64_blob(line_text)
                    ):
                        body_lines.append(line_text[:220])
    result["attachments"] = attachments
    result["body_lines"] = body_lines
    return result


def analyze_email(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> EmailSummary:
    errors: list[str] = []
    if TCP is None:
        errors.append("Scapy TCP layers unavailable; install scapy for email analysis.")
        return EmailSummary(
            path=path,
            total_packets=0,
            email_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            email_counts=Counter(),
            from_counts=Counter(),
            to_counts=Counter(),
            subject_counts=Counter(),
            username_counts=Counter(),
            password_counts=Counter(),
            secret_counts=Counter(),
            auth_methods=Counter(),
            smtp_command_counts=Counter(),
            imap_command_counts=Counter(),
            pop3_command_counts=Counter(),
            response_counts=Counter(),
            webmail_provider_counts=Counter(),
            webmail_host_counts=Counter(),
            webmail_page_counts=Counter(),
            webmail_action_counts=Counter(),
            attachment_counts=Counter(),
            message_id_counts=Counter(),
            plaintext_strings=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            timeline_events=[],
            deterministic_checks={},
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path,
        packets=packets,
        meta=meta,
        show_status=show_status,
    )

    total_packets = 0
    email_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    email_counts: Counter[str] = Counter()
    from_counts: Counter[str] = Counter()
    to_counts: Counter[str] = Counter()
    subject_counts: Counter[str] = Counter()
    username_counts: Counter[str] = Counter()
    password_counts: Counter[str] = Counter()
    secret_counts: Counter[str] = Counter()
    auth_methods: Counter[str] = Counter()
    smtp_command_counts: Counter[str] = Counter()
    imap_command_counts: Counter[str] = Counter()
    pop3_command_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    webmail_provider_counts: Counter[str] = Counter()
    webmail_host_counts: Counter[str] = Counter()
    webmail_page_counts: Counter[str] = Counter()
    webmail_action_counts: Counter[str] = Counter()
    attachment_counts: Counter[str] = Counter()
    message_id_counts: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    artifacts: list[EmailArtifact] = []
    timeline_events: list[EmailTimelineEvent] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    seen_device_artifacts: set[str] = set()
    seen_mime_messages: set[str] = set()
    client_server_fanout: dict[str, set[str]] = defaultdict(set)
    auth_failures_by_client: Counter[str] = Counter()
    auth_success_by_client: Counter[str] = Counter()
    bytes_by_client_server: Counter[tuple[str, str]] = Counter()
    stream_state: dict[tuple[str, str, int, int], dict[str, object]] = {}

    def _stream_bucket(src: str, dst: str, sport: int, dport: int) -> dict[str, object]:
        key = (src, dst, sport, dport)
        state = stream_state.get(key)
        if state is None:
            state = {
                "buf": "",
                "in_data": False,
                "data_lines": [],
                "body_preview_count": 0,
                "smtp_auth_login": False,
                "smtp_pending_user": None,
                "smtp_expect": None,
            }
            stream_state[key] = state
        return state

    def _process_line(
        line: str,
        src_ip: str,
        dst_ip: str,
        packet_no: int,
        proto: str,
        ts: Optional[float],
        direction: str,
        state: dict[str, object],
    ) -> None:
        nonlocal total_messages
        if not line:
            return
        total_messages += 1
        upper = line.upper()
        stage = "Interaction"

        def _timeline_emit(event_stage: str, action: str, detail: str) -> None:
            timeline_events.append(
                EmailTimelineEvent(
                    ts=ts,
                    protocol=proto,
                    direction=direction,
                    stage=event_stage,
                    action=action,
                    detail=detail[:220],
                    src=src_ip,
                    dst=dst_ip,
                    packet=packet_no,
                )
            )

        for mail_addr in EMAIL_RE.findall(line):
            email_counts[mail_addr] += 1
        _extract_pair_tokens(line, username_counts, password_counts, secret_counts)

        subject_match = SUBJECT_RE.search(line)
        if subject_match:
            subject_value = subject_match.group(1).strip()
            if subject_value:
                subject_counts[subject_value] += 1
                artifacts.append(
                    EmailArtifact("subject", subject_value, src_ip, dst_ip, packet_no)
                )
                _timeline_emit("Message Build", "Subject", subject_value)
                if SUSPICIOUS_SUBJECT_RE.search(subject_value):
                    detections.append(
                        {
                            "severity": "warning",
                            "summary": "Suspicious email subject content",
                            "details": f"{src_ip}->{dst_ip} Subject: {subject_value[:140]}",
                            "source": "EMAIL",
                        }
                    )

        from_match = FROM_RE.search(line)
        if from_match:
            for mail_addr in EMAIL_RE.findall(from_match.group(1)):
                from_counts[mail_addr] += 1
                _timeline_emit("Message Build", "From", mail_addr)

        to_match = TO_RE.search(line)
        if to_match:
            for mail_addr in EMAIL_RE.findall(to_match.group(1)):
                to_counts[mail_addr] += 1
                _timeline_emit("Message Build", "Recipient", mail_addr)

        msg_match = MESSAGE_ID_RE.search(line)
        if msg_match:
            msg_id = msg_match.group(1).strip()
            if msg_id:
                message_id_counts[msg_id] += 1

        for match in ATTACHMENT_RE.findall(line):
            name = match.strip()
            if name:
                attachment_counts[name] += 1
                artifacts.append(
                    EmailArtifact("attachment", name, src_ip, dst_ip, packet_no)
                )
                _timeline_emit("Attachment", "Attachment Name", name)
        for match in NAME_RE.findall(line):
            name = match.strip()
            if name:
                attachment_counts[name] += 1
        for match in FILE_NAME_RE.findall(line):
            name = match.strip()
            if name:
                attachment_counts[name] += 1

        if proto == "SMTP":
            smtp_auth_login = bool(state.get("smtp_auth_login"))
            smtp_pending_user = state.get("smtp_pending_user")
            smtp_expect = state.get("smtp_expect")
            if upper.startswith("220"):
                _timeline_emit("Server Response", "SMTP Banner", line)
                banner = line[3:].lstrip("- ").strip()
                if banner:
                    for detail in device_fingerprints_from_text(
                        banner, source="SMTP banner"
                    ):
                        marker = f"device:{detail}"
                        if marker in seen_device_artifacts:
                            continue
                        seen_device_artifacts.add(marker)
                        artifacts.append(
                            EmailArtifact("device", detail, src_ip, dst_ip, packet_no)
                        )
            if upper.startswith("AUTH "):
                _timeline_emit("Authentication", "SMTP AUTH", line)
                auth_match = AUTH_RE.search(line)
                if auth_match:
                    method = auth_match.group(1).upper()
                    blob = auth_match.group(2).strip()
                    auth_methods[method] += 1
                    if method == "LOGIN":
                        smtp_auth_login = True
                        smtp_expect = "username"
                        smtp_pending_user = None
                    if blob:
                        decoded = _safe_b64decode(blob)
                        if decoded and _looks_reasonable_credential(decoded):
                            artifacts.append(
                                EmailArtifact(
                                    "auth_blob", decoded, src_ip, dst_ip, packet_no
                                )
                            )
                            _extract_pair_tokens(
                                decoded, username_counts, password_counts, secret_counts
                            )
                            _timeline_emit(
                                "Authentication", "Decoded AUTH Blob", decoded
                            )
                            if method == "LOGIN":
                                decoded_clean = decoded.replace("\x00", " ").strip()
                                if decoded_clean and _looks_reasonable_credential(
                                    decoded_clean
                                ):
                                    if smtp_expect == "username":
                                        username_counts[decoded_clean] += 1
                                        smtp_pending_user = decoded_clean
                                        smtp_expect = "password"
                                        _timeline_emit(
                                            "Authentication", "Username", decoded_clean
                                        )
                                    elif smtp_expect == "password":
                                        password_counts[decoded_clean] += 1
                                        secret_counts[decoded_clean] += 1
                                        _timeline_emit(
                                            "Authentication", "Password", decoded_clean
                                        )
                                        smtp_auth_login = False
                                        smtp_expect = None
            for cmd in (
                "HELO",
                "EHLO",
                "MAIL FROM",
                "RCPT TO",
                "DATA",
                "STARTTLS",
                "QUIT",
            ):
                if upper.startswith(cmd):
                    smtp_command_counts[cmd] += 1
                    if cmd in {"EHLO", "HELO"}:
                        stage = "Session Setup"
                    elif cmd in {"MAIL FROM", "RCPT TO"}:
                        stage = "Envelope"
                    elif cmd == "DATA":
                        stage = "Message Build"
                    elif cmd == "QUIT":
                        stage = "Session End"
                    else:
                        stage = "Interaction"
                    _timeline_emit(stage, f"SMTP {cmd}", line)
                    break
            smtp_resp = SMTP_RESPONSE_RE.match(line)
            if smtp_resp:
                code = smtp_resp.group(1)
                response_counts[f"SMTP {code}"] += 1
                _timeline_emit("Server Response", f"SMTP {code}", line)
                if smtp_auth_login and line.startswith("334"):
                    challenge = line[4:].strip()
                    decoded_challenge = (_safe_b64decode(challenge) or "").lower()
                    if "username" in decoded_challenge:
                        smtp_expect = "username"
                    elif "password" in decoded_challenge:
                        smtp_expect = "password"
                if code in {"535", "534", "530", "454"}:
                    auth_failures_by_client[src_ip] += 1
                    smtp_auth_login = False
                    smtp_pending_user = None
                    smtp_expect = None
                if code in {"235", "250"}:
                    auth_success_by_client[src_ip] += 1
                    smtp_auth_login = False
                    smtp_pending_user = None
                    smtp_expect = None

            if (
                smtp_auth_login
                and smtp_expect in {"username", "password"}
                and re.fullmatch(r"[A-Za-z0-9+/=]{8,}", line)
            ):
                decoded_blob = _safe_b64decode(line)
                decoded_clean = (
                    decoded_blob.replace("\x00", " ").strip() if decoded_blob else ""
                )
                if decoded_clean and _looks_reasonable_credential(decoded_clean):
                    artifacts.append(
                        EmailArtifact(
                            "auth_blob", decoded_clean, src_ip, dst_ip, packet_no
                        )
                    )
                    if smtp_expect == "username":
                        username_counts[decoded_clean] += 1
                        smtp_pending_user = decoded_clean
                        smtp_expect = "password"
                        _timeline_emit("Authentication", "Username", decoded_clean)
                    elif smtp_expect == "password":
                        password_counts[decoded_clean] += 1
                        secret_counts[decoded_clean] += 1
                        _timeline_emit("Authentication", "Password", decoded_clean)
                        if smtp_pending_user:
                            artifacts.append(
                                EmailArtifact(
                                    "credential_pair",
                                    f"{smtp_pending_user}:{decoded_clean}",
                                    src_ip,
                                    dst_ip,
                                    packet_no,
                                )
                            )
                            _timeline_emit(
                                "Authentication",
                                "Credential Pair",
                                f"{smtp_pending_user}:{decoded_clean}",
                            )
                        smtp_auth_login = False
                        smtp_expect = None
            if upper.startswith(("MAIL FROM", "RCPT TO", "DATA", "RSET", "QUIT")):
                smtp_auth_login = False
                smtp_pending_user = None
                smtp_expect = None

            in_data = bool(state.get("in_data"))
            data_lines = list(state.get("data_lines") or [])
            body_preview_count = int(state.get("body_preview_count") or 0)
            if in_data:
                if line == ".":
                    mime_text = "\n".join(data_lines)
                    for match in ATTACHMENT_RE.findall(mime_text):
                        name = match.strip()
                        if name:
                            attachment_counts[name] += 1
                    mime_fingerprint = hashlib.sha256(
                        mime_text.encode("utf-8", errors="ignore")
                    ).hexdigest()[:24]
                    if mime_fingerprint not in seen_mime_messages and mime_text.strip():
                        seen_mime_messages.add(mime_fingerprint)
                        parsed_mime = _parse_mime_message(mime_text)
                        parsed_subject = str(
                            parsed_mime.get("subject", "") or ""
                        ).strip()
                        parsed_from = str(parsed_mime.get("from", "") or "").strip()
                        parsed_to = str(parsed_mime.get("to", "") or "").strip()
                        parsed_mid = str(
                            parsed_mime.get("message_id", "") or ""
                        ).strip()

                        if parsed_subject:
                            subject_counts[parsed_subject] += 1
                            artifacts.append(
                                EmailArtifact(
                                    "mime_subject",
                                    parsed_subject,
                                    src_ip,
                                    dst_ip,
                                    packet_no,
                                )
                            )
                            _timeline_emit(
                                "Message Build", "MIME Subject", parsed_subject
                            )
                            if SUSPICIOUS_SUBJECT_RE.search(parsed_subject):
                                detections.append(
                                    {
                                        "severity": "warning",
                                        "summary": "Suspicious MIME email subject content",
                                        "details": f"{src_ip}->{dst_ip} Subject: {parsed_subject[:140]}",
                                        "source": "EMAIL",
                                    }
                                )
                        if parsed_from:
                            for addr in EMAIL_RE.findall(parsed_from):
                                from_counts[addr] += 1
                                email_counts[addr] += 1
                                _timeline_emit("Message Build", "MIME From", addr)
                        if parsed_to:
                            for addr in EMAIL_RE.findall(parsed_to):
                                to_counts[addr] += 1
                                email_counts[addr] += 1
                                _timeline_emit("Message Build", "MIME Recipient", addr)
                        if parsed_mid:
                            message_id_counts[parsed_mid] += 1
                            artifacts.append(
                                EmailArtifact(
                                    "mime_message_id",
                                    parsed_mid,
                                    src_ip,
                                    dst_ip,
                                    packet_no,
                                )
                            )

                        parsed_emails = parsed_mime.get("emails", set())
                        if isinstance(parsed_emails, set):
                            for addr in parsed_emails:
                                email_counts[str(addr)] += 1

                        parsed_attachments = parsed_mime.get("attachments", [])
                        if isinstance(parsed_attachments, list):
                            for item in parsed_attachments[:50]:
                                if not isinstance(item, dict):
                                    continue
                                att_name = str(item.get("filename", "") or "").strip()
                                att_type = str(
                                    item.get("content_type", "") or ""
                                ).strip()
                                att_size = int(item.get("size", 0) or 0)
                                att_hash = str(item.get("sha256", "") or "").strip()
                                if att_name:
                                    attachment_counts[att_name] += 1
                                detail = f"{att_name or '-'} type={att_type or '-'} size={att_size}"
                                if att_hash:
                                    detail += f" sha256={att_hash[:16]}"
                                artifacts.append(
                                    EmailArtifact(
                                        "mime_attachment",
                                        detail,
                                        src_ip,
                                        dst_ip,
                                        packet_no,
                                    )
                                )
                                _timeline_emit("Attachment", "MIME Attachment", detail)

                        parsed_body = parsed_mime.get("body_lines", [])
                        if isinstance(parsed_body, list):
                            for body_line in parsed_body[:16]:
                                body_text = str(body_line).strip()
                                if not body_text:
                                    continue
                                _extract_pair_tokens(
                                    body_text,
                                    username_counts,
                                    password_counts,
                                    secret_counts,
                                )
                                _timeline_emit(
                                    "Message Body", "MIME Body Line", body_text
                                )
                    state["in_data"] = False
                    state["data_lines"] = []
                    state["body_preview_count"] = 0
                    _timeline_emit(
                        "Send", "SMTP Message End", "DATA terminator received"
                    )
                else:
                    data_lines.append(line)
                    state["data_lines"] = data_lines
                    if (
                        body_preview_count < 14
                        and _looks_human_text(line)
                        and not _looks_base64_blob(line)
                        and not line.lower().startswith(
                            ("content-", "mime-version:", "message-id:", "date:", "x-")
                        )
                    ):
                        _timeline_emit("Message Body", "Body Line", line)
                        body_preview_count += 1
                state["smtp_auth_login"] = smtp_auth_login
                state["smtp_pending_user"] = smtp_pending_user
                state["smtp_expect"] = smtp_expect
                state["body_preview_count"] = body_preview_count
                return
            if upper.startswith("DATA"):
                state["in_data"] = True
                state["data_lines"] = []
                state["body_preview_count"] = 0
            state["smtp_auth_login"] = smtp_auth_login
            state["smtp_pending_user"] = smtp_pending_user
            state["smtp_expect"] = smtp_expect

        if proto == "POP3":
            if upper.startswith("USER "):
                pop3_command_counts["USER"] += 1
                user = line[5:].strip()
                if user:
                    username_counts[user] += 1
                    _timeline_emit("Authentication", "POP3 USER", user)
            elif upper.startswith("PASS "):
                pop3_command_counts["PASS"] += 1
                password = line[5:].strip()
                if password:
                    password_counts[password] += 1
                    secret_counts[password] += 1
                    _timeline_emit("Authentication", "POP3 PASS", password)
            else:
                for cmd in (
                    "STAT",
                    "LIST",
                    "RETR",
                    "TOP",
                    "UIDL",
                    "DELE",
                    "QUIT",
                    "APOP",
                    "CAPA",
                ):
                    if upper.startswith(cmd):
                        pop3_command_counts[cmd] += 1
                        _timeline_emit("Interaction", f"POP3 {cmd}", line)
                        break
            pop_status = POP3_STATUS_RE.match(line)
            if pop_status:
                status_text = pop_status.group(1)
                response_counts[f"POP3 {status_text}"] += 1
                _timeline_emit("Server Response", f"POP3 {status_text}", line)
                if status_text == "-ERR":
                    auth_failures_by_client[src_ip] += 1
                elif status_text == "+OK":
                    auth_success_by_client[src_ip] += 1

        if proto == "IMAP":
            imap_match = IMAP_LINE_RE.match(line)
            if imap_match:
                cmd = imap_match.group(2).upper()
                args = imap_match.group(3).strip()
                imap_command_counts[cmd] += 1
                _timeline_emit("Interaction", f"IMAP {cmd}", line)
                if cmd == "LOGIN":
                    parts = [part.strip('"') for part in args.split()]
                    if parts:
                        username_counts[parts[0]] += 1
                        _timeline_emit("Authentication", "IMAP Username", parts[0])
                    if len(parts) > 1:
                        password_counts[parts[1]] += 1
                        secret_counts[parts[1]] += 1
                        _timeline_emit("Authentication", "IMAP Password", parts[1])
                if cmd == "AUTHENTICATE":
                    method = args.split()[0].upper() if args else "UNKNOWN"
                    auth_methods[f"IMAP-{method}"] += 1
            imap_status = IMAP_STATUS_RE.match(line)
            if imap_status:
                status_text = imap_status.group(1).upper()
                response_counts[f"IMAP {status_text}"] += 1
                _timeline_emit("Server Response", f"IMAP {status_text}", line)
                if status_text in {"NO", "BAD"}:
                    auth_failures_by_client[src_ip] += 1
                elif status_text == "OK":
                    auth_success_by_client[src_ip] += 1
            decoded = _safe_b64decode(line)
            if "\x00" in decoded or " " in decoded:
                _extract_pair_tokens(
                    decoded.replace("\x00", " "),
                    username_counts,
                    password_counts,
                    secret_counts,
                )

        for pattern, reason in SUSPICIOUS_CONTENT_RE:
            if pattern.search(line):
                detections.append(
                    {
                        "severity": "warning",
                        "summary": f"Suspicious email content: {reason}",
                        "details": f"{src_ip}->{dst_ip} {line[:140]}",
                        "source": "EMAIL",
                    }
                )

    try:
        for pkt_no, pkt in enumerate(reader, start=1):
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

            src_ip, dst_ip = extract_packet_endpoints(pkt)

            if not src_ip or not dst_ip:
                continue
            if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp_layer, "sport", 0) or 0)
            dport = int(getattr(tcp_layer, "dport", 0) or 0)
            payload: bytes
            try:
                payload = bytes(tcp_layer.payload)
            except Exception:
                payload = b""
            if not payload:
                continue

            text = _readable_text(payload)
            if not text:
                continue

            webmail_context = _detect_webmail_context(text)
            known_port_mail = sport in MAIL_PORTS or dport in MAIL_PORTS
            if (
                not known_port_mail
                and not _looks_like_mail_text(text)
                and webmail_context is None
            ):
                continue

            email_packets += 1
            if webmail_context is not None:
                proto = "WEBMAIL"
            else:
                proto = _protocol_from_ports_or_text(sport, dport, text)
            protocol_counts[proto] += 1

            if proto == "WEBMAIL":
                client_to_server = True
                first_line = (text.splitlines()[0] if text.splitlines() else "").strip()
                if first_line.upper().startswith("HTTP/"):
                    client_to_server = False
                elif dport in {80, 443, 8080, 8443}:
                    client_to_server = True
                elif sport in {80, 443, 8080, 8443}:
                    client_to_server = False
            else:
                client_to_server = _is_client_to_server(sport, dport, text)
            if client_to_server:
                client_ip = src_ip
                server_ip = dst_ip
                server_port = dport if dport else sport
            else:
                client_ip = dst_ip
                server_ip = src_ip
                server_port = sport if sport else dport

            client_counts[client_ip] += 1
            server_counts[server_ip] += 1
            server_ports[int(server_port)] += 1
            client_server_fanout[client_ip].add(server_ip)
            bytes_by_client_server[(client_ip, server_ip)] += pkt_len

            conv_key = (client_ip, server_ip, proto, int(server_port))
            conv = conv_map.get(conv_key)
            if conv is None:
                conv = {"packets": 0, "bytes": 0, "first_seen": ts, "last_seen": ts}
                conv_map[conv_key] = conv
                timeline_events.append(
                    EmailTimelineEvent(
                        ts=ts,
                        protocol=proto,
                        direction="C->S",
                        stage="Session Setup",
                        action=f"{proto} Connection",
                        detail=f"{client_ip}:{sport} -> {server_ip}:{server_port}",
                        src=client_ip,
                        dst=server_ip,
                        packet=pkt_no,
                    )
                )
            conv["packets"] = int(conv["packets"]) + 1
            conv["bytes"] = int(conv["bytes"]) + pkt_len
            if ts is not None:
                if conv["first_seen"] is None or ts < conv["first_seen"]:
                    conv["first_seen"] = ts
                if conv["last_seen"] is None or ts > conv["last_seen"]:
                    conv["last_seen"] = ts

            if proto == "WEBMAIL" and isinstance(webmail_context, dict):
                provider = str(webmail_context.get("provider", "")).strip()
                host = str(webmail_context.get("host", "")).strip()
                uri = str(webmail_context.get("uri", "")).strip()
                request_line = str(webmail_context.get("request_line", "")).strip()
                method = str(webmail_context.get("method", "")).strip()
                pages = list(webmail_context.get("pages", []) or [])
                actions = list(webmail_context.get("actions", []) or [])
                user_agent = str(webmail_context.get("user_agent", "")).strip()
                if provider:
                    webmail_provider_counts[provider] += 1
                if host and host != "-":
                    webmail_host_counts[host] += 1
                for page in pages:
                    if page:
                        webmail_page_counts[str(page)] += 1
                for action in actions:
                    if action:
                        webmail_action_counts[str(action)] += 1
                if request_line:
                    timeline_events.append(
                        EmailTimelineEvent(
                            ts=ts,
                            protocol="WEBMAIL",
                            direction="C->S" if client_to_server else "S->C",
                            stage="Webmail",
                            action=f"{method or 'HTTP'} Request",
                            detail=f"{provider} host={host or '-'} uri={uri or '-'} line={request_line[:120]}",
                            src=src_ip,
                            dst=dst_ip,
                            packet=pkt_no,
                        )
                    )
                if user_agent and len(user_agent) > 2:
                    marker = f"webmail-ua:{provider}:{user_agent[:120]}"
                    if marker not in seen_device_artifacts:
                        seen_device_artifacts.add(marker)
                        artifacts.append(
                            EmailArtifact(
                                "webmail_user_agent",
                                f"{provider} {user_agent[:120]}",
                                src_ip,
                                dst_ip,
                                pkt_no,
                            )
                        )
                if host and host != "-":
                    artifacts.append(
                        EmailArtifact(
                            "webmail_host", f"{provider} {host}", src_ip, dst_ip, pkt_no
                        )
                    )

            state = _stream_bucket(src_ip, dst_ip, sport, dport)
            state["buf"] = str(state.get("buf", "")) + text
            buf = str(state.get("buf", ""))
            if "\n" not in buf:
                continue
            raw_lines = buf.splitlines()
            if not (buf.endswith("\n") or buf.endswith("\r\n")):
                state["buf"] = raw_lines[-1]
                raw_lines = raw_lines[:-1]
            else:
                state["buf"] = ""
            lines = [line.strip() for line in raw_lines if line.strip()]

            for line in lines[:250]:
                if len(plaintext_strings) < 5000 or line in plaintext_strings:
                    plaintext_strings[line] += 1
                _process_line(
                    line,
                    src_ip,
                    dst_ip,
                    pkt_no,
                    proto,
                    ts,
                    "C->S" if client_to_server else "S->C",
                    state,
                )

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    deterministic_checks: dict[str, list[str]] = {
        "credential_exposure": [],
        "auth_abuse": [],
        "suspicious_attachments": [],
        "phishing_indicators": [],
        "exfiltration_signals": [],
        "server_fanout": [],
        "webmail_activity": [],
        "webmail_credential_submission": [],
    }

    if username_counts or password_counts or secret_counts:
        top_users = ", ".join(
            f"{name}({count})" for name, count in username_counts.most_common(6)
        )
        top_passwords = ", ".join(
            f"{name}({count})" for name, count in password_counts.most_common(6)
        )
        if top_users:
            deterministic_checks["credential_exposure"].append(
                f"usernames: {top_users}"
            )
        if top_passwords:
            deterministic_checks["credential_exposure"].append(
                f"passwords: {top_passwords}"
            )
        detections.append(
            {
                "severity": "high",
                "summary": "Email credential exposure detected",
                "details": f"Observed {sum(password_counts.values())} password and {sum(secret_counts.values())} secret artifacts.",
                "source": "EMAIL",
            }
        )

    for client, count in auth_failures_by_client.items():
        if count >= 6:
            deterministic_checks["auth_abuse"].append(
                f"{client} had {count} mail authentication failures"
            )
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Mail authentication abuse suspected",
                    "details": f"{client} produced {count} failed auth responses.",
                    "source": "EMAIL",
                }
            )

    for filename, count in attachment_counts.items():
        suffix = Path(filename).suffix.lower()
        if suffix in RISKY_EXTENSIONS and count > 0:
            deterministic_checks["suspicious_attachments"].append(
                f"{filename} ({count})"
            )

    if deterministic_checks["suspicious_attachments"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Potentially dangerous email attachments observed",
                "details": ", ".join(
                    deterministic_checks["suspicious_attachments"][:8]
                ),
                "source": "EMAIL",
            }
        )

    for subject, count in subject_counts.items():
        if SUSPICIOUS_SUBJECT_RE.search(subject):
            deterministic_checks["phishing_indicators"].append(f"{subject} ({count})")
    if deterministic_checks["phishing_indicators"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential phishing indicators in email subjects",
                "details": ", ".join(deterministic_checks["phishing_indicators"][:8]),
                "source": "EMAIL",
            }
        )

    for (client, server), bytes_sent in bytes_by_client_server.items():
        if bytes_sent >= 1_000_000:
            deterministic_checks["exfiltration_signals"].append(
                f"{client}->{server} sent {bytes_sent} bytes over mail protocols"
            )
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Potential email data exfiltration",
                    "details": f"{client}->{server} sent {bytes_sent} bytes.",
                    "source": "EMAIL",
                }
            )

    for client, servers in client_server_fanout.items():
        if len(servers) >= 8:
            deterministic_checks["server_fanout"].append(
                f"{client} contacted {len(servers)} mail servers"
            )
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Mail server fan-out/scanning behavior",
                    "details": f"{client} contacted {len(servers)} unique mail endpoints.",
                    "source": "EMAIL",
                }
            )

    if webmail_provider_counts or webmail_host_counts:
        deterministic_checks["webmail_activity"].append(
            "providers: "
            + ", ".join(
                f"{name}({count})"
                for name, count in webmail_provider_counts.most_common(8)
            )
        )
        deterministic_checks["webmail_activity"].append(
            "hosts: "
            + ", ".join(
                f"{name}({count})" for name, count in webmail_host_counts.most_common(8)
            )
        )
        detections.append(
            {
                "severity": "info",
                "summary": "Webmail client/page activity identified",
                "details": f"Providers={len(webmail_provider_counts)} Hosts={len(webmail_host_counts)} Actions={sum(webmail_action_counts.values())}",
                "source": "EMAIL",
            }
        )

    if webmail_action_counts.get("POST", 0) > 0 and (
        username_counts or password_counts
    ):
        deterministic_checks["webmail_credential_submission"].append(
            f"Observed POST webmail actions ({webmail_action_counts.get('POST', 0)}) with extracted username/password artifacts."
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential webmail credential submission observed",
                "details": f"POST actions={webmail_action_counts.get('POST', 0)} usernames={sum(username_counts.values())} passwords={sum(password_counts.values())}",
                "source": "EMAIL",
            }
        )

    conversations: list[EmailConversation] = []
    for (client_ip, server_ip, proto, port), item in conv_map.items():
        conversations.append(
            EmailConversation(
                client_ip=client_ip,
                server_ip=server_ip,
                protocol=proto,
                server_port=port,
                packets=int(item["packets"]),
                bytes=int(item["bytes"]),
                first_seen=item.get("first_seen"),
                last_seen=item.get("last_seen"),
            )
        )
    conversations.sort(key=lambda c: c.packets, reverse=True)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    timeline_events.sort(
        key=lambda item: (item.ts is None, item.ts or 0.0, item.packet or 0)
    )
    if len(timeline_events) > 1200:
        timeline_events = timeline_events[:1200]

    return EmailSummary(
        path=path,
        total_packets=total_packets,
        email_packets=email_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        email_counts=email_counts,
        from_counts=from_counts,
        to_counts=to_counts,
        subject_counts=subject_counts,
        username_counts=username_counts,
        password_counts=password_counts,
        secret_counts=secret_counts,
        auth_methods=auth_methods,
        smtp_command_counts=smtp_command_counts,
        imap_command_counts=imap_command_counts,
        pop3_command_counts=pop3_command_counts,
        response_counts=response_counts,
        webmail_provider_counts=webmail_provider_counts,
        webmail_host_counts=webmail_host_counts,
        webmail_page_counts=webmail_page_counts,
        webmail_action_counts=webmail_action_counts,
        attachment_counts=attachment_counts,
        message_id_counts=message_id_counts,
        plaintext_strings=plaintext_strings,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        timeline_events=timeline_events,
        deterministic_checks=deterministic_checks,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_email_summaries(summaries: Iterable[EmailSummary]) -> EmailSummary:
    summary_list = list(summaries)
    if not summary_list:
        return EmailSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            email_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            email_counts=Counter(),
            from_counts=Counter(),
            to_counts=Counter(),
            subject_counts=Counter(),
            username_counts=Counter(),
            password_counts=Counter(),
            secret_counts=Counter(),
            auth_methods=Counter(),
            smtp_command_counts=Counter(),
            imap_command_counts=Counter(),
            pop3_command_counts=Counter(),
            response_counts=Counter(),
            webmail_provider_counts=Counter(),
            webmail_host_counts=Counter(),
            webmail_page_counts=Counter(),
            webmail_action_counts=Counter(),
            attachment_counts=Counter(),
            message_id_counts=Counter(),
            plaintext_strings=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            timeline_events=[],
            deterministic_checks={},
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=0.0,
        )

    total_packets = 0
    email_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds = 0.0

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    email_counts: Counter[str] = Counter()
    from_counts: Counter[str] = Counter()
    to_counts: Counter[str] = Counter()
    subject_counts: Counter[str] = Counter()
    username_counts: Counter[str] = Counter()
    password_counts: Counter[str] = Counter()
    secret_counts: Counter[str] = Counter()
    auth_methods: Counter[str] = Counter()
    smtp_command_counts: Counter[str] = Counter()
    imap_command_counts: Counter[str] = Counter()
    pop3_command_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    webmail_provider_counts: Counter[str] = Counter()
    webmail_host_counts: Counter[str] = Counter()
    webmail_page_counts: Counter[str] = Counter()
    webmail_action_counts: Counter[str] = Counter()
    attachment_counts: Counter[str] = Counter()
    message_id_counts: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[EmailArtifact] = []
    timeline_events: list[EmailTimelineEvent] = []
    errors: list[str] = []
    deterministic_checks: dict[str, list[str]] = defaultdict(list)

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    seen_detections: set[tuple[str, str, str]] = set()
    seen_errors: set[str] = set()
    seen_checks: set[tuple[str, str]] = set()

    for summary in summary_list:
        total_packets += summary.total_packets
        email_packets += summary.email_packets
        total_bytes += summary.total_bytes
        total_messages += summary.total_messages
        if summary.first_seen is not None and (
            first_seen is None or summary.first_seen < first_seen
        ):
            first_seen = summary.first_seen
        if summary.last_seen is not None and (
            last_seen is None or summary.last_seen > last_seen
        ):
            last_seen = summary.last_seen
        if summary.duration_seconds is not None:
            duration_seconds += summary.duration_seconds

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        server_ports.update(summary.server_ports)
        protocol_counts.update(summary.protocol_counts)
        email_counts.update(summary.email_counts)
        from_counts.update(summary.from_counts)
        to_counts.update(summary.to_counts)
        subject_counts.update(summary.subject_counts)
        username_counts.update(summary.username_counts)
        password_counts.update(summary.password_counts)
        secret_counts.update(summary.secret_counts)
        auth_methods.update(summary.auth_methods)
        smtp_command_counts.update(summary.smtp_command_counts)
        imap_command_counts.update(summary.imap_command_counts)
        pop3_command_counts.update(summary.pop3_command_counts)
        response_counts.update(summary.response_counts)
        webmail_provider_counts.update(summary.webmail_provider_counts)
        webmail_host_counts.update(summary.webmail_host_counts)
        webmail_page_counts.update(summary.webmail_page_counts)
        webmail_action_counts.update(summary.webmail_action_counts)
        attachment_counts.update(summary.attachment_counts)
        message_id_counts.update(summary.message_id_counts)
        plaintext_strings.update(summary.plaintext_strings)

        for det in summary.detections:
            key = (
                str(det.get("severity", "")),
                str(det.get("summary", "")),
                str(det.get("details", "")),
            )
            if key in seen_detections:
                continue
            seen_detections.add(key)
            detections.append(det)

        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        timeline_events.extend(summary.timeline_events)

        for key, values in (summary.deterministic_checks or {}).items():
            for value in values:
                marker = (str(key), str(value))
                if marker in seen_checks:
                    continue
                seen_checks.add(marker)
                deterministic_checks[str(key)].append(str(value))

        for err in summary.errors:
            if err in seen_errors:
                continue
            seen_errors.add(err)
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
            if conv.first_seen is not None and (
                current["first_seen"] is None or conv.first_seen < current["first_seen"]
            ):
                current["first_seen"] = conv.first_seen
            if conv.last_seen is not None and (
                current["last_seen"] is None or conv.last_seen > current["last_seen"]
            ):
                current["last_seen"] = conv.last_seen

    conversations = [
        EmailConversation(
            client_ip=key[0],
            server_ip=key[1],
            protocol=key[2],
            server_port=key[3],
            packets=int(value["packets"]),
            bytes=int(value["bytes"]),
            first_seen=value.get("first_seen"),
            last_seen=value.get("last_seen"),
        )
        for key, value in conv_map.items()
    ]
    conversations.sort(key=lambda c: c.packets, reverse=True)

    timeline_events.sort(
        key=lambda item: (item.ts is None, item.ts or 0.0, item.packet or 0)
    )

    return EmailSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        email_packets=email_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        email_counts=email_counts,
        from_counts=from_counts,
        to_counts=to_counts,
        subject_counts=subject_counts,
        username_counts=username_counts,
        password_counts=password_counts,
        secret_counts=secret_counts,
        auth_methods=auth_methods,
        smtp_command_counts=smtp_command_counts,
        imap_command_counts=imap_command_counts,
        pop3_command_counts=pop3_command_counts,
        response_counts=response_counts,
        webmail_provider_counts=webmail_provider_counts,
        webmail_host_counts=webmail_host_counts,
        webmail_page_counts=webmail_page_counts,
        webmail_action_counts=webmail_action_counts,
        attachment_counts=attachment_counts,
        message_id_counts=message_id_counts,
        plaintext_strings=plaintext_strings,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        timeline_events=timeline_events,
        deterministic_checks={k: list(v) for k, v in deterministic_checks.items()},
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
