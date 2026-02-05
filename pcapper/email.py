from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Optional
import base64
import re

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


EMAIL_PORTS = {
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP",
    24: "LMTP",
    110: "POP3",
    995: "POP3S",
    109: "POP2",
    143: "IMAP",
    993: "IMAPS",
    4190: "MANAGESIEVE",
}

SMTP_COMMANDS = ("HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "RSET", "NOOP", "QUIT", "STARTTLS")
POP3_COMMANDS = ("USER", "PASS", "STAT", "LIST", "RETR", "DELE", "QUIT", "CAPA")
IMAP_COMMANDS = ("LOGIN", "AUTHENTICATE", "SELECT", "FETCH", "LIST", "IDLE", "LOGOUT")
SIEVE_COMMANDS = ("AUTHENTICATE", "STARTTLS", "LOGOUT", "CAPABILITY", "PUTSCRIPT", "SETACTIVE")


@dataclass(frozen=True)
class EmailSummary:
    path: Path
    total_packets: int
    email_packets: int
    protocols: Counter[str]
    sessions: int
    commands: Counter[str]
    auth_users: Counter[str]
    auth_passwords: Counter[str]
    mail_from: Counter[str]
    rcpt_to: Counter[str]
    subjects: Counter[str]
    message_ids: Counter[str]
    attachments: Counter[str]
    urls: Counter[str]
    errors: list[str]


def _reassemble_stream(chunks: list[tuple[int, bytes]]) -> bytes:
    if not chunks:
        return b""
    chunks.sort(key=lambda item: item[0])
    assembled = bytearray()
    expected = chunks[0][0]
    for seq, payload in chunks:
        if not payload:
            continue
        if seq > expected:
            expected = seq
        if seq < expected:
            overlap = expected - seq
            if overlap >= len(payload):
                continue
            payload = payload[overlap:]
        assembled.extend(payload)
        expected = seq + len(payload)
        if len(assembled) > 50_000_000:
            break
    return bytes(assembled)


def _guess_protocol(sport: int, dport: int, text: str) -> str:
    for port in (sport, dport):
        if port in EMAIL_PORTS:
            return EMAIL_PORTS[port]
    upper = text.upper()
    if any(cmd in upper for cmd in SMTP_COMMANDS):
        return "SMTP"
    if any(cmd in upper for cmd in POP3_COMMANDS):
        return "POP3"
    if "IMAP" in upper or any(cmd in upper for cmd in IMAP_COMMANDS):
        return "IMAP"
    if "SIEVE" in upper or any(cmd in upper for cmd in SIEVE_COMMANDS):
        return "MANAGESIEVE"
    if "JMAP" in upper or "application/json" in upper:
        return "JMAP"
    return "UNKNOWN"


def _decode_base64(value: str) -> Optional[str]:
    try:
        raw = base64.b64decode(value.strip(), validate=False)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _extract_auth_plain(value: str) -> tuple[Optional[str], Optional[str]]:
    decoded = _decode_base64(value)
    if not decoded:
        return None, None
    parts = decoded.split("\x00")
    if len(parts) >= 3:
        return parts[1] or None, parts[2] or None
    if len(parts) == 2:
        return parts[0] or None, parts[1] or None
    return None, None


def _extract_addresses(value: str) -> list[str]:
    matches = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value)
    return [m.lower() for m in matches]


def _extract_urls(value: str) -> list[str]:
    matches = re.findall(r"https?://[^\s'\"<>]+", value)
    return matches


def _parse_email_segment(segment: bytes) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    try:
        msg = BytesParser(policy=policy.default).parsebytes(segment)
    except Exception:
        return [], [], [], [], []
    from_vals = []
    to_vals = []
    subjects = []
    message_ids = []
    attachments = []

    if msg.get("From"):
        from_vals.extend(_extract_addresses(msg.get("From", "")))
    for header in ("To", "Cc", "Bcc"):
        if msg.get(header):
            to_vals.extend(_extract_addresses(msg.get(header, "")))
    if msg.get("Subject"):
        subjects.append(str(msg.get("Subject")))
    if msg.get("Message-ID"):
        message_ids.append(str(msg.get("Message-ID")))

    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        cd = part.get("Content-Disposition", "") or ""
        match = re.search(r"filename\*?=\"?([^\";]+)", cd, re.IGNORECASE)
        if match:
            attachments.append(match.group(1))
    return from_vals, to_vals, subjects, message_ids, attachments


def analyze_email(path: Path, show_status: bool = True) -> EmailSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for email analysis.")
        return EmailSummary(
            path=path,
            total_packets=0,
            email_packets=0,
            protocols=Counter(),
            sessions=0,
            commands=Counter(),
            auth_users=Counter(),
            auth_passwords=Counter(),
            mail_from=Counter(),
            rcpt_to=Counter(),
            subjects=Counter(),
            message_ids=Counter(),
            attachments=Counter(),
            urls=Counter(),
            errors=errors,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)

    total_packets = 0
    email_packets = 0
    protocols: Counter[str] = Counter()
    commands: Counter[str] = Counter()
    auth_users: Counter[str] = Counter()
    auth_passwords: Counter[str] = Counter()
    mail_from: Counter[str] = Counter()
    rcpt_to: Counter[str] = Counter()
    subjects: Counter[str] = Counter()
    message_ids: Counter[str] = Counter()
    attachments: Counter[str] = Counter()
    urls: Counter[str] = Counter()

    stream_chunks: dict[tuple[str, str, int, int], list[tuple[int, bytes]]] = defaultdict(list)

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

            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue
            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp_layer, "sport", 0) or 0)
            dport = int(getattr(tcp_layer, "dport", 0) or 0)
            seq = int(getattr(tcp_layer, "seq", 0) or 0)
            payload = b""
            try:
                payload = bytes(tcp_layer.payload)
            except Exception:
                payload = b""

            if payload:
                stream_chunks[(src_ip or "", dst_ip or "", sport, dport)].append((seq, payload))
    finally:
        status.finish()
        reader.close()

    sessions = 0
    for (src_ip, dst_ip, sport, dport), chunks in stream_chunks.items():
        data = _reassemble_stream(chunks)
        if not data:
            continue
        try:
            text = data.decode("latin-1", errors="ignore")
        except Exception:
            continue
        protocol = _guess_protocol(sport, dport, text)
        if protocol == "UNKNOWN":
            continue
        protocols[protocol] += 1
        sessions += 1
        email_packets += len(chunks)

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        auth_login_pending = False
        auth_login_user = None
        for line in lines:
            upper = line.upper()
            for cmd in SMTP_COMMANDS + POP3_COMMANDS + IMAP_COMMANDS + SIEVE_COMMANDS:
                if upper.startswith(cmd):
                    commands[cmd] += 1
                    break

            if upper.startswith("MAIL FROM"):
                mail_from.update(_extract_addresses(line))
            if upper.startswith("RCPT TO"):
                rcpt_to.update(_extract_addresses(line))

            if upper.startswith("AUTH PLAIN"):
                parts = line.split()
                if len(parts) >= 3:
                    user, pwd = _extract_auth_plain(parts[2])
                    if user:
                        auth_users[user] += 1
                    if pwd:
                        auth_passwords[pwd] += 1
            elif upper.startswith("AUTH LOGIN"):
                auth_login_pending = True
                auth_login_user = None
            elif auth_login_pending:
                decoded = _decode_base64(line)
                if decoded:
                    if auth_login_user is None:
                        auth_login_user = decoded
                        auth_users[decoded] += 1
                    else:
                        auth_passwords[decoded] += 1
                        auth_login_pending = False
                else:
                    auth_login_pending = False

            if upper.startswith("USER "):
                value = line.split(" ", 1)[1]
                auth_users[value] += 1
            if upper.startswith("PASS "):
                value = line.split(" ", 1)[1]
                auth_passwords[value] += 1

        urls.update({url: urls.get(url, 0) + 1 for url in _extract_urls(text)})

        segments: list[bytes] = []
        if b"\r\n.\r\n" in data:
            segments = [seg for seg in data.split(b"\r\n.\r\n") if seg]
        elif b"Content-Type" in data or b"MIME-Version" in data:
            segments = [data]

        for seg in segments:
            from_vals, to_vals, subj_vals, msg_ids, attach_vals = _parse_email_segment(seg)
            for value in from_vals:
                mail_from[value] += 1
            for value in to_vals:
                rcpt_to[value] += 1
            for value in subj_vals:
                subjects[value] += 1
            for value in msg_ids:
                message_ids[value] += 1
            for value in attach_vals:
                attachments[value] += 1

    return EmailSummary(
        path=path,
        total_packets=total_packets,
        email_packets=email_packets,
        protocols=protocols,
        sessions=sessions,
        commands=commands,
        auth_users=auth_users,
        auth_passwords=auth_passwords,
        mail_from=mail_from,
        rcpt_to=rcpt_to,
        subjects=subjects,
        message_ids=message_ids,
        attachments=attachments,
        urls=urls,
        errors=errors,
    )
