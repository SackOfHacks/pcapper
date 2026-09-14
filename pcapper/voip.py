"""Phone-over-IP analysis: signalling, media, provisioning and NAT traversal.

``--voip`` is the whole call path, not one protocol:

===================  ======================================================
Signalling           SIP (any port, UDP/TCP/TLS), SIP over WebSocket,
                     Cisco SCCP/Skinny, MGCP, MEGACO/H.248, IAX2,
                     H.323 (H.225 call signalling, H.225 RAS, H.245)
Session description  SDP — addresses, ports, codecs, direction, SRTP keys
Media                RTP, RTCP, SRTP, T.38 fax over UDPTL
NAT traversal        STUN / TURN / ICE
Provisioning         TFTP and HTTP phone configuration fetches
Numbering            ENUM (``e164.arpa`` NAPTR lookups)
===================  ======================================================

The point of covering all of it is that an investigation rarely gets to pick
the protocol. A Cisco shop signals with Skinny, an Asterisk trunk uses IAX2, a
video bridge still speaks H.323, and the gateway that actually placed the call
is driven by MGCP. Reading only SIP on such a network returns "no VoIP traffic"
on a capture that is nothing but VoIP traffic.

What the module goes out of its way to recover, because it is what an
investigation actually needs:

**Who called whom, and what happened.** Dialogs with participants, dialled
number, disposition and duration — from whichever protocol carried them.

**Credentials.** SIP Digest responses (emitted as ``hashcat -m 11400`` lines),
IAX2 MD5 challenge/response pairs and plaintext IAX2 passwords, TURN long-term
credentials, and the phone configuration files fetched over TFTP that contain
the SIP secret in the clear.

**Keypad digits.** RFC 4733 telephone-events in RTP, SIP INFO
``application/dtmf-relay``, Skinny ``KeypadButton``, and MGCP observed events.
Those digits are routinely IVR PINs, calling-card numbers and card data.

**Media keys.** ``a=crypto ... inline:`` in SDP puts the SRTP master key in the
signalling; if the signalling was not itself encrypted, every "encrypted" call
in the capture is decryptable by whoever captured it.

**The audio itself.** With ``--voip-out``, G.711 streams are decoded to WAV.

Not to be confused with :mod:`pcapper.srtp`, which is GE SRTP — an industrial
PLC protocol on ports 18245/18246, unrelated to Secure RTP.
"""

from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import (
    extract_packet_endpoints,
    is_public_ip,
    memoize_analysis,
    packet_length,
    restrict_dir_permissions,
    restrict_permissions,
    safe_float,
)
from .voip_media import (
    RTP_STATIC_PAYLOAD_TYPES,
    STUN_PORTS,
    RtpState,
    decode_dtmf_event,
    is_rtcp,
    is_rtp_candidate,
    is_stun,
    is_udptl_t38,
    parse_rtcp,
    parse_rtp,
    parse_stun,
    parse_t38,
    update_rtp_state,
    write_wav,
)
from .voip_signaling import (
    H225_PORT,
    H225_RAS_PORTS,
    MEGACO_PORTS,
    MGCP_PORTS,
    SCCP_PORTS,
    TFTP_PORT,
    classify_provisioning,
    looks_like_iax2,
    looks_like_mgcp,
    looks_like_sccp,
    looks_like_tpkt,
    looks_like_unistim,
    parse_iax2,
    parse_megaco,
    parse_mgcp,
    parse_q931,
    parse_ras,
    parse_sccp,
    parse_tftp_request,
)

try:  # pragma: no cover - exercised only when scapy is absent
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


# --- limits -----------------------------------------------------------------
# Bounded so a large or hostile capture cannot exhaust memory. A capture that
# hits a cap is still analysed; the excess is counted and reported, not stored.
MAX_CALLS = int(os.getenv("PCAPPER_VOIP_MAX_CALLS", "5000"))
MAX_CREDENTIALS = int(os.getenv("PCAPPER_VOIP_MAX_CREDENTIALS", "2000"))
MAX_RTP_STREAMS = int(os.getenv("PCAPPER_VOIP_MAX_RTP_STREAMS", "5000"))
MAX_DTMF_DIGITS = int(os.getenv("PCAPPER_VOIP_MAX_DTMF_DIGITS", "256"))
MAX_MESSAGE_BODY = int(os.getenv("PCAPPER_VOIP_MAX_BODY", "512"))
# 8 kHz 16-bit mono: 16 kB per second, so 16 MB is roughly 17 minutes a stream.
MAX_AUDIO_BYTES = int(os.getenv("PCAPPER_VOIP_MAX_AUDIO_BYTES", str(16 * 1024 * 1024)))
MIN_RTP_PACKETS = int(os.getenv("PCAPPER_VOIP_MIN_RTP_PACKETS", "4"))


# --- protocol constants -----------------------------------------------------
SIP_PORTS = {5060, 5061}
# Ports that commonly carry SIP but are not the registered pair. Traffic here is
# analysed and reported as non-standard, which is itself worth knowing.
SIP_ALT_PORTS = {5062, 5064, 5065, 5066, 5070, 5080, 5081, 5090, 5160, 5161}

SIP_METHODS = frozenset(
    {
        "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "PRACK",
        "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE",
    }
)

SIP_SCANNER_PATTERNS = [
    (re.compile(r"friendly-scanner", re.I), "SIPVicious (svmap/svwar/svcrack)"),
    (re.compile(r"sipvicious", re.I), "SIPVicious"),
    (re.compile(r"sipcli", re.I), "sipcli"),
    (re.compile(r"sundayddr", re.I), "sundayddr scanner"),
    (re.compile(r"VaxSIPUserAgent", re.I), "VaxSIPUserAgent (scanner / toll fraud)"),
    (re.compile(r"sipsak", re.I), "sipsak"),
    (re.compile(r"\bsmap\b", re.I), "smap SIP scanner"),
    (re.compile(r"SIPp\b", re.I), "SIPp (load/stress generator)"),
    (re.compile(r"\bnmap\b|Nmap NSE", re.I), "Nmap"),
    (re.compile(r"sip-?scan", re.I), "sip-scan"),
    (re.compile(r"pplsip|iWar|Sivus", re.I), "SIP war-dialer"),
    (re.compile(r"sipptk|SIPVicious|svcrack", re.I), "SIP toolkit"),
]

# One-letter compact header forms (RFC 3261 s7.3.3). Real phones use these; a
# parser that only knows the long spellings silently loses the Call-ID, and
# every dialog with it.
COMPACT_HEADERS = {
    "i": "call-id", "f": "from", "t": "to", "v": "via", "m": "contact",
    "c": "content-type", "l": "content-length", "s": "subject",
    "k": "supported", "e": "content-encoding", "o": "event", "r": "refer-to",
    "b": "referred-by", "u": "allow-events", "x": "session-expires",
    "a": "accept-contact", "j": "reject-contact", "d": "request-disposition",
    "y": "identity", "n": "identity-info",
}

_START_LINE_RE = re.compile(
    r"^(?:(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+SIP/2\.0"
    r"|SIP/2\.0\s+(?P<code>\d{3})\s*(?P<reason>.*))$"
)
_URI_RE = re.compile(r"<([^>]+)>|(sips?:[^\s;,>]+)", re.I)
_AUTH_PARAM_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')
_SIP_USER_RE = re.compile(r"sips?:([^@;>\s]+)(?:@([^;>\s,]+))?", re.I)
_INTERNATIONAL_RE = re.compile(r"^\+?(?:00)?([1-9]\d{7,})$")
_DTMF_RELAY_RE = re.compile(r"Signal\s*=\s*([0-9*#A-D])", re.I)
_ENUM_RE = re.compile(r"(?:\d\.){4,}e164\.arpa", re.I)

# Premium-rate and high-cost destination prefixes that dominate real toll-fraud
# cases. Reported as a shape to check, never asserted as fraud.
PREMIUM_PREFIXES = (
    "900", "976", "1900", "1976",
    "88", "881", "882", "883",
    "239", "247", "248", "252", "255", "257", "261", "265", "268", "269",
    "290", "291", "297", "298", "299",
    "371", "372", "373", "374", "375", "376", "377", "378", "379",
    "381", "382", "383", "385", "386", "387", "389",
    "670", "672", "673", "674", "675", "676", "677", "678", "679",
    "680", "681", "682", "683", "685", "686", "687", "688", "689",
    "690", "691", "692",
)

CLEARTEXT_SECRET_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*(\S+)", re.I
)
FLAGGISH_RE = re.compile(r"\b(?:flag|ctf|key|pcapper)\{[^}]{1,120}\}", re.I)


# --- data model -------------------------------------------------------------
@dataclass(frozen=True)
class VoipCredential:
    """Recovered authentication material, from whichever protocol carried it.

    ``crackable`` holds a ready tool line where one exists — a ``hashcat``
    ``-m 11400`` candidate for SIP Digest, or the challenge/response pair for
    IAX2. pcapper deliberately does not redact what it recovers.
    """

    ts: Optional[float]
    protocol: str
    src_ip: str
    dst_ip: str
    context: str
    username: str
    realm: str
    secret: str
    crackable: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ts": self.ts,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "context": self.context,
            "username": self.username,
            "realm": self.realm,
            "secret": self.secret,
            "crackable": self.crackable,
        }


@dataclass(frozen=True)
class SdpMedia:
    """One ``m=`` line and the attributes attached to it."""

    call_id: str
    owner_ip: str
    media_type: str
    transport: str
    address: str
    port: int
    codecs: tuple[str, ...]
    direction: str
    crypto_suites: tuple[str, ...]
    cleartext_keys: tuple[str, ...]
    dtls_fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return {
            "call_id": self.call_id,
            "owner_ip": self.owner_ip,
            "media_type": self.media_type,
            "transport": self.transport,
            "address": self.address,
            "port": self.port,
            "codecs": list(self.codecs),
            "direction": self.direction,
            "crypto_suites": list(self.crypto_suites),
            "cleartext_keys": list(self.cleartext_keys),
            "dtls_fingerprint": self.dtls_fingerprint,
        }


@dataclass(frozen=True)
class VoipCall:
    """A call, from whichever signalling protocol described it."""

    protocol: str
    call_id: str
    from_uri: str
    to_uri: str
    from_user: str
    to_user: str
    methods: tuple[str, ...]
    caller_ip: str
    callee_ip: str
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    status_codes: tuple[int, ...]
    final_status: Optional[int]
    disposition: str
    user_agents: tuple[str, ...]
    authenticated: bool
    challenged: bool
    dtmf: str
    media: tuple[SdpMedia, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "call_id": self.call_id,
            "from_uri": self.from_uri,
            "to_uri": self.to_uri,
            "from_user": self.from_user,
            "to_user": self.to_user,
            "methods": list(self.methods),
            "caller_ip": self.caller_ip,
            "callee_ip": self.callee_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
            "status_codes": list(self.status_codes),
            "final_status": self.final_status,
            "disposition": self.disposition,
            "user_agents": list(self.user_agents),
            "authenticated": self.authenticated,
            "challenged": self.challenged,
            "dtmf": self.dtmf,
            "media": [m.to_dict() for m in self.media],
        }


@dataclass(frozen=True)
class VoipRegistration:
    """An address-of-record or device and the contacts that bound to it."""

    protocol: str
    aor: str
    contacts: tuple[str, ...]
    source_ips: tuple[str, ...]
    user_agents: tuple[str, ...]
    attempts: int
    successes: int
    challenges: int
    failures: int
    expires: Optional[int]
    first_seen: Optional[float]
    last_seen: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "aor": self.aor,
            "contacts": list(self.contacts),
            "source_ips": list(self.source_ips),
            "user_agents": list(self.user_agents),
            "attempts": self.attempts,
            "successes": self.successes,
            "challenges": self.challenges,
            "failures": self.failures,
            "expires": self.expires,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(frozen=True)
class RtpStreamSummary:
    """One media stream, identified by its 5-tuple and SSRC."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ssrc: int
    payload_type: int
    codec: str
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    expected_packets: int
    lost_packets: int
    out_of_order: int
    duplicates: int
    jitter_ms: float
    signaled: bool
    encrypted: bool
    dtmf_digits: str
    audio_path: str

    @property
    def loss_percent(self) -> float:
        if self.expected_packets <= 0:
            return 0.0
        return round(100.0 * self.lost_packets / self.expected_packets, 2)

    def to_dict(self) -> dict[str, object]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "ssrc": f"0x{self.ssrc:08x}",
            "payload_type": self.payload_type,
            "codec": self.codec,
            "packets": self.packets,
            "bytes": self.bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
            "expected_packets": self.expected_packets,
            "lost_packets": self.lost_packets,
            "loss_percent": self.loss_percent,
            "out_of_order": self.out_of_order,
            "duplicates": self.duplicates,
            "jitter_ms": self.jitter_ms,
            "signaled": self.signaled,
            "encrypted": self.encrypted,
            "dtmf_digits": self.dtmf_digits,
            "audio_path": self.audio_path,
        }


@dataclass(frozen=True)
class VoipMessage:
    """An in-band message body: SIP MESSAGE/INFO, or a Skinny display string."""

    ts: Optional[float]
    protocol: str
    src_ip: str
    dst_ip: str
    kind: str
    content_type: str
    from_uri: str
    to_uri: str
    body: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ts": self.ts,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "kind": self.kind,
            "content_type": self.content_type,
            "from_uri": self.from_uri,
            "to_uri": self.to_uri,
            "body": self.body,
        }


@dataclass(frozen=True)
class DtmfSequence:
    """Keypad digits recovered from one source, however they were carried."""

    protocol: str
    source: str
    destination: str
    stream: str
    digits: str

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "source": self.source,
            "destination": self.destination,
            "stream": self.stream,
            "digits": self.digits,
        }


@dataclass(frozen=True)
class ProvisioningFetch:
    """A phone downloading its configuration — often with the SIP password in it."""

    ts: Optional[float]
    transport: str
    client_ip: str
    server_ip: str
    filename: str
    classification: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ts": self.ts,
            "transport": self.transport,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "filename": self.filename,
            "classification": self.classification,
        }


@dataclass
class VoipSummary:
    path: Path
    total_packets: int = 0
    signaling_packets: int = 0
    signaling_bytes: int = 0
    rtp_packets: int = 0
    rtp_bytes: int = 0
    rtcp_packets: int = 0
    stun_packets: int = 0
    t38_packets: int = 0
    protocols: Counter[str] = field(default_factory=Counter)
    request_counts: Counter[str] = field(default_factory=Counter)
    response_counts: Counter[int] = field(default_factory=Counter)
    transport_counts: Counter[str] = field(default_factory=Counter)
    server_ports: Counter[int] = field(default_factory=Counter)
    client_counts: Counter[str] = field(default_factory=Counter)
    server_counts: Counter[str] = field(default_factory=Counter)
    user_agents: Counter[str] = field(default_factory=Counter)
    servers: Counter[str] = field(default_factory=Counter)
    from_users: Counter[str] = field(default_factory=Counter)
    to_users: Counter[str] = field(default_factory=Counter)
    realms: Counter[str] = field(default_factory=Counter)
    codecs: Counter[str] = field(default_factory=Counter)
    rtcp_cnames: Counter[str] = field(default_factory=Counter)
    devices: Counter[str] = field(default_factory=Counter)
    enum_lookups: Counter[str] = field(default_factory=Counter)
    stun_mapped_addresses: Counter[str] = field(default_factory=Counter)
    calls: list[VoipCall] = field(default_factory=list)
    registrations: list[VoipRegistration] = field(default_factory=list)
    credentials: list[VoipCredential] = field(default_factory=list)
    rtp_streams: list[RtpStreamSummary] = field(default_factory=list)
    media: list[SdpMedia] = field(default_factory=list)
    messages: list[VoipMessage] = field(default_factory=list)
    dtmf: list[DtmfSequence] = field(default_factory=list)
    provisioning: list[ProvisioningFetch] = field(default_factory=list)
    extracted_audio: list[str] = field(default_factory=list)
    detections: list[dict[str, object]] = field(default_factory=list)
    anomalies: list[dict[str, object]] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    threat_hypotheses: list[dict[str, object]] = field(default_factory=list)
    benign_context: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    analysis_notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds: Optional[float] = None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "signaling_packets": self.signaling_packets,
            "signaling_bytes": self.signaling_bytes,
            "rtp_packets": self.rtp_packets,
            "rtp_bytes": self.rtp_bytes,
            "rtcp_packets": self.rtcp_packets,
            "stun_packets": self.stun_packets,
            "t38_packets": self.t38_packets,
            "protocols": dict(self.protocols),
            "request_counts": dict(self.request_counts),
            "response_counts": {str(k): v for k, v in self.response_counts.items()},
            "transport_counts": dict(self.transport_counts),
            "server_ports": {str(k): v for k, v in self.server_ports.items()},
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "user_agents": dict(self.user_agents),
            "servers": dict(self.servers),
            "from_users": dict(self.from_users),
            "to_users": dict(self.to_users),
            "realms": dict(self.realms),
            "codecs": dict(self.codecs),
            "rtcp_cnames": dict(self.rtcp_cnames),
            "devices": dict(self.devices),
            "enum_lookups": dict(self.enum_lookups),
            "stun_mapped_addresses": dict(self.stun_mapped_addresses),
            "calls": [c.to_dict() for c in self.calls],
            "registrations": [r.to_dict() for r in self.registrations],
            "credentials": [c.to_dict() for c in self.credentials],
            "rtp_streams": [s.to_dict() for s in self.rtp_streams],
            "media": [m.to_dict() for m in self.media],
            "messages": [m.to_dict() for m in self.messages],
            "dtmf": [d.to_dict() for d in self.dtmf],
            "provisioning": [p.to_dict() for p in self.provisioning],
            "extracted_audio": list(self.extracted_audio),
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "deterministic_checks": {
                k: list(v) for k, v in self.deterministic_checks.items()
            },
            "threat_hypotheses": list(self.threat_hypotheses),
            "benign_context": list(self.benign_context),
            "artifacts": list(self.artifacts),
            "analysis_notes": list(self.analysis_notes),
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def _transport_payload(pkt: object, layer: object) -> bytes:
    """Return every byte above the transport header, exactly as captured.

    Reading ``pkt[Raw].load`` is wrong here and quietly loses data. Scapy ships
    dissectors for several of the ports this module cares about — SIP on 5060,
    Skinny on 2000, MGCP on 2427/2727 — so on those ports it parses the payload
    into a typed layer and ``Raw`` holds only whatever it could not account for.
    In practice that meant the Skinny 12-byte header and the MGCP request line
    disappeared before the parser ever saw them.

    ``layer.payload.original`` is the byte string the layer was dissected from,
    which is the capture's own bytes regardless of how far scapy got.
    """
    try:
        inner = layer.payload  # type: ignore[attr-defined]
    except Exception:
        return b""
    original = getattr(inner, "original", None)
    if original:
        return bytes(original)
    try:
        data = bytes(inner)
        if data:
            return data
    except Exception:
        pass
    try:
        if Raw is not None and pkt.haslayer(Raw):  # type: ignore[attr-defined]
            return bytes(pkt[Raw].load)  # type: ignore[index]
    except Exception:
        pass
    return b""


# --- SIP parsing ------------------------------------------------------------
def _looks_like_sip(text: str) -> bool:
    """True when the payload starts with a SIP request or status line.

    Recognising SIP by its start line rather than by port is what lets the
    analyzer see a PBX moved off 5060 — both a common hardening step and a
    common way for a rogue service to stay out of a port-based inventory.
    """
    if not text:
        return False
    head = text[:16].lstrip()
    if head.startswith("SIP/2.0"):
        return True
    token = head.split(" ", 1)[0]
    return token in SIP_METHODS and "SIP/2.0" in text[:512]


def _split_sip_messages(text: str) -> list[str]:
    """Split a payload into individual SIP messages.

    Best effort by design. Over UDP a datagram holds exactly one message; over
    TCP a segment may hold several, or half of one. Framing strictly by
    ``Content-Length`` would need cross-segment reassembly, which this analyzer
    does not do, so splitting on the next start line recovers the common case
    and loses only bodies that straddle a segment boundary.
    """
    if not text:
        return []
    starts = [
        m.start()
        for m in re.finditer(r"(?m)^(?:[A-Z]+ \S+ SIP/2\.0|SIP/2\.0 \d{3})", text)
    ]
    if not starts:
        return []
    starts.append(len(text))
    return [text[starts[i] : starts[i + 1]] for i in range(len(starts) - 1)]


def _parse_headers(raw: str) -> tuple[dict[str, list[str]], str]:
    """Return ``(headers, body)``.

    Header names are lower-cased, compact one-letter forms expanded, and folded
    continuation lines unfolded, so a caller can ask for ``call-id`` without
    caring which of the four spellings the endpoint used.
    """
    split = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    head = split[0]
    body = split[1] if len(split) > 1 else ""

    unfolded: list[str] = []
    for line in head.splitlines():
        if line[:1] in (" ", "\t") and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)

    headers: dict[str, list[str]] = defaultdict(list)
    for line in unfolded[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        headers[COMPACT_HEADERS.get(key, key)].append(value.strip())
    return headers, body


def _first(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name)
    return values[0] if values else ""


def _extract_uri(value: str) -> str:
    if not value:
        return ""
    match = _URI_RE.search(value)
    if match:
        return (match.group(1) or match.group(2) or "").strip()
    return value.split(";", 1)[0].strip()


def _uri_user(uri: str) -> tuple[str, str]:
    """Split a SIP URI into ``(user, host)``."""
    match = _SIP_USER_RE.search(uri or "")
    if not match:
        return "", ""
    return match.group(1) or "", match.group(2) or ""


def _parse_auth(value: str) -> dict[str, str]:
    if not value:
        return {}
    params: dict[str, str] = {}
    for match in _AUTH_PARAM_RE.finditer(value):
        key = match.group(1).lower()
        params[key] = match.group(2) if match.group(2) is not None else match.group(3)
    return params


def hashcat_sip_digest(
    params: dict[str, str], method: str, src_ip: str, dst_ip: str
) -> str:
    """Build a hashcat ``-m 11400`` line from a SIP Digest ``Authorization``.

    Field order is the mode's own: ``$sip$*server*client*user*realm*method*
    uri_prefix*uri_resource*uri_suffix*nonce*cnonce*nonce_count*qop*directive*
    response``.
    """
    uri = params.get("uri", "")
    prefix, _, rest = uri.partition(":")
    resource, _, suffix = rest.partition(";")
    if not rest:
        prefix, resource, suffix = "sip", uri, ""
    return "*".join(
        [
            "$sip$",
            dst_ip,
            src_ip,
            params.get("username", ""),
            params.get("realm", ""),
            method,
            prefix,
            resource,
            suffix,
            params.get("nonce", ""),
            params.get("cnonce", ""),
            params.get("nc", ""),
            params.get("qop", ""),
            params.get("algorithm", "MD5"),
            params.get("response", ""),
        ]
    )


def parse_sdp(body: str, call_id: str, owner_ip: str) -> list[SdpMedia]:
    """Parse an SDP body into one :class:`SdpMedia` per ``m=`` line."""
    if not body or "m=" not in body:
        return []
    session_address = ""
    media: list[SdpMedia] = []
    current: Optional[dict] = None
    rtpmap: dict[int, str] = {}

    def _flush() -> None:
        if current is None:
            return
        codecs = tuple(
            rtpmap.get(pt, RTP_STATIC_PAYLOAD_TYPES.get(pt, f"PT{pt}"))
            for pt in current["payload_types"]
        )
        media.append(
            SdpMedia(
                call_id=call_id,
                owner_ip=owner_ip,
                media_type=str(current["media_type"]),
                transport=str(current["transport"]),
                address=str(current["address"] or session_address),
                port=int(current["port"]),
                codecs=codecs,
                direction=str(current["direction"]),
                crypto_suites=tuple(current["crypto"]),
                cleartext_keys=tuple(current["keys"]),
                dtls_fingerprint=str(current["fingerprint"]),
            )
        )

    for line in body.splitlines():
        line = line.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        kind, value = line[0], line[2:]
        if kind == "c":
            parts = value.split()
            address = parts[2] if len(parts) >= 3 else ""
            if current is None:
                session_address = address
            else:
                current["address"] = address
        elif kind == "m":
            _flush()
            parts = value.split()
            payload_types: list[int] = []
            for token in parts[3:]:
                try:
                    payload_types.append(int(token))
                except ValueError:
                    continue
            current = {
                "media_type": parts[0] if parts else "?",
                "transport": parts[2] if len(parts) > 2 else "",
                "port": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                "address": "",
                "payload_types": payload_types,
                "direction": "sendrecv",
                "crypto": [],
                "keys": [],
                "fingerprint": "",
            }
        elif kind == "a":
            attr, _, rest = value.partition(":")
            attr = attr.lower()
            if attr == "rtpmap":
                pt_str, _, name = rest.partition(" ")
                try:
                    rtpmap[int(pt_str)] = name.strip()
                except ValueError:
                    pass
            elif attr in {"sendrecv", "sendonly", "recvonly", "inactive"}:
                if current is not None:
                    current["direction"] = attr
            elif attr == "crypto" and current is not None:
                fields = rest.split()
                if len(fields) >= 2:
                    current["crypto"].append(fields[1])
                for token in fields[2:]:
                    if token.lower().startswith("inline:"):
                        current["keys"].append(token[7:])
            elif attr == "fingerprint" and current is not None:
                current["fingerprint"] = rest.strip()
    _flush()
    return media


# --- mutable per-run state --------------------------------------------------
@dataclass
class _CallState:
    call_id: str
    protocol: str = "SIP"
    from_uri: str = ""
    to_uri: str = ""
    methods: list = field(default_factory=list)
    caller_ip: str = ""
    callee_ip: str = ""
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    status_codes: list = field(default_factory=list)
    user_agents: list = field(default_factory=list)
    challenged: bool = False
    authenticated: bool = False
    media: list = field(default_factory=list)
    dtmf: list = field(default_factory=list)
    answered_ts: Optional[float] = None
    ended_ts: Optional[float] = None


@dataclass
class _RegistrationState:
    aor: str
    protocol: str = "SIP"
    contacts: set = field(default_factory=set)
    source_ips: set = field(default_factory=set)
    user_agents: set = field(default_factory=set)
    attempts: int = 0
    successes: int = 0
    challenges: int = 0
    failures: int = 0
    expires: Optional[int] = None
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


# --- per-protocol handlers --------------------------------------------------
def _handle_sip(
    *,
    text: str,
    transport: str,
    sport: int,
    dport: int,
    src_ip: str,
    dst_ip: str,
    ts: Optional[float],
    counters: dict,
    totals: dict,
    calls_get,
    registrations: dict,
    credential,
    media_list: list,
    messages: list,
    signaled_endpoints: set,
    t38_ports: set,
    dtmf_payload_types: set,
    auth_failures: Counter,
    probe_targets: dict,
    invite_times: dict,
    cleartext_secrets: list,
    flag_strings: list,
    dtmf,
) -> None:
    """Parse every SIP message in one payload and fold it into the run state."""
    known_ports = SIP_PORTS | SIP_ALT_PORTS
    for raw in _split_sip_messages(text):
        lines = raw.splitlines()
        if not lines:
            continue
        match = _START_LINE_RE.match(lines[0].strip())
        if not match:
            continue
        headers, body = _parse_headers(raw)

        counters["protocols"]["SIP"] += 1
        totals["signaling_packets"] += 1
        totals["signaling_bytes"] += len(raw)
        counters["transport_counts"][transport] += 1
        # Prefer whichever side is a recognised SIP port; fall back to the
        # lower port, which is the conventional server side. Choosing sport
        # whenever dport was unrecognised labelled every reply to an ephemeral
        # port as a non-standard SIP port.
        if dport in SIP_PORTS:
            server_port = dport
        elif sport in SIP_PORTS:
            server_port = sport
        elif dport in known_ports:
            server_port = dport
        elif sport in known_ports:
            server_port = sport
        else:
            server_port = min(sport, dport)
        counters["server_ports"][server_port] += 1

        method = (match.group("method") or "").upper()
        code = int(match.group("code")) if match.group("code") else None
        request_uri = match.group("uri") or ""

        call_id = _first(headers, "call-id") or "(no Call-ID)"
        from_uri = _extract_uri(_first(headers, "from"))
        to_uri = _extract_uri(_first(headers, "to"))
        from_user, _ = _uri_user(from_uri)
        to_user, _ = _uri_user(to_uri)
        agent = _first(headers, "user-agent")
        server_hdr = _first(headers, "server")

        if method:
            counters["request_counts"][method] += 1
            counters["client_counts"][src_ip] += 1
            counters["server_counts"][dst_ip] += 1
            if from_user:
                counters["from_users"][from_user[:80]] += 1
            if to_user:
                counters["to_users"][to_user[:80]] += 1
            target = to_uri or request_uri
            if target:
                probe_targets[src_ip].add(target[:120])
            if method == "INVITE" and ts is not None:
                invite_times[src_ip].append(ts)
        elif code is not None:
            counters["response_counts"][code] += 1
        if agent:
            counters["user_agents"][agent[:120]] += 1
        if server_hdr:
            counters["servers"][server_hdr[:120]] += 1

        state = calls_get(call_id, "SIP")
        if state is not None:
            if state.first_seen is None:
                state.first_seen = ts
            state.last_seen = ts
            if from_uri and not state.from_uri:
                state.from_uri = from_uri
            if to_uri and not state.to_uri:
                state.to_uri = to_uri
            if method:
                if method not in state.methods:
                    state.methods.append(method)
                if not state.caller_ip:
                    state.caller_ip = src_ip
                    state.callee_ip = dst_ip
                if method == "BYE" and state.ended_ts is None:
                    state.ended_ts = ts
            if code is not None:
                state.status_codes.append(code)
                if code in (401, 407):
                    state.challenged = True
                if code == 200 and "INVITE" in state.methods and state.answered_ts is None:
                    state.answered_ts = ts
            for value in (agent, server_hdr):
                if value and value[:120] not in state.user_agents:
                    state.user_agents.append(value[:120])

        # Digest authentication.
        for header_name in ("authorization", "proxy-authorization"):
            for value in headers.get(header_name, []):
                params = _parse_auth(value)
                if not params.get("response"):
                    continue
                if params.get("realm"):
                    counters["realms"][params["realm"][:80]] += 1
                if state is not None:
                    state.authenticated = True
                credential(
                    ts=ts,
                    protocol="SIP",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    context=f"{method or 'REGISTER'} Digest",
                    username=params.get("username", ""),
                    realm=params.get("realm", ""),
                    secret=params.get("response", ""),
                    crackable=hashcat_sip_digest(
                        params, method or "REGISTER", src_ip, dst_ip
                    ),
                )
        for header_name in ("www-authenticate", "proxy-authenticate"):
            for value in headers.get(header_name, []):
                realm = _parse_auth(value).get("realm")
                if realm:
                    counters["realms"][realm[:80]] += 1

        # REGISTER bindings.
        if method == "REGISTER":
            aor = to_uri or from_uri or "(unknown)"
            reg = registrations.get(aor)
            if reg is None:
                reg = _RegistrationState(aor=aor, protocol="SIP")
                registrations[aor] = reg
            reg.attempts += 1
            reg.source_ips.add(src_ip)
            if agent:
                reg.user_agents.add(agent[:120])
            contact = _extract_uri(_first(headers, "contact"))
            if contact:
                reg.contacts.add(contact[:160])
            expires = _first(headers, "expires")
            if expires.isdigit():
                reg.expires = int(expires)
            if reg.first_seen is None:
                reg.first_seen = ts
            reg.last_seen = ts
        if code is not None and state is not None and "REGISTER" in state.methods:
            aor = state.to_uri or state.from_uri or "(unknown)"
            reg = registrations.get(aor)
            if reg is not None:
                if code == 200:
                    reg.successes += 1
                elif code in (401, 407):
                    reg.challenges += 1
                elif code >= 400:
                    reg.failures += 1
                    auth_failures[state.caller_ip or dst_ip] += 1
        if code is not None and code in (401, 403, 407) and state is not None:
            if "INVITE" in state.methods and code == 403:
                auth_failures[state.caller_ip or dst_ip] += 1

        content_type = _first(headers, "content-type").lower()
        if body and "application/sdp" in content_type:
            for pt_str, name in re.findall(r"a=rtpmap:(\d+)\s+([^\s/]+)", body, re.I):
                if name.lower() == "telephone-event":
                    try:
                        dtmf_payload_types.add(int(pt_str))
                    except ValueError:
                        pass
            for entry in parse_sdp(body, call_id, src_ip):
                media_list.append(entry)
                if state is not None:
                    state.media.append(entry)
                if entry.address and entry.port:
                    signaled_endpoints.add((entry.address, entry.port))
                    if entry.media_type == "image" or "t38" in " ".join(
                        entry.codecs
                    ).lower():
                        t38_ports.add(entry.port)
                for codec in entry.codecs:
                    counters["codecs"][codec] += 1
        elif body and "dtmf-relay" in content_type:
            # SIP INFO DTMF: the digit travels in the signalling, not the media.
            digits = "".join(_DTMF_RELAY_RE.findall(body))
            if digits:
                dtmf("SIP INFO", src_ip, dst_ip, call_id[:40], digits)
                if state is not None:
                    state.dtmf.append(digits)
        elif body and method in {"MESSAGE", "INFO", "NOTIFY"}:
            trimmed = body.strip()[:MAX_MESSAGE_BODY]
            if trimmed:
                messages.append(
                    VoipMessage(
                        ts=ts,
                        protocol="SIP",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        kind=method,
                        content_type=content_type or "(none)",
                        from_uri=from_uri,
                        to_uri=to_uri,
                        body=trimmed,
                    )
                )

        for secret in CLEARTEXT_SECRET_RE.finditer(raw[:4096]):
            entry_text = f"{src_ip} -> {dst_ip}: {secret.group(0)[:120]}"
            if entry_text not in cleartext_secrets:
                cleartext_secrets.append(entry_text)
        for flag in FLAGGISH_RE.finditer(raw[:4096]):
            entry_text = flag.group(0)[:160]
            if entry_text not in flag_strings:
                flag_strings.append(entry_text)


def _handle_sccp(
    parsed_messages: list,
    ts: Optional[float],
    src_ip: str,
    dst_ip: str,
    counters: dict,
    registrations: dict,
    dtmf,
    messages: list,
) -> None:
    """Fold Cisco Skinny messages into the run state.

    ``KeypadButton`` is the reason this decoder exists: on a Cisco network the
    dialled digits never appear in SIP, because there is no SIP. They arrive one
    button press at a time from the handset.
    """
    digits: list[str] = []
    for message in parsed_messages:
        counters["request_counts"][f"SCCP {message['name']}"] += 1
        if message.get("device"):
            counters["devices"][f"Skinny device: {message['device']}"] += 1
            aor = message["device"]
            reg = registrations.get(aor)
            if reg is None:
                reg = _RegistrationState(aor=aor, protocol="SCCP")
                registrations[aor] = reg
            reg.attempts += 1
            reg.source_ips.add(src_ip)
            if message.get("device_ip"):
                reg.contacts.add(str(message["device_ip"]))
            if reg.first_seen is None:
                reg.first_seen = ts
            reg.last_seen = ts
        if message["name"] == "RegisterAck":
            for reg in registrations.values():
                if reg.protocol == "SCCP" and reg.last_seen == ts:
                    reg.successes += 1
        if message["name"] == "RegisterReject":
            for reg in registrations.values():
                if reg.protocol == "SCCP":
                    reg.failures += 1
        if message.get("digit"):
            digits.append(str(message["digit"]))
        if message.get("called"):
            counters["to_users"][str(message["called"])[:40]] += 1
        if message.get("calling"):
            counters["from_users"][str(message["calling"])[:40]] += 1
        if message.get("text"):
            messages.append(
                VoipMessage(
                    ts=ts,
                    protocol="SCCP",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    kind=message["name"],
                    content_type="text/plain",
                    from_uri="",
                    to_uri="",
                    body=str(message["text"])[:MAX_MESSAGE_BODY],
                )
            )
    if digits:
        dtmf("SCCP", src_ip, dst_ip, "keypad", "".join(digits))


def _handle_iax2(
    frame: dict,
    ts: Optional[float],
    src_ip: str,
    dst_ip: str,
    counters: dict,
    calls: dict,
    registrations: dict,
    iax_challenges: dict,
    credential,
    calls_get,
) -> None:
    """Fold an IAX2 control frame into the run state.

    IAX2 authentication is worth recovering in full: ``AUTHREQ`` carries the
    challenge, ``AUTHREP`` the MD5 of challenge+secret, and the pair is an
    offline cracking candidate. Plaintext ``PASSWORD`` information elements
    still occur in the wild and are captured verbatim.
    """
    name = frame.get("name", "")
    ies = frame.get("ies", {})
    counters["request_counts"][f"IAX2 {name}"] += 1
    counters["protocols"]["IAX2"] += 0  # already counted by the caller

    username = str(ies.get("USERNAME", ""))
    if username:
        counters["from_users"][username[:80]] += 1
    called = str(ies.get("CALLED_NUMBER", ""))
    if called:
        counters["to_users"][called[:40]] += 1
    calling = str(ies.get("CALLING_NUMBER", ""))
    if calling:
        counters["from_users"][calling[:40]] += 1

    call_key = f"IAX2:{src_ip}:{frame.get('source_call')}"
    if name in ("NEW", "REGREQ"):
        state = calls_get(call_key, "IAX2")
        if state is not None:
            if state.first_seen is None:
                state.first_seen = ts
            state.last_seen = ts
            state.from_uri = calling or username
            state.to_uri = called
            state.caller_ip = src_ip
            state.callee_ip = dst_ip
            if name not in state.methods:
                state.methods.append(name)

    if name == "AUTHREQ":
        challenge = str(ies.get("CHALLENGE", ""))
        if challenge:
            iax_challenges[(dst_ip, src_ip)] = challenge
    elif name in ("AUTHREP", "REGREQ"):
        md5 = str(ies.get("MD5_RESULT", ""))
        challenge = iax_challenges.get((src_ip, dst_ip), "")
        if md5:
            credential(
                ts=ts,
                protocol="IAX2",
                src_ip=src_ip,
                dst_ip=dst_ip,
                context=name,
                username=username,
                realm="",
                secret=md5,
                crackable=(
                    f"IAX2 MD5 challenge-response user={username} "
                    f"challenge={challenge or '(not captured)'} md5={md5} "
                    "-- md5(challenge + secret)"
                ),
            )
    if ies.get("PASSWORD"):
        credential(
            ts=ts,
            protocol="IAX2",
            src_ip=src_ip,
            dst_ip=dst_ip,
            context=f"{name} plaintext",
            username=username,
            realm="",
            secret=str(ies["PASSWORD"]),
            crackable=f"IAX2 PLAINTEXT password user={username} pass={ies['PASSWORD']}",
        )
    if ies.get("DEVICETYPE"):
        counters["devices"][f"IAX2 device: {str(ies['DEVICETYPE'])[:60]}"] += 1


# --- analysis ---------------------------------------------------------------
@memoize_analysis
def analyze_voip(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    target_ip: str | None = None,
    output_dir: Path | None = None,
) -> VoipSummary:
    """Analyse every phone-over-IP protocol in a capture.

    ``output_dir`` enables audio extraction: G.711 streams are decoded to WAV
    there. Nothing is written without it.
    """
    if UDP is None:
        return VoipSummary(
            path=path,
            errors=["Scapy unavailable (UDP layer missing); cannot analyze VoIP."],
        )

    keep_audio = output_dir is not None
    counters: dict[str, Counter] = {
        name: Counter()
        for name in (
            "protocols", "request_counts", "response_counts", "transport_counts",
            "server_ports", "client_counts", "server_counts", "user_agents",
            "servers", "from_users", "to_users", "realms", "codecs",
            "rtcp_cnames", "devices", "enum_lookups", "stun_mapped_addresses",
        )
    }
    totals = {
        "total_packets": 0, "signaling_packets": 0, "signaling_bytes": 0,
        "rtcp_packets": 0, "stun_packets": 0, "t38_packets": 0,
    }
    errors: list[str] = []
    notes: list[str] = []

    calls: dict[str, _CallState] = {}
    registrations: dict[str, _RegistrationState] = {}
    credentials: list[VoipCredential] = []
    media_list: list[SdpMedia] = []
    messages: list[VoipMessage] = []
    provisioning: list[ProvisioningFetch] = []
    rtp_states: dict[tuple, RtpState] = {}
    signaled_endpoints: set[tuple[str, int]] = set()
    t38_ports: set[int] = set()
    dtmf_payload_types: set[int] = set()
    other_dtmf: list[DtmfSequence] = []

    auth_failures: Counter[str] = Counter()
    probe_targets: dict[str, set[str]] = defaultdict(set)
    invite_times: dict[str, list[float]] = defaultdict(list)
    iax_challenges: dict[tuple[str, str], str] = {}
    cleartext_secrets: list[str] = []
    flag_strings: list[str] = []
    dropped = Counter()

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def _touch(value: Optional[float]) -> None:
        nonlocal first_seen, last_seen
        if value is None:
            return
        if first_seen is None or value < first_seen:
            first_seen = value
        if last_seen is None or value > last_seen:
            last_seen = value

    def _call(call_id: str, protocol: str) -> Optional[_CallState]:
        state = calls.get(call_id)
        if state is None:
            if len(calls) >= MAX_CALLS:
                dropped["calls"] += 1
                return None
            state = _CallState(call_id=call_id, protocol=protocol)
            calls[call_id] = state
        return state

    def _credential(**kwargs) -> None:
        if len(credentials) >= MAX_CREDENTIALS:
            dropped["credentials"] += 1
            return
        credentials.append(VoipCredential(**kwargs))

    def _dtmf(protocol: str, source: str, destination: str, stream_id: str, digits: str) -> None:
        if not digits:
            return
        for entry in other_dtmf:
            if (
                entry.protocol == protocol
                and entry.source == source
                and entry.destination == destination
                and entry.stream == stream_id
            ):
                combined = (entry.digits + digits)[:MAX_DTMF_DIGITS]
                other_dtmf[other_dtmf.index(entry)] = DtmfSequence(
                    protocol=protocol,
                    source=source,
                    destination=destination,
                    stream=stream_id,
                    digits=combined,
                )
                return
        other_dtmf.append(
            DtmfSequence(
                protocol=protocol,
                source=source,
                destination=destination,
                stream=stream_id,
                digits=digits[:MAX_DTMF_DIGITS],
            )
        )

    try:
        for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
            totals["total_packets"] += 1
            ts = safe_float(getattr(pkt, "time", None))
            _touch(ts)

            is_udp = UDP is not None and pkt.haslayer(UDP)
            is_tcp = TCP is not None and pkt.haslayer(TCP)
            if not is_udp and not is_tcp:
                continue

            layer = pkt[UDP] if is_udp else pkt[TCP]
            sport = int(getattr(layer, "sport", 0) or 0)
            dport = int(getattr(layer, "dport", 0) or 0)
            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue
            if target_ip and target_ip not in (src_ip, dst_ip):
                continue

            payload = _transport_payload(pkt, layer)
            if not payload:
                continue

            ports = {sport, dport}
            frame_bytes = packet_length(pkt)

            # --- UDP media and NAT traversal --------------------------------
            if is_udp:
                if is_stun(payload) and (ports & STUN_PORTS or not ports & SIP_PORTS):
                    parsed = parse_stun(payload)
                    if parsed.get("method"):
                        totals["stun_packets"] += 1
                        counters["protocols"]["STUN/TURN"] += 1
                        attrs = parsed.get("attributes", {})
                        for key in (
                            "XOR-MAPPED-ADDRESS",
                            "XOR-RELAYED-ADDRESS",
                        ):
                            if attrs.get(key):
                                counters["stun_mapped_addresses"][
                                    f"{key}={attrs[key]}"
                                ] += 1
                        if attrs.get("USERNAME") and attrs.get("MESSAGE-INTEGRITY"):
                            _credential(
                                ts=ts,
                                protocol="TURN",
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                context=f"{parsed['method']} {parsed['class']}",
                                username=attrs.get("USERNAME", ""),
                                realm=attrs.get("REALM", ""),
                                secret=attrs.get("MESSAGE-INTEGRITY", ""),
                                crackable=(
                                    f"TURN long-term credential "
                                    f"user={attrs.get('USERNAME', '')} "
                                    f"realm={attrs.get('REALM', '')} "
                                    f"nonce={attrs.get('NONCE', '')} "
                                    f"hmac-sha1={attrs.get('MESSAGE-INTEGRITY', '')}"
                                ),
                            )
                        continue

                if is_rtcp(payload):
                    totals["rtcp_packets"] += 1
                    counters["protocols"]["RTCP"] += 1
                    report = parse_rtcp(payload)
                    for item, text in report.get("sdes", []):
                        if item == "CNAME" and text:
                            counters["rtcp_cnames"][text[:120]] += 1
                        elif text and item in ("NAME", "EMAIL", "PHONE", "TOOL"):
                            counters["devices"][f"{item}: {text[:100]}"] += 1
                    continue

                if (sport in t38_ports or dport in t38_ports) and is_udptl_t38(payload):
                    totals["t38_packets"] += 1
                    counters["protocols"]["T.38 fax"] += 1
                    parse_t38(payload)
                    continue

                # TFTP phone provisioning.
                if dport == TFTP_PORT:
                    request = parse_tftp_request(payload)
                    if request:
                        counters["protocols"]["TFTP provisioning"] += 1
                        provisioning.append(
                            ProvisioningFetch(
                                ts=ts,
                                transport="TFTP",
                                client_ip=src_ip,
                                server_ip=dst_ip,
                                filename=request["filename"],
                                classification=classify_provisioning(
                                    request["filename"]
                                ),
                            )
                        )
                        continue

                # IAX2.
                if looks_like_iax2(payload, sport, dport):
                    frame = parse_iax2(payload)
                    if frame:
                        counters["protocols"]["IAX2"] += 1
                        if frame.get("kind") == "full":
                            _handle_iax2(
                                frame, ts, src_ip, dst_ip, counters, calls,
                                registrations, iax_challenges, _credential, _call,
                            )
                        continue

                if looks_like_unistim(payload, sport, dport):
                    counters["protocols"]["UNISTIM"] += 1
                    continue

                if is_rtp_candidate(payload, sport, dport):
                    parsed = parse_rtp(payload)
                    if parsed is not None:
                        key = (src_ip, sport, dst_ip, dport, parsed["ssrc"])
                        state = rtp_states.get(key)
                        if state is None:
                            if len(rtp_states) >= MAX_RTP_STREAMS:
                                dropped["rtp"] += 1
                                continue
                            state = RtpState(
                                src_ip=src_ip,
                                src_port=sport,
                                dst_ip=dst_ip,
                                dst_port=dport,
                                ssrc=int(parsed["ssrc"]),
                                payload_type=int(parsed["payload_type"]),
                            )
                            rtp_states[key] = state
                        update_rtp_state(
                            state,
                            parsed,
                            ts,
                            frame_bytes,
                            keep_audio=keep_audio,
                            max_audio_bytes=MAX_AUDIO_BYTES,
                        )
                        pt = int(parsed["payload_type"])
                        if pt in dtmf_payload_types or pt == 101:
                            event = decode_dtmf_event(parsed["payload"])
                            if event is not None:
                                digit, _duration, _end = event
                                if parsed["marker"] or state.last_dtmf_event != digit:
                                    if len(state.dtmf) < MAX_DTMF_DIGITS:
                                        state.dtmf.append(digit)
                                    state.last_dtmf_event = digit
                        continue

            # --- text signalling (UDP or TCP) --------------------------------
            text = payload.decode("utf-8", errors="replace")

            if _looks_like_sip(text):
                transport = "UDP" if is_udp else "TCP"
                if 5061 in ports:
                    transport = "TLS-port"
                _handle_sip(
                    text=text,
                    transport=transport,
                    sport=sport,
                    dport=dport,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    counters=counters,
                    totals=totals,
                    calls_get=_call,
                    registrations=registrations,
                    credential=_credential,
                    media_list=media_list,
                    messages=messages,
                    signaled_endpoints=signaled_endpoints,
                    t38_ports=t38_ports,
                    dtmf_payload_types=dtmf_payload_types,
                    auth_failures=auth_failures,
                    probe_targets=probe_targets,
                    invite_times=invite_times,
                    cleartext_secrets=cleartext_secrets,
                    flag_strings=flag_strings,
                    dtmf=_dtmf,
                )
                continue

            if is_udp and (ports & MGCP_PORTS or looks_like_mgcp(text)) and ports & MGCP_PORTS:
                parsed = parse_mgcp(text)
                if parsed:
                    counters["protocols"]["MGCP"] += 1
                    totals["signaling_packets"] += 1
                    totals["signaling_bytes"] += len(payload)
                    if parsed["verb"]:
                        counters["request_counts"][f"MGCP {parsed['verb']}"] += 1
                    elif parsed["code"]:
                        counters["response_counts"][int(parsed["code"])] += 1
                    if parsed["endpoint"]:
                        counters["devices"][f"MGCP endpoint: {parsed['endpoint'][:80]}"] += 1
                    if parsed["digits"]:
                        _dtmf(
                            "MGCP",
                            f"{src_ip}",
                            f"{dst_ip}",
                            parsed["endpoint"][:60] or "-",
                            parsed["digits"],
                        )
                    continue

            if ports & MEGACO_PORTS:
                parsed = parse_megaco(text)
                counters["protocols"]["MEGACO/H.248"] += 1
                totals["signaling_packets"] += 1
                totals["signaling_bytes"] += len(payload)
                if parsed:
                    for command in parsed["commands"]:
                        counters["request_counts"][f"MEGACO {command}"] += 1
                    if parsed["digits"]:
                        _dtmf("MEGACO", src_ip, dst_ip, parsed["context"] or "-", parsed["digits"])
                continue

            if is_tcp and (ports & SCCP_PORTS) and looks_like_sccp(payload):
                counters["protocols"]["SCCP/Skinny"] += 1
                totals["signaling_packets"] += 1
                totals["signaling_bytes"] += len(payload)
                _handle_sccp(
                    parse_sccp(payload), ts, src_ip, dst_ip, counters,
                    registrations, _dtmf, messages,
                )
                continue

            if is_tcp and H225_PORT in ports:
                if looks_like_tpkt(payload):
                    parsed = parse_q931(payload)
                    if parsed:
                        counters["protocols"]["H.323 (H.225)"] += 1
                        totals["signaling_packets"] += 1
                        totals["signaling_bytes"] += len(payload)
                        counters["request_counts"][f"H.225 {parsed['message']}"] += 1
                        for alias in parsed["aliases"]:
                            counters["devices"][f"H.323 alias: {alias[:60]}"] += 1
                        for number in parsed["numbers"]:
                            counters["to_users"][number[:40]] += 1
                        continue

            if is_udp and ports & H225_RAS_PORTS:
                parsed = parse_ras(payload)
                if parsed:
                    counters["protocols"]["H.323 (RAS)"] += 1
                    totals["signaling_packets"] += 1
                    totals["signaling_bytes"] += len(payload)
                    counters["request_counts"][f"RAS {parsed['message']}"] += 1
                    for alias in parsed["aliases"]:
                        counters["devices"][f"H.323 alias: {alias[:60]}"] += 1
                    continue

            # ENUM lookups ride DNS but are pure telephony numbering.
            if is_udp and 53 in ports:
                for match in _ENUM_RE.finditer(text):
                    counters["enum_lookups"][match.group(0)[:120]] += 1
                    counters["protocols"]["ENUM"] += 1
                continue

            # HTTP provisioning fetches.
            if is_tcp and text[:4] in ("GET ", "POST", "PUT ", "HEAD"):
                line = text.split("\r\n", 1)[0][:300]
                classification = classify_provisioning(line)
                if classification:
                    counters["protocols"]["HTTP provisioning"] += 1
                    provisioning.append(
                        ProvisioningFetch(
                            ts=ts,
                            transport="HTTP",
                            client_ip=src_ip,
                            server_ip=dst_ip,
                            filename=line,
                            classification=classification,
                        )
                    )

    except Exception as exc:  # pragma: no cover - reader failure path
        errors.append(f"{type(exc).__name__}: {exc}")

    for key, label_text, cap, env in (
        ("calls", "call", MAX_CALLS, "PCAPPER_VOIP_MAX_CALLS"),
        ("credentials", "credential", MAX_CREDENTIALS, "PCAPPER_VOIP_MAX_CREDENTIALS"),
        ("rtp", "RTP stream", MAX_RTP_STREAMS, "PCAPPER_VOIP_MAX_RTP_STREAMS"),
    ):
        if dropped[key]:
            notes.append(
                f"{label_text} tracking capped at {cap}; {dropped[key]} further "
                f"{label_text}(s) not recorded (raise {env})."
            )

    return _finalize(
        path=path,
        totals=totals,
        counters=counters,
        calls=calls,
        registrations=registrations,
        credentials=credentials,
        media_list=media_list,
        messages=messages,
        provisioning=provisioning,
        rtp_states=rtp_states,
        signaled_endpoints=signaled_endpoints,
        other_dtmf=other_dtmf,
        auth_failures=auth_failures,
        probe_targets=probe_targets,
        invite_times=invite_times,
        cleartext_secrets=cleartext_secrets,
        flag_strings=flag_strings,
        output_dir=output_dir,
        notes=notes,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
    )


# --- verdict ----------------------------------------------------------------
def _disposition(state: _CallState) -> str:
    """Human-readable outcome for a dialog, from its methods and final status."""
    codes = state.status_codes
    final = codes[-1] if codes else None
    if state.protocol == "IAX2":
        return "IAX2 " + (state.methods[0].lower() if state.methods else "frame")
    if "REGISTER" in state.methods:
        if 200 in codes:
            return "registered"
        if any(c in (401, 407) for c in codes):
            return "auth challenged"
        if final and final >= 400:
            return f"register failed ({final})"
        return "register attempt"
    if "INVITE" not in state.methods:
        return state.methods[0].lower() if state.methods else "response only"
    if 200 in codes:
        return "answered" if state.ended_ts else "answered (no BYE seen)"
    if final == 486:
        return "busy"
    if final == 487:
        return "cancelled"
    if final == 480:
        return "unavailable"
    if final in (401, 407):
        return "auth challenged"
    if final in (403, 404):
        return f"rejected ({final})"
    if final and final >= 400:
        return f"failed ({final})"
    if 180 in codes or 183 in codes:
        return "ringing (no answer seen)"
    return "setup incomplete"


def classify_destination(number: str) -> str:
    """Classify a dialled number as international or premium-rate.

    Deliberately narrow, and deliberately descriptive rather than accusatory:
    plenty of legitimate dialling is international, so this reports the shape
    and leaves the judgement to the analyst.
    """
    digits = re.sub(r"[^\d+]", "", number or "")
    if not digits or len(digits) < 8:
        return ""
    stripped = digits.lstrip("+").lstrip("0")
    for prefix in PREMIUM_PREFIXES:
        if stripped.startswith(prefix):
            return f"premium/high-cost prefix +{prefix}"
    if _INTERNATIONAL_RE.match(digits):
        return "international-format destination"
    return ""


def _safe_stream_name(stream) -> str:
    raw = (
        f"{stream.src_ip}_{stream.src_port}-{stream.dst_ip}_{stream.dst_port}"
        f"_{stream.ssrc:08x}"
    )
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)


def _finalize(
    *,
    path: Path,
    totals: dict,
    counters: dict,
    calls: dict,
    registrations: dict,
    credentials: list,
    media_list: list,
    messages: list,
    provisioning: list,
    rtp_states: dict,
    signaled_endpoints: set,
    other_dtmf: list,
    auth_failures: Counter,
    probe_targets: dict,
    invite_times: dict,
    cleartext_secrets: list,
    flag_strings: list,
    output_dir: Optional[Path],
    notes: list,
    errors: list,
    first_seen: Optional[float],
    last_seen: Optional[float],
) -> VoipSummary:
    """Turn the collected state into a summary, with detections attached."""
    detections: list[dict[str, object]] = []
    checks: dict[str, list[str]] = defaultdict(list)
    hypotheses: list[dict[str, object]] = []
    benign: list[str] = []
    artifacts: list[str] = []
    extracted_audio: list[str] = []

    # A stream counts as encrypted only when a *secure profile* was
    # negotiated (RTP/SAVP, RTP/SAVPF) or DTLS-SRTP was set up. An a=crypto
    # attribute on a plain RTP/AVP profile is best-effort SRTP, which commonly
    # falls back to cleartext media -- flagging that as encrypted would both
    # mislabel the stream and suppress audio extraction from a plaintext call.
    encrypted_ports = {
        entry.port
        for entry in media_list
        if "SAVP" in entry.transport.upper() or entry.dtls_fingerprint
    }

    # --- RTP streams ---------------------------------------------------------
    streams: list[RtpStreamSummary] = []
    rtp_packets = 0
    rtp_bytes = 0
    dtmf_entries: list[DtmfSequence] = list(other_dtmf)

    if output_dir is not None:
        try:
            restrict_dir_permissions(output_dir)
        except Exception as exc:
            errors.append(f"Cannot create VoIP output directory: {exc}")
            output_dir = None

    for state in rtp_states.values():
        if state.packets < MIN_RTP_PACKETS:
            continue
        rtp_packets += state.packets
        rtp_bytes += state.bytes
        expected = 0
        lost = 0
        if state.first_seq is not None:
            expected = state.cycles * 65536 + state.highest_seq - state.first_seq + 1
            lost = max(0, expected - state.packets)
        duration = None
        if state.first_seen is not None and state.last_seen is not None:
            duration = max(0.0, state.last_seen - state.first_seen)
        signaled = (state.dst_ip, state.dst_port) in signaled_endpoints or (
            state.src_ip,
            state.src_port,
        ) in signaled_endpoints
        digits = "".join(state.dtmf)
        codec = RTP_STATIC_PAYLOAD_TYPES.get(
            state.payload_type,
            "telephone-event"
            if state.payload_type == 101
            else f"PT{state.payload_type}",
        )
        encrypted = state.dst_port in encrypted_ports or state.src_port in encrypted_ports

        summary_stream = RtpStreamSummary(
            src_ip=state.src_ip,
            src_port=state.src_port,
            dst_ip=state.dst_ip,
            dst_port=state.dst_port,
            ssrc=state.ssrc,
            payload_type=state.payload_type,
            codec=codec,
            packets=state.packets,
            bytes=state.bytes,
            first_seen=state.first_seen,
            last_seen=state.last_seen,
            duration_seconds=duration,
            expected_packets=expected,
            lost_packets=lost,
            out_of_order=state.out_of_order,
            duplicates=state.duplicates,
            jitter_ms=round(state.jitter / 8.0, 2),
            signaled=signaled,
            encrypted=encrypted,
            dtmf_digits=digits,
            audio_path="",
        )

        # Audio extraction. Only G.711 is decodable here, and only when the
        # media was not SRTP -- decoding ciphertext produces convincing noise,
        # which is worse than producing nothing.
        if output_dir is not None and state.audio and not encrypted:
            try:
                target = output_dir / f"rtp_{_safe_stream_name(summary_stream)}.wav"
                write_wav(target, bytes(state.audio))
                restrict_permissions(target)
                extracted_audio.append(str(target))
                summary_stream = RtpStreamSummary(
                    **{
                        **summary_stream.__dict__,
                        "audio_path": str(target),
                    }
                )
            except Exception as exc:
                errors.append(f"Audio extraction failed: {exc}")

        streams.append(summary_stream)
        if digits:
            dtmf_entries.append(
                DtmfSequence(
                    protocol="RTP (RFC 4733)",
                    source=f"{state.src_ip}:{state.src_port}",
                    destination=f"{state.dst_ip}:{state.dst_port}",
                    stream=f"0x{state.ssrc:08x}",
                    digits=digits,
                )
            )

    # Total orders throughout: a report has to be reproducible run to run.
    streams.sort(
        key=lambda s: (-s.packets, s.src_ip, s.src_port, s.dst_ip, s.dst_port, s.ssrc)
    )
    dtmf_entries.sort(key=lambda d: (d.protocol, d.source, d.destination, d.stream))
    extracted_audio.sort()

    # --- calls ---------------------------------------------------------------
    call_list: list[VoipCall] = []
    for state in calls.values():
        duration = None
        if state.answered_ts is not None and state.ended_ts is not None:
            duration = max(0.0, state.ended_ts - state.answered_ts)
        elif state.first_seen is not None and state.last_seen is not None:
            duration = max(0.0, state.last_seen - state.first_seen)
        from_user, _ = _uri_user(state.from_uri)
        to_user, _ = _uri_user(state.to_uri)
        call_list.append(
            VoipCall(
                protocol=state.protocol,
                call_id=state.call_id,
                from_uri=state.from_uri,
                to_uri=state.to_uri,
                from_user=from_user or state.from_uri,
                to_user=to_user or state.to_uri,
                methods=tuple(state.methods),
                caller_ip=state.caller_ip,
                callee_ip=state.callee_ip,
                first_seen=state.first_seen,
                last_seen=state.last_seen,
                duration_seconds=duration,
                status_codes=tuple(sorted(set(state.status_codes))),
                final_status=state.status_codes[-1] if state.status_codes else None,
                disposition=_disposition(state),
                user_agents=tuple(state.user_agents),
                authenticated=state.authenticated,
                challenged=state.challenged,
                dtmf="".join(state.dtmf),
                media=tuple(state.media),
            )
        )
    call_list.sort(
        key=lambda c: (c.first_seen if c.first_seen is not None else 0.0, c.call_id)
    )

    registration_list = [
        VoipRegistration(
            protocol=reg.protocol,
            aor=reg.aor,
            contacts=tuple(sorted(reg.contacts)),
            source_ips=tuple(sorted(reg.source_ips)),
            user_agents=tuple(sorted(reg.user_agents)),
            attempts=reg.attempts,
            successes=reg.successes,
            challenges=reg.challenges,
            failures=reg.failures,
            expires=reg.expires,
            first_seen=reg.first_seen,
            last_seen=reg.last_seen,
        )
        for reg in registrations.values()
    ]
    registration_list.sort(key=lambda r: (-r.attempts, r.protocol, r.aor))
    provisioning.sort(key=lambda p: (p.transport, p.client_ip, p.filename))

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    def _add(severity: str, title: str, details: str, check: str = "") -> None:
        detections.append({"severity": severity, "summary": title, "details": details})
        if check:
            checks[check].append(f"{title}: {details}")

    # 1. Tooling that announces itself.
    for agent, count in sorted(counters["user_agents"].items()):
        for pattern, name in SIP_SCANNER_PATTERNS:
            if pattern.search(agent):
                _add(
                    "high",
                    "VoIP scanning/attack tool User-Agent observed",
                    f"{name} — User-Agent {agent!r} in {count} message(s). SIP "
                    "enumeration and toll-fraud tooling (ATT&CK T1046 Network "
                    "Service Discovery, T1595 Active Scanning).",
                    "voip_scanning_or_enumeration",
                )
                break

    # 2. Enumeration by behaviour.
    for src, targets in sorted(probe_targets.items()):
        if len(targets) >= 20:
            _add(
                "high",
                "SIP extension enumeration",
                f"{src} addressed {len(targets)} distinct SIP URIs — an extension "
                "or user sweep (ATT&CK T1046, T1589.002).",
                "voip_scanning_or_enumeration",
            )
    rejected = counters["response_counts"].get(404, 0) + counters["response_counts"].get(403, 0)
    accepted = counters["response_counts"].get(200, 0)
    if rejected >= 20 and rejected > accepted:
        _add(
            "warning",
            "High SIP rejection rate",
            f"{rejected} 403/404 responses against {accepted} 200 OK — the shape of "
            "an extension sweep rather than normal calling (ATT&CK T1046).",
            "voip_scanning_or_enumeration",
        )

    # 3. Authentication attacks.
    for src, count in sorted(auth_failures.items()):
        if count >= 10:
            _add(
                "high",
                "VoIP authentication brute force / password spray",
                f"{count} failed authentications involving {src} "
                "(ATT&CK T1110 Brute Force).",
                "voip_authentication_attacks",
            )
    failing_accounts = [r for r in registration_list if r.failures]
    if len(failing_accounts) >= 10:
        _add(
            "high",
            "Registration failures across many accounts",
            f"{len(failing_accounts)} distinct accounts saw failed registrations — "
            "password spraying rather than one locked-out user (ATT&CK T1110.003).",
            "voip_authentication_attacks",
        )

    # 4. Recovered credentials.
    if credentials:
        by_protocol = Counter(c.protocol for c in credentials)
        users = sorted({c.username for c in credentials if c.username})
        _add(
            "high",
            "VoIP credentials recovered (offline-crackable)",
            f"{len(credentials)} credential(s) across "
            f"{', '.join(f'{k} x{v}' for k, v in sorted(by_protocol.items()))} for "
            f"{len(users)} account(s): {', '.join(users[:8])}"
            f"{'…' if len(users) > 8 else ''}. SIP Digest lines are hashcat -m 11400 "
            "candidates; IAX2 pairs are md5(challenge+secret) "
            "(ATT&CK T1040 Network Sniffing, T1110.002 Password Cracking).",
            "voip_credential_exposure",
        )
        artifacts.extend(c.crackable for c in credentials[:50] if c.crackable)
    if cleartext_secrets:
        _add(
            "high",
            "Cleartext secret in VoIP signalling",
            f"{len(cleartext_secrets)} occurrence(s), e.g. {cleartext_secrets[0]} "
            "(ATT&CK T1040 Network Sniffing).",
            "voip_credential_exposure",
        )
        artifacts.extend(cleartext_secrets[:20])

    # 5. Provisioning fetches — the richest credential source in a VoIP capture.
    config_fetches = [p for p in provisioning if p.classification]
    if config_fetches:
        _add(
            "high",
            "Phone configuration downloaded over a cleartext channel",
            f"{len(config_fetches)} fetch(es), e.g. {config_fetches[0].client_ip} -> "
            f"{config_fetches[0].server_ip} {config_fetches[0].filename!r} "
            f"({config_fetches[0].classification}). Phone config files carry the SIP "
            "account password in the clear, and TFTP has no authentication at all — "
            "anyone on the segment can fetch any handset's config "
            "(ATT&CK T1552.001 Credentials In Files, T1040 Network Sniffing).",
            "voip_provisioning_exposure",
        )
        for entry in config_fetches[:20]:
            artifacts.append(
                f"provisioning {entry.transport} {entry.client_ip} -> "
                f"{entry.server_ip}: {entry.filename}"
            )
    elif provisioning:
        _add(
            "info",
            "TFTP/HTTP fetch on a VoIP segment",
            f"{len(provisioning)} request(s) not matching a known phone config "
            "pattern; review in case they are provisioning under a custom name.",
            "voip_provisioning_exposure",
        )

    # 6. Media keys in the clear.
    keyed = [m for m in media_list if m.cleartext_keys]
    if keyed:
        _add(
            "high",
            "SRTP master key transmitted in cleartext SDP",
            f"{len(keyed)} media description(s) carry a=crypto inline: keying "
            "material (SDES, RFC 4568) over unencrypted signalling. Whoever "
            "captured this traffic can decrypt the associated media "
            "(ATT&CK T1040 Network Sniffing, T1557 Adversary-in-the-Middle).",
            "voip_media_key_exposure",
        )
        for entry in keyed[:20]:
            artifacts.append(
                f"SRTP key {entry.media_type} {entry.address}:{entry.port} "
                f"{entry.crypto_suites[0] if entry.crypto_suites else '?'} "
                f"inline:{entry.cleartext_keys[0]}"
            )

    # 7. Calls that were never challenged.
    unauthenticated = [
        c for c in call_list
        if "INVITE" in c.methods and 200 in c.status_codes and not c.challenged
    ]
    if unauthenticated:
        _add(
            "warning",
            "Call set up without authentication",
            f"{len(unauthenticated)} INVITE dialog(s) reached 200 OK with no 401/407 "
            "challenge. An open relay accepts calls from anyone who can reach it, "
            "which is the standard toll-fraud entry point.",
            "voip_toll_fraud_indicators",
        )

    # 8. Expensive destinations.
    fraud_targets: list[str] = []
    for call in call_list:
        if "INVITE" not in call.methods and call.protocol != "IAX2":
            continue
        reason = classify_destination(call.to_user)
        if reason:
            fraud_targets.append(
                f"{call.from_user or call.caller_ip} -> {call.to_user} ({reason})"
            )
    if fraud_targets:
        _add(
            "high" if len(fraud_targets) >= 5 else "warning",
            "Calls to international / premium-rate destinations",
            f"{len(fraud_targets)} call(s), e.g. {fraud_targets[0]}. Confirm against "
            "the expected dialling profile; this is the payload of PBX toll fraud "
            "(ATT&CK T1657 Financial Theft).",
            "voip_toll_fraud_indicators",
        )

    # 9. Transport hygiene.
    odd_ports = sorted(p for p in counters["server_ports"] if p not in SIP_PORTS)
    if odd_ports:
        _add(
            "info",
            "SIP on non-standard ports",
            f"{', '.join(str(p) for p in odd_ports[:12])} — expected 5060/5061. "
            "Legitimate as hardening, and also how a rogue service stays out of a "
            "port-based inventory.",
            "voip_transport_or_dos_abuse",
        )
    if counters["protocols"].get("SIP") and not counters["transport_counts"].get("TLS-port"):
        _add(
            "warning",
            "SIP signalling is unencrypted",
            "All SIP was observed in cleartext (no 5061/TLS). Credentials, dialled "
            "numbers and any SDES media keys are readable by anyone on the path "
            "(ATT&CK T1040 Network Sniffing).",
            "voip_transport_or_dos_abuse",
        )

    # 10. Internet exposure.
    public_peers = sorted(
        {
            ip
            for ip in list(counters["client_counts"]) + list(counters["server_counts"])
            if is_public_ip(ip)
        }
    )
    if public_peers:
        _add(
            "warning",
            "VoIP signalling to/from public addresses",
            f"{len(public_peers)} public peer(s): {', '.join(public_peers[:6])}. An "
            "internet-reachable PBX is scanned continuously; confirm it is meant to "
            "be exposed (ATT&CK T1590).",
            "voip_internet_exposure",
        )
    public_media = sorted({f"{s.dst_ip}:{s.dst_port}" for s in streams if is_public_ip(s.dst_ip)})
    if public_media:
        _add(
            "warning",
            "RTP media to public addresses",
            f"{len(public_media)} destination(s): {', '.join(public_media[:6])}. "
            "Confirm against the expected carrier/SBC "
            "(ATT&CK T1048 Exfiltration Over Alternative Protocol).",
            "voip_internet_exposure",
        )

    # 11. One account, several places.
    for reg in registration_list:
        if len(reg.source_ips) > 1 and reg.successes:
            _add(
                "high",
                "Account registered from multiple addresses",
                f"{reg.aor} bound from {', '.join(reg.source_ips[:6])} with "
                f"{len(reg.contacts)} contact(s). Registration hijacking redirects a "
                "victim's calls to the attacker (ATT&CK T1556, T1098).",
                "voip_registration_hijack",
            )

    # 12. Media nobody signalled.
    unsignaled = [s for s in streams if not s.signaled]
    if unsignaled and media_list:
        _add(
            "warning",
            "RTP stream with no matching SDP offer",
            f"{len(unsignaled)} of {len(streams)} stream(s) were never announced in "
            "SDP seen in this capture. Either the signalling is missing, or UDP is "
            "being used as a covert channel behind RTP framing "
            "(ATT&CK T1048, T1095 Non-Application Layer Protocol).",
            "voip_unsignaled_or_hijacked_media",
        )
    elif unsignaled and not media_list:
        _add(
            "info",
            "RTP media present with no signalling in capture",
            f"{len(unsignaled)} stream(s) recovered heuristically; the call setup is "
            "outside this capture. Media analysis below still applies.",
            "voip_unsignaled_or_hijacked_media",
        )

    # 13. Two SSRCs on one path.
    path_ssrcs: dict[tuple, set] = defaultdict(set)
    for s in streams:
        path_ssrcs[(s.src_ip, s.src_port, s.dst_ip, s.dst_port)].add(s.ssrc)
    for key, ssrcs in sorted(path_ssrcs.items()):
        if len(ssrcs) > 1:
            _add(
                "warning",
                "Multiple RTP SSRCs on one media path",
                f"{key[0]}:{key[1]} -> {key[2]}:{key[3]} carried {len(ssrcs)} "
                "synchronisation sources. Normal on a re-INVITE or codec change, and "
                "also what RTP injection or a hijacked stream looks like "
                "(ATT&CK T1557 Adversary-in-the-Middle).",
                "voip_unsignaled_or_hijacked_media",
            )

    # 14. Keypad digits.
    if dtmf_entries:
        total_digits = sum(len(d.digits) for d in dtmf_entries)
        carriers = sorted({d.protocol for d in dtmf_entries})
        _add(
            "warning",
            "DTMF keypad digits recovered",
            f"{total_digits} digit(s) across {len(dtmf_entries)} stream(s) via "
            f"{', '.join(carriers)}, e.g. {dtmf_entries[0].digits!r}. These are "
            "unencrypted here; IVR PINs, calling-card numbers, account numbers and "
            "card data travel this way (ATT&CK T1040 Network Sniffing).",
            "voip_dtmf_or_sensitive_digits",
        )
        for entry in dtmf_entries[:20]:
            artifacts.append(
                f"DTMF [{entry.protocol}] {entry.source} -> {entry.destination} "
                f"{entry.stream}: {entry.digits}"
            )

    # 15. Signalling volume.
    for src, times in sorted(invite_times.items()):
        if len(times) < 20:
            continue
        window = max(times) - min(times)
        if window <= 0:
            continue
        rate = len(times) / window
        if rate >= 10:
            _add(
                "warning",
                "High-rate INVITE flood",
                f"{src} sent {len(times)} INVITEs at {rate:.1f}/s — SIP flood or "
                "stress tooling (ATT&CK T1499 Endpoint Denial of Service).",
                "voip_transport_or_dos_abuse",
            )

    # 16. Fax.
    if totals["t38_packets"]:
        _add(
            "info",
            "T.38 fax over IP observed",
            f"{totals['t38_packets']} UDPTL packet(s). Fax pages carry contracts, "
            "invoices and medical records; the transfer is unencrypted.",
            "voip_dtmf_or_sensitive_digits",
        )

    # 17. Recovered audio.
    if extracted_audio:
        _add(
            "info",
            "Call audio extracted",
            f"{len(extracted_audio)} G.711 stream(s) decoded to WAV. Recorded "
            "conversation is evidence — handle the output directory accordingly.",
            "",
        )
        artifacts.extend(extracted_audio[:20])
    elif streams and output_dir is not None:
        undecodable = sorted({s.codec for s in streams if s.payload_type not in (0, 8)})
        if undecodable:
            notes.append(
                "No audio extracted: the streams use "
                f"{', '.join(undecodable[:6])}, and only G.711 (PCMU/PCMA) is "
                "decodable without a licensed codec."
            )

    # 18. CTF / hunting string finds.
    if flag_strings:
        _add(
            "info",
            "Flag-formatted string in VoIP traffic",
            f"{len(flag_strings)} match(es): {', '.join(flag_strings[:3])}",
            "voip_dtmf_or_sensitive_digits",
        )
        artifacts.extend(flag_strings[:20])
    if messages:
        _add(
            "info",
            "In-band message bodies recovered",
            f"{len(messages)} SIP MESSAGE/INFO or Skinny display string(s). SIP "
            "instant messaging is cleartext and has been used for C2 "
            "(ATT&CK T1071 Application Layer Protocol).",
            "",
        )
    if counters["enum_lookups"]:
        _add(
            "info",
            "ENUM (e164.arpa) lookups observed",
            f"{len(counters['enum_lookups'])} distinct number(s) resolved through "
            "DNS. ENUM leaks the dialled number to the DNS path in cleartext.",
            "voip_dtmf_or_sensitive_digits",
        )

    # --- false-positive context ---------------------------------------------
    if not any(
        pattern.search(agent)
        for agent in counters["user_agents"]
        for pattern, _ in SIP_SCANNER_PATTERNS
    ):
        benign.append("No self-identifying VoIP scanner User-Agent observed")
    if not auth_failures:
        benign.append("No failed VoIP authentications observed")
    if not keyed:
        benign.append("No cleartext SRTP keying material in SDP")
    if not fraud_targets:
        benign.append("No international/premium-rate destinations dialled")
    if streams and not unsignaled:
        benign.append("Every RTP stream matches an SDP offer seen in the capture")
    if not config_fetches:
        benign.append("No phone configuration files fetched in the clear")

    # --- hypotheses ----------------------------------------------------------
    if credentials or auth_failures:
        hypotheses.append(
            {
                "hypothesis": "VoIP account takeover",
                "rationale": (
                    f"{len(credentials)} recoverable credential(s) and "
                    f"{sum(auth_failures.values())} authentication failure(s)."
                ),
                "next_step": (
                    "Crack the recovered material offline (hashcat -m 11400 for SIP "
                    "Digest) to confirm weak secrets, then check the PBX CDR for "
                    "calls placed by those accounts."
                ),
            }
        )
    if fraud_targets or unauthenticated:
        hypotheses.append(
            {
                "hypothesis": "PBX toll fraud",
                "rationale": (
                    f"{len(unauthenticated)} unauthenticated call setup(s) and "
                    f"{len(fraud_targets)} international/premium destination(s)."
                ),
                "next_step": (
                    "Compare against billing records and the site's normal dialling "
                    "profile, especially outside business hours."
                ),
            }
        )
    if unsignaled and media_list:
        hypotheses.append(
            {
                "hypothesis": "Covert channel behind RTP framing",
                "rationale": f"{len(unsignaled)} RTP stream(s) with no SDP offer.",
                "next_step": (
                    "Check payload entropy and packet timing against a real codec: "
                    "genuine G.711 is fixed-size and isochronous."
                ),
            }
        )
    if config_fetches:
        hypotheses.append(
            {
                "hypothesis": "Credential harvest via phone provisioning",
                "rationale": f"{len(config_fetches)} config fetch(es) in the clear.",
                "next_step": (
                    "Retrieve the same files from the provisioning server and check "
                    "whether they contain SIP secrets; TFTP requires no credentials."
                ),
            }
        )

    return VoipSummary(
        path=path,
        total_packets=totals["total_packets"],
        signaling_packets=totals["signaling_packets"],
        signaling_bytes=totals["signaling_bytes"],
        rtp_packets=rtp_packets,
        rtp_bytes=rtp_bytes,
        rtcp_packets=totals["rtcp_packets"],
        stun_packets=totals["stun_packets"],
        t38_packets=totals["t38_packets"],
        protocols=counters["protocols"],
        request_counts=counters["request_counts"],
        response_counts=counters["response_counts"],
        transport_counts=counters["transport_counts"],
        server_ports=counters["server_ports"],
        client_counts=counters["client_counts"],
        server_counts=counters["server_counts"],
        user_agents=counters["user_agents"],
        servers=counters["servers"],
        from_users=counters["from_users"],
        to_users=counters["to_users"],
        realms=counters["realms"],
        codecs=counters["codecs"],
        rtcp_cnames=counters["rtcp_cnames"],
        devices=counters["devices"],
        enum_lookups=counters["enum_lookups"],
        stun_mapped_addresses=counters["stun_mapped_addresses"],
        calls=call_list,
        registrations=registration_list,
        credentials=credentials,
        rtp_streams=streams,
        media=media_list,
        messages=messages,
        dtmf=dtmf_entries,
        provisioning=provisioning,
        extracted_audio=extracted_audio,
        detections=detections,
        anomalies=[],
        deterministic_checks=dict(checks),
        threat_hypotheses=hypotheses,
        benign_context=benign,
        artifacts=artifacts,
        analysis_notes=notes,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_voip_summaries(summaries) -> VoipSummary:
    """Combine per-capture summaries for a multi-PCAP rollup."""
    items = [s for s in summaries if s is not None]
    if not items:
        return VoipSummary(path=Path("ALL_PCAPS"))

    merged = VoipSummary(path=Path("ALL_PCAPS"))
    seen: set[tuple[str, str]] = set()
    for item in items:
        for name in (
            "total_packets", "signaling_packets", "signaling_bytes", "rtp_packets",
            "rtp_bytes", "rtcp_packets", "stun_packets", "t38_packets",
        ):
            setattr(merged, name, getattr(merged, name) + getattr(item, name))
        for name in (
            "protocols", "request_counts", "response_counts", "transport_counts",
            "server_ports", "client_counts", "server_counts", "user_agents",
            "servers", "from_users", "to_users", "realms", "codecs",
            "rtcp_cnames", "devices", "enum_lookups", "stun_mapped_addresses",
        ):
            getattr(merged, name).update(getattr(item, name))
        for name in (
            "calls", "registrations", "credentials", "rtp_streams", "media",
            "messages", "dtmf", "provisioning", "extracted_audio", "artifacts",
            "analysis_notes", "errors", "threat_hypotheses",
        ):
            getattr(merged, name).extend(getattr(item, name))
        for key, values in (item.deterministic_checks or {}).items():
            merged.deterministic_checks.setdefault(key, []).extend(values)
        for detection in item.detections:
            key = (
                str(detection.get("severity", "")),
                str(detection.get("summary", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.detections.append(detection)
        if item.first_seen is not None:
            merged.first_seen = (
                item.first_seen
                if merged.first_seen is None
                else min(merged.first_seen, item.first_seen)
            )
        if item.last_seen is not None:
            merged.last_seen = (
                item.last_seen
                if merged.last_seen is None
                else max(merged.last_seen, item.last_seen)
            )

    # A "nothing seen" note only holds for the rollup if it held for every capture.
    counts: Counter[str] = Counter()
    for item in items:
        counts.update(set(item.benign_context))
    merged.benign_context.extend(
        sorted(note for note, count in counts.items() if count == len(items))
    )

    merged.calls.sort(
        key=lambda c: (c.first_seen if c.first_seen is not None else 0.0, c.call_id)
    )
    merged.registrations.sort(key=lambda r: (-r.attempts, r.protocol, r.aor))
    merged.rtp_streams.sort(
        key=lambda s: (-s.packets, s.src_ip, s.src_port, s.dst_ip, s.dst_port, s.ssrc)
    )
    merged.dtmf.sort(key=lambda d: (d.protocol, d.source, d.destination, d.stream))
    merged.errors[:] = sorted({e for e in merged.errors if e})
    merged.analysis_notes[:] = sorted(set(merged.analysis_notes))
    if merged.first_seen is not None and merged.last_seen is not None:
        merged.duration_seconds = max(0.0, merged.last_seen - merged.first_seen)
    return merged
