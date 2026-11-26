from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .lite import UNSUPPORTED, LitePacket
from .pcap_cache import PcapMeta, iter_packets
from .utils import beacon_score as _beaconing_score
from .utils import (
    env_int,
    extract_packet_endpoints,
    is_public_ip,
    memoize_analysis,
    packet_length,
    safe_float,
    tcp_segment_length,
)
from .utils import extract_ascii_strings as _extract_ascii_strings

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore
    Raw = None  # type: ignore


VNC_PORTS = {5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5800}
MAX_VNC_SESSIONS = env_int("PCAPPER_MAX_VNC_SESSIONS", 50000, minimum=1)
MAX_VNC_UNIQUE_VALUES = env_int("PCAPPER_MAX_VNC_UNIQUE_VALUES", 2000, minimum=1)
MAX_VNC_ARTIFACTS = env_int("PCAPPER_MAX_VNC_ARTIFACTS", 2000, minimum=1)
MAX_VNC_MACS_PER_IP = env_int("PCAPPER_MAX_VNC_MACS_PER_IP", 32, minimum=1)
# A VNC port on the *source* side is the service only when the destination is
# an ephemeral port; a flow from ephemeral 5900 to 443 is not VNC.
_EPHEMERAL_MIN = 1024
VNC_BANNER_RE = re.compile(r"(RFB\s+\d+\.\d+)")
# A viewer listening for reverse connections ("vncviewer -listen", UltraVNC's
# listening viewer) uses 5500; UltraVNC servers announce themselves to a
# repeater / listening viewer with "ID:<number>" NUL-padded to 250 bytes.
REVERSE_VNC_PORTS = {5500}
ULTRAVNC_ID_RE = re.compile(rb"^ID:(\d{1,12})\x00")
PENDING_FLOW_PACKETS = 16
MAX_PENDING_FLOWS = env_int("PCAPPER_MAX_VNC_PENDING_FLOWS", 200000, minimum=1)
# RFB security types are BINARY bytes negotiated in the handshake (NOT text), so
# they must be parsed from the handshake — matching the words "None"/"Tight" in
# arbitrary framebuffer/clipboard text produced constant false "no auth" alerts.
VNC_SECURITY_TYPES = {
    0: "Invalid",
    1: "None (no authentication)",
    2: "VNC Authentication (DES challenge-response)",
    5: "RA2",
    6: "RA2ne",
    16: "Tight",
    17: "Ultra",
    18: "TLS",
    19: "VeNCrypt",
    20: "SASL",
    30: "Apple Remote Desktop",
}


def _parse_rfb_version(payload: bytes) -> Optional[tuple[int, int]]:
    """Parse an 'RFB 003.008\\n' ProtocolVersion (exactly 12 bytes)."""
    if len(payload) < 12 or not payload.startswith(b"RFB ") or payload[11] != 0x0A:
        return None
    try:
        major = int(payload[4:7])
        minor = int(payload[8:11])
        return (major, minor)
    except (ValueError, IndexError):
        return None


def _parse_rfb_security_types(payload: bytes, version: tuple[int, int]) -> list[int]:
    """Parse the server's security-type message. RFB 3.3 sends a single 4-byte
    big-endian type; RFB 3.7+ sends [count][type bytes]."""
    if not payload:
        return []
    if version <= (3, 3):
        if len(payload) >= 4:
            return [int.from_bytes(payload[:4], "big")]
        return []
    count = payload[0]
    if count == 0 or len(payload) < 1 + count:
        return []
    return list(payload[1 : 1 + count])

SUSPICIOUS_PLAINTEXT = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential indicator"),
    (re.compile(r"(?<![\w-])user(name)?\s*[:=]\s*\S", re.IGNORECASE), "User indicator"),
    (re.compile(r"vncpasswd|x11vnc|tigervnc", re.IGNORECASE), "VNC tooling"),
    (re.compile(r"wget\s+|curl\s+|tftp\s+", re.IGNORECASE), "File transfer tooling"),
]

FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/](?:[\w\-.()\[\]/]| (?! ))*\.(?:exe|bin|elf|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class VncConversation:
    client_ip: str
    server_ip: str
    server_port: int
    client_port: int
    client_mac: Optional[str]
    server_mac: Optional[str]
    packets: int
    bytes: int
    client_packets: int
    server_packets: int
    client_bytes: int
    server_bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    client_banner: Optional[str]
    server_banner: Optional[str]
    # The VNC server opened the TCP connection to a listening viewer.
    reverse: bool = False
    repeater_id: str = ""  # UltraVNC repeater/backconnect "ID:" number
    handshake: str = ""  # how far the RFB handshake got
    hello_strings: tuple[str, ...] = ()  # strings in the UltraVNC hello buffer
    security: str = ""  # the security type the session settled on


@dataclass(frozen=True)
class VncSummary:
    path: Path
    total_packets: int
    vnc_packets: int
    total_bytes: int
    client_packets: int
    server_packets: int
    client_bytes: int
    server_bytes: int
    total_sessions: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    client_macs: Counter[str]
    server_macs: Counter[str]
    ip_to_macs: dict[str, list[str]]
    server_ports: Counter[int]
    client_banners: Counter[str]
    server_banners: Counter[str]
    auth_types: Counter[str]
    plaintext_strings: Counter[str]
    suspicious_plaintext: Counter[str]
    file_artifacts: Counter[str]
    conversations: list[VncConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "vnc_packets": self.vnc_packets,
            "total_bytes": self.total_bytes,
            "client_packets": self.client_packets,
            "server_packets": self.server_packets,
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "total_sessions": self.total_sessions,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "client_macs": dict(self.client_macs),
            "server_macs": dict(self.server_macs),
            "ip_to_macs": {key: list(value) for key, value in self.ip_to_macs.items()},
            "server_ports": dict(self.server_ports),
            "client_banners": dict(self.client_banners),
            "server_banners": dict(self.server_banners),
            "auth_types": dict(self.auth_types),
            "plaintext_strings": dict(self.plaintext_strings),
            "suspicious_plaintext": dict(self.suspicious_plaintext),
            "file_artifacts": dict(self.file_artifacts),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "server_port": conv.server_port,
                    "client_port": conv.client_port,
                    "client_mac": conv.client_mac,
                    "server_mac": conv.server_mac,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "client_packets": conv.client_packets,
                    "server_packets": conv.server_packets,
                    "client_bytes": conv.client_bytes,
                    "server_bytes": conv.server_bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                    "client_banner": conv.client_banner,
                    "server_banner": conv.server_banner,
                }
                for conv in self.conversations
            ],
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class _SessionState:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_mac: Optional[str] = None
    server_mac: Optional[str] = None
    packets: int = 0
    bytes: int = 0
    client_packets: int = 0
    server_packets: int = 0
    client_bytes: int = 0
    server_bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    client_banner: Optional[str] = None
    server_banner: Optional[str] = None
    # RFB handshake state for binary security-type parsing.
    rfb_version: tuple[int, int] = (0, 0)
    rfb_stage: int = 0  # 0=init, 1=server-version, 2=client-version, 3=sec-types parsed
    vnc_security: str = ""
    offered_security_types: tuple[int, ...] = ()
    initiator: Optional[tuple[str, int]] = None  # the side that sent the SYN
    roles_fixed: bool = False
    reverse: bool = False
    repeater_id: str = ""
    hello_strings: tuple[str, ...] = ()
    side_macs: dict = field(default_factory=dict)

    def swap_roles(self) -> None:
        self.client_ip, self.server_ip = self.server_ip, self.client_ip
        self.client_port, self.server_port = self.server_port, self.client_port
        self.client_packets, self.server_packets = self.server_packets, self.client_packets
        self.client_bytes, self.server_bytes = self.server_bytes, self.client_bytes
        self.client_banner, self.server_banner = self.server_banner, self.client_banner

    def handshake(self) -> str:
        if self.rfb_stage >= 3:
            return f"security: {self.vnc_security}" if self.vnc_security else "security types offered"
        if self.rfb_stage == 2:
            return "versions exchanged"
        if self.rfb_stage == 1:
            return "viewer never answered"
        return "repeater hello only" if self.repeater_id else "no RFB handshake seen"


def _scan_plaintext(
    payload: bytes,
    plaintext_counter: Counter[str],
    suspicious_counter: Counter[str],
    file_counter: Counter[str],
    artifacts: list[str],
    auth_types: Counter[str],
    max_unique: int = MAX_VNC_UNIQUE_VALUES,
) -> None:
    def _increment_limited(counter: Counter[str], key: str) -> None:
        if key in counter or len(counter) < max_unique:
            counter[key] += 1

    for item in _extract_ascii_strings(payload):
        if not item:
            continue
        if len(plaintext_counter) < max_unique or item in plaintext_counter:
            plaintext_counter[item] += 1
        for pattern, reason in SUSPICIOUS_PLAINTEXT:
            if pattern.search(item):
                _increment_limited(suspicious_counter, f"{reason}: {item}")
        for match in FILE_NAME_RE.findall(item):
            _increment_limited(file_counter, match)
        # NOTE: VNC security types are parsed from the binary RFB handshake (see
        # the analyze loop), NOT matched as text here — matching "None"/"Tight"
        # in framebuffer/clipboard text caused constant false "no auth" alerts.
        if "RFB" in item and len(artifacts) < MAX_VNC_ARTIFACTS:
            artifacts.append(item)


def _tcp_payload_bytes(pkt: object, tcp: object) -> bytes:
    """TCP application data without scapy's trailing Ethernet ``Padding``.

    Short frames are padded to 60 bytes and scapy hangs the pad under TCP, so
    ``bytes(tcp.payload)`` of a one-keystroke segment is the keystroke plus
    NULs. The IP total length is immune to padding.
    """
    try:
        raw = bytes(getattr(tcp, "payload", b"") or b"")
    except Exception:
        return b""
    if not raw:
        return b""
    ip_layer = pkt.getlayer(IP) if IP is not None else None  # type: ignore[attr-defined]
    if ip_layer is None and IPv6 is not None:
        ip_layer = pkt.getlayer(IPv6)  # type: ignore[attr-defined]
    length = tcp_segment_length(tcp, ip_layer)
    return raw if length is None else raw[:length]


def _direction(
    src_ip: str, dst_ip: str, sport: int, dport: int
) -> tuple[str, str, int, int]:
    if dport in VNC_PORTS:
        return src_ip, dst_ip, sport, dport
    if sport in VNC_PORTS and dport >= _EPHEMERAL_MIN:
        return dst_ip, src_ip, dport, sport
    if dport < 1024 and sport >= 1024:
        return src_ip, dst_ip, sport, dport
    if sport < 1024 and dport >= 1024:
        return dst_ip, src_ip, dport, sport
    return src_ip, dst_ip, sport, dport


@memoize_analysis
def analyze_vnc(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> VncSummary:
    errors: list[str] = []
    if TCP is None or (IP is None and IPv6 is None):
        errors.append(
            "Scapy IP/TCP layers unavailable; install scapy for VNC analysis."
        )
        return VncSummary(
            path=path,
            total_packets=0,
            vnc_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_ports=Counter(),
            client_banners=Counter(),
            server_banners=Counter(),
            auth_types=Counter(),
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )


    total_packets = 0
    vnc_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    sessions: dict[tuple, _SessionState] = {}
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_ports: Counter[int] = Counter()
    client_banners: Counter[str] = Counter()
    server_banners: Counter[str] = Counter()
    auth_types: Counter[str] = Counter()

    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    artifacts: list[str] = []

    short_session_counts: Counter[tuple[str, str]] = Counter()
    short_session_by_client: Counter[str] = Counter()
    short_session_targets: dict[str, set[str]] = defaultdict(set)
    pair_first_seen: dict[tuple[str, str], list[float]] = defaultdict(list)
    session_cap_reached = False

    def _flow_key(a_ip: str, a_port: int, b_ip: str, b_port: int) -> tuple:
        a, b = (a_ip, a_port), (b_ip, b_port)
        return (a, b) if a <= b else (b, a)

    # The first packets of every TCP flow, briefly: a flow identified as VNC
    # only later (an UltraVNC hello or a banner on an unregistered port, e.g.
    # a reverse connection to a viewer listening on 5500) is then counted from
    # its handshake on, not from the banner packet.
    pending: dict[tuple, dict] = {}

    try:
        for pkt in iter_packets(
            path, packets=packets, meta=meta, show_status=show_status, lite=True
        ):
            total_packets += 1
            pkt_len = packet_length(pkt)
            total_bytes += pkt_len

            if type(pkt) is LitePacket:
                # Read from disk, a segment that is not VNC (yet) only feeds
                # the pending-flow table: that is done here from the record's
                # bytes, exactly as the scapy path below does it, and only a
                # segment that may be VNC is dissected.
                l4 = pkt.lite_l4()
                if l4 is None:
                    continue  # no TCP layer
                if l4 is not UNSUPPORTED:
                    if not l4[0]:
                        continue  # UDP: haslayer(TCP) is false
                    if l4[5] >= 0:
                        src_ip, dst_ip = extract_packet_endpoints(pkt)
                        if not src_ip or not dst_ip:
                            continue
                        sport, dport = l4[1], l4[2]
                        flow = _flow_key(src_ip, sport, dst_ip, dport)
                        # _tcp_payload_bytes() is a prefix of everything from
                        # the payload's start (cut to the IP/TCP length): it
                        # opens with a banner or a hello only if that does.
                        head = pkt.original[l4[5] : l4[5] + 16]
                        if sessions.get(flow) is None and not (
                            dport in VNC_PORTS
                            or (sport in VNC_PORTS and dport >= _EPHEMERAL_MIN)
                            or head[:4] == b"RFB "
                            or ULTRAVNC_ID_RE.match(head) is not None
                        ):
                            ts = safe_float(getattr(pkt, "time", None))
                            state = pending.get(flow)
                            if state is None:
                                if len(pending) >= MAX_PENDING_FLOWS:
                                    pending.clear()
                                state = pending[flow] = {"packets": Counter(), "bytes": Counter(), "first": ts,
                                                         "last": ts, "syn": None}
                            elif state.get("done"):
                                continue
                            side = (src_ip, sport)
                            state["packets"][side] += 1
                            state["bytes"][side] += pkt_len
                            if ts is not None:
                                state["first"] = ts if state["first"] is None else min(state["first"], ts)
                                state["last"] = ts if state["last"] is None else max(state["last"], ts)
                            if l4[4] & 0x02 and not l4[4] & 0x10:  # SYN without ACK
                                state["syn"] = side
                            if sum(state["packets"].values()) > PENDING_FLOW_PACKETS:
                                pending[flow] = {"done": True}
                            continue
                pkt = pkt.materialize()

            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            tcp = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            try:
                tcp_flags = int(getattr(tcp, "flags", 0) or 0)
            except Exception:
                tcp_flags = 0
            is_syn = bool(tcp_flags & 0x02) and not tcp_flags & 0x10
            payload = _tcp_payload_bytes(pkt, tcp)
            ts = safe_float(getattr(pkt, "time", None))
            flow = _flow_key(src_ip, sport, dst_ip, dport)
            hello = ULTRAVNC_ID_RE.match(payload) if payload else None

            session = sessions.get(flow)
            if session is None:
                is_vnc = (
                    dport in VNC_PORTS
                    or (sport in VNC_PORTS and dport >= _EPHEMERAL_MIN)
                    or payload[:4] == b"RFB "
                    or hello is not None
                )
                if not is_vnc:
                    state = pending.get(flow)
                    if state is None:
                        if len(pending) >= MAX_PENDING_FLOWS:
                            pending.clear()
                        state = pending[flow] = {"packets": Counter(), "bytes": Counter(), "first": ts, "last": ts,
                                                 "syn": None}
                    elif state.get("done"):
                        continue
                    side = (src_ip, sport)
                    state["packets"][side] += 1
                    state["bytes"][side] += pkt_len
                    if ts is not None:
                        state["first"] = ts if state["first"] is None else min(state["first"], ts)
                        state["last"] = ts if state["last"] is None else max(state["last"], ts)
                    if is_syn:
                        state["syn"] = side
                    if sum(state["packets"].values()) > PENDING_FLOW_PACKETS:
                        pending[flow] = {"done": True}
                    continue
                if len(sessions) >= MAX_VNC_SESSIONS:
                    if not session_cap_reached:
                        errors.append(
                            f"VNC session tracking capped at {MAX_VNC_SESSIONS}; "
                            "additional session details were omitted."
                        )
                        session_cap_reached = True
                    continue
                client_ip, server_ip, client_port, server_port = _direction(src_ip, dst_ip, sport, dport)
                session = _SessionState(
                    client_ip=client_ip, server_ip=server_ip, client_port=client_port, server_port=server_port,
                    first_seen=ts, last_seen=ts,
                )
                prior = pending.pop(flow, None)
                if prior and not prior.get("done"):
                    for side, n in prior["packets"].items():
                        nbytes = prior["bytes"][side]
                        session.packets += n
                        session.bytes += nbytes
                        vnc_packets += n
                        if side == (client_ip, client_port):
                            session.client_packets += n
                            session.client_bytes += nbytes
                        else:
                            session.server_packets += n
                            session.server_bytes += nbytes
                    session.initiator = prior["syn"]
                    for value in (prior["first"], prior["last"]):
                        if value is not None:
                            session.first_seen = value if session.first_seen is None else min(session.first_seen, value)
                            first_seen = value if first_seen is None else min(first_seen, value)
                            last_seen = value if last_seen is None else max(last_seen, value)
                sessions[flow] = session
            if is_syn and session.initiator is None:
                session.initiator = (src_ip, sport)

            vnc_packets += 1
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            # Roles follow the protocol, not the ports: the VNC server speaks
            # first (its ProtocolVersion, or UltraVNC's "ID:" hello to a
            # repeater/listening viewer). When that side opened the TCP
            # connection, the server dialled the viewer: a reverse connection.
            ver = _parse_rfb_version(payload)
            if (hello is not None or ver is not None) and not session.roles_fixed:
                session.roles_fixed = True
                if (src_ip, sport) != (session.server_ip, session.server_port):
                    session.swap_roles()
                if session.initiator is not None:
                    session.reverse = session.initiator == (src_ip, sport)
                else:  # capture started mid-connection: judge by the ports
                    session.reverse = sport not in VNC_PORTS and dport not in VNC_PORTS and (
                        dport in REVERSE_VNC_PORTS or sport > dport
                    )
            if hello is not None and not session.repeater_id:
                session.repeater_id = hello.group(1).decode("ascii", "replace")
                session.hello_strings = tuple(
                    item for item in _extract_ascii_strings(payload[len(hello.group(0)):], min_len=4)[:8]
                    if any(ch.isalpha() for ch in item)
                )

            eth_src = None
            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                try:
                    eth_layer = pkt[Ether]  # type: ignore[index]
                    eth_src = str(getattr(eth_layer, "src", "")) or None
                    eth_dst = str(getattr(eth_layer, "dst", "")) or None
                except Exception:
                    eth_src = eth_dst = None
                for ip_value, mac in ((src_ip, eth_src), (dst_ip, eth_dst)):
                    if mac and (len(ip_to_macs[ip_value]) < MAX_VNC_MACS_PER_IP or mac.lower() in ip_to_macs[ip_value]):
                        ip_to_macs[ip_value].add(mac.lower())
            if eth_src:
                session.side_macs.setdefault((src_ip, sport), eth_src.lower())

            from_server = (src_ip, sport) == (session.server_ip, session.server_port)
            session.packets += 1
            session.bytes += pkt_len
            if from_server:
                session.server_packets += 1
                session.server_bytes += pkt_len
            else:
                session.client_packets += 1
                session.client_bytes += pkt_len
            if ts is not None:
                if session.first_seen is None or ts < session.first_seen:
                    session.first_seen = ts
                if session.last_seen is None or ts > session.last_seen:
                    session.last_seen = ts

            text = ""
            if payload:
                try:
                    text = payload.decode("latin-1", errors="ignore")
                except Exception:
                    text = ""

            # ---- RFB handshake security-type parsing (binary) ----------------
            if ver is not None:
                session.rfb_version = ver
                # Server sends its version first, then the client echoes its own.
                if from_server and session.rfb_stage == 0:
                    session.rfb_stage = 1
                elif not from_server and session.rfb_stage in (0, 1):
                    session.rfb_stage = 2
            elif from_server and session.rfb_stage == 2 and not session.vnc_security:
                # First server payload after the version exchange = security types.
                sec_types = _parse_rfb_security_types(payload, session.rfb_version)
                if sec_types:
                    session.rfb_stage = 3
                    if session.rfb_version <= (3, 3):
                        selected_type = sec_types[0]
                        name = VNC_SECURITY_TYPES.get(
                            selected_type, f"Security Type {selected_type}"
                        )
                        session.vnc_security = name
                        auth_types[name] += 1
                    else:
                        session.offered_security_types = tuple(sec_types)
            elif not from_server and session.rfb_stage == 3 and not session.vnc_security:
                # RFB 3.7+ clients select exactly one of the server's offered
                # types. An offered "None" type is not proof that it was used.
                if payload and payload[0] in session.offered_security_types:
                    selected_type = payload[0]
                    name = VNC_SECURITY_TYPES.get(
                        selected_type, f"Security Type {selected_type}"
                    )
                    session.vnc_security = name
                    auth_types[name] += 1
                    session.rfb_stage = 4

            if text:
                banner = VNC_BANNER_RE.search(text)
                if banner:
                    value = banner.group(1)
                    if not from_server:
                        session.client_banner = session.client_banner or value
                        if value in client_banners or len(client_banners) < MAX_VNC_UNIQUE_VALUES:
                            client_banners[value] += 1
                    else:
                        session.server_banner = session.server_banner or value
                        if value in server_banners or len(server_banners) < MAX_VNC_UNIQUE_VALUES:
                            server_banners[value] += 1
                _scan_plaintext(
                    payload,
                    plaintext_strings,
                    suspicious_plaintext,
                    file_artifacts,
                    artifacts,
                    auth_types,
                )

    except Exception as exc:
        errors.append(str(exc))

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversations: list[VncConversation] = []
    for session in sessions.values():
        session.client_mac = session.side_macs.get((session.client_ip, session.client_port))
        session.server_mac = session.side_macs.get((session.server_ip, session.server_port))
        client_counts[session.client_ip] += session.packets
        server_counts[session.server_ip] += session.packets
        server_ports[session.server_port] += session.packets
        client_packets += session.client_packets
        server_packets += session.server_packets
        client_bytes += session.client_bytes
        server_bytes += session.server_bytes
        if session.client_mac:
            client_macs[session.client_mac] += session.client_packets
        if session.server_mac:
            server_macs[session.server_mac] += session.server_packets
        conversations.append(
            VncConversation(
                client_ip=session.client_ip,
                server_ip=session.server_ip,
                server_port=session.server_port,
                client_port=session.client_port,
                client_mac=session.client_mac,
                server_mac=session.server_mac,
                packets=session.packets,
                bytes=session.bytes,
                client_packets=session.client_packets,
                server_packets=session.server_packets,
                client_bytes=session.client_bytes,
                server_bytes=session.server_bytes,
                first_seen=session.first_seen,
                last_seen=session.last_seen,
                client_banner=session.client_banner,
                server_banner=session.server_banner,
                reverse=session.reverse,
                repeater_id=session.repeater_id,
                handshake=session.handshake(),
                hello_strings=session.hello_strings,
                security=session.vnc_security,
            )
        )
        if session.packets <= 6 and session.bytes < 2000:
            short_session_counts[(session.client_ip, session.server_ip)] += 1
            short_session_by_client[session.client_ip] += 1
            short_session_targets[session.client_ip].add(session.server_ip)
        if session.first_seen is not None:
            pair_first_seen[(session.client_ip, session.server_ip)].append(
                session.first_seen
            )

    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    reverse = [c for c in conversations if c.reverse]
    for conv in sorted(reverse, key=lambda c: (-c.packets, c.server_ip))[:5]:
        viewer_public = is_public_ip(conv.client_ip)
        duration = (conv.last_seen - conv.first_seen) if conv.first_seen is not None and conv.last_seen is not None else None
        detections.append(
            {
                "severity": "high" if viewer_public else "warning",
                "summary": "Reverse VNC: a VNC server connected out to a listening viewer",
                "details": (
                    f"{conv.server_ip} (the desktop) dialled {conv.client_ip}:{conv.client_port} "
                    f"({'external' if viewer_public else 'internal'} viewer)"
                    + (f", UltraVNC repeater ID {conv.repeater_id}" if conv.repeater_id else "")
                    + f"; handshake: {conv.handshake}; {conv.packets} packets"
                    + (f" over {duration:.0f}s" if duration else "")
                    + (f"; hello buffer strings: {', '.join(conv.hello_strings)}" if conv.hello_strings else "")
                    + ". Remote-control malware (hVNC / UltraVNC backconnect) connects out like this to pass firewalls."
                ),
                "source": "VNC",
                "mitre": "T1219",
                "src": conv.server_ip,
                "dst": f"{conv.client_ip}:{conv.client_port}",
                "ts": conv.first_seen,
            }
        )

    non_standard_ports = [port for port in server_ports if port not in VNC_PORTS
                          and not any(c.reverse and c.server_port == port for c in conversations)]
    if non_standard_ports:
        detections.append(
            {
                "severity": "info",
                "summary": "VNC observed on non-standard ports",
                "details": ", ".join(str(port) for port in sorted(non_standard_ports)),
            }
        )

    if auth_types:
        if any("no authentication" in name.lower() for name in auth_types):
            detections.append(
                {
                    "severity": "high",
                    "summary": "VNC server offering NO authentication",
                    "details": (
                        "RFB security type 1 (None) negotiated — the VNC server "
                        "grants remote screen/keyboard/mouse control with no "
                        "password. Anyone who can reach the port has full control "
                        "(ATT&CK T1021.005 Remote Services: VNC)."
                    ),
                }
            )
        if any("DES challenge-response" in name for name in auth_types):
            detections.append(
                {
                    "severity": "warning",
                    "summary": "VNC using weak DES challenge-response auth",
                    "details": (
                        "RFB security type 2 (VNC Authentication) uses a DES "
                        "challenge/response limited to an 8-character password — "
                        "the captured challenge/response is offline-crackable."
                    ),
                }
            )

    if suspicious_plaintext:
        detections.append(
            {
                "severity": "warning",
                "summary": "Suspicious plaintext strings observed in VNC payloads",
                "details": "Potential credentials, tooling, or sensitive strings in cleartext.",
            }
        )

    for (client_ip, server_ip), count in short_session_counts.items():
        if count >= 20:
            anomalies.append(
                {
                    "title": "Potential brute force or probing",
                    "details": f"{client_ip} -> {server_ip} short sessions: {count}",
                }
            )

    for client_ip, count in short_session_by_client.items():
        targets = short_session_targets.get(client_ip, set())
        if count >= 30 and len(targets) >= 10:
            anomalies.append(
                {
                    "title": "Potential VNC scanning",
                    "details": f"{client_ip} short sessions: {count} across {len(targets)} servers",
                }
            )

    for (client_ip, server_ip), times in pair_first_seen.items():
        score = _beaconing_score(times)
        if score:
            detections.append(
                {
                    "severity": "info",
                    "summary": "Potential VNC beaconing",
                    "details": f"{client_ip} -> {server_ip} avg interval {score['avg']:.1f}s, stddev {score['stddev']:.1f}s",
                }
            )

    for session in sessions.values():
        if (
            session.client_bytes >= 50 * 1024 * 1024
            and session.client_bytes > session.server_bytes * 3
        ):
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Potential VNC data upload/exfiltration",
                    "details": (
                        f"{session.client_ip} -> {session.server_ip} "
                        f"client->server {session.client_bytes / (1024 * 1024):.1f} MB"
                    ),
                }
            )
        if session.last_seen is not None and session.first_seen is not None:
            duration = session.last_seen - session.first_seen
            if duration >= 4 * 3600:
                anomalies.append(
                    {
                        "title": "Long-lived VNC session",
                        "details": f"{session.client_ip} -> {session.server_ip} duration {duration:.0f}s",
                    }
                )

    total_sessions = len(conversations)

    return VncSummary(
        path=path,
        total_packets=total_packets,
        vnc_packets=vnc_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_ports=server_ports,
        client_banners=client_banners,
        server_banners=server_banners,
        auth_types=auth_types,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_vnc_summaries(
    summaries: list[VncSummary] | tuple[VncSummary, ...] | set[VncSummary],
) -> VncSummary:
    summary_list = list(summaries)
    if not summary_list:
        return VncSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            vnc_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_ports=Counter(),
            client_banners=Counter(),
            server_banners=Counter(),
            auth_types=Counter(),
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    vnc_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    total_sessions = 0

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_ports: Counter[int] = Counter()
    client_banners: Counter[str] = Counter()
    server_banners: Counter[str] = Counter()
    auth_types: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    conversations: list[VncConversation] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[str] = []
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        vnc_packets += summary.vnc_packets
        total_bytes += summary.total_bytes
        client_packets += summary.client_packets
        server_packets += summary.server_packets
        client_bytes += summary.client_bytes
        server_bytes += summary.server_bytes
        total_sessions += summary.total_sessions

        if summary.first_seen is not None:
            first_seen = (
                summary.first_seen
                if first_seen is None
                else min(first_seen, summary.first_seen)
            )
        if summary.last_seen is not None:
            last_seen = (
                summary.last_seen
                if last_seen is None
                else max(last_seen, summary.last_seen)
            )

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        client_macs.update(summary.client_macs)
        server_macs.update(summary.server_macs)
        for ip_value, macs in summary.ip_to_macs.items():
            ip_to_macs[ip_value].update(macs)
        server_ports.update(summary.server_ports)
        client_banners.update(summary.client_banners)
        server_banners.update(summary.server_banners)
        auth_types.update(summary.auth_types)
        plaintext_strings.update(summary.plaintext_strings)
        suspicious_plaintext.update(summary.suspicious_plaintext)
        file_artifacts.update(summary.file_artifacts)
        conversations.extend(summary.conversations)
        detections.extend(summary.detections)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        errors.extend(summary.errors)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return VncSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        vnc_packets=vnc_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_ports=server_ports,
        client_banners=client_banners,
        server_banners=server_banners,
        auth_types=auth_types,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
