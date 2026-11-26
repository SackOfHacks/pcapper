"""SOCKS proxy / tunnel detection (SOCKS4, SOCKS4a, SOCKS5).

A SOCKS proxy relays a client's TCP (or, via UDP ASSOCIATE, UDP) to an
arbitrary destination the client names in the handshake -- which is exactly
what makes it a hunt-relevant tunnel: it moves traffic past egress controls,
hides the real destination behind the proxy, and is the transport under many
C2 implants (including *reverse* SOCKS, where the implant dials out and then
serves the operator a proxy back into the network).

Detection is by *structure*, never by port: these are found on 1080 but just
as often on 9901, 8855 or an ephemeral port, so the parser reads the actual
SOCKS greeting/request/reply bytes. A conversation is only reported once a
coherent handshake is seen in both directions (a greeting answered by a method
selection, or a request answered by a reply), which keeps raw-TCP payloads that
happen to begin with 0x05/0x04 from being mislabelled.

What it surfaces: the proxy and its clients, the SOCKS version, the command
(CONNECT / BIND / UDP ASSOCIATE), the tunnelled target (host:port -- the thing
egress logs never see), the negotiated authentication (including any cleartext
username/password, like :mod:`pcapper.creds`), the reply status, and the
threat/anomaly reads a hunter cares about: reverse/server-initiated proxies,
cleartext or failed auth, tunnels to sensitive service ports (RDP/SMB/SSH/...),
UDP relays, legacy SOCKS4 and non-standard proxy ports.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .lite import UNSUPPORTED, LitePacket
from .pcap_cache import PcapMeta, iter_packets
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

try:
    from scapy.layers.inet import TCP  # type: ignore
except Exception:  # pragma: no cover
    TCP = None  # type: ignore


# Ports a SOCKS proxy conventionally listens on (classic 1080/1081/1085 and the
# Tor client SOCKS ports). A proxy anywhere else is noted, not because it is
# wrong, but because moving the listener off 1080 is a common evasion.
STANDARD_SOCKS_PORTS = {1080, 1081, 1085, 9050, 9051}

# Tunnelling to one of these through a proxy is a lateral-movement / pivot
# signal: the proxy is relaying an admin or data-store protocol, not the web.
SENSITIVE_TARGET_PORTS = {
    22: "SSH",
    23: "Telnet",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM",
    6379: "Redis",
}

SOCKS5_COMMANDS = {1: "CONNECT", 2: "BIND", 3: "UDP ASSOCIATE"}
SOCKS4_COMMANDS = {1: "CONNECT", 2: "BIND"}

SOCKS5_AUTH_METHODS = {
    0x00: "No authentication",
    0x01: "GSSAPI",
    0x02: "Username/Password",
    0xFF: "No acceptable methods",
}

SOCKS5_REPLY = {
    0x00: "granted",
    0x01: "general failure",
    0x02: "connection not allowed",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}

SOCKS4_REPLY = {
    0x5A: "granted",
    0x5B: "rejected or failed",
    0x5C: "rejected (no identd)",
    0x5D: "rejected (identd auth failed)",
}

# First byte of every SOCKS control message: 0x05 (v5 greeting/method/request/
# reply), 0x04 (v4 request), 0x01 (v5 user/pass auth), 0x00 (v4 reply). Anything
# else cannot be SOCKS control and is skipped before any structural work.
_CONTROL_LEAD_BYTES = frozenset({0x00, 0x01, 0x04, 0x05})
_MAX_CONTROL_LEN = 1024
_MAX_EVENTS_PER_FLOW = 256


@dataclass(frozen=True)
class SocksSummary:
    path: Path
    total_packets: int
    socks_packets: int
    flows: int
    version_counts: Counter[str]
    command_counts: Counter[str]
    offered_method_counts: Counter[str]
    auth_method_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    proxy_port_counts: Counter[int]
    target_counts: Counter[str]
    reply_status_counts: Counter[str]
    artifact_correlations: Counter[str]
    credential_items: list[dict[str, object]]
    cleartext_cred_count: int
    failed_auth_count: int
    reverse_flow_count: int
    udp_associate_count: int
    threat_counts: Counter[str]
    anomaly_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


@dataclass
class _FlowState:
    syn_initiator: Optional[tuple[str, int]] = None
    events: list[dict[str, object]] = field(default_factory=list)


def _printable(raw: bytes) -> bool:
    """A host name / user id a SOCKS handshake would actually carry: non-empty
    and only printable ASCII. Rejects random tunnel bytes that happen to sit
    where a string would."""
    if not raw:
        return False
    return all(0x20 <= b < 0x7F for b in raw)


def _port(raw: bytes) -> int:
    return (raw[0] << 8) | raw[1]


def _ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw[:4])


def _ipv6(raw: bytes) -> str:
    groups = [f"{(raw[i] << 8) | raw[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(groups)


def _parse_socks5_greeting(p: bytes) -> Optional[dict[str, object]]:
    if len(p) < 3 or p[0] != 0x05:
        return None
    nmethods = p[1]
    if not (1 <= nmethods <= 255) or len(p) != 2 + nmethods:
        return None
    return {"kind": "greet5", "methods": list(p[2 : 2 + nmethods])}


def _parse_socks5_method(p: bytes) -> Optional[dict[str, object]]:
    # Server's method selection: exactly two bytes, and the chosen method is one
    # the realistic set (no-auth / GSSAPI / user-pass / none-acceptable) so a
    # stray two-byte 0x05 payload does not read as a selection.
    if len(p) != 2 or p[0] != 0x05 or p[1] not in SOCKS5_AUTH_METHODS:
        return None
    return {"kind": "method5", "method": p[1]}


def _parse_socks5_addr(p: bytes) -> Optional[tuple[str, int]]:
    """Shared SOCKS5 ATYP/ADDR/PORT tail of a request or reply, with the whole
    message length validated against the address type."""
    atyp = p[3]
    if atyp == 0x01:
        if len(p) != 4 + 4 + 2:
            return None
        return _ipv4(p[4:8]), _port(p[8:10])
    if atyp == 0x04:
        if len(p) != 4 + 16 + 2:
            return None
        return _ipv6(p[4:20]), _port(p[20:22])
    if atyp == 0x03:
        if len(p) < 5:
            return None
        dlen = p[4]
        if dlen == 0 or len(p) != 4 + 1 + dlen + 2:
            return None
        host = p[5 : 5 + dlen]
        if not _printable(host):
            return None
        return host.decode("ascii"), _port(p[5 + dlen : 7 + dlen])
    return None


def _parse_socks5_request(p: bytes) -> Optional[dict[str, object]]:
    if len(p) < 7 or p[0] != 0x05 or p[1] not in SOCKS5_COMMANDS or p[2] != 0x00:
        return None
    addr = _parse_socks5_addr(p)
    if addr is None:
        return None
    return {"kind": "req5", "command": p[1], "host": addr[0], "port": addr[1]}


def _parse_socks5_reply(p: bytes) -> Optional[dict[str, object]]:
    if len(p) < 7 or p[0] != 0x05 or p[1] not in SOCKS5_REPLY or p[2] != 0x00:
        return None
    addr = _parse_socks5_addr(p)
    if addr is None:
        return None
    return {"kind": "rep5", "reply": p[1], "host": addr[0], "port": addr[1]}


def _parse_socks5_userpass(p: bytes) -> Optional[dict[str, object]]:
    # RFC 1929: 0x01, ULEN, UNAME, PLEN, PASSWD.
    if len(p) < 3 or p[0] != 0x01:
        return None
    ulen = p[1]
    if len(p) < 2 + ulen + 1:
        return None
    plen = p[2 + ulen]
    if len(p) != 3 + ulen + plen:
        return None
    user = p[2 : 2 + ulen]
    secret = p[3 + ulen : 3 + ulen + plen]
    if not _printable(user):
        return None
    return {
        "kind": "auth5",
        "user": user.decode("ascii"),
        "secret": secret.decode("ascii", "replace"),
    }


def _parse_socks5_userpass_reply(p: bytes) -> Optional[dict[str, object]]:
    # RFC 1929 reply: 0x01, STATUS (0x00 success, non-zero failure).
    if len(p) != 2 or p[0] != 0x01:
        return None
    return {"kind": "authrep5", "status": p[1]}


def _parse_socks4_request(p: bytes) -> Optional[dict[str, object]]:
    # VER(0x04) CMD DSTPORT(2) DSTIP(4) USERID\0 [DOMAIN\0 for SOCKS4a].
    if len(p) < 9 or p[0] != 0x04 or p[1] not in SOCKS4_COMMANDS:
        return None
    null = p.find(b"\x00", 8)
    if null < 0:
        return None
    userid = p[8:null]
    if userid and not _printable(userid):
        return None
    port = _port(p[2:4])
    ip_bytes = p[4:8]
    socks4a = ip_bytes[0] == 0 and ip_bytes[1] == 0 and ip_bytes[2] == 0 and ip_bytes[3] != 0
    if socks4a:
        dom_end = p.find(b"\x00", null + 1)
        if dom_end < 0:
            return None
        domain = p[null + 1 : dom_end]
        if not _printable(domain):
            return None
        host: str = domain.decode("ascii")
    else:
        host = _ipv4(ip_bytes)
    return {
        "kind": "req4",
        "command": p[1],
        "host": host,
        "port": port,
        "socks4a": socks4a,
        "user": userid.decode("ascii", "replace"),
    }


def _parse_socks4_reply(p: bytes) -> Optional[dict[str, object]]:
    if len(p) != 8 or p[0] != 0x00 or p[1] not in SOCKS4_REPLY:
        return None
    return {"kind": "rep4", "reply": p[1], "host": _ipv4(p[4:8]), "port": _port(p[2:4])}


def _classify(payload: bytes) -> list[dict[str, object]]:
    """Every SOCKS control message ``payload`` validly parses as. A request and
    a reply are byte-compatible when the command/reply code overlaps, so both
    are returned and the flow logic picks by direction."""
    if not payload or payload[0] not in _CONTROL_LEAD_BYTES or len(payload) > _MAX_CONTROL_LEN:
        return []
    out: list[dict[str, object]] = []
    lead = payload[0]
    if lead == 0x05:
        for parser in (
            _parse_socks5_greeting,
            _parse_socks5_method,
            _parse_socks5_request,
            _parse_socks5_reply,
        ):
            parsed = parser(payload)
            if parsed is not None:
                out.append(parsed)
    elif lead == 0x01:
        for parser in (_parse_socks5_userpass, _parse_socks5_userpass_reply):
            parsed = parser(payload)
            if parsed is not None:
                out.append(parsed)
    elif lead == 0x04:
        parsed = _parse_socks4_request(payload)
        if parsed is not None:
            out.append(parsed)
    elif lead == 0x00:
        parsed = _parse_socks4_reply(payload)
        if parsed is not None:
            out.append(parsed)
    return out


def _tcp_fields(pkt: object) -> Optional[tuple[int, int, int, bytes]]:
    """``(sport, dport, flags, payload)`` for a TCP packet, from the lite view
    without materialising where possible; None when the packet is not TCP."""
    if type(pkt) is LitePacket:
        transport = pkt.lite_transport()
        if transport is not None and transport is not UNSUPPORTED:
            is_tcp, sport, dport, _seq, flags, payload = transport
            if not is_tcp or payload is None:
                return None if not is_tcp else (int(sport or 0), int(dport or 0), int(flags or 0), b"")
            return int(sport or 0), int(dport or 0), int(flags or 0), bytes(payload)
        pkt = pkt.materialize()
    if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        return None
    tcp = pkt[TCP]  # type: ignore[index]
    try:
        flags = int(tcp.flags)
    except Exception:
        flags = 0
    payload = b""
    try:
        payload = bytes(getattr(tcp, "payload", b"") or b"")
    except Exception:
        payload = b""
    return int(getattr(tcp, "sport", 0) or 0), int(getattr(tcp, "dport", 0) or 0), flags, payload


def _by_direction(events: list[dict[str, object]], kind: str) -> dict[tuple[str, int], list[dict[str, object]]]:
    out: dict[tuple[str, int], list[dict[str, object]]] = {}
    for ev in events:
        if ev["kind"] == kind:
            out.setdefault(ev["from"], []).append(ev)  # type: ignore[arg-type]
    return out


def _first(events: list[dict[str, object]], kind: str, side: tuple[str, int]) -> Optional[dict[str, object]]:
    for ev in events:
        if ev["kind"] == kind and ev["from"] == side:
            return ev
    return None


@dataclass
class _ResolvedFlow:
    version: str
    client: tuple[str, int]
    server: tuple[str, int]
    control_packets: int
    reverse: bool
    command: Optional[str]
    target: Optional[str]
    target_port: Optional[int]
    offered: list[str]
    auth_method: Optional[str]
    reply_status: Optional[str]
    credential: Optional[dict[str, object]]
    auth_failed: bool
    udp_associate: bool
    first_seen: Optional[float]
    last_seen: Optional[float]


def _resolve_flow(state: _FlowState) -> Optional[_ResolvedFlow]:
    """Confirm a conversation as SOCKS only when a handshake is answered across
    directions, and read the client/server roles, command, target and auth from
    it. Returns None for a conversation that never completes a handshake."""
    events = state.events
    if not events:
        return None

    client: Optional[tuple[str, int]] = None
    server: Optional[tuple[str, int]] = None
    version = ""

    # SOCKS5: a greeting answered by a method selection, or a request answered
    # by a reply, in the opposite direction. The greeter/requester is the
    # client (proxy user); the responder is the proxy server.
    greets = _by_direction(events, "greet5")
    methods = _by_direction(events, "method5")
    reqs5 = _by_direction(events, "req5")
    reps5 = _by_direction(events, "rep5")
    for g_side in greets:
        for m_side in methods:
            if m_side != g_side:
                client, server, version = g_side, m_side, "SOCKS5"
                break
        if client:
            break
    if client is None:
        for q_side in reqs5:
            for r_side in reps5:
                if r_side != q_side:
                    client, server, version = q_side, r_side, "SOCKS5"
                    break
            if client:
                break

    # SOCKS4 / SOCKS4a: a request answered by a reply in the opposite direction.
    if client is None:
        reqs4 = _by_direction(events, "req4")
        reps4 = _by_direction(events, "rep4")
        for q_side in reqs4:
            for r_side in reps4:
                if r_side != q_side:
                    client, server, version = q_side, r_side, "SOCKS4"
                    break
            if client:
                break

    if client is None or server is None:
        return None

    # Only the control messages of the two confirmed endpoints count.
    flow_events = [ev for ev in events if ev["from"] in (client, server)]
    control_packets = len(flow_events)
    times = [ev["ts"] for ev in flow_events if ev.get("ts") is not None]  # type: ignore[misc]
    first_seen = min(times) if times else None
    last_seen = max(times) if times else None

    request = _first(flow_events, "req5", client) or _first(flow_events, "req4", client)
    command_code = int(request["command"]) if request else None  # type: ignore[arg-type]
    if version == "SOCKS5":
        command = SOCKS5_COMMANDS.get(command_code) if command_code is not None else None
    else:
        command = SOCKS4_COMMANDS.get(command_code) if command_code is not None else None
    target = str(request["host"]) if request else None
    target_port = int(request["port"]) if request else None  # type: ignore[arg-type]
    udp_associate = command == "UDP ASSOCIATE"

    if version == "SOCKS4" and request and bool(request.get("socks4a")):
        version = "SOCKS4a"

    greeting = _first(flow_events, "greet5", client)
    offered = (
        [SOCKS5_AUTH_METHODS.get(m, f"method 0x{m:02x}") for m in greeting["methods"]]  # type: ignore[union-attr]
        if greeting
        else []
    )
    method_sel = _first(flow_events, "method5", server)
    auth_method = (
        SOCKS5_AUTH_METHODS.get(int(method_sel["method"]), f"method 0x{int(method_sel['method']):02x}")  # type: ignore[arg-type]
        if method_sel
        else None
    )

    reply = _first(flow_events, "rep5", server)
    reply_status = None
    if reply:
        reply_status = SOCKS5_REPLY.get(int(reply["reply"]))  # type: ignore[arg-type]
    else:
        reply4 = _first(flow_events, "rep4", server)
        if reply4:
            reply_status = SOCKS4_REPLY.get(int(reply4["reply"]))  # type: ignore[arg-type]

    auth = _first(flow_events, "auth5", client)
    credential: Optional[dict[str, object]] = None
    auth_failed = False
    auth_reply = _first(flow_events, "authrep5", server)
    if auth_reply and int(auth_reply["status"]) != 0:  # type: ignore[arg-type]
        auth_failed = True
    if auth:
        credential = {
            "proxy": f"{server[0]}:{server[1]}",
            "client": client[0],
            "user": auth["user"],
            "secret": auth["secret"],
            "result": "failed" if auth_failed else "accepted",
            # When: merged across captures as the earliest (a timestamp named
            # "ts" would make the same credential of two captures two rows).
            "first_seen": auth.get("ts"),
        }

    reverse = state.syn_initiator is not None and state.syn_initiator == server

    return _ResolvedFlow(
        version=version,
        client=client,
        server=server,
        control_packets=control_packets,
        reverse=reverse,
        command=command,
        target=target,
        target_port=target_port,
        offered=offered,
        auth_method=auth_method,
        reply_status=reply_status,
        credential=credential,
        auth_failed=auth_failed,
        udp_associate=udp_associate,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def _record_artifact_correlation(
    correlations: Counter[str], artifact: str, client_ip: str, server_ip: str
) -> None:
    artifact_name = str(artifact).strip()
    if not artifact_name or not client_ip or not server_ip:
        return
    correlations[f"{artifact_name} | {client_ip} -> {server_ip}"] += 1


@memoize_analysis
def analyze_socks(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> SocksSummary:
    total_packets = 0
    flows_state: dict[tuple[tuple[str, int], tuple[str, int]], _FlowState] = {}
    errors: list[str] = []

    try:
        for pkt in iter_packets(
            path, packets=packets, meta=meta, show_status=show_status, lite=True
        ):
            total_packets += 1
            fields = _tcp_fields(pkt)
            if fields is None:
                continue
            sport, dport, flags, payload = fields

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue
            frm = (src_ip, sport)
            to = (dst_ip, dport)
            key = (frm, to) if frm <= to else (to, frm)
            state = flows_state.get(key)

            # A lone SYN marks the TCP connector -- used only to tell a normal
            # proxy (client dials the proxy) from a reverse one (the proxy-server
            # role dials out, as a reverse-SOCKS implant does).
            if (flags & 0x02) and not (flags & 0x10):
                if state is None:
                    state = flows_state[key] = _FlowState()
                if state.syn_initiator is None:
                    state.syn_initiator = frm

            classified = _classify(payload)
            if not classified:
                continue
            if state is None:
                state = flows_state[key] = _FlowState()
            if len(state.events) >= _MAX_EVENTS_PER_FLOW:
                continue
            ts = safe_float(getattr(pkt, "time", None))
            for parsed in classified:
                parsed["from"] = frm
                parsed["to"] = to
                parsed["ts"] = ts
                state.events.append(parsed)
    except Exception as exc:
        # One malformed packet must not abort the capture -- record and return
        # what resolved, as the other analyzers do.
        errors.append(f"{type(exc).__name__}: {exc}")

    socks_packets = 0
    flows = 0
    version_counts: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    offered_method_counts: Counter[str] = Counter()
    auth_method_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    proxy_port_counts: Counter[int] = Counter()
    target_counts: Counter[str] = Counter()
    reply_status_counts: Counter[str] = Counter()
    artifact_correlations: Counter[str] = Counter()
    credential_items: list[dict[str, object]] = []
    cleartext_cred_count = 0
    failed_auth_count = 0
    reverse_flow_count = 0
    udp_associate_count = 0
    threat_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    sensitive_targets: Counter[str] = Counter()
    legacy_flows = 0
    nonstandard_port_flows = 0

    def _mark_window(a: Optional[float], b: Optional[float]) -> None:
        nonlocal first_seen, last_seen
        for ts in (a, b):
            if ts is None:
                continue
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

    for state in flows_state.values():
        resolved = _resolve_flow(state)
        if resolved is None:
            continue
        flows += 1
        socks_packets += resolved.control_packets
        _mark_window(resolved.first_seen, resolved.last_seen)

        client_ip, server_ip = resolved.client[0], resolved.server[0]
        proxy_port = resolved.server[1]
        version_counts[resolved.version] += 1
        client_counts[client_ip] += 1
        server_counts[server_ip] += 1
        proxy_port_counts[proxy_port] += 1
        _record_artifact_correlation(
            artifact_correlations, f"{resolved.version} proxy", client_ip, server_ip
        )

        if resolved.command:
            command_counts[resolved.command] += 1
        for method in resolved.offered:
            offered_method_counts[method] += 1
        if resolved.auth_method:
            auth_method_counts[resolved.auth_method] += 1
        if resolved.reply_status:
            reply_status_counts[resolved.reply_status] += 1
        if resolved.target:
            tgt = (
                f"{resolved.target}:{resolved.target_port}"
                if resolved.target_port is not None
                else resolved.target
            )
            target_counts[tgt] += 1
            _record_artifact_correlation(
                artifact_correlations, f"tunnel -> {tgt}", client_ip, server_ip
            )
            if resolved.target_port in SENSITIVE_TARGET_PORTS:
                svc = SENSITIVE_TARGET_PORTS[resolved.target_port]
                sensitive_targets[f"{tgt} ({svc})"] += 1

        if resolved.udp_associate:
            udp_associate_count += 1
        if resolved.version in ("SOCKS4", "SOCKS4a"):
            legacy_flows += 1
        if proxy_port not in STANDARD_SOCKS_PORTS:
            nonstandard_port_flows += 1
        if resolved.reverse:
            reverse_flow_count += 1
            _record_artifact_correlation(
                artifact_correlations, "reverse SOCKS (server dialled out)", client_ip, server_ip
            )
        if resolved.credential is not None:
            credential_items.append(resolved.credential)
            cleartext_cred_count += 1
            _record_artifact_correlation(
                artifact_correlations, "cleartext proxy credentials", client_ip, server_ip
            )
        if resolved.auth_failed:
            failed_auth_count += 1
        if resolved.auth_method == "No acceptable methods":
            anomaly_counts["SOCKS auth negotiation failed (no acceptable methods)"] += 1

    # ---- threat / anomaly reads -------------------------------------------
    if reverse_flow_count:
        threat_counts["Reverse SOCKS proxy (server-initiated tunnel)"] += reverse_flow_count
    if cleartext_cred_count:
        threat_counts["SOCKS proxy credentials in cleartext"] += cleartext_cred_count
    sensitive_total = sum(sensitive_targets.values())
    if sensitive_total:
        threat_counts["SOCKS tunnel to sensitive service port"] += sensitive_total
    if failed_auth_count:
        anomaly_counts["SOCKS proxy authentication failures"] += failed_auth_count
    if udp_associate_count:
        anomaly_counts["SOCKS UDP ASSOCIATE (UDP relay)"] += udp_associate_count
    if legacy_flows:
        anomaly_counts["Legacy SOCKS4/4a (no authentication, no IPv6)"] += legacy_flows
    if nonstandard_port_flows:
        anomaly_counts["SOCKS proxy on non-standard port"] += nonstandard_port_flows
    if len(client_counts) >= 10 and len(server_counts) <= 2:
        anomaly_counts["Many clients sharing few SOCKS proxies"] += len(client_counts)

    detections: list[dict[str, object]] = []
    if flows:
        detections.append(
            {
                "severity": "info",
                "summary": "SOCKS proxy tunneling observed",
                "details": (
                    f"{flows} SOCKS conversation(s) across {len(version_counts)} version(s); "
                    f"{len(target_counts)} tunnelled target(s)."
                ),
            }
        )

    # High-severity: a reverse proxy is a classic C2 transport; naming the
    # sensitive targets turns the medium reads into something actionable.
    if reverse_flow_count:
        detections.append(
            {
                "severity": "high",
                "summary": "Reverse SOCKS proxy (server-initiated tunnel)",
                "details": (
                    f"{reverse_flow_count} conversation(s) where the proxy-server role dialled out "
                    "first -- the shape of a reverse-SOCKS implant / C2 tunnel."
                ),
                "attack": "T1090.001",
            }
        )
    if sensitive_total:
        detections.append(
            {
                "severity": "warning",
                "summary": "SOCKS tunnel to sensitive service port",
                "details": f"{sensitive_total} tunnel(s) to admin/data-store services.",
                "evidence": [t for t, _ in sensitive_targets.most_common(8)],
                "attack": "T1090",
            }
        )
    if cleartext_cred_count:
        detections.append(
            {
                "severity": "warning",
                "summary": "SOCKS proxy credentials in cleartext",
                "details": f"{cleartext_cred_count} username/password exchange(s) sent in the clear.",
                "evidence": [
                    f"{c.get('user')} @ {c.get('proxy')} ({c.get('result')})"
                    for c in credential_items[:8]
                ],
                "attack": "T1090",
            }
        )

    for label, count in anomaly_counts.most_common(8):
        detections.append(
            {
                "severity": "low",
                "summary": label,
                "details": f"{count} related indicator(s) observed.",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return SocksSummary(
        path=path,
        total_packets=total_packets,
        socks_packets=socks_packets,
        flows=flows,
        version_counts=version_counts,
        command_counts=command_counts,
        offered_method_counts=offered_method_counts,
        auth_method_counts=auth_method_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        proxy_port_counts=proxy_port_counts,
        target_counts=target_counts,
        reply_status_counts=reply_status_counts,
        artifact_correlations=artifact_correlations,
        credential_items=credential_items,
        cleartext_cred_count=cleartext_cred_count,
        failed_auth_count=failed_auth_count,
        reverse_flow_count=reverse_flow_count,
        udp_associate_count=udp_associate_count,
        threat_counts=threat_counts,
        anomaly_counts=anomaly_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )


def merge_socks_summaries(summaries: list[SocksSummary]) -> SocksSummary:
    if not summaries:
        return SocksSummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            socks_packets=0,
            flows=0,
            version_counts=Counter(),
            command_counts=Counter(),
            offered_method_counts=Counter(),
            auth_method_counts=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            proxy_port_counts=Counter(),
            target_counts=Counter(),
            reply_status_counts=Counter(),
            artifact_correlations=Counter(),
            credential_items=[],
            cleartext_cred_count=0,
            failed_auth_count=0,
            reverse_flow_count=0,
            udp_associate_count=0,
            threat_counts=Counter(),
            anomaly_counts=Counter(),
            detections=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = sum(item.total_packets for item in summaries)
    socks_packets = sum(item.socks_packets for item in summaries)
    flows = sum(item.flows for item in summaries)
    version_counts: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    offered_method_counts: Counter[str] = Counter()
    auth_method_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    proxy_port_counts: Counter[int] = Counter()
    target_counts: Counter[str] = Counter()
    reply_status_counts: Counter[str] = Counter()
    artifact_correlations: Counter[str] = Counter()
    credential_items: list[dict[str, object]] = []
    cleartext_cred_count = 0
    failed_auth_count = 0
    reverse_flow_count = 0
    udp_associate_count = 0
    threat_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    for item in summaries:
        version_counts.update(item.version_counts)
        command_counts.update(item.command_counts)
        offered_method_counts.update(item.offered_method_counts)
        auth_method_counts.update(item.auth_method_counts)
        client_counts.update(item.client_counts)
        server_counts.update(item.server_counts)
        proxy_port_counts.update(item.proxy_port_counts)
        target_counts.update(item.target_counts)
        reply_status_counts.update(item.reply_status_counts)
        artifact_correlations.update(item.artifact_correlations)
        cleartext_cred_count += int(item.cleartext_cred_count)
        failed_auth_count += int(item.failed_auth_count)
        reverse_flow_count += int(item.reverse_flow_count)
        udp_associate_count += int(item.udp_associate_count)
        threat_counts.update(item.threat_counts)
        anomaly_counts.update(item.anomaly_counts)
        if item.first_seen is not None:
            first_seen = item.first_seen if first_seen is None else min(first_seen, item.first_seen)
        if item.last_seen is not None:
            last_seen = item.last_seen if last_seen is None else max(last_seen, item.last_seen)

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    # A credential or finding several captures share is listed once; errors
    # once each, in the order found.
    from .rollup import merge_records

    credential_items = merge_records([list(item.credential_items or []) for item in summaries])
    detections = merge_records([list(item.detections or []) for item in summaries])
    errors = list(dict.fromkeys(err for item in summaries for err in (item.errors or []) if err))
    return SocksSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        socks_packets=socks_packets,
        flows=flows,
        version_counts=version_counts,
        command_counts=command_counts,
        offered_method_counts=offered_method_counts,
        auth_method_counts=auth_method_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        proxy_port_counts=proxy_port_counts,
        target_counts=target_counts,
        reply_status_counts=reply_status_counts,
        artifact_correlations=artifact_correlations,
        credential_items=credential_items,
        cleartext_cred_count=cleartext_cred_count,
        failed_auth_count=failed_auth_count,
        reverse_flow_count=reverse_flow_count,
        udp_associate_count=udp_associate_count,
        threat_counts=threat_counts,
        anomaly_counts=anomaly_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
