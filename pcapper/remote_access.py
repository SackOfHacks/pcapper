"""Inbound remote-access detection and IT->OT pivot correlation.

Detects completed inbound remote-access sessions (someone connecting INTO a
host as a server on SSH/Telnet/RDP/VNC/WinRM/SMB/rlogin/X11) and the classic
industrial attack pivot: a host that receives such a remote-access connection
and then issues an OT/control command to another host.

Shared by --timeline (shows "Remote IN" events for the -ip), and by
--threats / --overview / --compromised (the pivot is a CRITICAL finding).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.packet import Raw
except ImportError:  # pragma: no cover - scapy optional at runtime
    TCP = UDP = Raw = None

from .ot_ports import OT_PORT_PROTOCOLS
from .pcap_cache import get_reader
from .utils import (
    extract_packet_endpoints,
    is_public_ip as _is_public_ip,
    memoize_analysis,
    safe_float,
    tcp_flags_int,
)

# Inbound services that constitute interactive/remote-execution access. A
# completed handshake to one of these (host = server) is a remote-access
# session INTO that host.
REMOTE_ACCESS_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    5985: "WinRM",
    5986: "WinRM",
    445: "SMB/PsExec",
    513: "rlogin",
    514: "rsh",
    6000: "X11",
    6001: "X11",
}

_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04

_MAX_SESSIONS = 2000
_MAX_OT_OUT_PER_HOST = 64


@dataclass
class RemoteInSession:
    server_ip: str  # the host that was connected INTO (pivot candidate)
    client_ip: str  # the remote source
    port: int
    proto: str
    ts: float  # when the handshake completed
    external: bool  # client is a public/Internet address


@dataclass
class RemotePivot:
    host: str  # received remote-access IN, then issued an OT command OUT
    severity: str  # "critical" (external remote source) or "high" (internal)
    remote_in: RemoteInSession
    ot_ts: float
    ot_target: str
    ot_proto: str


@dataclass
class RemoteAccessAnalysis:
    path: Path
    sessions: list[RemoteInSession] = field(default_factory=list)
    pivots: list[RemotePivot] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _payload_len(layer) -> int:
    try:
        payload = layer.payload
        if payload is None:
            return 0
        raw = bytes(payload)
        return len(raw)
    except Exception:
        return 0


@memoize_analysis
def analyze_remote_access(
    path: Path, show_status: bool = True
) -> RemoteAccessAnalysis:
    errors: list[str] = []
    analysis = RemoteAccessAnalysis(path=path)
    if TCP is None:
        errors.append("scapy unavailable; remote-access analysis skipped.")
        analysis.errors = errors
        return analysis

    reader, status, stream, size_bytes, _ft = get_reader(path, show_status=show_status)

    # Handshake state per directed flow (client_ip, server_ip, client_port,
    # server_port): which of SYN / SYN-ACK / ACK we have observed and the ts.
    hs: dict[tuple[str, str, int, int], dict[str, object]] = {}
    seen_sessions: set[tuple[str, str, int]] = set()
    # Per host: earliest remote-in ts and the sessions seen (for severity).
    ot_out_by_host: dict[str, list[tuple[float, str, str]]] = {}

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    status.update(int(min(100, (stream.tell() / size_bytes) * 100)))
                except Exception:
                    pass
            ts = safe_float(getattr(pkt, "time", None)) or 0.0
            src, dst = extract_packet_endpoints(pkt)
            if not src or not dst or src == dst:
                continue

            has_tcp = TCP is not None and pkt.haslayer(TCP)
            has_udp = UDP is not None and pkt.haslayer(UDP)

            if has_tcp:
                tcp = pkt[TCP]
                try:
                    sport = int(tcp.sport)
                    dport = int(tcp.dport)
                except Exception:
                    continue
                flags = tcp_flags_int(getattr(tcp, "flags", 0))
                is_syn = bool(flags & _SYN)
                is_ack = bool(flags & _ACK)
                # --- remote-access handshake tracking ---
                if is_syn and not is_ack and dport in REMOTE_ACCESS_PORTS:
                    # client=src -> server=dst:dport
                    key = (src, dst, sport, dport)
                    st = hs.setdefault(key, {"syn": False, "synack": False, "ack": False, "ts": ts})
                    st["syn"] = True
                elif is_syn and is_ack and sport in REMOTE_ACCESS_PORTS:
                    # SYN-ACK: server=src:sport -> client=dst; flip to client view
                    key = (dst, src, dport, sport)
                    st = hs.setdefault(key, {"syn": False, "synack": False, "ack": False, "ts": ts})
                    st["synack"] = True
                elif is_ack and not is_syn and dport in REMOTE_ACCESS_PORTS:
                    # final ACK (and subsequent data ACKs) client->server
                    key = (src, dst, sport, dport)
                    st = hs.get(key)
                    if st is not None:
                        st["ack"] = True
                        st["ts"] = ts
                        if st["syn"] and st["synack"] and st["ack"]:
                            client_ip, server_ip, _cp, server_port = key
                            dedup = (client_ip, server_ip, server_port)
                            if dedup not in seen_sessions and len(seen_sessions) < _MAX_SESSIONS:
                                seen_sessions.add(dedup)
                                analysis.sessions.append(
                                    RemoteInSession(
                                        server_ip=server_ip,
                                        client_ip=client_ip,
                                        port=server_port,
                                        proto=REMOTE_ACCESS_PORTS.get(server_port, str(server_port)),
                                        ts=float(st["ts"]),
                                        external=_is_public_ip(client_ip),
                                    )
                                )

            # --- OT command-out tracking (host = client issuing OT traffic) ---
            transport = None
            ot_dport = None
            if has_tcp:
                transport = pkt[TCP]
                ot_dport = dport
            elif has_udp:
                transport = pkt[UDP]
                try:
                    ot_dport = int(pkt[UDP].dport)
                except Exception:
                    ot_dport = None
            if (
                transport is not None
                and ot_dport in OT_PORT_PROTOCOLS
                and _payload_len(transport) > 0
            ):
                bucket = ot_out_by_host.setdefault(src, [])
                if len(bucket) < _MAX_OT_OUT_PER_HOST:
                    bucket.append((ts, dst, OT_PORT_PROTOCOLS[ot_dport]))
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        reader.close()

    # --- correlate: host received remote-in, then issued an OT command out ---
    sessions_by_host: dict[str, list[RemoteInSession]] = {}
    for sess in analysis.sessions:
        sessions_by_host.setdefault(sess.server_ip, []).append(sess)

    for host, sessions in sessions_by_host.items():
        ot_events = ot_out_by_host.get(host)
        if not ot_events:
            continue
        earliest_in = min(s.ts for s in sessions)
        # OT command issued strictly after an inbound remote-access session.
        later = sorted((e for e in ot_events if e[0] > earliest_in), key=lambda e: e[0])
        if not later:
            continue
        ot_ts, ot_target, ot_proto = later[0]
        # Severity escalates if any qualifying remote-in (before the OT command)
        # came from an external/public source.
        preceding = [s for s in sessions if s.ts <= ot_ts]
        external = any(s.external for s in preceding)
        chosen = min(
            (s for s in preceding) or sessions,
            key=lambda s: s.ts,
        )
        analysis.pivots.append(
            RemotePivot(
                host=host,
                severity="critical" if external else "high",
                remote_in=chosen,
                ot_ts=ot_ts,
                ot_target=ot_target,
                ot_proto=ot_proto,
            )
        )

    analysis.errors = errors
    return analysis
