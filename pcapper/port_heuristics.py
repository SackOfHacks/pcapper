"""Find OT protocols on ports they do not normally use, by payload structure.

Every analyzer selects traffic by port, so S7comm moved to tcp/10203 (MAPNA
CTF 2024) or tcp/5678 (CISA ICSNPP ``s7comm_plus_port_change``) was invisible:
``--overview`` listed ``TCP/10203`` and ``--s7`` reported zero packets.

Counting packets that "decode" is not evidence. Weakly framed protocols
(Modbus, IEC-104) parse fragments of SSH, OPC UA or MELSOFT traffic if every
hit counts; the ICS-PCAP-Challenges classifier measured exactly that. So a
port is assigned to a protocol only when, over that port's payload packets:

* each counted packet is *structurally* framed by the protocol's own length
  fields (the PDU lengths must account for the payload exactly - SSH forced
  through the IEC-104 test passes 1 packet in 154; real IEC-104 passes all);
* at least ``MIN_RATIO`` (60 %) of the port's payload packets frame cleanly;
* at least ``MIN_HITS`` (3) carry protocol-specific content (an S7 PDU, not
  just TPKT; a valid Modbus function code, not just an MBAP header).

Detections are registered as decode-as overrides scoped to the capture they
were proven on (:mod:`pcapper.port_overrides`), so every analyzer, the
overview and the threat engine pick the port up.
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .industrial_helpers import _record_payload, _tcp_seq_flags, _transport_record
from .pcap_cache import PcapMeta, iter_packets
from .port_overrides import register, scope_key

try:
    from scapy.layers.inet import TCP, UDP  # type: ignore
except Exception:  # pragma: no cover
    TCP = UDP = None  # type: ignore

MIN_HITS = 3
MIN_RATIO = 0.6
MIN_PACKETS = 3
SAMPLE_CAP = 64
SAMPLE_BYTES = 512
MAX_PACKETS = 50_000
MAX_PORTS = 1024
CANDIDATES_PER_TRANSPORT = 12

_Probe = Callable[[bytes, int], bool]


def _u16be(data: bytes, pos: int) -> int:
    return (data[pos] << 8) | data[pos + 1]


def _u16le(data: bytes, pos: int) -> int:
    return data[pos] | (data[pos + 1] << 8)


def _u32le(data: bytes, pos: int) -> int:
    return struct.unpack_from("<I", data, pos)[0]


def _walk(data: bytes, length: int, frame_size: Callable[[bytes, int], int | None], header: int) -> bool:
    """True when back-to-back frames tile the payload exactly.

    ``data`` may be a prefix of the payload (``length`` is the real size): a
    frame whose header lies beyond the prefix is trusted to its declared
    size, but the walk must still not overrun ``length``.
    """
    pos = 0
    frames = 0
    while pos < length:
        if pos + header > len(data):
            return frames > 0 and len(data) < length
        size = frame_size(data, pos)
        if size is None or size <= 0:
            return False
        pos += size
        frames += 1
    return pos == length and frames > 0


# --- TPKT / COTP (S7comm, S7comm-plus, MMS) ------------------------------------


def _tpkt_size(data: bytes, pos: int) -> int | None:
    if data[pos] != 3 or data[pos + 1] != 0:
        return None
    size = _u16be(data, pos + 2)
    return size if size >= 7 else None


def _tpkt_frame(data: bytes, length: int) -> bool:
    if length < 7 or not _walk(data, length, _tpkt_size, 4):
        return False
    li = data[4]
    return 2 <= li + 1 <= _u16be(data, 2) - 4 and data[5] in (0xF0, 0xE0, 0xD0, 0x80, 0xC0)


def _cotp_dt_payload(data: bytes) -> int | None:
    """Offset of the user data after a COTP DT header, or None."""
    if len(data) < 8 or data[5] != 0xF0:
        return None
    offset = 4 + 1 + data[4]
    return offset if offset < len(data) else None


def _s7_hit(data: bytes, length: int) -> bool:
    offset = _cotp_dt_payload(data)
    return offset is not None and data[offset] in (0x32, 0x72)


def _mms_hit(data: bytes, length: int) -> bool:
    offset = _cotp_dt_payload(data)
    if offset is None:
        return False
    spdu = data[offset:offset + 4]
    # ISO 8327 session: CONNECT / ACCEPT, or GIVE-TOKENS + DATA-TRANSFER.
    return bool(spdu) and (spdu[0] in (0x0D, 0x0E) or spdu == b"\x01\x00\x01\x00")


# --- Modbus/TCP ---------------------------------------------------------------

_MODBUS_FUNCTIONS = {1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 20, 21, 22, 23, 24, 43, 90}


def _mbap_size(data: bytes, pos: int) -> int | None:
    if _u16be(data, pos + 2) != 0:
        return None
    size = _u16be(data, pos + 4)
    return size + 6 if 2 <= size <= 254 else None


def _modbus_frame(data: bytes, length: int) -> bool:
    return length >= 8 and _walk(data, length, _mbap_size, 6)


def _modbus_hit(data: bytes, length: int) -> bool:
    if len(data) < 8:
        return False
    function = data[7]
    if function & 0x80:
        return len(data) >= 9 and (function & 0x7F) in _MODBUS_FUNCTIONS and 1 <= data[8] <= 11
    return function in _MODBUS_FUNCTIONS


# --- DNP3 -----------------------------------------------------------------------


def _dnp3_frame(data: bytes, length: int) -> bool:
    from .dnp3 import _check_crc

    def size(buf: bytes, pos: int) -> int | None:
        if buf[pos] != 0x05 or buf[pos + 1] != 0x64 or buf[pos + 2] < 5:
            return None
        if pos + 10 <= len(buf) and not _check_crc(buf[pos:pos + 8], buf[pos + 8:pos + 10]):
            return None
        user = buf[pos + 2] - 5
        return 10 + user + 2 * ((user + 15) // 16)

    return length >= 10 and _walk(data, length, size, 10)


# --- EtherNet/IP ------------------------------------------------------------------

_ENIP_COMMANDS = {0x0001, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F, 0x0070, 0x0072, 0x0073}


def _enip_size(data: bytes, pos: int) -> int | None:
    if _u16le(data, pos) not in _ENIP_COMMANDS:
        return None
    if pos + 24 <= len(data) and _u32le(data, pos + 20) != 0:
        return None  # options field must be zero
    return 24 + _u16le(data, pos + 2)


def _enip_frame(data: bytes, length: int) -> bool:
    return length >= 24 and _walk(data, length, _enip_size, 24)


def _enip_hit(data: bytes, length: int) -> bool:
    return len(data) >= 2 and _u16le(data, 0) in {0x6F, 0x70, 0x65, 0x63, 0x04}


# --- IEC 60870-5-104 --------------------------------------------------------------

_U_FORMAT = {0x07, 0x0B, 0x13, 0x23, 0x43, 0x83}


def _apci_size(data: bytes, pos: int) -> int | None:
    if data[pos] != 0x68 or not 4 <= data[pos + 1] <= 253:
        return None
    return 2 + data[pos + 1]


def _iec104_frame(data: bytes, length: int) -> bool:
    return length >= 6 and _walk(data, length, _apci_size, 2)


def _iec104_hit(data: bytes, length: int) -> bool:
    from .iec104 import ASDU_TYPES

    if len(data) < 6:
        return False
    control = data[2]
    if data[1] == 4:
        return control in _U_FORMAT or control == 0x01
    return control & 0x01 == 0 and len(data) > 6 and data[6] in ASDU_TYPES


# --- OPC UA binary ------------------------------------------------------------------

_UA_TYPES = {b"HEL", b"ACK", b"ERR", b"RHE", b"OPN", b"MSG", b"CLO"}


def _ua_size(data: bytes, pos: int) -> int | None:
    if pos + 8 > len(data):
        return None
    if bytes(data[pos:pos + 3]) not in _UA_TYPES or data[pos + 3] not in b"FCA":
        return None
    size = _u32le(data, pos + 4)
    return size if size >= 8 else None


def _opcua_frame(data: bytes, length: int) -> bool:
    return length >= 8 and _walk(data, length, _ua_size, 8)


# --- BACnet/IP (BVLC) -----------------------------------------------------------------


def _bacnet_frame(data: bytes, length: int) -> bool:
    return length >= 4 and data[0] == 0x81 and data[1] <= 0x0C and _u16be(data, 2) == length


def _bacnet_hit(data: bytes, length: int) -> bool:
    return _bacnet_frame(data, length) and len(data) > 4 and data[1] in (0x0A, 0x0B, 0x04) and data[4] == 0x01


# --- KNXnet/IP ------------------------------------------------------------------------


def _knx_frame(data: bytes, length: int) -> bool:
    if length < 6 or data[0] != 0x06 or data[1] not in (0x10, 0x20):
        return False
    service = _u16be(data, 2)
    return 0x0200 <= service <= 0x09FF and _u16be(data, 4) == length


# --- Beckhoff ADS / AMS over TCP --------------------------------------------------------


def _ams_size(data: bytes, pos: int) -> int | None:
    if data[pos] != 0 or data[pos + 1] != 0:
        return None
    size = _u32le(data, pos + 2)
    if size < 32:
        return None
    if pos + 38 <= len(data):
        command = _u16le(data, pos + 6 + 16)
        data_len = _u32le(data, pos + 6 + 20)
        if command > 9 or data_len + 32 != size:
            return None
    return 6 + size


def _ads_frame(data: bytes, length: int) -> bool:
    return length >= 38 and _walk(data, length, _ams_size, 6)


# --- LS ELECTRIC XGT FEnet ---------------------------------------------------------------


def _xgt_frame(data: bytes, length: int) -> bool:
    if length < 20 or len(data) < 20:
        return False
    if not (data[:8] == b"LSIS-XGT" or data[:10] == b"LGIS-GLOFA"):
        return False
    return _u16le(data, 16) + 20 == length


# --- Omron FINS/TCP, MELSEC SLMP/MC, HART-IP --------------------------------------------


def _fins_tcp_frame(data: bytes, length: int) -> bool:
    return length >= 16 and data[:4] == b"FINS" and struct.unpack_from(">I", data, 4)[0] + 8 == length


def _melsec_frame(data: bytes, length: int) -> bool:
    if length < 11 or len(data) < 11:
        return False
    if data[:2] in (b"\x50\x00", b"\xd0\x00"):
        return _u16le(data, 7) + 9 == length
    if data[:2] in (b"\x54\x00", b"\xd4\x00") and len(data) >= 15:
        return _u16le(data, 11) + 13 == length
    return False


def _hartip_frame(data: bytes, length: int) -> bool:
    return (
        length >= 8
        and data[0] == 1
        and data[1] in (0, 1, 2, 3, 15)
        and data[2] in (0, 1, 2, 3, 128)
        and _u16be(data, 6) == length
    )


# --- IEC 61850-90-5 R-GOOSE (CLTP + session header over UDP) ------------------------


def _rgoose_frame(data: bytes, length: int) -> bool:
    if length < 31 or data[:2] != b"\x01\x40" or data[2] not in (0xA0, 0xA1, 0xA2, 0xA3):
        return False
    if data[4] != 0x80:
        return False
    if length > len(data):
        return True  # beyond the sampled prefix; the header itself checked out
    from .goose import parse_rgoose

    return parse_rgoose(data) is not None


def _rgoose_hit(data: bytes, length: int) -> bool:
    return _rgoose_frame(data, length) and data[2] in (0xA0, 0xA1)


# --- ROC Plus (CRC-16/MODBUS), ANSI C12.22 (ACSE), DLMS/COSEM wrapper -------------


def _roc_frame(data: bytes, length: int) -> bool:
    if length > len(data):
        return False
    from .rocplus import parse_roc_frames

    return bool(parse_roc_frames(data))


def _c1222_frame(data: bytes, length: int) -> bool:
    if length > len(data) or data[:1] != b"\x60":
        return False
    from .c1222 import parse_c1222

    message = parse_c1222(data)
    return message is not None and bool(message.services or message.security_mode == 2)


def _dlms_frame(data: bytes, length: int) -> bool:
    if length > len(data):
        return False
    from .dlms import parse_dlms

    return parse_dlms(data) is not None


@dataclass(frozen=True)
class ProtocolProbe:
    step: str
    label: str
    transports: tuple[str, ...]
    default_ports: frozenset[int]
    frame: _Probe
    hit: _Probe


PROBES: tuple[ProtocolProbe, ...] = (
    ProtocolProbe("s7", "S7comm (TPKT/COTP)", ("tcp",), frozenset({102}), _tpkt_frame, _s7_hit),
    ProtocolProbe("mms", "IEC 61850 MMS (TPKT/COTP)", ("tcp",), frozenset({102}), _tpkt_frame, _mms_hit),
    ProtocolProbe("modbus", "Modbus/TCP (MBAP)", ("tcp",), frozenset({502}), _modbus_frame, _modbus_hit),
    ProtocolProbe("dnp3", "DNP3", ("tcp", "udp"), frozenset({20000}), _dnp3_frame, _dnp3_frame),
    ProtocolProbe("enip", "EtherNet/IP", ("tcp",), frozenset({44818, 2222, 2221}), _enip_frame, _enip_hit),
    ProtocolProbe("iec104", "IEC 60870-5-104", ("tcp",), frozenset({2404}), _iec104_frame, _iec104_hit),
    ProtocolProbe("opc", "OPC UA binary", ("tcp",), frozenset({4840}), _opcua_frame, _opcua_frame),
    ProtocolProbe("bacnet", "BACnet/IP (BVLC)", ("udp",), frozenset({47808}), _bacnet_frame, _bacnet_hit),
    ProtocolProbe("knx", "KNXnet/IP", ("udp", "tcp"), frozenset({3671}), _knx_frame, _knx_frame),
    ProtocolProbe("ads", "Beckhoff ADS/AMS", ("tcp",), frozenset({48898}), _ads_frame, _ads_frame),
    ProtocolProbe("xgt", "LS XGT FEnet", ("tcp", "udp"), frozenset({2004, 2005}), _xgt_frame, _xgt_frame),
    ProtocolProbe("fins", "Omron FINS/TCP", ("tcp",), frozenset({9600}), _fins_tcp_frame, _fins_tcp_frame),
    ProtocolProbe("melsec", "MELSEC SLMP/MC (3E/4E)", ("tcp", "udp"), frozenset({5006, 5007}), _melsec_frame, _melsec_frame),
    ProtocolProbe("hart", "HART-IP", ("tcp", "udp"), frozenset({5094}), _hartip_frame, _hartip_frame),
    ProtocolProbe("rocplus", "ROC Plus", ("tcp", "udp"), frozenset({4000}), _roc_frame, _roc_frame),
    ProtocolProbe("c1222", "ANSI C12.22", ("tcp", "udp"), frozenset({1153}), _c1222_frame, _c1222_frame),
    ProtocolProbe("dlms", "DLMS/COSEM wrapper", ("tcp", "udp"), frozenset({4059}), _dlms_frame, _dlms_frame),
    # The GOOSE analyzer finds R-GOOSE on any UDP port by itself; the probe
    # exists so --overview knows to run it. UDP 102 is R-GOOSE's own port.
    ProtocolProbe("goose", "IEC 61850-90-5 R-GOOSE", ("udp",), frozenset(), _rgoose_frame, _rgoose_hit),
)


@dataclass(frozen=True)
class PortDetection:
    transport: str
    port: int
    step: str
    label: str
    hits: int
    clean: int
    total: int

    @property
    def ratio(self) -> float:
        return self.clean / self.total if self.total else 0.0

    @property
    def basis(self) -> str:
        return (
            f"{self.clean}/{self.total} payload packets frame as {self.label}, "
            f"{self.hits} with {self.step} content"
        )

    def describe(self) -> str:
        return f"{self.label} on {self.transport}/{self.port} ({self.basis})"


def detect_nonstandard_ports(
    path: Path,
    *,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    show_status: bool = False,
    max_packets: int = MAX_PACKETS,
) -> list[PortDetection]:
    """OT protocols carried on non-registered ports, proven by payload structure.

    Reads at most ``max_packets`` packets. A server port is the destination
    of a SYN when one was seen, otherwise the lower of the two ports.
    """
    if TCP is None:
        return []
    syn_servers: set[tuple[str, int]] = set()
    counts: Counter[tuple[str, int]] = Counter()
    samples: dict[tuple[str, int], list[tuple[bytes, int]]] = {}

    head = None
    if packets is None:
        from . import sharedpass
        from .pcap_cache import read_head

        if not sharedpass.consuming(path):
            # Read from disk, the records are kept for the pass that follows,
            # which replays them instead of reading them again.
            head = read_head(path, max_packets)
    source = head if head is not None else iter_packets(
        path, packets=packets, meta=meta, show_status=show_status, lite=True
    )
    for index, pkt in enumerate(source):
        if index >= max_packets:
            break
        record = _transport_record(pkt)
        if record is None:
            continue
        transport = "tcp" if record[0] else "udp"
        sport, dport = record[1], record[2]
        if transport == "tcp":
            seq_flags = _tcp_seq_flags(pkt)
            flags = seq_flags[1] if seq_flags is not None else 0
            if flags & 0x02 and not flags & 0x10:
                syn_servers.add(("tcp", dport))
        payload = _record_payload(pkt, record)
        if not payload:
            continue
        # A registered OT/IT server port decides first: one stray SYN to a
        # client port (a scan, a reset storm) must not turn every client of
        # tcp/502 into a "Modbus server" on its ephemeral port.
        if dport in _KNOWN_SERVER_PORTS and sport not in _KNOWN_SERVER_PORTS:
            server = dport
        elif sport in _KNOWN_SERVER_PORTS and dport not in _KNOWN_SERVER_PORTS:
            server = sport
        elif (transport, dport) in syn_servers:
            server = dport
        elif (transport, sport) in syn_servers:
            server = sport
        else:
            # Lower port as a last resort. A registered OT port always wins
            # first: old Windows hands out client ports from 1025-5000, so
            # "lower" would pick the client of an EtherNet/IP session on
            # 44818 (tcp/1054 -> 44818) and report EtherNet/IP on tcp/1054.
            server = min(sport, dport) or max(sport, dport)
        key = (transport, server)
        if key not in counts and len(counts) >= MAX_PORTS:
            continue
        counts[key] += 1
        bucket = samples.setdefault(key, [])
        if len(bucket) < SAMPLE_CAP:
            bucket.append((bytes(payload[:SAMPLE_BYTES]), len(payload)))
    if head is not None:
        head.close()  # type: ignore[attr-defined]  # stores the kept records

    found: list[PortDetection] = []
    for transport in ("tcp", "udp"):
        ranked = [
            key for key, total in counts.most_common()
            if key[0] == transport and total >= MIN_PACKETS
        ][:CANDIDATES_PER_TRANSPORT]
        for key in ranked:
            port = key[1]
            port_samples = samples.get(key, [])
            total = len(port_samples)
            best: PortDetection | None = None
            for probe in PROBES:
                if transport not in probe.transports or port in probe.default_ports:
                    continue
                clean = hits = 0
                for data, length in port_samples:
                    try:
                        if not probe.frame(data, length):
                            continue
                        clean += 1
                        if probe.hit(data, length):
                            hits += 1
                    except (IndexError, struct.error):
                        continue
                if hits < MIN_HITS or clean < MIN_RATIO * total:
                    continue
                candidate = PortDetection(transport, port, probe.step, probe.label, hits, clean, total)
                # TPKT carries S7 or MMS: the one with protocol content wins.
                if best is None or (candidate.hits, candidate.clean) > (best.hits, best.clean):
                    best = candidate
            if best is not None:
                found.append(best)
    return found


def _known_server_ports() -> frozenset[int]:
    from .ot_ports import OT_PORT_PROTOCOLS

    ports = set(OT_PORT_PROTOCOLS)
    for probe in PROBES:
        ports |= probe.default_ports
    # Common IT services: never the client side of a conversation.
    ports |= {20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137,
              138, 139, 143, 161, 162, 389, 443, 445, 514, 636, 1433, 1883, 3389,
              5353, 5355, 5985, 5986, 8080, 8883}
    return frozenset(ports)


_KNOWN_SERVER_PORTS = _known_server_ports()


_DETECTED: dict[str, list[PortDetection]] = {}
_ENABLED = True


def set_auto_decode_enabled(enabled: bool) -> None:
    """``--no-auto-decode``: every caller (CLI, overview, threats) honours it."""
    global _ENABLED
    _ENABLED = bool(enabled)


def auto_decode_enabled() -> bool:
    return _ENABLED


def auto_decode(
    path: Path,
    *,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    show_status: bool = False,
) -> list[PortDetection]:
    """Detect once per capture and register the results as scoped overrides."""
    if not _ENABLED:
        return []
    key = scope_key(path)
    cached = _DETECTED.get(key)
    if cached is not None:
        return cached
    from . import utils

    if utils._MEMO_RECORDER is not None:
        # A shared-pass dry run (pcapper.sharedpass.discover) sees an empty
        # packet view: detecting -- and caching -- "nothing" here would turn
        # auto decode-as off for the real run.
        return []
    detections = detect_nonstandard_ports(
        path, packets=packets, meta=meta, show_status=show_status
    )
    for detection in detections:
        register(
            detection.transport,
            detection.port,
            detection.step,
            origin=f"auto: {detection.basis}",
            scope=path,
        )
        # EtherNet/IP encapsulation carries CIP: both analyzers read the port.
        if detection.step == "enip":
            register(detection.transport, detection.port, "cip", origin=f"auto: {detection.basis}", scope=path)
    _DETECTED[key] = detections
    return detections


def detections_for(path: Path) -> list[PortDetection]:
    return list(_DETECTED.get(scope_key(path), []))


def clear_detections() -> None:
    _DETECTED.clear()
