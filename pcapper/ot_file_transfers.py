"""File transfers carried by OT/ICS protocols, for ``--files``.

DNP3 file transfer (function codes 25-30 with Group 70 objects), MMS file
services (FileOpen/FileRead/FileClose, FileDirectory, FileDelete, FileRename,
ObtainFile) and BACnet AtomicReadFile/AtomicWriteFile are rebuilt from the
TCP streams and UDP datagrams the dpkt pass of files.py collects.

Content is carved only when the protocol says where every piece belongs and
all of them were captured: DNP3 blocks 0..N with the last-block flag, MMS
FileRead replies on one FRSM up to ``moreFollows`` false (and the size
FileOpen announced), BACnet stream data from position 0 up to end-of-file.
Anything less is reported with its name, direction and declared size, without
content, and its note says why.

Not rebuilt here: ROC Plus, CODESYS and Modicon/UMAS file transfers, and DNP3
AUTHENTICATE_FILE (it carries a user name and password, which are --creds'
business, not a file).
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from .dnp3 import (
    QUALIFIER_ALL_OBJECTS,
    QUALIFIER_COUNT_SIZES,
    QUALIFIER_INDEX_PREFIX_SIZES,
    QUALIFIER_RANGE_SIZES,
    _check_crc,
    _object_data_length,
    _strip_crc_blocks,
)
from .mms import MMS_SERVICE_TAGS, _read_ber_tlv

TcpStreams = Dict[Tuple[str, str, int, int], List[Tuple[int, bytes, int]]]
UdpPackets = List[Tuple[str, str, int, int, bytes, int]]
Endpoint = Tuple[str, int]

# Transfers reported per protocol, and carved bytes kept in all: a BACnet
# controller polled for its trend files can answer tens of thousands of reads.
MAX_TRANSFERS_PER_PROTOCOL = 500
MAX_CARVED_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_NOTE_NAMES = 6
# A note opens with one of these when the artifact holds no file bytes: the
# --files table cuts notes at 40 characters, and whether the content is there
# is the first thing to know. NOT_CARVED: a file moved but it could not be
# rebuilt (the reason follows); NO_CONTENT: the operation moves no content.
NOT_CARVED = "[not carved]"
NO_CONTENT = "[no content]"


@dataclass
class OtFileTransfer:
    """One file operation. ``src``/``dst`` follow the content: the side that
    sent the file's bytes comes first (the outstation/server for a read, the
    master/client for a write); for an operation that moves no content
    (delete, rename, a failed open) the requester comes first."""

    protocol: str
    operation: str
    name: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    packets: List[int]
    size: Optional[int] = None
    payload: Optional[bytes] = None
    detail: str = ""

    @property
    def first_packet(self) -> int:
        return min(self.packets) if self.packets else 0


@dataclass
class _Pdu:
    """One protocol message rebuilt from the wire. ``packet`` (the packet
    that completed it) orders the messages of both directions of a flow."""

    packet: int
    src: Endpoint
    dst: Endpoint
    packets: List[int]
    body: object
    gap_before: bool = False


def extract_ot_file_transfers(
    tcp_streams: TcpStreams, udp_packets: UdpPackets
) -> Tuple[List[OtFileTransfer], List[str]]:
    """Every DNP3, MMS and BACnet file transfer in the streams/datagrams,
    and the errors met rebuilding them."""
    transfers: List[OtFileTransfer] = []
    errors: List[str] = []
    for label, finder in (
        ("DNP3", lambda: _dnp3_transfers(tcp_streams, udp_packets)),
        ("MMS", lambda: _mms_transfers(tcp_streams)),
        ("BACnet", lambda: _bacnet_transfers(udp_packets)),
    ):
        try:
            found = finder()
        except Exception as exc:  # noqa: BLE001 - one parser must not cost the rest
            errors.append(f"{label} file-transfer parsing failed: {type(exc).__name__}: {exc}")
            continue
        found.sort(key=lambda item: item.first_packet)
        if len(found) > MAX_TRANSFERS_PER_PROTOCOL:
            errors.append(
                f"{len(found) - MAX_TRANSFERS_PER_PROTOCOL} more {label} file transfer(s) "
                f"not listed (first {MAX_TRANSFERS_PER_PROTOCOL} kept)."
            )
            found = found[:MAX_TRANSFERS_PER_PROTOCOL]
        transfers.extend(found)
    carved = 0
    for item in transfers:
        if item.payload is None:
            continue
        if carved + len(item.payload) > MAX_CARVED_BYTES:
            item.payload = None
            rebuilt = item.detail.replace(" B carved", " B rebuilt")
            item.detail = f"{NOT_CARVED} {rebuilt}; over the {MAX_CARVED_BYTES >> 20} MiB carving budget"
            continue
        carved += len(item.payload)
    return transfers, errors


# --- shared helpers -----------------------------------------------------------


def _ordered_segments(
    chunks: List[Tuple[int, bytes, int]],
) -> Iterator[Tuple[Optional[bytes], int]]:
    """A TCP direction's payload in sequence order as (bytes, packet number),
    retransmitted bytes dropped. ``None`` marks a gap: bytes never captured,
    or another connection on the same ports (OT masters often reuse a fixed
    source port) whose sequence numbers start elsewhere. Each message keeps
    the packet numbers it came in, so both directions still replay in
    capture order."""
    expected: Optional[int] = None
    for seq, payload, idx in sorted(chunks, key=lambda item: (item[0], item[2])):
        if not payload:
            continue
        if expected is not None:
            if seq > expected:
                yield None, idx
            elif seq < expected:
                overlap = expected - seq
                if overlap >= len(payload):
                    continue
                payload = payload[overlap:]
                seq = expected
        yield payload, idx
        expected = seq + len(payload)


class _Buffer:
    """Bytes of one direction awaiting a whole frame, with the packet each
    run of them came in."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.marks: List[Tuple[int, int]] = []  # (end offset, packet)

    def add(self, data: bytes, idx: int) -> None:
        self.data.extend(data)
        self.marks.append((len(self.data), idx))

    def packets(self, start: int, end: int) -> List[int]:
        """The packets that brought bytes ``start:end``."""
        out: List[int] = []
        begin = 0
        for mark_end, idx in self.marks:
            if mark_end > start and begin < end and idx not in out:
                out.append(idx)
            begin = mark_end
        return out

    def consume(self, count: int) -> None:
        if count <= 0:
            return
        del self.data[:count]
        self.marks = [(end - count, idx) for end, idx in self.marks if end > count]

    def clear(self) -> None:
        self.data.clear()
        self.marks.clear()


def _flow_key(src: Endpoint, dst: Endpoint) -> Tuple[Endpoint, Endpoint]:
    return (src, dst) if src <= dst else (dst, src)


def _local_name(name: str) -> str:
    """The last component of a wire path, under POSIX and Windows rules."""
    return name.replace("\\", "/").rstrip("/").split("/")[-1].strip()


def _names_preview(names: List[str]) -> str:
    shown = ", ".join(names[:_MAX_NOTE_NAMES])
    if len(names) > _MAX_NOTE_NAMES:
        shown += f", +{len(names) - _MAX_NOTE_NAMES} more"
    return shown


def _packets_text(packets: List[int]) -> str:
    ordered = sorted(set(packets))
    if len(ordered) <= 8:
        return ",".join(str(p) for p in ordered)
    return f"{ordered[0]}-{ordered[-1]} ({len(ordered)} packets)"


# --- DNP3 ---------------------------------------------------------------------

_DNP3_START = b"\x05\x64"
_DNP3_MAX_FRAGMENT = 65535
_DNP3_MODES = {0: "null", 1: "read", 2: "write", 3: "append"}
# Group 70 command / transport status codes (IEEE 1815-2012).
_DNP3_STATUS = {
    0: "success",
    1: "permission denied",
    2: "invalid mode",
    3: "file not found",
    4: "file locked",
    5: "too many open files",
    6: "invalid handle",
    7: "write block size",
    8: "communication lost",
    9: "cannot abort",
    16: "file not open",
    17: "handle expired",
    18: "buffer overrun",
    19: "fatal error",
    20: "block sequence error",
    255: "undefined error",
}


def _dnp3_status(code: Optional[int]) -> str:
    if code is None:
        return "unknown"
    return _DNP3_STATUS.get(code, f"status {code}")


def _dnp3_frames(buf: _Buffer) -> Iterator[Tuple[int, int, bytes, List[int]]]:
    """Whole link frames at the start of the buffer, both CRCs checked:
    (link source, link destination, user data, packets). Bytes before a
    valid header are skipped; an incomplete frame stays buffered."""
    data = buf.data
    pos = 0
    while True:
        start = data.find(_DNP3_START, pos)
        if start < 0:
            buf.consume(len(data) - (1 if data.endswith(b"\x05") else 0))
            return
        if len(data) - start < 10:
            buf.consume(start)
            return
        length = data[start + 2]
        header, header_crc = bytes(data[start : start + 8]), bytes(data[start + 8 : start + 10])
        if length < 5 or not _check_crc(header, header_crc):
            pos = start + 1
            continue
        n_user = length - 5
        end = start + 10 + n_user + 2 * ((n_user + 15) // 16)
        if end > len(data):
            buf.consume(start)
            return
        frame = bytes(data[start:end])
        packets = buf.packets(start, end)
        buf.consume(end)
        pos = 0
        user, crc_ok = _strip_crc_blocks(frame)
        if crc_ok and user:
            dl_dst = int.from_bytes(frame[4:6], "little")
            dl_src = int.from_bytes(frame[6:8], "little")
            yield dl_src, dl_dst, user, packets


class _Dnp3Direction:
    """Link frames -> transport segments -> application fragments of one
    direction of one flow."""

    def __init__(self) -> None:
        self.buf = _Buffer()
        self.transport: Dict[Tuple[int, int], Tuple[bytearray, int, List[int]]] = {}

    def reset(self) -> None:
        self.buf.clear()
        self.transport.clear()

    def feed(self, data: bytes, idx: int) -> Iterator[Tuple[bytes, List[int]]]:
        self.buf.add(data, idx)
        for dl_src, dl_dst, user, packets in _dnp3_frames(self.buf):
            header = user[0]
            fin, fir, seq = bool(header & 0x80), bool(header & 0x40), header & 0x3F
            key = (dl_src, dl_dst)
            if fir:
                self.transport[key] = (bytearray(user[1:]), seq, list(packets))
            elif key in self.transport and seq == (self.transport[key][1] + 1) % 64:
                fragment, _seq, frag_packets = self.transport[key]
                fragment.extend(user[1:])
                frag_packets.extend(p for p in packets if p not in frag_packets)
                self.transport[key] = (fragment, seq, frag_packets)
            else:
                self.transport.pop(key, None)
                continue
            if len(self.transport[key][0]) > _DNP3_MAX_FRAGMENT:
                self.transport.pop(key, None)
                continue
            if fin:
                fragment, _seq, frag_packets = self.transport.pop(key)
                yield bytes(fragment), frag_packets


def _dnp3_group70(fragment: bytes) -> Tuple[Optional[int], List[Tuple[int, bytes]]]:
    """(function code, [(variation, object bytes)]) of the Group 70 objects in
    an application fragment. Free-format (0x5B) objects carry their own size;
    other objects are skipped when their size is known, else parsing stops."""
    if len(fragment) < 2:
        return None, []
    fc = fragment[1]
    pos = 4 if fc in (129, 130) else 2
    objects: List[Tuple[int, bytes]] = []
    while pos + 3 <= len(fragment):
        group, variation, qualifier = fragment[pos], fragment[pos + 1], fragment[pos + 2]
        pos += 3
        if qualifier == 0x5B:
            if pos >= len(fragment):
                break
            count = fragment[pos]
            pos += 1
            for _ in range(count):
                if pos + 2 > len(fragment):
                    return fc, objects
                size = int.from_bytes(fragment[pos : pos + 2], "little")
                pos += 2
                if pos + size > len(fragment):
                    return fc, objects
                if group == 70:
                    objects.append((variation, fragment[pos : pos + size]))
                pos += size
            continue
        if qualifier == QUALIFIER_ALL_OBJECTS:
            continue
        count: Optional[int] = None
        if qualifier in QUALIFIER_RANGE_SIZES:
            size = QUALIFIER_RANGE_SIZES[qualifier]
            if pos + 2 * size > len(fragment):
                break
            first = int.from_bytes(fragment[pos : pos + size], "little")
            last = int.from_bytes(fragment[pos + size : pos + 2 * size], "little")
            count = max(last - first + 1, 0)
            pos += 2 * size
        elif qualifier in QUALIFIER_COUNT_SIZES:
            size = QUALIFIER_COUNT_SIZES[qualifier]
            if pos + size > len(fragment):
                break
            count = int.from_bytes(fragment[pos : pos + size], "little")
            pos += size
        else:
            break
        data_len = _object_data_length(
            group, variation, count, QUALIFIER_INDEX_PREFIX_SIZES.get(qualifier, 0)
        )
        if data_len is None:
            break
        pos += data_len
    return fc, objects


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def _u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "little")


def _dnp3_name(obj: bytes, fixed: int) -> Optional[str]:
    """A Group 70 name: the string-offset and string-size fields that open the
    object, the name itself after the ``fixed``-byte part."""
    offset, size = _u16(obj, 0), _u16(obj, 2)
    if offset < fixed or offset + size > len(obj):
        return None
    return obj[offset : offset + size].decode("latin-1", errors="replace")


def _dnp3_events(fc: int, objects: List[Tuple[int, bytes]]) -> List[dict]:
    """The file-transfer meaning of each Group 70 object of a fragment."""
    events: List[dict] = []
    for variation, obj in objects:
        if variation == 3 and len(obj) >= 26:  # file command
            events.append(
                {
                    "kind": "command",
                    "name": _dnp3_name(obj, 26),
                    "size": _u32(obj, 16),
                    "mode": _u16(obj, 20),
                    "request_id": _u16(obj, 24),
                }
            )
        elif variation == 4 and len(obj) >= 13:  # file command status
            events.append(
                {
                    "kind": "status",
                    "handle": _u32(obj, 0),
                    "size": _u32(obj, 4),
                    "request_id": _u16(obj, 10),
                    "status": obj[12],
                }
            )
        elif variation == 5 and len(obj) >= 8:  # file transport
            block = _u32(obj, 4)
            events.append(
                {
                    "kind": "read" if fc == 1 else "data",
                    "handle": _u32(obj, 0),
                    "block": block & 0x7FFFFFFF,
                    "last": bool(block & 0x80000000),
                    "data": obj[8:],
                }
            )
        elif variation == 6 and len(obj) >= 9:  # file transport status
            events.append({"kind": "transport_status", "handle": _u32(obj, 0), "status": obj[8]})
        elif variation == 7 and len(obj) >= 20:  # file descriptor
            events.append(
                {
                    "kind": "descriptor",
                    "name": _dnp3_name(obj, 20),
                    "type": _u16(obj, 4),
                    "size": _u32(obj, 6),
                    "request_id": _u16(obj, 18),
                }
            )
        elif variation == 8 and obj:  # file specification string
            events.append({"kind": "spec", "name": obj.decode("latin-1", errors="replace")})
    return events


def _dnp3_directory(payload: bytes) -> Optional[List[str]]:
    """Entry names when ``payload`` is a whole run of Group 70 file
    descriptors (what a directory read returns), else None."""
    names: List[str] = []
    pos = 0
    while pos < len(payload):
        if pos + 20 > len(payload):
            return None
        offset, size, kind = _u16(payload, pos), _u16(payload, pos + 2), _u16(payload, pos + 4)
        if offset != 20 or pos + offset + size > len(payload) or kind > 1:
            return None
        name = payload[pos + offset : pos + offset + size].decode("latin-1", errors="replace")
        names.append(name + ("/" if kind == 0 else ""))
        pos += offset + size
    return names or None


@dataclass
class _Dnp3File:
    name: Optional[str]
    mode: Optional[int]
    master: Optional[Endpoint]
    outstation: Optional[Endpoint]
    declared_size: Optional[int]
    handle: int
    packets: List[int] = field(default_factory=list)
    blocks: Dict[int, bytes] = field(default_factory=dict)
    last_block: Optional[int] = None
    from_outstation: bool = False
    from_master: bool = False
    gap: bool = False
    conflict: bool = False
    closing: bool = False
    aborted: bool = False
    write_errors: List[str] = field(default_factory=list)


def _dnp3_finish(item: _Dnp3File) -> OtFileTransfer:
    reading = item.from_outstation or (item.mode == 1 and not item.from_master)
    sender, receiver = (item.outstation, item.master) if reading else (item.master, item.outstation)
    sender = sender or ("", None)
    receiver = receiver or ("", None)
    wire_name = item.name or ""
    blocks = item.blocks
    payload: Optional[bytes] = None
    reasons: List[str] = []
    if not blocks:
        reasons.append("no file data captured")
    elif item.last_block is None:
        reasons.append("last block not captured")
    elif any(block not in blocks for block in range(item.last_block + 1)):
        missing = sum(1 for block in range(item.last_block + 1) if block not in blocks)
        reasons.append(f"{missing} of {item.last_block + 1} blocks not captured")
    elif item.gap:
        reasons.append("capture gap in the transfer")
    elif item.conflict:
        reasons.append("a block number seen twice with different data")
    else:
        payload = b"".join(blocks[block] for block in range(item.last_block + 1))
        if len(payload) > MAX_FILE_BYTES:
            payload = None
            reasons.append("larger than the carving limit")
        elif reading and item.declared_size and item.declared_size != len(payload):
            reasons.append(f"{len(payload)} B carved but {item.declared_size} B announced")
            payload = None
    listing = _dnp3_directory(payload) if payload is not None and reading else None
    if listing is not None:
        operation = "directory"
        filename = f"dnp3_directory_{item.handle:08x}.bin"
        what = (
            f"DNP3 directory listing of {wire_name or '?'}: {len(listing)} entries "
            f"({_names_preview(listing)})"
        )
    else:
        operation = "read" if reading else ("append" if item.mode == 3 else "write")
        filename = _local_name(wire_name) or f"dnp3_file_{item.handle:08x}.bin"
        what = f"DNP3 file {operation} ({'upload from' if reading else 'download to'} outstation)"
        what += f" {wire_name}" if wire_name else ""
    if payload is not None:
        what += f"; {len(blocks)} block(s), {len(payload)} B carved"
    else:
        size_text = f"; {item.declared_size} B announced" if item.declared_size else ""
        what = f"{NOT_CARVED} {what}; {'; '.join(reasons)}{size_text}"
    if item.aborted:
        what += "; transfer aborted"
    if item.write_errors:
        what += f"; write status: {', '.join(item.write_errors[:3])}"
    what += f"; packets {_packets_text(item.packets)}"
    return OtFileTransfer(
        protocol="DNP3",
        operation=operation,
        name=filename,
        src_ip=sender[0],
        dst_ip=receiver[0],
        src_port=sender[1],
        dst_port=receiver[1],
        packets=sorted(set(item.packets)),
        size=len(payload) if payload is not None else (item.declared_size or None),
        payload=payload,
        detail=what,
    )


def _dnp3_no_content(
    operation: str,
    name: Optional[str],
    master: Endpoint,
    outstation: Endpoint,
    packets: List[int],
    outcome: str,
    size: Optional[int] = None,
) -> OtFileTransfer:
    wire_name = name or ""
    return OtFileTransfer(
        protocol="DNP3",
        operation=operation,
        name=_local_name(wire_name) or "dnp3_file.bin",
        src_ip=master[0],
        dst_ip=outstation[0],
        src_port=master[1],
        dst_port=outstation[1],
        packets=sorted(set(packets)),
        size=size,
        detail=(
            f"{NO_CONTENT} DNP3 {operation} {wire_name or '?'} ({outcome}); "
            f"packets {_packets_text(packets)}"
        ),
    )


def _dnp3_candidate(chunks: List[Tuple[int, bytes, int]]) -> bool:
    """A TCP direction with a DNP3 link header (start bytes and a good header
    CRC) in one of its first segments."""
    for _seq, payload, _idx in heapq.nsmallest(4, chunks, key=lambda item: (item[0], item[2])):
        pos = payload.find(_DNP3_START)
        while 0 <= pos <= len(payload) - 10:
            if _check_crc(payload[pos : pos + 8], payload[pos + 8 : pos + 10]):
                return True
            pos = payload.find(_DNP3_START, pos + 1)
    return False


def _dnp3_pdus(tcp_streams: TcpStreams, udp_packets: UdpPackets) -> Dict[tuple, List[_Pdu]]:
    """Application fragments of every DNP3 flow (TCP on any port whose stream
    carries DNP3 link frames, UDP datagrams that start with one)."""
    flows: Dict[tuple, List[_Pdu]] = defaultdict(list)
    for (src, dst, sport, dport), chunks in tcp_streams.items():
        if not _dnp3_candidate(chunks):
            continue
        direction = _Dnp3Direction()
        gap = False
        for data, idx in _ordered_segments(chunks):
            if data is None:
                direction.reset()
                gap = True
                continue
            for fragment, packets in direction.feed(data, idx):
                flows[_flow_key((src, sport), (dst, dport))].append(
                    _Pdu(max(packets), (src, sport), (dst, dport), packets, fragment, gap)
                )
                gap = False
    udp_directions: Dict[Tuple[str, str, int, int], _Dnp3Direction] = {}
    for src, dst, sport, dport, payload, idx in udp_packets:
        if not payload.startswith(_DNP3_START):
            continue
        direction = udp_directions.setdefault((src, dst, sport, dport), _Dnp3Direction())
        direction.buf.clear()  # a datagram holds whole frames: nothing carries over
        for fragment, packets in direction.feed(payload, idx):
            flows[_flow_key((src, sport), (dst, dport))].append(
                _Pdu(idx, (src, sport), (dst, dport), packets, fragment)
            )
    return flows


def _dnp3_transfers(tcp_streams: TcpStreams, udp_packets: UdpPackets) -> List[OtFileTransfer]:
    out: List[OtFileTransfer] = []
    for pdus in _dnp3_pdus(tcp_streams, udp_packets).values():
        out.extend(_dnp3_flow_transfers(sorted(pdus, key=lambda pdu: pdu.packet)))
    return out


@dataclass
class _Dnp3Command:
    """An OPEN_FILE, DELETE_FILE or GET_FILE_INFO request awaiting its answer."""

    fc: int
    event: dict
    master: Endpoint
    outstation: Endpoint
    packets: List[int]

    @property
    def operation(self) -> str:
        if self.fc == 25:
            mode = self.event.get("mode")
            return f"file open ({_DNP3_MODES.get(mode, mode)})"
        return "file delete" if self.fc == 27 else "file info"

    def no_content(
        self, operation: str, outcome: str, more_packets: List[int], name: Optional[str] = None,
        size: Optional[int] = None,
    ) -> OtFileTransfer:
        return _dnp3_no_content(
            operation,
            name or self.event.get("name"),
            self.master,
            self.outstation,
            self.packets + list(more_packets),
            outcome,
            size,
        )


def _dnp3_flow_transfers(pdus: List[_Pdu]) -> List[OtFileTransfer]:
    """Replay one flow's fragments in packet order: OPEN_FILE and its status
    name a handle, file transport objects carry its blocks, CLOSE/ABORT end it."""
    out: List[OtFileTransfer] = []
    commands: Dict[int, _Dnp3Command] = {}  # by request id
    files: Dict[int, _Dnp3File] = {}  # by file handle
    for pdu in pdus:
        fc, objects = _dnp3_group70(pdu.body)  # type: ignore[arg-type]
        if pdu.gap_before:
            for item in files.values():
                item.gap = True
        if fc is None or not objects:
            continue
        is_response = fc in (129, 130)
        master, outstation = (pdu.dst, pdu.src) if is_response else (pdu.src, pdu.dst)
        for event in _dnp3_events(fc, objects):
            kind = event["kind"]
            if not is_response and kind in ("command", "descriptor", "spec") and fc in (25, 27, 28):
                commands[event.get("request_id", -1)] = _Dnp3Command(
                    fc, event, master, outstation, list(pdu.packets)
                )
            elif kind == "status" and not is_response and fc in (26, 30):  # CLOSE / ABORT
                item = files.get(event["handle"])
                if item is not None:
                    item.packets.extend(pdu.packets)
                    item.closing = True
                    item.aborted = item.aborted or fc == 30
            elif kind == "status" and is_response:
                item = files.get(event["handle"])
                if item is not None and item.closing:
                    item.packets.extend(pdu.packets)
                    out.append(_dnp3_finish(files.pop(event["handle"])))
                    continue
                command = commands.pop(event["request_id"], None)
                if command is None:
                    if item is not None:
                        item.packets.extend(pdu.packets)
                    continue
                status = _dnp3_status(event["status"])
                if command.fc in (27, 28):
                    out.append(command.no_content(command.operation, status, pdu.packets))
                elif event["status"] != 0:
                    operation = f"{command.operation} refused"
                    out.append(command.no_content(operation, status, pdu.packets))
                else:
                    previous = files.pop(event["handle"], None)
                    if previous is not None:
                        out.append(_dnp3_finish(previous))
                    mode = command.event["mode"]
                    declared = event["size"] if mode == 1 else command.event["size"]
                    files[event["handle"]] = _Dnp3File(
                        command.event["name"],
                        mode,
                        command.master,
                        command.outstation,
                        declared or None,
                        event["handle"],
                        packets=command.packets + list(pdu.packets),
                    )
            elif kind == "descriptor" and is_response:
                command = commands.pop(event["request_id"], None)
                if command is not None:
                    kind_name = "directory" if event["type"] == 0 else "file"
                    out.append(
                        command.no_content(
                            "file info", f"{kind_name}, {event['size']} B", pdu.packets,
                            name=event["name"], size=event["size"],
                        )
                    )
            elif kind == "data" and (is_response or fc == 2):
                item = files.get(event["handle"])
                if item is None:
                    item = _Dnp3File(None, None, master, outstation, None, event["handle"])
                    files[event["handle"]] = item
                item.packets.extend(pdu.packets)
                if is_response:
                    item.from_outstation = True
                else:
                    item.from_master = True
                if item.blocks.setdefault(event["block"], event["data"]) != event["data"]:
                    item.conflict = True
                if event["last"]:
                    item.last_block = event["block"]
            elif kind == "read":
                item = files.get(event["handle"])
                if item is not None:
                    item.packets.extend(pdu.packets)
            elif kind == "transport_status" and is_response:
                item = files.get(event["handle"])
                if item is not None:
                    item.packets.extend(pdu.packets)
                    if event["status"] != 0:
                        item.write_errors.append(_dnp3_status(event["status"]))
    for item in files.values():
        out.append(_dnp3_finish(item))
    for command in commands.values():
        out.append(command.no_content(command.operation, "no response captured", []))
    return out


# --- MMS ----------------------------------------------------------------------

_MMS_PORT = 102
_MMS_FILE_SERVICES = {
    "FileOpen",
    "FileRead",
    "FileClose",
    "FileDelete",
    "FileRename",
    "FileDirectory",
    "ObtainFile",
}


class _CotpDirection:
    """TPKT/COTP data TPDUs of one direction joined into transport service
    data units (a TSDU ends with a TPDU carrying the EOT bit)."""

    def __init__(self) -> None:
        self.buf = _Buffer()
        self.tsdu = bytearray()
        self.tsdu_packets: List[int] = []

    def reset(self) -> None:
        self.buf.clear()
        self.tsdu = bytearray()
        self.tsdu_packets = []

    def feed(self, data: bytes, idx: int) -> Iterator[Tuple[bytes, List[int]]]:
        self.buf.add(data, idx)
        while len(self.buf.data) >= 4:
            pending = self.buf.data
            if pending[0] != 0x03 or pending[1] != 0x00:
                self.reset()  # framing lost: resynchronise on a later segment
                return
            length = int.from_bytes(pending[2:4], "big")
            if length < 7:
                self.reset()
                return
            if len(pending) < length:
                return
            tpdu = bytes(pending[4:length])
            packets = self.buf.packets(0, length)
            self.buf.consume(length)
            li = tpdu[0]
            if li < 2 or li + 1 > len(tpdu) or (tpdu[1] & 0xF0) != 0xF0:
                continue  # not a data TPDU (connection setup, expedited, ...)
            self.tsdu.extend(tpdu[li + 1 :])
            self.tsdu_packets.extend(p for p in packets if p not in self.tsdu_packets)
            if len(self.tsdu) > MAX_FILE_BYTES:
                self.tsdu = bytearray()
                self.tsdu_packets = []
                continue
            # The EOT/TPDU-NR octet: third in class 0 (RFC 1006), after the
            # destination reference in the other classes.
            eot = tpdu[2] if li == 2 else (tpdu[4] if len(tpdu) > 4 else 0)
            if eot & 0x80:
                yield bytes(self.tsdu), self.tsdu_packets
                self.tsdu = bytearray()
                self.tsdu_packets = []


def _tlvs(data: bytes) -> List[Tuple[int, bytes]]:
    """The BER TLVs one after another in ``data`` (stopping at a bad one)."""
    out: List[Tuple[int, bytes]] = []
    idx = 0
    while idx < len(data):
        tag, value, end = _read_ber_tlv(data, idx)
        if tag is None or end <= idx:
            break
        out.append((tag, value))
        idx = end
    return out


def _mms_pdu(tsdu: bytes) -> Optional[bytes]:
    """The MMS PDU of a session DATA TRANSFER carrying presentation
    fully-encoded data with one single-ASN1-type value, else None."""
    idx = 0
    # GIVE-TOKENS and DATA-TRANSFER SPDUs (SI 1) and their parameters.
    while idx + 2 <= len(tsdu) and tsdu[idx] == 0x01:
        length = tsdu[idx + 1]
        idx += 2
        if length == 0xFF:
            if idx + 2 > len(tsdu):
                return None
            length = int.from_bytes(tsdu[idx : idx + 2], "big")
            idx += 2
        idx += length
    if idx >= len(tsdu) or tsdu[idx] != 0x61:  # fully-encoded-data
        return None
    tag, ppdu, _end = _read_ber_tlv(tsdu, idx)
    if tag != 0x61:
        return None
    for list_tag, pdv in _tlvs(ppdu):
        if list_tag != 0x30:
            continue
        for item_tag, item in _tlvs(pdv):
            if item_tag == 0xA0:  # single-ASN1-type
                return item
    return None


def _ber_int(raw: bytes, signed: bool = True) -> Optional[int]:
    if not raw or len(raw) > 8:
        return None
    return int.from_bytes(raw, "big", signed=signed)


def _mms_filename(value: bytes) -> str:
    """FileName ::= SEQUENCE OF GraphicString."""
    parts = [
        item.decode("latin-1", errors="replace")
        for tag, item in _tlvs(value)
        if tag in (0x19, 0x1A, 0x16, 0x0C)
    ]
    return "/".join(part for part in parts if part)


def _mms_message(pdu: bytes) -> Optional[dict]:
    """A confirmed request/response for a file service, or a confirmed error
    (any service: it is matched to its request by invoke id)."""
    items = _tlvs(pdu)
    if not items:
        return None
    tag, value = items[0]
    if tag == 0xA2:  # Confirmed-ErrorPDU: invokeID [0] IMPLICIT
        fields = _tlvs(value)
        if not fields or fields[0][0] != 0x80:
            return None
        return {"pdu": "error", "invoke": _ber_int(fields[0][1], signed=False)}
    if tag not in (0xA0, 0xA1):
        return None
    fields = _tlvs(value)
    if not fields or fields[0][0] != 0x02:
        return None
    for service_tag, body in fields[1:]:
        service = MMS_SERVICE_TAGS.get(service_tag)
        if service is None:
            continue
        if service not in _MMS_FILE_SERVICES:
            return None
        return {
            "pdu": "request" if tag == 0xA0 else "response",
            "invoke": _ber_int(fields[0][1], signed=False),
            "service": service,
            "body": body,
        }
    return None


def _mms_file_size(attributes: bytes) -> Optional[int]:
    """sizeOfFile [0] of FileAttributes."""
    for tag, item in _tlvs(attributes):
        if tag == 0x80:
            return _ber_int(item, signed=False)
    return None


def _mms_request(message: dict) -> Optional[dict]:
    service = message["service"]
    body = message["body"]
    request: dict = {"service": service, "name": "", "frsm": None, "extra": ""}
    if service == "FileOpen":
        for tag, value in _tlvs(body):
            if tag == 0xA0:
                request["name"] = _mms_filename(value)
    elif service in ("FileRead", "FileClose"):
        request["frsm"] = _ber_int(body)
        if request["frsm"] is None:
            return None
    elif service == "FileDelete":
        request["name"] = _mms_filename(body)
    elif service == "FileRename":
        names = {tag: _mms_filename(value) for tag, value in _tlvs(body)}
        request["name"] = names.get(0xA0, "")
        request["extra"] = f" -> {names.get(0xA1) or '?'}"
    elif service == "FileDirectory":
        for tag, value in _tlvs(body):
            if tag == 0xA0:
                request["name"] = _mms_filename(value)
    elif service == "ObtainFile":
        names = {tag: _mms_filename(value) for tag, value in _tlvs(body)}
        request["name"] = names.get(0xA2, "")
        request["extra"] = f" from {names.get(0xA1) or '?'}"
    return request


def _mms_directory(body: bytes) -> Tuple[List[str], bool]:
    """Entry names (with sizes) and moreFollows of a FileDirectory response."""
    entries: List[str] = []
    more = False
    for tag, value in _tlvs(body):
        if tag == 0x81:
            more = bool(value and value[0])
            continue
        if tag != 0xA0:
            continue
        items = _tlvs(value)
        # [0] SEQUENCE OF DirectoryEntry, with or without its own SEQUENCE.
        if len(items) == 1 and items[0][0] == 0x30:
            inner = _tlvs(items[0][1])
            if inner and all(inner_tag == 0x30 for inner_tag, _ in inner):
                items = inner
        for entry_tag, entry in items:
            if entry_tag != 0x30:
                continue
            name, size = "", None
            for field_tag, field_value in _tlvs(entry):
                if field_tag == 0xA0:
                    name = _mms_filename(field_value)
                elif field_tag == 0xA1:
                    size = _mms_file_size(field_value)
            entries.append(f"{name} ({size} B)" if size is not None else name)
    return entries, more


@dataclass
class _MmsFile:
    name: str
    reader: Endpoint
    provider: Endpoint
    declared_size: Optional[int]
    packets: List[int]
    chunks: List[bytes] = field(default_factory=list)
    finished: bool = False
    pending_reads: int = 0
    problems: List[str] = field(default_factory=list)


def _mms_finish(item: _MmsFile) -> OtFileTransfer:
    payload: Optional[bytes] = None
    reasons = list(item.problems)
    if item.pending_reads:
        reasons.append(f"{item.pending_reads} FileRead response(s) not captured")
    if not item.chunks:
        reasons.append("no FileRead data captured")
    elif not item.finished:
        reasons.append("last FileRead (moreFollows false) not captured")
    if not reasons:
        payload = b"".join(item.chunks)
        if item.declared_size is not None and item.declared_size != len(payload):
            reasons.append(f"{len(payload)} B read but {item.declared_size} B announced")
            payload = None
        elif len(payload) > MAX_FILE_BYTES:
            reasons.append("larger than the carving limit")
            payload = None
    what = f"MMS file read {item.name or '?'}"
    if payload is not None:
        what += f"; {len(item.chunks)} FileRead(s), {len(payload)} B carved"
    else:
        size_text = f"; {item.declared_size} B announced" if item.declared_size else ""
        what = f"{NOT_CARVED} {what}; {'; '.join(dict.fromkeys(reasons))}{size_text}"
    what += f"; packets {_packets_text(item.packets)}"
    return OtFileTransfer(
        protocol="MMS",
        operation="read",
        name=_local_name(item.name) or "mms_file.bin",
        src_ip=item.provider[0],
        dst_ip=item.reader[0],
        src_port=item.provider[1],
        dst_port=item.reader[1],
        packets=sorted(set(item.packets)),
        size=len(payload) if payload is not None else item.declared_size,
        payload=payload,
        detail=what,
    )


_MMS_OPERATIONS = {
    "FileOpen": "file open",
    "FileDelete": "file delete",
    "FileRename": "file rename",
    "FileDirectory": "file directory",
    "ObtainFile": "obtain file",
}


def _mms_no_content(
    request: dict, requester: Endpoint, responder: Endpoint, packets: List[int], outcome: str
) -> OtFileTransfer:
    """A file service that moved no file content (or whose content is not
    rebuilt here), named after the file it was about."""
    operation = _MMS_OPERATIONS.get(request["service"], request["service"])
    name = request["name"]
    return OtFileTransfer(
        protocol="MMS",
        operation=operation,
        name=_local_name(name) or f"mms_{operation.replace(' ', '_')}.bin",
        src_ip=requester[0],
        dst_ip=responder[0],
        src_port=requester[1],
        dst_port=responder[1],
        packets=sorted(set(packets)),
        detail=(
            f"{NO_CONTENT} MMS {operation} {name or '?'}{request['extra']}{outcome}; "
            f"packets {_packets_text(packets)}"
        ),
    )


def _mms_transfers(tcp_streams: TcpStreams) -> List[OtFileTransfer]:
    flows: Dict[tuple, List[_Pdu]] = defaultdict(list)
    for (src, dst, sport, dport), chunks in tcp_streams.items():
        if _MMS_PORT not in (sport, dport):
            continue
        direction = _CotpDirection()
        gap = False
        for data, idx in _ordered_segments(chunks):
            if data is None:
                direction.reset()
                gap = True
                continue
            for tsdu, packets in direction.feed(data, idx):
                pdu = _mms_pdu(tsdu)
                message = _mms_message(pdu) if pdu else None
                if message is None:
                    continue
                flows[_flow_key((src, sport), (dst, dport))].append(
                    _Pdu(max(packets), (src, sport), (dst, dport), list(packets), message, gap)
                )
                gap = False
    out: List[OtFileTransfer] = []
    for pdus in flows.values():
        out.extend(_mms_flow_transfers(sorted(pdus, key=lambda pdu: pdu.packet)))
    return out


def _mms_flow_transfers(pdus: List[_Pdu]) -> List[OtFileTransfer]:
    """Replay one association's file services in packet order. Requests are
    matched to responses by (requester, invoke id): either side may request,
    as an ObtainFile makes the server read the file from the client."""
    out: List[OtFileTransfer] = []
    # (requester, invoke id) -> (request, packets, responder)
    pending: Dict[Tuple[Endpoint, Optional[int]], Tuple[dict, List[int], Endpoint]] = {}
    files: Dict[Tuple[Endpoint, int], _MmsFile] = {}
    for pdu in pdus:
        message: dict = pdu.body  # type: ignore[assignment]
        if pdu.gap_before:
            for item in files.values():
                item.problems.append("capture gap in the transfer")
        if message["pdu"] == "request":
            request = _mms_request(message)
            if request is None:
                continue
            pending[(pdu.src, message["invoke"])] = (request, list(pdu.packets), pdu.dst)
            if request["service"] == "FileRead":
                item = files.get((pdu.src, request["frsm"]))
                if item is not None:
                    item.pending_reads += 1
                    item.packets.extend(pdu.packets)
            continue
        entry = pending.pop((pdu.dst, message["invoke"]), None)
        if entry is None:
            continue
        request, packets, _responder = entry
        packets = packets + list(pdu.packets)
        requester, responder = pdu.dst, pdu.src
        service = request["service"]
        failed = message["pdu"] == "error"
        if not failed and message["service"] != service:
            continue
        if service == "FileOpen":
            if failed:
                out.append(_mms_no_content(request, requester, responder, packets, " (refused)"))
                continue
            frsm, size = None, None
            for tag, value in _tlvs(message["body"]):
                if tag == 0x80:
                    frsm = _ber_int(value)
                elif tag == 0xA1:
                    size = _mms_file_size(value)
            if frsm is None:
                continue
            previous = files.pop((requester, frsm), None)
            if previous is not None:
                out.append(_mms_finish(previous))
            files[(requester, frsm)] = _MmsFile(
                request["name"], requester, responder, size, packets
            )
        elif service == "FileRead":
            key = (requester, request["frsm"])
            item = files.get(key)
            if item is None:
                item = files[key] = _MmsFile("", requester, responder, None, [])
                item.problems.append("FileOpen not captured")
            else:
                item.pending_reads = max(0, item.pending_reads - 1)
            item.packets.extend(packets)
            if failed:
                item.problems.append("FileRead refused")
                continue
            data, more = b"", True
            for tag, value in _tlvs(message["body"]):
                if tag == 0x80:
                    data = value
                elif tag == 0x81:
                    more = bool(value and value[0])
            item.chunks.append(data)
            if not more:
                item.finished = True
        elif service == "FileClose":
            item = files.pop((requester, request["frsm"]), None)
            if item is not None:
                item.packets.extend(packets)
                out.append(_mms_finish(item))
        elif service == "FileDirectory":
            if failed:
                listing = " (refused)"
            else:
                entries, more = _mms_directory(message["body"])
                listing = ": no entries"
                if entries:
                    listing = f": {len(entries)} entries ({_names_preview(entries)})"
                if more:
                    listing += ", more follow"
            out.append(_mms_no_content(request, requester, responder, packets, listing))
        else:  # FileDelete, FileRename, ObtainFile
            outcome = " (refused)" if failed else ""
            out.append(_mms_no_content(request, requester, responder, packets, outcome))
    for item in files.values():
        out.append(_mms_finish(item))
    for (requester, _invoke), (request, packets, responder) in pending.items():
        if request["service"] in _MMS_OPERATIONS:
            # A request with no answer still names the file the peer was asked about.
            outcome = " (no response captured)"
            out.append(_mms_no_content(request, requester, responder, packets, outcome))
    return out


# --- BACnet -------------------------------------------------------------------

_BACNET_PORT = 47808
_BACNET_FILE_OBJECT = 10
_ATOMIC_READ_FILE = 6
_ATOMIC_WRITE_FILE = 7


def _bacnet_apdu(payload: bytes) -> Optional[bytes]:
    """The APDU of a BACnet/IP datagram (BVLC and NPDU stripped); None for a
    network-layer message or anything that is not BACnet/IP."""
    if len(payload) < 6 or payload[0] != 0x81:
        return None
    function = payload[1]
    if function == 0x04:  # Forwarded-NPDU: origin address first
        off = 10
    elif function in (0x09, 0x0A, 0x0B):
        off = 4
    else:
        return None
    if off + 2 > len(payload) or payload[off] != 0x01:
        return None
    control = payload[off + 1]
    idx = off + 2
    if control & 0x80:
        return None
    if control & 0x20:  # DNET, DLEN, DADR (hop count follows SADR)
        if idx + 3 > len(payload):
            return None
        idx += 3 + payload[idx + 2]
    if control & 0x08:  # SNET, SLEN, SADR
        if idx + 3 > len(payload):
            return None
        idx += 3 + payload[idx + 2]
    if control & 0x20:
        idx += 1  # hop count
    if idx >= len(payload):
        return None
    return payload[idx:]


def _bacnet_tags(data: bytes) -> List[Tuple[int, bool, str, bytes]]:
    """(tag number, context?, kind, value) of each tag; kind is "open",
    "close" or "value". An application BOOLEAN holds its value in the tag."""
    out: List[Tuple[int, bool, str, bytes]] = []
    idx = 0
    while idx < len(data):
        first = data[idx]
        idx += 1
        number = first >> 4
        context = bool(first & 0x08)
        lvt = first & 0x07
        if number == 0x0F:
            if idx >= len(data):
                break
            number = data[idx]
            idx += 1
        if context and lvt in (6, 7):
            out.append((number, True, "open" if lvt == 6 else "close", b""))
            continue
        if not context and number == 1:  # BOOLEAN
            out.append((number, False, "value", bytes([lvt])))
            continue
        length = lvt
        if lvt == 5:
            if idx >= len(data):
                break
            length = data[idx]
            idx += 1
            if length == 254:
                length = int.from_bytes(data[idx : idx + 2], "big")
                idx += 2
            elif length == 255:
                length = int.from_bytes(data[idx : idx + 4], "big")
                idx += 4
        if idx + length > len(data):
            break
        out.append((number, context, "value", data[idx : idx + length]))
        idx += length
    return out


def _bacnet_signed(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=True) if raw else 0


def _bacnet_file_request(service_data: bytes) -> Optional[dict]:
    """fileIdentifier and access method of an AtomicReadFile/AtomicWriteFile
    request: stream access [0] or record access [1], its start, then the rest
    (count for a read, data for a write)."""
    tags = _bacnet_tags(service_data)
    if len(tags) < 3 or tags[0][:3] != (12, False, "value") or len(tags[0][3]) != 4:
        return None
    oid = int.from_bytes(tags[0][3], "big")
    if (oid >> 22) != _BACNET_FILE_OBJECT:
        return None
    access = tags[1]
    if access[2] != "open" or access[0] not in (0, 1):
        return None
    values = [tag for tag in tags[2:] if tag[2] == "value" and not tag[1]]
    if not values:
        return None
    return {
        "instance": oid & 0x3FFFFF,
        "record": access[0] == 1,
        "start": _bacnet_signed(values[0][3]),
        "data": [tag[3] for tag in values[1:] if tag[0] == 6],
    }


def _bacnet_read_ack(service_data: bytes) -> Optional[dict]:
    """endOfFile, start and data of an AtomicReadFile-ACK."""
    tags = _bacnet_tags(service_data)
    if len(tags) < 3 or tags[0][:3] != (1, False, "value"):
        return None
    access = tags[1]
    if access[2] != "open" or access[0] not in (0, 1):
        return None
    values = [tag for tag in tags[2:] if tag[2] == "value" and not tag[1]]
    if not values:
        return None
    return {
        "eof": bool(tags[0][3][0]),
        "record": access[0] == 1,
        "start": _bacnet_signed(values[0][3]),
        "data": [tag[3] for tag in values[1:] if tag[0] == 6],
    }


@dataclass
class _BacnetRun:
    """Consecutive reads (or writes) of one File object between two peers."""

    instance: int
    client: Endpoint
    server: Endpoint
    writing: bool
    record: bool
    pieces: Dict[int, List[bytes]] = field(default_factory=dict)
    packets: List[int] = field(default_factory=list)
    eof: bool = False
    errors: int = 0
    requests: int = 0
    last_start: Optional[int] = None


def _bacnet_finish(run: _BacnetRun) -> OtFileTransfer:
    operation = "write" if run.writing else "read"
    reasons: List[str] = []
    ordered: List[bytes] = []
    position = 0
    for start in sorted(run.pieces):
        piece = run.pieces[start]
        span = len(piece) if run.record else sum(len(chunk) for chunk in piece)
        if start > position:
            reasons.append("data does not run contiguously from the start of the file")
            break
        if start < position:
            if start + span > position:
                reasons.append("overlapping file data")
                break
            continue  # repeated data already placed
        ordered.extend(piece)
        position += span
    if not run.pieces:
        reasons.append("no file data captured")
    elif not run.writing and not run.eof:
        reasons.append("end of file not reached")
    if run.errors:
        reasons.append(f"{run.errors} error response(s)")
    payload: Optional[bytes] = None
    if not reasons:
        payload = b"".join(ordered)
        if len(payload) > MAX_FILE_BYTES:
            payload = None
            reasons.append("larger than the carving limit")
    if run.writing:
        what = f"BACnet AtomicWriteFile (download to device) of File object {run.instance}"
    else:
        what = f"BACnet AtomicReadFile (upload from device) of File object {run.instance}"
    what += f" ({'record' if run.record else 'stream'} access, {run.requests} request(s))"
    if payload == b"":
        what += "; empty file (0 B)"
    elif payload is not None:
        what += f"; {len(payload)} B carved"
    else:
        what = f"{NOT_CARVED} {what}; {'; '.join(dict.fromkeys(reasons))}"
    what += f"; packets {_packets_text(run.packets)}"
    sender, receiver = (run.client, run.server) if run.writing else (run.server, run.client)
    first = min(run.packets) if run.packets else 0
    return OtFileTransfer(
        protocol="BACnet",
        operation=operation,
        name=f"bacnet_file_{run.instance}_{operation}_{first}.bin",
        src_ip=sender[0],
        dst_ip=receiver[0],
        src_port=sender[1],
        dst_port=receiver[1],
        packets=sorted(set(run.packets)),
        size=len(payload) if payload is not None else None,
        payload=payload,
        detail=what,
    )


def _bacnet_transfers(udp_packets: UdpPackets) -> List[OtFileTransfer]:
    """AtomicReadFile/AtomicWriteFile requests matched to their ACKs by
    invoke id (segmented APDUs joined first). A run of reads or writes of one
    File object is one transfer; it starts over when position 0 is asked
    for again."""
    out: List[OtFileTransfer] = []
    pending: Dict[Tuple[Endpoint, Endpoint, int], Tuple[int, dict]] = {}
    segments: Dict[Tuple[Endpoint, Endpoint, int, int], Dict[int, Tuple[bytes, int]]] = {}
    runs: Dict[Tuple[Endpoint, Endpoint, int, bool], _BacnetRun] = {}

    def run_for(client: Endpoint, server: Endpoint, request: dict, writing: bool) -> _BacnetRun:
        key = (client, server, request["instance"], writing)
        run = runs.get(key)
        restart = run is not None and bool(run.pieces) and request["start"] == 0
        if run is None or restart or run.record != request["record"]:
            if run is not None:
                out.append(_bacnet_finish(run))
            run = _BacnetRun(request["instance"], client, server, writing, request["record"])
            runs[key] = run
        return run

    for src, dst, sport, dport, payload, idx in udp_packets:
        if _BACNET_PORT not in (sport, dport):
            continue
        apdu = _bacnet_apdu(payload)
        if not apdu or len(apdu) < 3:
            continue
        pdu_type = apdu[0] >> 4
        sender, receiver = (src, sport), (dst, dport)
        if pdu_type in (0, 3):  # Confirmed-Request / Complex-ACK
            segmented = bool(apdu[0] & 0x08)
            more = bool(apdu[0] & 0x04)
            invoke = apdu[2] if pdu_type == 0 else apdu[1]
            head = (5 if segmented else 3) if pdu_type == 0 else (4 if segmented else 2)
            if len(apdu) <= head or apdu[head] not in (_ATOMIC_READ_FILE, _ATOMIC_WRITE_FILE):
                continue
            service = apdu[head]
            body = apdu[head + 1 :]
            packets = [idx]
            if segmented:
                seq = apdu[head - 2]
                key = (sender, receiver, invoke, pdu_type)
                parts = segments.setdefault(key, {})
                parts[seq] = (body, idx)
                if more or any(n not in parts for n in range(seq)):
                    continue
                segments.pop(key, None)
                body = b"".join(parts[n][0] for n in range(seq + 1))
                packets = [parts[n][1] for n in range(seq + 1)]
            if pdu_type == 0:
                request = _bacnet_file_request(body)
                if request is None:
                    continue
                writing = service == _ATOMIC_WRITE_FILE
                pending[(sender, receiver, invoke)] = (service, request)
                run = run_for(sender, receiver, request, writing)
                run.requests += 1
                run.packets.extend(packets)
                run.last_start = request["start"]
                if writing and request["start"] >= 0 and request["data"]:
                    run.pieces.setdefault(request["start"], request["data"])
                continue
            entry = pending.pop((receiver, sender, invoke), None)
            if entry is None or entry[0] != service:
                continue
            run = runs.get((receiver, sender, entry[1]["instance"], service == _ATOMIC_WRITE_FILE))
            if run is None:
                continue
            run.packets.extend(packets)
            if service == _ATOMIC_READ_FILE:
                ack = _bacnet_read_ack(body)
                if ack is None:
                    continue
                if ack["data"] and ack["start"] >= 0:
                    run.pieces.setdefault(ack["start"], ack["data"])
                if ack["eof"]:
                    run.eof = True
        elif pdu_type in (5, 6, 7):  # Error / Reject / Abort
            entry = pending.pop((receiver, sender, apdu[1]), None)
            if entry is None:
                continue
            run = runs.get((receiver, sender, entry[1]["instance"], entry[0] == _ATOMIC_WRITE_FILE))
            if run is not None:
                run.errors += 1
                run.packets.append(idx)
    for run in runs.values():
        out.append(_bacnet_finish(run))
    return out
