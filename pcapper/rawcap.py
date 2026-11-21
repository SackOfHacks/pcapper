"""Capture records without dissection: streaming, byte windows, sizing.

Three jobs share one record walker:

* :func:`iter_lite` streams a capture (every split part, or one byte window)
  as :class:`pcapper.lite.LitePacket` records -- about 1-3 µs per packet
  against ~150 µs for scapy's dissecting readers. Records come from the same
  places scapy's readers take them: classic and nanosecond pcap with scapy's
  65,535-byte record cap, pcapper's modified-pcap layout, and pcapng through
  scapy's own raw block reader (interfaces, process-information and
  decryption-secret blocks behave exactly as in ``PcapNgReader``).
* :func:`plan_windows` walks record headers only (no packet bytes) and cuts a
  capture into contiguous byte ranges of about equal packet counts, each
  readable on its own: what ``--jobs`` hands to its worker processes.
* :func:`estimate_packets` reads the first records to estimate the packet
  count of a capture without walking it, for the large-capture warning and
  the in-memory cache decision.
"""

from __future__ import annotations

import os
import struct
import time as _time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from .capture_parts import capture_parts
from .lite import LitePacket, refresh_bindings
from .utils import PCAP_MODIFIED_MAGIC_BYTES

try:
    from scapy.data import MTU
    from scapy.utils import PcapReader_metaclass, RawPcapNgReader
except Exception:  # pragma: no cover - scapy missing
    MTU = 65535
    PcapReader_metaclass = None  # type: ignore[assignment]
    RawPcapNgReader = None  # type: ignore[assignment]

_CLASSIC_MAGIC = {
    b"\xa1\xb2\xc3\xd4": (">", "us"),
    b"\xd4\xc3\xb2\xa1": ("<", "us"),
    b"\xa1\xb2\x3c\x4d": (">", "ns"),
    b"\x4d\x3c\xb2\xa1": ("<", "ns"),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_MODIFIED_READ_LIMIT = 262144  # pcap_cache.ModifiedPcapReader
_READ_ERRORS = (OSError, OverflowError, EOFError, zlib.error)
_PACKET_BLOCKS = (2, 3, 6)  # PB (obsolete), SPB, EPB
_STATE_BLOCKS = (1, 10, 0x80000001)  # IDB, DSB, Apple PIB: change reader state


def raw_reading_available() -> bool:
    return PcapReader_metaclass is not None and RawPcapNgReader is not None


@dataclass(frozen=True)
class Segment:
    """Records of one capture file whose header starts in ``[start, end)``.

    ``end`` None runs to the end of the file. ``replay`` lists the pcapng
    state blocks (SHB/IDB/PIB/DSB) before ``start``, replayed in file order so
    a reader that seeks into the middle of the file knows every interface.
    """

    path: str
    start: int = 0
    end: Optional[int] = None
    replay: tuple[int, ...] = ()


# First and last record times of each --split window a read went all the way
# through (the window's report needs them; no second read for them).
_WINDOW_SPANS: dict[tuple, tuple[float, float]] = {}


def _window_key(window: "CaptureWindow") -> tuple:
    return (window.index, window.count, tuple((seg.path, seg.start, seg.end) for seg in window.segments))


def window_span(window: "CaptureWindow") -> Optional[tuple[float, float]]:
    """(first, last) record time of ``window``, when a read of it went through."""
    return _WINDOW_SPANS.get(_window_key(window))


@dataclass(frozen=True)
class CaptureWindow:
    """A contiguous slice of a capture, possibly spanning split parts."""

    segments: tuple[Segment, ...]
    first_packet: int
    packets: int
    index: int = 0
    count: int = 1

    @property
    def size_bytes(self) -> int:
        total = 0
        for seg in self.segments:
            end = seg.end if seg.end is not None else _file_size(seg.path)
            total += max(0, end - seg.start)
        return total

    def key(self) -> tuple:
        return tuple((s.path, s.start, s.end) for s in self.segments)


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _open(path: str):  # type: ignore[no-untyped-def]
    """``(fdesc, magic)`` exactly as scapy's readers open a capture (gzip too);
    hashing the file on the way when the run wants its hashes."""
    from .pcap_cache import capture_file

    handle = capture_file(Path(path), single=True)
    if handle is None:
        _filename, fdesc, magic = PcapReader_metaclass.open(path)  # type: ignore[union-attr]
        return fdesc, magic
    try:
        _filename, fdesc, magic = PcapReader_metaclass.open(handle)  # type: ignore[union-attr]
    except BaseException:
        handle.close()
        raise
    return fdesc, magic


def _is_gzip(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"\x1f\x8b"
    except OSError:
        return False


class _ClassicReader:
    """Record loop of scapy's RawPcapReader/PcapReader (and pcapper's
    ModifiedPcapReader) without the dissection."""

    def __init__(self, path: str, fdesc, magic: bytes) -> None:  # type: ignore[no-untyped-def]
        self.f = fdesc
        modified = PCAP_MODIFIED_MAGIC_BYTES.get(bytes(magic))
        if modified is not None:
            self.endian, self.kind = modified, "us"
        else:
            self.endian, self.kind = _CLASSIC_MAGIC[bytes(magic)]
        header = fdesc.read(20)
        if len(header) < 20:
            raise EOFError("pcap global header too short")
        _vmaj, _vmin, _tz, _sig, self.snaplen, self.linktype = struct.unpack(
            self.endian + "HHIIII", header
        )
        if modified is not None:
            from .pcap_cache import _modified_pcap_record_size

            self.record = _modified_pcap_record_size(Path(path), self.endian, int(self.snaplen or 0))
            self.read_cap = _MODIFIED_READ_LIMIT
            self.size_cap = 0
        else:
            self.record = 16
            self.read_cap = MTU * 4
            self.size_cap = MTU
        self.interfaces = None

    def records(self, end: Optional[int]) -> Iterator[LitePacket]:
        read = self.f.read
        tell = self.f.tell
        record = self.record
        unpack = struct.Struct(self.endian + "IIII").unpack_from
        read_cap, size_cap = self.read_cap, self.size_cap
        linktype, kind = self.linktype, self.kind
        while True:
            try:
                if end is not None and tell() >= end:
                    return
                hdr = read(record)
                if len(hdr) < record:
                    return
                sec, frac, caplen, wirelen = unpack(hdr)
                data = read(caplen if caplen < read_cap else read_cap)
                remaining = caplen - len(data)
                while remaining > 0:
                    skipped = read(remaining if remaining < read_cap else read_cap)
                    if not skipped:
                        break
                    remaining -= len(skipped)
            except _READ_ERRORS:
                return
            if size_cap and len(data) > size_cap:
                data = data[:size_cap]
            yield LitePacket(data, linktype, (kind, sec, frac), wirelen)


class _PcapNgReader:
    """scapy's RawPcapNgReader, block by block, so a window can stop exactly
    at its end offset and skip none of the state blocks inside it."""

    def __init__(self, path: str, fdesc, magic: bytes) -> None:  # type: ignore[no-untyped-def]
        # Built the way PcapReader_metaclass.__call__ builds it (the class
        # itself only accepts a filename).
        reader = object.__new__(RawPcapNgReader)  # type: ignore[arg-type]
        reader.__init__(path, fdesc, magic)  # type: ignore[misc]
        self.reader = reader
        self.f = fdesc
        self.snaplen = None
        self.linktype = None

    @property
    def interfaces(self):  # type: ignore[no-untyped-def]
        return self.reader.interfaces

    def replay(self, offsets: tuple[int, ...]) -> None:
        for offset in offsets:
            self.f.seek(offset)
            try:
                self.reader._read_block(size=MTU)
            except _READ_ERRORS:
                return

    def records(self, end: Optional[int]) -> Iterator[LitePacket]:
        """scapy's ``_read_block`` loop, with the common block -- an Enhanced
        Packet Block without options -- decoded inline. Section headers,
        interface/process/secret blocks and option-carrying EPBs go to
        scapy's own handlers, so reader state and packet metadata match
        ``PcapNgReader`` exactly."""
        reader = self.reader
        f = self.f
        read, tell, seek = f.read, f.tell, f.seek
        ifnames: list = []
        iface_count = -1
        endian = reader.endian
        head_unpack = struct.Struct(endian + "II").unpack
        epb_unpack = struct.Struct(endian + "5I").unpack_from
        tail_unpack = struct.Struct(endian + "I").unpack
        while True:
            try:
                if end is not None and tell() >= end:
                    return
                head = read(8)
                if len(head) < 8:
                    return
                if head[:4] == _PCAPNG_MAGIC:
                    seek(-4, 1)  # _read_block_shb reads the length itself
                    reader._read_block_shb()
                    if reader.endian != endian:
                        endian = reader.endian
                        head_unpack = struct.Struct(endian + "II").unpack
                        epb_unpack = struct.Struct(endian + "5I").unpack_from
                        tail_unpack = struct.Struct(endian + "I").unpack
                    continue
                btype, blen = head_unpack(head)
                if blen < 12:
                    return
                body_len = blen - 12
                body = read(body_len)
                if len(body) != body_len:
                    return
                if blen % 4:
                    reader._read_block_tail(blen)
                else:
                    tail = read(4)
                    if len(tail) < 4 or tail_unpack(tail)[0] != blen:
                        return
                if btype != 6:
                    handler = reader.blocktypes.get(btype)
                    result = handler(body, MTU) if handler is not None else None
                    if result is None:
                        continue
                    yield self._from_metadata(*result)
                    continue
                if body_len < 20:
                    return
                intid, tshigh, tslow, caplen, wirelen = epb_unpack(body)
                if 20 + caplen + (-caplen % 4) < body_len:  # options present
                    result = reader._read_block_epb(body, MTU)
                    if result is not None:
                        yield self._from_metadata(*result)
                    continue
                interfaces = reader.interfaces
                if not reader._check_interface_id(intid):
                    continue
                if iface_count != len(interfaces):
                    iface_count = len(interfaces)
                    ifnames = [
                        (opts.get("name") if isinstance(opts, dict) else None)
                        for _lt, _snap, opts in interfaces
                    ]
                    ifnames = [
                        name.decode("utf-8", "backslashreplace") if name is not None else None
                        for name in ifnames
                    ]
                linktype, _snaplen, options = interfaces[intid]
            except (*_READ_ERRORS, struct.error):
                return
            data = body[20 : 20 + caplen]
            if len(data) > MTU:
                data = data[:MTU]
            yield LitePacket(
                data,
                linktype,
                ("ng", (tshigh << 32) + tslow, options["tsresol"]),
                wirelen,
                pcapng=True,
                process_information={},
                sniffed_on=ifnames[intid],
            )

    @staticmethod
    def _from_metadata(data: bytes, md) -> LitePacket:  # type: ignore[no-untyped-def]
        if md.tshigh is not None:
            tspec = ("ng", (md.tshigh << 32) + md.tslow, md.tsresol)
        else:
            tspec = ("now", _time.time())
        ifname = md.ifname
        return LitePacket(
            data,
            md.linktype,
            tspec,
            md.wirelen,
            pcapng=True,
            comments=md.comments,
            direction=md.direction,
            process_information=md.process_information.copy(),
            sniffed_on=ifname.decode("utf-8", "backslashreplace") if ifname is not None else None,
        )


def _open_reader(path: str):  # type: ignore[no-untyped-def]
    fdesc, magic = _open(path)
    try:
        if bytes(magic) == _PCAPNG_MAGIC:
            return _PcapNgReader(path, fdesc, magic)
        return _ClassicReader(path, fdesc, magic)
    except Exception:
        fdesc.close()
        raise


class LiteStream:
    """Lite records of a whole capture (all split parts) or of one window.

    ``tell()`` reports bytes consumed across segments for the status bar and
    ``size_bytes`` the total it runs to; ``linktype``/``snaplen``/
    ``interfaces`` describe the first segment, like the scapy readers.
    """

    def __init__(self, path: Path, window: Optional[CaptureWindow] = None) -> None:
        refresh_bindings()
        if window is not None:
            self.segments = window.segments
        else:
            self.segments = tuple(Segment(str(part)) for part in capture_parts(path))
        self.size_bytes = sum(
            max(0, (s.end if s.end is not None else _file_size(s.path)) - s.start)
            for s in self.segments
        )
        self._done = 0
        self._current = None
        self._current_start = 0
        self._seg_index = 0  # the segment (split part) being read
        self._window = window
        self.linktype = None
        self.snaplen = None
        self.interfaces = None
        first = self._open(self.segments[0]) if self.segments else None
        if first is not None:
            self.linktype = first.linktype
            self.snaplen = first.snaplen
            self.interfaces = first.interfaces
        self._first = first

    def _open(self, seg: Segment):  # type: ignore[no-untyped-def]
        reader = _open_reader(seg.path)
        if isinstance(reader, _PcapNgReader) and seg.replay:
            reader.replay(seg.replay)
        if seg.start:
            reader.f.seek(seg.start)
        return reader

    def __iter__(self) -> Iterator[LitePacket]:
        first = last = None
        for index, seg in enumerate(self.segments):
            reader = self._first if index == 0 else None
            self._first = None
            if reader is None:
                try:
                    reader = self._open(seg)
                except Exception:
                    continue
            self._current = reader
            self._current_start = seg.start
            self._seg_index = index
            try:
                if self._window is None:
                    yield from reader.records(seg.end)
                else:
                    # A --split window notes its time span as it goes by.
                    for record in reader.records(seg.end):
                        if first is None:
                            first = record.time
                        last = record.time
                        yield record
            finally:
                end = seg.end if seg.end is not None else _file_size(seg.path)
                self._done += max(0, end - seg.start)
                self._current = None
                try:
                    reader.f.close()
                except Exception:
                    pass
        if self._window is not None and first is not None:
            _WINDOW_SPANS[_window_key(self._window)] = (float(first), float(last))

    def tell(self) -> int:
        """Bytes of the capture file(s) read so far (compressed bytes for a
        gzip-compressed capture, to compare with ``size_bytes``)."""
        current = self._current
        if current is None:
            return self._done
        try:
            handle = current.f
            raw = getattr(handle, "fileobj", None)  # gzip: position in the file itself
            position = int(raw.tell()) if raw is not None else int(handle.tell())
            return self._done + max(0, position - self._current_start)
        except Exception:
            return self._done

    def close(self) -> None:
        for reader in (self._current, self._first):
            if reader is not None:
                try:
                    reader.f.close()
                except Exception:
                    pass
        self._current = self._first = None


def iter_lite(path: Path, window: Optional[CaptureWindow] = None) -> Iterator[LitePacket]:
    stream = LiteStream(path, window)
    try:
        yield from stream
    finally:
        stream.close()


# ---------------------------------------------------------------------------
# Record-header walks: windows and estimates
# ---------------------------------------------------------------------------

_SAMPLE_EVERY = 256


@dataclass
class _PartIndex:
    path: str
    packets: int
    samples: list[int]  # offset of every _SAMPLE_EVERY-th packet record
    replay: list[int]  # pcapng state-block offsets, in file order
    end: int


def _walk_part(path: str) -> Optional[_PartIndex]:
    """Offsets of a part's packet records, reading only record headers."""
    if _is_gzip(path):
        return None  # seeking a gzip stream re-inflates it from the start
    size = _file_size(path)
    samples: list[int] = []
    replay: list[int] = []
    packets = 0
    from .pcap_cache import capture_file

    # Through capture_file: the walk reads every byte anyway, so it hashes the
    # capture (and collects a pcapng's details) on the way.
    handle = capture_file(Path(path), single=True) or open(path, "rb")  # noqa: SIM115
    with handle:
        magic = handle.read(4)
        if magic == _PCAPNG_MAGIC:
            pos = 0
            endian = "<"
            while True:
                handle.seek(pos)
                head = handle.read(12)
                if len(head) < 12:
                    break
                if head[:4] == _PCAPNG_MAGIC:
                    bom = head[8:12]
                    if bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                    elif bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"
                    else:
                        break
                    replay.append(pos)
                    blen = struct.unpack(endian + "I", head[4:8])[0]
                else:
                    btype, blen = struct.unpack(endian + "II", head[:8])
                    if btype in _PACKET_BLOCKS:
                        if not packets % _SAMPLE_EVERY:
                            samples.append(pos)
                        packets += 1
                    elif btype in _STATE_BLOCKS:
                        replay.append(pos)
                if blen < 12:
                    break
                pos += blen + (-blen % 4)
            return _PartIndex(path, packets, samples, replay, min(pos, size))
        endian_kind = _CLASSIC_MAGIC.get(magic)
        modified = PCAP_MODIFIED_MAGIC_BYTES.get(magic)
        if endian_kind is None and modified is None:
            return None
        endian = modified if modified is not None else endian_kind[0]  # type: ignore[index]
        record = 16
        if modified is not None:
            header = handle.read(20)
            if len(header) < 20:
                return None
            from .pcap_cache import _modified_pcap_record_size

            snaplen = struct.unpack(endian + "I", header[12:16])[0]
            record = _modified_pcap_record_size(Path(path), endian, int(snaplen or 0))
        caplen_at = struct.Struct(endian + "I").unpack_from
        pos = 24
        handle.seek(pos)
        read, seek = handle.read, handle.seek
        while True:
            hdr = read(record)
            if len(hdr) < record:
                break
            if not packets % _SAMPLE_EVERY:
                samples.append(pos)
            packets += 1
            pos += record + caplen_at(hdr, 8)[0]
            seek(pos)
        return _PartIndex(path, packets, samples, replay, min(pos, size))


def plan_windows(path: Path, count: int, *, min_packets: int = 1) -> Optional[list[CaptureWindow]]:
    """Cut a capture into at most ``count`` windows of about equal packet
    counts (None when it cannot be windowed: gzip, unknown format).

    Windows break only at record boundaries and never overlap; together they
    cover every record of every split part exactly once.
    """
    parts = [str(p) for p in capture_parts(path)]
    indexes: list[_PartIndex] = []
    for part in parts:
        index = _walk_part(part)
        if index is None:
            return None
        indexes.append(index)
    total = sum(ix.packets for ix in indexes)
    if total == 0:
        return None
    count = max(1, min(int(count), max(1, total // max(1, min_packets))))
    # Global cut points (packet numbers), snapped to sampled records.
    cuts = sorted({(total * k) // count // _SAMPLE_EVERY * _SAMPLE_EVERY for k in range(1, count)})
    cuts = [c for c in cuts if 0 < c < total]

    def _position(packet: int) -> tuple[int, int]:
        base = 0
        for i, ix in enumerate(indexes):
            if packet < base + ix.packets:
                return i, ix.samples[(packet - base) // _SAMPLE_EVERY]
            base += ix.packets
        last = len(indexes) - 1
        return last, indexes[last].end

    bounds = [(0, indexes[0].samples[0] if indexes[0].samples else 0)] + [_position(c) for c in cuts]
    starts = [0] + cuts
    windows: list[CaptureWindow] = []
    for w, (part_i, offset) in enumerate(bounds):
        if w + 1 < len(bounds):
            end_part, end_offset = bounds[w + 1]
        else:
            end_part, end_offset = len(indexes) - 1, None
        segments: list[Segment] = []
        for i in range(part_i, end_part + 1):
            ix = indexes[i]
            start = offset if i == part_i else (ix.samples[0] if ix.samples else 0)
            end = end_offset if i == end_part else None
            if end is not None and end <= start:
                continue
            replay = tuple(o for o in ix.replay if o < start)
            segments.append(Segment(ix.path, start, end, replay))
        packets = (starts[w + 1] if w + 1 < len(starts) else total) - starts[w]
        if segments:
            windows.append(CaptureWindow(tuple(segments), starts[w], packets))
    n = len(windows)
    return [
        CaptureWindow(win.segments, win.first_packet, win.packets, index=i, count=n)
        for i, win in enumerate(windows)
    ]


def _sample_records(data: bytes, start: int, magic: bytes, endian: str, record: int, aligned: bool) -> tuple[int, int]:
    """``(records, bytes)`` of the complete records in ``data``. ``aligned``
    False means ``data`` starts mid-file: first find a record boundary that
    chains through several consecutive records."""
    pcapng = magic == _PCAPNG_MAGIC

    def _walk(pos: int, limit: int) -> tuple[int, int]:
        count = 0
        begin = pos
        while pos + 12 <= len(data) and count < limit:
            if pcapng:
                btype, blen = struct.unpack_from(endian + "II", data, pos)
                if blen < 12 or blen % 4 or pos + blen > len(data):
                    break
                if struct.unpack_from(endian + "I", data, pos + blen - 4)[0] != blen:
                    return -1, 0
                if btype in _PACKET_BLOCKS:
                    count += 1
                pos += blen
            else:
                if pos + record > len(data):
                    break
                _sec, usec, caplen, wirelen = struct.unpack_from(endian + "IIII", data, pos)
                if caplen > 262144 or caplen > max(wirelen, 1) or (not aligned and usec >= 1_000_000_000):
                    return -1, 0
                if pos + record + caplen > len(data):
                    break
                count += 1
                pos += record + caplen
        return count, pos - begin

    if aligned:
        return _walk(start, 1 << 30)
    for offset in range(start, min(len(data) - 64, start + 65536)):
        probe, _ = _walk(offset, 8)
        if probe >= 8:
            return _walk(offset, 1 << 30)
    return 0, 0


def _gzip_head(path: str, want: int) -> tuple[bytes, int, bool]:
    """The first ``want`` (or more) inflated bytes of a gzip file, the
    compressed bytes they took, and whether that was the whole file."""
    inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    fed = 0
    with open(path, "rb") as handle:
        while len(out) < want and not inflate.eof:
            chunk = handle.read(65536)
            if not chunk:
                break
            fed += len(chunk)
            out += inflate.decompress(chunk)
        whole = not inflate.unused_data and not handle.read(1)
    return bytes(out), fed - len(inflate.unused_data), whole


def estimate_from_head(path: Path, head: bytes) -> Optional[int]:
    """Packets extrapolated from the complete records in ``head`` (the first
    bytes of the capture, already read) to the capture's size: no read of its
    own. Exact when ``head`` is the whole file; None when the format is not
    recognised or the capture is compressed."""
    parts = [str(p) for p in capture_parts(path)]
    if not parts or len(head) < 24 or head[:2] == b"\x1f\x8b":
        return None
    total_size = sum(_file_size(p) for p in parts)
    magic = head[:4]
    record = 16
    if magic == _PCAPNG_MAGIC:
        endian = ">" if head[8:12] == b"\x1a\x2b\x3c\x4d" else "<"
        first = 0
    else:
        endian_kind = _CLASSIC_MAGIC.get(magic)
        if endian_kind is None or PCAP_MODIFIED_MAGIC_BYTES.get(magic) is not None:
            return None
        endian = endian_kind[0]
        first = 24
    records, used = _sample_records(head, first, magic, endian, record, True)
    if records == 0 or used == 0:
        return 0
    if len(parts) == 1 and len(head) >= total_size:
        return records
    return int(records * (total_size / used))


def estimate_packets(path: Path, sample_bytes: int = 1024 * 1024, points: int = 5) -> Optional[int]:
    """Packet count estimated from the record sizes at ``points`` places
    through the capture (its start, then evenly spaced, each resynchronised
    on a record boundary). Exact for captures smaller than one sample; None
    when the format is not recognised. A gzip-compressed capture is sampled
    at its start only, scaled by the compression ratio there."""
    parts = [str(p) for p in capture_parts(path)]
    sizes = [_file_size(p) for p in parts]
    total_size = sum(sizes)
    if not parts:
        return None
    gzipped = _is_gzip(parts[0])
    try:
        if gzipped:
            # Inflating to sample further in would read the whole file: the
            # head alone, its size through the file scaled by its compression.
            head, fed, whole = _gzip_head(parts[0], max(sample_bytes, 4096))
        else:
            with open(parts[0], "rb") as handle:
                head = handle.read(max(sample_bytes, 4096))
    except (OSError, zlib.error):
        return None
    if len(head) < 24:
        return 0 if len(head) else None
    magic = head[:4]
    record = 16
    if magic == _PCAPNG_MAGIC:
        bom = head[8:12]
        endian = ">" if bom == b"\x1a\x2b\x3c\x4d" else "<"
        first = 0
    else:
        endian_kind = _CLASSIC_MAGIC.get(magic)
        modified = PCAP_MODIFIED_MAGIC_BYTES.get(magic)
        if endian_kind is None and modified is None:
            return None
        endian = modified if modified is not None else endian_kind[0]  # type: ignore[index]
        if modified is not None:
            from .pcap_cache import _modified_pcap_record_size

            snaplen = struct.unpack_from(endian + "I", head, 16)[0]
            record = _modified_pcap_record_size(Path(parts[0]), endian, int(snaplen or 0))
        first = 24
    records, used = _sample_records(head, first, magic, endian, record, True)
    if records == 0 or used == 0:
        return 0
    if gzipped:
        if whole and len(parts) == 1:
            return records
        inflated_size = total_size * (len(head) / max(1, fed))
        return int(records * (inflated_size / used))
    if len(head) < sample_bytes and len(parts) == 1:
        return records  # the whole file was read
    # Further samples through the first part (the parts of a split capture
    # come from one capture and look alike).
    part_size = sizes[0]
    try:
        with open(parts[0], "rb") as handle:
            for k in range(1, points):
                offset = (part_size * k) // points
                if offset + 4096 > part_size:
                    break
                handle.seek(offset)
                chunk = handle.read(sample_bytes)
                got, span = _sample_records(chunk, 0, magic, endian, record, False)
                if got > 0 and span > 0:
                    records += got
                    used += span
    except OSError:
        pass
    return int(records * (total_size / used))

