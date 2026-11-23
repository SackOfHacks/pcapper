from __future__ import annotations

import collections
import gzip
import hashlib
import io
import ipaddress
import os
import threading
import time
import weakref
import re
import struct
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

try:
    from scapy.utils import PcapNgReader, PcapReader  # type: ignore
except Exception:  # pragma: no cover
    PcapReader = None  # type: ignore
    PcapNgReader = None  # type: ignore
try:
    from scapy.all import sniff  # type: ignore
except Exception:  # pragma: no cover
    sniff = None  # type: ignore
try:
    from scapy.layers.inet import IP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    IPv6 = None  # type: ignore

from .capture_parts import capture_parts, capture_size, part_group
from .progress import build_busy_statusbar, build_statusbar
from .rawcap import LiteStream, raw_reading_available
from .utils import (
    PCAP_MAGIC,
    PCAP_MODIFIED_MAGIC_BYTES,
    capture_head,
    capture_prefix,
    detect_file_type,
    is_gzip_file,
    open_capture_file,
)

# Set by pcapper.sharedpass while a shared analysis pass runs: called as
# hook(path, packets, lite, prefilter, stats) and returns an iterator of the
# shared packets for a consumer thread, or None to read normally.
_SHARED_PASS_HOOK = None

_PACKET_CACHE: "OrderedDict[Path, tuple[list[object], 'PcapMeta']]" = OrderedDict()
_CACHE_BYTES = 0
_FORCED_PACKET_VIEWS: dict[Path, tuple[list[object], "PcapMeta | None"]] = {}
_HOST_ONLY_BPF_RE = re.compile(r"^\s*\(?\s*host\s+([0-9A-Fa-f:.]+)\s*\)?\s*$")

__all__ = ["PCAP_MAGIC"]  # re-exported for callers that imported it from here


def _path_key(path: Path) -> Path:
    path_obj = Path(path).expanduser()
    try:
        return path_obj.resolve()
    except Exception:
        return path_obj.absolute()


@dataclass(frozen=True)
class PcapMeta:
    path: Path
    file_type: str
    size_bytes: int
    linktype: object | None
    snaplen: object | None
    interfaces: object | None
    capture_hardware: str | None = None
    capture_os: str | None = None
    capture_application: str | None = None
    modified_ns: int | None = None


def _cached_packets(path: Path) -> tuple[list[object], PcapMeta] | None:
    global _CACHE_BYTES
    key = _path_key(path)
    cached = _PACKET_CACHE.get(key)
    if cached is None:
        return None
    try:
        stat = key.stat()
        valid = (
            cached[1].size_bytes == capture_size(key)
            and cached[1].modified_ns == stat.st_mtime_ns
        )
    except OSError:
        valid = False
    if not valid:
        _PACKET_CACHE.pop(key, None)
        _CACHE_BYTES = max(0, _CACHE_BYTES - max(0, cached[1].size_bytes))
        return None
    _PACKET_CACHE.move_to_end(key)
    return cached


def _read_pcap_header(path: Path) -> tuple[object | None, object | None]:
    try:
        from .utils import capture_head

        header = capture_head(path)[:24]
        if len(header) < 24:
            return None, None
        magic_bytes = header[:4]
        endian_by_magic = {
            b"\xa1\xb2\xc3\xd4": ">",
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            **PCAP_MODIFIED_MAGIC_BYTES,
        }
        endian = endian_by_magic.get(magic_bytes)
        if endian is None:
            return None, None
        snaplen = struct.unpack(f"{endian}I", header[16:20])[0]
        linktype = struct.unpack(f"{endian}I", header[20:24])[0]
        return linktype, snaplen
    except Exception:
        return None, None


def _decode_pcapng_text(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("utf-8", errors="ignore").strip()


# Interface (IDB, with ISB drop counts) and section (SHB) metadata of a pcapng,
# per file version (path, size, mtime): from the run's read of the capture when
# one went by (_CaptureRaw collects it on the way), else from a walk of its own.
_PCAPNG_META: dict[tuple, tuple[list[dict[str, object]], dict[str, str]]] = {}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _pcapng_metadata_steps():  # type: ignore[no-untyped-def]
    """The pcapng block walk, as a generator, so one parser serves a read of
    its own (:func:`_scan_pcapng_metadata`) and the bytes of the run's read
    (:class:`_PcapngMetaTap`). It yields ``("read", n)`` and is sent the
    bytes (fewer at the end of the file), or ``("skip", n)`` (a seek ahead,
    sent None), and returns ``(interfaces, section_info)``."""
    interfaces: list[dict[str, object]] = []
    if_stats: dict[int, dict[str, object]] = {}
    section_info: dict[str, str] = {}
    try:
        endian = "<"
        while True:
            header = yield ("read", 8)
            if len(header) < 8:
                break
            block_type = struct.unpack("<I", header[:4])[0]
            if block_type == 0x0A0D0D0A:
                block_len = struct.unpack("<I", header[4:8])[0]
                if block_len < 12:
                    block_len = struct.unpack(">I", header[4:8])[0]
            else:
                block_len = struct.unpack(f"{endian}I", header[4:8])[0]

            if block_len < 12 or block_len > 64 * 1024 * 1024:
                break

            if block_type == 0x0A0D0D0A:
                body_len = block_len - 12
                body = yield ("read", body_len)
                if len(body) < body_len or len(body) < 4:
                    break
                bom = struct.unpack("<I", body[:4])[0]
                if bom == 0x1A2B3C4D:
                    endian = "<"
                elif bom == 0x4D3C2B1A:
                    endian = ">"
                if len(body) >= 16:
                    opt_offset = 16
                    while opt_offset + 4 <= len(body):
                        code, length = struct.unpack(
                            f"{endian}HH", body[opt_offset : opt_offset + 4]
                        )
                        opt_offset += 4
                        if code == 0:
                            break
                        value = body[opt_offset : opt_offset + length]
                        opt_offset += (length + 3) & ~3
                        text = _decode_pcapng_text(value)
                        if not text:
                            continue
                        if code == 2 and "hardware" not in section_info:
                            section_info["hardware"] = text
                        elif code == 3 and "os" not in section_info:
                            section_info["os"] = text
                        elif code == 4 and "application" not in section_info:
                            section_info["application"] = text
                yield ("skip", 4)
                continue

            if block_type == 0x00000001:
                body_len = block_len - 12
                body = yield ("read", body_len)
                if len(body) < body_len:
                    break
                if len(body) >= 8:
                    linktype, _reserved, snaplen = struct.unpack(
                        f"{endian}HHI", body[:8]
                    )
                    iface: dict[str, object] = {
                        "linktype": linktype,
                        "snaplen": snaplen,
                    }
                    opt_offset = 8
                    while opt_offset + 4 <= len(body):
                        code, length = struct.unpack(
                            f"{endian}HH", body[opt_offset : opt_offset + 4]
                        )
                        opt_offset += 4
                        if code == 0:
                            break
                        value = body[opt_offset : opt_offset + length]
                        opt_offset += (length + 3) & ~3

                        if code == 2:  # if_name
                            iface["if_name"] = _decode_pcapng_text(value)
                        elif code == 3:  # if_description
                            iface["if_description"] = _decode_pcapng_text(value)
                        elif code == 6:  # if_MACaddr
                            iface["if_macaddr"] = ":".join(
                                f"{b:02x}" for b in value[:6]
                            )
                        elif code == 8 and len(value) >= 8:  # if_speed
                            iface["if_speed"] = struct.unpack(
                                f"{endian}Q", value[:8]
                            )[0]
                        elif code == 11 and len(value) >= 1:  # if_filter
                            filter_val = value[1:]
                            iface["if_filter"] = _decode_pcapng_text(filter_val)
                        elif code == 12:  # if_os
                            iface["if_os"] = _decode_pcapng_text(value)

                    iface["id"] = len(interfaces)
                    interfaces.append(iface)

                yield ("skip", 4)
                continue

            if block_type == 0x00000005:
                body_len = block_len - 12
                body = yield ("read", body_len)
                if len(body) < body_len:
                    break
                if len(body) >= 12:
                    iface_id = struct.unpack(f"{endian}I", body[:4])[0]
                    opt_offset = 12
                    stats = if_stats.setdefault(iface_id, {})
                    while opt_offset + 4 <= len(body):
                        code, length = struct.unpack(
                            f"{endian}HH", body[opt_offset : opt_offset + 4]
                        )
                        opt_offset += 4
                        if code == 0:
                            break
                        value = body[opt_offset : opt_offset + length]
                        opt_offset += (length + 3) & ~3
                        if code == 5 and len(value) >= 8:  # isb_ifdrop
                            stats["dropcount"] = struct.unpack(
                                f"{endian}Q", value[:8]
                            )[0]
                yield ("skip", 4)
                continue

            yield ("skip", block_len - 8)
    except Exception:
        return interfaces, section_info

    for iface_id, stats in if_stats.items():
        if 0 <= iface_id < len(interfaces):
            interfaces[iface_id].update(stats)

    return interfaces, section_info




def _scan_pcapng_metadata(path: Path) -> tuple[list[dict[str, object]], dict[str, str]]:
    """:func:`_pcapng_metadata_steps` over a read of the file of its own."""
    steps = _pcapng_metadata_steps()
    request = next(steps)
    try:
        handle_cm = open_capture_file(path)
    except Exception:
        return [], {}
    try:
        with handle_cm as handle:
            while True:
                kind, size = request
                if kind == "read":
                    request = steps.send(handle.read(size))
                else:
                    handle.seek(size, 1)
                    request = steps.send(None)
    except StopIteration as stop:
        return stop.value
    except Exception as exc:  # noqa: BLE001 - an I/O error: what the walk had
        try:
            steps.throw(exc)
        except StopIteration as stop:
            return stop.value
        except Exception:  # noqa: BLE001
            pass
        return [], {}


class _PcapngMetaTap:
    """:func:`_pcapng_metadata_steps` fed the bytes of a read of the whole
    capture as they go by (:class:`_CaptureRaw`): a pcapng's metadata then
    needs no read of the file of its own."""

    def __init__(self) -> None:
        self._steps = _pcapng_metadata_steps()
        self._skip = 0
        self._need = 0
        self._buf = bytearray()
        self.result: Optional[tuple[list[dict[str, object]], dict[str, str]]] = None
        self._next(next(self._steps))

    def _next(self, request) -> None:  # type: ignore[no-untyped-def]
        while True:
            kind, size = request
            if kind == "read":
                self._need = size
                return
            self._skip += size
            request = self._steps.send(None)

    def _send(self, data: bytes) -> None:
        try:
            self._next(self._steps.send(data))  # type: ignore[union-attr]
        except StopIteration as stop:
            self.result = stop.value
            self._steps = None  # type: ignore[assignment]

    def feed(self, data) -> None:  # type: ignore[no-untyped-def]
        view = memoryview(data)
        pos = 0
        end = len(view)
        while pos < end and self._steps is not None:
            if self._skip:
                step = min(self._skip, end - pos)
                self._skip -= step
                pos += step
                continue
            step = min(self._need - len(self._buf), end - pos)
            self._buf += view[pos : pos + step]
            pos += step
            if len(self._buf) >= self._need:
                chunk = bytes(self._buf)
                self._buf.clear()
                self._send(chunk)

    def finish(self) -> tuple[list[dict[str, object]], dict[str, str]]:
        """The end of the file: what reads there return (short, then empty)."""
        while self._steps is not None:
            self._skip = 0  # a seek past the end
            chunk = bytes(self._buf)
            self._buf.clear()
            self._send(chunk)
        return self.result if self.result is not None else ([], {})


def _pcapng_meta_key(path: Path) -> Optional[tuple]:
    try:
        key_path = _path_key(path)
        st = os.stat(key_path)
    except (OSError, ValueError):
        return None
    return (str(key_path), st.st_size, st.st_mtime_ns)


def _read_pcapng_metadata(
    path: Path,
) -> tuple[list[dict[str, object]], dict[str, str]]:
    """A pcapng's interface and section metadata (copies: callers may change
    them). Taken from the run's read when one went by, else walked for once
    per file version; a dry run (planning) reads nothing."""
    from .utils import planning

    key = _pcapng_meta_key(path)
    cached = _PCAPNG_META.get(key) if key is not None else None
    if cached is None:
        if planning():
            return [], {}
        cached = _scan_pcapng_metadata(path)
        if key is not None:
            _PCAPNG_META[key] = cached
    interfaces, section_info = cached
    return [dict(item) for item in interfaces], dict(section_info)


def _read_pcapng_interfaces(path: Path) -> list[dict[str, object]]:
    interfaces, _section_info = _read_pcapng_metadata(path)
    return interfaces


def _finalize_meta(
    path: Path,
    file_type: str,
    size_bytes: int,
    linktype: object | None,
    snaplen: object | None,
    interfaces: object | None,
) -> PcapMeta:
    if file_type == "pcap":
        header_linktype, header_snaplen = _read_pcap_header(path)
        if header_linktype is not None:
            linktype = header_linktype
        if header_snaplen is not None:
            snaplen = header_snaplen

    if file_type == "pcapng":
        parsed_interfaces, section_info = _read_pcapng_metadata(path)
        if not interfaces:
            interfaces = parsed_interfaces
        elif isinstance(interfaces, list) and parsed_interfaces:
            if not any(_iface_has_name(item) for item in interfaces):
                interfaces = parsed_interfaces
            else:
                for idx, parsed in enumerate(parsed_interfaces):
                    if idx < len(interfaces):
                        current = interfaces[idx]
                        if isinstance(current, dict):
                            for key, value in parsed.items():
                                if current.get(key) is None and value is not None:
                                    current[key] = value
                    else:
                        interfaces.append(parsed)

        if linktype is None and parsed_interfaces:
            linktype = parsed_interfaces[0].get("linktype")
        if snaplen is None and parsed_interfaces:
            snaplen = parsed_interfaces[0].get("snaplen")
    else:
        section_info = {}

    try:
        modified_ns = path.stat().st_mtime_ns
    except OSError:
        modified_ns = None
    return PcapMeta(
        path=path,
        file_type=file_type,
        size_bytes=size_bytes,
        linktype=linktype,
        snaplen=snaplen,
        interfaces=interfaces,
        capture_hardware=section_info.get("hardware"),
        capture_os=section_info.get("os"),
        capture_application=section_info.get("application"),
        modified_ns=modified_ns,
    )


def _iface_has_name(value: object) -> bool:
    if isinstance(value, dict):
        for key in ("if_name", "if_description", "name", "description"):
            if value.get(key):
                return True
        return False
    for attr in ("if_name", "if_description", "name", "description"):
        if getattr(value, attr, None):
            return True
    return False


class PacketListReader:
    def __init__(self, packets: list[object], meta: Optional[PcapMeta] = None) -> None:
        self._packets = packets
        self.linktype = meta.linktype if meta else None
        self.snaplen = meta.snaplen if meta else None
        self.interfaces = meta.interfaces if meta else None
        self.capture_hardware = meta.capture_hardware if meta else None
        self.capture_os = meta.capture_os if meta else None
        self.capture_application = meta.capture_application if meta else None
        self._pos = 0

    def __iter__(self):
        self._pos = 0
        for pkt in self._packets:
            self._pos += 1
            yield pkt

    def __len__(self) -> int:
        return len(self._packets)

    def tell(self) -> int:
        return self._pos

    def close(self) -> None:
        return None


def _reader_stream(reader: object) -> Optional[object]:
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            return candidate
    return None


def _extract_host_only_bpf_ip(bpf: str | None) -> str | None:
    if not bpf:
        return None
    match = _HOST_ONLY_BPF_RE.match(str(bpf).strip())
    if not match:
        return None
    candidate = match.group(1).strip()
    try:
        ipaddress.ip_address(candidate)
    except Exception:
        return None
    return candidate


def _packet_matches_host(pkt: object, host_addr: object) -> bool:
    getlayer = getattr(pkt, "getlayer", None)
    if not callable(getlayer):
        return False
    for layer_cls in (IP, IPv6):
        if layer_cls is None:
            continue
        try:
            layer = getlayer(layer_cls)
            if layer is None:
                continue
            src = ipaddress.ip_address(str(layer.src))
            dst = ipaddress.ip_address(str(layer.dst))
            if src == host_addr or dst == host_addr:
                return True
        except Exception:
            continue
    return False


def _cache_config() -> tuple[bool, int, int]:
    enabled = os.environ.get("PCAPPER_CACHE_ENABLED", "1") != "0"
    try:
        max_cache = int(
            os.environ.get("PCAPPER_CACHE_MAX_BYTES", str(256 * 1024 * 1024))
        )
    except Exception:
        max_cache = 256 * 1024 * 1024
    try:
        max_file = int(
            os.environ.get("PCAPPER_CACHE_FILE_MAX_BYTES", str(64 * 1024 * 1024))
        )
    except Exception:
        max_file = 64 * 1024 * 1024
    if max_cache < 0:
        max_cache = 0
    if max_file < 0:
        max_file = 0
    return enabled, max_cache, max_file


def get_cache_config() -> tuple[bool, int, int]:
    return _cache_config()


# Memory a dissected scapy packet takes (measured: ~5.9 KB per packet on mixed
# OT/IT traffic, scapy 2.8). File size is a poor proxy: a 256 MB capture of
# 60-byte frames is ~3.5M packets, ~20 GB once dissected.
PACKET_MEMORY_BYTES = 6000
_ESTIMATES: dict[tuple, int | None] = {}


def _available_memory() -> int | None:
    try:
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES")) // 2
    except (AttributeError, OSError, ValueError):
        return None


def max_cache_packets() -> int:
    """Most packets one capture may keep in memory: ``PCAPPER_CACHE_MAX_PACKETS``,
    else a quarter of available memory at :data:`PACKET_MEMORY_BYTES` each
    (100k to 4M packets; 1M when memory cannot be read)."""
    configured = os.environ.get("PCAPPER_CACHE_MAX_PACKETS")
    if configured:
        try:
            return max(0, int(configured))
        except ValueError:
            pass
    available = _available_memory()
    if not available:
        return 1_000_000
    return max(100_000, min(4_000_000, int(available * 0.25 / PACKET_MEMORY_BYTES)))


def estimated_packets(path: Path) -> int | None:
    """Packet count of a capture (or of the active window), estimated from
    its first records; cached per file version."""
    window = get_capture_window(path)
    if window is not None:
        return int(getattr(window, "packets", 0)) or None
    try:
        key_path = _path_key(path)
        key = (str(key_path), capture_size(path), key_path.stat().st_mtime_ns)
    except OSError:
        return None
    if key not in _ESTIMATES:
        try:
            from .rawcap import estimate_packets

            _ESTIMATES[key] = estimate_packets(path)
        except Exception:
            _ESTIMATES[key] = None
    return _ESTIMATES[key]


def packets_at_most(path: Path) -> int | None:
    """An upper bound on the capture's packets read off its size alone (every
    record takes at least a 16-byte header), or None when the size says
    nothing (a gzip-compressed capture). Decisions whose threshold lies above
    it need no sampled estimate."""
    window = get_capture_window(path)
    if window is not None:
        return int(getattr(window, "packets", 0)) or None
    try:
        parts = capture_parts(path)
        if any(capture_head(part)[:2] == b"\x1f\x8b" for part in parts):
            return None
        return max(0, capture_size(path) - 24 * len(parts)) // 16
    except OSError:
        return None


def quick_packet_estimate(path: Path, *, prime: bool = False) -> int | None:
    """Packets of a capture from what the run reads anyway: the sampled
    estimate when one was made, else the head of the capture kept for the
    next whole read (exact when it holds the whole capture, else extrapolated
    from its records) -- with ``prime``, read now when no head is kept yet,
    since the read that follows replays it. For a heuristic (how many --jobs
    processes pay), not the memory budget."""
    window = get_capture_window(path)
    if window is not None:
        return int(getattr(window, "packets", 0)) or None
    try:
        key_path = _path_key(path)
        cached = _ESTIMATES.get((str(key_path), capture_size(path), key_path.stat().st_mtime_ns), _MISSING_ESTIMATE)
    except OSError:
        return None
    if cached is not _MISSING_ESTIMATE:
        return cached  # type: ignore[return-value]
    stream = _PRIMED.get(key_path) if _PRIMED else None
    if stream is None and prime:
        head = read_head(path, _QUICK_HEAD_PACKETS)
        if head is not None:
            for _record in head:
                pass
            head.close()  # type: ignore[attr-defined]
            stream = _PRIMED.get(key_path) if _PRIMED else None
    if stream is None:
        return None
    if stream.complete:
        return stream.count
    try:
        position = int(stream._stream._current.f.tell())
    except Exception:  # noqa: BLE001
        position = 0
    if position <= 0 or not stream.count:
        return None
    return int(stream.count * capture_size(path) / position)


_MISSING_ESTIMATE = object()
_QUICK_HEAD_PACKETS = 50_000  # the decode-as check's head: the same records


def fits_in_memory(path: Path) -> bool:
    """False when the capture's estimated packets exceed max_cache_packets()."""
    bound = packets_at_most(path)
    if bound is not None and bound <= max_cache_packets():
        return True
    estimate = estimated_packets(path)
    return estimate is None or estimate <= max_cache_packets()


def is_scapy_available() -> bool:
    return PcapReader is not None and PcapNgReader is not None


def _modified_pcap_record_size(path: Path, endian: str, snaplen: int) -> int:
    """24 or 28: the record-header size under which a modified-pcap file's
    first records are self-consistent (caplen within snaplen and wirelen,
    microseconds below one second, each record ending where the next begins).
    """
    try:
        with open_capture_file(path) as handle:
            data = handle.read(1 << 16)
    except OSError:
        return 24
    cap_limit = snaplen if 0 < snaplen <= 262144 else 262144

    def _walks(size: int) -> int:
        offset = 24
        records = 0
        while offset + size <= len(data) and records < 32:
            _sec, usec, caplen, wirelen = struct.unpack(
                endian + "IIII", data[offset : offset + 16]
            )
            if usec >= 1_000_000 or caplen > cap_limit or caplen > max(wirelen, 1):
                return -1
            offset += size + caplen
            records += 1
        # A clean walk ends exactly at the end of what was read, or runs past
        # it only because the buffer was cut short.
        if offset == len(data) or len(data) == (1 << 16):
            return records
        return -1

    best_size, best_records = 24, -1
    for size in (24, 28):
        records = _walks(size)
        if records > best_records:
            best_size, best_records = size, records
    return best_size


if PcapReader is not None:

    class ModifiedPcapReader(PcapReader):  # type: ignore[misc, valid-type]
        """Reader for the Kuznetzov "modified pcap" format (magic a1b2cd34).

        Same global header as classic pcap, but every record header is 24
        bytes: the classic ts_sec/ts_usec/caplen/len followed by ifindex (4),
        protocol (2), packet type (1) and one pad byte. scapy rejects the
        magic outright, so the format used to be unreadable; tshark and
        libpcap both read it.
        """

        _RECORD_HEADER = 24

        def __init__(self, filename, fdesc=None, magic=None):  # type: ignore[no-untyped-def]
            endian = PCAP_MODIFIED_MAGIC_BYTES.get(bytes(magic or b""))
            if endian is None:
                from scapy.error import Scapy_Exception  # type: ignore

                raise Scapy_Exception("Not a modified-pcap capture file")
            # Hand scapy the classic magic of the same byte order: everything
            # it parses from the global header is identical.
            classic = b"\xa1\xb2\xc3\xd4" if endian == ">" else b"\xd4\xc3\xb2\xa1"
            super().__init__(filename, fdesc, classic)
            # The same magic is shared by two record layouts: 24-byte headers
            # (Kuznetzov ss991029, the common one) and 28-byte headers (SuSE
            # 6.3's ss990915, two extra CPU bytes + padding). Pick the layout
            # under which the first records walk cleanly, as Wireshark does.
            self._RECORD_HEADER = _modified_pcap_record_size(
                Path(str(filename)), self.endian, int(self.snaplen or 0)
            )

        def read_packet(self, size=None, **kwargs):  # type: ignore[no-untyped-def, override]
            from decimal import Decimal

            from scapy.config import conf  # type: ignore
            from scapy.utils import EDecimal  # type: ignore

            try:
                hdr = self.f.read(self._RECORD_HEADER)
            except (OSError, OverflowError) as exc:
                raise EOFError from exc
            if len(hdr) < self._RECORD_HEADER:
                raise EOFError
            sec, usec, caplen, wirelen = struct.unpack(self.endian + "IIII", hdr[:16])
            # Bound the read like scapy does: a corrupt caplen must not make
            # one record swallow gigabytes.
            limit = 262144
            data = self.f.read(min(caplen, limit))
            remaining = caplen - len(data)
            while remaining > 0:
                skipped = self.f.read(min(remaining, limit))
                if not skipped:
                    break
                remaining -= len(skipped)
            if size:
                data = data[:size]
            try:
                pkt = self.LLcls(data, **kwargs)
            except Exception:
                pkt = conf.raw_layer(data)
            pkt.time = EDecimal(sec + Decimal(10) ** Decimal(-6) * usec)
            pkt.wirelen = wirelen
            return pkt

else:  # pragma: no cover - scapy missing
    ModifiedPcapReader = None  # type: ignore[assignment, misc]


class _ChainedStream:
    """``tell()`` across the parts of a joined capture, for the progress bar."""

    def __init__(self, owner: "ChainedCaptureReader") -> None:
        self._owner = owner

    def tell(self) -> int:
        return self._owner.tell()


class ChainedCaptureReader:
    """Stream the parts of a split capture back to back as one capture.

    Each part is a complete capture (its own global header), opened only when
    the previous one is exhausted, so memory use is that of a single reader.
    Link type and snap length are taken from the first part; a part whose link
    type differs is still read (every packet carries its own dissection).
    """

    def __init__(self, parts: tuple[Path, ...]) -> None:
        self._parts = parts
        first = _open_single_capture(parts[0])
        self._current = first
        self._index = 0
        self._done_bytes = 0
        self.linktype = getattr(first, "linktype", None)
        self.snaplen = getattr(first, "snaplen", None)
        self.interfaces = getattr(first, "interfaces", None)
        self.f = _ChainedStream(self)

    def __iter__(self) -> Iterator[object]:
        while self._current is not None:
            try:
                for pkt in self._current:
                    yield pkt
            finally:
                self._close_current()
            self._index += 1
            if self._index >= len(self._parts):
                break
            self._current = _open_single_capture(self._parts[self._index])

    def _close_current(self) -> None:
        current = self._current
        if current is None:
            return
        try:
            self._done_bytes += self._parts[self._index].stat().st_size
        except OSError:
            pass
        try:
            current.close()  # type: ignore[attr-defined]
        except Exception:
            pass
        self._current = None

    def tell(self) -> int:
        current = self._current
        stream = _reader_stream(current) if current is not None else None
        try:
            offset = int(stream.tell()) if stream is not None else 0  # type: ignore[attr-defined]
        except Exception:
            offset = 0
        return self._done_bytes + offset

    def close(self) -> None:
        self._close_current()


def open_capture_reader(path: Path, file_type: str | None = None) -> object:
    """A scapy packet reader for ``path``, chosen by the file's magic number.

    The single place a capture is opened for reading, so every reader path
    (streaming, cached, BPF-filtered fallback) supports the same formats:
    pcapng, classic pcap (micro- and nanosecond, either byte order), the
    modified-pcap variant, and split captures joined with
    :func:`pcapper.capture_parts.group_split_captures`.
    """
    _require_scapy()
    window = get_capture_window(path)
    if window is not None:
        return WindowReader(path, window)
    parts = capture_parts(path)
    if len(parts) > 1:
        return ChainedCaptureReader(parts)
    return _open_single_capture(path, file_type)


def _open_single_capture(path: Path, file_type: str | None = None) -> object:
    """Reader for exactly one file, ignoring any split-capture group it heads."""
    kind = file_type or detect_file_type(path)
    if kind == "pcapng":
        reader_class = PcapNgReader
    else:
        try:
            magic = capture_head(path)[:4]  # cached: no read of its own
        except OSError:
            magic = b""
        if magic in PCAP_MODIFIED_MAGIC_BYTES and ModifiedPcapReader is not None:
            reader_class = ModifiedPcapReader
        else:
            reader_class = PcapReader
    # The run's hashes come from this read when it wants them.
    handle = capture_file(path, single=True)
    if handle is None:
        return reader_class(str(path))
    try:
        return reader_class(handle)
    except BaseException:
        handle.close()
        raise


def _require_scapy() -> None:
    if not is_scapy_available():
        raise RuntimeError(
            "Scapy is required for packet parsing (install scapy>=2.5.0)."
        )


def load_capture_meta(path: Path) -> PcapMeta:
    file_type = detect_file_type(path)
    try:
        size_bytes = capture_size(path)
    except Exception:
        size_bytes = 0
    return _finalize_meta(
        path=path,
        file_type=file_type,
        size_bytes=size_bytes,
        linktype=None,
        snaplen=None,
        interfaces=None,
    )


def load_packets(path: Path, show_status: bool = True) -> tuple[list[object], PcapMeta]:
    _require_scapy()
    file_type = detect_file_type(path)
    size_bytes = 0
    try:
        size_bytes = capture_size(path)
    except Exception:
        size_bytes = 0

    reader = open_capture_reader(path, file_type)
    status = build_statusbar(path, enabled=show_status)
    stream = _reader_stream(reader)

    packets: list[object] = []
    track_progress = status.enabled and stream is not None and bool(size_bytes)
    append = packets.append
    count = 0
    try:
        for pkt in reader:
            append(pkt)
            count += 1
            # Throttle progress updates; stream.tell() per packet is wasted
            # work on large captures.
            if track_progress and not (count & 0x1FF):
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass
    finally:
        status.finish()
        reader.close()

    linktype = getattr(reader, "linktype", None)
    snaplen = getattr(reader, "snaplen", None)
    interfaces = getattr(reader, "interfaces", None)

    meta = _finalize_meta(
        path=path,
        file_type=file_type,
        size_bytes=size_bytes,
        linktype=linktype,
        snaplen=snaplen,
        interfaces=interfaces,
    )
    return packets, meta


def get_cached_packets(
    path: Path, show_status: bool = True
) -> tuple[list[object], PcapMeta]:
    global _CACHE_BYTES
    key = _path_key(path)
    cached = _cached_packets(path)
    if cached is not None:
        return cached
    packets, meta = load_packets(path, show_status=show_status)
    size_bytes = max(0, int(getattr(meta, "size_bytes", 0) or 0))
    enabled, max_cache, _max_file = _cache_config()
    if not enabled or max_cache == 0:
        return packets, meta
    if size_bytes > max_cache:
        return packets, meta
    while _PACKET_CACHE and _CACHE_BYTES + size_bytes > max_cache:
        _, evicted = _PACKET_CACHE.popitem(last=False)
        evicted_meta = evicted[1]
        evicted_size = max(0, int(getattr(evicted_meta, "size_bytes", 0) or 0))
        _CACHE_BYTES = max(0, _CACHE_BYTES - evicted_size)
    _PACKET_CACHE[key] = (packets, meta)
    _CACHE_BYTES += size_bytes
    return packets, meta


def memory_admissible(path: Path, *, max_file_override: int | None = None) -> bool:
    """Whether :func:`load_packets_if_allowed` keeps ``path`` in memory: the
    cache is on, the file is within the per-file byte cap (or the override)
    and its packets within :func:`max_cache_packets`."""
    enabled, max_cache, max_file = _cache_config()
    if max_file_override is not None:
        try:
            max_file = max(max_file, int(max_file_override))
        except Exception:
            pass
    if not enabled or max_cache <= 0 or max_file <= 0:
        return False
    try:
        size_bytes = capture_size(path)
    except Exception:
        size_bytes = 0
    if size_bytes and size_bytes > max_file:
        return False
    return fits_in_memory(path)


def load_packets_if_allowed(
    path: Path,
    show_status: bool = True,
    *,
    max_file_override: int | None = None,
) -> tuple[list[object], PcapMeta] | tuple[None, None]:
    if not memory_admissible(path, max_file_override=max_file_override):
        return None, None
    try:
        return get_cached_packets(path, show_status=show_status)
    except Exception:
        # Unreadable/unsupported capture: behave as "not preloaded" so the
        # caller falls back to the per-analyzer reader (which degrades to an
        # empty reader) instead of crashing the whole run.
        return None, None


def _bpf_filtered(path: Path, bpf: str) -> Iterator[object]:
    """The packets of the one file ``path`` that pass ``bpf``, as scapy's
    offline sniff filters them (tcpdump ``-w -``, the filter checked first
    against the capture's link type) -- but tcpdump reads a copy of this
    process's read of the file, down its standard input: the read hashes the
    capture, copies it to whoever waits for it and collects a pcapng's
    details on the way, as any read of it does, and a compressed capture
    reaches tcpdump inflated. Where tcpdump reads no standard input (macOS)
    it reads the file, as with scapy."""
    import subprocess

    from scapy.arch.common import compile_filter  # type: ignore
    from scapy.config import conf  # type: ignore
    from scapy.consts import DARWIN, OPENBSD  # type: ignore
    from scapy.sendrecv import _offline_pcap_reader  # type: ignore

    prog = conf.prog.tcpdump
    if DARWIN or not prog:
        reader = _offline_pcap_reader(str(path), bpf, True)
        try:
            yield from reader
        finally:
            reader.close()
        return
    linktype = None
    if is_gzip_file(path):
        # A compressed capture's first packet from its inflated start (no
        # 128 KiB gzip read); too short a start falls back to the file.
        try:
            with PcapReader(io.BytesIO(capture_prefix(path))) as probe:
                linktype = probe._read_packet()[1].linktype if isinstance(probe, PcapNgReader) else probe.linktype
        except Exception:  # noqa: BLE001
            linktype = None
    if linktype is None:
        with open_capture_file(path, buffering=4096) as head, PcapReader(head) as probe:
            if isinstance(probe, PcapNgReader):
                try:
                    linktype = probe._read_packet()[1].linktype
                except EOFError as exc:
                    raise ValueError("Cannot get linktype from a PcapNg packet.") from exc
            else:
                linktype = probe.linktype
    if OPENBSD and linktype == 228:
        linktype = 12  # DLT_RAW
    compile_filter(bpf, linktype=linktype)  # an invalid filter fails here, as with scapy
    handle = capture_file(path, single=True)
    if handle is None:
        reader = _offline_pcap_reader(str(path), bpf, True)
        try:
            yield from reader
        finally:
            reader.close()
        return
    stdin_opts = ["-r", "-"] if OPENBSD else ["-U", "-r", "-"]
    try:
        proc = subprocess.Popen(
            [prog, *stdin_opts, "-w", "-", bpf],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except BaseException:
        handle.close()
        raise

    def _feed() -> None:
        try:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                proc.stdin.write(chunk)  # type: ignore[union-attr]
        except OSError:
            pass  # tcpdump went away: its output says how far it got
        finally:
            try:
                proc.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass
            handle.close()  # the read's copies, hashes and metadata completed

    feeder = threading.Thread(target=_feed, name="pcapper-bpf-feed", daemon=True)
    feeder.start()
    try:
        reader = PcapReader(proc.stdout)
        try:
            yield from reader
        finally:
            reader.close()
    finally:
        try:
            proc.stdout.close()  # type: ignore[union-attr]
        except OSError:
            pass
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        feeder.join()


def load_filtered_packets(
    path: Path,
    *,
    show_status: bool = True,
    bpf: str | None = None,
    time_start: float | None = None,
    time_end: float | None = None,
    bpf_status: dict[str, object] | None = None,
) -> tuple[list[object], PcapMeta]:
    _require_scapy()
    file_type = detect_file_type(path)
    host_only_ip = _extract_host_only_bpf_ip(bpf)
    try:
        size_bytes = capture_size(path)
    except Exception:
        size_bytes = 0

    if bpf and sniff is not None and host_only_ip is None:
        try:
            status = build_busy_statusbar(path, enabled=show_status, desc="Filtering")
            has_time_filter = time_start is not None or time_end is not None

            def _in_window(pkt: object) -> bool:
                if not has_time_filter:
                    return True
                ts = getattr(pkt, "time", None)
                if ts is None:
                    return False
                if time_start is not None and ts < time_start:
                    return False
                if time_end is not None and ts > time_end:
                    return False
                return True

            # Only the packets that pass the time window are kept, instead of
            # materialising every BPF match first and filtering the list again.
            packets = []
            with status:
                for part in capture_parts(path):  # in order: one part after the other
                    for pkt in _bpf_filtered(part, bpf):
                        if _in_window(pkt):
                            packets.append(pkt)
            if bpf_status is not None:
                bpf_status["used_bpf"] = True
            meta = _finalize_meta(
                path=path,
                file_type=file_type,
                size_bytes=size_bytes,
                linktype=None,
                snaplen=None,
                interfaces=None,
            )
            return packets, meta
        except Exception as exc:
            if bpf_status is not None:
                bpf_status["used_bpf"] = False
                bpf_status["error"] = f"{type(exc).__name__}: {exc}"
            pass
    elif bpf and bpf_status is not None:
        bpf_status["used_bpf"] = False
        bpf_status["error"] = "Scapy sniff unavailable (libpcap/BPF not available)."

    reader = open_capture_reader(path, file_type)
    status = build_statusbar(path, enabled=show_status)
    stream = _reader_stream(reader)
    linktype = getattr(reader, "linktype", None)
    snaplen = getattr(reader, "snaplen", None)
    interfaces = getattr(reader, "interfaces", None)
    host_only_addr = None
    if host_only_ip:
        try:
            host_only_addr = ipaddress.ip_address(host_only_ip)
        except Exception:
            host_only_addr = None
    packets: list[object] = []
    track_progress = status.enabled and stream is not None and bool(size_bytes)
    has_time_filter = time_start is not None or time_end is not None
    count = 0
    try:
        for pkt in reader:
            count += 1
            if track_progress and not (count & 0x1FF):
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass
            if has_time_filter:
                ts = getattr(pkt, "time", None)
                if ts is None:
                    continue
                if time_start is not None and ts < time_start:
                    continue
                if time_end is not None and ts > time_end:
                    continue
            if host_only_addr is not None and not _packet_matches_host(
                pkt, host_only_addr
            ):
                continue
            packets.append(pkt)
    finally:
        status.finish()
        reader.close()

    linktype = getattr(reader, "linktype", linktype)
    snaplen = getattr(reader, "snaplen", snaplen)
    interfaces = getattr(reader, "interfaces", interfaces)

    meta = _finalize_meta(
        path=path,
        file_type=file_type,
        size_bytes=size_bytes,
        linktype=linktype,
        snaplen=snaplen,
        interfaces=interfaces,
    )
    return packets, meta


def has_cached_packets(path: Path) -> bool:
    return _cached_packets(path) is not None


_HASH_CACHE: dict[tuple[str, int, int, int], tuple[str | None, str | None]] = {}
# Captures whose hashes this run reports (the base summary, --overview, case
# metadata): the first whole read of the file computes them on the way.
_HASH_WANTED: set[Path] = set()
_HASH_PLAN_REQUESTS = 0  # hash requests seen in dry runs (sharedpass.discover)


def _hashes_key(path: Path, parts: list[Path] | None = None) -> tuple[str, int, int, int] | None:
    parts = capture_parts(path) if parts is None else parts
    try:
        key_path = _path_key(path)
        st = key_path.stat()
        return (str(key_path), capture_size(path), st.st_mtime_ns, len(parts))
    except OSError:
        return None


def want_hashes(path: Path) -> None:
    """The run will report ``path``'s hashes: hash it during its first whole read."""
    _HASH_WANTED.add(_path_key(path))


def _tee_buffer_bytes() -> int:
    from .utils import env_int

    return env_int("PCAPPER_TEE_BUFFER_BYTES", 64 * 1024 * 1024, minimum=1 << 20)


_LIVE_SINKS: "weakref.WeakSet[TeeSink]" = weakref.WeakSet()


class TeeSink:
    """A copy of a capture's bytes on its way to another reader -- a pipe to a
    --jobs worker, the FIFO Suricata reads -- so that reader needs no read of
    the file of its own. The read of the capture hands it every chunk in order
    (:meth:`put`); a writer thread passes them on, holding up the read only
    when it falls ``PCAPPER_TEE_BUFFER_BYTES`` (64 MiB) behind, so one slow
    reader does not set the pace for the others. :meth:`finish` ends the
    stream; ``complete`` then says whether every byte of the file went out.

    ``target`` is an open file descriptor, or None with ``opener``: a callable
    run in the writer thread that returns one (a FIFO's write end blocks until
    its reader opens it), or None when the reader is gone."""

    def __init__(  # type: ignore[no-untyped-def]
        self,
        target: Optional[int],
        *,
        opener=None,
        name: str = "copy",
        stall_timeout: Optional[float] = None,
        on_stall=None,
        watchdog: bool = False,
    ) -> None:
        self.fd = target
        self._opener = opener
        # A reader that takes nothing for this long is taken to be stuck: the
        # copy is abandoned (its owner falls back to the file). select() tells
        # when the reader takes more; where it cannot watch a pipe (Windows) a
        # watchdog thread sees a write blocked that long and calls
        # ``on_stall`` (which stops the reader, so the write fails).
        self._stall_timeout = stall_timeout
        self._on_stall = on_stall
        self._select_ok = not watchdog
        self._writing_since: Optional[float] = None
        self._watching: Optional[threading.Event] = None
        self._chunks: "collections.deque[bytes]" = collections.deque()
        self._queued = 0
        self._limit = _tee_buffer_bytes()
        self._cond = threading.Condition()
        self._done = False
        self.failed = False
        self.complete = False
        self.sent = 0
        self.expected: Optional[int] = None
        _LIVE_SINKS.add(self)
        self._thread = threading.Thread(target=self._run, name=f"pcapper-{name}", daemon=True)
        self._thread.start()

    def put(self, data: bytes) -> None:
        with self._cond:
            while not self.failed and self._queued >= self._limit:
                self._cond.wait()
            if self.failed:
                return
            self._chunks.append(data)
            self._queued += len(data)
            self._cond.notify_all()

    def finish(self) -> None:
        with self._cond:
            self._done = True
            self._cond.notify_all()

    def abandon(self) -> None:
        with self._cond:
            self.failed = True
            self._chunks.clear()
            self._queued = 0
            self._cond.notify_all()

    def wait(self, timeout: Optional[float] = None) -> bool:
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def _run(self) -> None:
        fd = self.fd
        if fd is None and self._opener is not None:
            try:
                fd = self._opener()
            except Exception:  # noqa: BLE001
                fd = None
            self.fd = fd
        if fd is None:
            self.abandon()
            return
        try:
            while True:
                with self._cond:
                    while not self._chunks and not self._done and not self.failed:
                        self._cond.wait()
                    if self.failed:
                        break
                    if not self._chunks:
                        self.complete = self.expected is None or self.sent == self.expected
                        break
                    data = self._chunks.popleft()
                view = memoryview(data)
                while view:
                    if self._stall_timeout is not None and not self._writable(fd):
                        raise OSError("the copy's reader stopped reading")
                    self._writing_since = time.monotonic()
                    try:
                        view = view[os.write(fd, view):]
                    finally:
                        self._writing_since = None
                with self._cond:
                    self.sent += len(data)
                    self._queued -= len(data)
                    self._cond.notify_all()
        except OSError:  # its reader went away (a worker that died, Suricata that stopped)
            self.abandon()
        finally:
            if self._watching is not None:
                self._watching.set()
            self.fd = None
            try:
                os.close(fd)
            except OSError:
                pass

    def _writable(self, fd: int) -> bool:
        """The reader takes more within the stall timeout (select), or a
        watchdog stands by to stop it if a write blocks that long."""
        if self._select_ok:
            import select

            try:
                return bool(select.select([], [fd], [], self._stall_timeout)[1])
            except (OSError, ValueError):  # not a selectable pipe (Windows)
                self._select_ok = False
        if self._watching is None:
            self._watching = threading.Event()
            threading.Thread(target=self._watch, name="pcapper-copy-watchdog", daemon=True).start()
        return True

    def _watch(self) -> None:
        assert self._watching is not None and self._stall_timeout is not None
        while not self._watching.wait(min(1.0, self._stall_timeout / 4)):
            since = self._writing_since
            if since is not None and time.monotonic() - since > self._stall_timeout:
                self.abandon()
                if self._on_stall is not None:
                    try:
                        self._on_stall()
                    except Exception:  # noqa: BLE001
                        pass
                return


class _CaptureRaw(io.RawIOBase):
    """The capture file, with what passes through it put to use on the way:
    hashed when the run reports its hashes (:func:`want_hashes`), copied to
    readers that need the capture's bytes (:class:`TeeSink`).

    Under an ``io.BufferedReader`` it sees the file in buffer-sized chunks (a
    record-by-record reader costs one call per megabyte here, not per record).
    A read that reaches the end of the file having hashed every byte from
    offset 0 stores the digests for :func:`capture_hashes`. Copies get every
    byte in order whatever the reader does: bytes it skips (a seek ahead) or
    leaves unread (it stops early) are read from the file for them, and their
    streams end when the file is closed."""

    def __init__(
        self,
        filename: str,
        key: Path,
        *,
        hash_key: Optional[tuple] = None,
        sinks: list[TeeSink] | None = None,
        group_hash: Optional[tuple] = None,
    ) -> None:
        super().__init__()
        # Everything close() touches exists before the file is opened: a file
        # that cannot be opened still leaves an object the finalizer closes.
        self._file: Optional[io.FileIO] = None
        self._sinks: list[TeeSink] = []
        self._front = 0  # bytes [0, _front) are hashed and copied
        self._pos = 0
        self._size = 0
        self._hash_ok = False
        self._meta_tap: Optional[_PcapngMetaTap] = None
        self._meta_key: Optional[tuple] = None
        # A forked process inherits this object with its parent's copies,
        # hashes and metadata: they stay the parent's (see _inherited).
        self._owner = os.getpid()
        self.name = filename
        self._key = key
        self._file = io.FileIO(filename, "rb")
        st = os.fstat(self._file.fileno())
        self._size = st.st_size
        self.meta_key = (str(key), st.st_size, st.st_mtime_ns)
        try:
            head = _read_at(self._file, 0, 4)
        except OSError:
            head = b""
        # Compressed: inflated by the layer above (:class:`_InflatingRaw`).
        self.gzipped = head[:2] == b"\x1f\x8b"
        # A pcapng's interface and section metadata, collected on the way
        # (:func:`_read_pcapng_metadata` then walks no file of its own).
        if head == _PCAPNG_MAGIC and self.meta_key not in _PCAPNG_META:
            self._meta_tap = _PcapngMetaTap()
            self._meta_key = self.meta_key
        self._hash_key = hash_key
        self._sha256 = hashlib.sha256() if hash_key is not None else None
        self._sha1 = hashlib.sha1() if hash_key is not None else None
        self._hash_ok = hash_key is not None
        # A part of a split capture: (state, index, key) of the group's hashes,
        # carried on from the state the parts before it left.
        self._group = group_hash
        if group_hash is not None:
            state = group_hash[0]
            self._sha256 = state.sha256.copy()
            self._sha1 = state.sha1.copy()
            self._hash_ok = True
        if sinks:
            self.add_sinks(sinks)
        _LIVE_RAW[key] = self

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._file.fileno()  # type: ignore[union-attr]

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._pos = self._file.seek(offset, whence)  # type: ignore[union-attr]
        return self._pos

    def add_sinks(self, sinks: list[TeeSink], start: int = 0) -> None:
        """Copies that join a read already under way get what went by from
        ``start`` first (read from the file again; from a record boundary of a
        primed head the readers replay themselves, only what the buffer read
        ahead of it)."""
        self._inherited()
        for sink in sinks:
            sink.expected = self._size - start
        offset = start
        while offset < self._front:
            data = _read_at(self._file, offset, min(1 << 20, self._front - offset))
            if not data:
                break
            for sink in sinks:
                sink.put(data)
            offset += len(data)
        self._sinks.extend(sinks)

    def _inherited(self) -> bool:
        """In a forked process: drop what is the parent's to finish (its
        copies, hashes and metadata) -- closing the file here must not read
        the rest of it for copies the parent feeds."""
        if self._owner == os.getpid():
            return False
        self._sinks = []
        self._hash_ok = False
        self._meta_tap = None
        return True

    def _pass_on(self, data) -> None:  # type: ignore[no-untyped-def]
        if self._owner != os.getpid() and self._inherited():
            return
        if self._meta_tap is not None:
            self._meta_tap.feed(data)
        if self._hash_ok:
            self._sha256.update(data)  # type: ignore[union-attr]
            self._sha1.update(data)  # type: ignore[union-attr]
        if self._sinks:
            chunk = bytes(data)  # the reader's buffer is reused
            for sink in self._sinks:
                sink.put(chunk)

    def _copy_from_file(self, upto: int) -> None:
        """Bytes [front, upto) the reader skipped or never read: from the file,
        for the copies (and the hash) -- when copies need them, or the skip is
        small (a reader seeking over a record's body: the hash and metadata
        then go on); a large one ends the hash for this read."""
        self._inherited()
        if upto <= self._front:
            return
        if not self._sinks and not (
            (self._hash_ok or self._meta_tap is not None) and upto - self._front <= _SMALL_SKIP
        ):
            self._hash_ok = False  # skipped ahead: never the whole file
            self._meta_tap = None
            return
        offset = self._front
        while offset < upto:
            data = _read_at(self._file, offset, min(1 << 20, upto - offset))
            if not data:
                break
            self._pass_on(data)
            offset += len(data)
        self._front = max(self._front, offset)

    def readinto(self, buffer) -> int | None:  # type: ignore[no-untyped-def, override]
        start = self._pos
        count = self._file.readinto(buffer)
        if count is None:
            return None
        if count:
            end = start + count
            if start > self._front:
                self._copy_from_file(start)
            if start <= self._front < end:
                self._pass_on(memoryview(buffer)[self._front - start : count])
                self._front = end
        self._pos = start + count
        if not count:
            self._store_hashes()
            self._store_meta()
        return count

    def _store_meta(self) -> None:
        tap, self._meta_tap = self._meta_tap, None
        if tap is None or self._front != self._size:
            return
        try:
            unchanged = os.fstat(self._file.fileno()).st_size == self._size  # type: ignore[union-attr]
        except OSError:
            unchanged = False
        if unchanged and self._meta_key is not None:
            _PCAPNG_META.setdefault(self._meta_key, tap.finish())

    def _store_hashes(self) -> None:
        if not self._hash_ok:
            return
        self._hash_ok = False
        try:
            unchanged = os.fstat(self._file.fileno()).st_size == self._size
        except OSError:
            unchanged = False
        if not (unchanged and self._front == self._size):
            return
        if self._group is not None:
            state, index, group_key = self._group
            state.part_done(index, self._sha256, self._sha1, group_key)
            return
        if self._hash_key not in _HASH_CACHE:
            _HASH_CACHE[self._hash_key] = (self._sha256.hexdigest(), self._sha1.hexdigest())  # type: ignore[index, union-attr]

    def close(self) -> None:
        if self.closed:
            return
        try:
            if self._file is not None and not self._inherited():
                if self._sinks:
                    self._copy_from_file(self._size)  # the rest, so every copy is whole
                if self._front == self._size:
                    self._store_hashes()
                    self._store_meta()
        finally:
            for sink in self._sinks:
                sink.finish()
            self._sinks = []
            live = _LIVE_RAW  # None while the interpreter shuts down
            if live is not None and live.get(self._key) is self:
                del live[self._key]
            if self._file is not None:
                self._file.close()
            super().close()


# The read of each capture under way (for copies that join it late) and the
# copies waiting for the next one to start; for a compressed capture also its
# inflated read and the copies that want it inflated.
_LIVE_RAW: "weakref.WeakValueDictionary[Path, _CaptureRaw]" = weakref.WeakValueDictionary()
_PENDING_SINKS: dict[Path, list[TeeSink]] = {}
_LIVE_INFLATING: "weakref.WeakValueDictionary[Path, _InflatingRaw]" = weakref.WeakValueDictionary()
_PENDING_PLAIN_SINKS: dict[Path, list[TeeSink]] = {}


class _GroupHash:
    """The SHA-256/SHA-1 of a split capture's parts read so far, in order: a
    part read whole carries them on (from a copy of this state, so a part
    read only in part leaves them as they were); the last one stores them."""

    def __init__(self, count: int) -> None:
        self.count = count
        self.next_index = 0
        self.sha256 = hashlib.sha256()
        self.sha1 = hashlib.sha1()

    def part_done(self, index: int, sha256, sha1, group_key: tuple) -> None:  # type: ignore[no-untyped-def]
        if index != self.next_index:
            return
        self.sha256, self.sha1 = sha256, sha1
        self.next_index += 1
        if self.next_index == self.count:
            _HASH_CACHE.setdefault(group_key, (sha256.hexdigest(), sha1.hexdigest()))
            _GROUP_HASHES.pop(group_key, None)


_GROUP_HASHES: dict[tuple, _GroupHash] = {}
# A skip ahead a hashing read fills in (reads) rather than giving up its hash.
_SMALL_SKIP = 4 * 1024 * 1024
# Callbacks per split capture (by its head), told the index of each part the
# moment a read opens it (fifo_feed starts the next part's copies then).
_PART_HOOKS: dict[Path, list] = {}


def _read_at(file: io.FileIO, offset: int, size: int) -> bytes:
    """Read from an absolute offset on platforms without ``os.pread``."""
    pread = getattr(os, "pread", None)
    if pread is not None:
        return pread(file.fileno(), size, offset)
    current = file.tell()
    try:
        file.seek(offset)
        return file.read(size)
    finally:
        file.seek(current)


def on_part_open(path: Path, callback) -> None:  # type: ignore[no-untyped-def]
    """Call ``callback(index)`` each time a read opens part ``index`` of the
    split capture ``path``."""
    _PART_HOOKS.setdefault(_path_key(path), []).append(callback)


def forget_part_hooks(path: Optional[Path] = None) -> None:
    if path is None:
        _PART_HOOKS.clear()
    else:
        _PART_HOOKS.pop(_path_key(path), None)


def capture_file(path: Path, *, single: bool = False) -> io.BufferedReader | None:
    """The file object a read of the whole of ``path`` goes through: it hashes
    the capture on the way when the run wants its hashes, and copies it to the
    readers waiting for its bytes (:func:`tee_capture`). None for a capture of
    several part files read as one; ``single``: the one file ``path`` names, a
    part of a split capture included -- its bytes carry the split capture's
    hashes on, in order."""
    try:
        key = _path_key(path)
    except Exception:  # noqa: BLE001
        return None
    group = part_group(path) if single else None
    if single:
        filename = Path(path)
    else:
        parts = capture_parts(path)
        if len(parts) != 1:
            return None
        filename = parts[0]
    hash_key = None
    group_hash = None
    if group is not None:
        head, index, group_parts = group
        head_key = _path_key(head)
        for hook in list(_PART_HOOKS.get(head_key, ())):
            try:
                hook(index)
            except Exception:  # noqa: BLE001 - a copy that cannot start reads its file
                pass
        if head_key in _HASH_WANTED:
            group_key = _hashes_key(head, list(group_parts))
            if group_key is not None and group_key not in _HASH_CACHE:
                state = _GROUP_HASHES.get(group_key)
                if state is None:
                    state = _GROUP_HASHES[group_key] = _GroupHash(len(group_parts))
                if state.next_index == index:
                    group_hash = (state, index, group_key)
    elif key in _HASH_WANTED:
        candidate = _hashes_key(path, [filename])
        if candidate is not None and candidate not in _HASH_CACHE:
            hash_key = candidate
    sinks = _PENDING_SINKS.pop(key, [])
    try:
        raw = _CaptureRaw(str(filename), key, hash_key=hash_key, sinks=sinks, group_hash=group_hash)
    except OSError:
        if sinks:
            _PENDING_SINKS[key] = sinks
        return None
    reader = io.BufferedReader(raw, buffer_size=1 << 20)
    if not raw.gzipped:
        return reader
    plain = _PENDING_PLAIN_SINKS.pop(key, [])
    return _InflatedReader(_InflatingRaw(reader, key, str(filename), raw.meta_key, plain), buffer_size=1 << 20)


class _InflatingRaw(io.RawIOBase):
    """A gzip-compressed capture as its readers see it -- inflated from the
    compressed file object below (a :class:`_CaptureRaw`: the hashes, and the
    copies of the file's own bytes) -- with what goes by put to use too:
    copied to readers that need the capture inflated (Suricata reads no
    gzip), and a pcapng's metadata collected. Copies get every inflated byte
    in order: a reader that stops early has the rest inflated for them when
    it closes."""

    def __init__(
        self, compressed: io.BufferedReader, key: Path, filename: str, meta_key: tuple, sinks: list[TeeSink]
    ) -> None:
        super().__init__()
        self._compressed = compressed
        self._sinks: list[TeeSink] = []
        self._key = key
        self._filename = filename
        self._pos = 0
        self._front = 0  # inflated bytes [0, _front) are copied
        self._meta_key = meta_key
        self._meta_tap: Optional[_PcapngMetaTap] = None
        self._meta_undecided = meta_key not in _PCAPNG_META
        self._ended = False
        self._owner = os.getpid()
        self.name = filename
        self._gz = gzip.GzipFile(fileobj=compressed, mode="rb")
        if sinks:
            self.add_sinks(sinks)
        _LIVE_INFLATING[key] = self

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def add_sinks(self, sinks: list[TeeSink]) -> None:
        """Copies that join a read already under way get what went by first,
        inflated again from the file up to where the read is."""
        if self._front:
            try:
                with gzip.open(self._filename, "rb") as again:
                    left = self._front
                    while left > 0:
                        data = again.read(min(1 << 20, left))
                        if not data:
                            break
                        for sink in sinks:
                            sink.put(data)
                        left -= len(data)
                if left:
                    raise OSError("the capture changed")
            except (OSError, EOFError, gzip.BadGzipFile):
                for sink in sinks:
                    sink.abandon()
        self._sinks.extend(sinks)

    def _pass_on(self, view) -> None:  # type: ignore[no-untyped-def]
        if self._owner != os.getpid():  # forked: the parent's copies and metadata
            self._sinks = []
            self._meta_tap = None
            self._meta_undecided = False
            return
        if self._meta_undecided:
            self._meta_undecided = False
            if self._front == 0 and bytes(view[:4]) == _PCAPNG_MAGIC:
                self._meta_tap = _PcapngMetaTap()
        if self._meta_tap is not None:
            self._meta_tap.feed(view)
        if self._sinks:
            chunk = bytes(view)
            for sink in self._sinks:
                sink.put(chunk)

    def _advance(self, data) -> None:  # type: ignore[no-untyped-def]
        """``data`` was just inflated at ``_pos``: pass on what lies past the front."""
        start = self._pos
        end = start + len(data)
        if start <= self._front < end:
            self._pass_on(memoryview(data)[self._front - start :])
            self._front = end
        self._pos = end

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def, override]
        count = self._gz.readinto(buffer)
        if count:
            self._advance(memoryview(buffer)[:count])
        else:
            self._end()
        return count

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            target = self._pos + offset
        elif whence == io.SEEK_SET:
            target = offset
        else:
            raise io.UnsupportedOperation("a gzip-compressed capture cannot seek from its end")
        if target > self._front:
            # Ahead of what went by: inflated through, so the copies and the
            # metadata miss nothing.
            if self._pos != self._front:
                self._pos = self._gz.seek(self._front)
            while self._pos < target:
                data = self._gz.read(min(1 << 20, target - self._pos))
                if not data:
                    break
                self._advance(data)
            return self._pos
        self._pos = self._gz.seek(target)
        return self._pos

    def _end(self) -> None:
        """The end of the inflated capture: every byte went by."""
        if self._ended:
            return
        self._ended = True
        tap, self._meta_tap = self._meta_tap, None
        if tap is not None:
            _PCAPNG_META.setdefault(self._meta_key, tap.finish())

    def close(self) -> None:
        if self.closed:
            return
        if self._owner != os.getpid():  # forked: the parent's copies, not ours to finish
            self._sinks = []
            self._meta_tap = None
        try:
            if any(not sink.failed for sink in self._sinks):
                self.seek(1 << 62)  # the rest, inflated, so every copy is whole
                self._end()
        except Exception:  # noqa: BLE001 - a damaged stream: the copies fall short
            for sink in self._sinks:
                sink.abandon()
        finally:
            for sink in self._sinks:
                sink.finish()
            self._sinks = []
            live = _LIVE_INFLATING  # None while the interpreter shuts down
            if live is not None and live.get(self._key) is self:
                del live[self._key]
            try:
                self._gz.close()
            finally:
                self._compressed.close()
                super().close()


class _InflatedReader(io.BufferedReader):
    """The buffered reader over :class:`_InflatingRaw`; like gzip.GzipFile, its
    ``fileobj`` is the compressed file object (whose position is the file's,
    for progress against the file's size)."""

    @property
    def fileobj(self) -> io.BufferedReader:
        return self.raw._compressed  # type: ignore[attr-defined]


hashing_file = capture_file  # the name it had while it only hashed


def can_tee(path: Path, *, single: bool = False) -> bool:
    """A capture in one file (``single``: the one file ``path`` names, a part
    of a split capture included): its bytes can be copied from the run's read."""
    try:
        return (single or len(capture_parts(path)) == 1) and _raw_reader_enabled()
    except Exception:  # noqa: BLE001
        return False


def tee_capture(path: Path, sinks: list[TeeSink], start: int = 0, *, plain: bool = False) -> None:
    """Copy the capture's bytes from ``start`` to ``sinks``: through the read
    of it already under way (a primed head) or else the next whole read; see
    :func:`feed_tees` for when no read comes. ``plain``: as its readers see
    them -- inflated, for a gzip-compressed capture (from its start)."""
    key = _path_key(path)
    if plain and is_gzip_file(path):
        live = _LIVE_INFLATING.get(key)
        if live is not None and not live.closed:
            live.add_sinks(sinks)
        else:
            _PENDING_PLAIN_SINKS.setdefault(key, []).extend(sinks)
        return
    raw = _LIVE_RAW.get(key)
    if raw is not None and not raw.closed:
        raw.add_sinks(sinks, start)
    else:
        _PENDING_SINKS.setdefault(key, []).extend(sinks)


class _FramedCopy:
    """A --jobs worker's copy of a split capture, down one pipe (a
    :class:`TeeSink`): each part's size (8 bytes, little-endian) and then
    its bytes, part after part."""

    def __init__(self, sink: TeeSink, count: int) -> None:
        self.sink = sink
        self.count = count

    def part(self, index: int, size: int) -> "_PartCopy":
        return _PartCopy(self, index, size)


class _PartCopy:
    """One part's share of a :class:`_FramedCopy`: to the read of that part
    (a :class:`_CaptureRaw`), one of its copies."""

    def __init__(self, copy: _FramedCopy, index: int, size: int) -> None:
        self._copy = copy
        self._index = index
        self._size = size
        self._started = False
        self._sent = 0
        self.expected: Optional[int] = None

    @property
    def failed(self) -> bool:
        return self._copy.sink.failed

    def _start(self) -> None:
        if not self._started:
            self._started = True
            self._copy.sink.put(struct.pack("<Q", self._size))

    def put(self, data: bytes) -> None:
        self._start()
        self._copy.sink.put(data)
        self._sent += len(data)

    def abandon(self) -> None:
        self._copy.sink.abandon()

    def finish(self) -> None:
        self._start()
        if self._sent != self._size:
            self._copy.sink.abandon()  # the worker sees a copy short of the file
        if self._index == self._copy.count - 1:
            self._copy.sink.finish()


def tee_parts(path: Path, sinks: list[TeeSink], resume: Optional[tuple[int, int]] = None) -> None:
    """Copy the parts of the split capture ``path`` to each of ``sinks``,
    framed (:class:`_FramedCopy`), through the run's read of the parts. With
    ``resume`` -- (part, offset) where a primed head the workers replay left
    off -- from there on; else every part: a part that read is in is caught
    up from its start, the parts before it (a primed head went past them)
    are read again from their files, the rest go with the read when it gets
    to them (or :func:`feed_tees`)."""
    parts = capture_parts(path)
    copies = [_FramedCopy(sink, len(parts)) for sink in sinks]
    for sink in sinks:
        sink.expected = None  # each part's frame says how much of it to expect
    if resume is not None:
        first, offset = resume
        raw = _LIVE_RAW.get(_path_key(parts[first]))
        for index in range(first, len(parts)):
            try:
                size = os.path.getsize(parts[index])
            except OSError:
                size = 0
            if index == first and raw is not None and not raw.closed:
                raw.add_sinks([copy.part(index, size - offset) for copy in copies], offset)  # type: ignore[misc]
            else:
                shares = [copy.part(index, size) for copy in copies]
                _PENDING_SINKS.setdefault(_path_key(parts[index]), []).extend(shares)  # type: ignore[arg-type]
        return
    live = -1
    for index, part in enumerate(parts):
        raw = _LIVE_RAW.get(_path_key(part))
        if raw is not None and not raw.closed:
            live = index
    for index, part in enumerate(parts):
        try:
            size = os.path.getsize(part)
        except OSError:
            size = 0
        shares = [copy.part(index, size) for copy in copies]
        if index < live:
            try:
                with open(part, "rb", buffering=0) as handle:
                    for data in iter(lambda: handle.read(1 << 20), b""):
                        for share in shares:
                            share.put(data)
            except OSError:
                for share in shares:
                    share.abandon()
            for share in shares:
                share.finish()
        elif index == live:
            _LIVE_RAW[_path_key(part)].add_sinks(shares, 0)  # type: ignore[arg-type]
        else:
            _PENDING_SINKS.setdefault(_path_key(part), []).extend(shares)  # type: ignore[arg-type]


def primed_part_resume(path: Path) -> Optional[tuple[int, int]]:
    """For a split capture: (part, offset) where a primed head left off (a
    record boundary in the part its read is in), when forked workers can
    replay their copy of the head and parse the rest from a copy from there;
    None when they cannot (as :func:`primed_resume_point`)."""
    stream = _PRIMED.get(_path_key(path)) if _PRIMED else None
    if stream is None or stream.complete:
        return None
    lite = stream._stream
    reader = getattr(lite, "_current", None)
    index = getattr(lite, "_seg_index", None)
    handle = getattr(reader, "f", None)
    raw = getattr(handle, "raw", None)
    parts = capture_parts(path)
    if index is None or not 0 <= index < len(parts) or not isinstance(raw, _CaptureRaw) or raw.closed:
        return None
    if _LIVE_RAW.get(_path_key(parts[index])) is not raw:
        return None
    try:
        return index, int(handle.tell())
    except (OSError, ValueError):
        return None


def primed_resume_point(path: Path) -> Optional[int]:
    """Where a primed head left off in the file (a record boundary) when a
    forked worker can replay its copy of the head and parse the rest from a
    copy of the bytes from there: None when it cannot (no head kept, the whole
    capture kept, a compressed capture, no read of the file under way)."""
    stream = _PRIMED.get(_path_key(path)) if _PRIMED else None
    if stream is None or stream.complete:
        return None
    reader = getattr(stream._stream, "_current", None)
    handle = getattr(reader, "f", None)
    raw = getattr(handle, "raw", None)
    if not isinstance(raw, _CaptureRaw) or raw.closed or _LIVE_RAW.get(_path_key(path)) is not raw:
        return None
    try:
        return int(handle.tell())
    except (OSError, ValueError):
        return None


def feed_tees(path: Path, *, parts: bool = False) -> None:
    """Copies no read took up, fed from a read of their own (of the one file
    ``path`` names, a split capture's part included; hashed on the way too
    when the run wants it); a primed head nobody continued is read on for
    them. ``parts``: of every part of the split capture ``path``, in order."""
    if parts and len(capture_parts(path)) > 1:
        discard_primed(path)
        for part in capture_parts(path):
            feed_tees(part)
        return
    key = _path_key(path)
    discard_primed(path)  # closing it copies the rest to its copies
    if not _PENDING_SINKS.get(key) and not _PENDING_PLAIN_SINKS.get(key):
        return
    handle = capture_file(path, single=True)
    if handle is None:
        for sink in _PENDING_SINKS.pop(key, []) + _PENDING_PLAIN_SINKS.pop(key, []):
            sink.abandon()
            sink.finish()
        return
    handle.close()  # copies the whole file to them


def forget_tees() -> None:
    """In a forked process: the parent's copies are its own (their file
    descriptors are closed here, never written)."""
    for sink in list(_LIVE_SINKS):
        fd = sink.fd
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    _LIVE_SINKS.clear()
    _PENDING_SINKS.clear()
    _LIVE_RAW.clear()
    _PENDING_PLAIN_SINKS.clear()
    _LIVE_INFLATING.clear()
    _PART_HOOKS.clear()


class IncompleteCopy(Exception):
    """A --jobs worker's copy of the capture ended before the file did."""


class ResumedPartsStream:
    """In a --jobs worker, for a split capture: the primed head it inherited,
    replayed, then the rest parsed from the framed copy its parent sends (see
    :func:`tee_parts`) -- the part the head stopped in from where it stopped,
    with a copy of the head's reader on the pipe, then each later part."""

    def __init__(self, path: Path, head: "PrimedStream", fd: int) -> None:
        import copy

        lite = head._stream
        reader = lite._current
        self._first = int(lite._seg_index)
        start = int(reader.f.tell())
        self._head = head  # keeps the inherited reader's generator from closing early
        self._records = head._records
        head._records = []
        self._parts = capture_parts(path)
        self._raw = _PipeRaw(fd)
        self._handle = io.BufferedReader(self._raw, buffer_size=1 << 20)
        self._frames = 0
        size, view = self._frame()
        pipe = _Rewindable(view)
        resumed = copy.copy(reader)
        resumed.f = pipe
        inner = getattr(resumed, "reader", None)
        if inner is not None:  # pcapng: scapy's reader reads the blocks itself
            inner = copy.copy(inner)
            inner.f = pipe
            resumed.reader = inner
        self._current = (resumed, view, size)
        self._before = sum(_file_size(p) for p in self._parts[: self._first]) + start
        self.size_bytes = head.size_bytes
        self.linktype = head.linktype
        self.snaplen = head.snaplen
        self.interfaces = head.interfaces

    def _frame(self) -> tuple[int, "_BoundedView"]:
        frame = self._handle.read(8)
        if len(frame) < 8:
            raise IncompleteCopy(f"part {self._first + self._frames} of {len(self._parts)} missing")
        self._frames += 1
        size = struct.unpack("<Q", frame)[0]
        return size, _BoundedView(self._handle, size)

    def __iter__(self) -> Iterator[object]:
        records, self._records = self._records, []
        records.reverse()
        while records:
            yield records.pop()
        current = self._current
        for index in range(self._first, len(self._parts)):
            if index > self._first:
                size, view = self._frame()
                current = (_stream_reader(self._parts[index], view), view, size)
            reader, view, size = current
            yield from reader.records(None)
            while view.read(1 << 20):  # bytes after the part's last record
                pass
            if view.consumed != size:
                raise IncompleteCopy(f"part {index}: {view.consumed} of {size} bytes")
        if self._handle.read(1):
            raise IncompleteCopy("bytes past the last part")

    def tell(self) -> int:
        return self._before + max(0, self._raw.received - 8 * self._frames)

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:  # noqa: BLE001
            pass


def _file_size(path: Path) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


class ResumedStream:
    """In a --jobs worker: the primed head it inherited, replayed, then the
    rest of the capture parsed from the copy its parent sends from where the
    head left off -- with a copy of the head's reader (endianness, link type,
    pcapng interfaces) on the pipe instead of the file."""

    def __init__(self, path: Path, head: "PrimedStream", fd: int) -> None:
        import copy

        reader = head._stream._current
        start = int(reader.f.tell())
        self._head = head  # keeps the inherited reader's generator from closing early
        self._records = head._records
        head._records = []
        self._raw = _PipeRaw(fd)
        self._handle = io.BufferedReader(self._raw, buffer_size=1 << 20)
        pipe = _Rewindable(self._handle)
        resumed = copy.copy(reader)
        resumed.f = pipe
        inner = getattr(resumed, "reader", None)
        if inner is not None:  # pcapng: scapy's reader reads the blocks itself
            inner = copy.copy(inner)
            inner.f = pipe
            resumed.reader = inner
        self._reader = resumed
        self._expected = head.size_bytes - start
        self.size_bytes = head.size_bytes
        self.linktype = head.linktype
        self.snaplen = head.snaplen
        self.interfaces = head.interfaces
        self._start = start

    def __iter__(self) -> Iterator[object]:
        records, self._records = self._records, []
        records.reverse()
        while records:
            yield records.pop()
        yield from self._reader.records(None)
        while self._handle.read(1 << 20):
            pass
        if self._raw.received != self._expected:
            raise IncompleteCopy(f"{self._raw.received} of {self._expected} bytes")

    def tell(self) -> int:
        return self._start + self._raw.received

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:  # noqa: BLE001
            pass


# In a --jobs worker: the pipe its parent copies the capture's bytes into
# (and, when the copy starts where a primed head left off, that head).
_FEEDS: dict[Path, tuple[int, Optional["PrimedStream"]]] = {}


def use_feed(path: Path, fd: int, *, resume: bool = False) -> None:
    """In a --jobs worker, before :func:`forget_primed`: the next read of the
    capture comes down ``fd`` -- from its start, or (``resume``) from where
    the inherited primed head left off, after replaying it."""
    key = _path_key(path)
    head = _PRIMED.pop(key, None) if resume else None
    _FEEDS[key] = (fd, head)


def fed(path: Path) -> bool:
    return bool(_FEEDS) and _path_key(path) in _FEEDS


class _BoundedView:
    """The next ``size`` bytes of a buffered stream, as a stream of their own."""

    def __init__(self, handle: io.BufferedReader, size: int) -> None:
        self._handle = handle
        self._left = size
        self.consumed = 0

    def peek(self, size: int = 0) -> bytes:
        return self._handle.peek(size)[: self._left]

    def read(self, size: int = -1) -> bytes:
        if self._left <= 0:
            return b""
        want = self._left if size is None or size < 0 else min(size, self._left)
        data = self._handle.read(want)
        self._left -= len(data)
        self.consumed += len(data)
        return data

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def]
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        pass


class PartsPipeStream:
    """A split capture's lite records parsed, part after part, from the pipe a
    --jobs worker's parent copies every part into (:class:`_FramedCopy`): the
    worker reads no file. Behaves like a LiteStream over the parts; raises
    :class:`IncompleteCopy` when a part's bytes stop short of its file."""

    def __init__(self, path: Path, fd: int) -> None:
        self._path = path
        self._parts = capture_parts(path)
        self.size_bytes = capture_size(path)
        self._raw = _PipeRaw(fd)
        self._handle = io.BufferedReader(self._raw, buffer_size=1 << 20)
        self._frames = 0
        self._first = self._open_part()
        reader = self._first[0]
        self.linktype = reader.linktype
        self.snaplen = reader.snaplen
        self.interfaces = reader.interfaces

    def _open_part(self):  # type: ignore[no-untyped-def]
        frame = self._handle.read(8)
        if len(frame) < 8:
            raise IncompleteCopy(f"part {self._frames} of {len(self._parts)} missing")
        self._frames += 1
        size = struct.unpack("<Q", frame)[0]
        view = _BoundedView(self._handle, size)
        return _stream_reader(self._parts[min(self._frames - 1, len(self._parts) - 1)], view), view, size

    def __iter__(self) -> Iterator[object]:
        current = self._first
        for index in range(len(self._parts)):
            if index:
                current = self._open_part()
            reader, view, size = current
            yield from reader.records(None)
            while view.read(1 << 20):  # bytes after the part's last record
                pass
            if view.consumed != size:
                raise IncompleteCopy(f"part {index}: {view.consumed} of {size} bytes")
        if self._raw.received != self.size_bytes + 8 * len(self._parts) or self._handle.read(1):
            raise IncompleteCopy(f"{self._raw.received - 8 * len(self._parts)} of {self.size_bytes} bytes")

    def tell(self) -> int:
        return max(0, self._raw.received - 8 * self._frames)

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:  # noqa: BLE001
            pass


class _PipeRaw(io.RawIOBase):
    """The pipe end a --jobs worker reads its copy of the capture from."""

    def __init__(self, fd: int) -> None:
        super().__init__()
        self._fd = fd
        self.received = 0

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.received

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def, override]
        data = os.read(self._fd, len(buffer))
        count = len(data)
        buffer[:count] = data
        self.received += count
        return count

    def close(self) -> None:
        if not self.closed:
            try:
                os.close(self._fd)
            except OSError:
                pass
            super().close()


class _Rewindable:
    """A forward-only byte stream (a pipe, or gzip over one) that can step
    back over the bytes it last returned: pcapng's reader re-reads the last
    four bytes of a section header it has peeked at."""

    def __init__(self, stream) -> None:  # type: ignore[no-untyped-def]
        self._stream = stream
        self._back = b""
        self._last = b""
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        if self._back:
            if size is None or size < 0:
                data = self._back + self._stream.read()
                self._back = b""
            else:
                data = self._back[:size]
                self._back = self._back[size:]
                if len(data) < size:
                    data += self._stream.read(size - len(data))
        else:
            data = self._stream.read(size)
        self._last = data[-64:]
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR and offset <= 0 and -offset <= len(self._last):
            if offset:
                self._back = self._last[offset:] + self._back
                self._last = self._last[:offset]
                self._pos += offset
            return self._pos
        raise io.UnsupportedOperation("a copied capture is read forward only")

    def tell(self) -> int:
        return self._pos

    def close(self) -> None:
        self._stream.close()


def _stream_reader(path: Path, handle):  # type: ignore[no-untyped-def]
    """A lite record reader over a forward-only byte stream (a pipe, or one
    part's bytes of it): gzip inflated, pcapng's step back allowed."""
    from .rawcap import _PCAPNG_MAGIC, _ClassicReader, _PcapNgReader

    head = handle.peek(4)[:2]
    if head == b"\x1f\x8b":
        fdesc = _Rewindable(gzip.GzipFile(fileobj=handle))  # type: ignore[arg-type]
    else:
        fdesc = _Rewindable(handle)
    magic = fdesc.read(4)
    if bytes(magic) == _PCAPNG_MAGIC:
        return _PcapNgReader(str(path), fdesc, magic)
    return _ClassicReader(str(path), fdesc, magic)


class PipeStream:
    """A capture's lite records parsed from the pipe a --jobs worker's parent
    copies the file into: the worker reads no file. Behaves like a LiteStream;
    raises :class:`IncompleteCopy` when the bytes stop short of the file."""

    def __init__(self, path: Path, fd: int) -> None:
        self.size_bytes = capture_size(path)
        self._raw = _PipeRaw(fd)
        handle = io.BufferedReader(self._raw, buffer_size=1 << 20)
        self._handle = handle
        self._reader = _stream_reader(path, handle)
        self.linktype = self._reader.linktype
        self.snaplen = self._reader.snaplen
        self.interfaces = self._reader.interfaces

    def __iter__(self) -> Iterator[object]:
        yield from self._reader.records(None)
        while self._handle.read(1 << 20):  # bytes after the last record
            pass
        if self._raw.received != self.size_bytes:
            raise IncompleteCopy(f"{self._raw.received} of {self.size_bytes} bytes")

    def tell(self) -> int:
        return self._raw.received

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:  # noqa: BLE001
            pass


def capture_hashes(path: Path) -> tuple[str | None, str | None]:
    """SHA-256 and SHA-1 of the capture file, computed once per file version.

    Keyed on (path, size, mtime) so a re-written capture is re-hashed. The
    base summary and the case-metadata writer both need these; before this
    each made its own full pass over the file. A capture the run wants hashes
    for gets them from its first whole read (:func:`hashing_file`); a shared
    pass making its plan only notes the want.
    """
    # A joined split capture hashes its parts' bytes in order: reproducible
    # with `cat part000 part001 ... | sha256sum`, and it changes if any part
    # does. (It is not the hash of the original, pre-split file — splitting
    # rewrites every part's global header.)
    from .utils import planning

    parts = capture_parts(path)
    key = _hashes_key(path, parts)
    if key is None:
        return None, None
    cached = _HASH_CACHE.get(key)
    if cached is not None:
        return cached
    if planning():
        # A dry run (empty packet view) must not read the capture: note the
        # want, so the pass that follows hashes the file as it reads it.
        global _HASH_PLAN_REQUESTS
        _HASH_PLAN_REQUESTS += 1
        want_hashes(path)
        return None, None
    result = _hash_parts(parts)
    if result[0] is not None:
        _HASH_CACHE[key] = result
    return result


def _hash_parts(parts: list[Path]) -> tuple[str | None, str | None]:
    """A read of the capture's files, in order, for nothing but their hashes."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    try:
        for part in parts:
            with part.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    sha256.update(chunk)
                    sha1.update(chunk)
    except OSError:
        return None, None
    return sha256.hexdigest(), sha1.hexdigest()


# Progress is refreshed every this-many packets. A tell() per packet is
# measurable on multi-million-packet captures and buys nothing visible.
_PROGRESS_EVERY = 0x1FF


class PassStats:
    """Totals over every record of a disk pass, kept or dropped by a prefilter.

    An analyzer that lets :func:`iter_packets` drop records before they are
    dissected still has to report the capture's packet and byte totals and its
    time span; these are those totals, computed from the records themselves.
    ``active`` is False when the pass was served from an in-memory view (no
    prefilter applied there): the caller then counts what it iterated.
    Times are exact (ordered on the record's integer timestamp, converted to
    float only at the end), so they equal what ``safe_float(pkt.time)`` gives.
    """

    __slots__ = ("active", "packets", "bytes", "_first", "_last", "_min", "_max", "_min_key", "_max_key")

    def __init__(self) -> None:
        self.active = False
        self.packets = 0
        self.bytes = 0
        self._first = self._last = self._min = self._max = None
        self._min_key = self._max_key = None

    def add(self, record: object) -> None:
        self.packets += 1
        self.bytes += len(record.original)  # type: ignore[attr-defined]
        key = _record_time_key(record)
        if self._first is None:
            self._first = self._min = self._max = record
            self._min_key = self._max_key = key
        else:
            if key < self._min_key:  # type: ignore[operator]
                self._min, self._min_key = record, key
            if key > self._max_key:  # type: ignore[operator]
                self._max, self._max_key = record, key
        self._last = record

    # The records themselves: callers convert ``.time`` exactly as they
    # convert a packet's time in their own loop.
    @property
    def first(self) -> object | None:
        return self._first

    @property
    def last(self) -> object | None:
        return self._last

    @property
    def earliest(self) -> object | None:
        return self._min

    @property
    def latest(self) -> object | None:
        return self._max


def _record_time_key(record: object) -> object:
    spec = record._tspec  # type: ignore[attr-defined]
    kind = spec[0]
    if kind == "us":
        return spec[1] * 1_000_000_000 + spec[2] * 1000
    if kind == "ns":
        return spec[1] * 1_000_000_000 + spec[2]
    if kind == "ng":
        whole, rest = divmod(1_000_000_000, spec[2])
        if not rest:
            return spec[1] * whole
        from fractions import Fraction

        return Fraction(spec[1] * 1_000_000_000, spec[2])
    return spec[1] * 1e9


# A byte window of a capture that this process analyses instead of the whole
# file (a --jobs worker). Every reader of the path honours it.
_CAPTURE_WINDOWS: dict[Path, object] = {}


def set_capture_window(path: Path, window: object) -> None:
    _CAPTURE_WINDOWS[_path_key(path)] = window


def clear_capture_window(path: Path) -> None:
    _CAPTURE_WINDOWS.pop(_path_key(path), None)


def get_capture_window(path: Path) -> object | None:
    if not _CAPTURE_WINDOWS:
        return None
    return _CAPTURE_WINDOWS.get(_path_key(path))


def _raw_reader_enabled() -> bool:
    return os.environ.get("PCAPPER_RAW_READER", "1") != "0" and raw_reading_available()


def _streams_from_disk(path: Path, packets: list[object] | None) -> bool:
    """True when a pass over ``path`` would read the file (no in-memory view)."""
    if packets is not None:
        return False
    key = _path_key(path)
    if key in _FORCED_PACKET_VIEWS:
        return False
    return _cached_packets(path) is None


class WindowReader:
    """scapy packets of one capture window, read like ``open_capture_reader``."""

    def __init__(self, path: Path, window: object) -> None:
        self._stream = LiteStream(path, window)  # type: ignore[arg-type]
        self.linktype = self._stream.linktype
        self.snaplen = self._stream.snaplen
        self.interfaces = self._stream.interfaces
        self.f = self._stream

    def __iter__(self) -> Iterator[object]:
        for record in self._stream:
            yield record.materialize()

    def close(self) -> None:
        self._stream.close()


# The first records of a capture the decode-as check read from disk, kept
# with the reader left where it stopped: the next whole read of the capture
# replays them and goes on from there, so the check costs no read of its own.
_PRIMED: dict[Path, "PrimedStream"] = {}


def _prime_max_bytes() -> int:
    from .utils import env_int

    return env_int("PCAPPER_PRIME_MAX_BYTES", 64 * 1024 * 1024, minimum=0)


class PrimedStream:
    """A capture's lite records whose first ones were already read: those are
    handed out from memory, then the same reader carries on. Behaves like the
    LiteStream it wraps (iteration, ``tell``, ``size_bytes``, ``close``)."""

    def __init__(
        self, stream: LiteStream, records: list, rest: Iterator[object], signature: object, *, complete: bool = False
    ) -> None:
        self._stream = stream
        self._records = records
        self.count = len(records)
        self._rest: Optional[Iterator[object]] = rest
        self.signature = signature
        # Every record of the capture is kept (the check read to its end): no
        # file stays open behind it, so a forked worker may replay its copy.
        self.complete = complete
        self.size_bytes = stream.size_bytes
        self.linktype = stream.linktype
        self.snaplen = stream.snaplen
        self.interfaces = stream.interfaces

    def __iter__(self) -> Iterator[object]:
        records, self._records = self._records, []
        records.reverse()
        while records:
            yield records.pop()  # each one let go of as it is handed out
        rest, self._rest = self._rest, None
        if rest is not None:
            yield from rest

    def tell(self) -> int:
        return self._stream.tell()

    def rebind(self, signature: object) -> None:
        """scapy's binding tables changed since the kept records were read (a
        layer module bound itself): they forget what they worked out under the
        old ones, like records read now."""
        for record in self._records:
            forget = getattr(record, "forget_derived", None)
            if forget is not None:
                forget()
        self.signature = signature

    def close(self) -> None:
        self._records = []
        rest, self._rest = self._rest, None
        if rest is not None:
            try:
                rest.close()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
        self._stream.close()


def read_head(path: Path, count: int) -> Optional[Iterator[object]]:
    """The first ``count`` lite records of ``path``, read from disk and kept
    (up to ``PCAPPER_PRIME_MAX_BYTES``) for the next whole read of the capture
    (:func:`open_lite_stream`); None when it cannot be primed (a window, the
    raw reader off, already primed)."""
    if count <= 0 or get_capture_window(path) is not None or not _raw_reader_enabled():
        return None
    key = _path_key(path)
    if key in _PRIMED:
        return None
    try:
        stream = LiteStream(path, None)
    except Exception:  # noqa: BLE001
        return None
    return _read_head(key, stream, count)


def _read_head(key: Path, stream: LiteStream, count: int) -> Iterator[object]:
    from . import lite as lite_module

    signature = lite_module._BINDINGS  # the tables these records were read with
    rest = iter(stream)
    kept: list = []
    budget = _prime_max_bytes()
    used = 0
    keep = True
    complete = False
    try:
        for _ in range(count):
            try:
                record = next(rest)
            except StopIteration:
                complete = True
                break
            except BaseException:
                keep = False
                raise
            if keep:
                used += len(getattr(record, "original", b"") or b"") + 512
                if used > budget:
                    keep, kept = False, []
                else:
                    kept.append(record)
            yield record
    finally:
        if keep:
            _PRIMED[key] = PrimedStream(stream, kept, rest, signature, complete=complete)
        else:
            try:
                rest.close()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
            stream.close()


def primed(path: Path) -> bool:
    return bool(_PRIMED) and _path_key(path) in _PRIMED


def take_primed(path: Path) -> Optional[PrimedStream]:
    """The primed stream of ``path`` (handed out once), or None. Kept records
    read under other scapy binding tables (a layer module bound itself since,
    e.g. Modbus on 502 when --modbus ran) forget what they worked out."""
    if not _PRIMED:
        return None
    stream = _PRIMED.pop(_path_key(path), None)
    if stream is None:
        return None
    from . import lite as lite_module

    lite_module.refresh_bindings()
    if lite_module._BINDINGS != stream.signature:
        stream.rebind(lite_module._BINDINGS)
    return stream


def discard_primed(path: Optional[Path] = None) -> None:
    """Close what nobody took (one capture's, or every one)."""
    keys = list(_PRIMED) if path is None else [_path_key(path)]
    for key in keys:
        stream = _PRIMED.pop(key, None)
        if stream is not None:
            stream.close()


def forget_primed(*, keep_complete: bool = False) -> None:
    """In a forked process: the parent's primed readers share their file
    offsets with it, so they are dropped unread -- all but (``keep_complete``)
    one holding every record of its capture, with no file behind it."""
    for key in list(_PRIMED):
        if not (keep_complete and _PRIMED[key].complete):
            del _PRIMED[key]


def primed_complete(path: Path) -> bool:
    stream = _PRIMED.get(_path_key(path)) if _PRIMED else None
    return stream is not None and stream.complete


def open_lite_stream(path: Path) -> object:
    """The capture's lite records: in a --jobs worker, from the pipe its
    parent copies the file into; else from disk -- its primed stream when the
    head was read already (one read for both), or a new LiteStream."""
    window = get_capture_window(path)
    if window is None:
        if _FEEDS:
            feed = _FEEDS.pop(_path_key(path), None)
            if feed is not None:
                fd, head = feed
                if head is not None:
                    if len(capture_parts(path)) > 1:
                        return ResumedPartsStream(path, head, fd)
                    return ResumedStream(path, head, fd)
                if len(capture_parts(path)) > 1:
                    return PartsPipeStream(path, fd)
                return PipeStream(path, fd)
        stream = take_primed(path)
        if stream is not None:
            return stream
    return LiteStream(path, window)  # type: ignore[arg-type]


def _iter_raw(
    path: Path,
    *,
    lite: bool,
    prefilter: Optional[object],
    stats: Optional[PassStats],
    show_status: bool,
) -> Iterator[object]:
    try:
        stream = open_lite_stream(path)
    except Exception:
        # Unreadable capture: zero packets, like get_reader()'s fallback.
        return
    if stats is not None:
        stats.active = True
    status = build_statusbar(path, enabled=show_status)
    size_bytes = stream.size_bytes
    track = status.enabled and bool(size_bytes)
    add = stats.add if stats is not None else None
    count = 0
    try:
        for record in stream:
            count += 1
            if track and not (count & _PROGRESS_EVERY):
                try:
                    status.update(int(min(100, (stream.tell() / size_bytes) * 100)))
                except Exception:
                    pass
            if add is not None:
                add(record)
            if prefilter is not None and not prefilter(record):  # type: ignore[operator]
                continue
            yield record if lite else record.materialize()
    finally:
        status.finish()
        stream.close()


# While a shared pass makes its plan (sharedpass.discover): told, for every
# read of the capture an analysis starts, whether it reads lite records.
_READ_NOTE: Optional[object] = None


def iter_packets(
    path: Path,
    *,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    show_status: bool = True,
    lite: bool = False,
    prefilter: Optional[object] = None,
    stats: Optional[PassStats] = None,
) -> Iterator[object]:
    """Yield every packet of a capture with throttled progress and clean-up.

    The one loop every analyzer used to write by hand — get the reader,
    ``tell()`` the stream on each packet for the status bar, close both in a
    ``finally`` — as a single generator. Serves the shared in-memory packet
    list when one is active (see :func:`get_reader`), so chained steps never
    re-read the file.

    When the capture is read from disk:

    * ``lite=True`` yields :class:`pcapper.lite.LitePacket` records, which
      answer transport questions without scapy and dissect themselves only
      when scapy's API is used on them;
    * ``prefilter(record) -> bool`` drops records before they are dissected
      (callers must still reject the same packets themselves: in-memory views
      yield everything);
    * ``stats`` (a :class:`PassStats`) counts every record, dropped or not.

    A shared analysis pass in progress for the capture (see
    :mod:`pcapper.sharedpass`) serves its packets instead of a new read.
    """
    note = _READ_NOTE
    if note is not None and packets is None:
        note(lite)  # a shared pass's plan: what each analysis reads
    if _SHARED_PASS_HOOK is not None:
        shared = _SHARED_PASS_HOOK(path, packets, lite, prefilter, stats)
        if shared is not None:
            yield from shared
            return
    if _raw_reader_enabled() and _streams_from_disk(path, packets):
        if (
            lite or prefilter is not None or stats is not None
            or get_capture_window(path) is not None or primed(path) or fed(path)
        ):
            yield from _iter_raw(
                path, lite=lite, prefilter=prefilter, stats=stats, show_status=show_status
            )
            return
    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )
    track = status.enabled and stream is not None and bool(size_bytes)
    count = 0
    try:
        for pkt in reader:
            count += 1
            if track and not (count & _PROGRESS_EVERY):
                try:
                    status.update(int(min(100, (stream.tell() / size_bytes) * 100)))
                except Exception:
                    pass
            yield pkt
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass


# Each registration gets a fresh serial. The analysis memo keys on it rather
# than on id(list): a list freed after clear_forced_packet_view() can have
# its id reused by the next view of the same capture, and two different
# filtered views of equal length would then alias in the memo.
_FORCED_VIEW_SERIAL = 0
_FORCED_VIEW_SERIALS: dict[Path, int] = {}
_COMPLETE_VIEWS: set[Path] = set()  # forced views that hold every record


def set_forced_packet_view(
    path: Path, packets: list[object], meta: PcapMeta | None = None, *, complete: bool = True
) -> None:
    """Serve ``packets`` to every analysis of ``path`` instead of a read.
    ``complete``: the view holds every record of the capture (not a -ip /
    BPF / time selection), so a reader that needs the whole capture -- the
    file analysis's dpkt pass -- may take it instead of the disk."""
    global _FORCED_VIEW_SERIAL
    _FORCED_VIEW_SERIAL += 1
    key = _path_key(path)
    _FORCED_PACKET_VIEWS[key] = (packets, meta)
    _FORCED_VIEW_SERIALS[key] = _FORCED_VIEW_SERIAL
    if complete:
        _COMPLETE_VIEWS.add(key)
    else:
        _COMPLETE_VIEWS.discard(key)
    remember_layers(packets)


def complete_packet_view(path: Path) -> list[object] | None:
    """The in-memory view of ``path`` when it holds the whole capture."""
    key = _path_key(path)
    forced = _FORCED_PACKET_VIEWS.get(key)
    return forced[0] if forced is not None and key in _COMPLETE_VIEWS else None


# --- layer lookups on packets kept in memory ---------------------------------
# Every analyzer asks each packet for its layers again: pkt.getlayer(TCP),
# pkt.haslayer(DNS), pkt[IP] ... -- 6M top-level lookups, each walking the
# layer chain, in a --threats run over a 49k-packet capture. A packet held in
# memory for a run is never modified once read, so its answer to a plain
# lookup (a class, the first match, no field filters) never changes: it is
# kept on the packet, keyed by the packet's identity so that a copy (which
# carries the dict along) asks scapy again. --threats 98.8 s -> 76.5 s, the
# same results; memory: one small table per packet.
_LAYER_MEMO_KEY = "_pcapper_layers"
_LAYER_MEMO_INSTALLED = False


def remember_layers(packets: list[object]) -> None:
    """Let the scapy packets of an in-memory view keep their layer lookups
    (install_layer_memo() makes getlayer/haslayer use it)."""
    try:
        from scapy.packet import Packet
    except Exception:  # noqa: BLE001
        return
    for pkt in packets or ():
        if isinstance(pkt, Packet):
            store = getattr(pkt, "__dict__", None)
            if store is not None:
                store[_LAYER_MEMO_KEY] = (id(pkt), {})


def install_layer_memo() -> None:
    """Route scapy's Packet.getlayer / haslayer through the per-packet table
    for packets remember_layers() marked; every other call is unchanged."""
    global _LAYER_MEMO_INSTALLED
    if _LAYER_MEMO_INSTALLED:
        return
    try:
        from scapy.packet import Packet
    except Exception:  # noqa: BLE001
        return
    getlayer, haslayer = Packet.getlayer, Packet.haslayer
    key = _LAYER_MEMO_KEY
    missing = object()

    def memo_getlayer(self, cls, nb=1, _track=None, _subclass=None, **flt):  # type: ignore[no-untyped-def]
        if nb == 1 and _track is None and _subclass is None and not flt:
            store = getattr(self, "__dict__", None)
            memo = store.get(key) if store is not None else None
            if memo is not None and memo[0] == id(self):
                found = memo[1].get(cls, missing)
                if found is not missing:
                    return found
                if isinstance(cls, type):
                    found = memo[1][cls] = getlayer(self, cls)
                    return found
        return getlayer(self, cls, nb=nb, _track=_track, _subclass=_subclass, **flt)

    def memo_haslayer(self, cls, _subclass=None):  # type: ignore[no-untyped-def]
        if _subclass is None:
            store = getattr(self, "__dict__", None)
            memo = store.get(key) if store is not None else None
            if memo is not None and memo[0] == id(self):
                found = memo[1].get(("has", cls), missing)
                if found is not missing:
                    return found
                if isinstance(cls, type):
                    found = memo[1][("has", cls)] = haslayer(self, cls)
                    return found
        return haslayer(self, cls, _subclass=_subclass)

    memo_getlayer.__wrapped__ = getlayer  # type: ignore[attr-defined]
    memo_haslayer.__wrapped__ = haslayer  # type: ignore[attr-defined]
    Packet.getlayer = memo_getlayer  # type: ignore[method-assign]
    Packet.haslayer = memo_haslayer  # type: ignore[method-assign]
    _LAYER_MEMO_INSTALLED = True
    # Packets dissected from disk records are shared by the analyses of a
    # shared pass as those held in memory are: they keep their lookups too.
    from . import lite as lite_module

    lite_module.LAYER_MEMO_KEY = key


def clear_forced_packet_view(path: Path) -> None:
    key = _path_key(path)
    _FORCED_PACKET_VIEWS.pop(key, None)
    _FORCED_VIEW_SERIALS.pop(key, None)
    _COMPLETE_VIEWS.discard(key)


def get_forced_packet_view(path: Path) -> list[object] | None:
    forced = _FORCED_PACKET_VIEWS.get(_path_key(path))
    return forced[0] if forced is not None else None


def get_forced_packet_view_serial(path: Path) -> int | None:
    """Registration serial of the forced view for ``path`` (None when unset)."""
    return _FORCED_VIEW_SERIALS.get(_path_key(path))


def get_reader(
    path: Path,
    *,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    show_status: bool = True,
) -> tuple[object, object, Optional[object], int, str]:
    key = _path_key(path)
    forced = _FORCED_PACKET_VIEWS.get(key)
    if forced is not None:
        forced_packets, forced_meta = forced
        size_bytes = len(forced_packets)
        reader = PacketListReader(forced_packets, forced_meta)
        status = build_statusbar(path, enabled=show_status)
        file_type = forced_meta.file_type if forced_meta else detect_file_type(path)
        return reader, status, reader, size_bytes, file_type

    if packets is not None:
        size_bytes = len(packets)
        reader = PacketListReader(packets, meta)
        status = build_statusbar(path, enabled=show_status)
        return (
            reader,
            status,
            reader,
            size_bytes,
            (meta.file_type if meta else detect_file_type(path)),
        )

    # Serve straight from the in-process cache when the packets are already
    # loaded (e.g. preloaded by the CLI for chained steps), regardless of the
    # per-file size limit that gates *new* cache loads.
    cached = _cached_packets(path)
    if cached is not None:
        cached_packets, cached_meta = cached
        reader = PacketListReader(cached_packets, cached_meta)
        status = build_statusbar(path, enabled=show_status)
        return reader, status, reader, len(cached_packets), cached_meta.file_type

    enabled, max_cache, max_file = _cache_config()
    file_type = meta.file_type if meta else detect_file_type(path)
    try:
        size_bytes = meta.size_bytes if meta else capture_size(path)
    except Exception:
        size_bytes = 0

    cache_allowed = (
        enabled
        and max_cache > 0
        and max_file > 0
        and (size_bytes == 0 or size_bytes <= max_file)
        and fits_in_memory(path)
    )
    # An unreadable / unsupported / truncated capture must not crash the run:
    # opening it raises (scapy's "Not a supported capture file"), and with the
    # analyzers and the --overview/--threats fan-out all calling get_reader, a
    # single bad file would abort the whole batch with a traceback. Fall back to
    # an empty reader so each analyzer simply reports zero packets.
    try:
        if cache_allowed:
            cached_packets, cached_meta = get_cached_packets(
                path, show_status=show_status
            )
            reader = PacketListReader(cached_packets, cached_meta)
            status = build_statusbar(path, enabled=show_status)
            return reader, status, reader, len(cached_packets), cached_meta.file_type

        _require_scapy()
        reader = open_capture_reader(path, file_type)
        status = build_statusbar(path, enabled=show_status)
        stream = _reader_stream(reader)
        return reader, status, stream, size_bytes, file_type
    except Exception:
        empty = PacketListReader([], None)
        status = build_statusbar(path, enabled=show_status)
        return empty, status, empty, 0, file_type or "unknown"
