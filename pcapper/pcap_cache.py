from __future__ import annotations

from dataclasses import dataclass
from collections import OrderedDict
import os
import struct
from pathlib import Path
from typing import Iterable, Optional

from scapy.utils import PcapReader, PcapNgReader
try:
    from scapy.all import sniff  # type: ignore
except Exception:  # pragma: no cover
    sniff = None  # type: ignore

from .progress import build_statusbar, build_busy_statusbar
from .utils import detect_file_type


_PACKET_CACHE: "OrderedDict[Path, tuple[list[object], 'PcapMeta']]" = OrderedDict()
_CACHE_BYTES = 0


@dataclass(frozen=True)
class PcapMeta:
    path: Path
    file_type: str
    size_bytes: int
    linktype: object | None
    snaplen: object | None
    interfaces: object | None


PCAP_MAGIC = {
    0xA1B2C3D4: ">",
    0xD4C3B2A1: "<",
    0xA1B23C4D: ">",
    0x4D3CB2A1: "<",
}


def _read_pcap_header(path: Path) -> tuple[object | None, object | None]:
    try:
        with path.open("rb") as handle:
            header = handle.read(24)
        if len(header) < 24:
            return None, None
        magic = struct.unpack("<I", header[:4])[0]
        endian = PCAP_MAGIC.get(magic)
        if endian is None:
            magic = struct.unpack(">I", header[:4])[0]
            endian = PCAP_MAGIC.get(magic)
        if endian is None:
            return None, None
        snaplen = struct.unpack(f"{endian}I", header[16:20])[0]
        linktype = struct.unpack(f"{endian}I", header[20:24])[0]
        return linktype, snaplen
    except Exception:
        return None, None


def _read_pcapng_interfaces(path: Path) -> list[dict[str, object]]:
    interfaces: list[dict[str, object]] = []
    if_stats: dict[int, dict[str, object]] = {}
    try:
        with path.open("rb") as handle:
            endian = "<"
            while True:
                header = handle.read(8)
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
                    bom_bytes = handle.read(4)
                    if len(bom_bytes) < 4:
                        break
                    bom = struct.unpack("<I", bom_bytes)[0]
                    if bom == 0x1A2B3C4D:
                        endian = "<"
                    elif bom == 0x4D3C2B1A:
                        endian = ">"
                    remaining = body_len - 4
                    if remaining > 0:
                        handle.seek(remaining, 1)
                    handle.seek(4, 1)
                    continue

                if block_type == 0x00000001:
                    body_len = block_len - 12
                    body = handle.read(body_len)
                    if len(body) < body_len:
                        break
                    if len(body) >= 8:
                        linktype, _reserved, snaplen = struct.unpack(f"{endian}HHI", body[:8])
                        iface: dict[str, object] = {
                            "linktype": linktype,
                            "snaplen": snaplen,
                        }
                        opt_offset = 8
                        while opt_offset + 4 <= len(body):
                            code, length = struct.unpack(f"{endian}HH", body[opt_offset:opt_offset + 4])
                            opt_offset += 4
                            if code == 0:
                                break
                            value = body[opt_offset:opt_offset + length]
                            opt_offset += (length + 3) & ~3

                            if code == 2:  # if_name
                                iface["if_name"] = value.rstrip(b"\x00").decode(errors="ignore")
                            elif code == 3:  # if_description
                                iface["if_description"] = value.rstrip(b"\x00").decode(errors="ignore")
                            elif code == 6:  # if_MACaddr
                                iface["if_macaddr"] = ":".join(f"{b:02x}" for b in value[:6])
                            elif code == 8 and len(value) >= 8:  # if_speed
                                iface["if_speed"] = struct.unpack(f"{endian}Q", value[:8])[0]
                            elif code == 11 and len(value) >= 1:  # if_filter
                                filter_val = value[1:]
                                iface["if_filter"] = filter_val.rstrip(b"\x00").decode(errors="ignore")
                            elif code == 12:  # if_os
                                iface["if_os"] = value.rstrip(b"\x00").decode(errors="ignore")

                        iface["id"] = len(interfaces)
                        interfaces.append(iface)

                    handle.seek(4, 1)
                    continue

                if block_type == 0x00000005:
                    body_len = block_len - 12
                    body = handle.read(body_len)
                    if len(body) < body_len:
                        break
                    if len(body) >= 12:
                        iface_id = struct.unpack(f"{endian}I", body[:4])[0]
                        opt_offset = 12
                        stats = if_stats.setdefault(iface_id, {})
                        while opt_offset + 4 <= len(body):
                            code, length = struct.unpack(f"{endian}HH", body[opt_offset:opt_offset + 4])
                            opt_offset += 4
                            if code == 0:
                                break
                            value = body[opt_offset:opt_offset + length]
                            opt_offset += (length + 3) & ~3
                            if code == 5 and len(value) >= 8:  # isb_ifdrop
                                stats["dropcount"] = struct.unpack(f"{endian}Q", value[:8])[0]
                    handle.seek(4, 1)
                    continue

                handle.seek(block_len - 8, 1)
    except Exception:
        return interfaces

    for iface_id, stats in if_stats.items():
        if 0 <= iface_id < len(interfaces):
            interfaces[iface_id].update(stats)

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
        parsed_interfaces = _read_pcapng_interfaces(path)
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

    return PcapMeta(
        path=path,
        file_type=file_type,
        size_bytes=size_bytes,
        linktype=linktype,
        snaplen=snaplen,
        interfaces=interfaces,
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


def _cache_config() -> tuple[bool, int, int]:
    enabled = os.environ.get("PCAPPER_CACHE_ENABLED", "1") != "0"
    try:
        max_cache = int(os.environ.get("PCAPPER_CACHE_MAX_BYTES", str(256 * 1024 * 1024)))
    except Exception:
        max_cache = 256 * 1024 * 1024
    try:
        max_file = int(os.environ.get("PCAPPER_CACHE_FILE_MAX_BYTES", str(64 * 1024 * 1024)))
    except Exception:
        max_file = 64 * 1024 * 1024
    if max_cache < 0:
        max_cache = 0
    if max_file < 0:
        max_file = 0
    return enabled, max_cache, max_file


def get_cache_config() -> tuple[bool, int, int]:
    return _cache_config()


def load_packets(path: Path, show_status: bool = True) -> tuple[list[object], PcapMeta]:
    file_type = detect_file_type(path)
    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        size_bytes = 0

    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))
    status = build_statusbar(path, enabled=show_status)
    stream = _reader_stream(reader)
    linktype = getattr(reader, "linktype", None)
    snaplen = getattr(reader, "snaplen", None)
    interfaces = getattr(reader, "interfaces", None)
    linktype = getattr(reader, "linktype", None)
    snaplen = getattr(reader, "snaplen", None)
    interfaces = getattr(reader, "interfaces", None)
    linktype = getattr(reader, "linktype", None)
    snaplen = getattr(reader, "snaplen", None)
    interfaces = getattr(reader, "interfaces", None)

    packets: list[object] = []
    try:
        for pkt in reader:
            packets.append(pkt)
            if status.enabled and stream is not None and size_bytes:
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


def get_cached_packets(path: Path, show_status: bool = True) -> tuple[list[object], PcapMeta]:
    global _CACHE_BYTES
    cached = _PACKET_CACHE.get(path)
    if cached:
        _PACKET_CACHE.move_to_end(path)
        return cached
    packets, meta = load_packets(path, show_status=show_status)
    size_bytes = max(0, int(getattr(meta, "size_bytes", 0) or 0))
    enabled, max_cache, _max_file = _cache_config()
    if not enabled or max_cache == 0:
        return packets, meta
    while _PACKET_CACHE and _CACHE_BYTES + size_bytes > max_cache:
        _, evicted = _PACKET_CACHE.popitem(last=False)
        evicted_meta = evicted[1]
        evicted_size = max(0, int(getattr(evicted_meta, "size_bytes", 0) or 0))
        _CACHE_BYTES = max(0, _CACHE_BYTES - evicted_size)
    _PACKET_CACHE[path] = (packets, meta)
    _CACHE_BYTES += size_bytes
    return packets, meta


def load_packets_if_allowed(
    path: Path,
    show_status: bool = True,
    *,
    max_file_override: int | None = None,
) -> tuple[list[object], PcapMeta] | tuple[None, None]:
    enabled, max_cache, max_file = _cache_config()
    if max_file_override is not None:
        try:
            max_file = max(max_file, int(max_file_override))
        except Exception:
            pass
    if not enabled or max_cache <= 0 or max_file <= 0:
        return None, None
    try:
        size_bytes = path.stat().st_size
    except Exception:
        size_bytes = 0
    if size_bytes and size_bytes > max_file:
        return None, None
    return get_cached_packets(path, show_status=show_status)


def load_filtered_packets(
    path: Path,
    *,
    show_status: bool = True,
    bpf: str | None = None,
    time_start: float | None = None,
    time_end: float | None = None,
    bpf_status: dict[str, object] | None = None,
) -> tuple[list[object], PcapMeta]:
    file_type = detect_file_type(path)
    try:
        size_bytes = path.stat().st_size
    except Exception:
        size_bytes = 0

    if bpf and sniff is not None:
        try:
            status = build_busy_statusbar(path, enabled=show_status, desc="Filtering")
            with status:
                packets = list(sniff(offline=str(path), filter=bpf))
            if bpf_status is not None:
                bpf_status["used_bpf"] = True
            if time_start is not None or time_end is not None:
                filtered: list[object] = []
                for pkt in packets:
                    ts = getattr(pkt, "time", None)
                    if ts is None:
                        continue
                    if time_start is not None and ts < time_start:
                        continue
                    if time_end is not None and ts > time_end:
                        continue
                    filtered.append(pkt)
                packets = filtered
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

    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))
    status = build_statusbar(path, enabled=show_status)
    stream = _reader_stream(reader)
    packets: list[object] = []
    try:
        for pkt in reader:
            if status.enabled and stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass
            if time_start is not None or time_end is not None:
                ts = getattr(pkt, "time", None)
                if ts is None:
                    continue
                if time_start is not None and ts < time_start:
                    continue
                if time_end is not None and ts > time_end:
                    continue
            packets.append(pkt)
    finally:
        status.finish()
        reader.close()

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
    return path in _PACKET_CACHE


def get_reader(
    path: Path,
    *,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    show_status: bool = True,
) -> tuple[object, object, Optional[object], int, str]:
    if packets is not None:
        size_bytes = len(packets)
        reader = PacketListReader(packets, meta)
        status = build_statusbar(path, enabled=show_status)
        return reader, status, reader, size_bytes, (meta.file_type if meta else detect_file_type(path))

    enabled, max_cache, max_file = _cache_config()
    file_type = meta.file_type if meta else detect_file_type(path)
    try:
        size_bytes = meta.size_bytes if meta else path.stat().st_size
    except Exception:
        size_bytes = 0

    cache_allowed = enabled and max_cache > 0 and max_file > 0 and (size_bytes == 0 or size_bytes <= max_file)
    if cache_allowed:
        cached_packets, cached_meta = get_cached_packets(path, show_status=show_status)
        reader = PacketListReader(cached_packets, cached_meta)
        status = build_statusbar(path, enabled=show_status)
        return reader, status, reader, len(cached_packets), cached_meta.file_type

    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))
    status = build_statusbar(path, enabled=show_status)
    stream = _reader_stream(reader)
    return reader, status, stream, size_bytes, file_type
