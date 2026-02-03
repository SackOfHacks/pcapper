from __future__ import annotations

from dataclasses import dataclass
import struct
from pathlib import Path
from typing import Iterable, Optional

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import detect_file_type


_PACKET_CACHE: dict[Path, tuple[list[object], "PcapMeta"]] = {}


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
            data = handle.read()
    except Exception:
        return interfaces

    offset = 0
    data_len = len(data)
    endian = "<"
    while offset + 12 <= data_len:
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            if offset + 16 <= data_len:
                bom = struct.unpack("<I", data[offset + 8:offset + 12])[0]
                if bom == 0x1A2B3C4D:
                    endian = "<"
                elif bom == 0x4D3C2B1A:
                    endian = ">"
        try:
            block_type, block_len = struct.unpack(f"{endian}II", data[offset:offset + 8])
        except Exception:
            break
        if block_len < 12 or offset + block_len > data_len:
            break
        body = data[offset + 8:offset + block_len - 4]

        if block_type == 0x00000001 and len(body) >= 8:
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

        elif block_type == 0x00000005 and len(body) >= 12:
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

        offset += block_len

    for iface_id, stats in if_stats.items():
        if 0 <= iface_id < len(interfaces):
            interfaces[iface_id].update(stats)

    return interfaces


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

    def __iter__(self):
        return iter(self._packets)

    def __len__(self) -> int:
        return len(self._packets)

    def close(self) -> None:
        return None


def load_packets(path: Path, show_status: bool = True) -> tuple[list[object], PcapMeta]:
    file_type = detect_file_type(path)
    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        size_bytes = 0

    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))
    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    packets: list[object] = []
    try:
        for pkt in reader:
            packets.append(pkt)
            if stream is not None and size_bytes:
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

    meta = PcapMeta(
        path=path,
        file_type=file_type,
        size_bytes=size_bytes,
        linktype=linktype,
        snaplen=snaplen,
        interfaces=interfaces,
    )
    return packets, meta


def get_cached_packets(path: Path, show_status: bool = True) -> tuple[list[object], PcapMeta]:
    cached = _PACKET_CACHE.get(path)
    if cached:
        return cached
    packets, meta = load_packets(path, show_status=show_status)
    _PACKET_CACHE[path] = (packets, meta)
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
        size_bytes = meta.size_bytes if meta else 0
        reader = PacketListReader(packets, meta)
        status = build_statusbar(path, enabled=show_status)
        return reader, status, None, size_bytes, (meta.file_type if meta else detect_file_type(path))

    cached_packets, cached_meta = get_cached_packets(path, show_status=show_status)
    reader = PacketListReader(cached_packets, cached_meta)
    status = build_statusbar(path, enabled=False)
    return reader, status, None, cached_meta.size_bytes, cached_meta.file_type
