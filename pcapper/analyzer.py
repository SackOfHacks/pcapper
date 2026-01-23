from __future__ import annotations

from collections import Counter, defaultdict
from numbers import Real
from pathlib import Path
from typing import Iterable, Optional

from scapy.utils import PcapReader, PcapNgReader

try:
    from scapy.layers.l2 import Dot1Q  # type: ignore
except Exception:  # pragma: no cover
    Dot1Q = None  # type: ignore

from .models import InterfaceStat, PcapSummary
from .progress import build_statusbar
from .utils import detect_file_type


IGNORE_LAYERS = {"Raw", "Padding", "NoPayload"}


def _layer_names(packet) -> Iterable[str]:
    for layer in packet.layers():
        name = layer.__name__
        if name not in IGNORE_LAYERS:
            yield name


def _get_iface_name(pkt) -> Optional[str]:
    iface = getattr(pkt, "sniffed_on", None)
    if iface:
        return str(iface)
    return None


def _get_iface_key(pkt) -> Optional[object]:
    iface = _get_iface_name(pkt)
    if iface:
        return iface

    for attr in ("interface", "iface", "ifname", "if_name", "ifindex", "if_id", "ifid"):
        value = getattr(pkt, attr, None)
        if value is not None:
            return value

    metadata = getattr(pkt, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("ifname", "interface", "iface", "if_name", "ifindex", "if_id", "ifid"):
            if key in metadata and metadata[key] is not None:
                return metadata[key]
    return None


def _normalize_iface_name(value: object) -> str:
    return str(value) if value is not None else "unknown"


def analyze_pcap(path: Path, show_status: bool = True) -> PcapSummary:
    file_type = detect_file_type(path)
    size_bytes = path.stat().st_size
    packet_count = 0
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    protocol_counts: Counter[str] = Counter()
    iface_counts = defaultdict(int)
    iface_vlans = defaultdict(set)

    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))
    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    try:
        for pkt in reader:
            packet_count += 1
            ts = getattr(pkt, "time", None)
            ts_value: Optional[float] = None
            if isinstance(ts, Real):
                ts_value = float(ts)
            elif ts is not None:
                try:
                    ts_value = float(ts)
                except (TypeError, ValueError):
                    ts_value = None

            if ts_value is not None:
                if start_ts is None or ts_value < start_ts:
                    start_ts = ts_value
                if end_ts is None or ts_value > end_ts:
                    end_ts = ts_value

            iface_key = _get_iface_key(pkt)
            if iface_key is None:
                iface_key = "unknown"
            iface_counts[iface_key] += 1

            if Dot1Q is not None:
                try:
                    if pkt.haslayer(Dot1Q):  # type: ignore[truthy-bool]
                        vlan_layer = pkt[Dot1Q]  # type: ignore[index]
                        vlan_id = int(getattr(vlan_layer, "vlan", 0) or 0)
                        if vlan_id > 0:
                            iface_vlans[iface_key].add(vlan_id)
                except Exception:
                    pass

            for name in set(_layer_names(pkt)):
                protocol_counts[name] += 1

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

    duration_seconds = None
    if start_ts is not None and end_ts is not None:
        duration_seconds = max(0.0, end_ts - start_ts)

    interface_stats: list[InterfaceStat] = []

    def _collect_iface_counts(keys: list[object]) -> tuple[Optional[int], list[int]]:
        total: Optional[int] = None
        vlan_ids: set[int] = set()
        for key in keys:
            if total is None and key in iface_counts:
                total = iface_counts.get(key, 0)
            vlan_ids.update(iface_vlans.get(key, set()))
        return total, sorted(vlan_ids)

    interfaces = getattr(reader, "interfaces", None)
    if interfaces and len(interfaces) > 0:
        for idx, iface in enumerate(interfaces):
            name = getattr(iface, "name", None) or getattr(iface, "if_name", None) or f"if{idx}"
            linktype = getattr(iface, "linktype", None)
            snaplen = getattr(iface, "snaplen", None)
            description = getattr(iface, "description", None) or getattr(iface, "if_description", None)
            speed = getattr(iface, "speed", None) or getattr(iface, "if_speed", None)
            mac = getattr(iface, "mac", None) or getattr(iface, "if_macaddr", None) or getattr(iface, "if_mac", None)
            os = getattr(iface, "os", None) or getattr(iface, "if_os", None)

            iface_keys = [name, str(name), idx, str(idx)]
            iface_count, vlan_ids = _collect_iface_counts(iface_keys)
            speed_bps: Optional[int] = None
            if isinstance(speed, Real):
                try:
                    speed_bps = int(speed)
                except Exception:
                    speed_bps = None
            elif speed is not None:
                try:
                    speed_bps = int(float(speed))
                except Exception:
                    speed_bps = None

            interface_stats.append(
                InterfaceStat(
                    name=_normalize_iface_name(name),
                    linktype=str(linktype) if linktype is not None else None,
                    snaplen=snaplen,
                    packet_count=iface_count,
                    description=str(description) if description else None,
                    speed_bps=speed_bps,
                    mac=str(mac) if mac else None,
                    os=str(os) if os else None,
                    vlan_ids=vlan_ids,
                )
            )
    else:
        linktype = getattr(reader, "linktype", None)
        snaplen = getattr(reader, "snaplen", None)
        observed_ifaces = list(iface_counts.keys()) or ["unknown"]
        for iface_key in sorted(observed_ifaces, key=lambda value: str(value)):
            iface_count, vlan_ids = _collect_iface_counts([iface_key])
            interface_stats.append(
                InterfaceStat(
                    name=_normalize_iface_name(iface_key),
                    linktype=str(linktype) if linktype is not None else None,
                    snaplen=snaplen,
                    packet_count=iface_count or (packet_count if packet_count else None),
                    description=None,
                    speed_bps=None,
                    mac=None,
                    os=None,
                    vlan_ids=vlan_ids,
                )
            )

    return PcapSummary(
        path=path,
        file_type=file_type,
        size_bytes=size_bytes,
        packet_count=packet_count,
        start_ts=start_ts,
        end_ts=end_ts,
        duration_seconds=duration_seconds,
        interface_stats=interface_stats,
        protocol_counts=protocol_counts,
    )
