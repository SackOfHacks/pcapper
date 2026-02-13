from __future__ import annotations

from collections import Counter, defaultdict
from numbers import Real
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, get_reader

try:
    from scapy.layers.l2 import Dot1Q, Ether  # type: ignore
    from scapy.layers.inet import TCP, UDP  # type: ignore
except Exception:  # pragma: no cover
    Dot1Q = None  # type: ignore
    TCP = UDP = None  # type: ignore
    Ether = None  # type: ignore

from .models import InterfaceStat, PcapSummary
from .utils import detect_file_type
from .services import COMMON_PORTS


IGNORE_LAYERS = {"Raw", "Padding", "NoPayload"}

ETHERTYPE_PROTOCOLS = {
    0x88A4: "EtherCAT",
    0x8892: "PROFINET RT",
    0x88B8: "IEC 61850 GOOSE",
    0x88BA: "IEC 61850 SV",
    0x88F7: "HSR/PRP",
}


def _layer_names(packet) -> Iterable[str]:
    for layer in packet.layers():
        name = layer.__name__
        if name not in IGNORE_LAYERS:
            yield name


def _port_protocol_name(pkt) -> str | None:
    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        try:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        except Exception:
            return None
        return COMMON_PORTS.get(sport) or COMMON_PORTS.get(dport)
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        try:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        except Exception:
            return None
        return COMMON_PORTS.get(sport) or COMMON_PORTS.get(dport)
    return None


def _extract_ethertype(pkt) -> int | None:
    if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
        try:
            return int(pkt[Ether].type)
        except Exception:
            return None
    try:
        raw = bytes(pkt)
        if len(raw) >= 14:
            return int.from_bytes(raw[12:14], "big")
    except Exception:
        return None
    return None


def _ethertype_protocol_name(pkt) -> str | None:
    ethertype = _extract_ethertype(pkt)
    if ethertype is None:
        return None
    return ETHERTYPE_PROTOCOLS.get(ethertype)


def _get_iface_name(pkt) -> Optional[str]:
    iface = getattr(pkt, "sniffed_on", None)
    if iface:
        return str(iface)
    return None


def _get_iface_key(pkt) -> Optional[object]:
    iface = _get_iface_name(pkt)
    if iface:
        return iface

    for attr in ("interface", "iface", "ifname", "if_name", "ifindex", "if_index", "if_id", "ifid"):
        value = getattr(pkt, attr, None)
        if value is not None:
            return value

    metadata = getattr(pkt, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("ifname", "interface", "iface", "if_name", "ifindex", "if_index", "if_id", "ifid"):
            if key in metadata and metadata[key] is not None:
                return metadata[key]
    return None


def _normalize_iface_name(value: object) -> str:
    return str(value) if value is not None else "unknown"


def _as_text(value: object | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _iface_get(iface: object, *keys: str) -> object | None:
    for key in keys:
        if isinstance(iface, dict) and key in iface:
            return iface.get(key)
        if hasattr(iface, key):
            return getattr(iface, key)
    return None


def _as_int(value: object | None) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except Exception:
        return None


def analyze_pcap(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> PcapSummary:
    file_type = meta.file_type if meta else detect_file_type(path)
    size_bytes = meta.size_bytes if meta else path.stat().st_size
    packet_count = 0
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    protocol_counts: Counter[str] = Counter()
    iface_counts = defaultdict(int)
    iface_vlans = defaultdict(set)

    reader, status, stream, _size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

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

            port_proto = _port_protocol_name(pkt)
            ethertype_proto = _ethertype_protocol_name(pkt)
            layer_names = set(_layer_names(pkt))
            if port_proto:
                layer_names.discard("TCP")
                layer_names.discard("UDP")

            for name in layer_names:
                protocol_counts[name] += 1

            if port_proto:
                protocol_counts[port_proto] += 1
            if ethertype_proto:
                protocol_counts[ethertype_proto] += 1

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

    interfaces = meta.interfaces if meta else getattr(reader, "interfaces", None)
    if interfaces and len(interfaces) > 0:
        all_vlan_ids: set[int] = set()
        for vlan_set in iface_vlans.values():
            all_vlan_ids.update(vlan_set)
        for idx, iface in enumerate(interfaces):
            name = _iface_get(iface, "name", "if_name")
            description = _iface_get(iface, "description", "if_description")
            if not name and description:
                name = description
            if not name:
                name = f"if{idx}"
            linktype = _iface_get(iface, "linktype", "if_linktype")
            snaplen = _iface_get(iface, "snaplen", "if_snaplen")
            speed = _iface_get(iface, "speed", "if_speed")
            mac = _iface_get(iface, "mac", "if_macaddr", "if_mac")
            os = _iface_get(iface, "os", "if_os")
            dropcount = _iface_get(iface, "dropcount", "if_dropcount", "if_drops", "if_drop")
            capture_filter = _iface_get(iface, "filter", "if_filter")

            iface_id = _iface_get(iface, "id", "if_id", "ifid", "if_index", "ifindex")
            iface_keys = [name, str(name), idx, str(idx)]
            if iface_id is not None:
                iface_keys.extend([iface_id, str(iface_id)])
            iface_count, vlan_ids = _collect_iface_counts(iface_keys)
            if len(interfaces) == 1:
                if iface_count is None:
                    iface_count = packet_count if packet_count else None
                if not vlan_ids and all_vlan_ids:
                    vlan_ids = sorted(all_vlan_ids)
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
                    linktype=_as_text(linktype) or _as_text(meta.linktype if meta else None),
                    snaplen=snaplen if snaplen is not None else (meta.snaplen if meta else None),
                    packet_count=iface_count,
                    dropped_packets=_as_int(dropcount),
                    capture_filter=_as_text(capture_filter),
                    description=_as_text(description),
                    speed_bps=speed_bps,
                    mac=_as_text(mac),
                    os=_as_text(os),
                    vlan_ids=vlan_ids,
                )
            )
    else:
        linktype = meta.linktype if meta else getattr(reader, "linktype", None)
        snaplen = meta.snaplen if meta else getattr(reader, "snaplen", None)
        observed_ifaces = list(iface_counts.keys()) or ["unknown"]
        for iface_key in sorted(observed_ifaces, key=lambda value: str(value)):
            iface_count, vlan_ids = _collect_iface_counts([iface_key])
            interface_stats.append(
                InterfaceStat(
                    name=_normalize_iface_name(iface_key),
                    linktype=str(linktype) if linktype is not None else None,
                    snaplen=snaplen,
                    packet_count=iface_count or (packet_count if packet_count else None),
                    dropped_packets=None,
                    capture_filter=None,
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


def merge_pcap_summaries(summaries: list[PcapSummary]) -> PcapSummary:
    if not summaries:
        return PcapSummary(
            path=Path("ALL_PCAPS_0"),
            file_type="pcap",
            size_bytes=0,
            packet_count=0,
            start_ts=None,
            end_ts=None,
            duration_seconds=0.0,
            interface_stats=[],
            protocol_counts=Counter(),
        )

    file_types = {summary.file_type for summary in summaries if summary.file_type}
    merged_file_type = file_types.pop() if len(file_types) == 1 else "mixed"
    merged_size = sum(summary.size_bytes for summary in summaries)
    merged_packets = sum(summary.packet_count for summary in summaries)

    start_values = [summary.start_ts for summary in summaries if summary.start_ts is not None]
    end_values = [summary.end_ts for summary in summaries if summary.end_ts is not None]
    merged_start = min(start_values) if start_values else None
    merged_end = max(end_values) if end_values else None
    merged_duration = sum((summary.duration_seconds or 0.0) for summary in summaries)

    merged_protocols: Counter[str] = Counter()
    for summary in summaries:
        merged_protocols.update(summary.protocol_counts)

    iface_data: dict[str, dict[str, object]] = {}
    for summary in summaries:
        for iface in summary.interface_stats:
            data = iface_data.setdefault(
                iface.name,
                {
                    "linktypes": set(),
                    "snaplens": set(),
                    "packet_count": 0,
                    "dropped_packets": 0,
                    "has_dropped": False,
                    "capture_filters": set(),
                    "descriptions": set(),
                    "speeds": set(),
                    "macs": set(),
                    "oses": set(),
                    "vlan_ids": set(),
                },
            )

            if iface.linktype:
                data["linktypes"].add(iface.linktype)
            if iface.snaplen is not None:
                data["snaplens"].add(iface.snaplen)
            if iface.packet_count is not None:
                data["packet_count"] = int(data["packet_count"]) + iface.packet_count
            if iface.dropped_packets is not None:
                data["has_dropped"] = True
                data["dropped_packets"] = int(data["dropped_packets"]) + iface.dropped_packets
            if iface.capture_filter:
                data["capture_filters"].add(iface.capture_filter)
            if iface.description:
                data["descriptions"].add(iface.description)
            if iface.speed_bps is not None:
                data["speeds"].add(iface.speed_bps)
            if iface.mac:
                data["macs"].add(iface.mac)
            if iface.os:
                data["oses"].add(iface.os)
            data["vlan_ids"].update(iface.vlan_ids)

    merged_interfaces: list[InterfaceStat] = []
    for name in sorted(iface_data.keys()):
        data = iface_data[name]
        linktypes = sorted(data["linktypes"])
        snaplens = sorted(data["snaplens"])
        capture_filters = sorted(data["capture_filters"])
        descriptions = sorted(data["descriptions"])
        speeds = sorted(data["speeds"])
        macs = sorted(data["macs"])
        oses = sorted(data["oses"])
        vlan_ids = sorted(data["vlan_ids"])

        merged_interfaces.append(
            InterfaceStat(
                name=name,
                linktype=linktypes[0] if len(linktypes) == 1 else ("mixed" if linktypes else None),
                snaplen=snaplens[0] if len(snaplens) == 1 else (max(snaplens) if snaplens else None),
                packet_count=int(data["packet_count"]) if int(data["packet_count"]) > 0 else None,
                dropped_packets=int(data["dropped_packets"]) if bool(data["has_dropped"]) else None,
                capture_filter=(capture_filters[0] if len(capture_filters) == 1 else ("multiple" if capture_filters else None)),
                description=(descriptions[0] if len(descriptions) == 1 else ("multiple" if descriptions else None)),
                speed_bps=speeds[0] if len(speeds) == 1 else None,
                mac=macs[0] if len(macs) == 1 else None,
                os=oses[0] if len(oses) == 1 else None,
                vlan_ids=vlan_ids,
            )
        )

    return PcapSummary(
        path=Path(f"ALL_PCAPS_{len(summaries)}"),
        file_type=merged_file_type,
        size_bytes=merged_size,
        packet_count=merged_packets,
        start_ts=merged_start,
        end_ts=merged_end,
        duration_seconds=merged_duration,
        interface_stats=merged_interfaces,
        protocol_counts=merged_protocols,
    )
