from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_cached_packets, PcapMeta


@dataclass(frozen=True)
class PcapMetaSummary:
    path: Path
    file_type: str
    size_bytes: int
    linktype: Optional[int]
    snaplen: Optional[int]
    interface_count: int
    interface_names: list[str]
    interface_details: list[dict[str, object]]
    dropcount: Optional[int]
    errors: list[str]


def analyze_pcapmeta(path: Path, show_status: bool = True) -> PcapMetaSummary:
    errors: list[str] = []
    try:
        _packets, meta = get_cached_packets(path, show_status=show_status)
    except Exception as exc:
        return PcapMetaSummary(
            path=path,
            file_type="unknown",
            size_bytes=0,
            linktype=None,
            snaplen=None,
            interface_count=0,
            interface_names=[],
            interface_details=[],
            dropcount=None,
            errors=[f"Error reading pcap metadata: {exc}"],
        )

    linktype = int(meta.linktype) if isinstance(meta.linktype, int) else None
    snaplen = int(meta.snaplen) if isinstance(meta.snaplen, int) else None
    interfaces: list[dict[str, object]] = []
    interface_names: list[str] = []
    dropcount: Optional[int] = None

    if isinstance(meta.interfaces, list):
        for iface in meta.interfaces:
            if isinstance(iface, dict):
                interfaces.append(dict(iface))
                name = iface.get("if_name") or iface.get("if_description") or iface.get("name")
                if name:
                    interface_names.append(str(name))
                if iface.get("dropcount") is not None:
                    try:
                        dropcount = int(iface.get("dropcount"))
                    except Exception:
                        pass
            else:
                interfaces.append({"detail": str(iface)})

    return PcapMetaSummary(
        path=path,
        file_type=meta.file_type,
        size_bytes=meta.size_bytes,
        linktype=linktype,
        snaplen=snaplen,
        interface_count=len(interfaces),
        interface_names=sorted(set(interface_names)),
        interface_details=interfaces,
        dropcount=dropcount,
        errors=errors,
    )
