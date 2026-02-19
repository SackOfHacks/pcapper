from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import struct

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    Ether = None  # type: ignore


SV_ETHERTYPE = 0x88BA

SV_TAGS = {
    0x80: "svID",
    0x82: "smpCnt",
    0x83: "confRev",
    0x85: "smpSynch",
    0x87: "seqOfData",
}

SV_STRING_TAGS = {"svID"}
SV_INT_TAGS = {"smpCnt", "confRev", "smpSynch"}


@dataclass(frozen=True)
class SvSummary:
    path: Path
    total_packets: int
    sv_packets: int
    src_macs: Counter[str]
    dst_macs: Counter[str]
    app_ids: Counter[str]
    lengths: Counter[int]
    sv_ids: Counter[str]
    smp_counts: Counter[int]
    conf_revs: Counter[int]
    seq_data_lengths: Counter[int]
    data_type_counts: Counter[str]
    data_value_samples: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _extract_appid(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[0:2], "big")


def _extract_length(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[2:4], "big")


def _read_ber_length(data: bytes, idx: int) -> tuple[Optional[int], int]:
    if idx >= len(data):
        return None, idx
    first = data[idx]
    idx += 1
    if (first & 0x80) == 0:
        return first, idx
    count = first & 0x7F
    if count == 0 or idx + count > len(data):
        return None, idx
    length = int.from_bytes(data[idx:idx + count], "big")
    idx += count
    return length, idx


def _parse_sv_tlvs(data: bytes, result: dict[str, object], depth: int = 0) -> None:
    if depth > 4:
        return
    idx = 0
    while idx < len(data):
        tag = data[idx]
        idx += 1
        length, idx = _read_ber_length(data, idx)
        if length is None or idx + length > len(data):
            break
        value = data[idx:idx + length]
        idx += length
        tag_name = SV_TAGS.get(tag)
        if tag_name:
            if tag_name in SV_STRING_TAGS:
                result[tag_name] = value.decode("utf-8", errors="ignore").strip("\x00")
            elif tag_name in SV_INT_TAGS:
                result[tag_name] = int.from_bytes(value, "big") if value else 0
            elif tag_name == "seqOfData":
                result["seqOfData_len"] = len(value)
                result["seqOfData_preview"] = value[:16].hex()
                dtype, values = _decode_seq_of_data(value)
                result["seqOfData_type"] = dtype
                result["seqOfData_values"] = values
        if tag == 0x60 or (tag & 0x20):
            _parse_sv_tlvs(value, result, depth + 1)


def _decode_seq_of_data(value: bytes) -> tuple[str, list[str]]:
    if not value:
        return "empty", []
    values: list[str] = []
    if len(value) % 4 == 0:
        for idx in range(0, min(len(value), 4 * 8), 4):
            try:
                val = struct.unpack(">i", value[idx:idx + 4])[0]
            except Exception:
                val = int.from_bytes(value[idx:idx + 4], "big", signed=True)
            values.append(str(val))
        return "int32", values
    if len(value) % 2 == 0:
        for idx in range(0, min(len(value), 2 * 8), 2):
            val = int.from_bytes(value[idx:idx + 2], "big", signed=True)
            values.append(str(val))
        return "int16", values
    return "bytes", [value[:16].hex()]


def _parse_sv_payload(payload: bytes) -> dict[str, object]:
    result: dict[str, object] = {}
    if len(payload) < 8:
        return result
    data = payload[8:]
    _parse_sv_tlvs(data, result)
    return result


def analyze_sv(path: Path, show_status: bool = True) -> SvSummary:
    if Ether is None:
        return SvSummary(
            path,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            [],
            ["Scapy Ether unavailable"],
            None,
            None,
            None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    sv_packets = 0
    src_macs: Counter[str] = Counter()
    dst_macs: Counter[str] = Counter()
    app_ids: Counter[str] = Counter()
    lengths: Counter[int] = Counter()
    sv_ids: Counter[str] = Counter()
    smp_counts: Counter[int] = Counter()
    conf_revs: Counter[int] = Counter()
    seq_data_lengths: Counter[int] = Counter()
    data_type_counts: Counter[str] = Counter()
    data_value_samples: Counter[str] = Counter()
    src_appids: dict[str, set[str]] = {}
    unicast_dsts: set[str] = set()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    smp_state: dict[tuple[str, str], int] = {}

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if not pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                continue
            eth = pkt[Ether]  # type: ignore[index]
            eth_type = int(getattr(eth, "type", 0) or 0)
            if eth_type != SV_ETHERTYPE:
                continue

            sv_packets += 1
            src_mac = str(getattr(eth, "src", "-"))
            dst_mac = str(getattr(eth, "dst", "-"))
            src_macs[src_mac] += 1
            dst_macs[dst_mac] += 1
            try:
                first_octet = int(dst_mac.split(":")[0], 16)
                if (first_octet & 1) == 0:
                    unicast_dsts.add(dst_mac)
            except Exception:
                pass
            try:
                payload = bytes(eth.payload)
            except Exception:
                payload = b""
            appid = _extract_appid(payload)
            if appid is not None:
                appid_label = f"0x{appid:04x}"
                app_ids[appid_label] += 1
                src_appids.setdefault(src_mac, set()).add(appid_label)
            length = _extract_length(payload)
            if length is not None:
                lengths[length] += 1

            sv_info = _parse_sv_payload(payload) if payload else {}
            sv_id = str(sv_info.get("svID", "") or "")
            smp_cnt = sv_info.get("smpCnt")
            conf_rev = sv_info.get("confRev")
            if sv_id:
                sv_ids[sv_id] += 1
            if isinstance(smp_cnt, int):
                smp_counts[smp_cnt] += 1
                if appid is not None:
                    key = (src_mac, f"0x{appid:04x}")
                    prev = smp_state.get(key)
                    if prev is not None and smp_cnt < prev:
                        detections.append({
                            "severity": "warning",
                            "summary": "SV Sample Counter Decrease",
                            "details": f"{key[0]} appid {key[1]} smpCnt decreased {prev}->{smp_cnt}.",
                        })
                    smp_state[key] = smp_cnt
            if isinstance(conf_rev, int):
                conf_revs[conf_rev] += 1
            seq_len = sv_info.get("seqOfData_len")
            seq_type = sv_info.get("seqOfData_type")
            seq_values = sv_info.get("seqOfData_values") or []
            if isinstance(seq_len, int):
                seq_data_lengths[seq_len] += 1
            if seq_type:
                data_type_counts[str(seq_type)] += 1
            for value in seq_values[:8]:
                data_value_samples[f"{seq_type}={value}"] += 1

    finally:
        status.finish()
        reader.close()

    if sv_packets:
        detections.append({
            "severity": "info",
            "summary": "IEC 61850 Sampled Values traffic observed",
            "details": f"{sv_packets} SV frames detected at L2.",
        })
    for src_mac, appid_set in src_appids.items():
        if len(appid_set) >= 5:
            detections.append({
                "severity": "warning",
                "summary": "SV Source Uses Many AppIDs",
                "details": f"{src_mac} advertised {len(appid_set)} AppIDs (possible spoofing or misconfiguration).",
            })
    if unicast_dsts:
        detections.append({
            "severity": "warning",
            "summary": "SV Unicast Destinations",
            "details": f"Unicast MAC destinations observed: {', '.join(sorted(unicast_dsts)[:5])}.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return SvSummary(
        path=path,
        total_packets=total_packets,
        sv_packets=sv_packets,
        src_macs=src_macs,
        dst_macs=dst_macs,
        app_ids=app_ids,
        lengths=lengths,
        sv_ids=sv_ids,
        smp_counts=smp_counts,
        conf_revs=conf_revs,
        seq_data_lengths=seq_data_lengths,
        data_type_counts=data_type_counts,
        data_value_samples=data_value_samples,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
