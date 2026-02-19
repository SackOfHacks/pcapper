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


GOOSE_ETHERTYPE = 0x88B8

GOOSE_TAGS = {
    0x80: "gocbRef",
    0x81: "timeAllowedToLive",
    0x82: "datSet",
    0x83: "goID",
    0x84: "t",
    0x85: "stNum",
    0x86: "sqNum",
    0x87: "simulation",
    0x88: "confRev",
    0x89: "ndsCom",
    0x8A: "numDatSetEntries",
    0x8B: "allData",
}

GOOSE_STRING_TAGS = {"gocbRef", "datSet", "goID"}
GOOSE_INT_TAGS = {"timeAllowedToLive", "stNum", "sqNum", "confRev", "numDatSetEntries"}

GOOSE_DATA_TAGS = {
    0x80: "boolean",
    0x81: "bit-string",
    0x82: "integer",
    0x83: "unsigned",
    0x84: "float",
    0x85: "octet-string",
    0x86: "visible-string",
    0x87: "generalized-time",
    0x88: "binary-time",
    0x89: "bcd",
    0x8A: "boolean-array",
}


@dataclass(frozen=True)
class GooseSummary:
    path: Path
    total_packets: int
    goose_packets: int
    src_macs: Counter[str]
    dst_macs: Counter[str]
    app_ids: Counter[str]
    lengths: Counter[int]
    datasets: Counter[str]
    gocb_refs: Counter[str]
    st_nums: Counter[int]
    sq_nums: Counter[int]
    num_entries: Counter[int]
    all_data_lengths: Counter[int]
    conf_revs: Counter[int]
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


def _parse_goose_tlvs(data: bytes, result: dict[str, object], depth: int = 0) -> None:
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

        tag_name = GOOSE_TAGS.get(tag)
        if tag_name:
            if tag_name in GOOSE_STRING_TAGS:
                result[tag_name] = value.decode("utf-8", errors="ignore").strip("\x00")
            elif tag_name in GOOSE_INT_TAGS:
                result[tag_name] = int.from_bytes(value, "big") if value else 0
            elif tag_name == "allData":
                result["allData_len"] = len(value)
                result["allData_preview"] = value[:16].hex()
                result["allData_values"] = _decode_all_data(value)
        if tag == 0x61 or (tag & 0x20):
            _parse_goose_tlvs(value, result, depth + 1)


def _decode_boolean(value: bytes) -> Optional[bool]:
    if not value:
        return None
    return bool(value[0])


def _decode_integer(value: bytes, signed: bool) -> Optional[int]:
    if not value:
        return None
    return int.from_bytes(value, "big", signed=signed)


def _decode_float(value: bytes) -> Optional[float]:
    if len(value) == 4:
        try:
            return struct.unpack(">f", value)[0]
        except Exception:
            return None
    if len(value) == 8:
        try:
            return struct.unpack(">d", value)[0]
        except Exception:
            return None
    return None


def _decode_bit_string(value: bytes) -> str:
    if not value:
        return ""
    unused_bits = value[0]
    bits = "".join(f"{b:08b}" for b in value[1:])
    if unused_bits:
        bits = bits[:-unused_bits]
    return bits


def _decode_all_data(data: bytes, depth: int = 0, limit: int = 24) -> list[tuple[str, str]]:
    if depth > 4 or not data:
        return []
    values: list[tuple[str, str]] = []
    idx = 0
    while idx < len(data) and len(values) < limit:
        tag = data[idx]
        idx += 1
        length, idx = _read_ber_length(data, idx)
        if length is None or idx + length > len(data):
            break
        value = data[idx:idx + length]
        idx += length

        if tag & 0x20:
            values.extend(_decode_all_data(value, depth + 1, limit - len(values)))
            continue

        dtype = GOOSE_DATA_TAGS.get(tag)
        decoded: Optional[str] = None
        if dtype == "boolean":
            val = _decode_boolean(value)
            decoded = str(val).lower() if val is not None else None
        elif dtype == "bit-string":
            decoded = _decode_bit_string(value)
        elif dtype == "integer":
            val = _decode_integer(value, signed=True)
            decoded = str(val) if val is not None else None
        elif dtype == "unsigned":
            val = _decode_integer(value, signed=False)
            decoded = str(val) if val is not None else None
        elif dtype == "float":
            val = _decode_float(value)
            decoded = f"{val:.6g}" if val is not None else None
        elif dtype in {"octet-string", "binary-time"}:
            decoded = value.hex()
        elif dtype in {"visible-string", "generalized-time"}:
            decoded = value.decode("utf-8", errors="ignore").strip("\x00")
        elif dtype == "bcd":
            decoded = value.hex()
        elif dtype == "boolean-array":
            decoded = _decode_bit_string(value)
        else:
            # Try universal tags as a fallback
            if tag == 0x01:
                val = _decode_boolean(value)
                decoded = str(val).lower() if val is not None else None
                dtype = "boolean"
            elif tag == 0x02:
                val = _decode_integer(value, signed=True)
                decoded = str(val) if val is not None else None
                dtype = "integer"
            elif tag == 0x03:
                decoded = _decode_bit_string(value)
                dtype = "bit-string"
            elif tag == 0x04:
                decoded = value.hex()
                dtype = "octet-string"
            elif tag == 0x09:
                val = _decode_float(value)
                decoded = f"{val:.6g}" if val is not None else None
                dtype = "float"

        if dtype and decoded is not None:
            values.append((dtype, decoded))
    return values


def _parse_goose_payload(payload: bytes) -> dict[str, object]:
    result: dict[str, object] = {}
    if len(payload) < 8:
        return result
    data = payload[8:]
    _parse_goose_tlvs(data, result)
    return result


def analyze_goose(path: Path, show_status: bool = True) -> GooseSummary:
    if Ether is None:
        return GooseSummary(
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
    goose_packets = 0
    src_macs: Counter[str] = Counter()
    dst_macs: Counter[str] = Counter()
    app_ids: Counter[str] = Counter()
    lengths: Counter[int] = Counter()
    datasets: Counter[str] = Counter()
    gocb_refs: Counter[str] = Counter()
    st_nums: Counter[int] = Counter()
    sq_nums: Counter[int] = Counter()
    num_entries: Counter[int] = Counter()
    all_data_lengths: Counter[int] = Counter()
    conf_revs: Counter[int] = Counter()
    data_type_counts: Counter[str] = Counter()
    data_value_samples: Counter[str] = Counter()
    src_appids: dict[str, set[str]] = {}
    unicast_dsts: set[str] = set()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    state_map: dict[tuple[str, str, str], tuple[int, int]] = {}
    conf_map: dict[tuple[str, str, str], int] = {}
    entries_map: dict[tuple[str, str, str], int] = {}
    data_len_map: dict[tuple[str, str, str], int] = {}

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
            if eth_type != GOOSE_ETHERTYPE:
                continue

            goose_packets += 1
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

            goose_info = _parse_goose_payload(payload) if payload else {}
            dataset = str(goose_info.get("datSet", "") or "")
            gocb_ref = str(goose_info.get("gocbRef", "") or "")
            st_num = goose_info.get("stNum")
            sq_num = goose_info.get("sqNum")
            conf_rev = goose_info.get("confRev")
            num_entries_val = goose_info.get("numDatSetEntries")
            data_len = goose_info.get("allData_len")
            data_values = goose_info.get("allData_values") or []
            if dataset:
                datasets[dataset] += 1
            if gocb_ref:
                gocb_refs[gocb_ref] += 1
            if isinstance(st_num, int):
                st_nums[st_num] += 1
            if isinstance(sq_num, int):
                sq_nums[sq_num] += 1
            if isinstance(conf_rev, int):
                conf_revs[conf_rev] += 1
            if isinstance(num_entries_val, int):
                num_entries[num_entries_val] += 1
            if isinstance(data_len, int):
                all_data_lengths[data_len] += 1
            if data_values:
                for dtype, value in data_values[:16]:
                    data_type_counts[str(dtype)] += 1
                    sample = f"{dtype}={value}"
                    data_value_samples[sample] += 1

            if appid is not None and isinstance(st_num, int) and isinstance(sq_num, int):
                key = (src_mac, f"0x{appid:04x}", dataset or gocb_ref or "-")
                prev = state_map.get(key)
                if prev:
                    prev_st, prev_sq = prev
                    if st_num < prev_st:
                        detections.append({
                            "severity": "warning",
                            "summary": "GOOSE State Number Decrease",
                            "details": f"{key[0]} {key[2]} stNum decreased {prev_st}->{st_num}.",
                        })
                    if st_num == prev_st and sq_num < prev_sq:
                        detections.append({
                            "severity": "warning",
                            "summary": "GOOSE Sequence Reset",
                            "details": f"{key[0]} {key[2]} sqNum decreased {prev_sq}->{sq_num}.",
                        })
                state_map[key] = (st_num, sq_num)
                if isinstance(conf_rev, int):
                    prev_conf = conf_map.get(key)
                    if prev_conf is not None and conf_rev != prev_conf:
                        detections.append({
                            "severity": "warning",
                            "summary": "GOOSE Config Revision Change",
                            "details": f"{key[0]} {key[2]} confRev changed {prev_conf}->{conf_rev}.",
                        })
                    conf_map[key] = conf_rev
                if isinstance(num_entries_val, int):
                    prev_entries = entries_map.get(key)
                    if prev_entries is not None and num_entries_val != prev_entries:
                        detections.append({
                            "severity": "warning",
                            "summary": "GOOSE Dataset Size Change",
                            "details": f"{key[0]} {key[2]} numDatSetEntries changed {prev_entries}->{num_entries_val}.",
                        })
                    entries_map[key] = num_entries_val
                if isinstance(data_len, int):
                    prev_len = data_len_map.get(key)
                    if prev_len is not None and data_len != prev_len:
                        detections.append({
                            "severity": "warning",
                            "summary": "GOOSE Dataset Payload Size Change",
                            "details": f"{key[0]} {key[2]} allData length changed {prev_len}->{data_len}.",
                        })
                    data_len_map[key] = data_len

    finally:
        status.finish()
        reader.close()

    if goose_packets:
        detections.append({
            "severity": "info",
            "summary": "IEC 61850 GOOSE traffic observed",
            "details": f"{goose_packets} GOOSE frames detected at L2.",
        })
    for src_mac, appid_set in src_appids.items():
        if len(appid_set) >= 5:
            detections.append({
                "severity": "warning",
                "summary": "GOOSE Source Uses Many AppIDs",
                "details": f"{src_mac} advertised {len(appid_set)} AppIDs (possible spoofing or misconfiguration).",
            })
    if unicast_dsts:
        detections.append({
            "severity": "warning",
            "summary": "GOOSE Unicast Destinations",
            "details": f"Unicast MAC destinations observed: {', '.join(sorted(unicast_dsts)[:5])}.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return GooseSummary(
        path=path,
        total_packets=total_packets,
        goose_packets=goose_packets,
        src_macs=src_macs,
        dst_macs=dst_macs,
        app_ids=app_ids,
        lengths=lengths,
        datasets=datasets,
        gocb_refs=gocb_refs,
        st_nums=st_nums,
        sq_nums=sq_nums,
        num_entries=num_entries,
        all_data_lengths=all_data_lengths,
        conf_revs=conf_revs,
        data_type_counts=data_type_counts,
        data_value_samples=data_value_samples,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
