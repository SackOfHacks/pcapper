from __future__ import annotations

import ipaddress
import math
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.packet import Raw
except ImportError:
    TCP = UDP = Raw = None

from .pcap_cache import get_reader
from .utils import extract_packet_endpoints, safe_float, memoize_analysis

# --- Constants ---

DNP3_PORT = 20000
DNP3_START_BYTES = b"\x05\x64"

# Application Layer Function Codes
FUNC_CODES = {
    0: "Confirm",
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate (No Ack)",
    7: "Immediate Freeze",
    8: "Immediate Freeze (No Ack)",
    9: "Freeze and Clear",
    10: "Freeze and Clear (No Ack)",
    11: "Freeze with Time",
    12: "Freeze with Time (No Ack)",
    13: "Cold Restart",
    14: "Warm Restart",
    15: "Initialize Data",
    16: "Initialize Application",
    17: "Start Application",
    18: "Stop Application",
    19: "Save Configuration",
    20: "Enable Unsolicited",
    21: "Disable Unsolicited",
    22: "Assign Class",
    23: "Delay Measurement",
    24: "Record Current Time",
    25: "Open File",
    26: "Close File",
    27: "Delete File",
    28: "Get File Info",
    29: "Authenticate File",
    30: "Abort File",
    31: "Activate Config",
    32: "Authenticate Req",
    33: "Authenticate Err",
    129: "Response",
    130: "Unsolicited Response",
}

CONTROL_FUNCTIONS = {2, 4, 5, 6}
FREEZE_FUNCTIONS = {7, 8, 9, 10, 11, 12}
RESTART_FUNCTIONS = {13, 14}
APP_CONTROL_FUNCTIONS = {15, 16, 17, 18, 19, 31}
UNSOLICITED_FUNCTIONS = {20, 21}
TIME_FUNCTIONS = {23, 24}
FILE_FUNCTIONS = {25, 26, 27, 28, 29, 30}
SAV5_FUNCTIONS = {32, 33}  # DNP3 Secure Authentication v5 (IEEE 1815-2012)
RESPONSE_FUNCTIONS = {129, 130}

# DNP3 Internal Indications (IIN) bits — present in outstation responses. The
# forensically interesting ones confirm device state (restart, trouble, local
# control) and request outcome (object unknown, parameter error, buffer overflow).
IIN1_BITS = {
    0x01: "Broadcast msg received",
    0x02: "Class 1 events available",
    0x04: "Class 2 events available",
    0x08: "Class 3 events available",
    0x10: "Need Time",
    0x20: "Local Control",
    0x40: "Device Trouble",
    0x80: "Device Restart",
}
IIN2_BITS = {
    0x01: "Function code not supported",
    0x02: "Object unknown",
    0x04: "Parameter error",
    0x08: "Event buffer overflow",
    0x10: "Operation already executing",
    0x20: "Configuration corrupt",
}
# IIN flags that are notable for triage (state/abuse signals, not routine
# class-data-available bits).
IIN_NOTABLE = {
    "Device Restart",
    "Device Trouble",
    "Local Control",
    "Configuration corrupt",
    "Event buffer overflow",
    "Operation already executing",
    "Function code not supported",
    "Parameter error",
    "Object unknown",
}

OBJECT_GROUPS = {
    1: "Binary Input",
    2: "Binary Input Event",
    3: "Double-Bit Binary Input",
    4: "Double-Bit Binary Input Event",
    10: "Binary Output",
    11: "Binary Output Event",
    12: "Control Relay Output Block",
    20: "Counter",
    21: "Counter Event",
    22: "Frozen Counter",
    23: "Frozen Counter Event",
    30: "Analog Input",
    31: "Analog Input Event",
    32: "Frozen Analog Input",
    33: "Frozen Analog Input Event",
    40: "Analog Output",
    41: "Analog Output Event",
    42: "Analog Output Command",
    50: "Time and Date",
    60: "Class Data",
    70: "File Control",
    80: "IIN",
    110: "Octet String",
}

CONTROL_OBJECT_GROUPS = {10, 11, 12, 40, 41, 42}
FILE_OBJECT_GROUPS = {70}

QUALIFIER_RANGE_SIZES = {0x00: 1, 0x01: 2, 0x02: 4}
QUALIFIER_COUNT_SIZES = {0x05: 1, 0x06: 2, 0x07: 4}

TIME_16 = 2
TIME_32 = 4
TIME_48 = 6

OBJECT_SIZES = {
    # Binary Input
    (1, 2): 1,  # flags only
    (1, 3): 1 + TIME_16,
    (1, 4): 1 + TIME_32,
    # Binary Input Event
    (2, 1): 1,  # no time
    (2, 2): 1 + TIME_48,
    (2, 3): 1 + TIME_16,
    # Double-Bit Binary Input
    (3, 2): 1,  # flags only
    (3, 3): 1 + TIME_16,
    (3, 4): 1 + TIME_32,
    # Double-Bit Binary Input Event
    (4, 1): 1,
    (4, 2): 1 + TIME_48,
    (4, 3): 1 + TIME_16,
    # Binary Output Status
    (10, 2): 1,
    (10, 3): 1 + TIME_16,
    (10, 4): 1 + TIME_32,
    # Binary Output Event
    (11, 1): 1,
    (11, 2): 1 + TIME_48,
    (11, 3): 1 + TIME_16,
    # Control Relay Output Block
    (12, 1): 11,
    (12, 2): 11,
    # Counter
    (20, 1): 5,
    (20, 2): 3,
    (20, 5): 4,
    (20, 6): 2,
    # Frozen Counter / Counter Event
    (21, 1): 5,
    (21, 2): 3,
    (21, 5): 5 + TIME_48,
    (21, 6): 3 + TIME_48,
    (21, 9): 4,
    (21, 10): 2,
    # Frozen Counter
    (22, 1): 5,
    (22, 2): 3,
    (22, 5): 4,
    (22, 6): 2,
    # Frozen Counter Event
    (23, 1): 5 + TIME_48,
    (23, 2): 3 + TIME_48,
    (23, 5): 5 + TIME_48,
    (23, 6): 3 + TIME_48,
    # Analog Input
    (30, 1): 5,
    (30, 2): 3,
    (30, 3): 4,
    (30, 4): 2,
    (30, 5): 5,
    (30, 6): 9,
    # Analog Input Event / Frozen Analog Input (best effort)
    (31, 1): 5 + TIME_48,
    (31, 2): 3 + TIME_48,
    (31, 3): 5 + TIME_48,
    (31, 4): 3 + TIME_48,
    (31, 5): 4,
    (31, 6): 2,
    (31, 7): 5,
    (31, 8): 9,
    # Frozen Analog Input / Analog Input Event (best effort)
    (32, 1): 5,
    (32, 2): 3,
    (32, 3): 5 + TIME_48,
    (32, 4): 3 + TIME_48,
    (32, 5): 5,
    (32, 6): 9,
    (32, 7): 5 + TIME_48,
    (32, 8): 9 + TIME_48,
    # Analog Output Status
    (40, 1): 5,
    (40, 2): 3,
    (40, 3): 5,
    (40, 4): 9,
    # Analog Output Event
    (41, 1): 5 + TIME_48,
    (41, 2): 3 + TIME_48,
    (41, 3): 5 + TIME_48,
    (41, 4): 9 + TIME_48,
    # Analog Output Command
    (42, 1): 5,
    (42, 2): 3,
    (42, 3): 5,
    (42, 4): 9,
    # Time and Date
    (50, 1): 6,
    (50, 2): 6,
    # IIN
    (80, 1): 2,
}

PACKED_BINARY_VARIATIONS = {(1, 1), (10, 1)}
PACKED_DOUBLE_VARIATIONS = {(3, 1)}


def _crc16_dnp(data: bytes) -> int:
    # DNP3 (IEEE 1815) link-layer CRC: poly 0x3D65 (0xA6BC reflected), initial
    # value 0x0000, reflected in/out, final one's-complement. The initial value
    # was 0xFFFF, which made *every* CRC wrong and raised a "CRC Mismatch" on
    # every valid DNP3 frame (hundreds of false LOW findings per capture).
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _check_crc(data: bytes, crc_bytes: bytes) -> bool:
    if len(crc_bytes) < 2:
        return False
    expected = int.from_bytes(crc_bytes[:2], "little")
    return _crc16_dnp(data) == expected


def _strip_crc_blocks(frame: bytes) -> tuple[bytes, bool]:
    if len(frame) <= 10:
        return b"", False
    data_with_crc = frame[10:]
    idx = 0
    out = bytearray()
    all_ok = True
    while idx < len(data_with_crc):
        remaining = len(data_with_crc) - idx
        if remaining < 3:
            break
        data_len = min(16, remaining - 2)
        data = data_with_crc[idx : idx + data_len]
        crc_bytes = data_with_crc[idx + data_len : idx + data_len + 2]
        if not _check_crc(data, crc_bytes):
            all_ok = False
        out.extend(data)
        idx += data_len + 2
    return bytes(out), all_ok


def _parse_dnp3_frames(payload: bytes) -> list[tuple[int, int, int, bytes, bool]]:
    frames: list[tuple[int, int, int, bytes, bool]] = []
    idx = 0
    while idx + 10 <= len(payload):
        start = payload.find(DNP3_START_BYTES, idx)
        if start < 0 or start + 10 > len(payload):
            break
        if start + 3 > len(payload):
            break
        length = payload[start + 2]
        # DNP3 LENGTH counts control+dst+src+user-data (= 5 + N), excluding the
        # start/length octets AND every CRC. The full frame on the wire is
        # 10 (header+header-CRC) + N user-data bytes + a 2-byte CRC per 16-byte
        # data block. The previous `start + 3 + length` stopped at the end of the
        # user data, truncating the data-block CRCs, so the data CRC check failed
        # on every valid multi-byte frame ("CRC Mismatch" flood).
        n_userdata = length - 5
        if n_userdata < 0:
            idx = start + 2
            continue
        n_blocks = (n_userdata + 15) // 16 if n_userdata > 0 else 0
        frame_end = start + 10 + n_userdata + 2 * n_blocks
        if frame_end > len(payload):
            break
        frame = payload[start:frame_end]
        if len(frame) < 10:
            idx = start + 2
            continue
        dl_ctrl = frame[3]
        dl_dst = struct.unpack("<H", frame[4:6])[0]
        dl_src = struct.unpack("<H", frame[6:8])[0]
        header_crc_ok = _check_crc(frame[0:8], frame[8:10])
        user_data, data_crc_ok = _strip_crc_blocks(frame)
        crc_ok = header_crc_ok and data_crc_ok
        frames.append((dl_src, dl_dst, dl_ctrl, user_data, crc_ok))
        idx = frame_end
    return frames


def _object_data_length(group: int, variation: int, count: int | None) -> int | None:
    if count is None:
        return None
    if (group, variation) in PACKED_BINARY_VARIATIONS:
        return math.ceil(count / 8)
    if (group, variation) in PACKED_DOUBLE_VARIATIONS:
        return math.ceil(count / 4)
    if group == 110 and variation > 0:
        return variation * count
    size = OBJECT_SIZES.get((group, variation))
    if size is None:
        return None
    return size * count


def _parse_objects(data: bytes) -> tuple[list[dict[str, object]], list[str]]:
    objects: list[dict[str, object]] = []
    details: list[str] = []
    idx = 0

    def _decode_values(
        group: int, variation: int, raw: bytes, count: int | None
    ) -> tuple[Optional[str], list[object]]:
        values_out: list[object] = []
        if count is None or count <= 0:
            return None, values_out

        # Layout map: (flags_size, value_type, value_size, time_size)
        layout: dict[tuple[int, int], tuple[int, str, int, int]] = {
            (1, 2): (1, "bool", 0, 0),
            (2, 1): (1, "bool", 0, 0),
            (2, 2): (1, "bool", 0, TIME_48),
            (2, 3): (1, "bool", 0, TIME_16),
            (3, 2): (1, "db", 0, 0),
            (4, 1): (1, "db", 0, 0),
            (4, 2): (1, "db", 0, TIME_48),
            (4, 3): (1, "db", 0, TIME_16),
            (10, 2): (1, "bool", 0, 0),
            (11, 1): (1, "bool", 0, 0),
            (11, 2): (1, "bool", 0, TIME_48),
            (11, 3): (1, "bool", 0, TIME_16),
            (20, 1): (1, "uint", 4, 0),
            (20, 2): (1, "uint", 2, 0),
            (20, 5): (0, "uint", 4, 0),
            (20, 6): (0, "uint", 2, 0),
            (21, 1): (1, "uint", 4, 0),
            (21, 2): (1, "uint", 2, 0),
            (21, 5): (1, "uint", 4, TIME_48),
            (21, 6): (1, "uint", 2, TIME_48),
            (21, 9): (0, "uint", 4, 0),
            (21, 10): (0, "uint", 2, 0),
            (22, 1): (1, "uint", 4, 0),
            (22, 2): (1, "uint", 2, 0),
            (22, 5): (0, "uint", 4, 0),
            (22, 6): (0, "uint", 2, 0),
            (23, 1): (1, "uint", 4, TIME_48),
            (23, 2): (1, "uint", 2, TIME_48),
            (23, 5): (1, "uint", 4, TIME_48),
            (23, 6): (1, "uint", 2, TIME_48),
            (30, 1): (1, "int", 4, 0),
            (30, 2): (1, "int", 2, 0),
            (30, 3): (0, "int", 4, 0),
            (30, 4): (0, "int", 2, 0),
            (30, 5): (1, "float", 4, 0),
            (30, 6): (1, "float", 8, 0),
            (31, 1): (1, "int", 4, TIME_48),
            (31, 2): (1, "int", 2, TIME_48),
            (31, 3): (1, "float", 4, TIME_48),
            (31, 4): (1, "float", 8, TIME_48),
            (31, 5): (0, "int", 4, 0),
            (31, 6): (0, "int", 2, 0),
            (31, 7): (1, "float", 4, 0),
            (31, 8): (1, "float", 8, 0),
            (32, 1): (1, "int", 4, 0),
            (32, 2): (1, "int", 2, 0),
            (32, 3): (1, "int", 4, TIME_48),
            (32, 4): (1, "int", 2, TIME_48),
            (32, 5): (1, "float", 4, 0),
            (32, 6): (1, "float", 8, 0),
            (32, 7): (1, "float", 4, TIME_48),
            (32, 8): (1, "float", 8, TIME_48),
            (40, 1): (1, "int", 4, 0),
            (40, 2): (1, "int", 2, 0),
            (40, 3): (1, "float", 4, 0),
            (40, 4): (1, "float", 8, 0),
            (41, 1): (1, "int", 4, TIME_48),
            (41, 2): (1, "int", 2, TIME_48),
            (41, 3): (1, "float", 4, TIME_48),
            (41, 4): (1, "float", 8, TIME_48),
            (42, 1): (1, "int", 4, 0),
            (42, 2): (1, "int", 2, 0),
            (42, 3): (1, "float", 4, 0),
            (42, 4): (1, "float", 8, 0),
        }

        layout_key = (group, variation)
        if layout_key not in layout:
            return None, values_out
        flags_size, value_type, value_size, time_size = layout[layout_key]
        element_size = flags_size + value_size + time_size
        if element_size <= 0:
            return None, values_out
        max_values = min(count, 4)
        values: list[str] = []
        for i in range(max_values):
            start = i * element_size
            if start + element_size > len(raw):
                break
            offset = start
            flags = raw[offset] if flags_size else None
            offset += flags_size
            val = None
            if value_type == "bool":
                if flags is not None:
                    val = bool(flags & 0x01)
            elif value_type == "db":
                if flags is not None:
                    val = (flags >> 0) & 0x03
            elif value_type == "int" and value_size:
                val = int.from_bytes(
                    raw[offset : offset + value_size], "little", signed=True
                )
            elif value_type == "uint" and value_size:
                val = int.from_bytes(
                    raw[offset : offset + value_size], "little", signed=False
                )
            elif value_type == "float" and value_size:
                try:
                    if value_size == 4:
                        val = struct.unpack("<f", raw[offset : offset + value_size])[0]
                    elif value_size == 8:
                        val = struct.unpack("<d", raw[offset : offset + value_size])[0]
                except Exception:
                    val = None
            if val is not None:
                values.append(str(val))
                values_out.append(val)
        if not values:
            return None, values_out
        suffix = ""
        if count > len(values):
            suffix = f" (+{count - len(values)} more)"
        return f"[{', '.join(values)}]{suffix}", values_out

    while idx + 3 <= len(data):
        group = data[idx]
        variation = data[idx + 1]
        qualifier = data[idx + 2]
        idx += 3
        count = None
        start = None
        stop = None
        if qualifier in QUALIFIER_RANGE_SIZES:
            size = QUALIFIER_RANGE_SIZES[qualifier]
            if idx + (2 * size) > len(data):
                break
            start = int.from_bytes(data[idx : idx + size], "little")
            stop = int.from_bytes(data[idx + size : idx + 2 * size], "little")
            count = max((stop - start + 1), 0)
            idx += 2 * size
        elif qualifier in QUALIFIER_COUNT_SIZES:
            size = QUALIFIER_COUNT_SIZES[qualifier]
            if idx + size > len(data):
                break
            count = int.from_bytes(data[idx : idx + size], "little")
            idx += size
        else:
            break

        group_name = OBJECT_GROUPS.get(group, f"Group {group}")
        range_text = ""
        if start is not None and stop is not None:
            range_text = f" range={start}-{stop}"
        elif count is not None:
            range_text = f" count={count}"
        summary = f"{group_name} {group}.{variation}{range_text}"
        objects.append(
            {
                "group": group,
                "variation": variation,
                "summary": summary,
                "count": count,
                "start": start,
                "stop": stop,
            }
        )
        details.append(f"{group}.{variation}")

        data_len = _object_data_length(group, variation, count)
        if data_len is None:
            break
        if idx + data_len > len(data):
            break
        value_preview, values_out = _decode_values(
            group, variation, data[idx : idx + data_len], count
        )
        if value_preview:
            summary = f"{summary} values={value_preview}"
            objects[-1]["summary"] = summary
        if values_out:
            objects[-1]["values"] = values_out
        idx += data_len
    return objects, details


# --- Dataclasses ---


@dataclass
class Dnp3Message:
    ts: float
    src_ip: str
    dst_ip: str
    src_addr: int  # Data Link Source
    dst_addr: int  # Data Link Dest
    len: int
    func_code: Optional[int]
    func_name: str
    is_master: bool  # True if sending requests typically (heuristically)
    object_summary: Optional[str] = None


@dataclass
class Dnp3Anomaly:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    src: str
    dst: str
    ts: float
    attack: str = ""  # ATT&CK for ICS technique id(s), e.g. "T0855"
    evidence: str = ""


@dataclass
class Dnp3Analysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    dnp3_packets: int = 0

    # Statistics
    func_counts: Counter[str] = field(default_factory=Counter)
    src_addrs: Counter[int] = field(default_factory=Counter)  # DNP3 Addresses
    dst_addrs: Counter[int] = field(default_factory=Counter)
    ip_endpoints: Counter[str] = field(
        default_factory=Counter
    )  # IP addresses participating

    # Protocol statistics (request/response/control breakdown)
    requests: int = 0
    responses: int = 0
    unsolicited_responses: int = 0
    control_count: int = 0
    src_requests: Counter[str] = field(default_factory=Counter)
    src_responses: Counter[str] = field(default_factory=Counter)
    # Master/outstation role inference (a master issues requests; an outstation
    # answers with responses). IP -> count.
    master_ips: Counter[str] = field(default_factory=Counter)
    outstation_ips: Counter[str] = field(default_factory=Counter)
    # IP -> set of DNP3 data-link addresses seen for that IP.
    ip_dnp3_addrs: dict[str, set] = field(default_factory=dict)
    # Conversations: (master_ip, outstation_ip) -> Counter of function names.
    conversations: dict = field(default_factory=dict)
    # IIN (Internal Indication) flags observed in outstation responses.
    iin_flags: Counter[str] = field(default_factory=Counter)
    # Secure Authentication v5 (IEEE 1815-2012) seen on the wire?
    sav5_present: bool = False
    # Individual control commands (Operate / Direct Operate / Select / Write to
    # an output) with evidence — the highest-value forensic artifact.
    control_commands: List[dict[str, object]] = field(default_factory=list)

    # Activity
    messages: List[Dnp3Message] = field(default_factory=list)
    object_counts: Counter[str] = field(default_factory=Counter)
    object_group_counts: Counter[str] = field(default_factory=Counter)
    anomalies: List[Dnp3Anomaly] = field(default_factory=list)
    value_changes: List[dict[str, object]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def unique_dnp3_addresses(self) -> int:
        return len(set(list(self.src_addrs.keys()) + list(self.dst_addrs.keys())))


@memoize_analysis
def analyze_dnp3(path: Path, show_status: bool = True) -> Dnp3Analysis:
    if TCP is None:
        return Dnp3Analysis(
            path,
            0.0,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            [],
            Counter(),
            Counter(),
            [],
            ["Scapy unavailable (TCP missing)"],
        )

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return Dnp3Analysis(
            path,
            0.0,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            [],
            Counter(),
            Counter(),
            [],
            [f"Error: {e}"],
        )

    total_packets = 0
    dnp3_packets = 0

    func_counts = Counter()
    src_addrs = Counter()
    dst_addrs = Counter()
    ip_endpoints = Counter()

    messages: List[Dnp3Message] = []
    anomalies: List[Dnp3Anomaly] = []
    object_counts: Counter[str] = Counter()
    object_group_counts: Counter[str] = Counter()
    value_changes: List[dict[str, object]] = []
    last_values: dict[tuple[int, int, int], object] = {}
    errors: List[str] = []
    max_anomalies = 200

    src_requests: Counter[str] = Counter()
    src_responses: Counter[str] = Counter()
    src_dst_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    src_dst_addrs: Dict[str, Set[int]] = defaultdict(set)
    src_control_counts: Counter[str] = Counter()
    src_unsolicited_counts: Counter[str] = Counter()
    src_restart_counts: Counter[str] = Counter()
    src_app_control_counts: Counter[str] = Counter()
    src_file_counts: Counter[str] = Counter()
    # Role / conversation / IIN / control-evidence accumulators (surfaced for IR).
    master_ips: Counter[str] = Counter()
    outstation_ips: Counter[str] = Counter()
    ip_dnp3_addrs: Dict[str, Set[int]] = defaultdict(set)
    conversations: Dict[tuple, Counter] = defaultdict(Counter)
    iin_flags: Counter[str] = Counter()
    control_commands: List[dict[str, object]] = []
    control_cmd_seen: Set[tuple] = set()
    sav5_present = False
    unsolicited_responses = 0
    src_time_counts: Counter[str] = Counter()
    nonstandard_port_counts: Counter[str] = Counter()
    reassembly_buffers: dict[tuple[str, str, int, int], bytearray] = {}
    selected_pairs: Set[Tuple[str, int]] = set()
    op_no_select_flagged: Set[Tuple[str, int]] = set()
    broadcast_flagged: Set[Tuple[str, int]] = set()

    start_time = None
    last_time = None

    def _parse_object_header(
        data: bytes,
    ) -> tuple[
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
    ]:
        if len(data) < 3:
            return None, None, None, None, None, None
        group = data[0]
        variation = data[1]
        qualifier = data[2]
        idx = 3
        start = None
        stop = None
        count = None
        if qualifier in QUALIFIER_RANGE_SIZES:
            size = QUALIFIER_RANGE_SIZES[qualifier]
            if idx + (2 * size) > len(data):
                return group, variation, qualifier, None, None, None
            start = int.from_bytes(data[idx : idx + size], "little")
            stop = int.from_bytes(data[idx + size : idx + 2 * size], "little")
            if stop is not None and start is not None:
                count = max((stop - start + 1), 0)
        elif qualifier in QUALIFIER_COUNT_SIZES:
            size = QUALIFIER_COUNT_SIZES[qualifier]
            if idx + size > len(data):
                return group, variation, qualifier, None, None, None
            count = int.from_bytes(data[idx : idx + size], "little")
        return group, variation, qualifier, count, start, stop

    try:
        with status as pbar:
            try:
                total_count = len(reader)
            except Exception:
                total_count = None
            for i, pkt in enumerate(reader):
                if total_count and i % 10 == 0:
                    try:
                        pbar.update(int((i / max(1, total_count)) * 100))
                    except Exception:
                        pass

                total_packets += 1
                ts = safe_float(getattr(pkt, "time", 0))
                if start_time is None:
                    start_time = ts
                last_time = ts

                # Check ports
                has_transport = False
                sport, dport = 0, 0
                payload = b""

                if pkt.haslayer(TCP):
                    has_transport = True
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    payload_obj = pkt[TCP].payload
                    payload = bytes(payload_obj) if payload_obj else b""
                    if not payload and Raw is not None and pkt.haslayer(Raw):
                        try:
                            payload = bytes(pkt[Raw].load)
                        except Exception:
                            pass
                elif pkt.haslayer(UDP):
                    has_transport = True
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                    payload_obj = pkt[UDP].payload
                    payload = bytes(payload_obj) if payload_obj else b""
                    if not payload and Raw is not None and pkt.haslayer(Raw):
                        try:
                            payload = bytes(pkt[Raw].load)
                        except Exception:
                            pass
                else:
                    # Fallback: parse TCP/UDP from raw bytes if scapy didn't dissect layers
                    try:
                        raw = bytes(pkt)
                        if (
                            len(raw) >= 34 and raw[12:14] == b"\x08\x00"
                        ):  # Ethernet + IPv4
                            ihl = (raw[14] & 0x0F) * 4
                            proto = raw[23]
                            ip_start = 14
                            total_len = int.from_bytes(raw[16:18], "big")
                            transport_start = ip_start + ihl
                            if proto == 6 and len(raw) >= transport_start + 20:
                                data_offset = (raw[transport_start + 12] >> 4) * 4
                                sport = int.from_bytes(
                                    raw[transport_start : transport_start + 2], "big"
                                )
                                dport = int.from_bytes(
                                    raw[transport_start + 2 : transport_start + 4],
                                    "big",
                                )
                                payload_start = transport_start + data_offset
                                ip_end = ip_start + total_len
                                payload = (
                                    raw[payload_start:ip_end]
                                    if ip_end <= len(raw)
                                    else raw[payload_start:]
                                )
                                has_transport = True
                            elif proto == 17 and len(raw) >= transport_start + 8:
                                sport = int.from_bytes(
                                    raw[transport_start : transport_start + 2], "big"
                                )
                                dport = int.from_bytes(
                                    raw[transport_start + 2 : transport_start + 4],
                                    "big",
                                )
                                payload_start = transport_start + 8
                                ip_end = ip_start + total_len
                                payload = (
                                    raw[payload_start:ip_end]
                                    if ip_end <= len(raw)
                                    else raw[payload_start:]
                                )
                                has_transport = True
                    except Exception:
                        pass

                if not has_transport:
                    continue

                frames = _parse_dnp3_frames(payload) if payload else []
                on_dnp3_port = sport == DNP3_PORT or dport == DNP3_PORT

                # Off the standard DNP3 port, only a CRC-VALID frame counts as
                # real DNP3: a chance 0x05 0x64 match in IT/malware traffic
                # parses into a "frame" but fails CRC, and previously still
                # triggered "DNP3 on Non-Standard Port"/"Exposure" false
                # positives. On-port, accept frames even with CRC errors (real
                # DNP3 corruption/tampering is itself worth surfacing).
                has_valid_frame = any(f[4] for f in frames)
                is_dnp3 = on_dnp3_port or has_valid_frame
                if not is_dnp3:
                    continue

                if has_valid_frame and not on_dnp3_port:
                    nonstandard_port_counts[f"{sport}->{dport}"] += 1

                dnp3_packets += 1

                # Network-layer addresses (DNP3 runs over TCP/UDP) — not the
                # Ethernet MACs that pkt[0].src would yield.
                src_ip, dst_ip = extract_packet_endpoints(pkt)
                if not src_ip:
                    src_ip = pkt[0].src if hasattr(pkt[0], "src") else "?"
                if not dst_ip:
                    dst_ip = pkt[0].dst if hasattr(pkt[0], "dst") else "?"

                for dl_src, dl_dst, dl_ctrl, user_data, crc_ok in frames:
                    ip_endpoints[src_ip] += 1
                    ip_endpoints[dst_ip] += 1

                    src_addrs[dl_src] += 1
                    dst_addrs[dl_dst] += 1

                    # A CRC-failed frame is not a trustworthy DNP3 frame: its
                    # "user data" is garbage, so parsing it as DNP3 application
                    # layer manufactures phantom File-Op/Write findings. This is
                    # also how a chance 0x05 0x64 match in non-DNP3 (IT/malware)
                    # traffic produced false DNP3 detections. Only flag the CRC
                    # mismatch as corruption on the actual DNP3 port (where the
                    # traffic really is DNP3), and never parse its app layer.
                    if not crc_ok:
                        on_dnp3_port = sport == DNP3_PORT or dport == DNP3_PORT
                        if on_dnp3_port and len(anomalies) < max_anomalies:
                            anomalies.append(
                                Dnp3Anomaly(
                                    "LOW",
                                    "DNP3 CRC Mismatch",
                                    "DNP3 frame CRC mismatch detected (possible corruption or tampering).",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )
                            )
                        continue

                    if not user_data or len(user_data) < 2:
                        continue

                    tp_header = user_data[0]
                    fir = bool(tp_header & 0x80)
                    fin = bool(tp_header & 0x40)
                    transport_seq = tp_header & 0x3F
                    _ = transport_seq

                    key = (src_ip, dst_ip, dl_src, dl_dst)
                    if fir:
                        reassembly_buffers[key] = bytearray()
                    buffer = reassembly_buffers.setdefault(key, bytearray())
                    buffer.extend(user_data[1:])
                    if not fin:
                        continue
                    app_data = bytes(reassembly_buffers.pop(key, buffer))
                    if len(app_data) < 2:
                        continue

                    func_code = app_data[1]
                    func_name = FUNC_CODES.get(func_code, f"Unknown ({func_code})")
                    func_counts[func_name] += 1

                    is_response = func_code in RESPONSE_FUNCTIONS
                    ip_dnp3_addrs[src_ip].add(dl_src)
                    ip_dnp3_addrs[dst_ip].add(dl_dst)
                    if func_code in SAV5_FUNCTIONS:
                        sav5_present = True
                    if is_response:
                        src_responses[src_ip] += 1
                        # The responder is the OUTSTATION (RTU/IED); its peer is
                        # the master.
                        outstation_ips[src_ip] += 1
                        conversations[(dst_ip, src_ip)][func_name] += 1
                        if func_code == 130:
                            unsolicited_responses += 1
                        # Parse IIN (the 2 bytes after the function code).
                        if len(app_data) >= 4:
                            iin1, iin2 = app_data[2], app_data[3]
                            for bit, name in IIN1_BITS.items():
                                if iin1 & bit:
                                    iin_flags[name] += 1
                            for bit, name in IIN2_BITS.items():
                                if iin2 & bit:
                                    iin_flags[name] += 1
                    else:
                        src_requests[src_ip] += 1
                        src_dst_counts[src_ip][dst_ip] += 1
                        src_dst_addrs[src_ip].add(dl_dst)
                        # The requester is the MASTER (issues commands/polls).
                        master_ips[src_ip] += 1
                        conversations[(src_ip, dst_ip)][func_name] += 1

                    if func_code in CONTROL_FUNCTIONS:
                        src_control_counts[src_ip] += 1
                        # Record each control command with evidence (deduped per
                        # src->dst+func+outstation-addr). This is the load-bearing
                        # forensic artifact: an Operate/Direct Operate/Write to an
                        # output is an actuation/setpoint change (ATT&CK T0855
                        # Unauthorized Command Message / T0831 Manipulation of
                        # Control). A single one is worth surfacing.
                        _cc_key = (src_ip, dst_ip, func_code, dl_dst)
                        if _cc_key not in control_cmd_seen:
                            control_cmd_seen.add(_cc_key)
                            control_commands.append(
                                {
                                    "ts": ts,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_addr": dl_src,
                                    "dst_addr": dl_dst,
                                    "func": func_name,
                                    "func_code": func_code,
                                }
                            )
                            # Operate / Direct Operate drive an output (relay/
                            # setpoint). Surface each distinct one — even a single
                            # command matters in OT.
                            if (
                                func_code in {4, 5, 6}
                                and len(anomalies) < max_anomalies
                            ):
                                anomalies.append(
                                    Dnp3Anomaly(
                                        "HIGH",
                                        "DNP3 Outstation Control Command",
                                        f"{func_name} issued to outstation Addr "
                                        f"{dl_dst} ({dst_ip}) — drives a control "
                                        "output (relay/analog setpoint). Confirm the "
                                        "source is the authorized master and within "
                                        "a change window.",
                                        src_ip,
                                        dst_ip,
                                        ts,
                                        attack="T0855 Unauthorized Command Message; T0831 Manipulation of Control",
                                        evidence=f"master {src_ip} (Addr {dl_src}) -> outstation {dst_ip} (Addr {dl_dst}) func={func_name}",
                                    )
                                )
                    if func_code in UNSOLICITED_FUNCTIONS:
                        src_unsolicited_counts[src_ip] += 1
                    if func_code in RESTART_FUNCTIONS:
                        src_restart_counts[src_ip] += 1
                    if func_code in APP_CONTROL_FUNCTIONS:
                        src_app_control_counts[src_ip] += 1
                    if func_code in FILE_FUNCTIONS:
                        src_file_counts[src_ip] += 1
                    if func_code in TIME_FUNCTIONS:
                        src_time_counts[src_ip] += 1

                    if (
                        func_code in RESTART_FUNCTIONS
                        and len(anomalies) < max_anomalies
                    ):
                        anomalies.append(
                            Dnp3Anomaly(
                                "HIGH",
                                "DNP3 Restart",
                                f"System restart command ({func_name}) issued to "
                                f"outstation Addr {dl_dst} ({dst_ip}) — forces the "
                                "RTU/IED offline (loss of monitoring & control).",
                                src_ip,
                                dst_ip,
                                ts,
                                attack="T0816 Device Restart/Shutdown",
                                evidence=f"{src_ip} (Addr {dl_src}) -> {dst_ip} (Addr {dl_dst}) func={func_name}",
                            )
                        )

                    if func_code == 2 and len(anomalies) < max_anomalies:
                        anomalies.append(
                            Dnp3Anomaly(
                                "MEDIUM",
                                "DNP3 Write",
                                f"Write command detected to {dst_ip} (Addr {dl_dst})",
                                src_ip,
                                dst_ip,
                                ts,
                            )
                        )

                    # Select-before-Operate state tracking. Select (3) arms a
                    # control point; Operate (4) should follow a prior Select.
                    # DirectOperate (5/6) is one-step by design, so only a bare
                    # Operate-4 with no observed Select is the SBO-bypass signal.
                    if func_code == 3:
                        selected_pairs.add((src_ip, dl_dst))
                    elif func_code == 4 and (src_ip, dl_dst) not in selected_pairs:
                        if (
                            (src_ip, dl_dst) not in op_no_select_flagged
                            and len(anomalies) < max_anomalies
                        ):
                            op_no_select_flagged.add((src_ip, dl_dst))
                            anomalies.append(
                                Dnp3Anomaly(
                                    "MEDIUM",
                                    "DNP3 Operate Without Select",
                                    f"Operate to Addr {dl_dst} with no preceding Select "
                                    "(single-stage control / possible SBO bypass; "
                                    "may also be a capture gap).",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )
                            )

                    # Broadcast control: a command to a DNP3 broadcast link
                    # address (0xFFFD-0xFFFF) actuates every outstation at once.
                    if (
                        dl_dst in (0xFFFD, 0xFFFE, 0xFFFF)
                        and func_code in (2, 3, 4, 5, 6, 13, 14)
                        and (src_ip, dl_dst) not in broadcast_flagged
                        and len(anomalies) < max_anomalies
                    ):
                        broadcast_flagged.add((src_ip, dl_dst))
                        anomalies.append(
                            Dnp3Anomaly(
                                "HIGH",
                                "DNP3 Broadcast Control",
                                f"Control/write ({func_name}) sent to broadcast address "
                                f"0x{dl_dst:04X}; affects all outstations.",
                                src_ip,
                                dst_ip,
                                ts,
                            )
                        )

                    if func_code in FILE_FUNCTIONS and len(anomalies) < max_anomalies:
                        anomalies.append(
                            Dnp3Anomaly(
                                "HIGH",
                                "DNP3 File Op",
                                f"File operation ({func_name}) detected",
                                src_ip,
                                dst_ip,
                                ts,
                            )
                        )

                    app_payload_start = 2
                    if is_response and len(app_data) >= 4:
                        iin = int.from_bytes(app_data[2:4], "little")
                        if iin & 0x0080 and len(anomalies) < max_anomalies:
                            anomalies.append(
                                Dnp3Anomaly(
                                    "MEDIUM",
                                    "IIN Device Restart",
                                    "Internal Indication: Device Restart detected",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )
                            )
                        if iin & 0x0040 and len(anomalies) < max_anomalies:
                            anomalies.append(
                                Dnp3Anomaly(
                                    "MEDIUM",
                                    "IIN Device Trouble",
                                    "Internal Indication: Device Trouble/Error",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )
                            )
                        app_payload_start = 4

                    object_summary = None
                    if app_payload_start < len(app_data):
                        obj_items, obj_keys = _parse_objects(
                            app_data[app_payload_start:]
                        )
                        if obj_items:
                            object_summary = str(obj_items[0].get("summary") or "")
                        for key in obj_keys:
                            object_counts[key] += 1
                            try:
                                group_id = int(key.split(".")[0])
                            except Exception:
                                group_id = None
                            if group_id is not None:
                                group_name = OBJECT_GROUPS.get(
                                    group_id, f"Group {group_id}"
                                )
                                object_group_counts[group_name] += 1
                        for item in obj_items:
                            values = item.get("values")
                            if not values:
                                continue
                            group_id = item.get("group")
                            variation = item.get("variation")
                            start_index = item.get("start") or 0
                            if not isinstance(group_id, int) or not isinstance(
                                variation, int
                            ):
                                continue
                            for offset, value in enumerate(values):
                                if len(value_changes) >= 200:
                                    break
                                index = start_index + offset
                                key = (group_id, variation, index)
                                prev = last_values.get(key)
                                if prev is not None and prev != value:
                                    value_changes.append(
                                        {
                                            "group": group_id,
                                            "variation": variation,
                                            "index": index,
                                            "old": prev,
                                            "new": value,
                                            "src": src_ip,
                                            "dst": dst_ip,
                                            "ts": ts,
                                        }
                                    )
                                last_values[key] = value
                        if obj_items and func_code in {2, 3, 4, 5, 6}:
                            for item in obj_items:
                                group_id = item.get("group")
                                if (
                                    isinstance(group_id, int)
                                    and group_id in CONTROL_OBJECT_GROUPS
                                ):
                                    if len(anomalies) < max_anomalies:
                                        anomalies.append(
                                            Dnp3Anomaly(
                                                "HIGH",
                                                "DNP3 Control Object Operation",
                                                f"{func_name} on {item.get('summary')}",
                                                src_ip,
                                                dst_ip,
                                                ts,
                                            )
                                        )
                                        break
                                if (
                                    isinstance(group_id, int)
                                    and group_id in FILE_OBJECT_GROUPS
                                ):
                                    if len(anomalies) < max_anomalies:
                                        anomalies.append(
                                            Dnp3Anomaly(
                                                "HIGH",
                                                "DNP3 File Object Operation",
                                                f"{func_name} on {item.get('summary')}",
                                                src_ip,
                                                dst_ip,
                                                ts,
                                            )
                                        )
                                        break

                    messages.append(
                        Dnp3Message(
                            ts=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_addr=dl_src,
                            dst_addr=dl_dst,
                            len=len(app_data),
                            func_code=func_code,
                            func_name=func_name,
                            is_master=(dl_src < 65500),
                            object_summary=object_summary,
                        )
                    )

                continue

    except Exception as e:
        errors.append(f"{type(e).__name__}: {e}")
    finally:
        try:
            reader.close()
        except Exception:
            pass

    duration = 0.0
    if start_time and last_time:
        duration = last_time - start_time

    if nonstandard_port_counts:
        for session, count in nonstandard_port_counts.most_common(6):
            if len(anomalies) < max_anomalies:
                anomalies.append(
                    Dnp3Anomaly(
                        "MEDIUM",
                        "DNP3 on Non-Standard Port",
                        f"Observed DNP3 signature on {session} ({count} packets)",
                        "*",
                        "*",
                        0.0,
                    )
                )

    for src_ip, dsts in src_dst_counts.items():
        unique_dsts = len(dsts)
        req_count = src_requests.get(src_ip, 0)
        resp_count = src_responses.get(src_ip, 0)
        if unique_dsts >= 20 and req_count > resp_count * 2:
            if len(anomalies) < max_anomalies:
                anomalies.append(
                    Dnp3Anomaly(
                        "MEDIUM",
                        "DNP3 Scanning/Probing",
                        f"Source contacted {unique_dsts} endpoints with low response rate.",
                        src_ip,
                        "*",
                        0.0,
                    )
                )

        addr_count = len(src_dst_addrs.get(src_ip, set()))
        if addr_count >= 20 and len(anomalies) < max_anomalies:
            anomalies.append(
                Dnp3Anomaly(
                    "MEDIUM",
                    "DNP3 Address Scan",
                    f"Source probed {addr_count} DNP3 destination addresses.",
                    src_ip,
                    "*",
                    0.0,
                )
            )

    for src_ip, count in src_control_counts.items():
        req_count = src_requests.get(src_ip, 0)
        ratio = (count / req_count) if req_count else 0.0
        if count >= 10 and ratio >= 0.2 and len(anomalies) < max_anomalies:
            anomalies.append(
                Dnp3Anomaly(
                    "HIGH",
                    "DNP3 Control Command Burst",
                    f"{count} control/operate commands ({ratio:.0%} of requests).",
                    src_ip,
                    "*",
                    0.0,
                )
            )

    for src_ip, count in src_unsolicited_counts.items():
        if count >= 5 and len(anomalies) < max_anomalies:
            anomalies.append(
                Dnp3Anomaly(
                    "MEDIUM",
                    "DNP3 Unsolicited Control",
                    f"{count} enable/disable unsolicited operations observed.",
                    src_ip,
                    "*",
                    0.0,
                )
            )

    for src_ip, count in src_restart_counts.items():
        if count and len(anomalies) < max_anomalies:
            anomalies.append(
                Dnp3Anomaly(
                    "HIGH",
                    "DNP3 Restart Activity",
                    f"{count} restart commands observed.",
                    src_ip,
                    "*",
                    0.0,
                )
            )

    for src_ip, count in src_app_control_counts.items():
        if count >= 5 and len(anomalies) < max_anomalies:
            anomalies.append(
                Dnp3Anomaly(
                    "HIGH",
                    "DNP3 Application Control",
                    f"{count} application control/config operations observed.",
                    src_ip,
                    "*",
                    0.0,
                )
            )

    for src_ip, count in src_file_counts.items():
        if count and len(anomalies) < max_anomalies:
            anomalies.append(
                Dnp3Anomaly(
                    "HIGH",
                    "DNP3 File Operations",
                    f"{count} file transfer/control operations observed.",
                    src_ip,
                    "*",
                    0.0,
                )
            )

    for src_ip, count in src_time_counts.items():
        if count >= 5 and len(anomalies) < max_anomalies:
            anomalies.append(
                Dnp3Anomaly(
                    "LOW",
                    "DNP3 Time Sync Activity",
                    f"{count} time sync/delay operations observed.",
                    src_ip,
                    "*",
                    0.0,
                )
            )

    public_endpoints = []
    for ip_value in ip_endpoints:
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints and len(anomalies) < max_anomalies:
        anomalies.append(
            Dnp3Anomaly(
                "HIGH",
                "DNP3 Exposure to Public IP",
                f"DNP3 traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                "*",
                "*",
                0.0,
            )
        )

    # Collapse identical repeated findings (same title/src/dst/detail) to one —
    # DNP3 emits an anomaly per control-object/CRC/write packet, so a busy or
    # merged capture floods with duplicates and buries the distinct findings.
    _seen: set[tuple[str, str, str, str]] = set()
    _deduped: list[Dnp3Anomaly] = []
    for _a in anomalies:
        _k = (
            str(getattr(_a, "title", "")),
            str(getattr(_a, "src", "")),
            str(getattr(_a, "dst", "")),
            str(getattr(_a, "description", "")),
        )
        if _k in _seen:
            continue
        _seen.add(_k)
        _deduped.append(_a)
    anomalies = _deduped

    return Dnp3Analysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        dnp3_packets=dnp3_packets,
        func_counts=func_counts,
        src_addrs=src_addrs,
        dst_addrs=dst_addrs,
        ip_endpoints=ip_endpoints,
        requests=sum(src_requests.values()),
        responses=sum(src_responses.values()),
        unsolicited_responses=unsolicited_responses,
        control_count=sum(src_control_counts.values()),
        src_requests=src_requests,
        src_responses=src_responses,
        master_ips=master_ips,
        outstation_ips=outstation_ips,
        ip_dnp3_addrs={k: set(v) for k, v in ip_dnp3_addrs.items()},
        conversations={k: dict(v) for k, v in conversations.items()},
        iin_flags=iin_flags,
        sav5_present=sav5_present,
        control_commands=control_commands,
        messages=messages,
        object_counts=object_counts,
        object_group_counts=object_group_counts,
        anomalies=anomalies,
        value_changes=value_changes,
        errors=errors,
    )
