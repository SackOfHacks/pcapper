from __future__ import annotations

from .utils import read_ber_length as _read_ber_length, memoize_analysis
import struct
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .industrial_helpers import _strip_padding
from .pcap_cache import PcapMeta, iter_packets
from .utils import extract_packet_endpoints, is_public_ip, safe_float

try:
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    Ether = None  # type: ignore
try:
    from scapy.layers.inet import UDP  # type: ignore
except Exception:  # pragma: no cover
    UDP = None  # type: ignore


GOOSE_ETHERTYPE = 0x88B8
MAX_GOOSE_DETECTIONS = 2000
MAX_GOOSE_TRACKED_STREAMS = 100000
MAX_GOOSE_VALUE_SAMPLES = 10000

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
    0xAB: "allData",
}

GOOSE_STRING_TAGS = {"gocbRef", "datSet", "goID"}
GOOSE_INT_TAGS = {"timeAllowedToLive", "stNum", "sqNum", "confRev", "numDatSetEntries"}
GOOSE_BOOL_TAGS = {"simulation", "ndsCom"}

GOOSE_DATA_TAGS = {
    0x83: "boolean",
    0x84: "bit-string",
    0x85: "integer",
    0x86: "unsigned",
    0x87: "float",
    0x89: "octet-string",
    0x8A: "visible-string",
    0x8B: "generalized-time",
    0x8C: "binary-time",
    0x8D: "bcd",
    0x8E: "boolean-array",
    0x90: "visible-string",
    0x91: "generalized-time",
}


# IEC 61850-90-5 session identifiers (first byte after the CLTP UD header).
RGOOSE_SESSION_IDS = {0xA0: "tunnelled", 0xA1: "GOOSE", 0xA2: "SV", 0xA3: "management"}
RGOOSE_PAYLOAD_TAGS = {0x81: "GOOSE", 0x82: "SV", 0x83: "tunnelled", 0x84: "management"}
# IEC 61850-90-5 binds the session protocol to UDP 102 (ISO-TSAP); any other
# port is a deployment choice (the SDN lab dataset uses 8694).
RGOOSE_STANDARD_UDP_PORT = 102


@dataclass(frozen=True)
class RGooseApdu:
    tag: int
    simulation: bool
    appid: int
    apdu: bytes


@dataclass(frozen=True)
class RGooseSession:
    """One IEC 61850-90-5 session PDU (R-GOOSE / R-SV) over CLTP/UDP."""

    session_id: int
    spdu_length: int
    spdu_number: int
    version: int
    time_of_current_key: int
    time_to_next_key: int
    key_id: int
    iv: bytes
    apdus: tuple[RGooseApdu, ...]
    signature: bytes
    payload_parsed: bool


def parse_rgoose(payload: bytes) -> RGooseSession | None:
    """Parse an IEC 61850-90-5 session PDU, or None if ``payload`` is not one.

    Layout (as Wireshark's R-GOOSE dissector): CLTP UD (``01 40``), session
    identifier, session-header length, common header (``0x80``, length, SPDU
    length, SPDU number, version), security information (time of current
    key, time to next key, key ID, IV length + IV), payload length, then
    payload entries (tag, simulation, APPID, APDU length, APDU) and an
    optional signature (``0x85``, length, HMAC). Structural checks only: the
    payload length and the signature TLV must account for the bytes exactly.
    """
    if len(payload) < 31 or payload[0] != 0x01 or payload[1] != 0x40:
        return None
    session_id = payload[2]
    if session_id not in RGOOSE_SESSION_IDS or payload[4] != 0x80:
        return None
    be32 = lambda pos: int.from_bytes(payload[pos:pos + 4], "big")  # noqa: E731
    spdu_length = be32(6)
    spdu_number = be32(10)
    version = int.from_bytes(payload[14:16], "big")
    time_current = be32(16)
    time_next = int.from_bytes(payload[20:22], "big")
    key_id = be32(22)
    iv_len = payload[26]
    pos = 27 + iv_len
    if pos + 4 > len(payload):
        return None
    iv = payload[27:pos]
    payload_len = be32(pos)
    pos += 4
    end = pos + payload_len
    if end > len(payload):
        return None
    tail = payload[end:]
    signature = b""
    if tail:
        if tail[0] != 0x85 or len(tail) < 2 or tail[1] + 2 != len(tail):
            return None
        signature = bytes(tail[2:])
    apdus: list[RGooseApdu] = []
    cursor = pos
    while cursor + 6 <= end:
        tag = payload[cursor]
        if tag not in RGOOSE_PAYLOAD_TAGS:
            break
        apdu_len = int.from_bytes(payload[cursor + 4:cursor + 6], "big")
        start = cursor + 6
        # Implementations differ on whether the APDU length counts its own two
        # bytes (the SDN lab capture: 104 for a 102-byte goosePdu). The PDU's
        # BER length decides; the declared length is the fallback.
        entry_end = _ber_tlv_end(payload, start, end)
        if entry_end is None:
            for candidate in (start + apdu_len, start + apdu_len - 2):
                if start < candidate <= end:
                    entry_end = candidate
                    break
        if entry_end is None:
            break
        apdus.append(
            RGooseApdu(
                tag,
                bool(payload[cursor + 1]),
                int.from_bytes(payload[cursor + 2:cursor + 4], "big"),
                bytes(payload[start:entry_end]),
            )
        )
        cursor = entry_end
    return RGooseSession(
        session_id=session_id,
        spdu_length=spdu_length,
        spdu_number=spdu_number,
        version=version,
        time_of_current_key=time_current,
        time_to_next_key=time_next,
        key_id=key_id,
        iv=bytes(iv),
        apdus=tuple(apdus),
        signature=signature,
        # An encrypted payload (IV present) does not walk as entries.
        payload_parsed=cursor == end,
    )


def _ber_tlv_end(data: bytes, start: int, limit: int) -> int | None:
    """End offset of the BER TLV at ``start`` if it fits within ``limit``."""
    if start + 2 > limit:
        return None
    first = data[start + 1]
    if first < 0x80:
        header, length = 2, first
    else:
        count = first & 0x7F
        if count == 0 or count > 3 or start + 2 + count > limit:
            return None
        header = 2 + count
        length = int.from_bytes(data[start + 2:start + 2 + count], "big")
    end = start + header + length
    return end if end <= limit else None


def _rgoose_from_packet(pkt: object) -> tuple[RGooseSession, str, str, int, int] | None:
    if UDP is None:
        return None
    udp = pkt.getlayer(UDP)  # type: ignore[attr-defined]
    if udp is None:
        return None
    payload = _strip_padding(udp.payload)
    if payload[:2] != b"\x01\x40":
        return None
    session = parse_rgoose(payload)
    if session is None:
        return None
    src_ip, dst_ip = extract_packet_endpoints(pkt)
    return (
        session,
        src_ip or "?",
        dst_ip or "?",
        int(getattr(udp, "sport", 0) or 0),
        int(getattr(udp, "dport", 0) or 0),
    )


def _l2_goose_payload(appid: int, pdu: bytes) -> bytes:
    """APPID/Length/Reserved header + PDU, the shape the L2 path parses."""
    return appid.to_bytes(2, "big") + (8 + len(pdu)).to_bytes(2, "big") + b"\x00" * 4 + pdu


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
    # IEC 61850-90-5 routable GOOSE (R-GOOSE) seen on UDP; its GOOSE PDUs are
    # also counted in goose_packets and checked like L2 GOOSE.
    rgoose_packets: int = 0
    rgoose_publishers: Counter[str] = field(default_factory=Counter)
    rgoose_groups: Counter[str] = field(default_factory=Counter)
    rgoose_ports: Counter[int] = field(default_factory=Counter)
    rgoose_key_ids: Counter[int] = field(default_factory=Counter)
    rgoose_signed: int = 0
    rgoose_unsigned: int = 0
    rgoose_encrypted: int = 0
    rsv_packets: int = 0


def _extract_appid(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[0:2], "big")


def _extract_length(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[2:4], "big")


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
        value = data[idx : idx + length]
        idx += length

        tag_name = GOOSE_TAGS.get(tag)
        if tag_name:
            if tag_name in GOOSE_STRING_TAGS:
                result[tag_name] = value.decode("utf-8", errors="ignore").strip("\x00")
            elif tag_name in GOOSE_INT_TAGS:
                result[tag_name] = int.from_bytes(value, "big") if value else 0
            elif tag_name in GOOSE_BOOL_TAGS:
                result[tag_name] = bool(value[0]) if value else False
            elif tag_name == "allData":
                result["allData_len"] = len(value)
                result["allData_preview"] = value[:16].hex()
                result["allData_values"] = _decode_all_data(value)
        if tag == 0x61:
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
    if len(value) == 5:
        try:
            return struct.unpack(">f", value[1:])[0]
        except Exception:
            return None
    if len(value) == 9:
        try:
            return struct.unpack(">d", value[1:])[0]
        except Exception:
            return None
    if len(value) == 4:
        return struct.unpack(">f", value)[0]
    if len(value) == 8:
        return struct.unpack(">d", value)[0]
    return None


def _decode_bit_string(value: bytes) -> str:
    if not value:
        return ""
    unused_bits = value[0]
    if unused_bits > 7:
        return ""
    bits = "".join(f"{b:08b}" for b in value[1:])
    if unused_bits:
        bits = bits[:-unused_bits]
    return bits


def _decode_all_data(
    data: bytes, depth: int = 0, limit: int = 24
) -> list[tuple[str, str]]:
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
        value = data[idx : idx + length]
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


@memoize_analysis
def analyze_goose(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> GooseSummary:
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
    truncated_header_reported = False
    invalid_length_reported = False
    truncated_payload_reported = False
    detection_limit_reported = False
    tracking_limit_reported = False
    value_sample_limit_reported = False

    def add_detection(detection: dict[str, object]) -> None:
        nonlocal detection_limit_reported
        if len(detections) < MAX_GOOSE_DETECTIONS:
            detections.append(detection)
        elif not detection_limit_reported:
            errors.append(
                "GOOSE detection record limit reached; additional findings were omitted."
            )
            detection_limit_reported = True
    state_map: dict[
        tuple[str, str, str], tuple[int, int, Optional[float], Optional[int]]
    ] = {}
    conf_map: dict[tuple[str, str, str], int] = {}
    entries_map: dict[tuple[str, str, str], int] = {}
    jump_flagged: set[tuple[str, str, str]] = set()
    sim_flagged: set[tuple[str, str, str]] = set()
    ndscom_flagged: set[tuple[str, str, str]] = set()
    # gocbRef -> set of publishing source MACs. A given GOOSE control block has
    # exactly ONE legitimate publisher MAC; the same gocbRef from a 2nd MAC is
    # the classic publisher-spoofing / injection attack (Industroyer-class,
    # ATT&CK ICS T0856 Spoof Reporting Message / T0832 Manipulation of View).
    gocbref_macs: dict[tuple[str, str, str], set[str]] = {}
    gocbref_spoof_flagged: set[tuple[str, str, str]] = set()
    data_len_map: dict[tuple[str, str, str], int] = {}

    routable_sq_seen: dict[tuple[str, str, str], tuple[int, set[int]]] = {}
    routable_reordered: Counter[tuple[str, str, str]] = Counter()

    def _process_frame(
        src_mac: str, dst_mac: str, payload: bytes, ts: Optional[float], routable: bool
    ) -> None:
        """One GOOSE PDU, from L2 (publisher = MAC) or from an R-GOOSE session
        (publisher = source IP). ``payload`` is APPID/Length/Reserved + PDU."""
        nonlocal goose_packets, first_seen, last_seen, truncated_header_reported
        nonlocal invalid_length_reported, truncated_payload_reported
        nonlocal tracking_limit_reported, value_sample_limit_reported
        goose_packets += 1
        # The report window spans this protocol's traffic, not every packet.
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts
        src_macs[src_mac] += 1
        dst_macs[dst_mac] += 1
        if not routable:
            try:
                first_octet = int(dst_mac.split(":")[0], 16)
                if (first_octet & 1) == 0:
                    unicast_dsts.add(dst_mac)
            except Exception:
                pass
        appid = _extract_appid(payload)
        if appid is not None:
            appid_label = f"0x{appid:04x}"
            app_ids[appid_label] += 1
            src_appids.setdefault(src_mac, set()).add(appid_label)
        length = _extract_length(payload)
        if length is not None:
            lengths[length] += 1
        if len(payload) < 8:
            if not truncated_header_reported:
                errors.append("GOOSE frame is shorter than its 8-byte Ethernet header.")
                truncated_header_reported = True
            return
        if length is None or length < 8:
            if not invalid_length_reported:
                errors.append("GOOSE frame has an invalid declared length.")
                invalid_length_reported = True
            return
        if length > len(payload):
            if not truncated_payload_reported:
                errors.append("GOOSE frame is shorter than its declared length.")
                truncated_payload_reported = True
            return
        payload = payload[:length]

        goose_info = _parse_goose_payload(payload) if payload else {}
        dataset = str(goose_info.get("datSet", "") or "")
        gocb_ref = str(goose_info.get("gocbRef", "") or "")
        st_num = goose_info.get("stNum")
        sq_num = goose_info.get("sqNum")
        conf_rev = goose_info.get("confRev")
        num_entries_val = goose_info.get("numDatSetEntries")
        data_len = goose_info.get("allData_len")
        data_values = goose_info.get("allData_values") or []

        # Simulation/test bit (IEC 61850-8-1 "simulation"/"test"): an IED in
        # Sim mode acts on these frames, so a test frame on a production bus
        # is a classic GOOSE-injection vector (ATT&CK ICS T0852/T0856).
        # ndsCom=true means the GoCB is not properly commissioned.
        sim_key = (src_mac, f"0x{appid:04x}" if appid is not None else "-",
                   dataset or gocb_ref or "-")
        if goose_info.get("simulation") and sim_key not in sim_flagged:
            if len(sim_flagged) < MAX_GOOSE_TRACKED_STREAMS:
                sim_flagged.add(sim_key)
            add_detection(
                {
                    "severity": "warning",
                    "summary": "GOOSE Simulation/Test Bit Set",
                    "details": (
                        f"{src_mac} {sim_key[2]} published GOOSE with the "
                        "simulation/test bit set; IEDs in Sim mode will act "
                        "on it (possible test-frame injection)."
                    ),
                }
            )
        if goose_info.get("ndsCom") and sim_key not in ndscom_flagged:
            if len(ndscom_flagged) < MAX_GOOSE_TRACKED_STREAMS:
                ndscom_flagged.add(sim_key)
            add_detection(
                {
                    "severity": "info",
                    "summary": "GOOSE needsCommissioning Set",
                    "details": (
                        f"{src_mac} {sim_key[2]} published GOOSE with "
                        "ndsCom=true (control block not commissioned / "
                        "configuration incomplete)."
                    ),
                }
            )
        if dataset:
            datasets[dataset] += 1
        if gocb_ref:
            gocb_refs[gocb_ref] += 1
            # Compare publishers only within the same GOOSE stream identity.
            spoof_key = (
                gocb_ref,
                f"0x{appid:04x}" if appid is not None else "-",
                dataset or "-",
            )
            macs = gocbref_macs.get(spoof_key)
            if macs is None and len(gocbref_macs) >= MAX_GOOSE_TRACKED_STREAMS:
                if not tracking_limit_reported:
                    errors.append(
                        "GOOSE stream tracking limit reached; additional publisher identities were omitted."
                    )
                    tracking_limit_reported = True
                macs = None
            else:
                macs = gocbref_macs.setdefault(spoof_key, set())
                if len(macs) < 2:
                    macs.add(src_mac)
            if macs is not None and len(macs) >= 2 and spoof_key not in gocbref_spoof_flagged:
                gocbref_spoof_flagged.add(spoof_key)
                add_detection(
                    {
                        "severity": "high",
                        "summary": "GOOSE Publisher Spoofing",
                        "details": (
                            f"gocbRef {gocb_ref} (APPID {spoof_key[1]}, "
                            f"dataset {spoof_key[2]}) published from multiple source "
                            f"MACs ({', '.join(sorted(macs))}); a control block has "
                            "one legitimate publisher — likely GOOSE spoofing/"
                            "injection (ATT&CK ICS T0856)."
                        ),
                    }
                )
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
                if sample in data_value_samples or len(data_value_samples) < MAX_GOOSE_VALUE_SAMPLES:
                    data_value_samples[sample] += 1
                elif not value_sample_limit_reported:
                    errors.append(
                        "GOOSE value sample limit reached; additional unique samples were omitted."
                    )
                    value_sample_limit_reported = True

        if (
            appid is not None
            and isinstance(st_num, int)
            and isinstance(sq_num, int)
        ):
            key = (src_mac, f"0x{appid:04x}", dataset or gocb_ref or "-")
            if key not in state_map and len(state_map) >= MAX_GOOSE_TRACKED_STREAMS:
                if not tracking_limit_reported:
                    errors.append(
                        "GOOSE stream tracking limit reached; additional publisher state was omitted."
                    )
                    tracking_limit_reported = True
                return
            prev = state_map.get(key)
            if prev:
                prev_st, prev_sq, prev_ts, prev_ttl = prev
                expired = (
                    ts is not None
                    and prev_ts is not None
                    and prev_ttl is not None
                    and prev_ttl > 0
                    and ts - prev_ts > prev_ttl / 1000
                )
                if not expired:
                    if st_num < prev_st:
                        add_detection(
                            {
                                "severity": "warning",
                                "summary": "GOOSE State Number Decrease",
                                "details": f"{key[0]} {key[2]} stNum decreased {prev_st}->{st_num}.",
                            }
                        )
                    reordered = False
                    if routable and st_num == prev_st and sq_num < prev_sq:
                        # Routed delivery reorders: a lower sqNum that was
                        # never seen in this state fills a gap, it is not a
                        # reset or a replay.
                        seen_sqs = routable_sq_seen.get(key)
                        reordered = not (
                            seen_sqs and seen_sqs[0] == st_num and sq_num in seen_sqs[1]
                        )
                        if reordered:
                            routable_reordered[key] += 1
                    if st_num == prev_st and sq_num < prev_sq and not reordered:
                        add_detection(
                            {
                                "severity": "warning",
                                "summary": "GOOSE Sequence Reset",
                                "details": f"{key[0]} {key[2]} sqNum decreased {prev_sq}->{sq_num}.",
                            }
                        )
                    # State advances normally restart sqNum at 0 (some stacks
                    # use 1). A skipped state or high starting sequence can
                    # indicate missed or injected GOOSE, but capture gaps look
                    # the same, so this is informational and emitted once.
                    if st_num > prev_st and key not in jump_flagged:
                        skipped_states = st_num - prev_st > 1
                        high_start_sq = sq_num > 1
                        if skipped_states or high_start_sq:
                            jump_flagged.add(key)
                            reasons = []
                            if skipped_states:
                                reasons.append(f"stNum jumped {prev_st}->{st_num}")
                            if high_start_sq:
                                reasons.append(f"new state started at sqNum={sq_num}")
                            add_detection(
                                {
                                    "severity": "info",
                                    "summary": "GOOSE State Jump",
                                    "details": (
                                        f"{key[0]} {key[2]} {'; '.join(reasons)} "
                                        "(possible missed frames or injected GOOSE)."
                                    ),
                                }
                            )
            if routable:
                seen_sqs = routable_sq_seen.get(key)
                if seen_sqs is None or seen_sqs[0] != st_num:
                    seen_sqs = (st_num, set())
                    routable_sq_seen[key] = seen_sqs
                if len(seen_sqs[1]) < 4096:
                    seen_sqs[1].add(sq_num)
            ttl = goose_info.get("timeAllowedToLive")
            if routable and prev and st_num == prev[0] and sq_num < prev[1]:
                # Keep the high-water mark so a reordered frame does not make
                # the next in-order one look like a jump.
                return
            state_map[key] = (
                st_num,
                sq_num,
                ts,
                ttl if isinstance(ttl, int) else None,
            )
            if isinstance(conf_rev, int):
                prev_conf = conf_map.get(key)
                if prev_conf is not None and conf_rev != prev_conf:
                    add_detection(
                        {
                            "severity": "warning",
                            "summary": "GOOSE Config Revision Change",
                            "details": f"{key[0]} {key[2]} confRev changed {prev_conf}->{conf_rev}.",
                        }
                    )
                conf_map[key] = conf_rev
            if isinstance(num_entries_val, int):
                prev_entries = entries_map.get(key)
                if prev_entries is not None and num_entries_val != prev_entries:
                    add_detection(
                        {
                            "severity": "warning",
                            "summary": "GOOSE Dataset Size Change",
                            "details": f"{key[0]} {key[2]} numDatSetEntries changed {prev_entries}->{num_entries_val}.",
                        }
                    )
                entries_map[key] = num_entries_val
            if isinstance(data_len, int):
                prev_len = data_len_map.get(key)
                if prev_len is not None and data_len != prev_len:
                    add_detection(
                        {
                            "severity": "warning",
                            "summary": "GOOSE Dataset Payload Size Change",
                            "details": f"{key[0]} {key[2]} allData length changed {prev_len}->{data_len}.",
                        }
                    )
                data_len_map[key] = data_len


    rgoose_packets = 0
    rsv_packets = 0
    rgoose_publishers: Counter[str] = Counter()
    rgoose_groups: Counter[str] = Counter()
    rgoose_ports: Counter[int] = Counter()
    rgoose_key_ids: Counter[int] = Counter()
    rgoose_signed = 0
    rgoose_unsigned = 0
    rgoose_encrypted = 0
    rgoose_flows: Counter[tuple[str, str, int]] = Counter()
    # Per publisher flow: the highest SPDU number, and recently seen numbers
    # with a content fingerprint and time, to tell a replay (a number seen
    # before, re-sent later or with different content) from an exact copy
    # captured twice (PRP/duplicate path) and from plain reordering.
    spdu_max: dict[tuple[str, str, int], int] = {}
    spdu_seen: dict[tuple[str, str, int], "OrderedDict[int, tuple[int, Optional[float]]]"] = {}
    spdu_replays: Counter[tuple[str, str, int]] = Counter()
    spdu_replay_samples: dict[tuple[str, str, int], str] = {}
    spdu_duplicates: Counter[tuple[str, str, int]] = Counter()
    spdu_reordered: Counter[tuple[str, str, int]] = Counter()
    publisher_keys: dict[str, set[int]] = {}

    def _process_rgoose(
        found: tuple[RGooseSession, str, str, int, int], ts: Optional[float]
    ) -> None:
        nonlocal rgoose_packets, rsv_packets, rgoose_signed, rgoose_unsigned
        nonlocal rgoose_encrypted
        session, src_ip, dst_ip, _sport, dport = found
        rgoose_packets += 1
        rgoose_publishers[src_ip] += 1
        rgoose_groups[dst_ip] += 1
        rgoose_ports[dport] += 1
        rgoose_key_ids[session.key_id] += 1
        rgoose_flows[(src_ip, dst_ip, dport)] += 1
        publisher_keys.setdefault(src_ip, set()).add(session.key_id)
        if session.signature:
            rgoose_signed += 1
        else:
            rgoose_unsigned += 1
        if session.iv and not session.payload_parsed:
            rgoose_encrypted += 1
        # SPDU numbers rise by one per session PDU from a publisher.
        flow = (src_ip, dst_ip, dport)
        number = session.spdu_number
        fingerprint = hash((number, tuple(a.apdu for a in session.apdus), session.signature))
        seen = spdu_seen.setdefault(flow, OrderedDict())
        earlier = seen.get(number)
        if earlier is not None:
            same_content = earlier[0] == fingerprint
            close = ts is not None and earlier[1] is not None and abs(ts - earlier[1]) <= 0.05
            if same_content and close:
                spdu_duplicates[flow] += 1
            else:
                spdu_replays[flow] += 1
                spdu_replay_samples.setdefault(
                    flow,
                    f"SPDU number {number} seen again"
                    + (" with different content" if not same_content else " later"),
                )
        elif flow in spdu_max and number < spdu_max[flow]:
            spdu_reordered[flow] += 1
        seen[number] = (fingerprint, ts)
        if len(seen) > 1024:
            seen.popitem(last=False)
        if number > spdu_max.get(flow, -1):
            spdu_max[flow] = number
        for apdu in session.apdus:
            if apdu.tag == 0x81:
                _process_frame(src_ip, dst_ip, _l2_goose_payload(apdu.appid, apdu.apdu), ts, True)
            elif apdu.tag == 0x82:
                rsv_packets += 1
            elif apdu.tag == 0x83:
                # A tunnelled Ethernet frame: GOOSE inside if its EtherType says so.
                frame = apdu.apdu
                offset = 12
                while len(frame) >= offset + 2 and frame[offset:offset + 2] in (b"\x81\x00", b"\x88\xa8"):
                    offset += 4
                if frame[offset:offset + 2] == b"\x88\xb8":
                    _process_frame(
                        f"{src_ip} (tunnelled {frame[6:12].hex(':')})",
                        dst_ip,
                        frame[offset + 2:],
                        ts,
                        True,
                    )

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        ts = safe_float(getattr(pkt, "time", None))

        if not pkt.haslayer(Ether):  # type: ignore[truthy-bool]
            # Cooked/raw-IP captures have no Ethernet header; R-GOOSE rides
            # on UDP and is still there.
            rgoose = _rgoose_from_packet(pkt)
            if rgoose is not None:
                _process_rgoose(rgoose, ts)
            continue
        eth = pkt[Ether]  # type: ignore[index]
        eth_type = int(getattr(eth, "type", 0) or 0)
        goose_layer = eth.payload
        while eth_type in {0x8100, 0x88A8, 0x9100}:
            inner_type = getattr(goose_layer, "type", None)
            if inner_type is None:
                break
            eth_type = int(inner_type)
            goose_layer = goose_layer.payload
        if eth_type != GOOSE_ETHERTYPE:
            rgoose = _rgoose_from_packet(pkt)
            if rgoose is not None:
                _process_rgoose(rgoose, ts)
            continue
        try:
            l2_payload = bytes(goose_layer)
        except Exception:
            l2_payload = b""
        _process_frame(
            str(getattr(eth, "src", "-")),
            str(getattr(eth, "dst", "-")),
            l2_payload,
            ts,
            False,
        )

    if goose_packets:
        add_detection(
            {
                "severity": "info",
                "summary": "IEC 61850 GOOSE traffic observed",
                "details": (
                    f"{goose_packets} GOOSE PDUs"
                    + (f", {rgoose_packets} of them in R-GOOSE session PDUs on UDP" if rgoose_packets else " at L2")
                    + "."
                ),
            }
        )
    if rgoose_packets:
        flows = ", ".join(
            f"{src} -> {dst} udp/{port} ({count})"
            for (src, dst, port), count in rgoose_flows.most_common(5)
        )
        public = sorted(
            ip for ip in set(rgoose_publishers) | set(rgoose_groups) if is_public_ip(ip)
        )
        if public:
            add_detection(
                {
                    "severity": "high",
                    "summary": "R-GOOSE exposed to a public IP",
                    "details": (
                        "Routable GOOSE with public endpoint(s): " + ", ".join(public[:5])
                        + " (ATT&CK for ICS T0883 Internet Accessible Device)."
                    ),
                }
            )
        add_detection(
            {
                "severity": "warning" if rgoose_unsigned else "info",
                "summary": "GOOSE routed beyond the substation LAN (R-GOOSE, IEC 61850-90-5)",
                "details": (
                    f"{rgoose_packets} R-GOOSE session PDU(s): {flows}. Protection "
                    "signalling crosses an IP boundary, so it is reachable (and "
                    "spoofable) from every routed network that can reach the group; "
                    "confirm the routing scope, multicast filtering and GDOI keying."
                ),
                "evidence": [
                    f"publisher {ip}: key ID(s) {', '.join(str(k) for k in sorted(keys))}"
                    for ip, keys in list(publisher_keys.items())[:6]
                ],
            }
        )
        if rgoose_unsigned:
            add_detection(
                {
                    "severity": "high",
                    "summary": "R-GOOSE without message authentication",
                    "details": (
                        f"{rgoose_unsigned} R-GOOSE session PDU(s) carry no signature "
                        "(HMAC); IEC 61850-90-5 requires one. Anyone who can route to the "
                        "group can inject protection signals (ATT&CK for ICS T0856 Spoof "
                        "Reporting Message, T0855 Unauthorized Command Message)."
                    ),
                }
            )
        for flow, count in spdu_replays.most_common(5):
            src, dst, port = flow
            add_detection(
                {
                    "severity": "high",
                    "summary": "R-GOOSE session PDU replayed (SPDU number reused)",
                    "details": (
                        f"{src} -> {dst} udp/{port}: {count} session PDU(s) reused an "
                        f"SPDU number ({spdu_replay_samples.get(flow, '')}); replayed or "
                        "injected R-GOOSE (ATT&CK for ICS T0856 Spoof Reporting Message)."
                    ),
                }
            )
        reordered = sum(spdu_reordered.values())
        duplicates = sum(spdu_duplicates.values())
        if reordered or duplicates:
            add_detection(
                {
                    "severity": "info",
                    "summary": "R-GOOSE delivery irregularities (reordering/duplicates)",
                    "details": (
                        f"{reordered} session PDU(s) arrived out of SPDU order and "
                        f"{duplicates} were exact copies within 50 ms (duplicate paths "
                        "or capture duplication); not replays: no SPDU number was reused "
                        "with new content or later in time."
                    ),
                }
            )
        nonstandard = sorted(port for port in rgoose_ports if port != RGOOSE_STANDARD_UDP_PORT)
        if nonstandard:
            add_detection(
                {
                    "severity": "info",
                    "summary": "R-GOOSE on a non-standard UDP port",
                    "details": (
                        "IEC 61850-90-5 binds the session protocol to UDP 102; observed on "
                        + ", ".join(f"udp/{port}" for port in nonstandard[:5])
                        + " (found by payload structure, port-agnostic)."
                    ),
                }
            )
    for src_mac, appid_set in src_appids.items():
        if len(appid_set) >= 5:
            add_detection(
                {
                    "severity": "warning",
                    "summary": "GOOSE Source Uses Many AppIDs",
                    "details": f"{src_mac} advertised {len(appid_set)} AppIDs (possible spoofing or misconfiguration).",
                }
            )
    if unicast_dsts:
        add_detection(
            {
                "severity": "warning",
                "summary": "GOOSE Unicast Destinations",
                "details": f"Unicast MAC destinations observed: {', '.join(sorted(unicast_dsts)[:5])}.",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
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
        rgoose_packets=rgoose_packets,
        rgoose_publishers=rgoose_publishers,
        rgoose_groups=rgoose_groups,
        rgoose_ports=rgoose_ports,
        rgoose_key_ids=rgoose_key_ids,
        rgoose_signed=rgoose_signed,
        rgoose_unsigned=rgoose_unsigned,
        rgoose_encrypted=rgoose_encrypted,
        rsv_packets=rsv_packets,
    )
