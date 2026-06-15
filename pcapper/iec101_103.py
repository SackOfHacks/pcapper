from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float, extract_packet_endpoints

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


@dataclass(frozen=True)
class Iec101103Summary:
    path: Path
    total_packets: int
    candidate_packets: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    type_counts: Counter[str]
    cause_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


CAUSES = {
    1: "Periodic",
    2: "Background",
    3: "Spontaneous",
    4: "Initialized",
    5: "Request",
    6: "Activation",
    7: "Activation Confirmation",
    8: "Deactivation",
    9: "Deactivation Confirmation",
    10: "Activation Termination",
}

# Control-direction ASDU type IDs (commands that change process/IED state).
# A command type carrying an Activation/Deactivation cause (COT 6/8) is an
# unauthorized-command indicator -- benign monitoring uses Periodic/Spontaneous.
IEC_COMMAND_TYPES = {
    45: "C_SC_NA (Single Command)",
    46: "C_DC_NA (Double Command)",
    47: "C_RC_NA (Regulating Step Command)",
    48: "C_SE_NA (Setpoint, normalized)",
    49: "C_SE_NB (Setpoint, scaled)",
    50: "C_SE_NC (Setpoint, short float)",
    51: "C_BO_NA (Bitstring 32-bit)",
    58: "C_SC_TA (Single Command +time)",
    59: "C_DC_TA (Double Command +time)",
    60: "C_RC_TA (Regulating Step +time)",
    61: "C_SE_TA (Setpoint normalized +time)",
    62: "C_SE_TB (Setpoint scaled +time)",
    63: "C_SE_TC (Setpoint float +time)",
    64: "C_BO_TA (Bitstring +time)",
    105: "C_RP_NA (Reset Process Command)",
}
_IEC_ACTIVATION_COTS = {6, 8}


def _parse_asdu(
    payload: bytes,
) -> tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    if len(payload) < 9:
        return None, None, None, None
    if payload[0] != 0x68:
        return None, None, None, None
    if len(payload) >= 6 and payload[3] == 0x68:
        idx = 6
    else:
        idx = 6
    if idx + 6 > len(payload):
        return None, None, None, None
    type_id = payload[idx]
    vsq = payload[idx + 1]
    _ = vsq
    cot_raw = int.from_bytes(payload[idx + 2 : idx + 4], "little")
    cot = cot_raw & 0x3F
    cause_name = CAUSES.get(cot, f"COT {cot}")
    type_name = f"ASDU {type_id}"
    return type_name, cause_name, type_id, cot


def _iec_apdu_candidate(payload: bytes) -> bool:
    # IEC 60870-5-101/103 FT1.2 *variable*-length frame: 0x68 L L 0x68 <L user
    # bytes> CS 0x16. Requiring the repeated start byte AND the repeated length
    # field (payload[1]==payload[2]) makes the signature specific — a bare
    # "starts with 0x68" test matches ~0.2% of arbitrary binary/IT traffic and
    # produced false "IEC-101/103 exposure" detections on malware/HTTP captures.
    if not payload or len(payload) < 6:
        return False
    if payload[0] != 0x68 or payload[3] != 0x68:
        return False
    length = payload[1]
    if length != payload[2] or not (1 <= length <= 253):
        return False
    # The frame is 0x68 L L 0x68 + L user bytes + checksum + 0x16. Validate the
    # declared length against the captured frame where it isn't TCP-coalesced.
    expected = length + 6
    if len(payload) >= expected and payload[expected - 1] != 0x16:
        return False
    return True


def analyze_iec101_103(path: Path, show_status: bool = True) -> Iec101103Summary:
    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        # Unreadable/unsupported capture — return gracefully like the other
        # analyzers instead of propagating the exception and crashing the run.
        return Iec101103Summary(
            path=path,
            total_packets=0,
            candidate_packets=0,
            client_counts=Counter(),
            server_counts=Counter(),
            type_counts=Counter(),
            cause_counts=Counter(),
            detections=[],
            errors=[f"{type(exc).__name__}: {exc}"],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )
    total_packets = 0
    candidate_packets = 0
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    cause_counts: Counter[str] = Counter()
    # (src, dst, type_id) -> count of control commands carrying an
    # Activation/Deactivation cause (the unauthorized-command surface).
    command_activations: dict[tuple[str, str, int], int] = {}
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

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

            payload = b""
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[TCP], "payload", b""))  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[UDP], "payload", b""))  # type: ignore[index]
            if not _iec_apdu_candidate(payload):
                continue

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            candidate_packets += 1
            client_counts[src_ip] += 1
            server_counts[dst_ip] += 1

            type_name, cause_name, type_id, cot = _parse_asdu(payload)
            if type_name:
                type_counts[type_name] += 1
            if cause_name:
                cause_counts[cause_name] += 1
            if (
                type_id in IEC_COMMAND_TYPES
                and cot in _IEC_ACTIVATION_COTS
            ):
                key = (src_ip, dst_ip, type_id)
                command_activations[key] = command_activations.get(key, 0) + 1

    finally:
        status.finish()
        reader.close()

    if candidate_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "IEC 60870-5-101/103 candidate traffic observed",
                "details": f"{candidate_packets} packets matched IEC 101/103 APDU framing heuristics.",
            }
        )
    if command_activations:
        top = sorted(
            command_activations.items(), key=lambda kv: kv[1], reverse=True
        )[:8]
        evidence = [
            f"{src} -> {dst}: {IEC_COMMAND_TYPES[tid]} x{cnt} (Activation)"
            for (src, dst, tid), cnt in top
        ]
        has_reset = any(tid == 105 for (_s, _d, tid) in command_activations)
        detections.append(
            {
                "severity": "high",
                "summary": "IEC 101/103 Control Command (Activation)",
                "details": (
                    f"{sum(command_activations.values())} control-command activation(s) "
                    "observed (setpoint/command/reset to controlled equipment). "
                    "Confirm authorization and change-window."
                ),
                "evidence": evidence,
                "attack": "T0816 Device Restart/Shutdown"
                if has_reset
                else "T0855 Unauthorized Command Message",
            }
        )

    unique_clients = len(client_counts)
    unique_servers = len(server_counts)
    if unique_servers >= 20 and candidate_packets >= 50:
        detections.append(
            {
                "severity": "warning",
                "summary": "IEC 101/103 Broad Polling Pattern",
                "details": f"{unique_clients} clients contacted {unique_servers} servers (possible scanning or wide polling).",
            }
        )
    public_endpoints = []
    for ip_value in set(client_counts) | set(server_counts):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints:
        detections.append(
            {
                "severity": "high",
                "summary": "IEC 101/103 Exposure to Public IP",
                "details": f"IEC 101/103 candidate traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return Iec101103Summary(
        path=path,
        total_packets=total_packets,
        candidate_packets=candidate_packets,
        client_counts=client_counts,
        server_counts=server_counts,
        type_counts=type_counts,
        cause_counts=cause_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
