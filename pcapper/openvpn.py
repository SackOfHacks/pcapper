from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


OPENVPN_OPCODES = {
    1: "OpenVPN P_CONTROL_HARD_RESET_CLIENT_V1",
    2: "OpenVPN P_CONTROL_HARD_RESET_SERVER_V1",
    3: "OpenVPN P_CONTROL_SOFT_RESET_V1",
    4: "OpenVPN P_CONTROL_V1",
    5: "OpenVPN P_ACK_V1",
    6: "OpenVPN P_DATA_V1",
    7: "OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2",
    8: "OpenVPN P_CONTROL_HARD_RESET_SERVER_V2",
    9: "OpenVPN P_DATA_V2",
    10: "OpenVPN P_CONTROL_HARD_RESET_CLIENT_V3",
}

OPENVPN_CONTROL_OPCODES = {1, 2, 3, 4, 5, 7, 8, 10}
OPENVPN_CLIENT_RESET_OPCODES = {1, 7, 10}
OPENVPN_SERVER_RESET_OPCODES = {2, 8}


@dataclass(frozen=True)
class OpenVpnFrame:
    opcode: int
    key_id: int
    name: str
    frame_len: int


@dataclass(frozen=True)
class OpenVpnControlPayload:
    opcode: int
    key_id: int
    packet_id: int | None
    data: bytes
    frame_len: int


def openvpn_opcode_name(opcode: int) -> str:
    return OPENVPN_OPCODES.get(opcode, f"OpenVPN opcode {opcode}")


def _parse_opcode_byte(value: int) -> tuple[int, int] | None:
    opcode = (int(value) >> 3) & 0x1F
    key_id = int(value) & 0x07
    if opcode not in OPENVPN_OPCODES:
        return None
    return opcode, key_id


def iter_openvpn_udp_frames(payload: bytes) -> Iterable[OpenVpnFrame]:
    if not payload:
        return
    parsed = _parse_opcode_byte(payload[0])
    if parsed is None:
        return
    opcode, key_id = parsed
    yield OpenVpnFrame(opcode, key_id, openvpn_opcode_name(opcode), len(payload))


def iter_openvpn_tcp_frames(payload: bytes) -> Iterable[OpenVpnFrame]:
    """Yield OpenVPN-over-TCP frames from a payload.

    OpenVPN TCP packets are length-prefixed: u16 big-endian length followed by
    opcode/key-id in the high/low bits of the first framed byte. Captures may
    contain one frame, a partial frame, or several coalesced frames; accept the
    complete leading frame(s) and ignore trailing partial bytes.
    """
    offset = 0
    total = len(payload or b"")
    while offset + 3 <= total:
        declared_len = int.from_bytes(payload[offset : offset + 2], "big")
        if declared_len <= 0:
            return
        frame_start = offset + 2
        frame_end = frame_start + declared_len
        if frame_end > total:
            return
        parsed = _parse_opcode_byte(payload[frame_start])
        if parsed is None:
            return
        opcode, key_id = parsed
        yield OpenVpnFrame(opcode, key_id, openvpn_opcode_name(opcode), declared_len)
        offset = frame_end


def iter_openvpn_tcp_frame_payloads(payload: bytes) -> Iterable[bytes]:
    """Yield OpenVPN TCP frame bodies, without the two-byte length prefix.

    The returned bytes still include OpenVPN's opcode/key-id byte and any
    control-channel metadata. Consumers that need embedded TLS records should
    scan inside the frame body rather than assuming TLS starts at offset zero.
    """
    offset = 0
    total = len(payload or b"")
    while offset + 3 <= total:
        declared_len = int.from_bytes(payload[offset : offset + 2], "big")
        if declared_len <= 0:
            return
        frame_start = offset + 2
        frame_end = frame_start + declared_len
        if frame_end > total:
            return
        parsed = _parse_opcode_byte(payload[frame_start])
        if parsed is None:
            return
        yield bytes(payload[frame_start:frame_end])
        offset = frame_end


def _parse_openvpn_control_payload(frame_payload: bytes) -> OpenVpnControlPayload | None:
    parsed = _parse_opcode_byte(frame_payload[0]) if frame_payload else None
    if parsed is None:
        return None
    opcode, key_id = parsed
    if opcode not in OPENVPN_CONTROL_OPCODES:
        return None

    pos = 1 + 8  # opcode/key-id + local session_id
    if pos >= len(frame_payload):
        return None
    ack_count = frame_payload[pos]
    pos += 1
    ack_bytes = ack_count * 4
    if pos + ack_bytes > len(frame_payload):
        return None
    pos += ack_bytes
    if ack_count:
        if pos + 8 > len(frame_payload):
            return None
        pos += 8  # remote_session_id

    packet_id: int | None = None
    if opcode != 5:  # P_ACK_V1 has no message packet-id or payload.
        if pos + 4 > len(frame_payload):
            return None
        packet_id = int.from_bytes(frame_payload[pos : pos + 4], "big")
        pos += 4

    return OpenVpnControlPayload(
        opcode=opcode,
        key_id=key_id,
        packet_id=packet_id,
        data=bytes(frame_payload[pos:]),
        frame_len=len(frame_payload),
    )


def iter_openvpn_tcp_control_payloads(payload: bytes) -> Iterable[OpenVpnControlPayload]:
    """Yield OpenVPN control-channel data after stripping protocol headers."""
    for frame_payload in iter_openvpn_tcp_frame_payloads(payload):
        parsed = _parse_openvpn_control_payload(frame_payload)
        if parsed is not None:
            yield parsed


def openvpn_tcp_control_opcodes(payload: bytes) -> list[int]:
    return [
        frame.opcode
        for frame in iter_openvpn_tcp_frames(payload)
        if frame.opcode in OPENVPN_CONTROL_OPCODES
    ]


def openvpn_udp_control_opcodes(payload: bytes) -> list[int]:
    return [
        frame.opcode
        for frame in iter_openvpn_udp_frames(payload)
        if frame.opcode in OPENVPN_CONTROL_OPCODES
    ]


def is_openvpn_tcp_control(payload: bytes) -> bool:
    return bool(openvpn_tcp_control_opcodes(payload))


def is_openvpn_udp_control(payload: bytes) -> bool:
    return bool(openvpn_udp_control_opcodes(payload))


def tcp_flow_id(
    src_ip: str, sport: int, dst_ip: str, dport: int
) -> tuple[tuple[str, int], tuple[str, int]]:
    left = (str(src_ip), int(sport))
    right = (str(dst_ip), int(dport))
    return (left, right) if left <= right else (right, left)
