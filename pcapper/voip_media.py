"""Media-plane decoding for VoIP: RTP, RTCP, SRTP, T.38 fax and STUN/TURN.

Split from :mod:`pcapper.voip` so the media parsing can be unit-tested against
synthetic packets without a capture, and so the signalling module stays
readable.

The G.711 decoders here are hand-written on purpose: ``audioop`` carried them
until it was removed from the standard library in Python 3.13, and this package
supports 3.9 through 3.13. They are the only codecs pcapper turns back into
audio — G.711 is a byte-per-sample table lookup, while G.729, G.722, iLBC and
Opus need real codec implementations. Anything else is reported and left as
raw payload.
"""

from __future__ import annotations

import struct
import wave
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# RFC 3551 static payload types.
RTP_STATIC_PAYLOAD_TYPES = {
    0: "PCMU/8000", 3: "GSM/8000", 4: "G723/8000", 5: "DVI4/8000",
    6: "DVI4/16000", 7: "LPC/8000", 8: "PCMA/8000", 9: "G722/8000",
    10: "L16/44100/2", 11: "L16/44100", 12: "QCELP/8000", 13: "CN/8000",
    14: "MPA/90000", 15: "G728/8000", 16: "DVI4/11025", 17: "DVI4/22050",
    18: "G729/8000", 25: "CelB/90000", 26: "JPEG/90000", 28: "nv/90000",
    31: "H261/90000", 32: "MPV/90000", 33: "MP2T/90000", 34: "H263/90000",
}

# RFC 3550 reserves 72-76 so an RTCP packet is never read as RTP.
RTCP_SHADOW_PAYLOAD_TYPES = frozenset(range(72, 77))

RTCP_PACKET_TYPES = {
    200: "Sender Report", 201: "Receiver Report", 202: "Source Description",
    203: "Goodbye", 204: "Application-Defined", 205: "Transport Feedback",
    206: "Payload-Specific Feedback", 207: "Extended Report",
}

RTCP_SDES_ITEMS = {
    1: "CNAME", 2: "NAME", 3: "EMAIL", 4: "PHONE", 5: "LOC",
    6: "TOOL", 7: "NOTE", 8: "PRIV",
}

# RFC 4733 telephone-event codes.
DTMF_EVENTS = {
    **{n: str(n) for n in range(10)},
    10: "*", 11: "#", 12: "A", 13: "B", 14: "C", 15: "D", 16: "!",
}

# Ports whose traffic must never be promoted to RTP no matter how the first two
# bytes fall. Every one of these carries binary that can satisfy a two-bit
# version field by accident.
NON_RTP_UDP_PORTS = frozenset(
    {53, 67, 68, 69, 88, 123, 137, 138, 161, 162, 389, 500, 514, 520, 546, 547,
     623, 1194, 1701, 1812, 1813, 1900, 2427, 2727, 4500, 4569, 5353, 5355,
     47808}
)

STUN_MAGIC_COOKIE = b"\x21\x12\xa4\x42"
STUN_PORTS = frozenset({3478, 3479, 5349, 5350, 19302})
STUN_METHODS = {
    0x0001: "Binding", 0x0003: "Allocate", 0x0004: "Refresh",
    0x0006: "Send", 0x0007: "Data", 0x0008: "CreatePermission",
    0x0009: "ChannelBind",
}
STUN_ATTRS = {
    0x0001: "MAPPED-ADDRESS", 0x0006: "USERNAME", 0x0008: "MESSAGE-INTEGRITY",
    0x0009: "ERROR-CODE", 0x0014: "REALM", 0x0015: "NONCE",
    0x0020: "XOR-MAPPED-ADDRESS", 0x000C: "CHANNEL-NUMBER",
    0x000D: "LIFETIME", 0x0012: "XOR-PEER-ADDRESS",
    0x0016: "XOR-RELAYED-ADDRESS", 0x0019: "REQUESTED-TRANSPORT",
    0x8022: "SOFTWARE", 0x0024: "PRIORITY", 0x0025: "USE-CANDIDATE",
}

# T.38 fax relay rides UDPTL (usually) on a dynamically negotiated port.
T38_INDICATORS = (b"\x00\x00", )


# --- G.711 ------------------------------------------------------------------
def _build_ulaw_table() -> tuple[int, ...]:
    """ITU-T G.711 mu-law -> 16-bit signed PCM, precomputed for all 256 bytes."""
    exp_lut = (0, 132, 396, 924, 1980, 4092, 8316, 16764)
    table = []
    for byte in range(256):
        value = ~byte & 0xFF
        sign = value & 0x80
        exponent = (value >> 4) & 0x07
        mantissa = value & 0x0F
        sample = exp_lut[exponent] + (mantissa << (exponent + 3))
        table.append(-sample if sign else sample)
    return tuple(table)


def _build_alaw_table() -> tuple[int, ...]:
    """ITU-T G.711 A-law -> 16-bit signed PCM, precomputed for all 256 bytes."""
    table = []
    for byte in range(256):
        value = byte ^ 0x55
        sign = value & 0x80
        exponent = (value & 0x70) >> 4
        mantissa = value & 0x0F
        if exponent == 0:
            sample = (mantissa << 4) + 8
        else:
            sample = ((mantissa << 4) + 0x108) << (exponent - 1)
        table.append(-sample if sign else sample)
    return tuple(table)


ULAW_TABLE = _build_ulaw_table()
ALAW_TABLE = _build_alaw_table()

# Payload types this module can turn back into audio.
DECODABLE_PAYLOAD_TYPES = {0: "PCMU", 8: "PCMA"}


def decode_g711(payload: bytes, payload_type: int) -> bytes:
    """Decode G.711 to little-endian 16-bit PCM. Empty for any other codec."""
    if payload_type == 0:
        table = ULAW_TABLE
    elif payload_type == 8:
        table = ALAW_TABLE
    else:
        return b""
    return struct.pack(f"<{len(payload)}h", *(table[b] for b in payload))


def write_wav(path: Path, pcm: bytes, sample_rate: int = 8000) -> None:
    """Write 16-bit mono PCM to a RIFF/WAVE file."""
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        handle.writeframes(pcm)


# --- RTP --------------------------------------------------------------------
@dataclass
class RtpState:
    """Accumulator for one (5-tuple, SSRC) media stream."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ssrc: int
    payload_type: int
    packets: int = 0
    bytes: int = 0
    payload_bytes: int = 0
    first_seq: Optional[int] = None
    highest_seq: int = 0
    cycles: int = 0
    out_of_order: int = 0
    duplicates: int = 0
    marker_count: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    jitter: float = 0.0
    _last_transit: Optional[float] = None
    _last_rtp_ts: Optional[int] = None
    seen_seqs: set = field(default_factory=set)
    dtmf: list = field(default_factory=list)
    last_dtmf_event: Optional[int] = None
    payload_types: set = field(default_factory=set)
    audio: bytearray = field(default_factory=bytearray)


def is_rtp_candidate(payload: bytes, sport: int, dport: int) -> bool:
    """Structural test for an RTP header, before SSRC agreement confirms it.

    Intentionally conservative. Any UDP payload can satisfy a two-bit version
    field, so this rejects everything with a cheaper explanation first; the
    caller then requires several packets to agree on a 32-bit SSRC, which does
    not happen by chance.
    """
    if len(payload) < 12:
        return False
    if sport in NON_RTP_UDP_PORTS or dport in NON_RTP_UDP_PORTS:
        return False
    if payload[0] >> 6 != 2:
        return False
    payload_type = payload[1] & 0x7F
    if payload_type in RTCP_SHADOW_PAYLOAD_TYPES:
        return False
    # STUN shares the media port during ICE and its cookie is unmistakable.
    if len(payload) >= 8 and payload[4:8] == STUN_MAGIC_COOKIE:
        return False
    # DTLS record types 20-23 with a plausible version — DTLS-SRTP setup.
    if payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0xFE:
        return False
    csrc_count = payload[0] & 0x0F
    header_len = 12 + 4 * csrc_count
    return len(payload) >= header_len


def parse_rtp(payload: bytes) -> Optional[dict]:
    """Split an RTP packet into header fields plus its payload."""
    if len(payload) < 12:
        return None
    byte0, byte1 = payload[0], payload[1]
    csrc_count = byte0 & 0x0F
    extension = bool(byte0 & 0x10)
    padding = bool(byte0 & 0x20)
    offset = 12 + 4 * csrc_count
    if extension:
        if len(payload) < offset + 4:
            return None
        ext_words = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4 + 4 * ext_words
    if offset > len(payload):
        return None
    body = payload[offset:]
    if padding and body:
        pad = body[-1]
        if 0 < pad <= len(body):
            body = body[:-pad]
    return {
        "payload_type": byte1 & 0x7F,
        "marker": bool(byte1 & 0x80),
        "sequence": int.from_bytes(payload[2:4], "big"),
        "timestamp": int.from_bytes(payload[4:8], "big"),
        "ssrc": int.from_bytes(payload[8:12], "big"),
        "csrc_count": csrc_count,
        "payload": body,
    }


def update_rtp_state(
    state: RtpState,
    parsed: dict,
    ts: Optional[float],
    frame_bytes: int,
    clock_rate: int = 8000,
    keep_audio: bool = False,
    max_audio_bytes: int = 0,
) -> None:
    """Fold one packet into a stream accumulator."""
    seq = int(parsed["sequence"])
    state.packets += 1
    state.bytes += frame_bytes
    state.payload_bytes += len(parsed["payload"])
    state.payload_types.add(int(parsed["payload_type"]))
    if parsed["marker"]:
        state.marker_count += 1

    if state.first_seq is None:
        state.first_seq = seq
        state.highest_seq = seq
    elif seq < state.highest_seq and state.highest_seq - seq > 0x8000:
        # The 16-bit sequence space wrapped. Counting the cycle keeps loss from
        # being reported as a 65,000-packet gap once per stream.
        state.cycles += 1
        state.highest_seq = seq
    elif seq > state.highest_seq:
        state.highest_seq = seq
    elif seq == state.highest_seq or seq in state.seen_seqs:
        state.duplicates += 1
    else:
        state.out_of_order += 1
    if len(state.seen_seqs) < 65536:
        state.seen_seqs.add(seq)

    if state.first_seen is None:
        state.first_seen = ts
    state.last_seen = ts

    # RFC 3550 appendix A.8 interarrival jitter, in RTP timestamp units.
    rtp_ts = int(parsed["timestamp"])
    if ts is not None:
        arrival = ts * clock_rate
        transit = arrival - rtp_ts
        if state._last_transit is not None:
            diff = abs(transit - state._last_transit)
            state.jitter += (diff - state.jitter) / 16.0
        state._last_transit = transit
    state._last_rtp_ts = rtp_ts

    if keep_audio and max_audio_bytes and len(state.audio) < max_audio_bytes:
        pcm = decode_g711(parsed["payload"], int(parsed["payload_type"]))
        if pcm:
            state.audio.extend(pcm[: max_audio_bytes - len(state.audio)])


def decode_dtmf_event(payload: bytes) -> Optional[tuple[str, int, bool]]:
    """Decode an RFC 4733 telephone-event payload.

    Returns ``(digit, duration, end_flag)``.
    """
    if len(payload) < 4:
        return None
    digit = DTMF_EVENTS.get(payload[0])
    if digit is None:
        return None
    end = bool(payload[1] & 0x80)
    duration = int.from_bytes(payload[2:4], "big")
    return digit, duration, end


# --- RTCP -------------------------------------------------------------------
def is_rtcp(payload: bytes) -> bool:
    if len(payload) < 8 or payload[0] >> 6 != 2:
        return False
    return payload[1] in RTCP_PACKET_TYPES


def parse_rtcp(payload: bytes) -> dict:
    """Walk a compound RTCP packet, pulling reports and SDES items out of it.

    The CNAME is the reason this matters: it identifies an endpoint across SSRC
    changes, which is the one durable attribution handle the media plane offers.
    """
    result: dict = {
        "types": [],
        "sdes": [],
        "reports": [],
        "bye_ssrcs": [],
    }
    offset = 0
    while offset + 4 <= len(payload):
        packet_type = payload[offset + 1]
        length = (int.from_bytes(payload[offset + 2 : offset + 4], "big") + 1) * 4
        if length <= 0 or offset + length > len(payload):
            break
        name = RTCP_PACKET_TYPES.get(packet_type)
        if name:
            result["types"].append(name)
        count = payload[offset] & 0x1F

        if packet_type in (200, 201):  # SR / RR
            base = offset + 8 if packet_type == 200 else offset + 8
            if packet_type == 200:
                base = offset + 28  # skip sender info
            for index in range(count):
                block = base + index * 24
                if block + 24 > offset + length:
                    break
                result["reports"].append(
                    {
                        "ssrc": int.from_bytes(payload[block : block + 4], "big"),
                        "fraction_lost": payload[block + 4],
                        "cumulative_lost": int.from_bytes(
                            payload[block + 5 : block + 8], "big"
                        ),
                        "jitter": int.from_bytes(
                            payload[block + 12 : block + 16], "big"
                        ),
                    }
                )
        elif packet_type == 202:  # SDES
            cursor = offset + 4
            end = offset + length
            for _ in range(count):
                if cursor + 4 > end:
                    break
                cursor += 4  # SSRC/CSRC
                while cursor + 2 <= end:
                    item_type = payload[cursor]
                    if item_type == 0:
                        cursor += 1
                        cursor += (-(cursor - offset)) % 4
                        break
                    item_len = payload[cursor + 1]
                    if cursor + 2 + item_len > end:
                        cursor = end
                        break
                    # Strip NULs as well as whitespace: an endpoint that counts
                    # its own terminator in the item length would otherwise put
                    # a NUL into a reported identity string.
                    text = (
                        payload[cursor + 2 : cursor + 2 + item_len]
                        .decode("utf-8", errors="replace")
                        .strip("\x00")
                        .strip()
                    )
                    result["sdes"].append(
                        (RTCP_SDES_ITEMS.get(item_type, f"item{item_type}"), text)
                    )
                    cursor += 2 + item_len
        elif packet_type == 203:  # BYE
            for index in range(count):
                block = offset + 4 + index * 4
                if block + 4 > offset + length:
                    break
                result["bye_ssrcs"].append(
                    int.from_bytes(payload[block : block + 4], "big")
                )
        offset += length
    return result


# --- STUN / TURN ------------------------------------------------------------
def is_stun(payload: bytes) -> bool:
    return (
        len(payload) >= 20
        and payload[0] >> 6 == 0
        and payload[4:8] == STUN_MAGIC_COOKIE
    )


def parse_stun(payload: bytes) -> dict:
    """Parse a STUN/TURN message.

    Worth doing for two reasons: ``XOR-MAPPED-ADDRESS`` is the endpoint's own
    view of its public address (useful for placing a host behind NAT), and a
    TURN ``USERNAME``/``REALM`` pair with ``MESSAGE-INTEGRITY`` is a long-term
    credential that can be attacked offline.
    """
    result: dict = {"method": "", "class": "", "attributes": {}}
    if not is_stun(payload):
        return result
    message_type = int.from_bytes(payload[0:2], "big")
    method = (
        (message_type & 0x000F)
        | ((message_type & 0x00E0) >> 1)
        | ((message_type & 0x3E00) >> 2)
    )
    klass = ((message_type & 0x0100) >> 7) | ((message_type & 0x0010) >> 4)
    result["method"] = STUN_METHODS.get(method, f"0x{method:04x}")
    result["class"] = {0: "request", 1: "indication", 2: "success", 3: "error"}.get(
        klass, "?"
    )

    length = int.from_bytes(payload[2:4], "big")
    offset = 20
    end = min(len(payload), 20 + length)
    while offset + 4 <= end:
        attr_type = int.from_bytes(payload[offset : offset + 2], "big")
        attr_len = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        value = payload[offset + 4 : offset + 4 + attr_len]
        name = STUN_ATTRS.get(attr_type, f"0x{attr_type:04x}")
        if name in ("USERNAME", "REALM", "NONCE", "SOFTWARE"):
            result["attributes"][name] = value.decode("utf-8", errors="replace")
        elif name in ("XOR-MAPPED-ADDRESS", "XOR-PEER-ADDRESS", "XOR-RELAYED-ADDRESS"):
            decoded = _xor_address(value)
            if decoded:
                result["attributes"][name] = decoded
        elif name == "MESSAGE-INTEGRITY":
            result["attributes"][name] = value.hex()
        offset += 4 + attr_len + ((-attr_len) % 4)
    return result


def _xor_address(value: bytes) -> str:
    if len(value) < 8:
        return ""
    family = value[1]
    port = int.from_bytes(value[2:4], "big") ^ 0x2112
    if family == 0x01:
        octets = bytes(b ^ c for b, c in zip(value[4:8], STUN_MAGIC_COOKIE))
        return f"{'.'.join(str(o) for o in octets)}:{port}"
    if family == 0x02 and len(value) >= 20:
        # IPv6 is XORed with the cookie followed by the transaction id, which
        # the caller does not pass in; report the port only rather than a wrong
        # address.
        return f"[ipv6]:{port}"
    return ""


# --- T.38 fax ---------------------------------------------------------------
def is_udptl_t38(payload: bytes) -> bool:
    """Heuristic for a T.38 fax packet carried over UDPTL.

    UDPTL has no magic number: a sequence number then an IFP packet. The type
    nibble of the primary IFP field is what distinguishes it, and the
    combination is weak on its own — the caller should require the port to have
    been negotiated as ``image/t38`` in SDP, or several packets to agree.
    """
    if len(payload) < 4:
        return False
    # Byte 2 high nibble is the IFP type-of-message: 0 = t30-indicator,
    # 1 = data, 2 = t4-non-ecm-sig-end and so on. Values above 7 are undefined.
    return (payload[2] >> 4) <= 7


T38_TYPE_OF_MSG = {
    0: "t30-indicator",
    1: "data",
    2: "t4-non-ecm-sig-end",
    3: "data-end",
}


def parse_t38(payload: bytes) -> dict:
    """Extract the little UDPTL carries in the clear: sequence and IFP type."""
    if len(payload) < 4:
        return {}
    return {
        "sequence": int.from_bytes(payload[0:2], "big"),
        "type": T38_TYPE_OF_MSG.get(payload[2] >> 4, f"type{payload[2] >> 4}"),
    }
