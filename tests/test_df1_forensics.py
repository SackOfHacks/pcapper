from __future__ import annotations

from pcapper.df1 import (
    DF1_DLE_ETX,
    DF1_DLE_STX,
    _df1_crc16,
    _extract_df1_frames,
    _match_signature,
    _parse_commands,
)


def _df1_frame(data: bytes, *, crc: bool = False, corrupt: bool = False) -> bytes:
    wire_data = data.replace(b"\x10", b"\x10\x10")
    checksum = (
        _df1_crc16(data + b"\x03").to_bytes(2, "little")
        if crc
        else bytes(((-sum(data)) & 0xFF,))
    )
    if corrupt:
        checksum = bytes((checksum[0] ^ 1,)) + checksum[1:]
    return DF1_DLE_STX + wire_data + DF1_DLE_ETX + checksum


def test_valid_bcc_and_crc_frames_are_recognized() -> None:
    request = bytes.fromhex("01 00 0f 00 2a 00") + b"\xab" * 8

    assert _parse_commands(_df1_frame(request)) == ["DF1 Protected Typed Logical Write"]
    assert _parse_commands(_df1_frame(request, crc=True)) == [
        "DF1 Protected Typed Logical Write"
    ]


def test_invalid_checksum_and_incomplete_frames_do_not_match() -> None:
    request = bytes.fromhex("01 00 0f 00 2a 00") + b"\xab" * 8

    assert not _match_signature(_df1_frame(request, corrupt=True))
    assert _extract_df1_frames(DF1_DLE_STX + request) == []
    assert not _match_signature(DF1_DLE_STX + request)
