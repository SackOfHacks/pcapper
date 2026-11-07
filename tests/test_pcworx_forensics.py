from __future__ import annotations

from pcapper.pcworx import _parse_commands


def test_pcworx_requires_a_complete_length_consistent_message() -> None:
    request = b"\x01\x06\x00\x06\x00\x02"

    assert _parse_commands(request) == ["Request: Read PLC Info (type/firmware)"]
    assert _parse_commands(request[:-1]) == []
    assert _parse_commands(b"\x01\x06\x00\x20\x00\x02") == []
