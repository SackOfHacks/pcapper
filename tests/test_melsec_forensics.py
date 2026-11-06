from __future__ import annotations

from pcapper.melsec import _detect_anomalies, _parse_commands


def _ascii_request(command: str, subcommand: str = "0000") -> bytes:
    return (
        b"5000"
        + b"00FF03FF00"
        + b"000C"
        + b"0010"
        + command.encode("ascii")
        + subcommand.encode("ascii")
    )


def _binary_request(command: int, subcommand: int = 0) -> bytes:
    return (
        b"\x50\x00"
        + b"\x00\xff\x03\xff\x00"
        + b"\x06\x00"
        + b"\x10\x00"
        + command.to_bytes(2, "little")
        + subcommand.to_bytes(2, "little")
    )


def test_melsec_ascii_and_binary_write_requests_are_decoded() -> None:
    ascii_commands = _parse_commands(_ascii_request("1401"))
    binary_commands = _parse_commands(_binary_request(0x1401))

    assert any("Batch Write" in command for command in ascii_commands)
    assert any("Batch Write" in command for command in binary_commands)
    assert _detect_anomalies(b"", "a", "b", 0.0, binary_commands)[0].title == (
        "MELSEC Write Operation"
    )


def test_melsec_response_subheaders_are_not_misread_as_commands() -> None:
    ascii_response = b"D000" + b"00FF03FF00" + b"0004" + b"0000"
    binary_response = b"\xd0\x00" + b"\x00\xff\x03\xff\x00" + b"\x02\x00\x00\x00"

    assert _parse_commands(ascii_response) == []
    assert _parse_commands(binary_response) == []


def test_melsec_declared_lengths_prevent_parsing_truncated_requests() -> None:
    ascii_request = _ascii_request("1002")[:-1]
    binary_request = _binary_request(0x1002)[:-1]

    assert _parse_commands(ascii_request) == ["MC ASCII (truncated)"]
    assert _parse_commands(binary_request) == ["MC Binary (truncated)"]
    assert not _detect_anomalies(
        binary_request, "a", "b", 0.0, _parse_commands(binary_request)
    )
