from __future__ import annotations

from pcapper.rpc import _rpc_stub_data


def _response_pdu(stub: bytes, auth_value: bytes = b"") -> bytes:
    header = bytearray(24)
    header[4:8] = b"\x10\x00\x00\x00"
    auth_trailer = b""
    if auth_value:
        auth_trailer = b"\x0a\x05\x00\x00" + b"\x00" * 4 + auth_value
    header[8:10] = (len(header) + len(stub) + len(auth_trailer)).to_bytes(2, "little")
    header[10:12] = len(auth_value).to_bytes(2, "little")
    return bytes(header) + stub + auth_trailer


def test_rpc_stub_excludes_auth_security_trailer() -> None:
    stub = b"alice example.org"
    pdu = _response_pdu(stub, b"private-auth-data")

    assert _rpc_stub_data(pdu, le=True) == stub


def test_rpc_stub_rejects_truncated_auth_trailer() -> None:
    pdu = _response_pdu(b"stub", b"secret")
    truncated = pdu[:-3]

    assert _rpc_stub_data(truncated, le=True) == b""
