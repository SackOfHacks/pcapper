from __future__ import annotations

from pcapper.wmic import _extract_utf16le_strings


def test_utf16le_extractor_handles_odd_payload_alignment() -> None:
    encoded = b"\xff" + "root\\cimv2".encode("utf-16le")

    assert "root\\cimv2" in _extract_utf16le_strings(encoded)
