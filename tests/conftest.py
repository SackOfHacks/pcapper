from __future__ import annotations

import re
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _read_hex_fixture(name: str) -> bytes:
    path = FIXTURE_DIR / name
    text = path.read_text(encoding="utf-8")
    hex_text = re.sub(r"[^0-9a-fA-F]", "", text)
    return bytes.fromhex(hex_text)


@pytest.fixture()
def dns_query_pcap(tmp_path: Path) -> Path:
    payload = _read_hex_fixture("dns_query_example.pcap.hex")
    out = tmp_path / "dns_query_example.pcap"
    out.write_bytes(payload)
    return out
