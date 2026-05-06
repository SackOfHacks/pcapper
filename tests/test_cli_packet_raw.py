from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP  # type: ignore
from scapy.packet import Raw  # type: ignore
from scapy.utils import wrpcap  # type: ignore


def _run_cli(args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pcapper", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout = proc.stdout.decode("latin-1", errors="ignore")
    stderr = proc.stderr.decode("latin-1", errors="ignore")
    return proc.returncode, stdout, stderr


def test_packet_raw_flag_switches_output_mode(tmp_path: Path) -> None:
    pcap_path = tmp_path / "one_packet.pcap"
    marker = "RAW_PACKET_MODE_MARKER_ABC123"

    pkt = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="PA", seq=1, ack=1)
        / Raw(load=marker.encode("ascii"))
    )
    wrpcap(str(pcap_path), [pkt])

    code_hex, out_hex, err_hex = _run_cli(
        [str(pcap_path), "--packet", "1", "--no-color"]
    )
    code_raw, out_raw, err_raw = _run_cli(
        [str(pcap_path), "--packet", "1", "-raw", "--no-color"]
    )

    assert code_hex == 0, err_hex
    assert code_raw == 0, err_raw

    # Default packet mode should include hexdump offsets.
    assert "00000000" in out_hex

    # -raw mode should not render ASCII/HEX hexdump offsets.
    assert "00000000" not in out_raw

    # Raw packet text should include the marker payload bytes.
    assert marker in out_raw
