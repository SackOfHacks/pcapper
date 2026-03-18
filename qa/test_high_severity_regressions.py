from __future__ import annotations

from pathlib import Path

import pytest

from pcapper.pcap_cache import load_filtered_packets
from pcapper.rdp import merge_rdp_summaries
from pcapper.ssh import analyze_ssh


scapy = pytest.importorskip("scapy.all")


def _write_single_tcp_packet(path: Path, *, sport: int, dport: int) -> None:
    packet = (
        scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / scapy.IP(src="10.0.0.1", dst="10.0.0.2")
        / scapy.TCP(sport=sport, dport=dport, flags="PA")
    )
    scapy.wrpcap(str(path), [packet])


def _ssh_string(value: str) -> bytes:
    data = value.encode("utf-8")
    return len(data).to_bytes(4, "big") + data


def test_load_filtered_packets_with_time_filter_does_not_nameerror(tmp_path: Path) -> None:
    capture = tmp_path / "one.pcap"
    _write_single_tcp_packet(capture, sport=12345, dport=80)

    packets, meta = load_filtered_packets(capture, show_status=False, time_start=0.0)

    assert len(packets) == 1
    assert meta.path == capture


def test_analyze_ssh_decrypted_auth_method_records_method(tmp_path: Path) -> None:
    capture = tmp_path / "ssh_one.pcap"
    _write_single_tcp_packet(capture, sport=55000, dport=22)

    # SSH_MSG_USERAUTH_REQUEST
    decrypted_message = (
        bytes([50])
        + _ssh_string("alice")
        + _ssh_string("ssh-connection")
        + _ssh_string("password")
    )

    summary = analyze_ssh(
        capture,
        show_status=False,
        decrypted_payloads={1: decrypted_message},
    )

    assert "name 'auth_methods' is not defined" not in summary.errors
    assert summary.auth_methods.get("password", 0) == 1
    assert summary.auth_usernames.get("alice", 0) == 1


def test_merge_rdp_summaries_with_nonempty_input_no_nameerror() -> None:
    empty_rollup = merge_rdp_summaries([])
    merged = merge_rdp_summaries([empty_rollup])

    assert merged.total_packets == 0
    assert isinstance(merged.analysis_notes, list)
