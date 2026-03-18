from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import pcapper.files as files_module
from pcapper.http import analyze_http
from pcapper.nfs import analyze_nfs


scapy = pytest.importorskip("scapy.all")


def _write_single_tcp_packet(path: Path, *, sport: int, dport: int) -> None:
    packet = (
        scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / scapy.IP(src="10.10.10.10", dst="20.20.20.20")
        / scapy.TCP(sport=sport, dport=dport, flags="PA")
    )
    scapy.wrpcap(str(path), [packet])


def test_analyze_nfs_missing_file_returns_error_summary(tmp_path: Path) -> None:
    missing = tmp_path / "missing_nfs_fixture.pcap"
    summary = analyze_nfs(missing, show_status=False)

    assert summary.total_packets == 0
    assert summary.nfs_packets == 0
    assert summary.errors
    assert "Error opening pcap:" in summary.errors[0]


def test_analyze_http_uses_dpkt_file_discovery_when_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "http_stub.pcap"
    _write_single_tcp_packet(capture, sport=12345, dport=80)

    artifact = SimpleNamespace(
        protocol="HTTP",
        src_ip="10.10.10.10",
        dst_ip="20.20.20.20",
        filename="payload.exe",
        file_type="EXE/DLL",
        content_type="application/octet-stream",
        size_bytes=321,
        packet_index=7,
    )
    stub_summary = SimpleNamespace(artifacts=[artifact], errors=[])

    def _stub_analyze_files(_path: Path, show_status: bool = False):
        return stub_summary

    monkeypatch.setattr(files_module, "analyze_files", _stub_analyze_files)

    summary = analyze_http(capture, show_status=False)

    assert summary.file_artifacts.get("payload.exe", 0) == 1
    assert any(item.get("filename") == "payload.exe" for item in summary.downloads)
