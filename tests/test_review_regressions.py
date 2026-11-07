from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from pcapper import exporting, ioc, pcap_cache, protocols, tcp
from pcapper.exporting import ExportBundle
from pcapper.pcap_cache import PcapMeta


def test_ioc_analysis_preserves_capture_metadata(tmp_path: Path, monkeypatch) -> None:
    capture_meta = PcapMeta(
        path=tmp_path / "capture.pcap",
        file_type="pcap",
        size_bytes=0,
        linktype=None,
        snaplen=None,
        interfaces=None,
    )
    ioc_path = tmp_path / "indicators.json"
    ioc_path.write_text(
        '{"indicators":[{"type":"ip","value":"192.0.2.1","source":"feed"}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ioc,
        "analyze_files",
        lambda *args, **kwargs: SimpleNamespace(artifacts=[]),
    )

    def fake_iter_packets(path, *, packets, meta, show_status):
        assert meta is capture_meta
        return iter(())

    monkeypatch.setattr(ioc, "iter_packets", fake_iter_packets)

    summary = ioc.analyze_iocs(
        capture_meta.path,
        ioc_path,
        show_status=False,
        packets=[],
        meta=capture_meta,
    )

    assert summary.indicator_meta["192.0.2.1"]["source"] == "feed"


def test_sqlite_export_failure_keeps_existing_database(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "out.sqlite"
    target.write_bytes(b"existing valid export")
    target.chmod(0o600)
    bundle = ExportBundle(
        path=Path("capture.pcap"),
        summaries={"creds": SimpleNamespace(detections=[{"value": "secret"}], artifacts=[])},
    )

    def fail_serialization(*args, **kwargs):
        raise RuntimeError("serialization failed")

    monkeypatch.setattr(exporting, "to_serializable", fail_serialization)

    with pytest.raises(RuntimeError, match="serialization failed"):
        exporting.export_sqlite(bundle, target)

    assert target.read_bytes() == b"existing valid export"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(tmp_path.glob(f".{target.name}.*.tmp")) == []


@pytest.mark.parametrize(
    ("transport", "dport", "expected"),
    [("TCP", 443, "HTTPS"), ("UDP", 53, "DNS")],
)
def test_ipv6_transport_is_attributed_in_protocol_summary(
    tmp_path: Path, transport: str, dport: int, expected: str
) -> None:
    scapy = pytest.importorskip("scapy.all")
    sport = 49152
    packet = (
        scapy.Ether()
        / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2")
        / getattr(scapy, transport)(sport=sport, dport=dport)
    )
    summary = protocols.analyze_protocols(
        tmp_path / "capture.pcap", show_status=False, packets=[packet]
    )

    assert (expected, 1) in summary.port_protocols
    assert summary.conversations[0].protocol == expected
    assert summary.conversations[0].ports == {sport, dport}


def test_packet_cache_reloads_capture_modified_at_same_path(
    tmp_path: Path, monkeypatch
) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"same size")
    monkeypatch.setattr(pcap_cache, "_PACKET_CACHE", pcap_cache.OrderedDict())
    monkeypatch.setattr(pcap_cache, "_CACHE_BYTES", 0)
    monkeypatch.setattr(pcap_cache, "_cache_config", lambda: (True, 1024, 1024))
    loaded: list[object] = []

    def fake_load(path: Path, show_status: bool = True):
        packet = object()
        loaded.append(packet)
        stat_result = path.stat()
        return [
            packet
        ], PcapMeta(
            path=path,
            file_type="pcap",
            size_bytes=stat_result.st_size,
            linktype=None,
            snaplen=None,
            interfaces=None,
            modified_ns=stat_result.st_mtime_ns,
        )

    monkeypatch.setattr(pcap_cache, "load_packets", fake_load)

    first_packets, _ = pcap_cache.get_cached_packets(capture, show_status=False)
    initial_stat = capture.stat()
    capture.write_bytes(b"new bytes")
    os.utime(
        capture,
        ns=(initial_stat.st_atime_ns, initial_stat.st_mtime_ns + 1_000_000_000),
    )
    second_packets, _ = pcap_cache.get_cached_packets(capture, show_status=False)

    assert first_packets[0] is not second_packets[0]
    assert len(loaded) == 2


def test_ipv6_extension_header_is_not_counted_as_tcp_payload(tmp_path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    from scapy.layers.inet6 import IPv6ExtHdrHopByHop

    packet = (
        scapy.Ether()
        / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IPv6ExtHdrHopByHop()
        / scapy.TCP(sport=49152, dport=443, flags="A")
    )
    packet = scapy.Ether(bytes(packet))
    summary = tcp.analyze_tcp(
        tmp_path / "capture.pcap", show_status=False, packets=[packet]
    )

    assert summary.tcp_payload_bytes == 0
