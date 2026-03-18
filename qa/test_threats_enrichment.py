from __future__ import annotations

from pathlib import Path

import pytest

from pcapper.threats import analyze_threats


scapy = pytest.importorskip("scapy.all")


def _enip_header(
    command: int,
    data: bytes,
    *,
    session: int = 0x01020304,
    status: int = 0,
    declared_length: int | None = None,
) -> bytes:
    length = len(data) if declared_length is None else declared_length
    return (
        command.to_bytes(2, "little")
        + length.to_bytes(2, "little")
        + session.to_bytes(4, "little")
        + status.to_bytes(4, "little")
        + b"\x00" * 8
        + b"\x00" * 4
        + data
    )


def _build_send_rr_data(cip_payload: bytes, *, session: int = 0x01020304) -> bytes:
    cpf = (
        b"\x00\x00\x00\x00"
        + b"\x00\x00"
        + (2).to_bytes(2, "little")
        + b"\x00\x00\x00\x00"
        + b"\xb2\x00"
        + len(cip_payload).to_bytes(2, "little")
        + cip_payload
    )
    return _enip_header(0x006F, cpf, session=session)


def _symbolic_path(tag_name: str) -> bytes:
    symbol = tag_name.encode("ascii")
    path = bytes([0x91, len(symbol)]) + symbol
    if len(symbol) % 2:
        path += b"\x00"
    return path


def _write_tag_request(tag_name: str) -> bytes:
    path = _symbolic_path(tag_name)
    write_data = b"\xca\x00\x01\x00\x00\x00\x80\x3f"
    return bytes([0x4C, len(path) // 2]) + path + write_data


def _write_tag_response_error() -> bytes:
    # 0xCC = response to service 0x4C, general status 0x05 (path destination unknown)
    return b"\xcc\x00\x05\x00"


def test_threats_multistage_and_external_beacon_detection(tmp_path: Path) -> None:
    capture = tmp_path / "threats_multistage_beacon.pcap"
    packets = []
    src = "10.50.0.10"
    ts = 1_700_000_000.0

    for idx in range(25):
        pkt = (
            scapy.Ether(src="aa:bb:cc:dd:ee:10", dst="aa:bb:cc:dd:ee:11")
            / scapy.IP(src=src, dst="8.8.8.8")
            / scapy.TCP(sport=50000 + idx, dport=4444, flags="S")
        )
        pkt.time = ts + (idx * 10)
        packets.append(pkt)

    for idx in range(35):
        pkt = (
            scapy.Ether(src="aa:bb:cc:dd:ee:10", dst="aa:bb:cc:dd:ee:12")
            / scapy.IP(src=src, dst=f"10.50.1.{idx + 1}")
            / scapy.TCP(sport=51000 + idx, dport=3200 + (idx % 20), flags="S")
        )
        pkt.time = ts + 300 + idx
        packets.append(pkt)

    for idx in range(12):
        pkt = (
            scapy.Ether(src="aa:bb:cc:dd:ee:10", dst="aa:bb:cc:dd:ee:13")
            / scapy.IP(src=src, dst=f"10.50.2.{idx + 1}")
            / scapy.TCP(sport=52000 + idx, dport=445, flags="PA")
            / scapy.Raw(load=b"SMB")
        )
        pkt.time = ts + 500 + idx
        packets.append(pkt)

    payload_pkt = (
        scapy.Ether(src="aa:bb:cc:dd:ee:10", dst="aa:bb:cc:dd:ee:14")
        / scapy.IP(src=src, dst="10.50.3.10")
        / scapy.TCP(sport=53000, dport=5985, flags="PA")
        / scapy.Raw(load=b"powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQ=")
    )
    payload_pkt.time = ts + 700
    packets.append(payload_pkt)

    for idx in range(25):
        pkt = (
            scapy.Ether(src="aa:bb:cc:dd:ee:10", dst="aa:bb:cc:dd:ee:15")
            / scapy.IP(src=src, dst="10.50.4.10")
            / scapy.TCP(sport=54000 + idx, dport=22, flags="S")
        )
        pkt.time = ts + 800 + idx
        packets.append(pkt)

    scapy.wrpcap(str(capture), packets)
    summary = analyze_threats(capture, show_status=False)
    summaries = {str(item.get("summary", "")) for item in summary.detections}

    assert "Probable external beaconing/C2 activity" in summaries
    assert "Multi-stage intrusion behavior correlation" in summaries


def test_threats_ot_artifact_and_recon_telemetry(tmp_path: Path) -> None:
    capture = tmp_path / "threats_ot_recon_artifacts.pcap"
    src = "10.60.0.5"
    dst = "8.8.4.4"
    req = _build_send_rr_data(_write_tag_request("SafetyTrip"), session=0x11112222)
    resp = _build_send_rr_data(_write_tag_response_error(), session=0x11112222)

    packets = [
        scapy.Ether(src="aa:bb:cc:dd:ee:20", dst="aa:bb:cc:dd:ee:21")
        / scapy.IP(src=src, dst=dst)
        / scapy.TCP(sport=44800, dport=44818, flags="PA")
        / scapy.Raw(load=req),
        scapy.Ether(src="aa:bb:cc:dd:ee:21", dst="aa:bb:cc:dd:ee:20")
        / scapy.IP(src=dst, dst=src)
        / scapy.TCP(sport=44818, dport=44800, flags="PA")
        / scapy.Raw(load=resp),
    ]
    scapy.wrpcap(str(capture), packets)

    summary = analyze_threats(capture, show_status=False)
    summaries = {str(item.get("summary", "")) for item in summary.detections}

    assert "OT reconnaissance error telemetry observed" in summaries
    assert "OT/ICS artifact and IOC trail observed" in summaries
