from __future__ import annotations

from pathlib import Path

import pytest

from pcapper.cip import CIP_TCP_PORT, analyze_cip
from pcapper.enip import ENIP_TCP_PORT, analyze_enip


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


def _build_send_rr_data(cip_payload: bytes, *, session: int = 0x01020304, declared_length: int | None = None) -> bytes:
    cpf = (
        b"\x00\x00\x00\x00"  # Interface handle
        + b"\x00\x00"        # Timeout
        + (2).to_bytes(2, "little")
        + b"\x00\x00\x00\x00"  # Null Address item
        + b"\xb2\x00"
        + len(cip_payload).to_bytes(2, "little")
        + cip_payload
    )
    return _enip_header(0x006F, cpf, session=session, declared_length=declared_length)


def _symbolic_path(tag_name: str) -> bytes:
    symbol = tag_name.encode("ascii")
    path = bytes([0x91, len(symbol)]) + symbol
    if len(symbol) % 2:
        path += b"\x00"
    return path


def _write_tag_request(tag_name: str) -> bytes:
    path = _symbolic_path(tag_name)
    # 0xCA == REAL, 1 element
    write_data = b"\xca\x00\x01\x00\x00\x00\x80\x3f"
    return bytes([0x4C, len(path) // 2]) + path + write_data


def _multi_service_request() -> bytes:
    # Embed WriteTag + Start inside Multiple_Service_Packet
    sub_write = b"\x4c\x00" + b"\xca\x00\x01\x00"
    sub_start = b"\x06\x00"
    offsets = (0).to_bytes(2, "little") + len(sub_write).to_bytes(2, "little")
    msp_payload = (2).to_bytes(2, "little") + offsets + sub_write + sub_start
    return b"\x0a\x00" + msp_payload


def test_cip_sensitive_tag_and_multi_service_detection(tmp_path: Path) -> None:
    capture = tmp_path / "cip_sensitive_multi.pcap"
    packets = [
        scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / scapy.IP(src="10.10.0.5", dst="10.10.0.20")
        / scapy.TCP(sport=41111, dport=CIP_TCP_PORT, flags="PA")
        / scapy.Raw(load=_build_send_rr_data(_write_tag_request("SafetyTrip"))),
        scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / scapy.IP(src="10.10.0.5", dst="10.10.0.20")
        / scapy.TCP(sport=41112, dport=CIP_TCP_PORT, flags="PA")
        / scapy.Raw(load=_build_send_rr_data(_multi_service_request())),
    ]
    scapy.wrpcap(str(capture), packets)

    summary = analyze_cip(capture, show_status=False)
    assert summary.cip_packets >= 2
    assert any(a.title == "CIP Sensitive Tag Write" for a in summary.anomalies)
    assert any(a.title == "CIP Multi-Service High-Risk Bundle" for a in summary.anomalies)
    assert any(art.kind == "tag_sensitive_write" for art in summary.artifacts)
    assert any(art.kind == "cip_multi_service" for art in summary.artifacts)
    assert any(name.startswith("MSP/") for name in summary.cip_services)


def test_enip_malformed_length_and_session_artifact(tmp_path: Path) -> None:
    capture = tmp_path / "enip_malformed_length.pcap"
    good_payload = _build_send_rr_data(_write_tag_request("MyTag"), session=0x11223344)
    bad_payload = _build_send_rr_data(_write_tag_request("MyTag"), session=0x55667788, declared_length=999)
    packets = [
        scapy.Ether(src="aa:bb:cc:dd:ee:03", dst="aa:bb:cc:dd:ee:04")
        / scapy.IP(src="10.20.0.10", dst="10.20.0.30")
        / scapy.TCP(sport=42222, dport=ENIP_TCP_PORT, flags="PA")
        / scapy.Raw(load=good_payload),
        scapy.Ether(src="aa:bb:cc:dd:ee:03", dst="aa:bb:cc:dd:ee:04")
        / scapy.IP(src="10.20.0.10", dst="10.20.0.30")
        / scapy.TCP(sport=42223, dport=ENIP_TCP_PORT, flags="PA")
        / scapy.Raw(load=bad_payload),
    ]
    scapy.wrpcap(str(capture), packets)

    summary = analyze_enip(capture, show_status=False)
    assert summary.enip_packets >= 2
    assert any(a.title == "Malformed ENIP Length" for a in summary.anomalies)
    assert any(art.kind == "enip_session" for art in summary.artifacts)


def test_enip_discovery_sweep_and_session_churn(tmp_path: Path) -> None:
    capture = tmp_path / "enip_discovery_churn.pcap"
    packets = []
    for idx in range(1, 26):
        list_identity = _enip_header(0x0063, b"", session=0)
        register = _enip_header(0x0065, b"\x01\x00\x00\x00", session=0)
        packets.append(
            scapy.Ether(src="aa:bb:cc:dd:ee:05", dst="aa:bb:cc:dd:ee:06")
            / scapy.IP(src="10.30.0.50", dst=f"10.30.1.{(idx % 8) + 1}")
            / scapy.TCP(sport=43000 + idx, dport=ENIP_TCP_PORT, flags="PA")
            / scapy.Raw(load=list_identity)
        )
        packets.append(
            scapy.Ether(src="aa:bb:cc:dd:ee:05", dst="aa:bb:cc:dd:ee:06")
            / scapy.IP(src="10.30.0.50", dst=f"10.30.1.{(idx % 8) + 1}")
            / scapy.TCP(sport=44000 + idx, dport=ENIP_TCP_PORT, flags="PA")
            / scapy.Raw(load=register)
        )

    scapy.wrpcap(str(capture), packets)
    summary = analyze_enip(capture, show_status=False)

    assert summary.enip_packets >= 50
    assert sum(summary.source_enip_enum_commands.values()) >= 20
    assert any(a.title == "ENIP Discovery Sweep" for a in summary.anomalies)
    assert any(a.title == "ENIP Session Churn" for a in summary.anomalies)
