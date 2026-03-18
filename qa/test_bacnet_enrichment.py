from __future__ import annotations

from pathlib import Path

import pytest

from pcapper.bacnet import (
    BACNET_PORT,
    _detect_anomalies,
    _parse_artifacts,
    _parse_commands,
    analyze_bacnet,
)


scapy = pytest.importorskip("scapy.all")


def _build_bvlc_frame(function: int, body: bytes, *, override_length: int | None = None) -> bytes:
    length = override_length if override_length is not None else (4 + len(body))
    return bytes([0x81, function]) + length.to_bytes(2, "big") + body


def _build_write_property_payload() -> bytes:
    object_identifier = (1 << 22) | 42  # analog-output:42
    service_data = (
        bytes([0x0C])
        + object_identifier.to_bytes(4, "big")
        + bytes([0x19, 0x55])  # property 85 (Present_Value)
    )
    apdu = bytes([0x00, 0x05, 0x01, 0x0F]) + service_data
    npdu = bytes([0x01, 0x04]) + apdu
    return _build_bvlc_frame(0x09, npdu)


def _build_who_is_payload(
    *,
    low_limit: int | None = None,
    high_limit: int | None = None,
    forwarded: bool = False,
    origin_ip: str = "8.8.8.8",
) -> bytes:
    apdu = bytes([0x10, 0x08])
    if low_limit is not None and high_limit is not None:
        apdu += (
            bytes([0x0C]) + low_limit.to_bytes(4, "big")
            + bytes([0x1C]) + high_limit.to_bytes(4, "big")
        )
    npdu = bytes([0x01, 0x00]) + apdu
    if forwarded:
        origin = bytes(int(part) for part in origin_ip.split("."))
        body = origin + BACNET_PORT.to_bytes(2, "big") + npdu
        return _build_bvlc_frame(0x04, body)
    return _build_bvlc_frame(0x0A, npdu)


def _build_register_foreign_device_payload(ttl: int) -> bytes:
    return _build_bvlc_frame(0x05, ttl.to_bytes(2, "big"))


def test_parse_commands_includes_bvlc_apdu_and_service() -> None:
    payload = _build_write_property_payload()
    commands = _parse_commands(payload)
    assert "BVLC" in commands
    assert "Original-Unicast-NPDU" in commands
    assert "APDU Confirmed-Request" in commands
    assert "WriteProperty" in commands


def test_parse_artifacts_extracts_forwarded_origin_ttl_and_scope() -> None:
    forwarded = _parse_artifacts(_build_who_is_payload(forwarded=True))
    assert ("bacnet_forwarded_origin", "8.8.8.8:47808") in forwarded

    registered = _parse_artifacts(_build_register_foreign_device_payload(3600))
    assert ("bacnet_foreign_device_ttl", "3600s") in registered

    scoped = _parse_artifacts(_build_who_is_payload(low_limit=0, high_limit=4_194_303))
    assert ("bacnet_discovery_scope", "Who-Is range 0-4194303") in scoped


def test_detect_anomalies_flags_write_forwarded_public_and_malformed() -> None:
    write_payload = _build_write_property_payload()
    write_cmds = _parse_commands(write_payload)
    write_anomalies = _detect_anomalies(write_payload, "10.0.0.10", "10.0.0.20", 1.0, write_cmds)
    assert any(item.title == "BACnet WriteProperty" for item in write_anomalies)

    forwarded_payload = _build_who_is_payload(forwarded=True)
    forwarded_cmds = _parse_commands(forwarded_payload)
    forwarded_anomalies = _detect_anomalies(forwarded_payload, "10.0.0.10", "10.0.0.20", 2.0, forwarded_cmds)
    assert any(item.title == "BACnet Forwarded NPDU from Public Origin" for item in forwarded_anomalies)

    malformed_payload = _build_bvlc_frame(0x09, bytes([0x01, 0x00, 0x10, 0x08]), override_length=32)
    malformed_cmds = _parse_commands(malformed_payload)
    assert "Malformed BACnet Frame" in malformed_cmds
    malformed_anomalies = _detect_anomalies(malformed_payload, "10.0.0.10", "10.0.0.20", 3.0, malformed_cmds)
    assert any(item.title == "BACnet Malformed Frame" for item in malformed_anomalies)


def test_analyze_bacnet_detects_discovery_sweep(tmp_path: Path) -> None:
    capture = tmp_path / "bacnet_discovery_sweep.pcap"
    packets = []
    who_is_payload = _build_who_is_payload()

    for idx in range(1, 22):
        packets.append(
            scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / scapy.IP(src="10.0.0.5", dst=f"10.0.1.{idx}")
            / scapy.UDP(sport=40000 + idx, dport=BACNET_PORT)
            / scapy.Raw(load=who_is_payload)
        )

    scapy.wrpcap(str(capture), packets)
    summary = analyze_bacnet(capture, show_status=False)

    assert summary.protocol_packets >= 21
    assert any(item.kind == "bacnet_discovery" and item.detail == "Who-Is" for item in summary.artifacts)
    assert any(item.title == "BACnet Discovery Sweep" for item in summary.anomalies)
