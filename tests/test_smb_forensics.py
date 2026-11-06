from __future__ import annotations

import struct

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.smb as smb


def _smb2_read_request(message_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = smb.SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 12, smb.SMB2_COM_READ)
    struct.pack_into("<Q", header, 24, message_id)
    struct.pack_into("<Q", header, 40, 1)
    body = bytearray(32)
    struct.pack_into("<I", body, 4, 512)
    return bytes(header + body)


def test_smb_pending_io_tracking_is_bounded_and_reported(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(smb, "MAX_SMB_PENDING", 1)
    capture = tmp_path / "smb_pending_io_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=1445, seq=message_id * 100)
            / Raw(load=_smb2_read_request(message_id))
            for message_id in (1, 2)
        ],
    )

    summary = smb.analyze_smb(capture, show_status=False)

    assert summary.smb_packets == 2
    assert len(summary.files) == 2
    assert any("pending io capped at 1" in error.lower() for error in summary.errors)
