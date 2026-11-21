"""VNC: sessions are counted from their first packet, roles follow the RFB
protocol (the server speaks first), reverse connections are flagged."""

from __future__ import annotations

from pcapper.vnc import analyze_vnc
from test_review_batches import T0, _tcp, _write


def _flow(packets: list[tuple[str, str, int, int, bytes, str]]):
    out = []
    for i, (src, dst, sport, dport, payload, flags) in enumerate(packets):
        pkt = _tcp(src, dst, sport, dport, payload, seq=1000 + i * 300, flags=flags)
        pkt.time = T0 + i
        out.append(pkt)
    return out


def test_reverse_vnc_with_ultravnc_hello(tmp_path) -> None:
    desktop, viewer = "10.0.0.5", "140.228.29.110"
    hello = b"ID:5376529\x00" + b"\x7fwu\x00" + b"C:\\Games\x00taskhost.exe\x00"
    hello += b"\x00" * (250 - len(hello))
    packets = _flow([
        (desktop, viewer, 50000, 5500, b"", "S"),
        (viewer, desktop, 5500, 50000, b"", "SA"),
        (desktop, viewer, 50000, 5500, b"", "A"),
        (desktop, viewer, 50000, 5500, hello, "PA"),
        (desktop, viewer, 50000, 5500, b"RFB 003.008\n", "PA"),
        (desktop, viewer, 50000, 5500, b"\x00", "PA"),
        (viewer, desktop, 5500, 50000, b"", "A"),
    ])
    summary = analyze_vnc(_write(tmp_path, "reverse_vnc.pcap", packets), show_status=False)
    [conv] = summary.conversations
    assert conv.reverse and conv.repeater_id == "5376529"
    assert (conv.server_ip, conv.client_ip, conv.client_port) == (desktop, viewer, 5500)
    assert conv.packets == 7 and summary.vnc_packets == 7
    assert conv.handshake == "viewer never answered"
    assert "taskhost.exe" in conv.hello_strings
    finding = next(d for d in summary.detections if "Reverse VNC" in str(d.get("summary")))
    assert finding["severity"] == "high" and "5376529" in finding["details"]


def test_normal_vnc_is_not_reverse(tmp_path) -> None:
    viewer, desktop = "10.0.0.7", "10.0.0.8"
    packets = _flow([
        (viewer, desktop, 51000, 5900, b"", "S"),
        (desktop, viewer, 5900, 51000, b"", "SA"),
        (viewer, desktop, 51000, 5900, b"", "A"),
        (desktop, viewer, 5900, 51000, b"RFB 003.008\n", "PA"),
        (viewer, desktop, 51000, 5900, b"RFB 003.008\n", "PA"),
        (desktop, viewer, 5900, 51000, b"\x01\x02", "PA"),
        (viewer, desktop, 51000, 5900, b"\x02", "PA"),
    ])
    summary = analyze_vnc(_write(tmp_path, "vnc.pcap", packets), show_status=False)
    [conv] = summary.conversations
    assert not conv.reverse
    assert (conv.client_ip, conv.server_ip, conv.server_port) == (viewer, desktop, 5900)
    assert conv.packets == 7
    assert conv.handshake.startswith("security")
    assert not any("Reverse VNC" in str(d.get("summary")) for d in summary.detections)
