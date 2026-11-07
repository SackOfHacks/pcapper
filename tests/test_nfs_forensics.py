from __future__ import annotations

import struct

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.nfs import analyze_nfs


def _nfs_call(xid: int) -> bytes:
    return struct.pack(">10I", xid, 0, 2, 100003, 3, 1, 0, 0, 0, 0)


def _nfs_reply(xid: int, nfs_status: int) -> bytes:
    return struct.pack(">7I", xid, 1, 0, 0, 0, 0, nfs_status)


def _packet(src: str, dst: str, sport: int, dport: int, payload: bytes):
    return (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / Raw(load=payload)
    )


def test_nfs_reply_status_and_xid_are_scoped_to_client(tmp_path) -> None:
    capture = tmp_path / "nfs_replies.pcap"
    server = "10.0.0.10"
    client_a = "10.0.0.1"
    client_b = "10.0.0.2"
    packets = [
        _packet(client_a, server, 50001, 2049, _nfs_call(7)),
        _packet(client_b, server, 50002, 2049, _nfs_call(7)),
        _packet(server, client_a, 2049, 50001, _nfs_reply(7, 0)),
        _packet(server, client_b, 2049, 50002, _nfs_reply(7, 13)),
        _packet(server, client_a, 2049, 50001, struct.pack(">6I", 8, 1, 0, 0, 0, 4)),
    ]
    wrpcap(str(capture), packets)

    result = analyze_nfs(capture, show_status=False)

    assert result.status_codes == {"OK": 1, "ACCES": 1, "RPC_ACCEPT_GARBAGE_ARGS": 1}
    assert {(session.client_ip, session.status) for session in result.sessions} == {
        (client_a, "OK"),
        (client_b, "ACCES"),
    }
    assert [item.title for item in result.anomalies].count("NFS Access Denied") == 1
