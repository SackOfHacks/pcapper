from __future__ import annotations

import ipaddress

from scapy.all import Ether, IP, UDP, wrpcap
from scapy.layers.dhcp import BOOTP, DHCP

from pcapper.dhcp import _parse_dhcp6_options
from pcapper.dhcp import analyze_dhcp


def _option(code: int, value: bytes) -> bytes:
    return code.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def test_dhcpv6_reply_parses_nested_address_and_client_fqdn() -> None:
    address = ipaddress.IPv6Address("2001:db8::1234").packed
    iaaddr = _option(5, address + (3600).to_bytes(4, "big") * 2)
    ia_na = b"\x00" * 12 + iaaddr
    fqdn = b"\x04\x00\x00\x03plc\x07example\x03com\x00"
    payload = b"\x07\x01\x02\x03" + _option(3, ia_na) + _option(39, fqdn)

    msg_type, options, xid = _parse_dhcp6_options(payload)

    assert msg_type == "REPLYv6"
    assert xid == 0x010203
    assert options["requested_addr"] == "2001:db8::1234"
    assert options["hostname"] == "plc.example.com"


def test_dhcpv4_transaction_messages_share_one_client_session(tmp_path) -> None:
    capture = tmp_path / "dhcp_transaction.pcap"
    client_mac = "02:00:00:00:00:01"
    mac_bytes = bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10
    server_mac = "02:00:00:00:00:02"
    xid = 0x12345678
    discover = (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, xid=xid, chaddr=mac_bytes)
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    offer = (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="10.0.0.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=xid, yiaddr="10.0.0.20", chaddr=mac_bytes)
        / DHCP(options=[("message-type", "offer"), ("server_id", "10.0.0.1"), "end"])
    )
    request = (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, xid=xid, chaddr=mac_bytes)
        / DHCP(
            options=[
                ("message-type", "request"),
                ("requested_addr", "10.0.0.20"),
                ("server_id", "10.0.0.1"),
                "end",
            ]
        )
    )
    ack = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src="10.0.0.1", dst="10.0.0.20")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=xid, yiaddr="10.0.0.20", chaddr=mac_bytes)
        / DHCP(options=[("message-type", "ack"), ("server_id", "10.0.0.1"), "end"])
    )
    wrpcap(str(capture), [discover, offer, request, ack])

    summary = analyze_dhcp(capture, show_status=False)

    assert len(summary.sessions) == 1
    session = summary.sessions[0]
    assert session.client_ip == "10.0.0.20"
    assert session.server_ip == "10.0.0.1"
    assert (session.requests, session.offers, session.acks) == (1, 1, 1)
