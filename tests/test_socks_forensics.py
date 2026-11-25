from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.socks import analyze_socks, merge_socks_summaries

PROXY = "10.0.0.2"
CLIENT = "10.0.0.1"


def _seg(src, dst, sport, dport, payload, flags="PA"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(load=payload)


def _write(tmp_path, name, packets):
    capture = tmp_path / name
    wrpcap(str(capture), packets)
    return capture


def test_generic_tls_on_random_port_is_not_socks(tmp_path) -> None:
    capture = _write(tmp_path, "tls.pcap", [
        _seg(CLIENT, PROXY, 50000, 4455, b"\x16\x03\x03\x00\x02\x01\x00"),
        _seg(PROXY, CLIENT, 4455, 50000, b"\x16\x03\x03\x00\x02\x02\x00"),
    ])
    assert analyze_socks(capture, show_status=False).flows == 0


def test_one_sided_greeting_is_not_confirmed(tmp_path) -> None:
    # A greeting with no method selection answered the other way is not a
    # completed handshake and must not be reported.
    capture = _write(tmp_path, "greet_only.pcap", [
        _seg(CLIENT, PROXY, 40000, 1080, b"\x05\x01\x00"),
    ])
    assert analyze_socks(capture, show_status=False).flows == 0


def test_socks5_connect_to_domain(tmp_path) -> None:
    req = b"\x05\x01\x00\x03\x0ewww.google.com\x00\x50"  # CONNECT www.google.com:80
    rep = b"\x05\x00\x00\x01\x0a\x00\x00\x02\x00\x50"
    capture = _write(tmp_path, "s5.pcap", [
        _seg(CLIENT, PROXY, 40000, 1080, b"\x05\x01\x00"),
        _seg(PROXY, CLIENT, 1080, 40000, b"\x05\x00"),
        _seg(CLIENT, PROXY, 40000, 1080, req),
        _seg(PROXY, CLIENT, 1080, 40000, rep),
    ])
    summary = analyze_socks(capture, show_status=False)
    assert summary.flows == 1
    assert summary.version_counts["SOCKS5"] == 1
    assert summary.command_counts["CONNECT"] == 1
    assert summary.target_counts["www.google.com:80"] == 1
    assert summary.client_counts[CLIENT] == 1
    assert summary.server_counts[PROXY] == 1


def test_socks4a_request_reply(tmp_path) -> None:
    # VER CMD PORT(443) IP(0.0.0.1 => 4a) USERID\0 DOMAIN\0
    req = b"\x04\x01\x01\xbb\x00\x00\x00\x01id\x00example.com\x00"
    rep = b"\x00\x5a\x01\xbb\x7f\x00\x00\x01"
    capture = _write(tmp_path, "s4a.pcap", [
        _seg(CLIENT, PROXY, 40001, 1080, req),
        _seg(PROXY, CLIENT, 1080, 40001, rep),
    ])
    summary = analyze_socks(capture, show_status=False)
    assert summary.flows == 1
    assert summary.version_counts["SOCKS4a"] == 1
    assert summary.target_counts["example.com:443"] == 1


def test_cleartext_credentials_are_captured(tmp_path) -> None:
    auth = b"\x01\x08testuser\x08testpass"
    capture = _write(tmp_path, "auth.pcap", [
        _seg(CLIENT, PROXY, 40002, 1080, b"\x05\x01\x02"),
        _seg(PROXY, CLIENT, 1080, 40002, b"\x05\x02"),
        _seg(CLIENT, PROXY, 40002, 1080, auth),
        _seg(PROXY, CLIENT, 1080, 40002, b"\x01\x00"),
    ])
    summary = analyze_socks(capture, show_status=False)
    assert summary.flows == 1
    assert summary.cleartext_cred_count == 1
    cred = summary.credential_items[0]
    assert cred["user"] == "testuser" and cred["secret"] == "testpass"
    assert cred["result"] == "accepted"


def test_tunnel_to_sensitive_port_is_a_threat(tmp_path) -> None:
    req = b"\x05\x01\x00\x01\x0a\x00\x00\x09\x0d\x3d"  # CONNECT 10.0.0.9:3389 (RDP)
    rep = b"\x05\x00\x00\x01\x0a\x00\x00\x09\x0d\x3d"
    capture = _write(tmp_path, "rdp.pcap", [
        _seg(CLIENT, PROXY, 40003, 1080, b"\x05\x01\x00"),
        _seg(PROXY, CLIENT, 1080, 40003, b"\x05\x00"),
        _seg(CLIENT, PROXY, 40003, 1080, req),
        _seg(PROXY, CLIENT, 1080, 40003, rep),
    ])
    summary = analyze_socks(capture, show_status=False)
    assert summary.threat_counts["SOCKS tunnel to sensitive service port"] == 1
    assert any(d["summary"] == "SOCKS tunnel to sensitive service port" for d in summary.detections)


def test_reverse_socks_is_detected_from_the_syn(tmp_path) -> None:
    # The proxy-server role (the greeting responder) opened the TCP connection:
    # the shape of a reverse-SOCKS implant dialling out.
    capture = _write(tmp_path, "reverse.pcap", [
        _seg(PROXY, CLIENT, 1080, 40004, b"", flags="S"),           # server dials out
        _seg(CLIENT, PROXY, 40004, 1080, b"", flags="SA"),
        _seg(CLIENT, PROXY, 40004, 1080, b"\x05\x01\x00"),          # client role greets
        _seg(PROXY, CLIENT, 1080, 40004, b"\x05\x00"),              # server role selects
    ])
    summary = analyze_socks(capture, show_status=False)
    assert summary.flows == 1
    assert summary.reverse_flow_count == 1
    assert summary.threat_counts["Reverse SOCKS proxy (server-initiated tunnel)"] == 1


def test_a_rollup_lists_a_credential_several_captures_share_once(tmp_path) -> None:
    """-summarize of two captures holding the same proxy login: the credential
    and its finding are listed once, the exchanges counted twice."""
    auth = b"\x01\x08testuser\x08testpass"

    def login(name, port):
        return analyze_socks(_write(tmp_path, name, [
            _seg(CLIENT, PROXY, port, 1080, b"\x05\x01\x02"),
            _seg(PROXY, CLIENT, 1080, port, b"\x05\x02"),
            _seg(CLIENT, PROXY, port, 1080, auth),
            _seg(PROXY, CLIENT, 1080, port, b"\x01\x00"),
        ]), show_status=False)

    first, second = login("a.pcap", 40002), login("b.pcap", 40002)
    merged = merge_socks_summaries([first, second])
    assert merged.cleartext_cred_count == 2
    assert len(merged.credential_items) == 1
    titles = [d["summary"] for d in merged.detections]
    assert len(titles) == len(set(titles)) == len(first.detections)
