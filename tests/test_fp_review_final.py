"""False positives found reviewing -summarize output on real captures."""

from __future__ import annotations

from scapy.layers.l2 import ARP, Ether

from pcapper.arp import analyze_arp
from pcapper.obfuscation import _http_declares_compressed_or_media, _is_http_auth_token
from pcapper.reporting import _style as st
from test_review_batches import T0, _write


def test_arp_probes_are_not_an_ip_conflict(tmp_path) -> None:
    """RFC 5227 probes come from 0.0.0.0: two devices probing made 0.0.0.0
    a HIGH "ARP IP/MAC Conflict" and a suspected compromise victim."""
    packets = []
    for i, mac in enumerate(("00:00:bc:d1:3e:f5", "00:1d:9c:ca:53:0b")):
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc="0.0.0.0", pdst=f"192.168.10.{20 + i}")
        pkt.time = T0 + i
        packets.append(pkt)
    summary = analyze_arp(_write(tmp_path, "probes.pcap", packets), show_status=False)
    assert summary.arp_probes == 2
    assert not [a for a in summary.anomalies if a.title == "ARP IP/MAC Conflict"]


def test_winrm_sealed_bodies_and_auth_tokens_are_expected() -> None:
    """PowerShell remoting on 5985: SPNEGO-sealed SOAP bodies and NTLM
    tokens in the auth headers were "obfuscation" and a covert channel."""
    head = ('POST /wsman HTTP/1.1\r\nContent-Type: multipart/encrypted;'
            'protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"\r\n\r\n')
    assert _http_declares_compressed_or_media(head)
    auth = "POST /wsman HTTP/1.1\r\nAuthorization: Negotiate TlRMTVNTUAADAAAAGAAYAHoAAABI\r\n"
    assert _is_http_auth_token(auth, auth.index("TlRM"))
    challenge = "HTTP/1.1 401\r\nWWW-Authenticate: Negotiate TlRMTVNTUAACAAAAHgAe\r\n"
    assert _is_http_auth_token(challenge, challenge.index("TlRM"))
    body = "POST /x HTTP/1.1\r\nX-Data: TlRMTVNTUAADAAAAGAAYAHoAAABI\r\n"
    assert not _is_http_auth_token(body, body.index("TlRM"))


def test_two_way_finding_is_not_a_self_flow() -> None:
    both = [("192.168.198.1", 3), ("192.168.198.129", 3)]
    f = st.finding({"severity": "medium", "summary": "x", "top_sources": both, "top_destinations": both})
    assert st._flow_text(f) == "192.168.198.1 -> 192.168.198.129"


def test_cip_findings_are_not_repeated_from_enip() -> None:
    """CipSession: the CIP Stop and enumeration were listed twice, once per
    analyzer, with different wording (so the exact-duplicate collapse missed)."""
    from pcapper.threats import _drop_enip_duplicates_of_cip

    dets = [
        {"source": "EtherNet/IP", "severity": "high", "summary": "CIP Control Command", "details": "Stop ... device Reset/Start/Stop"},
        {"source": "CIP", "severity": "high", "summary": "CIP Control Command", "details": "Stop ... controller run state / logic"},
        {"source": "EtherNet/IP", "severity": "warning", "summary": "ENIP Enumeration Burst", "details": "ListIdentity"},
        {"source": "EtherNet/IP", "severity": "critical", "summary": "CIP Control Command", "details": "rated higher: kept"},
    ]
    kept = [(d["source"], d["summary"], d["severity"]) for d in _drop_enip_duplicates_of_cip(dets)]
    assert kept == [("CIP", "CIP Control Command", "high"), ("EtherNet/IP", "ENIP Enumeration Burst", "warning"),
                    ("EtherNet/IP", "CIP Control Command", "critical")]


def _dhcp_discover(mac: str, index: int, **options):
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP

    raw_mac = bytes.fromhex(mac.replace(":", ""))
    opts = [("message-type", "discover"), *options.items(), "end"]
    pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
           / UDP(sport=68, dport=67) / BOOTP(chaddr=raw_mac, xid=0x1000 + index) / DHCP(options=opts))
    pkt.time = T0 + index
    return pkt


def test_dhcp_client_identifier_is_not_exfiltration(tmp_path) -> None:
    """CipSession: a client resending its DUID / client identifier was a HIGH
    "Potential DHCP Option Exfiltration" (binary identifiers have high entropy)."""
    from pcapper.dhcp import analyze_dhcp

    mac = "ec:f4:bb:1f:01:09"
    duid = bytes.fromhex("ff1f0109000100011c9cdd8decf4bb1f0109")  # RFC 4361: IAID + DUID-LLT
    quiet = [_dhcp_discover(mac, i, client_id=duid) for i in range(4)]
    summary = analyze_dhcp(_write(tmp_path, "duid.pcap", quiet), show_status=False)
    assert not [a for a in summary.anomalies if "Exfiltration" in a.title]

    smuggled = [_dhcp_discover(mac, i, hostname=f"q{i}Zx9Lk2Vb7Np4Rt6Yw8Ms3Hd5Jf1Gc0") for i in range(4)]
    summary = analyze_dhcp(_write(tmp_path, "hosts.pcap", smuggled), show_status=False)
    assert [a for a in summary.anomalies if "Exfiltration" in a.title]
