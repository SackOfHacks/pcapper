"""--creds reports what the protocol analyzers recover.

The review behind these tests found --creds saying "no cleartext credentials"
for captures in which another report (--socks, --voip, --routing, --ldap,
--mqtt, ...) showed a password, and logins --creds missed for reasons of its
own: a port it did not know, an HTTP version string it did not accept, a
Telnet session with more than one login, and a 200-hit cap that hid the
privileged account a brute-force run reached late. Each test builds the
smallest capture that shows one of them.
"""

from __future__ import annotations

import base64
import json
import struct

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # type: ignore

from pcapper.creds import analyze_creds

CLIENT, SERVER = "10.0.0.5", "10.0.0.10"
T0 = 1_700_000_000.0


def _stamp(pkts):
    for i, pkt in enumerate(pkts):
        pkt.time = T0 + i * 0.01
    return pkts


def _tcp(messages, dport, sport=50000, client=CLIENT, server=SERVER):
    """A TCP conversation: ("c"|"s", bytes) messages with running sequence numbers."""
    pkts, cseq, sseq = [], 1000, 5000
    for side, data in messages:
        if side == "c":
            pkts.append(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(data))
            cseq += len(data)
        else:
            pkts.append(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(data))
            sseq += len(data)
    return pkts


def _udp(data, dport, sport=50001, src=CLIENT, dst=SERVER):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(data)


def _hits(tmp_path, name, pkts):
    capture = tmp_path / f"{name}.pcap"
    wrpcap(str(capture), _stamp(pkts))
    summary = analyze_creds(capture, show_status=False)
    return summary, {(h.kind, h.username, h.secret) for h in summary.hits}


# --- BER (LDAP, SNMP) ---------------------------------------------------------------
def _len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, value):
    return bytes([tag]) + _len(len(value)) + value


def _int(v):
    return _tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))


def _oct(v):
    return _tlv(0x04, v if isinstance(v, bytes) else v.encode())


def _seq(*items):
    return _tlv(0x30, b"".join(items))


def _set(*items):
    return _tlv(0x31, b"".join(items))


# --- logins --credsmissed for reasons of its own --------------------------------------
def test_ftp_logins_on_any_port(tmp_path):
    """FTP on a port --creds did not list: learnt from the server greeting and
    the client's USER, or (capture started late) from USER followed by 331."""
    login = [("s", b"220 Service ready\r\n"), ("c", b"USER bob\r\n"), ("s", b"331 Password required\r\n"),
             ("c", b"PASS FtpS3cret!\r\n"), ("s", b"230 Logged in\r\n")]
    late = [("c", b"USER carol\r\n"), ("s", b"331 Password required\r\n"), ("c", b"PASS c4rol!x\r\n")]
    _summary, hits = _hits(tmp_path, "ftp", _tcp(login, 2100) + _tcp(late, 4021, sport=50002))
    assert {("FTP USER", "bob", None), ("FTP PASS", None, "FtpS3cret!"),
            ("FTP USER", "carol", None), ("FTP PASS", None, "c4rol!x")} <= hits


def test_http_request_with_an_odd_version_string(tmp_path):
    """An embedded stack's "HTTP/1.0.8" request line skipped every HTTP check."""
    request = b"GET /weatherstation/update.php?ID=KS01&PASSWORD=12345678 HTTP/1.0.8\r\nHost: wx\r\n\r\n"
    _summary, hits = _hits(tmp_path, "http", _tcp([("c", request)], 80))
    assert any(secret == "12345678" for _kind, _user, secret in hits)


def test_every_telnet_login_of_a_session(tmp_path):
    """A rejected attempt followed by the one that worked: both are reported,
    in order, and the first is marked rejected."""
    session = [("s", b"login: "), ("c", b"alice\r\n"), ("s", b"Password: "), ("c", b"wrong1\r\n"),
               ("s", b"\r\nLogin incorrect\r\nlogin: "), ("c", b"alice\r\n"), ("s", b"Password: "),
               ("c", b"right2\r\n"), ("s", b"\r\nWelcome\r\n$ ")]
    summary, _hits_ = _hits(tmp_path, "telnet", _tcp(session, 23))
    logins = [(h.username, h.secret, h.evidence) for h in summary.hits if h.kind == "Telnet Login"]
    assert [(u, s) for u, s, _e in logins] == [("alice", "wrong1"), ("alice", "right2")]
    assert "rejected by the server" in logins[0][2] and "rejected" not in logins[1][2]


def test_privileged_account_after_two_hundred_hits(tmp_path):
    """The 200-hit cap applied before the exposure checks, so the privileged
    account a brute-force run reached late was never flagged."""
    messages = [("s", b"220 FTP ready\r\n")]
    for i in range(150):
        messages += [("c", b"USER guest\r\n"), ("s", b"331 Password required\r\n"),
                     ("c", f"PASS guess{i}\r\n".encode()), ("s", b"530 Login incorrect\r\n")]
    for i in range(10):
        messages += [("c", b"USER administrator\r\n"), ("s", b"331 Password required\r\n"),
                     ("c", f"PASS admin{i}\r\n".encode()), ("s", b"530 Login incorrect\r\n")]
    summary, _hits_ = _hits(tmp_path, "brute", _tcp(messages, 21))
    assert summary.matches == len(summary.hits) == 320 and not summary.truncated
    admin = [row for row in summary.privileged_exposures if row["user"] == "administrator"]
    assert len(admin) == 1 and admin[0]["count"] == 10


def test_credentials_written_in_a_mail(tmp_path):
    mail = [("s", b"220 mail ESMTP\r\n"), ("c", b"EHLO ws01\r\n"), ("s", b"250 mail\r\n"), ("c", b"DATA\r\n"),
            ("s", b"354 go ahead\r\n"),
            ("c", b"Subject: VPN\r\n\r\nYour login is user=jdoe password=Welcome2024!\r\nPassword: has been reset\r\n.\r\n")]
    _summary, hits = _hits(tmp_path, "mail", _tcp(mail, 25))
    assert ("Mail Body Credential Field", None, "Welcome2024!") in hits
    assert ("Mail Body Credential Field", "jdoe", None) in hits
    assert not any(secret == "has" for _kind, _user, secret in hits)
    # "Your login is user=..." in an SMTP flow is not an IMAP LOGIN command.
    assert not any(kind == "IMAP LOGIN" for kind, _user, _secret in hits)


def test_email_auth_capability_is_not_a_secret(tmp_path):
    """--email raised "Token or secret in email content" on AUTH=PLAIN/LOGIN."""
    from pcapper.email import analyze_email

    capture = tmp_path / "ehlo.pcap"
    wrpcap(str(capture), _stamp(_tcp([("s", b"220 mail ESMTP\r\n"), ("c", b"EHLO ws01\r\n"),
                                      ("s", b"250-mail\r\n250-AUTH=LOGIN PLAIN\r\n250 AUTH=XAOL-UAS-MB\r\n"),
                                      ("c", b"QUIT\r\n")], 25)))
    summaries = [d.get("summary") for d in analyze_email(capture, show_status=False).detections]
    assert "Token or secret in email content" not in summaries


# --- credentials the analyzers recover ------------------------------------------------
def test_socks5_username_password(tmp_path):
    proxy = [("c", b"\x05\x01\x02"), ("s", b"\x05\x02"), ("c", b"\x01\x05alice\x08Pr0xyPw!"), ("s", b"\x01\x00"),
             ("c", b"\x05\x01\x00\x01\xc0\xa8\x01\x0a\x0d\x3d"), ("s", b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")]
    summary, hits = _hits(tmp_path, "socks", _tcp(proxy, 1080))
    assert ("SOCKS5 Username/Password", "alice", "Pr0xyPw!") in hits
    assert next(h for h in summary.hits if h.kind.startswith("SOCKS")).ts == T0 + 0.02


def test_sip_digest_is_an_offline_guessable_exchange(tmp_path):
    register = ("REGISTER sip:pbx.local SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK1\r\n"
                "From: <sip:alice@pbx.local>;tag=1\r\nTo: <sip:alice@pbx.local>\r\nCall-ID: abc@10.0.0.5\r\n"
                "CSeq: 2 REGISTER\r\nAuthorization: Digest username=\"alice\", realm=\"asterisk\", nonce=\"5f1b2c3d\", "
                "uri=\"sip:pbx.local\", response=\"0123456789abcdef0123456789abcdef\", algorithm=MD5\r\n"
                "Content-Length: 0\r\n\r\n").encode()
    summary, hits = _hits(tmp_path, "sip", [_udp(register, 5060, sport=5060)])
    assert ("SIP Digest Challenge Response", "alice", None) in hits
    assert summary.deterministic_checks["crackable_hash_capture"]


def test_routing_cleartext_passwords(tmp_path):
    ospf_body = bytes([255, 255, 255, 0]) + struct.pack(">HBBI", 10, 2, 1, 40) + b"\x00" * 8
    ospf = (struct.pack(">BBH", 2, 1, 24 + len(ospf_body)) + bytes([10, 0, 0, 2]) + bytes(4)
            + struct.pack(">HH", 0, 1) + b"ospfpwd\x00" + ospf_body)
    vrrp = bytes([0x21, 1, 100, 1, 1, 1, 0, 0]) + bytes([10, 0, 0, 254]) + b"vrrppass"
    rip = (bytes([2, 2, 0, 0]) + b"\xff\xff" + struct.pack(">H", 2) + b"ripsecret".ljust(16, b"\x00")
           + struct.pack(">HH", 2, 0) + bytes([10, 1, 0, 0]) + bytes([255, 255, 0, 0]) + bytes(4) + struct.pack(">I", 1))
    pkts = [Ether() / IP(src="10.0.0.2", dst="224.0.0.5", proto=89, ttl=1) / Raw(ospf),
            Ether() / IP(src="10.0.0.6", dst="224.0.0.18", proto=112, ttl=255) / Raw(vrrp),
            _udp(rip, 520, sport=520, src="10.0.0.3", dst="224.0.0.9")]
    _summary, hits = _hits(tmp_path, "routing", pkts)
    assert {("OSPF Cleartext Authentication", None, "ospfpwd"),
            ("VRRP Cleartext Authentication", None, "vrrppass"),
            ("RIP Cleartext Authentication", None, "ripsecret")} <= hits


def test_ldap_passwords_beyond_simple_binds(tmp_path):
    sasl = _seq(_int(2), _tlv(0x60, _int(3) + _oct("") + _tlv(0xA3, _oct("PLAIN") + _oct(b"\x00alice\x00SaslPl@in1"))))
    modify = _seq(_int(3), _tlv(0x66, _oct("CN=bob,CN=Users,DC=corp,DC=local") + _seq(
        _seq(_tlv(0x0A, b"\x02"), _seq(_oct("userPassword"), _set(_oct("NewPassw0rd!")))))))
    entry = _seq(_int(4), _tlv(0x64, _oct("CN=WS01,OU=Computers,DC=corp,DC=local") + _seq(
        _seq(_oct("ms-Mcs-AdmPwd"), _set(_oct("LapsS3cret#99"))), _seq(_oct("sAMAccountName"), _set(_oct("WS01$"))))))
    _summary, hits = _hits(tmp_path, "ldap", _tcp([("c", sasl), ("c", modify), ("s", entry)], 389))
    assert {("LDAP SASL PLAIN Bind", "alice", "SaslPl@in1"),
            ("LDAP Password Attribute Written", "CN=bob,CN=Users,DC=corp,DC=local", "NewPassw0rd!"),
            ("LDAP Password Attribute Returned", "CN=WS01,OU=Computers,DC=corp,DC=local", "LapsS3cret#99")} <= hits


def test_mqtt_connect_credentials(tmp_path):
    def s16(raw):
        return struct.pack(">H", len(raw)) + raw
    body = s16(b"MQTT") + bytes([4, 0xC2]) + struct.pack(">H", 60) + s16(b"dev001") + s16(b"sensor01") + s16(b"MqttP@ss")
    _summary, hits = _hits(tmp_path, "mqtt", _tcp([("c", bytes([0x10, len(body)]) + body), ("s", b"\x20\x02\x00\x00")], 1883))
    assert ("MQTT CONNECT Credentials", "sensor01", "MqttP@ss") in hits


def test_bacnet_device_communication_control_password(tmp_path):
    apdu = bytes([0x00, 0x05, 0x01, 0x11, 0x19, 0x01, 0x2D, 0x09, 0x00]) + b"bacnetpw"
    data = bytes([0x01, 0x04]) + apdu
    frame = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(data)) + data
    _summary, hits = _hits(tmp_path, "bacnet", [_udp(frame, 47808, sport=47808)])
    assert ("BACnet Service Password", None, "bacnetpw") in hits


def test_snmpv3_user_name(tmp_path):
    usm = _seq(_oct(bytes.fromhex("80001f888056c0a8")), _int(5), _int(1234), _oct("snmpadmin"), _oct(bytes(12)), _oct(b""))
    message = _seq(_int(3), _seq(_int(42), _int(65507), _oct(b"\x05"), _int(3)), _oct(usm),
                   _seq(_oct(b""), _oct(b""), _tlv(0xA0, _int(7) + _int(0) + _int(0) + _seq())))
    _summary, hits = _hits(tmp_path, "snmpv3", [_udp(message, 161)])
    assert ("SNMPv3 USM User Name", "snmpadmin", None) in hits


def test_vnc_password_authentication(tmp_path):
    rfb = [("s", b"RFB 003.008\n"), ("c", b"RFB 003.008\n"), ("s", b"\x01\x02"), ("c", b"\x02"),
           ("s", bytes(range(16))), ("c", bytes(range(100, 116))), ("s", b"\x00\x00\x00\x00")]
    _summary, hits = _hits(tmp_path, "vnc", _tcp(rfb, 5900))
    assert ("VNC Authentication Challenge Response", None, None) in hits


# --- OT passwords ----------------------------------------------------------------------
def test_acse_s7_and_melsec_passwords(tmp_path):
    acse = (b"\x03\x00\x00\x2c\x02\xf0\x80\x60\x20\x8a\x02\x06\x80\x8b\x03\x52\x03\x01"
            b"\xac\x0a\x80\x08pass1234")
    password = b"secret12"
    encoded = bytearray(8)
    for i in range(8):
        encoded[i] = password[i] ^ 0x55 ^ (encoded[i - 2] if i >= 2 else 0)
    param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x45, 0x01, 0x00])
    data = bytes([0xFF, 0x09, 0x00, 0x08]) + bytes(encoded)
    s7 = bytes([0x32, 0x07, 0, 0, 1, 0]) + struct.pack(">HH", len(param), len(data)) + param + data
    tpkt = b"\x03\x00" + struct.pack(">H", 7 + len(s7)) + b"\x02\xf0\x80" + s7
    melsec = bytes([0x50, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00]) + struct.pack("<H", 16) + b"\x10\x00" \
        + struct.pack("<HH", 0x1630, 0) + struct.pack("<H", 8) + b"melsecpw"
    pkts = _tcp([("c", acse)], 102) + _tcp([("c", tpkt)], 102, sport=50003) + _tcp([("c", melsec)], 5007, sport=50004)
    _summary, hits = _hits(tmp_path, "ot", pkts)
    assert {("ACSE Password Authentication", None, "pass1234"), ("S7 PLC Password", None, "secret12"),
            ("MELSEC Remote Password", None, "melsecpw")} <= hits


# --- text in any payload -----------------------------------------------------------------
def test_secrets_in_scripts_cookies_and_tokens(tmp_path):
    claims = base64.urlsafe_b64encode(json.dumps({"sub": "alice"}).encode()).rstrip(b"=").decode()
    jwt = f"eyJhbGciOiJIUzI1NiJ9.{claims}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    soap = (b"POST /wsman HTTP/1.1\r\nHost: srv01:5985\r\n\r\n<rsp:Command>powershell -c \"$p = ConvertTo-SecureString "
            b"'Spring2025!' -AsPlainText -Force; $c = New-Object PSCredential('corp\\svc_sql', $p)\"</rsp:Command>")
    cookie = b"Cookie: mstshash=administr\r\n\x01\x00\x08\x00\x03\x00\x00\x00"
    rdp = b"\x03\x00" + struct.pack(">H", 11 + len(cookie)) + bytes([6 + len(cookie), 0xE0, 0, 0, 0, 0, 0]) + cookie
    response = f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"access_token":"{jwt}"}}'.encode()
    dump = b"Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    pkts = (_tcp([("c", soap)], 5985) + _tcp([("c", rdp)], 3389, sport=50005)
            + _tcp([("c", b"GET /api HTTP/1.1\r\nHost: app\r\n\r\n"), ("s", response)], 8080, sport=50006)
            + _tcp([("c", dump)], 4444, sport=50007))
    _summary, hits = _hits(tmp_path, "text", pkts)
    assert {("PowerShell SecureString Plaintext", "corp\\svc_sql", "Spring2025!"),
            ("RDP Connection Cookie User", "administr", None),
            ("JSON Web Token", "alice", jwt),
            ("Password Hash Dump Line", "Administrator", None)} <= hits


def test_ike_aggressive_mode_identity(tmp_path):
    def payload(next_type, body):
        return bytes([next_type, 0]) + struct.pack(">H", 4 + len(body)) + body
    chain = payload(4, bytes(8)) + payload(10, bytes(4)) + payload(5, bytes(4)) + payload(0, bytes([11, 0, 0, 0]) + b"vpngroup")
    header = bytes(range(1, 9)) + bytes(8) + bytes([1, 0x10, 4, 0]) + bytes(4) + struct.pack(">I", 28 + len(chain))
    _summary, hits = _hits(tmp_path, "ike", [_udp(header + chain, 500, sport=500)])
    assert ("IKEv1 Aggressive Mode Identity", "vpngroup", None) in hits


# --- network-access authentication -------------------------------------------------------
def test_radius_tacacs_bfd_ppp_and_eap(tmp_path):
    attrs = bytes([1, 12]) + b"radiususer" + bytes([2, 18]) + bytes(16)
    radius = bytes([1, 7]) + struct.pack(">H", 20 + len(attrs)) + bytes(16) + attrs
    user, port, secret = b"tacuser", b"tty1", b"tacpass"
    body = bytes([1, 1, 2, 1, len(user), len(port), 0, len(secret)]) + user + port + secret
    tacacs = bytes([0xC1, 1, 1, 1]) + b"\x00\x00\x00\x2a" + struct.pack(">I", len(body)) + body
    bfd_auth = bytes([1, 3 + 7, 1]) + b"bfdpass"
    bfd = bytes([0x20, 0xC4, 3, 24 + len(bfd_auth)]) + bytes(20) + bfd_auth
    pap = bytes([1, 1]) + struct.pack(">H", 6 + 7 + 7) + bytes([7]) + b"pppuser" + bytes([7]) + b"ppppass"
    ppp = struct.pack(">H", 0xC023) + pap
    pppoe = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb", type=0x8864) / Raw(
        bytes([0x11, 0x00, 0x00, 0x01]) + struct.pack(">H", len(ppp)) + ppp)
    eap = bytes([2, 1]) + struct.pack(">H", 5 + 9) + bytes([1]) + b"dot1xuser"
    eapol = Ether(src="00:11:22:33:44:56", dst="01:80:c2:00:00:03", type=0x888E) / Raw(
        bytes([1, 0]) + struct.pack(">H", len(eap)) + eap)
    pkts = [_udp(radius, 1812), *_tcp([("c", tacacs)], 49, sport=50008), _udp(bfd, 3784, sport=49152), pppoe, eapol]
    _summary, hits = _hits(tmp_path, "access", pkts)
    assert {("RADIUS PAP Access-Request", "radiususer", None), ("TACACS+ PAP Password", "tacuser", "tacpass"),
            ("BFD Simple Password", None, "bfdpass"), ("PPP PAP Password", "pppuser", "ppppass"),
            ("EAP Identity", "dot1xuser", None)} <= hits
