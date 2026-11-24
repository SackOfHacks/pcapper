"""The SMB, RDP, WinRM, WMIC, PowerShell, RPC, VNC and remote-access analyses
read lite records from disk and dissect only the packets they may use: their
results must equal the ones computed over scapy packets (in memory), record
for record."""

from __future__ import annotations

import re
import shutil
import struct
import uuid as uuidlib
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import (  # noqa: E402
    ICMP,
    IP,
    LLC,
    SNAP,
    STP,
    TCP,
    UDP,
    Dot1Q,
    Dot3,
    Ether,
    IPOption_RR,
    IPv6,
    Raw,
    wrpcap,
)

from pcapper import pcap_cache, powershell, rdp, rpc, utils, winrm, wmic  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.powershell import analyze_powershell  # noqa: E402
from pcapper.rdp import analyze_rdp  # noqa: E402
from pcapper.remote_access import analyze_remote_access  # noqa: E402
from pcapper.rpc import analyze_rpc  # noqa: E402
from pcapper.smb import analyze_smb  # noqa: E402
from pcapper.vnc import analyze_vnc  # noqa: E402
from pcapper.winrm import analyze_winrm  # noqa: E402
from pcapper.wmic import analyze_wmic  # noqa: E402

DATA = Path(__file__).parent / "data"
T0 = 1_700_000_000.0

A, B = "10.0.0.1", "10.0.0.2"
_ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


# --- payload builders ------------------------------------------------------------


def _nbss(body: bytes) -> bytes:
    return b"\x00" + len(body).to_bytes(3, "big") + body


def _smb2(command: int, body: bytes = b"\x00" * 36, *, response: bool = False) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<HH", header, 4, 64, 0)
    struct.pack_into("<H", header, 12, command)
    struct.pack_into("<I", header, 16, 1 if response else 0)
    struct.pack_into("<Q", header, 24, 7)
    struct.pack_into("<Q", header, 40, 0x1122334455667788)
    return bytes(header) + body


def _smb1_negotiate() -> bytes:
    header = b"\xffSMB" + bytes([0x72]) + b"\x00" * 4 + b"\x18" + b"\x01\x28" + b"\x00" * 20
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00"
    return header + b"\x00" + len(dialects).to_bytes(2, "little") + dialects


def _tpkt(x224: bytes) -> bytes:
    return b"\x03\x00" + (4 + len(x224)).to_bytes(2, "big") + x224


def _rdp_request(user: bytes) -> bytes:
    cookie = b"Cookie: mstshash=" + user + b"\r\n"
    neg = bytes.fromhex("0100080003000000")  # RDP_NEG_REQ: TLS | CredSSP
    return _tpkt(bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg)


def _rdp_confirm(selected: int) -> bytes:
    neg = bytes([2, 0, 8, 0]) + selected.to_bytes(4, "little")  # RDP_NEG_RSP
    return _tpkt(bytes([6 + len(neg), 0xD0, 0, 0, 0x12, 0x34, 0]) + neg)


EPM_UUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"


def _dce_bind(iface: str = EPM_UUID, call_id: int = 1) -> bytes:
    abstract = uuidlib.UUID(iface).bytes_le + struct.pack("<HH", 3, 0)
    ndr = uuidlib.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le + struct.pack("<I", 2)
    ctx = struct.pack("<HBB", 0, 1, 0) + abstract + ndr
    body = struct.pack("<HHIB3x", 5840, 5840, 0, 1) + ctx
    return struct.pack("<BBBB4sHHI", 5, 0, 11, 3, b"\x10\x00\x00\x00", 16 + len(body), 0, call_id) + body


def _dce_bind_ack(call_id: int = 1) -> bytes:
    body = struct.pack("<HHI", 5840, 5840, 0x1234) + b"\x04\x00135\x00" + b"\x00" * 30
    return struct.pack("<BBBB4sHHI", 5, 0, 12, 3, b"\x10\x00\x00\x00", 16 + len(body), 0, call_id) + body


def _dce_request(opnum: int, stub: bytes = b"\x00" * 24, call_id: int = 2) -> bytes:
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    return struct.pack("<BBBB4sHHI", 5, 0, 0, 3, b"\x10\x00\x00\x00", 16 + len(body), 0, call_id) + body


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


# --- the edge capture ------------------------------------------------------------


def _base_frames() -> list:
    """tests/test_lite_it_paths.py's edge frames: padding, VLAN, IPv6, IP
    options, STP over LLC/SNAP, ICMP, an application layer scapy dissects."""
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    return [
        eth / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="S"),
        eth / IP(src=A, dst=B) / TCP(sport=40000, dport=80) / Raw(b"GET /login?user=bob&password=hunter2 HTTP/1.1\r\nHost: x\r\n\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40001, dport=8081) / Raw(b"POST /a HTTP/1.1\r\nAuthorization: Basic Ym9iOnNlY3JldA==\r\n\r\n"),
        eth / IP(src=B, dst=A) / TCP(sport=80, dport=40000) / Raw(b"HTTP/1.1 200 OK\r\n\r\nusername=x"),
        eth / IP(src=A, dst=B) / TCP(sport=40002, dport=21) / Raw(b"USER a\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40002, dport=21) / Raw(b"PASS b\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40003, dport=23) / Raw(b"login: "),
        eth / IP(src=B, dst=A) / TCP(sport=40004, dport=4444) / Raw(b"\xff\xfb\x01\xff\xfd\x03"),
        eth / IP(src=A, dst=B) / TCP(sport=40005, dport=4445) / Raw(b"\xff"),
        eth / Dot1Q(vlan=5) / IP(src=A, dst=B) / TCP(sport=40006, dport=110) / Raw(b"USER v\r\nPASS w\r\n"),
        eth / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40007, dport=143) / Raw(b"a1 LOGIN u p\r\n"),
        eth / IP(src=A, dst=B, options=[IPOption_RR()]) / TCP(sport=40008, dport=80) / Raw(b"GET /?pass=x HTTP/1.0\r\n\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=900, dport=2049) / Raw(b"\x80\x00\x00\x28" + b"\x00" * 40),
        eth / IP(src=A, dst=B) / UDP(sport=901, dport=2049) / Raw(b"\x00\x00\x00\x01\x00\x00\x00\x00" + b"\x00" * 32),
        eth / IP(src=A, dst=B) / TCP(sport=40009, dport=5190) / Raw(b"*\x01\x00\x01\x00\x04\x00\x00\x00\x01"),
        eth / IP(src=A, dst=B) / TCP(sport=40010, dport=443) / Raw(b"*\x02\x00\x02\x00\x10" + b"\x00" * 16),
        eth / IP(src=A, dst=B) / UDP(sport=40011, dport=161) / Raw(bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")),
        eth / IP(src=A, dst=B) / ICMP() / Raw(b"password=icmp"),
        Dot3(src="00:11:22:33:44:55", dst="01:80:c2:00:00:00") / LLC() / STP(),
        eth / Dot1Q(vlan=9, type=0x32) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0x0C, code=0x10B) / STP() / Raw(b"\x00\x00\x00\x00\x02\x01\x0e"),
        eth / IP(src=A, dst=B) / UDP(sport=40012, dport=5000, len=12) / Raw(b"user=a pass=b"),
    ]


def _after(frame, trailing: bytes):  # type: ignore[no-untyped-def]
    """``frame`` with bytes past its IP length, which scapy hangs behind the
    transport layer as padding (and the lite parser leaves out of the Raw
    payload): a payload test that reads them must still agree."""
    return frame.__class__(bytes(frame) + trailing)


def _windows_frames() -> list:
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    C, S, X = "10.0.1.1", "10.0.1.2", "10.0.1.3"
    smb2 = _nbss(_smb2(0))
    v6 = IPv6(src="fe80::1", dst="fe80::2")
    frames = [
        # SMB: on 445/139 (also an empty, padded ACK), off them by its magic,
        # magic in the padding, over UDP (never SMB), IPv6, VLAN, IP options.
        eth / IP(src=C, dst=S) / TCP(sport=40100, dport=445, flags="PA") / Raw(smb2),
        eth / IP(src=S, dst=C) / TCP(sport=445, dport=40100, flags="A"),
        eth / IP(src=S, dst=C) / TCP(sport=445, dport=40100, flags="PA") / Raw(_nbss(_smb2(0, response=True))),
        eth / IP(src=C, dst=S) / TCP(sport=40101, dport=4455, flags="PA") / Raw(smb2),
        eth / IP(src=C, dst=S) / TCP(sport=40102, dport=139, flags="PA") / Raw(_nbss(_smb1_negotiate())),
        eth / IP(src=C, dst=S) / UDP(sport=40103, dport=445) / Raw(smb2),
        eth / v6 / TCP(sport=40104, dport=4458, flags="PA") / Raw(smb2),
        eth / Dot1Q(vlan=7) / IP(src=C, dst=S) / TCP(sport=40105, dport=4456, flags="PA") / Raw(smb2),
        _after(eth / IP(src=C, dst=S) / TCP(sport=40106, dport=4457, flags="A"), b"\x00\x00\x00\x10\xfeSMB" + b"\x00" * 8),
        eth / IP(src=C, dst=S) / TCP(sport=40107, dport=4459, flags="PA") / Raw(b"\x00\x00"),
        eth / IP(src=C, dst=S, options=[IPOption_RR()]) / TCP(sport=40108, dport=4460, flags="PA") / Raw(smb2),
        # RDP: on its ports (TCP and UDP-only ones), a cookie or RDPUDP tag off
        # them, a cookie past the 128-byte prefix or in the padding, an RDP
        # source port to a privileged port, IPv6.
        eth / IP(src=C, dst=S) / TCP(sport=40200, dport=3389, flags="PA") / Raw(_rdp_request(b"alice")),
        eth / IP(src=S, dst=C) / TCP(sport=3389, dport=40200, flags="PA") / Raw(_rdp_confirm(2)),
        eth / IP(src=C, dst=X) / TCP(sport=40201, dport=8443, flags="PA") / Raw(_rdp_request(b"bob")),
        eth / IP(src=X, dst=C) / TCP(sport=8443, dport=40201, flags="PA") / Raw(_rdp_confirm(0)),
        eth / IP(src=C, dst=S) / TCP(sport=40202, dport=8444, flags="PA") / Raw(b"x" * 120 + b"Cookie: mstshash=carol\r\n"),
        eth / IP(src=C, dst=S) / TCP(sport=40208, dport=8446, flags="PA") / Raw(b"x" * 80 + b"Cookie: mstshash=frank\r\n"),
        eth / IP(src=C, dst=S) / UDP(sport=40203, dport=3389) / Raw(b"\xff\xff\xff\xff\x00\x10RDPUDP"),
        eth / IP(src=C, dst=S) / UDP(sport=40204, dport=9999) / Raw(b"\x00RDPUDP\x00"),
        eth / IP(src=C, dst=S) / UDP(sport=40205, dport=3391) / Raw(b"\x16\xfe\xfd" + b"\x00" * 10),
        eth / IP(src=S, dst=C) / TCP(sport=3389, dport=999, flags="PA") / Raw(b"\x16\x03\x01\x00\x05hello"),
        _after(eth / IP(src=C, dst=S) / TCP(sport=40206, dport=8445, flags="A"), b"Cookie: mstshash=dave\r\n"),
        eth / v6 / TCP(sport=40207, dport=3389, flags="PA") / Raw(_rdp_request(b"eve")),
        # WinRM: on its ports, WSMAN in the first 64 bytes off them, past them,
        # in the padding, a WinRM source port to a privileged port, a SYN.
        eth / IP(src=C, dst=S) / TCP(sport=40300, dport=5985, flags="PA") / Raw(
            b"POST /wsman HTTP/1.1\r\nHost: s:5985\r\nUser-Agent: Microsoft WinRM Client\r\n"
            b"Authorization: Negotiate TlRMTVNTUAAB\r\n\r\n"
        ),
        eth / IP(src=S, dst=C) / TCP(sport=5985, dport=40300, flags="PA") / Raw(b"HTTP/1.1 401 \r\nWWW-Authenticate: Negotiate\r\n\r\n"),
        eth / IP(src=C, dst=X) / TCP(sport=40301, dport=8080, flags="PA") / Raw(
            b"POST /WSMAN HTTP/1.1\r\nHost: x\r\n\r\n"
            b"<a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>"
        ),
        eth / IP(src=C, dst=X) / TCP(sport=40302, dport=8081, flags="PA") / Raw(b"y" * 70 + b"wsman"),
        _after(eth / IP(src=C, dst=X) / TCP(sport=40303, dport=8082, flags="PA") / Raw(b"GET / HTTP/1.1\r\n"), b"WinRM"),
        eth / IP(src=X, dst=C) / TCP(sport=5986, dport=999, flags="PA") / Raw(b"\x16\x03\x01"),
        eth / IP(src=C, dst=S) / TCP(sport=40304, dport=5986, flags="S"),
        # WMIC: hints as UTF-16LE at an odd offset, ASCII, upper case; a hint
        # word that is no hint; over UDP (never WMIC); in the padding.
        eth / IP(src=C, dst=S) / TCP(sport=40400, dport=49665, flags="PA") / Raw(
            _dce_request(6, b"\x00" + _utf16("root\\cimv2") + b"\x00\x00" + _utf16("Win32_Process"))
        ),
        eth / IP(src=C, dst=S) / TCP(sport=40401, dport=49666, flags="PA") / Raw(b"cmd /c wmic /node:10.0.1.9 process call create calc.exe"),
        eth / IP(src=C, dst=S) / TCP(sport=40402, dport=49667, flags="PA") / Raw(b"\x01" + _utf16("SELECT * FROM WIN32_SERVICE")),
        eth / IP(src=C, dst=S) / TCP(sport=40403, dport=49668, flags="PA") / Raw(b"wmiprvse.exe started"),
        eth / IP(src=C, dst=S) / UDP(sport=40404, dport=49669) / Raw(b"wmic process list"),
        _after(eth / IP(src=C, dst=S) / TCP(sport=40405, dport=49670, flags="A"), b"IWbemServices"),
        # PowerShell: a hint, the port context, command + encoded command, a
        # hint alone (score 2: counted, not reported), UTF-16LE, WinRM +
        # suspicious (score 2), suspicious alone (score 1), an empty padded
        # segment on a PowerShell port, a command in the padding.
        eth / IP(src=C, dst=X) / TCP(sport=40500, dport=80, flags="PA") / Raw(
            b"GET /a.ps1 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0) WindowsPowerShell/5.1\r\n\r\n"
        ),
        eth / IP(src=C, dst=S) / TCP(sport=40501, dport=5985, flags="PA") / Raw(b"some text payload here"),
        eth / IP(src=C, dst=X) / TCP(sport=40502, dport=8000, flags="PA") / Raw(
            b"powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA="
        ),
        eth / IP(src=C, dst=X) / TCP(sport=40503, dport=8001, flags="PA") / Raw(b"xpwshx tooling"),
        eth / IP(src=C, dst=X) / TCP(sport=40504, dport=8002, flags="PA") / Raw(_utf16("Windows PowerShell host")),
        eth / IP(src=C, dst=X) / TCP(sport=40505, dport=8003, flags="PA") / Raw(b"<wsman> invoke-expression $x"),
        eth / IP(src=C, dst=X) / TCP(sport=40506, dport=8004, flags="PA") / Raw(b"invoke-expression only"),
        eth / IP(src=C, dst=X) / TCP(sport=40507, dport=47001, flags="A"),
        _after(eth / IP(src=C, dst=X) / TCP(sport=40508, dport=8005, flags="A"), b"pwsh -c whoami"),
        # RPC: bind / bind_ack on 135, a request on a dynamic port, a PDU at an
        # offset over SMB, over UDP, too short, after junk, in the padding.
        eth / IP(src=C, dst=S) / TCP(sport=40600, dport=135, flags="PA") / Raw(_dce_bind()),
        eth / IP(src=S, dst=C) / TCP(sport=135, dport=40600, flags="PA") / Raw(_dce_bind_ack()),
        eth / IP(src=C, dst=S) / TCP(sport=40601, dport=49667, flags="PA") / Raw(_dce_request(3)),
        eth / IP(src=C, dst=S) / TCP(sport=40602, dport=445, flags="PA") / Raw(_nbss(_smb2(9, b"\x31\x00" + b"\x00" * 46) + _dce_request(1))),
        eth / IP(src=C, dst=S) / UDP(sport=40603, dport=135) / Raw(_dce_request(1)),
        eth / IP(src=C, dst=S) / TCP(sport=40604, dport=135, flags="PA") / Raw(b"\x05\x00\x0b\x03short"),
        eth / IP(src=C, dst=S) / TCP(sport=40605, dport=50000, flags="PA") / Raw(b"junk\x05" + _dce_request(2)),
        _after(eth / IP(src=C, dst=S) / TCP(sport=40606, dport=50001, flags="A"), _dce_request(4)),
        eth / IP(src=C, dst=S) / UDP(sport=40607, dport=50002) / Raw(_dce_request(5)),
    ]
    return frames


def _tcp(src: str, dst: str, sport: int, dport: int, payload: bytes, flags: str):  # type: ignore[no-untyped-def]
    pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return pkt / Raw(payload) if payload else pkt


def _vnc_frames() -> list:
    viewer, desktop, remote = "10.0.2.1", "10.0.2.2", "10.0.2.3"
    hello = b"ID:5376529\x00" + b"\x7fwu\x00" + b"C:\\Games\x00taskhost.exe\x00"
    hello += b"\x00" * (250 - len(hello))
    flows = [
        # A viewer on 5900: the handshake, versions, security types.
        (viewer, desktop, 40700, 5900, b"", "S"),
        (desktop, viewer, 5900, 40700, b"", "SA"),
        (viewer, desktop, 40700, 5900, b"", "A"),
        (desktop, viewer, 5900, 40700, b"RFB 003.008\n", "PA"),
        (viewer, desktop, 40700, 5900, b"RFB 003.008\n", "PA"),
        (desktop, viewer, 5900, 40700, b"\x01\x02", "PA"),
        (viewer, desktop, 40700, 5900, b"\x02", "PA"),
        # A desktop dialling a listening viewer: pending until the hello.
        (desktop, viewer, 50000, 5500, b"", "S"),
        (viewer, desktop, 5500, 50000, b"", "SA"),
        (desktop, viewer, 50000, 5500, b"", "A"),
        (desktop, viewer, 50000, 5500, hello, "PA"),
        (desktop, viewer, 50000, 5500, b"RFB 003.008\n", "PA"),
        (viewer, desktop, 5500, 50000, b"", "A"),
        # A banner on an unregistered port after a pending handshake.
        (remote, desktop, 40701, 4444, b"", "S"),
        (desktop, remote, 4444, 40701, b"", "SA"),
        (remote, desktop, 40701, 4444, b"", "A"),
        (desktop, remote, 4444, 40701, b"RFB 003.003\n", "PA"),
        (remote, desktop, 40701, 4444, b"RFB 003.003\n", "PA"),
        (desktop, remote, 4444, 40701, b"\x00\x00\x00\x02", "PA"),
        # A desktop dialling out from a low port: only the pending SYN shows
        # the connection is reverse (by the ports it would not be).
        (desktop, viewer, 3000, 6000, b"", "S"),
        (viewer, desktop, 6000, 3000, b"", "SA"),
        (desktop, viewer, 3000, 6000, b"", "A"),
        (desktop, viewer, 3000, 6000, b"RFB 003.008\n", "PA"),
    ]
    # More than PENDING_FLOW_PACKETS before the banner: the flow is done.
    flows += [(remote, desktop, 40702, 4445, b"data", "PA")] * 18
    flows += [(desktop, remote, 4445, 40702, b"RFB 003.008\n", "PA")]
    frames = [_tcp(*flow) for flow in flows]
    frames += [
        # A banner past the IP length (padding): not VNC.
        _after(_tcp(remote, desktop, 40703, 4446, b"", "A"), b"RFB 003.008\n"),
        _after(_tcp(remote, desktop, 40704, 4447, b"", "A"), b"ID:12\x00"),
        # A banner over UDP: never VNC.
        _ETH / IP(src=remote, dst=desktop) / UDP(sport=40705, dport=5900) / Raw(b"RFB 003.008\n"),
    ]
    return frames


def _remote_access_frames() -> list:
    outside, server, plc, other = "93.184.216.34", "10.0.3.2", "10.0.3.3", "10.0.3.4"
    flows = [
        # An RDP login from outside, then the server drives a PLC: a pivot.
        (outside, server, 40800, 3389, b"", "S"),
        (server, outside, 3389, 40800, b"", "SA"),
        (outside, server, 40800, 3389, b"", "A"),
        (outside, server, 40800, 3389, b"\x03\x00\x00\x08\x02\xf0\x80\x00", "PA"),
        (server, plc, 40801, 502, b"", "S"),
        (server, plc, 40801, 502, b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01", "PA"),
        (server, plc, 40801, 502, b"", "A"),
        # A half-open SMB handshake, ACKs with no handshake, data from 445.
        (outside, server, 40802, 445, b"", "S"),
        (server, outside, 445, 40802, b"", "SA"),
        (other, server, 40803, 22, b"", "A"),
        (server, other, 22, 40803, b"SSH-2.0-x\r\n", "PA"),
        (other, server, 40804, 8080, b"GET / HTTP/1.0\r\n\r\n", "PA"),
    ]
    frames = [_tcp(*flow) for flow in flows]
    frames += [
        _ETH / IP(src=server, dst=other) / UDP(sport=40805, dport=47808) / Raw(b"\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"),
        _ETH / IP(src=server, dst=other) / UDP(sport=40806, dport=5353) / Raw(b"\x00" * 12),
        _ETH / IP(src=other, dst=other) / TCP(sport=40807, dport=3389, flags="S"),
    ]
    return frames


def _frames() -> list:
    out = []
    for index, frame in enumerate(_base_frames() + _windows_frames() + _vnc_frames() + _remote_access_frames()):
        data = bytes(frame)
        if len(data) < 60:
            data += bytes(range(1, 61 - len(data)))  # padding that is not zero
        pkt = Ether(data) if isinstance(frame, Ether) and not isinstance(frame, Dot3) else frame.__class__(data)
        pkt.time = T0 + index
        out.append(pkt)
    return out


@pytest.fixture()
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "edge_windows.pcap"
    wrpcap(str(path), _frames())
    return path


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    yield
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()


def _captures(tmp_path: Path, capture: Path) -> list[Path]:
    paths = [capture]
    for name in ("mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap", "voip_attack.pcap"):
        target = tmp_path / name
        shutil.copy(DATA / name, target)
        paths.append(target)
    return paths


ANALYSES = [
    analyze_smb,
    analyze_rdp,
    analyze_winrm,
    analyze_wmic,
    analyze_powershell,
    analyze_rpc,
    analyze_vnc,
    analyze_remote_access,
]
IDS = ["smb", "rdp", "winrm", "wmic", "powershell", "rpc", "vnc", "remote_access"]


@pytest.mark.parametrize("analyze", ANALYSES, ids=IDS)
def test_from_disk_equals_scapy_packets(tmp_path: Path, capture: Path, analyze) -> None:  # type: ignore[no-untyped-def]
    for path in _captures(tmp_path, capture):
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta)
        assert repr(from_disk) == repr(in_memory), path.name  # same path: the whole summary


@pytest.fixture()
def raw_on_windows_ports():  # type: ignore[no-untyped-def]
    """scapy's TCP bindings for 135, 139 and 445 (DCE/RPC, NetBIOS) left out:
    with them every record on those ports is one the lite parser cannot
    answer (it is dissected), so the port tests of the skips run only here."""
    from pcapper import lite

    saved = TCP.__dict__["payload_guess"]
    TCP.payload_guess = [(f, c) for f, c in saved if not set(f.values()) & {135, 139, 445}]
    lite.refresh_bindings()
    try:
        yield
    finally:
        TCP.payload_guess = saved
        lite.refresh_bindings()


@pytest.mark.parametrize("analyze", ANALYSES, ids=IDS)
def test_from_disk_equals_scapy_packets_without_smb_bindings(
    tmp_path: Path, capture: Path, raw_on_windows_ports, analyze  # type: ignore[no-untyped-def]
) -> None:
    on_445 = [r.lite_l4() for r in pcap_cache.iter_packets(capture, show_status=False, lite=True)]
    assert any(l4 not in (None, UNSUPPORTED) and 445 in l4[1:3] and l4[5] >= 0 for l4 in on_445)
    from_disk = analyze(capture, show_status=False)
    packets, meta = pcap_cache.load_packets(capture, show_status=False)
    utils.clear_analysis_memo()
    in_memory = analyze(capture, show_status=False, packets=packets, meta=meta)
    assert repr(from_disk) == repr(in_memory)


def test_the_edge_capture_finds_every_protocol(capture: Path) -> None:
    """The comparisons above are not between two empty summaries."""
    assert analyze_smb(capture, show_status=False).smb_packets >= 5
    summary = analyze_rdp(capture, show_status=False)
    # A cookie within the 128-byte prefix (also one in the padding) counts.
    assert set(summary.client_names) == {"alice", "bob", "dave", "eve", "frank"}
    assert analyze_winrm(capture, show_status=False).winrm_packets >= 4
    assert analyze_wmic(capture, show_status=False).wmic_packets >= 3
    assert analyze_powershell(capture, show_status=False).powershell_packets >= 3
    assert analyze_rpc(capture, show_status=False).rpc_packets >= 5
    summary = analyze_vnc(capture, show_status=False)
    reverse = {(conv.client_port, conv.server_port) for conv in summary.conversations if conv.reverse}
    assert summary.total_sessions == 5 and reverse == {(5500, 50000), (6000, 3000)}
    summary = analyze_remote_access(capture, show_status=False)
    assert summary.sessions and [p.severity for p in summary.pivots] == ["critical"]


def test_the_edge_capture_reaches_every_path(capture: Path) -> None:
    kinds = set()
    for record in pcap_cache.iter_packets(capture, show_status=False, lite=True):
        l4 = record.lite_l4()
        if l4 is UNSUPPORTED:
            kinds.add("unsupported")
        elif l4 is None:
            kinds.add("no-l4")
        elif l4[5] < 0:
            kinds.add("app-layer")
        elif len(record.original) > l4[6]:
            kinds.add("raw+padding" if l4[6] > l4[5] else "empty+padding")
        else:
            kinds.add("raw" if l4[6] > l4[5] else "empty")
    assert {"unsupported", "no-l4", "app-layer", "raw", "raw+padding", "empty+padding"} <= kinds


def test_tcp_flags_from_the_bytes_are_scapys(tmp_path: Path) -> None:
    """VNC and remote-access read the TCP flags from the record (``l4[4]``):
    the value is the int scapy's flags field gives, for all 512 values."""
    path = tmp_path / "flags.pcap"
    wrpcap(str(path), [_ETH / IP(src=A, dst=B) / TCP(sport=1000, dport=2000, flags=value) for value in range(512)])
    records = list(pcap_cache.iter_packets(path, show_status=False, lite=True))
    assert len(records) == 512
    for value, record in enumerate(records):
        l4 = record.lite_l4()
        tcp = record.materialize()[TCP]
        assert l4[4] == value == int(tcp.flags) == utils.tcp_flags_int(tcp.flags)
        assert l4[4] == int(getattr(tcp, "flags", 0) or 0)  # vnc's reading


# --- each lite skip drops only what the scapy path drops -------------------------


def _scapy_payload(pkt) -> bytes:  # type: ignore[no-untyped-def]
    """``bytes(pkt[Raw])``, else ``bytes(transport.payload)``: the payload the
    RDP, WMIC and PowerShell loops read."""
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw])
    layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    return bytes(layer.payload) if layer is not None else b""


def _rdp_kept(pkt) -> bool:  # type: ignore[no-untyped-def]
    is_udp, is_tcp = pkt.haslayer(UDP), pkt.haslayer(TCP)
    if not (is_tcp or is_udp):
        return False
    layer = pkt[TCP] if is_tcp else pkt[UDP]
    sport, dport = int(layer.sport), int(layer.dport)
    ports = rdp.RDP_UDP_PORTS if is_udp else rdp.RDP_TCP_PORTS
    prefix = _scapy_payload(pkt)[:128]
    return bool(
        dport in ports
        or (sport in ports and dport >= rdp._EPHEMERAL_MIN)
        or (prefix and (b"Cookie: mstshash=" in prefix or b"RDPUDP" in prefix))
    )


def _winrm_kept(pkt) -> bool:  # type: ignore[no-untyped-def]
    if not pkt.haslayer(TCP):
        return False
    tcp = pkt[TCP]
    sport, dport = int(tcp.sport), int(tcp.dport)
    payload = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    length = utils.tcp_segment_length(tcp, ip_layer)
    payload = payload[:length] if length is not None else bytes(tcp.payload)
    text = payload[:64].decode("latin-1", errors="ignore")
    return bool(
        dport in winrm.WINRM_PORTS
        or (sport in winrm.WINRM_PORTS and dport >= winrm._EPHEMERAL_MIN)
        or (text and winrm.WSMAN_RE.search(text))
    )


def _wmic_kept(pkt) -> bool:  # type: ignore[no-untyped-def]
    if not pkt.haslayer(TCP):
        return False
    payload = _scapy_payload(pkt)
    strings = utils.extract_ascii_strings(payload) + wmic._extract_utf16le_strings(payload)
    return any(wmic.WMI_HINT_RE.search(value) for value in strings)


def _powershell_score(pkt) -> int:  # type: ignore[no-untyped-def]
    if not pkt.haslayer(TCP):
        return 0
    tcp = pkt[TCP]
    payload = _scapy_payload(pkt)
    strings = utils.extract_ascii_strings(payload) + powershell._extract_utf16le_strings(payload)
    if not strings:
        return 0
    score = 2 if (int(tcp.sport) in powershell.POWERSHELL_PORTS or int(tcp.dport) in powershell.POWERSHELL_PORTS) else 0
    score += 1 if any(powershell.PS_WINRM_RE.search(v) for v in strings) else 0
    score += 2 if any(powershell.POWERSHELL_HINT_RE.search(v) for v in strings) else 0
    score += 1 if any(powershell.PS_COMMAND_RE.search(v) for v in strings) else 0
    score += 1 if any(powershell._SUSPICIOUS_ANY.search(v) for v in strings) else 0
    return score


def _rpc_kept(pkt) -> bool:  # type: ignore[no-untyped-def]
    layer = pkt.getlayer(TCP) if pkt.haslayer(TCP) else pkt.getlayer(UDP)
    if layer is None:
        return False
    return bool(rpc._find_rpc_pdu(bytes(layer.payload))[0])


def test_lite_skips_drop_only_what_scapy_drops(tmp_path: Path, capture: Path) -> None:
    """Record for record: a record a lite test skips is one the scapy path
    drops without a trace (the in-memory comparison checks the rest)."""
    skipped = dict.fromkeys(("rdp", "winrm", "wmic", "powershell", "rpc"), 0)
    for path in _captures(tmp_path, capture):
        for index, record in enumerate(pcap_cache.iter_packets(path, show_status=False, lite=True), start=1):
            pkt = record.materialize()
            if rdp._lite_not_rdp(record, None, index, None):
                skipped["rdp"] += 1
                assert not _rdp_kept(pkt), (path.name, index)
            if winrm._lite_not_winrm(record):
                skipped["winrm"] += 1
                assert not _winrm_kept(pkt), (path.name, index)
            if wmic._lite_not_wmic(record):
                skipped["wmic"] += 1
                assert not _wmic_kept(pkt), (path.name, index)
            if powershell._lite_not_powershell(record):
                skipped["powershell"] += 1
                assert _powershell_score(pkt) < 2, (path.name, index)
            if rpc._lite_not_rpc(record):
                skipped["rpc"] += 1
                assert not _rpc_kept(pkt), (path.name, index)
    assert all(skipped.values()), skipped


def test_rdp_decrypted_payloads_are_never_skipped(capture: Path) -> None:
    """A record with a decrypted payload handed in goes the scapy way."""
    records = list(pcap_cache.iter_packets(capture, show_status=False, lite=True))
    plain = [
        i for i, r in enumerate(records, start=1)
        if r.lite_l4() not in (None, UNSUPPORTED) and rdp._lite_not_rdp(r, None, i, None)
    ]
    assert plain
    decrypted = {plain[0]: b"username=mallory domain=corp"}
    assert not rdp._lite_not_rdp(records[plain[0] - 1], None, plain[0], decrypted)
    from_disk = analyze_rdp(capture, show_status=False, decrypted_payloads=decrypted)
    packets, meta = pcap_cache.load_packets(capture, show_status=False)
    utils.clear_analysis_memo()
    in_memory = analyze_rdp(capture, show_status=False, packets=packets, meta=meta, decrypted_payloads=decrypted)
    assert repr(from_disk) == repr(in_memory)
    assert from_disk.decrypted_username["mallory"] == 1


# --- the hint words the WMIC and PowerShell skips look for -----------------------


def _alternatives(pattern: re.Pattern) -> list[str]:  # type: ignore[type-arg]
    """The top-level alternatives of a ``(a|b|c)`` pattern as the literal text
    each must match, lower-cased: a ``\\b`` or ``\\s*`` (which only sit
    between words) becomes a space, an escaped character itself; anything
    else that is not a plain literal fails the test."""
    body = pattern.pattern
    assert body.startswith("(") and body.endswith(")") and body.count("(") == 1, body
    out = []
    for alt in body[1:-1].split("|"):
        chars, i = [], 0
        while i < len(alt):
            if alt.startswith((r"\b", r"\s*"), i):
                chars.append(" ")
                i += 2 if alt.startswith(r"\b", i) else 3
            elif alt[i] == "\\":
                assert alt[i + 1] in ".\\/", alt  # an escaped literal
                chars.append(alt[i + 1])
                i += 2
            else:
                assert alt[i] not in ".[](){}*+?^$|", alt  # no wildcard
                chars.append(alt[i])
                i += 1
        out.append("".join(chars).lower())
    return out


@pytest.mark.parametrize(
    ("patterns", "words"),
    [
        ([wmic.WMI_HINT_RE], wmic._WMI_HINT_WORDS),
        ([powershell.POWERSHELL_HINT_RE, powershell.PS_WINRM_RE], powershell._PS_SCORE_WORDS),
    ],
    ids=["wmic", "powershell"],
)
def test_every_hint_alternative_holds_a_word(patterns, words) -> None:  # type: ignore[no-untyped-def]
    for pattern in patterns:
        for text in _alternatives(pattern):
            assert any(word.decode() in part for word in words for part in text.split(" ")), text


def test_powershell_command_shape_implies_the_hint() -> None:
    """PS_COMMAND_RE matches only where POWERSHELL_HINT_RE does, so off the
    PowerShell ports a score of 2 needs the hint, or WinRM and suspicious."""
    assert powershell.PS_COMMAND_RE.pattern.startswith(r"\b(?:powershell|pwsh)\b")
    assert {"powershell", "pwsh"} <= set(_alternatives(powershell.POWERSHELL_HINT_RE))


@pytest.mark.parametrize(
    ("predicate", "samples"),
    [
        (wmic._lite_not_wmic, ["wmic", "WMIExec", "Win32_Process", "CIM_DataFile", "ROOT\\CIMv2", "root\\subscription", "IWbemServices", "wbem"]),
        (powershell._lite_not_powershell, ["PowerShell", "pwsh", "System.Management.Automation", "Windows  Power Shell", "WinRM", "WSMan", "wsmv", "schemas.microsoft.com/powershell", "Schemas.XmlSoap.org/ws/"]),
    ],
    ids=["wmic", "powershell"],
)
def test_hint_payloads_are_never_skipped(tmp_path: Path, predicate, samples) -> None:  # type: ignore[no-untyped-def]
    """Each alternative, as ASCII and as UTF-16LE at even and odd offsets,
    keeps the record."""
    frames = []
    for sample in samples:
        for payload in (sample.encode(), _utf16(sample), b"\x01" + _utf16(sample), b"<" + sample.upper().encode() + b">"):
            frames.append(_ETH / IP(src=A, dst=B) / TCP(sport=40000, dport=40001) / Raw(b"x " + payload + b" y"))
    path = tmp_path / "hints.pcap"
    wrpcap(str(path), frames)
    records = list(pcap_cache.iter_packets(path, show_status=False, lite=True))
    assert len(records) == len(frames)
    assert not any(predicate(record) for record in records)
