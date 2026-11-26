"""Credentials the protocol analyzers recover, in ``--creds`` terms.

``--creds`` reads every packet itself, but a credential is often only visible
to the analyzer that understands its protocol's state (a SOCKS handshake, a
SIP dialogue, an LDAP search result) or its layer (OSPF and VRRP ride on IP,
IS-IS and 802.11 below it). When ``--creds`` reported nothing while another
report showed a cleartext password, the two disagreed about the same capture.

Two kinds of source live here:

* :data:`PACKET_SOURCES` -- stateless readers that ``--creds`` runs on each
  TCP/UDP payload, each returning ``(kind, user, secret, evidence)`` tuples;
* :data:`ANALYZER_SOURCES` -- analyzers that run once per capture, only when a
  cheap gate fired on one of its packets, and whose results become hits.

A hit whose evidence says ``offline-guessable`` is a challenge/response (or
equivalent) that exposes the account to offline guessing; it carries the
account, never a ready-to-crack string.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from . import bacnet, melsec, mms, mqtt, s7

Cred = tuple[str, Optional[str], Optional[str], str]

OFFLINE_GUESSABLE = "offline-guessable"


@dataclass(frozen=True)
class SourcedHit:
    protocol: str
    kind: str
    user: Optional[str]
    secret: Optional[str]
    evidence: str
    src_ip: str = "-"
    dst_ip: str = "-"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packet_number: int = 0
    ts: Optional[float] = None


# --- stateless per-payload readers ---------------------------------------------
_PS_SECURESTRING_RE = re.compile(r"(?i)ConvertTo-SecureString\b([^\r\n;|]{0,300})")
_PS_QUOTED_RE = re.compile(r"""(['"])([^'"\r\n]{1,128})\1""")
_PS_CREDENTIAL_USER_RE = re.compile(r"""(?i)PSCredential\s*\(\s*(['"])([^'"\r\n]{1,128})\1""")


def powershell_securestring(text: str, lowered: str) -> list[Cred]:
    """``ConvertTo-SecureString '<password>' -AsPlainText``: a password typed
    into a command line or script that crossed the wire in the clear."""
    if "securestring" not in lowered:
        return []
    user_match = _PS_CREDENTIAL_USER_RE.search(text)
    user = user_match.group(2) if user_match else None
    found: list[Cred] = []
    for match in _PS_SECURESTRING_RE.finditer(text):
        statement = match.group(1)
        if "-asplaintext" not in statement.lower():
            continue
        quoted = _PS_QUOTED_RE.search(statement)
        if quoted:
            found.append(
                (
                    "PowerShell SecureString Plaintext",
                    user,
                    quoted.group(2),
                    f"ConvertTo-SecureString{statement[:120]}",
                )
            )
    return found


# Phone provisioning files put the SIP account's password in the clear.
_PROVISIONING_PASS_RE = re.compile(
    r"""(?im)(?:\breg\.\d+\.auth\.password\s*=\s*"([^"\r\n]{1,128})"|"""
    r"""\baccount\.\d+\.password\s*=\s*([^\s"<]{1,128})|"""
    r"""<Password_\d+_[^>]*>([^<\r\n]{1,128})</Password_\d+_>|"""
    r"""\buser_pass\d*\s*[$!&]?\s*[:=]\s*"?([^\s"<]{1,128}))"""
)
_PROVISIONING_USER_RE = re.compile(
    r"""(?im)(?:\breg\.\d+\.auth\.userId\s*=\s*"([^"\r\n]{1,128})"|"""
    r"""\baccount\.\d+\.(?:auth_name|user_name)\s*=\s*([^\s"<]{1,128})|"""
    r"""<(?:Auth_ID|User_ID)_\d+_[^>]*>([^<\r\n]{1,128})</(?:Auth_ID|User_ID)_\d+_>|"""
    r"""\buser_name\d*\s*[$!&]?\s*[:=]\s*"?([^\s"<]{1,128}))"""
)
_PROVISIONING_MARKERS = ("auth.password", ".password", "password_", "user_pass")


def provisioning_passwords(text: str, lowered: str) -> list[Cred]:
    if not any(marker in lowered for marker in _PROVISIONING_MARKERS):
        return []
    users = [next(g for g in m.groups() if g) for m in _PROVISIONING_USER_RE.finditer(text)]
    found: list[Cred] = []
    for index, match in enumerate(_PROVISIONING_PASS_RE.finditer(text)):
        secret = next(g for g in match.groups() if g)
        user = users[index] if index < len(users) else (users[0] if users else None)
        found.append(("VoIP Provisioning Password", user, secret, match.group(0).strip()[:160]))
    return found


_RDP_COOKIE_RE = re.compile(r"Cookie: mstshash=([^\r\n\s]{1,64})")


def rdp_cookie(text: str, lowered: str) -> list[Cred]:
    """The account a Remote Desktop client typed, in its X.224 Connection
    Request cookie (older clients cut it to 9 characters)."""
    if "mstshash=" not in text:
        return []
    return [
        ("RDP Connection Cookie User", match.group(1), None, f"X.224 Connection Request {match.group(0)}")
        for match in _RDP_COOKIE_RE.finditer(text)
    ]


_AWS_KEY_ID_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
_AWS_SECRET_RE = re.compile(r"(?i)aws_secret_access_key[\"'\s]*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})")


def aws_keys(text: str, lowered: str) -> list[Cred]:
    if "AKIA" not in text and "ASIA" not in text:
        return []
    secret_match = _AWS_SECRET_RE.search(text)
    secret = secret_match.group(1) if secret_match else None
    return [
        ("AWS Access Key", match.group(1), secret, "AWS access key id" + (" with its secret key" if secret else ""))
        for match in _AWS_KEY_ID_RE.finditer(text)
    ]


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


def _jwt_subject(token: str) -> Optional[str]:
    try:
        body = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception:  # noqa: BLE001 - not a JSON body: no subject
        return None
    if not isinstance(claims, dict):
        return None
    for claim in ("upn", "preferred_username", "unique_name", "email", "sub"):
        value = claims.get(claim)
        if isinstance(value, str) and value:
            return value[:128]
    return None


def json_web_tokens(text: str, lowered: str) -> list[Cred]:
    """Signed tokens in bodies, URLs and responses (an ``access_token`` the
    server hands out is as good as the password while it lives). Tokens in an
    ``Authorization: Bearer`` header are reported by the HTTP reader."""
    if "eyJ" not in text:
        return []
    found: list[Cred] = []
    for match in _JWT_RE.finditer(text):
        if text[max(0, match.start() - 7) : match.start()].lower().endswith("bearer "):
            continue
        token = match.group(0)
        found.append(("JSON Web Token", _jwt_subject(token), token, "signed JWT in cleartext traffic"))
    return found


_HASH_DUMP_RE = re.compile(r"(?m)^([^:\s]{1,64}):(\d{1,10}):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")


def hash_dump_lines(text: str, lowered: str) -> list[Cred]:
    """``account:RID:LM:NT:::`` lines (pwdump/secretsdump output) crossing the
    wire: a credential dump in transit. Reported by account."""
    if ":::" not in text:
        return []
    return [
        (
            "Password Hash Dump Line",
            match.group(1),
            None,
            f"LM:NT hash pair for RID {match.group(2)} in cleartext traffic (credential dump in transit?)",
        )
        for match in _HASH_DUMP_RE.finditer(text)
    ]


TEXT_READERS: tuple[Callable[[str, str], list[Cred]], ...] = (
    powershell_securestring,
    provisioning_passwords,
    rdp_cookie,
    aws_keys,
    json_web_tokens,
    hash_dump_lines,
)


def text_credentials(text: str) -> list[Cred]:
    """Every text reader's tuples for one decoded payload."""
    found: list[Cred] = []
    lowered = text.lower()
    for reader in TEXT_READERS:
        found.extend(reader(text, lowered))
    return found


_IKE_ID_TYPES = {2: "FQDN", 3: "USER_FQDN", 11: "KEY_ID"}


def ike_aggressive_identity(payload: bytes, sport: Optional[int], dport: Optional[int]) -> list[Cred]:
    """IKEv1 Aggressive Mode sends the peer identity (often a VPN group name)
    in the clear, and the responder's HASH_R lets the pre-shared key be
    guessed offline."""
    data = payload
    if 4500 in (sport, dport):
        if data[:4] != b"\x00\x00\x00\x00":  # non-ESP marker
            return []
        data = data[4:]
    elif 500 not in (sport, dport):
        return []
    if len(data) < 28 or data[17] >> 4 != 1 or data[18] != 4 or data[19] & 0x01:
        return []
    next_payload, pos, identity, responder = data[16], 28, None, False
    for _ in range(32):
        if not next_payload or pos + 4 > len(data):
            break
        current, next_payload = next_payload, data[pos]
        size = int.from_bytes(data[pos + 2 : pos + 4], "big")
        if size < 4 or pos + size > len(data):
            break
        body = data[pos + 4 : pos + size]
        if current == 5 and len(body) > 4:  # Identification
            id_type = body[0]
            if id_type == 1 and len(body) >= 8:
                identity = ".".join(str(b) for b in body[4:8])
            elif id_type in _IKE_ID_TYPES:
                identity = body[4:].decode("latin-1", errors="replace")
        elif current == 8:  # Hash: only the responder's message carries one
            responder = True
        pos += size
    if not identity:
        return []
    role = "responder" if responder else "initiator"
    return [
        (
            "IKEv1 Aggressive Mode Identity",
            identity,
            None,
            f"aggressive-mode {role} message: the identity travels in the clear and "
            f"the pre-shared key is {OFFLINE_GUESSABLE} from the responder's HASH_R",
        )
    ]


# (protocol label, reader) run on every TCP/UDP payload; each checks its own
# framing first, so a payload that is not theirs costs a byte comparison.
PAYLOAD_READERS: tuple[tuple[str, Callable[[bytes], list[Cred]]], ...] = (
    (mqtt.PROTOCOL_NAME, mqtt.credentials),
    (bacnet.PROTOCOL_NAME, bacnet.credentials),
    ("ACSE (MMS/ICCP)", mms.credentials),
    ("S7", s7.credentials),
    ("MELSEC", melsec.credentials),
)


# --- analyzers run once per capture ----------------------------------------------
@dataclass(frozen=True)
class AnalyzerSource:
    name: str
    # Fired by one TCP/UDP payload (sport, dport, payload) ...
    payload_gate: Optional[Callable[[Optional[int], Optional[int], bytes], bool]]
    # ... or by one frame that carries no TCP/UDP (raw bytes, linktype).
    frame_gate: Optional[Callable[[bytes, int], bool]]
    collect: Callable[[Path, Optional[list], object], Iterable[SourcedHit]]


def _either_port(sport: Optional[int], dport: Optional[int], ports: set[int]) -> bool:
    return sport in ports or dport in ports


def _socks_gate(sport: Optional[int], dport: Optional[int], payload: bytes) -> bool:
    # RFC 1929 username/password request: 0x01, ULEN, UNAME, PLEN, PASSWD.
    if payload[:1] != b"\x01" or not 5 <= len(payload) <= 513:
        return False
    ulen = payload[1]
    return 3 + ulen <= len(payload) and len(payload) == 3 + ulen + payload[2 + ulen]


def _socks_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .socks import analyze_socks

    summary = analyze_socks(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for item in summary.credential_items or []:
        proxy = str(item.get("proxy", "-"))
        host, _sep, port = proxy.rpartition(":")
        yield SourcedHit(
            protocol="SOCKS",
            kind="SOCKS5 Username/Password",
            user=str(item.get("user") or "") or None,
            secret=str(item.get("secret") or "") or None,
            evidence=f"proxy {proxy}: authentication {item.get('result', '-')}",
            src_ip=str(item.get("client") or "-"),
            dst_ip=host or proxy,
            dst_port=int(port) if port.isdigit() else None,
            ts=item.get("first_seen"),  # type: ignore[arg-type]
        )


_VOIP_PORTS = {5060, 5061, 4569, 3478, 3479}


def _voip_gate(sport: Optional[int], dport: Optional[int], payload: bytes) -> bool:
    return _either_port(sport, dport, _VOIP_PORTS) or b"SIP/2.0" in payload[:256]


def _voip_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .voip import analyze_voip

    summary = analyze_voip(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for cred in summary.credentials or []:
        protocol, context = str(cred.protocol), str(cred.context)
        user = str(cred.username or "") or None
        realm = f" realm {cred.realm}" if cred.realm else ""
        if protocol == "IAX2" and "plaintext" in context.lower():
            kind, secret, evidence = "IAX2 Plaintext Password", str(cred.secret or "") or None, f"IAX2 {context}"
        elif protocol == "SIP":
            kind, secret = "SIP Digest Challenge Response", None
            evidence = f"SIP {context}{realm}: {OFFLINE_GUESSABLE} digest response (the password itself is not sent)"
        elif protocol == "IAX2":
            kind, secret = "IAX2 MD5 Challenge Response", None
            evidence = f"IAX2 {context}: {OFFLINE_GUESSABLE} MD5 challenge-response"
        else:
            kind, secret = f"{protocol} Long-Term Credential Challenge Response", None
            evidence = f"{protocol} {context}{realm}: {OFFLINE_GUESSABLE} message integrity"
        yield SourcedHit(protocol, kind, user, secret, evidence, src_ip=cred.src_ip, dst_ip=cred.dst_ip, ts=cred.ts)
    for media in summary.media or []:
        for key in media.cleartext_keys:
            yield SourcedHit(
                protocol="SIP/SDP",
                kind="SRTP Master Key",
                user=None,
                secret=str(key),
                evidence=(
                    f"a=crypto inline key for {media.media_type} {media.address}:{media.port} "
                    "in cleartext SDP: the call's media can be decrypted"
                ),
                src_ip=str(media.owner_ip or "-"),
                dst_ip=str(media.address or "-"),
                dst_port=int(media.port) if media.port else None,
            )


_ROUTING_UDP_PORTS = {520, 1985, 2029}
_ROUTING_IP_PROTOCOLS = {89, 112}  # OSPF, VRRP


def _routing_gate(sport: Optional[int], dport: Optional[int], payload: bytes) -> bool:
    return _either_port(sport, dport, _ROUTING_UDP_PORTS)


def _routing_frame_gate(raw: bytes, linktype: int) -> bool:
    proto = ip_protocol(raw, linktype)
    return proto in _ROUTING_IP_PROTOCOLS or is_isis(raw, linktype)


def _routing_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .routing import analyze_routing

    summary = analyze_routing(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for row in getattr(summary, "cleartext_auth", []) or []:
        protocol = str(row.get("protocol", "Routing"))
        yield SourcedHit(
            protocol=protocol,
            kind=f"{protocol} Cleartext Authentication",
            user=None,
            secret=str(row.get("password") or "") or None,
            evidence=f"{protocol} cleartext authentication key (every neighbour on the segment reads it)",
            src_ip=str(row.get("src") or "-"),
            dst_ip=str(row.get("dst") or "-"),
            ts=row.get("ts"),  # type: ignore[arg-type]
        )


_LDAP_PORTS = {389, 3268}


def _ldap_gate(sport: Optional[int], dport: Optional[int], payload: bytes) -> bool:
    return payload[:1] == b"\x30" and _either_port(sport, dport, _LDAP_PORTS)


def _ldap_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .ldap import analyze_ldap

    summary = analyze_ldap(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for row in getattr(summary, "secret_records", []) or []:
        op = str(row.get("op", ""))
        if op == "simple bind":
            continue  # --creds reads simple binds itself
        if op == "SASL PLAIN bind":
            kind, user = "LDAP SASL PLAIN Bind", str(row.get("dn") or "") or None
            evidence = "SASL PLAIN bind: identity and password in the clear"
        elif op == "SearchResultEntry":
            kind, user = "LDAP Password Attribute Returned", str(row.get("dn") or "") or None
            evidence = f"{row.get('attr')} returned in a search result for {row.get('dn')}"
        else:
            kind, user = "LDAP Password Attribute Written", str(row.get("dn") or "") or None
            evidence = f"{op} sets {row.get('attr')} on {row.get('dn')}"
        port = row.get("port") if isinstance(row.get("port"), int) else None
        # A search result flows server -> client: the LDAP port is the source.
        returned = op == "SearchResultEntry"
        yield SourcedHit(
            protocol="LDAP",
            kind=kind,
            user=user,
            secret=str(row.get("value") or "") or None,
            evidence=evidence,
            src_ip=str(row.get("src") or "-"),
            dst_ip=str(row.get("dst") or "-"),
            src_port=port if returned else None,  # type: ignore[arg-type]
            dst_port=None if returned else port,  # type: ignore[arg-type]
            ts=row.get("ts"),  # type: ignore[arg-type]
        )


def _snmpv3_gate(sport: Optional[int], dport: Optional[int], payload: bytes) -> bool:
    return payload[:1] == b"\x30" and b"\x02\x01\x03" in payload[:8] and _either_port(sport, dport, {161, 162})


def _snmpv3_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .snmp import analyze_snmp

    summary = analyze_snmp(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for name in sorted(getattr(summary, "usm_users", {}) or {}):
        if name:
            yield SourcedHit(
                protocol="SNMP",
                kind="SNMPv3 USM User Name",
                user=str(name),
                secret=None,
                evidence="SNMPv3 user name sent in the clear (the authentication key is not)",
            )


def _kerberos_gate(sport: Optional[int], dport: Optional[int], payload: bytes) -> bool:
    return _either_port(sport, dport, {88})


def _kerberos_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .kerberos import analyze_kerberos

    summary = analyze_kerberos(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for row in getattr(summary, "asrep_roastable", []) or []:
        yield SourcedHit(
            protocol="Kerberos",
            kind="Kerberos AS-REP Without Pre-Authentication",
            user=str(row.get("account") or "") or None,
            secret=None,
            evidence=(
                f"the KDC answered an AS-REQ that carried no pre-authentication: the AS-REP is "
                f"{OFFLINE_GUESSABLE} against the account's password"
            ),
            src_ip=str(row.get("client") or "-"),
            dst_ip=str(row.get("server") or "-"),
            dst_port=88,
            ts=row.get("ts"),  # type: ignore[arg-type]
        )


def _vnc_gate(sport: Optional[int], dport: Optional[int], payload: bytes) -> bool:
    return payload.startswith(b"RFB 00")


def _vnc_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .vnc import analyze_vnc

    summary = analyze_vnc(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for conv in getattr(summary, "conversations", []) or []:
        if "VNC Authentication" not in str(getattr(conv, "security", "") or ""):
            continue
        yield SourcedHit(
            protocol="VNC",
            kind="VNC Authentication Challenge Response",
            user=None,
            secret=None,
            evidence=f"VNC password authentication: the DES challenge-response is {OFFLINE_GUESSABLE}",
            src_ip=conv.client_ip,
            dst_ip=conv.server_ip,
            src_port=conv.client_port,
            dst_port=conv.server_port,
            ts=conv.first_seen,
        )


_WLAN_LINKTYPES = {105, 119, 127, 163, 192}


def _wlan_frame_gate(raw: bytes, linktype: int) -> bool:
    return linktype in _WLAN_LINKTYPES and b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in raw


def _wlan_collect(path: Path, packets: Optional[list], meta: object) -> Iterable[SourcedHit]:
    from .wlan import analyze_wlan

    summary = analyze_wlan(path, show_status=False, packets=packets, meta=meta)  # type: ignore[arg-type]
    for row in getattr(summary, "wpa_handshakes", []) or []:
        yield SourcedHit(
            protocol="WLAN",
            kind="WPA Handshake",
            user=None,
            secret=None,
            evidence=(
                f"EAPOL 4-way handshake ({row.get('eapol_frames', '?')} frames) between AP "
                f"{row.get('bssid', '-')} and station {row.get('station', '-')}: the network's "
                f"passphrase is {OFFLINE_GUESSABLE}"
            ),
            src_ip=str(row.get("station") or "-"),
            dst_ip=str(row.get("bssid") or "-"),
        )


ANALYZER_SOURCES: tuple[AnalyzerSource, ...] = (
    AnalyzerSource("SOCKS", _socks_gate, None, _socks_collect),
    AnalyzerSource("VoIP", _voip_gate, None, _voip_collect),
    AnalyzerSource("Routing", _routing_gate, _routing_frame_gate, _routing_collect),
    AnalyzerSource("LDAP", _ldap_gate, None, _ldap_collect),
    AnalyzerSource("SNMPv3", _snmpv3_gate, None, _snmpv3_collect),
    AnalyzerSource("Kerberos", _kerberos_gate, None, _kerberos_collect),
    AnalyzerSource("VNC", _vnc_gate, None, _vnc_collect),
    AnalyzerSource("WLAN", None, _wlan_frame_gate, _wlan_collect),
)


# --- frames -----------------------------------------------------------------------
_RAW_IP_LINKTYPES = {12, 14, 101, 228, 229}


def _l3_start(raw: bytes, linktype: int) -> tuple[int, int]:
    """(ethertype, offset of the network header), or (-1, -1)."""
    if linktype == 1:
        if len(raw) < 14:
            return -1, -1
        pos = 12
        ethertype = int.from_bytes(raw[pos : pos + 2], "big")
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(raw) >= pos + 6:
            pos += 4
            ethertype = int.from_bytes(raw[pos : pos + 2], "big")
        return ethertype, pos + 2
    if linktype == 113 and len(raw) >= 16:  # Linux cooked v1
        return int.from_bytes(raw[14:16], "big"), 16
    if linktype == 276 and len(raw) >= 20:  # Linux cooked v2
        return int.from_bytes(raw[0:2], "big"), 20
    if linktype in _RAW_IP_LINKTYPES and raw:
        return (0x0800 if raw[0] >> 4 == 4 else 0x86DD), 0
    return -1, -1


def ip_protocol(raw: bytes, linktype: int) -> int:
    """The IPv4 protocol / IPv6 next-header number of a frame, or -1."""
    ethertype, pos = _l3_start(raw, linktype)
    if ethertype == 0x0800 and len(raw) >= pos + 20:
        return raw[pos + 9]
    if ethertype == 0x86DD and len(raw) >= pos + 40:
        return raw[pos + 6]
    return -1


def is_isis(raw: bytes, linktype: int) -> bool:
    """An 802.3 frame with the OSI LLC SAPs (0xFE) IS-IS uses."""
    if linktype != 1 or len(raw) < 17:
        return False
    return int.from_bytes(raw[12:14], "big") <= 1500 and raw[14] == 0xFE and raw[15] == 0xFE
