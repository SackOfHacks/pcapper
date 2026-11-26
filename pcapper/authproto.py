"""Network-access authentication protocols, read for ``--creds``.

RADIUS, TACACS+, BFD, PPP (PAP/CHAP over PPPoE or a PPP link) and EAP (over
PPP, wired 802.1X or 802.11) carry logins that no other analyzer reads. Each
reader returns ``--creds`` tuples ``(kind, user, secret, evidence)``:

* a password sent in the clear (PPP PAP, unencrypted TACACS+, BFD simple
  password) is reported with the password;
* a challenge/response or a hidden password (RADIUS User-Password, CHAP,
  EAP-MD5, MS-CHAPv2) is reported by account only, with ``offline-guessable``
  in the evidence -- the exchange exposes the account to guessing, not the
  password itself.
"""

from __future__ import annotations

from typing import Optional

Cred = tuple[str, Optional[str], Optional[str], str]

OFFLINE_GUESSABLE = "offline-guessable"

RADIUS_PORTS = {1812, 1645}
TACACS_PORT = 49
BFD_PORTS = {3784, 4784}

_PPP_PAP = 0xC023
_PPP_CHAP = 0xC223
_PPP_EAP = 0xC227
_ETHERTYPE_PPPOE_SESSION = 0x8864
_ETHERTYPE_EAPOL = 0x888E
_ETHERTYPE_VLAN = {0x8100, 0x88A8, 0x9100}
_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
_WLAN_LINKTYPES = {105, 119, 127, 163, 192}
_PPP_LINKTYPES = {9, 50}

_EAP_TYPES = {4: "EAP-MD5", 6: "EAP-GTC", 13: "EAP-TLS", 21: "EAP-TTLS", 25: "PEAP", 26: "EAP-MSCHAPv2", 43: "EAP-FAST"}


def _text(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    value = raw.decode("utf-8", errors="replace").strip("\x00")
    return value if value and value.isprintable() else None


# --- EAP ---------------------------------------------------------------------
def eap_credentials(packet: bytes, carrier: str) -> list[Cred]:
    """One EAP packet: the identity a peer announces, and the challenge/response
    methods that expose it to offline guessing."""
    if len(packet) < 5 or packet[0] != 2:  # Responses only: the peer's side
        return []
    length = int.from_bytes(packet[2:4], "big")
    body = packet[5:length] if 5 <= length <= len(packet) else packet[5:]
    eap_type = packet[4]
    if eap_type == 1:
        identity = _text(body)
        if identity:
            return [("EAP Identity", identity, None, f"EAP-Response/Identity over {carrier} (sent in the clear)")]
    elif eap_type == 4 and body:  # MD5-Challenge response: size, value, name
        size = body[0]
        name = _text(body[1 + size :])
        return [
            (
                "EAP-MD5 Challenge Response",
                name,
                None,
                f"EAP-MD5 response over {carrier}: {OFFLINE_GUESSABLE} with the server's challenge",
            )
        ]
    elif eap_type == 26 and len(body) >= 5 and body[0] == 2:  # MS-CHAPv2 Response
        value_size = body[4]
        name = _text(body[5 + value_size :])
        return [
            (
                "EAP-MSCHAPv2 Challenge Response",
                name,
                None,
                f"MS-CHAPv2 response over {carrier}: {OFFLINE_GUESSABLE} with the server's challenge",
            )
        ]
    return []


# --- PPP ---------------------------------------------------------------------
def ppp_credentials(protocol: int, body: bytes, carrier: str) -> list[Cred]:
    if protocol == _PPP_PAP and len(body) >= 6 and body[0] == 1:  # Authenticate-Request
        user_len = body[4]
        user = body[5 : 5 + user_len]
        pos = 5 + user_len
        if pos < len(body):
            secret = body[pos + 1 : pos + 1 + body[pos]]
            return [("PPP PAP Password", _text(user), secret.decode("latin-1"), f"PAP Authenticate-Request over {carrier}")]
    elif protocol == _PPP_CHAP and len(body) >= 5 and body[0] == 2:  # Response
        size = body[4]
        name = _text(body[5 + size : int.from_bytes(body[2:4], "big")])
        method = "MS-CHAPv2" if size == 49 else "CHAP"
        return [
            (
                f"PPP {method} Challenge Response",
                name,
                None,
                f"{method} response over {carrier}: {OFFLINE_GUESSABLE} with the authenticator's challenge",
            )
        ]
    elif protocol == _PPP_EAP:
        return eap_credentials(body, carrier)
    return []


def _ppp_frame(data: bytes, carrier: str) -> list[Cred]:
    if data[:2] == b"\xff\x03":
        data = data[2:]
    if len(data) < 2:
        return []
    if data[0] & 0x01:  # protocol-field compression: one byte
        return ppp_credentials(data[0], data[1:], carrier)
    return ppp_credentials(int.from_bytes(data[:2], "big"), data[2:], carrier)


# --- frames below IP -----------------------------------------------------------
def _ethernet_payload(raw: bytes) -> tuple[int, bytes]:
    if len(raw) < 14:
        return -1, b""
    pos = 12
    ethertype = int.from_bytes(raw[pos : pos + 2], "big")
    while ethertype in _ETHERTYPE_VLAN and len(raw) >= pos + 6:
        pos += 4
        ethertype = int.from_bytes(raw[pos : pos + 2], "big")
    return ethertype, raw[pos + 2 :]


def frame_credentials(raw: bytes, linktype: int) -> list[Cred]:
    """Credentials in a frame that carries no IP: PPPoE sessions, wired
    802.1X, EAPOL inside 802.11 data frames, and PPP links."""
    if not raw:
        return []
    if linktype == 1:
        ethertype, body = _ethernet_payload(raw)
        if ethertype == _ETHERTYPE_PPPOE_SESSION and len(body) >= 8:
            length = int.from_bytes(body[4:6], "big")
            return _ppp_frame(body[6 : 6 + length], "PPPoE")
        if ethertype == _ETHERTYPE_EAPOL and len(body) >= 4 and body[1] == 0:
            return eap_credentials(body[4:], "802.1X (EAPOL)")
        return []
    if linktype in _WLAN_LINKTYPES:
        at = raw.find(_SNAP_EAPOL)
        if at >= 0:
            eapol = raw[at + len(_SNAP_EAPOL) :]
            if len(eapol) >= 4 and eapol[1] == 0:
                return eap_credentials(eapol[4:], "802.11 (EAPOL)")
        return []
    if linktype in _PPP_LINKTYPES:
        return _ppp_frame(raw, "PPP")
    return []


def frame_may_carry_credentials(raw: bytes, linktype: int) -> bool:
    """Cheap pre-test for :func:`frame_credentials`."""
    if linktype == 1:
        ethertype, _body = _ethernet_payload(raw)
        return ethertype in (_ETHERTYPE_PPPOE_SESSION, _ETHERTYPE_EAPOL)
    if linktype in _WLAN_LINKTYPES:
        return _SNAP_EAPOL in raw
    return linktype in _PPP_LINKTYPES


# --- RADIUS ------------------------------------------------------------------
def radius_credentials(payload: bytes) -> list[Cred]:
    """An Access-Request: the account, and how its password travels."""
    if len(payload) < 20 or payload[0] != 1:
        return []
    length = int.from_bytes(payload[2:4], "big")
    if length < 20 or length > len(payload):
        return []
    user: Optional[str] = None
    methods: list[str] = []
    eap_parts: list[bytes] = []
    pos = 20
    while pos + 2 <= length:
        attr, size = payload[pos], payload[pos + 1]
        if size < 2 or pos + size > length:
            break
        value = payload[pos + 2 : pos + size]
        if attr == 1:
            user = _text(value)
        elif attr == 2:
            methods.append("PAP")
        elif attr == 3:
            methods.append("CHAP")
        elif attr == 79:
            eap_parts.append(value)
        elif attr == 26 and len(value) >= 6 and value[:4] == b"\x00\x00\x01\x37" and value[4] == 25:
            methods.append("MS-CHAPv2")  # Microsoft VSA MS-CHAP2-Response
        pos += size
    found: list[Cred] = []
    if eap_parts:
        eap = b"".join(eap_parts)
        found.extend(eap_credentials(eap, "RADIUS"))
        if len(eap) >= 5 and eap[0] == 2 and eap[4] not in (1, 4, 26):
            methods.append(_EAP_TYPES.get(eap[4], f"EAP type {eap[4]}"))
    if user and "PAP" in methods:
        found.append(
            (
                "RADIUS PAP Access-Request",
                user,
                None,
                "User-Password hidden with the RADIUS shared secret: anyone holding the secret reads it",
            )
        )
    elif user and ("CHAP" in methods or "MS-CHAPv2" in methods):
        method = "MS-CHAPv2" if "MS-CHAPv2" in methods else "CHAP"
        found.append(
            (
                f"RADIUS {method} Challenge Response",
                user,
                None,
                f"{method} Access-Request: {OFFLINE_GUESSABLE} with the request's challenge",
            )
        )
    elif user and not found:
        found.append(("RADIUS Access-Request User", user, None, "User-Name in an Access-Request (sent in the clear)"))
    return found


# --- TACACS+ -----------------------------------------------------------------
class TacacsState:
    """What each TACACS+ session's server last asked for (GETUSER/GETPASS)."""

    def __init__(self) -> None:
        self.prompt: dict[tuple[bytes, str, str], int] = {}


def tacacs_credentials(payload: bytes, client: str, server: str, state: TacacsState) -> list[Cred]:
    """Authentication packets of a session sent without body obfuscation
    (TAC_PLUS_UNENCRYPTED_FLAG). Obfuscated bodies expose nothing."""
    if len(payload) < 12 or payload[0] >> 4 != 0xC or payload[1] != 1 or not payload[3] & 0x01:
        return []
    session = payload[4:8]
    length = int.from_bytes(payload[8:12], "big")
    body = payload[12 : 12 + length]
    seq = payload[2]
    key = (session, client, server)
    if seq == 1 and len(body) >= 8:  # START from the client
        authen_type = body[2]
        user_len, port_len, rem_len, data_len = body[4], body[5], body[6], body[7]
        pos = 8
        user = _text(body[pos : pos + user_len])
        pos += user_len + port_len + rem_len
        data = body[pos : pos + data_len]
        if authen_type == 2 and data:  # PAP: the password is the data field
            return [("TACACS+ PAP Password", user, data.decode("latin-1"), "unencrypted TACACS+ START (PAP)")]
        if user:
            return [("TACACS+ Login User", user, None, "unencrypted TACACS+ START")]
        return []
    if seq % 2 == 0 and len(body) >= 6:  # REPLY from the server: remember the prompt
        state.prompt[key] = body[0]
        return []
    if len(body) >= 5:  # CONTINUE from the client
        user_msg_len = int.from_bytes(body[0:2], "big")
        value = body[5 : 5 + user_msg_len]
        prompt = state.prompt.get(key)
        if prompt == 5 and value:  # GETPASS
            return [("TACACS+ Login Password", None, value.decode("latin-1"), "unencrypted TACACS+ CONTINUE (password prompt)")]
        if prompt == 4 and value:  # GETUSER
            return [("TACACS+ Login User", _text(value), None, "unencrypted TACACS+ CONTINUE (username prompt)")]
    return []


# --- BFD -----------------------------------------------------------------------
def bfd_credentials(payload: bytes) -> list[Cred]:
    """A BFD control packet authenticated with a simple password (type 1)."""
    if len(payload) < 27 or payload[0] >> 5 != 1 or not payload[1] & 0x04:
        return []
    auth = payload[24:]
    if auth[0] != 1 or auth[1] < 4 or len(auth) < auth[1]:
        return []
    password = auth[3 : auth[1]]
    return [("BFD Simple Password", None, password.decode("latin-1"), f"BFD control packet, key id {auth[2]}")]


def credentials(
    sport: Optional[int],
    dport: Optional[int],
    payload: bytes,
    *,
    tcp: bool,
    src: str = "",
    dst: str = "",
    tacacs: Optional[TacacsState] = None,
) -> list[Cred]:
    """Dispatch one TCP/UDP payload (``src`` -> ``dst``) by its port."""
    if tcp:
        if TACACS_PORT in (sport, dport) and tacacs is not None:
            if dport == TACACS_PORT:
                return tacacs_credentials(payload, src, dst, tacacs)
            return tacacs_credentials(payload, dst, src, tacacs)
        return []
    if dport in RADIUS_PORTS:
        return radius_credentials(payload)
    if dport in BFD_PORTS or sport in BFD_PORTS:
        return bfd_credentials(payload)
    return []

