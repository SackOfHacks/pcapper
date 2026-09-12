"""Non-SIP VoIP call control: SCCP, MGCP, MEGACO/H.248, IAX2, H.323, UNISTIM.

SIP is not the whole story. A real enterprise capture routinely carries Cisco
Skinny between handsets and CallManager, MGCP or MEGACO down to the gateways,
H.323 on older video and trunk equipment, and IAX2 between Asterisk boxes. A
VoIP analyzer that only reads SIP misses the call entirely on those networks.

Each decoder here is deliberately targeted rather than complete: it recovers the
fields that matter to an investigation — who registered, who dialled what, which
digits were pressed, and any credential material — and ignores the rest of the
protocol. Where a protocol is ASN.1-encoded (H.323), the approach is to identify
the message and pull printable identifiers out of it rather than to implement a
PER decoder.

Split from :mod:`pcapper.voip` so each decoder can be tested against synthetic
bytes without a capture file.
"""

from __future__ import annotations

import re
from typing import Optional

# --- Cisco SCCP / Skinny ----------------------------------------------------
SCCP_PORTS = frozenset({2000, 2443})

# Only the messages worth recovering. Skinny has hundreds; these carry the
# identity, the dialled digits and the call state.
SCCP_MESSAGE_IDS = {
    0x0000: "KeepAlive",
    0x0001: "Register",
    0x0002: "IpPort",
    0x0003: "KeypadButton",
    0x0004: "EnblocCall",
    0x0005: "StimulusMessage",
    0x0006: "OffHook",
    0x0007: "OnHook",
    0x0008: "HookFlash",
    0x0009: "ForwardStatReq",
    0x000A: "SpeedDialStatReq",
    0x000B: "LineStatReq",
    0x000C: "ConfigStatReq",
    0x000D: "TimeDateReq",
    0x000E: "ButtonTemplateReq",
    0x000F: "VersionReq",
    0x0010: "CapabilitiesRes",
    0x0011: "MediaPortList",
    0x0012: "ServerReq",
    0x0020: "Alarm",
    0x0021: "MulticastMediaReceptionAck",
    0x0022: "OpenReceiveChannelAck",
    0x0024: "SoftKeySetReq",
    0x0026: "SoftKeyEvent",
    0x0027: "UnregisterMessage",
    0x0081: "RegisterAck",
    0x0082: "StartTone",
    0x0083: "StopTone",
    0x0085: "SetRinger",
    0x0086: "SetLamp",
    0x0088: "SetSpeakerMode",
    0x008A: "StartMediaTransmission",
    0x008B: "StopMediaTransmission",
    0x009D: "RegisterReject",
    0x009E: "ResetMessage",
    0x0090: "ForwardStatMessage",
    0x0091: "SpeedDialStatMessage",
    0x0092: "LineStatMessage",
    0x0093: "ConfigStatMessage",
    0x0094: "DefineTimeDate",
    0x0097: "ButtonTemplateMessage",
    0x0098: "VersionMessage",
    0x0099: "DisplayTextMessage",
    0x009F: "KeepAliveAck",
    0x0105: "OpenReceiveChannel",
    0x0106: "CloseReceiveChannel",
    0x0110: "SelectSoftKeys",
    0x0111: "CallStateMessage",
    0x0112: "DisplayPromptStatus",
    0x0114: "DisplayNotify",
    0x0116: "ActivateCallPlane",
    0x011D: "DialedNumberMessage",
    0x011F: "CallInfoMessage",
}

# The keypad codes a Skinny handset reports for a physical button press.
SCCP_KEYPAD = {
    **{n: str(n) for n in range(10)},
    0x0A: "*", 0x0B: "#", 0x0E: "A", 0x0F: "B", 0x10: "C", 0x11: "D",
}


def parse_sccp(payload: bytes) -> list[dict]:
    """Decode the Skinny messages in one TCP segment.

    Framing is ``[length:4 LE][reserved:4 LE][message id:4 LE][body]`` — all
    little-endian, which is the usual reason a hand-rolled parser reads Skinny
    as garbage.
    """
    messages: list[dict] = []
    offset = 0
    while offset + 12 <= len(payload):
        length = int.from_bytes(payload[offset : offset + 4], "little")
        if length < 4 or length > 4096:
            break
        end = offset + 8 + length
        if end > len(payload):
            break
        message_id = int.from_bytes(payload[offset + 8 : offset + 12], "little")
        body = payload[offset + 12 : end]
        entry: dict = {
            "id": message_id,
            "name": SCCP_MESSAGE_IDS.get(message_id, f"Unknown-0x{message_id:04x}"),
        }
        if message_id == 0x0001 and len(body) >= 16:  # Register
            entry["device"] = _c_string(body[:16])
            entry["device_ip"] = ".".join(str(b) for b in body[20:24][::-1]) if len(body) >= 24 else ""
        elif message_id == 0x0003 and len(body) >= 4:  # KeypadButton
            code = int.from_bytes(body[0:4], "little")
            digit = SCCP_KEYPAD.get(code)
            if digit:
                entry["digit"] = digit
        elif message_id == 0x0004:  # EnblocCall — the whole dialled string
            entry["called"] = _c_string(body[:24])
        elif message_id == 0x011D:  # DialedNumber
            entry["called"] = _c_string(body[:24])
        elif message_id == 0x011F:  # CallInfo
            parts = [p for p in _c_strings(body, limit=6) if p]
            if parts:
                entry["calling"] = parts[0]
                if len(parts) > 1:
                    entry["called"] = parts[1]
                entry["names"] = parts[:4]
        elif message_id == 0x0099 and body:  # DisplayText
            entry["text"] = _c_string(body[:64])
        elif message_id == 0x0020 and len(body) > 4:  # Alarm
            entry["text"] = _c_string(body[4:84])
        messages.append(entry)
        offset = end
    return messages


def _c_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def _c_strings(raw: bytes, limit: int = 4) -> list[str]:
    out: list[str] = []
    for chunk in raw.split(b"\x00"):
        if len(out) >= limit:
            break
        text = chunk.decode("utf-8", errors="replace").strip()
        if text and all(32 <= ord(c) < 127 for c in text):
            out.append(text)
    return out


def looks_like_sccp(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    length = int.from_bytes(payload[0:4], "little")
    reserved = int.from_bytes(payload[4:8], "little")
    message_id = int.from_bytes(payload[8:12], "little")
    if not (4 <= length <= 4096) or reserved not in (0, 0x11):
        return False
    return message_id in SCCP_MESSAGE_IDS


# --- MGCP -------------------------------------------------------------------
MGCP_PORTS = frozenset({2427, 2727})
MGCP_VERBS = frozenset(
    {"CRCX", "MDCX", "DLCX", "RQNT", "NTFY", "AUEP", "AUCX", "RSIP", "EPCF"}
)
_MGCP_START = re.compile(
    r"^(?:(?P<verb>[A-Z]{4})\s+(?P<txn>\d+)\s+(?P<endpoint>\S+)\s+MGCP\s+"
    r"|(?P<code>\d{3})\s+(?P<rtxn>\d+))"
)
# The observed-events parameter is where a gateway reports pressed digits.
_MGCP_OBSERVED = re.compile(r"^O:\s*(.+)$", re.M | re.I)
_MGCP_DTMF = re.compile(r"[dD]/([0-9*#A-D])")


def parse_mgcp(text: str) -> Optional[dict]:
    """Parse an MGCP command or response.

    ``NTFY`` with an ``O:`` (ObservedEvents) parameter is the forensic prize:
    that is where the media gateway reports the digits the caller pressed.
    """
    match = _MGCP_START.match(text.strip())
    if not match:
        return None
    result: dict = {
        "verb": match.group("verb") or "",
        "code": int(match.group("code")) if match.group("code") else None,
        "transaction": match.group("txn") or match.group("rtxn") or "",
        "endpoint": match.group("endpoint") or "",
        "digits": "",
        "events": "",
    }
    observed = _MGCP_OBSERVED.search(text)
    if observed:
        result["events"] = observed.group(1).strip()[:200]
        digits = _MGCP_DTMF.findall(observed.group(1))
        if digits:
            result["digits"] = "".join(digits)
    return result


def looks_like_mgcp(text: str) -> bool:
    head = text[:5].strip()
    return head[:4] in MGCP_VERBS or bool(re.match(r"^\d{3}\s+\d+", text[:12]))


# --- MEGACO / H.248 ---------------------------------------------------------
MEGACO_PORTS = frozenset({2944, 2945})
_MEGACO_START = re.compile(r"^\s*(?:MEGACO/\d|!/\d)", re.I)
_MEGACO_COMMAND = re.compile(
    r"\b(Add|Modify|Subtract|Move|AuditValue|AuditCapability|Notify|"
    r"ServiceChange)\b",
    re.I,
)
_MEGACO_DIGITS = re.compile(r"\bdd/(?:ce|std)\b.*?\bds=\"?([0-9*#A-D]+)", re.I | re.S)


def parse_megaco(text: str) -> Optional[dict]:
    """Parse the text encoding of MEGACO/H.248.

    Only the text form is handled. The binary (ASN.1) encoding on port 2945 is
    detected by the caller and counted, not decoded.
    """
    if not _MEGACO_START.match(text):
        return None
    commands = sorted({m.group(1).title() for m in _MEGACO_COMMAND.finditer(text)})
    digits_match = _MEGACO_DIGITS.search(text)
    context = ""
    context_match = re.search(r"C\s*=\s*(\S+)", text)
    if context_match:
        context = context_match.group(1)[:32]
    return {
        "commands": commands,
        "context": context,
        "digits": digits_match.group(1) if digits_match else "",
    }


# --- IAX2 -------------------------------------------------------------------
IAX2_PORT = 4569

IAX2_SUBCLASS_NEW = 0x01
IAX2_FRAME_IAX = 0x06

IAX2_IAX_SUBCLASSES = {
    0x01: "NEW", 0x02: "PING", 0x03: "PONG", 0x04: "ACK", 0x05: "HANGUP",
    0x06: "REJECT", 0x07: "ACCEPT", 0x08: "AUTHREQ", 0x09: "AUTHREP",
    0x0A: "INVAL", 0x0B: "LAGRQ", 0x0C: "LAGRP", 0x0D: "REGREQ",
    0x0E: "REGAUTH", 0x0F: "REGACK", 0x10: "REGREJ", 0x11: "REGREL",
    0x12: "VNAK", 0x13: "DPREQ", 0x14: "DPREP", 0x15: "DIAL",
    0x16: "TXREQ", 0x1F: "TXMEDIA", 0x20: "TRANSFER",
}

# Information elements that carry identity or secrets.
IAX2_IES = {
    0x01: "CALLED_NUMBER", 0x02: "CALLING_NUMBER", 0x04: "CALLING_NAME",
    0x05: "CALLED_CONTEXT", 0x06: "USERNAME", 0x07: "PASSWORD",
    0x08: "CAPABILITY", 0x09: "FORMAT", 0x0A: "LANGUAGE", 0x0B: "VERSION",
    0x0E: "DNID", 0x0F: "AUTHMETHODS", 0x10: "CHALLENGE", 0x11: "MD5_RESULT",
    0x12: "RSA_RESULT", 0x13: "APPARENT_ADDR", 0x14: "REFRESH",
    0x15: "DPSTATUS", 0x16: "CALLNO", 0x17: "CAUSE", 0x18: "IAX_UNKNOWN",
    0x19: "MSGCOUNT", 0x1A: "AUTOANSWER", 0x1B: "MUSICONHOLD",
    0x1C: "TRANSFERID", 0x1D: "RDNIS", 0x26: "DEVICETYPE",
    0x27: "SERVICEIDENT", 0x28: "FIRMWAREVER", 0x2F: "OSPTOKEN",
}


def parse_iax2(payload: bytes) -> Optional[dict]:
    """Parse an IAX2 full frame.

    Only full frames (high bit of the first byte set) carry the control
    messages. Mini frames are media and are counted by the caller.

    IAX2 authentication is worth the effort: ``AUTHREQ`` carries the challenge
    and ``AUTHREP`` the MD5 of challenge+password, so the pair is an offline
    cracking candidate, and plaintext ``PASSWORD`` IEs still occur in the wild.
    """
    if len(payload) < 12:
        return None
    if not payload[0] & 0x80:
        return {"kind": "mini"}
    frame_type = payload[10]
    subclass = payload[11]
    result: dict = {
        "kind": "full",
        "source_call": int.from_bytes(payload[0:2], "big") & 0x7FFF,
        "dest_call": int.from_bytes(payload[2:4], "big") & 0x7FFF,
        "frame_type": frame_type,
        "subclass": subclass,
        "name": (
            IAX2_IAX_SUBCLASSES.get(subclass, f"0x{subclass:02x}")
            if frame_type == IAX2_FRAME_IAX
            else f"frametype{frame_type}"
        ),
        "ies": {},
    }
    if frame_type != IAX2_FRAME_IAX:
        return result
    offset = 12
    while offset + 2 <= len(payload):
        ie_id = payload[offset]
        ie_len = payload[offset + 1]
        if offset + 2 + ie_len > len(payload):
            break
        raw = payload[offset + 2 : offset + 2 + ie_len]
        name = IAX2_IES.get(ie_id, f"IE{ie_id}")
        if name in ("CHALLENGE", "MD5_RESULT", "RSA_RESULT"):
            result["ies"][name] = raw.decode("utf-8", errors="replace")
        elif name in ("CAPABILITY", "FORMAT", "AUTHMETHODS", "REFRESH"):
            result["ies"][name] = int.from_bytes(raw, "big") if raw else 0
        else:
            text = raw.decode("utf-8", errors="replace").strip("\x00")
            if text:
                result["ies"][name] = text
        offset += 2 + ie_len
    return result


def looks_like_iax2(payload: bytes, sport: int, dport: int) -> bool:
    if IAX2_PORT not in (sport, dport):
        return False
    if len(payload) < 4:
        return False
    if payload[0] & 0x80:
        return len(payload) >= 12
    return True


# --- H.323 ------------------------------------------------------------------
H225_PORT = 1720
H225_RAS_PORTS = frozenset({1718, 1719})

# Q.931 message types carried inside H.225 call signalling.
Q931_MESSAGE_TYPES = {
    0x01: "ALERTING", 0x02: "CALL PROCEEDING", 0x03: "PROGRESS",
    0x05: "SETUP", 0x07: "CONNECT", 0x0D: "SETUP ACKNOWLEDGE",
    0x0F: "CONNECT ACKNOWLEDGE", 0x26: "RESTART", 0x45: "DISCONNECT",
    0x46: "RESTART ACKNOWLEDGE", 0x4D: "RELEASE", 0x5A: "RELEASE COMPLETE",
    0x60: "SEGMENT", 0x62: "FACILITY", 0x68: "NOTIFY", 0x6E: "STATUS ENQUIRY",
    0x7B: "INFORMATION", 0x7D: "STATUS",
}

# RAS message names in the order of the H.225.0 RasMessage CHOICE. The index is
# the first byte of the PER encoding, which is enough to name the message
# without a full ASN.1 decoder.
RAS_MESSAGES = [
    "gatekeeperRequest", "gatekeeperConfirm", "gatekeeperReject",
    "registrationRequest", "registrationConfirm", "registrationReject",
    "unregistrationRequest", "unregistrationConfirm", "unregistrationReject",
    "admissionRequest", "admissionConfirm", "admissionReject",
    "bandwidthRequest", "bandwidthConfirm", "bandwidthReject",
    "disengageRequest", "disengageConfirm", "disengageReject",
    "locationRequest", "locationConfirm", "locationReject",
    "infoRequest", "infoRequestResponse", "nonStandardMessage",
    "unknownMessageResponse", "requestInProgress", "resourcesAvailableIndicate",
    "resourcesAvailableConfirm", "infoRequestAck", "infoRequestNak",
    "serviceControlIndication", "serviceControlResponse",
]

_E164_RE = re.compile(rb"[0-9*#]{4,20}")
_ALIAS_RE = re.compile(rb"[\x20-\x7e]{4,40}")


def parse_q931(payload: bytes) -> Optional[dict]:
    """Identify a Q.931/H.225 message and pull identifiers out of the user data.

    H.225 is ASN.1 PER inside a Q.931 user-user information element. Rather than
    decode PER, this names the Q.931 message type — which is a fixed offset —
    and scrapes printable aliases and E.164 digit strings out of the remainder.
    Enough to answer "who called whom" without a megabyte of generated decoder.
    """
    # TPKT: version 3, reserved 0, 16-bit length.
    if len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
        payload = payload[4:]
    if len(payload) < 5 or payload[0] != 0x08:  # Q.931 protocol discriminator
        return None
    call_ref_len = payload[1] & 0x0F
    offset = 2 + call_ref_len
    if offset >= len(payload):
        return None
    message_type = payload[offset]
    name = Q931_MESSAGE_TYPES.get(message_type)
    if name is None:
        return None
    body = payload[offset + 1 :]
    aliases = []
    for match in _ALIAS_RE.finditer(body):
        text = match.group(0).decode("ascii", errors="replace").strip()
        if len(text) >= 4 and not text.isdigit():
            aliases.append(text)
    numbers = [m.group(0).decode("ascii") for m in _E164_RE.finditer(body)]
    return {
        "message": name,
        "aliases": aliases[:6],
        "numbers": numbers[:6],
    }


def parse_ras(payload: bytes) -> Optional[dict]:
    """Name an H.225 RAS message from the leading CHOICE index."""
    if not payload:
        return None
    index = payload[0] >> 3
    if index >= len(RAS_MESSAGES):
        return None
    aliases = [
        m.group(0).decode("ascii", errors="replace").strip()
        for m in _ALIAS_RE.finditer(payload[1:])
    ]
    return {
        "message": RAS_MESSAGES[index],
        "aliases": [a for a in aliases if len(a) >= 4][:6],
    }


def looks_like_tpkt(payload: bytes) -> bool:
    return len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00


# --- UNISTIM (Nortel / Avaya) ----------------------------------------------
UNISTIM_PORT = 5000


def looks_like_unistim(payload: bytes, sport: int, dport: int) -> bool:
    """UNISTIM has no magic; require the registered port and a plausible header."""
    if UNISTIM_PORT not in (sport, dport) or len(payload) < 5:
        return False
    return payload[0] in (0x00, 0x01, 0x02, 0x03)


# --- provisioning -----------------------------------------------------------
# Phone configuration files are the single richest credential source in a VoIP
# capture: they contain the SIP account password in cleartext, and phones fetch
# them over TFTP or plain HTTP at boot.
PROVISIONING_PATTERNS = [
    (re.compile(r"SEP[0-9A-F]{12}\.cnf(\.xml)?", re.I), "Cisco phone config"),
    (re.compile(r"SIP[0-9A-F]{12}\.cnf(\.xml)?", re.I), "Cisco SIP phone config"),
    (re.compile(r"XMLDefault\.cnf\.xml", re.I), "Cisco default config"),
    (re.compile(r"\b[0-9a-f]{12}\.cfg\b", re.I), "Yealink/Grandstream MAC config"),
    (re.compile(r"y0{9,12}\d*\.cfg", re.I), "Yealink common config"),
    (re.compile(r"cfg[0-9a-f]{12}(\.xml)?", re.I), "Grandstream config"),
    (re.compile(r"spa\$?[0-9A-F]{12}\.xml", re.I), "Linksys/Sipura config"),
    (re.compile(r"\b[0-9A-F]{12}\.(?:cfg|xml|tuz|boot)\b", re.I), "MAC-named config"),
    (re.compile(r"snom\d+[-_].*\.(?:xml|htm)", re.I), "Snom config"),
    (re.compile(r"polycom.*\.cfg|\b\d{12}-directory\.xml", re.I), "Polycom config"),
    (re.compile(r"/provisioning/|/provision/|/phone/cfg", re.I), "provisioning path"),
]

TFTP_PORT = 69
TFTP_OPCODES = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR", 6: "OACK"}


def parse_tftp_request(payload: bytes) -> Optional[dict]:
    """Pull the filename out of a TFTP read/write request."""
    if len(payload) < 4:
        return None
    opcode = int.from_bytes(payload[0:2], "big")
    if opcode not in (1, 2):
        return None
    parts = payload[2:].split(b"\x00")
    if not parts or not parts[0]:
        return None
    return {
        "opcode": TFTP_OPCODES[opcode],
        "filename": parts[0].decode("utf-8", errors="replace")[:200],
        "mode": parts[1].decode("utf-8", errors="replace")[:20] if len(parts) > 1 else "",
    }


def classify_provisioning(name: str) -> str:
    for pattern, label in PROVISIONING_PATTERNS:
        if pattern.search(name):
            return label
    return ""
