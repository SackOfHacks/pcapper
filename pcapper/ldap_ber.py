"""Minimal BER decoding of cleartext LDAP messages (RFC 4511, RFC 4515).

Only what forensic reporting needs: the operation and message ID; for a bind
the name, authentication type and simple-bind password; for a search the
base, scope, filter and requested attributes; for writes the target DN and
the attributes touched; for results the code and diagnostic message; for a
returned entry its DN and attributes.

A TCP segment may hold several messages, or the start of one that continues
in the next segment. Decoding walks the messages in order and stops at the
first that does not parse; a message cut short by the segment end is decoded
as far as its bytes go (``truncated``). Nothing is guessed: SASL-sealed LDAP
(signing/sealing, the AD default) does not decode and yields no messages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

OPS = {
    0: "BindRequest", 1: "BindResponse", 2: "UnbindRequest", 3: "SearchRequest",
    4: "SearchResultEntry", 5: "SearchResultDone", 6: "ModifyRequest", 7: "ModifyResponse",
    8: "AddRequest", 9: "AddResponse", 10: "DelRequest", 11: "DelResponse",
    12: "ModifyDNRequest", 13: "ModifyDNResponse", 14: "CompareRequest", 15: "CompareResponse",
    16: "AbandonRequest", 19: "SearchResultReference", 23: "ExtendedRequest",
    24: "ExtendedResponse", 25: "IntermediateResponse",
}
RESPONSES = {1, 5, 7, 9, 11, 13, 15, 24}
SCOPES = {0: "base", 1: "one", 2: "sub", 3: "children"}
MODIFY_OPS = {0: "add", 1: "delete", 2: "replace", 3: "increment"}
EXTENDED_NAMES = {
    "1.3.6.1.4.1.1466.20037": "StartTLS",
    "1.3.6.1.4.1.4203.1.11.1": "PasswordModify",
    "1.3.6.1.4.1.4203.1.11.3": "WhoAmI",
    "1.3.6.1.4.1.1466.101.119.1": "DynamicRefresh",
    "1.2.840.113556.1.4.1781": "FastBind",
}
MAX_VALUES = 8  # values kept per returned attribute


@dataclass
class LdapMessage:
    message_id: int
    op: str
    dn: str = ""  # bind name, search base, target DN or returned entry DN
    auth: str = ""  # "simple", "sasl:<mechanism>"
    password: str = ""  # simple-bind credential, in the clear
    scope: str = ""
    filter: str = ""
    attributes: tuple[str, ...] = ()  # requested (search) or touched (writes)
    values: dict[str, list[str]] = field(default_factory=dict)  # returned / added attribute values
    changes: tuple[str, ...] = ()  # modify: "replace:member", ...
    result_code: Optional[int] = None
    diagnostic: str = ""
    name: str = ""  # extended operation OID (or its name)
    truncated: bool = False


class _Short(Exception):
    """The data ends inside an element."""


def _tlv(data: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """(tag, value start, value end) of the element at ``pos``; the value end
    may lie past ``end`` when the element is cut short."""
    if pos + 2 > end:
        raise _Short
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tag")
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise ValueError("bad length")
        if pos + n > end:
            raise _Short
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def _int(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=True) if data else 0


def _text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _value(raw: bytes) -> str:
    """An assertion value in RFC 4515 form: printable text as is, otherwise
    escaped as \\xx bytes (objectSid, GUIDs)."""
    try:
        text = raw.decode("utf-8")
        if all(ch.isprintable() for ch in text):
            return "".join("\\" + f"{ord(ch):02x}" if ch in "*()\\" else ch for ch in text)
    except UnicodeDecodeError:
        pass
    return "".join(f"\\{b:02x}" for b in raw)


def _children(data: bytes, start: int, stop: int) -> Iterator[tuple[int, int, int]]:
    pos = start
    while pos < stop:
        tag, vs, ve = _tlv(data, pos, stop)
        if ve > stop:
            raise _Short
        yield tag, vs, ve
        pos = ve


def _filter(data: bytes, pos: int, end: int, depth: int = 0) -> tuple[str, int]:
    if depth > 32:
        raise ValueError("filter too deep")
    tag, vs, ve = _tlv(data, pos, end)
    if ve > end:
        raise _Short
    kind = tag & 0x1F
    if tag in (0xA0, 0xA1):  # and / or
        parts = []
        inner = vs
        while inner < ve:
            text, inner = _filter(data, inner, ve, depth + 1)
            parts.append(text)
        return f"({'&' if tag == 0xA0 else '|'}{''.join(parts)})", ve
    if tag == 0xA2:  # not
        text, _ = _filter(data, vs, ve, depth + 1)
        return f"(!{text})", ve
    if tag == 0x87:  # present
        return f"({_text(data[vs:ve])}=*)", ve
    if tag in (0xA3, 0xA5, 0xA6, 0xA8):  # equality, >=, <=, ~=
        items = list(_children(data, vs, ve))
        if len(items) != 2:
            raise ValueError("bad assertion")
        attr = _text(data[items[0][1]:items[0][2]])
        val = _value(data[items[1][1]:items[1][2]])
        op = {3: "=", 5: ">=", 6: "<=", 8: "~="}[kind]
        return f"({attr}{op}{val})", ve
    if tag == 0xA4:  # substrings
        items = list(_children(data, vs, ve))
        if len(items) != 2:
            raise ValueError("bad substrings")
        attr = _text(data[items[0][1]:items[0][2]])
        initial = final = ""
        middle: list[str] = []
        for stag, svs, sve in _children(data, items[1][1], items[1][2]):
            part = _value(data[svs:sve])
            if stag == 0x80:
                initial = part
            elif stag == 0x81:
                middle.append(part)
            elif stag == 0x82:
                final = part
        return f"({attr}={initial}*{''.join(m + '*' for m in middle)}{final})", ve
    if tag == 0xA9:  # extensible match
        rule = attr = val = ""
        dn_attrs = False
        for stag, svs, sve in _children(data, vs, ve):
            if stag == 0x81:
                rule = _text(data[svs:sve])
            elif stag == 0x82:
                attr = _text(data[svs:sve])
            elif stag == 0x83:
                val = _value(data[svs:sve])
            elif stag == 0x84:
                dn_attrs = bool(data[svs:sve].strip(b"\x00"))
        return f"({attr}{':dn' if dn_attrs else ''}{':' + rule if rule else ''}:={val})", ve
    raise ValueError(f"unknown filter tag {tag:#x}")


def _octet_strings(data: bytes, start: int, stop: int) -> list[str]:
    return [_text(data[vs:ve]) for tag, vs, ve in _children(data, start, stop) if tag == 0x04]


def _attribute_list(data: bytes, start: int, stop: int, msg: LdapMessage) -> None:
    """A PartialAttributeList; complete attributes only when cut short."""
    names: list[str] = []
    try:
        for tag, vs, ve in _children(data, start, stop):
            items = list(_children(data, vs, ve))
            if len(items) < 2:
                continue
            name = _text(data[items[0][1]:items[0][2]])
            names.append(name)
            vals = [data[a:b] for _t, a, b in _children(data, items[1][1], items[1][2])]
            msg.values[name] = [_value(v) if not v.isascii() or not v.decode("ascii").isprintable() else v.decode("ascii")
                                for v in vals[:MAX_VALUES]]
    except _Short:
        msg.truncated = True
    msg.attributes = tuple(names)


def _result(data: bytes, vs: int, ve: int, msg: LdapMessage) -> None:
    items = list(_children(data, vs, min(ve, len(data))))
    if items and items[0][0] == 0x0A:
        msg.result_code = _int(data[items[0][1]:items[0][2]])
    if len(items) > 1 and items[1][0] == 0x04:
        msg.dn = _text(data[items[1][1]:items[1][2]])
    if len(items) > 2 and items[2][0] == 0x04:
        msg.diagnostic = _text(data[items[2][1]:items[2][2]])


def _decode_op(data: bytes, msg_id: int, tag: int, vs: int, ve: int) -> LdapMessage:
    op = tag & 0x1F
    msg = LdapMessage(message_id=msg_id, op=OPS.get(op, f"op{op}"))
    if ve > len(data):
        msg.truncated = True
    stop = min(ve, len(data))
    if op == 0:  # BindRequest: version, name, authentication
        items = list(_children(data, vs, stop))
        if len(items) >= 2:
            msg.dn = _text(data[items[1][1]:items[1][2]])
        if len(items) >= 3:
            atag, avs, ave = items[2]
            if atag == 0x80:
                msg.auth, msg.password = "simple", _text(data[avs:ave])
            elif atag == 0xA3:
                mech = _octet_strings(data, avs, ave)
                msg.auth = "sasl:" + (mech[0] if mech else "?")
            else:
                msg.auth = f"auth[{atag & 0x1F}]"
    elif op == 3:  # SearchRequest
        items: list[tuple[int, int, int]] = []
        pos = vs
        for _ in range(6):  # base, scope, deref, size, time, typesOnly
            tag2, a, b = _tlv(data, pos, stop)
            if b > stop:
                raise _Short
            items.append((tag2, a, b))
            pos = b
        msg.dn = _text(data[items[0][1]:items[0][2]])
        msg.scope = SCOPES.get(_int(data[items[1][1]:items[1][2]]), "?")
        msg.filter, pos = _filter(data, pos, stop)
        if pos < stop:
            tag2, a, b = _tlv(data, pos, stop)
            if tag2 == 0x30 and b <= stop:
                msg.attributes = tuple(_octet_strings(data, a, b))
    elif op in (4, 8):  # SearchResultEntry / AddRequest: DN, attributes
        tag2, a, b = _tlv(data, vs, stop)
        msg.dn = _text(data[a:min(b, stop)])
        if b < stop:
            tag3, c, d = _tlv(data, b, stop)
            _attribute_list(data, c, min(d, stop), msg)
            if d > stop:
                msg.truncated = True
    elif op == 6:  # ModifyRequest: object, changes
        tag2, a, b = _tlv(data, vs, stop)
        msg.dn = _text(data[a:min(b, stop)])
        changes: list[str] = []
        names: list[str] = []
        try:
            tag3, c, d = _tlv(data, b, stop)
            for _t, cs, ce in _children(data, c, min(d, stop)):
                parts = list(_children(data, cs, ce))
                if len(parts) < 2:
                    continue
                kind = MODIFY_OPS.get(_int(data[parts[0][1]:parts[0][2]]), "?")
                inner = list(_children(data, parts[1][1], parts[1][2]))
                if inner:
                    name = _text(data[inner[0][1]:inner[0][2]])
                    names.append(name)
                    changes.append(f"{kind}:{name}")
                    if len(inner) > 1:
                        vals = [data[x:y] for _u, x, y in _children(data, inner[1][1], inner[1][2])]
                        msg.values[name] = [_value(v) for v in vals[:MAX_VALUES]]
        except _Short:
            msg.truncated = True
        msg.attributes, msg.changes = tuple(names), tuple(changes)
    elif op == 10:  # DelRequest: the DN itself
        msg.dn = _text(data[vs:stop])
    elif op == 12:  # ModifyDNRequest: entry, newrdn, deleteoldrdn, [newSuperior]
        items = list(_children(data, vs, stop))
        if items:
            msg.dn = _text(data[items[0][1]:items[0][2]])
        if len(items) > 1:
            msg.attributes = (_text(data[items[1][1]:items[1][2]]),)
    elif op == 14:  # CompareRequest: entry, AVA
        items = list(_children(data, vs, stop))
        if items:
            msg.dn = _text(data[items[0][1]:items[0][2]])
        if len(items) > 1:
            ava = list(_children(data, items[1][1], items[1][2]))
            if len(ava) == 2:
                msg.attributes = (_text(data[ava[0][1]:ava[0][2]]),)
                msg.filter = f"({msg.attributes[0]}={_value(data[ava[1][1]:ava[1][2]])})"
    elif op == 23:  # ExtendedRequest: requestName [0]
        for tag2, a, b in _children(data, vs, stop):
            if tag2 == 0x80:
                oid = _text(data[a:b])
                msg.name = EXTENDED_NAMES.get(oid, oid)
                break
    elif op in RESPONSES:
        _result(data, vs, ve, msg)
        if op == 24:
            for tag2, a, b in _children(data, vs, stop):
                if tag2 == 0x8A:  # responseName [10]
                    oid = _text(data[a:b])
                    msg.name = EXTENDED_NAMES.get(oid, oid)
    return msg


def _message_start(data: bytes, pos: int) -> bool:
    """Whether an LDAPMessage header starts at ``pos``: SEQUENCE, a 1-4 byte
    INTEGER message ID, then a known APPLICATION operation tag."""
    end = len(data)
    try:
        tag, vs, _ve = _tlv(data, pos, end)
        if tag != 0x30:
            return False
        id_tag, ivs, ive = _tlv(data, vs, end)
        if id_tag != 0x02 or not 1 <= ive - ivs <= 4 or ive >= end:
            return False
        op_tag = data[ive]
        return op_tag & 0xC0 == 0x40 and (op_tag & 0x1F) in OPS
    except (_Short, ValueError, IndexError):
        return False


def iter_ldap_messages(payload: bytes, *, resync: bool = True) -> Iterator[LdapMessage]:
    """The LDAP messages in one TCP payload, in order. With ``resync`` a
    segment that starts inside a message (the tail of a large search result)
    is scanned for the next message header instead of being given up on."""
    data = bytes(payload or b"")
    pos = 0
    end = len(data)
    while pos < end:
        if not _message_start(data, pos):
            if not resync:
                return
            nxt = data.find(b"\x30", pos + 1)
            while nxt != -1 and not _message_start(data, nxt):
                nxt = data.find(b"\x30", nxt + 1)
            if nxt == -1:
                return
            pos = nxt
        try:
            tag, vs, ve = _tlv(data, pos, end)
            id_tag, ivs, ive = _tlv(data, vs, end)
            msg_id = _int(data[ivs:ive])
            op_tag, ovs, ove = _tlv(data, ive, end)
            msg = _decode_op(data, msg_id, op_tag, ovs, ove)
        except (_Short, ValueError, IndexError):
            # A header that does not decode: look for the next one.
            if not resync:
                return
            pos += 1
            continue
        if ve > end:
            msg.truncated = True
        yield msg
        if ve > end:
            return
        pos = ve
