"""OPC Classic (OPC DA / A&E / HDA over DCOM) analysis.

OPC Classic is COM/DCOM: a client activates the server through the endpoint
mapper (tcp/135, ``ISystemActivator``), then talks to the server's dynamic
port over connection-oriented DCE/RPC. An interface is *bound* to a context id
on that connection (``bind`` / ``alter_context``) and every later request
names only the context id and an opnum. So the protocol cannot be read packet
by packet: this module reassembles each TCP direction into DCE/RPC PDUs,
keeps the context-id -> interface table per connection, and names each
request ``IOPCSyncIO::Write`` and so on.

On top of that it decodes what an analyst actually needs from the NDR stub:

* ``IOPCItemMgt::AddItems`` item IDs and the server/client handles they map to
  (from the response), so later reads, writes and callbacks name the item;
* ``Write`` values (``IOPCSyncIO``, ``IOPCAsyncIO``/``2``/``3``, ``WriteVQT``),
  ``Read`` results and ``IOPCDataCallback`` updates, decoded from the
  ``wireVARIANT`` structures (I2/I4/R4/R8/BSTR/BOOL/...);
* group names, client names, browse positions/results and the OPCEnum
  server list (ProgIDs).

Interfaces are recognised by IID only. ``ISystemActivator`` and ``IRemUnknown``
appear in *every* DCOM conversation and are never treated as OPC on their own.
A request on a context bound before the capture started cannot be attributed
to an interface; those are counted, not guessed.
"""

from __future__ import annotations

import struct
import uuid
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .industrial_helpers import IndustrialCommandEvent, _strip_padding
from .lite import UNSUPPORTED, LitePacket
from .pcap_cache import PassStats, PcapMeta, iter_packets
from .reassembly import relative_seq
from .utils import extract_packet_endpoints, is_public_ip, memoize_analysis, safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


# --------------------------------------------------------------------------
# Interface catalogue
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OpcInterface:
    """One OPC Classic COM interface: its family and methods in vtable order.

    DCOM opnums are vtable indices; 0-2 are IUnknown (never sent over the
    wire, ``IRemUnknown`` is used instead), so the first method is opnum 3.
    """

    name: str
    family: str
    methods: tuple[str, ...] = ()
    callback: bool = False  # called by the OPC server on the client

    def method(self, opnum: int) -> str:
        index = opnum - 3
        if 0 <= index < len(self.methods):
            return self.methods[index]
        return f"opnum {opnum}"

    @property
    def display(self) -> str:
        if self.family == "COM":
            return f"COM {self.name} (on an OPC connection)"
        return f"OPC {self.family} {self.name}"


_DA = "-011e-11d0-9675-0020afd8adb3"
_COMMON = "-07b6-11d2-b2d8-0060083ba1fb"
_HDA = "-dee0-11d2-a5e5-000086339399"
_AE = "-5783-11d1-84a0-00608cb8a7e9"

_DA_SYNC_IO = ("Read", "Write")
_DA_ASYNC_IO2 = ("Read", "Write", "Refresh2", "Cancel2", "SetEnable", "GetEnable")
_DA_GROUP_STATE = ("GetState", "SetState", "SetName", "CloneGroup")

# Sources: OPC DA 2.05a/3.00 opcda.idl, OPC Common opccomn.idl, OPCEnum
# opcEnum.idl, OPC A&E 1.10 opc_ae.idl, OPC HDA 1.20 opchda.idl. The DA
# family's IIDs and method order were cross-checked against live traffic
# (binds of 39c13a52/54/70/71/72 and their opnums in the ICSC 2021 capture).
OPC_INTERFACES: dict[str, OpcInterface] = {
    # --- Data Access ---------------------------------------------------------
    "39c13a4d" + _DA: OpcInterface(
        "IOPCServer", "DA",
        ("AddGroup", "GetErrorString", "GetGroupByName", "GetStatus",
         "RemoveGroup", "CreateGroupEnumerator"),
    ),
    "39c13a4e" + _DA: OpcInterface(
        "IOPCServerPublicGroups", "DA", ("GetPublicGroupByName", "RemovePublicGroup")
    ),
    "39c13a4f" + _DA: OpcInterface(
        "IOPCBrowseServerAddressSpace", "DA",
        ("QueryOrganization", "ChangeBrowsePosition", "BrowseOPCItemIDs",
         "GetItemID", "BrowseAccessPaths"),
    ),
    "39c13a50" + _DA: OpcInterface("IOPCGroupStateMgt", "DA", _DA_GROUP_STATE),
    "39c13a51" + _DA: OpcInterface(
        "IOPCPublicGroupStateMgt", "DA", ("GetState", "MoveToPublic")
    ),
    "39c13a52" + _DA: OpcInterface("IOPCSyncIO", "DA", _DA_SYNC_IO),
    "39c13a53" + _DA: OpcInterface(
        "IOPCAsyncIO", "DA", ("Read", "Write", "Refresh", "Cancel")
    ),
    "39c13a54" + _DA: OpcInterface(
        "IOPCItemMgt", "DA",
        ("AddItems", "ValidateItems", "RemoveItems", "SetActiveState",
         "SetClientHandles", "SetDatatypes", "CreateEnumerator"),
    ),
    "39c13a55" + _DA: OpcInterface(
        "IEnumOPCItemAttributes", "DA", ("Next", "Skip", "Reset", "Clone")
    ),
    "39c13a70" + _DA: OpcInterface(
        "IOPCDataCallback", "DA",
        ("OnDataChange", "OnReadComplete", "OnWriteComplete", "OnCancelComplete"),
        callback=True,
    ),
    "39c13a71" + _DA: OpcInterface("IOPCAsyncIO2", "DA", _DA_ASYNC_IO2),
    "39c13a72" + _DA: OpcInterface(
        "IOPCItemProperties", "DA",
        ("QueryAvailableProperties", "GetItemProperties", "LookupItemIDs"),
    ),
    # --- Data Access 3.0 -----------------------------------------------------
    "39227004-a18f-4b57-8b0a-5235670f4468": OpcInterface(
        "IOPCBrowse", "DA", ("GetProperties", "Browse")
    ),
    "85c0b427-2893-4cbc-bd78-e5fc5146f08f": OpcInterface(
        "IOPCItemIO", "DA", ("Read", "WriteVQT")
    ),
    "730f5f0f-55b1-4c81-9e18-ff8a0904e1fa": OpcInterface(
        "IOPCSyncIO2", "DA", _DA_SYNC_IO + ("ReadMaxAge", "WriteVQT")
    ),
    "0967b97b-36ef-423e-b6f8-6bff1e40d39d": OpcInterface(
        "IOPCAsyncIO3", "DA",
        _DA_ASYNC_IO2 + ("ReadMaxAge", "WriteVQT", "RefreshMaxAge"),
    ),
    "5946da93-8b39-4ec8-ab3d-aa73df5bc86f": OpcInterface(
        "IOPCItemDeadbandMgt", "DA",
        ("SetItemDeadband", "GetItemDeadband", "ClearItemDeadband"),
    ),
    "3e22d313-f08b-41a5-86c8-95e95cb49ffc": OpcInterface(
        "IOPCItemSamplingMgt", "DA",
        ("SetItemSamplingRate", "GetItemSamplingRate", "ClearItemSamplingRate",
         "SetItemBufferEnable", "GetItemBufferEnable"),
    ),
    "8e368666-d72e-4f78-87ed-647611c61c9f": OpcInterface(
        "IOPCGroupStateMgt2", "DA", _DA_GROUP_STATE + ("SetKeepAlive", "GetKeepAlive")
    ),
    # --- OPC Common / server enumeration --------------------------------------
    "f31dfde2" + _COMMON: OpcInterface(
        "IOPCCommon", "Common",
        ("SetLocaleID", "GetLocaleID", "QueryAvailableLocaleIDs",
         "GetErrorString", "SetClientName"),
    ),
    "f31dfde1" + _COMMON: OpcInterface(
        "IOPCShutdown", "Common", ("ShutdownRequest",), callback=True
    ),
    "13486d50-4821-11d2-a494-3cb306c10000": OpcInterface(
        "IOPCServerList", "Enum",
        ("EnumClassesOfCategories", "GetClassDetails", "CLSIDFromProgID"),
    ),
    "9dd0b56c-ad9e-43ee-8305-487f3188bf7a": OpcInterface(
        "IOPCServerList2", "Enum",
        ("EnumClassesOfCategories", "GetClassDetails", "CLSIDFromProgID"),
    ),
    "55c382c8-21c7-4e88-96c1-becfb1e3f483": OpcInterface(
        "IOPCEnumGUID", "Enum", ("Next", "Skip", "Reset", "Clone")
    ),
    # --- Alarms & Events -----------------------------------------------------
    "65168851" + _AE: OpcInterface(
        "IOPCEventServer", "AE",
        ("GetStatus", "CreateEventSubscription", "QueryAvailableFilters",
         "QueryEventCategories", "QueryConditionNames", "QuerySubConditionNames",
         "QuerySourceConditions", "QueryEventAttributes", "TranslateToItemIDs",
         "GetConditionState", "EnableConditionByArea", "EnableConditionBySource",
         "DisableConditionByArea", "DisableConditionBySource", "AckCondition",
         "CreateAreaBrowser"),
    ),
    # --- Historical Data Access ----------------------------------------------
    "1f1217b0" + _HDA: OpcInterface(
        "IOPCHDA_Server", "HDA",
        ("GetItemAttributes", "GetAggregates", "GetHistorianStatus",
         "GetItemHandles", "ReleaseItemHandles", "ValidateItemIDs", "CreateBrowse"),
    ),
    "1f1217b1" + _HDA: OpcInterface(
        "IOPCHDA_Browser", "HDA",
        ("GetEnum", "ChangeBrowsePosition", "GetItemID", "GetBranchPosition"),
    ),
    "1f1217b2" + _HDA: OpcInterface(
        "IOPCHDA_SyncRead", "HDA",
        ("ReadRaw", "ReadProcessed", "ReadAtTime", "ReadModified", "ReadAttribute"),
    ),
    "1f1217b3" + _HDA: OpcInterface(
        "IOPCHDA_SyncUpdate", "HDA",
        ("QueryCapabilities", "Insert", "Replace", "InsertReplace", "DeleteRaw",
         "DeleteAtTime"),
    ),
    "1f1217b4" + _HDA: OpcInterface(
        "IOPCHDA_SyncAnnotations", "HDA", ("QueryCapabilities", "Read", "Insert")
    ),
    "1f1217b5" + _HDA: OpcInterface(
        "IOPCHDA_AsyncRead", "HDA",
        ("ReadRaw", "AdviseRaw", "ReadProcessed", "AdviseProcessed", "ReadAtTime",
         "ReadModified", "ReadAttribute", "Cancel"),
    ),
    "1f1217b6" + _HDA: OpcInterface(
        "IOPCHDA_AsyncUpdate", "HDA",
        ("QueryCapabilities", "Insert", "Replace", "InsertReplace", "DeleteRaw",
         "DeleteAtTime", "Cancel"),
    ),
    "1f1217b7" + _HDA: OpcInterface(
        "IOPCHDA_AsyncAnnotations", "HDA", ("QueryCapabilities", "Read", "Insert", "Cancel")
    ),
    "1f1217b9" + _HDA: OpcInterface(
        "IOPCHDA_DataCallback", "HDA",
        ("OnDataChange", "OnReadComplete", "OnReadModifiedComplete",
         "OnReadAttributeComplete", "OnReadAnnotations", "OnInsertAnnotations",
         "OnPlayback", "OnUpdateComplete", "OnCancelComplete"),
        callback=True,
    ),
}

# Family patterns for interfaces not individually catalogued (vendor or
# minor-version variants share the IID suffix): named by family, methods
# shown as opnums.
_FAMILY_SUFFIXES = ((_DA, "DA"), (_COMMON, "Common"), (_AE, "AE"), (_HDA, "HDA"))

# COM's own string enumerator: OPC browse results (BrowseOPCItemIDs,
# BrowseAccessPaths, QueryAvailableLocaleIDs ...) come back through it. Only
# followed on a connection that has already bound an OPC interface.
IENUMSTRING_IID = "00000101-0000-0000-c000-000000000046"
_ENUM_STRING = OpcInterface("IEnumString", "COM", ("Next", "Skip", "Reset", "Clone"))

def _uuid_to_le_bytes(value: str) -> bytes:
    """An IID as it appears on the wire (DCE/RPC encodes UUIDs little-endian)."""
    return uuid.UUID(value).bytes_le


# Kept for callers and tests that used the former marker table.
OPC_UUIDS: dict[str, str] = {iid: iface.display for iid, iface in OPC_INTERFACES.items()}
UUID_MARKERS: dict[str, bytes] = {iid: _uuid_to_le_bytes(iid) for iid in OPC_INTERFACES}
_MARKER_LOOKUP: dict[bytes, str] = {marker: iid for iid, marker in UUID_MARKERS.items()}


def lookup_interface(iid: str) -> OpcInterface | None:
    iid = iid.lower()
    iface = OPC_INTERFACES.get(iid)
    if iface is not None:
        return iface
    for suffix, family in _FAMILY_SUFFIXES:
        if iid.endswith(suffix):
            return OpcInterface(f"{{{iid}}}", family)
    return None


# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------


@dataclass
class OpcItem:
    item_id: str
    access_path: str = ""
    client: str = ""
    server: str = ""
    server_handle: int | None = None
    client_handle: int | None = None
    canonical_type: str = ""
    access_rights: str = ""
    reads: int = 0
    writes: int = 0
    updates: int = 0
    last_value: str = ""
    values: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OpcValueEvent:
    ts: float | None
    client: str
    server: str
    operation: str
    item: str
    value: str
    vartype: str


@dataclass(frozen=True)
class OpcClassicSummary:
    path: Path
    total_packets: int
    opc_packets: int
    interface_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    operation_counts: Counter[str] = field(default_factory=Counter)
    items: dict[str, OpcItem] = field(default_factory=dict)
    writes: list[OpcValueEvent] = field(default_factory=list)
    reads: list[OpcValueEvent] = field(default_factory=list)
    updates: list[OpcValueEvent] = field(default_factory=list)
    group_names: Counter[str] = field(default_factory=Counter)
    client_names: Counter[str] = field(default_factory=Counter)
    server_progids: Counter[str] = field(default_factory=Counter)
    browse_names: list[str] = field(default_factory=list)
    unattributed_requests: Counter[str] = field(default_factory=Counter)
    faults: Counter[str] = field(default_factory=Counter)
    write_value_text: str = ""
    # IndustrialAnalysis-compatible views, so --ot-commands and --overview
    # treat OPC Classic like every other OT protocol.
    commands: Counter[str] = field(default_factory=Counter)
    command_events: list[object] = field(default_factory=list)
    service_endpoints: dict[str, Counter[str]] = field(default_factory=dict)

    @property
    def protocol_packets(self) -> int:
        return self.opc_packets


# --------------------------------------------------------------------------
# NDR helpers
# --------------------------------------------------------------------------


class _NdrError(Exception):
    pass


class _Ndr:
    """Minimal little-endian NDR reader (alignment relative to stub start)."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def align(self, size: int) -> None:
        self.pos += (-self.pos) % size

    def _take(self, size: int, fmt: str) -> int:
        self.align(size)
        end = self.pos + size
        if end > len(self.data):
            raise _NdrError("short stub")
        value = struct.unpack_from(fmt, self.data, self.pos)[0]
        self.pos = end
        return int(value)

    def u16(self) -> int:
        return self._take(2, "<H")

    def u32(self) -> int:
        return self._take(4, "<I")

    def skip(self, size: int) -> None:
        if size < 0 or self.pos + size > len(self.data):
            raise _NdrError("short stub")
        self.pos += size

    def wstring(self) -> str:
        """A conformant varying ``[string] wchar_t*`` (max, offset, actual)."""
        max_count = self.u32()
        offset = self.u32()
        actual = self.u32()
        if offset != 0 or actual > max_count or max_count > 65536:
            raise _NdrError("not an NDR string")
        end = self.pos + actual * 2
        if end > len(self.data):
            raise _NdrError("short string")
        raw = self.data[self.pos:end]
        self.pos = end
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    def handles(self) -> list[int]:
        """``[size_is(n)] DWORD*``: conformance then the values."""
        count = self.u32()
        if count > 65536:
            raise _NdrError("implausible array")
        return [self.u32() for _ in range(count)]


_ORPCTHIS_LEN = 32  # COMVERSION, flags, reserved1, CID, extensions pointer
_ORPCTHAT_LEN = 8  # flags, extensions pointer


def _request_body(stub: bytes) -> _Ndr | None:
    """NDR reader positioned after ORPCTHIS, or None when extensions follow
    (rare; positional decoding is then not attempted)."""
    if len(stub) < _ORPCTHIS_LEN:
        return None
    if struct.unpack_from("<I", stub, 28)[0] != 0:
        return None
    return _Ndr(stub, _ORPCTHIS_LEN)


def _response_body(stub: bytes) -> _Ndr | None:
    if len(stub) < _ORPCTHAT_LEN:
        return None
    if struct.unpack_from("<I", stub, 4)[0] != 0:
        return None
    return _Ndr(stub, _ORPCTHAT_LEN)


_VT_NAMES = {
    0: "EMPTY", 1: "NULL", 2: "I2", 3: "I4", 4: "R4", 5: "R8", 6: "CY", 7: "DATE",
    8: "BSTR", 10: "ERROR", 11: "BOOL", 16: "I1", 17: "UI1", 18: "UI2", 19: "UI4",
    20: "I8", 21: "UI8", 22: "INT", 23: "UINT",
}
_VT_FIXED = {
    2: ("<h", 2), 3: ("<i", 4), 4: ("<f", 4), 5: ("<d", 8), 6: ("<q", 8),
    7: ("<d", 8), 10: ("<I", 4), 11: ("<h", 2), 16: ("<b", 1), 17: ("<B", 1),
    18: ("<H", 2), 19: ("<I", 4), 20: ("<q", 8), 21: ("<Q", 8), 22: ("<i", 4),
    23: ("<I", 4),
}
_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def vartype_name(vt: int) -> str:
    base = _VT_NAMES.get(vt & 0x0FFF, f"0x{vt & 0x0FFF:x}")
    if vt & 0x2000:
        return f"ARRAY|{base}"
    if vt & 0x4000:
        return f"BYREF|{base}"
    return base


def _format_number(value: float) -> str:
    text = f"{value:.6g}"
    return text


def _decode_variant_at(stub: bytes, offset: int) -> tuple[int, str, int] | None:
    """Decode a ``wireVARIANT`` starting at ``offset``.

    Layout: clSize (u32, size in 8-byte units), rpcReserved (u32, 0), vt (u16),
    three reserved u16s (often uninitialised garbage, so ignored), the union
    discriminant (u32, equal to vt), then the arm. Returns
    ``(vt, text, end_offset)`` or None when the bytes are not a VARIANT.
    """
    if offset + 20 > len(stub):
        return None
    cl_size, reserved = struct.unpack_from("<II", stub, offset)
    vt = struct.unpack_from("<H", stub, offset + 8)[0]
    switch = struct.unpack_from("<I", stub, offset + 16)[0]
    if reserved != 0 or switch != vt or not 1 <= cl_size <= 8192:
        return None
    base = vt & 0x0FFF
    if vt & 0x6000 or (base not in _VT_NAMES):
        if vt & 0x2000 and base in _VT_NAMES:
            # SAFEARRAY: report the type, do not walk the array.
            return vt, f"<{vartype_name(vt)}>", offset + 20
        return None
    arm = offset + 20
    if base in (0, 1):
        return vt, ("<empty>" if base == 0 else "NULL"), arm
    if base == 8:  # BSTR: unique pointer -> FLAGGED_WORD_BLOB
        if arm + 4 > len(stub):
            return None
        referent = struct.unpack_from("<I", stub, arm)[0]
        if referent == 0:
            return vt, '""', arm + 4
        blob = arm + 4
        if blob + 12 > len(stub):
            return None
        max_count, byte_len, char_count = struct.unpack_from("<III", stub, blob)
        if char_count > max_count or char_count > 65536 or byte_len > char_count * 2:
            return None
        start = blob + 12
        end = start + char_count * 2
        if end > len(stub):
            return None
        text = stub[start:start + byte_len].decode("utf-16-le", errors="replace")
        return vt, repr(text), end
    fmt, size = _VT_FIXED[base]
    pos = arm
    if size == 8:
        pos += (-pos) % 8
    if pos + size > len(stub):
        return None
    raw = struct.unpack_from(fmt, stub, pos)[0]
    if base == 11:
        text = "TRUE" if raw != 0 else "FALSE"
    elif base == 6:
        text = _format_number(raw / 10000.0)
    elif base == 7:
        try:
            text = (_OLE_EPOCH + timedelta(days=float(raw))).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, ValueError):
            text = _format_number(raw)
    elif base == 10:
        text = f"SCODE 0x{raw:08x}"
    elif base in (4, 5):
        text = _format_number(float(raw))
    else:
        text = str(int(raw))
    return vt, text, pos + size


def scan_variants(stub: bytes, start: int = 0, limit: int = 4096) -> list[tuple[int, str]]:
    """Every ``wireVARIANT`` in ``stub`` from ``start``, in order."""
    found: list[tuple[int, str]] = []
    pos = start + ((-start) % 4)
    end = len(stub) - 20
    while pos <= end and len(found) < limit:
        decoded = _decode_variant_at(stub, pos)
        if decoded is None:
            pos += 4
            continue
        vt, text, next_pos = decoded
        found.append((vt, text))
        pos = max(pos + 4, next_pos + ((-next_pos) % 4))
    return found


def scan_wstrings(stub: bytes, start: int = 0, limit: int = 512) -> list[str]:
    """Every NDR conformant-varying UTF-16 string (NUL-terminated) in order."""
    found: list[str] = []
    pos = start + ((-start) % 4)
    while pos + 14 <= len(stub) and len(found) < limit:
        max_count, offset, actual = struct.unpack_from("<III", stub, pos)
        if offset == 0 and 1 <= actual <= max_count <= 4096:
            end = pos + 12 + actual * 2
            if end <= len(stub) and stub[end - 2:end] == b"\x00\x00":
                raw = stub[pos + 12:end - 2]
                text = raw.decode("utf-16-le", errors="replace")
                if text == "" or all(ch.isprintable() for ch in text):
                    found.append(text)
                    pos = end + ((-end) % 4)
                    continue
        pos += 4
    return found


# --------------------------------------------------------------------------
# DCE/RPC over TCP
# --------------------------------------------------------------------------

_PTYPE_REQUEST = 0
_PTYPE_RESPONSE = 2
_PTYPE_FAULT = 3
_PTYPE_BIND = 11
_PTYPE_BIND_ACK = 12
_PTYPE_ALTER = 14
_PTYPE_ALTER_RESP = 15
_VALID_PTYPES = set(range(0, 21))
_SERVER_PTYPES = {2, 3, 12, 13, 15}
_PFC_FIRST = 0x01
_PFC_LAST = 0x02
_PFC_OBJECT = 0x80
_MAX_STREAMS = 4096
_MAX_BUFFER = 1 << 20
_MAX_STUB = 4 << 20
_EVENT_CAP = 5000


def _dcerpc_from_server(payload: bytes) -> bool:
    if len(payload) < 3 or payload[0] != 5:
        return False
    return payload[2] in _SERVER_PTYPES


def _looks_like_pdu_start(data: bytes) -> bool:
    if len(data) < 16 or data[0] != 5 or data[1] not in (0, 1):
        return False
    if data[2] not in _VALID_PTYPES or data[4] & 0xEF not in (0x00,):
        return False
    little = bool(data[4] & 0x10)
    frag_len = struct.unpack_from("<H" if little else ">H", data, 8)[0]
    auth_len = struct.unpack_from("<H" if little else ">H", data, 10)[0]
    return frag_len >= 16 + auth_len


class _Direction:
    __slots__ = ("buffer", "next_seq", "synced")

    def __init__(self) -> None:
        self.buffer = b""
        self.next_seq: int | None = None
        self.synced = False


def _feed(state: _Direction, seq: int, payload: bytes) -> list[bytes]:
    """Append one TCP segment and return the complete PDUs now available."""
    if state.next_seq is not None:
        delta = relative_seq(seq, state.next_seq)
        if delta < 0:  # retransmission or overlap
            overlap = -delta
            if overlap >= len(payload):
                return []
            payload = payload[overlap:]
            seq = state.next_seq
        elif delta > 0:  # bytes missing: drop the partial PDU, resync
            state.buffer = b""
            state.synced = False
    state.next_seq = (seq + len(payload)) % (1 << 32)
    if not state.synced:
        if not _looks_like_pdu_start(payload):
            return []
        state.synced = True
        state.buffer = b""
    state.buffer += payload
    pdus: list[bytes] = []
    while len(state.buffer) >= 16:
        head = state.buffer
        if not _looks_like_pdu_start(head):
            state.buffer = b""
            state.synced = False
            break
        little = bool(head[4] & 0x10)
        frag_len = struct.unpack_from("<H" if little else ">H", head, 8)[0]
        if len(head) < frag_len:
            break
        pdus.append(head[:frag_len])
        state.buffer = head[frag_len:]
    if len(state.buffer) > _MAX_BUFFER:
        state.buffer = b""
        state.synced = False
    return pdus


@dataclass
class _Call:
    iface: OpcInterface | None
    iid: str
    opnum: int
    operation: str
    client: str
    server: str
    ts: float | None
    stub: bytes = b""
    request_info: dict[str, object] = field(default_factory=dict)
    response_stub: bytes = b""


def _opc_classic_prefilter(record: LitePacket) -> bool:
    """Only TCP segments with payload feed the DCE/RPC tracker; the rest
    count toward the capture totals alone."""
    l4 = record.lite_l4()
    if l4 is UNSUPPORTED:
        return True
    return l4 is not None and l4[0] and (l4[5] < 0 or l4[6] > l4[5])


def _canonical_conn(src: str, sport: int, dst: str, dport: int) -> tuple:
    a = (src, sport)
    b = (dst, dport)
    return (a, b) if a <= b else (b, a)


# --------------------------------------------------------------------------
# Analyzer
# --------------------------------------------------------------------------


@memoize_analysis
def analyze_opc_classic(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> OpcClassicSummary:
    if TCP is None:
        return OpcClassicSummary(
            path, 0, 0, Counter(), Counter(), Counter(), [],
            ["Scapy TCP unavailable"], None, None, None,
        )

    total_packets = 0
    opc_packets = 0
    interface_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    operation_counts: Counter[str] = Counter()
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    directions: "OrderedDict[tuple, _Direction]" = OrderedDict()
    contexts: dict[tuple, dict[int, str]] = defaultdict(dict)
    pending_binds: dict[tuple, list[int]] = {}
    pending_calls: dict[tuple, _Call] = {}
    partial_requests: dict[tuple, bytearray] = {}
    partial_responses: dict[tuple, bytearray] = {}
    opc_connections: set[tuple] = set()

    items: dict[str, OpcItem] = {}
    server_handles: dict[tuple[str, str], dict[int, str]] = defaultdict(dict)
    client_handles: dict[tuple[str, str], dict[int, str]] = defaultdict(dict)
    writes: list[OpcValueEvent] = []
    reads: list[OpcValueEvent] = []
    updates: list[OpcValueEvent] = []
    group_names: Counter[str] = Counter()
    client_names: Counter[str] = Counter()
    server_progids: Counter[str] = Counter()
    browse_names: list[str] = []
    browse_seen: set[str] = set()
    unattributed: Counter[str] = Counter()
    faults: Counter[str] = Counter()
    browse_ops = 0
    enum_ops = 0
    hda_modify: Counter[str] = Counter()
    ae_suppress: Counter[str] = Counter()
    command_events: list[object] = []
    service_endpoints: dict[str, Counter[str]] = {}
    marker_only_packets = 0
    pdu_count = 0

    def _item(pair: tuple[str, str], name: str) -> OpcItem:
        entry = items.get(name)
        if entry is None:
            entry = OpcItem(item_id=name, client=pair[0], server=pair[1])
            items[name] = entry
        return entry

    def _item_name(table: dict[int, str], handle: int) -> str:
        return table.get(handle) or f"handle {handle}"

    def _record_value(
        bucket: list[OpcValueEvent], kind: str, call: _Call, ts: float | None,
        pair: tuple[str, str], name: str, vt: int, text: str,
    ) -> None:
        entry = _item(pair, name)
        if kind == "write":
            entry.writes += 1
        elif kind == "read":
            entry.reads += 1
        else:
            entry.updates += 1
        entry.last_value = text
        if text not in entry.values and len(entry.values) < 20:
            entry.values.append(text)
        if len(bucket) < _EVENT_CAP:
            bucket.append(
                OpcValueEvent(ts, pair[0], pair[1], call.operation, name, text, vartype_name(vt))
            )

    def _add_browse(names: list[str]) -> None:
        for name in names:
            if name and name not in browse_seen and len(browse_names) < 2000:
                browse_seen.add(name)
                browse_names.append(name)

    def _decode_request(call: _Call, pair: tuple[str, str], ts: float | None) -> None:
        nonlocal browse_ops, enum_ops
        iface = call.iface
        if iface is None:
            return
        name = iface.name
        method = iface.method(call.opnum)
        stub = call.stub
        body = _request_body(stub)
        try:
            if name in ("IOPCItemMgt",) and method in ("AddItems", "ValidateItems") and body:
                count = body.u32()
                if body.u32() != count or count > 65536:
                    raise _NdrError("bad OPCITEMDEF array")
                defs = []
                for _ in range(count):
                    access_ptr, item_ptr = body.u32(), body.u32()
                    _active, h_client, _blob_size, blob_ptr = (
                        body.u32(), body.u32(), body.u32(), body.u32()
                    )
                    req_vt = body.u16()
                    body.u16()
                    defs.append([access_ptr, item_ptr, h_client, blob_ptr, req_vt, "", ""])
                for entry in defs:
                    if entry[0]:
                        entry[5] = body.wstring()
                        body.align(4)
                    if entry[1]:
                        entry[6] = body.wstring()
                        body.align(4)
                    if entry[3]:
                        body.skip(body.u32())
                        body.align(4)
                call.request_info["items"] = [
                    (str(e[6]), str(e[5]), int(e[2])) for e in defs
                ]
                for item_id, access, _h in call.request_info["items"]:  # type: ignore[union-attr]
                    if item_id:
                        entry = _item(pair, item_id)
                        if access:
                            entry.access_path = access
                return
            if name == "IOPCItemMgt" and method == "SetClientHandles" and body:
                # Re-keys callbacks: OnDataChange names items by *client*
                # handle, so a stale table attributes updates to the wrong item.
                count = body.u32()
                server_list = body.handles()
                client_list = body.handles()
                if len(server_list) == count == len(client_list):
                    by_server = server_handles[pair]
                    table = client_handles[pair]
                    for h_server, h_client in zip(server_list, client_list):
                        item_id = by_server.get(h_server)
                        if item_id:
                            table[h_client] = item_id
                            items[item_id].client_handle = h_client
                return
            if method in ("Read", "Write", "WriteVQT", "ReadMaxAge") and name in (
                "IOPCSyncIO", "IOPCSyncIO2", "IOPCAsyncIO", "IOPCAsyncIO2", "IOPCAsyncIO3",
            ) and body:
                if name == "IOPCAsyncIO":
                    body.u32()  # dwConnection
                if method == "Read" and name in ("IOPCSyncIO", "IOPCSyncIO2", "IOPCAsyncIO"):
                    body.u16()  # OPCDATASOURCE
                count = body.u32()
                handles = body.handles()
                if len(handles) != count:
                    raise _NdrError("handle count mismatch")
                call.request_info["handles"] = handles
                if method in ("Write", "WriteVQT"):
                    values = scan_variants(stub, body.pos)
                    table = server_handles[pair]
                    for handle, (vt, text) in zip(handles, values):
                        _record_value(
                            writes, "write", call, ts, pair,
                            _item_name(table, handle), vt, text,
                        )
                    if len(values) < len(handles):
                        for handle in handles[len(values):]:
                            _item(pair, _item_name(table, handle)).writes += 1
                return
            if name == "IOPCItemIO" and body:
                count = body.u32()
                ids = scan_wstrings(stub, body.pos, limit=count or 1)
                if method == "WriteVQT":
                    values = scan_variants(stub, body.pos)
                    for item_id, (vt, text) in zip(ids, values):
                        _record_value(writes, "write", call, ts, pair, item_id, vt, text)
                else:
                    for item_id in ids:
                        _item(pair, item_id).reads += 1
                return
            if name == "IOPCDataCallback" and method in ("OnDataChange", "OnReadComplete") and body:
                for _ in range(4):  # transid, hGroup, hrMasterquality, hrMastererror
                    body.u32()
                count = body.u32()
                handles = body.handles()
                if len(handles) != count:
                    raise _NdrError("handle count mismatch")
                values = scan_variants(stub, body.pos)
                table = client_handles[pair]
                bucket = updates if method == "OnDataChange" else reads
                kind = "update" if method == "OnDataChange" else "read"
                for handle, (vt, text) in zip(handles, values):
                    _record_value(bucket, kind, call, ts, pair, _item_name(table, handle), vt, text)
                return
            if name == "IOPCServer" and method in ("AddGroup", "GetGroupByName") and body:
                group = body.wstring()
                if group:
                    group_names[group] += 1
                return
            if name == "IOPCCommon" and method == "SetClientName" and body:
                client = body.wstring()
                if client:
                    client_names[client] += 1
                return
            if name in ("IOPCBrowseServerAddressSpace", "IOPCBrowse", "IOPCItemProperties",
                        "IOPCHDA_Browser"):
                browse_ops += 1
                _add_browse(scan_wstrings(stub, _ORPCTHIS_LEN))
                return
            if iface.family == "Enum":
                enum_ops += 1
                if method == "CLSIDFromProgID":
                    for text in scan_wstrings(stub, _ORPCTHIS_LEN, limit=1):
                        if text:
                            server_progids[text] += 1
                return
            if name in ("IOPCHDA_SyncUpdate", "IOPCHDA_AsyncUpdate") and method not in (
                "QueryCapabilities", "Cancel"
            ):
                hda_modify[method] += 1
                return
            if name == "IOPCEventServer" and method in (
                "DisableConditionByArea", "DisableConditionBySource", "AckCondition"
            ):
                ae_suppress[method] += 1
                return
        except (_NdrError, struct.error):
            return

    def _decode_response(call: _Call, pair: tuple[str, str], ts: float | None) -> None:
        iface = call.iface
        if iface is None:
            return
        name = iface.name
        method = iface.method(call.opnum)
        stub = call.response_stub
        body = _response_body(stub)
        try:
            if name == "IOPCItemMgt" and method == "AddItems" and body:
                requested = list(call.request_info.get("items") or [])
                results: list[tuple[int, int, int]] = []
                if body.u32():
                    count = body.u32()
                    if count > 65536:
                        raise _NdrError("bad OPCITEMRESULT array")
                    blob_ptrs = []
                    for _ in range(count):
                        h_server = body.u32()
                        vt = body.u16()
                        body.u16()
                        rights = body.u32()
                        body.u32()
                        blob_ptrs.append(body.u32())
                        results.append((h_server, vt, rights))
                    for ptr in blob_ptrs:
                        if ptr:
                            body.skip(body.u32())
                            body.align(4)
                errs: list[int] = []
                if body.u32():
                    errs = body.handles()
                for index, (item_id, _access, h_client) in enumerate(requested):
                    if index >= len(results) or not item_id:
                        continue
                    if index < len(errs) and errs[index] & 0x80000000:
                        continue
                    h_server, vt, rights = results[index]
                    server_handles[pair][h_server] = item_id
                    client_handles[pair][h_client] = item_id
                    entry = _item(pair, item_id)
                    entry.server_handle = h_server
                    entry.client_handle = h_client
                    entry.canonical_type = vartype_name(vt)
                    entry.access_rights = {1: "R", 2: "W", 3: "RW"}.get(rights & 3, "-")
                return
            if name in ("IOPCSyncIO", "IOPCSyncIO2") and method in ("Read", "ReadMaxAge"):
                handles = list(call.request_info.get("handles") or [])
                values = scan_variants(stub, _ORPCTHAT_LEN)
                table = server_handles[pair]
                for handle, (vt, text) in zip(handles, values):
                    _record_value(reads, "read", call, ts, pair, _item_name(table, handle), vt, text)
                return
            if name == "IOPCItemIO" and method == "Read":
                values = scan_variants(stub, _ORPCTHAT_LEN)
                for vt, text in values:
                    _record_value(reads, "read", call, ts, pair, "(by item ID)", vt, text)
                return
            if iface.family == "Enum" and method == "GetClassDetails":
                # ProgID, user type (and, for IOPCServerList2, the
                # version-independent ProgID): the first string names the server.
                for text in scan_wstrings(stub, _ORPCTHAT_LEN, limit=1):
                    if text:
                        server_progids[text] += 1
                return
            if name in ("IOPCBrowseServerAddressSpace", "IOPCBrowse", "IOPCItemProperties",
                        "IOPCHDA_Browser", "IEnumString"):
                _add_browse(scan_wstrings(stub, _ORPCTHAT_LEN))
                return
        except (_NdrError, struct.error):
            return

    # Read from disk, only TCP segments with payload are handed over (the
    # totals come from the pass), as lite records parsed from their bytes.
    stats = PassStats()
    for pkt in iter_packets(
        path,
        packets=packets,
        meta=meta,
        show_status=show_status,
        lite=True,
        prefilter=_opc_classic_prefilter,
        stats=stats,
    ):
        total_packets += 1
        lite = pkt.lite_l4() if type(pkt) is LitePacket else UNSUPPORTED
        if lite is None or (lite is not UNSUPPORTED and (not lite[0] or lite[5] >= 0)):  # type: ignore[index]
            # The packet's only transport layer, its payload a Raw layer.
            if lite is None or not lite[0]:  # type: ignore[index]
                continue
            payload = pkt.original[lite[5] : lite[6]]  # type: ignore[index]
            if not payload:
                continue
            sport, dport, seq = lite[1], lite[2], lite[3]  # type: ignore[index]
        else:
            if type(pkt) is LitePacket:
                pkt = pkt.materialize()
            if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue
            tcp = pkt[TCP]  # type: ignore[index]
            # Without stripping, scapy hands back the Ethernet padding of a short
            # ACK as six zero "payload" bytes at the ACK's sequence number; fed to
            # the reassembler they corrupt the next real PDU.
            payload = _strip_padding(tcp.payload)
            if not payload:
                continue
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            seq = int(getattr(tcp, "seq", 0) or 0)
        ts = safe_float(getattr(pkt, "time", None))
        src_ip, dst_ip = extract_packet_endpoints(pkt)
        if not src_ip or not dst_ip:
            continue
        key = (src_ip, sport, dst_ip, dport)
        state = directions.get(key)
        if state is None and _looks_like_pdu_start(payload):
            # Only connections that start (or resynchronise) on a DCE/RPC
            # header are tracked; everything else costs one header check.
            state = _Direction()
            directions[key] = state
            if len(directions) > _MAX_STREAMS:
                directions.popitem(last=False)
        elif state is not None:
            directions.move_to_end(key)
        if state is None and payload[:1] != b"\x05":
            continue
        pdus: list[bytes] = []
        if state is not None:
            try:
                pdus = _feed(state, seq, payload)
            except Exception as exc:  # noqa: BLE001 - one bad segment must not end the pass
                errors.append(f"DCE/RPC reassembly: {type(exc).__name__}: {exc}")
                continue

        conn = _canonical_conn(src_ip, sport, dst_ip, dport)
        packet_is_opc = False
        for pdu in pdus:
            pdu_count += 1
            if pdu[4] & 0x10 == 0:
                continue  # big-endian NDR: not decoded
            ptype = pdu[2]
            flags = pdu[3]
            frag_len, auth_len, call_id = struct.unpack_from("<HHI", pdu, 8)
            body_end = frag_len - (auth_len + 8 if auth_len else 0)
            call_key = (conn, call_id)

            if ptype in (_PTYPE_BIND, _PTYPE_ALTER) and len(pdu) >= 28:
                n_ctx = pdu[24]
                pos = 28
                order: list[int] = []
                for _ in range(n_ctx):
                    if pos + 24 > len(pdu):
                        break
                    ctx_id = struct.unpack_from("<H", pdu, pos)[0]
                    n_syntax = pdu[pos + 2]
                    iid = str(uuid.UUID(bytes_le=pdu[pos + 4:pos + 20]))
                    contexts[conn][ctx_id] = iid
                    order.append(ctx_id)
                    iface = lookup_interface(iid)
                    if iface is not None:
                        interface_counts[iface.display] += 1
                        packet_is_opc = True
                        opc_connections.add(conn)
                    pos += 24 + 20 * n_syntax
                pending_binds[call_key] = order
                continue

            if ptype in (_PTYPE_BIND_ACK, _PTYPE_ALTER_RESP):
                order = pending_binds.pop(call_key, [])
                if ptype == _PTYPE_BIND_ACK and len(pdu) >= 26:
                    sec_len = struct.unpack_from("<H", pdu, 24)[0]
                    pos = 26 + sec_len
                else:
                    pos = 24 + 2  # alter_context_resp: empty secondary address
                    if len(pdu) >= 26:
                        sec_len = struct.unpack_from("<H", pdu, 24)[0]
                        pos = 26 + sec_len
                pos += (-pos) % 4
                if pos + 4 <= len(pdu):
                    n_results = pdu[pos]
                    pos += 4
                    for index in range(n_results):
                        if pos + 24 > len(pdu):
                            break
                        result = struct.unpack_from("<H", pdu, pos)[0]
                        if result != 0 and index < len(order):
                            contexts[conn].pop(order[index], None)
                        pos += 24
                continue

            if ptype == _PTYPE_REQUEST and len(pdu) >= 24:
                ctx_id, opnum = struct.unpack_from("<HH", pdu, 20)
                stub_start = 24 + (16 if flags & _PFC_OBJECT else 0)
                fragment = pdu[stub_start:body_end]
                if not flags & _PFC_LAST or not flags & _PFC_FIRST:
                    buf = partial_requests.setdefault(call_key, bytearray())
                    if flags & _PFC_FIRST:
                        buf.clear()
                    if len(buf) + len(fragment) <= _MAX_STUB:
                        buf.extend(fragment)
                    if not flags & _PFC_LAST:
                        continue
                    fragment = bytes(partial_requests.pop(call_key, b""))
                iid = contexts.get(conn, {}).get(ctx_id, "")
                iface = lookup_interface(iid) if iid else None
                if iface is None and iid == IENUMSTRING_IID and conn in opc_connections:
                    iface = _ENUM_STRING
                if iface is None:
                    if not iid and conn in opc_connections:
                        unattributed[f"context {ctx_id} opnum {opnum}"] += 1
                    continue
                packet_is_opc = True
                operation = f"{iface.name}::{iface.method(opnum)}"
                operation_counts[operation] += 1
                interface_counts[iface.display] += 1
                # A callback interface is invoked by the OPC server on the
                # client, so the request's sender is the server.
                if iface.callback:
                    opc_client, opc_server = dst_ip, src_ip
                else:
                    opc_client, opc_server = src_ip, dst_ip
                client_counts[opc_client] += 1
                server_counts[opc_server] += 1
                endpoints = service_endpoints.setdefault(operation, Counter())
                endpoints[f"{src_ip} -> {dst_ip}"] += 1
                if len(command_events) < _EVENT_CAP:
                    command_events.append(
                        IndustrialCommandEvent(ts=ts or 0.0, src=src_ip, dst=dst_ip, command=operation)
                    )
                call = _Call(iface, iid, opnum, operation, opc_client, opc_server, ts, stub=fragment)
                pair = (opc_client, opc_server)
                _decode_request(call, pair, ts)
                call.stub = b""  # decoded; keep only what the response needs
                pending_calls[call_key] = call
                continue

            if ptype in (_PTYPE_RESPONSE, _PTYPE_FAULT) and len(pdu) >= 24:
                call = pending_calls.get(call_key)
                if call is None:
                    continue
                packet_is_opc = True
                if ptype == _PTYPE_FAULT:
                    pending_calls.pop(call_key, None)
                    status = struct.unpack_from("<I", pdu, 24)[0] if len(pdu) >= 28 else 0
                    faults[f"{call.operation} (status 0x{status:08x})"] += 1
                    continue
                fragment = pdu[24:body_end]
                if not flags & _PFC_LAST or not flags & _PFC_FIRST:
                    buf = partial_responses.setdefault(call_key, bytearray())
                    if flags & _PFC_FIRST:
                        buf.clear()
                    if len(buf) + len(fragment) <= _MAX_STUB:
                        buf.extend(fragment)
                    if not flags & _PFC_LAST:
                        continue
                    fragment = bytes(partial_responses.pop(call_key, b""))
                pending_calls.pop(call_key, None)
                call.response_stub = fragment
                _decode_response(call, (call.client, call.server), ts)
                call.response_stub = b""
                continue

        if not packet_is_opc:
            # Interface IDs carried outside a bind (DCOM activation asks for
            # them by IID): count the reference, attribute the endpoints.
            matched = False
            for marker, iid in _MARKER_LOOKUP.items():
                if marker in payload:
                    interface_counts[OPC_INTERFACES[iid].display] += 1
                    matched = True
            if not matched:
                continue
            marker_only_packets += 1
            if _dcerpc_from_server(payload):
                client_counts[dst_ip] += 1
                server_counts[src_ip] += 1
            else:
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1

        opc_packets += 1
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts
    if stats.active:
        total_packets = stats.packets

    write_text = _ascii_from_values([event.value for event in writes])
    detections = _build_detections(
        opc_packets=opc_packets,
        operation_counts=operation_counts,
        writes=writes,
        browse_ops=browse_ops,
        enum_ops=enum_ops,
        server_progids=server_progids,
        hda_modify=hda_modify,
        ae_suppress=ae_suppress,
        client_counts=client_counts,
        server_counts=server_counts,
        unattributed=unattributed,
        write_text=write_text,
    )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return OpcClassicSummary(
        path=path,
        total_packets=total_packets,
        opc_packets=opc_packets,
        interface_counts=interface_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        detections=detections,
        errors=errors[:20],
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
        operation_counts=operation_counts,
        items=items,
        writes=writes,
        reads=reads,
        updates=updates,
        group_names=group_names,
        client_names=client_names,
        server_progids=server_progids,
        browse_names=browse_names,
        unattributed_requests=unattributed,
        faults=faults,
        write_value_text=write_text,
        commands=Counter(operation_counts),
        command_events=command_events,
        service_endpoints=service_endpoints,
    )


def _ascii_from_values(values: list[str]) -> str:
    """Written integers that are all printable ASCII codes, as text.

    CTF-style captures hide a string in a run of single-character writes;
    real process writes almost never form a printable run of 4+.
    """
    chars: list[str] = []
    for value in values:
        try:
            number = int(value)
        except ValueError:
            return "".join(chars) if len(chars) >= 4 else ""
        if 32 <= number <= 126:
            chars.append(chr(number))
        else:
            return "".join(chars) if len(chars) >= 4 else ""
    return "".join(chars) if len(chars) >= 4 else ""


def _build_detections(
    *,
    opc_packets: int,
    operation_counts: Counter[str],
    writes: list[OpcValueEvent],
    browse_ops: int,
    enum_ops: int,
    server_progids: Counter[str],
    hda_modify: Counter[str],
    ae_suppress: Counter[str],
    client_counts: Counter[str],
    server_counts: Counter[str],
    unattributed: Counter[str],
    write_text: str,
) -> list[dict[str, object]]:
    detections: list[dict[str, object]] = []
    if not opc_packets:
        return detections

    top_ops = ", ".join(f"{op} x{n}" for op, n in operation_counts.most_common(6))
    detections.append(
        {
            "severity": "info",
            "summary": "OPC Classic (DCOM) traffic observed",
            "details": (
                f"{opc_packets} packets on OPC Classic interfaces"
                + (f"; operations: {top_ops}" if top_ops else "")
                + (
                    f"; {sum(unattributed.values())} request(s) on contexts bound "
                    "before the capture started (interface unknown)"
                    if unattributed
                    else ""
                )
                + "."
            ),
            "top_sources": client_counts.most_common(5),
            "top_destinations": server_counts.most_common(5),
        }
    )

    if writes:
        writers = Counter(event.client for event in writes)
        evidence = [
            f"{event.client} -> {event.server} {event.operation}: {event.item} = {event.value} ({event.vartype})"
            for event in writes[:10]
        ]
        if write_text:
            evidence.insert(0, f"written values as ASCII: {write_text!r}")
        detections.append(
            {
                "severity": "high",
                "summary": "OPC DA item writes (process values changed over DCOM)",
                "details": (
                    f"{len(writes)} item write(s) from {len(writers)} client(s); "
                    "confirm each writer is an authorised HMI/engineering host "
                    "(ATT&CK for ICS T0855 Unauthorized Command Message, "
                    "T0836 Modify Parameter)."
                ),
                "top_sources": writers.most_common(5),
                "evidence": evidence,
            }
        )

    if browse_ops:
        detections.append(
            {
                "severity": "warning" if browse_ops >= 50 else "info",
                "summary": "OPC address-space browsing (tag enumeration)",
                "details": (
                    f"{browse_ops} browse/property request(s): a client walked the "
                    "server's item tree (ATT&CK for ICS T0861 Point & Tag Identification)."
                ),
            }
        )

    if enum_ops:
        progids = ", ".join(name for name, _n in server_progids.most_common(6))
        detections.append(
            {
                "severity": "info",
                "summary": "OPC server enumeration via OPCEnum",
                "details": (
                    f"{enum_ops} IOPCServerList request(s)"
                    + (f"; servers named: {progids}" if progids else "")
                    + " (ATT&CK for ICS T0888 Remote System Information Discovery)."
                ),
            }
        )

    if hda_modify:
        detections.append(
            {
                "severity": "high",
                "summary": "OPC HDA history modified (insert/replace/delete)",
                "details": (
                    "Historian data changed through IOPCHDA_SyncUpdate/AsyncUpdate: "
                    + ", ".join(f"{m} x{n}" for m, n in hda_modify.most_common())
                    + " (ATT&CK for ICS T0872 Indicator Removal on Host)."
                ),
            }
        )

    if ae_suppress:
        disables = sum(n for m, n in ae_suppress.items() if m.startswith("Disable"))
        detections.append(
            {
                "severity": "high" if disables else "warning",
                "summary": "OPC A&E alarm conditions disabled or acknowledged",
                "details": (
                    ", ".join(f"{m} x{n}" for m, n in ae_suppress.most_common())
                    + " (ATT&CK for ICS T0878 Alarm Suppression)."
                ),
            }
        )

    public = sorted(
        ip for ip in set(client_counts) | set(server_counts) if is_public_ip(ip)
    )
    if public:
        detections.append(
            {
                "severity": "high",
                "summary": "OPC Classic (DCOM) exposed to a public IP",
                "details": (
                    "DCOM/OPC traffic with public endpoint(s): "
                    + ", ".join(public[:6])
                    + " (ATT&CK for ICS T0883 Internet Accessible Device)."
                ),
            }
        )
    return detections
