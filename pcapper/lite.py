"""Lightweight packets: transport fields read straight from the capture bytes.

scapy dissects every layer of every packet it reads, about 150 µs per packet
on a typical OT capture, and an analyzer that only needs ports, endpoints and
the TCP/UDP payload pays all of it. A :class:`LitePacket` holds the raw record
(bytes, link type, timestamp, pcapng metadata) and answers three questions by
parsing a few header bytes itself:

* the transport record (TCP/UDP, ports, sequence number, flags, payload),
* the endpoints :func:`pcapper.utils.extract_packet_endpoints` reports,
* the EtherType view ``_match_ethertype`` uses for L2 OT protocols.

Every answer is the one scapy would give. Which class scapy builds for a
payload (DNS on udp/53, TLS on tcp/443, Dot3 for an 802.3 length field, a
tunnel that hides an inner TCP header ...) is resolved by scapy's own binding
tables, once per key, and anything the parser does not reproduce exactly --
IP options, IPv6 extension headers, tunnels, ICMP errors, truncated headers,
non-Ethernet link types it does not know, payloads scapy dissects into a
non-``Raw`` layer -- is answered by the real scapy packet instead.

That packet is built on demand (:meth:`LitePacket.materialize`) exactly as
scapy's capture readers build it (same class, bytes, ``time``, ``wirelen``
and pcapng comments/direction/interface/process information), and any
attribute the lite packet does not define is read from it. Code that was
handed a lite packet and uses scapy's API on it therefore still sees scapy's
answers; it only stops being fast.
"""

from __future__ import annotations

import socket
import struct
import threading
import time as _time
from decimal import Decimal
from typing import Optional

try:  # pragma: no cover - exercised whenever scapy is installed
    from scapy.config import conf
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, CookedLinux, Dot1AD, Dot1Q, Ether, Loopback, LoopbackOpenBSD
    from scapy.packet import Packet, Raw
    from scapy.utils import EDecimal

    try:
        from scapy.layers.l2 import CookedLinuxV2
    except Exception:  # older scapy
        CookedLinuxV2 = None  # type: ignore[assignment, misc]
    _SCAPY = True
except Exception:  # pragma: no cover - scapy missing
    _SCAPY = False
    conf = None  # type: ignore[assignment]
    Packet = Raw = IP = IPv6 = TCP = UDP = ICMP = ARP = Ether = None  # type: ignore[assignment, misc]
    Dot1Q = Dot1AD = CookedLinux = CookedLinuxV2 = None  # type: ignore[assignment, misc]
    Loopback = LoopbackOpenBSD = None  # type: ignore[assignment, misc]
    EDecimal = Decimal  # type: ignore[assignment, misc]

__all__ = [
    "LitePacket",
    "UNSUPPORTED",
    "is_lite",
    "lite_available",
    "refresh_bindings",
]


class _Unsupported:
    """Sentinel: the lite parser cannot answer exactly; ask scapy."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNSUPPORTED"


UNSUPPORTED = _Unsupported()

# Timestamp powers exactly as scapy's PcapReader computes them.
_POW = {"us": Decimal(10) ** Decimal(-6), "ns": Decimal(10) ** Decimal(-9)}

# Serialises on-demand dissection when several threads share one lite packet
# (the shared analysis pass); scapy itself is not re-entrant per packet.
_MATERIALIZE_LOCK = threading.Lock()
# Set by pcap_cache.install_layer_memo(): the key under which a packet keeps
# its layer lookups. A packet built here is shared by every analysis of a
# shared pass and never modified, as one held in memory is.
LAYER_MEMO_KEY: Optional[str] = None


def lite_available() -> bool:
    return _SCAPY


def is_lite(pkt: object) -> bool:
    return type(pkt) is LitePacket


class LitePacket:
    """One capture record, dissected only when somebody needs scapy's view.

    ``original``/``wirelen``/``comments``/``direction``/``process_information``
    /``sniffed_on`` and ``time`` hold what scapy's reader would set on the
    packet it builds from this record.
    """

    __slots__ = (
        "original",
        "wirelen",
        "comments",
        "direction",
        "process_information",
        "sniffed_on",
        "_linktype",
        "_tspec",
        "_time",
        "_hdr",
        "_pkt",
        "_cache",
        "_pcapng",
        "_ep",
    )

    def __init__(
        self,
        data: bytes,
        linktype: int,
        tspec: tuple,
        wirelen: int,
        *,
        pcapng: bool = False,
        comments: object = None,
        direction: Optional[int] = None,
        process_information: Optional[dict] = None,
        sniffed_on: Optional[str] = None,
    ) -> None:
        self.original = data
        self.wirelen = wirelen
        self.comments = comments
        self.direction = direction
        self.process_information = process_information
        self.sniffed_on = sniffed_on
        self._linktype = linktype
        self._tspec = tspec
        self._time = None
        self._hdr = None
        self._pkt = None
        self._cache = None
        self._pcapng = pcapng
        self._ep = None

    # -- timestamp ---------------------------------------------------------
    @property
    def time(self):  # type: ignore[no-untyped-def]
        value = self._time
        if value is None:
            spec = self._tspec
            kind = spec[0]
            if kind == "ng":
                value = EDecimal(spec[1]) / spec[2]
            elif kind == "now":
                value = spec[1]
            else:
                value = EDecimal(spec[1] + _POW[kind] * spec[2])
            self._time = value
        return value

    @property
    def linktype(self) -> int:
        return self._linktype

    def sort_key(self) -> tuple:
        """Exact ordering key for the timestamp without building a Decimal."""
        spec = self._tspec
        kind = spec[0]
        if kind == "us":
            return (spec[1] * 1_000_000_000 + spec[2] * 1000, 1)
        if kind == "ns":
            return (spec[1] * 1_000_000_000 + spec[2], 1)
        if kind == "ng":
            return (spec[1], spec[2])
        return (spec[1], 0)

    # -- scapy fallback ----------------------------------------------------
    def materialize(self) -> object:
        """The scapy packet scapy's own reader would have produced."""
        pkt = self._pkt
        if pkt is not None:
            return pkt
        with _MATERIALIZE_LOCK:
            pkt = self._pkt
            if pkt is None:
                pkt = _build_scapy(self)
                memo_key = LAYER_MEMO_KEY
                if memo_key is not None:
                    store = getattr(pkt, "__dict__", None)
                    if store is not None:
                        store[memo_key] = (id(pkt), {})
                self._pkt = pkt
        return pkt

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        # Reached only for names that are not slots/properties above.
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return getattr(self.materialize(), name)

    def __bytes__(self) -> bytes:
        return bytes(self.materialize())  # type: ignore[call-overload]

    def __len__(self) -> int:
        return len(self.materialize())  # type: ignore[arg-type]

    def __getitem__(self, item):  # type: ignore[no-untyped-def]
        return self.materialize()[item]  # type: ignore[index]

    def __contains__(self, item) -> bool:  # type: ignore[no-untyped-def]
        return item in self.materialize()  # type: ignore[operator]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.materialize())  # type: ignore[call-overload]

    def __bool__(self) -> bool:
        return True

    def __repr__(self) -> str:
        return repr(self.materialize())

    def __str__(self) -> str:
        return str(self.materialize())

    def forget_derived(self) -> None:
        """Drop what was worked out under scapy's binding tables -- the header
        parse, endpoints, cached answers and the scapy packet -- so asked again
        it is worked out under the current ones, as for a record read now."""
        self._hdr = None
        self._ep = None
        self._cache = None
        self._pkt = None

    # -- fast answers --------------------------------------------------------
    def headers(self) -> tuple:
        """``(ether, l3, l4)`` offsets parsed once; formatted only on request."""
        hdr = self._hdr
        if hdr is None:
            if _BINDINGS is None:
                refresh_bindings()
            try:
                hdr = _parse(self.original, self._linktype)
            except Exception:  # noqa: BLE001 - any surprise means "ask scapy"
                hdr = _ALL_UNSUPPORTED
            self._hdr = hdr
        return hdr

    def lite_ports(self):  # type: ignore[no-untyped-def]
        """``(is_tcp, sport, dport, ...)`` / ``None`` (no TCP/UDP) / UNSUPPORTED,
        without building the payload."""
        return self.headers()[2]

    def lite_l4(self):  # type: ignore[no-untyped-def]
        """:meth:`lite_ports` when that layer is the packet's only TCP/UDP
        layer, so ``getlayer(TCP)`` and ``getlayer(UDP)`` both answer from it
        (the one that does not match finds nothing); UNSUPPORTED when an IPv4
        TCP payload scapy dissects further could hide another one."""
        hdr = self.headers()
        l4 = hdr[2]
        if l4 is None or l4 is UNSUPPORTED or l4[5] >= 0 or not l4[0]:
            return l4
        return l4 if _nothing_below(hdr) else UNSUPPORTED

    def lite_transport(self):  # type: ignore[no-untyped-def]
        """``(is_tcp, sport, dport, seq, flags, payload)`` / ``None`` / UNSUPPORTED.

        ``payload`` is the padding-stripped transport payload, or ``None`` when
        scapy would dissect it into a non-``Raw`` layer (ask scapy for it).
        ``seq``/``flags`` are ``None`` for UDP.
        """
        l4 = self.headers()[2]
        if l4 is None or l4 is UNSUPPORTED:
            return l4
        start = l4[5]
        payload = None if start < 0 else self.original[start : l4[6]]
        return (l4[0], l4[1], l4[2], l4[3], l4[4], payload)

    def lite_payload(self) -> Optional[bytes]:
        """Transport payload, or None when only scapy can produce it."""
        l4 = self.headers()[2]
        if l4 is None or l4 is UNSUPPORTED or l4[5] < 0:
            return None
        return self.original[l4[5] : l4[6]]

    def lite_endpoints(self, include_arp: bool = True):  # type: ignore[no-untyped-def]
        l3 = self.headers()[1]
        if l3 is UNSUPPORTED:
            return UNSUPPORTED
        if l3 is None:
            return (None, None)
        kind = l3[0]
        if kind == 1 and not include_arp:
            return (None, None)
        endpoints = self._ep
        if endpoints is None:
            data, off = self.original, l3[1]
            if kind == 4:
                endpoints = (_inet_ntoa(data[off : off + 4]), _inet_ntoa(data[off + 4 : off + 8]))
            elif kind == 6:
                endpoints = (_ntop6(data[off : off + 16]), _ntop6(data[off + 16 : off + 32]))
            else:  # ARP: psrc, then pdst 10 bytes on (past hwdst)
                endpoints = (_inet_ntoa(data[off : off + 4]), _inet_ntoa(data[off + 10 : off + 14]))
            self._ep = endpoints
        return endpoints

    def lite_ether(self, ethertype: int):  # type: ignore[no-untyped-def]
        """``_match_ethertype`` answer: ``(src, dst, payload)`` / ``None`` / UNSUPPORTED."""
        hdr = self.headers()
        ether = hdr[0]
        if ether is None:
            # No outer Ethernet header; getlayer(Ether) would still find one
            # tunnelled further in (GRE/TEB, VXLAN ...) in a cooked or raw-IP
            # capture, so "none" stands only when every layer is accounted for.
            return None if _nothing_below(hdr) else UNSUPPORTED
        if ether is UNSUPPORTED:
            return ether
        final_type, payload_offset = ether
        if final_type is UNSUPPORTED:
            return UNSUPPORTED
        if final_type != ethertype:
            return None
        if payload_offset < 0:
            return UNSUPPORTED
        data = self.original
        return (_mac(data, 6), _mac(data, 0), data[payload_offset:])

    def lite_first_ether(self):  # type: ignore[no-untyped-def]
        """``getlayer(Ether)`` without walking VLAN tags: ``(type, src, dst,
        payload_offset)`` of the first Ethernet layer (``payload_offset`` -1
        when scapy dissects its payload into a non-Raw layer), ``None`` when
        the packet has none, UNSUPPORTED when only scapy can tell."""
        if self._linktype != 1:
            return None if _nothing_below(self.headers()) else UNSUPPORTED
        if _BINDINGS is None:
            refresh_bindings()
        data = self.original
        if len(data) < 14:
            return UNSUPPORTED
        etype = (data[12] << 8) | data[13]
        if etype <= 1500:  # Ether.dispatch_hook -> Dot3
            return UNSUPPORTED
        cls = _ETHER_NEXT.get(etype) or _ether_next(etype)
        return (etype, _mac(data, 6), _mac(data, 0), 14 if cls is _RAW else -1)

    def cache(self) -> dict:
        store = self._cache
        if store is None:
            store = self._cache = {}
        return store


def _build_scapy(lite: LitePacket) -> object:
    data = lite.original
    cls = conf.l2types.num2layer.get(lite._linktype)
    try:
        if cls is None:
            raise KeyError(lite._linktype)
        pkt = cls(data)
    except KeyboardInterrupt:
        raise
    except Exception:
        if conf.debug_dissector:
            raise
        pkt = conf.raw_layer(data)
    pkt.time = lite.time
    pkt.wirelen = lite.wirelen
    if lite._pcapng:
        pkt.comments = lite.comments
        pkt.direction = lite.direction
        info = lite.process_information
        pkt.process_information = info.copy() if isinstance(info, dict) else info
        if lite.sniffed_on is not None:
            pkt.sniffed_on = lite.sniffed_on
    return pkt


def _mac(data: bytes, offset: int) -> str:
    return ":".join("%02x" % b for b in data[offset : offset + 6])


# ---------------------------------------------------------------------------
# Binding resolution: which class does scapy build next?  Asked of scapy's
# own guess_payload_class on a template instance, memoised per integer key
# and dropped whenever scapy's binding tables change (refresh_bindings).
# ---------------------------------------------------------------------------

_ALL_UNSUPPORTED = (UNSUPPORTED, UNSUPPORTED, UNSUPPORTED)
_L3L4_UNSUPPORTED = (UNSUPPORTED, UNSUPPORTED)
_VLAN_TYPES = frozenset((0x8100, 0x88A8, 0x9100))  # industrial_helpers._VLAN_ETHERTYPES
_TERMINAL: dict[object, bool] = {}
_ETHER_NEXT: dict[int, object] = {}
_VLAN_NEXT: dict[int, object] = {}
_IP_NEXT: dict[int, object] = {}
_SLL_NEXT: dict[int, object] = {}
_LOOP_NEXT: dict[tuple, object] = {}
_APP_NEXT: dict[tuple, object] = {}
_MEMOS = (_TERMINAL, _ETHER_NEXT, _VLAN_NEXT, _IP_NEXT, _SLL_NEXT, _LOOP_NEXT, _APP_NEXT)
_DYNAMIC_HOOKS = (
    "guess_payload_class",
    "default_payload_class",
    "dispatch_hook",
    "do_dissect_payload",
    "dissect",
)


def _dynamic(cls: object) -> bool:
    """A class whose next layer (or own class) depends on the bytes."""
    for hook in _DYNAMIC_HOOKS:
        for base in cls.__mro__:  # type: ignore[attr-defined]
            if hook in base.__dict__:
                if base is not Packet:
                    return True
                break
    return False


def _transport_classes() -> frozenset:
    names = [IP, IPv6, TCP, UDP, ARP, Ether, Dot1Q, Dot1AD, CookedLinux]
    if CookedLinuxV2 is not None:
        names.append(CookedLinuxV2)
    return frozenset(names)


def _terminal(cls: object, _seen: Optional[set] = None) -> bool:
    """True when nothing scapy can build below ``cls`` is an exact IP, IPv6,
    TCP, UDP, ARP or Ethernet layer (so the outer answers stand)."""
    cached = _TERMINAL.get(cls)
    if cached is not None:
        return cached
    seen = _seen if _seen is not None else set()
    if cls in seen:
        return True
    seen.add(cls)
    result = True
    if cls is Raw or cls is conf.raw_layer or cls is conf.padding_layer:
        result = True
    elif cls in _TRANSPORT_SET or _dynamic(cls):
        result = False
    else:
        for alias in getattr(cls, "aliastypes", ()) or ():
            for _fields, child in getattr(alias, "payload_guess", ()) or ():
                if not _terminal(child, seen):
                    result = False
                    break
            if not result:
                break
    if _seen is None:
        _TERMINAL[cls] = result
    return result


def _port_index(cls: object) -> Optional[frozenset]:
    """Ports named by ``cls``'s bindings, or None when a binding keys on
    anything else (then every pair is resolved through scapy)."""
    ports: set[int] = set()
    for alias in cls.aliastypes:  # type: ignore[attr-defined]
        for fields, _child in alias.payload_guess:
            if not fields or set(fields) - {"sport", "dport"}:
                return None
            ports.update(int(v) for v in fields.values())
    return frozenset(ports)


if _SCAPY:
    _TRANSPORT_SET = _transport_classes()
    _RAW = conf.raw_layer
    _ICMP_ERRORS = frozenset((3, 4, 5, 11, 12))
else:  # pragma: no cover
    _TRANSPORT_SET = frozenset()
    _RAW = None
    _ICMP_ERRORS = frozenset()
_TCP_PORTS: Optional[frozenset] = None
_UDP_PORTS: Optional[frozenset] = None
_IPV6_DIRECT = False  # IPv6 next-header 6/17 always builds TCP/UDP
_BINDINGS: Optional[tuple] = None


def _binding_signature() -> tuple:
    classes = (
        Packet, Ether, Dot1Q, Dot1AD, IP, IPv6, TCP, UDP, ARP,
        CookedLinux, CookedLinuxV2, Loopback, LoopbackOpenBSD,
    )
    sizes = tuple(len(getattr(cls, "payload_guess", ()) or ()) for cls in classes if cls is not None)
    return sizes + (len(conf.layers),)


def refresh_bindings() -> None:
    """Re-read scapy's binding tables when they changed (a layer module such
    as TLS bound itself after this module was imported). Called before each
    pass; every memoised answer is dropped with the old tables."""
    global _TCP_PORTS, _UDP_PORTS, _IPV6_DIRECT, _BINDINGS
    if not _SCAPY:
        return
    signature = _binding_signature()
    if signature == _BINDINGS:
        return
    for memo in _MEMOS:
        memo.clear()
    _TCP_PORTS = None if _dynamic(TCP) else _port_index(TCP)
    _UDP_PORTS = None if _dynamic(UDP) else _port_index(UDP)
    probe = b"\x00" * 48
    _IPV6_DIRECT = (
        IPv6(nh=6).guess_payload_class(probe) is TCP
        and IPv6(nh=17).guess_payload_class(probe) is UDP
    )
    _BINDINGS = signature


def _ether_next(etype: int) -> object:
    cls = _ETHER_NEXT[etype] = Ether(type=etype).guess_payload_class(b"")
    return cls


def _vlan_next(owner: object, vtype: int, key: int) -> object:
    cls = _VLAN_NEXT[key] = owner(type=vtype).guess_payload_class(b"")  # type: ignore[operator]
    return cls


def _ip_next(proto: int, frag: int, key: int) -> object:
    cls = _IP_NEXT[key] = IP(proto=proto, frag=frag).guess_payload_class(b"")
    return cls


def _sll_next(owner: object, proto: int, key: int) -> object:
    cls = _SLL_NEXT[key] = owner(proto=proto).guess_payload_class(b"")  # type: ignore[operator]
    return cls


def _loopback_next(linktype: int, data: bytes) -> object:
    """The layer scapy builds after a BSD loopback header (linktype 0 or
    108), its family decoded by scapy's own field (on Linux only the first of
    the four bytes counts, and only Linux's AF_INET6 value names IPv6)."""
    owner = conf.l2types.num2layer.get(linktype)
    if owner is None or _dynamic(owner):
        return UNSUPPORTED
    field = owner.fields_desc[0]
    family = field.m2i(None, field.struct.unpack_from(data, 0)[0])
    key = (linktype, family)
    cls = _LOOP_NEXT.get(key)
    if cls is None:
        cls = _LOOP_NEXT[key] = owner(**{field.name: family}).guess_payload_class(b"")
    return cls


def _app_class(is_tcp: bool, sport: int, dport: int) -> object:
    ports = _TCP_PORTS if is_tcp else _UDP_PORTS
    if ports is not None:
        # Only ports some binding names can matter: every other port
        # collapses to -1 (matches nothing), which keeps the memo bounded by
        # the bound ports instead of growing with every ephemeral port.
        sport = sport if sport in ports else -1
        dport = dport if dport in ports else -1
        if sport == -1 and dport == -1:
            return _RAW
    key = (is_tcp, sport, dport)
    cls = _APP_NEXT.get(key)
    if cls is None:
        owner = TCP if is_tcp else UDP
        cls = _APP_NEXT[key] = owner(sport=sport, dport=dport).guess_payload_class(b"")  # type: ignore[misc]
    return cls


def _nothing_below(hdr: tuple) -> bool:
    """True when no exact IP/IPv6/TCP/UDP/ARP/Ethernet layer can sit below
    the headers parsed into ``hdr`` (its ``(ether, l3, l4)``)."""
    l3, l4 = hdr[1], hdr[2]
    if l3 is UNSUPPORTED or l4 is UNSUPPORTED:
        return False
    if l4 is None or l4[5] >= 0:
        return True
    # A non-Raw payload layer: UDP and IPv6-TCP ones were checked terminal
    # while parsing; an IPv4-TCP one is checked here.
    return _terminal(_app_class(l4[0], l4[1], l4[2]))


_TCP_UNPACK = struct.Struct("!HHI4xBB").unpack_from
_UDP_UNPACK = struct.Struct("!HHH").unpack_from
_inet_ntoa = socket.inet_ntoa


def _ntop6(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)


def _parse(data: bytes, linktype: int) -> tuple:
    """``(ether, l3, l4)`` for one record.

    * ether: None (no Ethernet layer) / UNSUPPORTED / ``(type, payload_off)``,
      the EtherType ``_match_ethertype`` ends on and where its Raw payload
      starts (-1: scapy dissects it further)
    * l3: None (no IP/IPv6/ARP layer) / UNSUPPORTED / ``(4|6|1, offset)``,
      IPv4/IPv6/ARP and where the source address sits
    * l4: None (no TCP/UDP) / UNSUPPORTED /
      ``(is_tcp, sport, dport, seq, flags, payload_start, payload_end, body)``,
      ``payload_start`` -1 when scapy dissects the payload into a non-Raw
      layer; ``body`` is where the payload starts in the record either way
    """
    n = len(data)
    ether: object = None
    if linktype == 1:
        if n < 14:
            return _ALL_UNSUPPORTED
        etype = (data[12] << 8) | data[13]
        if etype <= 1500:  # Ether.dispatch_hook -> Dot3 (802.3 length field)
            return _ALL_UNSUPPORTED
        cls = _ETHER_NEXT.get(etype) or _ether_next(etype)
        off = 14
        depth = 0
        while cls is Dot1Q or cls is Dot1AD:
            if n < off + 4 or depth > 8:
                return _ALL_UNSUPPORTED
            vtype = (data[off + 2] << 8) | data[off + 3]
            if vtype <= 1500:  # Dot1Q length field -> LLC + padding split
                return _ALL_UNSUPPORTED
            key = vtype | (0x10000 if cls is Dot1AD else 0)
            cls = _VLAN_NEXT.get(key) or _vlan_next(cls, vtype, key)
            etype = vtype
            off += 4
            depth += 1
        # _match_ethertype walks VLAN tags by their ``type`` field; a VLAN
        # EtherType scapy left as Raw (0x9100) ends that walk at type 0.
        if etype in _VLAN_TYPES:
            ether = (0 if cls is _RAW else UNSUPPORTED, -1)
        else:
            ether = (etype, off if cls is _RAW else -1)
    elif linktype == 113:  # Linux cooked capture
        if n < 16:
            return _ALL_UNSUPPORTED
        proto = (data[14] << 8) | data[15]
        cls = _SLL_NEXT.get(proto) or _sll_next(CookedLinux, proto, proto)
        off = 16
    elif linktype == 276 and CookedLinuxV2 is not None:
        if n < 20:
            return _ALL_UNSUPPORTED
        proto = (data[0] << 8) | data[1]
        key = proto | 0x10000
        cls = _SLL_NEXT.get(key) or _sll_next(CookedLinuxV2, proto, key)
        off = 20
    elif linktype == 12 or linktype == 101:  # IPv46: version nibble picks
        if not n:
            return _ALL_UNSUPPORTED
        version = data[0] >> 4
        if version == 4:
            cls = IP
        elif version == 6:
            cls = IPv6
        else:
            return _ALL_UNSUPPORTED
        off = 0
    elif linktype == 0 or linktype == 108:  # BSD loopback: 4-byte address family
        if n < 4 or Loopback is None:
            return _ALL_UNSUPPORTED
        cls = _loopback_next(linktype, data)
        if cls is UNSUPPORTED:
            return _ALL_UNSUPPORTED
        off = 4
    elif linktype == 228:
        cls, off = IP, 0
    elif linktype == 229:
        cls, off = IPv6, 0
    else:
        return _ALL_UNSUPPORTED

    if cls is IP:
        l3, l4 = _parse_ipv4(data, off, n)
    elif cls is IPv6:
        l3, l4 = _parse_ipv6(data, off, n)
    elif cls is ARP:
        l3, l4 = _parse_arp(data, off, n), None
    elif cls is _RAW or _terminal(cls):
        l3, l4 = None, None
    else:
        l3, l4 = UNSUPPORTED, UNSUPPORTED
    return (ether, l3, l4)


def _parse_ipv4(data: bytes, off: int, n: int) -> tuple:
    if n < off + 20 or data[off] != 0x45:  # IPv4 without options, else scapy
        return _L3L4_UNSUPPORTED
    total = (data[off + 2] << 8) | data[off + 3]
    frag = ((data[off + 6] << 8) | data[off + 7]) & 0x1FFF
    proto = data[off + 9]
    l3 = (4, off + 12)
    start = off + 20
    # IP.extract_padding: payload is total length minus header, unless negative
    end = n if total < 20 else (off + total if off + total < n else n)
    key = proto | (frag << 8)
    nxt = _IP_NEXT.get(key) or _ip_next(proto, frag, key)
    if nxt is TCP:
        return (l3, _parse_tcp(data, start, end, False))
    if nxt is UDP:
        return (l3, _parse_udp(data, start, end))
    if nxt is ICMP:
        if start < end and data[start] in _ICMP_ERRORS:
            return (l3, UNSUPPORTED)  # quotes an inner IP header
        return (l3, None)
    if nxt is _RAW or _terminal(nxt):
        return (l3, None)
    return (l3, UNSUPPORTED)


def _parse_ipv6(data: bytes, off: int, n: int) -> tuple:
    if n < off + 40 or data[off] >> 4 != 6 or not _IPV6_DIRECT:
        return _L3L4_UNSUPPORTED
    plen = (data[off + 4] << 8) | data[off + 5]
    nh = data[off + 6]
    if plen == 0 and nh == 0:  # jumbogram
        return _L3L4_UNSUPPORTED
    start = off + 40
    end = start + plen if start + plen < n else n
    # extract_packet_endpoints looks for an IPv4 layer first: the IPv6
    # endpoints stand only when nothing below can be an IPv4 header.
    if nh == 6:
        l4 = _parse_tcp(data, start, end, True)
        if l4 is UNSUPPORTED:
            return _L3L4_UNSUPPORTED
    elif nh == 17:
        l4 = _parse_udp(data, start, end)
        if l4 is UNSUPPORTED:
            return _L3L4_UNSUPPORTED
    elif nh == 58:
        if start < end and (data[start] < 128 or data[start] == 137):
            return _L3L4_UNSUPPORTED  # ICMPv6 errors/redirects quote packets
        l4 = None
    elif nh == 59:
        l4 = None
    else:
        return _L3L4_UNSUPPORTED
    return ((6, off + 8), l4)


def _parse_tcp(data: bytes, start: int, end: int, need_terminal: bool) -> object:
    """``need_terminal``: the caller's endpoints (IPv6) are only right when no
    IPv4 header can be dissected out of the payload."""
    if end - start < 20:
        return UNSUPPORTED
    sport, dport, seq, offbyte, flagbyte = _TCP_UNPACK(data, start)
    doff = offbyte >> 4
    if doff < 5:
        return UNSUPPORTED
    body = start + doff * 4
    if body > end:
        return UNSUPPORTED
    ports = _TCP_PORTS
    if ports is not None and sport not in ports and dport not in ports:
        app = _RAW
    else:
        app = _app_class(True, sport, dport)
    if app is _RAW:
        pstart, pend = body, end
    elif need_terminal and not _terminal(app):
        return UNSUPPORTED
    else:
        pstart = pend = -1
    return (True, sport, dport, seq, ((offbyte & 1) << 8) | flagbyte, pstart, pend, body)


def _parse_udp(data: bytes, start: int, end: int) -> object:
    if end - start < 8:
        return UNSUPPORTED
    sport, dport, length = _UDP_UNPACK(data, start)
    ports = _UDP_PORTS
    if ports is not None and sport not in ports and dport not in ports:
        app = _RAW
    else:
        app = _app_class(False, sport, dport)
    if app is _RAW:
        # UDP.extract_padding: s[:len - 8], with Python slice semantics
        pstart = start + 8
        avail = end - pstart
        keep = length - 8
        if keep >= 0:
            size = keep if keep < avail else avail
        else:
            size = avail + keep if avail + keep > 0 else 0
        return (False, sport, dport, None, None, pstart, pstart + size, pstart)
    if _terminal(app):
        return (False, sport, dport, None, None, -1, -1, start + 8)
    return UNSUPPORTED  # a tunnel (VXLAN, L2TP ...) may hide a TCP header


def _parse_arp(data: bytes, off: int, n: int) -> object:
    if n < off + 28:
        return UNSUPPORTED
    if data[off + 2] != 0x08 or data[off + 3] != 0x00 or data[off + 4] != 6 or data[off + 5] != 4:
        return UNSUPPORTED
    return (1, off + 14)


def now_tspec() -> tuple:
    """Timestamp spec for a pcapng Simple Packet Block (no timestamp): scapy
    leaves such packets at their creation time."""
    return ("now", _time.time())
