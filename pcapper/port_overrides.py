"""Decode-as: analyse a protocol on a port it does not normally use.

OT protocols are routinely moved off their registered ports: a PLC reached
through a NAT/port-forward (MAPNA CTF 2024: S7comm on tcp/10203), an ICS
honeypot, a vendor gateway, a lab. Every analyzer here selects its traffic by
port, so on a moved port it reports nothing at all.

This module is the registry the analyzers consult. Entries come from two
places: the user (``--decode-as tcp/10203=s7``, also accepting tshark's
``tcp.port==10203,s7comm`` form) and the payload-structure detector in
:mod:`pcapper.port_heuristics`, which only registers a port when the
protocol's own framing checks out on most of the port's packets. It is a
dependency-free leaf so any analyzer can import it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# User-facing protocol tokens (pcapper flag names, tshark dissector names and
# common spellings) -> the analyzer steps that should look at the port. TPKT
# carries both S7 and IEC 61850 MMS/ICCP; each analyzer validates its own
# payload, so registering all of them is safe.
PROTOCOL_ALIASES: dict[str, tuple[str, ...]] = {
    "s7": ("s7",),
    "s7comm": ("s7",),
    "s7comm-plus": ("s7",),
    "s7comm_plus": ("s7",),
    "tpkt": ("s7", "mms", "iccp"),
    "cotp": ("s7", "mms", "iccp"),
    "mms": ("mms",),
    "iec61850": ("mms",),
    "iccp": ("iccp",),
    "tase2": ("iccp",),
    "modbus": ("modbus",),
    "mbtcp": ("modbus",),
    "modbus-tcp": ("modbus",),
    "umas": ("modbus", "modicon"),
    "modicon": ("modicon",),
    "dnp3": ("dnp3",),
    "dnp": ("dnp3",),
    "iec104": ("iec104",),
    "iec-104": ("iec104",),
    "iec60870_104": ("iec104",),
    "104apci": ("iec104",),
    "104asdu": ("iec104",),
    "enip": ("enip", "cip"),
    "ethernet/ip": ("enip", "cip"),
    "cip": ("cip", "enip"),
    "bacnet": ("bacnet",),
    "bvlc": ("bacnet",),
    "opc": ("opc",),
    "opcua": ("opc",),
    "opc-ua": ("opc",),
    "fins": ("fins",),
    "omron-fins": ("fins",),
    "melsec": ("melsec",),
    "slmp": ("melsec",),
    "hart": ("hart",),
    "hartip": ("hart",),
    "hart-ip": ("hart",),
    "niagara": ("niagara",),
    "fox": ("niagara",),
    "codesys": ("codesys",),
    "mqtt": ("mqtt",),
    "coap": ("coap",),
    "synchrophasor": ("synchrophasor",),
    "synphasor": ("synchrophasor",),
    "c37118": ("synchrophasor",),
    "srtp": ("srtp",),
    "gesrtp": ("srtp",),
    "pcworx": ("pcworx",),
    "crimson": ("crimson",),
    "profinet": ("profinet",),
    "pn_io": ("profinet",),
    "tristation": ("safety",),
    "triconex": ("safety",),
    "safety": ("safety",),
    "knx": ("knx",),
    "knxip": ("knx",),
    "knxnetip": ("knx",),
    "kip": ("knx",),
    "xgt": ("xgt",),
    "fenet": ("xgt",),
    "roc": ("rocplus",),
    "rocplus": ("rocplus",),
    "roc-plus": ("rocplus",),
    "ads": ("ads",),
    "ams": ("ads",),
    "dlms": ("dlms",),
    "cosem": ("dlms",),
    "c1222": ("c1222",),
    "c12.22": ("c1222",),
    "lontalk": ("lontalk",),
    "cnip": ("lontalk",),
    "lon": ("lontalk",),
    "rgoose": ("goose",),
    "r-goose": ("goose",),
    "rsv": ("sv",),
    "r-sv": ("sv",),
}

_SPEC_PATTERNS = (
    # tcp/10203=s7   udp/4000=roc
    re.compile(r"^(?P<proto>tcp|udp)/(?P<port>\d{1,5})=(?P<name>[\w.+/-]+)$", re.I),
    # tcp.port==10203,s7comm   (tshark -d syntax)
    re.compile(r"^(?P<proto>tcp|udp)\.port==?(?P<port>\d{1,5}),(?P<name>[\w.+/-]+)$", re.I),
    # tcp.port=10203:s7
    re.compile(r"^(?P<proto>tcp|udp)\.port=(?P<port>\d{1,5}):(?P<name>[\w.+/-]+)$", re.I),
    # 10203=s7 (both transports)
    re.compile(r"^(?P<port>\d{1,5})=(?P<name>[\w.+/-]+)$", re.I),
)


@dataclass(frozen=True)
class PortOverride:
    transport: str  # "tcp" or "udp"
    port: int
    step: str
    origin: str  # "user" or "auto: <basis>"
    # "" applies to every capture (--decode-as); otherwise the resolved path
    # of the one capture whose payloads proved the port (auto-detection), so
    # a port proven in one file is never forced onto another in a batch.
    scope: str = ""

    def describe(self) -> str:
        return f"{self.transport}/{self.port} as {self.step} ({self.origin})"


# Ports a protocol is *registered* on but that the port-based analyzers do
# not claim (the protocol is found by payload structure anywhere): an
# auto-detection there is not a "non-standard port".
STANDARD_PORTS: dict[str, frozenset[tuple[str, int]]] = {
    "goose": frozenset({("udp", 102)}),  # IEC 61850-90-5 R-GOOSE session protocol
}


def is_standard(override: "PortOverride") -> bool:
    return (override.transport, override.port) in STANDARD_PORTS.get(override.step, frozenset())


_OVERRIDES: dict[tuple[str, int, str, str], PortOverride] = {}
_GENERATION = 0


def scope_key(path: object) -> str:
    from pathlib import Path

    try:
        return str(Path(str(path)).expanduser().resolve())
    except OSError:
        return str(path)


class DecodeAsError(ValueError):
    pass


def parse_decode_as(spec: str) -> list[tuple[str, int, tuple[str, ...]]]:
    """``[(transport, port, steps), ...]`` for one ``--decode-as`` value."""
    text = str(spec or "").strip()
    for pattern in _SPEC_PATTERNS:
        match = pattern.match(text)
        if not match:
            continue
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            raise DecodeAsError(f"port out of range in --decode-as {spec!r}")
        name = match.group("name").lower()
        steps = PROTOCOL_ALIASES.get(name)
        if steps is None:
            known = ", ".join(sorted({key for key in PROTOCOL_ALIASES}))
            raise DecodeAsError(
                f"unknown protocol {name!r} in --decode-as {spec!r}; known: {known}"
            )
        proto = match.groupdict().get("proto")
        transports = (proto.lower(),) if proto else ("tcp", "udp")
        return [(transport, port, steps) for transport in transports]
    raise DecodeAsError(
        f"cannot parse --decode-as {spec!r}; use tcp/PORT=PROTO "
        "(e.g. tcp/10203=s7), tcp.port==PORT,PROTO or PORT=PROTO"
    )


def register(
    transport: str,
    port: int,
    step: str,
    origin: str = "user",
    scope: object | None = None,
) -> PortOverride:
    global _GENERATION
    scope_text = scope_key(scope) if scope is not None else ""
    key = (transport.lower(), int(port), step, scope_text)
    existing = _OVERRIDES.get(key)
    if existing is not None:
        return existing
    override = PortOverride(transport.lower(), int(port), step, origin, scope_text)
    _OVERRIDES[key] = override
    _GENERATION += 1
    return override


def register_spec(spec: str, origin: str = "user") -> list[PortOverride]:
    registered = []
    for transport, port, steps in parse_decode_as(spec):
        for step in steps:
            registered.append(register(transport, port, step, origin))
    return registered


def extra_ports(
    step: str | None, transport: str, path: object | None = None
) -> frozenset[int]:
    """Ports registered for ``step`` on ``transport`` beyond its defaults:
    every --decode-as entry, plus auto-detected ports of capture ``path``."""
    if not step or not _OVERRIDES:
        return frozenset()
    transport = transport.lower()
    scope = scope_key(path) if path is not None else None
    return frozenset(
        override.port
        for override in _OVERRIDES.values()
        if override.transport == transport
        and override.step == step
        and (not override.scope or override.scope == scope)
    )


def overrides(path: object | None = None) -> list[PortOverride]:
    """Overrides in effect (for ``path``: global ones plus its own)."""
    scope = scope_key(path) if path is not None else None
    selected = [
        o for o in _OVERRIDES.values()
        if not o.scope or path is None or o.scope == scope
    ]
    return sorted(selected, key=lambda o: (o.transport, o.port, o.step, o.scope))


def overrides_for_port(transport: str, port: int, path: object | None = None) -> list[PortOverride]:
    transport = transport.lower()
    return [o for o in overrides(path) if o.transport == transport and o.port == port]


def generation() -> int:
    """Changes whenever the registry does; part of the analysis memo key."""
    return _GENERATION


def clear() -> None:
    global _GENERATION
    if _OVERRIDES:
        _OVERRIDES.clear()
        _GENERATION += 1
