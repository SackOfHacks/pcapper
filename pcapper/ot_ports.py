"""Canonical OT/ICS port -> protocol-label map.

Single source of truth shared by hostname.py (OT host/role detection) and
timeline.py (event categorisation). Kept as a dependency-free leaf module of
literal port numbers so it can be imported from anywhere without circular
imports (industrial_helpers / the protocol modules import each other, so this
map cannot live there). Labels are display strings only -- no logic branches on
their exact value.
"""

from __future__ import annotations

OT_PORT_PROTOCOLS: dict[int, str] = {
    102: "S7",
    502: "Modbus",
    1217: "CODESYS",
    1502: "Triconex/SIS",
    1911: "Niagara Fox",
    1962: "PCWorx",
    2221: "CIP Security",
    2222: "CIP",
    2404: "IEC-104",
    2455: "CODESYS",
    4840: "OPC UA",
    4911: "Niagara Fox",
    5006: "MELSEC",
    5007: "MELSEC",
    5094: "HART-IP",
    5683: "CoAP",
    5684: "CoAP",
    9600: "FINS",
    18245: "SRTP",
    18246: "SRTP",
    20000: "DNP3",
    20547: "ProConOS",
    34962: "PROFINET",
    34963: "PROFINET",
    34964: "PROFINET",
    44818: "ENIP",
    47808: "BACnet",
}
