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
    319: "PTP Event",
    320: "PTP General",
    502: "Modbus",
    789: "Crimson",
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
    5313: "Yokogawa Vnet/IP",
    55565: "Honeywell CDA",
    5683: "CoAP",
    5684: "CoAP",
    9600: "FINS",
    18245: "SRTP",
    18246: "SRTP",
    20000: "DNP3",
    20547: "ProConOS",
    34378: "P-NET",
    34379: "P-NET",
    34380: "P-NET",
    34962: "PROFINET",
    34963: "PROFINET",
    34964: "PROFINET",
    44818: "ENIP",
    47808: "BACnet",
    1153: "C12.22",
    1628: "LonTalk CN/IP",
    1629: "LonTalk CN/IP",
    2004: "XGT FEnet",
    2005: "XGT FEnet",
    3671: "KNXnet/IP",
    3819: "POWERLINK",
    4000: "ROC Plus",
    4059: "DLMS/COSEM",
    48898: "ADS/AMS",
    48899: "ADS/AMS",
}


def foreign_service_reply(sport: int, server_ports) -> bool:
    """A reply from another service: the source is a well-known or OT
    service port that is not one of ``server_ports``, so a destination equal
    to one of them is the peer's ephemeral port by coincidence -- a Modbus
    slave on 502 answering a master whose source port is 2222, 3671 or 20000
    is not EtherNet/IP, KNXnet/IP or DNP3."""
    return sport not in server_ports and (sport < 1024 or sport in OT_PORT_PROTOCOLS)
