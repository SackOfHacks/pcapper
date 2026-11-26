"""Canonical OT/ICS port -> protocol-label map.

Single source of truth for every module that names or classes OT/ICS ports:
hostname.py (OT host/role detection), timeline.py (event categorisation),
services.py (service names and the OT service set), hosts.py, beacon.py,
exfil.py, remote_access.py and baseline_profile.py. Kept as a dependency-free
leaf module of literal port numbers so it can be imported from anywhere without
circular imports (industrial_helpers / the protocol modules import each other,
so this map cannot live there). Labels are display strings only -- no logic
branches on their exact value.

Every port an OT analyzer decodes as that protocol belongs here, with that
analyzer's label. Left out on purpose: UDP/1234 (bsap.py claims it by port
alone, with no frame check, and it is the default port of IPTV/VLC multicast
streams), TCP/10001 (genisys.py matches the Genisys frame on any port; 10001
is not Genisys-specific), 1500-1501 (safety.py counts Triconex TSAA by port
without decoding it) and MQTT 1883/8883 (IoT messaging, not OT).
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
    # CODESYS V3 gateway/runtime (codesys.py CODESYS_TCP_PORTS / _UDP_PORTS).
    1740: "CODESYS",
    1741: "CODESYS",
    1742: "CODESYS",
    1743: "CODESYS",
    11740: "CODESYS",
    11741: "CODESYS",
    11742: "CODESYS",
    11743: "CODESYS",
    # IEEE C37.118 PMU/PDC frames (synchrophasor.py SYNCHROPHASOR_PORTS).
    4712: "Synchrophasor",
    4713: "Synchrophasor",
    # HART-IP UDP handover port (hart.py HART_UDP_HANDOVER_PORT).
    5095: "HART-IP",
    # MELSOFT engineering connection, decoded by melsec.py (UDP 5560, TCP 5562).
    5560: "MELSEC",
    5562: "MELSEC",
}

# Registry ports whose protocol is not specific to OT networks. PTP (IEEE
# 1588) also times data-centre, trading, broadcast and telecom networks and
# Windows hosts; CoAP is a general IoT protocol (baseline_profile classes it as
# IoT). Port sets derived from the registry subtract what does not fit the
# question they answer -- see services._OT_SERVICE_PORTS, beacon.OT_PORTS.
PTP_PORTS = frozenset({319, 320})
COAP_PORTS = frozenset({5683, 5684})


def foreign_service_reply(sport: int, server_ports) -> bool:
    """A reply from another service: the source is a well-known or OT
    service port that is not one of ``server_ports``, so a destination equal
    to one of them is the peer's ephemeral port by coincidence -- a Modbus
    slave on 502 answering a master whose source port is 2222, 3671 or 20000
    is not EtherNet/IP, KNXnet/IP or DNP3."""
    return sport not in server_ports and (sport < 1024 or sport in OT_PORT_PROTOCOLS)
