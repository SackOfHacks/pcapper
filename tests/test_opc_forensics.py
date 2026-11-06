from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.opc import (
    OPC_UA_SERVICE_NAMES,
    _is_opcua_message,
    _parse_opcua,
    analyze_opc,
)


def _opcua_message(service_id: int, namespace: int = 0) -> bytes:
    node_id = b"\x01" + bytes((namespace,)) + service_id.to_bytes(2, "little")
    payload = b"MSGF" + b"\x00" * 4 + b"\x00" * 16 + node_id
    return payload[:4] + len(payload).to_bytes(4, "little") + payload[8:]


def test_service_ids_use_standard_binary_encodings() -> None:
    assert OPC_UA_SERVICE_NAMES[428] == "GetEndpointsRequest"
    assert OPC_UA_SERVICE_NAMES[461] == "CreateSessionRequest"
    assert OPC_UA_SERVICE_NAMES[464] == "CreateSessionResponse"
    assert OPC_UA_SERVICE_NAMES[712] == "CallRequest"
    assert OPC_UA_SERVICE_NAMES[751] == "CreateMonitoredItemsRequest"
    assert OPC_UA_SERVICE_NAMES[787] == "CreateSubscriptionRequest"
    assert 459 not in OPC_UA_SERVICE_NAMES
    assert 704 not in OPC_UA_SERVICE_NAMES


def test_nonzero_namespace_service_nodeid_is_not_misclassified() -> None:
    commands, artifacts = _parse_opcua(_opcua_message(712, namespace=1))

    assert "CallRequest" not in commands
    assert ("opcua_service", "ns=1;i=712") in artifacts


def test_opcua_signature_classifies_nonstandard_tcp_port(tmp_path) -> None:
    payload = _opcua_message(712)
    assert _is_opcua_message(payload)

    capture = tmp_path / "opcua_nonstandard_port.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=12001)
            / Raw(load=payload)
        ],
    )

    result = analyze_opc(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["CallRequest"] == 1


def test_opcua_signature_rejects_malformed_headers() -> None:
    assert not _is_opcua_message(b"MSGF")
    assert not _is_opcua_message(b"MSGF" + b"\x07\x00\x00\x00")
    assert not _is_opcua_message(b"MSG?" + b"\x08\x00\x00\x00")
