from pcapper.ot_ports import OT_PORT_PROTOCOLS
from pcapper.protocols import INDUSTRIAL_PORTS


def test_ot_port_registry_includes_industrial_ptp_and_crimson() -> None:
    assert OT_PORT_PROTOCOLS[319] == INDUSTRIAL_PORTS[319] == "PTP Event"
    assert OT_PORT_PROTOCOLS[320] == INDUSTRIAL_PORTS[320] == "PTP General"
    assert OT_PORT_PROTOCOLS[789] == INDUSTRIAL_PORTS[789] == "Crimson"


def test_codesys_port_labels_are_consistent() -> None:
    for port in (1217, 2455):
        assert OT_PORT_PROTOCOLS[port] == INDUSTRIAL_PORTS[port] == "CODESYS"
