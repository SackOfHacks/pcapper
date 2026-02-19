from __future__ import annotations

import unittest
from pathlib import Path

from pcapper.modbus import analyze_modbus
from pcapper.cip import analyze_cip
from pcapper.enip import analyze_enip
from pcapper.profinet import analyze_profinet
from pcapper.goose import analyze_goose
from pcapper.ethercat import analyze_ethercat

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "ot"


class TestOTFixtures(unittest.TestCase):
    def test_modbus_fixture(self) -> None:
        summary = analyze_modbus(FIXTURES / "modbus_rw.pcap", show_status=False)
        self.assertGreater(summary.modbus_packets, 0)
        self.assertTrue(any(a.title == "Modbus Unexpected Write Target" for a in summary.anomalies))
        self.assertTrue(any(msg.detail and "holding_register" in msg.detail for msg in summary.messages))

    def test_cip_fixture(self) -> None:
        summary = analyze_cip(FIXTURES / "cip_tag_rw.pcap", show_status=False)
        self.assertGreater(summary.cip_packets, 0)
        self.assertGreaterEqual(summary.cip_services.get("WriteTag", 0), 1)
        self.assertTrue(any(a.title == "CIP Unexpected Write Target" for a in summary.anomalies))
        self.assertTrue(any(art.kind == "tag" and art.detail == "MyTag" for art in summary.artifacts))

    def test_enip_fixture(self) -> None:
        summary = analyze_enip(FIXTURES / "cip_tag_rw.pcap", show_status=False)
        self.assertGreater(summary.enip_packets, 0)
        self.assertGreaterEqual(summary.cip_services.get("WriteTag", 0), 1)
        self.assertTrue(any(art.kind == "tag" and art.detail == "MyTag" for art in summary.artifacts))

    def test_profinet_fixture(self) -> None:
        summary = analyze_profinet(FIXTURES / "profinet_dcp.pcap", show_status=False)
        self.assertGreater(summary.protocol_packets, 0)
        self.assertTrue(any(a.title == "PROFINET DCP Set/Reset" for a in summary.anomalies))
        self.assertTrue(any(art.kind == "dcp_device_name" for art in summary.artifacts))
        self.assertTrue(any(art.kind == "alarm_type" for art in summary.artifacts))

    def test_goose_fixture(self) -> None:
        summary = analyze_goose(FIXTURES / "goose_sequence.pcap", show_status=False)
        self.assertGreater(summary.goose_packets, 0)
        self.assertTrue(any(item.get("summary") == "GOOSE Sequence Reset" for item in summary.detections))
        self.assertTrue(summary.sq_nums)

    def test_ethercat_fixture(self) -> None:
        summary = analyze_ethercat(FIXTURES / "ethercat_mailbox.pcap", show_status=False)
        self.assertGreater(summary.protocol_packets, 0)
        self.assertTrue(any("Mailbox FoE" in cmd for cmd in summary.commands))


if __name__ == "__main__":
    unittest.main()
