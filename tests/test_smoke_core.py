from __future__ import annotations

import inspect
import io
import tomllib
import unittest
from collections import Counter
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pcapper
import pcapper.cli as cli
import pcapper.cip as cip
import pcapper.dnp3 as dnp3
import pcapper.enip as enip
import pcapper.exfil as exfil
import pcapper.industrial_helpers as industrial_helpers
import pcapper.modbus as modbus
import pcapper.protocols as protocols
import pcapper.arp as arp
import pcapper.dhcp as dhcp
import pcapper.beacon as beacon
import pcapper.hostname as hostname
import pcapper.netbios as netbios
import pcapper.reporting as reporting
import pcapper.threats as threats
from pcapper.search import SearchSummary


class _DummyStatus:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def update(self, _percent: int) -> None:
        return None

    def finish(self) -> None:
        return None


class _ReaderNoLen:
    def __init__(self) -> None:
        self.closed = False

    def __iter__(self):
        return iter(())

    def __len__(self):
        raise TypeError("length unavailable")

    def close(self) -> None:
        self.closed = True


class _LayerNode:
    def __init__(self, name: str, payload: object | None = None) -> None:
        self.name = name
        self.payload = payload


class _NoPayloadNode:
    name = "NoPayload"
    payload = None


class _ProtocolTestPacket(_LayerNode):
    def __contains__(self, _item: object) -> bool:
        return False

    def __len__(self) -> int:
        return 128


class _DummyReader:
    def __init__(self, packets: list[object]) -> None:
        self._packets = packets
        self.closed = False

    def __iter__(self):
        return iter(self._packets)

    def close(self) -> None:
        self.closed = True


class TestSmokeCore(unittest.TestCase):
    def test_version_consistency(self) -> None:
        pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["version"], pcapper.__version__)

    def test_cli_no_forced_preload_path(self) -> None:
        source = inspect.getsource(cli)
        self.assertNotIn("load_packets(", source)
        self.assertNotIn("def _patch_readers", source)

    def test_industrial_helpers_handles_reader_without_len(self) -> None:
        reader = _ReaderNoLen()
        with patch.object(industrial_helpers, "TCP", object()), patch.object(
            industrial_helpers,
            "get_reader",
            return_value=(reader, _DummyStatus(), None, 0, "pcap"),
        ):
            result = industrial_helpers.analyze_port_protocol(
                path=Path("dummy.pcap"),
                protocol_name="TEST",
                tcp_ports={1234},
                show_status=False,
            )
        self.assertTrue(reader.closed)
        self.assertEqual(result.errors, [])

    def test_cip_handles_reader_without_len(self) -> None:
        reader = _ReaderNoLen()
        with patch.object(cip, "TCP", object()), patch.object(
            cip, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")
        ):
            result = cip.analyze_cip(path=Path("dummy.pcap"), show_status=False)
        self.assertTrue(reader.closed)
        self.assertEqual(result.errors, [])

    def test_enip_handles_reader_without_len(self) -> None:
        reader = _ReaderNoLen()
        with patch.object(enip, "TCP", object()), patch.object(
            enip, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")
        ):
            result = enip.analyze_enip(path=Path("dummy.pcap"), show_status=False)
        self.assertTrue(reader.closed)
        self.assertEqual(result.errors, [])

    def test_render_enip_summary_omits_packet_payload_size_section(self) -> None:
        summary = enip.ENIPAnalysis(path=Path("dummy.pcap"))
        output = reporting.render_enip_summary(summary)
        self.assertNotIn("Packet/Payload Size Analysis", output)
        self.assertIn("Anomalies & Threats", output)

    def test_render_cip_summary_omits_packet_payload_size_section(self) -> None:
        summary = cip.CIPAnalysis(path=Path("dummy.pcap"))
        output = reporting.render_cip_summary(summary)
        self.assertNotIn("Packet/Payload Size Analysis", output)
        self.assertIn("Anomalies & Threats", output)

    def test_render_cip_summary_includes_command_risk_and_distribution(self) -> None:
        summary = cip.CIPAnalysis(path=Path("dummy.pcap"))
        summary.cip_services.update({"WriteTag": 12, "ReadTag": 8})
        summary.high_risk_services.update({"WriteTag": 12})
        summary.suspicious_services.update({"ReadTag": 8})
        summary.source_risky_commands.update({"10.0.0.10": 12})
        summary.server_error_responses.update({"10.0.0.20": 6})
        summary.service_error_counts.update({"WriteTag": 4})
        summary.packet_size_buckets = [
            cip.SizeBucket(label="80-159", count=10, avg=120.0, min=80, max=159, pct=50.0),
            cip.SizeBucket(label="160-319", count=10, avg=220.0, min=160, max=319, pct=50.0),
        ]
        summary.payload_size_buckets = [
            cip.SizeBucket(label="40-79", count=8, avg=60.0, min=40, max=79, pct=40.0),
            cip.SizeBucket(label="80-159", count=12, avg=110.0, min=80, max=159, pct=60.0),
        ]

        output = reporting.render_cip_summary(summary)

        self.assertIn("Command Risking Overview", output)
        self.assertIn("Top Risky Command Sources", output)
        self.assertIn("Error-Heavy Servers", output)
        self.assertIn("Error Responses by Service", output)
        self.assertNotIn("Traffic Size Distribution", output)
        self.assertNotIn("Packet/Payload Size Analysis", output)
        self.assertNotIn("Packet Size Buckets", output)
        self.assertNotIn("Payload Size Buckets", output)

    def test_merge_cip_summaries_includes_risk_and_error_counters(self) -> None:
        first = cip.CIPAnalysis(path=Path("one.pcap"))
        second = cip.CIPAnalysis(path=Path("two.pcap"))
        first.high_risk_services.update({"WriteTag": 3})
        second.high_risk_services.update({"WriteTag": 2})
        first.source_risky_commands.update({"10.0.0.10": 4})
        second.source_risky_commands.update({"10.0.0.10": 1, "10.0.0.11": 2})
        first.server_error_responses.update({"10.0.0.20": 3})
        second.server_error_responses.update({"10.0.0.20": 2})
        first.service_error_counts.update({"WriteTag": 2})
        second.service_error_counts.update({"WriteTag": 1, "ReadTag": 5})

        merged = cip.merge_cip_summaries([first, second])

        self.assertEqual(merged.high_risk_services["WriteTag"], 5)
        self.assertEqual(merged.source_risky_commands["10.0.0.10"], 5)
        self.assertEqual(merged.source_risky_commands["10.0.0.11"], 2)
        self.assertEqual(merged.server_error_responses["10.0.0.20"], 5)
        self.assertEqual(merged.service_error_counts["WriteTag"], 3)
        self.assertEqual(merged.service_error_counts["ReadTag"], 5)

    def test_analyze_cip_detects_control_command_burst(self) -> None:
        class _Pkt:
            def __init__(self, ts: float) -> None:
                self.time = ts

        packets = [_Pkt(float(i)) for i in range(30)]
        reader = _DummyReader(packets)

        with (
            patch.object(cip, "TCP", object()),
            patch.object(cip, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
            patch.object(
                cip,
                "_extract_transport",
                return_value=(True, "10.0.0.10", "10.0.0.20", 40000, cip.CIP_TCP_PORT, b"\x00"),
            ),
            patch.object(cip, "_parse_enip", return_value=(0x006F, "SendRRData", 0x00000000, b"\x00", False)),
            patch.object(
                cip,
                "_parse_cip_message",
                return_value=(0x4C, "WriteTag", True, None, None, 0x04, 1, 1, "Class:4/Instance:1/Attribute:1", b""),
            ),
        ):
            result = cip.analyze_cip(path=Path("dummy.pcap"), show_status=False)

        self.assertTrue(
            any(anomaly.title == "CIP Control Command Burst" for anomaly in result.anomalies)
        )

    def test_modbus_handles_reader_without_len(self) -> None:
        reader = _ReaderNoLen()
        with patch.object(modbus, "TCP", object()), patch.object(
            modbus, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")
        ):
            result = modbus.analyze_modbus(path=Path("dummy.pcap"), show_status=False)
        self.assertTrue(reader.closed)
        self.assertEqual(result.errors, [])

    def test_dnp3_handles_reader_without_len(self) -> None:
        reader = _ReaderNoLen()
        with patch.object(dnp3, "TCP", object()), patch.object(
            dnp3, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")
        ):
            result = dnp3.analyze_dnp3(path=Path("dummy.pcap"), show_status=False)
        self.assertTrue(reader.closed)
        self.assertEqual(result.errors, [])

    def test_threats_ot_presence_confident_rejects_weak_cip_enip_signal(self) -> None:
        weak = SimpleNamespace(
            cip_packets=1,
            requests=1,
            responses=0,
            sessions={},
            identities=[],
            enip_commands={},
            cip_services={},
            suspicious_services={},
            high_risk_services={},
            status_codes={},
            artifacts=[],
        )
        anomalies = [SimpleNamespace(title="Suspicious CIP Service", description="Stop observed", src="a", dst="b")]

        self.assertFalse(threats._ot_presence_confident("CIP", weak, anomalies))
        self.assertFalse(threats._ot_presence_confident("EtherNet/IP", weak, anomalies))

    def test_threats_ot_presence_confident_accepts_strong_cip_enip_signal(self) -> None:
        strong = SimpleNamespace(
            cip_packets=12,
            requests=8,
            responses=8,
            sessions={"1": 3, "2": 2},
            identities=[{"vendor": "x"}],
            enip_commands={"RegisterSession": 3, "SendRRData": 4},
            cip_services={"WriteTag": 4, "ReadTag": 4},
            suspicious_services={"WriteTag": 4},
            high_risk_services={"WriteTag": 4},
            status_codes={"Success": 8},
            artifacts=[object()],
        )
        anomalies = [SimpleNamespace(title="Suspicious CIP Service", description="Stop observed", src="a", dst="b")]

        self.assertTrue(threats._ot_presence_confident("CIP", strong, anomalies))
        self.assertTrue(threats._ot_presence_confident("EtherNet/IP", strong, anomalies))

    def test_threats_append_ot_anomalies_deduplicates_rows(self) -> None:
        detections: list[dict[str, object]] = []
        duplicate_anomalies = [
            SimpleNamespace(title="Suspicious CIP Service", description="Stop observed", src="10.0.0.1", dst="10.0.0.2"),
            SimpleNamespace(title="Suspicious CIP Service", description="Stop observed", src="10.0.0.1", dst="10.0.0.2"),
        ]

        threats._append_ot_anomalies(detections, "CIP", duplicate_anomalies)

        self.assertEqual(len(detections), 1)

    def test_threats_strict_ot_signatures_suppress_false_cip_enip_dnp3(self) -> None:
        class _ThreatPacket:
            def __init__(self, layers: dict[object, object], pkt_len: int = 128) -> None:
                self._layers = layers
                self._pkt_len = pkt_len
                self.time = 1.0

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

            def __len__(self) -> int:
                return self._pkt_len

        ip_layer = SimpleNamespace(src="172.16.165.132", dst="91.146.108.148")
        tcp_layer = SimpleNamespace(sport=12345, dport=80, flags="PA", payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        raw_layer = SimpleNamespace(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

        ip_sentinel = object()
        tcp_sentinel = object()
        udp_sentinel = object()
        raw_sentinel = object()
        dns_sentinel = object()
        dnsqr_sentinel = object()
        ipv6_sentinel = object()

        packets = [_ThreatPacket({ip_sentinel: ip_layer, tcp_sentinel: tcp_layer, raw_sentinel: raw_layer})]
        reader = _DummyReader(packets)

        strong_cip = SimpleNamespace(
            anomalies=[SimpleNamespace(title="Suspicious CIP Service", description="Stop observed", src="172.16.165.132", dst="172.16.165.2", severity="warning")],
            errors=[],
            cip_packets=20,
            requests=12,
            responses=12,
            sessions={"s1": 2, "s2": 1},
            identities=[{"vendor": "x"}],
            enip_commands={"RegisterSession": 5},
            cip_services={"WriteTag": 5},
            suspicious_services={"WriteTag": 5},
            high_risk_services={"WriteTag": 5},
            status_codes={"Success": 10},
            artifacts=[object(), object(), object(), object(), object()],
        )
        strong_enip = SimpleNamespace(
            anomalies=[SimpleNamespace(title="ENIP Error Status", description="Encapsulation status 0x000000ff.", src="178.63.209.91", dst="172.16.165.133", severity="info")],
            errors=[],
            enip_packets=20,
            requests=12,
            responses=12,
            sessions={"s1": 2, "s2": 1},
            identities=[{"vendor": "x"}],
            enip_commands={"RegisterSession": 5},
            cip_services={"WriteTag": 5},
            suspicious_services={"WriteTag": 5},
            high_risk_services={"WriteTag": 5},
            status_codes={"Success": 10},
            artifacts=[object(), object(), object(), object(), object()],
        )
        strong_dnp3 = SimpleNamespace(
            anomalies=[SimpleNamespace(title="DNP3 Restart", description="System restart command (Cold Restart) detected", src="00:50:56:f3:ca:52", dst="00:0c:29:fe:9a:67", severity="high")],
            errors=[],
            dnp3_packets=20,
            requests=8,
            responses=8,
            artifacts=[object(), object(), object(), object(), object()],
        )
        empty_ot = SimpleNamespace(anomalies=[], errors=[], artifacts=[])

        with ExitStack() as stack:
            stack.enter_context(patch.object(threats, "IP", ip_sentinel))
            stack.enter_context(patch.object(threats, "TCP", tcp_sentinel))
            stack.enter_context(patch.object(threats, "UDP", udp_sentinel))
            stack.enter_context(patch.object(threats, "Raw", raw_sentinel))
            stack.enter_context(patch.object(threats, "DNS", dns_sentinel))
            stack.enter_context(patch.object(threats, "DNSQR", dnsqr_sentinel))
            stack.enter_context(patch.object(threats, "IPv6", ipv6_sentinel))

            stack.enter_context(patch.object(threats, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")))

            stack.enter_context(patch.object(threats, "analyze_icmp", return_value=SimpleNamespace(detections=[])))
            stack.enter_context(patch.object(threats, "analyze_dns", return_value=SimpleNamespace(detections=[])))
            stack.enter_context(patch.object(threats, "analyze_beacons", return_value=SimpleNamespace(detections=[], candidates=[])))
            stack.enter_context(patch.object(threats, "analyze_files", return_value=SimpleNamespace(detections=[], artifacts=[])))
            stack.enter_context(patch.object(threats, "analyze_http", return_value=SimpleNamespace(
                detections=[],
                errors=[],
                downloads=[],
                file_artifacts=Counter(),
                referrer_token_counts=Counter(),
                referrer_request_host_counts={},
                user_agents=Counter(),
                url_counts=Counter(),
                status_counts=Counter(),
                host_counts=Counter(),
            )))
            stack.enter_context(patch.object(threats, "analyze_creds", return_value=SimpleNamespace(matches=0, hits=[], kind_counts=Counter(), errors=[])))

            stack.enter_context(patch.object(threats, "analyze_cip", return_value=strong_cip))
            stack.enter_context(patch.object(threats, "analyze_enip", return_value=strong_enip))
            stack.enter_context(patch.object(threats, "analyze_dnp3", return_value=strong_dnp3))

            stack.enter_context(patch.object(threats, "analyze_modbus", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_iec104", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_bacnet", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_profinet", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_s7", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_opc", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_ethercat", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_fins", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_crimson", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_pcworx", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_melsec", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_odesys", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_niagara", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_mms", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_srtp", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_df1", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_pccc", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_csp", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_modicon", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_yokogawa", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_honeywell", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_mqtt", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_coap", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_hart", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_prconos", return_value=empty_ot))
            stack.enter_context(patch.object(threats, "analyze_iccp", return_value=empty_ot))

            summary = threats.analyze_threats(Path("dummy.pcap"), show_status=False)

        ot_sources = {str(item.get("source", "")) for item in summary.detections}
        self.assertNotIn("CIP", ot_sources)
        self.assertNotIn("EtherNet/IP", ot_sources)
        self.assertNotIn("DNP3", ot_sources)

    def test_search_rolls_up_when_summarize_enabled(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        summaries = [
            SearchSummary(
                path=paths[0],
                query="token",
                total_packets=10,
                matches=2,
                hits=[],
                truncated=False,
                errors=[],
            ),
            SearchSummary(
                path=paths[1],
                query="token",
                total_packets=7,
                matches=1,
                hits=[],
                truncated=False,
                errors=[],
            ),
        ]

        output = io.StringIO()
        with (
            patch.object(cli, "analyze_search", side_effect=summaries),
            patch.object(cli, "render_search_summary", return_value="PER_FILE") as per_file_mock,
            patch.object(cli, "render_search_rollup", return_value="ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query="token",
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=False,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["search"],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertIn("ROLLUP", output.getvalue())
        self.assertNotIn("PER_FILE", output.getvalue())
        self.assertEqual(per_file_mock.call_count, 0)
        self.assertEqual(rollup_mock.call_count, 1)

    def test_base_rolls_up_when_only_summarize_enabled(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        merged = object()
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_pcap", side_effect=[object(), object()]),
            patch.object(cli, "merge_pcap_summaries", return_value=merged) as merge_mock,
            patch.object(cli, "render_summary", return_value="BASE_SUMMARY") as base_render_mock,
            patch.object(cli, "render_generic_rollup", return_value="BASE_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=False,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=[],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertIn("BASE_SUMMARY", output.getvalue())
        self.assertNotIn("BASE_ROLLUP", output.getvalue())
        self.assertEqual(merge_mock.call_count, 1)
        self.assertEqual(base_render_mock.call_count, 1)
        self.assertEqual(rollup_mock.call_count, 0)

    def test_cli_analyze_paths_does_not_hardcode_status_off(self) -> None:
        source = inspect.getsource(cli._analyze_paths)
        self.assertNotIn("show_status=False", source)

    def test_ordered_steps_includes_arp(self) -> None:
        steps = cli._ordered_steps(["pcapper", "sample.pcap", "--arp"])
        self.assertIn("arp", steps)

    def test_ordered_steps_includes_dhcp(self) -> None:
        steps = cli._ordered_steps(["pcapper", "sample.pcap", "--dhcp"])
        self.assertIn("dhcp", steps)

    def test_ordered_steps_includes_hostname(self) -> None:
        steps = cli._ordered_steps(["pcapper", "sample.pcap", "--hostname"])
        self.assertIn("hostname", steps)

    def test_main_hostname_without_ip_runs_analysis(self) -> None:
        args = cli.build_parser().parse_args([str(Path(__file__)), "--hostname"])

        output = io.StringIO()
        with (
            patch.object(cli, "build_parser") as parser_mock,
            patch.object(cli, "_build_banner", return_value="BANNER"),
            patch.object(cli, "is_supported_pcap", return_value=True),
            patch.object(cli, "_analyze_paths", return_value=0) as analyze_mock,
            patch.object(cli.sys, "argv", ["pcapper", "sample.pcap", "--hostname"]),
            redirect_stdout(output),
        ):
            parser_mock.return_value.parse_args.return_value = args
            rc = cli.main()

        self.assertEqual(rc, 0)
        self.assertEqual(analyze_mock.call_count, 1)
        self.assertTrue(analyze_mock.call_args.kwargs["show_hostname"])
        self.assertIsNone(analyze_mock.call_args.kwargs["timeline_ip"])

    def test_arp_rolls_up_when_summarize_enabled(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        summaries = [arp.ArpSummary(path=paths[0]), arp.ArpSummary(path=paths[1])]
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_arp", side_effect=summaries),
            patch.object(cli, "render_arp_summary", return_value="ARP_PER_FILE") as per_file_mock,
            patch.object(cli, "render_generic_rollup", return_value="ARP_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=False,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=True,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["arp"],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertIn("ARP_ROLLUP", output.getvalue())
        self.assertNotIn("ARP_PER_FILE", output.getvalue())
        self.assertEqual(per_file_mock.call_count, 0)
        self.assertEqual(rollup_mock.call_count, 1)

    def test_dhcp_rolls_up_when_summarize_enabled(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        summaries = [dhcp.DhcpSummary(path=paths[0]), dhcp.DhcpSummary(path=paths[1])]
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_dhcp", side_effect=summaries),
            patch.object(cli, "render_dhcp_summary", return_value="DHCP_PER_FILE") as per_file_mock,
            patch.object(cli, "render_generic_rollup", return_value="DHCP_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=False,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["dhcp"],
                summarize=True,
                show_dhcp=True,
            )

        self.assertEqual(rc, 0)
        self.assertIn("DHCP_ROLLUP", output.getvalue())
        self.assertNotIn("DHCP_PER_FILE", output.getvalue())
        self.assertEqual(per_file_mock.call_count, 0)
        self.assertEqual(rollup_mock.call_count, 1)

    def test_ips_summarize_renders_merged_summary(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        summaries = [object(), object()]
        merged = object()
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_ips", side_effect=summaries),
            patch.object(cli, "merge_ips_summaries", return_value=merged) as merge_mock,
            patch.object(cli, "render_ips_summary", return_value="IPS_FULL") as full_mock,
            patch.object(cli, "render_generic_rollup", return_value="IPS_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=True,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["ips"],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertNotIn("IPS_ROLLUP", output.getvalue())
        self.assertIn("IPS_FULL", output.getvalue())
        self.assertEqual(merge_mock.call_count, 1)
        self.assertEqual(full_mock.call_count, 1)
        self.assertEqual(rollup_mock.call_count, 0)

    def test_summarize_rollup_applies_with_single_path(self) -> None:
        paths = [Path("one.pcap")]
        summary_obj = object()
        merged = object()
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_ips", return_value=summary_obj),
            patch.object(cli, "merge_ips_summaries", return_value=merged) as merge_mock,
            patch.object(cli, "render_ips_summary", return_value="IPS_FULL") as full_mock,
            patch.object(cli, "render_generic_rollup", return_value="IPS_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=True,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["ips"],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertNotIn("IPS_ROLLUP", output.getvalue())
        self.assertIn("IPS_FULL", output.getvalue())
        self.assertEqual(merge_mock.call_count, 1)
        self.assertEqual(full_mock.call_count, 1)
        self.assertEqual(rollup_mock.call_count, 0)

    def test_timeline_summarize_renders_merged_summary(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        summaries = [object(), object()]
        merged = object()
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_timeline", side_effect=summaries),
            patch.object(cli, "merge_timeline_summaries", return_value=merged) as merge_mock,
            patch.object(cli, "render_timeline_summary", return_value="TIMELINE_FULL") as full_mock,
            patch.object(cli, "render_generic_rollup", return_value="TIMELINE_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=False,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=True,
                timeline_ip="10.182.207.28",
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["timeline"],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertNotIn("TIMELINE_ROLLUP", output.getvalue())
        self.assertIn("TIMELINE_FULL", output.getvalue())
        self.assertEqual(merge_mock.call_count, 1)
        self.assertEqual(full_mock.call_count, 1)
        self.assertEqual(rollup_mock.call_count, 0)

    def test_enip_summarize_renders_merged_summary(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        summaries = [object(), object()]
        merged = object()
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_enip", side_effect=summaries),
            patch.object(cli, "merge_enip_summaries", return_value=merged) as merge_mock,
            patch.object(cli, "render_enip_summary", return_value="ENIP_FULL") as full_mock,
            patch.object(cli, "render_generic_rollup", return_value="ENIP_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=False,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=True,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=False,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["enip"],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertNotIn("ENIP_ROLLUP", output.getvalue())
        self.assertIn("ENIP_FULL", output.getvalue())
        self.assertEqual(merge_mock.call_count, 1)
        self.assertEqual(full_mock.call_count, 1)
        self.assertEqual(rollup_mock.call_count, 0)

    def test_cip_summarize_renders_merged_summary(self) -> None:
        paths = [Path("one.pcap"), Path("two.pcap")]
        summaries = [object(), object()]
        merged = object()
        output = io.StringIO()

        with (
            patch.object(cli, "analyze_cip", side_effect=summaries),
            patch.object(cli, "merge_cip_summaries", return_value=merged) as merge_mock,
            patch.object(cli, "render_cip_summary", return_value="CIP_FULL") as full_mock,
            patch.object(cli, "render_generic_rollup", return_value="CIP_ROLLUP") as rollup_mock,
            redirect_stdout(output),
        ):
            rc = cli._analyze_paths(
                paths=paths,
                protocol_limit=12,
                show_base=False,
                show_status=False,
                search_query=None,
                search_case=False,
                show_vlan=False,
                show_icmp=False,
                show_dns=False,
                show_http=False,
                show_tls=False,
                show_ssh=False,
                show_syslog=False,
                show_tcp=False,
                show_udp=False,
                show_exfil=False,
                show_sizes=False,
                show_ips=False,
                show_beacon=False,
                show_threats=False,
                show_files=False,
                show_protocols=False,
                show_services=False,
                show_smb=False,
                show_nfs=False,
                show_strings=False,
                show_creds=False,
                show_certificates=False,
                show_health=False,
                show_hostname=False,
                show_timeline=False,
                timeline_ip=None,
                show_ntlm=False,
                show_netbios=False,
                show_arp=False,
                show_modbus=False,
                show_dnp3=False,
                show_iec104=False,
                show_bacnet=False,
                show_enip=False,
                show_profinet=False,
                show_s7=False,
                show_opc=False,
                show_ethercat=False,
                show_fins=False,
                show_crimson=False,
                show_pcworx=False,
                show_melsec=False,
                show_cip=True,
                show_odesys=False,
                show_niagara=False,
                show_mms=False,
                show_srtp=False,
                show_df1=False,
                show_pccc=False,
                show_csp=False,
                show_modicon=False,
                show_yokogawa=False,
                show_honeywell=False,
                show_mqtt=False,
                show_coap=False,
                show_hart=False,
                show_prconos=False,
                show_iccp=False,
                verbose=False,
                extract_name=None,
                view_name=None,
                show_domain=False,
                show_ldap=False,
                show_kerberos=False,
                ordered_steps=["cip"],
                summarize=True,
            )

        self.assertEqual(rc, 0)
        self.assertNotIn("CIP_ROLLUP", output.getvalue())
        self.assertIn("CIP_FULL", output.getvalue())
        self.assertEqual(merge_mock.call_count, 1)
        self.assertEqual(full_mock.call_count, 1)
        self.assertEqual(rollup_mock.call_count, 0)

    def test_main_does_not_force_recursive_discovery_when_summarize_enabled(self) -> None:
        target = Path("captures")

        class _Args:
            pass

        args = _Args()
        args.no_color = True
        args.timeline = False
        args.timeline_ip = None
        args.target = target
        args.recursive = False
        args.summarize = True
        args.base = False
        args.no_status = True
        args.search = None
        args.search_case = False
        args.vlan = args.icmp = args.dns = args.http = args.tls = args.ssh = args.syslog = args.tcp = args.udp = args.exfil = False
        args.sizes = args.ips = args.beacon = args.threats = args.files = args.protocols = args.services = False
        args.smb = args.nfs = args.strings = args.creds = args.certificates = args.health = args.hostname = False
        args.ntlm = args.netbios = args.arp = False
        args.modbus = args.dnp3 = args.iec104 = args.bacnet = args.enip = args.profinet = args.s7 = args.opc = False
        args.ethercat = args.fins = args.crimson = args.pcworx = args.melsec = args.cip = args.odesys = args.niagara = False
        args.mms = args.srtp = args.df1 = args.pccc = args.csp = args.modicon = args.yokogawa = args.honeywell = False
        args.mqtt = args.coap = args.hart = args.prconos = args.iccp = False
        args.verbose = False
        args.extract = None
        args.view = None
        args.domain = args.ldap = args.kerberos = False
        args.limit_protocols = 15

        with (
            patch.object(cli, "build_parser") as parser_mock,
            patch.object(cli, "_build_banner", return_value="BANNER"),
            patch.object(cli, "_ordered_steps", return_value=[]),
            patch.object(cli, "set_color_override"),
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "is_file", return_value=False),
            patch.object(cli, "find_pcaps", return_value=[Path("a.pcap")]) as find_mock,
            patch.object(cli, "_analyze_paths", return_value=0),
            patch.object(cli.sys, "argv", ["pcapper", "captures", "--summarize"]),
        ):
            parser_mock.return_value.parse_args.return_value = args
            rc = cli.main()

        self.assertEqual(rc, 0)
        find_mock.assert_called_once_with(target, recursive=False)

    def test_main_expands_wildcard_target_pattern(self) -> None:
        target = Path("home*")

        class _Args:
            pass

        args = _Args()
        args.no_color = True
        args.timeline = False
        args.timeline_ip = None
        args.target = target
        args.recursive = False
        args.summarize = False
        args.base = False
        args.no_status = True
        args.search = None
        args.search_case = False
        args.vlan = args.icmp = args.dns = args.http = args.tls = args.ssh = args.syslog = args.tcp = args.udp = args.exfil = False
        args.sizes = args.ips = args.beacon = args.threats = args.files = args.protocols = args.services = False
        args.smb = args.nfs = args.strings = args.creds = args.certificates = args.health = args.hostname = False
        args.ntlm = args.netbios = args.arp = False
        args.modbus = args.dnp3 = args.iec104 = args.bacnet = args.enip = args.profinet = args.s7 = args.opc = False
        args.ethercat = args.fins = args.crimson = args.pcworx = args.melsec = args.cip = args.odesys = args.niagara = False
        args.mms = args.srtp = args.df1 = args.pccc = args.csp = args.modicon = args.yokogawa = args.honeywell = False
        args.mqtt = args.coap = args.hart = args.prconos = args.iccp = False
        args.verbose = False
        args.extract = None
        args.view = None
        args.domain = args.ldap = args.kerberos = False
        args.limit_protocols = 15

        matched = [Path("home01.pcap"), Path("home02.pcapng")]
        with (
            patch.object(cli, "build_parser") as parser_mock,
            patch.object(cli, "_build_banner", return_value="BANNER"),
            patch.object(cli, "_ordered_steps", return_value=[]),
            patch.object(cli, "set_color_override"),
            patch.object(cli, "_expand_target_wildcard", return_value=matched) as expand_mock,
            patch.object(cli, "find_pcaps") as find_mock,
            patch.object(cli, "_analyze_paths", return_value=0) as analyze_mock,
            patch.object(cli.sys, "argv", ["pcapper", "home*", "--ips"]),
        ):
            parser_mock.return_value.parse_args.return_value = args
            rc = cli.main()

        self.assertEqual(rc, 0)
        expand_mock.assert_called_once_with(target, recursive=False)
        find_mock.assert_not_called()
        analyze_mock.assert_called_once()
        self.assertEqual(analyze_mock.call_args.args[0], matched)

    def test_main_wildcard_target_with_no_matches_returns_2(self) -> None:
        target = Path("home*")

        class _Args:
            pass

        args = _Args()
        args.no_color = True
        args.timeline = False
        args.timeline_ip = None
        args.target = target
        args.recursive = False
        args.summarize = False
        args.base = False
        args.no_status = True
        args.search = None
        args.search_case = False
        args.vlan = args.icmp = args.dns = args.http = args.tls = args.ssh = args.syslog = args.tcp = args.udp = args.exfil = False
        args.sizes = args.ips = args.beacon = args.threats = args.files = args.protocols = args.services = False
        args.smb = args.nfs = args.strings = args.creds = args.certificates = args.health = args.hostname = False
        args.ntlm = args.netbios = args.arp = False
        args.modbus = args.dnp3 = args.iec104 = args.bacnet = args.enip = args.profinet = args.s7 = args.opc = False
        args.ethercat = args.fins = args.crimson = args.pcworx = args.melsec = args.cip = args.odesys = args.niagara = False
        args.mms = args.srtp = args.df1 = args.pccc = args.csp = args.modicon = args.yokogawa = args.honeywell = False
        args.mqtt = args.coap = args.hart = args.prconos = args.iccp = False
        args.verbose = False
        args.extract = None
        args.view = None
        args.domain = args.ldap = args.kerberos = False
        args.limit_protocols = 15

        output = io.StringIO()
        with (
            patch.object(cli, "build_parser") as parser_mock,
            patch.object(cli, "_build_banner", return_value="BANNER"),
            patch.object(cli, "_ordered_steps", return_value=[]),
            patch.object(cli, "set_color_override"),
            patch.object(cli, "_expand_target_wildcard", return_value=[]),
            patch.object(cli, "_analyze_paths") as analyze_mock,
            patch.object(cli.sys, "argv", ["pcapper", "home*", "--ips"]),
            redirect_stdout(output),
        ):
            parser_mock.return_value.parse_args.return_value = args
            rc = cli.main()

        self.assertEqual(rc, 2)
        self.assertIn("No pcap/pcapng files found matching pattern", output.getvalue())
        analyze_mock.assert_not_called()

    def test_parser_accepts_multiple_targets(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["one.pcap", "two.pcapng", "--arp"])
        self.assertEqual(args.target, [Path("one.pcap"), Path("two.pcapng")])

    def test_help_groups_are_alphabetized_and_complete(self) -> None:
        parser = cli.build_parser()
        groups = {group.title: group for group in parser._action_groups}

        it_group = groups.get("IT/ENTERPRISE FUNCTIONS")
        self.assertIsNotNone(it_group)
        ics_group = groups.get("OT/ICS/INDUSTRIAL FUNCTIONS")
        self.assertIsNotNone(ics_group)

        def _long_flags(group) -> list[str]:
            flags: list[str] = []
            for action in group._group_actions:
                for opt in action.option_strings:
                    if opt.startswith("--"):
                        flags.append(opt)
                        break
            return flags

        it_flags = _long_flags(it_group)
        ics_flags = _long_flags(ics_group)

        self.assertEqual(it_flags, sorted(it_flags))
        self.assertEqual(ics_flags, sorted(ics_flags))

        expected_it = {
            "--arp", "--beacon", "--certificates", "--creds", "--dhcp", "--dns", "--domain", "--exfil", "--files",
            "--health", "--hostname", "--http", "--icmp", "--ips", "--kerberos", "--ldap", "--netbios", "--nfs",
            "--ntlm", "--protocols", "--services", "--sizes", "--smb", "--ssh", "--strings", "--syslog",
            "--tcp", "--threats", "--timeline", "--tls", "--udp", "--vlan",
        }
        expected_ics = {
            "--bacnet", "--cip", "--coap", "--crimson", "--csp", "--df1", "--dnp3", "--enip",
            "--ethercat", "--fins", "--hart", "--honeywell", "--iccp", "--iec104", "--melsec", "--mms",
            "--modbus", "--modicon", "--mqtt", "--niagara", "--odesys", "--opc", "--pccc", "--pcworx",
            "--prconos", "--profinet", "--s7", "--srtp", "--yokogawa",
        }

        self.assertEqual(set(it_flags), expected_it)
        self.assertEqual(set(ics_flags), expected_ics)

    def test_main_accepts_shell_expanded_wildcard_targets(self) -> None:
        targets = [
            Path("/Users/pac/Downloads/pcaps/Unauthorized Device Discovery _ Network Scanning - Hudsonbay 3.pcap"),
            Path("/Users/pac/Downloads/pcaps/Unauthorized Device Discovery _ Network Scanning - Hudsonbay 4.pcap"),
        ]

        class _Args:
            pass

        args = _Args()
        args.no_color = True
        args.timeline = False
        args.timeline_ip = None
        args.target = targets
        args.recursive = False
        args.summarize = False
        args.base = False
        args.no_status = True
        args.search = None
        args.search_case = False
        args.vlan = args.icmp = args.dns = args.http = args.tls = args.ssh = args.syslog = args.tcp = args.udp = args.exfil = False
        args.sizes = args.ips = args.beacon = args.threats = args.files = args.protocols = args.services = False
        args.smb = args.nfs = args.strings = args.creds = args.certificates = args.health = args.hostname = False
        args.ntlm = args.netbios = args.arp = True
        args.modbus = args.dnp3 = args.iec104 = args.bacnet = args.enip = args.profinet = args.s7 = args.opc = False
        args.ethercat = args.fins = args.crimson = args.pcworx = args.melsec = args.cip = args.odesys = args.niagara = False
        args.mms = args.srtp = args.df1 = args.pccc = args.csp = args.modicon = args.yokogawa = args.honeywell = False
        args.mqtt = args.coap = args.hart = args.prconos = args.iccp = False
        args.verbose = False
        args.extract = None
        args.view = None
        args.domain = args.ldap = args.kerberos = False
        args.limit_protocols = 15

        with (
            patch.object(cli, "build_parser") as parser_mock,
            patch.object(cli, "_build_banner", return_value="BANNER"),
            patch.object(cli, "_ordered_steps", return_value=["arp"]),
            patch.object(cli, "set_color_override"),
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "is_file", return_value=True),
            patch.object(cli, "is_supported_pcap", return_value=True),
            patch.object(cli, "_analyze_paths", return_value=0) as analyze_mock,
            patch.object(cli.sys, "argv", ["pcapper", *[str(t) for t in targets], "--arp"]),
        ):
            parser_mock.return_value.parse_args.return_value = args
            rc = cli.main()

        self.assertEqual(rc, 0)
        analyze_mock.assert_called_once()
        self.assertEqual(analyze_mock.call_args.args[0], targets)

    def test_summarize_renderer_covers_all_title_map_steps(self) -> None:
        source = inspect.getsource(cli._analyze_paths)
        expected_steps = [
            "search", "vlan", "icmp", "dns", "http", "tls", "ssh", "syslog", "tcp", "udp",
            "exfil", "sizes", "ips", "beacon", "threats", "files", "protocols", "services", "smb",
            "nfs", "strings", "creds", "certificates", "health", "hostname", "timeline", "domain", "ldap",
            "kerberos", "ntlm", "netbios", "arp", "iec104", "bacnet", "enip", "profinet", "s7",
            "opc", "ethercat", "fins", "crimson", "pcworx", "melsec", "cip", "odesys", "niagara",
            "mms", "srtp", "df1", "pccc", "csp", "modicon", "yokogawa", "honeywell", "mqtt",
            "coap", "hart", "prconos", "iccp",
        ]
        for step in expected_steps:
            self.assertIn(f'"{step}":', source)

    def test_summarize_aggregation_and_render_routing_covers_all_steps(self) -> None:
        source = inspect.getsource(cli._analyze_paths)

        summarized_steps = [
            "search", "vlan", "icmp", "dns", "http", "tls", "ssh", "syslog", "tcp", "udp",
            "exfil", "sizes", "ips", "beacon", "threats", "files", "protocols", "services", "smb",
            "nfs", "strings", "creds", "certificates", "health", "hostname", "timeline", "domain", "ldap",
            "kerberos", "ntlm", "netbios", "arp", "iec104", "bacnet", "enip", "profinet", "s7",
            "opc", "ethercat", "fins", "crimson", "pcworx", "melsec", "cip", "odesys", "niagara",
            "mms", "srtp", "df1", "pccc", "csp", "modicon", "yokogawa", "honeywell", "mqtt",
            "coap", "hart", "prconos", "iccp",
        ]

        for step in summarized_steps:
            self.assertIn(f'rollups.setdefault("{step}", []).append(', source)

        self.assertIn('modbus_rollups.append(modbus_summary)', source)
        self.assertIn('dnp3_rollups.append(dnp3_summary)', source)

        self.assertIn('print(render_search_rollup(rollups[step]))', source)
        self.assertIn('merged_ips = merge_ips_summaries(rollups[step])', source)
        self.assertIn('print(render_ips_summary(merged_ips, verbose=verbose))', source)
        self.assertIn('merged_timeline = merge_timeline_summaries(rollups[step])', source)
        self.assertIn('print(render_timeline_summary(merged_timeline))', source)
        self.assertIn('merged_hostname = merge_hostname_summaries(rollups[step])', source)
        self.assertIn('print(render_hostname_summary(merged_hostname))', source)
        self.assertIn('merged_enip = merge_enip_summaries(rollups[step])', source)
        self.assertIn('print(render_enip_summary(merged_enip))', source)
        self.assertIn('merged_cip = merge_cip_summaries(rollups[step])', source)
        self.assertIn('print(render_cip_summary(merged_cip))', source)
        self.assertIn('print(render_udp_rollup(rollups[step], verbose=verbose))', source)
        self.assertIn('print(render_generic_rollup(title_map.get(step, step.upper()), rollups[step]))', source)
        self.assertIn('print(render_vlan_rollup(rollups["vlan"], verbose=verbose))', source)
        self.assertIn('print(render_modbus_rollup(modbus_rollups))', source)
        self.assertIn('print(render_dnp3_rollup(dnp3_rollups))', source)

    def test_protocol_hierarchy_collapses_consecutive_duplicate_layers(self) -> None:
        tls_chain = _ProtocolTestPacket(
            "Ethernet",
            _LayerNode(
                "IP",
                _LayerNode(
                    "TCP",
                    _LayerNode(
                        "TLS",
                        _LayerNode(
                            "TLS",
                            _LayerNode("TLS", _NoPayloadNode()),
                        ),
                    ),
                ),
            ),
        )
        sslv2_chain = _ProtocolTestPacket(
            "Ethernet",
            _LayerNode(
                "IP",
                _LayerNode(
                    "TCP",
                    _LayerNode(
                        "SSLv2",
                        _LayerNode("SSLv2", _NoPayloadNode()),
                    ),
                ),
            ),
        )

        reader = _DummyReader([tls_chain, sslv2_chain])
        with patch.object(protocols, "IP", object()), patch.object(
            protocols, "IPv6", object()
        ), patch.object(protocols, "ARP", object()), patch.object(
            protocols, "ICMP", object()
        ), patch.object(protocols, "TCP", object()), patch.object(
            protocols, "UDP", object()
        ), patch.object(protocols, "Ether", object()), patch.object(
            protocols, "Raw", object()
        ), patch.object(
            protocols,
            "get_reader",
            return_value=(reader, _DummyStatus(), None, 0, "pcap"),
        ):
            summary = protocols.analyze_protocols(Path("dummy.pcap"), show_status=False)

        ethernet = summary.hierarchy.sub_protocols.get("Ethernet")
        self.assertIsNotNone(ethernet)
        ip_node = ethernet.sub_protocols.get("IP") if ethernet else None
        self.assertIsNotNone(ip_node)
        tcp_node = ip_node.sub_protocols.get("TCP") if ip_node else None
        self.assertIsNotNone(tcp_node)

        tls_node = tcp_node.sub_protocols.get("TLS") if tcp_node else None
        self.assertIsNotNone(tls_node)
        self.assertNotIn("TLS", tls_node.sub_protocols if tls_node else {})

        sslv2_node = tcp_node.sub_protocols.get("SSLv2") if tcp_node else None
        self.assertIsNotNone(sslv2_node)
        self.assertNotIn("SSLv2", sslv2_node.sub_protocols if sslv2_node else {})

    def test_protocol_hierarchy_caps_oscillation_pattern(self) -> None:
        alternating_names = ["A", "B"] * 8
        payload: object = _NoPayloadNode()
        for name in reversed(alternating_names):
            payload = _LayerNode(name, payload)

        oscillating_chain = _ProtocolTestPacket(
            "Ethernet",
            _LayerNode("IP", _LayerNode("TCP", payload)),
        )

        reader = _DummyReader([oscillating_chain])
        with patch.object(protocols, "IP", object()), patch.object(
            protocols, "IPv6", object()
        ), patch.object(protocols, "ARP", object()), patch.object(
            protocols, "ICMP", object()
        ), patch.object(protocols, "TCP", object()), patch.object(
            protocols, "UDP", object()
        ), patch.object(protocols, "Ether", object()), patch.object(
            protocols, "Raw", object()
        ), patch.object(
            protocols,
            "get_reader",
            return_value=(reader, _DummyStatus(), None, 0, "pcap"),
        ):
            summary = protocols.analyze_protocols(Path("dummy.pcap"), show_status=False)

        ethernet = summary.hierarchy.sub_protocols.get("Ethernet")
        self.assertIsNotNone(ethernet)
        ip_node = ethernet.sub_protocols.get("IP") if ethernet else None
        self.assertIsNotNone(ip_node)
        tcp_node = ip_node.sub_protocols.get("TCP") if ip_node else None
        self.assertIsNotNone(tcp_node)

        node = tcp_node
        expected = "A"
        traversed = 0
        while expected in (node.sub_protocols if node else {}):
            node = node.sub_protocols[expected]
            traversed += 1
            expected = "B" if expected == "A" else "A"

        expected_depth = protocols.OSCILLATION_REPEAT_CAP + 2
        self.assertEqual(traversed, expected_depth)
        self.assertNotIn(expected, node.sub_protocols if node else {})

    def test_netbios_renderer_includes_new_threat_sections(self) -> None:
        summary = netbios.NetbiosAnalysis(path=Path("dummy.pcap"))
        summary.total_packets = 100
        summary.total_bytes = 2048
        summary.protocol_packets["TCP"] = 70
        summary.protocol_packets["UDP"] = 30
        summary.service_counts["NBNS (Name Service)"] = 60
        summary.smb_commands["SMB2:Write"] = 12
        summary.suspicious_smb_commands["SMB2:Write"] = 12
        summary.threat_summary["Potential Exfiltration"] = 1

        output = reporting.render_netbios_summary(summary)
        self.assertIn("Overall Traffic Statistics", output)
        self.assertIn("Protocol Statistics", output)
        self.assertIn("Observed NETBIOS Functions / Services / Commands", output)
        self.assertIn("Threat Hunting Detections", output)

    def test_exfil_detects_per_source_dns_tunnel_and_uncommon_outbound_port(self) -> None:
        class _ExfilPacket:
            def __init__(self, layers: dict[object, object], ts: float, pkt_len: int = 256) -> None:
                self._layers = layers
                self.time = ts
                self._pkt_len = pkt_len

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

            def __len__(self) -> int:
                return self._pkt_len

        ip_sentinel = object()
        tcp_sentinel = object()
        udp_sentinel = object()
        dns_sentinel = object()

        packets: list[object] = []
        for idx in range(25):
            query = f"{idx:02x}{'a'*36}.exfil.example.com".encode("utf-8")
            packets.append(
                _ExfilPacket(
                    {
                        ip_sentinel: SimpleNamespace(src="10.0.0.5", dst="8.8.8.8"),
                        udp_sentinel: SimpleNamespace(dport=53),
                        dns_sentinel: SimpleNamespace(qr=0, qd=SimpleNamespace(qname=query)),
                    },
                    ts=float(idx),
                    pkt_len=240,
                )
            )

        for idx in range(5):
            query = f"printer{idx}.corp.local".encode("utf-8")
            packets.append(
                _ExfilPacket(
                    {
                        ip_sentinel: SimpleNamespace(src="10.0.0.6", dst="8.8.8.8"),
                        udp_sentinel: SimpleNamespace(dport=53),
                        dns_sentinel: SimpleNamespace(qr=0, qd=SimpleNamespace(qname=query)),
                    },
                    ts=100.0 + float(idx),
                    pkt_len=220,
                )
            )

        for idx in range(15):
            packets.append(
                _ExfilPacket(
                    {
                        ip_sentinel: SimpleNamespace(src="10.0.0.5", dst="91.146.108.148"),
                        tcp_sentinel: SimpleNamespace(dport=4444),
                    },
                    ts=200.0 + float(idx),
                    pkt_len=120_000,
                )
            )

        reader = _DummyReader(packets)
        http_summary = SimpleNamespace(post_payloads=[], host_counts=Counter(), errors=[])
        dns_summary = SimpleNamespace(qname_counts=Counter(), errors=[])
        file_summary = SimpleNamespace(artifacts=[], errors=[])

        with (
            patch.object(exfil, "IP", ip_sentinel),
            patch.object(exfil, "IPv6", None),
            patch.object(exfil, "TCP", tcp_sentinel),
            patch.object(exfil, "UDP", udp_sentinel),
            patch.object(exfil, "DNS", dns_sentinel),
            patch.object(exfil, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
            patch.object(exfil, "analyze_http", return_value=http_summary),
            patch.object(exfil, "analyze_dns", return_value=dns_summary),
            patch.object(exfil, "analyze_files", return_value=file_summary),
        ):
            summary = exfil.analyze_exfil(Path("dummy.pcap"), show_status=False)

        suspect_sources = {str(item.get("src", "")) for item in summary.dns_tunnel_suspects}
        self.assertIn("10.0.0.5", suspect_sources)
        self.assertNotIn("10.0.0.6", suspect_sources)
        self.assertTrue(any("avg_entropy" in item for item in summary.dns_tunnel_suspects))
        self.assertTrue(
            any(
                str(item.get("summary", "")) == "High-volume outbound traffic on uncommon ports"
                for item in summary.detections
            )
        )

    def test_beacon_detects_multi_destination_fanout(self) -> None:
        class _BeaconPacket:
            def __init__(self, layers: dict[object, object], ts: float, pkt_len: int = 128) -> None:
                self._layers = layers
                self.time = ts
                self._pkt_len = pkt_len

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

            def __len__(self) -> int:
                return self._pkt_len

        ip_sentinel = object()
        tcp_sentinel = object()

        packets: list[object] = []
        ts = 0.0
        destinations = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        for dest_index, dst_ip in enumerate(destinations):
            for event in range(5):
                packets.append(
                    _BeaconPacket(
                        {
                            ip_sentinel: SimpleNamespace(src="10.0.0.5", dst=dst_ip),
                            tcp_sentinel: SimpleNamespace(
                                sport=40_000 + (dest_index * 100) + event,
                                dport=443,
                                flags="S",
                            ),
                        },
                        ts=ts,
                        pkt_len=96,
                    )
                )
                ts += 60.0

        reader = _DummyReader(packets)
        with (
            patch.object(beacon, "IP", ip_sentinel),
            patch.object(beacon, "IPv6", None),
            patch.object(beacon, "TCP", tcp_sentinel),
            patch.object(beacon, "UDP", None),
            patch.object(beacon, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
        ):
            summary = beacon.analyze_beacons(Path("dummy.pcap"), show_status=False, min_events=3)

        self.assertGreaterEqual(summary.candidate_count, 3)
        self.assertTrue(
            any(
                str(item.get("summary", "")) == "Source beaconing to multiple destinations"
                for item in summary.detections
            )
        )

    def test_hostname_target_filter_keeps_only_requested_ip_mappings(self) -> None:
        class _HostnamePacket:
            def __init__(self, layers: dict[object, object], payload: bytes, ts: float = 1.0) -> None:
                self._layers = layers
                self._payload = payload
                self.time = ts

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

        ip_sentinel = object()
        tcp_sentinel = object()
        raw_sentinel = object()

        payload = b"GET / HTTP/1.1\r\nHost: c2.example.com\r\n\r\n"
        packets = [
            _HostnamePacket(
                {
                    ip_sentinel: SimpleNamespace(src="172.16.165.133", dst="8.8.8.8"),
                    tcp_sentinel: SimpleNamespace(payload=payload),
                    raw_sentinel: SimpleNamespace(load=payload),
                },
                payload,
                ts=1.0,
            ),
            _HostnamePacket(
                {
                    ip_sentinel: SimpleNamespace(src="10.0.0.5", dst="172.16.165.133"),
                    tcp_sentinel: SimpleNamespace(payload=payload),
                    raw_sentinel: SimpleNamespace(load=payload),
                },
                payload,
                ts=2.0,
            ),
        ]

        reader = _DummyReader(packets)
        with (
            patch.object(hostname, "IP", ip_sentinel),
            patch.object(hostname, "IPv6", None),
            patch.object(hostname, "TCP", tcp_sentinel),
            patch.object(hostname, "UDP", None),
            patch.object(hostname, "Raw", raw_sentinel),
            patch.object(hostname, "DNS", None),
            patch.object(hostname, "TLSClientHello", None),
            patch.object(hostname, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
        ):
            summary = hostname.analyze_hostname(
                Path("dummy.pcap"),
                target_ip="172.16.165.133",
                show_status=False,
            )

        self.assertTrue(summary.findings)
        self.assertTrue(all(item.mapped_ip == "172.16.165.133" for item in summary.findings))

    def test_hostname_decodes_nbns_level1_encoded_name(self) -> None:
        host_name = "K34EN6W3N-PC"
        padded = host_name.ljust(15).encode("ascii") + b"\x00"
        encoded = "".join(
            chr(((byte_val >> 4) & 0x0F) + ord("A")) + chr((byte_val & 0x0F) + ord("A"))
            for byte_val in padded
        )

        decoded = hostname._decode_nbns_level1_name(encoded)

        self.assertEqual(decoded, host_name)

    def test_hostname_extracts_mail_banner_and_smb_unc_hostnames(self) -> None:
        class _HostnamePacket:
            def __init__(self, layers: dict[object, object], payload: bytes, ts: float = 1.0) -> None:
                self._layers = layers
                self.time = ts
                self._payload = payload

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

        ip_sentinel = object()
        tcp_sentinel = object()
        raw_sentinel = object()

        smtp_payload = b"220 mail.example.org ESMTP ready\r\n"
        smb_payload = b"\\\\fileserver.corp.local\\share\\secret.txt"

        packets = [
            _HostnamePacket(
                {
                    ip_sentinel: SimpleNamespace(src="172.16.165.10", dst="172.16.165.165"),
                    tcp_sentinel: SimpleNamespace(sport=25, dport=50000, payload=smtp_payload),
                    raw_sentinel: SimpleNamespace(load=smtp_payload),
                },
                smtp_payload,
                ts=1.0,
            ),
            _HostnamePacket(
                {
                    ip_sentinel: SimpleNamespace(src="172.16.165.165", dst="172.16.165.20"),
                    tcp_sentinel: SimpleNamespace(sport=51000, dport=445, payload=smb_payload),
                    raw_sentinel: SimpleNamespace(load=smb_payload),
                },
                smb_payload,
                ts=2.0,
            ),
        ]

        reader = _DummyReader(packets)
        with (
            patch.object(hostname, "IP", ip_sentinel),
            patch.object(hostname, "IPv6", None),
            patch.object(hostname, "TCP", tcp_sentinel),
            patch.object(hostname, "UDP", None),
            patch.object(hostname, "Raw", raw_sentinel),
            patch.object(hostname, "DNS", None),
            patch.object(hostname, "TLSClientHello", None),
            patch.object(hostname, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
        ):
            summary = hostname.analyze_hostname(
                Path("dummy.pcap"),
                target_ip="172.16.165.165",
                show_status=False,
            )

        discovered = {item.hostname for item in summary.findings}
        self.assertIn("mail.example.org", discovered)
        self.assertIn("fileserver.corp.local", discovered)
        self.assertTrue(all(item.mapped_ip == "172.16.165.165" for item in summary.findings))

    def test_hostname_extracts_tls_certificate_san_and_cn(self) -> None:
        class _HostnamePacket:
            def __init__(self, layers: dict[object, object], payload: bytes, ts: float = 1.0) -> None:
                self._layers = layers
                self.time = ts
                self._payload = payload

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

        ip_sentinel = object()
        tcp_sentinel = object()
        raw_sentinel = object()
        cert_sentinel = object()

        cert_payload = b"subject=CN=www.corp.local SAN=DNS:api.corp.local"
        packets = [
            _HostnamePacket(
                {
                    ip_sentinel: SimpleNamespace(src="172.16.165.133", dst="10.0.0.9"),
                    tcp_sentinel: SimpleNamespace(sport=443, dport=50100, payload=cert_payload),
                    raw_sentinel: SimpleNamespace(load=cert_payload),
                    cert_sentinel: SimpleNamespace(certs=[], data="CN=www.corp.local DNS:api.corp.local"),
                },
                cert_payload,
                ts=1.0,
            )
        ]

        reader = _DummyReader(packets)
        with (
            patch.object(hostname, "IP", ip_sentinel),
            patch.object(hostname, "IPv6", None),
            patch.object(hostname, "TCP", tcp_sentinel),
            patch.object(hostname, "UDP", None),
            patch.object(hostname, "Raw", raw_sentinel),
            patch.object(hostname, "DNS", None),
            patch.object(hostname, "TLSClientHello", None),
            patch.object(hostname, "TLSCertificate", cert_sentinel),
            patch.object(hostname, "DHCP", None),
            patch.object(hostname, "BOOTP", None),
            patch.object(hostname, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
        ):
            summary = hostname.analyze_hostname(
                Path("dummy.pcap"),
                target_ip="172.16.165.133",
                show_status=False,
            )

        discovered = {item.hostname for item in summary.findings}
        self.assertIn("api.corp.local", discovered)
        self.assertIn("www.corp.local", discovered)
        self.assertTrue(all(item.mapped_ip == "172.16.165.133" for item in summary.findings))

    def test_hostname_extracts_dhcp_hostname_option_with_bootp_mapping(self) -> None:
        class _HostnamePacket:
            def __init__(self, layers: dict[object, object], ts: float = 1.0) -> None:
                self._layers = layers
                self.time = ts

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

        ip_sentinel = object()
        udp_sentinel = object()
        dhcp_sentinel = object()
        bootp_sentinel = object()

        packets = [
            _HostnamePacket(
                {
                    ip_sentinel: SimpleNamespace(src="0.0.0.0", dst="255.255.255.255"),
                    udp_sentinel: SimpleNamespace(sport=68, dport=67, payload=b""),
                    dhcp_sentinel: SimpleNamespace(options=[("message-type", "request"), ("hostname", "workstation7.corp.local")]),
                    bootp_sentinel: SimpleNamespace(ciaddr="0.0.0.0", yiaddr="172.16.165.133"),
                },
                ts=1.0,
            )
        ]

        reader = _DummyReader(packets)
        with (
            patch.object(hostname, "IP", ip_sentinel),
            patch.object(hostname, "IPv6", None),
            patch.object(hostname, "TCP", None),
            patch.object(hostname, "UDP", udp_sentinel),
            patch.object(hostname, "Raw", None),
            patch.object(hostname, "DNS", None),
            patch.object(hostname, "TLSClientHello", None),
            patch.object(hostname, "TLSCertificate", None),
            patch.object(hostname, "DHCP", dhcp_sentinel),
            patch.object(hostname, "BOOTP", bootp_sentinel),
            patch.object(hostname, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
        ):
            summary = hostname.analyze_hostname(
                Path("dummy.pcap"),
                target_ip="172.16.165.133",
                show_status=False,
            )

        discovered = {item.hostname for item in summary.findings}
        self.assertIn("workstation7.corp.local", discovered)
        self.assertTrue(all(item.mapped_ip == "172.16.165.133" for item in summary.findings))

    def test_hostname_extracts_arp_payload_hostname_tokens(self) -> None:
        class _HostnamePacket:
            def __init__(self, layers: dict[object, object], ts: float = 1.0) -> None:
                self._layers = layers
                self.time = ts

            def haslayer(self, layer: object) -> bool:
                return layer in self._layers

            def __getitem__(self, layer: object):
                return self._layers[layer]

        arp_sentinel = object()
        raw_sentinel = object()

        payload = b"arp-note host camera-west.corp.local owner"
        packets = [
            _HostnamePacket(
                {
                    arp_sentinel: SimpleNamespace(psrc="172.16.165.133", pdst="172.16.165.1"),
                    raw_sentinel: SimpleNamespace(load=payload),
                },
                ts=1.0,
            )
        ]

        reader = _DummyReader(packets)
        with (
            patch.object(hostname, "IP", None),
            patch.object(hostname, "IPv6", None),
            patch.object(hostname, "TCP", None),
            patch.object(hostname, "UDP", None),
            patch.object(hostname, "Raw", raw_sentinel),
            patch.object(hostname, "DNS", None),
            patch.object(hostname, "ARP", arp_sentinel),
            patch.object(hostname, "TLSClientHello", None),
            patch.object(hostname, "TLSCertificate", None),
            patch.object(hostname, "DHCP", None),
            patch.object(hostname, "BOOTP", None),
            patch.object(hostname, "get_reader", return_value=(reader, _DummyStatus(), None, 0, "pcap")),
        ):
            summary = hostname.analyze_hostname(
                Path("dummy.pcap"),
                target_ip="172.16.165.133",
                show_status=False,
            )

        discovered = {item.hostname for item in summary.findings}
        self.assertIn("camera-west.corp.local", discovered)
        self.assertTrue(all(item.mapped_ip == "172.16.165.133" for item in summary.findings))


if __name__ == "__main__":
    unittest.main()
