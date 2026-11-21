"""--scan triage: OT reconnaissance vs. a broad sweep, and the tool guess."""

from __future__ import annotations

from collections import Counter

from pcapper.reporting.scan import _ot_focused, _scan_source_severity
from pcapper.scan import ScanSourceResult, ScanTargetResult, _guess_scanner_tool


def _source(ports: int, ot_ports: list[int], open_ports: list[int] = (), scope: str = "external") -> ScanSourceResult:
    src = ScanSourceResult(scanner_ip="198.51.100.7", scan_type="vertical", unique_targets=1, unique_ports=ports, syn_packets=ports,
                           first_seen=0.0, last_seen=1.0, mac_addresses=[], possible_os="-", hostname_hints=[],
                           scanner_software_guess="-", top_ports=[],
                           targets=[ScanTargetResult(target_ip="10.0.0.5", open_ports=list(open_ports))])
    src.ot_ports = list(ot_ports)
    src.ot_targets = ["10.0.0.5"] if ot_ports else []
    src.scanner_scope = scope
    src.target_scope = "external"
    return src


def test_default_nmap_sweep_is_not_ics_reconnaissance() -> None:
    # nmap's top-1000 list contains 2222, 4000 and 20000; nothing answered.
    src = _source(1000, [2222, 4000, 20000])
    assert not _ot_focused(src)
    severity, reasons = _scan_source_severity(src)
    assert severity != "CRITICAL"
    assert any("not OT-specific" in r for r in reasons)


def test_narrow_or_answered_ot_scan_is_critical() -> None:
    assert _scan_source_severity(_source(4, [502, 102, 44818, 20000]))[0] == "CRITICAL"
    assert _scan_source_severity(_source(1000, [502, 20000], open_ports=[502]))[0] == "CRITICAL"


def test_tool_guess_for_vertical_sweeps() -> None:
    def guess(ports: int, scan_type: str = "vertical", targets: int = 1) -> str:
        return _guess_scanner_tool(scan_type, targets, ports, max(ports, 400), max(ports, 400), [], Counter())

    assert "top-1000" in guess(1000)
    assert "full port-range" in guess(65535)
    assert "Masscan" not in guess(1000)
    assert "Masscan" in guess(1, "horizontal", 5000)



def test_dns_server_replies_are_not_a_udp_scan(tmp_path) -> None:
    from pcapper.scan import analyze_scan
    from test_review_batches import T0, _udp, _write

    packets = []
    for i, port in enumerate(range(50000, 50040)):
        query = _udp("10.0.0.5", "10.0.0.1", port, 53, b"q")
        query.time = T0 + i
        reply = _udp("10.0.0.1", "10.0.0.5", 53, port, b"a")
        reply.time = T0 + i + 0.01
        packets += [query, reply]
    summary = analyze_scan(_write(tmp_path, "dns.pcap", packets), show_status=False)
    assert "10.0.0.1" not in {s.scanner_ip for s in summary.scan_sources}


def test_udp_port_sweep_is_still_a_scan(tmp_path) -> None:
    from pcapper.scan import analyze_scan
    from test_review_batches import T0, _udp, _write

    packets = []
    for i, port in enumerate(range(1, 120)):
        probe = _udp("10.0.0.9", "10.0.0.20", 40000, port, b"")
        probe.time = T0 + i * 0.01
        packets.append(probe)
    summary = analyze_scan(_write(tmp_path, "udp_scan.pcap", packets), show_status=False)
    assert "10.0.0.9" in {s.scanner_ip for s in summary.scan_sources}
