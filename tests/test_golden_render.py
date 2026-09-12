"""Golden-output tests: parse, analyse and render, pinned byte for byte.

One assertion per analyzer covers the whole chain, and a regression shows up as
a readable diff rather than as a subtly wrong number in a report. That is the
property that matters here — pcapper's output is used as forensic evidence, so a
wrong figure is not a cosmetic defect.

After an intentional output change:

    pytest tests/test_golden_render.py --regenerate-golden

then read the diff before committing it. A golden file that changed without
anyone looking at it is worse than no golden file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pcapper.carving import analyze_carving
from pcapper.dns import analyze_dns
from pcapper.http import analyze_http
from pcapper.modbus import analyze_modbus
from pcapper.protocols import analyze_protocols
from pcapper.reporting import (
    render_carve_summary,
    render_dns_summary,
    render_http_summary,
    render_modbus_summary,
    render_protocols_summary,
)

# (golden name, capture, analyze, render)
CASES = [
    ("dns", "dns.pcap", analyze_dns, render_dns_summary),
    ("http", "http.pcap", analyze_http, render_http_summary),
    ("modbus", "modbus.pcap", analyze_modbus, render_modbus_summary),
    ("protocols_dns", "dns.pcap", analyze_protocols, render_protocols_summary),
    ("protocols_modbus", "modbus.pcap", analyze_protocols, render_protocols_summary),
    ("carve_wrap", "carve_wrap.pcap", analyze_carving, render_carve_summary),
    ("carve_gap", "carve_gap.pcap", analyze_carving, render_carve_summary),
]


@pytest.mark.parametrize(
    "name,capture,analyze,render", CASES, ids=[case[0] for case in CASES]
)
def test_rendered_output_matches_golden(
    name: str, capture: str, analyze, render, pcap, golden
) -> None:
    summary = analyze(pcap(capture), show_status=False)
    golden(name, render(summary))


@pytest.mark.parametrize(
    "name,capture,analyze,render", CASES, ids=[case[0] for case in CASES]
)
def test_rendering_is_deterministic(
    name: str, capture: str, analyze, render, pcap
) -> None:
    """Two analyses of the same capture must render identically.

    Guards against ordering that depends on set or dict iteration, which would
    make the golden files flap between runs rather than fail honestly.
    """
    path: Path = pcap(capture)
    first = render(analyze(path, show_status=False))
    second = render(analyze(path, show_status=False))
    assert first == second


@pytest.mark.parametrize("capture", ["dns.pcap", "http.pcap", "modbus.pcap"])
def test_analyzers_report_no_errors_on_clean_captures(capture: str, pcap) -> None:
    for analyze in (analyze_dns, analyze_http, analyze_modbus, analyze_protocols):
        summary = analyze(pcap(capture), show_status=False)
        assert getattr(summary, "errors", []) == [], f"{analyze.__name__} on {capture}"
