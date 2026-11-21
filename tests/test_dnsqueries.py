"""--dnsqueries: every DNS / LLMNR / mDNS lookup with the response observed,
in the pipeline like any other step (-ip, -summarize, -v, exports)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from pcapper.dns import analyze_dns
from pcapper.dnsqueries import analyze_dns_queries
from test_review_batches import T0, _write

CLIENT, OTHER, RESOLVER = "10.0.0.5", "10.0.0.6", "10.0.0.53"


def _pkt(src: str, dst: str, sport: int, dport: int, layer, at: float):
    pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / layer
    pkt.time = T0 + at
    return pkt


def _capture(tmp_path: Path, name: str = "lookups.pcap") -> Path:
    q = lambda txid, qname, qtype="A": DNS(id=txid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))  # noqa: E731
    packets = [
        _pkt(CLIENT, RESOLVER, 40001, 53, q(1, "www.example.com"), 0.0),
        _pkt(RESOLVER, CLIENT, 53, 40001, DNS(id=1, qr=1, ra=1, qd=DNSQR(qname="www.example.com"), an=[
            DNSRR(rrname="www.example.com", type="CNAME", rdata="edge.example.net"),
            DNSRR(rrname="edge.example.net", type="A", rdata="93.184.216.34")]), 0.040),
        _pkt(CLIENT, RESOLVER, 40002, 53, q(2, "www.example.com"), 5.0),  # a repeat: ×2 by default
        _pkt(RESOLVER, CLIENT, 53, 40002, DNS(id=2, qr=1, ra=1, qd=DNSQR(qname="www.example.com"), an=[
            DNSRR(rrname="www.example.com", type="CNAME", rdata="edge.example.net"),
            DNSRR(rrname="edge.example.net", type="A", rdata="93.184.216.34")]), 5.030),
        _pkt(CLIENT, RESOLVER, 40003, 53, q(3, "nope.invalid"), 6.0),
        _pkt(RESOLVER, CLIENT, 53, 40003, DNS(id=3, qr=1, rcode=3, qd=DNSQR(qname="nope.invalid")), 6.020),
        _pkt(OTHER, RESOLVER, 40004, 53, q(4, "lost.example.org", "AAAA"), 7.0),  # never answered
        _pkt(RESOLVER, OTHER, 53, 40009, DNS(id=9, qr=1, qd=DNSQR(qname="late.example.org"),
                                              an=DNSRR(rrname="late.example.org", type="A", rdata="198.51.100.7")), 8.0),
        _pkt(CLIENT, "224.0.0.252", 50000, 5355, LLMNRQuery(id=7, qd=DNSQR(qname="FILESRV")), 9.0),
        _pkt(OTHER, CLIENT, 5355, 50000, LLMNRResponse(id=7, qd=DNSQR(qname="FILESRV"),
                                                       an=DNSRR(rrname="FILESRV", type="A", rdata=OTHER)), 9.010),
        _pkt(CLIENT, "224.0.0.251", 5353, 5353, DNS(id=0, qd=DNSQR(qname="_printer._tcp.local", qtype="PTR")), 10.0),
    ]
    return _write(tmp_path, name, packets)


def test_lookups_pair_with_their_responses(tmp_path: Path) -> None:
    records = analyze_dns_queries(_capture(tmp_path), show_status=False).queries
    by_name = {}
    for r in records:
        by_name.setdefault(str(r["name"]).lower(), []).append(r)
    first = by_name["www.example.com"][0]
    assert first["status"] == "answered" and first["rcode"] == "NOERROR"
    assert first["answers"] == ["CNAME edge.example.net", "93.184.216.34"] and first["rtt_ms"] == 40.0
    assert len(by_name["www.example.com"]) == 2
    assert by_name["nope.invalid"][0]["rcode"] == "NXDOMAIN"
    assert by_name["lost.example.org"][0]["status"] == "no response" and by_name["lost.example.org"][0]["qtype"] == "AAAA"
    assert by_name["late.example.org"][0]["status"] == "response only"
    llmnr = by_name["filesrv"][0]  # answered by another host: that host is the "server"
    assert (llmnr["protocol"], llmnr["status"], llmnr["server"], llmnr["answers"]) == ("LLMNR", "answered", OTHER, [OTHER])
    assert by_name["_printer._tcp.local"][0]["protocol"] == "mDNS"


def test_llmnr_reaches_the_dns_analyzer(tmp_path: Path) -> None:
    """scapy decodes UDP 5355 as LLMNRQuery / LLMNRResponse, not DNS: the
    DNS report's LLMNR counters and finding never saw it."""
    summary = analyze_dns(_capture(tmp_path), show_status=False)
    assert summary.llmnr_packets == 2 and summary.llmnr_client_counts.get(CLIENT)


def _run(*args: str) -> str:
    out = subprocess.run([sys.executable, "-m", "pcapper", *args, "--no-color", "--no-status"],
                         capture_output=True, text=True, timeout=300, cwd=Path(__file__).resolve().parents[1])
    assert out.returncode == 0, out.stderr[-1500:]
    return re.sub(r"\x1b\[[0-9;]*m", "", out.stdout)


def test_cli_lists_lookups_once_by_default_and_every_query_with_v(tmp_path: Path) -> None:
    path = str(_capture(tmp_path))
    text = _run(path, "--dnsqueries")
    assert "DNS QUERIES · lookups.pcap" in text and "7 queries for 6 names · 1 NXDOMAIN · 2 unanswered" in text
    assert "DNS 5 · LLMNR 1 · mDNS 1" in text
    row = next(line for line in text.splitlines() if "www.example.com" in line)
    assert re.search(r"\b2\s+CNAME edge\.example\.net, 93\.184\.216\.34", row)  # ×2
    assert "no response" in text and "(query not captured)" in text and "LLMNR" in text
    assert "-v adds" in text and "every query" in text
    verbose = _run(path, "--dnsqueries", "-v")
    assert sum("www.example.com" in line for line in verbose.splitlines()) == 2
    assert "0x0001" in verbose and "40.0" in verbose


def test_cli_scopes_to_one_host_and_merges_captures(tmp_path: Path) -> None:
    one, two = str(_capture(tmp_path, "one.pcap")), str(_capture(tmp_path, "two.pcap"))
    scoped = _run(one, "--dnsqueries", "-ip", OTHER)
    assert "lost.example.org" in scoped and "www.example.com" not in scoped
    merged = _run(one, two, "--dnsqueries", "-summarize")
    assert "DNS QUERIES · all captures" in merged and "CAPTURE" in merged
    assert "one.pcap" in merged and "two.pcap" in merged


def test_json_export_carries_every_lookup(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    _run(str(_capture(tmp_path)), "--dnsqueries", "--json", str(out))
    data = json.loads(out.read_text())
    records = data["summaries"]["dnsqueries"]["queries"]
    assert len(records) == 7 and {r["status"] for r in records} == {"answered", "no response", "response only"}
