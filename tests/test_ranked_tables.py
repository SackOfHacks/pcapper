"""Ranked artifact tables: the default view shows the top 10 and the bottom
10 (the rarest), -v all of them; and DNS lookups moved to --dnsqueries."""

from __future__ import annotations

import base64
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from pcapper.reporting import _style as st
from pcapper.reporting import set_verbose_output
from pcapper.reporting._remote import counts
from pcapper.utils import ranked_slice


def _plain(lines: list[str]) -> list[str]:
    return [re.sub(r"\x1b\[[0-9;]*m", "", line) for line in lines]


def test_top_and_bottom_ten_by_default_everything_with_v() -> None:
    rows = [[f"d{i}.example", 100 - i] for i in range(37)]
    lines = _plain(st.ranked(["Domain", "Queries"], rows, align="lr", noun="domain"))
    assert len(lines) == 1 + 10 + 1 + 10
    assert lines[1].split()[0] == "d0.example" and lines[10].split()[0] == "d9.example"
    assert lines[11].strip() == "┄ 17 more domains · bottom 10 below (-v shows all)"
    assert lines[12].split()[0] == "d27.example" and lines[-1].split()[0] == "d36.example"
    assert len(st.ranked(["Domain", "Queries"], rows[:20])) == 21  # nothing hidden: every row
    set_verbose_output(True)
    try:
        assert len(st.ranked(["Domain", "Queries"], rows)) == 38
    finally:
        set_verbose_output(False)


def test_a_ranking_the_analyzer_trimmed_says_so() -> None:
    rows = [[f"h{i}", 34 - i] for i in range(34)]  # kept: top 24 and bottom 10 of 500
    lines = _plain(st.ranked(["Host", "Packets"], rows, total=500, noun="host"))
    assert lines[11].strip() == "┄ 480 more hosts · bottom 10 below (-v shows 14 of them)"
    set_verbose_output(True)
    try:
        lines = _plain(st.ranked(["Host", "Packets"], rows, total=500, noun="host"))
    finally:
        set_verbose_output(False)
    assert lines[25].strip() == "┄ 466 more hosts not kept · bottom 10 below" and len(lines) == 36


def test_ranked_slice_keeps_the_true_bottom() -> None:
    items = list(range(100))
    assert ranked_slice(items, 30) == list(range(20)) + list(range(90, 100))
    assert ranked_slice(items[:25], 30) == items[:25]


def test_decoded_powershell_stays_under_its_row_in_the_bottom_block() -> None:
    """counts() decodes -EncodedCommand under its row by position: the
    divider must not shift the bottom rows onto the wrong commands."""
    script = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
    counter = Counter({f"cmd{i} /c dir": 100 - i for i in range(30)})
    counter[f"powershell -enc {script}"] = 1  # the rarest: last of the bottom 10
    lines = _plain(counts(counter, "Command", width=100, decode=True))
    at = next(i for i, line in enumerate(lines) if "powershell -enc" in line)
    assert lines[at + 1].strip() == "decoded: whoami /all"
    assert sum("decoded:" in line for line in lines) == 1


def _run(*args: str) -> str:
    out = subprocess.run([sys.executable, "-m", "pcapper", *args, "--no-color", "--no-status"],
                         capture_output=True, text=True, timeout=600, cwd=Path(__file__).resolve().parents[1])
    assert out.returncode == 0, out.stderr[-1500:]
    return re.sub(r"\x1b\[[0-9;]*m", "", out.stdout)


def test_timeline_and_hostdetails_point_to_dnsqueries(tmp_path: Path) -> None:
    from test_dnsqueries import CLIENT, _capture

    path = str(_capture(tmp_path))
    timeline = _run(path, "--timeline", "-ip", CLIENT)
    assert "DNS query" not in timeline and "\nDNS ─" not in timeline
    assert f"--dnsqueries -ip {CLIENT} lists them" in timeline
    details = _run(path, "--hostdetails", "-ip", CLIENT, "-v")
    assert "DNS queries ─" not in details and f"--dnsqueries -ip {CLIENT} lists them" in details


def test_overview_counts_every_host_and_ranks_the_tail(tmp_path: Path) -> None:
    """The overview kept 24 hosts and called them "unique IPs"; its host
    table now ends with the 10 quietest hosts of the full ranking."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from pcapper.overview import analyze_overview
    from test_review_batches import T0, _write

    packets = []
    for i in range(40):  # host i sends 40 - i packets: a strict ranking
        for n in range(40 - i):
            pkt = Ether() / IP(src=f"10.1.0.{i + 10}", dst="10.1.1.1") / TCP(sport=40000 + n, dport=443, flags="S")
            pkt.time = T0 + n
            packets.append(pkt)
    summary = analyze_overview(_write(tmp_path, "hosts.pcap", packets), show_status=False)
    assert summary.summary_details["unique_ips"] == 41
    assert summary.ip_activity_total == 41 and len(summary.ip_activity) == 24
    assert [r["ip"] for r in summary.ip_activity_tail][-1] == "10.1.0.49"  # the quietest host


def test_strings_domains_are_whole_names_with_real_tlds() -> None:
    """The pattern's capturing group made findall() return "adobe." for
    www.adobe.com; and JavaScript tokens were counted as domains."""
    from pcapper.strings import DOMAIN_PATTERN
    from pcapper.utils import plausible_domain

    text = "GET http://www.adobe.com/x element.value=n.push(y.hR) dc01.corp.local evil.xyz"
    found = [d for d in DOMAIN_PATTERN.findall(text) if plausible_domain(d)]
    assert found == ["www.adobe.com", "dc01.corp.local", "evil.xyz"]


def test_divider_and_more_lines_use_real_plurals() -> None:
    assert [st._nouns(2, w) for w in ("address", "query", "key", "match", "URL")] == [
        "addresses", "queries", "keys", "matches", "URLs"]
    assert "3 more addresses" in st.more(3, "address")
