"""The terminal display: one progress bar per capture by default; with -v
the detail (pass percentages, analysis timing, library warnings), each on
its own line. Report output and warnings never share a line with either."""

from __future__ import annotations

import io
import logging
import re
import sys
import warnings
from pathlib import Path

import pytest

from pcapper import progress


class _Terminal:
    """stdout and stderr of one terminal: every write, in order."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str]] = []

    def stream(self, name: str) -> io.TextIOBase:
        terminal = self

        class _Stream(io.TextIOBase):
            encoding = "utf-8"

            def write(self, text: str) -> int:
                terminal.writes.append((name, text))
                return len(text)

            def isatty(self) -> bool:
                return True

            def fileno(self) -> int:
                raise OSError("no fd")  # columns fall back to 80

        return _Stream()

    def screen(self) -> list[str]:
        """What the terminal shows: \\r returns to column 0, \\n ends a line."""
        out, line, col = [], [], 0
        for ch in "".join(text for _name, text in self.writes):
            if ch == "\n":
                out.append("".join(line).rstrip())
                line, col = [], 0
            elif ch == "\r":
                col = 0
            else:
                line[col:col + 1] = [ch]
                col += 1
        out.append("".join(line).rstrip())
        return [re.sub(r"\x1b\[[0-9;]*m", "", text) for text in out]


def _attach(monkeypatch: pytest.MonkeyPatch) -> _Terminal:
    """A terminal on stdout and stderr. Called in the test body: pytest puts
    its own capture streams back when the body starts."""
    term = _Terminal()
    monkeypatch.setattr(sys, "stdout", term.stream("out"))
    monkeypatch.setattr(sys, "stderr", term.stream("err"))
    monkeypatch.setattr(progress, "_TICK", 3600.0)  # the test draws, not the ticker
    return term


def test_default_display_is_one_bar(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = _attach(monkeypatch)
    monkeypatch.setattr(sys, "warnoptions", [])
    saved_level = logging.getLogger("scapy").level
    with progress.display_session(verbose=False, status=True, color=False):
        progress.capture_begin(Path("wannacry.pcapng"), index=1, total=1, weights=[1.0])
        bar = progress.build_statusbar(Path("wannacry.pcapng"))
        bar.update(40)  # a read pass feeds the bar instead of drawing a line
        assert progress.run_with_busy_status(Path("wannacry.pcapng"), True, "Threats", lambda: 7) == 7
        assert logging.getLogger("scapy").level == logging.ERROR  # its per-record warnings: -v only
        with warnings.catch_warnings(record=True) as caught:
            warnings.warn("cryptography deprecation", DeprecationWarning)
        assert caught == []
        progress.redraw_bar()
        drawn = terminal.screen()
        bar.finish()
    assert len([line for line in drawn if line]) == 1
    assert re.fullmatch(r"\s+wannacry\.pcapng\s+━+─+\s+36%\s+0:00", drawn[-1]), drawn
    assert not any("Processing" in line or "Threats" in line for line in drawn)
    assert terminal.screen() == [""]  # the bar is gone once the run is over
    assert logging.getLogger("scapy").level == saved_level  # restored


def test_report_output_takes_the_bar_off_its_line(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = _attach(monkeypatch)
    with progress.display_session(verbose=False, status=True, color=False):
        progress.capture_begin(Path("a.pcap"), index=1, total=2, weights=[1.0])
        progress.redraw_bar()
        print("DNS · a.pcap")
        progress.redraw_bar()  # report output still flowing: the bar waits
        assert terminal.screen() == ["DNS · a.pcap", ""]
        monkeypatch.setattr(progress, "_LAST_WRITE", 0.0)
        progress.redraw_bar()  # quiet again, at a line start: it comes back below
        assert terminal.screen()[0] == "DNS · a.pcap"
        assert terminal.screen()[1].strip().startswith("[1/2] a.pcap")
        print("  OK no findings")
    assert terminal.screen() == ["DNS · a.pcap", "  OK no findings", ""]


def test_verbose_display_keeps_warnings_off_the_status_line(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = _attach(monkeypatch)
    level = logging.getLogger("scapy").level
    with progress.display_session(verbose=True, status=True, color=False):
        assert logging.getLogger("scapy").level == level  # scapy's warnings are detail: shown
        bar = progress.build_statusbar(Path("x.pcap"))
        bar.update(9)
        # What the interpreter's showwarning does with a warning (pytest
        # records them instead): format it and write it to sys.stderr.
        sys.stderr.write(warnings.formatwarning(
            "Parsed a serial number which wasn't positive", UserWarning, "files.py", 3535))
        bar.update(10)
        bar.finish()
        progress.run_with_busy_status(Path("x.pcap"), False, "Threats", lambda: None)
    screen = [line for line in terminal.screen() if line]
    assert any(line.endswith("UserWarning: Parsed a serial number which wasn't positive") for line in screen)
    assert all("%" not in line for line in screen if "Warning" in line)
    assert "Processing x.pcap 100%" in screen
    assert screen[-2:] == ["[pcapper] Threats x.pcap: starting...", screen[-1]]
    assert re.fullmatch(r"\[pcapper\] Threats x\.pcap: done in \d+\.\ds", screen[-1])


def test_bar_follows_the_cost_of_planned_analyses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(progress, "_BAR_MODE", True)
    progress.set_analysis_weigher(lambda module: 1.0 if module == "pcapper.modbus" else 6.0)
    try:
        # read 40, then one step planned at 3 IT analyses + 2 OT ones = 20
        progress.capture_begin(Path("c.pcap"), weights=[40.0, 20.0], expected=[0.0, 20.0])
        capture = progress._CAPTURE
        progress.build_statusbar(Path("c.pcap"), enabled=False)  # disabled: no effect
        progress._capture_pass(100)
        assert capture.fraction() == pytest.approx(40 * 0.9 / 60)
        progress.capture_next_unit()
        assert capture.fraction() == pytest.approx(40 / 60)
        progress.subtask_done(module="pcapper.dns")
        progress.subtask_done(module="pcapper.modbus")
        assert capture.fraction() == pytest.approx((40 + 7) / 60)
        for _ in range(9):  # more than planned: the step never shows full early
            progress.subtask_done(module="pcapper.http")
        assert capture.fraction() == pytest.approx((40 + 20 * 0.97) / 60)
        progress.capture_plan(weights=[1.0, 99.0], expected=[0.0, 99.0])
        assert capture.fraction() == pytest.approx((40 + 20 * 0.97) / 60)  # never moves back
    finally:
        progress.capture_end()
        progress.set_analysis_weigher(None)


def test_a_dry_run_leaves_the_capture_as_it_was(tmp_path: Path) -> None:
    """The bar's plan comes from the shared pass's dry run, before the real
    read: it must not unset the capture's packet view (every memoised result
    would miss) nor cache auto decode-as results from an empty view."""
    from pcapper import pcap_cache, port_heuristics, sharedpass
    from pcapper.threats import analyze_threats
    from test_review_batches import T0, _tcp, _write

    pkt = _tcp("10.0.0.9", "10.0.0.5", 40000, 10203, b"\x03\x00\x00\x16")
    pkt.time = T0
    path = _write(tmp_path, "plc.pcap", [pkt])
    packets, meta = pcap_cache.load_packets_if_allowed(path, show_status=False)
    pcap_cache.set_forced_packet_view(path, packets, meta)
    try:
        serial = pcap_cache.get_forced_packet_view_serial(path)
        keys = sharedpass.dry_run_keys(path, [(analyze_threats, (), {})])
        assert len(keys) > 20
        assert pcap_cache.get_forced_packet_view(path) is packets
        assert pcap_cache.get_forced_packet_view_serial(path) == serial
        assert port_heuristics.detections_for(path) == [] and port_heuristics._DETECTED == {}
    finally:
        pcap_cache.clear_forced_packet_view(path)


def test_dry_run_roots_are_what_the_shared_pass_already_dry_runs(pcap) -> None:
    """The bar dry-runs a step's roots: each must be called by its step, and
    be a fan-out orchestrator or an analyzer the orchestrators' own dry runs
    run in production (never Suricata, a lookup or an export)."""
    from pcapper import cli, sharedpass

    src = Path(cli.__file__).read_text()
    loop = src[src.index("        for step in ordered_steps:"):src.index("        if forced_view_for_path:")]
    orchestrators = {name for names in cli._DRY_RUN_STEP_ROOTS.values() for name in names
                     if getattr(getattr(cli, name), "_pcapper_fan_out", False)}
    planned = set()
    for name in orchestrators:
        plan = sharedpass.discover(pcap("dns.pcap"), [(getattr(cli, name), (), {})])
        planned |= {func.__name__ for func, _args, _kwargs in plan.calls}
    for step, names in cli._DRY_RUN_STEP_ROOTS.items():
        body = loop[loop.index(f'step == "{step}"'):]
        for name in names:
            assert hasattr(getattr(cli, name), "__wrapped__"), name  # memoised
            assert name in orchestrators or name in planned, name
            assert f"{name}(" in body[:4000], (step, name)


@pytest.mark.skipif(not hasattr(__import__("os"), "openpty"), reason="needs a pseudo-terminal")
@pytest.mark.parametrize("verbose", [False, True])
def test_cli_on_a_terminal(pcap, verbose: bool) -> None:
    """The real CLI with stderr on a terminal: a bar by default, the read
    pass's percentage lines with -v."""
    import os
    import subprocess

    master, slave = os.openpty()
    env = dict(os.environ, PCAPPER_CACHE_ENABLED="0", PYTHONIOENCODING="utf-8")
    env.pop("NO_COLOR", None)
    proc = subprocess.Popen(
        [sys.executable, "-m", "pcapper", str(pcap("dns.pcap")), "--dns", *(["-v"] if verbose else [])],
        stdout=subprocess.PIPE, stderr=slave, env=env, cwd=Path(__file__).parent.parent,
    )
    os.close(slave)
    chunks = []
    while True:
        try:
            data = os.read(master, 4096)
        except OSError:  # the child closed the terminal
            break
        if not data:
            break
        chunks.append(data)
    os.close(master)
    with proc.stdout:
        out = proc.stdout.read().decode("utf-8", "replace")
    assert proc.wait(timeout=120) == 0
    shown = re.sub(r"\x1b\[[0-9;]*m", "", b"".join(chunks).decode("utf-8", "replace"))
    assert "DNS · dns.pcap" in out
    if verbose:
        assert "Processing dns.pcap 100%" in shown
        assert not re.search(r"\d+%\s+\d+:\d\d", shown)
    else:
        assert re.search(r"dns\.pcap\s+[━#]+[━─#-]*\s+\d+%\s+0:0\d", shown), shown
        assert "Processing" not in shown and "WARNING" not in shown
