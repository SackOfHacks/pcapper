"""Regressions for --files HTTP extraction (wannacry-20170515 capture).

Four defects hid or mislabelled the executables in that capture:
- large HTTP response streams parsed as OpenVPN and skipped HTTP extraction;
- nameless requests ("/1") were not queued, shifting filenames onto the wrong
  responses;
- 304 responses were read to EOF, swallowing later responses as their body;
- table cells escaped pcapper's own colour codes into literal "\\x1b[...m".
"""

from __future__ import annotations

import re

import pytest

from pcapper.files import _http_body_note, _parse_http_stream
from pcapper.reporting_format import format_table
from test_review_batches import _tcp, _write

CLIENT, SERVER = "10.10.110.131", "10.10.110.135"


def _segments(src, dst, sport, dport, data: bytes, seq: int, mss: int = 1400):
    return [
        _tcp(src, dst, sport, dport, data[off : off + mss], seq=seq + off)
        for off in range(0, len(data), mss)
    ]


def _response(status: str, body: bytes = b"", headers: str = "") -> bytes:
    head = f"HTTP/1.1 {status}\r\n{headers}"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    return head.encode() + b"\r\n" + body


def _get(path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {SERVER}\r\n\r\n".encode()


def test_format_table_keeps_colour_but_escapes_other_controls() -> None:
    coloured = "\x1b[1m\x1b[33mncsi.txt\x1b[0m"
    out = format_table([["A", "B"], [coloured, "x"], ["evil\x1b]0;pwn\x07", "y"]])
    assert coloured in out
    assert "\\x1b[1m" not in out
    assert "\\x1b]0;pwn\\x07" in out
    # Width is computed on visible text, so columns still line up once the
    # colour codes are stripped.
    visible = re.sub(r"\x1b\[[0-9;]*m", "", out).splitlines()
    assert visible[1].rindex("x") == visible[0].index("B")


def test_304_response_has_no_body() -> None:
    stream = _response("304 Not Modified", headers="ETag: \"1\"\r\n") + _response(
        "403 Forbidden", b"<html>forbidden</html>"
    )
    msgs = _parse_http_stream(stream)
    assert [m["status_code"] for m in msgs] == [304, 403]
    assert msgs[0]["body"] == b""
    assert msgs[1]["body"] == b"<html>forbidden</html>"


def test_error_page_note_names_status() -> None:
    assert _http_body_note({"status_code": 403}, b"x") == (
        "HTTP 403 Response Body (not the requested file)"
    )
    assert _http_body_note({"status_code": 200}, b"x") == "HTTP Response Body"


def test_large_exe_download_and_pairing_end_to_end(tmp_path) -> None:
    pytest.importorskip("scapy.all")
    from pcapper.files import analyze_files

    exe = b"MZ" + b"\x90" * 40000  # > 18.5 KB: used to classify as OpenVPN
    packets = []
    # Keep-alive connection: nameless /1 (301), 304, then a 403 error page.
    packets.append(_tcp(CLIENT, SERVER, 50000, 80, _get("/1") + _get("/icons/x.gif") + _get("/1/tool.chm"), seq=100))
    packets.append(
        _tcp(
            SERVER, CLIENT, 80, 50000,
            _response("301 Moved Permanently", b"<html>moved</html>")
            + _response("304 Not Modified")
            + _response("403 Forbidden", b"<html>forbidden page</html>"),
            seq=500,
        )
    )
    # Separate connection carrying the large executable.
    packets.append(_tcp(CLIENT, SERVER, 50001, 80, _get("/1/wannacry.exe"), seq=1000))
    packets += _segments(
        SERVER, CLIENT, 80, 50001,
        _response("200 OK", exe, "Content-Type: application/x-msdos-program\r\n"),
        seq=9000,
    )
    pcap = _write(tmp_path, "http_exe.pcap", packets)

    summary = analyze_files(pcap, show_status=False)
    by_name = {a.filename: a for a in summary.artifacts}

    assert "wannacry.exe" in by_name
    assert by_name["wannacry.exe"].file_type == "EXE/DLL"
    assert by_name["wannacry.exe"].size_bytes == len(exe)
    # The 403 page is paired with its own request and labelled as an error page.
    assert "tool.chm" in by_name
    assert "HTTP 403" in (by_name["tool.chm"].note or "")
    # The 304 no longer swallows the 403 as a fake x.gif body.
    assert "x.gif" not in by_name

    checks = summary.deterministic_checks
    assert any("wannacry.exe" in e for e in checks.get("known_malware_filename", []))
    assert any("wannacry.exe" in e for e in checks.get("internal_executable_staging", []))


def test_named_internal_server_is_not_staging(tmp_path) -> None:
    pytest.importorskip("scapy.all")
    from pcapper.files import analyze_files

    exe = b"MZ" + b"\x90" * 2000
    req = b"GET /pkg/setup.exe HTTP/1.1\r\nHost: deploy.corp.example\r\n\r\n"
    pcap = _write(tmp_path, "named.pcap", [
        _tcp(CLIENT, SERVER, 50002, 80, req, seq=100),
        *_segments(SERVER, CLIENT, 80, 50002, _response("200 OK", exe), seq=700),
    ])
    summary = analyze_files(pcap, show_status=False)
    assert any(a.filename == "setup.exe" for a in summary.artifacts)
    assert not summary.deterministic_checks.get("internal_executable_staging")
    assert not summary.deterministic_checks.get("known_malware_filename")
