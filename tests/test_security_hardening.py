"""Hostile-capture hardening found by the 2.9.0 security review.

Each test reproduces a reviewer finding on a synthetic capture: a gzip bomb,
oversized BER integers, an unparseable certificate name, terminal escape
injection through renderers that skipped ``display_safe``, and credentials
that ``--redact`` did not hide.
"""

from __future__ import annotations

import gzip
import json
import sys
import zlib
from collections import Counter

from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore

from pcapper import cli
from pcapper.coloring import ANSI_BLACK, PALETTE, danger, suspicious_bg
from pcapper.files import _safe_decompress
from pcapper.goose import analyze_goose
from pcapper.utils import redact_sensitive_text, terminal_safe, to_serializable


def test_gzip_bomb_is_capped_without_inflating_everything() -> None:
    bomb = gzip.compress(b"\x00" * (64 * 1024 * 1024))
    out = _safe_decompress(bomb, "gzip", max_output=1024 * 1024)
    assert len(out) == 1024 * 1024
    small = zlib.compress(b"hello world" * 10)
    assert _safe_decompress(small, "deflate") == b"hello world" * 10


def test_oversized_goose_integers_do_not_crash(tmp_path) -> None:
    huge = bytes([0x85, 0x82, 0x07, 0xD0]) + b"\xff" * 2000  # stNum of 2000 bytes
    pdu_body = bytes([0x80, 0x03]) + b"gcb" + huge
    pdu = bytes([0x61, 0x82]) + len(pdu_body).to_bytes(2, "big") + pdu_body
    goose = (0x0001).to_bytes(2, "big") + (8 + len(pdu)).to_bytes(2, "big") + b"\x00" * 4 + pdu
    capture = tmp_path / "goose.pcap"
    wrpcap(str(capture), [Ether(dst="01:0c:cd:01:00:01", type=0x88B8) / Raw(goose)])
    summary = analyze_goose(capture, show_status=False)
    assert summary.goose_packets == 1
    json.dumps(to_serializable(summary))
    assert Counter({2**4000: 1}).most_common()  # patched most_common sort key


def test_terminal_safe_keeps_colours_and_escapes_controls() -> None:
    high = danger("HIGH", enabled=True)
    badge = suspicious_bg("WARN", enabled=True)  # black text on a yellow badge
    safe = terminal_safe(f"{high} {badge} var=\x1b]0;PWNED\x07 end\x1b[2J")
    assert safe.startswith(f"{high} {badge} var=")
    assert "\x1b]" not in safe and "\x07" not in safe and "\x1b[2J" not in safe


def test_terminal_safe_keeps_only_pcappers_own_colours() -> None:
    """Packet text that reaches a renderer unescaped can colour text only the
    way pcapper does: concealed, reverse-video, blinking, 256-colour, 24-bit
    and bare black text (invisible on a dark terminal) are shown escaped."""
    for code in PALETTE - {ANSI_BLACK}:
        assert terminal_safe(f"x{code}y") == f"x{code}y"
    for injected in ("\x1b[8m", "\x1b[7m", "\x1b[5m", "\x1b[38;5;16m",
                     "\x1b[38;2;0;0;0m", "\x1b[40m", "\x1b[1;31m", "\x1b[30m"):
        safe = terminal_safe(f"ioc {injected}evil.example\x1b[0m")
        assert safe == f"ioc \\x1b{injected[1:]}evil.example\x1b[0m"


def test_redaction_covers_ot_evidence_and_common_forms() -> None:
    for text, secret in (
        ("operator 'OP1' password '13330'", "13330"),
        ("user 'Administrator' password '1'", "'1'"),
        ('{"password": "hunter22"}', "hunter22"),
        ("USER bob PASS ftpsecret", "ftpsecret"),
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
        ("GET /login?password=hunter22&x=1", "hunter22"),
    ):
        assert secret not in redact_sensitive_text(text), text


def test_export_redacts_secret_fields_and_keys() -> None:
    data = {"secret": "s3cr3t", "password_counts": {"hunter22": 2}, "note": "password=abc12"}
    out = to_serializable(data, redact=True)
    assert "s3cr3t" not in json.dumps(out) and "hunter22" not in json.dumps(out)
    assert "abc12" not in json.dumps(out)
    assert to_serializable(data)["secret"] == "s3cr3t"  # unredacted by default


def test_rendered_report_neutralises_escape_injection(tmp_path, monkeypatch, capfd) -> None:
    body = b"\x00\x00\x01\x00" + b"\x0c\x00%MB\x1b]0;PWN\x07AA" + b"\x01\x00A"
    inst = (0x58).to_bytes(2, "little") + b"\x14\x00" + body
    frame = b"LSIS-XGT\x00\x00\x00\x00\xa0\x33\x00\x00" + len(inst).to_bytes(2, "little") + b"\x03\x00" + inst
    capture = tmp_path / "xgt.pcap"
    wrpcap(str(capture), [Ether() / IP() / TCP(sport=40000, dport=2004) / Raw(frame)])
    monkeypatch.setattr(sys, "argv", ["pcapper", str(capture), "--xgt"])
    assert cli.main() == 0
    out = capfd.readouterr().out
    assert "\x1b]" not in out and "\x07" not in out
