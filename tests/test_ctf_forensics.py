"""CTF analyzer and report: decoding and de-duplicating flag candidates."""

from __future__ import annotations

import base64
import re
from collections import Counter
from pathlib import Path

from pcapper.ctf import _PARAM_VALUE_RE, CtfSummary, _iter_decode_candidates
from pcapper.reporting.ctf import render_ctf_summary


def test_key_value_token_value_is_decoded() -> None:
    token = "d=" + base64.b64encode(b"picoCTF{b4s3_64_1n_ur1}").decode()
    found = [(value, chain) for value, chain in _iter_decode_candidates(token) if value == "picoCTF{b4s3_64_1n_ur1}"]
    assert found and found[0][1] == "raw->param->b64"


def test_base64_padding_is_not_a_key_value_pair() -> None:
    assert _PARAM_VALUE_RE.match("YWJjZA==") is None
    assert _PARAM_VALUE_RE.match("YWJj=") is None
    assert _PARAM_VALUE_RE.match("password=hunter2").group(1) == "hunter2"


def _candidate(value: str, packet: int, chain: str = "raw", source: str = "payload") -> dict:
    return {"candidate": value, "score": 6, "confidence": "high", "decode_chain": chain, "source": source,
            "reassembled": False, "packet": packet, "ts": 1700000000.0 + packet, "src": "10.0.0.9", "dst": "10.0.0.5",
            "protocol": "TCP/80", "context": "raw payload wrapper match"}


def test_report_lists_each_flag_once_and_credentials_separately() -> None:
    candidates = [_candidate("picoCTF{n0t_tw1c3}", 3), _candidate("picoCTF{n0t_tw1c3}", 9),
                  _candidate("admin:Sup3rS3cret", 4, chain="http-basic", source="http")]
    summary = CtfSummary(
        path=Path("synthetic.pcap"), total_packets=10, hits=[], decoded_hits=[], token_counts=Counter(), file_hints=[],
        errors=[], first_seen=1700000000.0, last_seen=1700000010.0, duration_seconds=10.0,
        confidence_counts=Counter(high=3), candidate_findings=candidates, deterministic_checks={}, timeline=[],
        false_positive_context=[],
    )
    text = re.sub(r"\x1b\[[0-9;]*m", "", render_ctf_summary(summary))
    flags = text.split("Flags", 1)[1].split("Credentials", 1)[0]
    assert flags.count("picoCTF{n0t_tw1c3}") == 1
    assert re.search(r"picoCTF\{n0t_tw1c3\}\s+2\s+3\s", flags)  # seen twice, first in packet 3
    assert "CTF{n0t_tw1c3}" not in flags.replace("picoCTF{n0t_tw1c3}", "")
    assert "1 flag found" in text and "admin:Sup3rS3cret" in text.split("Credentials", 1)[1]
