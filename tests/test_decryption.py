"""Unit tests for the tshark-driven decryption helpers.

These run without tshark installed: the subprocess boundary is stubbed, which is
the point — the defects being pinned here were all in how pcapper *interpreted*
tshark's output, not in tshark itself.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from pcapper import decryption
from pcapper.decryption import (
    _STREAM_FIELDS,
    _collect_streams,
    _follow_stream,
    _label_from_row,
    _run_tshark,
    _split_fields,
    _stream_label,
)


class _Completed:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestSplitFields:
    def test_ipv4_row(self) -> None:
        row = "3\t10.0.0.1\t44300\t10.0.0.2\t443\t\t"
        assert _split_fields(row, 7) == [
            "3", "10.0.0.1", "44300", "10.0.0.2", "443", "", "",
        ]

    def test_ipv6_row_keeps_its_empty_leading_columns(self) -> None:
        """The bug: tshark pads unmatched fields, and for IPv6 the empty
        columns come first. Stripping the row before splitting removed the
        leading tab and shifted every index down by one."""
        row = "7\t\t44300\t\t443\tfe80::1\tfe80::2"
        assert _split_fields(row, 7) == [
            "7", "", "44300", "", "443", "fe80::1", "fe80::2",
        ]

    def test_short_row_is_padded(self) -> None:
        assert _split_fields("9\t10.0.0.1", 7) == ["9", "10.0.0.1", "", "", "", "", ""]

    def test_long_row_is_clipped(self) -> None:
        assert len(_split_fields("\t".join("abcdefghij"), 7)) == 7

    def test_empty_row(self) -> None:
        assert _split_fields("", 7) == [""] * 7


class TestLabelFromRow:
    def test_ipv4_label(self) -> None:
        row = _split_fields("3\t10.0.0.1\t44300\t10.0.0.2\t443\t\t", 7)
        assert _label_from_row(row) == "10.0.0.1-44300_to_10.0.0.2-443"

    def test_ipv6_label_uses_the_ipv6_columns(self) -> None:
        row = _split_fields("7\t\t44300\t\t443\tfe80::1\tfe80::2", 7)
        assert _label_from_row(row) == "fe80::1-44300_to_fe80::2-443"

    def test_row_without_addresses_yields_no_label(self) -> None:
        assert _label_from_row(_split_fields("5\t\t\t\t\t\t", 7)) == ""


class TestStreamLabel:
    def test_known_stream_is_sanitised(self) -> None:
        labels = {4: "fe80::1-44300_to_fe80::2-443"}
        # ':' is not filename-safe and must not reach a path.
        assert _stream_label(4, labels) == "fe80_1-44300_to_fe80_2-443"

    def test_unknown_stream_falls_back(self) -> None:
        assert _stream_label(9, {}) == "stream_9"

    def test_empty_label_falls_back(self) -> None:
        assert _stream_label(9, {9: ""}) == "stream_9"


class TestCollectStreams:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, result) -> list[list[str]]:
        seen: list[list[str]] = []

        def fake(cmd, timeout=None):
            seen.append(cmd)
            return result

        monkeypatch.setattr(decryption, "_run_tshark", fake)
        return seen

    def test_streams_and_labels_come_from_one_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stdout = (
            "0\t10.0.0.1\t44300\t10.0.0.2\t443\t\t\n"
            "0\t10.0.0.2\t443\t10.0.0.1\t44300\t\t\n"
            "1\t\t50000\t\t443\tfe80::1\tfe80::2\n"
        )
        cmds = self._patch(monkeypatch, _Completed(stdout=stdout))
        streams, labels, errors, _frames = _collect_streams(Path("x.pcap"), "tls", None)
        assert streams == [0, 1]
        assert labels[0] == "10.0.0.1-44300_to_10.0.0.2-443"
        assert labels[1] == "fe80::1-50000_to_fe80::2-443"
        assert errors == []
        assert len(cmds) == 1, "labelling must not cost an extra pass per stream"

    def test_no_packet_count_cap_is_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``-c`` caps packets *read*, not packets matched, so combining it with
        a display filter returned nothing for every stream that did not contain
        the capture's first packet."""
        cmds = self._patch(monkeypatch, _Completed(stdout=""))
        _collect_streams(Path("x.pcap"), "tls", None)
        assert "-c" not in cmds[0]

    def test_all_label_fields_are_requested(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cmds = self._patch(monkeypatch, _Completed(stdout=""))
        _collect_streams(Path("x.pcap"), "tls", None)
        assert [c for c in cmds[0] if c in _STREAM_FIELDS] == list(_STREAM_FIELDS)

    def test_first_occurrence_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Without occurrence=f a tunnelled packet yields "0,1" for tcp.stream,
        # which fails int() and silently drops the stream from the listing.
        cmds = self._patch(monkeypatch, _Completed(stdout=""))
        _collect_streams(Path("x.pcap"), "tls", None)
        assert "occurrence=f" in cmds[0]

    def test_unparseable_stream_ids_are_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(
            monkeypatch,
            _Completed(stdout="\n-\t\t\t\t\t\t\nnope\t\t\t\t\t\t\n2\t1.1.1.1\t1\t2.2.2.2\t2\t\t\n"),
        )
        streams, labels, errors, _frames = _collect_streams(Path("x.pcap"), "tls", None)
        assert streams == [2]
        assert errors == []

    def test_later_packets_can_supply_a_missing_label(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(
            monkeypatch,
            _Completed(stdout="4\t\t\t\t\t\t\n4\t10.0.0.1\t1\t10.0.0.2\t2\t\t\n"),
        )
        _, labels, _, _ = _collect_streams(Path("x.pcap"), "tls", None)
        assert labels[4] == "10.0.0.1-1_to_10.0.0.2-2"

    def test_nonzero_exit_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, _Completed(stderr="boom", returncode=2))
        streams, labels, errors, _frames = _collect_streams(Path("x.pcap"), "tls", None)
        assert streams == [] and labels == {}
        assert errors == ["boom"]

    def test_timeout_is_reported_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, None)
        streams, labels, errors, _frames = _collect_streams(Path("capture.pcap"), "tls", None)
        assert streams == [] and labels == {}
        assert len(errors) == 1
        assert "timed out" in errors[0]
        assert "capture.pcap" in errors[0]


class TestRunTshark:
    def test_timeout_returns_none_rather_than_propagating(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="tshark", timeout=1)

        monkeypatch.setattr(subprocess, "run", boom)
        assert _run_tshark(["tshark"], timeout=1) is None

    def test_a_timeout_is_always_passed_to_subprocess(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = {}

        def fake(cmd, **kwargs):
            seen.update(kwargs)
            return _Completed()

        monkeypatch.setattr(subprocess, "run", fake)
        _run_tshark(["tshark"])
        assert seen.get("timeout") == decryption.TSHARK_TIMEOUT
        assert seen["timeout"] > 0


class TestFollowStream:
    def test_timeout_surfaces_as_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(decryption, "_run_tshark", lambda cmd, **kw: None)
        assert _follow_stream(Path("x.pcap"), 1, None, "tls") is None

    def test_output_is_returned_verbatim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            decryption, "_run_tshark", lambda cmd, **kw: _Completed("body", "warn")
        )
        assert _follow_stream(Path("x.pcap"), 1, None, "tls") == ("body", "warn")


class TestDecryptTls:
    def test_a_stalled_stream_is_skipped_not_fatal(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """One pathological stream must not take the whole run with it."""
        monkeypatch.setattr(decryption, "_tshark_available", lambda: True)
        monkeypatch.setattr(
            decryption,
            "_collect_streams",
            lambda path, flt, pref: ([0, 1], {0: "a-1_to_b-2", 1: "c-3_to_d-4"}, [], {}),
        )
        calls: list[int] = []

        def fake_follow(path, stream_id, pref, proto):
            calls.append(stream_id)
            if stream_id == 0:
                return None  # stalled
            return ("decrypted payload", "")

        monkeypatch.setattr(decryption, "_follow_stream", fake_follow)
        monkeypatch.setattr(decryption, "_follow_streams", lambda *a, **k: None)  # the batch timed out

        summary = decryption.decrypt_tls(
            Path("x.pcap"), tmp_path / "keys.log", tmp_path / "out", limit=0
        )
        assert calls == [0, 1], "the second stream must still be attempted"
        assert summary.stream_count == 1
        assert len(summary.outputs) == 1
        assert any("timed out" in err for err in summary.errors)

    def test_filename_uses_the_endpoint_label(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(decryption, "_tshark_available", lambda: True)
        monkeypatch.setattr(
            decryption,
            "_collect_streams",
            lambda path, flt, pref: ([2], {2: "fe80::1-44300_to_fe80::2-443"}, [], {}),
        )
        monkeypatch.setattr(
            decryption, "_follow_stream", lambda *a, **k: ("payload", "")
        )
        monkeypatch.setattr(decryption, "_follow_streams", lambda *a, **k: {})
        summary = decryption.decrypt_tls(
            Path("x.pcap"), tmp_path / "keys.log", tmp_path / "out", limit=0
        )
        assert summary.outputs[0].name == "tls_2_fe80_1-44300_to_fe80_2-443.txt"



def _follow_block(stream_id: int, body: str) -> str:
    """What ``tshark -q -z follow,tls,ascii,<id>`` prints for one stream."""
    rule = "=" * 67
    return (
        f"\n{rule}\nFollow: tls,ascii\nFilter: tcp.stream eq {stream_id}\n"
        f"Node 0: 10.0.0.1:5000{stream_id}\nNode 1: 10.0.0.2:443\n{body}{rule}\n"
    )


class TestFollowManyStreamsInOneRun:
    def test_blocks_are_split_by_stream(self) -> None:
        # tshark prints the taps last first; a body may hold a rule of '='.
        output = _follow_block(5, "five\n" + "=" * 67 + "\n") + _follow_block(1, "one\n") + _follow_block(0, "")
        blocks = decryption._split_follow_output(output, [("tls", 0), ("tls", 1), ("tls", 5)])
        assert blocks == {
            ("tls", 5): _follow_block(5, "five\n" + "=" * 67 + "\n"),
            ("tls", 1): _follow_block(1, "one\n"),
            ("tls", 0): _follow_block(0, ""),
        }

    def test_a_payload_that_looks_like_a_block_header_is_not_trusted(self) -> None:
        """A stream that carries tshark's own block header (someone following
        a follow) would cut it short: such a run is followed stream by stream."""
        fake = "\n" + "=" * 67 + "\nFollow: tls,ascii\nFilter: tcp.stream eq 9\n"
        output = _follow_block(1, "one" + fake + "more\n") + _follow_block(0, "")
        assert decryption._split_follow_output(output, [("tls", 0), ("tls", 1)]) == {}
        # A block missing, one extra, or another stream than asked for: same.
        assert decryption._split_follow_output(_follow_block(1, "x\n"), [("tls", 0), ("tls", 1)]) == {}
        both = _follow_block(1, "x\n") + _follow_block(2, "y\n")
        assert decryption._split_follow_output(both, [("tls", 0), ("tls", 1)]) == {}
        assert decryption._split_follow_output("tshark: invalid -z argument\n", [("tls", 0)]) == {}

    def test_one_run_follows_every_stream(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """One tshark read for all the streams, each file what a run of its
        own would have written."""
        monkeypatch.setattr(decryption, "_tshark_available", lambda: True)
        monkeypatch.setattr(
            decryption, "_collect_streams",
            lambda path, flt, pref: ([0, 1, 5], {0: "a_to_b", 1: "c_to_d", 5: "e_to_f"}, [], {0: 7, 1: 9, 5: 4}),
        )
        runs: list[list[str]] = []

        def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
            runs.append(cmd)
            follows = [arg for arg in cmd if arg.startswith("follow,")]
            out = "".join(_follow_block(int(arg.rsplit(",", 1)[1]), f"body {arg}\n") for arg in reversed(follows))
            return _Completed(out, "")

        monkeypatch.setattr(decryption, "_run_tshark", fake_run)
        monkeypatch.setattr(decryption, "_follow_stream", lambda *a, **k: pytest.fail("followed on its own"))
        summary = decryption.decrypt_tls(Path("x.pcap"), tmp_path / "keys.log", tmp_path / "out", limit=0)
        assert len(runs) == 1
        assert runs[0][runs[0].index("-c") + 1] == "9", "the follow run stops at the last frame its streams need"
        assert summary.stream_count == 3
        texts = {path.name: path.read_text() for path in summary.outputs}
        assert texts["tls_1_c_to_d.txt"] == _follow_block(1, "body follow,tls,ascii,1\n")

    def test_a_timed_out_run_falls_back_to_one_stream_at_a_time(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(decryption, "_tshark_available", lambda: True)
        monkeypatch.setattr(decryption, "_collect_streams", lambda path, flt, pref: ([3, 4], {}, [], {}))
        monkeypatch.setattr(decryption, "_follow_streams", lambda *a, **k: None)
        followed: list[int] = []

        def fake_follow(path, stream_id, pref, proto):  # type: ignore[no-untyped-def]
            followed.append(stream_id)
            return ("payload", "")

        monkeypatch.setattr(decryption, "_follow_stream", fake_follow)
        summary = decryption.decrypt_tls(Path("x.pcap"), tmp_path / "keys.log", tmp_path / "out", limit=0)
        assert followed == [3, 4] and summary.stream_count == 2



def _ssh_block(stream_id: int, body: str) -> str:
    return _follow_block(stream_id, body).replace("Follow: tls,ascii", "Follow: ssh,ascii")


class TestFrameBoundAndOneRunForBothProtocols:
    def test_listing_keeps_each_stream_s_last_frame(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rows = (
            "0\t10.0.0.1\t1\t10.0.0.2\t443\t\t\t12\n"
            "0\t10.0.0.2\t443\t10.0.0.1\t1\t\t\t40\n"
            "3\t10.0.0.3\t2\t10.0.0.4\t443\t\t\t33\n"
            "4\t10.0.0.5\t3\t10.0.0.6\t443\t\t\t\n"
        )
        monkeypatch.setattr(decryption, "_run_tshark", lambda cmd, **kw: _Completed(rows, ""))
        streams, _labels, _errors, frames = _collect_streams(Path("x.pcap"), "tls", None)
        assert streams == [0, 3, 4]
        assert frames == {0: 40, 3: 33}  # stream 4: a row without one, so no bound for it

    def test_no_bound_when_a_stream_has_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(decryption, "_tshark_available", lambda: True)
        monkeypatch.setattr(decryption, "_collect_streams", lambda path, flt, pref: ([1, 2], {}, [], {1: 5}))
        seen: list[list[str]] = []

        def fake_follow(path, wanted, prefs, last_frame=None):  # type: ignore[no-untyped-def]
            seen.append([last_frame])
            return {}

        monkeypatch.setattr(decryption, "_follow_streams", fake_follow)
        monkeypatch.setattr(decryption, "_follow_stream", lambda *a, **k: ("", ""))
        decryption.decrypt_tls(Path("x.pcap"), tmp_path / "keys.log", tmp_path / "out", limit=0)
        assert seen == [[None]]

    def test_tls_and_ssh_are_followed_in_one_run(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Both key logs: one tshark read follows the streams of both, and each
        protocol's files are the ones a run of its own writes."""
        monkeypatch.setattr(decryption, "_tshark_available", lambda: True)

        def listing(path, flt, pref):  # type: ignore[no-untyped-def]
            if flt == "tls":
                return [0, 2], {0: "a_to_b", 2: "c_to_d"}, [], {0: 10, 2: 30}
            return [5], {5: "e_to_f"}, [], {5: 20}

        monkeypatch.setattr(decryption, "_collect_streams", listing)
        runs: list[list[str]] = []

        def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
            runs.append(cmd)
            taps = [arg.split(",") for arg in cmd if arg.startswith("follow,")]
            blocks = [
                (_follow_block if proto == "tls" else _ssh_block)(int(stream), f"{proto} body {stream}\n")
                for _f, proto, _fmt, stream in reversed(taps)
            ]
            return _Completed("".join(blocks), "")

        monkeypatch.setattr(decryption, "_run_tshark", fake_run)
        monkeypatch.setattr(decryption, "_follow_stream", lambda *a, **k: pytest.fail("followed on its own"))
        tls_out, ssh_out = tmp_path / "tls", tmp_path / "ssh"
        summaries = decryption.decrypt_capture(
            Path("x.pcap"), tls_keylog=tmp_path / "tls.keys", ssh_keylog=tmp_path / "ssh.keys",
            tls_output_dir=tls_out, ssh_output_dir=ssh_out, limit=0,
        )
        assert [summary.protocol for summary in summaries] == ["TLS", "SSH"]
        assert len(runs) == 1
        command = runs[0]
        assert f"tls.keylog_file:{tmp_path / 'tls.keys'}" in command and f"ssh.keylog_file:{tmp_path / 'ssh.keys'}" in command
        assert command[command.index("-c") + 1] == "30"
        assert sorted(p.name for p in tls_out.iterdir()) == ["tls_0_a_to_b.txt", "tls_2_c_to_d.txt"]
        assert (ssh_out / "ssh_5_e_to_f.txt").read_text() == _ssh_block(5, "ssh body 5\n")
