"""Unit tests for pcapper.reassembly.

The two defects these pin were both silent: a mis-assembled stream produced no
error and no warning, just an artifact that was never carved, and a stream with
a hole in it produced a blob that looked complete and carried a confident
SHA-256. Neither needed a capture file to reproduce, which is the argument for
testing the reassembler directly.
"""

from __future__ import annotations

from pcapper.reassembly import SEQ_MODULO, Reassembly, reassemble, relative_seq


class TestRelativeSeq:
    def test_forward_distance(self) -> None:
        assert relative_seq(110, 100) == 10

    def test_backward_distance_is_negative(self) -> None:
        # A segment preceding the origin must sort before it, not 4 GB after it.
        assert relative_seq(90, 100) == -10

    def test_distance_across_the_wrap_point(self) -> None:
        assert relative_seq(2, SEQ_MODULO - 2) == 4
        assert relative_seq(SEQ_MODULO - 2, 2) == -4

    def test_identity(self) -> None:
        assert relative_seq(12345, 12345) == 0


class TestOrdering:
    def test_in_order_segments(self) -> None:
        assert reassemble([(100, b"AAA"), (103, b"BBB")], 1024).data == b"AAABBB"

    def test_out_of_order_segments(self) -> None:
        assert reassemble([(103, b"BBB"), (100, b"AAA")], 1024).data == b"AAABBB"

    def test_segment_preceding_the_first_one_observed(self) -> None:
        # Reordering at the start of a capture: the first packet read is not the
        # first packet of the stream. It must not be treated as the origin in a
        # way that flings the earlier segment to the end.
        assert reassemble([(104, b"BBBB"), (100, b"AAAA")], 1024).data == b"AAAABBBB"

    def test_sequence_wraparound(self) -> None:
        """The bug: a stream whose ISN sits near 2**32 wraps mid-transfer.

        Ordering by raw sequence number puts the post-wrap (low) segments at the
        front, so the reassembled buffer is garbled, no signature is found, and
        the artifact is silently not carved.
        """
        isn = SEQ_MODULO - 4
        segments = [
            (isn, b"AAAA"),
            ((isn + 4) % SEQ_MODULO, b"BBBB"),
            ((isn + 8) % SEQ_MODULO, b"CCCC"),
        ]
        result = reassemble(segments, 1024)
        assert result.data == b"AAAABBBBCCCC"
        assert result.gap_count == 0

    def test_sequence_wraparound_out_of_order(self) -> None:
        isn = SEQ_MODULO - 4
        segments = [
            ((isn + 8) % SEQ_MODULO, b"CCCC"),
            (isn, b"AAAA"),
            ((isn + 4) % SEQ_MODULO, b"BBBB"),
        ]
        assert reassemble(segments, 1024).data == b"AAAABBBBCCCC"


class TestOverlap:
    def test_partial_retransmission_contributes_only_new_bytes(self) -> None:
        assert reassemble([(100, b"AAAA"), (102, b"AABBBB")], 1024).data == b"AAAABBBB"

    def test_exact_duplicate_is_dropped(self) -> None:
        assert reassemble([(100, b"AAAA"), (100, b"AAAA")], 1024).data == b"AAAA"

    def test_fully_contained_retransmission_is_dropped(self) -> None:
        assert reassemble([(100, b"AAAABBBB"), (102, b"AA")], 1024).data == b"AAAABBBB"


class TestGaps:
    def test_gap_is_recorded_when_not_filled(self) -> None:
        result = reassemble([(100, b"AAAA"), (110, b"BBBB")], 1024)
        assert result.data == b"AAAABBBB"
        assert result.gap_count == 1
        assert result.gap_bytes == 6
        assert result.gaps[0].at_seq == 104

    def test_gap_is_zero_filled_on_request(self) -> None:
        result = reassemble([(100, b"AAAA"), (110, b"BBBB")], 1024, fill_gaps=True)
        assert result.data == b"AAAA" + b"\x00" * 6 + b"BBBB"
        assert result.gaps[0].offset == 4
        assert result.gaps[0].length == 6

    def test_multiple_gaps(self) -> None:
        result = reassemble(
            [(0, b"AA"), (10, b"BB"), (20, b"CC")], 1024, fill_gaps=True
        )
        assert result.gap_count == 2
        assert result.gap_bytes == 16
        assert len(result.data) == 22

    def test_no_gap_recorded_for_contiguous_data(self) -> None:
        assert reassemble([(0, b"AA"), (2, b"BB")], 1024).gap_count == 0

    def test_gaps_within_identifies_a_spanning_range(self) -> None:
        result = reassemble([(100, b"AAAA"), (110, b"BBBB")], 1024, fill_gaps=True)
        assert result.gaps_within(0, 4) == (0, 0)  # before the hole
        assert result.gaps_within(10, 4) == (0, 0)  # after the hole
        assert result.gaps_within(0, 14) == (1, 6)  # spans it entirely
        assert result.gaps_within(2, 4) == (1, 2)  # clips into it

    def test_gap_at_seq_wraps_with_the_sequence_space(self) -> None:
        isn = SEQ_MODULO - 2
        result = reassemble([(isn, b"AA"), ((isn + 6) % SEQ_MODULO, b"BB")], 1024)
        assert result.gap_count == 1
        assert result.gaps[0].at_seq == 0  # (2**32 - 2 + 2) mod 2**32


class TestBounds:
    def test_max_bytes_truncates_and_flags(self) -> None:
        result = reassemble([(0, b"A" * 100), (100, b"B" * 100)], 150)
        assert len(result.data) == 150
        assert result.truncated

    def test_zero_fill_cannot_exceed_max_bytes(self) -> None:
        # A 10 MB hole must not allocate 10 MB when the budget is 64 bytes.
        result = reassemble([(0, b"AAAA"), (10_000_000, b"BBBB")], 64, fill_gaps=True)
        assert len(result.data) == 64
        assert result.truncated

    def test_empty_input(self) -> None:
        assert reassemble([], 1024) == Reassembly()

    def test_all_empty_payloads(self) -> None:
        assert reassemble([(0, b""), (10, b"")], 1024).data == b""

    def test_zero_budget(self) -> None:
        assert reassemble([(0, b"AAAA")], 0).data == b""


class TestCallerContract:
    def test_carving_fills_gaps(self) -> None:
        from pcapper.carving import _reassemble as carve_reassemble

        result = carve_reassemble([(100, b"AAAA"), (110, b"BBBB")], 1024)
        assert result.data == b"AAAA" + b"\x00" * 6 + b"BBBB"

    def test_streams_does_not_fill_gaps_and_keeps_its_legacy_shape(self) -> None:
        from pcapper.streams import _reassemble as stream_reassemble

        payload, gaps = stream_reassemble([(100, b"AAAA"), (110, b"BBBB")], 1024)
        assert payload == b"AAAABBBB"
        assert gaps == [{"at_seq": 104, "gap_bytes": 6}]

    def test_streams_reassembly_also_handles_wraparound(self) -> None:
        from pcapper.streams import _reassemble as stream_reassemble

        isn = SEQ_MODULO - 4
        payload, gaps = stream_reassemble(
            [(isn, b"AAAA"), ((isn + 4) % SEQ_MODULO, b"BBBB")], 1024
        )
        assert payload == b"AAAABBBB"
        assert gaps == []
