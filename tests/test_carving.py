"""End-to-end carving tests, pinned to committed captures.

``tests/data/carve_wrap.pcap`` and ``carve_gap.pcap`` were built specifically to
reproduce two silent failures. Before the fix the first carved an 8-byte stub
instead of the 193-byte PDF, and the second carved a 177-byte blob that reported
no gaps at all — a partial file presented with an authoritative SHA-256.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from pcapper.carving import analyze_carving

# The PDF the fixtures transfer; see tests/make_fixtures.py.
PDF_LENGTH = 193


def _only_hit(path: Path):
    summary = analyze_carving(path, show_status=False)
    assert summary.errors == []
    assert summary.total_hits == 1, summary.hits
    return summary, summary.hits[0]


class TestWraparound:
    def test_pdf_is_carved_from_a_wrapping_stream(self, pcap) -> None:
        summary, hit = _only_hit(pcap("carve_wrap.pcap"))
        assert hit.file_type == "PDF"
        # The whole PDF, not the single pre-wrap segment the old ordering left.
        assert hit.length == PDF_LENGTH
        assert summary.total_streams == 1

    def test_wrapping_stream_has_no_spurious_gaps(self, pcap) -> None:
        _, hit = _only_hit(pcap("carve_wrap.pcap"))
        assert hit.gap_count == 0
        assert hit.gap_bytes == 0
        assert not hit.incomplete

    def test_carved_bytes_are_the_real_pdf(self, pcap) -> None:
        _, hit = _only_hit(pcap("carve_wrap.pcap"))
        assert hit.sha256 == hashlib.sha256(_expected_pdf()).hexdigest()


class TestGaps:
    def test_missing_segment_is_reported_not_hidden(self, pcap) -> None:
        _, hit = _only_hit(pcap("carve_gap.pcap"))
        assert hit.incomplete
        assert hit.gap_count == 1
        assert hit.gap_bytes == 16

    def test_incomplete_carve_says_so_in_its_note(self, pcap) -> None:
        _, hit = _only_hit(pcap("carve_gap.pcap"))
        assert hit.note is not None
        assert "INCOMPLETE" in hit.note
        assert "16 byte(s) missing" in hit.note

    def test_incomplete_carve_is_flagged_in_the_detection(self, pcap) -> None:
        summary, _ = _only_hit(pcap("carve_gap.pcap"))
        detail = " ".join(str(d.get("details", "")) for d in summary.detections)
        assert "carved across gaps" in detail
        evidence = " ".join(
            str(item) for d in summary.detections for item in d.get("evidence", [])
        )
        assert "INCOMPLETE" in evidence

    def test_gap_is_zero_filled_so_offsets_stay_true(self, pcap) -> None:
        _, hit = _only_hit(pcap("carve_gap.pcap"))
        # The hole is padded rather than closed up, so the blob still spans the
        # full extent of the original file.
        assert hit.length == PDF_LENGTH

    def test_hash_of_a_partial_carve_differs_from_the_original(self, pcap) -> None:
        _, hit = _only_hit(pcap("carve_gap.pcap"))
        assert hit.sha256 != hashlib.sha256(_expected_pdf()).hexdigest()


class TestExtraction:
    def test_artifacts_are_written_to_the_output_directory(self, pcap, tmp_path) -> None:
        out = tmp_path / "carved"
        summary = analyze_carving(pcap("carve_wrap.pcap"), show_status=False, output_dir=out)
        assert len(summary.extracted) == 1
        written = summary.extracted[0]
        assert written.is_file()
        assert written.read_bytes() == _expected_pdf()


def _expected_pdf() -> bytes:
    # pytest's default import mode puts tests/ on sys.path, so the fixture
    # builder is importable by its bare name. Sharing the constant keeps the
    # expected bytes and the generated capture from drifting apart.
    from make_fixtures import PDF_BODY

    return PDF_BODY
