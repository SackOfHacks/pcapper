"""TCP payload reassembly shared by stream following and file carving.

Both :mod:`pcapper.streams` and :mod:`pcapper.carving` rebuild one direction of a
TCP conversation from the ``(seq, payload)`` pairs they collected while reading
the capture. They previously each carried their own copy of the logic, and each
copy repeated the same two defects:

* raw 32-bit sequence numbers were sorted numerically, so any stream whose
  initial sequence number sat near ``2**32`` was silently mis-ordered once it
  wrapped (see :func:`relative_seq`);
* a missing run of bytes was closed by concatenation, so the buffer no longer
  lined up with the stream and nothing recorded that data was absent.

This module is the single implementation. It is deliberately dependency-free so
it can be unit-tested against synthetic segment lists without a capture file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEQ_MODULO = 1 << 32
_SEQ_HALF = SEQ_MODULO >> 1


def relative_seq(seq: int, base: int) -> int:
    """Signed distance from ``base`` in TCP sequence space.

    TCP sequence numbers wrap at ``2**32`` and initial sequence numbers are
    randomised across that whole range, so a long transfer whose ISN sits near
    the top wraps partway through. Sorting the raw values puts every post-wrap
    segment at the *front* of the list, which mis-orders the stream and — once
    the running end offset has been taken from a low post-wrap value — makes the
    genuine pre-wrap segments look like fresh data appended in the wrong place.

    Comparing modulo ``2**32`` as a *signed* distance is the rule TCP itself
    uses. It keeps ordering in stream space regardless of where the ISN sits,
    and it tolerates a segment that legitimately precedes the first one observed
    (a retransmission, or simple reordering) by mapping it to a negative offset
    rather than to one just under ``2**32``.
    """
    return ((seq - base + _SEQ_HALF) % SEQ_MODULO) - _SEQ_HALF


@dataclass(frozen=True)
class Gap:
    """A run of bytes missing from one reassembled direction.

    ``offset`` is the position of the hole inside :attr:`Reassembly.data` when
    gaps were zero-filled; when they were not, it is the position at which the
    missing bytes would have started. ``at_seq`` is the real wire sequence
    number the hole begins at, so it can be compared against what a packet
    analyser shows for the same capture.
    """

    offset: int
    length: int
    at_seq: int

    def as_dict(self) -> dict[str, int]:
        """Legacy mapping form used by ``StreamRecord`` gap lists."""
        return {"at_seq": self.at_seq, "gap_bytes": self.length}


@dataclass(frozen=True)
class Reassembly:
    """The bytes recovered for one direction, plus what was missing from them."""

    data: bytes = b""
    gaps: tuple[Gap, ...] = field(default_factory=tuple)
    truncated: bool = False

    @property
    def gap_count(self) -> int:
        return len(self.gaps)

    @property
    def gap_bytes(self) -> int:
        return sum(gap.length for gap in self.gaps)

    def gaps_within(self, offset: int, length: int) -> tuple[int, int]:
        """Count the gaps overlapping ``data[offset:offset + length]``.

        Returns ``(count, missing_bytes)``. Carving uses this to flag a hit that
        straddles a hole, so a partially-reconstructed file is never presented
        with a bare SHA-256 as though it were complete.
        """
        end = offset + length
        count = 0
        missing = 0
        for gap in self.gaps:
            gap_end = gap.offset + gap.length
            if gap.offset >= end or gap_end <= offset:
                continue
            count += 1
            missing += min(gap_end, end) - max(gap.offset, offset)
        return count, missing


def reassemble(
    segments: list[tuple[int, bytes]],
    max_bytes: int,
    fill_gaps: bool = False,
) -> Reassembly:
    """Rebuild one direction of a TCP stream from ``(seq, payload)`` pairs.

    ``segments`` is taken in capture order; the sequence number of the first
    entry is used as the origin for :func:`relative_seq`, so ordering is done in
    stream space rather than wire space. Overlapping retransmissions contribute
    only the bytes beyond what has already been written.

    ``fill_gaps`` controls what happens to a hole left by a dropped packet, a
    snaplen-truncated capture, or a capture that began mid-stream. With it set,
    the hole is zero-filled: offsets into :attr:`Reassembly.data` then mean the
    same thing as offsets into the stream, and the missing bytes are visible in
    any artifact carved across them instead of being papered over by
    concatenation. Either way the hole is recorded in :attr:`Reassembly.gaps`.

    ``max_bytes`` bounds the result — including zero fill, so a stream with an
    enormous hole cannot be made to allocate without limit.
    """
    if not segments or max_bytes <= 0:
        return Reassembly()

    base = segments[0][0]
    ordered = sorted(
        ((relative_seq(seq, base), data) for seq, data in segments if data),
        key=lambda item: item[0],
    )
    if not ordered:
        return Reassembly()

    out = bytearray()
    gaps: list[Gap] = []
    current_end = ordered[0][0]

    for rel, data in ordered:
        if rel > current_end:
            hole = rel - current_end
            gaps.append(
                Gap(
                    offset=len(out),
                    length=hole,
                    at_seq=(base + current_end) % SEQ_MODULO,
                )
            )
            if fill_gaps:
                fill = min(hole, max_bytes - len(out))
                out.extend(b"\x00" * fill)
                if fill < hole:
                    return Reassembly(bytes(out), tuple(gaps), True)
            current_end = rel
        if rel >= current_end:
            out.extend(data)
        else:
            overlap = current_end - rel
            if overlap < len(data):
                out.extend(data[overlap:])
        current_end = max(current_end, rel + len(data))
        if len(out) >= max_bytes:
            return Reassembly(bytes(out[:max_bytes]), tuple(gaps), True)

    return Reassembly(bytes(out), tuple(gaps), False)
