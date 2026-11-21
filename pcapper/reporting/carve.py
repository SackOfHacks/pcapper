"""Rendered output for stream carving: files found inside reassembled TCP
streams, and whether each carve is complete."""

from __future__ import annotations

from . import _style as st


def render_carve_summary(summary) -> str:  # type: ignore[no-untyped-def]
    if not summary:
        return ""
    rep = st.Report("Stream carving", getattr(summary, "path", "") or "streams")
    hits = list(summary.hits or [])
    if not hits and not summary.errors:
        return rep.absent(f"carvable files in {st.plural(summary.total_streams, 'stream')}")
    incomplete = [h for h in hits if getattr(h, "gap_count", 0)]
    rep.headline(
        "medium" if incomplete else None,
        st.join([st.plural(summary.total_hits, "file signature"), f"{st.count(len(summary.extracted))} extracted" if summary.extracted else ""]),
        st.plural(summary.total_streams, "stream") + " searched",
    )
    if incomplete:
        # A carve across a hole in the reassembled stream is a partial
        # reconstruction: its SHA-256 will not match the original file.
        rep.note("PARTIAL", f"{len(incomplete)} of {len(hits)} hit(s) span gaps in the reassembled stream: "
                            "those artifacts are incomplete and their SHA-256 will not match the original")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Hits", st.table(
        ["Stream", "Dir", "Type", "Bytes", "Missing", "Source", "Destination"],
        [[h.stream_id, h.direction, h.file_type, st.count(h.length),
          st.bad(f"{getattr(h, 'gap_bytes', 0)}B/{h.gap_count}") if getattr(h, "gap_count", 0) else "-",
          f"{h.src}:{h.src_port}", f"{h.dst}:{h.dst_port}"] for h in hits],
        align="lllrrll", noun="hit",
    ))
    rep.section("Extracted", st.bullets([str(x) for x in (summary.extracted or [])], max_items=10, noun="file"))
    return rep.render()
