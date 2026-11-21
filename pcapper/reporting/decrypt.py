"""Rendered output for --decrypt (TLS/SSH sessions decrypted with key logs)."""

from __future__ import annotations

from . import _style as st


def render_decrypt_summary(summary) -> str:  # type: ignore[no-untyped-def]
    if not summary:
        return ""
    rep = st.Report(f"{summary.protocol} decryption", getattr(summary, "path", "") or "")
    outputs = list(summary.outputs or [])
    rep.headline(
        "medium" if summary.errors and not outputs else False,
        st.join([st.plural(len(outputs), "decrypted output"), f"from {st.plural(summary.stream_count, 'stream')}"]),
        f"written to {summary.output_dir}",
    )
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Notes", st.bullets(summary.notes or [], max_items=None, noun="note"))
    rep.section("Outputs", st.bullets([str(o) for o in outputs], max_items=10, noun="output"))
    if getattr(summary, "keylog_path", None):
        rep.section("Key log", [f"  {summary.keylog_path}"], detail=True)
    return rep.render()
