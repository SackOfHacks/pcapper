"""Rendered output for --search: every packet whose payload matched, with
the match highlighted in its context."""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from ..search import SearchSummary
from ..utils import display_safe
from . import _style as st


def _highlight_search_text(text: str, query: str) -> str:
    if not text or not query:
        return text
    try:
        pattern = re.compile(re.escape(query), re.IGNORECASE)
    except re.error:
        return text
    return pattern.sub(lambda m: st.good(m.group(0)), text)


def _hit_row(hit, query: str, capture: str = "") -> list:  # type: ignore[no-untyped-def]
    context = st.cut(hit.context, 80)
    return ([capture] if capture else []) + [
        hit.packet_number, st.ts(hit.ts), st.flow(hit.src_ip, hit.dst_ip), hit.protocol,
        f"{hit.src_port if hit.src_port is not None else '-'} -> {hit.dst_port if hit.dst_port is not None else '-'}",
        hit.payload_len, _highlight_search_text(context, query) if context else "-",
    ]


_COLUMNS = ["Pkt", "Time", "Flow", "Proto", "Ports", "Len", "Context"]


def render_search_summary(summary: SearchSummary) -> str:
    rep = st.Report("Search", summary.path)
    query = display_safe(summary.query)
    rep.headline(False, f"{st.plural(summary.matches, 'match', 'matches')} for {st.good(query)}",
                 f"{st.count(summary.total_packets)} packets scanned")
    if summary.truncated:
        rep.note("CAPPED", f"showing the first {len(summary.hits)} matches")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Matches", st.table(_COLUMNS, [_hit_row(h, query) for h in summary.hits], align="rllllrl", max_rows=None))
    return rep.render()


def render_search_rollup(summaries: Iterable[SearchSummary], limit: int = 20) -> str:
    items = list(summaries)
    rep = st.Report("Search", f"ALL_PCAPS_{len(items)}")
    if not items:
        return rep.absent("search summaries to aggregate")
    queries = Counter(s.query for s in items)
    query = display_safe(queries.most_common(1)[0][0]) if queries else "-"
    total_matches = sum(s.matches for s in items)
    rep.headline(False, f"{st.plural(total_matches, 'match', 'matches')} for {st.good(query)}",
                 st.join([f"{st.count(sum(s.total_packets for s in items))} packets scanned",
                          st.plural(len(items), "capture"),
                          f"{sum(1 for s in items if s.truncated)} capped" if any(s.truncated for s in items) else ""]))
    errors = [f"{s.path.name}: {e}" for s in items for e in s.errors]
    if errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in errors])
    rep.section("Per capture", st.table(
        ["Capture", "Matches", "Packets", "Shown", "Errors"],
        [[s.path.name, st.count(s.matches), st.count(s.total_packets), st.count(len(s.hits)), len(s.errors)] for s in items],
        align="lrrrr", max_rows=None,
    ))
    rows = [_hit_row(h, query, s.path.name) for s in sorted(items, key=lambda x: x.matches, reverse=True) for h in s.hits]
    rep.section("Matches", st.table(["Capture"] + _COLUMNS, rows, align="lrllllrl",
                                    max_rows=None if st.verbose() else limit, noun="match"))
    return rep.render()
