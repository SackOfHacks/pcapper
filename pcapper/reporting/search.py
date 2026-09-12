"""Rendered output for search analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
import re
from collections import Counter
from typing import Iterable
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..search import SearchSummary
from ..utils import (
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _truncate_text,
)


def _highlight_search_text(text: str, query: str) -> str:
    if not text or not query:
        return text
    try:
        pattern = re.compile(re.escape(query), re.IGNORECASE)
    except re.error:
        return text
    return pattern.sub(lambda match: ok(match.group(0)), text)


def render_search_summary(summary: SearchSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SEARCH RESULTS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Query", ok(summary.query)))
    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("Matches", str(summary.matches)))
    if summary.truncated:
        lines.append(warn(f"[WARN] Showing first {len(summary.hits)} matches."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Match Details"))
    if not summary.hits:
        lines.append(muted("No matches found."))
    else:
        rows = [
            ["Pkt", "Time", "Src", "Dst", "Proto", "Sport", "Dport", "Len", "Context"]
        ]
        for hit in summary.hits:
            context_text = _truncate_text(hit.context, 80)
            if context_text:
                context_text = _highlight_search_text(context_text, summary.query)
            rows.append(
                [
                    str(hit.packet_number),
                    format_ts(hit.ts),
                    hit.src_ip,
                    hit.dst_ip,
                    hit.protocol,
                    str(hit.src_port) if hit.src_port is not None else "-",
                    str(hit.dst_port) if hit.dst_port is not None else "-",
                    str(hit.payload_len),
                    context_text or "-",
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_search_rollup(summaries: Iterable[SearchSummary], limit: int = 20) -> str:
    limit = _apply_verbose_limit(limit)
    summary_list = list(summaries)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SEARCH RESULTS :: ALL PCAPS ({len(summary_list)})"))
    lines.append(SECTION_BAR)

    if not summary_list:
        lines.append(muted("No search summaries to aggregate."))
        lines.append(SECTION_BAR)
        return _finalize_output(lines)

    query_counts: Counter[str] = Counter()
    total_packets = 0
    total_matches = 0
    total_hits = 0
    truncated_pcaps = 0
    all_errors: list[str] = []
    rows = [["PCAP", "Matches", "Packets", "Shown Hits", "Errors"]]

    for summary in summary_list:
        query_counts.update([summary.query])
        total_packets += summary.total_packets
        total_matches += summary.matches
        total_hits += len(summary.hits)
        if summary.truncated:
            truncated_pcaps += 1
        err_count = len(summary.errors)
        rows.append(
            [
                summary.path.name,
                str(summary.matches),
                str(summary.total_packets),
                str(len(summary.hits)),
                str(err_count),
            ]
        )
        for err in summary.errors:
            all_errors.append(f"{summary.path.name}: {err}")

    query = query_counts.most_common(_limit_value(1))[0][0] if query_counts else "-"
    lines.append(_format_kv("Query", ok(query) if query != "-" else query))
    lines.append(_format_kv("PCAPs Analyzed", str(len(summary_list))))
    lines.append(_format_kv("Packets Scanned", str(total_packets)))
    lines.append(_format_kv("Total Matches", str(total_matches)))
    lines.append(_format_kv("Shown Hits", str(total_hits)))
    lines.append(_format_kv("Truncated PCAPs", str(truncated_pcaps)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Per-PCAP Match Totals"))
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Match Details"))
    detail_rows = [
        [
            "PCAP",
            "Pkt",
            "Time",
            "Src",
            "Dst",
            "Proto",
            "Sport",
            "Dport",
            "Len",
            "Context",
        ]
    ]
    for summary in sorted(summary_list, key=lambda item: item.matches, reverse=True):
        for hit in summary.hits:
            if len(detail_rows) > limit:
                break
            detail_rows.append(
                [
                    summary.path.name,
                    str(hit.packet_number),
                    format_ts(hit.ts),
                    hit.src_ip,
                    hit.dst_ip,
                    hit.protocol,
                    str(hit.src_port) if hit.src_port is not None else "-",
                    str(hit.dst_port) if hit.dst_port is not None else "-",
                    str(hit.payload_len),
                    _truncate_text(hit.context, 80),
                ]
            )
        if len(detail_rows) > limit:
            break

    if len(detail_rows) == 1:
        lines.append(muted("No matches found."))
    else:
        lines.append(_format_table(detail_rows))
        shown = len(detail_rows) - 1
        if shown < total_hits:
            lines.append(
                warn(f"[WARN] Showing first {shown} hit rows across all pcaps.")
            )

    if all_errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in all_errors[: _limit_value(25)]:
            lines.append(danger(f"- {err}"))
        if len(all_errors) > 25:
            lines.append(muted(f"... {len(all_errors) - 25} more errors"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
