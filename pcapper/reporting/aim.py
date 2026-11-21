"""Rendered output for AIM/OSCAR instant messaging: accounts, cleartext
passwords and secrets, recovered messages and files."""

from __future__ import annotations

from ..aim import AimSummary
from ..utils import format_bytes_as_mb, format_duration
from . import _style as st
from ._kv import counter_line, findings_for


def render_aim_summary(summary: AimSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("AIM", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.aim_packets and not st.material(findings):
        return rep.absent("AIM/OSCAR traffic", summary.errors)
    rows = None if (st.verbose() or verbose) else limit
    severity, text = st.verdict(findings, high="credentials or sensitive content in cleartext IM: treat as evidence",
                                medium="IM activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.aim_packets)} AIM packets", st.size(summary.aim_bytes),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(f"{st.plural(summary.unique_clients, 'client')} -> {st.plural(summary.unique_servers, 'server')}")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    def _counts(title: str, counter: object, label_text: str, width: int) -> None:
        rep.section(title, st.table([label_text, "Seen"], [[k, st.count(v)] for k, v in (counter or {}).items()]
                                    if not hasattr(counter, "most_common") else [[k, st.count(v)] for k, v in counter.most_common()],
                                    align="lr", widths=(width,), **({"max_rows": None} if rows is None
                                                                   else {"max_rows": st.TOP_ROWS, "tail": st.TOP_ROWS})))

    _counts("Usernames", summary.username_counts, "Username", 48)
    _counts("Passwords", summary.password_counts, "Password", 64)
    _counts("Secrets", summary.secret_counts, "Secret", 64)
    _counts("Messages", summary.message_counts, "Message", 96)
    _counts("Files", summary.file_counts, "Filename", 80)
    rep.section("Artifacts", st.table(
        ["Kind", "Detail", "Packet", "Flow"],
        [[a.kind, a.detail, a.packet_index, st.flow(a.src, a.dst)] for a in summary.artifacts],
        widths=(None, 96), max_rows=rows,
    ))
    rep.section("Endpoints", st.kv([counter_line("Clients", summary.client_counts), counter_line("Servers", summary.server_counts),
                                    counter_line("Server ports", summary.server_ports)]))
    convs = sorted(summary.conversations, key=lambda c: (c.packets, c.bytes), reverse=True)
    rep.section("Conversations", st.table(
        ["Client", "Server", "Port", "Packets", "Bytes", "First", "Last"],
        [[c.client_ip, c.server_ip, c.server_port, st.count(c.packets), format_bytes_as_mb(c.bytes), st.ts(c.first_seen),
          st.ts(c.last_seen)] for c in convs], align="llrrrll", max_rows=None,
    ), detail=True)
    rep.section("Traffic", st.kv([
        ("Packets scanned / AIM", f"{summary.total_packets} / {summary.aim_packets}"),
        ("Bytes total / AIM", f"{format_bytes_as_mb(summary.total_bytes)} / {format_bytes_as_mb(summary.aim_bytes)}"),
        ("Start / end", f"{st.ts(summary.first_seen)} / {st.ts(summary.last_seen)}"),
        ("Duration", format_duration(summary.duration_seconds)),
    ]), detail=True)
    return rep.render()
