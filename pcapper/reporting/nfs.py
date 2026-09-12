"""Rendered output for nfs analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..nfs import NfsSummary
from ..utils import (
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _conv_value,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _limit_value,
    _render_protocol_verdict,
)


def render_nfs_summary(summary: NfsSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"NFS PROTOCOL ANALYSIS :: {summary.path.name}"))
    _render_protocol_verdict(
        lines,
        label="NFS",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("NFS Packets", str(summary.nfs_packets)))
    versions_text = (
        ", ".join([f"{k} ({v})" for k, v in summary.versions.items()])
        if summary.versions
        else "-"
    )
    lines.append(_format_kv("NFS Versions", versions_text))
    lines.append(_format_kv("Unique Clients", str(len(summary.clients))))
    lines.append(_format_kv("Unique Servers", str(len(summary.servers))))
    lines.append(_format_kv("RPC Sessions", str(len(summary.sessions))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Requests vs Responses"))
    if not summary.requests and not summary.responses:
        lines.append(muted("No NFS request/response counts."))
    else:
        rows = [["Procedure", "Requests", "Responses"]]
        all_cmds = set(summary.requests.keys()).union(summary.responses.keys())
        for cmd in sorted(all_cmds):
            rows.append(
                [
                    cmd,
                    str(summary.requests.get(cmd, 0)),
                    str(summary.responses.get(cmd, 0)),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top NFS Procedures"))
    if not summary.procedures:
        lines.append(muted("No NFS procedures decoded."))
    else:
        lines.append(_counter_table(summary.procedures, "Procedure", limit=_limit_value(12)))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NFS Status Codes"))
        lines.append(_counter_table(summary.status_codes, "Status", limit=_limit_value(12)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Sessions"))
    if not summary.conversations:
        lines.append(muted("No NFS sessions summarized."))
    else:
        lines.append(
            _format_sessions_table(
                summary.conversations,
                _limit_value(10),
                extra_cols=[
                    ("Requests", lambda c: _conv_value(c, "requests") or 0),
                    ("Responses", lambda c: _conv_value(c, "responses") or 0),
                ],
            )
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Servers"))
    if not summary.servers:
        lines.append(muted("No NFS servers identified."))
    else:
        rows = [["Server", "Versions", "Packets", "First Seen", "Last Seen"]]
        for srv in summary.servers:
            rows.append(
                [
                    srv.ip,
                    ", ".join(sorted(srv.versions)) if srv.versions else "-",
                    str(srv.packets),
                    format_ts(srv.first_seen),
                    format_ts(srv.last_seen),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Clients"))
    if not summary.clients:
        lines.append(muted("No NFS clients identified."))
    else:
        rows = [["Client", "Versions", "Users", "UIDs", "Packets"]]
        for cli in summary.clients:
            users = ", ".join(sorted(cli.usernames)) if cli.usernames else "-"
            uids = ", ".join(str(uid) for uid in sorted(cli.uids)) if cli.uids else "-"
            rows.append(
                [
                    cli.ip,
                    ", ".join(sorted(cli.versions)) if cli.versions else "-",
                    users,
                    uids,
                    str(cli.packets),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Files & Artifacts"))
    if summary.files:
        rows = [["Action", "Name", "Client", "Server", "Time"]]
        for item in summary.files[: _limit_value(20)]:
            rows.append(
                [
                    item.action,
                    item.name,
                    item.client_ip,
                    item.server_ip,
                    format_ts(item.ts),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No file operations decoded."))

    if summary.artifacts:
        lines.append(
            muted("Artifacts: " + ", ".join(summary.artifacts[: _limit_value(25)]))
        )

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        lines.append(_counter_table(summary.observed_users, "User", limit=_limit_value(10)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NFS Anomalies & Risks"))
    if not summary.anomalies:
        lines.append(ok("No NFS-specific anomalies detected."))
    else:
        for a in summary.anomalies:
            sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
            lines.append(sev_color(f"[{a.severity}] {a.title}"))
            lines.append(f"  {a.description}")
            lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
            lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
