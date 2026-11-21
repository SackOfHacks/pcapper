"""Rendered output for NFS: files touched, by which client and user (UIDs),
on which server; procedures and status codes are -v detail."""

from __future__ import annotations

from ..nfs import NfsSummary
from . import _style as st
from ._common import _conv_value
from ._kv import counter_line, findings_for, sessions


def render_nfs_summary(summary: NfsSummary) -> str:
    rep = st.Report("NFS", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.nfs_packets and not st.material(findings):
        return rep.absent("NFS traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity NFS activity (exposure, root access): investigate",
                                medium="NFS activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.nfs_packets)} NFS packets",
        ", ".join(f"{k} ({v})" for k, v in summary.versions.items()) if summary.versions else "",
    ]))
    rep.scope(st.join([f"{st.plural(len(summary.clients), 'client')} -> {st.plural(len(summary.servers), 'server')}",
                       st.plural(len(summary.sessions), "RPC session")]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("File operations", st.table(
        ["Time", "Action", "Name", "Client", "Server"],
        [[st.ts(f.ts), f.action, f.name, f.client_ip, f.server_ip] for f in summary.files],
        noun="file operation",
    ))
    rep.section("Clients", st.table(
        ["Client", "Versions", "Users", "UIDs", "Packets"],
        [[c.ip, ", ".join(sorted(c.versions)) or "-", ", ".join(sorted(c.usernames)) or "-",
          ", ".join(str(u) for u in sorted(c.uids)) or "-", st.count(c.packets)] for c in summary.clients],
        align="llllr", noun="client",
    ))
    rep.section("Servers", st.table(
        ["Server", "Versions", "Packets", "First", "Last"],
        [[s.ip, ", ".join(sorted(s.versions)) or "-", st.count(s.packets), st.ts(s.first_seen), st.ts(s.last_seen)]
         for s in summary.servers],
        align="llrll", noun="server",
    ))
    rep.section("Users", st.kv([counter_line("Observed users", summary.observed_users, 10)]))

    all_cmds = sorted(set(summary.requests) | set(summary.responses))
    rep.section("Procedures", st.table(
        ["Procedure", "Requests", "Responses"],
        [[c, st.count(summary.requests.get(c, 0)), st.count(summary.responses.get(c, 0))] for c in all_cmds],
        align="lrr", max_rows=None,
    ) + st.kv([counter_line("Top procedures", summary.procedures, None), counter_line("Status codes", summary.status_codes, None)]),
        detail=True)
    rep.section("Sessions", sessions(summary.conversations, max_rows=None, extra_cols=[
        ("Requests", lambda c: _conv_value(c, "requests") or 0), ("Responses", lambda c: _conv_value(c, "responses") or 0)]),
        detail=True)
    rep.section("Artifacts", st.bullets(summary.artifacts or [], max_items=None), detail=True)
    rep.section("Capture", st.kv([("Total packets", st.count(summary.total_packets)),
                                  ("GIDs", "; ".join(f"{c.ip}: {', '.join(str(g) for g in sorted(c.gids))}"
                                                     for c in summary.clients if getattr(c, "gids", None)))]), detail=True)
    return rep.render()
