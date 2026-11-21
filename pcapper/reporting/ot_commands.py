"""Rendered output for --ot-commands: every OT command observed across the
decoded protocols, with the state-changing ones (writes, control, restarts,
program transfers) first: who sent them, to which targets, how often."""

from __future__ import annotations

from collections import Counter

from ..ot_commands import OtCommandSummary
from . import _style as st
from ._common import _ot_command_risk
from ._kv import counter_line, findings_for


def render_ot_commands_summary(
    summary: OtCommandSummary, session_limit: int = 10, verbose: bool = False
) -> str:
    rep = st.Report("OT commands", summary.path)
    findings = findings_for(summary)
    all_cmds: Counter = getattr(summary, "all_command_counts", None) or Counter()
    control: Counter = getattr(summary, "command_counts", None) or Counter()
    streams = list(getattr(summary, "unnormalized_streams", []) or [])
    if not all_cmds and not control and not findings and not streams:
        return rep.absent("decodable OT protocol commands", summary.errors)

    if control:
        clean = f"{st.plural(sum(control.values()), 'state-changing command')} without findings"
    elif streams:
        clean = "no control commands; publish/subscribe signalling present (see note)"
    else:
        clean = "read-only/monitoring: no writes, control, restarts or program transfers"
    severity, text = st.verdict(
        findings,
        high="state-changing OT commands: confirm each source is an authorized master or EWS",
        medium="OT command activity to review",
        clean=clean,
    )
    rep.headline(severity, text, st.join([
        st.plural(len(all_cmds), "command type"),
        st.plural(len(control), "state-changing type"),
        f"{float(summary.control_rate_per_min or 0.0):.2f} control/min" if summary.control_rate_per_min is not None else "",
        f"burst {summary.control_burst_max} in 60s" if getattr(summary, "control_burst_max", 0) else "",
    ]))
    if getattr(summary, "fast_mode", False):
        rep.note("FAST", "port-heuristic mode: commands are inferred from ports, not decoded")
        for note in getattr(summary, "fast_notes", []) or []:
            rep.scope(str(note))
    if streams and not control:
        flags = " ".join(f"--{s.lower().replace('c37.118', 'synchrophasor')}" for s in streams)
        rep.note("NOTE", f"{', '.join(streams)} is publish/subscribe signalling, not commands: evaluate it with {flags}")

    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    if control:
        rep.section("State-changing commands", st.kv([
            ("Commands", st.top(control, 8)),
            counter_line("Sources", summary.sources),
            counter_line("Destinations", summary.destinations),
        ]))
    targets = getattr(summary, "control_targets", None) or {}
    target_rows = [[proto, target, st.count(n)] for proto in sorted(targets, key=str.casefold)
                   for target, n in targets[proto].most_common(None if st.verbose() else 6)]
    rep.section("Control targets", st.table(["Protocol", "Target", "Count"], target_rows, align="llr", max_rows=None))

    times = getattr(summary, "command_session_times", {}) or {}
    rep.section("Command sessions", st.table(
        ["Session", "Commands", "First", "Last"],
        [[s, st.count(n), st.ts(times.get(s, (None, None))[0]), st.ts(times.get(s, (None, None))[1])]
         for s, n in (summary.command_sessions or Counter()).most_common()],
        align="lrll", max_rows=session_limit, noun="session",
    ))

    rank = {"CONTROL": 0, "REVIEW": 1}
    rows = []
    for key, n in sorted(all_cmds.items(), key=lambda kv: (rank.get(_ot_command_risk(str(kv[0]).partition(":")[2]), 2), -kv[1], str(kv[0]))):
        proto, _, cmd = str(key).partition(":")
        risk = _ot_command_risk(cmd)
        shown = st.bad(cmd) if risk == "CONTROL" else st.caution(cmd) if risk == "REVIEW" else cmd
        rows.append([proto, shown, st.count(n), risk.lower()])
    rep.section("All commands", st.ranked(["Protocol", "Command", "Count", "Class"], rows, align="llrl",
                                          noun="command type"))

    markers = []
    for label_text, name in (("Write markers", "write_markers"), ("Protocol markers", "protocol_markers")):
        value = getattr(summary, name, None)
        if value:
            markers.append((label_text, st.top(value, None) if hasattr(value, "items") else ", ".join(map(str, value))))
    rep.section("Markers", st.kv(markers), detail=True)
    return rep.render()

