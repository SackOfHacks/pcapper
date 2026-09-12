"""Rendered output for ot_commands analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..ot_commands import OtCommandSummary
from ..utils import (
    format_ts,
)

from ._common import (
    SUBSECTION_BAR,
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
    _ot_command_risk,
)


def render_ot_commands_summary(
    summary: OtCommandSummary, session_limit: int = 10, verbose: bool = False
) -> str:
    lines = [header("OT COMMANDS")]
    if getattr(summary, "fast_mode", False):
        lines.append(_format_kv("Mode", "FAST (port heuristic)"))
        for note in getattr(summary, "fast_notes", []) or []:
            lines.append(muted(f"- {note}"))

    all_cmds = getattr(summary, "all_command_counts", Counter()) or Counter()
    control_cmds = getattr(summary, "command_counts", Counter()) or Counter()

    # All observed OT commands (reads + writes) across every decoded protocol —
    # risk-classified so control/write commands stand out. Shown by default; this
    # is the section that makes --ot-commands useful on read-only captures.
    lines.append(SUBSECTION_BAR)
    lines.append(header("All Observed OT Commands (by protocol)"))
    if all_cmds:
        rows = [["Protocol", "Command", "Count", "Class"]]
        n_control = 0
        for key, count in all_cmds.most_common(_limit_value(25)):
            proto, _, cmd = str(key).partition(":")
            risk = _ot_command_risk(cmd)
            disp = (
                danger(cmd) if risk == "CONTROL"
                else warn(cmd) if risk == "REVIEW"
                else cmd
            )
            if risk == "CONTROL":
                n_control += 1
            rows.append([proto, disp, str(count), risk])
        lines.append(_format_table(rows))
        distinct = len(all_cmds)
        if distinct > 25:
            lines.append(muted(f"  ... and {distinct - 25} more distinct command types"))
        if n_control:
            lines.append(muted(
                f"  {n_control} distinct control/state-changing command type(s) in view "
                "— see Control/Write Commands below."
            ))
    else:
        lines.append(muted("No decodable OT protocol commands observed in this capture."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Control/Write Commands (state-changing)"))
    if control_cmds:
        lines.append(_format_kv("Commands", _format_counter(control_cmds, 8)))
        lines.append(_format_kv("Top Sources", _format_counter(summary.sources, 5)))
        lines.append(
            _format_kv("Top Destinations", _format_counter(summary.destinations, 5))
        )
    else:
        lines.append(ok(
            "None observed — traffic is read-only / monitoring "
            "(no writes, control, restart, or program transfers)."
        ))
    if getattr(summary, "control_rate_per_min", None) is not None:
        rate = float(summary.control_rate_per_min or 0.0)
        lines.append(_format_kv("Control Rate", f"{rate:.2f}/min"))
        lines.append(
            _format_kv(
                "Control Burst (60s)", str(getattr(summary, "control_burst_max", 0))
            )
        )
    if getattr(summary, "command_sessions", None):
        lines.append(header("Top Command Sessions"))
        rows = [["Session", "Count", "First Seen", "Last Seen"]]
        session_times = getattr(summary, "command_session_times", {}) or {}
        for session, count in summary.command_sessions.most_common(
            _limit_value(session_limit)
        ):
            first, last = session_times.get(session, (None, None))
            rows.append([session, str(count), format_ts(first), format_ts(last)])
        lines.append(_format_table(rows))
    if getattr(summary, "control_targets", None):
        targets = summary.control_targets or {}
        if targets:
            lines.append(header("Top Control Targets"))
            for proto in sorted(targets.keys(), key=str.casefold):
                rows = [["Target", "Count"]]
                for target, count in targets[proto].most_common(_limit_value(6)):
                    rows.append([target, str(count)])
                if len(rows) > 1:
                    lines.append(muted(proto))
                    lines.append(_format_table(rows))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    # Show all detections by default — --ot-commands does not require -v.
    detections = _filtered_detections(summary, True)
    if detections:
        lines.append(header("Detections"))
        for item in detections[: _limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)
