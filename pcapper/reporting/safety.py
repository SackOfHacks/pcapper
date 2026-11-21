"""Rendered output for safety instrumented systems (SIS) traffic, with
TriStation (Triconex) decoded: key switch, program state, project and the
logic/state-changing commands a TRITON-class attack would issue."""

from __future__ import annotations

from . import _style as st
from ._common import _ot_attack_for_title
from ._kv import counter_line

# The analyzer's always-present "traffic observed" note: the headline says it.
_PRESENCE = "Safety PLC/SIS protocol traffic observed"


def render_safety_summary(summary) -> str:  # type: ignore[no-untyped-def]
    if not summary:
        return ""
    rep = st.Report("Safety systems", summary.path)
    detections = [d for d in (getattr(summary, "detections", None) or []) if d.get("summary") != _PRESENCE]
    if not st.verbose():
        detections = [d for d in detections if str(d.get("severity", "info")).lower() not in ("info", "informational")]
    findings = [st.finding(d, _ot_attack_for_title) for d in detections]
    frames = int(getattr(summary, "tristation_frames", 0) or 0)
    if not summary.hits and not frames and not st.material(findings):
        return rep.absent("safety-system (SIS) traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="safety-system state or logic changes: confirm an authorized engineering session",
        medium="safety-system activity to review",
    )
    rep.headline(severity, text, st.join([
        st.plural(len(summary.hits), "safety-protocol packet"),
        f"{st.count(frames)} TriStation frames" if frames else "",
    ]))
    rep.scope(st.join([
        f"{st.plural(len(summary.source_counts or {}), 'source')} -> {st.plural(len(summary.destination_counts or {}), 'destination')}",
        st.top(summary.service_counts, 4) if summary.service_counts else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    if frames:
        rep.section("TriStation (Triconex)", st.kv([
            counter_line("Key switch", summary.key_states, 4),
            counter_line("Program state", summary.run_states, 4),
            counter_line("Project", summary.projects, 4),
            counter_line("Requests", summary.tristation_requests, 12),
            counter_line("Rejected", summary.tristation_rejects, 6),
            counter_line("Replies", summary.tristation_replies, 8),
            counter_line("TCM messages", summary.tristation_tcm, 6),
        ]))
        rows, previous = [], None
        for when, src, dst, name in list(summary.tristation_timeline or []):
            if (src, dst, name) == previous:
                continue  # a run of the same command is one row
            previous = (src, dst, name)
            rows.append([st.ts(when), st.flow(src, dst), st.bad(name)])
        rep.section("Logic and state commands", st.table(["Time", "Workstation -> controller", "Function"], rows,
                                                         max_rows=12, noun="command"))

    rep.section("Services", st.kv([
        counter_line("Services", summary.service_counts, 6),
        counter_line("Sources", summary.source_counts, 6),
        counter_line("Destinations", summary.destination_counts, 6),
    ]))
    rep.section("Hits", st.table(
        ["Protocol", "Service", "Source", "Destination"],
        [[h.protocol, h.service, f"{h.src}:{h.src_port}", f"{h.dst}:{h.dst_port}"] for h in summary.hits],
        max_rows=None,
    ), detail=True)
    rep.section("Capture", st.kv([("Total packets", st.count(summary.total_packets))]), detail=True)
    return rep.render()
