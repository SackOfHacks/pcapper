"""Rendered output for syslog: the log messages themselves -- the notable
ones (warning and worse, or matching an auth/execution/tampering pattern)
first -- with who sent them, plus the facility, severity, host and app mix.
Binary payloads on syslog ports are counted, not printed."""

from __future__ import annotations

from ..syslog import SUSPICIOUS_PATTERNS, SyslogSummary, is_text_message
from . import _style as st
from ._common import _meaningful_plaintext_items
from ._kv import counter_line, findings_for
from ._remote import counts, session_table

_SEVERITY_STYLE = {0: st.bad, 1: st.bad, 2: st.bad, 3: st.caution, 4: st.caution}


def _flag(message: str) -> str:
    return next((label for pattern, label in SUSPICIOUS_PATTERNS if pattern.search(message)), "")


def render_syslog_summary(summary: SyslogSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    rep = st.Report("Syslog", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.syslog_packets and not st.material(findings):
        return rep.absent("syslog traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity events in the logs: investigate",
                                medium="log events to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_messages)} messages",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    ports = ", ".join(str(p) for p, _ in summary.server_ports.most_common(4))
    rep.scope(st.join([f"{st.plural(summary.unique_clients, 'sender')} -> {st.plural(summary.unique_servers, 'collector')}",
                       f"port {ports}" if ports else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    messages = list(getattr(summary, "messages", None) or [])
    texts = [m for m in messages if is_text_message(str(m.get("message") or ""))]
    binary = len(messages) - len(texts)
    if binary:
        rep.note("NOTE", f"{st.count(binary)} payloads on syslog ports are not text (binary or padding); not listed")
    if summary.total_messages > len(messages):
        rep.note("CAPPED", f"the first {st.count(len(messages))} of {st.count(summary.total_messages)} messages were kept")

    def _rows(items: list) -> list:
        rows = []
        for m in sorted(items, key=lambda m: m.get("ts") or 0.0):
            pri = m.get("pri")
            sev = str(m.get("severity") or "-")
            msg = str(m.get("message") or "").rstrip("\x00\r\n ")
            flag = _flag(msg)
            rows.append([st.ts(m.get("ts"))] + ([m.get("logged") or "-"] if st.verbose() else [])
                        + [m.get("src") or "-", m.get("hostname") or "-", m.get("appname") or "-",
                           _SEVERITY_STYLE.get(pri, str)(sev) if isinstance(pri, int) else sev,
                           st.bad(flag) if flag else "", msg])
        return rows

    # "Logged" (-v) is the sender's own header timestamp: compare it with the
    # capture time to spot clock skew or replayed logs.
    columns = ["Time"] + (["Logged"] if st.verbose() else []) + ["Sender", "Host", "App", "Severity", "Flag", "Message"]
    notable = [m for m in texts if (isinstance(m.get("pri"), int) and m["pri"] <= 4) or _flag(str(m.get("message") or ""))]
    if notable:
        rep.section("Notable messages", st.table(columns, _rows(notable), widths=(None, None, 24, 20, None, 26, 90) if not st.verbose() else (),
                                                 max_rows=15, noun="message"))
    if st.verbose() or not notable:
        rep.section("Messages", st.table(columns, _rows(texts), widths=(None, None, 24, 20, None, 26, 90) if not st.verbose() else (),
                                         max_rows=10, noun="message"))
    rep.section("Mix", st.kv([
        counter_line("Severities", summary.severity_counts, 8),
        counter_line("Facilities", summary.facility_counts, 6),
        counter_line("Hosts", summary.hostname_counts, 6),
        counter_line("Apps", summary.appname_counts, 6),
        counter_line("Senders", summary.client_counts, 6),
        counter_line("Collectors", summary.server_counts, 6),
    ]))
    rep.section("Files", counts(summary.file_artifacts, "File", width=100, noun="file"))

    message_texts = {str(m.get("message") or "") for m in messages}
    carved = [(t, n) for t, n in _meaningful_plaintext_items(summary.plaintext_strings, 10**9) if t not in message_texts]
    rep.section("Carved strings", st.table(["String", "Count"], [[t, st.count(n)] for t, n in carved], align="lr",
                                           max_rows=None), detail=True)
    rep.section("Sessions", session_table(summary.conversations, [("Proto", lambda c: c.protocol)], max_rows=None),
                detail=True)
    rep.section("Header fields", st.kv([
        counter_line("Versions", summary.version_counts, None),
        counter_line("Process IDs", getattr(summary, "procid_counts", None), None),
        counter_line("Message IDs", getattr(summary, "msgid_counts", None), None),
        counter_line("Transports", getattr(summary, "protocol_counts", None), None),
        counter_line("Ports", summary.server_ports, None),
    ]), detail=True)
    rep.section("Artifacts", st.table(["Kind", "Detail", "Flow"],
                                      [[a.kind, a.detail, st.flow(a.src, a.dst)] for a in summary.artifacts],
                                      max_rows=None), detail=True)
    rep.section("Traffic", st.kv([
        ("Packets", f"{summary.total_packets} total · {summary.syslog_packets} syslog"),
        ("Bytes", st.size(summary.total_bytes)),
    ]), detail=True)
    return rep.render()
