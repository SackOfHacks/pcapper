"""The shared report for remote-access and remote-administration protocols:
Telnet, SSH, RDP, VNC, TeamViewer, WinRM, WMI/WMIC and PowerShell remoting.

Default view, in order: the verdict, findings, the protocol's own evidence
(accounts, commands, client names, software, fingerprints), files, and the
sessions themselves -- who connected to whom, when, for how long. Carved
plaintext, artifacts, MAC addresses, endpoint counters and traffic totals are
-v detail.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from typing import Callable, Optional, Sequence

from ..utils import format_duration
from . import _style as st
from ._common import _annotate_macs, _meaningful_plaintext_items, _render_deterministic_checks
from ._kv import findings_for

# (title, lines, detail): one report section, -v only when ``detail``.
Section = tuple[str, list[str], bool]

SESSION_ROWS = 10


def counts(
    counter: object,
    label_text: str,
    *,
    width: Optional[int] = 80,
    max_rows: Optional[int] = st.TOP_ROWS,
    noun: str = "",
    fmt: Optional[Callable[[object], object]] = None,
    decode: bool = False,
) -> list[str]:
    """A value/count table, most common first: the default view shows the
    top 10 and the bottom 10 (``max_rows=None``: every row). ``decode`` adds
    the script behind any encoded PowerShell command under its row."""
    if not counter:
        return []
    items = (
        counter.most_common()  # type: ignore[attr-defined]
        if hasattr(counter, "most_common")
        else sorted(dict(counter).items(), key=lambda kv: (-kv[1], str(kv[0])))  # type: ignore[arg-type]
    )
    lines = st.table(
        [label_text, "Count"],
        [[fmt(k) if fmt else k, st.count(v)] for k, v in items],
        align="lr", widths=(width,), max_rows=max_rows, noun=noun or label_text.lower(),
        tail=st.TOP_ROWS if max_rows is not None else None,
    )
    return _with_decoded(lines, [str(k) for k, _ in items]) if decode else lines


def _with_decoded(lines: list[str], keys: Sequence[str]) -> list[str]:
    """``lines`` (a table of ``keys``, header first) with each key's decoded
    script under its row. A ranked table's bottom rows are the last keys."""
    body = [st._ANSI_RE.sub("", line).lstrip() for line in lines[1:]]
    marks = [i for i, text in enumerate(body) if text.startswith(("…", "┄"))]
    gap_at = next((i for i in marks if body[i].startswith("┄")), None)
    rows_after = 0 if gap_at is None else len([i for i in range(gap_at + 1, len(body)) if i not in marks])
    out = lines[:1]
    for i, line in enumerate(lines[1:]):
        out.append(line)
        if i in marks:
            continue
        key_index = i if gap_at is None or i < gap_at else len(keys) - rows_after + (i - gap_at - 1)
        if 0 <= key_index < len(keys):
            script = decoded_command(keys[key_index])
            if script:
                text = script if st.verbose() else st.cut(" ".join(script.split()), st.LINE_WIDTH - 16)
                out.append(f"    {st.dim('decoded:')} {text}")
    return out


# PowerShell accepts any prefix of -EncodedCommand (-e, -en, -enc ...) and -ec.
_ENC_ARG_RE = re.compile(r"(?:^|\s)[-/]([A-Za-z]{1,14})\s+([A-Za-z0-9+/]{16,}={0,2})")


def decoded_command(text: str) -> str:
    """The script behind a ``powershell -EncodedCommand <base64>`` argument
    (UTF-16LE), or "" when ``text`` carries none. A payload cut short by the
    analyzer decodes as far as it goes, ending in "…"."""
    for match in _ENC_ARG_RE.finditer(text or ""):
        flag, blob = match.group(1).lower(), match.group(2)
        if not ("encodedcommand".startswith(flag) or flag == "ec"):
            continue
        whole = len(blob) % 4 == 0
        usable = blob if whole else blob.rstrip("=")[: len(blob.rstrip("=")) - len(blob.rstrip("=")) % 4]
        try:
            raw = base64.b64decode(usable, validate=True)
        except (binascii.Error, ValueError):
            continue
        raw = raw[: len(raw) - len(raw) % 2]
        if not raw or raw[1::2].count(0) < 0.8 * (len(raw) // 2):
            continue  # not UTF-16LE text
        script = raw.decode("utf-16-le", errors="replace").strip()
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in script)
        if script and printable >= 0.9 * len(script):
            return script if whole else script + "…"
    return ""


def labelled_commands(counter: object, *, label_text: str = "Command") -> list[str]:
    """Indicators keyed ``"<why it matched>: <command>"``, grouped by command
    so one command matched by two rules is one row; an encoded PowerShell
    payload is decoded on the line under its row."""
    grouped: dict[str, tuple[list[str], int]] = {}
    items = counter.most_common() if hasattr(counter, "most_common") else list(dict(counter or {}).items())  # type: ignore[union-attr]
    for key, n in items:
        reason, sep, command = str(key).partition(": ")
        if not sep:
            reason, command = "", str(key)
        reasons, total = grouped.get(command, ([], 0))
        if reason and reason not in reasons:
            reasons.append(reason)
        grouped[command] = (reasons, max(total, int(n)))
    if not grouped:
        return []
    ordered = sorted(grouped.items(), key=lambda kv: (-kv[1][1], kv[0]))
    lines = st.ranked([label_text, "Count", "Matched"],
                      [[cmd, st.count(n), "; ".join(reasons) or "-"] for cmd, (reasons, n) in ordered],
                      align="lrl", widths=(90, None, 60), noun=label_text.lower())
    return _with_decoded(lines, [cmd for cmd, _ in ordered])


def _port_text(ports: Sequence[tuple[str, object]]) -> str:
    parts = []
    named = len([1 for _, c in ports if c]) > 1
    for proto, counter in ports:
        if not counter:
            continue
        values = [str(p) for p, _ in Counter(dict(counter)).most_common(4)]  # type: ignore[arg-type]
        more = len(counter) - len(values)  # type: ignore[arg-type]
        prefix = f"{proto}/" if named else ""
        parts.append(", ".join(prefix + v for v in values) + (f" +{more}" if more > 0 else ""))
    if not parts:
        return ""
    single = sum(len(c) for _, c in ports if c) == 1  # type: ignore[arg-type]
    return ("port " if single else "ports ") + ", ".join(parts)


def _end(conv: object, role: str) -> str:
    ip, port = getattr(conv, f"{role}_ip", "?"), getattr(conv, f"{role}_port", None)
    return f"{ip}:{port}" if port not in (None, "") else str(ip)


def session_table(
    conversations: Sequence[object],
    extra_cols: Sequence[tuple[str, Callable[[object], object]]] = (),
    *,
    max_rows: Optional[int] = SESSION_ROWS,
) -> list[str]:
    """Sessions, largest first: client, server, start, duration, packets,
    bytes and protocol extras; -v adds the end time and bytes per direction."""
    verbose = st.verbose()
    # An extra column with no value in any row is noise.
    extra_cols = [(label, fn) for label, fn in extra_cols
                  if any(str(fn(c)).strip() not in ("", "-") for c in conversations)]
    header = (["Client", "Server", "Start"] + (["End"] if verbose else []) + ["Duration", "Packets", "Bytes"]
              + (["C->S", "S->C"] if verbose else []) + [label for label, _ in extra_cols])
    rows = []
    for c in sorted(conversations, key=lambda c: (getattr(c, "bytes", 0) or 0, getattr(c, "packets", 0) or 0), reverse=True):
        first, last = getattr(c, "first_seen", None), getattr(c, "last_seen", None)
        dur = max(0.0, last - first) if first is not None and last is not None else None
        rows.append(
            [_end(c, "client"), _end(c, "server"), st.ts(first)]
            + ([st.ts(last)] if verbose else [])
            + [st.duration(dur) if dur is not None else "-", st.count(getattr(c, "packets", 0)), st.size(getattr(c, "bytes", 0))]
            + ([st.size(getattr(c, "client_bytes", 0)), st.size(getattr(c, "server_bytes", 0))] if verbose else [])
            + [fn(c) for _, fn in extra_cols]
        )
    align = "lll" + ("l" if verbose else "") + "lrr" + ("rr" if verbose else "") + "l" * len(extra_cols)
    return st.table(header, rows, align=align, max_rows=max_rows, noun="session")


def yes_no(value: object) -> str:
    return "yes" if value else "no"


def remote_report(
    name: str,
    summary: object,
    *,
    packets: int,
    sections: Sequence[Section] = (),
    session_cols: Sequence[tuple[str, Callable[[object], object]]] = (),
    ports: Sequence[tuple[str, object]] = (),
    scope: Sequence[str] = (),
    plaintext_title: str = "Plaintext",
    plaintext_default: bool = False,
    files_default: bool = True,
    traffic: Sequence[tuple[str, object]] = (),
    notes: Sequence[str] = (),
    high: str = "high-severity remote access to investigate",
    medium: str = "remote access to review",
    deterministic: Optional[tuple[str, list[tuple[str, str]]]] = None,
) -> str:
    rep = st.Report(name, getattr(summary, "path", "") or "")
    findings = findings_for(summary, ot=False)
    errors = list(getattr(summary, "errors", None) or [])
    if not packets and not st.material(findings):
        return rep.absent(f"{name} traffic", errors)

    conversations = list(getattr(summary, "conversations", None) or [])
    client_bytes = int(getattr(summary, "client_bytes", 0) or 0)
    server_bytes = int(getattr(summary, "server_bytes", 0) or 0)
    dur = getattr(summary, "duration_seconds", None)
    first, last = getattr(summary, "first_seen", None), getattr(summary, "last_seen", None)
    severity, text = st.verdict(findings, high=high, medium=medium)
    rep.headline(severity, text, st.join([
        f"{st.count(packets)} {name} packets",
        st.size(client_bytes + server_bytes) if (client_bytes or server_bytes) else "",
        st.duration(dur) if dur else "",
        st.ts_range(first, last) if first else "",
    ]))
    n_sessions = int(getattr(summary, "total_sessions", 0) or len(conversations))
    rep.scope(st.join([
        f"{st.plural(int(getattr(summary, 'unique_clients', 0) or 0), 'client')} -> "
        f"{st.plural(int(getattr(summary, 'unique_servers', 0) or 0), 'server')}",
        st.plural(n_sessions, "session"),
        _port_text(ports),
    ] + list(scope)))
    if errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in errors])
    rep.section("Findings", st.findings_block(findings))
    for title, lines, detail in sections:
        rep.section(title, lines, detail=detail)

    files = getattr(summary, "file_artifacts", None)
    rep.section("Files", counts(files, "File", width=100, noun="file"), detail=not files_default)
    truncated = len(conversations) > SESSION_ROWS
    rep.section("Sessions", session_table(conversations, session_cols))

    client_counts = getattr(summary, "client_counts", None) or Counter()
    server_counts = getattr(summary, "server_counts", None) or Counter()
    endpoint_lines = st.kv([
        ("Clients", st.top(client_counts, 6)),
        ("Servers", st.top(server_counts, 6)),
    ] + [(f"{proto.upper()} ports" if len(ports) > 1 else "Server ports", st.top(counter, 6)) for proto, counter in ports])
    rep.section("Endpoints", endpoint_lines, detail=not truncated)

    plaintext = getattr(summary, "plaintext_strings", None)
    if plaintext:
        cap = 10**9 if st.verbose() else 8
        items = _meaningful_plaintext_items(plaintext, cap)
        rows = [[text, st.count(n)] for text, n in items]
        rep.section(plaintext_title, st.table(["String", "Count"], rows, align="lr", widths=(100,), max_rows=None)
                    + ([st.dim("  … more with -v")] if not st.verbose() and len(items) >= cap else []),
                    detail=not plaintext_default)
    artifacts = Counter(str(a) for a in (getattr(summary, "artifacts", None) or []) if str(a).strip())
    rep.section("Artifacts", st.bullets(
        [a + (st.dim(f"  ×{n}") if n > 1 else "") for a, n in artifacts.items()], max_items=None), detail=True)

    ip_to_macs = getattr(summary, "ip_to_macs", None) or {}
    ranked = sorted(ip_to_macs, key=lambda ip: client_counts.get(ip, 0) + server_counts.get(ip, 0), reverse=True)
    rep.section("MAC addresses", st.table(["IP", "MACs"], [[ip, _annotate_macs(ip_to_macs.get(ip, []))] for ip in ranked],
                                          max_rows=None), detail=True)
    rep.section("Notes", st.bullets(notes, max_items=None), detail=True)
    rep.section("Traffic", st.kv([
        ("Packets", f"{getattr(summary, 'total_packets', 0)} total · {packets} {name}"),
        ("Capture bytes", st.size(getattr(summary, "total_bytes", 0))),
        ("Client -> server", st.size(client_bytes)),
        ("Server -> client", st.size(server_bytes)),
        ("Duration", format_duration(dur) if dur is not None else ""),
        ("Sessions", str(n_sessions)),
        ("Clients / servers", f"{getattr(summary, 'unique_clients', 0)} / {getattr(summary, 'unique_servers', 0)}"),
    ] + list(traffic)), detail=True)

    if deterministic and st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, deterministic[0], deterministic[1])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
