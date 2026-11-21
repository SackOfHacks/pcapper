"""One visual language for every pcapper report.

A report reads from conclusion to evidence::

    MODBUS · Electron_SUC1_S4_Modbus_Attack_Traffic.pcapng
    ════════════════════════════════════════════════════════════════════════════════
      HIGH  2 findings · writes from 1 master to 1 server
            568 packets · 36.46 KB · 11m 27s · 2024-05-20T08:45:48Z → 08:57:15Z

    Findings ───────────────────────────────────────────────────────────────────────
      HIGH  Modbus Write Operation  192.168.20.54 -> 192.168.20.59  T0836 Modify Parameter
            Write Multiple Registers to unit 1 (x34) holding_register[8-9] …

      -v adds  traffic statistics · polling cadence · response times

Rules every renderer follows:

* The default view is what an analyst acts on: the verdict, the findings, the
  evidence behind them (who, what, when) and the protocol's key facts.
  ``-v`` prints every section and every row.
* A section with nothing to say is not printed, and nothing is padded with
  "none" lines.
* Severity is a fixed-width word (CRIT, HIGH, MED, LOW, INFO). Colour adds
  emphasis but is never the only signal, so a report survives --no-color, grep
  and copy-paste unchanged.
* Flows are written ``src -> dst``; timestamps are ISO-8601 UTC; counts carry
  thousands separators; sizes and durations are human-readable.
* Tables align on two spaces with numbers right-aligned and no borders; long
  cells are cut with "…" in the default view and printed whole with -v.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Sequence

from ..coloring import (
    ANSI_BOLD,
    ANSI_CYAN,
    ANSI_GREEN,
    ANSI_MAGENTA,
    ANSI_RED,
    ANSI_RED_BG,
    ANSI_RESET,
    ANSI_WHITE,
    ANSI_YELLOW,
    colorize,
    severity_rank,
    use_color,
)
from ..utils import format_bytes_as_mb, format_ts

WIDTH = 80
LINE_WIDTH = 120  # default-view lines are cut to fit this terminal width
DEFAULT_ROWS = 10  # table rows in the default view; -v prints all
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# Output mode
# ---------------------------------------------------------------------------


ROLLUP_NAME = "ALL_PCAPS"


def is_rollup(summary: object) -> bool:
    """A -summarize rollup: the merge of several captures' summaries (named
    ALL_PCAPS, or ALL_PCAPS_<n> by the dedicated merges)."""
    return str(getattr(getattr(summary, "path", None), "name", "") or "").startswith(ROLLUP_NAME)


def verbose() -> bool:
    """True when the user asked for everything (-v)."""
    from . import _common

    return _common._verbose_output()


def quiet() -> bool:
    from . import _common

    return _common._quiet_mode()


_ANALYSIS_SECTIONS = False


def analysis_sections() -> bool:
    """Whether the analysis-only sections (the "Deterministic ... Security
    Checks" blocks and similar) are rendered. Off: the default report is
    the evidence. A future ``--analyze`` flag turns them back on (and lets
    the analyzers skip computing them while it is off)."""
    return _ANALYSIS_SECTIONS


def set_analysis_sections(enabled: bool) -> None:
    global _ANALYSIS_SECTIONS
    _ANALYSIS_SECTIONS = bool(enabled)


def limit(default: int) -> Optional[int]:
    """Rows to show: ``default`` normally, all of them with -v."""
    return None if verbose() else default


# ---------------------------------------------------------------------------
# Colour roles (never the only signal: every coloured token is also a word)
# ---------------------------------------------------------------------------


def accent(text: str) -> str:
    return colorize(text, ANSI_CYAN, bold=True)


def strong(text: str) -> str:
    return colorize(text, ANSI_WHITE, bold=True)


def dim(text: str) -> str:
    return colorize(text, ANSI_WHITE, dim=True)


def good(text: str) -> str:
    return colorize(text, ANSI_GREEN, bold=True)


def bad(text: str) -> str:
    return colorize(text, ANSI_RED, bold=True)


def caution(text: str) -> str:
    return colorize(text, ANSI_YELLOW, bold=True)


def external(text: str) -> str:
    """A public (internet-routable) address: notable, not a severity."""
    return colorize(text, ANSI_MAGENTA)


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def cut(text: object, width: Optional[int]) -> str:
    """``text`` shortened to ``width`` visible characters with "…" (default
    view only; -v prints it whole)."""
    value = "" if text is None else str(text)
    if width is None or verbose() or len(value) <= width or "\x1b" in value:
        return value
    if width <= 1:
        return value[:width]
    head = value[: width - 1]
    # Prefer a nearby word boundary: "for hunt leads…" reads better than
    # "for hun…". Tokens without spaces (IPs, hashes) still cut mid-token.
    if head[-1:].isalnum() and value[width - 1 : width].isalnum():
        space = head.rfind(" ")
        if space >= max(1, width - 16):
            head = head[:space]
    return head.rstrip(" ,;:-|/") + "…"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

_SEV_CODE = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
BADGE_W = 8  # widest severity word
INDENT = " " * (2 + BADGE_W + 2)  # text under a badge


def sev_rank(value: object) -> int:
    return severity_rank(value)


def sev_code(value: object) -> str:
    return _SEV_CODE[max(0, min(4, sev_rank(value)))]


def badge(value: object) -> str:
    """Severity as a word padded to the widest one: CRITICAL, HIGH, MEDIUM,
    LOW or INFO (the vocabulary of CVSS and Sigma, so it greps as expected)."""
    rank = max(0, min(4, sev_rank(value)))
    code = _SEV_CODE[rank]
    pad = " " * (BADGE_W - len(code))
    if not use_color():
        return code + pad
    if rank >= 4:
        return f"{ANSI_RED_BG}{ANSI_WHITE}{ANSI_BOLD}{code}{ANSI_RESET}{pad}"
    if rank == 3:
        return bad(code) + pad
    if rank == 2:
        return caution(code) + pad
    if rank == 1:
        return colorize(code, ANSI_CYAN) + pad
    return dim(code) + pad


def ok_badge(text: str = "OK") -> str:
    return good(text) + " " * max(0, BADGE_W - len(text))


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def count(value: object) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def size(value: object) -> str:
    try:
        return format_bytes_as_mb(int(value or 0))
    except (TypeError, ValueError):
        return str(value)


def duration(seconds: object) -> str:
    """``0.05s``, ``42.3s``, ``11m 27s``, ``3h 05m``, ``2d 04h``; with -v the
    exact form (``134.9 ms``, ``35.17 s``, ``2m 8.1s``)."""
    try:
        value = float(seconds or 0.0)
    except (TypeError, ValueError):
        return str(seconds)
    if value < 0:
        value = 0.0
    if verbose():
        from ..utils import format_duration

        return format_duration(value)
    if value < 60:
        return f"{value:.2f}s" if value < 10 else f"{value:.1f}s"
    minutes, sec = divmod(int(round(value)), 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours:02d}h"


_FRACTION_RE = re.compile(r"\.\d+(?=Z$)")


def ts(value: object) -> str:
    """ISO-8601 UTC, or "-" when unknown: whole seconds in the default view,
    microseconds with -v."""
    if value in (None, "", 0, 0.0):
        return "-"
    try:
        text = format_ts(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return str(value)
    return text if verbose() else _FRACTION_RE.sub("", text)


def ts_range(first: object, last: object) -> str:
    """``2024-05-20T08:45:48Z → 08:57:15Z`` (the date is not repeated)."""
    start, end = ts(first), ts(last)
    if start == "-" and end == "-":
        return "-"
    if end in ("-", start):
        return start
    if start != "-" and start[:11] == end[:11]:
        return f"{start} → {end[11:]}"
    return f"{start} → {end}"


def sparkline_of(values: Sequence[int]) -> str:
    from ..utils import sparkline

    return sparkline(list(values))


def plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{count(n)} {word if n == 1 else (many or word + 's')}"


def flow(src: object, dst: object) -> str:
    return f"{src or '?'} -> {dst or '?'}"


def _flow_text(f: "Finding") -> str:
    """``src -> dst``, or the one end a finding names."""
    src, dst = str(f.src or "").strip(), str(f.dst or "").strip()
    blank = ("", "*", "?", "-")
    if src not in blank and dst not in blank:
        return flow(src, dst)
    return dst if dst not in blank else src


def _has_flow(f: "Finding") -> bool:
    """A finding names a flow unless both ends are blank or wildcards."""
    return any(str(x).strip() not in ("", "*", "?", "-") for x in (f.src, f.dst))


def join(parts: Iterable[object], sep: str = " · ") -> str:
    return sep.join(str(p) for p in parts if p not in (None, ""))


def top(counter: object, n: Optional[int] = 5, fmt: Callable[[object, object], str] | None = None) -> str:
    """``a (12), b (3), +4 more`` from a Counter or dict; all items with -v."""
    if not counter:
        return ""
    items = (
        counter.most_common()  # type: ignore[attr-defined]
        if hasattr(counter, "most_common")
        else sorted(dict(counter).items(), key=lambda kv: (-kv[1], str(kv[0])))  # type: ignore[arg-type]
    )
    render = fmt or (lambda k, v: f"{k} ({count(v)})")
    if verbose():
        return ", ".join(render(k, v) for k, v in items)
    return _fit((render(cut(str(k), TOP_ITEM_WIDTH) if len(str(k)) > TOP_ITEM_WIDTH else k, v)
                 for k, v in (items if n is None else items[:n])), len(items))


def listing(items: Iterable[object], n: Optional[int] = 8) -> str:
    """``a, b, c, +4 more`` from a plain list (the ``top`` of lists without
    counts); all items with -v."""
    values = [str(i) for i in items if str(i)]
    if verbose():
        return ", ".join(values)
    return _fit((cut(v, TOP_ITEM_WIDTH) if len(v) > TOP_ITEM_WIDTH else v
                 for v in (values if n is None else values[:n])), len(values))


def _fit(parts_in: Iterable[str], total: int) -> str:
    """Default view: each item at most TOP_ITEM_WIDTH wide (cut by the
    caller) and the line within TOP_LINE_WIDTH, the rest folded into
    "+N more"."""
    parts: list[str] = []
    used = 0
    for part in parts_in:
        if parts and used + 2 + visible_len(part) > TOP_LINE_WIDTH:
            break
        parts.append(part)
        used += (2 if used else 0) + visible_len(part)
    hidden = total - len(parts)
    return ", ".join(parts) + (dim(f", +{hidden} more") if hidden > 0 else "")


TOP_ITEM_WIDTH = 48
TOP_LINE_WIDTH = 96


# ---------------------------------------------------------------------------
# Building blocks (each returns lines)
# ---------------------------------------------------------------------------


def title(name: str, capture: str) -> list[str]:
    from ..capture_parts import apply_display_names

    capture = apply_display_names(capture)
    return ["", f"{accent(name.upper())} {dim('·')} {strong(capture)}", dim("═" * WIDTH)]


def section_title(name: str) -> str:
    fill = max(3, WIDTH - len(name) - 1)
    return f"{accent(name)} {dim('─' * fill)}"


def kv(pairs: Sequence[tuple[str, object]], indent: int = 2) -> list[str]:
    """``Key:  value`` lines with the values aligned; empty values skipped."""
    pairs = [(k, v) for k, v in pairs if v not in (None, "")]
    if not pairs:
        return []
    width = max(len(k) for k, _ in pairs) + 1
    pad = " " * indent
    return [f"{pad}{dim((k + ':').ljust(width))}  {v}" for k, v in pairs]


def _nouns(n: int, noun: str) -> str:
    if n == 1:
        return noun
    if noun.endswith("y") and noun[-2:-1] not in "aeiou":
        return noun[:-1] + "ies"
    if noun.endswith(("s", "x", "z", "ch", "sh")):
        return noun + "es"  # addresses, boxes
    return noun + "s"


def more(hidden: int, noun: str = "row") -> str:
    """``… 1 more row (-v shows all)`` / ``… 12 more rows (-v shows all)``."""
    return dim(f"  … {count(hidden)} more {_nouns(hidden, noun)} (-v shows all)")


def gap(hidden: int, tail: int, noun: str = "row", *, kept: bool = True, reveal: Optional[int] = None) -> str:
    """The line between the top and the bottom of a ranked table:
    ``┄ 37 more domains · bottom 10 below (-v shows all)``. When the analyzer
    kept only part of the ranking: ``(-v shows 14 of them)`` by default and
    ``┄ 466 more hosts not kept · bottom 10 below`` with -v."""
    if not kept:
        return dim(f"  ┄ {count(hidden)} more {_nouns(hidden, noun)} not kept · bottom {tail} below")
    hint = " (-v shows all)" if reveal is None else (f" (-v shows {count(reveal)} of them)" if reveal else "")
    return dim(f"  ┄ {count(hidden)} more {_nouns(hidden, noun)} · bottom {tail} below{hint}")


TOP_ROWS = 10  # a ranked table's default view: the top and the bottom this many


def table(
    header: Sequence[str],
    rows: Sequence[Sequence[object]],
    *,
    align: str = "",
    max_rows: Optional[int] = DEFAULT_ROWS,
    widths: Sequence[Optional[int]] = (),
    indent: int = 2,
    noun: str = "row",
    tail: Optional[int] = None,
    total: Optional[int] = None,
) -> list[str]:
    """An aligned, borderless table. ``align`` holds one of ``l``/``r`` per
    column (default left); ``widths`` caps a column in the default view;
    ``max_rows`` applies to the default view only. With ``tail`` (rows ranked
    most to least frequent) the default view also keeps the last ``tail``
    rows -- the rarest, where the long tail of an investigation lives.
    ``total`` is how many rows ``rows`` stands for when the analyzer kept
    only its top and its bottom ``tail``."""
    rows = list(rows)
    if not rows:
        return []
    total = max(len(rows), int(total or 0))
    split_at: Optional[int] = None  # where the bottom rows start in ``shown``
    kept = True
    if max_rows is None or verbose():
        shown = rows
        if tail and total > len(rows) and len(rows) > tail:
            split_at, kept = len(rows) - tail, False  # the middle was never kept
    elif tail and total > max_rows + tail:
        shown = rows[:max_rows] + rows[-tail:]
        split_at = max_rows
    else:
        shown = rows[:max_rows] if not tail else rows[: max_rows + tail]
    ncols = max(len(header), max(len(r) for r in shown))
    cells: list[list[str]] = []
    for r in shown:
        # Captured text can carry line breaks; show them, do not break the row.
        row = [("" if c is None else str(c)).replace("\r", "\\r").replace("\n", "\\n") for c in r] + [""] * (ncols - len(r))
        for i, cap in enumerate(widths):
            if i < ncols and cap:
                row[i] = cut(row[i], cap)
        cells.append(row)
    head = list(header) + [""] * (ncols - len(header))
    col_w = [
        max([visible_len(head[i])] + [visible_len(row[i]) for row in cells]) for i in range(ncols)
    ]
    pad = " " * indent

    def fmt(row: Sequence[str], style: Callable[[str], str] | None = None) -> str:
        out = []
        for i, cell in enumerate(row):
            gap = col_w[i] - visible_len(cell)
            right = i < len(align) and align[i] == "r"
            text = style(cell) if style else cell
            if i == ncols - 1 and not right:
                out.append(text)
            else:
                out.append(" " * gap + text if right else text + " " * gap)
        return (pad + "  ".join(out)).rstrip()

    lines = [fmt([h.upper() for h in head], dim)]
    hidden = total - len(shown)
    if split_at is not None:
        lines += [fmt(row) for row in cells[:split_at]]
        reveal = None if total == len(rows) else len(rows) - len(shown)
        lines.append(gap(hidden, len(cells) - split_at, noun, kept=kept, reveal=reveal))
        lines += [fmt(row) for row in cells[split_at:]]
        return lines
    lines += [fmt(row) for row in cells]
    if hidden > 0:
        lines.append(more(hidden, noun))
    return lines


def ranked(header: Sequence[str], rows: Sequence[Sequence[object]], **kwargs: object) -> list[str]:
    """A table of artifacts ranked most to least frequent (domains, hosts,
    URLs, user agents, commands ...): the default view shows the top 10 and
    the bottom 10, -v all of them."""
    kwargs.setdefault("max_rows", TOP_ROWS)
    kwargs.setdefault("tail", TOP_ROWS)
    return table(header, rows, **kwargs)  # type: ignore[arg-type]


def bullets(items: Iterable[object], *, max_items: Optional[int] = DEFAULT_ROWS, indent: int = 2, noun: str = "item") -> list[str]:
    items = [str(i) for i in items if str(i).strip()]
    shown = items if (max_items is None or verbose()) else items[:max_items]
    lines = [f"{' ' * indent}{dim('•')} {item}" for item in shown]
    if len(items) > len(shown):
        lines.append(more(len(items) - len(shown), noun))
    return lines


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    src: str = ""
    dst: str = ""
    ts: Optional[float] = None
    attack: str = ""
    evidence: list[str] = field(default_factory=list)


def _first(obj: object, *names: str) -> object:
    for name in names:
        value = obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)
        if value not in (None, "", [], ()):
            return value
    return None


def _scrub(value: object) -> str:
    """Finding text as displayed: secrets masked under --redact, terminal
    control bytes escaped (a detection can quote a community string, a
    password or raw payload)."""
    from ..utils import display_safe, output_redaction_enabled, redact_sensitive_text

    text = str(value)
    if output_redaction_enabled():
        text = redact_sensitive_text(text)
    return display_safe(text)


def _is_endpoint(value: object) -> bool:
    """An IP (with or without port), MAC, prefix or URI-like address -- not an
    analyzer or category name."""
    text = str(value or "").strip()
    return bool(text) and (any(ch.isdigit() for ch in text) or ":" in text or "@" in text)


_RANKED_EVIDENCE = (
    ("top_clients", "clients"),
    ("top_servers", "servers"),
    ("top_sources", "sources"),
    ("top_destinations", "destinations"),
)


def finding(obj: object, attack_for: Callable[[str], str] | None = None) -> Finding:
    """A Finding from any analyzer's anomaly object or detection dict (a bare
    string is an informational finding titled by the string)."""
    if isinstance(obj, str):
        return Finding(severity="info", title=obj)
    sev = str(_first(obj, "severity", "level") or "info")
    title_text = str(_first(obj, "title", "summary", "name", "kind") or "Finding")
    detail = _first(obj, "description", "details", "detail", "reason")
    detail = _scrub(detail) if detail is not None else None
    src = _first(obj, "src", "src_ip", "client")
    dst = _first(obj, "dst", "dst_ip", "server")
    # Many analyzers file their own name under "source" ("Files", "OT/ICS");
    # it names an endpoint only when it looks like an address.
    if src is None and _is_endpoint(_first(obj, "source")):
        src = _first(obj, "source")
    if dst is None and _is_endpoint(_first(obj, "destination")):
        dst = _first(obj, "destination")
    when = _first(obj, "ts", "first_seen", "timestamp")
    attack = str(_first(obj, "attack", "technique", "mitre") or "")
    if not attack and attack_for is not None:
        attack = attack_for(title_text) or ""
    evidence_raw = _first(obj, "evidence")
    if isinstance(evidence_raw, (list, tuple)):
        evidence = [_scrub(e) for e in evidence_raw if str(e).strip()]
    elif evidence_raw:
        evidence = [_scrub(evidence_raw)]
    else:
        evidence = []
    # Detection dicts carry their pivots as ranked (value, count) lists.
    ranked: dict[str, list] = {}
    for key, label_text in _RANKED_EVIDENCE:
        values = _first(obj, key)
        if isinstance(values, (list, tuple)) and values:
            pairs = []
            for entry in values:
                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    pairs.append((entry[0], entry[1]))
                elif entry not in (None, ""):
                    pairs.append((entry, None))
            if pairs:
                ranked[key] = pairs
                evidence.append(f"{label_text}: " + ", ".join(
                    f"{v} ({count(n)})" if n is not None else str(v) for v, n in pairs))
    ip_counts = _first(obj, "ip_counts", "ips")
    if isinstance(ip_counts, dict) and ip_counts:
        evidence.append("IPs: " + ", ".join(f"{k} ({count(v)})" for k, v in sorted(
            ip_counts.items(), key=lambda kv: -int(kv[1] or 0))))
    elif isinstance(ip_counts, (list, tuple)) and ip_counts:
        evidence.append("IPs: " + ", ".join(str(v) for v in ip_counts))
    for key, label_text in (("artifacts", "artifact"),):
        values = _first(obj, key)
        if isinstance(values, (list, tuple)):
            evidence += [f"{label_text}: {v}" for v in values if str(v).strip()]
    vt = _first(obj, "vt_findings")
    if isinstance(vt, (list, tuple)):
        for entry in vt:
            if isinstance(entry, dict):
                evidence.append(
                    f"VirusTotal: {entry.get('domain') or entry.get('target', '-')} "
                    f"malicious {entry.get('malicious', 0)} / suspicious {entry.get('suspicious', 0)} / "
                    f"harmless {entry.get('harmless', 0)}" + (f" {entry['report_url']}" if entry.get("report_url") else "")
                )
    if src is None:
        for key in ("top_clients", "top_sources"):
            if key in ranked:
                src = ranked[key][0][0]
                break
    if dst is None:
        for key in ("top_servers", "top_destinations"):
            if key in ranked:
                # Two-way evidence ranks the same host first on both sides:
                # the flow runs to the first destination that is not the source.
                others = [value for value, _n in ranked[key] if str(value) != str(src)]
                dst = others[0] if others else None
                break
    try:
        when_f = float(when) if when not in (None, "") else None  # type: ignore[arg-type]
    except (TypeError, ValueError):
        when_f = None
    return Finding(
        severity=sev,
        title=title_text,
        detail="" if detail is None else (", ".join(map(str, detail)) if isinstance(detail, (list, tuple)) else str(detail)),
        src="" if src is None else str(src),
        dst="" if dst is None else str(dst),
        ts=when_f or None,
        attack=attack,
        evidence=evidence,
    )


def worst(findings: Iterable[Finding]) -> int:
    return max((sev_rank(f.severity) for f in findings), default=-1)


def material(findings: Iterable[Finding]) -> bool:
    """Whether any finding is above INFO. An absent protocol with only
    informational findings ("no X traffic detected") is still absent."""
    return any(sev_rank(f.severity) > 0 for f in findings)


def verdict(
    findings: Sequence[Finding],
    *,
    high: str,
    medium: str,
    clean: str = "no findings",
    low: str = "low severity only",
) -> tuple[Optional[str], str]:
    """(badge severity, headline text) for a report. The badge is the worst
    finding's severity; None (shown as OK) only when there are no findings."""
    if not findings:
        return None, clean
    rank = worst(findings)
    severity = next(f.severity for f in findings if sev_rank(f.severity) == rank)
    if rank >= 3:
        text = high
    elif rank == 2:
        text = medium
    elif rank == 1 or low != "low severity only":
        text = low
    else:
        text = "informational only"
    return severity, join([plural(len(findings), "finding"), text])


def findings_block(
    items: Iterable[Finding],
    *,
    max_groups: Optional[int] = 12,
    detail_width: int = 110,
) -> list[str]:
    """Findings grouped by (severity, title), worst first. Each group is one
    aligned line (badge, title, flow, count, ATT&CK technique) and one dim line
    with its time and first detail. With -v every occurrence is listed with
    its time, flow, detail and evidence."""
    items = list(items)
    if not items:
        return []
    groups: dict[tuple[int, str], list[Finding]] = {}
    for f in items:
        groups.setdefault((sev_rank(f.severity), f.title), []).append(f)
    ordered = sorted(groups.items(), key=lambda kv: (-kv[0][0], -len(kv[1]), kv[0][1]))
    shown = ordered if (max_groups is None or verbose()) else ordered[:max_groups]

    rows = []
    for (_rank, name), group in shown:
        flows = Counter(_flow_text(f) for f in group if _has_flow(f))
        flow_txt = ""
        if flows:
            flow_txt = flows.most_common(1)[0][0]
            if len(flows) > 1:
                flow_txt += f" +{len(flows) - 1}"
        rows.append((name, group, flow_txt))
    flow_w = min(44, max((len(ft) for _, _, ft in rows), default=0))
    count_w = max((len(f"×{len(g)}") for _, g, _ in rows if len(g) > 1), default=0)
    attack_w = max((len(next((f.attack for f in g if f.attack), "")) for _, g, _ in rows), default=0)
    # The title takes whatever the line has left after the other columns.
    budget = (LINE_WIDTH - 2 - BADGE_W - 2 - (flow_w + 2 if flow_w else 0) - (count_w + 2 if count_w else 0)
              - (min(attack_w, 24) + 2 if attack_w else 0))
    longest = max(len(name) for name, _, _ in rows)
    title_w = longest if verbose() else min(longest, max(42, budget))

    lines: list[str] = []
    indent = INDENT
    for name, group, flow_txt in rows:
        attack = next((f.attack for f in group if f.attack), "")
        head = [badge(group[0].severity), cut(name, title_w).ljust(title_w)]
        if flow_w:
            head.append(cut(flow_txt, flow_w).ljust(flow_w))
        if count_w:
            head.append(dim(f"×{len(group)}".rjust(count_w)) if len(group) > 1 else " " * count_w)
        if attack:
            head.append(dim(attack))
        lines.append("  " + "  ".join(head).rstrip())
        if verbose():
            for f in sorted(group, key=lambda f: (f.ts or 0.0)):
                where = join([ts(f.ts) if f.ts else "", _flow_text(f) if _has_flow(f) else ""], "  ")
                text = join([where, f.detail], "  ")
                if text:
                    lines.append(indent + dim(text))
                for ev in f.evidence:
                    lines.append(indent + dim(f"  {ev}"))
        else:
            times = sorted(f.ts for f in group if f.ts)
            sample = next((f for f in group if f.detail), None) or next((f for f in group if f.evidence), None)
            text = (sample.detail or "; ".join(sample.evidence)) if sample else ""
            when = ts_range(times[0], times[-1]) if times else ""
            room = max(40, min(detail_width, LINE_WIDTH - len(indent) - len(when) - 2))
            info = join([when, cut(text, room)], "  ")
            if info:
                lines.append(indent + dim(info))
    hidden = len(ordered) - len(shown)
    if hidden > 0:
        lines.append(more(hidden, "finding type"))
    return lines


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


class Report:
    """Collects one analyzer's report and renders it in the house style.

    ``section(..., detail=True)`` marks a section as reference material: it is
    printed with -v and listed in the footer otherwise.
    """

    def __init__(self, name: str, capture: object) -> None:
        self.name = name
        self.capture = str(getattr(capture, "name", capture) or "")
        self.rollup = self.capture.startswith(ROLLUP_NAME)
        if self.rollup:  # ALL_PCAPS, or ALL_PCAPS_<n> from a dedicated merge
            count = self.capture[len(ROLLUP_NAME):].lstrip("_")
            self.capture = f"all captures ({count})" if count.isdigit() else "all captures"
        self._head: list[str] = []
        self._body: list[str] = []
        self._omitted: list[str] = []

    # -- headline -----------------------------------------------------------
    def headline(self, severity: object, text: str, scope: str = "") -> "Report":
        """The verdict under the title: ``severity`` None/"" means no findings
        (OK); False is a lookup or tool result with no verdict (neutral mark)."""
        if severity is False:
            mark = dim("•".ljust(BADGE_W))
        else:
            mark = badge(severity) if severity not in (None, "") else ok_badge()
        self._head.append(f"  {mark}  {text}".rstrip())
        if scope:
            self.scope(scope)
        return self

    def scope(self, text: str) -> "Report":
        """A dim context line under the headline (counts, roles, time span)."""
        if text:
            self._head.append(INDENT + dim(text))
        return self

    def note(self, label_text: str, text: str) -> "Report":
        """A highlighted hint under the headline, e.g. ``NOTE  2 masters``."""
        self._head.append(f"  {caution(label_text.ljust(BADGE_W))}  {text}")
        return self

    def absent(self, what: str, errors: Iterable[object] = ()) -> str:
        """The whole report for a capture without this protocol: one line
        (plus any errors, which may explain the absence)."""
        where = "in these captures" if self.rollup else "in this capture"
        self._head.append(f"  {dim('–'.ljust(BADGE_W))}  {dim(f'no {what} {where}')}")
        errs = [str(e) for e in errors if str(e).strip()]
        if errs:
            self.section("Errors", [f"  {bad('!')} {e}" for e in errs])
        return self.render()

    def line(self, text: str) -> "Report":
        self._head.append(text)
        return self

    # -- body ---------------------------------------------------------------
    def section(self, name: str, lines: Iterable[str], *, detail: bool = False) -> "Report":
        lines = [ln for ln in lines if ln is not None]
        if not lines:
            return self
        if detail and not verbose():
            self._omitted.append(name.lower())
            return self
        self._body.append("")
        self._body.append(section_title(name))
        self._body.extend(lines)
        return self

    def omitted(self, name: str) -> "Report":
        """Record a -v-only section that was built outside :meth:`section`."""
        if not verbose():
            self._omitted.append(name.lower())
        return self

    # -- output -------------------------------------------------------------
    def lines(self) -> list[str]:
        out = title(self.name, self.capture)
        out += self._head
        out += self._body
        if self._omitted and not quiet():
            seen: list[str] = []
            for name in self._omitted:
                if name not in seen:
                    seen.append(name)
            if len(seen) > 7:
                seen = seen[:6] + [f"+{len(seen) - 6} more"]
            out += ["", f"  {dim('-v adds')}  {dim(join(seen))}"]
        return out

    def render(self) -> str:
        return finalize(self.lines())


def finalize(lines: Iterable[str]) -> str:
    """Redaction, terminal-safety and external-address colouring, the same
    for every report."""
    from ..utils import is_public_ip, output_redaction_enabled, redact_sensitive_text, terminal_safe

    text = "\n".join(lines)
    if output_redaction_enabled():
        text = redact_sensitive_text(text)
    text = terminal_safe(text)
    if not use_color():
        return text

    def _ip(match: re.Match[str]) -> str:
        value = match.group(0)
        return external(value) if is_public_ip(value) else value

    # Colour public addresses only in unstyled text: inside a styled span the
    # address's own reset would end that span's colour or dimming early.
    out: list[str] = []
    styled = False
    pos = 0
    for m in _ANSI_RE.finditer(text):
        chunk = text[pos:m.start()]
        out.append(chunk if styled else _IPV6_RE.sub(_ip, _IPV4_RE.sub(_ip, chunk)))
        out.append(m.group(0))
        styled = m.group(0) not in ("\x1b[0m", "\x1b[m")
        pos = m.end()
    tail = text[pos:]
    out.append(tail if styled else _IPV6_RE.sub(_ip, _IPV4_RE.sub(_ip, tail)))
    return "".join(out)


_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Two or more colons: an IPv6 address; is_public_ip() rejects the times, MACs
# and other colon-separated tokens this also matches.
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
