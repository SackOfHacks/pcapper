"""Primitives shared across the reporting package.

Constants, formatting helpers, and the mutable output-mode state
(verbose, quiet, OUI annotation, OT full-render) with the accessors
that read it. Everything here is reached by renderers in more than
one module, or by none.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..utils import is_public_ip as _is_public_ip
import re
from collections import Counter, defaultdict
from typing import Callable, Iterable, Protocol
from ..coloring import (
    danger,
    header,
    highlight,
    label,
    muted,
    ok,
    warn,
)
from ..ipmac import mac_manufacturer
from ..reporting_format import format_table
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
    sparkline,
)


class _SizeBucketLike(Protocol):
    count: int
    avg: float
    min: int
    max: int


SECTION_BAR = "=" * 72


SUBSECTION_BAR = "-" * 72


_VERBOSE_OUTPUT = False


_FULL_OUTPUT_LIMIT = 1_000_000


# Quiet mode — suppresses decoration intended for human readers (the banner
# is gated in cli.main(); the trailing "Output is summarized…" footer is
# gated below). Designed for programmatic consumers (e.g. /threathunt review
# -pcapper) so they don't have to post-process. Independent of --verbose.
_QUIET_MODE = False


def set_verbose_output(enabled: bool) -> None:
    global _VERBOSE_OUTPUT
    _VERBOSE_OUTPUT = enabled


def set_quiet_mode(enabled: bool) -> None:
    """Toggle programmatic-friendly output: suppress trailing summary notes
    and (caller-side) the startup banner. Does not affect data accuracy or
    truncation thresholds — those are controlled by set_verbose_output()."""
    global _QUIET_MODE
    _QUIET_MODE = enabled


def is_quiet_mode() -> bool:
    return _QUIET_MODE


# OUI vendor annotation — when enabled, MAC addresses in "Observed MACs"
# tables are suffixed with the manufacturer name from scapy's manufdb.
# Default OFF for backward compatibility (existing test outputs / parsers
# don't see column shifts). Opt-in via --oui CLI flag.
_OUI_ANNOTATE = False


def set_oui_annotation(enabled: bool) -> None:
    global _OUI_ANNOTATE
    _OUI_ANNOTATE = enabled


def is_oui_annotation_enabled() -> bool:
    return _OUI_ANNOTATE


def _annotate_macs(macs: list[str] | tuple[str, ...]) -> str:
    """Render a MAC list as a string. With OUI annotation on, suffix each MAC
    with its manufacturer (e.g. ``70:70:8b:67:c1:f2 (Honeywell)``) when the
    scapy manufdb has a known vendor. Returns ``"-"`` for empty input."""
    if not macs:
        return "-"
    if not _oui_annotate():
        return ", ".join(macs) or "-"
    parts = []
    for mac in macs:
        vendor = mac_manufacturer(mac)
        if vendor and vendor != "-":
            parts.append(f"{mac} ({vendor})")
        else:
            parts.append(mac)
    return ", ".join(parts) or "-"


# OT/ICS protocol reports show FULL output by default (no -v needed) and omit
# the truncation footer — an OT analyst triaging a control-network capture wants
# every endpoint/command/anomaly without re-running. Set for the duration of an
# OT renderer via @_ot_full_render.
_OT_FULL_OUTPUT = False


def _ot_full_render(fn):
    """Decorator: render an OT protocol summary at full depth (no truncation,
    no "use -v" footer) regardless of the global verbose flag."""
    import functools

    @functools.wraps(fn)
    def _wrap(*args, **kwargs):
        global _OT_FULL_OUTPUT
        prev = _ot_full_output()
        _OT_FULL_OUTPUT = True
        try:
            return fn(*args, **kwargs)
        finally:
            _OT_FULL_OUTPUT = prev

    return _wrap


# --scan and --overview always render at full depth (no truncation, no "use -v"
# footer, verbose sections always shown) regardless of the -v flag.
_always_full_render = _ot_full_render


def _verbose_output() -> bool:
    return _VERBOSE_OUTPUT


def _quiet_mode() -> bool:
    return _QUIET_MODE


def _oui_annotate() -> bool:
    return _OUI_ANNOTATE


def _ot_full_output() -> bool:
    return _OT_FULL_OUTPUT


def _apply_verbose_limit(limit: int | None) -> int | None:
    if _verbose_output() or _ot_full_output():
        if limit is None:
            return None
        return _FULL_OUTPUT_LIMIT
    return limit


def _limit_value(value: int) -> int:
    return _FULL_OUTPUT_LIMIT if (_verbose_output() or _ot_full_output()) else value


def _redact_secret(value: str | None) -> str:
    # Redaction intentionally disabled. pcapper is a forensic / credential-
    # recovery tool whose purpose is to surface secrets, passwords, tokens and
    # keys recovered from a capture, so they are shown in full by default.
    if value is None:
        return "-"
    text = str(value).strip()
    if not text:
        return "-"
    return text


def _redact_in_text(text: str) -> str:
    # Redaction intentionally disabled — see _redact_secret. Inline secrets in
    # free-text findings (e.g. "PASS hunter2", "Authorization: Bearer ...") are
    # shown verbatim so the full recovered value is visible by default.
    return text


def _format_kv(
    label_text: str, value: str, width: int = 24, color: bool | None = None
) -> str:
    # Pad on the *visible* label width: label() may wrap the text in ANSI
    # escapes, and applying ":<width" to the colorized string would count the
    # invisible escape bytes and misalign the ": value" column when color is
    # on. Padding by len(label_text) is byte-identical to the old behaviour
    # when color is disabled.
    pad = max(0, width - len(label_text))
    return f"{label(label_text, color)}{' ' * pad}: {value}"


def _format_counter(counter: object, limit: int = 5, key_max: int = 40) -> str:
    if not counter:
        return "-"
    if hasattr(counter, "most_common"):
        items = list(counter.most_common(_limit_value(limit)))
    elif isinstance(counter, dict):
        items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[
            : _limit_value(limit)
        ]
    else:
        return "-"
    parts: list[str] = []
    for key, value in items:
        name = _truncate_text(str(key), key_max)
        try:
            count = int(value)
        except Exception:
            count = value
        parts.append(f"{name}({count})")
    return ", ".join(parts) if parts else "-"


def _format_table(rows: Iterable[list[str]]) -> str:
    return format_table(rows)


def _counter_table(
    counter: object,
    key_label: str,
    *,
    limit: int = 5,
    count_label: str = "Count",
) -> str:
    """Render a Counter as a 2-column "<key_label> | Count" table.

    Consolidates the dominant reporting idiom (build [[label,"Count"]] rows,
    append str(key)/str(count) for most_common, format_table). Behaviour matches
    the inline form exactly: keys are stringified, so it is a drop-in for both
    the `[name, str(count)]` and `[str(name), str(count)]` variants.
    """
    rows = [[key_label, count_label]]
    most_common = getattr(counter, "most_common", None)
    items = most_common(limit) if callable(most_common) else []
    for key, count in items:
        rows.append([str(key), str(count)])
    return _format_table(rows)


def _merge_ranked_detection_pairs(values: list[object], limit: int = 10) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for value in values:
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            name = str(item[0]).strip()
            if not name:
                continue
            try:
                count = int(item[1])
            except Exception:
                count = 0
            if count <= 0:
                continue
            counts[name] += count
    return [(str(name), int(count)) for name, count in counts.most_common(limit)]


def _merge_detection_evidence_lines(values: list[object], limit: int = 10) -> list[str]:
    merged: list[str] = []
    for value in values:
        if isinstance(value, list):
            for item in value:
                text = str(item).strip()
                if text:
                    merged.append(text)
        elif isinstance(value, str):
            text = value.strip()
            if text:
                merged.append(text)
    return list(dict.fromkeys(merged))[:limit]


def _collapse_detection_details(details: list[str]) -> str:
    cleaned = [str(item).strip() for item in details if str(item).strip()]
    if not cleaned:
        return ""
    if len(set(cleaned)) == 1:
        return cleaned[0]

    num_re = re.compile(r"\d+")
    templates = [num_re.sub("#", item) for item in cleaned]
    number_groups = [[int(v) for v in num_re.findall(item)] for item in cleaned]
    if (
        templates
        and len(set(templates)) == 1
        and number_groups
        and all(len(group) == len(number_groups[0]) for group in number_groups)
        and len(number_groups[0]) > 0
    ):
        summed = [
            sum(group[idx] for group in number_groups)
            for idx in range(len(number_groups[0]))
        ]
        next_index = 0

        def _replace_num(_match: re.Match[str]) -> str:
            nonlocal next_index
            value = str(summed[next_index])
            next_index += 1
            return value

        merged = num_re.sub(_replace_num, cleaned[0])
        return f"{merged} Aggregated across {len(cleaned)} capture result(s)."

    unique = list(dict.fromkeys(cleaned))
    if len(unique) == 2:
        return f"{unique[0]} | {unique[1]}"
    preview = " | ".join(unique[:2])
    return (
        f"{preview} | +{len(unique) - 2} additional detail variant(s) "
        f"across {len(cleaned)} capture result(s)."
    )


def _collapse_rollup_detections(
    detections: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not detections:
        return []
    merged_by_key: dict[tuple[str, str, str], dict[str, object]] = {}
    order: list[tuple[str, str, str]] = []

    for item in detections:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source", "")).strip() or "Unknown"
        severity = str(item.get("severity", "info")).strip().lower() or "info"
        summary = str(item.get("summary", "")).strip()
        if not summary:
            continue
        key = (source, severity, summary)

        if key not in merged_by_key:
            normalized = dict(item)
            normalized["source"] = source
            normalized["severity"] = severity
            normalized["summary"] = summary
            normalized["_details"] = [str(item.get("details", "")).strip()]
            try:
                normalized["occurrences"] = max(1, int(item.get("occurrences", 1) or 1))
            except Exception:
                normalized["occurrences"] = 1
            merged_by_key[key] = normalized
            order.append(key)
            continue

        existing = merged_by_key[key]
        try:
            existing_count = max(1, int(existing.get("occurrences", 1) or 1))
        except Exception:
            existing_count = 1
        try:
            incoming_count = max(1, int(item.get("occurrences", 1) or 1))
        except Exception:
            incoming_count = 1
        existing["occurrences"] = existing_count + incoming_count
        details_list = list(existing.get("_details", []) or [])
        detail_text = str(item.get("details", "")).strip()
        if detail_text:
            details_list.append(detail_text)
        existing["_details"] = details_list

        for ranked_key in (
            "top_sources",
            "top_destinations",
            "top_clients",
            "top_servers",
            "tools",
        ):
            merged_pairs = _merge_ranked_detection_pairs(
                [existing.get(ranked_key), item.get(ranked_key)],
                limit=10,
            )
            if merged_pairs:
                existing[ranked_key] = merged_pairs
            else:
                existing.pop(ranked_key, None)

        merged_evidence = _merge_detection_evidence_lines(
            [existing.get("evidence"), item.get("evidence")],
            limit=10,
        )
        if merged_evidence:
            existing["evidence"] = merged_evidence
        else:
            existing.pop("evidence", None)

    severity_order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    collapsed = [merged_by_key[key] for key in order if key in merged_by_key]
    collapsed.sort(
        key=lambda item: (
            severity_order.get(str(item.get("severity", "info")), 99),
            str(item.get("source", "")),
            str(item.get("summary", "")),
        )
    )
    for item in collapsed:
        item["details"] = _collapse_detection_details(
            [str(v) for v in list(item.get("_details", []) or []) if str(v).strip()]
        )
        item.pop("_details", None)
    return collapsed


def _filtered_detections(summary, verbose: bool) -> list[dict[str, object]]:
    detections = list(getattr(summary, "detections", []) or [])
    if not detections:
        return []
    if not verbose:
        filtered = []
        for item in detections:
            severity = str(item.get("severity") or "info").lower()
            if severity in {"info", "informational"}:
                continue
            filtered.append(item)
        detections = filtered
    if not detections:
        return []
    ot_counts_raw = getattr(summary, "ot_protocol_counts", None)
    ot_counts = (
        {str(k).upper(): int(v) for k, v in (ot_counts_raw or {}).items()}
        if ot_counts_raw
        else {}
    )
    ot_aliases = {
        "DF1": ["DF1"],
        "PCCC": ["PCCC"],
        "MODBUS": ["MODBUS"],
        "DNP3": ["DNP3"],
        "IEC-104": ["IEC-104"],
        "BACNET": ["BACNET"],
        # CIP rides EtherNet/IP, so CIP traffic is counted under "EtherNet/IP"
        # (not a separate "CIP" key). Without these cross-aliases the OT-presence
        # gate dropped every genuine CIP detection (high-risk commands, unexpected
        # writes, multi-service bundles) on real EtherNet/IP captures.
        "ETHERNET/IP": ["ETHERNET/IP", "ENIP", "CIP"],
        "CIP": ["CIP", "ETHERNET/IP", "ENIP"],
        "PROFINET": ["PROFINET"],
        "S7": ["S7"],
        "OPC UA": ["OPC UA"],
        "OPC CLASSIC": ["OPC CLASSIC"],
        "ETHERCAT": ["ETHERCAT"],
        "FINS": ["FINS"],
        "CRIMSON": ["CRIMSON"],
        "PCWORX": ["PCWORX"],
        "MELSEC": ["MELSEC"],
        "ODESYS": ["ODESYS"],
        "NIAGARA": ["NIAGARA"],
        "MMS": ["MMS"],
        "SRTP": ["SRTP"],
        "CSP": ["CSP"],
        "MODICON": ["MODICON"],
        "YOKOGAWA": ["YOKOGAWA"],
        "HONEYWELL": ["HONEYWELL"],
        "MQTT": ["MQTT"],
        "COAP": ["COAP"],
        "HART-IP": ["HART-IP", "HART"],
        "PROCONOS": ["PROCONOS"],
        "ICCP": ["ICCP"],
        "GOOSE": ["GOOSE"],
        "SV": ["SV"],
        "PTP": ["PTP"],
        "LLDP/DCP": ["LLDP", "DCP"],
        "LLDP": ["LLDP"],
        "DCP": ["DCP"],
    }

    def _ot_present(label: str) -> bool:
        for token in ot_aliases.get(label, [label]):
            if ot_counts.get(token.upper(), 0) > 0:
                return True
        return False

    def _detect_ot_label(item: dict[str, object]) -> str | None:
        source = str(item.get("source", ""))
        summary_text = str(item.get("summary", ""))
        details_text = str(item.get("details", ""))
        blob = f"{source} {summary_text} {details_text}".upper()
        for alias in ot_aliases.keys():
            if alias in blob:
                return alias
        return None

    proto_counts = getattr(summary, "protocol_counts", None)
    if proto_counts:
        proto_set = {str(key).upper() for key in proto_counts.keys()}
        filtered = []
        for item in detections:
            proto = item.get("protocol") or item.get("proto")
            if proto:
                if str(proto).upper() not in proto_set:
                    continue
            if ot_counts:
                ot_label = _detect_ot_label(item)
                if ot_label and not _ot_present(ot_label):
                    continue
            filtered.append(item)
        detections = filtered
    elif ot_counts:
        filtered = []
        for item in detections:
            ot_label = _detect_ot_label(item)
            if ot_label and not _ot_present(ot_label):
                continue
            filtered.append(item)
        detections = filtered

    path_obj = getattr(summary, "path", None)
    if path_obj is not None and getattr(path_obj, "name", "") == "ALL_PCAPS":
        detections = _collapse_rollup_detections(detections)
    return detections


def _format_client_server_table(
    client_counts: Counter[str],
    server_counts: Counter[str],
    limit: int = 8,
) -> str:
    rows = [["Clients", "Servers"]]
    client_items = [
        f"{ip}({count})" for ip, count in client_counts.most_common(_limit_value(limit))
    ]
    server_items = [
        f"{ip}({count})" for ip, count in server_counts.most_common(_limit_value(limit))
    ]
    max_len = max(len(client_items), len(server_items))
    if max_len == 0:
        rows.append(["-", "-"])
    else:
        for idx in range(max_len):
            rows.append(
                [
                    client_items[idx] if idx < len(client_items) else "-",
                    server_items[idx] if idx < len(server_items) else "-",
                ]
            )
    return _format_table(rows)


def _conv_value(
    conv: object, name: str, default: object | None = None
) -> object | None:
    if isinstance(conv, dict):
        return conv.get(name, default)
    return getattr(conv, name, default)


def _format_sessions_table(
    conversations: list[object],
    limit: int,
    *,
    packet_label: str = "Packets",
    packet_value_fn: Callable[[object], object] | None = None,
    extra_cols: list[tuple[str, Callable[[object], object]]] | None = None,
) -> str:
    extra_cols = extra_cols or []
    rows = [
        ["Client", "Server", "Start", "End", "Duration", packet_label, "Size"]
        + [label for label, _fn in extra_cols]
    ]

    def _to_float(value: object | None) -> float | None:
        if value is None:
            return None
        try:
            return float(value)
        except Exception:
            return None

    def _session_sort_key(conv: object) -> tuple[float, float]:
        bytes_val = _conv_value(conv, "bytes", 0) or 0
        packets_val = _conv_value(conv, "packets", 0) or 0
        try:
            return (float(bytes_val), float(packets_val))
        except Exception:
            return (0.0, 0.0)

    top_sessions = sorted(conversations, key=_session_sort_key, reverse=True)[:limit]
    for conv in top_sessions:
        client_ip = (
            _conv_value(conv, "client_ip")
            or _conv_value(conv, "src_ip")
            or _conv_value(conv, "src")
            or "-"
        )
        server_ip = (
            _conv_value(conv, "server_ip")
            or _conv_value(conv, "dst_ip")
            or _conv_value(conv, "dst")
            or "-"
        )
        client_port = _conv_value(conv, "client_port") or _conv_value(conv, "src_port")
        server_port = _conv_value(conv, "server_port") or _conv_value(conv, "dst_port")
        client = (
            f"{client_ip}:{client_port}" if client_port is not None else str(client_ip)
        )
        server = (
            f"{server_ip}:{server_port}" if server_port is not None else str(server_ip)
        )

        first_seen = _conv_value(conv, "first_seen")
        last_seen = _conv_value(conv, "last_seen")
        first_val = _to_float(first_seen)
        last_val = _to_float(last_seen)
        duration = None
        if first_val is not None and last_val is not None:
            duration = max(0.0, last_val - first_val)

        if packet_value_fn is not None:
            packet_val = packet_value_fn(conv)
        else:
            packet_val = _conv_value(conv, "packets")
            if packet_val is None:
                requests = _conv_value(conv, "requests")
                responses = _conv_value(conv, "responses")
                if requests is not None or responses is not None:
                    packet_val = int(requests or 0) + int(responses or 0)
        packet_text = str(packet_val) if packet_val is not None else "-"

        bytes_val = _conv_value(conv, "bytes")
        size_text = (
            format_bytes_as_mb(int(bytes_val))
            if isinstance(bytes_val, (int, float))
            else "-"
        )

        row = [
            client,
            server,
            format_ts(
                first_seen if isinstance(first_seen, (int, float)) else first_val
            ),
            format_ts(last_seen if isinstance(last_seen, (int, float)) else last_val),
            format_duration(duration),
            packet_text,
            size_text,
        ]
        for _label, extractor in extra_cols:
            try:
                value = extractor(conv)
            except Exception:
                value = "-"
            row.append(str(value))
        rows.append(row)

    return _format_table(rows)


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


_IPV6_RE = re.compile(r"\b[0-9A-Fa-f:]{2,}\b")


def _highlight_public_ips(text: str) -> str:
    def _replace_ipv4(match: re.Match[str]) -> str:
        ip_value = match.group(0)
        return danger(ip_value) if _is_public_ip(ip_value) else ip_value

    def _replace_ipv6(match: re.Match[str]) -> str:
        token = match.group(0)
        if ":" not in token:
            return token
        return danger(token) if _is_public_ip(token) else token

    text = _IPV4_RE.sub(_replace_ipv4, text)
    return _IPV6_RE.sub(_replace_ipv6, text)


def _finalize_output(lines: list[str], show_truncation_note: bool = True) -> str:
    # Suppress the human-facing "Use -v" footer in quiet mode so programmatic
    # consumers don't have to grep it out. The truncation still happens; the
    # caller can pass --verbose if they want the full data.
    if (
        lines
        and show_truncation_note
        and not _verbose_output()
        and not _quiet_mode()
        and not _ot_full_output()
    ):
        lines.append(
            muted("Output is summarized/truncated. Use -v to view all output.")
        )
    return _highlight_public_ips("\n".join(lines))


_PROTO_SEV_RANK = {
    "critical": 4,
    "high": 3,
    "warning": 2,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _normalize_finding(item: object) -> tuple[str, str, str]:
    """Normalize a detection dict OR an anomaly dataclass to (severity, title,
    detail) so a shared verdict block works across analyzers with different
    finding shapes."""
    if isinstance(item, dict):
        sev = str(item.get("severity", "info")).lower()
        title = str(item.get("summary") or item.get("title") or "-")
        detail = str(item.get("details") or item.get("description") or "")
    else:
        sev = str(getattr(item, "severity", "info") or "info").lower()
        # Fall back to `.type` (the anomaly category, e.g. NetbiosAnomaly) so the
        # verdict ribbon never shows a bare "-" when a dataclass lacks title/summary.
        title = str(
            getattr(item, "title", None)
            or getattr(item, "summary", None)
            or getattr(item, "type", None)
            or "-"
        )
        detail = str(
            getattr(item, "description", None) or getattr(item, "details", None) or ""
        )
    return sev, title, detail


_PLAINTEXT_WORD_RE = re.compile(r"[A-Za-z]{3,}")


def _is_meaningful_plaintext(text: str) -> bool:
    """An "Observed Plaintext" entry worth showing an analyst, vs. binary noise.

    Protocol string-carvers (e.g. rpc/_extract_strings) emit every printable
    4+ byte run found in binary payloads, which floods the verbose view with
    junk like ``@gE::`` and ``Cj::#6?\\``. A real artifact (username, UNC path,
    hostname, command) contains an actual word and is mostly text/path chars."""
    t = (text or "").strip()
    if len(t) < 5:
        return False
    if not _PLAINTEXT_WORD_RE.search(t):  # needs a >=3-letter run
        return False
    texty = sum(1 for c in t if c.isalnum() or c in " ._-\\/:@$")
    return texty / len(t) >= 0.75


def _meaningful_plaintext_items(
    counter: "Counter[str]", limit: int
) -> list[tuple[str, int]]:
    """Filter a plaintext-string counter to meaningful entries, most-common
    first, capped at ``limit`` — keeps the carved-string sections useful for
    forensics instead of an unreadable binary-noise dump."""
    out: list[tuple[str, int]] = []
    for text, count in counter.most_common():
        if _is_meaningful_plaintext(str(text)):
            out.append((text, count))
        if len(out) >= limit:
            break
    return out


def _render_deterministic_checks(
    lines: list[str],
    summary: object,
    title: str,
    check_labels: list[tuple[str, str]],
) -> None:
    """Render a module's computed deterministic_checks as a standard
    "Deterministic … Security Checks" section (label + per-finding evidence,
    with cleared checks collapsed to one line). Used by protocol renderers that
    compute rich checks but had no surfacing path of their own."""
    checks = getattr(summary, "deterministic_checks", {}) or {}
    if not isinstance(checks, dict):
        return
    lines.append(SUBSECTION_BAR)
    lines.append(header(title))
    cleared: list[str] = []
    any_fired = False
    for key, label_text in check_labels:
        evidence = [str(v) for v in list(checks.get(key, []) or []) if str(v).strip()]
        if evidence:
            any_fired = True
            lines.append(label(label_text))
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence[: _limit_value(6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            cleared.append(label_text)
    if not any_fired:
        lines.append(ok("No deterministic checks crossed threshold in this capture."))
    elif cleared:
        lines.append(muted(f"Cleared (no evidence): {', '.join(cleared)}"))


def _render_protocol_verdict(
    lines: list[str],
    *,
    label: str,
    detections: object = None,
    anomalies: object = None,
) -> None:
    """Prepend a triage-style Analyst Verdict + Focus-Here-First ribbon to a
    protocol renderer. Silent on benign captures (only emits when a warning+
    finding exists) so it doesn't add noise. The detailed tables follow below."""
    items: list[tuple[str, str, str]] = []
    for src in list(detections or []) + list(anomalies or []):
        items.append(_normalize_finding(src))
    if not items:
        return
    worst = max(_PROTO_SEV_RANK.get(s, 0) for s, _, _ in items)
    if worst < 2:  # only low/info findings — stay silent on benign traffic
        return
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if worst >= 4:
        lines.append(danger(f"CRITICAL - {label}: critical-severity activity observed."))
    elif worst >= 3:
        lines.append(danger(f"HIGH - {label}: high-severity activity observed."))
    else:
        lines.append(warn(f"REVIEW - {label}: notable activity observed."))
    ranked = sorted(items, key=lambda t: _PROTO_SEV_RANK.get(t[0], 0), reverse=True)
    lines.append(muted("Focus Here First:"))
    for sev, title, detail in ranked[: _limit_value(6)]:
        if _PROTO_SEV_RANK.get(sev, 0) < 2:
            continue
        mark = (
            danger(f"[{sev.upper()}]")
            if _PROTO_SEV_RANK.get(sev, 0) >= 3
            else warn(f"[{sev.upper()}]")
        )
        suffix = f" — {_truncate_text(detail, 90)}" if detail else ""
        lines.append(f"  {mark} {title}{suffix}")


def _truncate_text(value: str, max_len: int = 80) -> str:
    if _verbose_output():
        return value
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def _short_browser_role(roles: list) -> str:
    """Collapse a Browser SV_TYPE role list into a compact triage tag, priority
    directory-infra first (DC/SQL/print/master browser)."""
    if not roles:
        return ""
    joined = ", ".join(str(r) for r in roles)
    for needle, tag in (
        ("Domain Controller (PDC)", "PDC"),
        ("Backup Domain Controller", "BDC"),
        ("Master Browser", "master-browser"),
        ("SQL Server", "SQL"),
        ("Print Queue Server", "print-srv"),
        ("Terminal Server", "term-srv"),
        ("Server", "server"),
    ):
        if needle in joined:
            return tag
    return ""


# Keyword -> ATT&CK for ICS technique, applied to OT anomaly TITLES so the
# shared industrial renderer (and any OT analyzer) maps findings to ICS
# techniques without each analyzer carrying the IDs. Order matters (first match).
_OT_ATTACK_KEYWORDS = [
    # Modbus-specific titles — placed first so they win over the generic
    # "write"/"unsolicited" fallbacks below (first match wins).
    ("broadcast write", "T0831 Manipulation of Control"),
    ("read-then-write", "T0836 Modify Parameter"),
    ("unanswered", "T0814 Denial of Service"),
    ("unsolicited response", "T0856 Spoof Reporting Message"),
    ("static transaction", "T0856 Spoof Reporting Message"),
    ("coil force", "T0831 Manipulation of Control"),
    ("enumeration campaign", "T0846 Remote System Discovery"),
    ("discovery sweep", "T0846 Remote System Discovery"),
    ("sensitive tag", "T0836 Modify Parameter"),
    ("write target", "T0836 Modify Parameter"),
    ("high-risk cip", "T0855 Unauthorized Command Message"),
    ("write burst", "T0836 Modify Parameter"),
    ("program download", "T0843 Program Download"),
    ("program upload", "T0845 Program Upload"),
    # Generic "program transfer" title (S7) — a transfer TO the PLC is the
    # ladder-logic injection vector (Stuxnet). Map to Program Download.
    ("program transfer", "T0843 Program Download"),
    ("download", "T0843 Program Download"),
    ("upload", "T0845 Program Upload"),
    ("firmware", "T0857 System Firmware"),
    # Generic "CPU state change"/"state change" title (S7 PLCStop/Start) =
    # device restart/shutdown / denial of control.
    ("cpu state change", "T0816 Device Restart/Shutdown"),
    ("state change", "T0816 Device Restart/Shutdown"),
    ("reinitialize", "T0816 Device Restart/Shutdown"),  # BACnet ReinitializeDevice
    ("restart", "T0816 Device Restart/Shutdown"),
    ("reboot", "T0816 Device Restart/Shutdown"),
    ("stop", "T0816 Device Restart/Shutdown"),
    ("shutdown", "T0816 Device Restart/Shutdown"),
    # BACnet DeviceCommunicationControl (disable comms) = denial of service.
    ("communication control", "T0814 Denial of Service"),
    ("denial of service", "T0814 Denial of Service"),
    ("key switch", "T0858 Change Operating Mode"),
    ("operating mode", "T0858 Change Operating Mode"),
    ("mode change", "T0858 Change Operating Mode"),
    ("spoof", "T0856 Spoof Reporting Message"),
    ("publisher", "T0856 Spoof Reporting Message"),
    ("write", "T0836 Modify Parameter"),
    ("set attribute", "T0836 Modify Parameter"),
    ("setpoint", "T0836 Modify Parameter"),
    ("config", "T0836 Modify Parameter"),
    ("force", "T0831 Manipulation of Control"),
    ("operate", "T0855 Unauthorized Command Message"),
    ("control command", "T0855 Unauthorized Command Message"),
    ("command", "T0855 Unauthorized Command Message"),
    ("unsolicited", "T0855 Unauthorized Command Message"),
    ("scan", "T0846 Remote System Discovery"),
    ("enumerat", "T0846 Remote System Discovery"),
    ("discovery", "T0846 Remote System Discovery"),
    ("read device", "T0888 Remote System Information Discovery"),
    ("identification", "T0888 Remote System Information Discovery"),
    ("interrogation", "T0846 Remote System Discovery"),
    ("public ip", "T0883 Internet Accessible Device"),
    ("public endpoint", "T0883 Internet Accessible Device"),
    ("exposure", "T0883 Internet Accessible Device"),
    ("brute", "T0859 Valid Accounts"),
    ("erase", "T0809 Data Destruction"),
    ("delete", "T0809 Data Destruction"),
]


def _ot_attack_for_title(title: str) -> str:
    low = str(title or "").lower()
    for needle, tech in _OT_ATTACK_KEYWORDS:
        if needle in low:
            return tech
    return ""


# Keyword sets to classify an OT command/operation name by consequence, shared
# by the generic industrial renderer's command summary across ~15 protocols.
# Kept specific to avoid false hits (e.g. bare "control" matching "Controller").
_OT_CMD_CONTROL_KW = (
    "write", "operate", "force", "set attr", "setattr", "set_attr", "download",
    "program download", "program upload", "reset", "restart", "reboot",
    "reinitial", "cold restart", "warm restart", "stop", "plc start", "start cpu",
    "start application", "control relay", "control output", "communication control",
    "communicationcontrol", "comm control", "actuat", "delete", "create object",
    "erase", "firmware",
    "select", "activate config", "set point", "setpoint", "mode change",
    "run mode", "format", "wipe", "clear ", "assign class",
)


_OT_CMD_REVIEW_KW = (
    "read device", "read identity", "identity", "enumerat", "discover", "list ",
    "get attr", "get_attr", "getattr", "browse", "who-is", "whois", "read file",
    "upload", "config", "auth", "login", "session", "unsolicited", "subscribe",
)


# Explicit read/monitor intent short-circuits to Normal (unless it also carries a
# write verb) so "Controller Status Read" / "Read Holding Registers" aren't CONTROL.
_OT_CMD_READ_KW = ("read", "poll", "status", "monitor", "get value", "scan value")


_OT_CMD_WRITE_VERB = ("write", "download", "program ", "operate", "force", "set ")


def _ot_command_risk(name: str) -> str:
    """Classify an OT command name as CONTROL (state-changing), REVIEW
    (recon/config/session), or Normal (read/poll/monitor)."""
    low = str(name or "").lower()
    is_read = any(k in low for k in _OT_CMD_READ_KW)
    has_write_verb = any(k in low for k in _OT_CMD_WRITE_VERB)
    if is_read and not has_write_verb:
        # A read that also names a recon target (device/identity/file) is REVIEW.
        return "REVIEW" if any(k in low for k in _OT_CMD_REVIEW_KW) else "Normal"
    if any(k in low for k in _OT_CMD_CONTROL_KW):
        return "CONTROL"
    if any(k in low for k in _OT_CMD_REVIEW_KW):
        return "REVIEW"
    return "Normal"


def _render_ot_verdict(lines: list[str], label: str, anomalies: object) -> None:
    """Prepend a triage Analyst Verdict + Focus-Here-First + ATT&CK-for-ICS
    block to a dedicated OT protocol renderer. Silent on benign captures (only
    emits when a warning+ finding exists). Reused across modbus/enip/cip/s7/
    goose/sv/profinet/iec101_103/synchrophasor so they all read like an IR tool.
    """
    anoms = list(anomalies or [])
    if not anoms:
        return
    # Normalize dicts (detections) AND dataclasses (anomalies) to (sev, title,
    # detail). Carry the original to recover src/dst/evidence where present.
    norm = [(_normalize_finding(a), a) for a in anoms]
    worst = max((_PROTO_SEV_RANK.get(n[0][0], 0) for n in norm), default=0)
    if worst < 2:
        return
    ranked = sorted(norm, key=lambda n: _PROTO_SEV_RANK.get(n[0][0], 0), reverse=True)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if worst >= 3:
        lines.append(
            danger(
                f"HIGH - {label}: high-severity OT activity (state-changing "
                "command / control-plane abuse) observed; confirm it is from an "
                "authorized source within a change window."
            )
        )
    else:
        lines.append(warn(f"REVIEW - {label}: notable OT activity observed."))
    lines.append(muted("Focus Here First:"))
    attack_ids: list[str] = []
    for (sev, title, detail), orig in ranked[: _limit_value(6)]:
        if _PROTO_SEV_RANK.get(sev, 0) < 2:
            continue
        mark = (
            danger(f"[{sev.upper()}]")
            if _PROTO_SEV_RANK.get(sev, 0) >= 3
            else warn(f"[{sev.upper()}]")
        )
        ev_raw = getattr(orig, "evidence", "")
        if isinstance(ev_raw, (list, tuple)):
            ev = "; ".join(str(x) for x in ev_raw if x).strip()
        else:
            ev = str(ev_raw or "").strip()
        if not ev:
            src = str(getattr(orig, "src", "") or "")
            dst = str(getattr(orig, "dst", "") or "")
            ev = f"{src} -> {dst}" if (src or dst) else _truncate_text(detail, 80)
        lines.append(f"  {mark} {title}" + (f" — {_truncate_text(ev, 90)}" if ev else ""))
    for (_sev, title, _detail), _orig in ranked:
        tech = getattr(_orig, "attack", "") or _ot_attack_for_title(title)
        if tech and tech not in attack_ids:
            attack_ids.append(tech)
    if attack_ids:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ATT&CK for ICS Mapping"))
        for tid in attack_ids[: _limit_value(12)]:
            lines.append(muted(f"- {tid}"))


@_ot_full_render
def _render_industrial_summary(
    title: str, summary: object, packet_label: str = "Protocol Packets"
) -> str:
    if not summary:
        return ""

    total_packets = getattr(summary, "total_packets", 0)
    protocol_packets = getattr(summary, "protocol_packets", 0)
    duration = getattr(summary, "duration", 0.0)
    src_ips = getattr(summary, "src_ips", Counter())
    dst_ips = getattr(summary, "dst_ips", Counter())
    # Direction-aware role counters (clients = requesters, servers = responders),
    # populated by the shared analyze loop. Fall back to raw src/dst when a
    # protocol analyzer ran without enrichment.
    client_ips = getattr(summary, "client_ips", Counter()) or Counter()
    server_ips = getattr(summary, "server_ips", Counter()) or Counter()
    sessions = getattr(summary, "sessions", Counter())
    commands = getattr(summary, "commands", Counter())
    artifacts = getattr(summary, "artifacts", [])
    anomalies = getattr(summary, "anomalies", [])
    errors = getattr(summary, "errors", [])

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"{title.upper()} ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    # Triage lead, consistent with the dedicated OT renderers (modbus/enip/cip/
    # s7/goose/...). Silent on benign captures; fires only on warning+ anomalies.
    _render_ot_verdict(lines, title, anomalies)

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in errors:
            lines.append(danger(f"- {err}"))

    # Prefer the direction-aware role split; fall back to raw src/dst counters.
    directional_roles = bool(client_ips or server_ips)
    top_clients = client_ips if directional_roles else src_ips
    top_servers = server_ips if directional_roles else dst_ips

    lines.append(_format_kv("Scan Duration", f"{duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv(packet_label, str(protocol_packets)))
    lines.append(_format_kv("Unique Clients", str(len(top_clients))))
    lines.append(_format_kv("Unique Servers", str(len(top_servers))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Clients / Servers"))
    if not top_clients and not top_servers:
        lines.append(muted("No endpoints detected."))
    else:
        col_width = 45
        c_hdr = "Clients (requesters)" if directional_roles else "Clients"
        s_hdr = "Servers (responders)" if directional_roles else "Servers"
        lines.append(highlight(f"{c_hdr:<{col_width}} | {s_hdr}"))
        lines.append(muted("-" * 90))
        clients = top_clients.most_common(_limit_value(10))
        servers = top_servers.most_common(_limit_value(10))
        max_rows = max(len(clients), len(servers))
        for i in range(max_rows):
            c_str = ""
            s_str = ""
            if i < len(clients):
                ip, cnt = clients[i]
                c_str = f"{ip} ({cnt})"
            if i < len(servers):
                ip, cnt = servers[i]
                s_str = f"{ip} ({cnt})"
            lines.append(f"{c_str:<{col_width}} | {s_str}")

    if commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed OT Commands"))
        rows = [["Command", "Count", "Class"]]
        n_control = 0
        for cmd, count in commands.most_common(_limit_value(16)):
            risk = _ot_command_risk(str(cmd))
            disp = (
                danger(str(cmd)) if risk == "CONTROL"
                else warn(str(cmd)) if risk == "REVIEW"
                else str(cmd)
            )
            if risk == "CONTROL":
                n_control += 1
            rows.append([disp, str(count), risk])
        lines.append(_format_table(rows))
        if n_control:
            lines.append(muted(
                f"  {n_control} distinct control/state-changing command type(s) "
                "observed — confirm authorized source + change window."
            ))

    if sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in sessions.most_common(_limit_value(10)):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for artifact in artifacts[: _limit_value(12)]:
            rows.append(
                [
                    str(getattr(artifact, "kind", "artifact")),
                    str(getattr(artifact, "detail", ""))[: _limit_value(80)],
                    str(getattr(artifact, "src", "?")),
                    str(getattr(artifact, "dst", "?")),
                ]
            )
        lines.append(_format_table(rows))

    if anomalies:
        # Sort by severity BEFORE truncating so a late HIGH "Write to PLC" /
        # "Control Command" isn't cut while early LOW Test-Frame entries show.
        _ot_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "WARNING": 1, "LOW": 0, "INFO": 0}
        ranked_anoms = sorted(
            anomalies,
            key=lambda a: _ot_rank.get(str(getattr(a, "severity", "INFO")).upper(), 0),
            reverse=True,
        )
        worst_sev = str(getattr(ranked_anoms[0], "severity", "INFO")).upper()
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if worst_sev in ("CRITICAL", "HIGH"):
            lines.append(
                danger(
                    f"{worst_sev} - {title}: high-consequence OT activity observed "
                    "(writes/control/program-transfer to industrial assets)."
                )
            )
        elif worst_sev in ("MEDIUM", "WARNING"):
            lines.append(warn(f"REVIEW - {title}: notable OT activity observed."))
        else:
            lines.append(ok(f"LOW - {title}: only low-severity/informational events."))
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Events (severity-ranked)"))
        _attack_ids: list[str] = []
        for anomaly in ranked_anoms[: _limit_value(12)]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            a_title = getattr(anomaly, "title", "Event")
            lines.append(
                sev_color(
                    f"[{sev}] {a_title}: {getattr(anomaly, 'description', '')}"
                )
            )
            lines.append(
                muted(
                    f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"
                )
            )
            for ev in getattr(anomaly, "evidence", None) or []:
                lines.append(muted(f"  Evidence: {ev}"))
            # Prefer an explicit ATT&CK id set by the analyzer; fall back to
            # title-keyword inference only when the analyzer left it blank.
            tech = getattr(anomaly, "attack", "") or _ot_attack_for_title(a_title)
            if tech:
                lines.append(muted(f"  ATT&CK ICS: {tech}"))
                if tech not in _attack_ids:
                    _attack_ids.append(tech)
        # Collect ATT&CK across ALL anomalies (not just the shown top-12).
        for anomaly in ranked_anoms:
            tech = getattr(anomaly, "attack", "") or _ot_attack_for_title(
                getattr(anomaly, "title", "")
            )
            if tech and tech not in _attack_ids:
                _attack_ids.append(tech)
        if _attack_ids:
            lines.append(SUBSECTION_BAR)
            lines.append(header("ATT&CK for ICS Mapping"))
            for tid in _attack_ids[: _limit_value(12)]:
                lines.append(muted(f"- {tid}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


@_ot_full_render
def _render_ot_protocol_summary(
    title: str,
    summary: object,
    packet_label: str,
    dangerous_tokens: set[str] | None = None,
    suspicious_tokens: set[str] | None = None,
    include_detected_devices: bool = False,
) -> str:
    if not summary:
        return ""

    total_packets = getattr(summary, "total_packets", 0)
    protocol_packets = getattr(summary, "protocol_packets", 0)
    total_bytes = getattr(summary, "total_bytes", 0)
    protocol_bytes = getattr(summary, "protocol_bytes", 0)
    duration = getattr(summary, "duration", 0.0)
    src_ips = getattr(summary, "src_ips", Counter())
    dst_ips = getattr(summary, "dst_ips", Counter())
    client_ips = getattr(summary, "client_ips", Counter())
    server_ips = getattr(summary, "server_ips", Counter())
    sessions = getattr(summary, "sessions", Counter())
    commands = getattr(summary, "commands", Counter())
    service_endpoints = getattr(summary, "service_endpoints", {})
    packet_buckets = getattr(summary, "packet_size_buckets", [])
    payload_buckets = getattr(summary, "payload_size_buckets", [])
    artifacts = getattr(summary, "artifacts", [])
    anomalies = getattr(summary, "anomalies", [])
    errors = getattr(summary, "errors", [])
    is_rollup = str(getattr(getattr(summary, "path", None), "name", "")) == "ALL_PCAPS"

    def _collapse_artifacts_for_display(
        values: list[object],
    ) -> list[tuple[object, int]]:
        if not is_rollup:
            return [(item, 1) for item in values]
        buckets: dict[tuple[str, str, str, str], tuple[object, int]] = {}
        order: list[tuple[str, str, str, str]] = []
        for item in values:
            key = (
                str(getattr(item, "kind", "") or ""),
                str(getattr(item, "detail", "") or ""),
                str(getattr(item, "src", "") or ""),
                str(getattr(item, "dst", "") or ""),
            )
            existing = buckets.get(key)
            if existing is None:
                buckets[key] = (item, 1)
                order.append(key)
            else:
                buckets[key] = (existing[0], existing[1] + 1)
        return [buckets[key] for key in order]

    def _collapse_anomalies_for_display(
        values: list[object],
    ) -> list[tuple[object, int]]:
        if not is_rollup:
            return [(item, 1) for item in values]
        buckets: dict[tuple[str, str, str, str, str], tuple[object, int]] = {}
        order: list[tuple[str, str, str, str, str]] = []
        for item in values:
            key = (
                str(getattr(item, "severity", "") or ""),
                str(getattr(item, "title", "") or ""),
                str(getattr(item, "description", "") or ""),
                str(getattr(item, "src", "") or ""),
                str(getattr(item, "dst", "") or ""),
            )
            existing = buckets.get(key)
            if existing is None:
                buckets[key] = (item, 1)
                order.append(key)
            else:
                buckets[key] = (existing[0], existing[1] + 1)
        return [buckets[key] for key in order]

    def _summarize_buckets(
        buckets: list[_SizeBucketLike],
    ) -> tuple[int, float, int, int]:
        total = sum(bucket.count for bucket in buckets)
        if not total:
            return 0, 0.0, 0, 0
        avg = sum(bucket.avg * bucket.count for bucket in buckets) / total
        min_val = min(bucket.min for bucket in buckets if bucket.count)
        max_val = max(bucket.max for bucket in buckets if bucket.count)
        return total, avg, min_val, max_val

    dangerous_tokens = dangerous_tokens or set()
    suspicious_tokens = suspicious_tokens or set()

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"{title.upper()} ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_ot_verdict(lines, title, getattr(summary, "anomalies", []))

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scan Duration", f"{duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv(packet_label, str(protocol_packets)))
    lines.append(_format_kv("Total Bytes", str(total_bytes)))
    lines.append(_format_kv(f"{title} Bytes", str(protocol_bytes)))
    if protocol_packets:
        lines.append(
            _format_kv("Avg Packet Size", f"{protocol_bytes / protocol_packets:.1f}")
        )

    if packet_buckets or payload_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet/Payload Size Analysis"))
        if packet_buckets:
            total, avg, min_val, max_val = _summarize_buckets(packet_buckets)
            counts = [bucket.count for bucket in packet_buckets]
            lines.append(label("Packet Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))
        if payload_buckets:
            total, avg, min_val, max_val = _summarize_buckets(payload_buckets)
            counts = [bucket.count for bucket in payload_buckets]
            lines.append(label("Payload Sizes"))
            lines.append(_format_kv("Count", str(total)))
            lines.append(_format_kv("Min/Avg/Max", f"{min_val}/{avg:.1f}/{max_val}"))
            lines.append(_format_kv("Distribution", sparkline(counts)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Clients / Servers"))
    _dir_roles = bool(client_ips or server_ips)
    lines.append(_format_kv("Unique Clients", str(len(client_ips) or len(src_ips))))
    lines.append(_format_kv("Unique Servers", str(len(server_ips) or len(dst_ips))))
    col_width = 45
    _c_hdr = "Clients (requesters)" if _dir_roles else "Clients"
    _s_hdr = "Servers (responders)" if _dir_roles else "Servers"
    lines.append(highlight(f"{_c_hdr:<{col_width}} | {_s_hdr}"))
    lines.append(muted("-" * 90))
    clients = (client_ips or src_ips).most_common(_limit_value(10))
    servers = (server_ips or dst_ips).most_common(_limit_value(10))
    max_rows = max(len(clients), len(servers))
    for i in range(max_rows):
        c_str = ""
        s_str = ""
        if i < len(clients):
            ip, cnt = clients[i]
            c_str = f"{ip} ({cnt})"
        if i < len(servers):
            ip, cnt = servers[i]
            s_str = f"{ip} ({cnt})"
        lines.append(f"{c_str:<{col_width}} | {s_str}")

    if sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in sessions.most_common(_limit_value(10)):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Commands/Operations"))
        rows = [["Command", "Count", "Risk"]]
        for cmd, count in commands.most_common(_limit_value(16)):
            cmd_text = str(cmd)
            lowered = cmd_text.lower()
            risk = "Normal"
            display = cmd_text
            if any(token in lowered for token in dangerous_tokens):
                risk = "Dangerous"
                display = danger(cmd_text)
            elif any(token in lowered for token in suspicious_tokens):
                risk = "Suspicious"
                display = warn(cmd_text)
            rows.append([display, str(count), risk])
        lines.append(_format_table(rows))

    if service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints (client -> server)"))
        rows = [["Service", "Top Endpoints"]]
        for service, _count in commands.most_common(_limit_value(10)):
            endpoints = service_endpoints.get(str(service), Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3))
            )
            rows.append([str(service), top_eps or "-"])
        lines.append(_format_table(rows))

    if artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        collapsed_artifacts = _collapse_artifacts_for_display(list(artifacts))
        if is_rollup and len(collapsed_artifacts) < len(list(artifacts)):
            lines.append(
                muted(
                    f"Summarized view collapsed {len(list(artifacts)) - len(collapsed_artifacts)} duplicate artifact observation(s)."
                )
            )
        for artifact, seen_count in collapsed_artifacts[: _limit_value(16)]:
            detail_text = str(getattr(artifact, "detail", ""))[: _limit_value(80)]
            if seen_count > 1:
                detail_text = f"{detail_text} [x{seen_count}]"
            rows.append(
                [
                    str(getattr(artifact, "kind", "artifact")),
                    detail_text,
                    str(getattr(artifact, "src", "?")),
                    str(getattr(artifact, "dst", "?")),
                ]
            )
        lines.append(_format_table(rows))

        equipment_hits = [
            artifact
            for artifact in artifacts
            if str(getattr(artifact, "kind", "")) == "equipment"
        ]
        if equipment_hits:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Equipment Inventory"))
            counts = Counter(
                str(getattr(artifact, "detail", "")) for artifact in equipment_hits
            )
            endpoints: dict[str, Counter[str]] = defaultdict(Counter)
            for artifact in equipment_hits:
                detail = str(getattr(artifact, "detail", ""))
                src = str(getattr(artifact, "src", "?"))
                dst = str(getattr(artifact, "dst", "?"))
                endpoints[detail][f"{src} -> {dst}"] += 1
            rows = [["Equipment", "Count", "Top Endpoints"]]
            for detail, count in counts.most_common(_limit_value(12)):
                top_eps = ", ".join(
                    f"{ep} ({cnt})"
                    for ep, cnt in endpoints[detail].most_common(_limit_value(3))
                )
                rows.append([detail, str(count), top_eps or "-"])
            lines.append(_format_table(rows))

    if include_detected_devices:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detected Devices Information"))
        device_counts: Counter[str] = Counter()
        device_endpoints: dict[str, Counter[str]] = defaultdict(Counter)

        for artifact in artifacts:
            kind = str(getattr(artifact, "kind", "")).strip().lower()
            detail = str(getattr(artifact, "detail", "")).strip()
            if not detail:
                continue
            include_artifact = kind in {
                "equipment",
                "device",
                "software",
                "firmware",
                "system",
                "identity",
            }
            if not include_artifact:
                lowered = detail.lower()
                include_artifact = any(
                    token in lowered
                    for token in (
                        "vendor=",
                        "model=",
                        "product=",
                        "software=",
                        "firmware=",
                        "simatic",
                        "siemens",
                        "plc",
                        "hmi",
                        "scada",
                        "dcs",
                        "rtu",
                    )
                )
            if not include_artifact:
                continue
            src = str(getattr(artifact, "src", "?"))
            dst = str(getattr(artifact, "dst", "?"))
            device_counts[detail] += 1
            device_endpoints[detail][f"{src} -> {dst}"] += 1

        for command, count in commands.items():
            cmd_text = str(command)
            if "SrcTSAP=" not in cmd_text or "DstTSAP=" not in cmd_text:
                continue
            profile = cmd_text.replace("COTP:CR:", "COTP CR ").replace(
                "COTP:CC:", "COTP CC "
            )
            device_counts[profile] += int(count)
            for endpoint, ep_count in service_endpoints.get(cmd_text, Counter()).items():
                device_endpoints[profile][endpoint] += int(ep_count)

        if not device_counts:
            lines.append(
                muted(
                    "No device/system/equipment/software details were discovered in S7 communications."
                )
            )
        else:
            rows = [["Detail", "Count", "Top Endpoints"]]
            for detail, count in device_counts.most_common(_limit_value(16)):
                top_eps = ", ".join(
                    f"{ep} ({cnt})"
                    for ep, cnt in device_endpoints[detail].most_common(_limit_value(3))
                )
                rows.append(
                    [
                        _truncate_text(detail, _limit_value(72)),
                        str(count),
                        _truncate_text(top_eps or "-", _limit_value(64)),
                    ]
                )
            lines.append(_format_table(rows))

    if anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        collapsed_anomalies = _collapse_anomalies_for_display(list(anomalies))
        if is_rollup and len(collapsed_anomalies) < len(list(anomalies)):
            lines.append(
                muted(
                    f"Summarized view collapsed {len(list(anomalies)) - len(collapsed_anomalies)} duplicate anomaly signal(s)."
                )
            )
        for anomaly, seen_count in collapsed_anomalies[: _limit_value(16)]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            title_text = str(getattr(anomaly, "title", "Event"))
            if seen_count > 1:
                title_text = f"{title_text} [x{seen_count}]"
            lines.append(
                sev_color(
                    f"[{sev}] {title_text}: {getattr(anomaly, 'description', '')}"
                )
            )
            lines.append(
                muted(
                    f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"
                )
            )

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
