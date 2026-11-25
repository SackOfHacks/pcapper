"""-summarize: merging per-capture summaries into one.

A rolled-up report should say what the captures say together. Dedicated
``merge_*`` functions do that for the analyses whose summaries need it
(recomputed verdicts, cross-capture correlation); every other summary goes
through :func:`merge_generic_rollup_summaries`, which combines two summaries
field by field with the rules below.

Rules, by what a field holds:

* Counter                 summed
* dict                    merged key by key (each value by these rules)
* set                     union
* list of rows/strings    merged by record (see "records" below): a row that
                          recurs in several captures is listed once, its
                          counts added; a string once
* other lists             concatenated, in capture order -- and
    - histogram buckets   (objects with ``label`` and ``count``) merged per label
    - "absence" detections ("No DNS traffic detected") kept only when every
      capture makes them: one quiet capture must not deny another's traffic
    - benign / false-positive context: explanations kept from the capture
      that gave them; claims of absence ("no SYN scan") only when every
      capture makes them
    - errors, warnings, notes, indicators: de-duplicated
* sample statistics       (``{min, max, avg, p50, p95}``) -- min/max exact;
                          averages and percentiles count-weighted and marked
                          ``approx``; a capture without samples ignored
* (first, last) times     earliest first, latest last
* numbers                 summed; first/last-seen fields min/max; fields
                          named like a ratio, rate, average, score, port ...
                          take the max; ``*_min`` the min; a duration is the
                          span of the merged first/last times when the
                          summary has them, the sum otherwise
* verdict / confidence    the most severe
* other strings, tuples   the first capture's (captures are merged in
                          chronological order, so this is the earliest)

Captures are merged in chronological order (see :func:`order_by_capture`),
so a rollup does not depend on the order its captures were named in.
"""

from __future__ import annotations

import copy
import dataclasses
import functools
import hashlib
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

ROLLUP_NAME = "ALL_PCAPS"

_ROLLUP_MIN_FIELDS = ("first_seen", "first_ts", "first_time", "start_ts", "start_time", "earliest")
_ROLLUP_MAX_FIELDS = ("last_seen", "last_ts", "last_time", "end_ts", "end_time", "latest")

# Numeric fields that are not counts: adding them across captures gives
# nonsense (two link-type-1 captures became "LINKTYPE_2", a snaplen doubled).
_ROLLUP_MAX_SEGMENTS = frozenset({
    "linktype", "snaplen", "version", "ratio", "rate", "score", "avg", "average", "mean", "median",
    "percent", "pct", "confidence", "ttl", "mtu", "unique", "max", "peak", "level", "entropy",
})

# Keys of a sample-statistics dict (see e.g. tcp._stats_from_samples).
STATS_KEYS = frozenset({"min", "max", "avg", "mean", "median", "p50", "p90", "p95", "p99", "std", "count", "approx"})
_STATS_CENTRAL = ("avg", "mean", "median", "p50", "p90", "p95", "p99", "std")

# List fields whose items are claims about the absence of something: true of
# the merged traffic only when every capture makes the claim.
_BENIGN_LIST_FIELDS = frozenset({"benign_context", "false_positive_context"})
_DEDUPED_LIST_FIELDS = frozenset({"errors", "warnings", "notes", "indicators"})

_VERDICT_RANK = (("YES", 4), ("LIKELY", 3), ("POSSIBLE", 2), ("NO", 1))
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def rollup_path(count: int) -> Path:
    """The path a merged summary carries: rendered "all captures (n)"."""
    return Path(f"{ROLLUP_NAME}_{count}")


def rollup_time_mode(field_name: str | None) -> str | None:
    """'min'/'max' for fields holding a first/last timestamp (or a map of
    them): merging rollups must keep the earliest/latest, not add times up."""
    name = str(field_name or "")
    if name in _ROLLUP_MIN_FIELDS:
        return "min"
    if name in _ROLLUP_MAX_FIELDS:
        return "max"
    return None


def rollup_numeric_kind(field_name: str | None) -> str:
    """How a rollup combines a numeric field: "sum" for counts, "max" for
    values that are not additive, "min" for minimums."""
    segments = set(str(field_name or "").lower().split("_"))
    if ("min" in segments or "minimum" in segments) and "per" not in segments:  # not "..._per_min"
        return "min"
    if segments & _ROLLUP_MAX_SEGMENTS or str(field_name or "").lower().endswith("_port"):
        return "max"
    return "sum"


def rollup_set(obj: object, name: str, value: object) -> None:
    """Set a field on a rollup's merged copy, frozen dataclasses included: the
    copy belongs to the rollup, and a silently refused setattr used to send
    every frozen summary (DNS, TLS, CTF, the OT protocols ...) to the generic
    rollup instead of its own report."""
    try:
        setattr(obj, name, value)
    except (AttributeError, TypeError):
        object.__setattr__(obj, name, value)


def tag_capture_records(summary: object) -> object:
    """Mark each per-capture record (a dict in a list field) of a summary
    copy with its capture's name, so merged rows such as CTF candidates keep
    saying where their packet numbers come from."""
    name = str(getattr(getattr(summary, "path", None), "name", "") or "")
    if not name or not hasattr(summary, "__dict__"):
        return summary
    for value in vars(summary).values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    item.setdefault("capture", name)
    return summary


def rollup_fix_duration(summary: object) -> None:
    """Duration of a merged summary from its merged first/last times: the
    span the captures cover, not the sum of their durations. Summaries pair
    their time fields with either duration name (CTF keeps first_seen /
    last_seen with duration_seconds), so the span goes to whichever exists."""
    for start_name, end_name in (
        ("start_ts", "end_ts"),
        ("first_seen", "last_seen"),
        ("start_time", "end_time"),
        ("first_ts", "last_ts"),
    ):
        start = getattr(summary, start_name, None)
        end = getattr(summary, end_name, None)
        if not (isinstance(start, (int, float)) and isinstance(end, (int, float))):
            continue
        if isinstance(start, bool) or isinstance(end, bool):
            continue
        span = max(0.0, float(end) - float(start))
        for duration_name in ("duration_seconds", "duration"):
            current = getattr(summary, duration_name, False)
            if current is None or (isinstance(current, (int, float)) and not isinstance(current, bool)):
                try:
                    rollup_set(summary, duration_name, span)
                except Exception:
                    pass
        return


_SUMMARY_WINDOWS = (("start_ts", "end_ts"), ("first_seen", "last_seen"), ("start_time", "end_time"), ("first_ts", "last_ts"))


def merge_window(merged: object, summaries: Iterable[object]) -> None:
    """Set a dedicated merge's time window from its captures' -- the earliest
    start and latest end of each first/last pair the summaries carry -- and
    its duration to the span between them (see :func:`rollup_fix_duration`).
    A merge that added durations up reported two overlapping captures of an
    hour as two hours."""
    items = list(summaries)
    for start_name, end_name in _SUMMARY_WINDOWS:
        starts = [v for v in (getattr(s, start_name, None) for s in items) if _is_number(v)]
        ends = [v for v in (getattr(s, end_name, None) for s in items) if _is_number(v)]
        if starts and hasattr(merged, start_name):
            rollup_set(merged, start_name, min(starts))
        if ends and hasattr(merged, end_name):
            rollup_set(merged, end_name, max(ends))
    rollup_fix_duration(merged)


# --- ordering -----------------------------------------------------------------


def order_by_capture(summaries: list, start_times: dict) -> list:
    """Summaries in chronological order of their captures (by name when the
    start is unknown): a rollup is the same whatever order the captures were
    named in, and lists it concatenates read in time order."""
    def key(item: object) -> tuple:
        path = getattr(item, "path", None)
        start = start_times.get(str(path)) if path is not None else None
        return (start is None, start if start is not None else 0.0, str(getattr(path, "name", path) or ""))

    return sorted(summaries, key=key)


# --- detections and claims ----------------------------------------------------


def _absence_key(item: object) -> Optional[tuple]:
    if isinstance(item, dict) and item.get("absence"):
        return (str(item.get("summary", "")), str(item.get("source", "")))
    return None


def filter_partial_absences(lists: list[list]) -> list[list]:
    """Each capture's detection list, keeping an absence detection ("No DNS
    traffic detected", flagged ``absence``) only when every list has it -- and
    then once: a quiet capture must not deny the traffic another one holds."""
    keys_per_list = [{_absence_key(i) for i in (lst or []) if _absence_key(i)} for lst in lists]
    common = set.intersection(*keys_per_list) if keys_per_list else set()
    out: list[list] = []
    kept: set = set()
    for lst in lists:
        filtered = []
        for item in lst or []:
            key = _absence_key(item)
            if key is not None:
                if key not in common or key in kept:
                    continue
                kept.add(key)
            filtered.append(item)
        out.append(filtered)
    return out


def drop_partial_absences(lists: list[list]) -> list:
    """:func:`filter_partial_absences`, concatenated."""
    return [item for lst in filter_partial_absences(lists) for item in lst]


def common_claims(lists: list[list]) -> list:
    """Items every list states (benign context: true of the merge only when
    true of each capture), in the first list's order."""
    if not lists:
        return []
    rest = [set(map(repr, lst or [])) for lst in lists[1:]]
    out = []
    for item in lists[0] or []:
        if all(repr(item) in other for other in rest) and item not in out:
            out.append(item)
    return out


_NEGATIVE_PREFIXES = ("no ", "none ", "nothing ", "not ", "zero ")
_NEGATIVE_PHRASES = (" not observed", " not detected", " not seen", "no evidence")


def is_negative_claim(item: object) -> bool:
    """A claim that something was not there ("No sustained SYN fan-out ...",
    "DNS not observed"): true of a merge only when true of every capture."""
    text = str(item or "").strip().lower()
    return text.startswith(_NEGATIVE_PREFIXES) or any(phrase in text for phrase in _NEGATIVE_PHRASES)


def merge_benign_claims(lists: list[list]) -> list:
    """Benign context of several captures: an explanation of what a capture
    holds ("answer rotation may reflect CDN behaviour") is kept from that
    capture; a claim of absence ("no SYN scan observed") only when every
    capture makes it -- a quiet capture's must not deny another's traffic."""
    negatives = [{repr(i) for i in (lst or []) if is_negative_claim(i)} for lst in lists]
    shared = set.intersection(*negatives) if negatives else set()
    out: list = []
    for lst in lists:
        for item in lst or []:
            if item in out:
                continue
            if is_negative_claim(item) and repr(item) not in shared:
                continue
            out.append(item)
    return out


def verdict_rank(text: object) -> int:
    upper = str(text or "").strip().upper()
    for prefix, rank in _VERDICT_RANK:
        if upper.startswith(prefix):
            return rank
    return 0


def confidence_rank(text: object) -> int:
    return _CONFIDENCE_RANK.get(str(text or "").strip().lower(), 0)


# --- statistics and histograms --------------------------------------------------


def is_stats_dict(value: object) -> bool:
    return (
        isinstance(value, dict)
        and bool(value)
        and set(value) <= STATS_KEYS
        and {"min", "max"} <= set(value)
        and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in value.values())
    )


def _stats_empty(stats: dict) -> bool:
    return not any(float(v or 0) for k, v in stats.items() if k != "approx")


def merge_sample_stats(stats_list: list[dict], weights: Optional[list[float]] = None) -> dict:
    """Sample statistics of several captures as one: min and max exact;
    averages and percentiles weighted by sample count (``count`` in the dict,
    else ``weights``, else equally) and marked ``approx`` -- percentiles of
    a union cannot be computed from the parts. A capture without samples
    (all zero) is ignored; a single capture's statistics are kept as they are."""
    pairs = [(s, (weights[i] if weights and i < len(weights) else None))
             for i, s in enumerate(stats_list) if is_stats_dict(s) and not _stats_empty(s)]
    if not pairs:
        return dict(stats_list[0]) if stats_list and isinstance(stats_list[0], dict) else {}
    if len(pairs) == 1:
        return dict(pairs[0][0])
    out: dict = {"min": min(float(s["min"]) for s, _ in pairs), "max": max(float(s["max"]) for s, _ in pairs)}
    wts = [float(s.get("count") or (w if w is not None else 1.0) or 1.0) for s, w in pairs]
    for key in _STATS_CENTRAL:
        present = [(float(s[key]), w) for (s, _), w in zip(pairs, wts) if key in s]
        if present:
            out[key] = sum(v * w for v, w in present) / (sum(w for _, w in present) or 1.0)
    if any("count" in s for s, _ in pairs):
        out["count"] = sum(float(s.get("count") or 0) for s, _ in pairs)
    out["approx"] = 1.0
    return out


def _is_bucket(item: object) -> bool:
    return hasattr(item, "label") and hasattr(item, "count") and dataclasses.is_dataclass(item)


def merge_bucket_lists(lists: list[list]) -> list:
    """Histograms of several captures as one, per bucket label: counts
    summed, averages count-weighted, min/max over non-empty buckets,
    percentages recomputed, rates as total count over total observed time,
    the busiest burst kept. Bucket order is the first histogram's."""
    order: list = []
    groups: dict = {}
    for lst in lists:
        for bucket in lst or []:
            label = getattr(bucket, "label", None)
            if label not in groups:
                order.append(label)
                groups[label] = []
            groups[label].append(bucket)
    total = sum(int(getattr(b, "count", 0) or 0) for g in groups.values() for b in g)
    merged = []
    for label in order:
        items = groups[label]
        live = [b for b in items if int(getattr(b, "count", 0) or 0) > 0]
        count = sum(int(getattr(b, "count", 0) or 0) for b in items)
        fields: dict = {"count": count}
        template = items[0]
        if hasattr(template, "avg"):
            fields["avg"] = (sum(float(b.avg) * int(b.count) for b in live) / count) if count else 0.0
        if hasattr(template, "min"):
            fields["min"] = min((b.min for b in live), default=getattr(template, "min", 0))
        if hasattr(template, "max"):
            fields["max"] = max((b.max for b in live), default=getattr(template, "max", 0))
        if hasattr(template, "pct"):
            fields["pct"] = (count / total * 100.0) if total else 0.0
        if hasattr(template, "rate"):
            observed = sum(int(b.count) / float(b.rate) for b in live if float(getattr(b, "rate", 0) or 0) > 0)
            fields["rate"] = (sum(int(b.count) for b in live if float(getattr(b, "rate", 0) or 0) > 0) / observed) if observed else 0.0
        if hasattr(template, "burst_rate"):
            busiest = max(items, key=lambda b: float(getattr(b, "burst_rate", 0) or 0))
            fields["burst_rate"] = getattr(busiest, "burst_rate", 0.0)
            if hasattr(template, "burst_start"):
                fields["burst_start"] = getattr(busiest, "burst_start", None)
        try:
            merged.append(dataclasses.replace(template, **fields))
        except Exception:  # noqa: BLE001 - an unexpected bucket shape keeps its first form
            merged.append(template)
    return merged


def earliest_per_key(maps: Iterable[dict]) -> dict:
    """First-seen maps (key -> timestamp) of several captures: each key's
    earliest time. ``dict.update`` kept whichever capture came last."""
    out: dict = {}
    for mapping in maps:
        for key, value in (mapping or {}).items():
            if value is None:
                continue
            out[key] = value if key not in out or out[key] is None else min(out[key], value)
    return out


def sum_per_key(maps: Iterable[dict]) -> dict:
    """Count maps (key -> number) of several captures, summed per key."""
    out: dict = {}
    for mapping in maps:
        for key, value in (mapping or {}).items():
            out[key] = out.get(key, 0) + value
    return out


def merge_stats_by_key(maps: Iterable[dict]) -> dict:
    """Per-key sample statistics (server -> {min, p50, p95, max}) of several
    captures: a key seen in one capture keeps its statistics exactly; one
    seen in several gets :func:`merge_sample_stats`."""
    grouped: dict = {}
    for mapping in maps:
        for key, stats in (mapping or {}).items():
            grouped.setdefault(key, []).append(stats)
    return {key: (dict(items[0]) if len(items) == 1 else merge_sample_stats(items)) for key, items in grouped.items()}


# --- records: the rows of a list field ----------------------------------------------
#
# Several captures of one network share most of what they list: the same
# conversations, hosts, services and ARP pairs recur in every file. A rollup
# lists each once -- packets added, first/last widened -- instead of once per
# capture with no way to tell the copies apart. A row's fields play roles:
#
#   key       says which row it is: addresses, names, ports, opcodes, a VLAN
#             id, an event's timestamp or packet number -- any string, and any
#             number not named below (so an unfamiliar row is never merged
#             with a different one; at worst it stays listed per capture)
#   sum       counts: packets, bytes, requests ... and most ``*_count``
#   distinct  counts of distinct things (``client_count``, ``hosts``):
#             recounted from the row's own list of them, else the largest
#   min/max   first/last times, ``max_*``, scores, confidence, entropy
#   mean      averages and shares, weighted by the row's packets (or count)
#   duration  the span of the merged first/last times, else the sum
#   rate      ``*_per_second`` and the like, recomputed from the merged totals
#   merge     collections: sets and lists unioned, counters added
#
# Rows merge only across captures, one to one: a capture's own rows are never
# collapsed (identity), and a capture merged with a copy of itself lists each
# row once with its counts doubled -- what the traffic twice over would show.
# Rows located by a packet number keep their capture: that number means
# nothing in another file.

_ROW_SUM_NAMES = frozenset({
    "packets", "bytes", "count", "requests", "replies", "responses", "offers", "acks", "naks",
    "syn", "syn_ack", "rst", "fin", "ack", "hits", "frames", "attempts", "failures", "successes",
    "reads", "writes", "exceptions", "retransmissions", "events", "messages", "queries", "answers",
    "duplicates", "out_of_order", "drops", "dropped", "lost", "retries",
})
_ROW_SUM_SUFFIXES = ("_packets", "_bytes", "_hits", "_frames", "_requests", "_responses")
# Stems of ``<stem>_count`` fields that count distinct things.
_DISTINCT_STEMS = frozenset({
    "host", "client", "server", "peer", "public_peer", "internal_peer", "asset", "service",
    "used_service", "target", "source", "destination", "src", "dst", "user", "device", "endpoint",
    "ip", "mac", "domain", "name", "hostname", "protocol", "family", "ot_family", "iot_family",
    "module", "resolver", "client_id", "vendor_class", "xid", "requested_ip", "ua", "cert",
    "bssid", "admin_port", "port", "conversation", "flow", "ioc", "candidate", "evidence", "unique",
})
# Numbers named as a plural of those: per-row counts of distinct things.
_DISTINCT_NAMES = frozenset({
    "hosts", "clients", "servers", "peers", "assets", "services", "targets", "sources",
    "destinations", "users", "devices", "endpoints", "ips", "macs", "domains", "names",
    "hostnames", "protocols", "families", "modules", "resolvers", "flows", "conversations",
})
_ROW_LOCATORS = frozenset({"packet", "frame", "packet_number", "frame_number", "packet_index", "pkt"})
_MEAN_SEGMENTS = frozenset({"avg", "mean", "average", "pct", "percent", "share", "ratio", "fraction", "jitter"})
_MAX_SEGMENTS = frozenset({"max", "maximum", "peak", "highest", "score", "confidence", "level", "entropy", "risk"})
_MIN_SEGMENTS = frozenset({"min", "minimum", "lowest"})
_RATE_METRICS = (
    # (rate field names, numerator field, factor)
    (("bytes_per_second", "bytes_per_sec", "byte_rate"), "bytes", 1.0),
    (("bits_per_second", "bits_per_sec", "bps"), "bytes", 8.0),
    (("packets_per_second", "packets_per_sec", "pps", "packet_rate"), "packets", 1.0),
)
_WINDOWS = (("first_seen", "last_seen"), ("start_ts", "end_ts"), ("first_ts", "last_ts"),
            ("start_time", "end_time"), ("first", "last"), ("start", "end"))


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@functools.lru_cache(maxsize=4096)
def _numeric_role(name: str) -> str:
    """The role a numeric row field named ``name`` plays (see above)."""
    lowered = name.lower()
    if lowered in _ROLLUP_MIN_FIELDS or lowered in ("first", "start"):
        return "min"
    if lowered in _ROLLUP_MAX_FIELDS or lowered in ("last", "end"):
        return "max"
    if lowered.endswith("_count"):
        return "distinct" if lowered[: -len("_count")] in _DISTINCT_STEMS else "sum"
    if lowered in _DISTINCT_NAMES:
        return "distinct"
    if lowered in _ROW_SUM_NAMES:
        return "sum"
    if lowered in ("duration", "duration_seconds"):
        return "duration"
    if any(lowered in names for names, _metric, _factor in _RATE_METRICS) or lowered.endswith(
        ("_per_second", "_per_sec")
    ):
        return "rate"
    # Before the count suffixes: avg_packet_bytes is an average, max_payload_bytes a maximum.
    segments = set(lowered.split("_"))
    if segments & _MEAN_SEGMENTS:
        return "mean"
    if segments & _MAX_SEGMENTS:
        return "max"
    if segments & _MIN_SEGMENTS:
        return "min"
    if lowered.endswith(_ROW_SUM_SUFFIXES):
        return "sum"
    return "key"


@functools.lru_cache(maxsize=1024)
def _dataclass_names(cls: type) -> tuple[str, ...]:
    return tuple(f.name for f in dataclasses.fields(cls))


def _row_fields(row: object) -> Optional[dict]:
    if isinstance(row, dict):
        return row
    if dataclasses.is_dataclass(row) and not isinstance(row, type):
        return {name: getattr(row, name) for name in _dataclass_names(type(row))}
    return None


def _kind(value: object) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "none"
    if isinstance(value, str):
        return "str"
    if isinstance(value, (set, frozenset, list, dict)) or _time_pair(value):
        return "collection"
    return "other"


@functools.lru_cache(maxsize=4096)
def _roles_for(shape: tuple[tuple[str, str], ...]) -> dict[str, str]:
    """Roles of a row's fields from its shape -- (name, kind of value) pairs.
    A string field that previews a distinct count of the same row (``clients``
    = "10.0.0.5, 10.0.0.9" beside ``client_count``) merges as a union of its
    parts instead of telling rows apart."""
    kinds = dict(shape)
    roles: dict[str, str] = {}
    for name, kind in shape:
        if name == "capture":
            roles[name] = "capture"
        elif kind == "str" and name.endswith("s") and kinds.get(f"{name[:-1]}_count") == "number":
            roles[name] = "preview"
        elif kind == "bool":
            roles[name] = "any"
        elif kind in ("number", "none"):
            # An unset value of an identifying field still identifies the row.
            roles[name] = _numeric_role(name)
        elif kind == "collection":
            roles[name] = "merge"
        else:
            roles[name] = "key"
    return roles


def _row_roles(fields: dict) -> dict[str, str]:
    return _roles_for(tuple((name, _kind(value)) for name, value in fields.items()))


def _freeze(value: object) -> object:
    try:
        hash(value)
        return value
    except TypeError:
        return repr(value)


def _record_key(row: object) -> object:
    """What identifies ``row`` among the rows of a list field."""
    if isinstance(row, str):
        return ("str", row)
    fields = _row_fields(row)
    if fields is None:
        return None
    roles = _row_roles(fields)
    key = tuple(sorted((name, _freeze(value)) for name, value in fields.items() if roles.get(name) == "key"))
    located = any(fields.get(name) is not None for name in _ROW_LOCATORS if roles.get(name) == "key")
    capture = fields.get("capture") if located else None
    return (type(row).__name__, key, capture)


def _parts(text: object) -> list[str]:
    return [p.strip() for p in str(text or "").split(",") if p.strip() and p.strip() != "-"]


def _union_list(left: list, right: list) -> list:
    """Two capture's lists of a row's attribute as one, each item once; sorted
    when both were (a port list stays a sorted port list)."""
    out = list(left)
    seen = {repr(v) for v in out}
    for value in right:
        if repr(value) not in seen:
            seen.add(repr(value))
            out.append(value)
    try:
        if left == sorted(left) and right == sorted(right):
            return sorted(out)
    except TypeError:
        pass
    return out


def _companion(fields: dict, name: str) -> Optional[str]:
    """The field listing what a distinct count counts (``client_count`` ->
    ``client_list``, else the ``clients`` preview), if the row has one: a
    full collection before a preview string, which may be cut short."""
    lowered = name.lower()
    stem = lowered[: -len("_count")] if lowered.endswith("_count") else lowered.rstrip("s")
    candidates = [c for c in (f"{stem}_list", f"{stem}s", f"{stem}es", f"{stem}_ips", stem)
                  if c != name and c in fields]
    for candidate in candidates:
        if isinstance(fields[candidate], (set, frozenset, list, dict)):
            return candidate
    for candidate in candidates:
        if isinstance(fields[candidate], str):
            return candidate
    return None


def _merge_rows(left: object, right: object) -> object:
    """Two captures' rows of one record as one row (see the roles above)."""
    lf, rf = _row_fields(left), _row_fields(right)
    assert lf is not None and rf is not None
    roles = {**_row_roles(rf), **_row_roles(lf)}
    weight_l = next((float(lf[w]) for w in ("packets", "count") if _is_number(lf.get(w))), 1.0)
    weight_r = next((float(rf[w]) for w in ("packets", "count") if _is_number(rf.get(w))), 1.0)
    out = dict(lf)
    truncated: dict[str, int] = {}
    for name in list(lf) + [n for n in rf if n not in lf]:
        a, b = lf.get(name), rf.get(name)
        role = roles.get(name, "key")
        if role == "key":
            out[name] = a if a is not None else b
        elif role == "capture":
            names = _parts(a) + [p for p in _parts(b) if p not in _parts(a)]
            out[name] = ", ".join(names) if names else a
        elif role == "preview":
            pa, pb = _parts(a), _parts(b)
            count_name = f"{name[:-1]}_count"
            cut = [len(p) for p, n in ((pa, lf.get(count_name)), (pb, rf.get(count_name))) if _is_number(n) and n > len(p)]
            merged = _union_list(pa, pb)
            if cut:
                truncated[count_name] = len(merged)
                merged = merged[: max(cut)]
            out[name] = ", ".join(merged) if merged else (a or b)
        elif b is None:
            out[name] = a
        elif a is None:
            out[name] = b
        elif role == "sum" and _is_number(a) and _is_number(b):
            out[name] = a + b
        elif role in ("min", "max") and _is_number(a) and _is_number(b):
            out[name] = min(a, b) if role == "min" else max(a, b)
        elif role == "any":
            out[name] = bool(a) or bool(b)
        elif role == "mean" and _is_number(a) and _is_number(b):
            value = (a * weight_l + b * weight_r) / ((weight_l + weight_r) or 1.0)
            out[name] = round(value) if isinstance(a, int) and isinstance(b, int) else value
        elif role in ("duration", "rate", "distinct") and _is_number(a) and _is_number(b):
            out[name] = (a, b)  # settled below, once the totals are known
        elif role == "merge":
            if isinstance(a, list) and isinstance(b, list):
                out[name] = _union_list(a, b)
            else:
                out[name] = merge_generic_rollup_value(a, b, name)
        else:
            out[name] = a
    # Derived numbers, from the merged totals.
    window = next(((f, l) for f, l in _WINDOWS if _is_number(out.get(f)) and _is_number(out.get(l))), None)
    for name, role in roles.items():
        pair = out.get(name)
        if not (isinstance(pair, tuple) and len(pair) == 2 and role in ("duration", "rate", "distinct")):
            continue
        a, b = pair
        as_int = isinstance(a, int) and isinstance(b, int)
        if role == "duration":
            value = (out[window[1]] - out[window[0]]) if window else a + b
            out[name] = max(0.0, float(value)) if not as_int else max(0, int(value))
        elif role == "distinct":
            companion = _companion(out, name)
            listed = out.get(companion) if companion else None
            if isinstance(listed, str):
                counted = len(_parts(listed)) if name not in truncated else truncated[name]
            elif isinstance(listed, (set, frozenset, list, dict)):
                counted = len(listed)
            else:
                counted = 0
            out[name] = max(a, b, counted)
        else:  # rate
            out[name] = max(a, b)
    duration_name = next((n for n, r in roles.items() if r == "duration" and _is_number(out.get(n))), None)
    seconds = float(out[duration_name]) if duration_name else (
        float(out[window[1]] - out[window[0]]) if window else 0.0
    )
    for name, role in roles.items():
        if role != "rate" or not _is_number(out.get(name)):
            continue
        lowered = name.lower()
        metric, factor = next(((m, f) for names, m, f in _RATE_METRICS if lowered in names), (None, 1.0))
        if metric is None and lowered.endswith(("_per_second", "_per_sec")):
            metric = lowered.rsplit("_per_", 1)[0]
        if metric and _is_number(out.get(metric)) and seconds > 0:
            value = float(out[metric]) * factor / seconds
            out[name] = int(value) if isinstance(lf.get(name), int) else round(value, 3)
    if isinstance(left, dict):
        return out
    return _rebuild_row(left, out)


def _rebuild_row(template: object, values: dict) -> object:
    init = {f.name: values[f.name] for f in dataclasses.fields(template) if f.init and f.name in values}
    try:
        row = dataclasses.replace(template, **init)
    except Exception:  # noqa: BLE001 - an unusual row keeps its first form
        return template
    for f in dataclasses.fields(template):
        if not f.init and f.name in values:
            try:
                object.__setattr__(row, f.name, values[f.name])
            except Exception:  # noqa: BLE001
                pass
    return row


def is_record_list(values: list) -> bool:
    """A list of rows or of strings: what :func:`merge_records` merges. Lists
    of numbers (a time series) and of tuples are left as they are."""
    return bool(values) and all(isinstance(v, str) or _row_fields(v) is not None for v in values)


def _reverse_pair(text: object) -> object:
    """"internal->public" read the other way round."""
    if isinstance(text, str) and "->" in text:
        left, _, right = text.partition("->")
        return f"{right}->{left}"
    return text


def _swapped(row: object, ends: tuple[str, str], mirrored: tuple[str, ...]) -> object:
    fields = dict(_row_fields(row) or {})
    a, b = ends
    fields[a], fields[b] = fields.get(b), fields.get(a)
    for name in mirrored:
        if name in fields:
            fields[name] = _reverse_pair(fields[name])
    return fields if isinstance(row, dict) else _rebuild_row(row, fields)


def merge_undirected(lists: list[list], *, ends: tuple[str, str] = ("src", "dst"),
                     mirrored: tuple[str, ...] = ("scope_pair",)) -> list:
    """:func:`merge_records` for rows that are one record whichever way round
    their endpoints are (a conversation A<->B keeps the direction its first
    packet had, so another capture can hold it as B->A): a later capture's row
    is turned to the earlier capture's orientation before it merges."""
    first: dict = {}
    oriented: list[list] = []
    for lst in lists:
        out = []
        for row in lst or []:
            fields = _row_fields(row)
            if fields is None or ends[0] not in fields or ends[1] not in fields:
                out.append(row)
                continue
            forward = str(fields.get(ends[0])) <= str(fields.get(ends[1]))
            canonical = row if forward else _swapped(row, ends, mirrored)
            key = _record_key(canonical)
            seen_forward = first.setdefault(key, forward)
            out.append(row if seen_forward == forward else _swapped(row, ends, mirrored))
        oriented.append(out)
    return merge_records(oriented)


def record_digest(row: object) -> int:
    """What identifies ``row`` among its list's rows (as :func:`merge_records`
    matches them), in 8 stable bytes: a summary can keep the digests of the
    records it counted, so a rollup counts them once across captures."""
    text = repr(_record_key(row)).encode("utf-8", "surrogatepass")
    return int.from_bytes(hashlib.blake2b(text, digest_size=8).digest(), "big")


def record_digests(rows: Iterable[object]) -> Counter:
    """Digests of ``rows``, with how often each occurs."""
    return Counter(record_digest(row) for row in rows)


def union_count(digest_counts: Iterable[Counter]) -> tuple[int, Counter]:
    """How many records several captures hold between them, counting a record
    in several captures once (and as often as the capture holding it most
    often): the size of what :func:`merge_records` would list."""
    merged: Counter = Counter()
    for counts in digest_counts:
        for digest, count in (counts or {}).items():
            if count > merged[digest]:
                merged[digest] = count
    return sum(merged.values()), merged


def merge_records(lists: list[list]) -> list:
    """The rows of one list field of several captures (in capture order) as
    one list: a row whose key equals a row of an earlier capture merges into
    it, one to one; others are appended. See the roles above."""
    out: list = []
    slots: dict = {}
    for lst in lists:
        taken: set[int] = set()
        for row in lst or []:
            key = _record_key(row)
            slot = None
            if key is not None:
                slot = next((i for i in slots.get(key, ()) if i not in taken), None)
            if slot is None:
                out.append(row)
                slot = len(out) - 1
                if key is not None:
                    slots.setdefault(key, []).append(slot)
            elif not isinstance(row, str):
                out[slot] = _merge_rows(out[slot], row)
            taken.add(slot)
    return out


# --- the generic merge ------------------------------------------------------------


def _dedupe_sequence(values: list) -> list:
    deduped: list = []
    seen: set = set()
    for value in values:
        try:
            key = ("hash", hash(value))
        except Exception:
            key = ("repr", repr(value))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped


def _time_pair(value: object) -> bool:
    return (
        isinstance(value, tuple) and len(value) == 2
        and all(v is None or (isinstance(v, (int, float)) and not isinstance(v, bool)) for v in value)
    )


def merge_generic_rollup_value(left: object, right: object, field_name: str | None = None) -> object:
    """``left`` and ``right`` (the same field of two summaries) as one value."""
    if right is None:
        return left
    if left is None:
        return copy.deepcopy(right)

    if isinstance(left, Counter) and isinstance(right, Counter):
        merged_counter = Counter(left)
        merged_counter.update(right)
        return merged_counter

    if is_stats_dict(left) and is_stats_dict(right):
        return merge_sample_stats([left, right])

    time_mode = rollup_time_mode(field_name)
    if isinstance(left, dict) and isinstance(right, dict):
        merged_dict = copy.deepcopy(left)
        for key, value in right.items():
            # Values under a first_seen/last_seen map keep its min/max rule;
            # anything else merges by its own key.
            nested = field_name if time_mode else str(key)
            if key in merged_dict:
                merged_dict[key] = merge_generic_rollup_value(merged_dict[key], value, nested)
            else:
                merged_dict[key] = copy.deepcopy(value)
        return merged_dict

    if isinstance(left, list) and isinstance(right, list):
        if (left or right) and all(_is_bucket(b) for b in (left + right)):
            return merge_bucket_lists([left, right])
        if field_name in _BENIGN_LIST_FIELDS:
            return merge_benign_claims([left, right])
        lists = filter_partial_absences([list(left), list(right)])
        if field_name in _DEDUPED_LIST_FIELDS:
            return _dedupe_sequence(lists[0] + lists[1])
        if is_record_list(lists[0] + lists[1]):
            return merge_records(lists)
        return lists[0] + lists[1]

    if _time_pair(left) and _time_pair(right):
        firsts = [v for v in (left[0], right[0]) if v is not None]
        lasts = [v for v in (left[1], right[1]) if v is not None]
        return (min(firsts) if firsts else None, max(lasts) if lasts else None)

    if (
        time_mode
        and isinstance(left, (int, float))
        and isinstance(right, (int, float))
        and not isinstance(left, bool)
        and not isinstance(right, bool)
    ):
        return min(left, right) if time_mode == "min" else max(left, right)

    if isinstance(left, set) and isinstance(right, set):
        return set(left) | set(right)

    if isinstance(left, bool) and isinstance(right, bool):
        return bool(left) or bool(right)

    if (
        isinstance(left, (int, float))
        and isinstance(right, (int, float))
        and not isinstance(left, bool)
        and not isinstance(right, bool)
    ):
        kind = rollup_numeric_kind(field_name)
        if kind == "min":
            return min(left, right)
        if kind == "max":
            return max(left, right)
        return left + right

    if isinstance(left, str) and isinstance(right, str):
        name = str(field_name or "")
        if name.endswith("verdict") and verdict_rank(right) > verdict_rank(left):
            return right
        if name.endswith("confidence") and confidence_rank(right) > confidence_rank(left):
            return right
        return left if left else right

    if hasattr(left, "__dict__") and hasattr(right, "__dict__"):
        merged_object = copy.deepcopy(left)
        if merge_generic_rollup_object(merged_object, right):
            return merged_object
        return left

    return left


def merge_generic_rollup_object(left_obj: object, right_obj: object) -> bool:
    if not hasattr(left_obj, "__dict__") or not hasattr(right_obj, "__dict__"):
        return False
    try:
        right_fields = vars(right_obj)
    except Exception:
        return False
    for field_name, right_value in right_fields.items():
        if field_name == "path":
            continue
        try:
            left_value = getattr(left_obj, field_name, None)
            merged_value = merge_generic_rollup_value(left_value, right_value, field_name)
            rollup_set(left_obj, field_name, merged_value)
        except Exception:
            continue
    return True


def recount_uniques(merged: object) -> None:
    """``unique_<x>`` counts of a merged summary from its merged counters
    (``unique_clients`` = ``len(client_counts)``, as the analyzers compute it):
    the max of the captures' counts undercounts hosts seen in different
    captures. A count with no matching counter keeps the max."""
    if not hasattr(merged, "__dict__"):
        return
    fields = vars(merged)
    for name, value in list(fields.items()):
        if not name.startswith("unique_") or not isinstance(value, int) or isinstance(value, bool):
            continue
        stem = name[len("unique_"):]
        for source in (f"{stem}_counts", f"{stem[:-1]}_counts" if stem.endswith("s") else None, stem):
            container = fields.get(source) if source else None
            if isinstance(container, (dict, set, frozenset)) and source != name:
                rollup_set(merged, name, len(container))
                break


def merge_generic_rollup_summaries(values: Iterable[object]) -> object | None:
    """Several captures' summaries of one analysis as one summary, field by
    field (see the module docstring), or None when they cannot be merged."""
    values = [v for v in values if v is not None]
    if not values:
        return None
    if len(values) == 1:
        merged_single = copy.deepcopy(values[0])
        if hasattr(merged_single, "path"):
            try:
                rollup_set(merged_single, "path", rollup_path(1))
            except Exception:
                pass
        return merged_single
    merged = tag_capture_records(copy.deepcopy(values[0]))
    for item in values[1:]:
        if not merge_generic_rollup_object(merged, tag_capture_records(copy.deepcopy(item))):
            return None
    if hasattr(merged, "path"):
        try:
            rollup_set(merged, "path", rollup_path(len(values)))
        except Exception:
            pass
    if hasattr(merged, "errors"):
        try:
            rollup_set(merged, "errors", _dedupe_sequence(list(getattr(merged, "errors", []) or [])))
        except Exception:
            pass
    # Absence detections and benign claims merge pairwise above; a claim the
    # first pair shared can still be denied by a later capture, so the
    # all-captures rule is applied once more over every input.
    for name in ("detections",):
        lists = [list(getattr(v, name, None) or []) for v in values]
        if any(lists) and isinstance(getattr(merged, name, None), list):
            keys = [{_absence_key(i) for i in lst if _absence_key(i)} for lst in lists]
            common = set.intersection(*keys) if keys else set()
            rollup_set(merged, name, [i for i in getattr(merged, name) if _absence_key(i) is None or _absence_key(i) in common])
    for name in _BENIGN_LIST_FIELDS:
        if isinstance(getattr(merged, name, None), list):
            rollup_set(merged, name, merge_benign_claims([list(getattr(v, name, None) or []) for v in values]))
    recount_uniques(merged)
    rollup_fix_duration(merged)
    merged_path_name = str(getattr(getattr(merged, "path", None), "name", ""))
    if not merged_path_name.startswith(ROLLUP_NAME):
        return None
    return merged
