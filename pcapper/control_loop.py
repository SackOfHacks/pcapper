from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from collections import Counter, defaultdict
from typing import Optional
import statistics

from .utils import safe_float
from .modbus import analyze_modbus
from .dnp3 import analyze_dnp3


@dataclass(frozen=True)
class ControlLoopFinding:
    protocol: str
    target: str
    kind: str
    old: Optional[float]
    new: Optional[float]
    delta: Optional[float]
    ts: Optional[float]
    src: str
    dst: str
    note: str


@dataclass(frozen=True)
class ControlLoopSummary:
    path: Path
    total_changes: int
    total_targets: int
    findings: list[ControlLoopFinding]
    kind_counts: Counter[str]
    target_counts: Counter[str]
    source_counts: Counter[str]
    destination_counts: Counter[str]
    detections: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _to_number(value: object) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.replace(".", "", 1).isdigit():
            try:
                return float(stripped)
            except Exception:
                return None
    return None


def _median(values: list[float]) -> Optional[float]:
    if not values:
        return None
    try:
        return float(statistics.median(values))
    except Exception:
        return None


def _iqr(values: list[float]) -> Optional[float]:
    if len(values) < 4:
        return None
    try:
        sorted_vals = sorted(values)
        mid = len(sorted_vals) // 2
        lower = sorted_vals[:mid]
        upper = sorted_vals[mid + (len(sorted_vals) % 2):]
        q1 = statistics.median(lower) if lower else sorted_vals[0]
        q3 = statistics.median(upper) if upper else sorted_vals[-1]
        return float(q3 - q1)
    except Exception:
        return None


def _normalize_change(protocol: str, item: dict[str, object]) -> dict[str, object] | None:
    target = str(item.get("target") or "").strip()
    if not target:
        group = item.get("group")
        variation = item.get("variation")
        index = item.get("index")
        if group is not None and variation is not None and index is not None:
            target = f"{protocol} G{group}.V{variation}[{index}]"
    if not target:
        return None
    old = _to_number(item.get("old"))
    new = _to_number(item.get("new"))
    if old is None and new is None:
        return None
    return {
        "protocol": protocol,
        "target": target,
        "old": old,
        "new": new,
        "delta": (new - old) if old is not None and new is not None else None,
        "ts": safe_float(item.get("ts")),
        "src": str(item.get("src") or ""),
        "dst": str(item.get("dst") or ""),
        "raw": item,
    }


def build_control_loop_summary(
    path: Path,
    changes_by_proto: dict[str, list[dict[str, object]]],
    *,
    errors: list[str] | None = None,
) -> ControlLoopSummary:
    records_by_target: dict[str, list[dict[str, object]]] = defaultdict(list)
    total_changes = 0
    target_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()

    for proto, changes in changes_by_proto.items():
        for item in changes:
            normalized = _normalize_change(proto, item)
            if not normalized:
                continue
            total_changes += 1
            target = normalized["target"]
            records_by_target[target].append(normalized)
            target_counts[target] += 1
            src = normalized.get("src") or ""
            dst = normalized.get("dst") or ""
            if src:
                source_counts[str(src)] += 1
            if dst:
                destination_counts[str(dst)] += 1

    findings: list[ControlLoopFinding] = []
    kind_counts: Counter[str] = Counter()
    max_findings = 200

    for target, records in records_by_target.items():
        records.sort(key=lambda rec: (rec.get("ts") is None, rec.get("ts")))
        values: list[float] = []
        deltas: list[float] = []
        timestamps: list[float] = []
        for rec in records:
            if rec.get("old") is not None:
                values.append(float(rec["old"]))
            if rec.get("new") is not None:
                values.append(float(rec["new"]))
            if rec.get("delta") is not None:
                deltas.append(abs(float(rec["delta"])))
            if rec.get("ts") is not None:
                timestamps.append(float(rec["ts"]))

        median_delta = _median(deltas) or 0.0
        median_value = _median(values)
        iqr_value = _iqr(values)

        last_vals: list[tuple[Optional[float], Optional[float]]] = []
        for idx, rec in enumerate(records):
            if len(findings) >= max_findings:
                break
            old_val = rec.get("old")
            new_val = rec.get("new")
            delta = rec.get("delta")
            ts = rec.get("ts")
            src = rec.get("src") or ""
            dst = rec.get("dst") or ""
            proto = rec.get("protocol") or "OT"

            prev_ts = records[idx - 1].get("ts") if idx > 0 else None
            dt = None
            if prev_ts is not None and ts is not None:
                dt = max(0.0, float(ts) - float(prev_ts))

            if delta is not None:
                abs_delta = abs(float(delta))
                large_threshold = max(1000.0, median_delta * 10.0) if median_delta else 1000.0
                if abs_delta >= large_threshold:
                    findings.append(
                        ControlLoopFinding(
                            protocol=str(proto),
                            target=target,
                            kind="large_jump",
                            old=old_val,
                            new=new_val,
                            delta=delta,
                            ts=ts,
                            src=str(src),
                            dst=str(dst),
                            note="Large step change",
                        )
                    )
                    kind_counts["large_jump"] += 1

                rapid_threshold = max(5.0, median_delta * 5.0) if median_delta else 25.0
                if dt is not None and dt <= 2.0 and abs_delta >= rapid_threshold:
                    findings.append(
                        ControlLoopFinding(
                            protocol=str(proto),
                            target=target,
                            kind="rapid_change",
                            old=old_val,
                            new=new_val,
                            delta=delta,
                            ts=ts,
                            src=str(src),
                            dst=str(dst),
                            note="Rapid change",
                        )
                    )
                    kind_counts["rapid_change"] += 1

            if iqr_value and median_value is not None and new_val is not None:
                lower = median_value - (iqr_value * 6.0)
                upper = median_value + (iqr_value * 6.0)
                if float(new_val) < lower or float(new_val) > upper:
                    findings.append(
                        ControlLoopFinding(
                            protocol=str(proto),
                            target=target,
                            kind="outlier_range",
                            old=old_val,
                            new=new_val,
                            delta=delta,
                            ts=ts,
                            src=str(src),
                            dst=str(dst),
                            note="Out-of-range vs observed baseline",
                        )
                    )
                    kind_counts["outlier_range"] += 1

            last_vals.append((new_val, ts))
            if len(last_vals) >= 3:
                prev_prev_val, prev_prev_ts = last_vals[-3]
                if prev_prev_val is not None and new_val is not None and prev_prev_val == new_val:
                    if prev_prev_ts is not None and ts is not None:
                        delta_ts = float(ts) - float(prev_prev_ts)
                        if 0.0 <= delta_ts <= 60.0:
                            findings.append(
                                ControlLoopFinding(
                                    protocol=str(proto),
                                    target=target,
                                    kind="oscillation",
                                    old=old_val,
                                    new=new_val,
                                    delta=delta,
                                    ts=ts,
                                    src=str(src),
                                    dst=str(dst),
                                    note="Value oscillation (A->B->A)",
                                )
                            )
                            kind_counts["oscillation"] += 1

        if len(timestamps) >= 6:
            timestamps_sorted = sorted(timestamps)
            for idx in range(len(timestamps_sorted)):
                start_ts = timestamps_sorted[idx]
                count = 1
                for j in range(idx + 1, len(timestamps_sorted)):
                    if timestamps_sorted[j] - start_ts <= 60.0:
                        count += 1
                    else:
                        break
                if count >= 6:
                    findings.append(
                        ControlLoopFinding(
                            protocol=str(records[0].get("protocol") or "OT"),
                            target=target,
                            kind="burst",
                            old=None,
                            new=None,
                            delta=None,
                            ts=start_ts,
                            src=str(records[0].get("src") or ""),
                            dst=str(records[0].get("dst") or ""),
                            note=f"{count} changes within 60s",
                        )
                    )
                    kind_counts["burst"] += 1
                    break

        if len(findings) >= max_findings:
            break

    detections: list[dict[str, object]] = []
    if findings:
        kind_counts_sorted = kind_counts.most_common()
        for kind, count in kind_counts_sorted:
            severity = "warning"
            if kind in {"large_jump"}:
                severity = "high"
            details = f"{count} {kind.replace('_', ' ')} finding(s)."
            evidence = [
                f"{f.target} {f.protocol} {f.note} src={f.src} dst={f.dst}"
                for f in findings
                if f.kind == kind
            ][:6]
            detections.append(
                {
                    "severity": severity,
                    "summary": f"Control-loop {kind.replace('_', ' ')} detected",
                    "details": details,
                    "source": "ControlLoop",
                    "top_sources": source_counts.most_common(5),
                    "top_destinations": destination_counts.most_common(5),
                    "evidence": evidence,
                }
            )

    return ControlLoopSummary(
        path=path,
        total_changes=total_changes,
        total_targets=len(records_by_target),
        findings=findings,
        kind_counts=kind_counts,
        target_counts=target_counts,
        source_counts=source_counts,
        destination_counts=destination_counts,
        detections=detections,
        errors=sorted({err for err in (errors or []) if err}),
    )


def analyze_control_loop(path: Path, show_status: bool = True) -> ControlLoopSummary:
    errors: list[str] = []
    modbus_summary = analyze_modbus(path, show_status=show_status)
    dnp3_summary = analyze_dnp3(path, show_status=show_status)
    errors.extend(getattr(modbus_summary, "errors", []) or [])
    errors.extend(getattr(dnp3_summary, "errors", []) or [])
    return build_control_loop_summary(
        path,
        {
            "Modbus": getattr(modbus_summary, "value_changes", []) or [],
            "DNP3": getattr(dnp3_summary, "value_changes", []) or [],
        },
        errors=errors,
    )


def merge_control_loop_summaries(summaries: list[ControlLoopSummary]) -> ControlLoopSummary:
    if not summaries:
        return ControlLoopSummary(
            path=Path("ALL_PCAPS"),
            total_changes=0,
            total_targets=0,
            findings=[],
            kind_counts=Counter(),
            target_counts=Counter(),
            source_counts=Counter(),
            destination_counts=Counter(),
            detections=[],
            errors=[],
        )
    total_changes = sum(item.total_changes for item in summaries)
    total_targets = sum(item.total_targets for item in summaries)
    findings: list[ControlLoopFinding] = []
    kind_counts: Counter[str] = Counter()
    target_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    for summary in summaries:
        findings.extend(summary.findings)
        kind_counts.update(summary.kind_counts)
        target_counts.update(summary.target_counts)
        source_counts.update(summary.source_counts)
        destination_counts.update(summary.destination_counts)
        detections.extend(summary.detections)
        errors.extend(summary.errors)
    return ControlLoopSummary(
        path=Path("ALL_PCAPS"),
        total_changes=total_changes,
        total_targets=total_targets,
        findings=findings[:200],
        kind_counts=kind_counts,
        target_counts=target_counts,
        source_counts=source_counts,
        destination_counts=destination_counts,
        detections=detections,
        errors=sorted({err for err in errors if err}),
    )
