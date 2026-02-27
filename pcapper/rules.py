from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
import json
import re

from .utils import safe_read_text


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    match: dict[str, Any]


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    title: str
    severity: str
    count: int
    examples: list[str]
    sources: list[str]


@dataclass(frozen=True)
class RulesSummary:
    path: Path
    total_rules: int
    total_matches: int
    hits: list[RuleHit]
    errors: list[str]


def _load_yaml(raw: str) -> Any:
    try:
        import yaml  # type: ignore
    except Exception:
        raise ValueError("YAML rules require PyYAML to be installed.")
    return yaml.safe_load(raw)


def _normalize_rule(entry: dict[str, Any]) -> Rule | None:
    rule_id = str(entry.get("id") or entry.get("rule_id") or "").strip()
    if not rule_id:
        return None
    title = str(entry.get("title") or rule_id).strip()
    severity = str(entry.get("severity") or "info").strip().lower()
    match = entry.get("match") or {}
    if isinstance(match, str):
        match = {"summary_contains": match}
    if not isinstance(match, dict):
        match = {}
    return Rule(rule_id=rule_id, title=title, severity=severity, match=match)


def load_rules(path: Path) -> tuple[list[Rule], list[str]]:
    errors: list[str] = []
    raw = safe_read_text(path, error_list=errors, context="rules file read")
    if not raw:
        return [], errors

    data: Any = None
    try:
        if path.suffix.lower() in {".yml", ".yaml"}:
            data = _load_yaml(raw)
        else:
            data = json.loads(raw)
    except Exception as exc:
        errors.append(f"Rules parse error: {exc}")
        return [], errors

    entries: list[dict[str, Any]] = []
    if isinstance(data, list):
        entries = [item for item in data if isinstance(item, dict)]
    elif isinstance(data, dict):
        rules_block = data.get("rules")
        if isinstance(rules_block, list):
            entries = [item for item in rules_block if isinstance(item, dict)]
        else:
            entries = [data]

    rules: list[Rule] = []
    for entry in entries:
        rule = _normalize_rule(entry)
        if rule is None:
            errors.append("Rule missing id.")
            continue
        rules.append(rule)
    return rules, errors


def _iter_detections(summary: Any) -> Iterable[dict[str, Any]]:
    detections = getattr(summary, "detections", None)
    if isinstance(detections, list):
        for item in detections:
            if isinstance(item, dict):
                yield item

    anomalies = getattr(summary, "anomalies", None)
    if isinstance(anomalies, list):
        for item in anomalies:
            if hasattr(item, "__dict__"):
                try:
                    yield vars(item)
                except Exception:
                    continue


def collect_detections(summaries: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for source, summary in summaries.items():
        for entry in _iter_detections(summary):
            items.append(
                {
                    "source": source,
                    "severity": str(entry.get("severity", "info")).lower(),
                    "summary": str(entry.get("summary", "") or entry.get("title", "") or ""),
                    "details": str(entry.get("details", "") or entry.get("description", "") or ""),
                    "category": str(entry.get("category", "") or ""),
                    "raw": entry,
                }
            )
    return items


def _coerce_number(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except Exception:
            return None
    return None


def _match_condition(condition: dict[str, Any], record: dict[str, Any]) -> bool:
    field = str(condition.get("field") or "").strip()
    if not field:
        return False
    op = str(condition.get("op") or "contains").strip().lower()
    value = condition.get("value")
    actual = record.get(field)

    if op == "eq":
        return str(actual) == str(value)
    if op == "neq":
        return str(actual) != str(value)
    if op == "contains":
        if value is None:
            return False
        actual_text = str(actual or "").lower()
        if isinstance(value, (list, tuple, set)):
            return any(str(item).lower() in actual_text for item in value)
        return str(value).lower() in actual_text
    if op == "regex":
        if value is None:
            return False
        try:
            return re.search(str(value), str(actual or ""), re.IGNORECASE) is not None
        except re.error:
            return False
    if op == "in":
        if isinstance(value, (list, tuple, set)):
            return str(actual) in {str(item) for item in value}
        return str(actual) == str(value)
    if op in {"gt", "gte", "lt", "lte"}:
        actual_num = _coerce_number(actual)
        target_num = _coerce_number(value)
        if actual_num is None or target_num is None:
            return False
        if op == "gt":
            return actual_num > target_num
        if op == "gte":
            return actual_num >= target_num
        if op == "lt":
            return actual_num < target_num
        if op == "lte":
            return actual_num <= target_num
    return False


def _match_rule(rule: Rule, record: dict[str, Any]) -> bool:
    match = rule.match or {}
    if "field" in match and "value" in match:
        return _match_condition(match, record)

    all_conditions = match.get("all") or []
    any_conditions = match.get("any") or []
    if not all_conditions and not any_conditions:
        # convenience match keys
        summary_contains = match.get("summary_contains")
        if summary_contains:
            return _match_condition({"field": "summary", "op": "contains", "value": summary_contains}, record)
        details_regex = match.get("details_regex")
        if details_regex:
            return _match_condition({"field": "details", "op": "regex", "value": details_regex}, record)
        sources = match.get("sources")
        if sources:
            return _match_condition({"field": "source", "op": "in", "value": sources}, record)
        return False

    for condition in all_conditions:
        if not isinstance(condition, dict) or not _match_condition(condition, record):
            return False
    if not any_conditions:
        return True
    for condition in any_conditions:
        if isinstance(condition, dict) and _match_condition(condition, record):
            return True
    return False


def apply_rules(path: Path, rules: list[Rule], detections: list[dict[str, Any]]) -> RulesSummary:
    hits: list[RuleHit] = []
    total_matches = 0

    for rule in rules:
        matched = [record for record in detections if _match_rule(rule, record)]
        if not matched:
            continue
        total_matches += len(matched)
        examples: list[str] = []
        sources: list[str] = []
        for record in matched:
            if len(examples) < 5:
                summary = record.get("summary", "")
                details = record.get("details", "")
                if details:
                    examples.append(f"{record.get('source', '-')}: {summary} :: {details}")
                else:
                    examples.append(f"{record.get('source', '-')}: {summary}")
            src = str(record.get("source", "") or "")
            if src and src not in sources:
                sources.append(src)
        hits.append(
            RuleHit(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                count=len(matched),
                examples=examples,
                sources=sources,
            )
        )

    return RulesSummary(
        path=path,
        total_rules=len(rules),
        total_matches=total_matches,
        hits=sorted(hits, key=lambda item: (-item.count, item.rule_id)),
        errors=[],
    )


def merge_rules_summaries(summaries: Iterable[RulesSummary]) -> RulesSummary:
    items = list(summaries)
    if not items:
        return RulesSummary(path=Path("ALL_PCAPS"), total_rules=0, total_matches=0, hits=[], errors=[])

    total_rules = max((item.total_rules for item in items), default=0)
    total_matches = 0
    hit_map: dict[str, RuleHit] = {}
    errors: list[str] = []
    for summary in items:
        total_matches += summary.total_matches
        errors.extend(summary.errors)
        for hit in summary.hits:
            existing = hit_map.get(hit.rule_id)
            if existing is None:
                hit_map[hit.rule_id] = RuleHit(
                    rule_id=hit.rule_id,
                    title=hit.title,
                    severity=hit.severity,
                    count=hit.count,
                    examples=list(hit.examples),
                    sources=list(hit.sources),
                )
            else:
                combined_examples = list(existing.examples)
                for example in hit.examples:
                    if len(combined_examples) >= 5:
                        break
                    if example not in combined_examples:
                        combined_examples.append(example)
                combined_sources = list(existing.sources)
                for src in hit.sources:
                    if src not in combined_sources:
                        combined_sources.append(src)
                hit_map[hit.rule_id] = RuleHit(
                    rule_id=hit.rule_id,
                    title=existing.title,
                    severity=existing.severity,
                    count=existing.count + hit.count,
                    examples=combined_examples,
                    sources=combined_sources,
                )

    hits = sorted(hit_map.values(), key=lambda item: (-item.count, item.rule_id))
    return RulesSummary(
        path=Path("ALL_PCAPS"),
        total_rules=total_rules,
        total_matches=total_matches,
        hits=hits,
        errors=sorted({err for err in errors if err}),
    )
