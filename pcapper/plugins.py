from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from typing import Any, Callable, Iterable


PluginAnalyze = Callable[..., object]
PluginRender = Callable[[object], str]
PluginMerge = Callable[[Iterable[object]], object]


@dataclass(frozen=True)
class PluginSpec:
    name: str
    flag: str
    help: str
    group: str = "it"
    analyze: PluginAnalyze | None = None
    render: PluginRender | None = None
    merge: PluginMerge | None = None
    title: str | None = None
    export_key: str | None = None

    def dest(self) -> str:
        return self.flag.lstrip("-").replace("-", "_")


@dataclass(frozen=True)
class PluginLoadResult:
    plugins: list[PluginSpec]
    errors: list[str]


def _normalize_group(group: str) -> str:
    text = str(group or "").strip().lower()
    if text in {"ot", "ics", "industrial"}:
        return "ot"
    return "it"


def _coerce_specs(value: object) -> list[PluginSpec]:
    if isinstance(value, PluginSpec):
        return [value]
    if isinstance(value, (list, tuple)):
        specs: list[PluginSpec] = []
        for item in value:
            if isinstance(item, PluginSpec):
                specs.append(item)
        return specs
    return []


def load_plugins() -> PluginLoadResult:
    plugins: list[PluginSpec] = []
    errors: list[str] = []

    try:
        entry_points = metadata.entry_points()
        if hasattr(entry_points, "select"):
            entries = entry_points.select(group="pcapper.plugins")
        else:
            entries = entry_points.get("pcapper.plugins", [])
    except Exception as exc:
        return PluginLoadResult(plugins=[], errors=[f"entry_points: {type(exc).__name__}: {exc}"])

    for entry in entries:
        try:
            factory = entry.load()
            specs = _coerce_specs(factory())
            for spec in specs:
                if not spec.name or not spec.flag:
                    continue
                if not spec.flag.startswith("--"):
                    continue
                group = _normalize_group(spec.group)
                plugins.append(PluginSpec(
                    name=spec.name,
                    flag=spec.flag,
                    help=spec.help,
                    group=group,
                    analyze=spec.analyze,
                    render=spec.render,
                    merge=spec.merge,
                    title=spec.title,
                    export_key=spec.export_key,
                ))
        except Exception as exc:
            errors.append(f"{entry.name}: {type(exc).__name__}: {exc}")

    return PluginLoadResult(plugins=plugins, errors=errors)


def plugin_map(plugins: Iterable[PluginSpec]) -> dict[str, PluginSpec]:
    return {spec.name: spec for spec in plugins}
