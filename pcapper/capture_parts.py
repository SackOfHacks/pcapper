"""Split captures: ``X.pcap.part000.pcap``, ``X.pcap.part001.pcap`` ... as one.

Large captures are routinely split to get under a size limit (a 2 GB release
asset, a mail attachment, a FAT32 stick) with ``tcpdump -C`` / ``editcap -c``.
Analysed file by file, one intrusion becomes N partial timelines and N
conversation tables, and anything that spans a part boundary (a scan, a
download, a beacon) is cut in two.

This module is a dependency-free leaf: it only recognises the naming
convention and keeps a registry mapping a *head* path (the first part, a real
file) to the ordered parts. ``pcap_cache`` consults the registry so every
reader of the head streams the parts back to back; nothing is concatenated on
disk and nothing beyond the normal packet cache is held in memory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# <base>.part<NNN>.<ext>, where <base> is usually the original file name
# (X.pcap) and NNN is zero-padded, three digits or more.
PART_NAME_RE = re.compile(
    r"^(?P<base>.+)\.part(?P<index>\d{3,})\.(?P<ext>pcapng|pcap|cap)$",
    re.IGNORECASE,
)

_PARTS: dict[str, tuple[Path, ...]] = {}
# Each registered part file: (head, index, parts) of its group.
_MEMBERS: dict[str, tuple[Path, int, tuple[Path, ...]]] = {}
_DISPLAY: dict[str, str] = {}


@dataclass(frozen=True)
class PartGroup:
    base: str
    head: Path
    parts: tuple[Path, ...]
    missing: tuple[int, ...]


def _key(path: Path) -> str:
    try:
        return str(path.expanduser().resolve())
    except OSError:
        return str(path)


def part_info(path: Path) -> tuple[str, int] | None:
    """``(base, index)`` when ``path`` follows the split-part naming."""
    match = PART_NAME_RE.match(path.name)
    if not match:
        return None
    return match.group("base"), int(match.group("index"))


def group_split_captures(paths: list[Path]) -> tuple[list[Path], list[PartGroup]]:
    """Collapse each set of sibling parts in ``paths`` into its head path.

    Order is preserved: a group takes the position of its first part. A
    lone part (the caller named exactly one) is left alone — that is an
    explicit request to look at that slice. Returns the new path list and
    the groups that were formed (registered, so readers chain the parts).
    """
    buckets: dict[tuple[str, str], list[tuple[int, Path]]] = {}
    for path in paths:
        info = part_info(path)
        if info is None:
            continue
        base, index = info
        buckets.setdefault((str(path.parent), base), []).append((index, path))

    groups: dict[tuple[str, str], PartGroup] = {}
    for bucket_key, members in buckets.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda item: item[0])
        indices = [index for index, _path in members]
        expected = set(range(indices[0], indices[-1] + 1))
        missing = tuple(sorted(expected - set(indices)))
        parts = tuple(path for _index, path in members)
        group = PartGroup(
            base=bucket_key[1], head=parts[0], parts=parts, missing=missing
        )
        register_capture_parts(parts, display=_display_for(group))
        groups[bucket_key] = group

    if not groups:
        return list(paths), []

    output: list[Path] = []
    emitted: set[tuple[str, str]] = set()
    for path in paths:
        info = part_info(path)
        bucket_key = (str(path.parent), info[0]) if info else None
        if bucket_key in groups:
            if bucket_key not in emitted:
                emitted.add(bucket_key)
                output.append(groups[bucket_key].head)
            continue
        output.append(path)
    return output, list(groups.values())


def _display_for(group: PartGroup) -> str:
    label = f"{group.base} [{len(group.parts)} parts joined]"
    if group.missing:
        label = f"{group.base} [{len(group.parts)} parts joined, {len(group.missing)} missing]"
    return label


def register_capture_parts(parts: tuple[Path, ...] | list[Path], display: str | None = None) -> Path:
    """Register ``parts`` (in order) as one capture; returns the head path."""
    ordered = tuple(parts)
    if not ordered:
        raise ValueError("a capture group needs at least one part")
    head = ordered[0]
    _PARTS[_key(head)] = ordered
    if len(ordered) > 1:
        for index, part in enumerate(ordered):
            _MEMBERS[_key(part)] = (head, index, ordered)
    if display:
        _DISPLAY[head.name] = display
    return head


def capture_parts(path: Path) -> tuple[Path, ...]:
    """The files behind ``path``: its parts when it heads a group, else itself."""
    return _PARTS.get(_key(path), (path,))


def part_group(path: Path) -> tuple[Path, int, tuple[Path, ...]] | None:
    """``(head, index, parts)`` when ``path`` is one part of a joined capture."""
    if not _MEMBERS:
        return None
    return _MEMBERS.get(_key(path))


def is_joined_capture(path: Path) -> bool:
    return len(capture_parts(path)) > 1


def display_name(name: str) -> str:
    """The name to show for a capture file name (a joined head shows its base)."""
    return _DISPLAY.get(name, name)


def apply_display_names(text: str) -> str:
    """Rewrite any registered head file name inside a report title."""
    if not _DISPLAY:
        return text
    for raw, shown in _DISPLAY.items():
        if raw in text:
            text = text.replace(raw, shown)
    return text


def clear_capture_parts() -> None:
    _PARTS.clear()
    _MEMBERS.clear()
    _DISPLAY.clear()


def capture_size(path: Path) -> int:
    """Total bytes of the files behind ``path`` (all parts of a joined capture)."""
    total = 0
    for part in capture_parts(path):
        try:
            total += part.stat().st_size
        except OSError:
            continue
    return total
