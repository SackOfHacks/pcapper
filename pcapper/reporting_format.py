from __future__ import annotations

from typing import Iterable
import re
import textwrap


def format_table(rows: Iterable[list[str]]) -> str:
    rows = list(rows)
    if not rows:
        return "(none)"

    def _cell_text(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    rows = [[_cell_text(cell) for cell in row] for row in rows]

    def _visible_len(text: str) -> int:
        return len(re.sub(r"\x1b\[[0-9;]*m", "", text))

    def _hard_wrap_visible(text: str, width: int) -> list[str]:
        if width <= 0:
            return [text]
        if not text:
            return [""]
        chunks: list[str] = []
        visible_count = 0
        current: list[str] = []
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\x1b":
                m = re.match(r"\x1b\[[0-9;]*m", text[i:])
                if m:
                    seq = m.group(0)
                    current.append(seq)
                    i += len(seq)
                    continue
            if ch == "\n":
                chunks.append("".join(current))
                current = []
                visible_count = 0
                i += 1
                continue
            current.append(ch)
            visible_count += 1
            i += 1
            if visible_count >= width:
                chunks.append("".join(current))
                current = []
                visible_count = 0
        chunks.append("".join(current))
        return chunks or [""]

    def _wrap_cell_lines(text: str, width: int) -> list[str]:
        if width <= 0:
            return [text]
        if not text:
            return [""]

        max_visible = max(_visible_len(part) for part in text.splitlines() or [text])
        if max_visible <= width and "\n" not in text:
            return [text]

        wrapped: list[str] = []
        for base_line in (text.splitlines() or [text]):
            if not base_line:
                wrapped.append("")
                continue
            plain_line = re.sub(r"\x1b\[[0-9;]*m", "", base_line)
            if _visible_len(base_line) <= width:
                wrapped.append(base_line)
                continue
            if re.search(r"\s", plain_line):
                word_wrapped = textwrap.wrap(
                    base_line,
                    width=width,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                if word_wrapped:
                    for seg in word_wrapped:
                        if _visible_len(seg) <= width:
                            wrapped.append(seg)
                        else:
                            wrapped.extend(_hard_wrap_visible(seg, width))
                    continue
            wrapped.extend(_hard_wrap_visible(base_line, width))
        return wrapped or [""]

    widths = [max(_visible_len(row[i]) for row in rows) for i in range(len(rows[0]))]
    max_col_width = 56
    wrapped_widths = [min(width, max_col_width) for width in widths]

    lines: list[str] = []
    for row in rows:
        wrapped_cells = [_wrap_cell_lines(value, wrapped_widths[idx]) for idx, value in enumerate(row)]
        row_height = max((len(cell_lines) for cell_lines in wrapped_cells), default=1)

        for line_idx in range(row_height):
            parts: list[str] = []
            for idx, cell_lines in enumerate(wrapped_cells):
                value = cell_lines[line_idx] if line_idx < len(cell_lines) else ""
                pad = wrapped_widths[idx] - _visible_len(value)
                parts.append(value + (" " * max(0, pad)))
            lines.append("  ".join(parts))
    return "\n".join(lines)
