from __future__ import annotations

import os
import sys


ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_DIM = "\x1b[2m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_BLUE = "\x1b[34m"
ANSI_MAGENTA = "\x1b[35m"
ANSI_CYAN = "\x1b[36m"
ANSI_WHITE = "\x1b[37m"

_COLOR_OVERRIDE: bool | None = None


def use_color(enabled: bool | None = None) -> bool:
    if enabled is not None:
        return enabled
    if _COLOR_OVERRIDE is not None:
        return _COLOR_OVERRIDE
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def colorize(text: str, color: str | None, enabled: bool | None = None, bold: bool = False, dim: bool = False) -> str:
    if not use_color(enabled) or color is None:
        return text
    parts = []
    if bold:
        parts.append(ANSI_BOLD)
    if dim:
        parts.append(ANSI_DIM)
    parts.append(color)
    parts.append(text)
    parts.append(ANSI_RESET)
    return "".join(parts)


def set_color_override(enabled: bool | None) -> None:
    global _COLOR_OVERRIDE
    _COLOR_OVERRIDE = enabled


def header(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_CYAN, enabled, bold=True)


def label(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_BLUE, enabled, bold=True)


def ok(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_GREEN, enabled)


def warn(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_YELLOW, enabled)


def danger(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_RED, enabled, bold=True)


def orange(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_YELLOW, enabled, bold=True)


def muted(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_WHITE, enabled, dim=True)


def highlight(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_WHITE, enabled, bold=True)

def highlight(text: str, enabled: bool | None = None) -> str:
    return colorize(text, ANSI_WHITE, enabled, bold=True)
