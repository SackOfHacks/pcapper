"""Find the capture files behind a CLI target.

A file is a capture when its *header* says so (pcap, pcapng or modified-pcap
magic), not when its name ends in ``.pcap``: capture appliances and rotating
ring buffers write ``cap_<n>_<timestamp>`` files with no extension at all, and
those used to be refused outright.
"""

from __future__ import annotations

from pathlib import Path

from .utils import detect_file_type

PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".pcap0", ".ntar"}


def has_capture_extension(path: Path) -> bool:
    return path.suffix.lower() in PCAP_EXTENSIONS


def is_capture_file(path: Path) -> bool:
    """True when ``path`` is a regular file starting with a capture magic."""
    try:
        if not path.is_file():
            return False
    except OSError:
        return False
    return detect_file_type(path) != "unknown"


def find_pcaps(
    target: Path,
    recursive: bool = False,
    *,
    rejected: list[Path] | None = None,
) -> list[Path]:
    """Every capture under ``target``, by magic number, sorted by path.

    Hidden files and directories are skipped. A file that *looks* like a
    capture by extension but has no capture header is appended to
    ``rejected`` (when given) so the caller can say it was skipped instead of
    dropping it silently.
    """
    if target.is_file():
        return [target]

    pattern = "**/*" if recursive else "*"
    results: list[Path] = []
    for entry in target.glob(pattern):
        try:
            relative_parts = entry.relative_to(target).parts
        except ValueError:
            relative_parts = (entry.name,)
        if any(part.startswith(".") for part in relative_parts):
            continue
        if not entry.is_file():
            continue
        if is_capture_file(entry):
            results.append(entry)
        elif rejected is not None and has_capture_extension(entry):
            rejected.append(entry)
    return sorted(results)


def is_supported_pcap(path: Path) -> bool:
    """A capture this tool can read, judged by its header, not its name."""
    return is_capture_file(path)
