from __future__ import annotations

from pathlib import Path
from typing import Iterable


PCAP_EXTENSIONS = {".pcap", ".pcapng"}


def find_pcaps(target: Path, recursive: bool = False) -> list[Path]:
    if target.is_file():
        return [target]

    pattern = "**/*" if recursive else "*"
    results: list[Path] = []
    for entry in target.glob(pattern):
        if entry.is_file() and entry.suffix.lower() in PCAP_EXTENSIONS:
            results.append(entry)
    return sorted(results)


def is_supported_pcap(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS
