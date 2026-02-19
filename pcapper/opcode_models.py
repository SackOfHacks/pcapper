from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from .utils import safe_read_text


@dataclass(frozen=True)
class OpcodeModel:
    protocol: str
    magic_ascii: tuple[str, ...]
    magic_hex: tuple[str, ...]
    opcode_offsets: tuple[int, ...]
    opcode_size: int
    opcode_endian: str
    opcodes: dict[int, str]
    max_scan: int = 256

    def _magic_bytes(self) -> list[bytes]:
        values: list[bytes] = []
        for text in self.magic_ascii:
            if text:
                values.append(text.encode("ascii", errors="ignore"))
        for hex_text in self.magic_hex:
            try:
                values.append(bytes.fromhex(hex_text))
            except Exception:
                continue
        return [val for val in values if val]

    def extract_opcodes(self, payload: bytes) -> list[tuple[int, str | None, int]]:
        if not payload or self.opcode_size <= 0:
            return []
        results: list[tuple[int, str | None, int]] = []
        max_len = min(len(payload), self.max_scan)
        payload = payload[:max_len]
        magic_values = self._magic_bytes()
        if not magic_values:
            return results
        for magic in magic_values:
            start = payload.find(magic)
            if start < 0:
                continue
            for offset in self.opcode_offsets:
                op_start = start + offset
                op_end = op_start + self.opcode_size
                if op_start < 0 or op_end > len(payload):
                    continue
                opcode = int.from_bytes(payload[op_start:op_end], self.opcode_endian, signed=False)
                label = self.opcodes.get(opcode)
                results.append((opcode, label, op_start))
        return results


@lru_cache(maxsize=8)
def load_opcode_model(path: Path) -> OpcodeModel | None:
    if not path.exists():
        return None
    raw = safe_read_text(path, encoding="utf-8", errors="ignore")
    if not raw:
        return None
    try:
        import json

        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    protocol = str(data.get("protocol") or path.stem)
    magic_ascii = tuple(str(item) for item in (data.get("magic_ascii") or []))
    magic_hex = tuple(str(item) for item in (data.get("magic_hex") or []))
    opcode_offsets = tuple(int(item) for item in (data.get("opcode_offsets") or [0]))
    opcode_size = int(data.get("opcode_size") or 2)
    opcode_endian = str(data.get("opcode_endian") or "little").lower()
    raw_opcodes = data.get("opcodes") if isinstance(data.get("opcodes"), dict) else {}
    opcodes: dict[int, str] = {}
    for key, value in raw_opcodes.items():
        try:
            if isinstance(key, str) and key.lower().startswith("0x"):
                code = int(key, 16)
            else:
                code = int(key)
        except Exception:
            continue
        opcodes[code] = str(value)
    return OpcodeModel(
        protocol=protocol,
        magic_ascii=magic_ascii,
        magic_hex=magic_hex,
        opcode_offsets=opcode_offsets,
        opcode_size=opcode_size,
        opcode_endian=opcode_endian,
        opcodes=opcodes,
        max_scan=int(data.get("max_scan") or 256),
    )


def format_opcode(opcode: int, label: str | None = None) -> str:
    if label:
        return f"0x{opcode:04x} {label}"
    return f"0x{opcode:04x}"
