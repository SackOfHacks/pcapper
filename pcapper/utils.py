from __future__ import annotations

from dataclasses import is_dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
import base64
from collections import OrderedDict
import os


PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_DECODE_CACHE: "OrderedDict[tuple[bytes, str, bool], str]" = OrderedDict()
_DECODE_CACHE_MAX_ITEMS = 2048
_DECODE_CACHE_MAX_BYTES = 4096
_MAX_COUNTER_KEYS = int(os.getenv("PCAPPER_MAX_COUNTER_KEYS", "50000"))
_MAX_SET_ITEMS = int(os.getenv("PCAPPER_MAX_SET_ITEMS", "50000"))
_MAX_SET_VALUES = int(os.getenv("PCAPPER_MAX_SET_VALUES", "2000"))


def decode_payload(
    payload: bytes | None,
    *,
    encoding: str = "latin-1",
    lower: bool = False,
    limit: int | None = None,
    cache: bool = True,
) -> str:
    if not payload:
        return ""
    view = payload[:limit] if limit else payload
    use_cache = cache and len(view) <= _DECODE_CACHE_MAX_BYTES
    key = (view, encoding, lower)
    if use_cache:
        cached = _DECODE_CACHE.get(key)
        if cached is not None:
            _DECODE_CACHE.move_to_end(key)
            return cached
    try:
        text = view.decode(encoding, errors="ignore")
    except Exception:
        text = ""
    if lower:
        text = text.lower()
    if use_cache:
        _DECODE_CACHE[key] = text
        if len(_DECODE_CACHE) > _DECODE_CACHE_MAX_ITEMS:
            _DECODE_CACHE.popitem(last=False)
    return text


def decode_payload_lower(payload: bytes | None, *, encoding: str = "latin-1", limit: int | None = None) -> str:
    return decode_payload(payload, encoding=encoding, lower=True, limit=limit)


def record_error(errors: list[str] | None, context: str, exc: Exception) -> None:
    if errors is None:
        return
    errors.append(f"{context}: {type(exc).__name__}: {exc}")


def safe_read_text(
    path: Path,
    *,
    encoding: str = "utf-8",
    errors: str = "ignore",
    error_list: list[str] | None = None,
    context: str = "read_text",
) -> str:
    try:
        return path.read_text(encoding=encoding, errors=errors)
    except Exception as exc:
        record_error(error_list, context, exc)
        return ""


def safe_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    errors_list: list[str] | None = None,
    context: str = "write_text",
) -> None:
    try:
        path.write_text(text, encoding=encoding)
    except Exception as exc:
        record_error(errors_list, context, exc)
        if errors_list is None:
            raise IOError(f"{context}: {type(exc).__name__}: {exc}") from exc


def counter_inc(counter: dict[object, int], key: object, inc: int = 1, max_keys: int | None = None) -> None:
    limit = _MAX_COUNTER_KEYS if max_keys is None else max_keys
    if key in counter or len(counter) < limit:
        counter[key] = int(counter.get(key, 0)) + inc
    else:
        counter["__other__"] = int(counter.get("__other__", 0)) + inc


def setdict_add(
    store: dict[object, set[object]],
    key: object,
    value: object,
    *,
    max_keys: int | None = None,
    max_values: int | None = None,
) -> None:
    limit = _MAX_COUNTER_KEYS if max_keys is None else max_keys
    value_limit = _MAX_SET_VALUES if max_values is None else max_values
    if key not in store:
        if len(store) >= limit:
            return
        store[key] = set()
    bucket = store[key]
    if len(bucket) >= value_limit:
        return
    bucket.add(value)


def set_add_cap(target: set[object], value: object, *, max_size: int | None = None) -> None:
    limit = _MAX_SET_ITEMS if max_size is None else max_size
    if len(target) >= limit:
        return
    target.add(value)


def detect_file_type(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
        if header == PCAPNG_MAGIC:
            return "pcapng"
    except Exception:
        pass
    return "pcap"


def detect_file_type_bytes(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "EXE/DLL"
    if data.startswith(b"%PDF"):
        return "PDF"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP/Office"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"\x89PNG"):
        return "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPG"
    if data.startswith(b"GIF8"):
        return "GIF"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP"
    if data.startswith(b"<!DOCTYPE html") or data.startswith(b"<html"):
        return "HTML"
    return "BINARY"


def format_bytes_as_mb(size_bytes: int) -> str:
    mb = size_bytes / (1024 * 1024)
    return f"{mb:.2f} MB"


def format_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "-"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {sec:.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {sec:.1f}s"


def format_speed_bps(speed_bps: Optional[int]) -> str:
    if speed_bps is None:
        return "-"
    if speed_bps <= 0:
        return "-"
    if speed_bps >= 1_000_000_000:
        return f"{speed_bps / 1_000_000_000:.2f} Gbps"
    if speed_bps >= 1_000_000:
        return f"{speed_bps / 1_000_000:.2f} Mbps"
    if speed_bps >= 1_000:
        return f"{speed_bps / 1_000:.2f} Kbps"
    return f"{speed_bps} bps"


def safe_float(value: object | None) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    levels = "▁▂▃▄▅▆▇█"
    max_val = max(values) if values else 0
    if max_val == 0:
        return "".join(levels[0] for _ in values)
    return "".join(levels[min(len(levels) - 1, int((val / max_val) * (len(levels) - 1)))] for val in values)


def hexdump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def to_serializable(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"_bytes_b64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(k): to_serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_serializable(item) for item in value]
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        try:
            return to_serializable(value.to_dict())
        except Exception:
            pass
    if is_dataclass(value):
        try:
            return to_serializable(asdict(value))
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            return to_serializable(vars(value))
        except Exception:
            pass
    return str(value)


def parse_time_arg(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return float(text)
    except Exception:
        pass
    try:
        if text.endswith("Z"):
            text = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None
