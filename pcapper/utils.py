from __future__ import annotations

import base64
import copy
import functools
import ipaddress
import math
import os
from collections import Counter, OrderedDict
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

try:
    from scapy.layers.inet import IP  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore

try:
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IPv6 = None  # type: ignore

try:
    from scapy.layers.l2 import ARP  # type: ignore
except Exception:  # pragma: no cover
    ARP = None  # type: ignore

try:
    from scapy.layers.inet import TCP, UDP  # type: ignore
except Exception:  # pragma: no cover
    TCP = UDP = None  # type: ignore

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
    if isinstance(payload, bytearray):
        payload = bytes(payload)
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


def decode_payload_lower(
    payload: bytes | None, *, encoding: str = "latin-1", limit: int | None = None
) -> str:
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


def counter_inc(
    counter: dict[object, int], key: object, inc: int = 1, max_keys: int | None = None
) -> None:
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


def set_add_cap(
    target: set[object], value: object, *, max_size: int | None = None
) -> None:
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
    # OLE2 / Compound File Binary — legacy Office (.doc/.xls/.ppt) and the
    # dominant macro-malware delivery container (Hancitor, Emotet, Dridex lures).
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE2/Office"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7Z"
    if data.startswith(b"MSCF"):  # Microsoft Cabinet — seen in malware staging
        return "CAB"
    if data.startswith((b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
        return "MACHO"
    # Windows shortcut (LNK) — common phishing/exec lure (HasLinkTargetIDList).
    if data.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "LNK"
    if data.startswith(b"<!DOCTYPE html") or data.startswith(b"<html"):
        return "HTML"
    if data.lstrip().startswith(b"{\\rtf"):
        return "RTF"
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


# --- Canonical IP classification ---------------------------------------------
# These replace ~35 near-duplicate per-module copies. "Public" means globally
# routable per IANA (ipaddress.is_global), which correctly excludes RFC1918,
# loopback, link-local, multicast, CGNAT (100.64/10), reserved, and
# documentation ranges — some old per-module copies used a looser
# "not private/loopback/multicast/link-local" test that misclassified CGNAT
# and reserved space as public. lru_cache keeps per-packet calls cheap.


@lru_cache(maxsize=100000)
def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=100000)
def is_public_ip(value: str) -> bool:
    try:
        return bool(ipaddress.ip_address(value).is_global)
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=100000)
def is_private_ip(value: str) -> bool:
    try:
        return bool(ipaddress.ip_address(value).is_private)
    except (ValueError, TypeError):
        return False


def shannon_entropy(value: str) -> float:
    """Base-2 Shannon entropy of a string (bits per symbol)."""
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total) for count in freq.values()
    )


def read_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode an ASN.1/BER length field at data[offset].

    Returns (length, next_offset). Short form (<0x80) is the value itself;
    long form encodes the byte-count in the low 7 bits followed by that many
    big-endian length octets. Returns (0, offset+1) on a malformed field.
    """
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(data):
        return 0, offset
    length = int.from_bytes(data[offset : offset + num_bytes], "big")
    return length, offset + num_bytes


def extract_packet_endpoints(
    pkt: object,
    *,
    include_arp: bool = True,
) -> tuple[Optional[str], Optional[str]]:
    getlayer = getattr(pkt, "getlayer", None)
    if not callable(getlayer):
        return None, None

    # Single layer walk per protocol (getlayer) instead of haslayer + index.
    try:
        if IP is not None:
            layer = getlayer(IP)
            if layer is not None:
                src = str(getattr(layer, "src", "")).strip()
                dst = str(getattr(layer, "dst", "")).strip()
                return (src or None), (dst or None)
    except Exception:
        pass

    try:
        if IPv6 is not None:
            layer = getlayer(IPv6)
            if layer is not None:
                src = str(getattr(layer, "src", "")).strip()
                dst = str(getattr(layer, "dst", "")).strip()
                return (src or None), (dst or None)
    except Exception:
        pass

    if not include_arp:
        return None, None

    try:
        if ARP is not None:
            layer = getlayer(ARP)
            if layer is not None:
                src = str(getattr(layer, "psrc", "")).strip()
                dst = str(getattr(layer, "pdst", "")).strip()
                return (src or None), (dst or None)
    except Exception:
        pass

    return None, None


_ANALYSIS_MEMO: "OrderedDict[tuple, Any]" = OrderedDict()
_ANALYSIS_MEMO_MAX = 24
_MEMO_SCALARS = (str, int, float, bool, Path)
_MEMO_SKIP_KWARGS = {"show_status", "packets", "meta"}


class _MemoUnkeyable(Exception):
    pass


def _memo_key_value(value: object) -> str:
    if value is None or isinstance(value, _MEMO_SCALARS):
        return repr(value)
    if isinstance(value, (list, tuple)):
        inner = ",".join(_memo_key_value(item) for item in value)
        return f"[{inner}]"
    if isinstance(value, (set, frozenset)):
        try:
            items = sorted(value)  # type: ignore[type-var]
        except Exception:
            raise _MemoUnkeyable()
        inner = ",".join(_memo_key_value(item) for item in items)
        return f"{{{inner}}}"
    if callable(value):
        module = getattr(value, "__module__", None)
        qualname = getattr(value, "__qualname__", None)
        if module is None or qualname is None:
            raise _MemoUnkeyable()
        # id() keeps distinct closures/lambdas with the same qualname from
        # aliasing; module-level functions keep a stable id per process.
        return f"<fn {module}.{qualname}#{id(value)}>"
    raise _MemoUnkeyable()


def clear_analysis_memo() -> None:
    _ANALYSIS_MEMO.clear()


def memoize_analysis(func):
    """Memoize an analyze_* function per capture state and arguments.

    Several analyzers run more than once within a single invocation: --ips
    runs the hostname analyzer internally, --hostdetails and --overview fan
    out into analyzers that may also be requested as top-level steps, and
    --files runs the NFS analyzer. The capture data is immutable for the
    duration of a run, so an identical repeat call can return a deep copy of
    the first result instead of re-iterating every packet.

    The cache key includes the capture file identity (path, size, mtime) and
    a fingerprint of the packet view in effect (explicit packets= argument or
    the forced packet view registered for the path), so filtered and
    unfiltered analyses never alias. Calls with non-scalar extra arguments
    bypass the cache entirely. Set PCAPPER_ANALYSIS_MEMO=0 to disable.
    """

    @functools.wraps(func)
    def wrapper(path, *args, **kwargs):
        if os.environ.get("PCAPPER_ANALYSIS_MEMO", "1") == "0":
            return func(path, *args, **kwargs)
        try:
            st = Path(path).stat()
            file_key = (str(path), st.st_size, st.st_mtime_ns)
        except Exception:
            return func(path, *args, **kwargs)

        packets = kwargs.get("packets")
        if packets is not None:
            view_key: tuple = ("packets", id(packets), len(packets))
        else:
            try:
                from .pcap_cache import get_forced_packet_view

                forced = get_forced_packet_view(Path(path))
            except Exception:
                forced = None
            if forced is not None:
                view_key = ("forced", id(forced), len(forced))
            else:
                view_key = ("disk",)

        try:
            key_args = [_memo_key_value(value) for value in args]
            key_kwargs = [
                (name, _memo_key_value(kwargs[name]))
                for name in sorted(kwargs)
                if name not in _MEMO_SKIP_KWARGS
            ]
        except _MemoUnkeyable:
            return func(path, *args, **kwargs)

        key = (
            func.__module__,
            func.__qualname__,
            file_key,
            view_key,
            tuple(key_args),
            tuple(key_kwargs),
        )
        cached = _ANALYSIS_MEMO.get(key)
        if cached is not None:
            _ANALYSIS_MEMO.move_to_end(key)
            try:
                return copy.deepcopy(cached)
            except Exception:
                _ANALYSIS_MEMO.pop(key, None)
                return func(path, *args, **kwargs)

        result = func(path, *args, **kwargs)
        try:
            snapshot = copy.deepcopy(result)
        except Exception:
            return result
        _ANALYSIS_MEMO[key] = snapshot
        while len(_ANALYSIS_MEMO) > _ANALYSIS_MEMO_MAX:
            _ANALYSIS_MEMO.popitem(last=False)
        return result

    return wrapper


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    levels = "▁▂▃▄▅▆▇█"
    max_val = max(values) if values else 0
    if max_val == 0:
        return "".join(levels[0] for _ in values)
    return "".join(
        levels[min(len(levels) - 1, int((val / max_val) * (len(levels) - 1)))]
        for val in values
    )


def hexdump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
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


def packet_length(pkt: object) -> int:
    """Length of the captured packet bytes without re-serializing.

    len(pkt) on a scapy Packet rebuilds the packet; for packets read from a
    capture, pkt.original holds the raw bytes and is authoritative.
    """
    original = getattr(pkt, "original", None)
    if isinstance(original, (bytes, bytearray)):
        return len(original)
    try:
        return int(len(pkt))  # type: ignore[arg-type]
    except Exception:
        return 0


def extract_ascii_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> list[str]:
    """Extract printable-ASCII runs (>= min_len) from a byte buffer.

    Canonical implementation shared by the protocol modules. Runs are split on
    any non-printable byte and decoded latin-1 with errors ignored; the trailing
    run (if any) is flushed so a string at the very end of the buffer is kept.
    """
    results: list[str] = []
    if not data:
        return results
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                results.append(current.decode("latin-1", errors="ignore")[:max_len])
            current = bytearray()
    if len(current) >= min_len:
        results.append(current.decode("latin-1", errors="ignore")[:max_len])
    return results


def extract_utf16le_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> list[str]:
    """Extract printable-ASCII runs encoded as UTF-16LE (Windows wide strings).

    Canonical implementation shared by the protocol modules (each printable byte
    followed by a 0x00). Runs are decoded latin-1 with errors ignored; the
    trailing run is flushed.
    """
    results: list[str] = []
    current = bytearray()
    i = 0
    while i + 1 < len(data):
        ch = data[i]
        if 32 <= ch <= 126 and data[i + 1] == 0:
            current.append(ch)
        elif len(current) >= min_len:
            results.append(current.decode("latin-1", errors="ignore")[:max_len])
            current = bytearray()
        else:
            current = bytearray()
        i += 2
    if len(current) >= min_len:
        results.append(current.decode("latin-1", errors="ignore")[:max_len])
    return results


def beacon_score(
    times: list[float],
    *,
    min_interval: float = 5.0,
    max_interval: float = 86400.0,
    rel_jitter: float = 0.25,
    abs_jitter_floor: float = 5.0,
) -> Optional[dict[str, float]]:
    """Score a timestamp series for periodic (beaconing) behaviour.

    Canonical implementation shared by the per-protocol analyzers (previously
    copy-pasted as `_beaconing_score`/`_beacon_score`). Returns {avg, stddev} when
    the inter-arrival deltas are regular (mean within [min_interval, max_interval]
    and stddev <= max(abs_jitter_floor, mean*rel_jitter)), else None.
    """
    if len(times) < 5:
        return None
    times_sorted = sorted(times)
    deltas = [b - a for a, b in zip(times_sorted, times_sorted[1:]) if b > a]
    if len(deltas) < 4:
        return None
    avg = sum(deltas) / len(deltas)
    if avg <= 0:
        return None
    variance = sum((d - avg) ** 2 for d in deltas) / len(deltas)
    stddev = variance**0.5
    if avg < min_interval or avg > max_interval:
        return None
    if stddev > max(abs_jitter_floor, avg * rel_jitter):
        return None
    return {"avg": avg, "stddev": stddev}


def tcp_flags_int(flags: object) -> int:
    """Normalize a scapy TCP flags value (FlagValue/str/int) to an int bitmask."""
    try:
        if isinstance(flags, str):
            value = 0
            for ch, bit in (
                ("F", 1), ("S", 2), ("R", 4), ("P", 8),
                ("A", 16), ("U", 32), ("E", 64), ("C", 128),
            ):
                if ch in flags:
                    value |= bit
            return value
        return int(flags)  # type: ignore[arg-type]
    except Exception:
        return 0


def get_packet_ports(pkt: object) -> tuple[Optional[int], Optional[int], str]:
    """Return (sport, dport, transport) for a packet; transport in TCP/UDP/OTHER."""
    if TCP is not None and TCP in pkt:
        try:
            return (int(pkt[TCP].sport), int(pkt[TCP].dport), "TCP")
        except Exception:
            return (None, None, "TCP")
    if UDP is not None and UDP in pkt:
        try:
            return (int(pkt[UDP].sport), int(pkt[UDP].dport), "UDP")
        except Exception:
            return (None, None, "UDP")
    return (None, None, "OTHER")
