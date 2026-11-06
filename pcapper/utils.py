from __future__ import annotations

import base64
import copy
import functools
import inspect
import ipaddress
import math
import os
import re
import stat
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
    from scapy.layers.l2 import ARP, Ether  # type: ignore
except Exception:  # pragma: no cover
    ARP = None  # type: ignore
    Ether = None  # type: ignore

try:
    from scapy.layers.inet import TCP, UDP  # type: ignore
except Exception:  # pragma: no cover
    TCP = UDP = None  # type: ignore

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Classic pcap magic numbers, both byte orders, microsecond and nanosecond
# timestamp variants. Anything else is not a capture this tool can read.
PCAP_MAGIC: dict[int, str] = {
    0xA1B2C3D4: ">",
    0xD4C3B2A1: "<",
    0xA1B23C4D: ">",
    0x4D3CB2A1: "<",
}


def env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    """Read an integer tuning knob from the environment.

    A malformed value falls back to the default instead of raising at import
    time — several modules read their limits at module load, so a stray
    ``PCAPPER_*=abc`` in a shell profile must not make ``import pcapper`` fail.
    """
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if minimum is not None and value < minimum:
        return minimum
    return value


_DECODE_CACHE: "OrderedDict[tuple[bytes, str, bool], str]" = OrderedDict()
_DECODE_CACHE_MAX_ITEMS = 2048
_DECODE_CACHE_MAX_BYTES = 4096
_MAX_COUNTER_KEYS = env_int("PCAPPER_MAX_COUNTER_KEYS", 50000, minimum=1)
_MAX_SET_ITEMS = env_int("PCAPPER_MAX_SET_ITEMS", 50000, minimum=1)
_MAX_SET_VALUES = env_int("PCAPPER_MAX_SET_VALUES", 2000, minimum=1)
_REDACT_OUTPUT = os.environ.get("PCAPPER_REDACT", "").strip().lower() in {
    "1", "true", "yes", "on",
}


def set_output_redaction(enabled: bool) -> None:
    """Toggle display/export redaction for the current process."""
    global _REDACT_OUTPUT
    _REDACT_OUTPUT = bool(enabled)


def output_redaction_enabled() -> bool:
    return _REDACT_OUTPUT


_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\b(password|passwd|pass|pwd|secret|token|api[_-]?key|apikey|session(?:id)?|authorization)\b"
        r"(\s*[:=]\s*)([^\s,;&]{3,})"
    ),
    re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)


def redact_sensitive_text(value: object) -> str:
    """Best-effort redaction for terminal/export modes that should hide secrets."""
    text = str(value or "")
    if not text:
        return text

    def _kv_repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}[REDACTED]"

    text = _SECRET_PATTERNS[0].sub(_kv_repl, text)
    text = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    text = _SECRET_PATTERNS[2].sub("[REDACTED_JWT]", text)
    text = _SECRET_PATTERNS[3].sub("[REDACTED_PRIVATE_KEY]", text)
    return text


def display_safe(value: object, *, preserve_newlines: bool = True) -> str:
    """Escape terminal control bytes from capture-derived text.

    This is display safety, not forensic redaction: exports and hashes can still
    preserve original bytes, but terminal output must not honor ESC/OSC/control
    sequences supplied by a packet or filename.
    """
    text = str(value or "")
    if not text:
        return text
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch == "\n" and preserve_newlines:
            out.append(ch)
        elif ch == "\t":
            out.append(ch)
        elif code < 32 or 0x7F <= code < 0xA0:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def egress_mode() -> str:
    raw = os.environ.get("PCAPPER_NETWORK", "enrichment").strip().lower()
    if raw in {"off", "none", "disabled"}:
        return "off"
    if raw in {"offline", "local"}:
        return "offline"
    return "enrichment"


def network_egress_allowed() -> bool:
    return egress_mode() == "enrichment"


def allow_plaintext_egress() -> bool:
    return os.environ.get("PCAPPER_ALLOW_PLAINTEXT_EGRESS", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


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


def restrict_permissions(path: Path) -> None:
    """Restrict a written artifact to owner-only access (0600, 0700 for a dir).

    pcapper deliberately does not redact recovered secrets (see
    reporting._redact_secret), so its outputs routinely contain cleartext
    credentials, session tokens and malware samples. Under a default umask
    those land world-readable, exposing them to every other local account on a
    shared analysis host.

    Best effort by design: POSIX mode bits are largely a no-op on Windows, and
    failing to tighten permissions must never abort an analysis run.
    """
    try:
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            return
        mode = 0o700 if stat.S_ISDIR(st.st_mode) else 0o600
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            return
        try:
            os.chmod(path, mode, follow_symlinks=False)
        except TypeError:  # pragma: no cover - older/platform-specific Python
            path.chmod(mode)
    except Exception:
        pass


def restrict_dir_permissions(path: Path) -> None:
    """``mkdir(parents=True, exist_ok=True)`` plus an owner-only chmod.

    Only a directory this call actually creates is tightened; one the analyst
    already had keeps the mode they gave it, so pointing an output flag at an
    existing shared directory does not silently re-permission it. mkdir errors
    propagate exactly as a bare ``mkdir`` would — only the chmod is best effort.
    """
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if created:
        restrict_permissions(path)


def open_private(
    path: Path,
    mode: str = "w",
    *,
    encoding: str | None = "utf-8",
    errors: str | None = None,
    newline: str | None = None,
):
    """Open an output file that is owner-only from the moment it exists.

    ``Path.write_text()`` followed by ``chmod`` leaves a window in which the
    file sits at the umask default — world-readable on most hosts — while it
    is being filled with recovered credentials or a carved sample. Creating
    it through ``os.open`` with mode ``0o600`` closes that window; the chmod
    afterwards still covers a pre-existing file, whose mode ``O_CREAT`` does
    not touch. Modes: ``w``, ``wb``, ``a``, ``ab``. Best effort on Windows,
    where POSIX mode bits are mostly ignored.
    """
    if mode not in {"w", "wb", "a", "ab"}:
        raise ValueError(f"open_private: unsupported mode {mode!r}")
    path = Path(path)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode):
            raise OSError(f"refusing to write through symlink: {path}")
        if not stat.S_ISREG(existing.st_mode):
            raise OSError(f"refusing to write non-regular file: {path}")
        if getattr(existing, "st_nlink", 1) > 1:
            raise OSError(f"refusing to write hard-linked file: {path}")

    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if mode.startswith("a") else os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if "b" in mode:
        flags |= getattr(os, "O_BINARY", 0)
        encoding = None
        errors = None
        newline = None
    fd = os.open(str(path), flags, 0o600)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"refusing to write non-regular file: {path}")
        try:
            os.fchmod(fd, 0o600)
        except Exception:
            pass
    except Exception:
        os.close(fd)
        raise
    try:
        handle = os.fdopen(fd, mode, encoding=encoding, errors=errors, newline=newline)
    except Exception:
        os.close(fd)
        raise
    restrict_permissions(path)
    return handle


def safe_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    errors_list: list[str] | None = None,
    context: str = "write_text",
) -> None:
    try:
        with open_private(path, "w", encoding=encoding) as handle:
            handle.write(text)
    except Exception as exc:
        record_error(errors_list, context, exc)
        if errors_list is None:
            raise IOError(f"{context}: {type(exc).__name__}: {exc}") from exc


def safe_write_bytes(path: Path, data: bytes) -> None:
    """Write a recovered artifact owner-only; errors propagate to the caller."""
    with open_private(path, "wb") as handle:
        handle.write(data)


def output_path_warnings(path: Path) -> list[str]:
    """Security notes for output locations that may leak names or allow races."""
    warnings: list[str] = []
    try:
        path_obj = Path(path)
        check = path_obj if path_obj.exists() else path_obj.parent
        st = check.stat()
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISDIR(st.st_mode) and mode & 0o077:
            warnings.append(
                f"Output directory is shared ({check}, mode {mode:04o}); "
                "file contents are owner-only, but names and creation times may be visible."
            )
        parent = check.parent
        if parent and parent.exists():
            pstat = parent.stat()
            pmode = stat.S_IMODE(pstat.st_mode)
            if stat.S_ISDIR(pstat.st_mode) and pmode & 0o002 and not pmode & 0o1000:
                warnings.append(
                    f"Parent directory is world-writable without sticky bit ({parent}, mode {pmode:04o})."
                )
    except Exception:
        pass
    return warnings


def executable_path_warnings(path: Path) -> list[str]:
    warnings: list[str] = []
    try:
        p = Path(path)
        if not p.is_absolute():
            warnings.append(f"Executable path is not absolute: {p}")
        for candidate in (p, p.parent):
            try:
                st = candidate.stat()
            except Exception:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o022:
                warnings.append(
                    f"Executable trust boundary is writable by group/others: {candidate} mode {mode:04o}"
                )
    except Exception:
        pass
    return warnings


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
    """Classify a capture by magic number: ``pcapng``, ``pcap`` or ``unknown``.

    ``unknown`` used to be reported as ``pcap``; scapy then raised on open and
    the analyzers fell back to an empty reader, so a non-capture target
    produced a report of zero packets with no error. Callers that need a
    reader treat ``unknown`` as a hard error instead.
    """
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
    except Exception:
        return "unknown"
    if header == PCAPNG_MAGIC:
        return "pcapng"
    if len(header) == 4:
        little = int.from_bytes(header, "little")
        big = int.from_bytes(header, "big")
        if little in PCAP_MAGIC or big in PCAP_MAGIC:
            return "pcap"
    return "unknown"


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
    """Human-readable byte count.

    The name is historical: it always rendered megabytes with two decimals,
    so every artifact, conversation and capture under about 5 KB was printed
    as ``0.00 MB`` — the size of a 1.5 KB PDF or a 900-byte credential file
    was invisible in the report. Values under 1 MB now carry their own unit;
    at and above 1 MB the output is unchanged.
    """
    try:
        value = float(size_bytes or 0)
    except (TypeError, ValueError):
        value = 0.0
    if value < 0:
        value = 0.0
    if value >= 1024 * 1024 * 1024:
        return f"{value / (1024 * 1024 * 1024):.2f} GB"
    if value >= 1024 * 1024:
        return f"{value / (1024 * 1024):.2f} MB"
    if value >= 1024:
        return f"{value / 1024:.2f} KB"
    return f"{int(value)} B"


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
def ip_object(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse once, share across every predicate below (one cache, not four)."""
    try:
        return ipaddress.ip_address(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


def is_valid_ip(value: str) -> bool:
    return ip_object(value) is not None


def is_public_ip(value: str) -> bool:
    # "Public" means a routable internet UNICAST peer. Python reports
    # global-scope IPv6 multicast (e.g. ff0e::/16, and even link-local ff02::
    # solicited-node groups) as is_global=True, so multicast must be excluded or
    # benign IPv6 Neighbor Discovery / mDNS is mislabeled as public exposure.
    obj = ip_object(value)
    return obj is not None and bool(obj.is_global) and not obj.is_multicast


def is_private_ip(value: str) -> bool:
    obj = ip_object(value)
    return obj is not None and bool(obj.is_private)


def is_unicast_host_ip(value: str) -> bool:
    """True only for a real unicast host address.

    Broadcast and multicast destinations (subnet .255 directed broadcast,
    255.255.255.255 limited broadcast, 224.0.0.0/4 multicast) are one-to-many
    announcement/discovery channels — NetBIOS Mailslot browse, LLMNR, mDNS,
    SSDP, NTP broadcast, OT multicast (GOOSE/SV) — NOT host targets or C2
    peers. Detections that count "targets"/"peers"/"beacon destinations" must
    exclude them or benign broadcast chatter reads as scanning/beaconing.
    """
    obj = ip_object(value)
    if obj is None:
        return False
    if obj.is_multicast or obj.is_unspecified or obj.is_reserved:
        return False
    if isinstance(obj, ipaddress.IPv4Address):
        # Limited broadcast + the common /24 directed broadcast (host octet .255).
        if int(obj) & 0xFF == 0xFF:
            return False
    return True


def shannon_entropy(value: str | bytes) -> float:
    """Base-2 Shannon entropy of a string or byte buffer (bits per symbol)."""
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


@lru_cache(maxsize=512)
def _call_accepts_kwarg(func: object, name: str) -> bool:
    try:
        params = inspect.signature(func).parameters
    except (TypeError, ValueError):
        return False
    return name in params


def call_with_packet_view(
    func,
    path: Path,
    *args,
    packets: list[object] | None = None,
    meta: object | None = None,
    **kwargs,
):
    """Invoke an analyzer with shared packet context when it supports it."""
    if (
        packets is not None
        and "packets" not in kwargs
        and _call_accepts_kwarg(func, "packets")
    ):
        kwargs["packets"] = packets
    if meta is not None and "meta" not in kwargs and _call_accepts_kwarg(func, "meta"):
        kwargs["meta"] = meta
    return func(path, *args, **kwargs)


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

    The stored object itself is handed out on every hit. Results are treated
    as immutable once returned: the builders that are post-processed in place
    are not memoized, and tests/test_review_guards.py pins in-place mutation
    of a memoized result at zero. Deep-copying on store and hit — the old
    behaviour, and the dominant cost of a hit on the large summaries — can be
    restored with PCAPPER_ANALYSIS_MEMO_COPY=1; the 920-run snapshot suite
    was byte-identical under both settings when the default changed.
    """

    @functools.wraps(func)
    def wrapper(path, *args, **kwargs):
        if os.environ.get("PCAPPER_ANALYSIS_MEMO", "1") == "0":
            return func(path, *args, **kwargs)
        copy_results = os.environ.get("PCAPPER_ANALYSIS_MEMO_COPY", "0") == "1"
        try:
            path_obj = Path(path).expanduser()
            try:
                key_path = path_obj.resolve()
            except Exception:
                key_path = path_obj.absolute()
            st = key_path.stat()
            file_key = (str(key_path), st.st_size, st.st_mtime_ns)
        except Exception:
            return func(path, *args, **kwargs)

        packets = kwargs.get("packets")
        if packets is not None:
            view_key: tuple = ("packets", id(packets), len(packets))
        else:
            try:
                from .pcap_cache import get_forced_packet_view, get_forced_packet_view_serial

                forced = get_forced_packet_view(Path(path))
                serial = get_forced_packet_view_serial(Path(path))
            except Exception:
                forced = None
                serial = None
            if forced is not None:
                view_key = ("forced", serial, len(forced))
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
            if not copy_results:
                return cached
            try:
                return copy.deepcopy(cached)
            except Exception:
                _ANALYSIS_MEMO.pop(key, None)
                return func(path, *args, **kwargs)

        result = func(path, *args, **kwargs)
        if not copy_results:
            snapshot = result
        else:
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


def to_serializable(value: Any, *, redact: bool = False) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return redact_sensitive_text(value) if redact else value
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        if redact:
            return {"_bytes_redacted": len(value)}
        return {"_bytes_b64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(k): to_serializable(v, redact=redact) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_serializable(item, redact=redact) for item in value]
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        try:
            return to_serializable(value.to_dict(), redact=redact)
        except Exception:
            pass
    if is_dataclass(value):
        try:
            return to_serializable(asdict(value), redact=redact)
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            return to_serializable(vars(value), redact=redact)
        except Exception:
            pass
    text = str(value)
    return redact_sensitive_text(text) if redact else text


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
    """Length of the *captured* packet bytes without re-serializing.

    len(pkt) on a scapy Packet rebuilds the packet; for packets read from a
    capture, pkt.original holds the raw bytes and is authoritative. This is
    the caplen: on a snaplen-truncated capture it is shorter than what was on
    the wire — see :func:`packet_wirelen`.
    """
    original = getattr(pkt, "original", None)
    if isinstance(original, (bytes, bytearray)):
        return len(original)
    try:
        return int(len(pkt))  # type: ignore[arg-type]
    except Exception:
        return 0


def packet_wirelen(pkt: object) -> int:
    """Length of the packet as it was on the wire.

    scapy's pcap readers record the header's ``orig_len`` on ``pkt.wirelen``;
    when it is missing (a packet built in memory) the captured length is the
    best available answer. Byte totals reported as "traffic volume" should use
    this, and ``wirelen > caplen`` is the signature of a truncated capture.
    """
    wirelen = getattr(pkt, "wirelen", None)
    if isinstance(wirelen, int) and wirelen > 0:
        return wirelen
    return packet_length(pkt)


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


_TCP_FLAG_BITS: tuple[tuple[str, int], ...] = (
    ("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
    ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80),
)


def tcp_segment_length(tcp_layer: object, ip_layer: object) -> Optional[int]:
    """Application data bytes of a TCP segment, from the IP/TCP header lengths.

    ``len(tcp_layer.payload)`` is wrong for small frames: scapy hangs the
    Ethernet padding (frames are padded to the 60-byte minimum) under TCP, so
    a data-less SYN/RST/probe reports up to 6 bytes of "payload". Header
    arithmetic is immune to padding. Returns None when the lengths are not
    available (no IP layer), so callers can fall back explicitly.
    """
    if ip_layer is None:
        return None
    try:
        tcp_hlen = int(getattr(tcp_layer, "dataofs", 0) or 0) * 4 or 20
        ihl = getattr(ip_layer, "ihl", None)
        if ihl:
            total = int(getattr(ip_layer, "len", 0) or 0)
            if total <= 0:
                return None
            return max(0, total - int(ihl) * 4 - tcp_hlen)
        plen = getattr(ip_layer, "plen", None)
        if plen is not None:
            return max(0, int(plen) - tcp_hlen)
    except Exception:
        return None
    return None


def tcp_flags_int(flags: object) -> int:
    """Normalize a scapy TCP flags value (FlagValue/str/int) to an int bitmask."""
    try:
        if isinstance(flags, str):
            value = 0
            for ch, bit in _TCP_FLAG_BITS:
                if ch in flags:
                    value |= bit
            return value
        return int(flags)  # type: ignore[arg-type]
    except Exception:
        return 0


def tcp_flags_text(flags: int) -> str:
    """Bitmask -> the usual letter form (``SA``, ``PA``, ``R``); ``-`` if none."""
    out = "".join(label for label, bit in _TCP_FLAG_BITS if flags & bit)
    return out or "-"


def extract_ethertype(pkt: object) -> Optional[int]:
    """The Ethernet type field, from the Ether layer or the raw frame bytes.

    Canonical implementation (was duplicated in analyzer.py and
    industrial_helpers.py). Falls back to bytes 12–13 of the frame so a
    capture whose link type scapy could not dissect still classifies.
    """
    getlayer = getattr(pkt, "getlayer", None)
    if Ether is not None and callable(getlayer):
        try:
            layer = getlayer(Ether)
            if layer is not None:
                return int(layer.type)
        except Exception:
            pass
    try:
        raw = getattr(pkt, "original", None) or bytes(pkt)  # type: ignore[arg-type]
        if len(raw) >= 14:
            return int.from_bytes(raw[12:14], "big")
    except Exception:
        return None
    return None


def dns_questions(dns_layer: object) -> list[tuple[str, int]]:
    """``(qname, qtype)`` for every question of a scapy DNS layer.

    ``qd`` is a list of ``DNSQR`` in scapy >= 2.6 and a single record (or
    None) before. The 2.6 shim still proxies ``.qname`` to the first entry,
    but warns on every packet and hides every question after the first.
    Names are decoded and returned without the trailing dot.
    """
    qd = getattr(dns_layer, "qd", None)
    if qd is None:
        return []
    try:
        items = list(qd)
    except TypeError:
        items = [qd]
    out: list[tuple[str, int]] = []
    for item in items:
        raw = getattr(item, "qname", b"")
        name = (
            raw.decode("utf-8", errors="ignore")
            if isinstance(raw, (bytes, bytearray))
            else str(raw or "")
        )
        name = name.rstrip(".")
        if not name:
            continue
        try:
            qtype = int(getattr(item, "qtype", 0) or 0)
        except (TypeError, ValueError):
            qtype = 0
        out.append((name, qtype))
    return out


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
