from __future__ import annotations

import base64
import copy
import functools
import gzip
import inspect
import ipaddress
import math
import os
import re
import stat
import threading
import zlib
from collections import Counter, OrderedDict
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePath
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

from . import progress as _progress
from .lite import UNSUPPORTED as _LITE_UNSUPPORTED
from .lite import LitePacket as _LitePacket

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Classic pcap magic numbers, both byte orders: microsecond, nanosecond and the
# Kuznetzov "modified pcap" variant (patched tcpdump on old Red Hat systems; the
# same 24-byte global header, but 24-byte record headers carrying ifindex,
# protocol and packet type). Anything else is not a capture this tool can read.
PCAP_MAGIC: dict[int, str] = {
    0xA1B2C3D4: ">",
    0xD4C3B2A1: "<",
    0xA1B23C4D: ">",
    0x4D3CB2A1: "<",
    0xA1B2CD34: ">",
    0x34CDB2A1: "<",
}

# The modified-pcap magic as it appears on disk, mapped to its byte order.
# Kept separate because only these need the extended record-header reader.
PCAP_MODIFIED_MAGIC_BYTES: dict[bytes, str] = {
    b"\xa1\xb2\xcd\x34": ">",
    b"\x34\xcd\xb2\xa1": "<",
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
    # key=value, key: value, and JSON "key": "value"
    re.compile(
        r"(?i)\b(password|passwd|pass|pwd|secret|token|api[_-]?key|apikey|session(?:id)?|authorization)\b"
        r"([\"']?\s*[:=]\s*[\"']?)([^\s,;&\"']{1,})"
    ),
    re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)


_QUOTED_SECRET = re.compile(r"(?i)\b(password|passwd|pwd|secret|pin)(\s+)('[^']*'|\"[^\"]*\")")
_PASS_COMMAND = re.compile(r"\b(PASS)\s+(?!\[REDACTED\])(\S+)")


def redact_sensitive_text(value: object) -> str:
    """Best-effort redaction for terminal/export modes that should hide secrets."""
    text = str(value or "")
    if not text:
        return text

    def _kv_repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}[REDACTED]"

    # Bearer/Basic first: the key=value rule would otherwise consume the word
    # "Basic" after "Authorization:" and leave the token itself in place.
    text = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    text = _SECRET_PATTERNS[0].sub(_kv_repl, text)
    # Analyzer evidence: password 'x' / password "x" (OT credential findings)
    text = _QUOTED_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}'[REDACTED]'", text)
    # FTP/POP3 command form: PASS secret
    text = _PASS_COMMAND.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    text = _SECRET_PATTERNS[2].sub("[REDACTED_JWT]", text)
    text = _SECRET_PATTERNS[3].sub("[REDACTED_PRIVATE_KEY]", text)
    return text


_SGR = re.compile(r"\x1b\[[0-9;]*m")
_UNSAFE_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def terminal_safe(text: str) -> str:
    """Neutralise terminal control sequences in a rendered report.

    Pcapper's own colours are SGR sequences (ESC[...m) and are kept; every
    other control byte - OSC title/hyperlink sequences, cursor movement,
    screen clears, BEL, lone ESC - is shown escaped. Applied to every rendered
    section, so a renderer that forgets ``display_safe`` on packet text (a
    variable name, a GOOSE dataset, a file name) cannot drive the terminal.
    """
    if not text:
        return text
    parts = []
    last = 0
    for match in _SGR.finditer(text):
        parts.append(_UNSAFE_CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text[last:match.start()]))
        parts.append(match.group())
        last = match.end()
    parts.append(_UNSAFE_CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text[last:]))
    return "".join(parts)


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
            try:
                _DECODE_CACHE.move_to_end(key)
            except KeyError:  # evicted by another thread (shared analysis pass)
                pass
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
            try:
                _DECODE_CACHE.popitem(last=False)
            except KeyError:
                pass
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


GZIP_MAGIC = b"\x1f\x8b"


def file_version(path: Path) -> Optional[tuple[str, int, int]]:
    """``(real path, size, mtime_ns)``: what a fact about a file's bytes is
    cached under (None when it cannot be stat'ed)."""
    try:
        st = os.stat(path)
    except (OSError, ValueError):
        return None
    return (os.path.realpath(path), st.st_size, st.st_mtime_ns)


def _inflate_start(path: str, size: int) -> bytes:
    """The first ``size`` inflated bytes of a gzip file, read 4 KiB at a time
    (the gzip module reads 128 KiB of compressed data for even a few bytes)."""
    out = bytearray()
    inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        with open(path, "rb", buffering=0) as handle:
            while len(out) < size:
                if inflate.eof:  # the next member of a concatenated file
                    data = inflate.unused_data or handle.read(4096)
                    inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
                else:
                    data = handle.read(4096)
                if not data:
                    break
                out += inflate.decompress(data)
    except zlib.error as exc:
        raise OSError(f"not a readable gzip file: {exc}") from exc
    return bytes(out[:size])


@functools.lru_cache(maxsize=512)
def _capture_head(version: tuple[str, int, int]) -> tuple[bool, bytes]:
    """(gzip-compressed?, the first 64 bytes a reader sees) of one version of
    a file. Every analysis used to sniff the capture again -- two opens and a
    buffered 128 KB read each, 326 opens for one --overview -- for answers
    that only change when the file does."""
    path = version[0]
    with open(path, "rb", buffering=0) as handle:
        gz = handle.read(2) == GZIP_MAGIC
    if gz:
        return True, _inflate_start(path, 64)
    with open(path, "rb", buffering=0) as handle:
        return False, handle.read(64)


@functools.lru_cache(maxsize=64)
def _capture_prefix(version: tuple[str, int, int], size: int) -> bytes:
    path = version[0]
    with open(path, "rb", buffering=0) as handle:
        gz = handle.read(2) == GZIP_MAGIC
    if gz:
        return _inflate_start(path, size)
    with open(path, "rb", buffering=0) as handle:
        return handle.read(size)


def capture_prefix(path: Path, size: int = 1 << 16) -> bytes:
    """The first ``size`` bytes of a capture as its readers see them
    (inflated for ``.pcap.gz``), read with as little as that takes; for
    header checks that need more than :func:`capture_head` keeps."""
    version = file_version(path)
    if version is None:
        raise OSError(f"cannot stat {path}")
    return _capture_prefix(version, size)


def capture_head(path: Path) -> bytes:
    """The first 64 bytes of a capture as its readers see them (decompressed
    for ``.pcap.gz``); raises OSError when it cannot be read."""
    version = file_version(path)
    if version is None:
        raise OSError(f"cannot stat {path}")
    return _capture_head(version)[1]


def is_gzip_file(path: Path) -> bool:
    version = file_version(path)
    if version is None:
        return False
    try:
        with open(version[0], "rb", buffering=0) as handle:
            return handle.read(2) == GZIP_MAGIC
    except OSError:
        return False


def open_capture_file(path: Path, buffering: int = -1):  # type: ignore[no-untyped-def]
    """A capture's bytes for reading: decompressed for a gzip-compressed
    capture (``.pcap.gz``), as scapy's readers read it. Hashes are still taken
    over the file as given. A reader of a header passes a small ``buffering``:
    the default reads 128 KiB ahead, all of a small capture."""
    path = Path(path)
    if is_gzip_file(path):
        return gzip.open(path, "rb")
    return path.open("rb", buffering=buffering)


def detect_file_type(path: Path) -> str:
    """Classify a capture by magic number: ``pcapng``, ``pcap`` or ``unknown``
    (a gzip-compressed capture by the magic inside it).

    ``unknown`` used to be reported as ``pcap``; scapy then raised on open and
    the analyzers fell back to an empty reader, so a non-capture target
    produced a report of zero packets with no error. Callers that need a
    reader treat ``unknown`` as a hard error instead.
    """
    try:
        header = capture_head(path)[:4]
    except Exception:
        return "unknown"
    return capture_type_from_header(header)


def capture_type_from_header(header: bytes) -> str:
    """``pcapng``, ``pcap`` or ``unknown`` for the first four bytes of a file.

    Detection is by magic number only; the file name is never consulted, so a
    capture saved without an extension (rotating ``cap_<n>_<timestamp>``
    files from a capture appliance) is recognised like any other.
    """
    if header[:4] == PCAPNG_MAGIC:
        return "pcapng"
    if len(header) >= 4:
        little = int.from_bytes(header[:4], "little")
        big = int.from_bytes(header[:4], "big")
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
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        # Garbage pcapng timestamps (year 31969 in the ICSC 2021 FINS/S7
        # captures) used to abort every renderer that prints a time window.
        return f"<out-of-range timestamp {ts:.0f}>"
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


def gateway_macs(ip_mac_counts: dict) -> set[str]:
    """MACs that frames pair with two or more public IPv4 addresses: a
    router's. It forwards for every off-link address, so its MAC rides on all
    of their frames, while one host rarely holds two public IPv4 addresses.
    (IPv4 only: one host routinely holds several global IPv6 addresses.)"""
    public_v4: dict[str, set[str]] = {}
    for ip_value, counter in (ip_mac_counts or {}).items():
        if ":" in str(ip_value) or not is_public_ip(str(ip_value)):
            continue
        for mac in counter or ():
            mac_text = str(mac or "").strip().lower()
            if mac_text and mac_text != "00:00:00:00:00:00":
                public_v4.setdefault(mac_text, set()).add(str(ip_value))
    return {mac for mac, ips in public_v4.items() if len(ips) >= 2}


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
    """Source/destination of the first IPv4, else IPv6, else ARP layer.

    Lite packets answer from their headers; a scapy packet keeps the answer
    on itself, since a --threats run asks every packet ~40 times (packets are
    never modified once read, which the shared in-memory view relies on).
    """
    if type(pkt) is _LitePacket:
        answer = pkt.lite_endpoints(include_arp)  # type: ignore[attr-defined]
        if answer is not _LITE_UNSUPPORTED:
            return answer[0] or None, answer[1] or None
        pkt = pkt.materialize()  # type: ignore[attr-defined]
    store = getattr(pkt, "__dict__", None)
    cache_key = "_pcapper_ep" if include_arp else "_pcapper_ep_noarp"
    if store is not None:
        cached = store.get(cache_key)
        if cached is not None:
            return cached
    result = _extract_packet_endpoints(pkt, include_arp=include_arp)
    if store is not None:
        store[cache_key] = result
    return result


def _extract_packet_endpoints(
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
# --threats alone runs ~90 memoized analyzers; a cap of 24 evicted results
# before --overview/--ot-commands reused them (every OT analyzer ran twice).
_ANALYSIS_MEMO_MAX = 512
_MEMO_SCALARS = (str, int, float, bool, Path)
_MEMO_SKIP_KWARGS = {"show_status", "packets", "meta"}


class _MemoUnkeyable(Exception):
    pass


def _memo_key_value(value: object) -> str:
    if value is None or isinstance(value, _MEMO_SCALARS):
        return repr(value)
    if isinstance(value, PurePath):
        # An output directory or an indicator file: the same path asks for
        # the same result (its files do not change during a run).
        return f"<path {os.fspath(value)}>"
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


def _analysis_context_key(path: Path) -> tuple:
    """Process-wide state that changes what an analyzer sees for ``path``:
    decode-as port overrides and split-capture joining."""
    try:
        from .capture_parts import capture_parts
        from .pcap_cache import get_capture_window
        from .port_overrides import generation

        window = get_capture_window(path)
        window_key = window.key() if window is not None else None  # type: ignore[attr-defined]
        return (generation(), len(capture_parts(path)), window_key)
    except Exception:
        return ()


@lru_cache(maxsize=None)
def _memo_defaults(func) -> dict[str, object]:
    try:
        return {
            name: param.default
            for name, param in inspect.signature(func).parameters.items()
            if param.default is not inspect.Parameter.empty
        }
    except (TypeError, ValueError):
        return {}


# Shared analysis pass support (pcapper.sharedpass). While a pass runs,
# analyzers execute concurrently in threads: the memo is locked, a call whose
# twin is already being computed waits for it instead of reading the capture
# again (_COORDINATE), a dry run records every memoised call it makes
# (_MEMO_RECORDER), and fan-out orchestrators may prefetch their sub-analyses
# in one shared pass before computing (_FAN_OUT_HOOK).
_MEMO_LOCK = threading.RLock()
_IN_FLIGHT: dict[tuple, "_Flight"] = {}
_COORDINATE = False
_MEMO_RECORDER: Optional[list] = None
_FAN_OUT_HOOK: Optional[Any] = None
_BLOCK_HOOK: Optional[Any] = None
_NO_HIT = object()


_DOMAIN_USER_RE = re.compile(r"\b([A-Za-z0-9_.-]{1,64})\\([A-Za-z0-9_.-]{1,64})\b")
# Path components that the bare DOMAIN\user shape also matches: WMI namespaces
# (root\cimv2), filesystem paths (windows\temp, system32\cmd.exe) and
# registry keys. None of them is an account.
_NOT_A_DOMAIN = frozenset({
    "root", "windows", "winnt", "system32", "syswow64", "sysnative", "temp", "tmp", "users", "documents",
    "programdata", "appdata", "local", "roaming", "microsoft", "software", "system", "currentcontrolset",
    "controlset001", "control", "services", "policies", "hklm", "hkcu", "hku", "hkcr", "hkey_local_machine",
    "hkey_current_user", "hkey_users", "hkey_classes_root", "wbem", "drivers", "tasks", "prefetch", "inetpub",
    "wwwroot", "desktop", "downloads", "public", "default", "cimv2", "subscription", "standardcimv2",
    "interop", "security", "microsoftdfs", "wmi", "rsop", "directory", "ldap", "policy", "cli", "ccm",
})
_NOT_A_USER = frozenset({
    "cimv2", "standardcimv2", "subscription", "system32", "syswow64", "windows", "winnt", "temp", "tmp", "wbem",
    "appdata", "programdata", "currentcontrolset", "software", "microsoft", "drivers", "tasks", "prefetch",
    "inetpub", "wwwroot", "desktop", "downloads",
})
_FILE_SUFFIXES = (".exe", ".dll", ".sys", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".txt", ".log", ".tmp",
                  ".dat", ".ini", ".xml", ".lnk", ".msi", ".zip", ".evtx", ".hta", ".scr")


def domain_user_pairs(text: str) -> list[tuple[str, str]]:
    """``DOMAIN\\user`` account references in ``text``, as written.

    The shape also matches WMI namespaces, file paths, registry keys and UNC
    host\\share prefixes; those are skipped, so ``root\\cimv2`` or
    ``C:\\windows\\temp`` never surface as a domain and a user."""
    pairs: list[tuple[str, str]] = []
    for match in _DOMAIN_USER_RE.finditer(text or ""):
        start = match.start()
        if start and text[start - 1] in "\\:/":  # UNC (\\host\\share) or a deeper path segment
            continue
        dom, user = match.group(1), match.group(2)
        low_dom, low_user = dom.lower(), user.lower()
        if low_dom in _NOT_A_DOMAIN or low_user in _NOT_A_USER or dom.isdigit() or is_valid_ip(dom):
            continue
        if low_user.endswith(_FILE_SUFFIXES) or low_dom.endswith(_FILE_SUFFIXES):
            continue
        end = match.end()
        if end < len(text) and text[end] == "\\":  # a path continues: dir\\dir\\...
            continue
        pairs.append((dom, user))
    return pairs


def planning() -> bool:
    """True while a shared pass makes its plan (sharedpass.discover): every
    analysis then runs over an empty packet view only to record the memoised
    calls it makes, so none may read the capture from disk meanwhile."""
    return _MEMO_RECORDER is not None


class _Flight:
    __slots__ = ("event",)

    def __init__(self) -> None:
        self.event = threading.Event()


def fan_out(func):
    """Decorate an orchestrator that runs many analyzers over one capture
    (--threats, --overview ...). On a capture too large to keep in memory its
    sub-analyses are first computed in one shared pass (pcapper.sharedpass),
    so the call below finds them in the memo instead of reading the capture
    once per analyzer. Place it above ``@memoize_analysis``."""

    @functools.wraps(func)
    def entry(path, *args, **kwargs):
        hook = _FAN_OUT_HOOK
        if hook is not None:
            try:
                hook(func, path, args, kwargs)
            except Exception:  # noqa: BLE001 - the plain run below still works
                pass
        return func(path, *args, **kwargs)

    entry._pcapper_fan_out = True
    return entry


def _memo_key(func, path, args: tuple, kwargs: dict) -> Optional[tuple]:
    """The memo key of a call, or None when the call cannot be memoised."""
    try:
        path_obj = Path(path).expanduser()
        try:
            key_path = path_obj.resolve()
        except Exception:
            key_path = path_obj.absolute()
        st = key_path.stat()
        file_key = (str(key_path), st.st_size, st.st_mtime_ns)
    except Exception:
        return None

    packets = kwargs.get("packets")
    forced_same = False
    if packets is not None:
        try:
            from .pcap_cache import get_forced_packet_view

            forced_same = packets is get_forced_packet_view(Path(path))
        except Exception:
            forced_same = False
    if packets is not None and not forced_same:
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

    # Arguments passed explicitly at their default value (vt_lookup=False,
    # port_filter=None ...) must not make a second cache entry.
    defaults = _memo_defaults(func)
    kwargs_for_key = {
        name: value
        for name, value in kwargs.items()
        if not (
            name in defaults
            and type(value) is type(defaults[name])
            and value == defaults[name]
        )
    }
    try:
        key_args = [_memo_key_value(value) for value in args]
        key_kwargs = [
            (name, _memo_key_value(kwargs_for_key[name]))
            for name in sorted(kwargs_for_key)
            if name not in _MEMO_SKIP_KWARGS
        ]
    except _MemoUnkeyable:
        return None
    return (
        func.__module__,
        func.__qualname__,
        file_key,
        view_key,
        _analysis_context_key(Path(path)),
        tuple(key_args),
        tuple(key_kwargs),
    )


def _memo_lookup(key: tuple, copy_results: bool) -> Any:
    with _MEMO_LOCK:
        cached = _ANALYSIS_MEMO.get(key)
        if cached is None:
            return _NO_HIT
        _ANALYSIS_MEMO.move_to_end(key)
    if not copy_results:
        return cached
    try:
        return copy.deepcopy(cached)
    except Exception:
        with _MEMO_LOCK:
            _ANALYSIS_MEMO.pop(key, None)
        return _NO_HIT


def _memo_store(key: tuple, result: Any, copy_results: bool) -> None:
    if copy_results:
        try:
            result = copy.deepcopy(result)
        except Exception:
            return
    with _MEMO_LOCK:
        _ANALYSIS_MEMO[key] = result
        while len(_ANALYSIS_MEMO) > _ANALYSIS_MEMO_MAX:
            _ANALYSIS_MEMO.popitem(last=False)


def _wait_for_flight(flight: _Flight) -> None:
    hook = _BLOCK_HOOK
    if hook is not None:
        hook(True)
    try:
        flight.event.wait()
    finally:
        if hook is not None:
            hook(False)


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
        key = _memo_key(func, path, args, kwargs)
        if key is None:
            return func(path, *args, **kwargs)
        recorder = _MEMO_RECORDER
        if recorder is not None:
            # Discovery (pcapper.sharedpass): note the call and what it calls.
            token = recorder.enter(wrapper, path, args, dict(kwargs))
            try:
                return func(path, *args, **kwargs)
            finally:
                recorder.exit(token)
        hit = _memo_lookup(key, copy_results)
        if hit is not _NO_HIT:
            return hit
        flight = None
        if _COORDINATE:
            with _MEMO_LOCK:
                existing = _IN_FLIGHT.get(key)
                if existing is None:
                    flight = _IN_FLIGHT[key] = _Flight()
            if existing is not None:
                _wait_for_flight(existing)
                hit = _memo_lookup(key, copy_results)
                if hit is not _NO_HIT:
                    return hit
                # The twin computation failed: compute it here.
        try:
            result = func(path, *args, **kwargs)
            _memo_store(key, result, copy_results)
            _progress.subtask_done(module=func.__module__)  # a finished analysis moves the capture bar
            return result
        finally:
            if flight is not None:
                with _MEMO_LOCK:
                    _IN_FLIGHT.pop(key, None)
                flight.event.set()

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


_SECRET_FIELD = re.compile(
    r"(?i)(^|_)(secret|secrets|password|passwords|passwd|pwd|token|tokens|api_?key|credential_value|password_counts|secret_counts)$"
)


def _is_secret_field(name: str) -> bool:
    """Export field names whose value is a credential (redacted by name)."""
    return bool(_SECRET_FIELD.search(name))


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
        if not redact:
            return {str(k): to_serializable(v) for k, v in value.items()}
        out: dict[str, Any] = {}
        for index, (k, v) in enumerate(value.items()):
            key = str(k)
            if _is_secret_field(key) and isinstance(v, (str, bytes)) and v:
                out[key] = "[REDACTED]"
                continue
            if _is_secret_field(key) and isinstance(v, dict):
                # A mapping *named* for secrets keys by them (password counters).
                out[key] = {f"[REDACTED#{i}]": to_serializable(cv, redact=True) for i, cv in enumerate(v.values())}
                continue
            out[redact_sensitive_text(key)] = to_serializable(v, redact=True)
        return out
    if isinstance(value, (list, tuple, set)):
        return [to_serializable(item, redact=redact) for item in value]
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        try:
            return to_serializable(value.to_dict(), redact=redact)
        except Exception:
            pass
    if is_dataclass(value) and not isinstance(value, type) and redact:
        try:
            return to_serializable(
                {f.name: getattr(value, f.name) for f in fields(value)}, redact=True
            )
        except Exception:
            pass
    if is_dataclass(value) and not isinstance(value, type):
        # Field by field, not dataclasses.asdict(): asdict rebuilds every dict
        # subclass by passing it (key, value) pairs, and Counter(pairs) counts
        # the pairs - every Counter field was exported as {"('k', n)": 1}.
        try:
            return {
                f.name: to_serializable(getattr(value, f.name), redact=redact)
                for f in fields(value)
            }
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


@functools.lru_cache(maxsize=32)
def _printable_runs(min_len: int) -> "re.Pattern[bytes]":
    return re.compile(rb"[\x20-\x7e]{%d,}" % min_len)


_UTF16_PAIRS = re.compile(rb"(?:[\x20-\x7e]\x00)+")
_ZERO_TO_FF = bytes([0xFF]) + bytes(255)  # translate(): 0x00 -> 0xFF, anything else -> 0x00


def extract_ascii_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> list[str]:
    """Extract printable-ASCII runs (>= min_len) from a byte buffer.

    Canonical implementation shared by the protocol modules. Runs are split on
    any non-printable byte and decoded latin-1; a run at the very end of the
    buffer is kept. One regex scan (the maximal runs a byte loop would flush)
    instead of a Python loop per byte: --threats spent 30 s here.
    """
    if not data:
        return []
    if min_len < 1:
        return _ascii_strings_loop(data, min_len, max_len)
    return [run.decode("latin-1")[:max_len] for run in _printable_runs(min_len).findall(data)]


def _ascii_strings_loop(data: bytes, min_len: int, max_len: int) -> list[str]:
    results: list[str] = []
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
    data: bytes, min_len: int = 4, max_len: int = 200, *, aligned: bool = True
) -> list[str]:
    """Extract printable-ASCII runs encoded as UTF-16LE (Windows wide strings):
    each printable byte followed by a 0x00, decoded latin-1.

    ``aligned`` (the default) reads the buffer as pairs from offset 0, as a
    scan stepping two bytes does; otherwise the scan steps one byte after a
    pair that is not text and so also finds strings at odd offsets (the WMI
    and RPC copies). Both run in C: the aligned scan masks every character
    whose second byte is not 0x00 with one big-integer AND, the other is one
    regex scan.
    """
    if not data or min_len < 1:
        return _utf16le_strings_loop(data, min_len, max_len, aligned) if data else []
    raw = bytes(data)
    if not aligned:
        return [m.group(0)[0::2].decode("latin-1")[:max_len] for m in _UTF16_PAIRS.finditer(raw)
                if len(m.group(0)) >= 2 * min_len]
    pairs = len(raw) // 2
    if pairs < min_len:
        return []
    chars, highs = raw[0 : 2 * pairs : 2], raw[1 : 2 * pairs : 2]
    masked = (int.from_bytes(chars, "big") & int.from_bytes(highs.translate(_ZERO_TO_FF), "big")).to_bytes(pairs, "big")
    return [run.decode("latin-1")[:max_len] for run in _printable_runs(min_len).findall(masked)]


def _utf16le_strings_loop(data: bytes, min_len: int, max_len: int, aligned: bool) -> list[str]:
    results: list[str] = []
    current = bytearray()
    i = 0
    while i + 1 < len(data):
        ch = data[i]
        if 32 <= ch <= 126 and data[i + 1] == 0:
            current.append(ch)
            i += 2
            continue
        if len(current) >= min_len:
            results.append(current.decode("latin-1", errors="ignore")[:max_len])
        current = bytearray()
        i += 2 if aligned else 1
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


# Top-level domains a domain-shaped token in free text must end with to be
# counted as a domain: every delegated country code, the legacy generics,
# common new generics and the internal suffixes analysts meet. Without it
# HTML/JavaScript ("element.value", "n.push", "window.Document") filled the
# strings report's domain ranking.
KNOWN_TLDS = frozenset("""
ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo bq br bs bt bw by bz
ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm
fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it
je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn
mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps
pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj
tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
com net org edu gov mil int arpa info biz name pro aero coop museum mobi asia tel travel jobs cat post xxx
app dev page cloud online site website store shop tech xyz top club live life news blog email world today
space fun icu buzz link click guru agency digital network systems services solutions support center company
group media zone one global host win bid loan work men vip ltd llc inc art design studio software tools wiki
academy social chat team ninja rocks cool cafe city download stream video tube photo photos pics games game
fit health care finance money bank insurance law legal capital ventures fund trade market exchange cash
credit deals sale gift lol wtf kim moe ooo ink help how pink red blue black green gold plus best mba
university college school education science bio eco energy earth farm garden pet surf golf run casino bet
hotel tours cars auto taxi rest bar pub wine beer pizza menu recipes cooking events party community church
house homes rent land estate realty properties directory guide reviews report review express direct
domains hosting webcam porn sex sexy adult dating date love xin wang ren top
google microsoft apple amazon azure windows bing office xbox youtube android chrome play search goog
local localdomain lan corp internal intranet home
""".split())


def plausible_domain(name: str) -> bool:
    """A domain-shaped token whose last label is a known top-level domain,
    written in one case (a mixed-case "hR" is a minified-JavaScript name)."""
    labels = str(name or "").strip().rstrip(".").split(".")
    if len(labels) < 2 or not all(labels):
        return False
    tld = labels[-1]
    return tld.lower() in KNOWN_TLDS and tld in (tld.lower(), tld.upper())


def ranked_slice(items: list, keep: int, tail: int = 10) -> list:
    """``items`` (ranked most to least frequent) cut to ``keep`` entries that
    still end with the true bottom ``tail``: what a report's top and bottom
    view needs from an analyzer that cannot keep everything."""
    items = list(items)
    if len(items) <= keep:
        return items
    tail = max(0, min(tail, keep))
    return items[: keep - tail] + (items[-tail:] if tail else [])


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


def dns_message(pkt: object) -> object:
    """The DNS-format layer of a packet, or None: DNS, or LLMNR -- scapy
    decodes UDP 5355 as LLMNRQuery / LLMNRResponse, which are not DNS
    subclasses, and getlayer() matches the exact class, so a getlayer(DNS)
    alone never sees an LLMNR lookup."""
    getlayer = getattr(pkt, "getlayer", None)
    if getlayer is None:
        return None
    try:
        from scapy.layers.dns import DNS
        from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
    except Exception:  # noqa: BLE001
        return None
    for layer in (DNS, LLMNRResponse, LLMNRQuery):
        found = getlayer(layer)
        if found is not None:
            return found
    return None


def _dns_text(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace").rstrip(".")
    return str(value if value is not None else "").rstrip(".")


def dns_answers(dns_layer: object, limit: int = 32) -> list[tuple[int, str, str]]:
    """``(rrtype, name, value)`` for the answer records of a scapy DNS layer:
    the address for A/AAAA, the target name for CNAME/NS/PTR/DNAME,
    ``"10 mail.example"`` for MX, ``"host:port"`` for SRV, the joined text for
    TXT and the primary server for SOA. ``an`` is a list in scapy >= 2.6 and
    a chained record before (walked through ``ancount``)."""
    an = getattr(dns_layer, "an", None)
    if an is None:
        return []
    if isinstance(an, (list, tuple)):
        items = list(an)
    else:
        items = []
        try:
            for index in range(int(getattr(dns_layer, "ancount", 0) or 0)):
                items.append(an[index])
        except Exception:  # noqa: BLE001 - a truncated chain ends the walk
            pass
    out: list[tuple[int, str, str]] = []
    for rr in items[:limit]:
        try:
            rrtype = int(getattr(rr, "type", 0) or 0)
        except (TypeError, ValueError):
            rrtype = 0
        name = _dns_text(getattr(rr, "rrname", ""))
        if rrtype == 15:
            value = f"{getattr(rr, 'preference', '')} {_dns_text(getattr(rr, 'exchange', ''))}".strip()
        elif rrtype == 33:
            value = f"{_dns_text(getattr(rr, 'target', ''))}:{getattr(rr, 'port', '')}"
        elif rrtype == 6:
            value = _dns_text(getattr(rr, "mname", ""))
        else:
            data = getattr(rr, "rdata", "")
            if isinstance(data, (list, tuple)):  # TXT: a list of strings
                value = " ".join(_dns_text(part) for part in data)
            else:
                value = _dns_text(data)
        out.append((rrtype, name, value))
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


def x509_names(cert: object) -> tuple[str, str]:
    """(subject, issuer) as RFC 4514 strings, never raising.

    ``cryptography`` parses names lazily: a certificate that loads fine can
    still raise on ``cert.subject`` (invalid UTF-8 in a UTF8String CN), which
    used to abort --tls/--certificates/--threats on one hostile handshake.
    """
    names = []
    for attr in ("subject", "issuer"):
        try:
            names.append(getattr(cert, attr).rfc4514_string())
        except Exception:  # noqa: BLE001 - malformed name in an attacker cert
            names.append("<unparseable name>")
    return names[0], names[1]
