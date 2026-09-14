from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .utils import env_int, open_private, restrict_dir_permissions


@dataclass(frozen=True)
class DecryptConfig:
    enabled: bool
    tls_keylog: Path | None
    ssh_keylog: Path | None
    output_dir: Path
    limit: int


@dataclass(frozen=True)
class DecryptSummary:
    path: Path
    protocol: str
    keylog_path: Path | None
    output_dir: Path
    stream_count: int
    outputs: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _sanitize_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return cleaned.strip("_") or "stream"


def _tshark_available() -> bool:
    return shutil.which("tshark") is not None


TSHARK_TIMEOUT = float(env_int("PCAPPER_TSHARK_TIMEOUT", 120, minimum=1))

# Fields requested, in order, by the single stream-enumeration pass. Every one is
# emitted as a column whether or not it matched, so the row width is fixed and a
# field can be read by position — see _label_from_row.
_STREAM_FIELDS = (
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "ipv6.src",
    "ipv6.dst",
)


def _run_tshark(
    cmd: list[str], timeout: float = TSHARK_TIMEOUT
) -> subprocess.CompletedProcess[str] | None:
    """Run tshark, returning ``None`` if it exceeded ``timeout``.

    A malformed or very large capture can stall tshark indefinitely. ``--decrypt``
    invokes it once per stream, so an unbounded call means one pathological
    stream can take the whole run with it, with no output and no way for the
    operator to tell a hang from slow progress. Callers record the expiry in
    ``DecryptSummary.errors`` and move to the next stream, matching how
    ``threats.py`` already handles its own subprocess calls.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _split_fields(line: str, count: int) -> list[str]:
    """Split one ``-T fields`` row into exactly ``count`` columns.

    Deliberately does not strip the row first. tshark pads every requested
    ``-e`` field, so a field that did not match is emitted as an empty column
    rather than omitted — and for an IPv6 packet the empty columns (``ip.src``,
    ``ip.dst``) come *first*. Stripping the leading tab before splitting is
    indistinguishable from stripping data: it shifts every index down by one and
    silently mislabels the stream. The IPv4 case only appeared to work because
    its empty columns are trailing.
    """
    parts = line.split("\t")
    if len(parts) < count:
        parts.extend([""] * (count - len(parts)))
    return parts[:count]


def _label_from_row(parts: list[str]) -> str:
    """Build ``src-sport_to_dst-dport`` from a padded ``_STREAM_FIELDS`` row."""
    src_ip = parts[1] or parts[5]
    src_port = parts[2]
    dst_ip = parts[3] or parts[6]
    dst_port = parts[4]
    if src_ip and dst_ip:
        return f"{src_ip}-{src_port}_to_{dst_ip}-{dst_port}"
    return ""


def _collect_streams(
    path: Path, display_filter: str, pref: str | None
) -> tuple[list[int], dict[int, str], list[str]]:
    """Enumerate matching TCP streams and label each by its endpoints.

    One pass over the capture yields both. The labels used to come from a
    separate ``tshark`` invocation per stream, which re-read the whole file each
    time — 2N+1 reads for N streams, the dominant cost of ``--decrypt`` on a
    multi-GB capture — and bounded that read with ``-c 1``. ``-c`` caps packets
    *read*, not packets *matched*, so tshark read packet #1, applied the display
    filter, and stopped: every stream except the one containing the capture's
    first packet fell through to the ``stream_<N>`` fallback, leaving the
    labelling feature effectively inert.
    """
    errors: list[str] = []
    cmd = ["tshark"]
    if pref:
        cmd.extend(["-o", pref])
    cmd.extend(["-r", str(path), "-Y", display_filter, "-T", "fields"])
    # occurrence=f: take the first occurrence of a field rather than joining all
    # of them with commas, so a tunnelled packet cannot produce a "0,1" that
    # fails int() and silently drops the stream from the listing.
    cmd.extend(["-E", "occurrence=f"])
    for name in _STREAM_FIELDS:
        cmd.extend(["-e", name])

    proc = _run_tshark(cmd)
    if proc is None:
        errors.append(
            f"tshark stream listing timed out after {TSHARK_TIMEOUT:.0f}s: {path.name}"
        )
        return [], {}, errors
    if proc.returncode != 0:
        errors.append(proc.stderr.strip() or "tshark stream listing failed.")
        return [], {}, errors

    labels: dict[int, str] = {}
    for line in proc.stdout.splitlines():
        parts = _split_fields(line, len(_STREAM_FIELDS))
        if not any(parts):
            continue
        try:
            stream_id = int(parts[0])
        except ValueError:
            continue
        if not labels.get(stream_id):
            labels[stream_id] = _label_from_row(parts)
    return sorted(labels), labels, errors


def _stream_label(stream_id: int, labels: dict[int, str]) -> str:
    return _sanitize_filename(labels.get(stream_id) or f"stream_{stream_id}")


def _follow_stream(
    path: Path, stream_id: int, pref: str | None, follow_proto: str
) -> tuple[str, str] | None:
    """Follow one stream. ``None`` means tshark timed out and was given up on."""
    cmd = ["tshark"]
    if pref:
        cmd.extend(["-o", pref])
    cmd.extend(
        ["-r", str(path), "-q", "-z", f"follow,{follow_proto},ascii,{stream_id}"]
    )
    proc = _run_tshark(cmd)
    if proc is None:
        return None
    return proc.stdout, proc.stderr


def _decrypt_protocol(
    path: Path,
    keylog: Path,
    output_dir: Path,
    limit: int,
    *,
    protocol: str,
    pref_key: str,
    display_filter: str,
    follow_protos: tuple[str, ...],
) -> DecryptSummary:
    """Shared body of :func:`decrypt_tls` and :func:`decrypt_ssh`.

    ``follow_protos`` lists the ``-z follow,<proto>`` names to try in order;
    TLS needs the ``ssl`` fallback for tshark builds that predate the rename.
    """
    errors: list[str] = []
    notes: list[str] = []
    outputs: list[Path] = []
    tag = protocol.lower()

    if not _tshark_available():
        return DecryptSummary(
            path=path,
            protocol=protocol,
            keylog_path=keylog,
            output_dir=output_dir,
            stream_count=0,
            outputs=[],
            errors=["tshark not found on PATH."],
            notes=[],
        )

    pref = f"{pref_key}:{keylog}"
    streams, labels, stream_errors = _collect_streams(path, display_filter, pref)
    errors.extend(stream_errors)
    if not streams:
        notes.append(f"No {protocol} streams detected for decryption.")

    restrict_dir_permissions(output_dir)
    count = 0
    for stream_id in streams:
        if limit and count >= limit:
            notes.append(f"{protocol} stream limit reached ({limit}).")
            break
        label = _stream_label(stream_id, labels)
        filename = output_dir / f"{tag}_{stream_id}_{label}.txt"
        stdout = stderr = ""
        timed_out = False
        for index, follow_proto in enumerate(follow_protos):
            followed = _follow_stream(path, stream_id, pref, follow_proto)
            if followed is None:
                suffix = f" as {follow_proto}" if index else ""
                errors.append(
                    f"tshark timed out after {TSHARK_TIMEOUT:.0f}s following "
                    f"{protocol} stream {stream_id}{suffix}; skipped."
                )
                timed_out = True
                break
            stdout, stderr = followed
            if stdout or not stderr:
                break  # got data, or a clean empty result: no fallback needed
        if timed_out:
            continue
        if stderr.strip():
            errors.append(stderr.strip())
        if stdout:
            with open_private(filename, "w", encoding="utf-8", errors="ignore") as handle:
                handle.write(stdout)
            outputs.append(filename)
            count += 1

    return DecryptSummary(
        path=path,
        protocol=protocol,
        keylog_path=keylog,
        output_dir=output_dir,
        stream_count=count,
        outputs=outputs,
        errors=errors,
        notes=notes,
    )


def decrypt_tls(
    path: Path, keylog: Path, output_dir: Path, limit: int
) -> DecryptSummary:
    return _decrypt_protocol(
        path, keylog, output_dir, limit,
        protocol="TLS", pref_key="tls.keylog_file", display_filter="tls",
        follow_protos=("tls", "ssl"),
    )


def decrypt_ssh(
    path: Path, keylog: Path, output_dir: Path, limit: int
) -> DecryptSummary:
    return _decrypt_protocol(
        path, keylog, output_dir, limit,
        protocol="SSH", pref_key="ssh.keylog_file", display_filter="ssh",
        follow_protos=("ssh",),
    )
